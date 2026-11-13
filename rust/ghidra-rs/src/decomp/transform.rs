//! Port of `transform.cc`: placeholders for a data-flow transform (`TransformVar`,
//! `TransformOp`, `TransformManager`), built while a trace decides whether the transform is
//! possible and applied to the function in one go, and the lane layouts of a laned register
//! (`LaneDescription`, `LanedRegister`). Used by `ActionLaneDivide` ([`super::lanedivide`]).
//!
//! The placeholders live in arenas with typed ids. A split varnode's lanes are consecutive in
//! the variable arena, so `lanes + i` is the C++ pointer arithmetic over a split array. The
//! varnode marks of the trace are a set in the trace, not varnode flags. Little-endian only
//! (`Arch::new` rejects a big-endian processor): the big-endian address arithmetic is left out.

use std::collections::{BTreeMap, HashSet};

use super::op::{OpFlags, OpId};
use super::opcode::Opcode;
use super::rangeutil::calc_mask;
use super::varnode::{Space, VarnodeId, VnFlags};
use super::{err, Arch, Funcdata, Result};

/// Port of `LaneDescription`: how a whole register of `whole_size` bytes divides into lanes.
#[derive(Debug, Clone)]
pub(crate) struct LaneDescription {
    whole_size: i32,
    lane_size: Vec<i32>,
    lane_position: Vec<i32>,
}

impl LaneDescription {
    /// Port of `LaneDescription(int4 origSize,int4 sz)`: lanes of `sz` bytes.
    pub(crate) fn new(orig_size: i32, sz: i32) -> LaneDescription {
        let num = orig_size / sz;
        LaneDescription {
            whole_size: orig_size,
            lane_size: vec![sz; num as usize],
            lane_position: (0..num).map(|i| i * sz).collect(),
        }
    }
    /// Port of `LaneDescription(int4 origSize,int4 lo,int4 hi)`: a low and a high piece.
    pub(crate) fn two(orig_size: i32, lo: i32, hi: i32) -> LaneDescription {
        LaneDescription { whole_size: orig_size, lane_size: vec![lo, hi], lane_position: vec![0, lo] }
    }
    /// `getWholeSize`.
    pub(crate) fn whole_size(&self) -> i32 {
        self.whole_size
    }
    pub(crate) fn num_lanes(&self) -> i32 {
        self.lane_size.len() as i32
    }
    /// `getSize`: the size of lane `i`; an error past the lanes, where the C++ reads out of range.
    pub(crate) fn size(&self, i: i32) -> Result<i32> {
        Self::lane(&self.lane_size, i)
    }
    /// `getPosition`: the byte position of lane `i`.
    pub(crate) fn position(&self, i: i32) -> Result<i32> {
        Self::lane(&self.lane_position, i)
    }
    fn lane(per_lane: &[i32], i: i32) -> Result<i32> {
        match usize::try_from(i).ok().and_then(|i| per_lane.get(i)) {
            Some(&v) => Ok(v),
            None => err(format!("lane {i} is outside the lane description")),
        }
    }

    /// Port of `LaneDescription::getBoundary`: the lane starting at `byte_pos`, the number of
    /// lanes at the end, -1 if no lane starts there.
    pub(crate) fn boundary(&self, byte_pos: i32) -> i32 {
        if byte_pos < 0 || byte_pos > self.whole_size {
            return -1;
        }
        if byte_pos == self.whole_size {
            return self.num_lanes();
        }
        self.lane_position.binary_search(&byte_pos).map_or(-1, |i| i as i32)
    }

    /// Port of `LaneDescription::restriction`: the lanes (count, skip) of the `size` bytes at
    /// `byte_pos` within the lanes starting at `skip_lanes`.
    pub(crate) fn restriction(&self, skip_lanes: i32, byte_pos: i32, size: i32) -> Result<Option<(i32, i32)>> {
        let base = self.position(skip_lanes)? + byte_pos;
        Ok(self.lane_range(base, size))
    }

    /// Port of `LaneDescription::extension`: the lanes (count, skip) of a `size`-byte varnode of
    /// which the lanes starting at `skip_lanes` are the bytes at `byte_pos`.
    pub(crate) fn extension(&self, skip_lanes: i32, byte_pos: i32, size: i32) -> Result<Option<(i32, i32)>> {
        let base = self.position(skip_lanes)? - byte_pos;
        Ok(self.lane_range(base, size))
    }

    fn lane_range(&self, base: i32, size: i32) -> Option<(i32, i32)> {
        let skip = self.boundary(base);
        if skip < 0 {
            return None;
        }
        let fin = self.boundary(base + size);
        if fin < 0 || fin == skip {
            return None;
        }
        Some((fin - skip, skip))
    }
}

/// Port of `LanedRegister`: a register size and its allowed lane sizes (bit `n` set: `n` bytes).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct LanedRegister {
    pub(crate) whole_size: u32,
    pub(crate) mask: u32,
}

impl LanedRegister {
    pub(crate) fn allowed(self, size: i32) -> bool {
        (0..32).contains(&size) && (self.mask >> size) & 1 != 0
    }
    pub(crate) fn add(&mut self, size: i32) {
        if (0..32).contains(&size) {
            self.mask |= 1 << size;
        }
    }
    /// The lane sizes, smallest first (`LanedIterator`).
    pub(crate) fn sizes(self) -> impl Iterator<Item = i32> {
        (0..32).filter(move |&s| (self.mask >> s) & 1 != 0)
    }

    /// Port of `LanedRegister::parseSizes`: the mask of a `vector_lane_sizes` list. As in the
    /// C++, nothing is read after a trailing comma and each value is read as a stream reads an
    /// `int4` with no base set ([`parse_c_int`]).
    pub(crate) fn parse(whole_size: u32, sizes: &str) -> Result<LanedRegister> {
        let mut res = LanedRegister { whole_size, mask: 0 };
        for value in sizes.strip_suffix(',').unwrap_or(sizes).split(',') {
            match parse_c_int(value) {
                Some(sz) if sz > 0 && sz < i64::from(whole_size) && sz <= 16 => res.add(sz as i32),
                _ => return err(format!("Bad lane size: {value}")),
            }
        }
        Ok(res)
    }
}

/// What `istream >> int` reads with no base flag set: leading white space, a sign, then the
/// longest run of digits in base 16 after `0x`, base 8 after `0`, else base 10; the rest of the
/// text is ignored. `None` without a digit or when the value does not fit.
fn parse_c_int(text: &str) -> Option<i64> {
    let s = text.trim_start();
    let (neg, s) = match s.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, s.strip_prefix('+').unwrap_or(s)),
    };
    let hex = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .filter(|r| r.starts_with(|c: char| c.is_ascii_hexdigit()));
    let (radix, digits) = match hex {
        Some(rest) => (16, rest),
        None if s.starts_with('0') => (8, s),
        None => (10, s),
    };
    let end = digits.find(|c: char| !c.is_digit(radix)).unwrap_or(digits.len());
    let val = i64::from_str_radix(digits.get(..end)?, radix).ok()?;
    i32::try_from(if neg { -val } else { val }).ok().map(i64::from)
}

/// Index of a [`TVar`] in [`TransformManager::vars`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TVarId(pub(crate) usize);

impl TVarId {
    /// The lane `i` lanes above this one in a split array.
    pub(crate) fn lane(self, i: i32) -> TVarId {
        TVarId(self.0.wrapping_add_signed(i as isize))
    }
}

/// Index of a [`TOp`] in [`TransformManager::ops`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TOpId(usize);

/// `TransformVar`'s types of replacement varnode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VarType {
    Piece,
    Preexisting,
    NormalTemp,
    PieceTemp,
    Constant,
}

/// Port of `TransformVar`.
#[derive(Debug, Clone)]
struct TVar {
    vn: Option<VarnodeId>,
    replacement: Option<VarnodeId>,
    ty: VarType,
    split_terminator: bool,
    input_duplicate: bool,
    byte_size: u32,
    /// the constant, or the bit position within the original varnode
    val: u64,
    def: Option<TOpId>,
}

/// `TransformOp` special flags.
const OP_REPLACEMENT: u32 = 1;
const OP_PREEXISTING: u32 = 2;
const OP_INDIRECT: u32 = 4;
const INDIRECT_CREATION: u32 = 8;
const INDIRECT_CREATION_POSSIBLE_OUT: u32 = 0x10;
pub(crate) const INSERT_BEFORE: u32 = 0x20;
pub(crate) const INSERT_AFTER: u32 = 0x40;

/// Port of `TransformOp`.
#[derive(Debug, Clone)]
struct TOp {
    op: OpId,
    replacement: Option<OpId>,
    opc: Opcode,
    special: u32,
    output: Option<TVarId>,
    anchor: Option<TOpId>,
    input: Vec<Option<TVarId>>,
}

/// Port of `TransformManager`: the placeholders of one transform.
#[derive(Debug, Default)]
pub(crate) struct TransformManager {
    vars: Vec<TVar>,
    /// split varnodes by creation index: the first of their placeholders (`pieceMap`)
    piece_map: BTreeMap<VarnodeId, TVarId>,
    /// the new temporaries and constants, in creation order (`newVarnodes`)
    new_vars: Vec<TVarId>,
    ops: Vec<TOp>,
}

impl TransformManager {
    fn push_var(&mut self, ty: VarType, vn: Option<VarnodeId>, byte_size: u32, val: u64) -> TVarId {
        self.vars.push(TVar {
            vn,
            replacement: None,
            ty,
            split_terminator: false,
            input_duplicate: false,
            byte_size,
            val,
            def: None,
        });
        TVarId(self.vars.len() - 1)
    }

    /// Port of `TransformManager::preserveAddress`: a byte-aligned piece of a non-unique varnode
    /// keeps its storage.
    fn preserve_address(fd: &Funcdata, vn: VarnodeId, lsb_offset: i32) -> bool {
        lsb_offset & 7 == 0 && fd.uniq.map(Space::Sleigh) != Some(fd.vn(vn).space)
    }

    /// Port of `TransformManager::newPreexistingVarnode`.
    pub(crate) fn new_preexisting_varnode(&mut self, fd: &Funcdata, vn: VarnodeId) -> TVarId {
        let res = self.push_var(VarType::Preexisting, Some(vn), fd.vn(vn).size, 0);
        self.vars[res.0].split_terminator = true;
        self.piece_map.insert(vn, res);
        res
    }

    /// Port of `TransformManager::newUnique`.
    pub(crate) fn new_unique(&mut self, size: u32) -> TVarId {
        let res = self.push_var(VarType::NormalTemp, None, size, 0);
        self.new_vars.push(res);
        res
    }

    /// Port of `TransformManager::newConstant` (`lsbOffset` 0).
    pub(crate) fn new_constant(&mut self, size: u32, val: u64) -> TVarId {
        let res = self.push_var(VarType::Constant, None, size, val & calc_mask(size));
        self.new_vars.push(res);
        res
    }

    /// Port of `TransformManager::newSplit(vn,description,numLanes,startLane)`.
    pub(crate) fn new_split(
        &mut self,
        fd: &Funcdata,
        vn: VarnodeId,
        desc: &LaneDescription,
        num_lanes: i32,
        start_lane: i32,
    ) -> Result<TVarId> {
        let first = TVarId(self.vars.len());
        let base_bit = desc.position(start_lane)? * 8;
        let v = fd.vn(vn);
        for i in 0..num_lanes {
            let bitpos = desc.position(start_lane + i)? * 8 - base_bit;
            let byte_size = desc.size(start_lane + i)? as u32;
            if v.is_constant() {
                let val = if (0..64).contains(&bitpos) { (v.offset >> bitpos) & calc_mask(byte_size) } else { 0 };
                self.push_var(VarType::Constant, Some(vn), byte_size, val);
            } else {
                let ty = if Self::preserve_address(fd, vn, bitpos) { VarType::Piece } else { VarType::PieceTemp };
                self.push_var(ty, Some(vn), byte_size, bitpos as u64);
            }
        }
        if let Some(last) = self.vars.last_mut() {
            last.split_terminator = true;
        }
        self.piece_map.insert(vn, first);
        Ok(first)
    }

    /// Port of `TransformManager::getPreexistingVarnode`.
    pub(crate) fn get_preexisting_varnode(&mut self, fd: &Funcdata, vn: VarnodeId) -> TVarId {
        let v = fd.vn(vn);
        if v.is_constant() {
            return self.new_constant(v.size, v.offset);
        }
        match self.piece_map.get(&vn) {
            Some(&res) => res,
            None => self.new_preexisting_varnode(fd, vn),
        }
    }

    /// Port of `TransformManager::getSplit(vn,description,numLanes,startLane)`.
    pub(crate) fn get_split(
        &mut self,
        fd: &Funcdata,
        vn: VarnodeId,
        desc: &LaneDescription,
        num_lanes: i32,
        start_lane: i32,
    ) -> Result<TVarId> {
        match self.piece_map.get(&vn) {
            Some(&res) => Ok(res),
            None => self.new_split(fd, vn, desc, num_lanes, start_lane),
        }
    }

    fn push_op(&mut self, op: OpId, opc: Opcode, special: u32, anchor: Option<TOpId>, num: usize) -> TOpId {
        self.ops.push(TOp { op, replacement: None, opc, special, output: None, anchor, input: vec![None; num] });
        TOpId(self.ops.len() - 1)
    }

    /// Port of `TransformManager::newOpReplace`.
    pub(crate) fn new_op_replace(&mut self, num: usize, opc: Opcode, replace: OpId) -> TOpId {
        self.push_op(replace, opc, OP_REPLACEMENT, None, num)
    }

    /// Port of `TransformManager::newIndirectReplace`.
    pub(crate) fn new_indirect_replace(&mut self, fd: &Funcdata, replace: OpId) -> Result<TOpId> {
        let mut special = OP_REPLACEMENT | OP_INDIRECT;
        if fd.op(replace).flags.has(OpFlags::INDIRECT_CREATION) {
            let in0 = fd.vn(fd.input(replace, 0)?);
            special |= if in0.is_constant() && in0.has(VnFlags::INDIRECT_CREATION) {
                INDIRECT_CREATION
            } else {
                INDIRECT_CREATION_POSSIBLE_OUT
            };
        }
        Ok(self.push_op(replace, Opcode::Indirect, special, None, 1))
    }

    /// Port of `TransformManager::newOp`: an op placed before or after `anchor`.
    pub(crate) fn new_op(&mut self, num: usize, opc: Opcode, anchor: TOpId, position: u32) -> TOpId {
        let op = self.ops[anchor.0].op;
        self.push_op(op, opc, position, Some(anchor), num)
    }

    /// Port of `TransformManager::newPreexistingOp`.
    pub(crate) fn new_preexisting_op(&mut self, num: usize, opc: Opcode, original: OpId) -> TOpId {
        self.push_op(original, opc, OP_PREEXISTING, None, num)
    }

    /// Port of `TransformManager::opSetInput`.
    pub(crate) fn set_input(&mut self, rop: TOpId, rvn: TVarId, slot: usize) -> Result<()> {
        match self.ops[rop.0].input.get_mut(slot) {
            Some(s) => *s = Some(rvn),
            None => return err(format!("transform op has no input slot {slot}")),
        }
        Ok(())
    }

    /// Port of `TransformManager::opSetOutput`.
    pub(crate) fn set_output(&mut self, rop: TOpId, rvn: TVarId) -> Result<()> {
        match self.vars.get_mut(rvn.0) {
            Some(v) => v.def = Some(rop),
            None => return err("transform output is not a lane of its split"),
        }
        self.ops[rop.0].output = Some(rvn);
        Ok(())
    }

    /// Port of `TransformManager::newPiece`: one placeholder for `bit_size` bits of `vn` at
    /// `lsb_offset`. `preserve` is the manager's `preserveAddress` answer (a subclass may
    /// override it, as `SubfloatFlow` does).
    pub(crate) fn new_piece(&mut self, vn: VarnodeId, bit_size: u32, lsb_offset: u32, preserve: bool) -> TVarId {
        let ty = if preserve { VarType::Piece } else { VarType::PieceTemp };
        let res = self.push_var(ty, Some(vn), bit_size.div_ceil(8), u64::from(lsb_offset));
        self.vars[res.0].split_terminator = true;
        self.piece_map.insert(vn, res);
        res
    }

    /// Port of `TransformManager::getPiece`.
    pub(crate) fn get_piece(
        &mut self,
        vn: VarnodeId,
        bit_size: u32,
        lsb_offset: u32,
        preserve: bool,
    ) -> Result<TVarId> {
        match self.piece_map.get(&vn) {
            Some(&res) => {
                let v = &self.vars[res.0];
                if v.byte_size * 8 != bit_size || v.val != u64::from(lsb_offset) {
                    return err("Cannot create multiple pieces for one Varnode through getPiece");
                }
                Ok(res)
            }
            None => Ok(self.new_piece(vn, bit_size, lsb_offset, preserve)),
        }
    }

    /// Port of `TransformManager::preexistingGuard`: whether a preexisting op reached on `slot`
    /// is built now (not when its slot 0 is visited).
    pub(crate) fn preexisting_guard(&self, slot: usize, rvn: TVarId) -> bool {
        slot == 0 || !matches!(self.vars.get(rvn.0).map(|v| v.ty), Some(VarType::Piece | VarType::PieceTemp))
    }

    /// The op defining a placeholder (`TransformVar::getDef`).
    pub(crate) fn var_def(&self, rvn: TVarId) -> Option<TOpId> {
        self.vars.get(rvn.0).and_then(|v| v.def)
    }

    /// A placeholder op's input (`TransformOp::getIn`).
    pub(crate) fn op_input(&self, rop: TOpId, slot: usize) -> Option<TVarId> {
        self.ops.get(rop.0).and_then(|o| o.input.get(slot).copied().flatten())
    }

    /// The original varnode a placeholder models (`TransformVar::getOriginal`).
    pub(crate) fn original(&self, rvn: TVarId) -> Option<VarnodeId> {
        self.vars.get(rvn.0).and_then(|v| v.vn)
    }

    /// Port of `TransformManager::apply`.
    pub(crate) fn apply(mut self, fd: &mut Funcdata, arch: &Arch) -> Result<()> {
        self.create_ops(fd)?;
        let inputs = self.create_varnodes(fd)?;
        self.remove_old(fd);
        self.transform_input_varnodes(fd, arch, &inputs)?;
        self.place_inputs(fd)
    }

    /// Port of `TransformVar::createReplacement`.
    fn create_var(&mut self, fd: &mut Funcdata, id: TVarId) -> Result<()> {
        let v = self.vars[id.0].clone();
        if v.replacement.is_some() {
            return Ok(());
        }
        // TransformVar::def->replacement: the defining op is made before its output
        let def = match v.def {
            None => None,
            Some(d) => match self.ops[d.0].replacement {
                Some(op) => Some(op),
                None => return err("transform varnode made before its defining op"),
            },
        };
        let uniq = fd.uniq.map_or_else(|| err("no unique space"), Ok)?;
        let repl = match v.ty {
            VarType::Preexisting => v.vn.map_or_else(|| err("preexisting without varnode"), Ok)?,
            VarType::Constant => fd.new_constant(v.byte_size, v.val),
            VarType::NormalTemp | VarType::PieceTemp => match def {
                None => fd.new_unique(v.byte_size, uniq),
                Some(op) => fd.new_unique_out(v.byte_size, uniq, op),
            },
            VarType::Piece => {
                let orig = v.vn.map_or_else(|| err("piece without varnode"), Ok)?;
                if v.val & 7 != 0 {
                    return err("Varnode piece is not byte aligned");
                }
                let lsb = (v.val >> 3) as u32;
                let o = fd.vn(orig);
                if o.space == Space::Join {
                    return err("lane divide: a piece of a join varnode is not ported");
                }
                let (space, off) = (o.space, o.offset + u64::from(lsb));
                let repl = match def {
                    None => fd.new_varnode(v.byte_size, space, off),
                    Some(op) => fd.new_varnode_out(v.byte_size, space, off, op),
                };
                transfer_varnode_properties(fd, orig, repl, lsb);
                repl
            }
        };
        self.vars[id.0].replacement = Some(repl);
        Ok(())
    }

    /// Port of `TransformOp::createReplacement`.
    fn create_op(&mut self, fd: &mut Funcdata, id: TOpId) -> Result<()> {
        let rop = self.ops[id.0].clone();
        let repl = if rop.special & OP_PREEXISTING != 0 {
            fd.op_set_opcode(rop.op, rop.opc);
            fd.op_clear_inputs(rop.op);
            rop.op
        } else if rop.special & OP_INDIRECT != 0 {
            let iop = fd.input(rop.op, 1)?;
            let target = fd.iop_target(iop).map_or_else(|| err("INDIRECT without op"), Ok)?;
            let repl = fd.new_indirect(target)?;
            self.ops[id.0].replacement = Some(repl);
            if let Some(out) = rop.output {
                self.create_var(fd, out)?;
            }
            fd.op_insert_before(repl, rop.op)?;
            repl
        } else {
            let repl = fd.new_op(rop.opc, fd.op(rop.op).seq.addr);
            self.ops[id.0].replacement = Some(repl);
            if let Some(out) = rop.output {
                self.create_var(fd, out)?;
            }
            if rop.anchor.is_none() {
                if rop.opc == Opcode::Multiequal {
                    let bl = fd.op(rop.op).parent.map_or_else(|| err("dead op"), Ok)?;
                    fd.op_insert_begin(repl, bl);
                } else {
                    fd.op_insert_before(repl, rop.op)?;
                }
            }
            repl
        };
        self.ops[id.0].replacement = Some(repl);
        Ok(())
    }

    /// Port of `TransformOp::attemptInsertion`.
    fn attempt_insertion(&mut self, fd: &mut Funcdata, id: TOpId) -> Result<bool> {
        let Some(anchor) = self.ops[id.0].anchor else { return Ok(true) };
        if self.ops[anchor.0].anchor.is_some() {
            return Ok(false);
        }
        let rop = &self.ops[id.0];
        let (Some(repl), Some(arepl)) = (rop.replacement, self.ops[anchor.0].replacement) else {
            return err("transform op without replacement");
        };
        if rop.opc == Opcode::Multiequal {
            let bl = fd.op(arepl).parent.map_or_else(|| err("dead op"), Ok)?;
            fd.op_insert_begin(repl, bl);
        } else if rop.special & INSERT_BEFORE != 0 {
            fd.op_insert_before(repl, arepl)?;
        } else {
            fd.op_insert_after(repl, arepl)?;
        }
        self.ops[id.0].anchor = None;
        Ok(true)
    }

    /// Port of `TransformManager::createOps`.
    fn create_ops(&mut self, fd: &mut Funcdata) -> Result<()> {
        for i in 0..self.ops.len() {
            self.create_op(fd, TOpId(i))?;
        }
        loop {
            let mut follow = 0;
            for i in 0..self.ops.len() {
                if !self.attempt_insertion(fd, TOpId(i))? {
                    follow += 1;
                }
            }
            if follow == 0 {
                return Ok(());
            }
        }
    }

    /// Port of `TransformManager::createVarnodes`: returns the pieces of function inputs.
    fn create_varnodes(&mut self, fd: &mut Funcdata) -> Result<Vec<TVarId>> {
        let mut inputs = Vec::new();
        let mut seen = HashSet::new();
        let firsts: Vec<TVarId> = self.piece_map.values().copied().collect();
        for first in firsts {
            let mut id = first;
            loop {
                let v = &self.vars[id.0];
                if let (VarType::Piece, Some(vn)) = (v.ty, v.vn) {
                    if fd.vn(vn).is_input() {
                        inputs.push(id);
                        if !seen.insert(vn) {
                            self.vars[id.0].input_duplicate = true;
                        }
                    }
                }
                self.create_var(fd, id)?;
                if self.vars[id.0].split_terminator {
                    break;
                }
                id = id.lane(1);
            }
        }
        for id in self.new_vars.clone() {
            self.create_var(fd, id)?;
        }
        Ok(inputs)
    }

    /// Port of `TransformManager::removeOld`.
    fn remove_old(&self, fd: &mut Funcdata) {
        for rop in &self.ops {
            if rop.special & OP_REPLACEMENT != 0 && !fd.op(rop.op).is_dead() {
                fd.op_destroy(rop.op);
            }
        }
    }

    /// Port of `TransformManager::transformInputVarnodes`.
    fn transform_input_varnodes(&mut self, fd: &mut Funcdata, arch: &Arch, inputs: &[TVarId]) -> Result<()> {
        for &id in inputs {
            let v = &self.vars[id.0];
            let (Some(vn), Some(repl)) = (v.vn, v.replacement) else { return err("input piece without varnode") };
            if !v.input_duplicate {
                fd.delete_varnode(vn);
            }
            self.vars[id.0].replacement = Some(fd.set_input_varnode(repl, arch)?);
        }
        Ok(())
    }

    /// Port of `TransformManager::placeInputs` with `specialHandling`.
    fn place_inputs(&self, fd: &mut Funcdata) -> Result<()> {
        for rop in &self.ops {
            let Some(op) = rop.replacement else { return err("transform op without replacement") };
            for (slot, rvn) in rop.input.iter().enumerate() {
                let Some(vn) = rvn.and_then(|r| self.vars[r.0].replacement) else {
                    return err("transform input without replacement");
                };
                if rop.special & OP_INDIRECT != 0 {
                    fd.set_indirect_input(op, vn)?;
                } else {
                    fd.op_set_input(op, vn, slot)?;
                }
            }
            if rop.special & INDIRECT_CREATION != 0 {
                mark_indirect_creation(fd, op, false)?;
            } else if rop.special & INDIRECT_CREATION_POSSIBLE_OUT != 0 {
                mark_indirect_creation(fd, op, true)?;
            }
        }
        Ok(())
    }
}

/// Port of `Funcdata::transferVarnodeProperties`: the consume mask and the `directwrite` and
/// `addrforce` flags of `vn`'s bytes from `lsb_offset` go to the piece `newvn`.
fn transfer_varnode_properties(fd: &mut Funcdata, vn: VarnodeId, newvn: VarnodeId, lsb_offset: u32) {
    let mut consume = u64::MAX;
    if lsb_offset < 8 {
        let fill = if lsb_offset != 0 { u64::MAX << (8 * (8 - lsb_offset)) } else { 0 };
        consume = ((fd.vn(vn).consume >> (8 * lsb_offset)) | fill) & calc_mask(fd.vn(newvn).size);
    }
    for f in [VnFlags::DIRECTWRITE, VnFlags::ADDRFORCE] {
        if fd.vn(vn).has(f) {
            fd.vn_set(newvn, f);
        }
    }
    fd.vn_mut(newvn).consume = consume;
}

/// Port of `Funcdata::markIndirectCreation`.
fn mark_indirect_creation(fd: &mut Funcdata, op: OpId, possible_output: bool) -> Result<()> {
    fd.op_mut(op).flags.set(OpFlags::INDIRECT_CREATION);
    let in0 = fd.input(op, 0)?;
    if !fd.vn(in0).is_constant() {
        return err("Indirect creation not properly formed");
    }
    if !possible_output {
        fd.vn_set(in0, VnFlags::INDIRECT_CREATION);
    }
    if let Some(out) = fd.op(op).out {
        fd.vn_set(out, VnFlags::INDIRECT_CREATION);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lane_description_ranges() -> Result<()> {
        let d = LaneDescription::new(16, 4);
        assert_eq!(d.boundary(8), 2);
        assert_eq!(d.boundary(16), 4);
        assert_eq!(d.boundary(6), -1);
        // the 8 bytes at 4 of the whole: lanes 1 and 2
        assert_eq!(d.restriction(0, 4, 8)?, Some((2, 1)));
        // lanes 1.. are bytes 4.. of a 16-byte varnode starting at lane 0
        assert_eq!(d.extension(1, 4, 16)?, Some((4, 0)));
        assert_eq!(d.restriction(0, 2, 4)?, None);
        assert!(d.size(4).is_err());
        let r = LanedRegister::parse(16, "1,2,4,8")?;
        assert_eq!(r.sizes().collect::<Vec<_>>(), vec![1, 2, 4, 8]);
        // parseSizes: hex, octal, a trailing comma
        let r = LanedRegister::parse(16, "0x4, 010,")?;
        assert_eq!(r.sizes().collect::<Vec<_>>(), vec![4, 8]);
        for bad in ["", "4,,8", "16", "0", "x"] {
            assert!(LanedRegister::parse(16, bad).is_err(), "{bad}");
        }
        Ok(())
    }
}
