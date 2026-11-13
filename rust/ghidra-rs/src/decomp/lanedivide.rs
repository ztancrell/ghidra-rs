//! Port of `ActionLaneDivide` (coreaction.cc) and `LaneDivide` (subflow.cc): a laned register
//! (x86: XMM, YMM, ZMM) whose data-flow only moves whole lanes is split into one varnode per
//! lane. The trace builds [`TransformManager`] placeholders; a trace that succeeds is applied.
//!
//! Data types are not locked before stage S6, so `setReplacement`'s check for a locked
//! primitive or structure type never fires; x86 is little-endian.

use std::collections::HashSet;
use std::ops::Bound;

use super::op::OpId;
use super::opcode::Opcode;
use super::transform::{LaneDescription, LanedRegister, TOpId, TVarId, TransformManager, INSERT_AFTER, INSERT_BEFORE};
use super::varnode::VarnodeId;
use super::{Arch, Funcdata, Result};

/// One varnode left to trace (`LaneDivide::WorkNode`).
struct WorkNode {
    lanes: TVarId,
    num_lanes: i32,
    skip_lanes: i32,
}

/// Port of `LaneDivide`.
struct LaneDivide<'a> {
    fd: &'a Funcdata,
    tm: TransformManager,
    desc: LaneDescription,
    work: Vec<WorkNode>,
    allow_subpiece_terminator: bool,
    /// the varnodes seen (`Varnode::setMark`)
    marks: HashSet<VarnodeId>,
}

impl<'a> LaneDivide<'a> {
    /// Port of `LaneDivide::LaneDivide`.
    fn new(fd: &'a Funcdata, root: VarnodeId, desc: LaneDescription, allow_downcast: bool) -> LaneDivide<'a> {
        let mut ld = LaneDivide {
            fd,
            tm: TransformManager::default(),
            work: Vec::new(),
            allow_subpiece_terminator: allow_downcast,
            marks: HashSet::new(),
            desc: desc.clone(),
        };
        ld.set_replacement(root, desc.num_lanes(), 0);
        ld
    }

    /// Port of `LaneDivide::setReplacement` (never null: see the module notes).
    fn set_replacement(&mut self, vn: VarnodeId, num_lanes: i32, skip_lanes: i32) -> TVarId {
        let fd = self.fd;
        if self.marks.contains(&vn) {
            return self.tm.get_split(fd, vn, &self.desc, num_lanes, skip_lanes);
        }
        if fd.vn(vn).is_constant() {
            return self.tm.new_split(fd, vn, &self.desc, num_lanes, skip_lanes);
        }
        self.marks.insert(vn);
        let res = self.tm.new_split(fd, vn, &self.desc, num_lanes, skip_lanes);
        if !fd.vn(vn).is_free() {
            self.work.push(WorkNode { lanes: res, num_lanes, skip_lanes });
        }
        res
    }

    /// One `newOpReplace` op `out = opc in` (a COPY of a lane, mostly).
    fn unary(&mut self, opc: Opcode, op: OpId, input: TVarId, out: TVarId) {
        let rop = self.tm.new_op_replace(1, opc, op);
        self.tm.set_output(rop, out);
        self.tm.set_input(rop, input, 0);
    }

    /// Port of `LaneDivide::buildUnaryOp`.
    fn build_unary(&mut self, opc: Opcode, op: OpId, ins: TVarId, outs: TVarId, num_lanes: i32) {
        for i in 0..num_lanes {
            self.unary(opc, op, ins.lane(i), outs.lane(i));
        }
    }

    /// Port of `LaneDivide::buildBinaryOp`.
    fn build_binary(&mut self, opc: Opcode, op: OpId, in0: TVarId, in1: TVarId, outs: TVarId, num_lanes: i32) {
        for i in 0..num_lanes {
            let rop = self.tm.new_op_replace(2, opc, op);
            self.tm.set_output(rop, outs.lane(i));
            self.tm.set_input(rop, in0.lane(i), 0);
            self.tm.set_input(rop, in1.lane(i), 1);
        }
    }

    /// A COPY of the zero constant into lane `out` (`size` bytes).
    fn zero_lane(&mut self, op: OpId, out: TVarId, size: i32) {
        let rop = self.tm.new_op_replace(1, Opcode::Copy, op);
        self.tm.set_output(rop, out);
        let c = self.tm.new_constant(size as u32, 0);
        self.tm.set_input(rop, c, 0);
    }

    /// The input of a PIECE or ZEXT covering `lanes` lanes from `skip` (one lane: the varnode
    /// itself), copied into the lanes from `out_start` of `outs` (`buildPiece`, `buildZext`).
    fn copy_part(&mut self, op: OpId, vn: VarnodeId, (lanes, skip): (i32, i32), outs: TVarId, out_start: i32) {
        if lanes == 1 {
            let rvn = self.tm.get_preexisting_varnode(self.fd, vn);
            let rop = self.tm.new_op_replace(1, Opcode::Copy, op);
            self.tm.set_input(rop, rvn, 0);
            self.tm.set_output(rop, outs.lane(out_start));
        } else {
            let rvn = self.set_replacement(vn, lanes, skip);
            for i in 0..lanes {
                let rop = self.tm.new_op_replace(1, Opcode::Copy, op);
                self.tm.set_input(rop, rvn.lane(i), 0);
                self.tm.set_output(rop, outs.lane(out_start + i));
            }
        }
    }

    /// Port of `LaneDivide::buildPiece`.
    fn build_piece(&mut self, op: OpId, outs: TVarId, num_lanes: i32, skip_lanes: i32) -> Result<bool> {
        let (high, low) = (self.fd.input(op, 0)?, self.fd.input(op, 1)?);
        let (hs, ls) = (self.fd.vn(high).size as i32, self.fd.vn(low).size as i32);
        let Some(h) = self.desc.restriction(skip_lanes, ls, hs) else { return Ok(false) };
        let Some(l) = self.desc.restriction(skip_lanes, 0, ls) else { return Ok(false) };
        let high_start = if h.0 == 1 { num_lanes - 1 } else { num_lanes - h.0 };
        self.copy_part(op, high, h, outs, high_start);
        self.copy_part(op, low, l, outs, 0);
        Ok(true)
    }

    /// Port of `LaneDivide::buildMultiequal`.
    fn build_multiequal(&mut self, op: OpId, outs: TVarId, num_lanes: i32, skip_lanes: i32) {
        let ins: Vec<TVarId> =
            self.fd.op(op).ins.clone().into_iter().map(|vn| self.set_replacement(vn, num_lanes, skip_lanes)).collect();
        for i in 0..num_lanes {
            let rop = self.tm.new_op_replace(ins.len(), Opcode::Multiequal, op);
            self.tm.set_output(rop, outs.lane(i));
            for (j, &inv) in ins.iter().enumerate() {
                self.tm.set_input(rop, inv.lane(i), j);
            }
        }
    }

    /// Port of `LaneDivide::buildIndirect`.
    fn build_indirect(&mut self, op: OpId, outs: TVarId, num_lanes: i32, skip_lanes: i32) -> Result<()> {
        let inv = self.set_replacement(self.fd.input(op, 0)?, num_lanes, skip_lanes);
        for i in 0..num_lanes {
            let rop = self.tm.new_indirect_replace(self.fd, op)?;
            self.tm.set_output(rop, outs.lane(i));
            self.tm.set_input(rop, inv.lane(i), 0);
        }
        Ok(())
    }

    /// The pointer `base + byte_pos` for the lane access `rop` (`buildStore`, `buildLoad`).
    fn lane_pointer(&mut self, rop: TOpId, base: TVarId, ptr_size: u32, byte_pos: i64) -> TVarId {
        if byte_pos == 0 {
            return base;
        }
        let ptr = self.tm.new_unique(ptr_size);
        let add = self.tm.new_op(2, Opcode::IntAdd, rop, INSERT_BEFORE);
        self.tm.set_output(add, ptr);
        self.tm.set_input(add, base, 0);
        let c = self.tm.new_constant(ptr_size, byte_pos as u64);
        self.tm.set_input(add, c, 1);
        ptr
    }

    /// The space constant and the base pointer of a LOAD or STORE, unless the pointer is free
    /// and not a constant.
    fn access_base(&mut self, op: OpId) -> Result<Option<(u32, u64, TVarId, u32)>> {
        let (spc, ptr) = (self.fd.input(op, 0)?, self.fd.input(op, 1)?);
        let p = self.fd.vn(ptr);
        if p.is_free() && !p.is_constant() {
            return Ok(None);
        }
        let ptr_size = p.size;
        let base = self.tm.get_preexisting_varnode(self.fd, ptr);
        let s = self.fd.vn(spc);
        Ok(Some((s.size, s.offset, base, ptr_size)))
    }

    /// Port of `LaneDivide::buildStore`.
    fn build_store(&mut self, op: OpId, num_lanes: i32, skip_lanes: i32) -> Result<bool> {
        let ins = self.set_replacement(self.fd.input(op, 2)?, num_lanes, skip_lanes);
        let Some((spc_size, spc, base, ptr_size)) = self.access_base(op)? else { return Ok(false) };
        let mut byte_pos = 0i64;
        let mut last: Option<TOpId> = None;
        for i in 0..num_lanes {
            let store = match last {
                None => self.tm.new_preexisting_op(3, Opcode::Store, op),
                Some(l) => self.tm.new_op(3, Opcode::Store, l, INSERT_AFTER),
            };
            let ptr = self.lane_pointer(store, base, ptr_size, byte_pos);
            let c = self.tm.new_constant(spc_size, spc);
            self.tm.set_input(store, c, 0);
            self.tm.set_input(store, ptr, 1);
            self.tm.set_input(store, ins.lane(i), 2);
            byte_pos += i64::from(self.desc.size(skip_lanes + i));
            last = Some(store);
        }
        Ok(true)
    }

    /// Port of `LaneDivide::buildLoad`.
    fn build_load(&mut self, op: OpId, outs: TVarId, num_lanes: i32, skip_lanes: i32) -> Result<bool> {
        let Some((spc_size, spc, base, ptr_size)) = self.access_base(op)? else { return Ok(false) };
        let mut byte_pos = 0i64;
        for i in 0..num_lanes {
            let load = self.tm.new_op_replace(2, Opcode::Load, op);
            let ptr = self.lane_pointer(load, base, ptr_size, byte_pos);
            let c = self.tm.new_constant(spc_size, spc);
            self.tm.set_input(load, c, 0);
            self.tm.set_input(load, ptr, 1);
            self.tm.set_output(load, outs.lane(i));
            byte_pos += i64::from(self.desc.size(skip_lanes + i));
        }
        Ok(true)
    }

    /// The lane where a constant byte shift of the lanes from `skip_lanes` starts, if the
    /// shift is by whole lanes (`buildRightShift`, `buildLeftShift`).
    fn shift_lane(&self, op: OpId, skip_lanes: i32) -> Result<Option<i32>> {
        let sa = self.fd.vn(self.fd.input(op, 1)?);
        if !sa.is_constant() {
            return Ok(None);
        }
        let shift = sa.offset as i32;
        if shift & 7 != 0 {
            return Ok(None);
        }
        let start = self.desc.boundary(shift / 8 + self.desc.position(skip_lanes));
        Ok((start >= 0).then_some(start))
    }

    /// Port of `LaneDivide::buildRightShift`.
    fn build_right_shift(&mut self, op: OpId, outs: TVarId, num_lanes: i32, skip_lanes: i32) -> Result<bool> {
        let Some(start) = self.shift_lane(op, skip_lanes)? else { return Ok(false) };
        let (mut src, mut dest) = (start, skip_lanes);
        while src - skip_lanes < num_lanes {
            if self.desc.size(src) != self.desc.size(dest) {
                return Ok(false);
            }
            src += 1;
            dest += 1;
        }
        let ins = self.set_replacement(self.fd.input(op, 0)?, num_lanes, skip_lanes);
        let moved = num_lanes - (start - skip_lanes);
        self.build_unary(Opcode::Copy, op, ins.lane(start - skip_lanes), outs, moved);
        for z in moved..num_lanes {
            self.zero_lane(op, outs.lane(z), self.desc.size(z));
        }
        Ok(true)
    }

    /// Port of `LaneDivide::buildLeftShift`.
    fn build_left_shift(&mut self, op: OpId, outs: TVarId, num_lanes: i32, skip_lanes: i32) -> Result<bool> {
        let Some(start) = self.shift_lane(op, skip_lanes)? else { return Ok(false) };
        let (mut src, mut dest) = (skip_lanes, start);
        while dest - skip_lanes < num_lanes {
            if self.desc.size(src) != self.desc.size(dest) {
                return Ok(false);
            }
            src += 1;
            dest += 1;
        }
        let ins = self.set_replacement(self.fd.input(op, 0)?, num_lanes, skip_lanes);
        for z in 0..start - skip_lanes {
            self.zero_lane(op, outs.lane(z), self.desc.size(z));
        }
        self.build_unary(Opcode::Copy, op, ins, outs.lane(start - skip_lanes), num_lanes - (start - skip_lanes));
        Ok(true)
    }

    /// Port of `LaneDivide::buildZext`.
    fn build_zext(&mut self, op: OpId, outs: TVarId, num_lanes: i32, skip_lanes: i32) -> Result<bool> {
        let invn = self.fd.input(op, 0)?;
        let v = self.fd.vn(invn);
        let mut in_lanes = 0;
        if !v.is_constant() || v.offset != 0 {
            let Some(r) = self.desc.restriction(skip_lanes, 0, v.size as i32) else { return Ok(false) };
            in_lanes = r.0;
            self.copy_part(op, invn, r, outs, 0);
        }
        for i in 0..num_lanes - in_lanes {
            self.zero_lane(op, outs.lane(in_lanes + i), self.desc.size(skip_lanes + in_lanes + i));
        }
        Ok(true)
    }

    /// Port of `LaneDivide::traceForward`.
    fn trace_forward(&mut self, rvn: TVarId, num_lanes: i32, skip_lanes: i32) -> Result<bool> {
        let fd = self.fd;
        let Some(orig) = self.tm.original(rvn) else { return Ok(false) };
        for &op in fd.vn(orig).descend.iter() {
            let out = fd.op(op).out;
            if out.is_some_and(|o| self.marks.contains(&o)) {
                continue;
            }
            let opc = fd.op(op).opc;
            if opc == Opcode::Store {
                if fd.input(op, 2)? != orig || !self.build_store(op, num_lanes, skip_lanes)? {
                    return Ok(false);
                }
                continue;
            }
            let Some(outvn) = out else { return Ok(false) };
            let out_size = fd.vn(outvn).size as i32;
            match opc {
                Opcode::Subpiece => {
                    let byte_pos = fd.vn(fd.input(op, 1)?).offset as i32;
                    match self.desc.restriction(skip_lanes, byte_pos, out_size) {
                        None => {
                            if !self.allow_subpiece_terminator {
                                return Ok(false);
                            }
                            let lane = self.desc.boundary(byte_pos + self.desc.position(skip_lanes));
                            if lane < 0 || lane >= self.desc.num_lanes() || self.desc.size(lane) <= out_size {
                                return Ok(false);
                            }
                            let rop = self.tm.new_preexisting_op(2, Opcode::Subpiece, op);
                            self.tm.set_input(rop, rvn.lane(lane - skip_lanes), 0);
                            let c = self.tm.new_constant(4, 0);
                            self.tm.set_input(rop, c, 1);
                        }
                        Some((1, out_skip)) => {
                            let rop = self.tm.new_preexisting_op(1, Opcode::Copy, op);
                            self.tm.set_input(rop, rvn.lane(out_skip - skip_lanes), 0);
                        }
                        Some((out_lanes, out_skip)) => {
                            self.set_replacement(outvn, out_lanes, out_skip);
                        }
                    }
                }
                Opcode::Piece => {
                    let byte_pos = if fd.input(op, 0)? == orig { fd.vn(fd.input(op, 1)?).size as i32 } else { 0 };
                    let Some((l, s)) = self.desc.extension(skip_lanes, byte_pos, out_size) else { return Ok(false) };
                    self.set_replacement(outvn, l, s);
                }
                Opcode::Copy
                | Opcode::IntNegate
                | Opcode::IntAnd
                | Opcode::IntOr
                | Opcode::IntXor
                | Opcode::Multiequal
                | Opcode::Indirect => {
                    self.set_replacement(outvn, num_lanes, skip_lanes);
                }
                Opcode::IntRight | Opcode::IntLeft => {
                    if !fd.vn(fd.input(op, 1)?).is_constant() {
                        return Ok(false);
                    }
                    self.set_replacement(outvn, num_lanes, skip_lanes);
                }
                Opcode::IntZext => {
                    let Some((l, s)) = self.desc.extension(skip_lanes, 0, out_size) else { return Ok(false) };
                    self.set_replacement(outvn, l, s);
                }
                _ => return Ok(false),
            }
        }
        Ok(true)
    }

    /// Port of `LaneDivide::traceBackward`.
    fn trace_backward(&mut self, rvn: TVarId, num_lanes: i32, skip_lanes: i32) -> Result<bool> {
        let fd = self.fd;
        let Some(op) = self.tm.original(rvn).and_then(|v| fd.vn(v).def) else { return Ok(true) };
        let opc = fd.op(op).opc;
        match opc {
            Opcode::IntNegate | Opcode::Copy => {
                let ins = self.set_replacement(fd.input(op, 0)?, num_lanes, skip_lanes);
                self.build_unary(opc, op, ins, rvn, num_lanes);
            }
            Opcode::IntAnd | Opcode::IntOr | Opcode::IntXor => {
                let in0 = self.set_replacement(fd.input(op, 0)?, num_lanes, skip_lanes);
                let in1 = self.set_replacement(fd.input(op, 1)?, num_lanes, skip_lanes);
                self.build_binary(opc, op, in0, in1, rvn, num_lanes);
            }
            Opcode::Multiequal => self.build_multiequal(op, rvn, num_lanes, skip_lanes),
            Opcode::Indirect => self.build_indirect(op, rvn, num_lanes, skip_lanes)?,
            Opcode::Subpiece => {
                let invn = fd.input(op, 0)?;
                let byte_pos = fd.vn(fd.input(op, 1)?).offset as i32;
                let Some((l, s)) = self.desc.extension(skip_lanes, byte_pos, fd.vn(invn).size as i32) else {
                    return Ok(false);
                };
                let ins = self.set_replacement(invn, l, s);
                self.build_unary(Opcode::Copy, op, ins.lane(skip_lanes - s), rvn, num_lanes);
            }
            Opcode::Piece => return self.build_piece(op, rvn, num_lanes, skip_lanes),
            Opcode::Load => return self.build_load(op, rvn, num_lanes, skip_lanes),
            Opcode::IntRight => return self.build_right_shift(op, rvn, num_lanes, skip_lanes),
            Opcode::IntLeft => return self.build_left_shift(op, rvn, num_lanes, skip_lanes),
            Opcode::IntZext => return self.build_zext(op, rvn, num_lanes, skip_lanes),
            _ => return Ok(false),
        }
        Ok(true)
    }

    /// Port of `LaneDivide::doTrace`: the transform, if every varnode reached splits.
    fn do_trace(mut self) -> Result<Option<TransformManager>> {
        if self.work.is_empty() {
            return Ok(None);
        }
        while let Some(w) = self.work.pop() {
            if !self.trace_backward(w.lanes, w.num_lanes, w.skip_lanes)?
                || !self.trace_forward(w.lanes, w.num_lanes, w.skip_lanes)?
            {
                return Ok(None);
            }
        }
        Ok(Some(self.tm))
    }
}

/// Port of `ActionLaneDivide::addPieceLaneSize`.
fn add_piece_lane_size(size: i32, offset: i32, allowed: LanedRegister, check: &mut LanedRegister) {
    if allowed.allowed(size) {
        check.add(size);
        return;
    }
    let mut best = 0;
    for lane in allowed.sizes() {
        if lane * 2 > size {
            break;
        }
        if size % lane == 0 && offset % lane == 0 {
            best = lane;
        }
    }
    if best > 0 {
        check.add(best);
    }
}

/// Port of `ActionLaneDivide::collectLaneSizes`.
fn collect_lane_sizes(fd: &Funcdata, vn: VarnodeId, allowed: LanedRegister, check: &mut LanedRegister) -> Result<()> {
    for &op in fd.vn(vn).descend.iter() {
        let o = fd.op(op);
        if o.opc != Opcode::Subpiece {
            continue;
        }
        let Some(out) = o.out else { continue };
        let off = fd.vn(fd.input(op, 1)?).offset as i32;
        add_piece_lane_size(fd.vn(out).size as i32, off, allowed, check);
    }
    let Some(op) = fd.vn(vn).def else { return Ok(()) };
    match fd.op(op).opc {
        Opcode::Piece => {
            let lo = fd.vn(fd.input(op, 1)?).size as i32;
            add_piece_lane_size(lo, 0, allowed, check);
            add_piece_lane_size(fd.vn(fd.input(op, 0)?).size as i32, lo, allowed, check);
        }
        Opcode::IntZext => {
            let in_size = fd.vn(fd.input(op, 0)?).size as i32;
            if !allowed.allowed(in_size) {
                add_piece_lane_size(in_size, 0, allowed, check);
            }
        }
        _ => {}
    }
    Ok(())
}

/// Port of `ActionLaneDivide::processVarnode`: whether `vn` was split.
fn process_varnode(fd: &mut Funcdata, arch: &Arch, vn: VarnodeId, laned: LanedRegister, mode: i32) -> Result<bool> {
    let mut check = LanedRegister::default();
    if mode < 2 {
        collect_lane_sizes(fd, vn, laned, &mut check)?;
    } else {
        let default_size = arch.pointer_size() as i32;
        if default_size == 4 && laned.allowed(4) {
            check.add(4);
        } else if laned.allowed(8) {
            check.add(8);
        } else if laned.allowed(4) {
            check.add(4);
        }
    }
    for size in check.sizes() {
        let desc = LaneDescription::new(laned.whole_size as i32, size);
        if let Some(tm) = LaneDivide::new(fd, vn, desc, mode > 0).do_trace()? {
            tm.apply(fd, arch)?;
            return Ok(true);
        }
    }
    Ok(false)
}

/// Port of `ActionLaneDivide::apply`: the laned accesses recorded since the last run, in three
/// modes (lane sizes from the pieces; also allowing a SUBPIECE to end a lane; the default lane
/// size), until every varnode is split or no mode is left.
pub(crate) fn lane_divide(fd: &mut Funcdata, arch: &Arch) -> Result<i32> {
    let mut count = 0;
    for mode in 0..3 {
        let mut all_storage = true;
        let mut cur = None;
        loop {
            let lower = cur.map_or(Bound::Unbounded, Bound::Excluded);
            let Some((&key, &(space, laned))) = fd.lane_access.range((lower, Bound::Unbounded)).next() else { break };
            cur = Some(key);
            let (off, size) = (key.1, laned.whole_size);
            let mut vns = fd.loc_at(space, off, size);
            let (mut i, mut all_vns) = (0, true);
            while i < vns.len() {
                let vn = vns[i];
                if fd.vn(vn).descend.is_empty() {
                    i += 1;
                    continue;
                }
                if process_varnode(fd, arch, vn, laned, mode)? {
                    count += 1;
                    vns = fd.loc_at(space, off, size);
                    i = 0;
                    all_vns = true;
                } else {
                    i += 1;
                    all_vns = false;
                }
            }
            all_storage &= all_vns;
        }
        if all_storage {
            break;
        }
    }
    fd.lane_access.clear();
    Ok(count)
}
