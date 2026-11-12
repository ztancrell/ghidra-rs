//! Port of `Funcdata` (funcdata.cc, funcdata_op.cc, funcdata_varnode.cc): one function's ops,
//! varnodes, basic blocks and calls, with the creation and editing primitives the actions use.
//! Every edit of an op's inputs or output goes through these primitives, which keep the
//! varnodes' reader lists (`descend`) and the location-sorted set (`VarnodeBank::loc_tree`).

use super::block::{BlockGraph, BlockId};
use super::fspec::{CallSpec, EffectKind, FuncProto, ParamActive};
use super::heritage::Heritage;
use super::op::{OpFlags, OpId, PcodeOp, SeqNum};
use super::opcode::Opcode;
use super::varnode::{LocKey, Space, Varnode, VarnodeId, VnFlags, CONST_SPACE};
use super::{err, flow, stdsort, Arch, LowlevelError, Result};
use std::collections::{BTreeMap, BTreeSet};

/// Size of the annotation varnodes that hold an op or call reference: the C++ stores a pointer
/// (`sizeof(void *)` on the 64-bit reference build).
const POINTER_SIZE: u32 = 8;

/// `Translate::ANALYSIS`: where the decompiler's own unique varnodes start.
const UNIQUE_ANALYSIS: u64 = 0x1000_0000;

/// Index of a call in [`Funcdata::calls`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CallId(pub(crate) u32);

/// Port of the S1a part of `JumpTable`: the indirect jump and its targets in table order.
#[derive(Debug, Clone)]
pub(crate) struct JumpTable {
    pub(crate) op: OpId,
    pub(crate) targets: Vec<u64>,
}

/// One function being decompiled.
pub struct Funcdata {
    pub(crate) entry: u64,
    pub(crate) ops: Vec<PcodeOp>,
    pub(crate) vns: Vec<Varnode>,
    /// the live varnodes in location order (`VarnodeBank::loc_tree`), once heritage needs it
    loc: BTreeSet<LocKey>,
    /// whether `loc` is built and kept: nothing reads it before the first heritage pass, so it
    /// is built there in one go ([`Funcdata::build_loc`])
    loc_on: bool,
    /// the input varnodes by address and size (the inputs of `VarnodeBank::def_tree`)
    inputs: BTreeSet<(u32, u64, u32, VarnodeId)>,
    /// the live ops by sequence number (`PcodeOpBank::optree`)
    seqs: BTreeMap<(u64, u32), OpId>,
    /// the ops in creation order, before they go into blocks (`PcodeOpBank::deadlist`)
    pub(crate) dead: Vec<OpId>,
    /// the next `SeqNum::time` (`PcodeOpBank::uniqid`)
    next_time: u32,
    pub(crate) blocks: BlockGraph,
    /// every call made so far; [`Funcdata::qlst`] lists the live ones
    pub(crate) calls: Vec<CallSpec>,
    /// the live calls, sorted by `sortCallSpecs` once blocks exist (`Funcdata::qlst`)
    pub(crate) qlst: Vec<CallId>,
    pub(crate) jumptables: Vec<JumpTable>,
    /// the function's own prototype (`Funcdata::funcp`)
    pub(crate) proto: FuncProto,
    /// the return-value trials (`Funcdata::activeoutput`), from `ActionPrototypeTypes` on
    pub(crate) active_output: Option<ParamActive>,
    /// the SSA builder's state across passes (`Funcdata::heritage`)
    pub(crate) heritage: Heritage,
    /// the next free offset of the unique space (`VarnodeBank::uniqid`)
    next_unique: u64,
    /// header warnings (`Funcdata::warningHeader`), for `print C`
    pub(crate) warnings: Vec<String>,
    /// the space the global scope owns (ram): its varnodes are `persist` and `addrtied`
    /// (`setVarnodeProperties` through `Scope::queryProperties`)
    pub(crate) ram: Option<u32>,
    /// the unique space (`IPTR_INTERNAL`)
    pub(crate) uniq: Option<u32>,
    /// the join records (pieces, most significant first) of `Space::Join` varnodes
    pub(crate) joins: Vec<Vec<(u32, u64, u32)>>,
    /// the `<incidentalcopy>` ranges (`Arch::incidental`)
    incidental: Vec<(u32, u64, u32)>,
    /// `ActionStackPtrFlow::analysis_finished` (the action is made per function)
    pub(crate) stackptrflow_done: bool,
}

impl Funcdata {
    /// A function starting at `entry`, before any analysis.
    pub fn new(entry: u64) -> Funcdata {
        Funcdata {
            entry,
            ops: Vec::new(),
            vns: Vec::new(),
            loc: BTreeSet::new(),
            loc_on: false,
            inputs: BTreeSet::new(),
            seqs: BTreeMap::new(),
            dead: Vec::new(),
            next_time: 0,
            blocks: BlockGraph::default(),
            calls: Vec::new(),
            qlst: Vec::new(),
            jumptables: Vec::new(),
            proto: FuncProto::default(),
            active_output: None,
            heritage: Heritage::default(),
            next_unique: UNIQUE_ANALYSIS,
            warnings: Vec::new(),
            ram: None,
            uniq: None,
            incidental: Vec::new(),
            joins: Vec::new(),
            stackptrflow_done: false,
        }
    }

    pub(crate) fn op(&self, id: OpId) -> &PcodeOp {
        &self.ops[id.0 as usize]
    }
    pub(crate) fn op_mut(&mut self, id: OpId) -> &mut PcodeOp {
        &mut self.ops[id.0 as usize]
    }
    pub(crate) fn vn(&self, id: VarnodeId) -> &Varnode {
        &self.vns[id.0 as usize]
    }
    pub(crate) fn vn_mut(&mut self, id: VarnodeId) -> &mut Varnode {
        &mut self.vns[id.0 as usize]
    }
    pub(crate) fn call(&self, id: CallId) -> &CallSpec {
        &self.calls[id.0 as usize]
    }
    pub(crate) fn call_mut(&mut self, id: CallId) -> &mut CallSpec {
        &mut self.calls[id.0 as usize]
    }

    /// Set varnode flags (`Varnode::setFlags`).
    pub(crate) fn vn_set(&mut self, id: VarnodeId, f: VnFlags) {
        self.vn_mut(id).flags.set(f);
    }
    /// Clear varnode flags (`Varnode::clearFlags`).
    pub(crate) fn vn_clear(&mut self, id: VarnodeId, f: VnFlags) {
        self.vn_mut(id).flags.clear(f);
    }

    /// Puts `id` into the location set, once it is kept.
    fn loc_add(&mut self, id: VarnodeId) {
        if self.loc_on {
            self.loc.insert(self.loc_key(id));
        }
    }

    /// Takes `id` out of the location set (before its key changes).
    fn loc_del(&mut self, id: VarnodeId) {
        if self.loc_on {
            self.loc.remove(&self.loc_key(id));
        }
    }

    /// Builds the location set from the live varnodes and keeps it from then on. The set holds
    /// the same keys as one kept from the start, since a key depends only on the varnode.
    pub(crate) fn build_loc(&mut self) {
        if self.loc_on {
            return;
        }
        self.loc = (0..self.vns.len() as u32)
            .map(VarnodeId)
            .filter(|&v| !self.vn(v).is_dead())
            .map(|v| self.loc_key(v))
            .collect();
        self.loc_on = true;
    }

    /// The varnode's key in the location set.
    fn loc_key(&self, id: VarnodeId) -> LocKey {
        let v = self.vn(id);
        LocKey::of(v, id, v.def.map(|d| self.op(d).seq))
    }

    /// The live varnodes from address `(space, start)` up to `(space, end)` (exclusive), or to
    /// the end of the space, in location order (`beginLoc`/`endLoc`).
    pub(crate) fn loc_range(&self, space: Space, start: u64, end: Option<u64>) -> Vec<VarnodeId> {
        let s = space.index();
        let from = LocKey::start(s, start);
        let to = match end {
            Some(e) => LocKey::start(s, e),
            None => LocKey::start(s + 1, 0),
        };
        if to <= from {
            return Vec::new();
        }
        self.loc.range(from..to).map(|k| k.id).collect()
    }

    /// Port of `Funcdata::newOp`: a new op at `addr` with the next creation time, appended to
    /// the dead list.
    pub(crate) fn new_op(&mut self, opc: Opcode, addr: u64) -> OpId {
        let id = OpId(self.ops.len() as u32);
        let seq = SeqNum { addr, time: self.next_time };
        self.next_time += 1;
        self.ops.push(PcodeOp {
            opc,
            seq,
            out: None,
            ins: Vec::new(),
            parent: None,
            order: 0,
            flags: OpFlags::default(),
            halt: None,
        });
        self.seqs.insert((addr, seq.time), id);
        self.dead.push(id);
        id
    }

    /// Port of `Funcdata::newVarnode` (also `newConstant`, `newCodeRef`): a free varnode.
    pub(crate) fn new_varnode(&mut self, size: u32, space: Space, offset: u64) -> VarnodeId {
        let id = VarnodeId(self.vns.len() as u32);
        let v = self.scoped(Varnode::new(space, offset, size));
        self.vns.push(v);
        self.loc_add(id);
        id
    }

    /// The scope's properties of a new varnode (`Scope::queryProperties`): the global scope
    /// owns ram, so its varnodes are `persist` and `addrtied`; the local scope (the stack) holds
    /// no symbols the console could give.
    fn scoped(&self, mut v: Varnode) -> Varnode {
        if self.ram.is_some_and(|r| v.space == Space::Sleigh(r)) {
            v.flags.set(VnFlags::PERSIST);
            v.flags.set(VnFlags::ADDRTIED);
        }
        if let Space::Sleigh(s) = v.space {
            if self.incidental.iter().any(|&(is, io, iz)| is == s && io <= v.offset && v.offset < io + u64::from(iz)) {
                v.flags.set(VnFlags::INCIDENTAL_COPY);
            }
        }
        v
    }

    pub(crate) fn new_constant(&mut self, size: u32, value: u64) -> VarnodeId {
        self.new_varnode(size, CONST_SPACE, value)
    }

    /// Port of `Funcdata::newVarnodeOut`: a varnode written by `op`.
    pub(crate) fn new_varnode_out(&mut self, size: u32, space: Space, offset: u64, op: OpId) -> VarnodeId {
        let id = VarnodeId(self.vns.len() as u32);
        let mut v = self.scoped(Varnode::new(space, offset, size));
        v.def = Some(op);
        self.vns.push(v);
        self.loc_add(id);
        self.op_mut(op).out = Some(id);
        id
    }

    /// Port of `Funcdata::newVarnodeIop`: an annotation naming `op`.
    pub(crate) fn new_varnode_iop(&mut self, op: OpId) -> VarnodeId {
        self.new_varnode(POINTER_SIZE, Space::Iop, u64::from(op.0))
    }

    /// Port of `Funcdata::newVarnodeCallSpecs`: an annotation naming a call.
    pub(crate) fn new_varnode_callspecs(&mut self, call: CallId) -> VarnodeId {
        self.new_varnode(POINTER_SIZE, Space::Fspec, u64::from(call.0))
    }

    /// The next free offset of the unique space for `size` bytes (`VarnodeBank::createUnique`).
    fn next_unique_offset(&mut self, size: u32) -> u64 {
        let offset = self.next_unique;
        self.next_unique += u64::from(size);
        offset
    }

    /// Port of `Funcdata::newUniqueOut`: a new unique-space varnode of `size` bytes written by
    /// `op`. `uniq` is the unique space.
    pub(crate) fn new_unique_out(&mut self, size: u32, uniq: u32, op: OpId) -> VarnodeId {
        let offset = self.next_unique_offset(size);
        self.new_varnode_out(size, Space::Sleigh(uniq), offset, op)
    }

    /// Port of `Funcdata::newUnique`: a new free unique-space varnode.
    pub(crate) fn new_unique(&mut self, size: u32, uniq: u32) -> VarnodeId {
        let offset = self.next_unique_offset(size);
        self.new_varnode(size, Space::Sleigh(uniq), offset)
    }

    /// Port of `Funcdata::newVarnodeSpace`: the constant naming a space (LOAD/STORE input 0).
    pub(crate) fn new_varnode_space(&mut self, space: u32) -> VarnodeId {
        self.new_constant(POINTER_SIZE, u64::from(space))
    }

    /// Port of `PcodeEmitFd::dump`: new ops at `addr` for the p-code `ops` (an instruction's
    /// translation or an injected snippet), appended to the dead list.
    pub(crate) fn emit_pcode(&mut self, addr: u64, ops: &[crate::sleigh::PcodeOp]) -> Result<()> {
        for p in ops {
            let opc = Opcode::from_u8(p.opc).ok_or_else(|| LowlevelError(format!("bad opcode {}", p.opc)))?;
            let op = self.new_op(opc, addr);
            if let Some(o) = p.out {
                self.new_varnode_out(o.size, Space::Sleigh(o.space), o.offset, op);
            }
            let mut ins: Vec<_> =
                p.ins.iter().map(|v| self.new_varnode(v.size, Space::Sleigh(v.space), v.offset)).collect();
            // PcodeOp::isCodeRef: input 0 is a code reference (`newCodeRef`: one byte, annotation)
            if matches!(opc, Opcode::Branch | Opcode::Cbranch | Opcode::Call) {
                if let Some(&target) = ins.first() {
                    if !self.vn(target).is_constant() {
                        self.vn_mut(target).size = 1;
                        self.vn_set(target, VnFlags::CODEREF);
                        self.vn_clear(target, VnFlags::PERSIST);
                        self.vn_clear(target, VnFlags::ADDRTIED);
                        ins[0] = target;
                    }
                }
            }
            self.op_set_all_input(op, &ins)?;
        }
        Ok(())
    }

    /// Port of `Varnode::addDescend`: a free varnode has at most one reader.
    fn add_descend(&mut self, vn: VarnodeId, op: OpId) -> Result<()> {
        let v = self.vn(vn);
        if v.is_free() && !v.is_constant() && !v.descend.is_empty() {
            return err("Free varnode has multiple descendants");
        }
        self.vn_mut(vn).descend.push(op);
        Ok(())
    }

    /// Port of `Varnode::eraseDescend`: drop the first occurrence of `op`.
    fn erase_descend(&mut self, vn: VarnodeId, op: OpId) {
        let d = &mut self.vn_mut(vn).descend;
        if let Some(p) = d.iter().position(|&o| o == op) {
            d.remove(p);
        }
    }

    /// `opSetInput`'s constant rule: a constant that already has a reader is copied.
    fn unshared_constant(&mut self, vn: VarnodeId) -> VarnodeId {
        let v = self.vn(vn);
        if v.is_constant() && !v.descend.is_empty() {
            let (size, offset) = (v.size, v.offset);
            return self.new_constant(size, offset);
        }
        vn
    }

    /// Port of `Funcdata::opSetInput`: `vn` becomes input `slot` of `op`; `slot` may be one past
    /// the last input, which appends it (the C++ op has its slots allocated by `newOp`).
    pub(crate) fn op_set_input(&mut self, op: OpId, vn: VarnodeId, slot: usize) -> Result<()> {
        let old = self.op(op).ins.get(slot).copied();
        if old == Some(vn) {
            return Ok(());
        }
        let vn = self.unshared_constant(vn);
        if let Some(o) = old {
            self.erase_descend(o, op);
        }
        self.add_descend(vn, op)?;
        let ins = &mut self.op_mut(op).ins;
        if slot < ins.len() {
            ins[slot] = vn;
        } else if slot == ins.len() {
            ins.push(vn);
        } else {
            return err(format!("opSetInput: slot {slot} past the inputs"));
        }
        Ok(())
    }

    /// Port of `Funcdata::opSetAllInput`.
    pub(crate) fn op_set_all_input(&mut self, op: OpId, vns: &[VarnodeId]) -> Result<()> {
        for vn in std::mem::take(&mut self.op_mut(op).ins) {
            self.erase_descend(vn, op);
        }
        for (slot, &vn) in vns.iter().enumerate() {
            self.op_set_input(op, vn, slot)?;
        }
        Ok(())
    }

    /// Port of `Funcdata::opInsertInput`: a new input at `slot`.
    pub(crate) fn op_insert_input(&mut self, op: OpId, vn: VarnodeId, slot: usize) -> Result<()> {
        let vn = self.unshared_constant(vn);
        self.add_descend(vn, op)?;
        self.op_mut(op).ins.insert(slot, vn);
        Ok(())
    }

    /// Port of `Funcdata::opRemoveInput`.
    pub(crate) fn op_remove_input(&mut self, op: OpId, slot: usize) {
        let vn = self.op_mut(op).ins.remove(slot);
        self.erase_descend(vn, op);
    }

    /// Port of `VarnodeBank::setDef`: a free varnode becomes written by `op`.
    fn set_def(&mut self, vn: VarnodeId, op: OpId) -> Result<()> {
        // Varnode::setDef
        if self.vn(vn).is_constant() {
            return err(format!("Assignment to constant at r0x{:08x}", self.op(op).seq.addr));
        }
        if !self.vn(vn).is_free() {
            return err(format!("Defining varnode which is not free at 0x{:08x}", self.op(op).seq.addr));
        }
        self.loc_del(vn);
        self.vn_mut(vn).def = Some(op);
        self.loc_add(vn);
        Ok(())
    }

    /// Port of `Funcdata::opSetOutput`.
    pub(crate) fn op_set_output(&mut self, op: OpId, vn: VarnodeId) -> Result<()> {
        if self.op(op).out == Some(vn) {
            return Ok(());
        }
        if self.op(op).out.is_some() {
            self.op_unset_output(op);
        }
        if let Some(def) = self.vn(vn).def {
            self.op_unset_output(def);
        }
        self.set_def(vn, op)?;
        self.op_mut(op).out = Some(vn);
        Ok(())
    }

    /// Port of `Funcdata::opUnsetOutput` (`VarnodeBank::makeFree`).
    pub(crate) fn op_unset_output(&mut self, op: OpId) {
        let Some(vn) = self.op_mut(op).out.take() else { return };
        self.loc_del(vn);
        let v = self.vn_mut(vn);
        v.def = None;
        v.flags.clear(VnFlags::INDIRECT_CREATION);
        self.loc_add(vn);
    }

    /// Port of `Funcdata::deleteVarnode` (`VarnodeBank::destroy`).
    pub(crate) fn delete_varnode(&mut self, vn: VarnodeId) {
        self.loc_del(vn);
        let v = self.vn(vn);
        if v.is_input() {
            self.inputs.remove(&(v.space.index(), v.offset, v.size, vn));
        }
        self.vn_set(vn, VnFlags::DEAD);
    }

    /// Port of `Funcdata::setInputVarnode`: `vn` becomes an input of the function, or the input
    /// already there is returned. Inputs the prototype leaves unaffected are marked so.
    pub(crate) fn set_input_varnode(&mut self, vn: VarnodeId, arch: &Arch) -> Result<VarnodeId> {
        let v = self.vn(vn);
        if v.is_input() {
            return Ok(vn);
        }
        let (s, off, size) = (v.space.index(), v.offset, v.size);
        // the last input before the end of vn (VarnodeBank::beginDef(input, addr + size), back one)
        if let Some(&(ps, poff, psize, prev)) =
            self.inputs.range(..(s, off + u64::from(size), 0, VarnodeId(0))).next_back()
        {
            let overlaps =
                ps == s && (off.wrapping_sub(poff) < u64::from(psize) || poff.wrapping_sub(off) < u64::from(size));
            if overlaps {
                if psize == size && poff == off {
                    return Ok(prev);
                }
                return err("Overlapping input varnodes");
            }
        }
        if !self.vn(vn).is_free() || self.vn(vn).is_constant() {
            return err("Making input out of varnode which is not free");
        }
        self.loc_del(vn);
        self.vn_set(vn, VnFlags::INPUT);
        self.loc_add(vn);
        self.inputs.insert((s, off, size, vn));
        let v = self.vn(vn);
        match self.proto.has_effect(arch, v.space, v.offset, v.size) {
            Some(EffectKind::Unaffected) => self.vn_set(vn, VnFlags::UNAFFECTED),
            Some(EffectKind::ReturnAddress) => {
                self.vn_set(vn, VnFlags::UNAFFECTED);
                self.vn_set(vn, VnFlags::RETURN_ADDRESS);
            }
            _ => {}
        }
        Ok(vn)
    }

    /// Port of `Funcdata::totalReplace`: every reader of `vn` reads `newvn` instead.
    pub(crate) fn total_replace(&mut self, vn: VarnodeId, newvn: VarnodeId) -> Result<()> {
        let readers = self.vn(vn).descend.to_vec();
        for op in readers {
            let slot = self
                .op(op)
                .ins
                .iter()
                .position(|&v| v == vn)
                .ok_or_else(|| LowlevelError("totalReplace: reader without the varnode".into()))?;
            self.op_set_input(op, newvn, slot)?;
        }
        Ok(())
    }

    /// Port of `Funcdata::newIndirect`: an INDIRECT at `indeffect`'s address naming it (its
    /// output and first input are the caller's).
    fn new_indirect(&mut self, indeffect: OpId) -> Result<OpId> {
        let op = self.new_op(Opcode::Indirect, self.op(indeffect).seq.addr);
        let iop = self.new_varnode_iop(indeffect);
        // input 1 first, as the C++ sets it before input 0
        self.op_mut(op).ins.push(iop);
        self.add_descend(iop, op)?;
        Ok(op)
    }

    /// Sets input 0 of an INDIRECT made by [`Funcdata::new_indirect`].
    fn set_indirect_input(&mut self, op: OpId, vn: VarnodeId) -> Result<()> {
        let vn = self.unshared_constant(vn);
        self.add_descend(vn, op)?;
        self.op_mut(op).ins.insert(0, vn);
        Ok(())
    }

    /// Port of `Funcdata::newIndirectOp`: `vn = vn [] indeffect`, before `indeffect`.
    pub(crate) fn new_indirect_op(
        &mut self,
        indeffect: OpId,
        space: Space,
        off: u64,
        size: u32,
        extra: OpFlags,
    ) -> Result<OpId> {
        let newin = self.new_varnode(size, space, off);
        let op = self.new_indirect(indeffect)?;
        self.op_mut(op).flags.set(extra);
        self.new_varnode_out(size, space, off, op);
        self.set_indirect_input(op, newin)?;
        self.op_insert_before(op, indeffect)?;
        Ok(op)
    }

    /// Port of `Funcdata::newIndirectCreation`: `vn = [create] indeffect`, before `indeffect`.
    pub(crate) fn new_indirect_creation(
        &mut self,
        indeffect: OpId,
        space: Space,
        off: u64,
        size: u32,
        possibleout: bool,
    ) -> Result<OpId> {
        let newin = self.new_constant(size, 0);
        let op = self.new_indirect(indeffect)?;
        self.op_mut(op).flags.set(OpFlags::INDIRECT_CREATION);
        let newout = self.new_varnode_out(size, space, off, op);
        if !possibleout {
            self.vn_set(newin, VnFlags::INDIRECT_CREATION);
        }
        self.vn_set(newout, VnFlags::INDIRECT_CREATION);
        self.set_indirect_input(op, newin)?;
        self.op_insert_before(op, indeffect)?;
        Ok(op)
    }

    /// Port of `Funcdata::opStackLoad`: a LOAD of `size` bytes at stack offset `off`, computed
    /// from the stack pointer `sp` (space, offset, size) just before `op`; `ram` is the space the
    /// stack lives in. Returns the loaded value.
    pub(crate) fn op_stack_load(
        &mut self,
        sp: (u32, u64, u32),
        ram: u32,
        uniq: u32,
        off: u64,
        size: u32,
        op: OpId,
    ) -> Result<VarnodeId> {
        let addout = self.create_stack_ref(sp, uniq, off, op)?;
        let addop = self.vn(addout).def.ok_or_else(|| LowlevelError("stack reference without its op".into()))?;
        let addr = self.op(op).seq.addr;
        let loadop = self.new_op(Opcode::Load, addr);
        let spc = self.new_varnode_space(ram);
        self.op_set_all_input(loadop, &[spc, addout])?;
        let res = self.new_unique_out(size, uniq, loadop);
        // the LOAD comes after the stack-building op
        self.op_insert_after(loadop, addop)?;
        Ok(res)
    }

    /// Port of `Funcdata::createStackRef` (no reused stack pointer, inserted before `op`):
    /// `u = SP + off`. x86 declares no segment op, so there is no `SEGMENTOP` around it.
    fn create_stack_ref(&mut self, sp: (u32, u64, u32), uniq: u32, off: u64, op: OpId) -> Result<VarnodeId> {
        let (space, spoff, size) = sp;
        let stackptr = self.new_varnode(size, Space::Sleigh(space), spoff);
        let addop = self.new_op(Opcode::IntAdd, self.op(op).seq.addr);
        let addout = self.new_unique_out(size, uniq, addop);
        let c = self.new_constant(size, off);
        self.op_set_all_input(addop, &[stackptr, c])?;
        self.op_insert_before(addop, op)?;
        Ok(addout)
    }

    /// Port of `Funcdata::opInsertAfter`: put `op` just after `prev` (after the store or call an
    /// INDIRECT `prev` stands for), past any MULTIEQUAL there.
    pub(crate) fn op_insert_after(&mut self, op: OpId, mut prev: OpId) -> Result<()> {
        if self.op(prev).opc == Opcode::Indirect {
            if let Some(&iop) = self.op(prev).ins.get(1) {
                let v = self.vn(iop);
                // the op the INDIRECT names, while it is alive (in a block)
                let target = OpId(v.offset as u32);
                if v.space == Space::Iop && self.op(target).parent.is_some() {
                    prev = target;
                }
            }
        }
        let Some(bl) = self.op(prev).parent else { return err("opInsertAfter: op outside any block") };
        let ops = &self.blocks.block(bl).ops;
        let Some(pos) = ops.iter().position(|&o| o == prev) else {
            return err("opInsertAfter: op missing from its block");
        };
        let mut at = pos + 1;
        if self.op(op).opc != Opcode::Multiequal {
            while ops.get(at).is_some_and(|&o| self.op(o).opc == Opcode::Multiequal) {
                at += 1;
            }
        }
        self.op_insert(op, bl, at);
        Ok(())
    }

    pub(crate) fn find_op(&self, seq: SeqNum) -> Option<OpId> {
        self.seqs.get(&(seq.addr, seq.time)).copied()
    }

    /// Port of `PcodeOpBank::findLastOp`: the live op at `addr` created last.
    pub(crate) fn find_last_op(&self, addr: u64) -> Option<OpId> {
        self.seqs.range((addr, 0)..=(addr, u32::MAX)).next_back().map(|(_, &id)| id)
    }

    /// Port of `Funcdata::opDestroyRaw` for ops still in the dead list (the caller removes it
    /// from the list): the op and its varnodes are gone.
    pub(crate) fn op_destroy_raw(&mut self, op: OpId) {
        let seq = self.op(op).seq;
        self.seqs.remove(&(seq.addr, seq.time));
        let o = self.op_mut(op);
        let vns: Vec<VarnodeId> = std::mem::take(&mut o.ins).into_iter().chain(o.out.take()).collect();
        for vn in vns {
            self.vn_mut(vn).descend.clear();
            self.delete_varnode(vn);
        }
    }

    /// Whether `op` still exists (not destroyed by [`Funcdata::op_destroy_raw`]).
    fn op_exists(&self, op: OpId) -> bool {
        let seq = self.op(op).seq;
        self.seqs.get(&(seq.addr, seq.time)) == Some(&op)
    }

    /// Port of `Funcdata::opDeadInsertAfter`: move `op` to just after `prev` in the dead list.
    pub(crate) fn op_dead_insert_after(&mut self, op: OpId, prev: OpId) {
        self.dead.retain(|&o| o != op);
        let at = self.dead.iter().position(|&o| o == prev).map_or(self.dead.len(), |p| p + 1);
        self.dead.insert(at, op);
    }

    /// Port of `Funcdata::opInsertBefore`: put `op` into the block of `follow`, before it and
    /// before any INDIRECTs right in front of it (unless `op` is an INDIRECT itself).
    pub(crate) fn op_insert_before(&mut self, op: OpId, follow: OpId) -> Result<()> {
        let Some(bl) = self.op(follow).parent else { return err("opInsertBefore: op outside any block") };
        let ops = &self.blocks.block(bl).ops;
        let Some(mut at) = ops.iter().position(|&o| o == follow) else {
            return err("opInsertBefore: op missing from its block");
        };
        if self.op(op).opc != Opcode::Indirect {
            while at > 0 && self.op(ops[at - 1]).opc == Opcode::Indirect {
                at -= 1;
            }
        }
        self.op_insert(op, bl, at);
        Ok(())
    }

    /// Input `slot` of `op`, or an error when the p-code gave it fewer inputs.
    pub(crate) fn input(&self, op: OpId, slot: usize) -> Result<VarnodeId> {
        let o = self.op(op);
        o.ins.get(slot).copied().ok_or_else(|| {
            LowlevelError(format!("{:?} at 0x{:08x}:{:x} has no input {slot}", o.opc, o.seq.addr, o.seq.time))
        })
    }

    /// Port of `Funcdata::opInsertBegin`: put `op` at the start of `bl`, after any MULTIEQUAL
    /// (unless `op` is one itself).
    pub(crate) fn op_insert_begin(&mut self, op: OpId, bl: BlockId) {
        let at = if self.op(op).opc == Opcode::Multiequal {
            0
        } else {
            self.blocks.block(bl).ops.iter().take_while(|&&o| self.op(o).opc == Opcode::Multiequal).count()
        };
        self.op_insert(op, bl, at);
    }

    /// Port of `BlockBasic::insert`: put `op` at position `at` of `bl` and give it an order key
    /// between its neighbours' (`SeqNum::order`, 32 bits as `uintm`). The key is not always the
    /// position: halving the gap can repeat the previous key, and `sortCallSpecs` sorts by it.
    pub(crate) fn op_insert(&mut self, op: OpId, bl: BlockId, at: usize) {
        // PcodeOpBank::markAlive: the op leaves the dead list (an op an action made is its last)
        if let Some(p) = self.dead.iter().rposition(|&o| o == op) {
            self.dead.remove(p);
        }
        self.blocks.block_mut(bl).ops.insert(at, op);
        self.op_mut(op).parent = Some(bl);
        let ops = &self.blocks.block(bl).ops;
        let before = if at == 0 { 2 } else { self.op(ops[at - 1]).order };
        let after = match ops.get(at + 1) {
            Some(&next) => self.op(next).order,
            None => before.saturating_add(0x100_0000),
        };
        if after.wrapping_sub(before) <= 1 {
            self.set_order(bl);
        } else {
            self.op_mut(op).order = after / 2 + before / 2;
        }
    }

    /// The live ops with opcode `opc` (`Funcdata::beginOp(opc)`), in block order.
    pub(crate) fn ops_with(&self, opc: Opcode) -> Vec<OpId> {
        self.blocks.ops().filter(|&o| self.op(o).opc == opc).collect()
    }

    /// The ops with opcode `opc` in the order the C++ keeps its per-opcode lists (`returnlist`,
    /// `storelist`: creation order), dead ones included.
    pub(crate) fn ops_created_with(&self, opc: Opcode) -> Vec<OpId> {
        (0..self.ops.len() as u32).map(OpId).filter(|&o| self.op(o).opc == opc && self.op_exists(o)).collect()
    }

    /// Port of `Funcdata::startProcessing`: follow flow, build blocks, order them and the calls.
    pub(crate) fn start_processing(&mut self, arch: &Arch) -> Result<()> {
        self.ram = Some(arch.spec.stack_container);
        self.uniq = Some(arch.sleigh.uniq_space());
        self.incidental = arch.incidental.clone();
        flow::follow_flow(self, arch)?;
        self.blocks.structure_loops()?;
        self.sort_call_specs();
        Ok(())
    }

    /// Port of `Funcdata::sortCallSpecs` (`compareCallspecs`): by block index, then by the op's
    /// order key. The keys tie in long blocks, so this is libstdc++'s unstable sort.
    fn sort_call_specs(&mut self) {
        let mut q = std::mem::take(&mut self.qlst);
        let key = |c: &CallId| {
            let op = self.op(self.call(*c).op);
            (op.parent.map(|b| self.blocks.block(b).index), op.order)
        };
        stdsort::sort(&mut q, |a, b| key(a) < key(b));
        self.qlst = q;
    }

    /// Port of `BlockBasic::setOrder`: renumber the block's order keys evenly.
    pub(crate) fn set_order(&mut self, bl: BlockId) {
        let ops = &self.blocks.block(bl).ops;
        let step = u32::MAX / ops.len() as u32 - 1;
        for (i, o) in self.blocks.block(bl).ops.iter().enumerate() {
            self.ops[o.0 as usize].order = step.wrapping_mul(i as u32 + 1);
        }
    }

    /// Port of `Funcdata::opSetOpcode` (the per-opcode lists follow the op's creation order
    /// here, see [`Funcdata::ops_created_with`]).
    pub(crate) fn op_set_opcode(&mut self, op: OpId, opc: Opcode) {
        self.op_mut(op).opc = opc;
    }

    /// Port of `Funcdata::opUninsert`: take `op` out of its block; it becomes dead.
    pub(crate) fn op_uninsert(&mut self, op: OpId) {
        if let Some(bl) = self.op_mut(op).parent.take() {
            self.blocks.block_mut(bl).ops.retain(|&o| o != op);
            self.dead.push(op);
        }
    }

    /// Port of `Funcdata::opUnsetInput` for every input.
    fn op_clear_inputs(&mut self, op: OpId) {
        for vn in std::mem::take(&mut self.op_mut(op).ins) {
            self.erase_descend(vn, op);
        }
    }

    /// Port of `Funcdata::opDestroy`: the output varnode is destroyed (its readers keep a stale
    /// reference, the C++ null input, and are expected to go too), the inputs unlinked, and the
    /// op made dead; [`Funcdata::clear_dead_ops`] frees it.
    pub(crate) fn op_destroy(&mut self, op: OpId) {
        if let Some(out) = self.op_mut(op).out.take() {
            self.loc_del(out);
            let v = self.vn_mut(out);
            v.def = None;
            v.descend.clear();
            self.delete_varnode(out);
        }
        self.op_clear_inputs(op);
        self.op_uninsert(op);
    }

    /// Port of `Funcdata::clearDeadOps`: the dead ops made by edits are freed.
    pub(crate) fn clear_dead_ops(&mut self) {
        for op in std::mem::take(&mut self.dead) {
            if self.op(op).parent.is_none() && self.op_exists(op) {
                self.op_clear_inputs(op);
                if let Some(out) = self.op_mut(op).out.take() {
                    self.loc_del(out);
                    self.vn_mut(out).def = None;
                    self.delete_varnode(out);
                }
                let seq = self.op(op).seq;
                self.seqs.remove(&(seq.addr, seq.time));
            }
        }
    }

    /// Port of `Funcdata::clearDeadVarnodes`: a varnode nothing reads goes, an input becoming
    /// free first.
    pub(crate) fn clear_dead_varnodes(&mut self) {
        let all: Vec<VarnodeId> = self.loc.iter().map(|k| k.id).collect();
        for vn in all {
            if !self.vn(vn).descend.is_empty() {
                continue;
            }
            if self.vn(vn).is_input() {
                let v = self.vn(vn);
                let key = (v.space.index(), v.offset, v.size, vn);
                self.loc_del(vn);
                self.inputs.remove(&key);
                self.vn_clear(vn, VnFlags::INPUT);
                self.loc_add(vn);
            }
            if self.vn(vn).is_free() {
                self.delete_varnode(vn);
            }
        }
    }

    /// The live varnodes of one space in location order (`beginLoc(spc)`).
    pub(crate) fn loc_space(&self, space: Space) -> Vec<VarnodeId> {
        self.loc_range(space, 0, None)
    }

    /// Every live varnode in location order (`beginLoc()`).
    pub(crate) fn loc_all(&self) -> Vec<VarnodeId> {
        self.loc.iter().map(|k| k.id).collect()
    }

    /// The varnodes at exactly `(space, off)` of `size` bytes, inputs first, then by the
    /// writing op's sequence number, free ones last (`beginLoc(size, addr)`).
    pub(crate) fn loc_at(&self, space: Space, off: u64, size: u32) -> Vec<VarnodeId> {
        let s = space.index();
        self.loc
            .range(LocKey::start(s, off)..LocKey::start(s, off.wrapping_add(1)))
            .filter(|k| k.size == size)
            .map(|k| k.id)
            .collect()
    }

    /// Port of `Funcdata::findCoveredInput`: the input containing the range.
    pub(crate) fn find_covered_input(&self, space: Space, off: u64, size: u32) -> Option<VarnodeId> {
        let s = space.index();
        let &(ps, poff, psize, id) = self.inputs.range(..=(s, off, u32::MAX, VarnodeId(u32::MAX))).next_back()?;
        (ps == s && poff <= off && off + u64::from(size) <= poff + u64::from(psize)).then_some(id)
    }

    /// The slot of `vn` among `op`'s inputs (`PcodeOp::getSlot`).
    pub(crate) fn slot_of(&self, op: OpId, vn: VarnodeId) -> Option<usize> {
        self.op(op).ins.iter().position(|&v| v == vn)
    }

    /// The op an iop annotation names (`PcodeOp::getOpFromConst`).
    pub(crate) fn iop_target(&self, vn: VarnodeId) -> Option<OpId> {
        let v = self.vn(vn);
        (v.space == Space::Iop).then_some(OpId(v.offset as u32))
    }

    /// The call whose op is `op` (`Funcdata::getCallSpecs(op)`).
    pub(crate) fn call_of(&self, op: OpId) -> Option<CallId> {
        self.qlst.iter().copied().find(|&c| self.call(c).op == op)
    }

    /// The op before `op` in its block (`PcodeOp::previousOp`).
    pub(crate) fn previous_op(&self, op: OpId) -> Option<OpId> {
        let bl = self.op(op).parent?;
        let ops = &self.blocks.block(bl).ops;
        let at = ops.iter().position(|&o| o == op)?;
        at.checked_sub(1).map(|i| ops[i])
    }

    /// Port of `AddrSpaceManager::joinPieces` for register pieces (most significant first)
    /// that are not contiguous: the join record's offset.
    pub(crate) fn join_pieces(&mut self, pieces: Vec<(u32, u64, u32)>) -> Result<u64> {
        let contiguous = pieces.windows(2).all(|w| w[0].0 == w[1].0 && w[1].1 + u64::from(w[1].2) == w[0].1);
        if contiguous {
            return err("joining contiguous pieces: not implemented in ghidra-rs yet");
        }
        let at = match self.joins.iter().position(|j| *j == pieces) {
            Some(i) => i,
            None => {
                self.joins.push(pieces);
                self.joins.len() - 1
            }
        };
        Ok(at as u64)
    }

    /// Port of `Funcdata::warningHeader`.
    pub(crate) fn warning_header(&mut self, msg: impl Into<String>) {
        self.warnings.push(msg.into());
    }
}
