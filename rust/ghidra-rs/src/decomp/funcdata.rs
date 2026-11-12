//! Port of `Funcdata` (funcdata.cc, funcdata_op.cc, funcdata_varnode.cc): one function's ops,
//! varnodes, basic blocks and calls, with the creation primitives the actions use.

use super::block::{BlockGraph, BlockId};
use super::fspec::{CallSpec, FuncProto};
use super::op::{OpFlags, OpId, PcodeOp, SeqNum};
use super::opcode::Opcode;
use super::varnode::{Space, Varnode, VarnodeId, CONST_SPACE};
use super::{err, flow, stdsort, Arch, LowlevelError, Result};
use std::collections::BTreeMap;

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
    /// the next free offset of the unique space (`VarnodeBank::uniqid`)
    next_unique: u64,
}

impl Funcdata {
    /// A function starting at `entry`, before any analysis.
    pub fn new(entry: u64) -> Funcdata {
        Funcdata {
            entry,
            ops: Vec::new(),
            vns: Vec::new(),
            seqs: BTreeMap::new(),
            dead: Vec::new(),
            next_time: 0,
            blocks: BlockGraph::default(),
            calls: Vec::new(),
            qlst: Vec::new(),
            jumptables: Vec::new(),
            proto: FuncProto::default(),
            next_unique: UNIQUE_ANALYSIS,
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
    pub(crate) fn call(&self, id: CallId) -> &CallSpec {
        &self.calls[id.0 as usize]
    }
    pub(crate) fn call_mut(&mut self, id: CallId) -> &mut CallSpec {
        &mut self.calls[id.0 as usize]
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
        });
        self.seqs.insert((addr, seq.time), id);
        self.dead.push(id);
        id
    }

    /// Port of `Funcdata::newVarnode` (also `newConstant`, `newCodeRef`).
    pub(crate) fn new_varnode(&mut self, size: u32, space: Space, offset: u64) -> VarnodeId {
        let id = VarnodeId(self.vns.len() as u32);
        self.vns.push(Varnode { space, offset, size, def: None });
        id
    }

    pub(crate) fn new_constant(&mut self, size: u32, value: u64) -> VarnodeId {
        self.new_varnode(size, CONST_SPACE, value)
    }

    /// Port of `Funcdata::newVarnodeOut`: a varnode written by `op`.
    pub(crate) fn new_varnode_out(&mut self, size: u32, space: Space, offset: u64, op: OpId) -> VarnodeId {
        let vn = self.new_varnode(size, space, offset);
        self.vns[vn.0 as usize].def = Some(op);
        self.op_mut(op).out = Some(vn);
        vn
    }

    /// Port of `Funcdata::newVarnodeIop`: an annotation naming `op`.
    pub(crate) fn new_varnode_iop(&mut self, op: OpId) -> VarnodeId {
        self.new_varnode(POINTER_SIZE, Space::Iop, u64::from(op.0))
    }

    /// Port of `Funcdata::newVarnodeCallSpecs`: an annotation naming a call.
    pub(crate) fn new_varnode_callspecs(&mut self, call: CallId) -> VarnodeId {
        self.new_varnode(POINTER_SIZE, Space::Fspec, u64::from(call.0))
    }

    /// Port of `Funcdata::newUniqueOut`: a new unique-space varnode of `size` bytes written by
    /// `op`, at the next free offset (`VarnodeBank::createUnique`). `uniq` is the unique space.
    pub(crate) fn new_unique_out(&mut self, size: u32, uniq: u32, op: OpId) -> VarnodeId {
        let offset = self.next_unique;
        self.next_unique += u64::from(size);
        self.new_varnode_out(size, Space::Sleigh(uniq), offset, op)
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
            let ins = p.ins.iter().map(|v| self.new_varnode(v.size, Space::Sleigh(v.space), v.offset)).collect();
            self.op_mut(op).ins = ins;
        }
        Ok(())
    }

    /// Port of `Funcdata::opInsertInput`: a new input at `slot`.
    pub(crate) fn op_insert_input(&mut self, op: OpId, vn: VarnodeId, slot: usize) {
        self.op_mut(op).ins.insert(slot, vn);
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
        self.op_mut(loadop).ins = vec![spc, addout];
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
        self.op_mut(addop).ins = vec![stackptr, c];
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
    /// from the list).
    pub(crate) fn op_destroy_raw(&mut self, op: OpId) {
        let seq = self.op(op).seq;
        self.seqs.remove(&(seq.addr, seq.time));
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

    /// Port of `Funcdata::opInsertBegin`: put `op` at the start of `bl`, after any MULTIEQUAL.
    pub(crate) fn op_insert_begin(&mut self, op: OpId, bl: BlockId) {
        let at = self.blocks.block(bl).ops.iter().take_while(|&&o| self.op(o).opc == Opcode::Multiequal).count();
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
            // BlockBasic::setOrder: renumber the block evenly
            let step = u32::MAX / ops.len() as u32 - 1;
            for (i, o) in self.blocks.block(bl).ops.iter().enumerate() {
                self.ops[o.0 as usize].order = step.wrapping_mul(i as u32 + 1);
            }
        } else {
            self.op_mut(op).order = after / 2 + before / 2;
        }
    }

    /// The live ops with opcode `opc` (`Funcdata::beginOp(opc)`), in block order.
    pub(crate) fn ops_with(&self, opc: Opcode) -> Vec<OpId> {
        self.blocks.ops().filter(|&o| self.op(o).opc == opc).collect()
    }

    /// Port of `Funcdata::startProcessing`: follow flow, build blocks, order them and the calls.
    pub(crate) fn start_processing(&mut self, arch: &Arch) -> Result<()> {
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
}
