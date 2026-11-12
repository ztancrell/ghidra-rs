//! Port of `Funcdata` (funcdata.cc, funcdata_op.cc, funcdata_varnode.cc): one function's ops,
//! varnodes, basic blocks and calls, with the creation primitives the actions use.

use super::block::{BlockGraph, BlockId};
use super::op::{OpFlags, OpId, PcodeOp, SeqNum};
use super::opcode::Opcode;
use super::varnode::{Space, Varnode, VarnodeId, CONST_SPACE};
use super::{flow, stdsort, Arch, Result};
use std::collections::BTreeMap;

/// Size of the annotation varnodes that hold an op or call reference: the C++ stores a pointer
/// (`sizeof(void *)` on the 64-bit reference build).
const POINTER_SIZE: u32 = 8;

/// Index of a call in [`Funcdata::calls`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallId(pub(crate) u32);

/// Port of the parts of `FuncCallSpecs` (fspec.cc) S1a needs.
#[derive(Debug, Clone)]
pub(crate) struct CallSpec {
    pub(crate) op: OpId,
    /// the called address of a direct call
    pub(crate) entry: Option<u64>,
    /// the callee's display name, when the scope knows a function there (`setFuncdata`)
    pub(crate) name: Option<String>,
}

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

    /// Port of `Funcdata::opInsertBefore`: put `op` into the block of `follow`, just before it.
    pub(crate) fn op_insert_before(&mut self, op: OpId, follow: OpId) {
        let Some(bl) = self.op(follow).parent else { return };
        let ops = &self.blocks.block(bl).ops;
        let at = ops.iter().position(|&o| o == follow).unwrap_or(ops.len());
        self.op_insert(op, bl, at);
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
            let ops = ops.clone();
            for (i, o) in ops.into_iter().enumerate() {
                self.op_mut(o).order = step.wrapping_mul(i as u32 + 1);
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
