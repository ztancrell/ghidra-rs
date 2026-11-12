//! P-code ops (port of the parts of `op.cc` and `funcdata_op.cc` that flow and raw printing
//! need). Ops live in an arena in [`super::Funcdata`], addressed by [`OpId`].

use super::block::BlockId;
use super::opcode::Opcode;
use super::varnode::VarnodeId;

/// Index of an op in its function's arena.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct OpId(pub(crate) u32);

/// Port of `SeqNum`: the instruction address and the creation counter (`uniq`), which the
/// C++ hands out in op creation order. `print raw` shows both, so creation order is kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct SeqNum {
    pub(crate) addr: u64,
    pub(crate) time: u32,
}

/// Port of the `PcodeOp::flags` bits flow uses.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct OpFlags(u8);

impl OpFlags {
    /// `startbasic`: the op starts a basic block
    pub(crate) const START_BASIC: OpFlags = OpFlags(1);
    /// `startmark`: the op is the first of its instruction
    pub(crate) const START_INSTRUCTION: OpFlags = OpFlags(2);

    pub(crate) fn has(self, f: OpFlags) -> bool {
        self.0 & f.0 != 0
    }
    pub(crate) fn set(&mut self, f: OpFlags) {
        self.0 |= f.0;
    }
}

/// Port of `PcodeOp`, the fields the early stages use.
#[derive(Debug, Clone)]
pub(crate) struct PcodeOp {
    pub(crate) opc: Opcode,
    pub(crate) seq: SeqNum,
    pub(crate) out: Option<VarnodeId>,
    pub(crate) ins: Vec<VarnodeId>,
    /// the basic block holding the op, once blocks are built
    pub(crate) parent: Option<BlockId>,
    /// the position key within the block (`SeqNum::order`), see `Funcdata::op_insert`
    pub(crate) order: u32,
    pub(crate) flags: OpFlags,
}
