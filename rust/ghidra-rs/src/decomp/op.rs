//! P-code ops (port of the parts of `op.cc` and `funcdata_op.cc` the stages so far need). Ops
//! live in an arena in [`super::Funcdata`], addressed by [`OpId`].

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

/// Port of the `PcodeOp::flags` bits the stages so far use.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct OpFlags(u32);

impl OpFlags {
    /// `startbasic`: the op starts a basic block
    pub(crate) const START_BASIC: OpFlags = OpFlags(1);
    /// `startmark`: the op is the first of its instruction
    pub(crate) const START_INSTRUCTION: OpFlags = OpFlags(2);
    /// `indirect_creation`: an INDIRECT whose output the call creates (`[create]`)
    pub(crate) const INDIRECT_CREATION: OpFlags = OpFlags(4);
    /// `return_copy`: a COPY guarding a global at a RETURN (`Funcdata::markReturnCopy`)
    pub(crate) const RETURN_COPY: OpFlags = OpFlags(16);
    /// `indirect_store`: an INDIRECT guarding a STORE
    pub(crate) const INDIRECT_STORE: OpFlags = OpFlags(32);
    /// `indirect_source` (`ActionDeadCode`)
    pub(crate) const INDIRECT_SOURCE: OpFlags = OpFlags(128);
    /// `boolean_flip` of a CBRANCH
    pub(crate) const BOOLEAN_FLIP: OpFlags = OpFlags(512);
    /// `calculated_bool`: the output is a boolean (`opMarkCalculatedBool`, stage S6)
    pub(crate) const CALCULATED_BOOL: OpFlags = OpFlags(1024);
    /// `immed_copy` (an additional flag in C++): a COPY was propagated into a MULTIEQUAL slot
    pub(crate) const IMMED_COPY: OpFlags = OpFlags(2048);
    /// `fallthru_true` of a CBRANCH (`opFlipCondition`, stage R2)
    pub(crate) const FALLTHRU_TRUE: OpFlags = OpFlags(4096);

    pub(crate) fn has(self, f: OpFlags) -> bool {
        self.0 & f.0 != 0
    }
    pub(crate) fn set(&mut self, f: OpFlags) {
        self.0 |= f.0;
    }
    pub(crate) fn clear(&mut self, f: OpFlags) {
        self.0 &= !f.0;
    }
}

/// The special halts a RETURN can stand for (the `PcodeOp` flags `getHaltType` returns).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Halt {
    BadInstruction,
    Unimplemented,
}

/// Port of `PcodeOp`, the fields the stages so far use.
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
    /// the special halt this RETURN stands for (`getHaltType`), if any
    pub(crate) halt: Option<Halt>,
}

impl PcodeOp {
    /// `isDead`: not in a basic block
    pub(crate) fn is_dead(&self) -> bool {
        self.parent.is_none()
    }
    /// `isCall`: CALL, CALLIND, CALLOTHER and NEW
    pub(crate) fn is_call(&self) -> bool {
        matches!(self.opc, Opcode::Call | Opcode::Callind | Opcode::Callother | Opcode::New)
    }
    /// `isMarker`: MULTIEQUAL and INDIRECT
    /// `PcodeOp::isBranch`.
    pub(crate) fn is_branch(&self) -> bool {
        matches!(self.opc, Opcode::Branch | Opcode::Cbranch | Opcode::Branchind)
    }
    pub(crate) fn is_marker(&self) -> bool {
        matches!(self.opc, Opcode::Multiequal | Opcode::Indirect)
    }
}
