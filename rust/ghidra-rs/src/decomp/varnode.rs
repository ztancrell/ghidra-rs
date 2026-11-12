//! Varnodes (port of the parts of `varnode.cc` and `funcdata_varnode.cc` that flow and raw
//! printing need). Varnodes live in an arena in [`super::Funcdata`], addressed by [`VarnodeId`].

use super::op::OpId;

/// Index of a varnode in its function's arena.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct VarnodeId(pub(crate) u32);

/// Where a varnode lives. SLEIGH spaces keep the engine's index; the decompiler's own
/// annotation spaces (`IopSpace`, `FspecSpace`) refer to an op or a call by id instead of by
/// pointer, as the C++ does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Space {
    /// A SLEIGH space (index into `Sleigh::spaces`; 0 is `const`).
    Sleigh(u32),
    /// `iop`: the offset names an op (the second input of an INDIRECT).
    Iop,
    /// `fspec`: the offset names a call (the first input of a CALL).
    Fspec,
}

/// The `const` space index in the SLEIGH engine.
pub(crate) const CONST_SPACE: Space = Space::Sleigh(0);

/// Port of `Varnode`, the fields the early stages use.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Varnode {
    pub(crate) space: Space,
    pub(crate) offset: u64,
    pub(crate) size: u32,
    /// the op writing this varnode (`Varnode::def`)
    pub(crate) def: Option<OpId>,
}

impl Varnode {
    pub(crate) fn is_constant(&self) -> bool {
        self.space == CONST_SPACE
    }
}
