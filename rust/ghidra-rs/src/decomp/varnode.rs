//! Varnodes (port of the parts of `varnode.cc` and `funcdata_varnode.cc` the stages so far
//! need). Varnodes live in an arena in [`super::Funcdata`], addressed by [`VarnodeId`]; the
//! function's location-sorted set of them (`VarnodeBank::loc_tree`) is keyed by [`LocKey`].

use super::op::{OpId, SeqNum};
use super::readers::Readers;

/// Index of a varnode in its function's arena. It counts creation, so it is also the C++
/// `create_index` that orders free varnodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
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
    /// the `stack` space the `.cspec`'s `<stackpointer>` makes (no varnode lives in it until
    /// the `stackvars` rules, stage R5)
    Stack,
    /// `join`: the offset indexes [`super::funcdata::Funcdata::joins`] (`JoinRecord`)
    Join,
}

impl Space {
    /// The space's index as `Address::operator<` compares spaces (`AddrSpace::getIndex`): the
    /// SLEIGH spaces by their index, the annotation spaces after them.
    pub(crate) fn index(self) -> u32 {
        match self {
            Space::Sleigh(i) => i,
            Space::Fspec => u32::MAX - 3,
            Space::Iop => u32::MAX - 2,
            Space::Stack => u32::MAX - 1,
            // made with fspec and iop in `restoreFromSpec`, before them
            Space::Join => u32::MAX - 4,
        }
    }
}

/// The `const` space index in the SLEIGH engine.
pub(crate) const CONST_SPACE: Space = Space::Sleigh(0);

/// Port of the `Varnode::flags` bits the stages so far use. `written` is kept as
/// [`Varnode::def`]; `insert` is `written` or `input`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct VnFlags(u32);

impl VnFlags {
    /// `input`: an input of the function
    pub(crate) const INPUT: VnFlags = VnFlags(1);
    /// `activeheritage`: being linked by the current heritage pass
    pub(crate) const ACTIVE_HERITAGE: VnFlags = VnFlags(2);
    /// `writemask`: a piece of a larger range heritage linked instead
    pub(crate) const WRITEMASK: VnFlags = VnFlags(4);
    /// `unaffected`: an input a call or the function leaves unchanged
    pub(crate) const UNAFFECTED: VnFlags = VnFlags(8);
    /// `return_address`: holds the return address
    pub(crate) const RETURN_ADDRESS: VnFlags = VnFlags(16);
    /// `indirect_creation`: made by an INDIRECT that creates its value
    pub(crate) const INDIRECT_CREATION: VnFlags = VnFlags(32);
    /// deleted (`VarnodeBank::destroy`): out of the location set, never read again
    pub(crate) const DEAD: VnFlags = VnFlags(64);
    /// global storage (`persist`), from the scope: ram
    pub(crate) const PERSIST: VnFlags = VnFlags(1 << 7);
    /// `addrtied`, from the scope: ram
    pub(crate) const ADDRTIED: VnFlags = VnFlags(1 << 8);
    /// `addrforce`: the value must exist at its address
    pub(crate) const ADDRFORCE: VnFlags = VnFlags(1 << 9);
    /// `directwrite` (`ActionDirectWrite`)
    pub(crate) const DIRECTWRITE: VnFlags = VnFlags(1 << 10);
    /// `spacebase` (`Funcdata::spacebase`)
    pub(crate) const SPACEBASE: VnFlags = VnFlags(1 << 11);
    /// `autolive_hold`
    pub(crate) const AUTOLIVE_HOLD: VnFlags = VnFlags(1 << 12);
    /// `consume_list` (`ActionDeadCode`'s work list)
    pub(crate) const CONSUME_LIST: VnFlags = VnFlags(1 << 13);
    /// `consume_vacuous`
    pub(crate) const CONSUME_VACUOUS: VnFlags = VnFlags(1 << 14);
    /// `annotation` on a code reference (`Funcdata::newCodeRef`): the target of a BRANCH,
    /// CBRANCH or CALL
    pub(crate) const CODEREF: VnFlags = VnFlags(1 << 17);
    /// `incidental_copy`, from the `.pspec`
    pub(crate) const INCIDENTAL_COPY: VnFlags = VnFlags(1 << 16);

    pub(crate) fn has(self, f: VnFlags) -> bool {
        self.0 & f.0 != 0
    }
    pub(crate) fn set(&mut self, f: VnFlags) {
        self.0 |= f.0;
    }
    pub(crate) fn clear(&mut self, f: VnFlags) {
        self.0 &= !f.0;
    }
}

/// Port of `Varnode`, the fields the stages so far use.
#[derive(Debug, Clone)]
pub(crate) struct Varnode {
    pub(crate) space: Space,
    pub(crate) offset: u64,
    pub(crate) size: u32,
    /// the op writing this varnode (`Varnode::def`, the `written` flag)
    pub(crate) def: Option<OpId>,
    /// the ops reading this varnode, in the order they were added (`descend`)
    pub(crate) descend: Readers,
    pub(crate) flags: VnFlags,
    /// the bits read by some op (`Varnode::consumed`, `ActionDeadCode`)
    pub(crate) consume: u64,
}

impl Varnode {
    pub(crate) fn new(space: Space, offset: u64, size: u32) -> Varnode {
        Varnode { space, offset, size, def: None, descend: Readers::default(), flags: VnFlags::default(), consume: u64::MAX }
    }

    pub(crate) fn is_constant(&self) -> bool {
        self.space == CONST_SPACE
    }
    pub(crate) fn is_annotation(&self) -> bool {
        matches!(self.space, Space::Iop | Space::Fspec) || self.has(VnFlags::CODEREF)
    }
    /// `isInput`
    pub(crate) fn is_input(&self) -> bool {
        self.flags.has(VnFlags::INPUT)
    }
    pub(crate) fn is_dead(&self) -> bool {
        self.flags.has(VnFlags::DEAD)
    }
    /// `isFree`: neither written nor an input
    pub(crate) fn is_free(&self) -> bool {
        self.def.is_none() && !self.is_input()
    }
    /// `isHeritageKnown`: inserted (written or input), a constant or an annotation
    pub(crate) fn is_heritage_known(&self) -> bool {
        !self.is_free() || self.is_constant() || self.is_annotation()
    }
    pub(crate) fn has(&self, f: VnFlags) -> bool {
        self.flags.has(f)
    }
    pub(crate) fn is_free_or_input(&self) -> bool {
        self.def.is_none()
    }
    pub(crate) fn is_written(&self) -> bool {
        self.def.is_some()
    }
    /// `Varnode::getNZMask` before `ActionNonzeroMask` (group `analysis`) ever runs: a
    /// constant's value, else all ones.
    pub(crate) fn nzmask(&self) -> u64 {
        if self.is_constant() {
            self.offset
        } else {
            u64::MAX
        }
    }
    /// `Varnode::isAutoLive`.
    pub(crate) fn is_auto_live(&self) -> bool {
        self.has(VnFlags::ADDRFORCE) || self.has(VnFlags::AUTOLIVE_HOLD)
    }

    /// Port of `Varnode::overlap(const Address &,int4)`: the offset of this varnode within the
    /// range `[off, off + size)` of its space, if it starts inside it. `mask` is the space's
    /// offset mask (`AddrSpace::wrapOffset`).
    pub(crate) fn overlap(&self, space: Space, off: u64, size: u32, mask: u64) -> Option<u32> {
        overlap(self.space, self.offset, space, off, size, mask)
    }
}

/// Port of `Address::overlap(0, ..)`: the distance of `(space, off)` past the start of the range
/// `[start, start + size)` of `rspace`, when it lies inside (constants never overlap). The
/// distance wraps within the space's offsets, whose mask is `mask`.
pub(crate) fn overlap(space: Space, off: u64, rspace: Space, start: u64, size: u32, mask: u64) -> Option<u32> {
    if space != rspace || space == CONST_SPACE {
        return None;
    }
    let dist = off.wrapping_sub(start) & mask;
    (dist < u64::from(size)).then_some(dist as u32)
}

/// The order of `VarnodeCompareLocDef`: address, size, then inputs, written varnodes (by their
/// op's sequence number) and free ones (by creation), with the id last. The C++ set has no
/// such tie-break: an insert equal to a present varnode (two inputs at one address and size)
/// is merged into it by `VarnodeBank::xref`; here `setInputVarnode` returns the present input
/// before that can happen, so keys never tie but for the id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct LocKey {
    pub(crate) space: u32,
    pub(crate) offset: u64,
    pub(crate) size: u32,
    /// 0 input, 1 written, 2 free (`(flags & (input|written)) - 1`, unsigned)
    class: u8,
    seq_addr: u64,
    seq_time: u32,
    pub(crate) id: VarnodeId,
}

impl LocKey {
    /// The key of `vn` (with id `id`) whose defining op, if any, has sequence number `seq`.
    pub(crate) fn of(vn: &Varnode, id: VarnodeId, seq: Option<SeqNum>) -> LocKey {
        let (class, seq_addr, seq_time) = match (vn.is_input(), seq) {
            (true, _) => (0, 0, 0),
            (false, Some(s)) => (1, s.addr, s.time),
            (false, None) => (2, 0, 0),
        };
        LocKey { space: vn.space.index(), offset: vn.offset, size: vn.size, class, seq_addr, seq_time, id }
    }

    /// The first key at or after address `(space, offset)`, for range scans (`beginLoc`).
    pub(crate) fn start(space: u32, offset: u64) -> LocKey {
        LocKey { space, offset, size: 0, class: 0, seq_addr: 0, seq_time: 0, id: VarnodeId(0) }
    }
}
