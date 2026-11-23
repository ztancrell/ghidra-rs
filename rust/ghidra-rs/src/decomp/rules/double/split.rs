//! Port of `SplitVarnode` (double.cc): a double-precision value as its two pieces, a whole
//! varnode standing for both, or a constant; and the static helpers that build the whole
//! operation once a form is recognised. x86 is little-endian: the big-endian address arithmetic
//! is left out. `Varnode::getSymbolEntry` is [`same_symbol`]: the functions and external references
//! of the global scope and the locked parameters of the function are the symbols there are. `inHandLoNoHi` and `inHandHiOut`
//! have no caller in the C++ and are left out.

use super::*;
use crate::decomp::infertypes::{query_global, Entry};
use crate::decomp::locked::param_symbol;

/// Port of `SplitVarnode`.
#[derive(Debug, Clone, Default)]
pub(super) struct SplitVarnode {
    /// least significant piece; `None` for a constant
    pub(super) lo: Option<VarnodeId>,
    /// most significant piece; `None` for a constant or a zero-extended `lo`
    pub(super) hi: Option<VarnodeId>,
    /// a varnode representing the whole
    pub(super) whole: Option<VarnodeId>,
    /// the op at which both pieces are defined
    defpoint: Option<OpId>,
    /// the block in which both pieces are defined
    defblock: Option<BlockId>,
    /// the value of a double-precision constant
    pub(super) val: u64,
    /// size of the (virtual) whole in bytes
    pub(super) wholesize: u32,
}

/// `SeqNum::getOrder`.
pub(super) fn order(fd: &Funcdata, op: OpId) -> u32 {
    fd.op(op).order
}

/// `PcodeOp::getParent`.
pub(super) fn parent(fd: &Funcdata, op: OpId) -> Option<BlockId> {
    fd.op(op).parent
}

/// Whether walking up the immediate dominators from `bl` (exclusive) reaches `target`.
pub(super) fn dominated_by(fd: &Funcdata, bl: Option<BlockId>, target: BlockId) -> bool {
    let mut cur = bl;
    while let Some(b) = cur {
        cur = fd.blocks.block(b).idom;
        if cur == Some(target) {
            return true;
        }
    }
    false
}

/// The readers of `vn`, copied (`beginDescend` .. `endDescend`).
pub(super) fn readers(fd: &Funcdata, vn: VarnodeId) -> Vec<OpId> {
    fd.vn(vn).descend.to_vec()
}

/// `PcodeOp::getSlot` for a varnode the op reads.
pub(super) fn slot(fd: &Funcdata, op: OpId, vn: VarnodeId) -> Result<usize> {
    fd.slot_of(op, vn).ok_or_else(|| LowlevelError("double precision: op does not read the varnode".into()))
}

/// `op->getIn(1 - op->getSlot(vn))`: the other input of a binary op reading `vn`.
pub(super) fn other_in(fd: &Funcdata, op: OpId, vn: VarnodeId) -> Result<VarnodeId> {
    let s = slot(fd, op, vn)?;
    inp(fd, op, 1 - s.min(1))
}

/// `Varnode::getAddr` as (space, offset).
fn vn_addr(fd: &Funcdata, vn: VarnodeId) -> (Space, u64) {
    (fd.vn(vn).space, fd.vn(vn).offset)
}

impl SplitVarnode {
    /// `SplitVarnode(int4 sz, uintb v)`: a double-precision constant.
    pub(super) fn constant(sz: u32, v: u64) -> SplitVarnode {
        SplitVarnode { val: v, wholesize: sz, ..Default::default() }
    }

    /// `SplitVarnode(Varnode *l, Varnode *h)`.
    pub(super) fn from_pieces(fd: &Funcdata, l: VarnodeId, h: VarnodeId) -> SplitVarnode {
        let mut s = SplitVarnode::default();
        s.init_partial(fd, sz(fd, l) + sz(fd, h), l, Some(h));
        s
    }

    /// `initPartial(int4 sz, uintb v)`.
    pub(super) fn init_constant(&mut self, sz: u32, v: u64) {
        *self = SplitVarnode::constant(sz, v);
    }

    /// `initPartial(int4 sz, Varnode *l, Varnode *h)`.
    pub(super) fn init_partial(&mut self, fd: &Funcdata, size: u32, l: VarnodeId, h: Option<VarnodeId>) {
        let mut val = self.val;
        let (lo, hi) = match h {
            None if is_const(fd, l) => {
                val = off(fd, l);
                (None, None)
            }
            None => (Some(l), None),
            Some(h) if is_const(fd, l) && is_const(fd, h) => {
                val = shl(off(fd, h), (sz(fd, l) * 8) as i32) | off(fd, l);
                (None, None)
            }
            Some(h) => (Some(l), Some(h)),
        };
        *self = SplitVarnode { lo, hi, whole: None, defpoint: None, defblock: None, val, wholesize: size };
    }

    /// `initAll`.
    pub(super) fn init_all(&mut self, fd: &Funcdata, w: VarnodeId, l: VarnodeId, h: Option<VarnodeId>) {
        *self = SplitVarnode {
            lo: Some(l),
            hi: h,
            whole: Some(w),
            defpoint: None,
            defblock: None,
            val: self.val,
            wholesize: sz(fd, w),
        };
    }

    pub(super) fn is_constant(&self) -> bool {
        self.lo.is_none()
    }

    /// The pieces, when both are set.
    pub(super) fn pieces(&self) -> Option<(VarnodeId, VarnodeId)> {
        Some((self.lo?, self.hi?))
    }

    /// The whole, once found or created.
    pub(super) fn whole_vn(&self) -> Result<VarnodeId> {
        self.whole.ok_or_else(|| LowlevelError("double precision: no whole varnode".into()))
    }

    /// `SplitVarnode::inHandHi`.
    pub(super) fn in_hand_hi(&mut self, fd: &Funcdata, h: VarnodeId) -> Result<bool> {
        if !fd.vn(h).is_precis_hi() {
            return Ok(false);
        }
        let Some(op) = def_with(fd, h, Subpiece) else { return Ok(false) };
        let w = inp(fd, op, 0)?;
        if off(fd, inp(fd, op, 1)?) != u64::from(sz(fd, w).wrapping_sub(sz(fd, h))) {
            return Ok(false);
        }
        for tmpop in readers(fd, w) {
            if code(fd, tmpop) != Subpiece {
                continue;
            }
            let Some(tmplo) = fd.op(tmpop).out else { continue };
            if !fd.vn(tmplo).is_precis_lo()
                || sz(fd, tmplo) + sz(fd, h) != sz(fd, w)
                || off(fd, inp(fd, tmpop, 1)?) != 0
            {
                continue;
            }
            self.init_all(fd, w, tmplo, Some(h));
            return Ok(true);
        }
        Ok(false)
    }

    /// The SUBPIECE at offset `lo`'s size of `w` whose output is a high piece fitting `l`.
    fn find_hi_sibling(fd: &Funcdata, w: VarnodeId, l: VarnodeId) -> Result<Option<VarnodeId>> {
        for tmpop in readers(fd, w) {
            if code(fd, tmpop) != Subpiece {
                continue;
            }
            let Some(tmphi) = fd.op(tmpop).out else { continue };
            if !fd.vn(tmphi).is_precis_hi()
                || sz(fd, tmphi) + sz(fd, l) != sz(fd, w)
                || off(fd, inp(fd, tmpop, 1)?) != u64::from(sz(fd, l))
            {
                continue;
            }
            return Ok(Some(tmphi));
        }
        Ok(None)
    }

    /// `SplitVarnode::inHandLo`.
    pub(super) fn in_hand_lo(&mut self, fd: &Funcdata, l: VarnodeId) -> Result<bool> {
        if !fd.vn(l).is_precis_lo() {
            return Ok(false);
        }
        let Some(op) = def_with(fd, l, Subpiece) else { return Ok(false) };
        let w = inp(fd, op, 0)?;
        if off(fd, inp(fd, op, 1)?) != 0 {
            return Ok(false);
        }
        if let Some(h) = Self::find_hi_sibling(fd, w, l)? {
            self.init_all(fd, w, l, Some(h));
            return Ok(true);
        }
        Ok(false)
    }

    /// `SplitVarnode::inHandLoOut`.
    pub(super) fn in_hand_lo_out(&mut self, fd: &Funcdata, l: VarnodeId) -> Result<bool> {
        let mut found = None;
        for pieceop in readers(fd, l) {
            if code(fd, pieceop) != Piece || inp(fd, pieceop, 1)? != l {
                continue;
            }
            let h = inp(fd, pieceop, 0)?;
            if !fd.vn(h).is_precis_hi() {
                continue;
            }
            if found.is_some() {
                return Ok(false);
            }
            found = Some((h, out(fd, pieceop)?));
        }
        let Some((h, outvn)) = found else { return Ok(false) };
        self.init_all(fd, outvn, l, Some(h));
        Ok(true)
    }

    /// The SUBPIECE behind `vn`, looking through one COPY.
    fn split_source(fd: &Funcdata, vn: VarnodeId) -> Option<OpId> {
        let mut op = def(fd, vn)?;
        if code(fd, op) == Copy {
            op = def(fd, fd.op(op).ins.first().copied()?)?;
        }
        (code(fd, op) == Subpiece).then_some(op)
    }

    /// `SplitVarnode::findWholeSplitToPieces`.
    fn find_whole_split_to_pieces(&mut self, fd: &Funcdata) -> Result<bool> {
        let whole = match self.whole {
            Some(w) => w,
            None => {
                let Some((lo, hi)) = self.pieces() else { return Ok(false) };
                let Some(subhi) = Self::split_source(fd, hi) else { return Ok(false) };
                if off(fd, inp(fd, subhi, 1)?) != u64::from(self.wholesize.wrapping_sub(sz(fd, hi))) {
                    return Ok(false);
                }
                let putative = inp(fd, subhi, 0)?;
                if sz(fd, putative) != self.wholesize {
                    return Ok(false);
                }
                let Some(sublo) = Self::split_source(fd, lo) else { return Ok(false) };
                if putative != inp(fd, sublo, 0)? || off(fd, inp(fd, sublo, 1)?) != 0 {
                    return Ok(false);
                }
                self.whole = Some(putative);
                putative
            }
        };
        if let Some(d) = def(fd, whole) {
            self.defpoint = Some(d);
            self.defblock = parent(fd, d);
        } else if fd.vn(whole).is_input() {
            self.defpoint = None;
            self.defblock = None;
        }
        Ok(true)
    }

    /// `SplitVarnode::findDefinitionPoint`.
    fn find_definition_point(&mut self, fd: &Funcdata) -> Result<bool> {
        let lo = self.lo.ok_or_else(|| LowlevelError("findDefinitionPoint on a constant".into()))?;
        if self.hi.is_some_and(|h| is_const(fd, h)) || is_const(fd, lo) {
            return Ok(false);
        }
        let Some(hi) = self.hi else {
            if fd.vn(lo).is_input() {
                self.defblock = None;
                self.defpoint = None;
            } else if let Some(d) = def(fd, lo) {
                self.defpoint = Some(d);
                self.defblock = parent(fd, d);
            } else {
                return Ok(false);
            }
            return Ok(true);
        };
        if let Some(lastop) = def(fd, hi) {
            let Some(lastop2) = def(fd, lo) else { return Ok(false) };
            return Ok(self.latest_of(fd, lastop, lastop2));
        }
        if fd.vn(hi).is_input() {
            if !fd.vn(lo).is_input() {
                return Ok(false);
            }
            self.defblock = None;
            self.defpoint = None;
        }
        Ok(true)
    }

    /// The part of `findDefinitionPoint` for two written pieces: the later definition when
    /// one block dominates the other.
    fn latest_of(&mut self, fd: &Funcdata, lastop: OpId, lastop2: OpId) -> bool {
        let defblock = parent(fd, lastop);
        let otherblock = parent(fd, lastop2);
        self.defblock = defblock;
        if defblock != otherblock {
            self.defpoint = Some(lastop);
            if otherblock.is_some_and(|o| dominated_by(fd, defblock, o)) {
                return true;
            }
            self.defblock = otherblock;
            self.defpoint = Some(lastop2);
            if defblock.is_some_and(|o| dominated_by(fd, otherblock, o)) {
                return true;
            }
            self.defblock = None;
            return false;
        }
        self.defpoint = Some(if order(fd, lastop2) > order(fd, lastop) { lastop2 } else { lastop });
        true
    }

    /// `SplitVarnode::findEarliestSplitPoint`.
    pub(super) fn find_earliest_split_point(&self, fd: &Funcdata) -> Option<OpId> {
        let hiop = def(fd, self.hi?)?;
        let loop_ = def(fd, self.lo?)?;
        if parent(fd, loop_) != parent(fd, hiop) {
            return None;
        }
        Some(if order(fd, loop_) < order(fd, hiop) { loop_ } else { hiop })
    }

    /// `SplitVarnode::findWholeBuiltFromPieces`.
    fn find_whole_built_from_pieces(&mut self, fd: &Funcdata) -> Result<bool> {
        let Some((lo, hi)) = self.pieces() else { return Ok(false) };
        let bb = if let Some(d) = def(fd, lo) {
            parent(fd, d)
        } else if fd.vn(lo).is_input() {
            None
        } else {
            return err("Trying to find whole on free varnode");
        };
        let mut res: Option<OpId> = None;
        for op in readers(fd, lo) {
            if code(fd, op) != Piece || inp(fd, op, 0)? != hi {
                continue;
            }
            let p = parent(fd, op);
            match bb {
                Some(_) if p != bb => continue,
                None if !p.is_some_and(|b| fd.blocks.is_entry_point(b)) => continue,
                _ => {}
            }
            if res.is_none_or(|r| order(fd, op) < order(fd, r)) {
                res = Some(op);
            }
        }
        match res {
            None => self.whole = None,
            Some(r) => {
                self.defpoint = Some(r);
                self.defblock = parent(fd, r);
                self.whole = fd.op(r).out;
            }
        }
        Ok(self.whole.is_some())
    }

    /// The three ways of finding where the whole is (or can be) defined.
    fn find_whole_or_point(&mut self, fd: &Funcdata) -> Result<bool> {
        Ok(self.find_whole_split_to_pieces(fd)?
            || self.find_whole_built_from_pieces(fd)?
            || self.find_definition_point(fd)?)
    }

    /// `SplitVarnode::isWholeFeasible`.
    pub(super) fn is_whole_feasible(&mut self, fd: &Funcdata, existop: OpId) -> Result<bool> {
        if self.is_constant() {
            return Ok(true);
        }
        if let Some((lo, hi)) = self.pieces() {
            if is_const(fd, lo) != is_const(fd, hi) {
                return Ok(false); // mixed constant/non-constant
            }
        }
        if !self.find_whole_or_point(fd)? {
            return Ok(false);
        }
        let Some(defblock) = self.defblock else { return Ok(true) };
        let curbl = parent(fd, existop);
        if curbl == Some(defblock) {
            let dp = self.defpoint.ok_or_else(|| LowlevelError("defblock without defpoint".into()))?;
            return Ok(order(fd, dp) <= order(fd, existop));
        }
        Ok(dominated_by(fd, curbl, defblock))
    }

    /// `SplitVarnode::isWholePhiFeasible`.
    pub(super) fn is_whole_phi_feasible(&mut self, fd: &Funcdata, bl: BlockId) -> Result<bool> {
        if self.is_constant() || !self.find_whole_or_point(fd)? {
            return Ok(false);
        }
        let Some(defblock) = self.defblock else { return Ok(true) };
        Ok(bl == defblock || dominated_by(fd, Some(bl), defblock))
    }

    /// Marks the pieces `precislo` / `precishi`.
    fn mark_pieces(&self, fd: &mut Funcdata) {
        if let Some(lo) = self.lo {
            fd.vn_set(lo, VnFlags::PRECIS_LO);
        }
        if let Some(hi) = self.hi {
            fd.vn_set(hi, VnFlags::PRECIS_HI);
        }
    }

    /// `SplitVarnode::findCreateWhole`.
    pub(super) fn find_create_whole(&mut self, fd: &mut Funcdata) -> Result<()> {
        if self.is_constant() {
            self.whole = Some(fd.new_constant(self.wholesize, self.val));
            return Ok(());
        }
        self.mark_pieces(fd);
        if self.whole.is_some() {
            return Ok(());
        }
        let lo = self.lo.ok_or_else(|| LowlevelError("no low piece".into()))?;
        let (addr, topblock) = match (self.defblock, self.defpoint) {
            (Some(_), Some(dp)) => (op_addr(fd, dp), None),
            (Some(_), None) => return err("findCreateWhole: defblock without defpoint"),
            (None, _) => {
                let tb = *fd.blocks.list.first().ok_or_else(|| LowlevelError("no blocks".into()))?;
                (fd.blocks.block(tb).start, Some(tb))
            }
        };
        let concatop = match self.hi {
            Some(hi) => {
                let o = fd.new_op(Piece, addr);
                self.whole = Some(uniq_out(fd, self.wholesize, o)?);
                fd.op_set_input(o, hi, 0)?;
                fd.op_set_input(o, lo, 1)?;
                o
            }
            None => {
                let o = fd.new_op(IntZext, addr);
                self.whole = Some(uniq_out(fd, self.wholesize, o)?);
                fd.op_set_input(o, lo, 0)?;
                o
            }
        };
        match (topblock, self.defpoint) {
            (Some(tb), _) => fd.op_insert_begin(concatop, tb),
            (None, Some(dp)) => fd.op_insert_after(concatop, dp)?,
            (None, None) => return err("findCreateWhole: no insertion point"),
        }
        self.defpoint = Some(concatop);
        self.defblock = parent(fd, concatop);
        Ok(())
    }

    /// `SplitVarnode::findCreateOutputWhole`.
    pub(super) fn find_create_output_whole(&mut self, fd: &mut Funcdata) -> Result<()> {
        self.mark_pieces(fd);
        if self.whole.is_none() {
            let uniq = fd.uniq.ok_or_else(|| LowlevelError("no unique space".into()))?;
            self.whole = Some(fd.new_unique(self.wholesize, uniq));
        }
        Ok(())
    }

    /// `SplitVarnode::createJoinedWhole`.
    pub(super) fn create_joined_whole(&mut self, fd: &mut Funcdata, arch: &Arch) -> Result<()> {
        self.mark_pieces(fd);
        if self.whole.is_some() {
            return Ok(());
        }
        let (lo, hi) = self.pieces().ok_or_else(|| LowlevelError("createJoinedWhole without pieces".into()))?;
        let (space, offset) = match is_addr_tied_contiguous(fd, arch, lo, hi) {
            Some(a) => a,
            None => {
                let piece = |v: VarnodeId| match fd.vn(v).space {
                    Space::Sleigh(s) => Ok((s, off(fd, v), sz(fd, v))),
                    _ => err("constructJoinAddress: a piece outside a SLEIGH space"),
                };
                let pieces = vec![piece(hi)?, piece(lo)?];
                fd.join_address(arch, pieces)?
            }
        };
        let w = fd.new_varnode(self.wholesize, space, offset);
        fd.vn_set(w, VnFlags::WRITEMASK);
        self.whole = Some(w);
        Ok(())
    }

    /// `buildLoFromWhole` / `buildHiFromWhole`: `piece`'s defining op becomes a SUBPIECE of the
    /// whole at byte `offset`.
    fn build_from_whole(&self, fd: &mut Funcdata, piece: VarnodeId, offset: u64) -> Result<()> {
        let Some(pop) = def(fd, piece) else {
            return err("Building low piece that was originally undefined");
        };
        let c = fd.new_constant(4, offset);
        let inlist = [self.whole_vn()?, c];
        match code(fd, pop) {
            Multiequal => {
                let bl = parent(fd, pop).ok_or_else(|| LowlevelError("MULTIEQUAL outside a block".into()))?;
                fd.op_uninsert(pop);
                fd.op_set_opcode(pop, Subpiece);
                fd.op_set_all_input(pop, &inlist)?;
                fd.op_insert_begin(pop, bl);
            }
            Indirect => {
                let affector =
                    fd.iop_target(inp(fd, pop, 1)?).ok_or_else(|| LowlevelError("INDIRECT without its iop".into()))?;
                let alive = !fd.op(affector).is_dead();
                if alive {
                    fd.op_uninsert(pop);
                }
                fd.op_set_opcode(pop, Subpiece);
                fd.op_set_all_input(pop, &inlist)?;
                if alive {
                    fd.op_insert_after(pop, affector)?;
                }
            }
            _ => {
                fd.op_set_opcode(pop, Subpiece);
                fd.op_set_all_input(pop, &inlist)?;
            }
        }
        Ok(())
    }

    /// `SplitVarnode::buildLoFromWhole` then `buildHiFromWhole`.
    fn build_pieces_from_whole(&self, fd: &mut Funcdata) -> Result<()> {
        let (lo, hi) = self.pieces().ok_or_else(|| LowlevelError("building pieces without pieces".into()))?;
        self.build_from_whole(fd, lo, 0)?;
        self.build_from_whole(fd, hi, u64::from(sz(fd, lo)))
    }

    /// `SplitVarnode::findOutExist`.
    fn find_out_exist(&mut self, fd: &Funcdata) -> Result<Option<OpId>> {
        if self.find_whole_built_from_pieces(fd)? {
            return Ok(self.defpoint);
        }
        Ok(self.find_earliest_split_point(fd))
    }

    /// `SplitVarnode::exceedsConstPrecision`.
    pub(super) fn exceeds_const_precision(&self) -> bool {
        self.is_constant() && self.wholesize > 8
    }
}

/// `SplitVarnode::adjacentOffsets`.
pub(super) fn adjacent_offsets(fd: &Funcdata, vn1: VarnodeId, vn2: VarnodeId, size1: u64) -> Result<bool> {
    if is_const(fd, vn1) {
        return Ok(is_const(fd, vn2) && off(fd, vn1).wrapping_add(size1) == off(fd, vn2));
    }
    let Some(op2) = def_with(fd, vn2, IntAdd) else { return Ok(false) };
    let c2vn = inp(fd, op2, 1)?;
    if !is_const(fd, c2vn) {
        return Ok(false);
    }
    let c2 = off(fd, c2vn);
    if inp(fd, op2, 0)? == vn1 {
        return Ok(size1 == c2);
    }
    let Some(op1) = def_with(fd, vn1, IntAdd) else { return Ok(false) };
    let c1vn = inp(fd, op1, 1)?;
    if !is_const(fd, c1vn) || inp(fd, op1, 0)? != inp(fd, op2, 0)? {
        return Ok(false);
    }
    Ok(off(fd, c1vn).wrapping_add(size1) == c2)
}

/// `Varnode::getSpaceFromConst` of a LOAD or STORE's first input: the space index.
pub(super) fn space_from_const(fd: &Funcdata, op: OpId) -> Result<u32> {
    Ok(off(fd, inp(fd, op, 0)?) as u32)
}

/// `SplitVarnode::testContiguousPointers` (little-endian): the least and most significant
/// LOAD or STORE as (first, second) and their space, when they access adjacent memory.
pub(super) fn test_contiguous_pointers(fd: &Funcdata, most: OpId, least: OpId) -> Result<Option<(OpId, OpId, u32)>> {
    let spc = space_from_const(fd, least)?;
    if space_from_const(fd, most)? != spc {
        return Ok(None);
    }
    let (first, second) = (least, most);
    let firstptr = inp(fd, first, 1)?;
    if is_free(fd, firstptr) {
        return Ok(None);
    }
    let sizeres = if code(fd, first) == Load { sz(fd, out(fd, first)?) } else { sz(fd, inp(fd, first, 2)?) };
    let ok = adjacent_offsets(fd, firstptr, inp(fd, second, 1)?, u64::from(sizeres))?;
    Ok(ok.then_some((first, second, spc)))
}

/// The symbol of `Varnode::getSymbolEntry`, compared as the C++ compares `getSymbol()` of two
/// pieces: a function or external reference of the global scope holding a ram varnode, or the
/// locked parameter of the function a varnode maps to. `None`: no entry.
fn symbol_of(fd: &Funcdata, arch: &Arch, vn: VarnodeId) -> Option<(Option<Entry>, Option<usize>)> {
    let v = fd.vn(vn);
    if fd.ram.is_some_and(|r| v.space == Space::Sleigh(r)) {
        return query_global(arch, v.offset, v.size).map(|e| (Some(e), None));
    }
    param_symbol(fd, vn).map(|i| (None, Some(i)))
}

/// The symbol test of `RuleDoubleOut::attemptMarking` and `isAddrTiedContiguous`: neither piece
/// has a symbol entry, or both are entries of one symbol.
pub(super) fn same_symbol(fd: &Funcdata, arch: &Arch, a: VarnodeId, b: VarnodeId) -> bool {
    symbol_of(fd, arch, a) == symbol_of(fd, arch, b)
}

/// `SplitVarnode::isAddrTiedContiguous` (little-endian): the address of the whole when `lo` and
/// `hi` are address-tied, no symbol keeps them apart, and `lo` sits right below `hi`.
pub(super) fn is_addr_tied_contiguous(
    fd: &Funcdata,
    arch: &Arch,
    lo: VarnodeId,
    hi: VarnodeId,
) -> Option<(Space, u64)> {
    let (l, h) = (fd.vn(lo), fd.vn(hi));
    if !l.flags.has(VnFlags::ADDRTIED) || !h.flags.has(VnFlags::ADDRTIED) || !same_symbol(fd, arch, lo, hi) {
        return None;
    }
    if l.space != h.space || l.offset >= h.offset || l.offset.wrapping_add(u64::from(l.size)) != h.offset {
        return None;
    }
    Some((l.space, l.offset))
}

/// `SplitVarnode::wholeList`: the double-precision objects `w` is the whole of.
pub(super) fn whole_list(fd: &Funcdata, w: VarnodeId) -> Result<Vec<SplitVarnode>> {
    let mut basic = SplitVarnode { whole: Some(w), wholesize: sz(fd, w), ..Default::default() };
    let mut res = 0;
    for subop in readers(fd, w) {
        if code(fd, subop) != Subpiece {
            continue;
        }
        let Some(vn) = fd.op(subop).out else { continue };
        let o = off(fd, inp(fd, subop, 1)?);
        if fd.vn(vn).is_precis_hi() {
            if o != u64::from(basic.wholesize.wrapping_sub(sz(fd, vn))) {
                continue;
            }
            basic.hi = Some(vn);
            res |= 2;
        } else if fd.vn(vn).is_precis_lo() {
            if o != 0 {
                continue;
            }
            basic.lo = Some(vn);
            res |= 1;
        }
    }
    if res == 0 {
        return Ok(Vec::new());
    }
    if let Some((lo, hi)) = basic.pieces() {
        if sz(fd, lo) + sz(fd, hi) != basic.wholesize {
            return Ok(Vec::new());
        }
    }
    let mut splitvec = vec![basic.clone()];
    find_copies(fd, &basic, &mut splitvec)?;
    Ok(splitvec)
}

/// `SplitVarnode::findCopies`: pairs of COPYs of both pieces into adjacent storage.
fn find_copies(fd: &Funcdata, sv: &SplitVarnode, splitvec: &mut Vec<SplitVarnode>) -> Result<()> {
    let Some((lo, hi)) = sv.pieces() else { return Ok(()) };
    let whole = sv.whole_vn()?;
    for loop_ in readers(fd, lo) {
        if code(fd, loop_) != Copy {
            continue;
        }
        let locpy = out(fd, loop_)?;
        let (space, offset) = vn_addr(fd, locpy);
        let addr = (space, offset.wrapping_add(u64::from(sz(fd, locpy))));
        for hiop in readers(fd, hi) {
            if code(fd, hiop) != Copy {
                continue;
            }
            let hicpy = out(fd, hiop)?;
            if vn_addr(fd, hicpy) != addr || parent(fd, hiop) != parent(fd, loop_) {
                continue;
            }
            let mut newsplit = SplitVarnode::default();
            newsplit.init_all(fd, whole, locpy, Some(hicpy));
            splitvec.push(newsplit);
        }
    }
    Ok(())
}

/// `SplitVarnode::getTrueFalse`: the (true, false) blocks of the CBRANCH `boolop`.
pub(super) fn get_true_false(fd: &Funcdata, boolop: OpId, flip: bool) -> (Option<BlockId>, Option<BlockId>) {
    let Some(p) = parent(fd, boolop) else { return (None, None) };
    let outs = &fd.blocks.block(p).outs;
    // getFalseOut is out edge 0, getTrueOut edge 1
    let (t, f) = (outs.get(1).map(|e| e.point), outs.first().map(|e| e.point));
    if fd.op(boolop).flags.has(OpFlags::BOOLEAN_FLIP) != flip {
        (f, t)
    } else {
        (t, f)
    }
}

/// `SplitVarnode::otherwiseEmpty`: the block of `branchop` has one way in and holds only the
/// branch and the op making its condition.
pub(super) fn otherwise_empty(fd: &Funcdata, branchop: OpId) -> Result<bool> {
    let Some(bl) = parent(fd, branchop) else { return Ok(false) };
    if fd.blocks.block(bl).ins.len() != 1 {
        return Ok(false);
    }
    let otherop = def(fd, inp(fd, branchop, 1)?);
    Ok(fd.blocks.block(bl).ops.iter().all(|&op| Some(op) == otherop || op == branchop))
}

/// `SplitVarnode::prepareBinaryOp`.
pub(super) fn prepare_binary_op(
    fd: &Funcdata,
    out: &mut SplitVarnode,
    in1: &mut SplitVarnode,
    in2: &mut SplitVarnode,
) -> Result<Option<OpId>> {
    let Some(existop) = out.find_out_exist(fd)? else { return Ok(None) };
    if !in1.is_whole_feasible(fd, existop)? || !in2.is_whole_feasible(fd, existop)? {
        return Ok(None);
    }
    Ok(Some(existop))
}

/// `SplitVarnode::createBinaryOp`.
pub(super) fn create_binary_op(
    fd: &mut Funcdata,
    out: &mut SplitVarnode,
    in1: &mut SplitVarnode,
    in2: &mut SplitVarnode,
    existop: OpId,
    opc: Opcode,
) -> Result<()> {
    out.find_create_output_whole(fd)?;
    in1.find_create_whole(fd)?;
    in2.find_create_whole(fd)?;
    create_whole_op(fd, out, &[in1.whole_vn()?, in2.whole_vn()?], existop, opc)
}

/// The shared tail of `createBinaryOp` and `createShiftOp`: the whole op before `existop`
/// with the pieces rebuilt from it, or `existop` (the PIECE making the output) changed into it.
fn create_whole_op(fd: &mut Funcdata, out: &SplitVarnode, ins: &[VarnodeId], existop: OpId, opc: Opcode) -> Result<()> {
    if code(fd, existop) != Piece {
        let newop = fd.new_op(opc, op_addr(fd, existop));
        fd.op_set_output(newop, out.whole_vn()?)?;
        for (i, &v) in ins.iter().enumerate() {
            fd.op_set_input(newop, v, i)?;
        }
        fd.op_insert_before(newop, existop)?;
        out.build_pieces_from_whole(fd)
    } else {
        fd.op_set_opcode(existop, opc);
        for (i, &v) in ins.iter().enumerate() {
            fd.op_set_input(existop, v, i)?;
        }
        Ok(())
    }
}

/// `SplitVarnode::prepareShiftOp`.
pub(super) fn prepare_shift_op(fd: &Funcdata, out: &mut SplitVarnode, inv: &mut SplitVarnode) -> Result<Option<OpId>> {
    let Some(existop) = out.find_out_exist(fd)? else { return Ok(None) };
    Ok(inv.is_whole_feasible(fd, existop)?.then_some(existop))
}

/// `SplitVarnode::createShiftOp`.
pub(super) fn create_shift_op(
    fd: &mut Funcdata,
    out: &mut SplitVarnode,
    inv: &mut SplitVarnode,
    mut sa: VarnodeId,
    existop: OpId,
    opc: Opcode,
) -> Result<()> {
    out.find_create_output_whole(fd)?;
    inv.find_create_whole(fd)?;
    if is_const(fd, sa) {
        sa = fd.new_constant(sz(fd, sa), off(fd, sa));
    }
    create_whole_op(fd, out, &[inv.whole_vn()?, sa], existop, opc)
}

/// `SplitVarnode::prepareBoolOp`.
pub(super) fn prepare_bool_op(
    fd: &Funcdata,
    in1: &mut SplitVarnode,
    in2: &mut SplitVarnode,
    testop: OpId,
) -> Result<bool> {
    Ok(in1.is_whole_feasible(fd, testop)? && in2.is_whole_feasible(fd, testop)?)
}

/// `SplitVarnode::replaceBoolOp`.
pub(super) fn replace_bool_op(
    fd: &mut Funcdata,
    boolop: OpId,
    in1: &mut SplitVarnode,
    in2: &mut SplitVarnode,
    opc: Opcode,
) -> Result<()> {
    in1.find_create_whole(fd)?;
    in2.find_create_whole(fd)?;
    fd.op_set_opcode(boolop, opc);
    fd.op_set_input(boolop, in1.whole_vn()?, 0)?;
    fd.op_set_input(boolop, in2.whole_vn()?, 1)
}

/// `SplitVarnode::createBoolOp`: a new comparison of the wholes feeds the CBRANCH.
pub(super) fn create_bool_op(
    fd: &mut Funcdata,
    cbranch: OpId,
    in1: &mut SplitVarnode,
    in2: &mut SplitVarnode,
    opc: Opcode,
) -> Result<()> {
    let addrop = def(fd, inp(fd, cbranch, 1)?).unwrap_or(cbranch);
    in1.find_create_whole(fd)?;
    in2.find_create_whole(fd)?;
    let ins = [in1.whole_vn()?, in2.whole_vn()?];
    let newbool = insert_new(fd, opc, op_addr(fd, addrop), 1, &ins, cbranch)?;
    fd.op_set_input(cbranch, newbool, 1)
}

/// `SplitVarnode::preparePhiOp`.
pub(super) fn prepare_phi_op(fd: &Funcdata, out: &SplitVarnode, inlist: &mut [SplitVarnode]) -> Result<Option<OpId>> {
    let Some(existop) = out.find_earliest_split_point(fd) else { return Ok(None) };
    if code(fd, existop) != Multiequal {
        return err("Trying to create phi-node double precision op with phi-node pieces");
    }
    let bl = parent(fd, existop).ok_or_else(|| LowlevelError("MULTIEQUAL outside a block".into()))?;
    for (i, sv) in inlist.iter_mut().enumerate() {
        let inbl = fd.blocks.block(bl).ins.get(i).map(|e| e.point);
        let inbl = inbl.ok_or_else(|| LowlevelError("MULTIEQUAL with more inputs than its block".into()))?;
        if !sv.is_whole_phi_feasible(fd, inbl)? {
            return Ok(None);
        }
    }
    Ok(Some(existop))
}

/// `SplitVarnode::createPhiOp`.
pub(super) fn create_phi_op(
    fd: &mut Funcdata,
    out: &mut SplitVarnode,
    inlist: &mut [SplitVarnode],
    existop: OpId,
) -> Result<()> {
    out.find_create_output_whole(fd)?;
    for sv in inlist.iter_mut() {
        sv.find_create_whole(fd)?;
    }
    let newop = fd.new_op(Multiequal, op_addr(fd, existop));
    fd.op_set_output(newop, out.whole_vn()?)?;
    for (i, sv) in inlist.iter().enumerate() {
        fd.op_set_input(newop, sv.whole_vn()?, i)?;
    }
    fd.op_insert_before(newop, existop)?;
    out.build_pieces_from_whole(fd)
}

/// `SplitVarnode::replaceIndirectOp`.
pub(super) fn replace_indirect_op(
    fd: &mut Funcdata,
    arch: &Arch,
    out: &mut SplitVarnode,
    inv: &mut SplitVarnode,
    affector: OpId,
) -> Result<()> {
    out.create_joined_whole(fd, arch)?;
    inv.find_create_whole(fd)?;
    let newop = fd.new_indirect(affector)?;
    fd.op_set_output(newop, out.whole_vn()?)?;
    fd.set_indirect_input(newop, inv.whole_vn()?)?;
    fd.op_insert_before(newop, affector)?;
    out.build_pieces_from_whole(fd)
}

/// `SplitVarnode::replaceCopyForce`: one COPY of the whole to `addr` replaces the two COPYs.
pub(super) fn replace_copy_force(
    fd: &mut Funcdata,
    addr: (Space, u64),
    inv: &SplitVarnode,
    copylo: OpId,
    copyhi: OpId,
) -> Result<()> {
    let mut in_vn = inv.whole_vn()?;
    let return_form = fd.op(copyhi).flags.has(OpFlags::RETURN_COPY);
    if return_form && vn_addr(fd, in_vn) != addr {
        // the whole lives elsewhere: copy it into the storage first
        let p1 =
            def(fd, inp(fd, copyhi, 0)?).ok_or_else(|| LowlevelError("return copy of an unwritten piece".into()))?;
        let p2 =
            def(fd, inp(fd, copylo, 0)?).ok_or_else(|| LowlevelError("return copy of an unwritten piece".into()))?;
        let point = if order(fd, p1) < order(fd, p2) { p2 } else { p1 };
        let other_copy = fd.new_op(Copy, op_addr(fd, point));
        let vn = fd.new_varnode_out(inv.wholesize, addr.0, addr.1, other_copy);
        fd.op_set_input(other_copy, in_vn, 0)?;
        fd.op_insert_before(other_copy, point)?;
        in_vn = vn;
    }
    let whole_copy = fd.new_op(Copy, op_addr(fd, copyhi));
    let out_vn = fd.new_varnode_out(inv.wholesize, addr.0, addr.1, whole_copy);
    fd.vn_set(out_vn, VnFlags::ADDRFORCE);
    if return_form {
        fd.op_mut(whole_copy).flags.set(OpFlags::RETURN_COPY); // markReturnCopy
    }
    fd.op_set_input(whole_copy, in_vn, 0)?;
    fd.op_insert_before(whole_copy, copyhi)?;
    fd.op_destroy(copyhi);
    fd.op_destroy(copylo);
    Ok(())
}
