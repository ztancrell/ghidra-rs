//! Port of `variable.cc` (stage S7): high variables, the groups of SSA varnodes merging makes,
//! and `HighIntersectTest`, the cached intersection test between them. Highs live in an arena
//! ([`Highs`], in [`Funcdata::highs`]) addressed by [`HighId`]; each varnode's high, its cover
//! and the cover's dirty bit (`Varnode::high`, `cover`, `coverdirty`) are side tables there.
//!
//! `VariablePiece` and `VariableGroup` (`groupWith`, from address-tied overlaps of different
//! sizes in `mergeAddrTied`) are a piece on the high and a list of member highs in [`Highs`].
//! (Superseded: "Not ported: `VariablePiece`/`VariableGroup`", before print slice 5.)
//!
//! Not ported: the group symbol offset (`establishGroupSymbolOffset`, for proto-partial PIECEs,
//! which no ported rule makes: `groupPartials` fails loudly), symbols (the local scope holds only the locked parameters, which `merge.rs`
//! reads from the prototype in `high_symbol`; `localrecovery` is not ported), and
//! `stripType` (no ported data-type has a stripped form).

use std::collections::BTreeMap;

use super::cover::{op_block_index, op_uindex, Cover, OpSet};
use super::funcdata::Funcdata;
use super::op::OpId;
use super::types::{Meta, TypeId};
use super::varnode::{Space, VarnodeId, VnFlags};
use super::{err, Result};

/// Index of a high variable in [`Highs`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct HighId(pub(crate) u32);

/// Port of `HighVariable`, the fields the merge range uses. Flags, type and name
/// representative are derived from the members on demand (the C++ caches them behind dirty
/// bits that every member change sets, so recomputing gives the same answer).
#[derive(Debug, Clone, Default)]
pub(crate) struct HighVariable {
    /// the members, sorted by storage address (`compareJustLoc`)
    pub(crate) inst: Vec<VarnodeId>,
    /// `numMergeClasses`
    merge_classes: u32,
    /// `internalCover`, valid while `cover_dirty` is clear
    cover: Cover,
    /// `coverdirty`
    cover_dirty: bool,
    /// `copy_in1` / `copy_in2`
    pub(crate) copy_in1: bool,
    pub(crate) copy_in2: bool,
    /// `piece`: the place in a group of overlapping highs, if any
    piece: Option<VariablePiece>,
    /// `intersectdirty` and `extendcoverdirty`
    intersect_dirty: bool,
    extend_dirty: bool,
}

/// Port of `VariablePiece`: a high as a piece of a `VariableGroup`.
#[derive(Debug, Clone, Default)]
struct VariablePiece {
    /// the group, an index into `Highs::groups`
    group: u32,
    /// `groupOffset`: the byte offset within the group
    offset: i32,
    size: i32,
    /// the highs of the pieces this one overlaps (`updateIntersections`)
    intersection: Vec<HighId>,
    /// the extended cover: with the covers of the intersecting pieces
    cover: Cover,
}

/// Port of `VariableGroup`: the highs whose pieces make it up, by offset then size, and its
/// size in bytes.
#[derive(Debug, Clone, Default)]
struct VariableGroup {
    pieces: Vec<HighId>,
    size: i32,
}

impl HighVariable {
    /// `HighVariable::getNumMergeClasses`
    pub(crate) fn num_merge_classes(&self) -> u32 {
        self.merge_classes
    }
}

/// The high-variable state of a function: `Funcdata::highlevel_on`, the arena, the per-varnode
/// links and covers, and `HighIntersectTest`'s cache and call set.
#[derive(Debug, Clone, Default)]
pub struct Highs {
    /// `highlevel_on` (`ActionAssignHigh`)
    pub(crate) on: bool,
    highs: Vec<HighVariable>,
    /// the `VariableGroup`s; an emptied one stays, unused
    groups: Vec<VariableGroup>,
    of: Vec<Option<HighId>>,
    vcover: Vec<Option<Cover>>,
    vdirty: Vec<bool>,
    /// `HighIntersectTest::highedgemap`
    edges: BTreeMap<(HighId, HighId), bool>,
    /// `StackAffectingOps`, once populated
    affecting: Option<OpSet>,
    /// `Merge::copyTrims`
    pub(crate) copy_trims: Vec<OpId>,
    /// `Merge::protoPartial`: the PIECE ops `registerProtoPartialRoot` recorded (no ported rule
    /// registers one yet; `SplitDatatype::buildOutConcats` and `RulePieceStructure` will)
    pub(crate) proto_partial: Vec<OpId>,
}

impl Highs {
    pub(crate) fn get(&self, h: HighId) -> &HighVariable {
        &self.highs[h.0 as usize]
    }
    pub(crate) fn get_mut(&mut self, h: HighId) -> &mut HighVariable {
        &mut self.highs[h.0 as usize]
    }
    fn grow(&mut self, n: usize) {
        if self.of.len() < n {
            self.of.resize(n, None);
            self.vcover.resize(n, None);
            self.vdirty.resize(n, false);
        }
    }
    /// The high of `vn`, if it has one.
    pub(crate) fn of(&self, vn: VarnodeId) -> Option<HighId> {
        self.of.get(vn.0 as usize).copied().flatten()
    }
}

/// `Varnode::hasCover`: written or an input, not a constant or annotation.
pub(crate) fn vn_has_cover(fd: &Funcdata, vn: VarnodeId) -> bool {
    let v = fd.vn(vn);
    (v.is_written() || v.is_input()) && !v.is_constant() && !v.is_annotation()
}

/// `Varnode::isImplied`
pub(crate) fn vn_implied(fd: &Funcdata, vn: VarnodeId) -> bool {
    fd.vn(vn).has(VnFlags::IMPLIED)
}

/// `Varnode::setFlags(coverdirty)`: the varnode's cover and its high's are stale.
pub(crate) fn vn_cover_dirty(fd: &mut Funcdata, vn: VarnodeId) {
    fd.highs.grow(vn.0 as usize + 1);
    fd.highs.vdirty[vn.0 as usize] = true;
    if let Some(h) = fd.highs.of(vn) {
        h_cover_dirty(fd, h);
    }
}

/// Port of `Funcdata::assignHigh` (with `Varnode::calcCover`): once high variables are on, a
/// varnode that is not an annotation gets a high of its own. Called for every varnode when they
/// are switched on and for each varnode merging makes; [`high`] also assigns lazily.
pub(crate) fn assign_high(fd: &mut Funcdata, vn: VarnodeId) -> Option<HighId> {
    if !fd.highs.on || fd.vn(vn).is_annotation() {
        return None;
    }
    calc_cover(fd, vn);
    fd.highs.grow(vn.0 as usize + 1);
    if let Some(h) = fd.highs.of(vn) {
        return Some(h);
    }
    let id = HighId(fd.highs.highs.len() as u32);
    fd.highs.highs.push(HighVariable { inst: vec![vn], merge_classes: 1, cover_dirty: true, ..Default::default() });
    fd.highs.of[vn.0 as usize] = Some(id);
    Some(id)
}

/// `Varnode::calcCover` as `setVarnodeProperties` calls it: a varnode with a cover and none yet
/// gets an empty, dirty one.
pub(crate) fn calc_cover(fd: &mut Funcdata, vn: VarnodeId) {
    fd.highs.grow(vn.0 as usize + 1);
    if vn_has_cover(fd, vn) && fd.highs.vcover[vn.0 as usize].is_none() {
        fd.highs.vcover[vn.0 as usize] = Some(Cover::default());
        vn_cover_dirty(fd, vn);
    }
}

/// Port of `Funcdata::setHighLevel` (`ActionAssignHigh`).
pub(crate) fn set_high_level(fd: &mut Funcdata) {
    if fd.highs.on {
        return;
    }
    fd.highs.on = true;
    for vn in fd.loc_all() {
        assign_high(fd, vn);
    }
}

/// `Varnode::getHigh`: an error when the varnode has none (an annotation).
pub(crate) fn high(fd: &mut Funcdata, vn: VarnodeId) -> Result<HighId> {
    match assign_high(fd, vn) {
        Some(h) => Ok(h),
        None => err("Requesting non-existent high-level"),
    }
}

/// Port of `Varnode::updateCover` / `getCover`: rebuild a dirty cover. Clearing the dirty bit
/// marks the high's cover dirty, as `clearFlags(coverdirty)` does.
pub(crate) fn update_vn_cover(fd: &mut Funcdata, vn: VarnodeId) {
    fd.highs.grow(vn.0 as usize + 1);
    let i = vn.0 as usize;
    if !fd.highs.vdirty[i] {
        return;
    }
    if vn_has_cover(fd, vn) && fd.highs.vcover[i].is_some() {
        let c = super::cover::rebuild(fd, vn, &|v| vn_implied(fd, v));
        fd.highs.vcover[i] = Some(c);
    }
    fd.highs.vdirty[i] = false;
    if let Some(h) = fd.highs.of(vn) {
        h_cover_dirty(fd, h);
    }
}

/// The (updated) cover of `vn`; empty when it has none.
pub(crate) fn vn_cover(fd: &mut Funcdata, vn: VarnodeId) -> Cover {
    update_vn_cover(fd, vn);
    fd.highs.vcover[vn.0 as usize].clone().unwrap_or_default()
}

/// The stored cover of `vn` without updating it (after [`update_vn_cover`]).
pub(crate) fn vn_cover_ref(fd: &Funcdata, vn: VarnodeId) -> Option<&Cover> {
    fd.highs.vcover.get(vn.0 as usize).and_then(Option::as_ref)
}

/// `HighVariable::updateFlags`: the union of the members' flags.
pub(crate) fn hflags(fd: &Funcdata, h: HighId) -> VnFlags {
    let mut f = VnFlags::default();
    for &vn in &fd.highs.get(h).inst {
        f.set(fd.vn(vn).flags);
    }
    f
}

/// Whether some member passes `test` (for the C++ flags kept outside `Varnode::flags` here).
fn hany(fd: &Funcdata, h: HighId, test: impl Fn(&super::varnode::Varnode) -> bool) -> bool {
    fd.highs.get(h).inst.iter().any(|&vn| test(fd.vn(vn)))
}

/// `HighVariable::hasCover`
pub(crate) fn h_has_cover(fd: &Funcdata, h: HighId) -> bool {
    hany(fd, h, |v| v.is_written() || v.is_input()) && !hany(fd, h, |v| v.is_constant() || v.is_annotation())
}
pub(crate) fn h_is(fd: &Funcdata, h: HighId, f: VnFlags) -> bool {
    hflags(fd, h).has(f)
}
/// `HighVariable::isExtraOut`
pub(crate) fn h_extra_out(fd: &Funcdata, h: HighId) -> bool {
    let f = hflags(fd, h);
    f.has(VnFlags::INDIRECT_CREATION) && !f.has(VnFlags::ADDRTIED)
}

/// `Datatype::typeOrderFormal`
fn type_order_formal(fd: &Funcdata, a: TypeId, b: TypeId) -> i32 {
    if a == b {
        return 0;
    }
    if fd.types.meta(a) == Meta::Bool {
        return 1;
    }
    if fd.types.meta(b) == Meta::Bool {
        return -1;
    }
    fd.types.order(a, b)
}

/// Port of `HighVariable::getTypeRepresentative`.
fn type_representative(fd: &mut Funcdata, h: HighId) -> VarnodeId {
    let inst = fd.highs.get(h).inst.clone();
    let mut rep = inst[0];
    for &vn in &inst[1..] {
        let (rl, vl) = (fd.vn(rep).has(VnFlags::TYPELOCK), fd.vn(vn).has(VnFlags::TYPELOCK));
        if rl != vl {
            if vl {
                rep = vn;
            }
        } else {
            let (tv, tr) = (super::infertypes::vn_type(fd, vn), super::infertypes::vn_type(fd, rep));
            if type_order_formal(fd, tv, tr) < 0 {
                rep = vn;
            }
        }
    }
    rep
}

/// Port of `HighVariable::updateType` / `getType` and `isTypeLock`: the representative's type
/// and lock. ponytail: `stripType` is left out, no ported type has a stripped form.
pub(crate) fn h_type(fd: &mut Funcdata, h: HighId) -> (TypeId, bool) {
    let rep = type_representative(fd, h);
    (super::infertypes::vn_type(fd, rep), fd.vn(rep).has(VnFlags::TYPELOCK))
}

/// `HighVariable::getTiedVarnode`
pub(crate) fn tied_varnode(fd: &Funcdata, h: HighId) -> Result<VarnodeId> {
    match fd.highs.get(h).inst.iter().find(|&&vn| fd.vn(vn).has(VnFlags::ADDRTIED)) {
        Some(&vn) => Ok(vn),
        None => err("Could not find address-tied varnode"),
    }
}

/// `HighVariable::getInputVarnode`
pub(crate) fn input_varnode(fd: &Funcdata, h: HighId) -> Result<VarnodeId> {
    match fd.highs.get(h).inst.iter().find(|&&vn| fd.vn(vn).is_input()) {
        Some(&vn) => Ok(vn),
        None => err("Could not find input varnode"),
    }
}

/// `AddrSpace::getType() == IPTR_INTERNAL`: the unique space.
pub(crate) fn is_internal(fd: &Funcdata, space: Space) -> bool {
    matches!(space, Space::Sleigh(i) if Some(i) == fd.uniq)
}

/// A key naming the high of `vn` for `print raw` (`DECOMP_RAW_EXTRA`, numbered by first
/// appearance there): `None` before high variables are on or for an annotation; a varnode not
/// yet given its high (assigned lazily) is a high of its own.
pub(crate) fn high_key(fd: &Funcdata, vn: VarnodeId) -> Option<u64> {
    if !fd.highs.on || fd.vn(vn).is_annotation() {
        return None;
    }
    Some(fd.highs.of(vn).map_or(1 << 32 | u64::from(vn.0), |h| u64::from(h.0)))
}

/// `compareJustLoc`: storage address order.
fn loc_key(fd: &Funcdata, vn: VarnodeId) -> (u32, u64) {
    let v = fd.vn(vn);
    (v.space.index(), v.offset)
}

/// Port of `HighVariable::remove`: take `vn` out of its high.
pub(crate) fn high_remove(fd: &mut Funcdata, vn: VarnodeId) {
    let Some(h) = fd.highs.of(vn) else { return };
    let key = loc_key(fd, vn);
    let inst = &fd.highs.get(h).inst;
    let start = inst.partition_point(|&v| loc_key(fd, v) < key);
    if let Some(p) = inst[start..].iter().position(|&v| v == vn) {
        let hv = fd.highs.get_mut(h);
        hv.inst.remove(start + p);
        let unattached = hv.inst.is_empty();
        h_cover_dirty(fd, h);
        if unattached {
            // the high is deleted with its last member, and its piece with it
            drop_piece(fd, h);
        }
    }
    // the varnode is destroyed next: it no longer names a high
    fd.highs.of[vn.0 as usize] = None;
}

/// `HighVariable::updateInternalCover`: the union of the members' covers.
pub(crate) fn update_internal_cover(fd: &mut Funcdata, h: HighId) {
    if !fd.highs.get(h).cover_dirty {
        return;
    }
    let inst = fd.highs.get(h).inst.clone();
    let mut cover = Cover::default();
    if inst.first().is_some_and(|&v| vn_has_cover(fd, v)) {
        for &vn in &inst {
            update_vn_cover(fd, vn);
        }
        let ui = |o| op_uindex(fd, o);
        for &vn in &inst {
            if let Some(c) = vn_cover_ref(fd, vn) {
                cover.merge(c, &ui);
            }
        }
    }
    let hv = fd.highs.get_mut(h);
    hv.cover = cover;
    hv.cover_dirty = false;
}

/// `HighVariable::getCover` (after an update): the internal cover, or the extended cover of a
/// piece.
pub(crate) fn h_cover(fd: &Funcdata, h: HighId) -> &Cover {
    let hv = fd.highs.get(h);
    hv.piece.as_ref().map_or(&hv.cover, |p| &p.cover)
}

/// `HighVariable::internalCover` (after an update).
pub(crate) fn h_internal_cover(fd: &Funcdata, h: HighId) -> &Cover {
    &fd.highs.get(h).cover
}

/// Port of `HighVariable::merge`: `h2` merges into `h1`. A piece of `h2` passes to `h1`; when
/// both are pieces their groups join, and the pieces that then coincide merge too.
pub(crate) fn high_merge(fd: &mut Funcdata, h1: HighId, h2: HighId, cache: bool, speculative: bool) -> Result<()> {
    if h1 == h2 {
        return Ok(());
    }
    if cache {
        move_intersect_tests(fd, h1, h2);
    }
    match (fd.highs.get(h1).piece.is_some(), fd.highs.get(h2).piece.is_some()) {
        (false, false) => return merge_internal(fd, h1, h2, speculative),
        (true, false) => {
            mark_extend_cover_dirty(fd, h1);
            return merge_internal(fd, h1, h2, speculative);
        }
        (false, true) => {
            transfer_piece(fd, h1, h2);
            mark_extend_cover_dirty(fd, h1);
            return merge_internal(fd, h1, h2, speculative);
        }
        (true, true) => {}
    }
    if speculative {
        return err("Trying speculatively merge variables in separate groups");
    }
    for (a, b) in merge_groups(fd, h1, h2)? {
        if cache {
            move_intersect_tests(fd, a, b);
        }
        merge_internal(fd, a, b, speculative)?;
    }
    if let Some((g, _, _)) = piece_of(fd, h1) {
        mark_intersection_dirty(fd, g);
    }
    Ok(())
}

/// Port of `HighVariable::mergeInternal`: `h2`'s members join `h1`.
fn merge_internal(fd: &mut Funcdata, h1: HighId, h2: HighId, speculative: bool) -> Result<()> {
    let (c1, c2) = (fd.highs.get(h1).merge_classes, fd.highs.get(h2).merge_classes);
    if speculative {
        fd.highs.get_mut(h1).merge_classes = c1 + c2;
    } else if c1 != 1 || c2 != 1 {
        return err("Making a non-speculative merge after speculative merges have occurred");
    }
    let moved = std::mem::take(&mut fd.highs.get_mut(h2).inst);
    for &vn in &moved {
        fd.highs.of[vn.0 as usize] = Some(h1);
    }
    let mine = std::mem::take(&mut fd.highs.get_mut(h1).inst);
    // std::merge: stable, the first range wins ties
    let mut merged = Vec::with_capacity(mine.len() + moved.len());
    let (mut i, mut j) = (0, 0);
    while i < mine.len() && j < moved.len() {
        if loc_key(fd, moved[j]) < loc_key(fd, mine[i]) {
            merged.push(moved[j]);
            j += 1;
        } else {
            merged.push(mine[i]);
            i += 1;
        }
    }
    merged.extend_from_slice(&mine[i..]);
    merged.extend_from_slice(&moved[j..]);
    let (other_cover, other_dirty) = {
        let o = fd.highs.get(h2);
        (o.cover.clone(), o.cover_dirty)
    };
    let hv = fd.highs.get_mut(h1);
    hv.inst = merged;
    if !hv.cover_dirty && !other_dirty {
        let mut cover = std::mem::take(&mut hv.cover);
        cover.merge(&other_cover, &|o| op_uindex(fd, o));
        fd.highs.get_mut(h1).cover = cover;
    } else {
        hv.cover_dirty = true;
    }
    Ok(())
}

// ---- VariablePiece and VariableGroup ----

/// `VariablePiece::markIntersectionDirty`: every piece of the group recomputes its
/// intersections and its extended cover.
fn mark_intersection_dirty(fd: &mut Funcdata, group: u32) {
    for h in fd.highs.groups[group as usize].pieces.clone() {
        let hv = fd.highs.get_mut(h);
        hv.intersect_dirty = true;
        hv.extend_dirty = true;
    }
}

/// `VariablePiece::markExtendCoverDirty`: the extended covers of the piece and of the pieces it
/// intersects are stale (a dirty intersection list recomputes them anyway).
fn mark_extend_cover_dirty(fd: &mut Funcdata, h: HighId) {
    let hv = fd.highs.get(h);
    let Some(p) = &hv.piece else { return };
    if hv.intersect_dirty {
        return;
    }
    for o in p.intersection.clone() {
        fd.highs.get_mut(o).extend_dirty = true;
    }
    fd.highs.get_mut(h).extend_dirty = true;
}

/// `HighVariable::coverDirty`
fn h_cover_dirty(fd: &mut Funcdata, h: HighId) {
    fd.highs.get_mut(h).cover_dirty = true;
    mark_extend_cover_dirty(fd, h);
}

/// The key of `VariableGroup::PieceCompareByOffset`: the offset, then the size.
fn piece_key(fd: &Funcdata, h: HighId) -> Option<(i32, i32)> {
    fd.highs.get(h).piece.as_ref().map(|p| (p.offset, p.size))
}

/// `VariableGroup::addPiece` of the piece `h` already holds.
fn group_add(fd: &mut Funcdata, h: HighId, group: u32) -> Result<()> {
    let k = piece_key(fd, h);
    let pieces = &fd.highs.groups[group as usize].pieces;
    let at = pieces.partition_point(|&x| piece_key(fd, x) < k);
    if pieces.get(at).is_some_and(|&x| piece_key(fd, x) == k) {
        return err("Duplicate VariablePiece");
    }
    let end = k.map_or(0, |(o, s)| o + s);
    let g = &mut fd.highs.groups[group as usize];
    g.pieces.insert(at, h);
    g.size = g.size.max(end);
    if let Some(p) = &mut fd.highs.get_mut(h).piece {
        p.group = group;
    }
    Ok(())
}

/// `VariableGroup::removePiece` (the size is not adjusted).
fn group_remove(fd: &mut Funcdata, h: HighId, group: u32) {
    fd.highs.groups[group as usize].pieces.retain(|&x| x != h);
}

/// The `VariablePiece` constructor: `h` becomes a piece at `offset` of the group of `grp`, or
/// of a new group.
fn new_piece(fd: &mut Funcdata, h: HighId, offset: i32, grp: Option<HighId>) -> Result<()> {
    let size = fd.highs.get(h).inst.first().map_or(0, |&v| fd.vn(v).size as i32);
    let group = match grp.and_then(|g| piece_of(fd, g)) {
        Some((g, _, _)) => g,
        None => {
            fd.highs.groups.push(VariableGroup::default());
            fd.highs.groups.len() as u32 - 1
        }
    };
    fd.highs.get_mut(h).piece = Some(VariablePiece { group, offset, size, ..Default::default() });
    group_add(fd, h, group)
}

/// The `VariablePiece` destructor: the piece leaves its group, whose other pieces recompute
/// their intersections.
fn drop_piece(fd: &mut Funcdata, h: HighId) {
    if let Some(p) = fd.highs.get_mut(h).piece.take() {
        group_remove(fd, h, p.group);
        mark_intersection_dirty(fd, p.group);
    }
}

/// `VariableGroup::adjustOffsets`
fn adjust_offsets(fd: &mut Funcdata, group: u32, amt: i32) {
    for h in fd.highs.groups[group as usize].pieces.clone() {
        if let Some(p) = &mut fd.highs.get_mut(h).piece {
            p.offset += amt;
        }
    }
    fd.highs.groups[group as usize].size += amt;
}

/// `VariablePiece::transferGroup`
fn transfer_group(fd: &mut Funcdata, h: HighId, from: u32, to: u32) -> Result<()> {
    group_remove(fd, h, from);
    group_add(fd, h, to)
}

/// The group, the offset in it and the size of the piece of `h` (`HighVariable::piece`).
pub(crate) fn piece_of(fd: &Funcdata, h: HighId) -> Option<(u32, i32, i32)> {
    fd.highs.get(h).piece.as_ref().map(|p| (p.group, p.offset, p.size))
}

/// `VariableGroup::getSize`
pub(crate) fn group_size(fd: &Funcdata, group: u32) -> i32 {
    fd.highs.groups[group as usize].size
}

/// `VariablePiece::updateIntersections`: the other pieces of the group overlapping this one.
pub(crate) fn update_intersections(fd: &mut Funcdata, h: HighId) {
    let Some((group, off, size)) = piece_of(fd, h) else { return };
    if !fd.highs.get(h).intersect_dirty {
        return;
    }
    let end = off + size;
    let list: Vec<HighId> = fd.highs.groups[group as usize]
        .pieces
        .iter()
        .copied()
        .filter(|&o| o != h && piece_of(fd, o).is_some_and(|(_, ooff, osize)| end > ooff && off < ooff + osize))
        .collect();
    let hv = fd.highs.get_mut(h);
    if let Some(p) = &mut hv.piece {
        p.intersection = list;
    }
    hv.intersect_dirty = false;
}

/// The pieces `h`'s piece intersects (`getIntersection`, as last computed): each high, its
/// offset from `h`'s piece and its size.
pub(crate) fn piece_intersections(fd: &Funcdata, h: HighId) -> Vec<(HighId, i32, i32)> {
    let Some(p) = &fd.highs.get(h).piece else { return Vec::new() };
    p.intersection.iter().filter_map(|&o| piece_of(fd, o).map(|(_, ooff, osize)| (o, ooff - p.offset, osize))).collect()
}

/// Port of `HighVariable::updateCover`: the internal cover, and for a piece its intersections
/// and the extended cover (`VariablePiece::updateCover`: its own cover and those of the pieces
/// it intersects).
pub(crate) fn update_cover(fd: &mut Funcdata, h: HighId) {
    if fd.highs.get(h).piece.is_none() {
        return update_internal_cover(fd, h);
    }
    update_intersections(fd, h);
    let hv = fd.highs.get(h);
    if !hv.cover_dirty && !hv.extend_dirty {
        return;
    }
    update_internal_cover(fd, h);
    let mut cover = fd.highs.get(h).cover.clone();
    for (o, _, _) in piece_intersections(fd, h) {
        update_internal_cover(fd, o);
        cover.merge(&fd.highs.get(o).cover, &|x| op_uindex(fd, x));
    }
    let hv = fd.highs.get_mut(h);
    if let Some(p) = &mut hv.piece {
        p.cover = cover;
    }
    hv.extend_dirty = false;
}

/// Port of `HighVariable::groupWith`: `h` and `h2` become pieces of one group, `h` at `off`
/// bytes from `h2`.
pub(crate) fn group_with(fd: &mut Funcdata, h: HighId, off: i32, h2: HighId) -> Result<()> {
    if h == h2 {
        return err("groupWith: a variable grouped with itself");
    }
    match (piece_of(fd, h), piece_of(fd, h2)) {
        (None, None) => {
            new_piece(fd, h2, 0, None)?;
            new_piece(fd, h, off, Some(h2))?;
            if let Some((g2, _, _)) = piece_of(fd, h2) {
                mark_intersection_dirty(fd, g2);
            }
        }
        (None, Some((g2, off2, _))) => {
            if !fd.highs.get(h2).intersect_dirty {
                mark_intersection_dirty(fd, g2);
            }
            let hv = fd.highs.get_mut(h);
            hv.intersect_dirty = true;
            hv.extend_dirty = true;
            new_piece(fd, h, off + off2, Some(h2))?;
        }
        (Some((g, poff, _)), None) => {
            let mut hi2_off = poff - off;
            if hi2_off < 0 {
                adjust_offsets(fd, g, -hi2_off);
                hi2_off = 0;
            }
            if !fd.highs.get(h).intersect_dirty {
                mark_intersection_dirty(fd, g);
            }
            let hv = fd.highs.get_mut(h2);
            hv.intersect_dirty = true;
            hv.extend_dirty = true;
            new_piece(fd, h2, hi2_off, Some(h))?;
        }
        (Some((g, poff, _)), Some((g2, off2, _))) => {
            let off_diff = off2 + off - poff;
            if off_diff != 0 {
                adjust_offsets(fd, g, off_diff);
            }
            // combineGroups: every piece of this group moves to the other
            if g != g2 {
                for x in fd.highs.groups[g as usize].pieces.clone() {
                    transfer_group(fd, x, g, g2)?;
                }
            }
            mark_intersection_dirty(fd, g2);
        }
    }
    Ok(())
}

/// `HighVariable::transferPiece`: `h1` takes over the piece of `h2`, which is merging into it.
fn transfer_piece(fd: &mut Funcdata, h1: HighId, h2: HighId) {
    let o = fd.highs.get_mut(h2);
    let Some(p) = o.piece.take() else { return };
    let (idirty, edirty) = (std::mem::take(&mut o.intersect_dirty), std::mem::take(&mut o.extend_dirty));
    let group = p.group;
    let hv = fd.highs.get_mut(h1);
    hv.piece = Some(p);
    hv.intersect_dirty |= idirty;
    hv.extend_dirty |= edirty;
    // the piece keeps its place in the group and in the other pieces' intersections
    for x in fd.highs.groups[group as usize].pieces.clone() {
        if let Some(q) = &mut fd.highs.get_mut(x).piece {
            q.intersection.iter_mut().filter(|o| **o == h2).for_each(|o| *o = h1);
        }
    }
    fd.highs.groups[group as usize].pieces.iter_mut().filter(|o| **o == h2).for_each(|o| *o = h1);
}

/// Port of `VariablePiece::mergeGroups`: the group of `h2` joins the group of `h1`, lined up on
/// the two pieces. A piece with the same offset and size as one already there is dropped and
/// its high returned paired with that one, to be merged.
fn merge_groups(fd: &mut Funcdata, h1: HighId, h2: HighId) -> Result<Vec<(HighId, HighId)>> {
    let (Some((g1, off1, _)), Some((g2, off2, _))) = (piece_of(fd, h1), piece_of(fd, h2)) else {
        return err("mergeGroups: a variable without a piece");
    };
    if g1 == g2 {
        return err("Merging two variables of one VariableGroup");
    }
    let diff = off1 - off2;
    if diff > 0 {
        adjust_offsets(fd, g2, diff);
    } else if diff < 0 {
        adjust_offsets(fd, g1, -diff);
    }
    let mut pairs = Vec::new();
    for x in fd.highs.groups[g2 as usize].pieces.clone() {
        let key = piece_key(fd, x);
        let found = fd.highs.groups[g1 as usize].pieces.iter().copied().find(|&m| piece_key(fd, m) == key);
        match found {
            Some(m) => {
                pairs.push((m, x));
                drop_piece(fd, x);
            }
            None => transfer_group(fd, x, g2, g1)?,
        }
    }
    Ok(pairs)
}

/// Port of `HighIntersectTest::updateHigh`: bring the cover up to date; a stale one
/// (`isCoverDirty`: the internal or the extended cover) drops the cached tests. Returns whether
/// it was clean.
pub(crate) fn update_high(fd: &mut Funcdata, h: HighId) -> bool {
    let hv = fd.highs.get(h);
    if !hv.cover_dirty && !hv.extend_dirty {
        return true;
    }
    update_cover(fd, h);
    purge_high(fd, h);
    false
}

/// The cached tests of `h`, as (other high, intersects).
fn tests_of(fd: &Funcdata, h: HighId) -> Vec<(HighId, bool)> {
    fd.highs.edges.range((h, HighId(0))..=(h, HighId(u32::MAX))).map(|(k, &v)| (k.1, v)).collect()
}

/// Port of `HighIntersectTest::purgeHigh`.
fn purge_high(fd: &mut Funcdata, h: HighId) {
    for (b, _) in tests_of(fd, h) {
        fd.highs.edges.remove(&(h, b));
        fd.highs.edges.remove(&(b, h));
    }
}

/// Port of `HighIntersectTest::moveIntersectTests`: before `h2` merges into `h1`, keep the
/// tests still valid for the result.
fn move_intersect_tests(fd: &mut Funcdata, h1: HighId, h2: HighId) {
    let mut yes = Vec::new();
    let mut no = std::collections::HashSet::new();
    for (b, v) in tests_of(fd, h2) {
        if b == h1 {
            continue;
        }
        if v {
            yes.push(b);
        } else {
            no.insert(b);
        }
    }
    purge_high(fd, h2);
    for (b, v) in tests_of(fd, h1) {
        if !v && !no.contains(&b) {
            fd.highs.edges.remove(&(b, h1));
            fd.highs.edges.remove(&(h1, b));
        }
    }
    for b in yes {
        fd.highs.edges.insert((h1, b), true);
        fd.highs.edges.insert((b, h1), true);
    }
}

/// Port of `HighIntersectTest::intersection`: whether two highs' covers intersect in a way
/// that forbids merging them.
pub(crate) fn intersection(fd: &mut Funcdata, a: HighId, b: HighId) -> Result<bool> {
    if a == b {
        return Ok(false);
    }
    let ares = update_high(fd, a);
    let bres = update_high(fd, b);
    if ares && bres {
        if let Some(&r) = fd.highs.edges.get(&(a, b)) {
            return Ok(r);
        }
    }
    let blocks = h_cover(fd, a).intersect_list(h_cover(fd, b), 2, &|o| op_uindex(fd, o));
    let mut res = false;
    for blk in blocks {
        if block_intersection(fd, a, b, blk) {
            res = true;
            break;
        }
    }
    if !res {
        let (at, bt) = (h_is(fd, a, VnFlags::ADDRTIED), h_is(fd, b, VnFlags::ADDRTIED));
        if at != bt {
            res = if at { untied_call_intersection(fd, a, b)? } else { untied_call_intersection(fd, b, a)? };
        }
    }
    fd.highs.edges.insert((a, b), res);
    fd.highs.edges.insert((b, a), res);
    Ok(res)
}

/// Port of `HighIntersectTest::gatherBlockVarnodes`.
fn gather_block_varnodes(fd: &mut Funcdata, a: HighId, blk: i32, cover: &Cover) -> Vec<VarnodeId> {
    let inst = fd.highs.get(a).inst.clone();
    let mut res = Vec::new();
    for vn in inst {
        let c = vn_cover(fd, vn);
        if 1 < c.intersect_by_block(blk, cover, &|o| op_uindex(fd, o)) {
            res.push(vn);
        }
    }
    res
}

/// Port of `HighIntersectTest::testBlockIntersection`: `rel_off` is the offset of `a` from the
/// high the varnodes of `blist` come from.
fn test_block_intersection(
    fd: &mut Funcdata,
    a: HighId,
    blk: i32,
    cover: &Cover,
    rel_off: i32,
    blist: &[VarnodeId],
) -> bool {
    let inst = fd.highs.get(a).inst.clone();
    for vn in inst {
        let c = vn_cover(fd, vn);
        if 2 > c.intersect_by_block(blk, cover, &|o| op_uindex(fd, o)) {
            continue;
        }
        for &vn2 in blist {
            let c2 = vn_cover(fd, vn2);
            if 1 < c2.intersect_by_block(blk, &c, &|o| op_uindex(fd, o)) {
                let shadow = if fd.vn(vn).size == fd.vn(vn2).size {
                    copy_shadow(fd, vn, vn2)
                } else {
                    partial_copy_shadow(fd, vn, vn2, rel_off)
                };
                if !shadow {
                    return true;
                }
            }
        }
    }
    false
}

/// Port of `HighIntersectTest::blockIntersection`: the two highs, then each with the pieces
/// the other intersects, at their relative offsets.
fn block_intersection(fd: &mut Funcdata, a: HighId, b: HighId, blk: i32) -> bool {
    let (ac, bc) = (h_cover(fd, a).clone(), h_cover(fd, b).clone());
    let blist = gather_block_varnodes(fd, b, blk, &ac);
    if test_block_intersection(fd, a, blk, &bc, 0, &blist) {
        return true;
    }
    let a_pieces = piece_intersections(fd, a);
    for &(inter, off, _) in &a_pieces {
        if test_block_intersection(fd, inter, blk, &bc, off, &blist) {
            return true;
        }
    }
    for (b_piece, b_off, b_size) in piece_intersections(fd, b) {
        let blist = gather_block_varnodes(fd, b_piece, blk, &ac);
        if test_block_intersection(fd, a, blk, &bc, -b_off, &blist) {
            return true;
        }
        for &(inter, a_off, size) in &a_pieces {
            let off = a_off - b_off;
            // whether the piece of a and the piece of b intersect at all
            if (off > 0 && off >= b_size) || (off < 0 && -off >= size) {
                continue;
            }
            if test_block_intersection(fd, inter, blk, &bc, off, &blist) {
                return true;
            }
        }
    }
    false
}

/// Port of `HighIntersectTest::testUntiedCallIntersection` with `Cover::intersect(PcodeOpSet)`:
/// whether the untied high is live across a call (or guarded STORE) that may change the tied
/// one. `hasNoLocalAlias` is never set (`localrecovery` is not ported).
fn untied_call_intersection(fd: &mut Funcdata, tied: HighId, untied: HighId) -> Result<bool> {
    if h_is(fd, tied, VnFlags::PERSIST) {
        return Ok(false);
    }
    let rep = tied_varnode(fd, tied)?;
    if fd.highs.affecting.is_none() {
        fd.highs.affecting = Some(stack_affecting_ops(fd));
    }
    let ui = |o| op_uindex(fd, o);
    // StackAffectingOps::affectsTest: a STORE with a guard only changes what its range holds
    let (space, off) = (fd.vn(rep).space, fd.vn(rep).offset);
    let affects = |op: OpId| {
        fd.op(op).opc != super::opcode::Opcode::Store
            || fd.heritage.store_guards.iter().find(|g| g.op == op).is_none_or(|g| g.is_guarded(space, off))
    };
    let set = fd.highs.affecting.as_ref().map(|s| s.intersects(h_cover(fd, untied), &ui, &affects));
    Ok(set.unwrap_or(false))
}

/// Port of `StackAffectingOps::populate`: every call and the STORE of every valid store guard,
/// sorted by block (`PcodeOpSet::finalize`).
fn stack_affecting_ops(fd: &Funcdata) -> OpSet {
    let calls = fd.qlst.iter().map(|&c| fd.call(c).op);
    let stores = fd.heritage.store_guards.iter().filter(|g| g.is_valid(fd, super::opcode::Opcode::Store)).map(|g| g.op);
    OpSet::finalize(calls.chain(stores).map(|op| (op_block_index(fd, op), fd.op(op).order, op)).collect())
}

/// Port of `Varnode::copyShadow`: the two hold the same value through COPYs.
pub(crate) fn copy_shadow(fd: &Funcdata, a: VarnodeId, b: VarnodeId) -> bool {
    if a == b {
        return true;
    }
    let mut vn = a;
    while let Some(src) = copy_source(fd, vn) {
        vn = src;
        if vn == b {
            return true;
        }
    }
    let mut op2 = b;
    while let Some(src) = copy_source(fd, op2) {
        op2 = src;
        if vn == op2 {
            return true;
        }
    }
    false
}

/// The input of the COPY writing `vn`, if a COPY writes it.
fn copy_source(fd: &Funcdata, vn: VarnodeId) -> Option<VarnodeId> {
    let op = fd.vn(vn).def?;
    let o = fd.op(op);
    (o.opc == super::opcode::Opcode::Copy).then(|| o.ins[0])
}

/// Follow COPYs back to the first varnode not written by one.
fn copy_root(fd: &Funcdata, mut vn: VarnodeId) -> VarnodeId {
    while let Some(src) = copy_source(fd, vn) {
        vn = src;
    }
    vn
}

/// Whether `vn` reaches `target` through COPYs (itself included).
fn copies_to(fd: &Funcdata, mut vn: VarnodeId, target: VarnodeId) -> bool {
    loop {
        if vn == target {
            return true;
        }
        match copy_source(fd, vn) {
            Some(s) => vn = s,
            None => return false,
        }
    }
}

/// Port of `Varnode::findSubpieceShadow`.
fn find_subpiece_shadow(fd: &Funcdata, me: VarnodeId, least: u32, whole: VarnodeId, mut recurse: i32) -> bool {
    use super::opcode::Opcode;
    let vn = copy_root(fd, me);
    let Some(def) = fd.vn(vn).def else {
        if fd.vn(vn).is_constant() {
            let w = copy_root(fd, whole);
            if !fd.vn(w).is_constant() {
                return false;
            }
            let off = fd.vn(w).offset.checked_shr(least * 8).unwrap_or(0) & super::rangeutil::calc_mask(fd.vn(vn).size);
            return off == fd.vn(vn).offset;
        }
        return false;
    };
    let d = fd.op(def);
    match d.opc {
        Opcode::Subpiece => {
            let tmp = d.ins[0];
            if fd.vn(d.ins[1]).offset != u64::from(least) || fd.vn(tmp).size != fd.vn(whole).size {
                return false;
            }
            copies_to(fd, tmp, whole)
        }
        Opcode::Multiequal => {
            recurse += 1;
            if recurse > 1 {
                return false;
            }
            let w = copy_root(fd, whole);
            let Some(big) = fd.vn(w).def else { return false };
            let bo = fd.op(big);
            if bo.opc != Opcode::Multiequal || bo.parent != d.parent {
                return false;
            }
            d.ins.iter().zip(&bo.ins).all(|(&s, &b)| find_subpiece_shadow(fd, s, least, b, recurse))
        }
        _ => false,
    }
}

/// Port of `Varnode::findPieceShadow`.
fn find_piece_shadow(fd: &Funcdata, me: VarnodeId, mut least: u32, piece: VarnodeId) -> bool {
    let vn = copy_root(fd, me);
    let Some(def) = fd.vn(vn).def else { return false };
    let d = fd.op(def);
    if d.opc != super::opcode::Opcode::Piece {
        return false;
    }
    let mut tmp = d.ins[1];
    if least >= fd.vn(tmp).size {
        least -= fd.vn(tmp).size;
        tmp = d.ins[0];
    } else if fd.vn(piece).size + least > fd.vn(tmp).size {
        return false;
    }
    if least == 0 && fd.vn(tmp).size == fd.vn(piece).size {
        return copies_to(fd, tmp, piece);
    }
    find_piece_shadow(fd, tmp, least, piece)
}

/// Port of `Varnode::partialCopyShadow` (little-endian spaces: every x86 space).
pub(crate) fn partial_copy_shadow(fd: &Funcdata, me: VarnodeId, op2: VarnodeId, rel_off: i32) -> bool {
    let (s1, s2) = (fd.vn(me).size, fd.vn(op2).size);
    let (vn, big, rel) = match s1.cmp(&s2) {
        std::cmp::Ordering::Less => (me, op2, rel_off),
        std::cmp::Ordering::Greater => (op2, me, -rel_off),
        std::cmp::Ordering::Equal => return false,
    };
    if rel < 0 || rel as u32 + fd.vn(vn).size > fd.vn(big).size {
        return false;
    }
    let least = rel as u32;
    find_subpiece_shadow(fd, vn, least, big, 0) || find_piece_shadow(fd, big, least, vn)
}
