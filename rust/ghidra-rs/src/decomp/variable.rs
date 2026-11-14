//! Port of `variable.cc` (stage S7): high variables, the groups of SSA varnodes merging makes,
//! and `HighIntersectTest`, the cached intersection test between them. Highs live in an arena
//! ([`Highs`], in [`Funcdata::highs`]) addressed by [`HighId`]; each varnode's high, its cover
//! and the cover's dirty bit (`Varnode::high`, `cover`, `coverdirty`) are side tables there.
//!
//! Not ported: `VariablePiece`/`VariableGroup` (only `groupWith` makes them, from address-tied
//! overlaps of different sizes and from proto-partial PIECEs, which no ported rule makes: both
//! fail loudly), symbols (the local scope holds none; `localrecovery` is not ported), and
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
}

/// The high-variable state of a function: `Funcdata::highlevel_on`, the arena, the per-varnode
/// links and covers, and `HighIntersectTest`'s cache and call set.
#[derive(Debug, Clone, Default)]
pub struct Highs {
    /// `highlevel_on` (`ActionAssignHigh`)
    pub(crate) on: bool,
    highs: Vec<HighVariable>,
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
        fd.highs.get_mut(h).cover_dirty = true;
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
        fd.highs.get_mut(h).cover_dirty = true;
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
        hv.cover_dirty = true;
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

/// `HighVariable::getCover` (after an update).
pub(crate) fn h_cover(fd: &Funcdata, h: HighId) -> &Cover {
    &fd.highs.get(h).cover
}

/// Port of `HighVariable::mergeInternal` / `merge` (no pieces): `h2`'s members join `h1`.
pub(crate) fn high_merge(fd: &mut Funcdata, h1: HighId, h2: HighId, cache: bool, speculative: bool) -> Result<()> {
    if h1 == h2 {
        return Ok(());
    }
    if cache {
        move_intersect_tests(fd, h1, h2);
    }
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

/// Port of `HighIntersectTest::updateHigh`: bring the cover up to date; a stale one drops
/// the cached tests. Returns whether it was clean.
pub(crate) fn update_high(fd: &mut Funcdata, h: HighId) -> bool {
    if !fd.highs.get(h).cover_dirty {
        return true;
    }
    update_internal_cover(fd, h);
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

/// Port of `HighIntersectTest::testBlockIntersection` (pieces not ported: `relOff` is 0).
fn test_block_intersection(fd: &mut Funcdata, a: HighId, blk: i32, cover: &Cover, blist: &[VarnodeId]) -> bool {
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
                    partial_copy_shadow(fd, vn, vn2, 0)
                };
                if !shadow {
                    return true;
                }
            }
        }
    }
    false
}

/// Port of `HighIntersectTest::blockIntersection` (no pieces).
fn block_intersection(fd: &mut Funcdata, a: HighId, b: HighId, blk: i32) -> bool {
    let (ac, bc) = (h_cover(fd, a).clone(), h_cover(fd, b).clone());
    let blist = gather_block_varnodes(fd, b, blk, &ac);
    test_block_intersection(fd, a, blk, &bc, &blist)
}

/// Port of `HighIntersectTest::testUntiedCallIntersection` with `Cover::intersect(PcodeOpSet)`:
/// whether the untied high is live across a call (or guarded STORE) that may change the tied
/// one. `hasNoLocalAlias` is never set (`localrecovery` is not ported).
fn untied_call_intersection(fd: &mut Funcdata, tied: HighId, untied: HighId) -> Result<bool> {
    if h_is(fd, tied, VnFlags::PERSIST) {
        return Ok(false);
    }
    tied_varnode(fd, tied)?;
    if fd.highs.affecting.is_none() {
        fd.highs.affecting = Some(stack_affecting_ops(fd)?);
    }
    let ui = |o| op_uindex(fd, o);
    let set = fd.highs.affecting.as_ref().map(|s| s.intersects(h_cover(fd, untied), &ui));
    Ok(set.unwrap_or(false))
}

/// Port of `StackAffectingOps::populate`: every call, sorted by block
/// (`PcodeOpSet::finalize`). The STOREs of valid store guards would join, with `affectsTest`
/// reading the guard's analysed range, which is not ported (`heritage_guard.rs`): fail while
/// one exists. Without them `affectsTest` is always true.
fn stack_affecting_ops(fd: &Funcdata) -> Result<OpSet> {
    if super::heritage_guard::has_valid_guards(fd, true) {
        return err("merge: a STORE guard of the stack heritage pass would affect a merge (StackAffectingOps), and its range needs the value-set analysis (ValueSetSolver): not implemented in ghidra-rs yet");
    }
    let ops = fd.qlst.iter().map(|&c| fd.call(c).op).map(|op| (op_block_index(fd, op), fd.op(op).order, op));
    Ok(OpSet::finalize(ops.collect()))
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
