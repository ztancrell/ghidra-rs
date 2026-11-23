//! `ActionRestructureVarnode` and `ActionMappedLocalSync`: the symbols of the local scope
//! (varmap.cc: `ScopeLocal::restructureVarnode` with `MapState`, `RangeHint`,
//! `fakeInputSymbols`, `markUnaliased`, `checkUnaliasedReturn`, `annotateRawStackPtr`),
//! `Funcdata::syncVarnodesWithSymbols` (funcdata_varnode.cc),
//! `Funcdata::opCollapseIndirectsForAlias` (funcdata_op.cc, what `RuleAliasUpdate` runs) and
//! `ActionRestructureVarnode::protectSwitchPaths` (coreaction.cc).
//!
//! One port serves the `decompile` root and the partial function of jump-table recovery. The
//! partial function has no data-types (`typerecovery` is not a group of the `jumptable` root),
//! so there every range hint has the unknown type of its size. A symbol is an entry of
//! `LocalMap` (its range and flags, varmap.rs) with a typed, unnamed symbol of the local scope
//! behind it (`Funcdata::symtab`), which type propagation, naming and the printer read.
//! (Superseded: "for the partial function of jump-table recovery", "The action of the
//! `decompile` root stays unported".)
//!
//! What the port leaves out fails with an error naming it ("not ported"). In the partial
//! function flow.rs then recovers the table without this action (the older test on the
//! INDIRECTs of stack varnodes); in the `decompile` root the decompile fails:
//! - a load or store guard whose pointer has a data-type needing resolution (`getTypeReadFacing`)
//!   or points to a union,
//! - a structure or union among the hints (`TypeStruct::getSubType`, partial structures),
//! - a locked prototype with parameters (its symbols are not in the scope).
//!
//! A piece of an array symbol is a partial struct (`getTypePartialStruct`, in
//! `ActionMappedLocalSync`), which `MapState::addFixedType` turns into an open hint of the
//! element. (Superseded: "a piece of an array symbol as a data-type ... fails".)
//!
//! The load and store guards give open hints (`MapState::addGuard`, with the value-set ranges
//! of `heritage_guard.rs`). (Superseded: "a valid load or store guard ... not ported".)

use super::heritage_guard::{stack_pointer_input, LoadGuard};
use super::infertypes::{vn_type, vn_type_facing};
use super::op::{OpFlags, OpId};
use super::opcode::Opcode;
use super::types::{Kind, Meta, TypeFactory, TypeId};
use super::varmap::{gather_additive_base, gather_offset, mark_not_mapped, LocalMap};
use super::varnode::{Space, VarnodeId, VnFlags};
use super::{err, Arch, Funcdata, Result};

fn unported<T>(what: &str) -> Result<T> {
    err(format!("restructure_varnode: {what}: not ported"))
}

/// `RangeHint::RangeType`, in its order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum RangeType {
    Fixed,
    Open,
    Endpoint,
}

/// `RangeHint::copy_constant` and `backfill` (`typelock` is never set: no symbol of the scope
/// is type-locked here).
const COPY_CONSTANT: u32 = 2;
const BACKFILL: u32 = 4;

/// What the hints read of the data-types: the factory and the unknown types of 1, 2, 4 and 8
/// bytes (`RangeHint::merge` gives up on a type with one of them).
#[derive(Clone, Copy)]
struct Types<'a> {
    f: &'a TypeFactory,
    unk: [TypeId; 4],
}

impl Types<'_> {
    /// `Datatype::getAlignSize`.
    fn align(&self, t: TypeId) -> i64 {
        i64::from(self.f.align_size(t))
    }

    /// An array of unknown bytes.
    fn unknown_array(&self, t: TypeId) -> bool {
        matches!(self.f.get(t).kind, Kind::Array { elem, .. } if self.f.meta(elem) == Meta::Unknown)
    }
}

/// The unknown types of 1, 2, 4 and 8 bytes.
fn unknown_types(types: &mut TypeFactory) -> [TypeId; 4] {
    [1, 2, 4, 8].map(|s| types.base(s, Meta::Unknown))
}

/// Port of `RangeHint`.
#[derive(Debug, Clone, Copy)]
struct RangeHint {
    start: u64,
    size: i32,
    sstart: i64,
    ty: TypeId,
    flags: u32,
    rt: RangeType,
    highind: i32,
}

impl RangeHint {
    /// `RangeHint::compare`.
    fn key(&self) -> (i64, i32, RangeType, u32, i32) {
        (self.sstart, self.size, self.rt, self.flags, self.highind)
    }

    fn is_backfill(&self) -> bool {
        self.flags & BACKFILL != 0
    }

    /// `RangeHint::isConstAbsorbable`.
    fn is_const_absorbable(&self, b: &RangeHint, t: Types) -> bool {
        if b.flags & COPY_CONSTANT == 0 || b.size < self.size {
            return false;
        }
        if !matches!(t.f.meta(self.ty), Meta::Int | Meta::Uint | Meta::Bool | Meta::Float) {
            return false;
        }
        if !matches!(t.f.meta(b.ty), Meta::Unknown | Meta::Int | Meta::Uint) {
            return false;
        }
        let len = if self.highind > 0 { i64::from(self.highind) * t.align(self.ty) } else { i64::from(self.size) };
        b.sstart <= self.sstart + len
    }

    /// `RangeHint::reconcile`: whether the two intersecting hints line up.
    fn reconcile(&self, b: &RangeHint, t: Types) -> bool {
        // b is the one with the smaller aligned size
        let (a, b) = if t.align(self.ty) < t.align(b.ty) { (b, self) } else { (self, b) };
        let mut off = (b.sstart - a.sstart).rem_euclid(t.align(a.ty));
        let mut sub = Some(a.ty);
        while let Some(s) = sub.filter(|&s| t.align(s) > t.align(b.ty)) {
            sub = t.f.sub_type(s, off).map(|(n, o)| {
                off = o;
                n
            });
        }
        if sub.is_some_and(|s| t.align(s) == t.align(b.ty)) {
            return true;
        }
        if b.rt == RangeType::Open && b.is_const_absorbable(a, t) {
            return true;
        }
        if !matches!(t.f.meta(a.ty), Meta::Struct | Meta::Union) && !t.unknown_array(a.ty) {
            return false;
        }
        // b looks like a partial or combined data-type
        matches!(t.f.meta(b.ty), Meta::Unknown | Meta::Int | Meta::Uint) || t.unknown_array(b.ty)
    }

    /// `RangeHint::contain`.
    fn contain(&self, b: &RangeHint) -> bool {
        self.sstart == b.sstart || b.sstart + i64::from(b.size) <= self.sstart + i64::from(self.size)
    }

    /// `RangeHint::preferred`.
    fn preferred(&self, b: &RangeHint, reconcile: bool, t: Types) -> bool {
        if self.start != b.start {
            return true;
        }
        if self.rt == RangeType::Open && b.rt != RangeType::Open {
            if !reconcile {
                return false;
            }
            if self.is_const_absorbable(b, t) {
                return true;
            }
        } else if b.rt == RangeType::Open && self.rt != RangeType::Open {
            if !reconcile {
                return true;
            }
            if b.is_const_absorbable(self, t) {
                return false;
            }
        } else if self.rt == RangeType::Fixed && b.rt == RangeType::Fixed && self.size != b.size && !reconcile {
            return self.size > b.size;
        }
        t.f.order(self.ty, b.ty) < 0
    }

    /// `RangeHint::attemptJoin`: an open hint takes in the next one when the two line up as
    /// elements of one array.
    fn attempt_join(&mut self, b: &mut RangeHint, t: Types) -> bool {
        if b.is_backfill() && self.attempt_backfill(b, t) {
            return true;
        }
        if self.rt != RangeType::Open || b.rt == RangeType::Endpoint {
            return false;
        }
        if self.is_const_absorbable(b, t) {
            self.absorb(b, t);
            return true;
        }
        if self.highind < 0 {
            return false;
        }
        let mut settype = self.ty;
        if t.align(settype) != t.align(b.ty) {
            return false;
        }
        if settype != b.ty {
            // through the pointers, while both are pointers
            let (mut at, mut bt) = (self.ty, b.ty);
            while let (Some(a2), Some(b2)) = (t.f.ptr_to(at), t.f.ptr_to(bt)) {
                (at, bt) = (a2, b2);
            }
            match (t.f.meta(at), t.f.meta(bt)) {
                (Meta::Unknown, _) => settype = b.ty,
                (_, Meta::Unknown) | (Meta::Int, Meta::Uint) | (Meta::Uint, Meta::Int) => {}
                _ if at != bt => return false,
                _ => {}
            }
        }
        let diffsz = b.sstart - self.sstart;
        if diffsz % t.align(settype) != 0 || diffsz / t.align(settype) > i64::from(self.highind) {
            return false;
        }
        self.ty = settype;
        self.absorb(b, t);
        true
    }

    /// `RangeHint::backfillToPoint`.
    fn backfill_to_point(&mut self, point: i64, t: Types) {
        let al = t.align(self.ty);
        let amount = (self.sstart - point) / al * al;
        self.sstart -= amount;
        self.start = self.start.wrapping_sub(amount as u64);
    }

    /// `RangeHint::attemptBackfill`: true when `b` counts as absorbed.
    fn attempt_backfill(&self, b: &mut RangeHint, t: Types) -> bool {
        let rightedge = self.sstart + i64::from(self.size);
        if b.sstart < rightedge {
            return true;
        }
        if self.rt != RangeType::Open {
            b.backfill_to_point(rightedge, t);
            return false;
        }
        if self.is_backfill() {
            return true;
        }
        b.backfill_to_point((b.sstart - rightedge) / 2, t);
        true
    }

    /// `RangeHint::backfillOpen` into the range `[first, last]`.
    fn backfill_open(&mut self, (first, last): (u64, u64), max_elements: u64, t: Types) {
        if self.start < first {
            return;
        }
        let al = t.align(self.ty) as u64;
        let amount = ((self.start - first) / al).min(max_elements) * al;
        let start = self.start - amount;
        if start < first || start > last {
            return;
        }
        self.start = start;
        self.sstart -= amount as i64;
    }

    /// `RangeHint::absorb`.
    fn absorb(&mut self, b: &RangeHint, t: Types) {
        let al = t.align(self.ty);
        if b.rt == RangeType::Open {
            if al == t.align(b.ty) {
                self.rt = RangeType::Open;
                if 0 <= b.highind {
                    let diffsz = (b.sstart - self.sstart) / al;
                    let trialhi = b.highind.wrapping_add(diffsz as i32);
                    self.highind = self.highind.max(trialhi);
                }
            } else if self.start == b.start && !matches!(t.f.meta(self.ty), Meta::Struct | Meta::Union) {
                self.rt = RangeType::Open;
            }
        } else if b.flags & COPY_CONSTANT != 0 && self.rt == RangeType::Open {
            let diffsz = b.sstart - self.sstart + i64::from(b.size);
            if diffsz > i64::from(self.size) {
                self.highind = self.highind.max((diffsz / al) as i32);
            }
        }
        if self.flags & COPY_CONSTANT != 0 && b.flags & COPY_CONSTANT == 0 {
            self.flags ^= COPY_CONSTANT;
        }
    }

    /// `RangeHint::merge` of an overlapping hint. (It never reports an overlap problem: that
    /// needs a type-locked hint.)
    fn merge(&mut self, b: &RangeHint, t: Types) -> Result<()> {
        if b.rt == RangeType::Endpoint {
            return err("RangeHint overlaps endpoint");
        }
        // 0: this, 1: b, 2: neither
        let res = if !self.contain(b) {
            2
        } else {
            let reconciled = self.reconcile(b, t);
            if !reconciled && self.start != b.start {
                2
            } else if self.preferred(b, reconciled, t) {
                0
            } else {
                1
            }
        };
        match res {
            0 => self.absorb(b, t),
            1 => {
                let copy = *self;
                (self.ty, self.flags, self.rt, self.highind, self.size) = (b.ty, b.flags, b.rt, b.highind, b.size);
                self.absorb(&copy, t);
            }
            _ => {
                // confusion about the types: an unknown one
                self.rt = RangeType::Fixed;
                let diff = (b.sstart - self.sstart) as i32;
                self.size = self.size.max(diff.wrapping_add(b.size));
                let at = [1, 2, 4, 8].iter().position(|&s| s == self.size);
                if at.is_none() {
                    self.size = 1;
                    self.rt = RangeType::Open;
                }
                self.ty = t.unk[at.unwrap_or(0)];
                self.flags = 0;
                self.highind = -1;
            }
        }
        Ok(())
    }
}

/// Port of `RangeList::inRange` on sorted, disjoint ranges.
fn in_range(ranges: &[(u64, u64)], off: u64, size: u64) -> bool {
    range_at(ranges, off).is_some_and(|r| u128::from(r.1) >= u128::from(off) + u128::from(size) - 1)
}

/// The last range starting at or before `off`.
fn range_at(ranges: &[(u64, u64)], off: u64) -> Option<(u64, u64)> {
    ranges.partition_point(|&(first, _)| first <= off).checked_sub(1).map(|i| ranges[i])
}

/// Port of `RangeList::getNearestRange`.
fn nearest_range(ranges: &[(u64, u64)], off: u64) -> Option<(u64, u64)> {
    let at = ranges.partition_point(|&(first, _)| first <= off);
    let (before, after) = (at.checked_sub(1).map(|i| ranges[i]), ranges.get(at).copied());
    match (before, after) {
        (Some(b), Some(a)) if b.1 < off && a.0 - off < off - b.1 => Some(a),
        (Some(b), _) => Some(b),
        (None, a) => a,
    }
}

/// A hint as gathered, before `MapState::addRange` places it.
struct RawHint {
    st: u64,
    ty: Option<TypeId>,
    fl: u32,
    rt: RangeType,
    hi: i32,
}

/// Port of `MapState`: the range hints of the stack space.
struct MapState {
    /// the scope's ranges less the parameter ranges
    range: Vec<(u64, u64)>,
    /// the model's parameter ranges
    params: Vec<(u64, u64)>,
    /// the stack space's highest offset
    highest: u64,
    maplist: Vec<RangeHint>,
    /// `paramRangeHit`: an open hint points into the parameters
    param_range_hit: bool,
}

impl MapState {
    /// The signed offset of `st` (`sign_extend` to the address size).
    fn signed(&self, st: u64) -> i64 {
        let bits = 64 - self.highest.leading_zeros();
        ((st << (64 - bits)) as i64) >> (64 - bits)
    }

    /// Port of `MapState::adjustOutOfRange`: an open hint outside the ranges is cut to unknown
    /// bytes when it starts inside one, or moved into the nearest range by whole elements (an
    /// array reference with a constant folded in); moved backward it is a backfill.
    fn adjust_out_of_range(&mut self, h: &mut RawHint, ty: &mut TypeId, t: Types) -> bool {
        let size = u64::from(t.f.size(*ty));
        if in_range(&self.params, h.st, size) {
            self.param_range_hit = true;
            return false;
        }
        if size > 1 && in_range(&self.range, h.st, 1) {
            *ty = t.unk[0];
            return true;
        }
        if h.st == 0 {
            return false; // annotateRawStackPtr handles this offset
        }
        let Some((first, last)) = nearest_range(&self.range, h.st) else { return false };
        let holds = |o: u64| first <= o && o <= last;
        let al = t.align(*ty) as u64;
        if last < h.st {
            let num = (h.st - last - 1) / al;
            h.st = h.st.wrapping_sub(al * (num + 1));
            if !holds(h.st.wrapping_add(size).wrapping_sub(1)) {
                h.st = h.st.wrapping_sub(al);
            }
            if !holds(h.st) {
                return false;
            }
            h.fl |= BACKFILL;
        } else {
            let num = first.wrapping_sub(h.st).wrapping_add(1) / al;
            h.st = h.st.wrapping_add(al * (num + 1));
            if !holds(h.st) || !holds(h.st.wrapping_add(size).wrapping_sub(1)) {
                return false;
            }
        }
        true
    }

    /// Port of `MapState::addRange`.
    fn add_range(&mut self, mut h: RawHint, t: Types) -> Result<()> {
        let mut ty = h.ty.filter(|&ty| t.f.size(ty) != 0).unwrap_or(t.unk[0]);
        if !in_range(&self.range, h.st, u64::from(t.f.size(ty)))
            && (h.rt != RangeType::Open || !self.adjust_out_of_range(&mut h, &mut ty, t))
        {
            return Ok(());
        }
        if matches!(t.f.meta(ty), Meta::Struct | Meta::Union) {
            return unported("a structure or union on the stack");
        }
        let (sstart, size) = (self.signed(h.st), t.f.size(ty) as i32);
        self.maplist.push(RangeHint { start: h.st, size, sstart, ty, flags: h.fl, rt: h.rt, highind: h.hi });
        Ok(())
    }

    /// Port of `MapState::initialize`: the bounding hint, the sort and `reconcileDatatypes`.
    /// False when there is nothing to lay out.
    fn initialize(&mut self, t: Types) -> bool {
        let highest = self.highest;
        // getLastSignedRange: the last range starting in the positive half, else the last one
        let Some(&(_, last)) = self.range.iter().rev().find(|r| r.0 <= highest / 2).or(self.range.last()) else {
            return false;
        };
        if self.maplist.is_empty() {
            return false;
        }
        let high = last.wrapping_add(1) & highest;
        let sstart = self.signed(high);
        self.maplist.push(RangeHint {
            start: high,
            size: 1,
            sstart,
            ty: t.unk[0],
            flags: 0,
            rt: RangeType::Endpoint,
            highind: -2,
        });
        self.maplist.sort_by_key(RangeHint::key);
        // reconcileDatatypes: the hints of one start, size and flags take the most specific of
        // their types; equal hints go
        let mut list: Vec<RangeHint> = Vec::with_capacity(self.maplist.len());
        let (mut group, mut start) = (0, self.maplist[0]);
        let mut ty = start.ty;
        list.push(start);
        for &cur in &self.maplist[1..] {
            if cur.start == start.start && cur.size == start.size && cur.flags == start.flags {
                if t.f.order(cur.ty, ty) < 0 {
                    ty = cur.ty;
                }
                if list.last().is_some_and(|l| l.key() != cur.key()) {
                    list.push(cur);
                }
            } else {
                list[group..].iter_mut().for_each(|h| h.ty = ty);
                group = list.len();
                start = cur;
                ty = cur.ty;
                list.push(cur);
            }
        }
        list[group..].iter_mut().for_each(|h| h.ty = ty);
        self.maplist = list;
        // an initial backfill into open space is filled now
        if self.maplist[0].is_backfill() {
            let first = self.maplist[0].start;
            if let Some(sub) = range_at(&self.range, first).filter(|r| r.1 >= first) {
                self.maplist[0].backfill_open(sub, 127, t);
            }
        }
        true
    }
}

/// Port of `MapState::isReadActive`.
fn is_read_active(fd: &Funcdata, vn: VarnodeId) -> bool {
    let v = fd.vn(vn);
    let same = |o: VarnodeId, off: u64| fd.vn(o).space == v.space && fd.vn(o).offset == off;
    v.descend.iter().any(|&op| {
        let o = fd.op(op);
        match o.opc {
            _ if o.is_marker() => !o.out.is_some_and(|out| same(out, v.offset)),
            Opcode::Piece => {
                let Some(out) = o.out else { return true };
                let mut off = fd.vn(out).offset;
                if o.ins[1] != vn {
                    off = off.wrapping_add(u64::from(fd.vn(o.ins[1]).size)) & fd.localmap.highest();
                }
                fd.vn(out).space != v.space || v.offset != off
            }
            Opcode::Subpiece => false,
            _ => true,
        }
    })
}

/// Port of `MapState::addFixedType` (varmap.cc:1052-1082): a fixed hint of the data-type; for
/// a piece of an array (a partial struct) an open hint of the element instead, unless it is
/// unknown, and a fixed hint of the undefined type when a constant is copied there. Partial
/// unions do not exist here.
fn add_fixed_type(fd: &mut Funcdata, out: &mut Vec<RawHint>, st: u64, ty: TypeId, fl: u32) {
    let fixed = |ty: TypeId| RawHint { st, ty: Some(ty), fl, rt: RangeType::Fixed, hi: -1 };
    let Kind::PartialStruct { container, offset, stripped } = fd.types.get(ty).kind else {
        out.push(fixed(ty));
        return;
    };
    let open = match fd.types.get(container).kind {
        // the first fields of a structure moved here
        Kind::Fields(_) if fd.types.meta(container) == Meta::Struct && offset == 0 => Some(container),
        // elements of an array moved here
        Kind::Array { elem, .. } if fd.types.meta(elem) != Meta::Unknown => Some(elem),
        _ => None,
    };
    if let Some(t) = open {
        out.push(RawHint { st, ty: Some(t), fl: 0, rt: RangeType::Open, hi: -1 });
    }
    if fl != 0 {
        out.push(fixed(stripped));
    }
}

/// Port of `MapState::gatherVarnodes`: a hint (`addFixedType`), with the varnode's data-type,
/// for each stack varnode something writes or reads other than by copying within its storage.
fn gather_varnodes(fd: &mut Funcdata, out: &mut Vec<RawHint>) {
    let mask = fd.localmap.highest();
    for vn in fd.loc_space(Space::Stack) {
        if fd.vn(vn).is_free() {
            continue;
        }
        let ty = vn_type(fd, vn);
        let v = fd.vn(vn);
        let offset = v.offset;
        let differs = |fd: &Funcdata, o: VarnodeId, off: u64| fd.vn(o).space != Space::Stack || fd.vn(o).offset != off;
        let Some(def) = v.def else {
            if is_read_active(fd, vn) {
                add_fixed_type(fd, out, offset, ty, 0);
            }
            continue;
        };
        let (opc, ins) = (fd.op(def).opc, fd.op(def).ins.clone());
        let mut flags = 0;
        let add = match opc {
            Opcode::Indirect => differs(fd, ins[0], offset) || is_read_active(fd, vn),
            Opcode::Multiequal => ins.iter().any(|&i| differs(fd, i, offset)) || is_read_active(fd, vn),
            Opcode::Piece => {
                // two COPYs: the low piece (slot 1), then the high one
                let (first, second) = (ins[1], ins[0]);
                let second_off = offset.wrapping_add(u64::from(fd.vn(first).size)) & mask;
                for (piece, off) in [(first, offset), (second, second_off)] {
                    if differs(fd, piece, off) {
                        let pty = vn_type(fd, piece);
                        add_fixed_type(fd, out, off, pty, 0);
                    }
                }
                is_read_active(fd, vn)
            }
            Opcode::Subpiece => {
                let off = fd.vn(ins[0]).offset.wrapping_add(fd.vn(ins[1]).offset) & mask;
                differs(fd, ins[0], fd.vn(ins[0]).offset) || off != offset || is_read_active(fd, vn)
            }
            Opcode::Copy => {
                if fd.vn(ins[0]).is_constant() {
                    flags = COPY_CONSTANT;
                }
                true
            }
            _ => true,
        };
        if add {
            add_fixed_type(fd, out, offset, ty, flags);
        }
    }
}

/// Port of `MapState::gatherOpen`: an open hint at each alias offset, of what the pointer
/// there points to. The alias offsets (`AliasChecker::getAlias`) are returned in the order
/// found. Then the hints of the load and store guards (`addGuard`).
fn gather_open(fd: &mut Funcdata, arch: &Arch, out: &mut Vec<RawHint>) -> Result<Vec<u64>> {
    let mut alias = Vec::new();
    if let Some(base) = stack_pointer_input(fd, arch) {
        for (vn, index) in gather_additive_base(fd, base) {
            let offset = gather_offset(fd, vn);
            alias.push(offset);
            // what a pointer points to, down to the element of an array; else unknown bytes
            let mut ty = fd.vn(vn).ty.and_then(|t| fd.types.ptr_to(t));
            while let Some(Kind::Array { elem, .. }) = ty.map(|t| &fd.types.get(t).kind) {
                ty = Some(*elem);
            }
            out.push(RawHint { st: offset, ty, fl: 0, rt: RangeType::Open, hi: if index { 3 } else { -1 } });
        }
    }
    for g in fd.heritage.load_guards.clone() {
        add_guard(fd, &g, Opcode::Load, out)?;
    }
    for g in fd.heritage.store_guards.clone() {
        add_guard(fd, &g, Opcode::Store, out)?;
    }
    Ok(alias)
}

/// Port of `MapState::addGuard`: an indexed LOAD or STORE with a step is an open hint, an
/// array of what its pointer points to when that has the step's size, else of unknown elements
/// of the step's size (always so in the partial function, which has no data-types).
fn add_guard(fd: &mut Funcdata, guard: &LoadGuard, opc: Opcode, out: &mut Vec<RawHint>) -> Result<()> {
    if !guard.is_valid(fd, opc) || guard.step == 0 {
        return Ok(());
    }
    // getTypeReadFacing of the pointer (a type needing resolution fails loudly)
    let mut ct = vn_type_facing(fd, fd.input(guard.op, 1)?, "restructure_varnode")?;
    if let Some(to) = fd.types.ptr_to(ct) {
        ct = to;
        while let Kind::Array { elem, .. } = fd.types.get(ct).kind {
            ct = elem;
        }
        if fd.types.meta(ct) == Meta::Union {
            return unported("a load or store guard through a pointer to a union");
        }
    }
    let op = fd.op(guard.op);
    let Some(out_size) = (if opc == Opcode::Store { op.ins.get(2).copied() } else { op.out }).map(|v| fd.vn(v).size)
    else {
        return Ok(());
    };
    let mut step = guard.step;
    if out_size != step {
        // a field in an array of structures, or something more unusual
        if out_size > step || !step.is_multiple_of(out_size) {
            return Ok(());
        }
        step = out_size;
    }
    if fd.types.align_size(ct) != step {
        // no primitive above 8 bytes is made
        if step > 8 {
            return Ok(());
        }
        ct = fd.types.base(step, Meta::Unknown);
    }
    let hi = if guard.is_range_locked() {
        ((guard.maximum.wrapping_sub(guard.minimum).wrapping_add(1) / u64::from(step)) as i32).wrapping_sub(1)
    } else {
        3
    };
    out.push(RawHint { st: guard.minimum, ty: Some(ct), fl: 0, rt: RangeType::Open, hi });
    Ok(())
}

/// Port of `ScopeLocal::adjustFit`; `tsize` is the size of the hint's data-type.
fn adjust_fit(lm: &LocalMap, a: &mut RangeHint, tsize: u64) -> bool {
    if a.size == 0 {
        return false;
    }
    // a negative size is a huge `uintb` in the C++, which `longestFit` then cuts
    let want = a.size as i64 as u64;
    let maxsize = lm.longest_fit(a.start, want);
    if maxsize == 0 {
        return false;
    }
    if maxsize < want {
        if maxsize < tsize {
            return false;
        }
        a.size = maxsize as i32;
    }
    let Some(entry) = lm.find_overlap(a.start, a.size as i64 as u64) else { return true };
    if entry.off <= a.start {
        return false;
    }
    let maxsize = entry.off - a.start;
    if maxsize < tsize {
        return false;
    }
    a.size = maxsize as i32;
    true
}

/// Port of `ScopeLocal::restructure`: the hints, merged and joined, become symbols.
fn restructure(fd: &mut Funcdata, state: &mut MapState, unk: [TypeId; 4]) -> Result<()> {
    if !state.initialize(Types { f: &fd.types, unk }) {
        return Ok(());
    }
    let mut cur = state.maplist[0];
    for i in 1..state.maplist.len() {
        let t = Types { f: &fd.types, unk };
        let next = &mut state.maplist[i];
        if next.sstart < cur.sstart + i64::from(cur.size) {
            cur.merge(next, t)?;
        } else if !cur.attempt_join(next, t) {
            if cur.rt == RangeType::Open {
                cur.size = (next.sstart - cur.sstart) as i32;
                if cur.size < 0 {
                    cur.size = 0x7fff_ffff;
                }
            }
            let next = *next;
            let tsize = u64::from(fd.types.size(cur.ty));
            if adjust_fit(&fd.localmap, &mut cur, tsize) {
                // createEntry: `concretize`, and an array when more than one element fits
                let mut ct = cur.ty;
                if fd.types.meta(ct) == Meta::Code {
                    if fd.types.size(ct) != 1 {
                        return err("Primitive code data-type that is not size 1");
                    }
                    ct = unk[0];
                }
                let num = cur.size / fd.types.align_size(ct) as i32;
                if num > 1 {
                    ct = fd.types.array_of(ct, num as u32).or_else(|e| unported(&e))?;
                }
                fd.add_local_sym(cur.start, ct, false)?;
            }
            cur = next;
        }
    }
    Ok(())
}

/// Port of `ScopeLocal::fakeInputSymbols`: a symbol of unknown bytes over each run of
/// overlapping stack inputs in the parameter range.
fn fake_input_symbols(fd: &mut Funcdata) -> Result<()> {
    let inputs: Vec<(u64, u64)> = fd
        .input_list()
        .into_iter()
        .map(|v| fd.vn(v))
        .filter(|v| v.space == Space::Stack)
        .map(|v| (v.offset, v.offset + u64::from(v.size) - 1))
        .collect();
    let mut i = 0;
    while i < inputs.len() {
        let (off, mut endpoint) = inputs[i];
        i += 1;
        if !in_range(fd.localmap.params(), off, 1) {
            continue;
        }
        while i < inputs.len() && inputs[i].0 <= endpoint {
            endpoint = endpoint.max(inputs[i].1);
            i += 1;
        }
        let ct = fd.types.base((endpoint - off + 1) as u32, Meta::Unknown);
        fd.add_local_sym(off, ct, true)?;
    }
    Ok(())
}

/// Port of `ScopeLocal::markUnaliased`: a symbol no alias offset reaches is `nolocalalias`.
/// (No symbol is typelocked, so none blocks an alias.)
fn mark_unaliased(lm: &mut LocalMap, alias: &[u64]) {
    let ranges = lm.ranges().to_vec();
    let (mut aliason, mut curalias, mut i, mut ri) = (false, 0u64, 0, 0);
    for s in lm.sym_list().to_vec() {
        let curoff = lm.sym(s).last;
        while i < alias.len() && alias[i] <= curoff {
            aliason = true;
            curalias = alias[i];
            i += 1;
        }
        // aliases do not go through unmapped regions of the local variables
        while let Some(&(first, last)) = ranges.get(ri) {
            if first > curalias && curoff >= first {
                aliason = false;
            }
            if last >= curoff {
                break;
            }
            if last > curalias {
                aliason = false;
            }
            ri += 1;
        }
        if aliason && curoff.wrapping_sub(curalias) > 0xffff {
            aliason = false;
        }
        if !aliason {
            lm.set_noalias(s);
        }
    }
}

/// Port of `ScopeLocal::checkUnaliasedReturn`: a return value in the stack space that no alias
/// points into is not a mapped variable.
fn check_unaliased_return(fd: &mut Funcdata, alias: &[u64]) -> Result<()> {
    // getFirstReturnOp
    let ret = fd.ops_created_with(Opcode::Return).into_iter().find(|&o| !fd.op(o).is_dead() && fd.op(o).halt.is_none());
    let Some(v) = ret.and_then(|o| fd.op(o).ins.get(1)).map(|&v| fd.vn(v)) else { return Ok(()) };
    if v.space != Space::Stack {
        return Ok(());
    }
    let (off, size) = (v.offset, v.size);
    let at = alias.partition_point(|&a| a < off);
    if alias.get(at).is_some_and(|&a| a <= off.wrapping_add(u64::from(size) - 1)) {
        return Ok(()); // an alias into the return storage
    }
    mark_not_mapped(fd, Space::Stack, off, size, false)
}

/// Port of `ScopeLocal::annotateRawStackPtr`: a read of the input stack pointer by an op that
/// does not add to it is a reference to offset 0 of the frame, so it reads `PTRSUB(sp, #0)`
/// instead, and a symbol stands at offset 0.
fn annotate_raw_stack_ptr(fd: &mut Funcdata, arch: &Arch, unk1: TypeId) -> Result<()> {
    if !fd.typerecovery_start {
        return Ok(());
    }
    let Some(sp) = stack_pointer_input(fd, arch) else { return Ok(()) };
    let (mut ref_ops, mut saw_raw) = (Vec::new(), false);
    for &op in fd.vn(sp).descend.iter() {
        let o = fd.op(op);
        if super::blocktransform::is_special(o.opc) && !o.is_call() {
            continue;
        }
        match o.opc {
            Opcode::Ptrsub => saw_raw |= fd.vn(o.ins[1]).offset == 0,
            Opcode::IntAdd | Opcode::Ptradd => {}
            _ => {
                ref_ops.push(op);
                saw_raw = true;
            }
        }
    }
    if saw_raw && fd.symtab.find_container(super::scope::LOCAL, Space::Stack, 0, 1, None)?.is_none() {
        fd.add_local_sym(0, unk1, false)?;
    }
    for op in ref_ops {
        // an op reading the pointer twice is listed twice
        let Some(slot) = fd.op(op).ins.iter().position(|&i| i == sp) else { continue };
        let (addr, size) = (fd.op(op).seq.addr, fd.vn(sp).size);
        let zero = fd.new_constant(size, 0);
        let ptrsub = super::rules::insert_new(fd, Opcode::Ptrsub, addr, size, &[sp, zero], op)?;
        fd.op_set_input(op, ptrsub, slot)?;
    }
    Ok(())
}

/// Port of `ScopeLocal::restructureVarnode`.
fn restructure_scope(fd: &mut Funcdata, arch: &Arch, aliasyes: bool) -> Result<()> {
    if fd.proto.locked.as_ref().is_some_and(|l| !l.inputs.is_empty()) {
        return unported("a locked prototype with parameters");
    }
    if fd.localmap.params().is_empty() {
        return unported("a model without a stack parameter range");
    }
    fd.clear_local_syms(false);
    let mut range = fd.localmap.ranges().to_vec();
    for &(a, b) in fd.localmap.params() {
        range = range
            .into_iter()
            .flat_map(|(f, l)| {
                let left = (f < a && l >= f).then(|| (f, l.min(a.wrapping_sub(1))));
                let right = (l > b).then(|| (f.max(b + 1), l));
                if l < a || f > b {
                    vec![(f, l)]
                } else {
                    left.into_iter().chain(right).collect()
                }
            })
            .collect();
    }
    let mut state = MapState {
        range,
        params: fd.localmap.params().to_vec(),
        highest: fd.localmap.highest(),
        maplist: Vec::new(),
        param_range_hit: false,
    };
    let mut hints = Vec::new();
    gather_varnodes(fd, &mut hints);
    let mut alias = gather_open(fd, arch, &mut hints)?;
    let unk = unknown_types(&mut fd.types);
    for h in hints {
        state.add_range(h, Types { f: &fd.types, unk })?;
    }
    // gatherSymbols: the symbols left are the fake inputs of the pass before, in the parameter
    // range, which the hints leave out
    if fd.localmap.sym_list().iter().any(|&s| {
        let s = fd.localmap.sym(s);
        in_range(&state.range, s.off, s.last - s.off + 1)
    }) {
        return unported("a fake input symbol in the local ranges");
    }
    fd.localmap.open_param_refs = state.param_range_hit;
    restructure(fd, &mut state, unk)?;
    fd.clear_local_syms(true);
    fake_input_symbols(fd)?;
    alias.sort_unstable();
    if aliasyes {
        mark_unaliased(&mut fd.localmap, &alias);
        check_unaliased_return(fd, &alias)?;
    }
    if alias.first() == Some(&0) {
        annotate_raw_stack_ptr(fd, arch, unk[0])?;
    }
    Ok(())
}

impl Funcdata {
    /// Port of `Funcdata::markIndirectAliasUpdate`.
    fn mark_indirect_alias_update(&mut self, vn: VarnodeId) {
        let Some(def) = self.vn(vn).def else { return };
        if self.op(def).opc != Opcode::Indirect {
            return;
        }
        if let Some(effect) = self.op(def).ins.get(1).and_then(|&i| self.iop_target(i)) {
            self.op_mut(effect).flags.set(OpFlags::ALIAS_UPDATE);
        }
    }

    /// `ScopeInternal::addSymbol` for an unnamed stack variable of type `ty` at `off`, valid
    /// everywhere; `fake_input` puts it in that category (`fakeInputSymbols`).
    pub(crate) fn add_local_sym(&mut self, off: u64, ty: TypeId, fake_input: bool) -> Result<()> {
        use super::scope::{SymbolEntry, LOCAL};
        let size = self.types.size(ty);
        let entry = SymbolEntry {
            space: Space::Stack,
            offset: off,
            size,
            uselimit: Default::default(),
            conflict: false,
            piece: None,
        };
        let id = self.symtab.add_symbol(LOCAL, "", Some(ty), None, Some(entry))?;
        if fake_input {
            self.symtab.set_category(id, super::scope::FAKE_INPUT, 0);
        }
        self.localmap.add_sym(off, u64::from(size), fake_input, id);
        Ok(())
    }

    /// `clearUnlockedCategory(-1)` (`fake_input` false) or `clearCategory(Symbol::fake_input)`
    /// for the symbols of `restructureVarnode`.
    pub(crate) fn clear_local_syms(&mut self, fake_input: bool) {
        for id in self.localmap.clear_syms(fake_input) {
            self.symtab.remove_symbol(id);
        }
    }

    /// Port of `TypeFactory::getExactPiece` (type.cc:4607-4639): the data-type of the `size`
    /// bytes at `off` in `ct`; a piece of an array is a partial struct. A piece of a
    /// structure, union or enumeration is not ported.
    pub(crate) fn exact_piece(&mut self, ct: TypeId, off: i64, size: u32) -> Result<Option<TypeId>> {
        let (mut cur, mut curoff, mut last) = (Some(ct), off, None);
        while let Some(c) = cur {
            if i64::from(self.types.size(c)) < i64::from(size) + curoff {
                break;
            }
            if self.types.size(c) == size {
                return Ok(Some(c));
            }
            last = Some((c, curoff));
            cur = self.types.sub_type(c, curoff).map(|(n, o)| {
                curoff = o;
                n
            });
        }
        match last {
            Some((l, o)) if matches!(self.types.meta(l), Meta::Array | Meta::PartialStruct) => {
                Ok(Some(self.types.partial_struct(l, o as i32, size)))
            }
            Some((l, _)) if matches!(self.types.meta(l), Meta::Struct | Meta::Union) || self.types.is_enum(l) => {
                err("getExactPiece: a piece of a structure, union or enumeration as a data-type is not ported")
            }
            _ => Ok(None),
        }
    }

    /// Port of `Funcdata::syncVarnodesWithSymbols` for the stack space: each stack varnode
    /// takes `mapped`, `addrtied` and `nolocalalias` from the symbol it overlaps, or from the
    /// scope; with `update_datatypes` also the data-type of its place in a symbol holding it,
    /// unless that is unknown. True when a varnode changed.
    pub(crate) fn sync_varnodes_with_symbols(
        &mut self,
        update_datatypes: bool,
        unmapped_alias_check: bool,
    ) -> Result<bool> {
        let tied = VnFlags::MAPPED.with(VnFlags::ADDRTIED);
        let mut updated = false;
        for vn in self.loc_space(Space::Stack) {
            let v = self.vn(vn);
            if v.is_free() {
                continue;
            }
            let (off, size) = (v.offset, v.size);
            let mut ct = None;
            let mut fl = match self.localmap.find_overlap(off, u64::from(size)).copied() {
                Some(s) => {
                    if update_datatypes && s.last - s.off + 1 >= u64::from(size) {
                        // SymbolEntry::getSizedType (the offset is an `int4`)
                        let sty = self.symtab.symbol(s.id).ty;
                        let at = i64::from(off.wrapping_sub(s.off) as i32);
                        ct = match sty {
                            Some(t) => self.exact_piece(t, at, size)?,
                            None => None,
                        };
                        ct = ct.filter(|&c| self.types.meta(c) != Meta::Unknown);
                    }
                    if s.noalias {
                        tied.with(VnFlags::NOLOCALALIAS)
                    } else {
                        tied
                    }
                }
                None if self.localmap.in_scope(off, size) => tied,
                None if unmapped_alias_check && self.localmap.is_unmapped_unaliased(off) => VnFlags::NOLOCALALIAS,
                None => VnFlags::default(),
            };
            // addrtied can be cleared but not set, nolocalalias set but not cleared
            let mut mask = VnFlags::MAPPED;
            if !fl.has(VnFlags::ADDRTIED) {
                mask = mask.with(VnFlags::ADDRTIED).with(VnFlags::ADDRFORCE);
            }
            if fl.has(VnFlags::NOLOCALALIAS) {
                mask = mask.with(VnFlags::NOLOCALALIAS).with(VnFlags::ADDRFORCE);
            }
            fl = fl.and(mask);
            if self.vn(vn).flags.and(mask) != fl {
                updated = true;
                self.vn_clear(vn, mask);
                self.vn_set(vn, fl);
                self.mark_indirect_alias_update(vn);
            }
            // Varnode::updateType
            if let Some(ct) = ct {
                let v = self.vn_mut(vn);
                if v.ty != Some(ct) && !v.has(VnFlags::TYPELOCK) {
                    v.ty = Some(ct);
                    updated = true;
                }
            }
        }
        Ok(updated)
    }

    /// Port of `Funcdata::opCollapseIndirectsForAlias`: the INDIRECTs of `effect` whose output
    /// nothing can alias any more go, and with a store guard those outside its range.
    pub(crate) fn op_collapse_indirects_for_alias(&mut self, effect: OpId) -> Result<()> {
        self.op_mut(effect).flags.clear(OpFlags::ALIAS_UPDATE);
        let Some(bb) = self.op(effect).parent else { return Ok(()) };
        let ops = &self.blocks.block(bb).ops;
        let pos = ops.iter().position(|&o| o == effect).unwrap_or(0);
        let inds: Vec<OpId> =
            ops[..pos].iter().rev().copied().take_while(|&o| self.op(o).opc == Opcode::Indirect).collect();
        let e = self.op(effect);
        // getStoreGuard
        let guard = (e.opc == Opcode::Store && e.flags.has(OpFlags::SPACEBASE_PTR))
            .then(|| self.heritage.store_guards.iter().find(|g| g.op == effect).copied())
            .flatten();
        for op in inds {
            let o = self.op(op);
            let Some(out) = o.out else { continue };
            let v = self.vn(out);
            if (v.has(VnFlags::NOLOCALALIAS)
                && !o.flags.has(OpFlags::INDIRECT_CREATION)
                && !o.flags.has(OpFlags::NO_INDIRECT_COLLAPSE))
                || guard.is_some_and(|g| !g.is_guarded(v.space, v.offset))
            {
                let inp = o.ins[0];
                self.total_replace(out, inp)?;
                self.op_destroy(op);
            }
        }
        Ok(())
    }
}

/// `ActionRestructureVarnode::isCopyConstant`.
fn is_copy_constant(fd: &Funcdata, vn: VarnodeId) -> bool {
    let v = fd.vn(vn);
    v.is_constant() || v.def.is_some_and(|d| fd.op(d).opc == Opcode::Copy && fd.vn(fd.op(d).ins[0]).is_constant())
}

/// `ActionRestructureVarnode::isDelayedConstant`.
fn is_delayed_constant(fd: &Funcdata, vn: VarnodeId) -> bool {
    let v = fd.vn(vn);
    if v.is_constant() {
        return true;
    }
    let Some(d) = v.def.map(|d| fd.op(d)) else { return false };
    match d.opc {
        Opcode::Copy => fd.vn(d.ins[0]).is_constant(),
        Opcode::IntAdd => is_copy_constant(fd, d.ins[1]) && is_copy_constant(fd, d.ins[0]),
        _ => false,
    }
}

/// Port of `ActionRestructureVarnode::protectSwitchPathIndirects`: when one path leads from a
/// constant to the BRANCHIND `op` through INDIRECTs, the earliest of them is never collapsed.
fn protect_switch_path_indirects(fd: &mut Funcdata, op: OpId) {
    let mut last_indirect = None;
    let mut cur = fd.op(op).ins[0];
    while let Some(def) = fd.vn(cur).def {
        let d = fd.op(def);
        let ternary = matches!(d.opc, Opcode::Ptradd | Opcode::Insert | Opcode::Zpull | Opcode::Spull);
        if d.opc.is_unary_or_binary() || ternary {
            cur = if d.ins.len() > 1 {
                if is_delayed_constant(fd, d.ins[1]) {
                    d.ins[0]
                } else if is_delayed_constant(fd, d.ins[0]) {
                    d.ins[1]
                } else {
                    return; // more than one path
                }
            } else {
                d.ins[0]
            };
        } else if d.opc == Opcode::Indirect {
            last_indirect = Some(def);
            cur = d.ins[0];
        } else if d.opc == Opcode::Load {
            cur = d.ins[1];
        } else if d.opc == Opcode::Multiequal {
            // an INDIRECT coming into the MULTIEQUAL is kept; no further backtracking
            let ind = d.ins.iter().filter_map(|&i| fd.vn(i).def).find(|&i| fd.op(i).opc == Opcode::Indirect);
            if let Some(ind) = ind {
                fd.op_mut(ind).flags.set(OpFlags::NO_INDIRECT_COLLAPSE);
            }
            return;
        } else {
            return;
        }
    }
    if !fd.vn(cur).is_constant() {
        return;
    }
    if let Some(ind) = last_indirect {
        fd.op_mut(ind).flags.set(OpFlags::NO_INDIRECT_COLLAPSE);
    }
}

/// Port of `ActionMappedLocalSync::apply`: the stack varnodes take the flags and the
/// data-types of their symbols. (`hasOverlapProblems` is never set: see `RangeHint::merge`.)
pub(crate) fn mapped_local_sync(fd: &mut Funcdata, _: &Arch) -> Result<i32> {
    Ok(i32::from(fd.sync_varnodes_with_symbols(true, true)?))
}

/// Port of `ActionRestructureVarnode::apply`.
pub(crate) fn restructure_varnode(fd: &mut Funcdata, arch: &Arch) -> Result<i32> {
    // alias calculations are not reliable on the first pass
    let aliasyes = fd.restructure_passes != 0;
    restructure_scope(fd, arch, aliasyes)?;
    let changed = fd.sync_varnodes_with_symbols(false, aliasyes)?;
    if fd.jumptablerecovery_on {
        // protectSwitchPaths
        for b in fd.blocks.list.clone() {
            if let Some(&last) = fd.blocks.block(b).ops.last() {
                if fd.op(last).opc == Opcode::Branchind {
                    protect_switch_path_indirects(fd, last);
                }
            }
        }
    }
    fd.restructure_passes += 1;
    Ok(i32::from(changed))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hint(fd: &mut Funcdata, start: u64, size: u32) -> RangeHint {
        let (sstart, ty) = (i64::from(start as i32), fd.types.base(size, Meta::Unknown));
        RangeHint { start, size: size as i32, sstart, ty, flags: 0, rt: RangeType::Fixed, highind: -1 }
    }

    /// Two overlapping hints, neither holding the other, become one open range of unknown bytes
    /// up to the next hint; an alias offset then reaches the symbols at and above it, and no
    /// symbol below it or among the parameters.
    #[test]
    fn overlapping_hints_merge_and_aliases_reach_upward() {
        let mut fd = Funcdata::new(0x1000);
        fd.localmap = LocalMap::new(0xffff_ffff, &[(4, 503)]);
        let mut state = MapState {
            range: vec![(0x8000_0000, 0xffff_ffff)],
            params: vec![(4, 503)],
            highest: 0xffff_ffff,
            maplist: [0xffff_ffe0, 0xffff_fff8, 0xffff_fff2, 0xffff_fff0].map(|at| hint(&mut fd, at, 4)).to_vec(),
            param_range_hit: false,
        };
        let unk = unknown_types(&mut fd.types);
        restructure(&mut fd, &mut state, unk).unwrap();
        fd.add_local_sym(4, unk[2], true).unwrap();
        // the merged symbol is an array of unknown bytes; the fake input has its category
        let types: Vec<String> = fd
            .symtab
            .map_records(super::super::scope::LOCAL)
            .iter()
            .map(|&(s, _)| fd.symtab.symbol(s))
            .map(|s| format!("{} {:?}", fd.types.print_raw(s.ty.unwrap()), s.category))
            .collect();
        assert_eq!(types, ["xunknown4 Some(3)", "xunknown4 None", "xunknown1 [8] None", "xunknown4 None"]);
        let syms = |fd: &Funcdata| -> Vec<(u64, u64, bool)> {
            let lm = &fd.localmap;
            lm.sym_list().iter().map(|&s| lm.sym(s)).map(|s| (s.off, s.last, s.noalias)).collect()
        };
        assert_eq!(
            syms(&fd),
            [
                (4, 7, false),
                (0xffff_ffe0, 0xffff_ffe3, false),
                (0xffff_fff0, 0xffff_fff7, false),
                (0xffff_fff8, 0xffff_fffb, false)
            ]
        );
        mark_unaliased(&mut fd.localmap, &[0xffff_fff4]);
        assert_eq!(syms(&fd).iter().map(|s| s.2).collect::<Vec<_>>(), [true, true, false, false]);
        // a varnode takes the flags of the symbol it overlaps
        assert!(fd.localmap.find_overlap(0xffff_ffe2, 4).is_some_and(|s| s.noalias));
        assert!(fd.localmap.find_overlap(0xffff_ffe4, 4).is_none());
        assert!(fd.localmap.has_container(0xffff_fff4, 4) && !fd.localmap.has_container(0xffff_fff6, 4));
    }
}
