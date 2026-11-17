//! `ActionRestructureVarnode` for the partial function of jump-table recovery: the symbols of
//! the local scope (varmap.cc: `ScopeLocal::restructureVarnode` with `MapState`, `RangeHint`,
//! `fakeInputSymbols`, `markUnaliased`), `Funcdata::syncVarnodesWithSymbols`
//! (funcdata_varnode.cc), `Funcdata::opCollapseIndirectsForAlias` (funcdata_op.cc, what
//! `RuleAliasUpdate` runs) and `ActionRestructureVarnode::protectSwitchPaths` (coreaction.cc).
//!
//! The partial function has no data-types (`typerecovery` is not a group of the `jumptable`
//! root), so every range hint has the unknown type of its size: a type is kept as that size.
//! What the port leaves out fails with an error naming it ("not ported"), and flow.rs then
//! recovers the table from the partial function without this action (`flow.rs`, the older
//! test on the INDIRECTs of stack varnodes):
//! - an open hint outside the scope's ranges and the parameter range (`adjustOutOfRange` with
//!   `getNearestRange`),
//! - a locked prototype, a typed stack varnode or one above `max_basetype_size` (arrays),
//! - a RETURN with a stack varnode as its value (`checkUnaliasedReturn`),
//! - `annotateRawStackPtr` once type recovery has started.
//!
//! The action of the `decompile` root stays unported: there the symbols carry types and names.

use super::heritage_guard::{stack_pointer_input, LoadGuard};
use super::op::{OpFlags, OpId};
use super::opcode::Opcode;
use super::varmap::{gather_additive_base, gather_offset, LocalMap};
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

/// `RangeHint::copy_constant` (`typelock` and `backfill` are never set here).
const COPY_CONSTANT: u32 = 2;

/// Port of `RangeHint`; `ty` is the size of its unknown data-type.
#[derive(Debug, Clone, Copy)]
struct RangeHint {
    start: u64,
    size: i32,
    sstart: i64,
    ty: u32,
    flags: u32,
    rt: RangeType,
    highind: i32,
}

impl RangeHint {
    /// `RangeHint::compare`.
    fn key(&self) -> (i64, i32, RangeType, u32, i32) {
        (self.sstart, self.size, self.rt, self.flags, self.highind)
    }

    /// `RangeHint::contain`.
    fn contain(&self, b: &RangeHint) -> bool {
        self.sstart == b.sstart || b.sstart + i64::from(b.size) <= self.sstart + i64::from(self.size)
    }

    /// `RangeHint::absorb`. (`isConstAbsorbable` is false for an unknown type.)
    fn absorb(&mut self, b: &RangeHint, align: impl Fn(u32) -> i64) {
        if b.rt == RangeType::Open {
            if align(self.ty) == align(b.ty) {
                self.rt = RangeType::Open;
                if 0 <= b.highind {
                    let diffsz = (b.sstart - self.sstart) / align(self.ty);
                    let trialhi = b.highind.wrapping_add(diffsz as i32);
                    self.highind = self.highind.max(trialhi);
                }
            } else if self.start == b.start {
                self.rt = RangeType::Open;
            }
        } else if b.flags & COPY_CONSTANT != 0 && self.rt == RangeType::Open {
            let diffsz = b.sstart - self.sstart + i64::from(b.size);
            if diffsz > i64::from(self.size) {
                self.highind = self.highind.max((diffsz / align(self.ty)) as i32);
            }
        }
        if self.flags & COPY_CONSTANT != 0 && b.flags & COPY_CONSTANT == 0 {
            self.flags ^= COPY_CONSTANT;
        }
    }

    /// `RangeHint::merge` of an overlapping hint. Two unknown types reconcile when their
    /// aligned sizes are equal (`RangeHint::reconcile`: a primitive has no sub-type).
    fn merge(&mut self, b: &RangeHint, align: impl Fn(u32) -> i64) -> Result<()> {
        if b.rt == RangeType::Endpoint {
            return err("RangeHint overlaps endpoint");
        }
        let reconciled = self.contain(b) && align(self.ty) == align(b.ty);
        // 0: this, 1: b, 2: neither
        let res = if !self.contain(b) || (!reconciled && self.start != b.start) {
            2
        } else if self.preferred(b, reconciled) {
            0
        } else {
            1
        };
        match res {
            0 => self.absorb(b, align),
            1 => {
                let copy = *self;
                (self.ty, self.flags, self.rt, self.highind, self.size) = (b.ty, b.flags, b.rt, b.highind, b.size);
                self.absorb(&copy, align);
            }
            _ => {
                self.rt = RangeType::Fixed;
                let diff = (b.sstart - self.sstart) as i32;
                self.size = self.size.max(diff.wrapping_add(b.size));
                if !matches!(self.size, 1 | 2 | 4 | 8) {
                    self.size = 1;
                    self.rt = RangeType::Open;
                }
                self.ty = self.size as u32;
                self.flags = 0;
                self.highind = -1;
            }
        }
        Ok(())
    }

    /// `RangeHint::preferred`; `typeOrder` puts the bigger unknown type first.
    fn preferred(&self, b: &RangeHint, reconcile: bool) -> bool {
        if self.start != b.start {
            return true;
        }
        if self.rt == RangeType::Open && b.rt != RangeType::Open {
            if !reconcile {
                return false;
            }
        } else if b.rt == RangeType::Open && self.rt != RangeType::Open {
            if !reconcile {
                return true;
            }
        } else if self.rt == RangeType::Fixed && b.rt == RangeType::Fixed && self.size != b.size && !reconcile {
            return self.size > b.size;
        }
        self.ty > b.ty
    }

    /// `RangeHint::attemptJoin` (no hint is a backfill).
    fn attempt_join(&mut self, b: &RangeHint, align: impl Fn(u32) -> i64) -> bool {
        if self.rt != RangeType::Open || b.rt == RangeType::Endpoint || self.highind < 0 {
            return false;
        }
        if align(self.ty) != align(b.ty) {
            return false;
        }
        // an unknown type takes the other's
        let settype = b.ty;
        let diffsz = b.sstart - self.sstart;
        if diffsz % align(settype) != 0 || diffsz / align(settype) > i64::from(self.highind) {
            return false;
        }
        self.ty = settype;
        self.absorb(b, align);
        true
    }
}

/// Port of `RangeList::inRange` on sorted, disjoint ranges.
fn in_range(ranges: &[(u64, u64)], off: u64, size: u64) -> bool {
    let at = ranges.partition_point(|&(first, _)| first <= off);
    at.checked_sub(1).is_some_and(|i| u128::from(ranges[i].1) >= u128::from(off) + u128::from(size) - 1)
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
    /// the alias offsets (`AliasChecker::getAlias`), in the order found
    alias: Vec<u64>,
}

impl MapState {
    /// The signed offset of `st` (`sign_extend` to the address size).
    fn signed(&self, st: u64) -> i64 {
        let bits = 64 - self.highest.leading_zeros();
        ((st << (64 - bits)) as i64) >> (64 - bits)
    }

    /// Port of `MapState::addRange`; `ty` is the size of the unknown type.
    fn add_range(&mut self, st: u64, ty: u32, fl: u32, rt: RangeType, hi: i32) -> Result<()> {
        if !in_range(&self.range, st, u64::from(ty)) {
            if rt != RangeType::Open {
                return Ok(());
            }
            // adjustOutOfRange: a reference into the parameters, or the raw stack pointer
            // (an unknown byte never shrinks to the default type)
            if in_range(&self.params, st, u64::from(ty)) || st == 0 {
                return Ok(());
            }
            return unported("an open range hint outside the local ranges (adjustOutOfRange)");
        }
        let sstart = self.signed(st);
        self.maplist.push(RangeHint { start: st, size: ty as i32, sstart, ty, flags: fl, rt, highind: hi });
        Ok(())
    }

    /// Port of `MapState::isReadActive`.
    fn is_read_active(&self, fd: &Funcdata, vn: VarnodeId) -> bool {
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

    /// Port of `MapState::gatherVarnodes` (`addFixedType` of an unknown type).
    fn gather_varnodes(&mut self, fd: &Funcdata) -> Result<()> {
        let mask = self.highest;
        for vn in fd.loc_space(Space::Stack) {
            let v = fd.vn(vn);
            if v.is_free() {
                continue;
            }
            if v.ty.is_some_and(|t| fd.types.meta(t) != super::types::Meta::Unknown) || v.has(VnFlags::TYPELOCK) {
                return unported("a typed stack varnode");
            }
            if v.size > 10 {
                return unported("a stack varnode above max_basetype_size");
            }
            let differs = |o: VarnodeId, off: u64| fd.vn(o).space != v.space || fd.vn(o).offset != off;
            let Some(def) = v.def else {
                if self.is_read_active(fd, vn) {
                    self.add_range(v.offset, v.size, 0, RangeType::Fixed, -1)?;
                }
                continue;
            };
            let d = fd.op(def);
            let mut flags = 0;
            let add = match d.opc {
                Opcode::Indirect => differs(d.ins[0], v.offset) || self.is_read_active(fd, vn),
                Opcode::Multiequal => d.ins.iter().any(|&i| differs(i, v.offset)) || self.is_read_active(fd, vn),
                Opcode::Piece => {
                    // two COPYs: the low piece (slot 1), then the high one
                    let (first, second) = (d.ins[1], d.ins[0]);
                    for (piece, off) in
                        [(first, v.offset), (second, v.offset.wrapping_add(u64::from(fd.vn(first).size)) & mask)]
                    {
                        if differs(piece, off) {
                            if fd.vn(piece).size > 10 {
                                return unported("a stack varnode above max_basetype_size");
                            }
                            self.add_range(off, fd.vn(piece).size, 0, RangeType::Fixed, -1)?;
                        }
                    }
                    self.is_read_active(fd, vn)
                }
                Opcode::Subpiece => {
                    let off = fd.vn(d.ins[0]).offset.wrapping_add(fd.vn(d.ins[1]).offset) & mask;
                    differs(d.ins[0], fd.vn(d.ins[0]).offset) || off != v.offset || self.is_read_active(fd, vn)
                }
                Opcode::Copy => {
                    if fd.vn(d.ins[0]).is_constant() {
                        flags = COPY_CONSTANT;
                    }
                    true
                }
                _ => true,
            };
            if add {
                self.add_range(v.offset, v.size, flags, RangeType::Fixed, -1)?;
            }
        }
        Ok(())
    }

    /// Port of `MapState::gatherOpen`: an open hint of unknown bytes at each alias offset.
    fn gather_open(&mut self, fd: &Funcdata, arch: &Arch) -> Result<()> {
        if let Some(base) = stack_pointer_input(fd, arch) {
            for (vn, index) in gather_additive_base(fd, base) {
                let offset = gather_offset(fd, vn);
                self.alias.push(offset);
                self.add_range(offset, 1, 0, RangeType::Open, if index { 3 } else { -1 })?;
            }
        }
        for g in &fd.heritage.load_guards {
            self.add_guard(fd, g, Opcode::Load)?;
        }
        for g in &fd.heritage.store_guards {
            self.add_guard(fd, g, Opcode::Store)?;
        }
        Ok(())
    }

    /// Port of `MapState::addGuard`: an indexed LOAD or STORE with a step is an open hint, an
    /// array of unknown elements of the step's size (the pointer has no data-type here).
    fn add_guard(&mut self, fd: &Funcdata, guard: &LoadGuard, opc: Opcode) -> Result<()> {
        if !guard.is_valid(fd, opc) || guard.step == 0 {
            return Ok(());
        }
        let op = fd.op(guard.op);
        let Some(out_size) =
            (if opc == Opcode::Store { op.ins.get(2).copied() } else { op.out }).map(|v| fd.vn(v).size)
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
        // the pointer's type is the unknown type of its size: no primitive above 8 bytes is made
        if fd.vn(fd.input(guard.op, 1)?).size != step && step > 8 {
            return Ok(());
        }
        let high = if guard.is_range_locked() {
            ((guard.maximum.wrapping_sub(guard.minimum).wrapping_add(1) / u64::from(step)) as i32).wrapping_sub(1)
        } else {
            3
        };
        self.add_range(guard.minimum, step, 0, RangeType::Open, high)
    }

    /// Port of `MapState::initialize`: the bounding hint, the sort and `reconcileDatatypes`.
    /// False when there is nothing to lay out.
    fn initialize(&mut self) -> bool {
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
            ty: 1,
            flags: 0,
            rt: RangeType::Endpoint,
            highind: -2,
        });
        self.maplist.sort_by_key(RangeHint::key);
        // reconcileDatatypes: the types of one group are equal already; equal hints go
        let mut list: Vec<RangeHint> = Vec::with_capacity(self.maplist.len());
        let mut start = self.maplist[0];
        list.push(start);
        for &cur in &self.maplist[1..] {
            if cur.start == start.start && cur.size == start.size && cur.flags == start.flags {
                if list.last().is_some_and(|l| l.key() != cur.key()) {
                    list.push(cur);
                }
            } else {
                start = cur;
                list.push(cur);
            }
        }
        self.maplist = list;
        true
    }
}

/// Port of `ScopeLocal::adjustFit`.
fn adjust_fit(lm: &LocalMap, a: &mut RangeHint) -> bool {
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
        if maxsize < u64::from(a.ty) {
            return false;
        }
        a.size = maxsize as i32;
    }
    let Some(entry) = lm.find_overlap(a.start, a.size as i64 as u64) else { return true };
    if entry.off <= a.start {
        return false;
    }
    let maxsize = entry.off - a.start;
    if maxsize < u64::from(a.ty) {
        return false;
    }
    a.size = maxsize as i32;
    true
}

/// Port of `ScopeLocal::restructure`: the hints, merged and joined, become symbols.
fn restructure(fd: &mut Funcdata, state: &mut MapState) -> Result<()> {
    if !state.initialize() {
        return Ok(());
    }
    let (types, lm) = (&fd.types, &mut fd.localmap);
    let align = |ty: u32| i64::from(types.primitive_align_size(ty));
    let mut cur = state.maplist[0];
    for next in &state.maplist[1..] {
        if next.sstart < cur.sstart + i64::from(cur.size) {
            cur.merge(next, align)?;
        } else if !cur.attempt_join(next, align) {
            if cur.rt == RangeType::Open {
                cur.size = (next.sstart - cur.sstart) as i32;
                if cur.size < 0 {
                    cur.size = 0x7fff_ffff;
                }
            }
            if adjust_fit(lm, &mut cur) {
                // createEntry: an array when more than one element fits
                let al = align(cur.ty) as u64;
                let num = cur.size as u64 / al;
                let size = if num > 1 { num * al } else { u64::from(cur.ty) };
                lm.add_sym(cur.start, size, false);
            }
            cur = *next;
        }
    }
    Ok(())
}

/// Port of `ScopeLocal::fakeInputSymbols`: a symbol over each run of overlapping stack inputs
/// in the parameter range.
fn fake_input_symbols(fd: &mut Funcdata) {
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
        fd.localmap.add_sym(off, endpoint - off + 1, true);
    }
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

/// Port of `ScopeLocal::restructureVarnode`.
fn restructure_scope(fd: &mut Funcdata, arch: &Arch, aliasyes: bool) -> Result<()> {
    if fd.proto.locked.is_some() {
        return unported("a locked prototype");
    }
    if fd.localmap.params().is_empty() {
        return unported("a model without a stack parameter range");
    }
    fd.localmap.clear_syms(false);
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
        alias: Vec::new(),
    };
    state.gather_varnodes(fd)?;
    state.gather_open(fd, arch)?;
    // gatherSymbols: the symbols left are the fake inputs of the pass before, in the parameter
    // range, which the hints leave out
    if fd.localmap.sym_list().iter().any(|&s| {
        let s = fd.localmap.sym(s);
        in_range(&state.range, s.off, s.last - s.off + 1)
    }) {
        return unported("a fake input symbol in the local ranges");
    }
    restructure(fd, &mut state)?;
    let mut alias = state.alias;
    fd.localmap.clear_syms(true);
    fake_input_symbols(fd);
    alias.sort_unstable();
    if aliasyes {
        mark_unaliased(&mut fd.localmap, &alias);
        // checkUnaliasedReturn: the first RETURN's value
        let stack_value = |&op: &OpId| {
            let o = fd.op(op);
            !o.is_dead() && o.ins.get(1).is_some_and(|&v| fd.vn(v).space == Space::Stack)
        };
        if fd.ops_created_with(Opcode::Return).iter().any(stack_value) {
            return unported("a RETURN of a stack varnode (checkUnaliasedReturn)");
        }
    }
    if alias.first() == Some(&0) && fd.typerecovery_start {
        return unported("annotateRawStackPtr");
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

    /// Port of `Funcdata::syncVarnodesWithSymbols` for the stack space, without data-types:
    /// each stack varnode takes `mapped`, `addrtied` and `nolocalalias` from the symbol it
    /// overlaps, or from the scope. True when a varnode changed.
    pub(crate) fn sync_varnodes_with_symbols(&mut self, unmapped_alias_check: bool) -> bool {
        let tied = VnFlags::MAPPED.with(VnFlags::ADDRTIED);
        let mut updated = false;
        for vn in self.loc_space(Space::Stack) {
            let v = self.vn(vn);
            if v.is_free() {
                continue;
            }
            let (off, size) = (v.offset, v.size);
            let mut fl = match self.localmap.find_overlap(off, u64::from(size)) {
                Some(s) if s.noalias => tied.with(VnFlags::NOLOCALALIAS),
                Some(_) => tied,
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
        }
        updated
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

/// Port of `ActionRestructureVarnode::apply` in the partial function of jump-table recovery.
pub(crate) fn restructure_varnode(fd: &mut Funcdata, arch: &Arch) -> Result<i32> {
    // alias calculations are not reliable on the first pass
    let aliasyes = fd.restructure_passes != 0;
    restructure_scope(fd, arch, aliasyes)?;
    let changed = fd.sync_varnodes_with_symbols(aliasyes);
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

    fn hint(start: u64, size: u32) -> RangeHint {
        let sstart = i64::from(start as i32);
        RangeHint { start, size: size as i32, sstart, ty: size, flags: 0, rt: RangeType::Fixed, highind: -1 }
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
            maplist: vec![hint(0xffff_ffe0, 4), hint(0xffff_fff8, 4), hint(0xffff_fff2, 4), hint(0xffff_fff0, 4)],
            alias: Vec::new(),
        };
        restructure(&mut fd, &mut state).unwrap();
        fd.localmap.add_sym(4, 4, true);
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
