//! The stack part of the local scope (varmap.cc) the stack heritage pass needs: which stack
//! offsets the local scope owns (`ScopeLocal` and its range tree), `ScopeLocal::markNotMapped`,
//! and `ActionRestrictLocal`.
//!
//! Local symbols (database.cc) are not ported: the scope holds only the locked parameters of the
//! function's own prototype. `ScopeLocal::restructureVarnode` (MapState, RangeHint, the alias
//! checker) builds symbols, so `ActionRestructureVarnode` stays unported.

use super::fspec::{EffectKind, Storage};
use super::funcdata::Funcdata;
use super::opcode::Opcode;
use super::varnode::{Space, VarnodeId, VnFlags};
use super::{Arch, Result};
use std::collections::HashSet;

/// The stack ranges of `ScopeLocal`: sorted, disjoint, inclusive offset pairs, and the
/// parameter extent `markNotMapped` records (`minParamOffset`, `maxParamOffset`).
#[derive(Debug, Clone)]
pub(crate) struct LocalMap {
    ranges: Vec<(u64, u64)>,
    /// the stack space's highest offset (`AddrSpace::getHighest`)
    highest: u64,
    min_param: u64,
    max_param: u64,
    /// the last offset of the model's parameter range (`paramrange.getLastRange()->getLast()`,
    /// the default range `[0, highest >> 2]` when the input list has no stack entry)
    param_last: u64,
}

impl LocalMap {
    /// Port of `ScopeLocal::resetLocalWindow` for a stack that grows down: the model's local
    /// range (`ProtoModel::defaultLocalRange`, the upper half of the space; x86 declares none)
    /// and its parameter range, the stack `<pentry>` ranges of its input list
    /// (`ParamListStandard::getRangeList`; `params`, inclusive). `highest` is the stack space's
    /// highest offset (its offset mask, [`super::heritage_guard::stack_mask`]).
    pub(crate) fn new(highest: u64, params: &[(u64, u64)]) -> LocalMap {
        let mut m = LocalMap::empty();
        m.highest = highest;
        m.insert(highest - (highest >> 1).min(0x7fff_ffff), highest);
        for &(a, b) in params {
            m.insert(a, b);
        }
        // the last of the merged parameter ranges ends at the largest end
        m.param_last = params.iter().map(|&(_, b)| b).max().unwrap_or((highest >> 2).min(0x7fff_ffff));
        m
    }

    /// A scope owning nothing, before `Funcdata::start_processing` knows the architecture.
    pub(crate) fn empty() -> LocalMap {
        LocalMap { ranges: Vec::new(), highest: u64::MAX, min_param: u64::MAX, max_param: 0, param_last: 0 }
    }

    /// Port of `RangeList::insertRange`: overlapping ranges merge (touching ones do not).
    fn insert(&mut self, mut first: u64, mut last: u64) {
        let mut out = Vec::with_capacity(self.ranges.len() + 1);
        for &(a, b) in &self.ranges {
            if b < first || last < a {
                out.push((a, b));
            } else {
                first = first.min(a);
                last = last.max(b);
            }
        }
        out.push((first, last));
        out.sort_unstable();
        self.ranges = out;
    }

    /// The ranges the scope owns, in order (`Scope::printBounds`).
    pub(crate) fn ranges(&self) -> &[(u64, u64)] {
        &self.ranges
    }

    /// The stack space's highest offset.
    pub(crate) fn highest(&self) -> u64 {
        self.highest
    }

    /// `minParamOffset` and `maxParamOffset`: the extent of the stack parameters of calls
    /// (`markNotMapped`).
    pub(crate) fn min_param(&self) -> u64 {
        self.min_param
    }
    pub(crate) fn max_param(&self) -> u64 {
        self.max_param
    }

    /// `ProtoModel::getLocalRange().inRange(addr, 1)` for the default local range, the upper
    /// half of the space (`defaultLocalRange`; x86 declares no `<localrange>`).
    pub(crate) fn in_local_range(&self, off: u64) -> bool {
        off >= self.highest - (self.highest >> 1).min(0x7fff_ffff) && off <= self.highest
    }

    /// The locked-parameter "symbol" of the local scope holding stack offset `addr`
    /// (`Scope::queryContainer`): its offset and type.
    pub(crate) fn locked_param_at(fd: &Funcdata, addr: u64) -> Option<(u64, super::types::TypeId)> {
        let l = fd.proto.locked.as_ref()?;
        l.inputs.iter().find_map(|p| match p.storage {
            Some(Storage::Stack { offset, size }) if offset <= addr && addr < offset + u64::from(size) => {
                Some((offset, p.ty))
            }
            _ => None,
        })
    }

    /// Port of `RangeList::inRange` on the scope's ranges: whether one range holds
    /// `[off, off + size)` (`Scope::inScope`, the test `queryProperties` makes for an address
    /// without a symbol).
    pub(crate) fn in_scope(&self, off: u64, size: u32) -> bool {
        let at = self.ranges.partition_point(|&(first, _)| first <= off);
        let Some(&(_, last)) = at.checked_sub(1).and_then(|i| self.ranges.get(i)) else { return false };
        u128::from(off) + u128::from(size.max(1)) - 1 <= u128::from(last)
    }

    /// `[first, first + sz)` clipped to the top of the space (`markNotMapped`'s `last`).
    fn clipped_last(&self, first: u64, sz: u32) -> u64 {
        match first.checked_add(u64::from(sz.max(1)) - 1) {
            Some(l) if l <= self.highest => l,
            _ => self.highest,
        }
    }

    /// The first part of `ScopeLocal::markNotMapped`, before any symbol is looked at: a
    /// parameter range widens the parameter extent.
    fn widen_params(&mut self, first: u64, sz: u32) {
        let last = self.clipped_last(first, sz);
        self.min_param = self.min_param.min(first);
        self.max_param = self.max_param.max(last);
    }

    #[cfg(test)]
    /// The range part of `ScopeLocal::markNotMapped` (`removeRange`): `[first, first + sz)`,
    /// clipped to the top of the space, leaves the scope.
    fn remove(&mut self, first: u64, sz: u32, parameter: bool) {
        if parameter {
            self.widen_params(first, sz);
        }
        self.remove_range(first, sz);
    }

    fn remove_range(&mut self, first: u64, sz: u32) {
        let last = self.clipped_last(first, sz);
        let mut out = Vec::with_capacity(self.ranges.len() + 1);
        for &(a, b) in &self.ranges {
            if b < first || a > last {
                out.push((a, b));
                continue;
            }
            if a < first {
                out.push((a, first - 1));
            }
            if b > last {
                out.push((last + 1, b));
            }
        }
        self.ranges = out;
    }
}

/// The locked stack parameters of `fd`'s own prototype: `(offset, size, name)`, the only local
/// symbols ghidra-rs has.
fn locked_stack_params(fd: &Funcdata) -> Vec<(u64, u32, String)> {
    let Some(l) = &fd.proto.locked else { return Vec::new() };
    l.inputs
        .iter()
        .filter_map(|p| match p.storage {
            Some(Storage::Stack { offset, size }) => Some((offset, size, p.name.clone())),
            _ => None,
        })
        .collect()
}

/// Port of `ScopeLocal::markNotMapped`: the stack range is no longer mapped by the local
/// scope. A parameter range widens the parameter extent first; a typelocked symbol under it (a
/// locked parameter) keeps the range, with a warning unless both are parameters. Any other
/// local symbol under it (removed, or a `fake_input` that keeps the range, in the C++) fails
/// loudly: ghidra-rs's local scope holds none while this runs.
pub(crate) fn mark_not_mapped(fd: &mut Funcdata, space: Space, first: u64, sz: u32, parameter: bool) -> Result<()> {
    if space != Space::Stack {
        return Ok(());
    }
    if parameter {
        fd.localmap.widen_params(first, sz);
    }
    let end = u128::from(first) + u128::from(sz);
    let locked = locked_stack_params(fd);
    let other = fd.symtab.overlapping(super::scope::LOCAL, Space::Stack, first, sz).into_iter().any(|s| {
        let sym = fd.symtab.symbol(s);
        !(sym.flags.type_locked && sym.entries.iter().any(|e| locked.iter().any(|l| l.0 == e.offset)))
    });
    if other {
        return super::err(
            "markNotMapped over a local symbol that is not a locked parameter: not implemented in ghidra-rs yet",
        );
    }
    let hit = locked
        .into_iter()
        .find(|&(off, size, _)| u128::from(off) < end && u128::from(first) < u128::from(off) + u128::from(size));
    if let Some((_, _, name)) = hit {
        // every symbol here is a typelocked function parameter
        if !parameter {
            fd.warning_header(format!("Variable defined which should be unmapped: {name}"));
        }
        return Ok(());
    }
    fd.localmap.remove_range(first, sz);
    Ok(())
}

/// Port of `ActionRestrictLocal::apply`: the stack parameters of calls with a locked prototype
/// and the stack slots saved registers are copied to are not local variables.
pub(crate) fn restrict_local(fd: &mut Funcdata, arch: &Arch) -> Result<i32> {
    for i in 0..fd.qlst.len() {
        let call = fd.call(fd.qlst[i]);
        let (Some(locked), Some(base)) = (&call.proto.locked, call.stack_offset) else { continue };
        let mut marks = Vec::new();
        for p in &locked.inputs {
            match p.storage {
                Some(Storage::Stack { offset, size }) => marks.push((base.wrapping_add(offset), size)),
                // a join's stack pieces would be un-mapped, its register pieces are left alone;
                // ghidra-rs joins hold SLEIGH-space (register) pieces only
                Some(Storage::Join(_)) => {}
                _ => {}
            }
        }
        let mask = fd.localmap.highest;
        for (off, size) in marks {
            mark_not_mapped(fd, Space::Stack, off & mask, size, true)?;
        }
    }
    let Some(model) = fd.proto.model.map(|m| arch.spec.models.get(m)) else { return Ok(0) };
    for e in &model.effects {
        if e.kind == EffectKind::KilledByCall {
            continue;
        }
        let (space, off, size) = match e.storage {
            Storage::Space { space, offset, size } => (Space::Sleigh(space), offset, size),
            Storage::Stack { offset, size } => (Space::Stack, offset, size),
            Storage::Join(_) => continue,
        };
        let Some(vn) = fd.loc_at(space, off, size).into_iter().find(|&v| fd.vn(v).is_input()) else { continue };
        if !fd.vn(vn).has(VnFlags::UNAFFECTED) {
            continue;
        }
        let saves: Vec<_> = fd
            .vn(vn)
            .descend
            .iter()
            .filter(|&&op| fd.op(op).opc == Opcode::Copy)
            .filter_map(|&op| fd.op(op).out)
            .filter(|&out| fd.vn(out).space == Space::Stack) // isUnaffectedStorage
            .map(|out| (fd.vn(out).offset, fd.vn(out).size))
            .collect();
        for (off, size) in saves {
            mark_not_mapped(fd, Space::Stack, off, size, false)?;
        }
    }
    Ok(0)
}

/// Port of `AliasChecker` for the stack space as `ActionActiveParam` uses it (`gather` deferred,
/// then `hasLocalAlias`): a stack offset at or above the lowest local offset some pointer into
/// the stack reaches may be aliased. The stack grows down on every ghidra-rs target
/// (`direction == 1`).
#[derive(Debug, Default)]
pub(crate) struct AliasChecker {
    /// `aliasBoundary`, once calculated (`gatherInternal` runs at the first query)
    boundary: Option<u64>,
}

impl AliasChecker {
    /// Port of `AliasChecker::hasLocalAlias`.
    pub(crate) fn has_local_alias(&mut self, fd: &Funcdata, arch: &Arch, vn: VarnodeId) -> bool {
        let boundary = *self.boundary.get_or_insert_with(|| alias_boundary(fd, arch));
        let v = fd.vn(vn);
        v.space == Space::Stack && v.offset >= boundary
    }
}

/// Port of `AliasChecker::gatherInternal` (with `deriveBoundaries`): the lowest offset, at or
/// above the end of the parameter range, of a sum based on the input stack pointer.
fn alias_boundary(fd: &Funcdata, arch: &Arch) -> u64 {
    let (sp, off, size) = arch.spec.stack_pointer;
    let base = fd.loc_at(Space::Sleigh(sp), off, size).into_iter().find(|&v| fd.vn(v).is_input());
    // localExtreme is ~0 for a stack growing down; a model always has both ranges (the defaults:
    // ProtoModel::decode refuses <localrange> and <paramrange>), and without one
    // deriveBoundaries keeps localBoundary at 0x1000000
    let local_boundary = if fd.proto.model.is_some() { fd.localmap.param_last } else { 0x100_0000 };
    base.map_or(u64::MAX, |base| boundary_from(fd, base, local_boundary))
}

/// The loop of `gatherInternal`: sums of `base` at or above `local_boundary` (below it they
/// reference parameters) start the aliased region.
fn boundary_from(fd: &Funcdata, base: VarnodeId, local_boundary: u64) -> u64 {
    let mut boundary = u64::MAX;
    for b in gather_additive_base(fd, base) {
        // addressToByte with a word size of 1
        let offset = gather_offset(fd, b);
        if offset >= local_boundary && offset < boundary {
            boundary = offset;
        }
    }
    boundary
}

/// Port of `AliasChecker::gatherAdditiveBase`: the varnodes of the sums `start` is in that are
/// used other than in a further sum (the index terms are not needed here).
fn gather_additive_base(fd: &Funcdata, start: VarnodeId) -> Vec<VarnodeId> {
    let mut queue = vec![start];
    let mut marked: HashSet<VarnodeId> = HashSet::from([start]);
    let mut out = Vec::new();
    let mut i = 0;
    while i < queue.len() {
        let vn = queue[i];
        i += 1;
        let mut nonadduse = false;
        for &op in fd.vn(vn).descend.iter() {
            let o = fd.op(op);
            let follow = match o.opc {
                Opcode::Copy => {
                    nonadduse = true;
                    true
                }
                Opcode::IntSub if o.ins[1] == vn => {
                    nonadduse = true;
                    false
                }
                Opcode::IntSub | Opcode::IntAdd | Opcode::Ptradd | Opcode::Ptrsub | Opcode::Segmentop => true,
                _ => {
                    nonadduse = true;
                    false
                }
            };
            if let Some(sub) = o.out.filter(|_| follow) {
                if marked.insert(sub) {
                    queue.push(sub);
                }
            }
        }
        if nonadduse {
            out.push(vn);
        }
    }
    out
}

/// Port of `AliasChecker::gatherOffset`: the constant part of the sum `vn` is the result of
/// (64-bit wrapping arithmetic, as the C++ `uintb`).
fn gather_offset(fd: &Funcdata, vn: VarnodeId) -> u64 {
    let v = fd.vn(vn);
    if v.is_constant() {
        return v.offset;
    }
    let Some(def) = v.def else { return 0 };
    let d = fd.op(def);
    let res = match d.opc {
        Opcode::Copy => gather_offset(fd, d.ins[0]),
        Opcode::Ptrsub | Opcode::IntAdd => gather_offset(fd, d.ins[0]).wrapping_add(gather_offset(fd, d.ins[1])),
        Opcode::IntSub => gather_offset(fd, d.ins[0]).wrapping_sub(gather_offset(fd, d.ins[1])),
        Opcode::Ptradd => {
            let (index, mult) = (fd.vn(d.ins[1]), fd.vn(d.ins[2]));
            let base = gather_offset(fd, d.ins[0]);
            if index.is_constant() {
                base.wrapping_add(index.offset.wrapping_mul(mult.offset))
            } else if mult.offset == 1 {
                base.wrapping_add(gather_offset(fd, d.ins[1]))
            } else {
                base
            }
        }
        Opcode::Segmentop => gather_offset(fd, d.ins[2]),
        _ => 0,
    };
    res & super::rangeutil::calc_mask(v.size)
}

#[cfg(test)]
mod tests {
    use super::LocalMap;

    /// `AliasChecker::gatherInternal`: from ESP, `ESP + 8` passed to a call references a
    /// parameter (below the parameter range's end, 503); `ESP + -0x20` copied and then
    /// `ESP + -0x20 + 4` stored through start the aliased region at the lowest local offset
    /// reached, -0x20.
    #[test]
    fn stack_pointers_into_locals_start_the_alias_region() {
        use super::super::funcdata::Funcdata;
        use super::super::opcode::Opcode;
        use super::super::varnode::{Space, VarnodeId};
        let mut fd = Funcdata::new(0x1000);
        let b = fd.blocks.new_block(0x1000);
        let esp = fd.new_varnode(4, Space::Sleigh(3), 0x10);
        fd.vn_set(esp, super::VnFlags::INPUT);
        let op = |fd: &mut Funcdata, opc: Opcode, ins: &[VarnodeId]| {
            let o = fd.new_op(opc, 0x1000);
            let out = fd.new_varnode_out(4, Space::Sleigh(1), u64::from(o.0) * 4, o);
            for (i, &v) in ins.iter().enumerate() {
                fd.op_set_input(o, v, i).unwrap();
            }
            fd.op_insert_end(o, b);
            out
        };
        // a constant has one use
        let c = |fd: &mut Funcdata, v: u64| fd.new_constant(4, v);
        let k = c(&mut fd, 8);
        let param = op(&mut fd, Opcode::IntAdd, &[esp, k]);
        let k = c(&mut fd, 0x2000);
        op(&mut fd, Opcode::Call, &[k, param]);
        let k = c(&mut fd, 0xffff_ffe0);
        let local = op(&mut fd, Opcode::IntAdd, &[esp, k]);
        let copy = op(&mut fd, Opcode::Copy, &[local]);
        let k = c(&mut fd, 4);
        let field = op(&mut fd, Opcode::IntAdd, &[copy, k]);
        let (k, v) = (c(&mut fd, 1), c(&mut fd, 0));
        op(&mut fd, Opcode::Store, &[k, field, v]);
        assert_eq!(super::boundary_from(&fd, esp, 503), 0xffff_ffe0);
        // with nothing but the parameter reference, nothing is aliased
        assert_eq!(super::boundary_from(&fd, param, 503), u64::MAX);
    }

    #[test]
    fn default_window_is_params_and_locals() {
        // x86win: one stack <pentry> at offset 4, 500 bytes
        let m = LocalMap::new(0xffff_ffff, &[(4, 503)]);
        assert_eq!(m.ranges, vec![(4, 503), (0x8000_0000, 0xffff_ffff)]);
        assert!(m.in_scope(4, 4) && m.in_scope(500, 4));
        assert!(!m.in_scope(0, 4) && !m.in_scope(502, 4) && !m.in_scope(0x1000, 4));
        assert!(m.in_scope(0xffff_fffc, 4) && !m.in_scope(0xffff_fffe, 4));
        // touching ranges stay apart, so no varnode spans two of them; overlapping ones merge
        let m = LocalMap::new(0xffff_ffff, &[(0x7fff_fff0, 0x7fff_ffff), (4, 7), (8, 11), (6, 9)]);
        assert_eq!(m.ranges, vec![(4, 11), (0x7fff_fff0, 0x7fff_ffff), (0x8000_0000, 0xffff_ffff)]);
        assert!(!m.in_scope(0x7fff_fffc, 8));
        let m = LocalMap::new(0xffff_ffff, &[(4, 7), (8, 11)]);
        assert!(m.in_scope(4, 4) && !m.in_scope(4, 8));
    }

    #[test]
    fn removing_splits_and_records_the_parameter_extent() {
        let mut m = LocalMap::new(0xffff_ffff, &[(0, 511)]);
        m.remove(8, 4, true);
        assert_eq!(m.ranges[..2], [(0, 7), (12, 511)]);
        assert!(!m.in_scope(8, 1) && m.in_scope(4, 4) && !m.in_scope(4, 8));
        assert_eq!((m.min_param, m.max_param), (8, 11));
        // clipped at the top of the space
        m.remove(0xffff_fff0, 0x40, false);
        assert_eq!(m.ranges.last(), Some(&(0x8000_0000, 0xffff_ffef)));
        // a range covering a whole piece removes it
        m.remove(0, 8, false);
        assert_eq!(m.ranges[0], (12, 511));
    }
}
