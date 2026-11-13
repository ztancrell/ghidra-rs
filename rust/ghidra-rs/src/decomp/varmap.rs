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
use super::varnode::{Space, VnFlags};
use super::{err, Arch, Result};

/// The stack ranges of `ScopeLocal`: sorted, disjoint, inclusive offset pairs, and the
/// parameter extent `markNotMapped` records (`minParamOffset`, `maxParamOffset`).
#[derive(Debug, Clone)]
pub(crate) struct LocalMap {
    ranges: Vec<(u64, u64)>,
    /// the stack space's highest offset (`AddrSpace::getHighest`)
    highest: u64,
    min_param: u64,
    max_param: u64,
}

impl LocalMap {
    /// Port of `ScopeLocal::resetLocalWindow` with the model's default ranges
    /// (`ProtoModel::defaultLocalRange`, `defaultParamRange`; x86's models declare neither): the
    /// million bytes below the top of the stack space and the 512 bytes from offset 0, for a
    /// stack that grows down. `addr_size` is the stack space's address size in bytes.
    pub(crate) fn new(addr_size: u32) -> LocalMap {
        let highest = if addr_size >= 8 { u64::MAX } else { (1u64 << (8 * addr_size)) - 1 };
        let (local, param) = match addr_size {
            4.. => (999_999, 511),
            2..=3 => (9_999, 255),
            _ => (99, 15),
        };
        let mut ranges = vec![(0, param), (highest - local, highest)];
        ranges.dedup();
        LocalMap { ranges, highest, min_param: u64::MAX, max_param: 0 }
    }

    /// Port of `RangeList::inRange` on the scope's ranges: whether one range holds
    /// `[off, off + size)` (`Scope::inScope`, the test `queryProperties` makes for an address
    /// without a symbol).
    pub(crate) fn in_scope(&self, off: u64, size: u32) -> bool {
        let at = self.ranges.partition_point(|&(first, _)| first <= off);
        let Some(&(_, last)) = at.checked_sub(1).and_then(|i| self.ranges.get(i)) else { return false };
        u128::from(off) + u128::from(size.max(1)) - 1 <= u128::from(last)
    }

    /// The range part of `ScopeLocal::markNotMapped`: `[first, first + sz)`, clipped to the
    /// top of the space, leaves the scope; a parameter range widens the parameter extent.
    fn remove(&mut self, first: u64, sz: u32, parameter: bool) {
        let last = match first.checked_add(u64::from(sz.max(1)) - 1) {
            Some(l) if l <= self.highest => l,
            _ => self.highest,
        };
        if parameter {
            self.min_param = self.min_param.min(first);
            self.max_param = self.max_param.max(last);
        }
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
/// scope. A typelocked symbol under it (a locked parameter) keeps it, with a warning unless both
/// are parameters.
pub(crate) fn mark_not_mapped(fd: &mut Funcdata, space: Space, first: u64, sz: u32, parameter: bool) {
    if space != Space::Stack {
        return;
    }
    let end = u128::from(first) + u128::from(sz);
    let hit = locked_stack_params(fd)
        .into_iter()
        .find(|&(off, size, _)| u128::from(off) < end && u128::from(first) < u128::from(off) + u128::from(size));
    if let Some((_, _, name)) = hit {
        // every symbol here is a typelocked function parameter
        if !parameter {
            fd.warning_header(format!("Variable defined which should be unmapped: {name}"));
        }
        return;
    }
    fd.localmap.remove(first, sz, parameter);
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
                Some(Storage::Join(_)) => {
                    return err("ActionRestrictLocal: a locked join parameter: not implemented in ghidra-rs yet")
                }
                _ => {}
            }
        }
        let mask = fd.localmap.highest;
        for (off, size) in marks {
            mark_not_mapped(fd, Space::Stack, off & mask, size, true);
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
            mark_not_mapped(fd, Space::Stack, off, size, false);
        }
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::LocalMap;

    #[test]
    fn default_window_is_params_and_locals() {
        let m = LocalMap::new(4);
        assert_eq!(m.ranges, vec![(0, 511), (0xfff0_bdc0, 0xffff_ffff)]);
        assert!(m.in_scope(4, 4));
        assert!(m.in_scope(508, 4));
        assert!(!m.in_scope(510, 4));
        assert!(!m.in_scope(0x1000, 4));
        assert!(m.in_scope(0xffff_fffc, 4));
        assert!(!m.in_scope(0xffff_fffe, 4));
    }

    #[test]
    fn removing_splits_and_records_the_parameter_extent() {
        let mut m = LocalMap::new(4);
        m.remove(8, 4, true);
        assert_eq!(m.ranges[..2], [(0, 7), (12, 511)]);
        assert!(!m.in_scope(8, 1) && m.in_scope(4, 4) && !m.in_scope(4, 8));
        assert_eq!((m.min_param, m.max_param), (8, 11));
        // clipped at the top of the space
        m.remove(0xffff_fff0, 0x40, false);
        assert_eq!(m.ranges.last(), Some(&(0xfff0_bdc0, 0xffff_ffef)));
        // a range covering a whole piece removes it
        m.remove(0, 8, false);
        assert_eq!(m.ranges[0], (12, 511));
    }
}
