//! Port of the `rangemap` template (rangemap.hh): records over inclusive ranges of a linear
//! domain, kept as a list of records and a multiset of disjoint sub-ranges ordered by their
//! last point, then a sub-sort. The record list order (what `ScopeInternal::printEntries`
//! walks) and the order of the sub-ranges holding one point (what `findContainer` walks) both
//! depend on the insertion history, so the multiset is reproduced with libstdc++'s placement of
//! equal keys (`_M_insert_equal`, the hinted `_M_insert_equal_`).
//!
//! Not ported: `find_overlap`, `find_first_after`, `find_last_before` (nothing ported calls them).

/// The sub-sort of a record (`SymbolRange::EntrySubsort`: space index, offset).
pub(crate) type Subsort = (u32, u64);

/// The earliest and the latest sub-sort (`EntrySubsort(false)`, `EntrySubsort(true)`).
pub(crate) const SUB_FIRST: Subsort = (0, 0);
pub(crate) const SUB_LAST: Subsort = (0xffff, 0);

/// `AddrRange`: one disjoint sub-range of a record.
#[derive(Debug, Clone, Copy)]
struct Part<K> {
    first: u64,
    last: u64,
    /// the record's whole range
    a: u64,
    b: u64,
    sub: Subsort,
    key: K,
}

/// Port of `rangemap<_recordtype>`; `K` names a record.
#[derive(Debug, Clone)]
pub(crate) struct RangeMap<K> {
    /// `tree`, in multiset order
    tree: Vec<Part<K>>,
    /// `record`, in list order
    list: Vec<K>,
}

impl<K> Default for RangeMap<K> {
    fn default() -> Self {
        RangeMap { tree: Vec::new(), list: Vec::new() }
    }
}

impl<K: Copy + PartialEq> RangeMap<K> {
    /// The records in list order (`begin_list` to `end_list`).
    pub(crate) fn records(&self) -> &[K] {
        &self.list
    }

    fn lower_bound(&self, last: u64, sub: Subsort) -> usize {
        self.tree.partition_point(|p| (p.last, p.sub) < (last, sub))
    }

    fn upper_bound(&self, last: u64, sub: Subsort) -> usize {
        self.tree.partition_point(|p| (p.last, p.sub) <= (last, sub))
    }

    /// `multiset::insert(hint, value)` as libstdc++ places it (`_M_get_insert_hint_equal_pos`,
    /// falling back to `_M_insert_equal_lower`). Returns the index the part went to.
    fn insert_hint(&mut self, hint: usize, part: Part<K>) -> usize {
        let key = (part.last, part.sub);
        let k = |p: &Part<K>| (p.last, p.sub);
        let n = self.tree.len();
        let pos = if hint == n {
            if n > 0 && key >= k(&self.tree[n - 1]) {
                n
            } else {
                self.upper_bound(key.0, key.1)
            }
        } else if key <= k(&self.tree[hint]) {
            if hint == 0 || key >= k(&self.tree[hint - 1]) {
                hint
            } else {
                self.upper_bound(key.0, key.1)
            }
        } else if hint == n - 1 || key <= k(&self.tree[hint + 1]) {
            hint + 1
        } else {
            self.lower_bound(key.0, key.1)
        };
        self.tree.insert(pos, part);
        pos
    }

    /// `unzip`: every sub-range holding `i` (the first at `iter`) splits after `i`. Returns how
    /// many parts went in at or before `iter`, so the caller's iterator stays on its element.
    fn unzip(&mut self, i: u64, iter: usize) -> usize {
        if self.tree[iter].last == i {
            return 0;
        }
        let (mut hint, mut it, mut shift) = (iter, iter, 0);
        while it < self.tree.len() && self.tree[it].first <= i {
            let old = self.tree[it];
            self.tree[it].first = i.wrapping_add(1);
            let pos = self.insert_hint(hint, Part { first: old.first, last: i, ..old });
            if pos <= hint {
                hint += 1;
                shift += 1;
            }
            if pos <= it {
                it += 1;
            }
            it += 1;
        }
        shift
    }

    /// `zip`: the sub-ranges ending at `i` (from `iter`) go, those starting after it extend back.
    fn zip(&mut self, mut i: u64, iter: usize) {
        let Some(f) = self.tree.get(iter).map(|p| p.first) else { return };
        while self.tree.get(iter).is_some_and(|p| p.last == i) {
            self.tree.remove(iter);
        }
        i = i.wrapping_add(1);
        let mut it = iter;
        while self.tree.get(it).is_some_and(|p| p.first == i) {
            self.tree[it].first = f;
            it += 1;
        }
    }

    /// Port of `rangemap::insert`: a record over `[a, b]`.
    pub(crate) fn insert(&mut self, key: K, a: u64, b: u64, sub: Subsort) {
        let mut f = a;
        let mut low = self.lower_bound(f, SUB_FIRST);
        if low < self.tree.len() && self.tree[low].first < f {
            low += self.unzip(f - 1, low);
        }
        // the record goes before the record of the first sub-range not below (b, sub)
        let spot = self.lower_bound(b, sub);
        let at = match self.tree.get(spot) {
            Some(p) => self.list.iter().position(|&r| r == p.key).unwrap_or(self.list.len()),
            None => self.list.len(),
        };
        self.list.insert(at, key);
        let part = |first, last| Part { first, last, a, b, sub, key };
        while low < self.tree.len() && self.tree[low].first <= b {
            if f <= self.tree[low].last {
                if f < self.tree[low].first {
                    if self.insert_hint(low, part(f, self.tree[low].first - 1)) <= low {
                        low += 1;
                    }
                    f = self.tree[low].first;
                }
                let last = self.tree[low].last;
                if last <= b {
                    if self.insert_hint(low, part(f, last)) <= low {
                        low += 1;
                    }
                    if last == b {
                        return;
                    }
                    f = last + 1;
                } else {
                    self.unzip(b, low);
                    break;
                }
            }
            low += 1;
        }
        if f <= b {
            let pos = self.upper_bound(b, sub);
            self.tree.insert(pos, part(f, b));
        }
    }

    /// Port of `rangemap::erase` of the record `key` over `[a, b]`.
    pub(crate) fn erase(&mut self, key: K, a: u64, b: u64) {
        let (mut leftsew, mut rightsew, mut rightoverlap, mut leftoverlap) = (true, true, false, false);
        let mut low = self.lower_bound(a, SUB_FIRST);
        let aminus1 = a.wrapping_sub(1);
        for p in self.tree[..low].iter().rev() {
            if p.last != aminus1 {
                break;
            }
            if p.b == aminus1 {
                leftsew = false; // still a split between a-1 and a
                break;
            }
        }
        while low < self.tree.len() && self.tree[low].first <= b {
            let p = self.tree[low];
            if p.key == key {
                self.tree.remove(low);
                continue;
            }
            if p.a < a {
                leftoverlap = true;
            } else if p.a == a {
                leftsew = false;
            }
            if b < p.b {
                rightoverlap = true;
            } else if p.b == b {
                rightsew = false;
            }
            low += 1;
        }
        if self.tree.get(low).is_some_and(|p| p.a.wrapping_sub(1) == b) {
            rightsew = false;
        }
        if leftsew && leftoverlap {
            self.zip(aminus1, self.lower_bound(aminus1, SUB_FIRST));
        }
        if rightsew && rightoverlap {
            self.zip(b, self.lower_bound(b, SUB_FIRST));
        }
        self.list.retain(|&r| r != key);
    }

    /// Port of `rangemap::find(point, sub1, sub2)`: the records of the sub-ranges holding
    /// `point` whose sub-sort is within the bounds, in multiset order.
    pub(crate) fn find(&self, point: u64, sub1: Subsort, sub2: Subsort) -> Vec<K> {
        let i1 = self.lower_bound(point, sub1);
        match self.tree.get(i1) {
            Some(p) if p.first <= point => {
                let i2 = self.upper_bound(p.last, sub2);
                self.tree[i1..i2.max(i1)].iter().map(|p| p.key).collect()
            }
            _ => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A record inside an earlier one is listed before it (it sorts by its last point), and
    /// both hold the inner points.
    #[test]
    fn inner_record_lists_first() {
        let mut m = RangeMap::default();
        m.insert('g', 0, 7, SUB_FIRST);
        m.insert('i', 4, 5, SUB_FIRST);
        assert_eq!(m.records(), ['i', 'g']);
        assert_eq!(m.find(4, SUB_FIRST, SUB_LAST).len(), 2);
        assert_eq!(m.find(2, SUB_FIRST, SUB_LAST), ['g']);
        assert_eq!(m.find(8, SUB_FIRST, SUB_LAST), Vec::<char>::new());
        m.erase('i', 4, 5);
        assert_eq!(m.records(), ['g']);
        assert_eq!(m.find(4, SUB_FIRST, SUB_LAST), ['g']);
        assert_eq!(m.tree.len(), 1);
    }

    /// Records over one range order by sub-sort; a new one goes before an equal one, and a
    /// use-point bound cuts the later ones off.
    #[test]
    fn equal_ranges_order_by_subsort() {
        let mut m = RangeMap::default();
        m.insert(1, 0, 3, (2, 0x10));
        m.insert(2, 0, 3, (2, 0x30));
        m.insert(3, 0, 3, (2, 0x10));
        assert_eq!(m.records(), [3, 1, 2]);
        assert_eq!(m.find(1, SUB_FIRST, SUB_LAST), [3, 1, 2]);
        assert_eq!(m.find(1, SUB_FIRST, (2, 0x20)), [3, 1]);
        m.insert(4, 8, 11, SUB_FIRST);
        assert_eq!(m.records(), [3, 1, 2, 4]);
    }
}
