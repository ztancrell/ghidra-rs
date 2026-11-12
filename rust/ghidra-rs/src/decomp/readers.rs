//! A varnode's reader list (`Varnode::descend`) without a heap allocation for the common case.
//!
//! Most varnodes have 0 to 2 readers, so a `Vec<OpId>` per varnode costs an allocation each,
//! time and memory (measured with `SmallVec<[OpId; 4]>`: about 0.8 s and 82 MB over the mercs2
//! Mall). Up to 4 readers live inline; the fifth moves the list to a `Vec`, which it keeps
//! (no shrinking back). Order is insertion order and `remove` shifts, exactly as `Vec` does,
//! since output depends on it. The slice view (`Deref`) gives `len`, `first`, `iter`, ...
//!
//! The inline length is not stored: unused slots hold `EMPTY` (no arena reaches 2^32 - 1 ops),
//! which keeps the enum at a `Vec`'s 24 bytes (a length byte would make it 32).

use super::op::OpId;
use std::ops::Deref;

const INLINE: usize = 4;
const EMPTY: OpId = OpId(u32::MAX);

#[derive(Debug, Clone)]
pub(crate) enum Readers {
    /// the readers first, then `EMPTY` in the unused slots
    Inline([OpId; INLINE]),
    Heap(Vec<OpId>),
}

impl Default for Readers {
    fn default() -> Readers {
        Readers::Inline([EMPTY; INLINE])
    }
}

impl Deref for Readers {
    type Target = [OpId];
    fn deref(&self) -> &[OpId] {
        match self {
            Readers::Inline(a) => &a[..a.iter().position(|&o| o == EMPTY).unwrap_or(INLINE)],
            Readers::Heap(v) => v,
        }
    }
}

impl Readers {
    pub(crate) fn push(&mut self, op: OpId) {
        assert!(op != EMPTY, "op id reserved for empty reader slots");
        let n = self.len();
        match self {
            Readers::Inline(a) if n < INLINE => a[n] = op,
            Readers::Inline(a) => {
                let mut v = Vec::with_capacity(2 * INLINE);
                v.extend_from_slice(a);
                v.push(op);
                *self = Readers::Heap(v);
            }
            Readers::Heap(v) => v.push(op),
        }
    }

    /// Removes the element at `i`, shifting the rest left (`Vec::remove`).
    pub(crate) fn remove(&mut self, i: usize) {
        let n = self.len();
        match self {
            Readers::Inline(a) => {
                assert!(i < n, "reader index out of range");
                a.copy_within(i + 1..n, i);
                a[n - 1] = EMPTY;
            }
            Readers::Heap(v) => {
                v.remove(i);
            }
        }
    }

    pub(crate) fn clear(&mut self) {
        match self {
            Readers::Inline(a) => *a = [EMPTY; INLINE],
            Readers::Heap(v) => v.clear(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(r: &Readers) -> Vec<u32> {
        r.iter().map(|o| o.0).collect()
    }

    fn filled(n: u32) -> Readers {
        let mut r = Readers::default();
        for i in 0..n {
            r.push(OpId(i));
        }
        r
    }

    #[test]
    fn size_is_a_vec() {
        assert_eq!(std::mem::size_of::<Readers>(), std::mem::size_of::<Vec<OpId>>());
    }

    #[test]
    fn inline_then_heap() {
        let mut r = Readers::default();
        assert!(r.is_empty());
        for i in 0..4 {
            r.push(OpId(i));
            assert!(matches!(r, Readers::Inline(..)));
        }
        r.push(OpId(4));
        assert!(matches!(r, Readers::Heap(_)));
        r.push(OpId(5));
        assert_eq!(ids(&r), [0, 1, 2, 3, 4, 5]);
        r.clear();
        assert!(r.is_empty());
    }

    #[test]
    fn remove_keeps_order_at_every_position() {
        for n in [1, 3, 4, 6] {
            for i in 0..n {
                let mut r = filled(n);
                r.remove(i as usize);
                let want: Vec<u32> = (0..n).filter(|&k| k != i).collect();
                assert_eq!(ids(&r), want, "n {n} remove {i}");
                r.push(OpId(99));
                assert_eq!(*ids(&r).last().unwrap(), 99);
                assert_eq!(r.len(), n as usize);
            }
        }
    }
}
