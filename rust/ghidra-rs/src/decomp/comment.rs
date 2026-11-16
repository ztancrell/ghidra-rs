//! Port of `CommentSorter` (comment.cc): the body comments of a function (the warnings at an
//! address, `Comment::warning`, which `Funcdata::warning` records), each placed at a statement
//! of a basic block, for `print C` to emit before that statement. The header warnings
//! (`Comment::warningheader`) are printed from `Funcdata::warnings` by `emitCommentFuncHeader`
//! and are not sorted here: every one sits at the function's entry, the `header_basic` group.
//!
//! The C++ walks a `map<Subsort, Comment *>` with three iterators; here the map is a sorted
//! vector and the iterators are positions in it.

use super::op::OpId;
use super::{Funcdata, LowlevelError, Result};

/// `CommentSorter::Subsort` without `pos`: the basic block index and the op's order in it
/// (`0xffffffff`: after every op of the block).
type Key = (i32, u32);

/// Port of `CommentSorter`.
#[derive(Debug, Default)]
pub(crate) struct CommentSorter {
    /// (block index, order, pos) and the comment's index in `Funcdata::comments`, sorted
    commmap: Vec<((i32, u32, u32), usize)>,
    /// `Comment::isEmitted`, by index in `Funcdata::comments`
    emitted: Vec<bool>,
    start: usize,
    stop: usize,
    opstop: usize,
}

impl CommentSorter {
    /// Port of `setupFunctionList` (no unplaced comments: `option_unplaced` is off). The
    /// comments are visited in the comment database's order, by address and then in the order
    /// they were added (`uniq`).
    pub(crate) fn setup_function_list(fd: &Funcdata) -> Result<CommentSorter> {
        let mut order: Vec<usize> = (0..fd.comments.len()).collect();
        order.sort_by_key(|&i| fd.comments[i].0); // stable: same address keeps insertion order
        let mut placed = Vec::new();
        for i in order {
            if let Some(key) = find_position(fd, fd.comments[i].0)? {
                placed.push((key, i));
            }
        }
        Ok(CommentSorter::from_placed(placed, fd.comments.len()))
    }

    /// The map from the placed comments in database order (`pos` counts them).
    fn from_placed(placed: Vec<(Key, usize)>, ncomments: usize) -> CommentSorter {
        let mut commmap: Vec<_> =
            placed.into_iter().enumerate().map(|(pos, ((index, ord), c))| ((index, ord, pos as u32), c)).collect();
        commmap.sort_unstable();
        CommentSorter { commmap, emitted: vec![false; ncomments], ..CommentSorter::default() }
    }

    fn lower_bound(&self, k: (i32, u32, u32)) -> usize {
        self.commmap.partition_point(|&(e, _)| e < k)
    }

    fn upper_bound(&self, k: (i32, u32, u32)) -> usize {
        self.commmap.partition_point(|&(e, _)| e <= k)
    }

    /// Port of `setupBlockList`: the comments of the basic block with index `index`.
    pub(crate) fn setup_block_list(&mut self, index: i32) {
        self.start = self.lower_bound((index, 0, 0));
        self.stop = self.upper_bound((index, u32::MAX, u32::MAX));
    }

    /// Port of `setupOpList`: stop after the comments up to the statement rooted at the op of
    /// block `index` with order `order`; `None` (a null op) takes the rest of the block.
    pub(crate) fn setup_op_list(&mut self, op: Option<(i32, u32)>) {
        self.opstop = match op {
            None => self.stop,
            Some((index, order)) => self.upper_bound((index, order, u32::MAX)),
        };
    }

    /// `hasNext` and `getNext` (the C++ compares the iterators for inequality; `start` never
    /// passes `opstop` while ops print in block order).
    pub(crate) fn next(&mut self) -> Option<usize> {
        if self.start >= self.opstop {
            return None;
        }
        let c = self.commmap[self.start].1;
        self.start += 1;
        Some(c)
    }

    pub(crate) fn is_emitted(&self, c: usize) -> bool {
        self.emitted[c]
    }

    pub(crate) fn set_emitted(&mut self, c: usize) {
        self.emitted[c] = true;
    }
}

/// `BlockBasic::contains` of the block holding `op`: its index when `addr` is in the block's
/// cover (the ranges `spliceBlockBasic` merged, else `start`..=`stop`).
fn block_contains(fd: &Funcdata, op: OpId, addr: u64) -> Result<Option<i32>> {
    let bb = fd.op(op).parent.ok_or_else(|| LowlevelError("Dead op reaching CommentSorter".into()))?;
    let b = fd.blocks.block(bb);
    let inside = if b.cover.is_empty() {
        (b.start..=b.stop).contains(&addr)
    } else {
        b.cover.iter().any(|&(s, e)| (s..=e).contains(&addr))
    };
    Ok(inside.then_some(b.index))
}

/// Port of `CommentSorter::findPosition` for a body comment at `addr`: the block and op order
/// to print it at, none when its block was removed (an unplaced comment, not printed).
fn find_position(fd: &Funcdata, addr: u64) -> Result<Option<Key>> {
    let (next, prev) = fd.main_ops_around(addr);
    let mut backup = None;
    if let Some(op) = next {
        if let Some(index) = block_contains(fd, op, addr)? {
            return Ok(Some((index, fd.op(op).order)));
        }
        if fd.op(op).seq.addr == addr {
            backup = Some(op);
        }
    }
    if let Some(op) = prev {
        if let Some(index) = block_contains(fd, op, addr)? {
            return Ok(Some((index, u32::MAX)));
        }
    }
    if let Some(op) = backup {
        // the op may have moved from its block; the address matches exactly
        let bb = fd.op(op).parent.ok_or_else(|| LowlevelError("Dead op reaching CommentSorter".into()))?;
        return Ok(Some((fd.blocks.block(bb).index, fd.op(op).order)));
    }
    if next.is_none() && prev.is_none() {
        return Ok(Some((0, 0)));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn drain(s: &mut CommentSorter) -> Vec<usize> {
        std::iter::from_fn(|| s.next()).collect()
    }

    #[test]
    fn sorts_by_block_then_order_then_database_order() {
        // database order: comments 0..5; keys (block, order)
        let placed = vec![((2, 5), 0), ((1, u32::MAX), 1), ((1, 3), 2), ((2, 5), 3), ((1, 3), 4)];
        let mut s = CommentSorter::from_placed(placed, 5);
        s.setup_block_list(1);
        s.setup_op_list(Some((1, 2)));
        assert!(drain(&mut s).is_empty(), "nothing at or before order 2");
        s.setup_op_list(Some((1, 3)));
        assert_eq!(drain(&mut s), vec![2, 4], "same key: database order");
        s.setup_op_list(None);
        assert_eq!(drain(&mut s), vec![1], "the end of the block");
        s.setup_block_list(2);
        s.setup_op_list(None);
        assert_eq!(drain(&mut s), vec![0, 3]);
        s.setup_block_list(3);
        s.setup_op_list(None);
        assert!(drain(&mut s).is_empty());
    }

    #[test]
    fn emitted_marks() {
        let mut s = CommentSorter::from_placed(vec![((0, 0), 1)], 2);
        assert!(!s.is_emitted(1));
        s.set_emitted(1);
        assert!(s.is_emitted(1) && !s.is_emitted(0));
    }
}
