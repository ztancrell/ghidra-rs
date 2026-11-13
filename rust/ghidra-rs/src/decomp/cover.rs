//! Port of `cover.cc` (stage S7): the code ranges a varnode or high variable is live over, per
//! basic block, and the intersection tests merging is built on.
//!
//! A [`CoverBlock`] bounds a range within one block by two points. The C++ uses op pointers
//! with three special values (0 start of block, 1 end of block, 2 the function's input); here
//! they are [`Pt`]. Points are compared by `getUIndex`, which reads the op's current position
//! (`SeqNum::order`), so ops inserted later keep covers consistent as in the C++.

use std::collections::BTreeMap;

use super::funcdata::Funcdata;
use super::op::OpId;
use super::opcode::Opcode;
use super::varnode::VarnodeId;

/// A point of a [`CoverBlock`]: the C++ `const PcodeOp *` with its special values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Pt {
    /// null: the start of the block (and, with a null stop, an empty block)
    Begin,
    /// 1: the end of the block
    End,
    /// 2: the function's input
    Input,
    Op(OpId),
}

/// Port of `CoverBlock`: a range within one basic block, possibly wrapping (two pieces).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CoverBlock {
    pub(crate) start: Pt,
    pub(crate) stop: Pt,
}

impl Default for CoverBlock {
    fn default() -> CoverBlock {
        CoverBlock { start: Pt::Begin, stop: Pt::Begin }
    }
}

/// `CoverBlock::getUIndex` for an op: its position in its block, an INDIRECT at the op it is
/// indirect for, a MULTIEQUAL at the very start.
pub(crate) fn op_uindex(fd: &Funcdata, op: OpId) -> u32 {
    let o = fd.op(op);
    match o.opc {
        Opcode::Multiequal => 0,
        Opcode::Indirect => match o.ins.get(1).and_then(|&iop| fd.iop_target(iop)) {
            Some(target) => fd.op(target).order,
            None => o.order,
        },
        _ => o.order,
    }
}

impl CoverBlock {
    /// `CoverBlock::empty`
    pub(crate) fn empty(&self) -> bool {
        self.start == Pt::Begin && self.stop == Pt::Begin
    }
    /// `CoverBlock::setAll`
    pub(crate) fn set_all(&mut self) {
        self.start = Pt::Begin;
        self.stop = Pt::End;
    }

    /// Port of `CoverBlock::getUIndex`; `ui` gives an op's index ([`op_uindex`]).
    pub(crate) fn uindex(p: Pt, ui: &dyn Fn(OpId) -> u32) -> u32 {
        match p {
            Pt::Begin | Pt::Input => 0,
            Pt::End => u32::MAX,
            Pt::Op(op) => ui(op),
        }
    }

    /// Port of `CoverBlock::intersect`: 0 none, 1 a boundary point, 2 an interval.
    pub(crate) fn intersect(&self, op2: &CoverBlock, ui: &dyn Fn(OpId) -> u32) -> i32 {
        if self.empty() || op2.empty() {
            return 0;
        }
        let (us, ue) = (Self::uindex(self.start, ui), Self::uindex(self.stop, ui));
        let (u2s, u2e) = (Self::uindex(op2.start, ui), Self::uindex(op2.stop, ui));
        let boundary = |a: bool| if a { 1 } else { 0 };
        if us <= ue {
            if u2s <= u2e {
                if ue <= u2s || u2e <= us {
                    return boundary(us == u2e || ue == u2s);
                }
            } else if us >= u2e && ue <= u2s {
                return boundary(us == u2e || ue == u2s);
            }
        } else if u2s <= u2e && u2s >= ue && u2e <= us {
            return boundary(u2s == ue || u2e == us);
        }
        2
    }

    /// Port of `CoverBlock::contain`.
    pub(crate) fn contain(&self, point: Pt, ui: &dyn Fn(OpId) -> u32) -> bool {
        if self.empty() {
            return false;
        }
        let up = Self::uindex(point, ui);
        let (us, ue) = (Self::uindex(self.start, ui), Self::uindex(self.stop, ui));
        if us <= ue {
            up >= us && up <= ue
        } else {
            up <= ue || up >= us
        }
    }

    /// Port of `CoverBlock::boundary`: 2 the point starts the range (and is not the block
    /// start), 1 it ends it, 0 neither.
    pub(crate) fn boundary(&self, point: Pt, ui: &dyn Fn(OpId) -> u32) -> i32 {
        if self.empty() {
            return 0;
        }
        let val = Self::uindex(point, ui);
        if Self::uindex(self.start, ui) == val && self.start != Pt::Begin {
            return 2;
        }
        if Self::uindex(self.stop, ui) == val {
            return 1;
        }
        0
    }

    /// Port of `CoverBlock::merge`.
    pub(crate) fn merge(&mut self, op2: &CoverBlock, ui: &dyn Fn(OpId) -> u32) {
        if op2.empty() {
            return;
        }
        if self.empty() {
            *self = *op2;
            return;
        }
        let ustart = Self::uindex(self.start, ui);
        let u2start = Self::uindex(op2.start, ui);
        let internal4 = ustart == 0 && op2.stop == Pt::End;
        let internal1 = internal4 || op2.contain(self.start, ui);
        let internal3 = u2start == 0 && self.stop == Pt::End;
        let internal2 = internal3 || self.contain(op2.start, ui);
        if internal1 && internal2 && (ustart != u2start || internal3 || internal4) {
            self.set_all();
            return;
        }
        if internal1 {
            self.start = op2.start;
        } else if !internal2 {
            if ustart < u2start {
                self.stop = op2.stop;
            } else {
                self.start = op2.start;
            }
            return;
        }
        if internal3 || op2.contain(self.stop, ui) {
            self.stop = op2.stop;
        }
    }
}

/// Port of `Cover`: a [`CoverBlock`] per block index.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Cover {
    pub(crate) blocks: BTreeMap<i32, CoverBlock>,
}

impl Cover {
    /// Port of `Cover::compareTo`: by the first block covered.
    pub(crate) fn compare_to(&self, op2: &Cover) -> std::cmp::Ordering {
        let first = |c: &Cover| c.blocks.keys().next().copied().unwrap_or(1_000_000);
        first(self).cmp(&first(op2))
    }

    /// The block pairs both covers have, with their intersection value.
    fn paired<'a>(&'a self, op2: &'a Cover, ui: &'a dyn Fn(OpId) -> u32) -> impl Iterator<Item = (i32, i32)> + 'a {
        self.blocks.iter().filter_map(move |(k, b)| op2.blocks.get(k).map(|b2| (*k, b.intersect(b2, ui))))
    }

    /// Port of `Cover::intersect(const Cover &)`: 0 none, 1 points only, 2 an interval.
    pub(crate) fn intersect(&self, op2: &Cover, ui: &dyn Fn(OpId) -> u32) -> i32 {
        let mut res = 0;
        for (_, v) in self.paired(op2, ui) {
            if v == 2 {
                return 2;
            }
            res = res.max(v);
        }
        res
    }

    /// Port of `Cover::intersectList`: the blocks where the covers intersect at `level` or more.
    pub(crate) fn intersect_list(&self, op2: &Cover, level: i32, ui: &dyn Fn(OpId) -> u32) -> Vec<i32> {
        self.paired(op2, ui).filter(|&(_, v)| v >= level).map(|(k, _)| k).collect()
    }

    /// Port of `Cover::intersectByBlock`.
    pub(crate) fn intersect_by_block(&self, blk: i32, op2: &Cover, ui: &dyn Fn(OpId) -> u32) -> i32 {
        match (self.blocks.get(&blk), op2.blocks.get(&blk)) {
            (Some(a), Some(b)) => a.intersect(b, ui),
            _ => 0,
        }
    }

    /// Port of `Cover::contain`: `max` 1 counts the boundary, 2 does not.
    pub(crate) fn contain(&self, blk: i32, op: OpId, max: i32, ui: &dyn Fn(OpId) -> u32) -> bool {
        match self.blocks.get(&blk) {
            Some(b) if b.contain(Pt::Op(op), ui) => max == 1 || b.boundary(Pt::Op(op), ui) == 0,
            _ => false,
        }
    }

    /// Port of `Cover::merge`.
    pub(crate) fn merge(&mut self, op2: &Cover, ui: &dyn Fn(OpId) -> u32) {
        for (k, b) in &op2.blocks {
            self.blocks.entry(*k).or_default().merge(b, ui);
        }
    }
}

/// The block index of an op in a basic block.
pub(crate) fn op_block_index(fd: &Funcdata, op: OpId) -> i32 {
    fd.op(op).parent.map_or(-1, |b| fd.blocks.block(b).index)
}

/// Port of `Cover::containVarnodeDef`: 0 the def point is outside, 1 inside, 2 at the start of
/// the range, 3 at its end.
pub(crate) fn contain_varnode_def(fd: &Funcdata, cover: &Cover, vn: VarnodeId) -> i32 {
    let (pt, blk) = match fd.vn(vn).def {
        None => (Pt::Input, 0),
        Some(op) => (Pt::Op(op), op_block_index(fd, op)),
    };
    let ui = |o| op_uindex(fd, o);
    match cover.blocks.get(&blk) {
        Some(b) if b.contain(pt, &ui) => match b.boundary(pt, &ui) {
            0 => 1,
            2 => 2,
            _ => 3,
        },
        _ => 0,
    }
}

/// Port of `Cover::addDefPoint`: the cover restarts at the varnode's definition.
pub(crate) fn add_def_point(fd: &Funcdata, cover: &mut Cover, vn: VarnodeId) {
    cover.blocks.clear();
    let v = fd.vn(vn);
    if let Some(def) = v.def {
        let b = CoverBlock { start: Pt::Op(def), stop: Pt::Op(def) };
        cover.blocks.insert(op_block_index(fd, def), b);
    } else if v.is_input() {
        cover.blocks.insert(0, CoverBlock { start: Pt::Input, stop: Pt::Input });
    }
}

/// Port of `Cover::addRefRecurse`: fill the block and, where it was empty, its predecessors.
fn add_ref_recurse(fd: &Funcdata, cover: &mut Cover, bl: super::block::BlockId) {
    // an explicit stack instead of the C++ recursion: the order of fills does not matter
    let ui = |o| op_uindex(fd, o);
    let mut stack = vec![bl];
    while let Some(bl) = stack.pop() {
        let b = fd.blocks.block(bl);
        let block = cover.blocks.entry(b.index).or_default();
        let preds = || b.ins.iter().rev().map(|e| e.point);
        if block.empty() {
            block.set_all();
            stack.extend(preds());
            continue;
        }
        let op = block.stop;
        let ustart = CoverBlock::uindex(block.start, &ui);
        let ustop = CoverBlock::uindex(op, &ui);
        if ustop != u32::MAX && ustop >= ustart {
            block.stop = Pt::End;
        }
        if ustop == 0 && block.start == Pt::Begin {
            if let Pt::Op(o) = op {
                if fd.op(o).opc == Opcode::Multiequal {
                    stack.extend(preds());
                }
            }
        }
    }
}

/// Port of `Cover::addRefPoint`: extend the cover to a read of `vn` by `rf`.
pub(crate) fn add_ref_point(fd: &Funcdata, cover: &mut Cover, rf: OpId, vn: VarnodeId) {
    let ui = |o| op_uindex(fd, o);
    let Some(bl) = fd.op(rf).parent else { return };
    let b = fd.blocks.block(bl);
    let block = cover.blocks.entry(b.index).or_default();
    let is_multi = fd.op(rf).opc == Opcode::Multiequal;
    if block.empty() {
        block.stop = Pt::Op(rf);
    } else if block.contain(Pt::Op(rf), &ui) {
        if !is_multi {
            return;
        }
    } else {
        let (op, startop) = (block.stop, block.start);
        block.stop = Pt::Op(rf);
        let ustop = CoverBlock::uindex(block.stop, &ui);
        if ustop >= CoverBlock::uindex(startop, &ui) {
            if let Pt::Op(o) = op {
                if fd.op(o).opc == Opcode::Multiequal && startop == Pt::Begin {
                    for e in &b.ins {
                        add_ref_recurse(fd, cover, e.point);
                    }
                }
            }
            return;
        }
    }
    if is_multi {
        for (j, &input) in fd.op(rf).ins.iter().enumerate() {
            if input == vn {
                if let Some(e) = b.ins.get(j) {
                    add_ref_recurse(fd, cover, e.point);
                }
            }
        }
    } else {
        for e in &b.ins {
            add_ref_recurse(fd, cover, e.point);
        }
    }
}

/// Port of `Cover::rebuild`: the cover of `vn` from its definition and reads, through the
/// outputs `implied` says are implied (they print inside the expression reading `vn`).
pub(crate) fn rebuild(fd: &Funcdata, vn: VarnodeId, implied: &dyn Fn(VarnodeId) -> bool) -> Cover {
    let mut cover = Cover::default();
    add_def_point(fd, &mut cover, vn);
    let mut path = vec![vn];
    let mut pos = 0;
    while pos < path.len() {
        let cur = path[pos];
        pos += 1;
        for &op in fd.vn(cur).descend.iter() {
            add_ref_point(fd, &mut cover, op, vn);
            if let Some(out) = fd.op(op).out {
                if implied(out) {
                    path.push(out);
                }
            }
        }
    }
    cover
}

/// Port of `PcodeOpSet` (finalized): ops sorted by block index, then position, with the index
/// where each block's ops start.
#[derive(Debug, Clone, Default)]
pub(crate) struct OpSet {
    /// (block index, op)
    ops: Vec<(i32, OpId)>,
    /// `blockStart`
    starts: Vec<usize>,
}

impl OpSet {
    /// Port of `PcodeOpSet::finalize` over `(block index, order, op)`: `std::sort` by
    /// `compareByBlock` (ties as libstdc++ leaves them), then the block starts.
    pub(crate) fn finalize(mut list: Vec<(i32, u32, OpId)>) -> OpSet {
        super::stdsort::sort(&mut list, |a, b| if a.0 != b.0 { a.0 < b.0 } else { a.1 < b.1 });
        let mut set = OpSet::default();
        let mut block = -1;
        for (i, &(b, _, op)) in list.iter().enumerate() {
            if b > block {
                set.starts.push(i);
                block = b;
            }
            set.ops.push((b, op));
        }
        set
    }

    /// Port of `Cover::intersect(const PcodeOpSet &, Varnode *)` (`affectsTest` always true):
    /// some op lies strictly inside `cover`. Ported with its walk exactly: after a block it
    /// tested, the set's block index is not refreshed, so the set block right after it is
    /// skipped when the cover moves on.
    pub(crate) fn intersects(&self, cover: &Cover, ui: &dyn Fn(OpId) -> u32) -> bool {
        let Some(&(first, _)) = self.ops.first() else { return false };
        let mut set_block = 0;
        let mut op_index = self.starts[0];
        let mut set_index = self.ops[op_index].0;
        let mut iter = cover.blocks.range(first..).peekable();
        while let Some(&(&cover_index, cblock)) = iter.peek() {
            if cover_index < set_index {
                iter.next();
            } else if cover_index > set_index {
                set_block += 1;
                if set_block >= self.starts.len() {
                    break;
                }
                op_index = self.starts[set_block];
                set_index = self.ops[op_index].0;
            } else {
                iter.next();
                set_block += 1;
                let op_max = self.starts.get(set_block).copied().unwrap_or(self.ops.len());
                while op_index < op_max {
                    let pt = Pt::Op(self.ops[op_index].1);
                    if cblock.contain(pt, ui) && cblock.boundary(pt, ui) == 0 {
                        return true;
                    }
                    op_index += 1;
                }
                if set_block >= self.starts.len() {
                    break;
                }
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ops numbered by their own id: OpId(n) sits at index n
    fn ui(op: OpId) -> u32 {
        op.0
    }
    fn blk(a: u32, b: u32) -> CoverBlock {
        CoverBlock { start: Pt::Op(OpId(a)), stop: Pt::Op(OpId(b)) }
    }

    #[test]
    fn block_intersections() {
        assert_eq!(blk(10, 20).intersect(&blk(30, 40), &ui), 0);
        assert_eq!(blk(10, 20).intersect(&blk(20, 40), &ui), 1);
        assert_eq!(blk(10, 30).intersect(&blk(20, 40), &ui), 2);
        assert_eq!(CoverBlock::default().intersect(&blk(1, 2), &ui), 0);
        // a two-piece range (wrapping through a loop) against a one-piece one
        assert_eq!(blk(30, 10).intersect(&blk(15, 25), &ui), 0);
        assert_eq!(blk(30, 10).intersect(&blk(10, 25), &ui), 1);
        assert_eq!(blk(30, 10).intersect(&blk(5, 25), &ui), 2);
        assert_eq!(blk(30, 10).intersect(&blk(40, 5), &ui), 2);
    }

    #[test]
    fn block_contain_and_boundary() {
        let b = blk(10, 20);
        assert!(b.contain(Pt::Op(OpId(15)), &ui));
        assert!(!b.contain(Pt::Op(OpId(25)), &ui));
        assert_eq!(b.boundary(Pt::Op(OpId(10)), &ui), 2);
        assert_eq!(b.boundary(Pt::Op(OpId(20)), &ui), 1);
        assert_eq!(b.boundary(Pt::Op(OpId(15)), &ui), 0);
        let all = CoverBlock { start: Pt::Begin, stop: Pt::End };
        assert!(all.contain(Pt::Op(OpId(7)), &ui));
        // the block start is not a boundary the range starts at
        assert_eq!(all.boundary(Pt::Begin, &ui), 0);
    }

    #[test]
    fn block_merge() {
        let mut a = blk(10, 20);
        a.merge(&blk(15, 30), &ui);
        assert_eq!(a, blk(10, 30));
        let mut d = blk(10, 20);
        d.merge(&blk(30, 40), &ui);
        assert_eq!(d, blk(10, 40));
        let mut e = CoverBlock { start: Pt::Begin, stop: Pt::Op(OpId(5)) };
        e.merge(&CoverBlock { start: Pt::Op(OpId(8)), stop: Pt::End }, &ui);
        // begin-5 and 8-end: one wrapping range
        assert_eq!(e, blk(8, 5));
    }

    #[test]
    fn cover_intersect() {
        let mut a = Cover::default();
        a.blocks.insert(0, blk(10, 20));
        a.blocks.insert(2, blk(1, 5));
        let mut b = Cover::default();
        b.blocks.insert(1, blk(10, 20));
        b.blocks.insert(2, blk(5, 9));
        assert_eq!(a.intersect(&b, &ui), 1);
        assert_eq!(a.intersect_list(&b, 1, &ui), vec![2]);
        b.blocks.insert(0, blk(15, 16));
        assert_eq!(a.intersect(&b, &ui), 2);
        assert_eq!(a.intersect_list(&b, 2, &ui), vec![0]);
        assert_eq!(a.compare_to(&b), std::cmp::Ordering::Equal);
        assert_eq!(Cover::default().compare_to(&b), std::cmp::Ordering::Greater);
    }

    #[test]
    fn op_set_walk() {
        // calls in blocks 2, 4 and 6 (given out of order: finalize sorts them)
        let set = OpSet::finalize(vec![(6, 9, OpId(9)), (2, 5, OpId(5)), (4, 7, OpId(7))]);
        let mut cover = Cover::default();
        cover.blocks.insert(2, CoverBlock { start: Pt::Op(OpId(10)), stop: Pt::End });
        cover.blocks.insert(4, CoverBlock { start: Pt::Begin, stop: Pt::End });
        // the block 2 call is before the cover starts; the C++ walk then skips block 4's call
        assert!(!set.intersects(&cover, &ui));
        cover.blocks.insert(2, CoverBlock { start: Pt::Op(OpId(3)), stop: Pt::End });
        assert!(set.intersects(&cover, &ui));
        // a cover starting at block 4 reaches its call
        cover.blocks.remove(&2);
        assert!(set.intersects(&cover, &ui));
        assert!(!OpSet::default().intersects(&cover, &ui));
    }
}
