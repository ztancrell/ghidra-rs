//! Stage S8 part two: `ActionPreferComplement` and `ActionStructureTransform` (blockaction.cc)
//! with what they call: `getSplitPoint`, `flipInPlaceTest`/`flipInPlaceExecute` of the block
//! kinds, `preferComplement` of `BlockIfElse`/`BlockIfNoExit`, `finalTransform` (the basic
//! block's `opNormalizeFlip` and `BlockWhileDo`'s for-loop recovery: `findLoopVariable`,
//! `findInitializer`, `PcodeOp::isMoveable`), and `Funcdata::opFlipInPlaceTest` /
//! `opFlipInPlaceExecute` (funcdata_op.cc). The boolean-flip table, `opNormalizeFlip` and
//! `replaceLessequal` are R2's (`rules`).

use super::block::BlockId;
use super::op::{OpFlags, OpId};
use super::opcode::Opcode;
use super::structure::{Kind, SId, Structure, F_FINAL_TRANSFORM, F_WHILEDO_OVERFLOW, ROOT};
use super::varnode::VnFlags;
use super::{err, Arch, Funcdata, Result};

/// Deepest expression or hierarchy nesting followed before giving up loudly (the C++ recurses
/// without a bound).
const MAX_DEPTH: usize = 1000;

/// A block `getSplitPoint` returns: a two-way basic block or a condition.
#[derive(Debug, Clone, Copy)]
enum Split {
    Basic(BlockId),
    Cond(SId),
}

/// `ActionPreferComplement` (allowing op removal, as the instance before `assignhigh` does).
pub(crate) fn prefer_complement(fd: &mut Funcdata, _: &Arch) -> Result<i32> {
    let mut s = std::mem::take(&mut fd.structure);
    let res = s.prefer_complement_all(fd, true);
    fd.structure = s;
    fd.clear_dead_ops();
    res
}

/// `ActionStructureTransform` (allowing op moves).
pub(crate) fn structure_transform(fd: &mut Funcdata, _: &Arch) -> Result<i32> {
    let mut s = std::mem::take(&mut fd.structure);
    let res = s.final_transform(fd, true);
    fd.structure = s;
    res.map(|()| 0)
}

impl Structure {
    /// `ActionPreferComplement::apply`: each graph block, breadth first, may swap its clauses.
    fn prefer_complement_all(&mut self, fd: &mut Funcdata, allow: bool) -> Result<i32> {
        if self.is_empty() || self.flag(ROOT, F_FINAL_TRANSFORM) {
            return Ok(0);
        }
        let mut count = 0;
        let mut vec = vec![ROOT];
        let mut pos = 0;
        while pos < vec.len() {
            let cur = vec[pos];
            pos += 1;
            vec.extend(self.b(cur).list.iter().copied().filter(|&c| !matches!(self.b(c).kind, Kind::Copy(_))));
            if self.prefer(fd, cur, allow)? {
                count += 1;
            }
        }
        Ok(count)
    }

    /// `preferComplement`: `BlockIfElse` and `BlockIfNoExit` flip their condition in place and
    /// swap the clauses; other kinds do nothing.
    fn prefer(&mut self, fd: &mut Funcdata, b: SId, allow: bool) -> Result<bool> {
        let noexit = match self.b(b).kind {
            Kind::IfElse => false,
            Kind::IfNoExit => true,
            _ => return Ok(false),
        };
        let mut diff = 0;
        if noexit {
            let (b1, b2) = (self.b(b).list[1], self.b(b).list[2]);
            diff = self.b(b1).depth - self.b(b2).depth;
            if diff < 0 {
                return Ok(false);
            }
            if diff == 0 {
                diff = self.b(b1).leaf_count - self.b(b2).leaf_count;
                if diff < 0 {
                    return Ok(false);
                }
                if diff == 0 {
                    let (h1, h2) = (self.halt_type(fd, b1), self.halt_type(fd, b2));
                    if h1 > h2 {
                        return Ok(false);
                    }
                    if h1 < h2 {
                        diff = 1;
                    }
                }
            }
        }
        let Some(split) = self.split_point(fd, self.b(b).list[0]) else { return Ok(false) };
        let mut fliplist = Vec::new();
        let test = self.flip_test(fd, split, &mut fliplist, allow, 0)?;
        if test == 2 || (test != 0 && (!noexit || diff == 0)) {
            return Ok(false);
        }
        self.flip_execute(fd, split, 0)?;
        op_flip_in_place_execute(fd, &fliplist)?;
        self.bm(b).list.swap(1, 2);
        Ok(true)
    }

    /// `FlowBlock::getHaltType` of the block's last op (the C++ flag bits).
    fn halt_type(&self, fd: &Funcdata, b: SId) -> u32 {
        use super::op::Halt;
        match self.last_op(fd, b).and_then(|op| fd.op(op).halt) {
            Some(Halt::BadInstruction) => 0x400000,
            Some(Halt::Unimplemented) => 0x800000,
            None => 0,
        }
    }

    /// `lastOp`: a copy's basic block's last op; a list's last component's; a condition's
    /// second component's; a goto, multi-goto or if-goto block's component 0; an if (no exit)
    /// block's component 2; none for the other kinds.
    pub(crate) fn last_op(&self, fd: &Funcdata, mut b: SId) -> Option<OpId> {
        loop {
            let bl = self.b(b);
            b = match bl.kind {
                Kind::Copy(bb) => return fd.blocks.block(bb).ops.last().copied(),
                Kind::List => *bl.list.last()?,
                Kind::Condition(_) => *bl.list.get(1)?,
                Kind::Goto(_) | Kind::MultiGoto { .. } | Kind::IfGoto(_) => *bl.list.first()?,
                Kind::IfNoExit => *bl.list.get(2)?,
                _ => return None,
            };
        }
    }

    /// `getSplitPoint` (a copy asks its basic block, which splits when it has two outputs).
    fn split_point(&self, fd: &Funcdata, mut b: SId) -> Option<Split> {
        loop {
            let bl = self.b(b);
            b = match bl.kind {
                Kind::Copy(bb) => return (fd.blocks.block(bb).outs.len() == 2).then_some(Split::Basic(bb)),
                Kind::List => *bl.list.last()?,
                Kind::Condition(_) => return Some(Split::Cond(b)),
                _ => return None,
            };
        }
    }

    /// `flipInPlaceTest`: 0 the flip normalizes, 1 it does not, 2 it cannot be done.
    fn flip_test(&self, fd: &Funcdata, s: Split, list: &mut Vec<OpId>, allow: bool, depth: usize) -> Result<i32> {
        if depth > MAX_DEPTH {
            return err("flipInPlaceTest: condition nesting too deep");
        }
        match s {
            Split::Basic(bb) => {
                let Some(&last) = fd.blocks.block(bb).ops.last() else { return Ok(2) };
                if fd.op(last).opc != Opcode::Cbranch {
                    return Ok(2);
                }
                if fd.op(last).flags.has(OpFlags::BOOLEAN_FLIP) {
                    op_flip_in_place_test(fd, last, &mut Vec::new(), allow, 0)
                } else {
                    op_flip_in_place_test(fd, last, list, allow, 0)
                }
            }
            Split::Cond(c) => {
                let l = &self.b(c).list;
                let (Some(s1), Some(s2)) = (self.split_point(fd, l[0]), self.split_point(fd, l[1])) else {
                    return Ok(2);
                };
                let t1 = self.flip_test(fd, s1, list, allow, depth + 1)?;
                if t1 == 2 || self.flip_test(fd, s2, list, allow, depth + 1)? == 2 {
                    return Ok(2);
                }
                Ok(t1)
            }
        }
    }

    /// `flipInPlaceExecute`.
    fn flip_execute(&mut self, fd: &mut Funcdata, s: Split, depth: usize) -> Result<()> {
        if depth > MAX_DEPTH {
            return err("flipInPlaceExecute: condition nesting too deep");
        }
        match s {
            Split::Basic(bb) => {
                let Some(&last) = fd.blocks.block(bb).ops.last() else { return err("flip of an empty block") };
                let fl = &mut fd.op_mut(last).flags;
                if fl.has(OpFlags::FALLTHRU_TRUE) {
                    fl.clear(OpFlags::FALLTHRU_TRUE);
                } else {
                    fl.set(OpFlags::FALLTHRU_TRUE);
                }
                fl.clear(OpFlags::BOOLEAN_FLIP);
                fd.blocks.swap_edges(bb);
            }
            Split::Cond(c) => {
                let Kind::Condition(opc) = self.b(c).kind else { return err("not a condition") };
                let opc = if opc == Opcode::BoolAnd { Opcode::BoolOr } else { Opcode::BoolAnd };
                self.bm(c).kind = Kind::Condition(opc);
                let (l0, l1) = (self.b(c).list[0], self.b(c).list[1]);
                for child in [l0, l1] {
                    let Some(sp) = self.split_point(fd, child) else { return err("condition without split point") };
                    self.flip_execute(fd, sp, depth + 1)?;
                }
            }
        }
        Ok(())
    }

    /// `BlockGraph::finalTransform` from the root, post-order (a work stack): each graph not yet
    /// transformed transforms its components, then itself (`BlockWhileDo`'s for loop), then is
    /// marked; a copy normalizes its basic block's flipped CBRANCH.
    fn final_transform(&mut self, fd: &mut Funcdata, allow_moves: bool) -> Result<()> {
        if self.is_empty() || self.flag(ROOT, F_FINAL_TRANSFORM) {
            return Ok(());
        }
        let mut stack = vec![(ROOT, false)];
        while let Some((b, done)) = stack.pop() {
            match self.b(b).kind {
                Kind::Copy(bb) => basic_final_transform(fd, bb)?,
                _ if done => {
                    if self.b(b).kind == Kind::WhileDo {
                        self.while_do_transform(fd, b, allow_moves)?;
                    }
                    self.bm(b).flags |= F_FINAL_TRANSFORM;
                }
                _ if self.flag(b, F_FINAL_TRANSFORM) => {}
                _ => {
                    stack.push((b, true));
                    stack.extend(self.b(b).list.iter().rev().map(|&c| (c, false)));
                }
            }
        }
        Ok(())
    }

    /// `getFrontLeaf`: component 0 down to a copy.
    fn front_leaf(&self, mut b: SId) -> Option<BlockId> {
        loop {
            match self.b(b).kind {
                Kind::Copy(bb) => return Some(bb),
                _ => b = *self.b(b).list.first()?,
            }
        }
    }

    /// The for-loop part of `BlockWhileDo::finalTransform` (`analyze_for_loops` is on).
    fn while_do_transform(&mut self, fd: &mut Funcdata, b: SId, allow_moves: bool) -> Result<()> {
        if self.flag(b, F_WHILEDO_OVERFLOW) {
            return Ok(());
        }
        let Some(head) = self.front_leaf(b) else { return Ok(()) };
        let (c0, c1) = (self.b(b).list[0], self.b(b).list[1]);
        let Some(mut last) = self.last_op(fd, c1) else { return Ok(()) };
        let Some(tail) = fd.op(last).parent else { return Ok(()) };
        if fd.blocks.block(tail).outs.len() != 1 || fd.blocks.block(tail).outs[0].point != head {
            return Ok(());
        }
        let Some(cbranch) = self.last_op(fd, c0).filter(|&op| fd.op(op).opc == Opcode::Cbranch) else {
            return Ok(());
        };
        if fd.op(last).is_branch() {
            let Some(prev) = previous_op(fd, last) else { return Ok(()) };
            last = prev;
        }
        let Some((loop_def, iterate)) = find_loop_variable(fd, cbranch, head, tail, last) else { return Ok(()) };
        let fl = &mut self.bm(b).for_loop;
        fl.loop_def = Some(loop_def);
        fl.iterate = Some(iterate);
        if iterate != last {
            if !allow_moves {
                return Ok(());
            }
            fd.op_uninsert(iterate);
            fd.op_insert_after(iterate, last)?;
        }
        let slot = fd.blocks.block(tail).outs[0].reverse;
        let Some((init, last)) = find_initializer(fd, head, slot, loop_def) else { return Ok(()) };
        if !is_moveable(fd, init, last) {
            return Ok(());
        }
        self.bm(b).for_loop.initialize = Some(init);
        if init != last {
            if !allow_moves {
                return Ok(());
            }
            fd.op_uninsert(init);
            fd.op_insert_after(init, last)?;
        }
        Ok(())
    }
}

/// `BlockBasic::finalTransform`: a flipped CBRANCH ending a two-way block is normalized.
fn basic_final_transform(fd: &mut Funcdata, bb: BlockId) -> Result<()> {
    let bl = fd.blocks.block(bb);
    if bl.outs.len() != 2 {
        return Ok(());
    }
    let Some(&cb) = bl.ops.last() else { return Ok(()) };
    if fd.op(cb).opc != Opcode::Cbranch || !fd.op(cb).flags.has(OpFlags::BOOLEAN_FLIP) {
        return Ok(());
    }
    super::rules::op_normalize_flip(fd, cb).map(|_| ())
}

/// `PcodeOp::previousOp`: the op before `op` in its block.
fn previous_op(fd: &Funcdata, op: OpId) -> Option<OpId> {
    let ops = &fd.blocks.block(fd.op(op).parent?).ops;
    let i = ops.iter().position(|&o| o == op)?;
    ops.get(i.checked_sub(1)?).copied()
}

/// `Funcdata::opFlipInPlaceTest`: can the boolean expression ending at `op` be complemented
/// in place, and would it normalize (0) or not (1); 2 when it cannot. The ops to change go in
/// `list`, in post-order.
fn op_flip_in_place_test(fd: &Funcdata, op: OpId, list: &mut Vec<OpId>, allow: bool, depth: usize) -> Result<i32> {
    use Opcode::*;
    if depth > MAX_DEPTH {
        return err("opFlipInPlaceTest: expression too deep");
    }
    let o = fd.op(op);
    // the input written by an op that only `op` reads
    let sole_def = |vn| (fd.vn(vn).descend[..] == [op]).then(|| fd.vn(vn).def).flatten();
    Ok(match o.opc {
        Cbranch => {
            let Some(d) = o.ins.get(1).and_then(|&v| sole_def(v)) else { return Ok(2) };
            let t = op_flip_in_place_test(fd, d, list, allow, depth + 1)?;
            if t != 2 && o.flags.has(OpFlags::BOOLEAN_FLIP) {
                1 - t
            } else {
                t
            }
        }
        IntEqual | FloatEqual => {
            list.push(op);
            1
        }
        BoolNegate => {
            if !allow {
                return Ok(2);
            }
            list.push(op);
            0
        }
        IntNotequal | FloatNotequal => {
            list.push(op);
            0
        }
        IntSless | IntLess => {
            list.push(op);
            i32::from(!fd.vn(o.ins[0]).is_constant())
        }
        IntSlessequal | IntLessequal => {
            list.push(op);
            i32::from(fd.vn(o.ins[1]).is_constant())
        }
        BoolOr | BoolAnd => {
            let Some(d0) = sole_def(o.ins[0]) else { return Ok(2) };
            let t1 = op_flip_in_place_test(fd, d0, list, allow, depth + 1)?;
            if t1 == 2 {
                return Ok(2);
            }
            let Some(d1) = sole_def(o.ins[1]) else { return Ok(2) };
            if op_flip_in_place_test(fd, d1, list, allow, depth + 1)? == 2 {
                return Ok(2);
            }
            list.push(op);
            t1
        }
        _ => 2,
    })
}

/// `Funcdata::opFlipInPlaceExecute`.
fn op_flip_in_place_execute(fd: &mut Funcdata, list: &[OpId]) -> Result<()> {
    for &op in list {
        match super::rules::boolean_flip(fd.op(op).opc) {
            // a BOOL_NEGATE goes: its reader reads its input
            Some((Opcode::Copy, _)) => {
                let vn = fd.op(op).ins[0];
                let Some(out) = fd.op(op).out else { return err("BOOL_NEGATE without output") };
                let [other] = fd.vn(out).descend[..] else { return err("flipped BOOL_NEGATE has several readers") };
                let Some(slot) = fd.slot_of(other, out) else { return err("reader lost its input") };
                fd.op_set_input(other, vn, slot)?;
                fd.op_destroy(op);
            }
            None => {
                let opc = match fd.op(op).opc {
                    Opcode::BoolAnd => Opcode::BoolOr,
                    Opcode::BoolOr => Opcode::BoolAnd,
                    _ => return err("Bad flipInPlace op"),
                };
                fd.op_set_opcode(op, opc);
            }
            Some((opc, reorder)) => {
                fd.op_set_opcode(op, opc);
                if reorder {
                    fd.op_swap_input(op, 0, 1);
                    if matches!(opc, Opcode::IntLessequal | Opcode::IntSlessequal) {
                        super::rules::replace_lessequal(fd, op)?;
                    }
                }
            }
        }
    }
    Ok(())
}

/// `BlockWhileDo::findLoopVariable`: walking at most three ops up from the CBRANCH's
/// condition, a MULTIEQUAL in `head` whose input along the tail edge is written in `tail` by an
/// op that can move to `last`: that MULTIEQUAL and the iterate op.
fn find_loop_variable(fd: &Funcdata, cbranch: OpId, head: BlockId, tail: BlockId, last: OpId) -> Option<(OpId, OpId)> {
    let op = fd.vn(*fd.op(cbranch).ins.get(1)?).def?;
    let slot = fd.blocks.block(tail).outs.first()?.reverse;
    if fd.op(op).is_call() || fd.op(op).is_marker() {
        return None;
    }
    let mut path: Vec<(OpId, usize)> = vec![(op, 0)];
    while let Some(top) = path.last_mut() {
        let (cur, ind) = *top;
        top.1 += 1;
        let Some(&next) = fd.op(cur).ins.get(ind) else {
            path.pop();
            continue;
        };
        let Some(def) = fd.vn(next).def else { continue };
        let d = fd.op(def);
        if d.opc == Opcode::Multiequal {
            if d.parent != Some(head) {
                continue;
            }
            let Some(it) = d.ins.get(slot).and_then(|&v| fd.vn(v).def) else { continue };
            if fd.op(it).parent == Some(tail) {
                if fd.op(it).is_marker() || !is_moveable(fd, it, last) {
                    continue;
                }
                return Some((def, it));
            }
        } else if path.len() < 4 && !d.is_call() && !d.is_marker() {
            path.push((def, 0));
        }
    }
    None
}

/// `BlockWhileDo::findInitializer`: the op writing the loop variable's value on entry, in the
/// block flowing into `head` (its only exit), and the op it would move after.
fn find_initializer(fd: &Funcdata, head: BlockId, slot: usize, loop_def: OpId) -> Option<(OpId, OpId)> {
    let h = fd.blocks.block(head);
    if h.ins.len() != 2 {
        return None;
    }
    let slot = 1 - slot;
    let res = fd.vn(*fd.op(loop_def).ins.get(slot)?).def?;
    if fd.op(res).is_marker() {
        return None;
    }
    let initial = fd.op(res).parent?;
    if initial != h.ins[slot].point || fd.blocks.block(initial).outs.len() != 1 {
        return None;
    }
    let mut last = *fd.blocks.block(initial).ops.last()?;
    if fd.op(last).is_branch() {
        last = previous_op(fd, last)?;
    }
    Some((res, last))
}

/// `getEvalType() == PcodeOp::special`: the TypeOps with the `special` flag (typeop.cc).
fn is_special(opc: Opcode) -> bool {
    use Opcode::*;
    matches!(
        opc,
        Load | Store
            | Branch
            | Cbranch
            | Branchind
            | Call
            | Callind
            | Callother
            | Return
            | Multiequal
            | Indirect
            | Cast
            | Segmentop
            | Cpoolref
            | New
    )
}

/// `PcodeOp::isMoveable`: can `op` move to just after `point`, later in the same block. (The C++
/// walks past the block's end when `point` is not after `op`; that is `false` here.)
fn is_moveable(fd: &Funcdata, op: OpId, point: OpId) -> bool {
    if op == point {
        return true;
    }
    let o = fd.op(op);
    let special = is_special(o.opc);
    let moving_load = special && o.opc == Opcode::Load;
    if special && !moving_load {
        return false;
    }
    let (Some(bl), true) = (o.parent, o.parent == fd.op(point).parent) else { return false };
    let porder = fd.op(point).order;
    if let Some(out) = o.out {
        let reads_before = fd.vn(out).descend.iter().any(|&r| fd.op(r).parent == Some(bl) && fd.op(r).order <= porder);
        if reads_before {
            return false;
        }
    }
    let tied = |v: super::varnode::VarnodeId| fd.vn(v).flags.has(VnFlags::ADDRTIED);
    let free_of_tie = |v| !tied(v) && !fd.vn(v).flags.has(VnFlags::PERSIST);
    let cross_calls = !special && o.out.is_some_and(free_of_tie) && o.ins.iter().all(|&v| free_of_tie(v));
    let tied_list: Vec<_> = o.ins.iter().copied().filter(|&v| tied(v)).collect();
    let ops = &fd.blocks.block(bl).ops;
    let Some(start) = ops.iter().position(|&x| x == op) else { return false };
    let Some(end) = ops.iter().position(|&x| x == point).filter(|&e| e > start) else { return false };
    for &other in &ops[start + 1..=end] {
        let p = fd.op(other);
        if is_special(p.opc) {
            let ok = match p.opc {
                Opcode::Load => !o.out.is_some_and(tied),
                Opcode::Store => !moving_load && tied_list.is_empty() && !o.out.is_some_and(tied),
                Opcode::Indirect | Opcode::Segmentop | Opcode::Cpoolref => true,
                Opcode::Call | Opcode::Callind | Opcode::New => cross_calls,
                _ => false,
            };
            if !ok {
                return false;
            }
        }
        if let Some(pout) = p.out {
            if moving_load && tied(pout) {
                return false;
            }
            let po = fd.vn(pout);
            for &t in &tied_list {
                let tv = fd.vn(t);
                if tv.space == po.space
                    && tv.offset < po.offset + u64::from(po.size)
                    && po.offset < tv.offset + u64::from(tv.size)
                {
                    return false;
                }
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    //! Hand-built graphs; the expected results are derived by hand from the C++ (block.cc,
    //! blockaction.cc, funcdata_op.cc), not run on the reference.
    use super::super::varnode::VarnodeId;
    use super::*;

    struct Build {
        fd: Funcdata,
        b: Vec<BlockId>,
    }

    impl Build {
        fn new(n: u64, edges: &[(usize, usize)]) -> Build {
            let mut fd = Funcdata::new(0x1000);
            fd.uniq = Some(1);
            let b: Vec<BlockId> = (0..n).map(|i| fd.blocks.new_block(0x1000 + 0x10 * i)).collect();
            fd.blocks.set_start_block(b[0]);
            for &(f, t) in edges {
                fd.blocks.add_edge(b[f], b[t]);
            }
            Build { fd, b }
        }

        /// An op `opc(ins)` at the end of block `bl`, with a 4-byte unique output unless `out`
        /// is false.
        fn op(&mut self, bl: usize, opc: Opcode, ins: &[VarnodeId], out: bool) -> (OpId, Option<VarnodeId>) {
            let fd = &mut self.fd;
            let addr = fd.blocks.block(self.b[bl]).start;
            let op = fd.new_op(opc, addr);
            let o = out.then(|| fd.new_unique_out(4, 1, op));
            for (i, &v) in ins.iter().enumerate() {
                fd.op_set_input(op, v, i).unwrap();
            }
            fd.op_insert_end(op, self.b[bl]);
            (op, o)
        }

        fn c(&mut self, v: u64) -> VarnodeId {
            self.fd.new_constant(4, v)
        }
    }

    /// I -> H; H -> {B, X}; B -> H. I: i0 = COPY #0; H: m = MULTIEQUAL(i0, i1),
    /// c = INT_LESS(m, #10), CBRANCH c; B: i1 = INT_ADD(m, #1), y = COPY m. The clause B is
    /// out 0, so `ruleBlockWhileDo` negates H. `structuretransform` then normalizes H's flip
    /// (INT_LESS(m,#10) -> INT_LESSEQUAL(#10,m) -> INT_LESS(#9,m)), finds the loop variable m
    /// (iterate i1, moved after y) and the initializer i0 (already last in I).
    #[test]
    fn for_loop() {
        let mut t = Build::new(4, &[(0, 1), (1, 2), (1, 3), (2, 1)]);
        let zero = t.c(0);
        let (init, i0) = t.op(0, Opcode::Copy, &[zero], true);
        let (multi, m) = t.op(1, Opcode::Multiequal, &[], true);
        let ten = t.c(10);
        let (less, c) = t.op(1, Opcode::IntLess, &[m.unwrap(), ten], true);
        let dest = t.c(0);
        let (cb, _) = t.op(1, Opcode::Cbranch, &[dest, c.unwrap()], false);
        let one = t.c(1);
        let (iter, i1) = t.op(2, Opcode::IntAdd, &[m.unwrap(), one], true);
        let (y, _) = t.op(2, Opcode::Copy, &[m.unwrap()], true);
        t.fd.op_set_input(multi, i0.unwrap(), 0).unwrap();
        t.fd.op_set_input(multi, i1.unwrap(), 1).unwrap();
        let mut fd = t.fd;
        fd.blocks.structure_loops().unwrap();
        assert_eq!(super::super::structure::build_and_collapse(&mut fd).unwrap(), 1);
        assert!(fd.op(cb).flags.has(OpFlags::BOOLEAN_FLIP));
        let mut s = std::mem::take(&mut fd.structure);
        s.final_transform(&mut fd, true).unwrap();
        let whiledo = (0..s.blocks.len() as u32).map(SId).find(|&b| s.b(b).kind == Kind::WhileDo).unwrap();
        let fl = s.b(whiledo).for_loop;
        assert_eq!((fl.loop_def, fl.iterate, fl.initialize), (Some(multi), Some(iter), Some(init)));
        assert!(!fd.op(cb).flags.has(OpFlags::BOOLEAN_FLIP));
        assert_eq!(fd.op(less).opc, Opcode::IntLess);
        assert_eq!(fd.vn(fd.op(less).ins[0]).offset, 9);
        assert_eq!(fd.blocks.block(t.b[2]).ops, vec![y, iter]);
        assert!(s.flag(ROOT, F_FINAL_TRANSFORM));
    }

    /// A -> {B, C}, B -> D, C -> D, with A's CBRANCH on c = INT_NOTEQUAL(x, #0): if/else with
    /// B as the false clause. `preferComplement` flips in place (NOTEQUAL normalizes: test 0):
    /// INT_EQUAL, A's out edges swap, and the clauses swap.
    #[test]
    fn prefer_complement_if_else() {
        let mut t = Build::new(4, &[(0, 1), (0, 2), (1, 3), (2, 3)]);
        let five = t.c(5);
        let (_, x) = t.op(0, Opcode::Copy, &[five], true);
        let zero = t.c(0);
        let (ne, c) = t.op(0, Opcode::IntNotequal, &[x.unwrap(), zero], true);
        let dest = t.c(0);
        let (cb, _) = t.op(0, Opcode::Cbranch, &[dest, c.unwrap()], false);
        let mut fd = t.fd;
        fd.blocks.structure_loops().unwrap();
        super::super::structure::build_and_collapse(&mut fd).unwrap();
        let mut s = std::mem::take(&mut fd.structure);
        assert_eq!(s.prefer_complement_all(&mut fd, true).unwrap(), 1);
        assert_eq!(fd.op(ne).opc, Opcode::IntEqual);
        assert!(fd.op(cb).flags.has(OpFlags::FALLTHRU_TRUE));
        assert_eq!(fd.blocks.block(t.b[0]).outs[0].point, t.b[2]);
        let ifelse = (0..s.blocks.len() as u32).map(SId).find(|&b| s.b(b).kind == Kind::IfElse).unwrap();
        let clauses: Vec<_> = s.b(ifelse).list[1..].iter().map(|&c| s.b(c).kind.clone()).collect();
        // the clauses were (C, B) (true clause first); now (B, C)
        assert_eq!(clauses, vec![Kind::Copy(t.b[1]), Kind::Copy(t.b[2])]);
    }
}
