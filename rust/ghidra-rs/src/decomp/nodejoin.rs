//! Port of `ActionNodeJoin` and `ConditionalJoin` (blockaction.cc) with
//! `Funcdata::nodeJoinCreateBlock` (funcdata_block.cc): two blocks ending in CBRANCHes on
//! functionally equal conditions, with the same false and true exits, branch to a new block
//! holding one CBRANCH; values the exits merge from the two blocks get a MULTIEQUAL there.

use std::collections::BTreeMap;

use super::block::BlockId;
use super::op::{OpFlags, OpId};
use super::opcode::Opcode;
use super::varnode::{VarnodeId, VnFlags};
use super::{err, Arch, Funcdata, Result};

/// `ConditionalJoin::MergePair` keyed as its `operator<` orders it: by the creation index of
/// `side1`, then of `side2`.
type MergeKey = (VarnodeId, VarnodeId);

fn key(a: VarnodeId, b: VarnodeId) -> (u32, u32) {
    (a.0, b.0)
}

/// Port of `ConditionalJoin` for one matched pair.
struct Join {
    block1: BlockId,
    block2: BlockId,
    exita: BlockId,
    exitb: BlockId,
    a_in1: usize,
    a_in2: usize,
    b_in1: usize,
    b_in2: usize,
    cbranch1: OpId,
    cbranch2: OpId,
    /// `mergeneed`: each pair of varnodes to merge, and its MULTIEQUAL output once made
    mergeneed: BTreeMap<(u32, u32), (MergeKey, Option<VarnodeId>)>,
}

/// `ActionNodeJoin::apply`. The block list is re-read each step: a join adds a block and
/// `structureReset` reorders the list, as in the C++.
pub(crate) fn node_join(fd: &mut Funcdata, _: &Arch) -> Result<i32> {
    join_all(fd)
}

fn join_all(fd: &mut Funcdata) -> Result<i32> {
    let mut count = 0;
    let mut i = 0;
    while i < fd.blocks.list.len() {
        let bb = fd.blocks.list[i];
        i += 1;
        let b = fd.blocks.block(bb);
        if b.outs.len() != 2 {
            continue;
        }
        let (o1, o2) = (b.outs[0].point, b.outs[1].point);
        let (leastout, inslot) = if fd.blocks.block(o1).ins.len() < fd.blocks.block(o2).ins.len() {
            (o1, b.outs[0].reverse)
        } else {
            (o2, b.outs[1].reverse)
        };
        if fd.blocks.block(leastout).ins.len() == 1 {
            continue;
        }
        for j in 0..fd.blocks.block(leastout).ins.len() {
            if j == inslot {
                continue;
            }
            let bb2 = fd.blocks.block(leastout).ins[j].point;
            if let Some(join) = Join::matches(fd, bb, bb2) {
                count += 1;
                join.execute(fd)?;
                break;
            }
        }
    }
    Ok(count)
}

impl Join {
    /// `ConditionalJoin::match`: the pattern, `findDups`, and `checkExitBlock` on both exits.
    fn matches(fd: &Funcdata, block1: BlockId, block2: BlockId) -> Option<Join> {
        let g = &fd.blocks;
        if block1 == block2 || g.block(block1).outs.len() != 2 || g.block(block2).outs.len() != 2 {
            return None;
        }
        let (o1, o2) = (&g.block(block1).outs, &g.block(block2).outs);
        let (exita, exitb) = (o1[0].point, o1[1].point);
        if exita == exitb || o2[0].point != exita || o2[1].point != exitb {
            return None;
        }
        let cbranch = |b: BlockId| g.block(b).ops.last().copied().filter(|&op| fd.op(op).opc == Opcode::Cbranch);
        let mut join = Join {
            block1,
            block2,
            exita,
            exitb,
            a_in1: o1[0].reverse,
            a_in2: o2[0].reverse,
            b_in1: o1[1].reverse,
            b_in2: o2[1].reverse,
            cbranch1: cbranch(block1)?,
            cbranch2: cbranch(block2)?,
            mergeneed: BTreeMap::new(),
        };
        if !join.find_dups(fd) {
            return None;
        }
        join.check_exit_block(fd, exita, join.a_in1, join.a_in2);
        join.check_exit_block(fd, exitb, join.b_in1, join.b_in2);
        Some(join)
    }

    fn need(&mut self, a: VarnodeId, b: VarnodeId) {
        self.mergeneed.insert(key(a, b), ((a, b), None));
    }

    /// `ConditionalJoin::findDups`: the two conditions are the same varnode, or functionally
    /// equal (`functionalEqualityLevel` 0 or 1) and then merged.
    fn find_dups(&mut self, fd: &Funcdata) -> bool {
        let (c1, c2) = (fd.op(self.cbranch1), fd.op(self.cbranch2));
        if c1.flags.has(OpFlags::BOOLEAN_FLIP) || c2.flags.has(OpFlags::BOOLEAN_FLIP) {
            return false; // the flip has not propagated yet
        }
        let (Some(&vn1), Some(&vn2)) = (c1.ins.get(1), c2.ins.get(1)) else { return false };
        if vn1 == vn2 {
            return true;
        }
        let (v1, v2) = (fd.vn(vn1), fd.vn(vn2));
        if v1.def.is_none() || v2.def.is_none() {
            return false;
        }
        if v1.flags.has(VnFlags::SPACEBASE) || v2.flags.has(VnFlags::SPACEBASE) {
            return false;
        }
        let (res, _, _) = super::rules::func_eq_level(fd, vn1, vn2);
        if !(0..=1).contains(&res) {
            return false;
        }
        if v1.def.is_some_and(|d| matches!(fd.op(d).opc, Opcode::Subpiece | Opcode::Copy)) {
            return false;
        }
        self.need(vn1, vn2);
        true
    }

    /// The leading MULTIEQUAL and COPY ops of `exit` (the scan of `checkExitBlock` and
    /// `cutDownMultiequals`, which stop at the first other op).
    fn head_ops(fd: &Funcdata, exit: BlockId) -> Vec<OpId> {
        let ops = &fd.blocks.block(exit).ops;
        ops.iter().copied().take_while(|&op| matches!(fd.op(op).opc, Opcode::Multiequal | Opcode::Copy)).collect()
    }

    /// `ConditionalJoin::checkExitBlock`.
    fn check_exit_block(&mut self, fd: &Funcdata, exit: BlockId, in1: usize, in2: usize) {
        for op in Self::head_ops(fd, exit) {
            let o = fd.op(op);
            if o.opc == Opcode::Multiequal && o.ins[in1] != o.ins[in2] {
                self.need(o.ins[in1], o.ins[in2]);
            }
        }
    }

    /// `ConditionalJoin::execute`.
    fn execute(mut self, fd: &mut Funcdata) -> Result<()> {
        let addr = fd.op(self.cbranch1).seq.addr;
        let joinblock = node_join_create_block(fd, &self, addr)?;
        self.setup_multiequals(fd, joinblock, addr)?;
        self.move_cbranch(fd, joinblock)?;
        self.cut_down_multiequals(fd, self.exita, self.a_in1, self.a_in2)?;
        self.cut_down_multiequals(fd, self.exitb, self.b_in1, self.b_in2)
    }

    /// `ConditionalJoin::setupMultiequals`: a MULTIEQUAL in the join block per pair, in key order.
    fn setup_multiequals(&mut self, fd: &mut Funcdata, joinblock: BlockId, addr: u64) -> Result<()> {
        let Some(uniq) = fd.uniq else { return err("no unique space") };
        for ((vn1, vn2), out) in self.mergeneed.values_mut() {
            if out.is_some() {
                continue;
            }
            let multi = fd.new_op(Opcode::Multiequal, addr);
            let size = fd.vn(*vn1).size;
            let outvn = fd.new_unique_out(size, uniq, multi);
            fd.op_set_input(multi, *vn1, 0)?;
            fd.op_set_input(multi, *vn2, 1)?;
            *out = Some(outvn);
            fd.op_insert_end(multi, joinblock);
        }
        Ok(())
    }

    fn merged(&self, a: VarnodeId, b: VarnodeId) -> Result<VarnodeId> {
        match self.mergeneed.get(&key(a, b)) {
            Some((_, Some(v))) => Ok(*v),
            _ => err("ConditionalJoin: missing merge pair"),
        }
    }

    /// `ConditionalJoin::moveCbranch`.
    fn move_cbranch(&self, fd: &mut Funcdata, joinblock: BlockId) -> Result<()> {
        let (vn1, vn2) = (fd.op(self.cbranch1).ins[1], fd.op(self.cbranch2).ins[1]);
        fd.op_uninsert(self.cbranch1);
        fd.op_insert_end(self.cbranch1, joinblock);
        let vn = if vn1 != vn2 { self.merged(vn1, vn2)? } else { vn1 };
        fd.op_set_input(self.cbranch1, vn, 1)?;
        fd.op_destroy(self.cbranch2);
        Ok(())
    }

    /// `ConditionalJoin::cutDownMultiequals`: each MULTIEQUAL of `exit` loses the input of the
    /// removed edge (`hi`) and reads the merged value at `lo`; one left with a single input
    /// becomes a COPY at the top of the block.
    fn cut_down_multiequals(&self, fd: &mut Funcdata, exit: BlockId, in1: usize, in2: usize) -> Result<()> {
        let (lo, hi) = (in1.min(in2), in1.max(in2));
        for op in Self::head_ops(fd, exit) {
            if fd.op(op).opc != Opcode::Multiequal {
                continue;
            }
            let (vn1, vn2) = (fd.op(op).ins[in1], fd.op(op).ins[in2]);
            fd.op_remove_input(op, hi);
            if vn1 != vn2 {
                let subvn = self.merged(vn1, vn2)?;
                fd.op_set_input(op, subvn, lo)?;
            }
            if fd.op(op).ins.len() == 1 {
                fd.op_uninsert(op);
                fd.op_set_opcode(op, Opcode::Copy);
                fd.op_insert_begin(op, exit);
            }
        }
        Ok(())
    }
}

/// Port of `Funcdata::nodeJoinCreateBlock`: the new block (at `addr`) takes one edge into each
/// exit (the one from the block with the lower in-slot), the other two edges go, and both
/// blocks flow to it. (`f_joined_block` is not kept: only printing reads it.)
fn node_join_create_block(fd: &mut Funcdata, j: &Join, addr: u64) -> Result<BlockId> {
    let g = &mut fd.blocks;
    let newblock = g.new_block(addr);
    let (block1, block2) = (j.block1, j.block2);
    let swapa = if j.a_in1 > j.a_in2 {
        g.remove_edge(block1, j.exita);
        block2
    } else {
        g.remove_edge(block2, j.exita);
        block1
    };
    let swapb = if j.b_in1 > j.b_in2 {
        g.remove_edge(block1, j.exitb);
        block2
    } else {
        g.remove_edge(block2, j.exitb);
        block1
    };
    for (swap, exit) in [(swapa, j.exita), (swapb, j.exitb)] {
        let Some(slot) = g.block(swap).outs.iter().position(|e| e.point == exit) else {
            return err("nodeJoinCreateBlock: lost exit edge");
        };
        g.move_out_edge(swap, slot, newblock);
    }
    g.add_edge(block1, newblock);
    g.add_edge(block2, newblock);
    super::coreaction::structure_reset(fd)?;
    Ok(newblock)
}

#[cfg(test)]
mod tests {
    //! A hand-built CFG; the expected shape is derived by hand from the C++ (`ActionNodeJoin`,
    //! `ConditionalJoin`, `nodeJoinCreateBlock`), not run on the reference.
    use super::super::varnode::Space;
    use super::*;

    /// E -> {B1, B2}; B1 -> {X, Y}; B2 -> {X, Y}; B1 and B2 branch on `c == 0`, computed
    /// separately. The list is E, B2, B1, Y, X, so B2 is `block1`: it keeps its CBRANCH, which
    /// moves to the new block N reading MULTIEQUAL(cond B2, cond B1); B1's CBRANCH goes; both
    /// edges into X and into Y now come from N (X first), and B1, B2 flow to N.
    #[test]
    fn joins_equal_conditions() {
        let mut fd = Funcdata::new(0x1000);
        fd.uniq = Some(1);
        let g = &mut fd.blocks;
        let b: Vec<BlockId> = (0..5).map(|i| g.new_block(0x1000 + 0x10 * i)).collect();
        let (e, b1, b2, x, y) = (b[0], b[1], b[2], b[3], b[4]);
        g.set_start_block(e);
        for (f, t) in [(e, b1), (e, b2), (b1, x), (b1, y), (b2, x), (b2, y)] {
            g.add_edge(f, t);
        }
        // c is written in E (a free varnode may have only one reader)
        let def = fd.new_op(Opcode::Copy, 0x1000);
        let c = fd.new_unique_out(4, 1, def);
        let seven = fd.new_varnode(4, Space::Sleigh(2), 0);
        fd.op_set_input(def, seven, 0).unwrap();
        fd.op_insert_end(def, e);
        let mut conds = Vec::new();
        for bl in [e, b1, b2] {
            let start = fd.blocks.block(bl).start;
            let eq = fd.new_op(Opcode::IntEqual, start);
            let cond = fd.new_unique_out(1, 1, eq);
            let zero = fd.new_constant(4, 0);
            fd.op_set_input(eq, c, 0).unwrap();
            fd.op_set_input(eq, zero, 1).unwrap();
            fd.op_insert_end(eq, bl);
            let cb = fd.new_op(Opcode::Cbranch, start + 1);
            let dest = fd.new_constant(4, 0);
            fd.op_set_input(cb, dest, 0).unwrap();
            fd.op_set_input(cb, cond, 1).unwrap();
            fd.op_insert_end(cb, bl);
            conds.push((cond, cb));
        }
        fd.blocks.structure_loops().unwrap();
        assert_eq!(fd.blocks.list, vec![e, b2, b1, y, x]);
        assert_eq!(join_all(&mut fd).unwrap(), 1);
        let (cond1, cb1) = conds[1];
        let (cond2, cb2) = conds[2];
        let n = BlockId(5);
        let outs = |bl: BlockId| fd.blocks.block(bl).outs.iter().map(|e| e.point).collect::<Vec<_>>();
        assert_eq!(outs(n), vec![x, y]);
        assert_eq!((outs(b1), outs(b2)), (vec![n], vec![n]));
        let ops = &fd.blocks.block(n).ops;
        assert_eq!(ops.len(), 2);
        let multi = fd.op(ops[0]);
        assert_eq!((multi.opc, multi.ins.clone()), (Opcode::Multiequal, vec![cond2, cond1]));
        assert_eq!(ops[1], cb2);
        assert_eq!(fd.op(cb2).ins[1], multi.out.unwrap());
        assert!(fd.op(cb1).parent.is_none());
    }
}
