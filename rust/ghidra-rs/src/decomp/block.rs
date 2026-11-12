//! Basic blocks and the control-flow graph (port of the `FlowBlock`, `BlockBasic` and
//! `BlockGraph` parts of `block.cc` that flow needs: edges, the start block, and the spanning
//! tree that puts the blocks in reverse post-order). Blocks live in an arena addressed by
//! [`BlockId`]; [`BlockGraph::list`] is the C++ `list`, whose order `print raw` follows.

use super::op::OpId;
use super::{err, Result};

/// Index of a block in its graph's arena.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BlockId(pub(crate) u32);

/// `FlowBlock` edge flags (block.hh), kept on both ends of an edge.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct EdgeFlags(u8);

impl EdgeFlags {
    const IRREDUCIBLE: EdgeFlags = EdgeFlags(1);
    const TREE: EdgeFlags = EdgeFlags(2);
    const FORWARD: EdgeFlags = EdgeFlags(4);
    const CROSS: EdgeFlags = EdgeFlags(8);
    const BACK: EdgeFlags = EdgeFlags(16);
    const LOOP: EdgeFlags = EdgeFlags(32);
    /// every spanning-tree label, `f_loop_exit_edge` (64) included
    const SPANNING: EdgeFlags = EdgeFlags(127);

    fn has(self, f: EdgeFlags) -> bool {
        self.0 & f.0 != 0
    }
}

/// Port of `BlockEdge`: the block at the other end, the flags, and the edge's position in
/// that block's opposite list.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Edge {
    pub(crate) point: BlockId,
    label: EdgeFlags,
    reverse: usize,
}

/// Port of `BlockBasic` (with its `FlowBlock` base).
#[derive(Debug, Clone)]
pub(crate) struct BlockBasic {
    pub(crate) ops: Vec<OpId>,
    /// first and last instruction address (`setBasicBlockRange`)
    pub(crate) start: u64,
    pub(crate) stop: u64,
    pub(crate) ins: Vec<Edge>,
    pub(crate) outs: Vec<Edge>,
    /// position in [`BlockGraph::list`] once the spanning tree is built
    pub(crate) index: i32,
    visitcount: i32,
    numdesc: i32,
    copymap: BlockId,
    mark: bool,
    entry_point: bool,
}

/// Port of the basic-block `BlockGraph` of a function (`Funcdata::bblocks`).
#[derive(Debug, Clone, Default)]
pub(crate) struct BlockGraph {
    blocks: Vec<BlockBasic>,
    pub(crate) list: Vec<BlockId>,
}

impl BlockGraph {
    pub(crate) fn block(&self, id: BlockId) -> &BlockBasic {
        &self.blocks[id.0 as usize]
    }
    pub(crate) fn block_mut(&mut self, id: BlockId) -> &mut BlockBasic {
        &mut self.blocks[id.0 as usize]
    }

    /// The live ops, block by block.
    pub(crate) fn ops(&self) -> impl Iterator<Item = OpId> + '_ {
        self.list.iter().flat_map(|&b| self.block(b).ops.iter().copied())
    }

    /// Port of `BlockGraph::newBlockBasic`.
    pub(crate) fn new_block(&mut self, start: u64) -> BlockId {
        let id = BlockId(self.blocks.len() as u32);
        self.blocks.push(BlockBasic {
            ops: Vec::new(),
            start,
            stop: start,
            ins: Vec::new(),
            outs: Vec::new(),
            index: self.list.len() as i32,
            visitcount: 0,
            numdesc: 0,
            copymap: id,
            mark: false,
            entry_point: false,
        });
        self.list.push(id);
        id
    }

    /// Port of `BlockGraph::addEdge` (`FlowBlock::addInEdge`).
    pub(crate) fn add_edge(&mut self, from: BlockId, to: BlockId) {
        let ourrev = self.block(from).outs.len();
        let brev = self.block(to).ins.len();
        self.block_mut(to).ins.push(Edge { point: from, label: EdgeFlags::default(), reverse: ourrev });
        self.block_mut(from).outs.push(Edge { point: to, label: EdgeFlags::default(), reverse: brev });
    }

    /// Port of `BlockGraph::setStartBlock`: move `bl` to the front of the list.
    pub(crate) fn set_start_block(&mut self, bl: BlockId) {
        let first = self.list[0];
        if self.block(first).entry_point {
            if first == bl {
                return;
            }
            self.block_mut(first).entry_point = false;
        }
        if let Some(i) = self.list.iter().position(|&b| b == bl) {
            self.list[..=i].rotate_right(1);
        }
        self.block_mut(bl).entry_point = true;
    }

    fn set_out_edge_flag(&mut self, bl: BlockId, i: usize, f: EdgeFlags) {
        let Edge { point, reverse, .. } = self.block(bl).outs[i];
        self.block_mut(bl).outs[i].label.0 |= f.0;
        self.block_mut(point).ins[reverse].label.0 |= f.0;
    }

    fn clear_out_edge_flag(&mut self, bl: BlockId, i: usize, f: EdgeFlags) {
        let Edge { point, reverse, .. } = self.block(bl).outs[i];
        self.block_mut(bl).outs[i].label.0 &= !f.0;
        self.block_mut(point).ins[reverse].label.0 &= !f.0;
    }

    fn clear_edge_flags(&mut self, f: EdgeFlags) {
        for b in &mut self.blocks {
            b.ins.iter_mut().chain(b.outs.iter_mut()).for_each(|e| e.label.0 &= !f.0);
        }
    }

    /// Port of `BlockGraph::structureLoops` up to the spanning tree: label the edges, mark
    /// irreducible ones, and put the blocks in reverse post-order. (`calcLoop` and the dominator
    /// tree only label edges further, which nothing before `funclink` reads.)
    pub(crate) fn structure_loops(&mut self) -> Result<()> {
        loop {
            let (preorder, _rootlist) = self.find_spanning_tree()?;
            if !self.find_irreducible(&preorder) {
                return Ok(());
            }
            self.clear_edge_flags(EdgeFlags(
                EdgeFlags::TREE.0 | EdgeFlags::FORWARD.0 | EdgeFlags::CROSS.0 | EdgeFlags::BACK.0 | EdgeFlags::LOOP.0,
            ));
        }
    }

    /// Port of `BlockGraph::findSpanningTree`: a depth-first search from the roots, labelling
    /// tree/forward/cross/back edges; the list becomes the reverse post-order. Returns the
    /// pre-order and the roots.
    fn find_spanning_tree(&mut self) -> Result<(Vec<BlockId>, Vec<BlockId>)> {
        let n = self.list.len();
        let mut preorder = Vec::with_capacity(n);
        let mut rootlist = Vec::new();
        if n == 0 {
            return Ok((preorder, rootlist));
        }
        let mut rpostorder = vec![self.list[0]; n];
        for i in 0..n {
            let b = self.list[i];
            self.reset_visit(b);
            if self.block(b).ins.is_empty() {
                rootlist.push(b);
            }
        }
        // the original head is visited last so that it comes first in the reverse post-order
        if rootlist.len() > 1 {
            let last = rootlist.len() - 1;
            rootlist.swap(0, last);
        } else if rootlist.is_empty() {
            rootlist.push(self.list[0]);
        }
        let origrootpos = rootlist.len() - 1;
        for repeat in 0..2 {
            let mut extraroots = false;
            let mut rpostcount = n;
            let mut rootindex = 0;
            self.clear_edge_flags(EdgeFlags::SPANNING);
            while preorder.len() < n {
                let mut startbl = None;
                while rootindex < rootlist.len() {
                    let b = rootlist[rootindex];
                    rootindex += 1;
                    if self.block(b).visitcount == -1 {
                        startbl = Some(b);
                        break;
                    }
                    // not really a root (a root from the previous pass)
                    rootindex -= 1;
                    rootlist.remove(rootindex);
                }
                let startbl = match startbl {
                    Some(b) => b,
                    None => {
                        extraroots = true;
                        let Some(&b) = self.list.iter().find(|&&b| self.block(b).visitcount == -1) else {
                            return err("Could not generate spanning tree");
                        };
                        rootlist.push(b);
                        rootindex += 1;
                        b
                    }
                };
                self.dfs(startbl, &mut preorder, &mut rpostorder, &mut rpostcount);
            }
            if !extraroots {
                break;
            }
            if repeat == 1 {
                return err("Could not generate spanning tree");
            }
            // extra roots: redo the order so that the entry block comes first
            let last = rootlist.len() - 1;
            rootlist.swap(last, origrootpos);
            for i in 0..n {
                self.reset_visit(self.list[i]);
            }
            preorder.clear();
        }
        if rootlist.len() > 1 {
            let last = rootlist.len() - 1;
            rootlist.swap(0, last);
        }
        self.list = rpostorder;
        Ok((preorder, rootlist))
    }

    fn reset_visit(&mut self, b: BlockId) {
        let bl = self.block_mut(b);
        bl.index = -1;
        bl.visitcount = -1;
        bl.copymap = b;
    }

    /// The depth-first walk of `findSpanningTree` from one root.
    fn dfs(&mut self, start: BlockId, preorder: &mut Vec<BlockId>, rpostorder: &mut [BlockId], rpostcount: &mut usize) {
        let mut state = vec![(start, 0usize)];
        self.block_mut(start).visitcount = preorder.len() as i32;
        preorder.push(start);
        self.block_mut(start).numdesc = 1;
        while let Some(top) = state.last_mut() {
            let (cur, e) = *top;
            if self.block(cur).outs.len() <= e {
                state.pop();
                *rpostcount -= 1;
                self.block_mut(cur).index = *rpostcount as i32;
                rpostorder[*rpostcount] = cur;
                if let Some(&(parent, _)) = state.last() {
                    self.block_mut(parent).numdesc += self.block(cur).numdesc;
                }
                continue;
            }
            top.1 += 1;
            let edge = self.block(cur).outs[e];
            if edge.label.has(EdgeFlags::IRREDUCIBLE) {
                continue; // pretend irreducible edges do not exist
            }
            let child = edge.point;
            let (cvisit, cindex) = (self.block(child).visitcount, self.block(child).index);
            if cvisit == -1 {
                self.set_out_edge_flag(cur, e, EdgeFlags::TREE);
                self.block_mut(child).visitcount = preorder.len() as i32;
                preorder.push(child);
                self.block_mut(child).numdesc = 1;
                state.push((child, 0));
            } else if cindex == -1 {
                self.set_out_edge_flag(cur, e, EdgeFlags(EdgeFlags::BACK.0 | EdgeFlags::LOOP.0));
            } else if self.block(cur).visitcount < cvisit {
                self.set_out_edge_flag(cur, e, EdgeFlags::FORWARD);
            } else {
                self.set_out_edge_flag(cur, e, EdgeFlags::CROSS);
            }
        }
    }

    /// Port of `BlockGraph::findIrreducible` (Tarjan's reducibility test): mark the edges that
    /// make the graph irreducible; `true` when a tree edge was marked and the tree must be rebuilt.
    fn find_irreducible(&mut self, preorder: &[BlockId]) -> bool {
        let mut needrebuild = false;
        let mut reachunder: Vec<BlockId> = Vec::new();
        for &x in preorder.iter().rev() {
            for i in 0..self.block(x).ins.len() {
                let edge = self.block(x).ins[i];
                if !edge.label.has(EdgeFlags::BACK) || edge.point == x {
                    continue;
                }
                let y = self.block(edge.point).copymap;
                reachunder.push(y);
                self.block_mut(y).mark = true;
            }
            let mut q = 0;
            while q < reachunder.len() {
                let t = reachunder[q];
                q += 1;
                for i in 0..self.block(t).ins.len() {
                    let edge = self.block(t).ins[i];
                    if edge.label.has(EdgeFlags::IRREDUCIBLE) {
                        continue;
                    }
                    let y = edge.point;
                    let yprime = self.block(y).copymap;
                    let (xv, xn, yv) = (self.block(x).visitcount, self.block(x).numdesc, self.block(yprime).visitcount);
                    if xv > yv || xv + xn <= yv {
                        self.set_out_edge_flag(y, edge.reverse, EdgeFlags::IRREDUCIBLE);
                        if edge.label.has(EdgeFlags::TREE) {
                            needrebuild = true;
                        } else {
                            self.clear_out_edge_flag(
                                y,
                                edge.reverse,
                                EdgeFlags(EdgeFlags::CROSS.0 | EdgeFlags::FORWARD.0),
                            );
                        }
                    } else if !self.block(yprime).mark && yprime != x {
                        reachunder.push(yprime);
                        self.block_mut(yprime).mark = true;
                    }
                }
            }
            for s in reachunder.drain(..) {
                let bl = self.block_mut(s);
                bl.mark = false;
                bl.copymap = x;
            }
        }
        needrebuild
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A diamond whose fall-through arm is listed first: the reverse post-order visits the
    /// fall-through arm last, so the branch arm gets the lower index (flow.cc + block.cc).
    #[test]
    fn reverse_post_order() {
        let mut g = BlockGraph::default();
        let b: Vec<BlockId> = (0..4).map(|i| g.new_block(i)).collect();
        g.set_start_block(b[0]);
        g.add_edge(b[0], b[1]); // fall-through
        g.add_edge(b[0], b[2]); // branch
        g.add_edge(b[1], b[3]);
        g.add_edge(b[2], b[3]);
        g.structure_loops().unwrap();
        assert_eq!(g.list, vec![b[0], b[2], b[1], b[3]]);
    }
}
