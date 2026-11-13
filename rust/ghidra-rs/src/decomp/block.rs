//! Basic blocks and the control-flow graph (port of the `FlowBlock`, `BlockBasic` and
//! `BlockGraph` parts of `block.cc` that flow needs: edges, the start block, and the spanning
//! tree that puts the blocks in reverse post-order). Blocks live in an arena addressed by
//! [`BlockId`]; [`BlockGraph::list`] is the C++ `list`, whose order `print raw` follows.

use super::op::OpId;
use super::{err, Result};

/// Index of a block in its graph's arena.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct BlockId(pub(crate) u32);

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
    /// `f_immed_copy`: a COPY has been propagated across the edge (`RulePropagateCopy`)
    const IMMED_COPY: EdgeFlags = EdgeFlags(128);
    /// every spanning-tree label, `f_loop_exit_edge` (64) included
    const SPANNING: EdgeFlags = EdgeFlags(127);
    /// the labels `structureLoops` clears before rebuilding the tree
    const CLASSIFIED: EdgeFlags =
        EdgeFlags(Self::TREE.0 | Self::FORWARD.0 | Self::CROSS.0 | Self::BACK.0 | Self::LOOP.0);
    const BACK_LOOP: EdgeFlags = EdgeFlags(Self::BACK.0 | Self::LOOP.0);
    const CROSS_FORWARD: EdgeFlags = EdgeFlags(Self::CROSS.0 | Self::FORWARD.0);

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
    pub(crate) reverse: usize,
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
    /// the immediate dominator (`immed_dom`), none for the entry
    pub(crate) idom: Option<BlockId>,
}

/// Port of the basic-block `BlockGraph` of a function (`Funcdata::bblocks`).
#[derive(Debug, Clone, Default)]
pub(crate) struct BlockGraph {
    blocks: Vec<BlockBasic>,
    pub(crate) list: Vec<BlockId>,
    /// the last `structureLoops` found more than one root (`Funcdata::blocks_unreachable`)
    pub(crate) unreachable: bool,
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
            idom: None,
        });
        self.list.push(id);
        id
    }

    /// Port of `BlockGraph::addEdge` (`FlowBlock::addInEdge`).
    /// `isLoopIn`: the `i`-th edge into `bl` is a loop edge.
    /// `FlowBlock::setImmedCopyEdge` on out edge `i` of `bl`.
    pub(crate) fn set_immed_copy_edge(&mut self, bl: BlockId, i: usize) {
        self.set_out_edge_flag(bl, i, EdgeFlags::IMMED_COPY);
    }

    /// `FlowBlock::hasImmedCopyEdge` on out edge `i` of `bl`.
    pub(crate) fn has_immed_copy_edge(&self, bl: BlockId, i: usize) -> bool {
        self.block(bl).outs[i].label.has(EdgeFlags::IMMED_COPY)
    }

    pub(crate) fn is_loop_in(&self, bl: BlockId, i: usize) -> bool {
        self.block(bl).ins[i].label.has(EdgeFlags::LOOP)
    }

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

    pub(crate) fn is_entry_point(&self, bl: BlockId) -> bool {
        self.block(bl).entry_point
    }

    /// Port of `FlowBlock::findCondition`: the block whose two-way branch decides between
    /// in-edge `edge1` of `bl1` and in-edge `edge2` of `bl2` (through blocks of one out-edge),
    /// with the out-edge of it on the `bl1` side. `None` where the C++ returns null (or would
    /// read past an edge list).
    pub(crate) fn find_condition(
        &self,
        mut bl1: BlockId,
        mut edge1: usize,
        mut bl2: BlockId,
        mut edge2: usize,
    ) -> Option<(BlockId, usize)> {
        let in_of = |b: BlockId, i: usize| self.block(b).ins.get(i).map(|e| e.point);
        let mut cond = in_of(bl1, edge1)?;
        while self.block(cond).outs.len() != 2 {
            if self.block(cond).outs.len() != 1 {
                return None;
            }
            bl1 = cond;
            edge1 = 0;
            cond = in_of(bl1, 0)?;
        }
        while Some(cond) != in_of(bl2, edge2) {
            bl2 = in_of(bl2, edge2)?;
            if self.block(bl2).outs.len() != 1 {
                return None;
            }
            edge2 = 0;
        }
        Some((cond, self.block(bl1).ins.get(edge1)?.reverse))
    }

    /// Port of `FlowBlock::halfDeleteInEdge`: drop in-edge `slot`, renumbering the reverse
    /// indices of the edges after it.
    fn half_delete_in_edge(&mut self, bl: BlockId, slot: usize) {
        self.block_mut(bl).ins.remove(slot);
        for i in slot..self.block(bl).ins.len() {
            let Edge { point, reverse, .. } = self.block(bl).ins[i];
            self.block_mut(point).outs[reverse].reverse -= 1;
        }
    }

    /// Port of `FlowBlock::halfDeleteOutEdge`.
    fn half_delete_out_edge(&mut self, bl: BlockId, slot: usize) {
        self.block_mut(bl).outs.remove(slot);
        for i in slot..self.block(bl).outs.len() {
            let Edge { point, reverse, .. } = self.block(bl).outs[i];
            self.block_mut(point).ins[reverse].reverse -= 1;
        }
    }

    /// Port of `FlowBlock::removeInEdge`.
    pub(crate) fn remove_in_edge(&mut self, bl: BlockId, slot: usize) {
        let Edge { point, reverse, .. } = self.block(bl).ins[slot];
        self.half_delete_in_edge(bl, slot);
        self.half_delete_out_edge(point, reverse);
    }

    /// Port of `FlowBlock::removeOutEdge`.
    pub(crate) fn remove_out_edge(&mut self, bl: BlockId, slot: usize) {
        let Edge { point, reverse, .. } = self.block(bl).outs[slot];
        self.half_delete_out_edge(bl, slot);
        self.half_delete_in_edge(point, reverse);
    }

    /// Port of `BlockGraph::removeEdge`: the first edge from `begin` into `end`.
    pub(crate) fn remove_edge(&mut self, begin: BlockId, end: BlockId) {
        if let Some(i) = self.block(end).ins.iter().position(|e| e.point == begin) {
            self.remove_in_edge(end, i);
        }
    }

    /// Port of `FlowBlock::replaceInEdge`: in-edge `num` of `bl` now comes from `b`.
    fn replace_in_edge(&mut self, bl: BlockId, num: usize, b: BlockId) {
        let Edge { point: oldb, reverse, label } = self.block(bl).ins[num];
        self.half_delete_out_edge(oldb, reverse);
        let rev = self.block(b).outs.len();
        self.block_mut(bl).ins[num] = Edge { point: b, label, reverse: rev };
        self.block_mut(b).outs.push(Edge { point: bl, label, reverse: num });
    }

    /// Port of `FlowBlock::replaceOutEdge`: out-edge `num` of `bl` now goes to `b`.
    fn replace_out_edge(&mut self, bl: BlockId, num: usize, b: BlockId) {
        let Edge { point: oldb, reverse, label } = self.block(bl).outs[num];
        self.half_delete_in_edge(oldb, reverse);
        let rev = self.block(b).ins.len();
        self.block_mut(bl).outs[num] = Edge { point: b, label, reverse: rev };
        self.block_mut(b).ins.push(Edge { point: bl, label, reverse: num });
    }

    /// Port of `BlockGraph::removeFromFlow`: `bl`'s predecessors go straight to its successor.
    pub(crate) fn remove_from_flow(&mut self, bl: BlockId) {
        while let Some(last) = self.block(bl).outs.len().checked_sub(1) {
            let bbout = self.block(bl).outs[last].point;
            self.remove_out_edge(bl, last);
            while let Some(&Edge { point: bbin, reverse, .. }) = self.block(bl).ins.first() {
                self.replace_out_edge(bbin, reverse, bbout);
            }
        }
    }

    /// Port of `BlockGraph::removeBlock`.
    pub(crate) fn remove_block(&mut self, bl: BlockId) {
        while let Some(e) = self.block(bl).ins.first().copied() {
            self.remove_edge(e.point, bl);
        }
        while let Some(e) = self.block(bl).outs.first().copied() {
            self.remove_edge(bl, e.point);
        }
        self.list.retain(|&b| b != bl);
    }

    /// Port of `BlockGraph::spliceBlock`: `bl`'s single successor (with `bl` its single
    /// predecessor) is merged into it; the successor's out-edges move to `bl`.
    pub(crate) fn splice_block(&mut self, bl: BlockId) {
        let outbl = self.block(bl).outs[0].point;
        let entry = self.block(bl).entry_point;
        self.remove_out_edge(bl, 0);
        for _ in 0..self.block(outbl).outs.len() {
            let Edge { point, reverse, .. } = self.block(outbl).outs[0];
            self.replace_in_edge(point, reverse, bl);
        }
        self.remove_block(outbl);
        self.block_mut(bl).entry_point = entry;
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

    /// Port of `BlockGraph::structureLoops` with the `calcForwardDominator` that
    /// `Funcdata::structureReset` runs after it: label the edges, mark irreducible ones, put the
    /// blocks in reverse post-order and find each block's immediate dominator. (`calcLoop` only
    /// labels loop-exit edges, which nothing ported reads.)
    pub(crate) fn structure_loops(&mut self) -> Result<()> {
        // each rebuild follows a newly irreducible tree edge, so there are at most edges + 1 rounds
        let edges: usize = self.blocks.iter().map(|b| b.outs.len()).sum();
        for _ in 0..=edges {
            let (preorder, rootlist) = self.find_spanning_tree()?;
            self.unreachable = rootlist.len() > 1;
            if !self.find_irreducible(&preorder) {
                self.calc_forward_dominator(&rootlist);
                return Ok(());
            }
            self.clear_edge_flags(EdgeFlags::CLASSIFIED);
        }
        err("Could not resolve irreducible edges")
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
                self.set_out_edge_flag(cur, e, EdgeFlags::BACK_LOOP);
            } else if self.block(cur).visitcount < cvisit {
                self.set_out_edge_flag(cur, e, EdgeFlags::FORWARD);
            } else {
                self.set_out_edge_flag(cur, e, EdgeFlags::CROSS);
            }
        }
    }

    /// Port of `BlockGraph::calcForwardDominator` (Cooper, Harvey and Kennedy's iterative
    /// algorithm over the reverse post-order). Several roots, or an entry with in-edges, get a
    /// virtual root with an edge to each root; it is dropped at the end, so those roots have no
    /// dominator. The C++ virtual root is a `FlowBlock` with index 0, which the intersection
    /// walk reads as the entry's position; [`Dom::Virtual`] keeps that.
    fn calc_forward_dominator(&mut self, rootlist: &[BlockId]) {
        #[derive(Clone, Copy, PartialEq, Eq)]
        enum Dom {
            Block(BlockId),
            Virtual,
        }
        let n = self.list.len();
        if n == 0 {
            return;
        }
        let numnodes = n - 1;
        let entry = self.list[0];
        let virtual_root = rootlist.len() > 1 || !self.block(entry).ins.is_empty();
        let mut idom: Vec<Option<Dom>> = vec![None; self.blocks.len()];
        let mut virtual_idom = None;
        let pos = |d: Dom, g: &BlockGraph| numnodes - g.index_of(d_block(d)).unwrap_or(0);
        fn d_block(d: Dom) -> Option<BlockId> {
            match d {
                Dom::Block(b) => Some(b),
                Dom::Virtual => None,
            }
        }
        let root = if virtual_root { Dom::Virtual } else { Dom::Block(entry) };
        match root {
            Dom::Virtual => {
                virtual_idom = Some(Dom::Virtual);
                for &r in rootlist {
                    idom[r.0 as usize] = Some(Dom::Virtual);
                }
            }
            Dom::Block(b) => {
                idom[b.0 as usize] = Some(root);
                for e in &self.block(b).outs {
                    idom[e.point.0 as usize] = Some(root);
                }
            }
        }
        let get = |idom: &[Option<Dom>], virtual_idom: Option<Dom>, d: Dom| match d {
            Dom::Block(b) => idom[b.0 as usize],
            Dom::Virtual => virtual_idom,
        };
        // the in-edges of a block, the virtual root's edge last
        let ins = |g: &BlockGraph, b: BlockId| {
            let mut v: Vec<Dom> = g.block(b).ins.iter().map(|e| Dom::Block(e.point)).collect();
            if virtual_root && rootlist.contains(&b) {
                v.push(Dom::Virtual);
            }
            v
        };
        let mut new_idom = root;
        let mut changed = true;
        while changed {
            changed = false;
            // every block in reverse post-order except the root (postorder[numnodes - i] = list[i])
            let skip = usize::from(!virtual_root);
            for i in skip..n {
                let b = self.list[i];
                if idom[b.0 as usize] == Some(root) {
                    continue;
                }
                let preds = ins(self, b);
                let mut j = 0;
                while j < preds.len() {
                    new_idom = preds[j];
                    if get(&idom, virtual_idom, new_idom).is_some() {
                        break;
                    }
                    j += 1;
                }
                for &rho in preds.iter().skip(j + 1) {
                    if get(&idom, virtual_idom, rho).is_none() {
                        continue;
                    }
                    let mut f1 = pos(rho, self);
                    let mut f2 = pos(new_idom, self);
                    let up = |f: usize| {
                        let d = get(&idom, virtual_idom, Dom::Block(self.list[numnodes - f])).unwrap_or(root);
                        pos(d, self)
                    };
                    while f1 != f2 {
                        while f1 < f2 {
                            f1 = up(f1);
                        }
                        while f2 < f1 {
                            f2 = up(f2);
                        }
                    }
                    new_idom = Dom::Block(self.list[numnodes - f1]);
                }
                if idom[b.0 as usize] != Some(new_idom) {
                    idom[b.0 as usize] = Some(new_idom);
                    changed = true;
                }
            }
        }
        for (i, b) in self.blocks.iter_mut().enumerate() {
            b.idom = match idom[i] {
                Some(Dom::Block(d)) if !(d == entry && i == entry.0 as usize && !virtual_root) => Some(d),
                _ => None,
            };
        }
    }

    /// The position of `b` in the list (its index), if any.
    fn index_of(&self, b: Option<BlockId>) -> Option<usize> {
        b.map(|b| self.block(b).index as usize)
    }

    /// Port of `BlockGraph::buildDomTree`: each block's children in the dominator tree, by
    /// index, in list order (the blocks without a dominator are not listed).
    pub(crate) fn dom_children(&self) -> Vec<Vec<usize>> {
        let mut child = vec![Vec::new(); self.list.len()];
        for (i, &b) in self.list.iter().enumerate() {
            if let Some(d) = self.block(b).idom {
                child[self.block(d).index as usize].push(i);
            }
        }
        child
    }

    /// Port of `BlockGraph::buildDomDepth`: each block's depth in the dominator tree (the entry
    /// is 1), and the largest.
    pub(crate) fn dom_depth(&self) -> (Vec<i32>, i32) {
        let mut depth = vec![0; self.list.len()];
        for (i, &b) in self.list.iter().enumerate() {
            depth[i] = self.block(b).idom.map_or(1, |d| depth[self.block(d).index as usize] + 1);
        }
        let max = depth.iter().copied().max().unwrap_or(0);
        (depth, max)
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
                            self.clear_out_edge_flag(y, edge.reverse, EdgeFlags::CROSS_FORWARD);
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
