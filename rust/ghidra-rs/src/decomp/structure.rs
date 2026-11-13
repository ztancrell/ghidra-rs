//! Control-flow structuring, stage S8 in part: the structured block hierarchy of `block.cc`
//! (`BlockGraph` and its subclasses `BlockCopy`, `BlockGoto`, `BlockMultiGoto`, `BlockList`,
//! `BlockCondition`, `BlockIf`, `BlockIfElse`, `BlockIfNoExit`, `BlockIfGoto`, `BlockWhileDo`,
//! `BlockDoWhile`, `BlockInfLoop`, `BlockSwitch`) as far as `ActionBlockStructure` builds them,
//! and `printTree`. The collapse itself (`CollapseStructure`, `LoopBody`, `TraceDAG`) is in
//! [`super::collapse`].
//!
//! The C++ hierarchy is a tree of heap objects linked by pointers; here every block lives in one
//! arena ([`Structure::blocks`]) addressed by [`SId`], and the subclass is [`Kind`]. Block 0 is
//! the root graph (`Funcdata::sblocks`) once built. Flags and edge labels keep the C++ bit values.

use super::block::BlockId;
use super::op::OpFlags;
use super::opcode::Opcode;
use super::varnode::VnFlags;
use super::{err, Funcdata, Result};

/// Index of a block in the structure arena.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct SId(pub(crate) u32);

/// The root graph, once built.
pub(crate) const ROOT: SId = SId(0);

// `FlowBlock::block_flags` (block.hh)
pub(crate) const F_SWITCH_OUT: u32 = 0x10;
pub(crate) const F_MARK: u32 = 0x80;
const F_MARK2: u32 = 0x100;
const F_INTERIOR_GOTOOUT: u32 = 0x400;
const F_INTERIOR_GOTOIN: u32 = 0x800;
pub(crate) const F_WHILEDO_OVERFLOW: u32 = 0x8000;

// `FlowBlock::edge_flags` (block.hh)
const E_GOTO: u32 = 1;
const E_LOOP: u32 = 2;
const E_DEFAULTSWITCH: u32 = 4;
const E_IRREDUCIBLE: u32 = 8;
const E_BACK: u32 = 0x80;
pub(crate) const E_LOOP_EXIT: u32 = 0x100;

/// The `FlowBlock` subclass of a structured block, with its subclass fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Kind {
    /// `BlockGraph` (the root)
    Graph,
    /// `BlockCopy` of a basic block
    Copy(BlockId),
    /// `BlockGoto`: the target of its unstructured edge
    Goto(SId),
    /// `BlockMultiGoto`: the unstructured edges' targets and whether one is the switch default
    MultiGoto {
        gotos: Vec<SId>,
        default_goto: bool,
    },
    List,
    /// `BlockCondition`: the boolean operation. `newBlockCondition` stores INT_OR/INT_AND, which
    /// `printHeader` reads as `||` until a negation turns it into BOOL_AND/BOOL_OR; kept as is.
    Condition(Opcode),
    If,
    IfElse,
    IfNoExit,
    /// `BlockIfGoto`: the target of its unstructured edge
    IfGoto(SId),
    WhileDo,
    DoWhile,
    InfLoop,
    Switch,
}

/// Port of `BlockEdge`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SEdge {
    pub(crate) point: SId,
    pub(crate) label: u32,
    pub(crate) reverse: usize,
}

/// Port of `FlowBlock` with the `BlockGraph` component list.
#[derive(Debug, Clone)]
pub(crate) struct SBlock {
    pub(crate) kind: Kind,
    pub(crate) parent: Option<SId>,
    pub(crate) list: Vec<SId>,
    pub(crate) ins: Vec<SEdge>,
    pub(crate) outs: Vec<SEdge>,
    pub(crate) flags: u32,
    pub(crate) index: i32,
    pub(crate) visitcount: i32,
}

/// The structured hierarchy (`Funcdata::sblocks`); empty until `ActionBlockStructure`.
#[derive(Debug, Clone, Default)]
pub(crate) struct Structure {
    pub(crate) blocks: Vec<SBlock>,
}

impl Structure {
    pub(crate) fn b(&self, id: SId) -> &SBlock {
        &self.blocks[id.0 as usize]
    }
    pub(crate) fn bm(&mut self, id: SId) -> &mut SBlock {
        &mut self.blocks[id.0 as usize]
    }

    /// `BlockGraph::clear` on the root.
    pub(crate) fn clear(&mut self) {
        self.blocks.clear();
    }

    /// `sblocks.getSize() == 0`.
    pub(crate) fn is_empty(&self) -> bool {
        self.blocks.first().is_none_or(|r| r.list.is_empty())
    }

    /// The root's components (`graph.getSize()`, `graph.getBlock(i)`).
    pub(crate) fn size(&self) -> usize {
        self.blocks.first().map_or(0, |r| r.list.len())
    }
    pub(crate) fn get(&self, i: usize) -> SId {
        self.b(ROOT).list[i]
    }

    fn new_block(&mut self, kind: Kind) -> SId {
        let id = SId(self.blocks.len() as u32);
        self.blocks.push(SBlock {
            kind,
            parent: None,
            list: Vec::new(),
            ins: Vec::new(),
            outs: Vec::new(),
            flags: 0,
            index: 0,
            visitcount: 0,
        });
        id
    }

    // ---- FlowBlock queries (block.hh) ----

    pub(crate) fn size_in(&self, b: SId) -> usize {
        self.b(b).ins.len()
    }
    pub(crate) fn size_out(&self, b: SId) -> usize {
        self.b(b).outs.len()
    }
    pub(crate) fn out(&self, b: SId, i: usize) -> SId {
        self.b(b).outs[i].point
    }
    pub(crate) fn in_(&self, b: SId, i: usize) -> SId {
        self.b(b).ins[i].point
    }
    pub(crate) fn out_label(&self, b: SId, i: usize) -> u32 {
        self.b(b).outs[i].label
    }
    pub(crate) fn in_label(&self, b: SId, i: usize) -> u32 {
        self.b(b).ins[i].label
    }
    pub(crate) fn flag(&self, b: SId, f: u32) -> bool {
        self.b(b).flags & f != 0
    }
    pub(crate) fn is_switch_out(&self, b: SId) -> bool {
        self.flag(b, F_SWITCH_OUT)
    }
    pub(crate) fn is_mark(&self, b: SId) -> bool {
        self.flag(b, F_MARK)
    }
    pub(crate) fn set_mark(&mut self, b: SId) {
        self.bm(b).flags |= F_MARK;
    }
    pub(crate) fn clear_mark(&mut self, b: SId) {
        self.bm(b).flags &= !F_MARK;
    }
    pub(crate) fn is_interior_goto_target(&self, b: SId) -> bool {
        self.flag(b, F_INTERIOR_GOTOIN)
    }
    /// `isGotoOut`: irreducible or goto edge.
    pub(crate) fn is_goto_out(&self, b: SId, i: usize) -> bool {
        self.out_label(b, i) & (E_IRREDUCIBLE | E_GOTO) != 0
    }
    pub(crate) fn is_goto_in(&self, b: SId, i: usize) -> bool {
        self.in_label(b, i) & (E_IRREDUCIBLE | E_GOTO) != 0
    }
    pub(crate) fn is_back_edge_in(&self, b: SId, i: usize) -> bool {
        self.in_label(b, i) & E_BACK != 0
    }
    pub(crate) fn is_back_edge_out(&self, b: SId, i: usize) -> bool {
        self.out_label(b, i) & E_BACK != 0
    }
    pub(crate) fn is_default_branch(&self, b: SId, i: usize) -> bool {
        self.out_label(b, i) & E_DEFAULTSWITCH != 0
    }
    /// `isDecisionOut`: not irreducible, back or goto.
    pub(crate) fn is_decision_out(&self, b: SId, i: usize) -> bool {
        self.out_label(b, i) & (E_IRREDUCIBLE | E_BACK | E_GOTO) == 0
    }
    /// `isLoopDAGOut`: not irreducible, back, loop exit or goto.
    pub(crate) fn is_loop_dag_out(&self, b: SId, i: usize) -> bool {
        self.out_label(b, i) & (E_IRREDUCIBLE | E_BACK | E_LOOP_EXIT | E_GOTO) == 0
    }
    pub(crate) fn is_loop_dag_in(&self, b: SId, i: usize) -> bool {
        self.in_label(b, i) & (E_IRREDUCIBLE | E_BACK | E_LOOP_EXIT | E_GOTO) == 0
    }
    /// `getOutIndex`: the first out edge to `to`.
    pub(crate) fn out_index(&self, b: SId, to: SId) -> Option<usize> {
        self.b(b).outs.iter().position(|e| e.point == to)
    }
    /// `getParent` walked up until the parent is the root (`FloatingEdge`, `LoopBody` updates).
    pub(crate) fn top_level(&self, mut b: SId) -> SId {
        while let Some(p) = self.b(b).parent.filter(|&p| p != ROOT) {
            b = p;
        }
        b
    }

    // ---- FlowBlock edge edits (block.cc) ----

    /// `FlowBlock::addInEdge`: an edge from `from` into `to`.
    fn add_in_edge(&mut self, to: SId, from: SId, label: u32) {
        let ourrev = self.size_out(from);
        let brev = self.size_in(to);
        self.bm(to).ins.push(SEdge { point: from, label, reverse: ourrev });
        self.bm(from).outs.push(SEdge { point: to, label, reverse: brev });
    }

    /// `FlowBlock::halfDeleteInEdge`.
    fn half_delete_in_edge(&mut self, b: SId, slot: usize) {
        self.bm(b).ins.remove(slot);
        for i in slot..self.size_in(b) {
            let SEdge { point, reverse, .. } = self.b(b).ins[i];
            self.bm(point).outs[reverse].reverse -= 1;
        }
    }

    /// `FlowBlock::halfDeleteOutEdge`.
    fn half_delete_out_edge(&mut self, b: SId, slot: usize) {
        self.bm(b).outs.remove(slot);
        for i in slot..self.size_out(b) {
            let SEdge { point, reverse, .. } = self.b(b).outs[i];
            self.bm(point).ins[reverse].reverse -= 1;
        }
    }

    /// `FlowBlock::removeInEdge`.
    fn remove_in_edge(&mut self, b: SId, slot: usize) {
        let SEdge { point, reverse, .. } = self.b(b).ins[slot];
        self.half_delete_in_edge(b, slot);
        self.half_delete_out_edge(point, reverse);
    }

    /// `FlowBlock::replaceInEdge`: in-edge `num` of `b` now comes from `from`.
    fn replace_in_edge(&mut self, b: SId, num: usize, from: SId) {
        let SEdge { point: oldb, reverse, label } = self.b(b).ins[num];
        self.half_delete_out_edge(oldb, reverse);
        let rev = self.size_out(from);
        self.bm(b).ins[num] = SEdge { point: from, label, reverse: rev };
        self.bm(from).outs.push(SEdge { point: b, label, reverse: num });
    }

    /// `FlowBlock::replaceOutEdge`: out-edge `num` of `b` now goes to `to`.
    fn replace_out_edge(&mut self, b: SId, num: usize, to: SId) {
        let SEdge { point: oldb, reverse, label } = self.b(b).outs[num];
        self.half_delete_in_edge(oldb, reverse);
        let rev = self.size_in(to);
        self.bm(b).outs[num] = SEdge { point: to, label, reverse: rev };
        self.bm(to).ins.push(SEdge { point: b, label, reverse: num });
    }

    /// `FlowBlock::swapEdges`. The `f_flip_path` toggle is left out: of the hierarchy nothing
    /// reads it (only `JumpBasic::foldInGuards` reads it, on basic blocks; see `BlockGraph::swap_edges`).
    fn swap_edges(&mut self, b: SId) {
        self.bm(b).outs.swap(0, 1);
        for i in 0..2 {
            let SEdge { point, reverse, .. } = self.b(b).outs[i];
            self.bm(point).ins[reverse].reverse = i;
        }
    }

    /// `FlowBlock::setOutEdgeFlag`.
    pub(crate) fn set_out_edge_flag(&mut self, b: SId, i: usize, lab: u32) {
        let SEdge { point, reverse, .. } = self.b(b).outs[i];
        self.bm(b).outs[i].label |= lab;
        self.bm(point).ins[reverse].label |= lab;
    }

    /// `FlowBlock::clearOutEdgeFlag`.
    pub(crate) fn clear_out_edge_flag(&mut self, b: SId, i: usize, lab: u32) {
        let SEdge { point, reverse, .. } = self.b(b).outs[i];
        self.bm(b).outs[i].label &= !lab;
        self.bm(point).ins[reverse].label &= !lab;
    }

    /// `FlowBlock::setGotoBranch`.
    pub(crate) fn set_goto_branch(&mut self, b: SId, i: usize) -> Result<()> {
        if i >= self.size_out(b) {
            return err("Could not find block edge to mark unstructured");
        }
        self.set_out_edge_flag(b, i, E_GOTO);
        self.bm(b).flags |= F_INTERIOR_GOTOOUT;
        let p = self.out(b, i);
        self.bm(p).flags |= F_INTERIOR_GOTOIN;
        Ok(())
    }

    /// `FlowBlock::setDefaultSwitch`.
    fn set_default_switch(&mut self, b: SId, pos: usize) {
        for i in 0..self.size_out(b) {
            if self.is_default_branch(b, i) {
                self.clear_out_edge_flag(b, i, E_DEFAULTSWITCH);
            }
        }
        self.set_out_edge_flag(b, pos, E_DEFAULTSWITCH);
    }

    /// `FlowBlock::dedup` (`findDups`, `eliminateInDups`, `eliminateOutDups`).
    fn dedup(&mut self, b: SId) {
        for out in [false, true] {
            let edges: Vec<SId> = if out { &self.b(b).outs } else { &self.b(b).ins }.iter().map(|e| e.point).collect();
            let mut duplist = Vec::new();
            for &p in &edges {
                if self.flag(p, F_MARK2) {
                    continue;
                }
                if self.flag(p, F_MARK) {
                    duplist.push(p);
                    self.bm(p).flags |= F_MARK2;
                } else {
                    self.bm(p).flags |= F_MARK;
                }
            }
            for &p in &edges {
                self.bm(p).flags &= !(F_MARK | F_MARK2);
            }
            for d in duplist {
                self.eliminate_dups(b, d, out);
            }
        }
    }

    /// `eliminateInDups` / `eliminateOutDups`: keep the first edge to `bl`, or-ing in the
    /// labels of the others.
    fn eliminate_dups(&mut self, b: SId, bl: SId, out: bool) {
        let mut indval = None;
        let mut i = 0;
        while i < if out { self.size_out(b) } else { self.size_in(b) } {
            let e = if out { self.b(b).outs[i] } else { self.b(b).ins[i] };
            if e.point != bl {
                i += 1;
                continue;
            }
            let Some(k) = indval else {
                indval = Some(i);
                i += 1;
                continue;
            };
            if out {
                self.bm(b).outs[k].label |= e.label;
                self.half_delete_out_edge(b, i);
                self.half_delete_in_edge(bl, e.reverse);
            } else {
                self.bm(b).ins[k].label |= e.label;
                self.half_delete_in_edge(b, i);
                self.half_delete_out_edge(bl, e.reverse);
            }
        }
    }

    // ---- BlockGraph edits (block.cc) ----

    /// `BlockGraph::addBlock`.
    fn add_block(&mut self, g: SId, bl: SId) {
        let min = self.b(bl).index;
        let gb = self.b(g);
        if gb.list.is_empty() || min < gb.index {
            self.bm(g).index = min;
        }
        self.bm(bl).parent = Some(g);
        self.bm(g).list.push(bl);
    }

    /// `BlockGraph::forceOutputNum`: self loop edges until `b` has `n` outputs.
    fn force_output_num(&mut self, b: SId, n: usize) {
        while self.size_out(b) < n {
            self.add_in_edge(b, b, E_LOOP | E_BACK);
        }
    }

    /// `BlockGraph::forceFalseEdge`.
    fn force_false_edge(&mut self, b: SId, out0: SId) -> Result<()> {
        if self.size_out(b) != 2 {
            return err("Can only preserve binary condition");
        }
        let out0 = if self.b(out0).parent == Some(b) { b } else { out0 };
        if self.out(b, 0) != out0 {
            self.swap_edges(b);
        }
        if self.out(b, 0) != out0 {
            return err("Unable to preserve condition");
        }
        Ok(())
    }

    /// `BlockGraph::removeEdge` (in the root).
    fn remove_edge(&mut self, begin: SId, end: SId) -> Result<()> {
        let Some(i) = self.b(end).ins.iter().position(|e| e.point == begin) else {
            return err("Bad edge remove");
        };
        self.remove_in_edge(end, i);
        Ok(())
    }

    /// `BlockGraph::selfIdentify` on `ident`: edges from or to blocks outside it now attach to it.
    fn self_identify(&mut self, ident: SId) {
        for k in 0..self.b(ident).list.len() {
            let mybl = self.b(ident).list[k];
            let mut i = 0;
            while i < self.size_in(mybl) {
                let other = self.in_(mybl, i);
                if self.b(other).parent == Some(ident) {
                    i += 1;
                    continue;
                }
                for j in 0..self.size_out(other) {
                    if self.out(other, j) == mybl {
                        self.replace_out_edge(other, j, ident);
                    }
                }
            }
            i = 0;
            while i < self.size_out(mybl) {
                let other = self.out(mybl, i);
                if self.b(other).parent == Some(ident) {
                    i += 1;
                    continue;
                }
                for j in 0..self.size_in(other) {
                    if self.in_(other, j) == mybl {
                        self.replace_in_edge(other, j, ident);
                    }
                }
                if self.is_switch_out(mybl) {
                    self.bm(ident).flags |= F_SWITCH_OUT;
                }
            }
        }
        self.dedup(ident);
    }

    /// `BlockGraph::identifyInternal` on the root: `nodes` move into `ident`.
    fn identify_internal(&mut self, ident: SId, nodes: &[SId]) {
        for &n in nodes {
            self.set_mark(n);
            self.add_block(ident, n);
            let fl = self.b(n).flags & (F_INTERIOR_GOTOOUT | F_INTERIOR_GOTOIN);
            self.bm(ident).flags |= fl;
        }
        let list = std::mem::take(&mut self.bm(ROOT).list);
        let mut newlist = Vec::with_capacity(list.len());
        for b in list {
            if self.is_mark(b) {
                self.clear_mark(b);
            } else {
                newlist.push(b);
            }
        }
        self.bm(ROOT).list = newlist;
        self.self_identify(ident);
    }

    /// The common start of the `newBlock*` constructors: a block of `kind` holding `nodes`,
    /// added to the root.
    fn new_internal(&mut self, kind: Kind, nodes: &[SId]) -> SId {
        let ret = self.new_block(kind);
        self.identify_internal(ret, nodes);
        self.add_block(ROOT, ret);
        ret
    }

    /// `BlockGraph::newBlockGoto`.
    pub(crate) fn new_goto(&mut self, bl: SId) -> Result<()> {
        let target = self.out(bl, 0);
        let ret = self.new_internal(Kind::Goto(target), &[bl]);
        self.force_output_num(ret, 1);
        self.remove_edge(ret, self.out(ret, 0))
    }

    /// `BlockGraph::newBlockMultiGoto`.
    pub(crate) fn new_multi_goto(&mut self, bl: SId, outedge: usize) -> Result<()> {
        let targetbl = self.out(bl, outedge);
        let isdefault = self.is_default_branch(bl, outedge);
        let ret = if matches!(self.b(bl).kind, Kind::MultiGoto { .. }) {
            self.push_goto(bl, targetbl);
            self.remove_edge(bl, targetbl)?;
            bl
        } else {
            let orig = self.size_out(bl);
            let ret = self.new_internal(Kind::MultiGoto { gotos: Vec::new(), default_goto: false }, &[bl]);
            self.push_goto(ret, targetbl);
            if targetbl != bl {
                if self.size_out(ret) != orig {
                    self.force_output_num(ret, self.size_out(ret) + 1);
                }
                self.remove_edge(ret, targetbl)?;
            }
            ret
        };
        if isdefault {
            if let Kind::MultiGoto { default_goto, .. } = &mut self.bm(ret).kind {
                *default_goto = true;
            }
        }
        Ok(())
    }

    /// `BlockMultiGoto::addEdge`.
    fn push_goto(&mut self, b: SId, target: SId) {
        if let Kind::MultiGoto { gotos, .. } = &mut self.bm(b).kind {
            gotos.push(target);
        }
    }

    /// `BlockGraph::newBlockList`.
    pub(crate) fn new_list(&mut self, nodes: &[SId]) -> Result<()> {
        let Some(&last) = nodes.last() else { return err("empty block list") };
        let outforce = self.size_out(last);
        let out0 = (outforce == 2).then(|| self.out(last, 0));
        let ret = self.new_internal(Kind::List, nodes);
        self.force_output_num(ret, outforce);
        match out0 {
            Some(o) if self.size_out(ret) == 2 => self.force_false_edge(ret, o),
            _ => Ok(()),
        }
    }

    /// `BlockGraph::newBlockCondition`.
    pub(crate) fn new_condition(&mut self, b1: SId, b2: SId) -> Result<()> {
        let out0 = self.out(b2, 0);
        let opc = if self.out(b1, 0) == b2 { Opcode::IntOr } else { Opcode::IntAnd };
        let ret = self.new_internal(Kind::Condition(opc), &[b1, b2]);
        self.force_output_num(ret, 2);
        self.force_false_edge(ret, out0)
    }

    /// `BlockGraph::newBlockIfGoto`.
    pub(crate) fn new_if_goto(&mut self, cond: SId) -> Result<()> {
        if !self.is_goto_out(cond, 1) {
            return err("Building ifgoto where true branch is not the goto");
        }
        let out0 = self.out(cond, 0);
        let ret = self.new_internal(Kind::IfGoto(self.out(cond, 1)), &[cond]);
        self.force_output_num(ret, 2);
        self.force_false_edge(ret, out0)?;
        self.remove_edge(ret, self.out(ret, 1))
    }

    /// `newBlockIf`, `newBlockIfElse`, `newBlockIfNoExit`, `newBlockWhileDo`, `newBlockDoWhile`,
    /// `newBlockInfLoop`: `nodes` collapse into a `kind` block forced to `outs` outputs.
    pub(crate) fn new_simple(&mut self, kind: Kind, nodes: &[SId], outs: Option<usize>) -> SId {
        let ret = self.new_internal(kind, nodes);
        if let Some(n) = outs {
            self.force_output_num(ret, n);
        }
        ret
    }

    /// `BlockGraph::newBlockSwitch`. `grabCaseBasic` (the case order and labels) is left out:
    /// only printing (`BlockSwitch::finalizePrinting`, stage S9) reads it.
    pub(crate) fn new_switch(&mut self, cs: &[SId], has_exit: bool) -> Result<()> {
        let leaf = cs.first().and_then(|&root| self.exit_leaf(root));
        if !leaf.is_some_and(|l| matches!(self.b(l).kind, Kind::Copy(_))) {
            return err("Could not get switch leaf");
        }
        let ret = self.new_internal(Kind::Switch, cs);
        if has_exit {
            self.force_output_num(ret, 1);
        }
        self.bm(ret).flags &= !F_SWITCH_OUT;
        Ok(())
    }

    /// `getExitLeaf`: a copy is its own; goto, multi-goto and if-goto blocks take component 0's,
    /// a list its last component's; the other kinds have none.
    fn exit_leaf(&self, mut b: SId) -> Option<SId> {
        loop {
            let bl = self.b(b);
            b = match bl.kind {
                Kind::Copy(_) => return Some(b),
                Kind::Goto(_) | Kind::MultiGoto { .. } | Kind::IfGoto(_) => *bl.list.first()?,
                Kind::List => *bl.list.last()?,
                _ => return None,
            };
        }
    }

    /// `BlockGraph::buildCopy` of the basic blocks into an empty root, with the defaults of
    /// `Funcdata::installSwitchDefaults` on the copies' edges. The copy takes the basic block's
    /// flags (`flags |= bl->flags`); of the basic flags only `f_switch_out` is read during
    /// structuring, and ghidra-rs sets no other basic flag the hierarchy reads (`f_entry_point`
    /// is read only by `spliceBlock`, which the hierarchy never runs), so only it is derived:
    /// `BlockBasic::insert` sets it for a BRANCHIND, `newBlockCopy` for more than two outputs.
    fn build_copy(&mut self, fd: &Funcdata) -> Result<()> {
        self.blocks.clear();
        let root = self.new_block(Kind::Graph);
        let g = &fd.blocks;
        let base = self.blocks.len() as u32;
        let map: std::collections::HashMap<BlockId, SId> =
            g.list.iter().enumerate().map(|(i, &b)| (b, SId(base + i as u32))).collect();
        let copy = |b: BlockId| map[&b];
        for &bb in &g.list {
            let bl = g.block(bb);
            let id = self.new_block(Kind::Copy(bb));
            let edge =
                |e: &super::block::Edge| SEdge { point: copy(e.point), label: e.cpp_label(), reverse: e.reverse };
            let s = self.bm(id);
            s.ins = bl.ins.iter().map(edge).collect();
            s.outs = bl.outs.iter().map(edge).collect();
            s.index = bl.index;
            let last = bl.ops.last().map(|&op| fd.op(op).opc);
            if last == Some(Opcode::Branchind) || s.outs.len() > 2 {
                s.flags |= F_SWITCH_OUT;
            }
            self.add_block(root, id);
        }
        for (pos, bb) in switch_defaults(fd) {
            if pos >= self.size_out(copy(bb)) {
                return err("switch default edge no longer exists");
            }
            self.set_default_switch(copy(bb), pos);
        }
        Ok(())
    }

    // ---- virtual methods dispatched on the kind ----

    /// `isComplex`: `BlockCopy` and `BlockCondition` delegate (to the copied block, to the
    /// first component), a graph is complex.
    pub(crate) fn is_complex(&self, fd: &Funcdata, mut b: SId) -> bool {
        loop {
            match self.b(b).kind {
                Kind::Copy(bb) => return basic_is_complex(fd, bb),
                Kind::Condition(_) => b = self.b(b).list[0],
                _ => return true,
            }
        }
    }

    /// `negateCondition`: `true` when the data-flow changed (a basic block's CBRANCH flipped).
    /// A list negates its last component, a condition both components (and swaps AND/OR), a
    /// copy its basic block; each of those inner calls passes `toporbottom` false, so only the
    /// basic blocks and `b` itself swap edges. The effects touch distinct blocks, so the work
    /// list visits them in any order with the same result.
    pub(crate) fn negate_condition(&mut self, fd: &mut Funcdata, b: SId, toporbottom: bool) -> Result<bool> {
        let mut res = false;
        let mut work = vec![b];
        while let Some(cur) = work.pop() {
            match self.b(cur).kind {
                Kind::Copy(bb) => res |= basic_negate_condition(fd, bb)?,
                Kind::List => {
                    let Some(&last) = self.b(cur).list.last() else { return err("negating an empty list") };
                    work.push(last);
                }
                Kind::Condition(opc) => {
                    work.extend_from_slice(&self.b(cur).list[..2]);
                    let opc = if opc == Opcode::BoolAnd { Opcode::BoolOr } else { Opcode::BoolAnd };
                    self.bm(cur).kind = Kind::Condition(opc);
                }
                _ => {}
            }
        }
        // FlowBlock::negateCondition
        if toporbottom {
            self.swap_edges(b);
        }
        Ok(res)
    }

    /// `Funcdata::printBlockTree`: `printTree` of the root, if structured: each block's header
    /// indented two spaces a level, then a graph's components in order (a work stack, depth
    /// first). `BlockCopy::printTree` prints its basic block.
    pub(crate) fn print_tree(&self, fd: &Funcdata) -> String {
        use std::fmt::Write;
        let mut s = String::new();
        if self.is_empty() {
            return s;
        }
        let mut stack = vec![(ROOT, 0usize)];
        while let Some((b, level)) = stack.pop() {
            s.push_str(&"  ".repeat(level));
            let bl = self.b(b);
            if let Kind::Copy(bb) = bl.kind {
                let basic = fd.blocks.block(bb);
                let _ = writeln!(s, "Basic Block {} 0x{:08x}-0x{:08x}", basic.index, basic.start, basic.stop);
                continue;
            }
            let _ = writeln!(s, "{}{}", self.header_name(b), bl.index);
            stack.extend(bl.list.iter().rev().map(|&c| (c, level + 1)));
        }
        s
    }

    /// The `printHeader` text before `FlowBlock::printHeader` (the index) of a graph block.
    fn header_name(&self, b: SId) -> String {
        let bl = self.b(b);
        match &bl.kind {
            Kind::Copy(_) | Kind::Graph => String::new(),
            Kind::Goto(_) => "Plain goto block ".into(),
            Kind::MultiGoto { .. } => "Multi goto block ".into(),
            Kind::List => "List block ".into(),
            Kind::Condition(opc) => format!("Condition block({}) ", if *opc == Opcode::BoolAnd { "&&" } else { "||" }),
            Kind::If => "If block ".into(),
            Kind::IfElse => "If/else block ".into(),
            Kind::IfNoExit => "If (no exit) block ".into(),
            Kind::IfGoto(_) => "If goto block ".into(),
            Kind::WhileDo if bl.flags & F_WHILEDO_OVERFLOW != 0 => "Whiledo block (overflow) ".into(),
            Kind::WhileDo => "Whiledo block ".into(),
            Kind::DoWhile => "Dowhile block ".into(),
            Kind::InfLoop => "Infinite loop block ".into(),
            Kind::Switch => "Switch block ".into(),
        }
    }
}

/// `Funcdata::installSwitchDefaults`: for each jump table with a default, the switch block and
/// the out-edge position of its default. The default is `JumpTable::switchOver`'s: the
/// destination most table entries go to, if more than one entry does (the lowest position on
/// a tie). Like the C++ `defaultBlock` it is an out-edge position as of `switchOver`: the flow
/// (`flow.rs`) gives the BRANCHIND one out edge per distinct table address, in table order, so
/// the position is the address's rank among the distinct addresses, whatever edits came since.
/// When `switchnorm` is ported (`foldInGuards`, `setLastAsDefault` change the default after
/// flow), the default must be stored on the `JumpTable` at switch-over time instead.
fn switch_defaults(fd: &Funcdata) -> Vec<(usize, BlockId)> {
    let mut res = Vec::new();
    for jt in &fd.jumptables {
        let Some(bb) = fd.op(jt.op).parent else { continue };
        let mut distinct: Vec<u64> = Vec::new();
        let mut counts: Vec<usize> = Vec::new();
        for &t in &jt.targets {
            match distinct.iter().position(|&d| d == t) {
                Some(pos) => counts[pos] += 1,
                None => {
                    distinct.push(t);
                    counts.push(1);
                }
            }
        }
        let mut best = None;
        let mut maxcount = 1;
        for (pos, &c) in counts.iter().enumerate() {
            if c > maxcount {
                maxcount = c;
                best = Some(pos);
            }
        }
        if let Some(pos) = best {
            res.push((pos, bb));
        }
    }
    res
}

/// `BlockBasic::isComplex`: more than two statements (the branch of a 2-way block counts; an
/// op whose output is read outside the block, by a marker, not at all, is address tied, or read
/// more than `max_implied_ref` = 2 times is a statement).
fn basic_is_complex(fd: &Funcdata, bb: BlockId) -> bool {
    /// `Architecture::max_implied_ref` (architecture.cc: 2; no console command or spec sets it)
    const MAX_IMPLIED_REF: usize = 2;
    let bl = fd.blocks.block(bb);
    let mut statement = usize::from(bl.outs.len() >= 2);
    for &op in &bl.ops {
        let o = fd.op(op);
        if o.is_marker() {
            continue;
        }
        if o.is_call() {
            statement += 1;
        } else if let Some(vn) = o.out {
            let v = fd.vn(vn);
            let yes = v.descend.is_empty()
                || v.flags.has(VnFlags::ADDRTIED)
                || v.descend.iter().enumerate().any(|(k, &d)| {
                    let dop = fd.op(d);
                    dop.is_marker() || dop.parent != Some(bb) || k + 1 > MAX_IMPLIED_REF
                });
            statement += usize::from(yes);
        } else if !(o.is_branch() || o.opc == Opcode::Return) {
            // isFlowBreak: the branch and return ops
            statement += 1;
        }
        if statement > 2 {
            return true;
        }
    }
    false
}

/// `BlockBasic::negateCondition`: flip the CBRANCH's `boolean_flip` and `fallthru_true` and
/// swap the basic block's out edges.
fn basic_negate_condition(fd: &mut Funcdata, bb: BlockId) -> Result<bool> {
    let Some(&last) = fd.blocks.block(bb).ops.last() else { return err("negating an empty basic block") };
    let fl = &mut fd.op_mut(last).flags;
    for f in [OpFlags::BOOLEAN_FLIP, OpFlags::FALLTHRU_TRUE] {
        if fl.has(f) {
            fl.clear(f);
        } else {
            fl.set(f);
        }
    }
    fd.blocks.swap_edges(bb);
    Ok(true)
}

/// `ActionBlockStructure`: build the copy of the basic blocks and collapse it, once.
pub(crate) fn block_structure(fd: &mut Funcdata, _: &super::Arch) -> Result<i32> {
    if !fd.structure.is_empty() {
        return Ok(0);
    }
    let mut s = std::mem::take(&mut fd.structure);
    s.build_copy(fd)?;
    let res = super::collapse::collapse_all(&mut s, fd);
    fd.structure = s;
    res
}

#[cfg(test)]
mod tests {
    //! Small hand-built graphs. The expected trees are derived by hand from the C++
    //! (blockaction.cc, block.cc), not run on the reference: a binary producing exactly these
    //! graphs is not practical to build. Block `i` starts at `0x1000 + 0x10 * i`.
    use super::super::funcdata::JumpTable;
    use super::super::op::OpId;
    use super::*;

    /// A function of `n` blocks with the edges in order (each block's out edges in the order
    /// given), a CBRANCH ending each two-way block and a BRANCHIND each wider one.
    fn graph(n: u64, edges: &[(usize, usize)]) -> (Funcdata, Vec<BlockId>) {
        let mut fd = Funcdata::new(0x1000);
        let b: Vec<BlockId> = (0..n).map(|i| fd.blocks.new_block(0x1000 + 0x10 * i)).collect();
        fd.blocks.set_start_block(b[0]);
        for &(f, t) in edges {
            fd.blocks.add_edge(b[f], b[t]);
        }
        for &bl in &b {
            let opc = match fd.blocks.block(bl).outs.len() {
                2 => Opcode::Cbranch,
                0 | 1 => continue,
                _ => Opcode::Branchind,
            };
            let op = fd.new_op(opc, fd.blocks.block(bl).start);
            fd.op_insert_end(op, bl);
        }
        fd.blocks.structure_loops().unwrap();
        (fd, b)
    }

    fn last_op(fd: &Funcdata, bl: BlockId) -> OpId {
        *fd.blocks.block(bl).ops.last().unwrap()
    }

    /// `ActionBlockStructure` without the architecture: the change count and the tree.
    fn structure(fd: &mut Funcdata) -> (i32, String) {
        let mut s = std::mem::take(&mut fd.structure);
        s.build_copy(fd).unwrap();
        let n = super::super::collapse::collapse_all(&mut s, fd).unwrap();
        fd.structure = s;
        (n, fd.structure.print_tree(fd))
    }

    /// A->{B,C}, B->D, C->D: if/else, no negation (the true clause is out 1). List order is
    /// A, C, B, D (reverse post-order, out 0 first).
    #[test]
    fn if_else() {
        let (mut fd, _) = graph(4, &[(0, 1), (0, 2), (1, 3), (2, 3)]);
        let (n, tree) = structure(&mut fd);
        assert_eq!(n, 0);
        assert_eq!(
            tree,
            "0\n  List block 0\n    If/else block 0\n      Basic Block 0 0x00001000-0x00001000\n      \
             Basic Block 1 0x00001020-0x00001020\n      Basic Block 2 0x00001010-0x00001010\n    \
             Basic Block 3 0x00001030-0x00001030\n"
        );
    }

    /// A->{B,D}, B->D: the clause is out 0, so `ruleBlockProperIf` negates A: both CBRANCH flags
    /// flip and A's basic out edges swap.
    #[test]
    fn proper_if_negates() {
        let (mut fd, b) = graph(3, &[(0, 1), (0, 2), (1, 2)]);
        let (n, tree) = structure(&mut fd);
        assert_eq!(n, 1);
        let fl = fd.op(last_op(&fd, b[0])).flags;
        assert!(fl.has(OpFlags::BOOLEAN_FLIP) && fl.has(OpFlags::FALLTHRU_TRUE));
        assert_eq!(fd.blocks.block(b[0]).outs[0].point, b[2]);
        assert_eq!(
            tree,
            "0\n  List block 0\n    If block 0\n      Basic Block 0 0x00001000-0x00001000\n      \
             Basic Block 1 0x00001010-0x00001010\n    Basic Block 2 0x00001020-0x00001020\n"
        );
    }

    /// A->B, A->C, B->C, C->B, B->X: a loop with two entries. `findIrreducible` marks A->C,
    /// which becomes an if-goto; B (negated) and C make the while loop.
    #[test]
    fn irreducible_loop() {
        let (mut fd, b) = graph(4, &[(0, 1), (0, 2), (1, 2), (2, 1), (1, 3)]);
        let (n, tree) = structure(&mut fd);
        assert_eq!(n, 1);
        assert!(fd.op(last_op(&fd, b[1])).flags.has(OpFlags::BOOLEAN_FLIP));
        assert_eq!(
            tree,
            "0\n  List block 0\n    If goto block 0\n      Basic Block 0 0x00001000-0x00001000\n    \
             Whiledo block 1\n      Basic Block 1 0x00001010-0x00001010\n      \
             Basic Block 3 0x00001020-0x00001020\n    Basic Block 2 0x00001030-0x00001030\n"
        );
    }

    /// S switches to D, C, E (table D, C, D, E: D is the default at position 0); D->E, C->E.
    /// The case edge S->E skips to the exit while the default does not, so `checkSwitchSkips`
    /// makes it a goto (a multi-goto block), then the switch collapses.
    #[test]
    fn switch_with_skip() {
        let (mut fd, b) = graph(4, &[(0, 1), (0, 2), (0, 3), (1, 3), (2, 3)]);
        let op = last_op(&fd, b[0]);
        fd.jumptables.push(JumpTable { op, targets: vec![0x1010, 0x1020, 0x1010, 0x1030] });
        assert_eq!(switch_defaults(&fd), vec![(0, b[0])]);
        let (_, tree) = structure(&mut fd);
        assert_eq!(
            tree,
            "0\n  List block 0\n    Switch block 0\n      Multi goto block 0\n        \
             Basic Block 0 0x00001000-0x00001000\n      Basic Block 2 0x00001010-0x00001010\n      \
             Basic Block 1 0x00001020-0x00001020\n    Basic Block 3 0x00001030-0x00001030\n"
        );
    }
}
