//! Port of `CollapseStructure` (blockaction.cc) with `LoopBody`, `TraceDAG` and `FloatingEdge`:
//! collapse the copy of the control-flow graph in [`Structure`] into structured blocks, marking
//! edges as unstructured (`goto`) when no rule applies. The order rules are tried, blocks are
//! visited and edges are picked follows the C++ exactly; it decides the output.

use super::structure::{Kind, SId, Structure, E_LOOP_EXIT, F_WHILEDO_OVERFLOW};
use super::{err, Funcdata, Result};

/// Port of `FloatingEdge`: an edge given by its end points, followed up the collapse hierarchy.
#[derive(Debug, Clone, Copy)]
struct FloatingEdge {
    top: SId,
    bottom: SId,
}

impl FloatingEdge {
    /// `FloatingEdge::getCurrentEdge`: the current top block and the out-edge index, if the
    /// edge still exists.
    fn current(&mut self, g: &Structure) -> Option<(SId, usize)> {
        self.top = g.top_level(self.top);
        self.bottom = g.top_level(self.bottom);
        g.out_index(self.top, self.bottom).map(|i| (self.top, i))
    }
}

/// Port of `LoopBody`. `head` is `None` once merged into another loop with the same head.
#[derive(Debug, Clone)]
struct LoopBody {
    head: Option<SId>,
    tails: Vec<SId>,
    depth: i32,
    uniquecount: usize,
    exitblock: Option<SId>,
    exitedges: Vec<FloatingEdge>,
    /// index of the immediately containing loop in `CollapseStructure::loops`
    immed_container: Option<usize>,
}

fn clear_marks(g: &mut Structure, body: &[SId]) {
    for &b in body {
        g.clear_mark(b);
    }
}

/// Mark and append every block reaching `body[from..]` backwards, not through goto edges
/// (the back-tracing loop shared by `findBase` and `extendToContainer`).
fn trace_back(g: &mut Structure, body: &mut Vec<SId>, mut i: usize) {
    while i < body.len() {
        let cur = body[i];
        i += 1;
        push_preds(g, cur, body);
    }
}

/// Mark and append the unmarked predecessors of `cur` not reached through a goto edge.
fn push_preds(g: &mut Structure, cur: SId, body: &mut Vec<SId>) {
    for k in 0..g.size_in(cur) {
        if g.is_goto_in(cur, k) {
            continue;
        }
        let bl = g.in_(cur, k);
        if !g.is_mark(bl) {
            g.set_mark(bl);
            body.push(bl);
        }
    }
}

/// Grow `body` by the blocks reached only from it (`LoopBody::extend` without the exit and
/// goto checks when `exit` is `None` and `skip_goto` false: `onlyReachableFromRoot`).
fn extend_reach(g: &mut Structure, body: &mut Vec<SId>, exit: Option<SId>, skip_goto: bool) {
    let mut trial = Vec::new();
    let mut i = 0;
    while i < body.len() {
        let bl = body[i];
        i += 1;
        for j in 0..g.size_out(bl) {
            if skip_goto && g.is_goto_out(bl, j) {
                continue;
            }
            let cur = g.out(bl, j);
            if g.is_mark(cur) || Some(cur) == exit {
                continue;
            }
            let mut count = g.b(cur).visitcount;
            if count == 0 {
                trial.push(cur);
            }
            count += 1;
            g.bm(cur).visitcount = count;
            if count as usize == g.size_in(cur) {
                g.set_mark(cur);
                body.push(cur);
            }
        }
    }
    for t in trial {
        g.bm(t).visitcount = 0;
    }
}

impl LoopBody {
    fn new(head: SId) -> LoopBody {
        LoopBody {
            head: Some(head),
            tails: Vec::new(),
            depth: 0,
            uniquecount: 0,
            exitblock: None,
            exitedges: Vec::new(),
            immed_container: None,
        }
    }

    fn head(&self) -> Result<SId> {
        self.head.ok_or_else(|| super::LowlevelError("loop body without a head".into()))
    }

    /// `LoopBody::findBase`.
    fn find_base(&mut self, g: &mut Structure, body: &mut Vec<SId>) -> Result<()> {
        let head = self.head()?;
        g.set_mark(head);
        body.push(head);
        for &t in &self.tails {
            if !g.is_mark(t) {
                g.set_mark(t);
                body.push(t);
            }
        }
        self.uniquecount = body.len();
        trace_back(g, body, 1);
        Ok(())
    }

    /// `LoopBody::extendToContainer`.
    fn extend_to_container(&self, container: &LoopBody, g: &mut Structure, body: &mut Vec<SId>) -> Result<()> {
        let chead = container.head()?;
        let mut i = 0;
        if !g.is_mark(chead) {
            g.set_mark(chead);
            body.push(chead);
            i = 1;
        }
        for &t in &container.tails {
            if !g.is_mark(t) {
                g.set_mark(t);
                body.push(t);
            }
        }
        let head = self.head()?;
        if head != chead {
            push_preds(g, head, body);
        }
        trace_back(g, body, i);
        Ok(())
    }

    /// `LoopBody::update`: the current tail, or the head looping to itself, or `None` once
    /// the loop has collapsed.
    fn update(&mut self, g: &Structure) -> Result<Option<SId>> {
        let head = g.top_level(self.head()?);
        self.head = Some(head);
        for t in self.tails.iter_mut() {
            *t = g.top_level(*t);
            if *t != head {
                return Ok(Some(*t));
            }
        }
        Ok((0..g.size_out(head)).rev().any(|i| g.out(head, i) == head).then_some(head))
    }

    /// The out edges of `b` that are not gotos, as targets (the scan of `findExit` and
    /// `labelExitEdges`).
    fn decision_outs(g: &Structure, b: SId) -> Vec<SId> {
        (0..g.size_out(b)).filter(|&i| !g.is_goto_out(b, i)).map(|i| g.out(b, i)).collect()
    }

    /// `LoopBody::findExit`.
    fn find_exit(&mut self, g: &mut Structure, body: &[SId], loops: &[LoopBody]) -> Result<()> {
        let mut trialexit = Vec::new();
        let sources = self
            .tails
            .iter()
            .copied()
            .chain(body.iter().enumerate().filter(|&(i, _)| i == 0 || i >= self.uniquecount).map(|(_, &b)| b));
        for b in sources.collect::<Vec<_>>() {
            for cur in Self::decision_outs(g, b) {
                if !g.is_mark(cur) {
                    if self.immed_container.is_none() {
                        self.exitblock = Some(cur);
                        return Ok(());
                    }
                    trialexit.push(cur);
                }
            }
        }
        self.exitblock = None;
        let Some(c) = self.immed_container else { return Ok(()) };
        if trialexit.is_empty() {
            return Ok(());
        }
        let mut extension = Vec::new();
        self.extend_to_container(&loops[c], g, &mut extension)?;
        self.exitblock = trialexit.iter().copied().find(|&b| g.is_mark(b));
        clear_marks(g, &extension);
        Ok(())
    }

    /// `LoopBody::orderTails`: a tail with an edge to the exit goes first.
    fn order_tails(&mut self, g: &Structure) {
        let Some(exit) = self.exitblock else { return };
        if self.tails.len() <= 1 {
            return;
        }
        let pref = self.tails.iter().position(|&t| (0..g.size_out(t)).any(|j| g.out(t, j) == exit));
        if let Some(p) = pref.filter(|&p| p != 0) {
            self.tails.swap(0, p);
        }
    }

    /// `LoopBody::labelExitEdges`: exits from the middle, then the head, then the tails (more
    /// preferred later), and last those to the exit block.
    fn label_exit_edges(&mut self, g: &Structure, body: &[SId]) -> Result<()> {
        let head = self.head()?;
        let mut sources: Vec<SId> = body[self.uniquecount..].to_vec();
        sources.push(head);
        sources.extend(self.tails.iter().rev().filter(|&&t| t != head));
        let mut toexit = Vec::new();
        for b in sources {
            for bl in Self::decision_outs(g, b) {
                if Some(bl) == self.exitblock {
                    toexit.push(b);
                } else if !g.is_mark(bl) {
                    self.exitedges.push(FloatingEdge { top: b, bottom: bl });
                }
            }
        }
        if let Some(exit) = self.exitblock {
            self.exitedges.extend(toexit.into_iter().map(|b| FloatingEdge { top: b, bottom: exit }));
        }
        Ok(())
    }

    /// `LoopBody::emitLikelyEdges`.
    fn emit_likely_edges(&mut self, g: &Structure, likely: &mut Vec<FloatingEdge>) -> Result<()> {
        let head = g.top_level(self.head()?);
        self.head = Some(head);
        self.exitblock = self.exitblock.map(|e| g.top_level(e));
        for i in 0..self.tails.len() {
            let t = g.top_level(self.tails[i]);
            self.tails[i] = t;
            if Some(t) == self.exitblock {
                self.exitblock = None;
            }
        }
        let mut hold = None;
        let n = self.exitedges.len();
        for k in 0..n {
            let Some((inbl, outedge)) = self.exitedges[k].current(g) else { continue };
            let outbl = g.out(inbl, outedge);
            if k + 1 == n && Some(outbl) == self.exitblock {
                hold = Some(FloatingEdge { top: inbl, bottom: outbl });
                break;
            }
            likely.push(FloatingEdge { top: inbl, bottom: outbl });
        }
        for i in (0..self.tails.len()).rev() {
            if let Some(h) = hold.filter(|_| i == 0) {
                likely.push(h);
            }
            let tail = self.tails[i];
            for j in 0..g.size_out(tail) {
                if g.out(tail, j) == head {
                    likely.push(FloatingEdge { top: tail, bottom: head });
                }
            }
        }
        Ok(())
    }

    /// `setExitMarks` (`set`) / `clearExitMarks`: the loop-exit label on each exit edge.
    fn exit_marks(&mut self, g: &mut Structure, set: bool) {
        for e in self.exitedges.iter_mut() {
            if let Some((b, i)) = e.current(g) {
                if set {
                    g.set_out_edge_flag(b, i, E_LOOP_EXIT);
                } else {
                    g.clear_out_edge_flag(b, i, E_LOOP_EXIT);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------------------
// TraceDAG

type BpId = usize;
type TrId = usize;

/// Port of `TraceDAG::BranchPoint`.
#[derive(Debug, Clone)]
struct BranchPoint {
    parent: Option<BpId>,
    depth: i32,
    pathout: usize,
    ismark: bool,
    top: Option<SId>,
    paths: Vec<TrId>,
}

/// Port of `TraceDAG::BlockTrace`.
#[derive(Debug, Clone)]
struct BlockTrace {
    active: bool,
    terminal: bool,
    top: BpId,
    pathout: usize,
    bottom: Option<SId>,
    destnode: Option<SId>,
    edgelump: i32,
    derivedbp: Option<BpId>,
}

/// Port of `TraceDAG::BadEdgeScore`.
#[derive(Debug, Clone)]
struct BadEdgeScore {
    exitproto: SId,
    trace: TrId,
    distance: i32,
    terminal: i32,
    siblingedge: i32,
}

/// Port of `TraceDAG`. The C++ active list (`std::list` with iterators) is a vector of trace
/// ids with a cursor position.
struct TraceDag<'a> {
    g: &'a mut Structure,
    likelygoto: Vec<FloatingEdge>,
    rootlist: Vec<SId>,
    bps: Vec<BranchPoint>,
    traces: Vec<BlockTrace>,
    activetrace: Vec<TrId>,
    finishblock: Option<SId>,
}

impl<'a> TraceDag<'a> {
    fn new(g: &'a mut Structure) -> TraceDag<'a> {
        TraceDag {
            g,
            likelygoto: Vec::new(),
            rootlist: Vec::new(),
            bps: Vec::new(),
            traces: Vec::new(),
            activetrace: Vec::new(),
            finishblock: None,
        }
    }

    fn new_trace(&mut self, top: BpId, pathout: usize, bottom: Option<SId>, destnode: SId) -> TrId {
        self.traces.push(BlockTrace {
            active: false,
            terminal: false,
            top,
            pathout,
            bottom,
            destnode: Some(destnode),
            edgelump: 1,
            derivedbp: None,
        });
        self.traces.len() - 1
    }

    /// The `BranchPoint(BlockTrace*)` constructor with `createTraces`.
    fn new_branch(&mut self, parenttrace: TrId) -> BpId {
        let pt = &self.traces[parenttrace];
        let (parent, pathout, top) = (pt.top, pt.pathout, pt.destnode);
        let bp = self.bps.len();
        let depth = self.bps[parent].depth + 1;
        self.bps.push(BranchPoint { parent: Some(parent), depth, pathout, ismark: false, top, paths: Vec::new() });
        if let Some(t) = top {
            for i in 0..self.g.size_out(t) {
                if self.g.is_loop_dag_out(t, i) {
                    let n = self.bps[bp].paths.len();
                    let tr = self.new_trace(bp, n, Some(t), self.g.out(t, i));
                    self.bps[bp].paths.push(tr);
                }
            }
        }
        bp
    }

    fn pos(&self, t: TrId) -> usize {
        self.activetrace.iter().position(|&x| x == t).unwrap_or(self.activetrace.len())
    }

    /// `TraceDAG::insertActive`: append, returning its position.
    fn insert_active(&mut self, t: TrId) -> usize {
        self.activetrace.push(t);
        self.traces[t].active = true;
        self.activetrace.len() - 1
    }

    /// `TraceDAG::removeActive`.
    fn remove_active(&mut self, t: TrId) {
        let p = self.pos(t);
        if p < self.activetrace.len() {
            self.activetrace.remove(p);
        }
        self.traces[t].active = false;
    }

    /// Make `t` terminal (it reaches no further block).
    fn set_terminal(&mut self, t: TrId) {
        let tr = &mut self.traces[t];
        tr.terminal = true;
        tr.bottom = None;
        tr.destnode = None;
        tr.edgelump = 0;
    }

    /// `TraceDAG::initialize`: a virtual root branch point with a trace to each root.
    fn initialize(&mut self) {
        self.bps.push(BranchPoint { parent: None, depth: 0, pathout: 0, ismark: false, top: None, paths: Vec::new() });
        for i in 0..self.rootlist.len() {
            let n = self.bps[0].paths.len();
            let tr = self.new_trace(0, n, None, self.rootlist[i]);
            self.bps[0].paths.push(tr);
            self.insert_active(tr);
        }
    }

    /// `TraceDAG::removeTrace`: the trace's edge becomes a likely goto.
    fn remove_trace(&mut self, t: TrId) -> Result<()> {
        let tr = self.traces[t].clone();
        let (Some(bottom), Some(dest)) = (tr.bottom, tr.destnode) else {
            return err("removing a trace without an edge");
        };
        self.likelygoto.push(FloatingEdge { top: bottom, bottom: dest });
        self.g.bm(dest).visitcount += tr.edgelump;
        let parentbp = tr.top;
        if Some(bottom) != self.bps[parentbp].top {
            self.set_terminal(t);
            return Ok(());
        }
        self.remove_active(t);
        let paths = self.bps[parentbp].paths.clone();
        for &moved in &paths[tr.pathout + 1..] {
            self.traces[moved].pathout -= 1;
            if let Some(d) = self.traces[moved].derivedbp {
                self.bps[d].pathout -= 1;
            }
        }
        self.bps[parentbp].paths.remove(tr.pathout);
        Ok(())
    }

    /// `BranchPoint::markPath`: toggle the marks up to the root.
    fn mark_path(&mut self, bp: BpId) {
        let mut cur = Some(bp);
        while let Some(c) = cur {
            self.bps[c].ismark = !self.bps[c].ismark;
            cur = self.bps[c].parent;
        }
    }

    /// `BranchPoint::distance` from the marked `bp` to `op2`.
    fn distance(&self, bp: BpId, op2: BpId) -> i32 {
        let mut cur = Some(op2);
        while let Some(c) = cur {
            if self.bps[c].ismark {
                return (self.bps[bp].depth - self.bps[c].depth) + (self.bps[op2].depth - self.bps[c].depth);
            }
            cur = self.bps[c].parent;
        }
        self.bps[bp].depth + self.bps[op2].depth + 1
    }

    /// `TraceDAG::processExitConflict` on the scores `list[start..end]`.
    fn process_exit_conflict(&mut self, list: &mut [BadEdgeScore]) {
        for s in 0..list.len() {
            let startbp = self.traces[list[s].trace].top;
            if s + 1 == list.len() {
                continue;
            }
            self.mark_path(startbp);
            for it in s + 1..list.len() {
                let itbp = self.traces[list[it].trace].top;
                if startbp == itbp {
                    list[s].siblingedge += 1;
                    list[it].siblingedge += 1;
                }
                let dist = self.distance(startbp, itbp);
                if list[s].distance == -1 || list[s].distance > dist {
                    list[s].distance = dist;
                }
                if list[it].distance == -1 || list[it].distance > dist {
                    list[it].distance = dist;
                }
            }
            self.mark_path(startbp);
        }
    }

    /// `BadEdgeScore::operator<` as a key: exit block, branch point block, path.
    fn score_key(&self, s: &BadEdgeScore) -> (i32, i32, usize) {
        let tr = &self.traces[s.trace];
        let bpi = self.bps[tr.top].top.map_or(-1, |b| self.g.b(b).index);
        (self.g.b(s.exitproto).index, bpi, tr.pathout)
    }

    /// `BadEdgeScore::compareFinal`: `a` is less likely to be the bad edge than `b`.
    fn compare_final(&self, a: &BadEdgeScore, b: &BadEdgeScore) -> bool {
        if a.siblingedge != b.siblingedge {
            return b.siblingedge < a.siblingedge;
        }
        if a.terminal != b.terminal {
            return a.terminal < b.terminal;
        }
        if a.distance != b.distance {
            return a.distance < b.distance;
        }
        self.bps[self.traces[a.trace].top].depth < self.bps[self.traces[b.trace].top].depth
    }

    /// `TraceDAG::selectBadEdge`.
    fn select_bad_edge(&mut self) -> Result<TrId> {
        let mut list = Vec::new();
        for &t in &self.activetrace {
            let tr = &self.traces[t];
            if tr.terminal || (self.bps[tr.top].top.is_none() && tr.bottom.is_none()) {
                continue;
            }
            let Some(dest) = tr.destnode else { continue };
            list.push(BadEdgeScore {
                exitproto: dest,
                trace: t,
                distance: -1,
                terminal: i32::from(self.g.size_out(dest) == 0),
                siblingedge: 0,
            });
        }
        // std::list::sort is stable
        list.sort_by_key(|s| self.score_key(s));
        let mut start = 0;
        while start < list.len() {
            let mut end = start + 1;
            while end < list.len() && list[end].exitproto == list[start].exitproto {
                end += 1;
            }
            if end - start > 1 {
                self.process_exit_conflict(&mut list[start..end]);
            }
            start = end;
        }
        let Some(first) = list.first() else { return err("Could not select an unstructured edge") };
        let mut max = first;
        for s in &list[1..] {
            if self.compare_final(max, s) {
                max = s;
            }
        }
        Ok(max.trace)
    }

    /// `TraceDAG::checkOpen`.
    fn check_open(&self, t: TrId) -> bool {
        let tr = &self.traces[t];
        if tr.terminal {
            return false;
        }
        let mut isroot = false;
        if self.bps[tr.top].depth == 0 {
            if tr.bottom.is_none() {
                return true;
            }
            isroot = true;
        }
        let Some(bl) = tr.destnode else { return false };
        if Some(bl) == self.finishblock && !isroot {
            return false;
        }
        let ignore = tr.edgelump + self.g.b(bl).visitcount;
        let count = (0..self.g.size_in(bl)).filter(|&i| self.g.is_loop_dag_in(bl, i)).count() as i32;
        count <= ignore
    }

    /// `TraceDAG::openBranch`: the position of the next trace to look at.
    fn open_branch(&mut self, parent: TrId) -> usize {
        let nb = self.new_branch(parent);
        if self.bps[nb].paths.is_empty() {
            self.traces[parent].derivedbp = None;
            self.set_terminal(parent);
            return self.pos(parent);
        }
        self.traces[parent].derivedbp = Some(nb);
        self.remove_active(parent);
        let paths = self.bps[nb].paths.clone();
        let first = self.activetrace.len();
        for p in paths {
            self.insert_active(p);
        }
        first
    }

    /// `TraceDAG::checkRetirement`: the exit block when `t`'s branch point can be retired.
    fn check_retirement(&self, t: TrId) -> Option<Option<SId>> {
        let tr = &self.traces[t];
        if tr.pathout != 0 {
            return None;
        }
        let bp = &self.bps[tr.top];
        if bp.depth == 0 {
            let all = bp.paths.iter().all(|&p| self.traces[p].active && self.traces[p].terminal);
            return all.then_some(None);
        }
        let mut outblock = None;
        for &p in &bp.paths {
            let cur = &self.traces[p];
            if !cur.active {
                return None;
            }
            if cur.terminal || outblock == cur.destnode {
                continue;
            }
            if outblock.is_some() {
                return None;
            }
            outblock = cur.destnode;
        }
        Some(outblock)
    }

    /// `TraceDAG::retireBranch`: the position of the next trace to look at.
    fn retire_branch(&mut self, bp: BpId, exitblock: Option<SId>) -> usize {
        let mut edgeout = None;
        let mut sum = 0;
        for p in self.bps[bp].paths.clone() {
            if !self.traces[p].terminal {
                sum += self.traces[p].edgelump;
                if edgeout.is_none() {
                    edgeout = self.traces[p].bottom;
                }
            }
            self.remove_active(p);
        }
        if self.bps[bp].depth == 0 {
            return 0;
        }
        let Some(parent) = self.bps[bp].parent else { return 0 };
        let pt = self.bps[parent].paths[self.bps[bp].pathout];
        self.traces[pt].derivedbp = None;
        if edgeout.is_none() {
            self.set_terminal(pt);
        } else {
            let tr = &mut self.traces[pt];
            tr.bottom = edgeout;
            tr.destnode = exitblock;
            tr.edgelump = sum;
        }
        self.insert_active(pt)
    }

    /// `TraceDAG::pushBranches`.
    fn push_branches(&mut self) -> Result<()> {
        let mut cur = 0;
        let mut missed = 0;
        while !self.activetrace.is_empty() {
            if cur >= self.activetrace.len() {
                cur = 0;
            }
            let t = self.activetrace[cur];
            if missed >= self.activetrace.len() {
                let bad = self.select_bad_edge()?;
                self.remove_trace(bad)?;
                cur = 0;
                missed = 0;
            } else if let Some(exit) = self.check_retirement(t) {
                cur = self.retire_branch(self.traces[t].top, exit);
                missed = 0;
            } else if self.check_open(t) {
                cur = self.open_branch(t);
                missed = 0;
            } else {
                missed += 1;
                cur += 1;
            }
        }
        // clearVisitCount
        for e in &self.likelygoto {
            self.g.bm(e.bottom).visitcount = 0;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------------------
// CollapseStructure

/// Port of `CollapseStructure`.
struct Collapse<'a> {
    g: &'a mut Structure,
    fd: &'a mut Funcdata,
    finaltrace: bool,
    likelylistfull: bool,
    likelygoto: Vec<FloatingEdge>,
    likelyiter: usize,
    /// the `std::list<LoopBody>`; `order` is its current order
    loops: Vec<LoopBody>,
    order: Vec<usize>,
    loopbodyiter: usize,
    dataflow_changecount: i32,
}

/// `CollapseStructure::collapseAll`: the number of data-flow changes (`getChangeCount`).
pub(crate) fn collapse_all(g: &mut Structure, fd: &mut Funcdata) -> Result<i32> {
    let mut c = Collapse {
        g,
        fd,
        finaltrace: false,
        likelylistfull: false,
        likelygoto: Vec::new(),
        likelyiter: 0,
        loops: Vec::new(),
        order: Vec::new(),
        loopbodyiter: 0,
        dataflow_changecount: 0,
    };
    for i in 0..c.g.size() {
        let b = c.g.get(i);
        c.g.bm(b).visitcount = 0;
    }
    c.order_loop_bodies()?;
    c.collapse_conditions()?;
    let mut isolated = c.collapse_internal(None)?;
    while isolated < c.g.size() {
        let target = c.select_goto()?;
        isolated = c.collapse_internal(target)?;
    }
    Ok(c.dataflow_changecount)
}

impl Collapse<'_> {
    /// `CollapseStructure::labelLoops`: a loop body per back edge, sorted by head then tail.
    fn label_loops(&mut self) -> Vec<usize> {
        let mut looporder = Vec::new();
        for i in 0..self.g.size() {
            let bl = self.g.get(i);
            for j in 0..self.g.size_in(bl) {
                if self.g.is_back_edge_in(bl, j) {
                    let mut lb = LoopBody::new(bl);
                    lb.tails.push(self.g.in_(bl, j));
                    self.loops.push(lb);
                    looporder.push(self.loops.len() - 1);
                }
            }
        }
        let g = &*self.g;
        let key =
            |lb: &LoopBody| (lb.head.map_or(-1, |h| g.b(h).index), lb.tails.first().map_or(-1, |&t| g.b(t).index));
        let loops = &self.loops;
        looporder.sort_by_key(|&i| key(&loops[i]));
        looporder
    }

    /// `LoopBody::mergeIdenticalHeads`.
    fn merge_identical_heads(&mut self, looporder: &mut Vec<usize>) {
        let mut i = 0;
        let mut cur = looporder[0];
        for j in 1..looporder.len() {
            let next = looporder[j];
            if self.loops[next].head == self.loops[cur].head {
                let t = self.loops[next].tails[0];
                self.loops[cur].tails.push(t);
                self.loops[next].head = None;
            } else {
                i += 1;
                looporder[i] = next;
                cur = next;
            }
        }
        looporder.truncate(i + 1);
    }

    /// `LoopBody::find`: binary search of `looporder` by head index.
    fn find_loop(&self, looptop: SId, looporder: &[usize]) -> Option<usize> {
        let idx = self.g.b(looptop).index;
        looporder
            .binary_search_by_key(&idx, |&l| self.loops[l].head.map_or(-1, |h| self.g.b(h).index))
            .ok()
            .map(|p| looporder[p])
    }

    /// `LoopBody::labelContainments` for loop `l`.
    fn label_containments(&mut self, l: usize, body: &[SId], looporder: &[usize]) {
        let head = self.loops[l].head;
        let mut containlist = Vec::new();
        for &b in body {
            if Some(b) != head {
                if let Some(sub) = self.find_loop(b, looporder) {
                    containlist.push(sub);
                    self.loops[sub].depth += 1;
                }
            }
        }
        let depth = self.loops[l].depth;
        for lb in containlist {
            let replace = self.loops[lb].immed_container.is_none_or(|c| self.loops[c].depth < depth);
            if replace {
                self.loops[lb].immed_container = Some(l);
            }
        }
    }

    /// `CollapseStructure::orderLoopBodies`.
    fn order_loop_bodies(&mut self) -> Result<()> {
        let mut looporder = self.label_loops();
        if !self.loops.is_empty() {
            self.merge_identical_heads(&mut looporder);
            self.order = (0..self.loops.len()).filter(|&l| self.loops[l].head.is_some()).collect();
            for l in self.order.clone() {
                let mut body = Vec::new();
                self.loops[l].find_base(self.g, &mut body)?;
                self.label_containments(l, &body, &looporder);
                clear_marks(self.g, &body);
            }
            // std::list::sort (stable), deepest first
            let loops = &self.loops;
            self.order.sort_by_key(|&l| std::cmp::Reverse(loops[l].depth));
            for l in self.order.clone() {
                let mut body = Vec::new();
                let mut lb = self.loops[l].clone();
                lb.find_base(self.g, &mut body)?;
                lb.find_exit(self.g, &body, &self.loops)?;
                lb.order_tails(self.g);
                extend_reach(self.g, &mut body, lb.exitblock, true);
                lb.label_exit_edges(self.g, &body)?;
                clear_marks(self.g, &body);
                self.loops[l] = lb;
            }
        }
        self.likelylistfull = false;
        self.loopbodyiter = 0;
        Ok(())
    }

    /// `CollapseStructure::updateLoopBody`: `true` while likely gotos are left.
    fn update_loop_body(&mut self) -> Result<bool> {
        if self.finaltrace {
            return Ok(false);
        }
        let mut loopbottom = None;
        let mut looptop = None;
        while self.loopbodyiter < self.order.len() {
            let l = self.order[self.loopbodyiter];
            loopbottom = self.loops[l].update(self.g)?;
            if let Some(bottom) = loopbottom {
                looptop = self.loops[l].head;
                if Some(bottom) == looptop {
                    self.likelygoto = vec![FloatingEdge { top: bottom, bottom }];
                    self.likelyiter = 0;
                    self.likelylistfull = true;
                    return Ok(true);
                }
                if !self.likelylistfull || self.likelyiter < self.likelygoto.len() {
                    break;
                }
            }
            self.loopbodyiter += 1;
            self.likelylistfull = false;
            loopbottom = None;
        }
        if self.likelylistfull && self.likelyiter < self.likelygoto.len() {
            return Ok(true);
        }
        self.likelygoto.clear();
        let mut tracer = TraceDag::new(self.g);
        if let (Some(bottom), Some(top)) = (loopbottom, looptop) {
            tracer.rootlist.push(top);
            tracer.finishblock = Some(bottom);
            let l = self.order[self.loopbodyiter];
            self.loops[l].exit_marks(tracer.g, true);
        } else {
            for i in 0..tracer.g.size() {
                let bl = tracer.g.get(i);
                if tracer.g.size_in(bl) == 0 {
                    tracer.rootlist.push(bl);
                }
            }
        }
        tracer.initialize();
        tracer.push_branches()?;
        self.likelygoto = tracer.likelygoto;
        self.likelylistfull = true;
        if loopbottom.is_some() {
            let l = self.order[self.loopbodyiter];
            self.loops[l].emit_likely_edges(self.g, &mut self.likelygoto)?;
            self.loops[l].exit_marks(self.g, false);
        } else if self.likelygoto.is_empty() {
            self.finaltrace = true;
            return Ok(false);
        }
        self.likelyiter = 0;
        Ok(true)
    }

    /// `CollapseStructure::selectGoto`: the block whose out edge became a goto.
    fn select_goto(&mut self) -> Result<Option<SId>> {
        while self.update_loop_body()? {
            while self.likelyiter < self.likelygoto.len() {
                let cur = self.likelygoto[self.likelyiter].current(self.g);
                self.likelyiter += 1;
                if let Some((startbl, outedge)) = cur {
                    self.g.set_goto_branch(startbl, outedge)?;
                    return Ok(Some(startbl));
                }
            }
        }
        if !self.clip_extra_roots()? {
            return err("Could not finish collapsing block structure");
        }
        Ok(None)
    }

    /// `CollapseStructure::clipExtraRoots` with `onlyReachableFromRoot` and `markExitsAsGotos`.
    fn clip_extra_roots(&mut self) -> Result<bool> {
        for i in 1..self.g.size() {
            let bl = self.g.get(i);
            if self.g.size_in(bl) != 0 {
                continue;
            }
            self.g.set_mark(bl);
            let mut body = vec![bl];
            extend_reach(self.g, &mut body, None, false);
            let mut count = 0;
            for &b in &body {
                for j in 0..self.g.size_out(b) {
                    if !self.g.is_mark(self.g.out(b, j)) {
                        self.g.set_goto_branch(b, j)?;
                        count += 1;
                    }
                }
            }
            clear_marks(self.g, &body);
            if count != 0 {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// `negateCondition(true)` counting a data-flow change.
    fn negate(&mut self, b: SId) -> Result<()> {
        if self.g.negate_condition(self.fd, b, true)? {
            self.dataflow_changecount += 1;
        }
        Ok(())
    }

    /// `CollapseStructure::ruleBlockCat`.
    fn rule_block_cat(&mut self, bl: SId) -> Result<bool> {
        let g = &*self.g;
        if g.size_out(bl) != 1 || g.is_switch_out(bl) {
            return Ok(false);
        }
        if g.size_in(bl) == 1 && g.size_out(g.in_(bl, 0)) == 1 {
            return Ok(false);
        }
        let mut outblock = g.out(bl, 0);
        if outblock == bl || g.size_in(outblock) != 1 || !g.is_decision_out(bl, 0) || g.is_switch_out(outblock) {
            return Ok(false);
        }
        let mut nodes = vec![bl, outblock];
        while g.size_out(outblock) == 1 {
            let outbl2 = g.out(outblock, 0);
            if outbl2 == bl || g.size_in(outbl2) != 1 || !g.is_decision_out(outblock, 0) || g.is_switch_out(outbl2) {
                break;
            }
            outblock = outbl2;
            nodes.push(outblock);
        }
        self.g.new_list(&nodes)?;
        Ok(true)
    }

    /// `CollapseStructure::ruleBlockOr`.
    fn rule_block_or(&mut self, bl: SId) -> Result<bool> {
        let g = &*self.g;
        if g.size_out(bl) != 2 || g.is_goto_out(bl, 0) || g.is_goto_out(bl, 1) || g.is_switch_out(bl) {
            return Ok(false);
        }
        for i in 0..2 {
            let orblock = g.out(bl, i);
            if orblock == bl
                || g.size_in(orblock) != 1
                || g.size_out(orblock) != 2
                || g.is_interior_goto_target(orblock)
                || g.is_switch_out(orblock)
                || g.is_back_edge_out(bl, i)
                || g.is_complex(self.fd, orblock)
            {
                continue;
            }
            let clauseblock = g.out(bl, 1 - i);
            if clauseblock == bl || clauseblock == orblock {
                continue;
            }
            let Some(j) = (0..2).find(|&j| g.out(orblock, j) == clauseblock) else { continue };
            if g.out(orblock, 1 - j) == bl {
                continue;
            }
            if i == 1 {
                self.negate(bl)?;
            }
            if j == 0 {
                self.negate(orblock)?;
            }
            self.g.new_condition(bl, orblock)?;
            return Ok(true);
        }
        Ok(false)
    }

    /// The common checks of `ruleBlockProperIf`, `ruleBlockIfNoExit` and `ruleBlockWhileDo`:
    /// a binary non-switch block, no self loop, no goto out.
    fn plain_binary(&self, bl: SId) -> bool {
        let g = &*self.g;
        g.size_out(bl) == 2
            && !g.is_switch_out(bl)
            && g.out(bl, 0) != bl
            && g.out(bl, 1) != bl
            && !g.is_goto_out(bl, 0)
            && !g.is_goto_out(bl, 1)
    }

    /// `CollapseStructure::ruleBlockProperIf`.
    fn rule_block_proper_if(&mut self, bl: SId) -> Result<bool> {
        if !self.plain_binary(bl) {
            return Ok(false);
        }
        for i in 0..2 {
            let g = &*self.g;
            let clause = g.out(bl, i);
            if g.size_in(clause) != 1
                || g.size_out(clause) != 1
                || g.is_switch_out(clause)
                || !g.is_decision_out(bl, i)
                || g.is_goto_out(clause, 0)
                || g.out(clause, 0) != g.out(bl, 1 - i)
            {
                continue;
            }
            if i == 0 {
                self.negate(bl)?;
            }
            self.g.new_simple(Kind::If, &[bl, clause], Some(1));
            return Ok(true);
        }
        Ok(false)
    }

    /// `CollapseStructure::ruleBlockIfElse`.
    fn rule_block_if_else(&mut self, bl: SId) -> Result<bool> {
        let g = &*self.g;
        if g.size_out(bl) != 2 || g.is_switch_out(bl) || !g.is_decision_out(bl, 0) || !g.is_decision_out(bl, 1) {
            return Ok(false);
        }
        let (tc, fc) = (g.out(bl, 1), g.out(bl, 0));
        if g.size_in(tc) != 1 || g.size_in(fc) != 1 || g.size_out(tc) != 1 || g.size_out(fc) != 1 {
            return Ok(false);
        }
        let outblock = g.out(tc, 0);
        if outblock == bl || outblock != g.out(fc, 0) {
            return Ok(false);
        }
        if g.is_switch_out(tc) || g.is_switch_out(fc) || g.is_goto_out(tc, 0) || g.is_goto_out(fc, 0) {
            return Ok(false);
        }
        self.g.new_simple(Kind::IfElse, &[bl, tc, fc], Some(1));
        Ok(true)
    }

    /// `CollapseStructure::ruleBlockGoto`.
    fn rule_block_goto(&mut self, bl: SId) -> Result<bool> {
        let sizeout = self.g.size_out(bl);
        for i in 0..sizeout {
            if !self.g.is_goto_out(bl, i) {
                continue;
            }
            if self.g.is_switch_out(bl) {
                self.g.new_multi_goto(bl, i)?;
                return Ok(true);
            }
            if sizeout == 2 {
                if !self.g.is_goto_out(bl, 1) {
                    self.negate(bl)?;
                }
                self.g.new_if_goto(bl)?;
                return Ok(true);
            }
            if sizeout == 1 {
                self.g.new_goto(bl)?;
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// `CollapseStructure::ruleBlockIfNoExit`.
    fn rule_block_if_no_exit(&mut self, bl: SId) -> Result<bool> {
        if !self.plain_binary(bl) {
            return Ok(false);
        }
        let g = &*self.g;
        let noexit = |i: usize| {
            let c = g.out(bl, i);
            g.size_in(c) == 1 && g.size_out(c) == 0 && !g.is_switch_out(c) && g.is_decision_out(bl, i)
        };
        let Some(i) = (0..2).find(|&i| noexit(i)) else { return Ok(false) };
        let clause = g.out(bl, i);
        if i == 0 {
            let other = g.out(bl, 1);
            let both = noexit(1);
            self.negate(bl)?;
            if both {
                self.g.new_simple(Kind::IfNoExit, &[bl, clause, other], None);
                return Ok(true);
            }
        }
        self.g.new_simple(Kind::If, &[bl, clause], Some(1));
        Ok(true)
    }

    /// `CollapseStructure::ruleBlockWhileDo`.
    fn rule_block_while_do(&mut self, bl: SId) -> Result<bool> {
        if !self.plain_binary(bl) || self.g.is_interior_goto_target(bl) {
            return Ok(false);
        }
        for i in 0..2 {
            let g = &*self.g;
            let clause = g.out(bl, i);
            if g.size_in(clause) != 1 || g.size_out(clause) != 1 || g.is_switch_out(clause) || g.out(clause, 0) != bl {
                continue;
            }
            let overflow = g.is_complex(self.fd, bl);
            if (i == 0) != overflow {
                self.negate(bl)?;
            }
            let nb = self.g.new_simple(Kind::WhileDo, &[bl, clause], Some(1));
            if overflow {
                self.g.bm(nb).flags |= F_WHILEDO_OVERFLOW;
            }
            return Ok(true);
        }
        Ok(false)
    }

    /// `CollapseStructure::ruleBlockDoWhile`.
    fn rule_block_do_while(&mut self, bl: SId) -> Result<bool> {
        let g = &*self.g;
        if g.size_out(bl) != 2 || g.is_switch_out(bl) || g.is_goto_out(bl, 0) || g.is_goto_out(bl, 1) {
            return Ok(false);
        }
        let Some(i) = (0..2).find(|&i| g.out(bl, i) == bl) else { return Ok(false) };
        if i == 0 {
            self.negate(bl)?;
        }
        self.g.new_simple(Kind::DoWhile, &[bl], Some(1));
        Ok(true)
    }

    /// `CollapseStructure::ruleBlockInfLoop` (a switch may loop on itself here).
    fn rule_block_inf_loop(&mut self, bl: SId) -> bool {
        let g = &*self.g;
        if g.size_out(bl) != 1 || g.is_goto_out(bl, 0) || g.out(bl, 0) != bl {
            return false;
        }
        self.g.new_simple(Kind::InfLoop, &[bl], None);
        true
    }

    /// `CollapseStructure::checkSwitchSkips`: `false` when edges skipping to the exit became
    /// gotos.
    fn check_switch_skips(&mut self, sw: SId, exit: Option<SId>) -> Result<bool> {
        let Some(exit) = exit else { return Ok(true) };
        let g = &*self.g;
        let n = g.size_out(sw);
        let anyskip = (0..n).any(|e| g.out(sw, e) == exit && !g.is_default_branch(sw, e));
        let mut defaultnottoexit = (0..n).any(|e| g.out(sw, e) != exit && g.is_default_branch(sw, e));
        if !anyskip {
            return Ok(true);
        }
        if !defaultnottoexit {
            defaultnottoexit = matches!(g.b(sw).kind, Kind::MultiGoto { default_goto: true, .. });
        }
        if !defaultnottoexit {
            return Ok(true);
        }
        for e in 0..n {
            if self.g.out(sw, e) == exit && !self.g.is_default_branch(sw, e) {
                self.g.set_goto_branch(sw, e)?;
            }
        }
        Ok(false)
    }

    /// The exit block search of `ruleBlockSwitch`: `Err(())` when the switch cannot collapse.
    fn switch_exit(&self, bl: SId) -> std::result::Result<Option<SId>, ()> {
        let g = &*self.g;
        let n = g.size_out(bl);
        let obvious = (0..n).map(|i| g.out(bl, i)).find(|&c| c == bl || g.size_out(c) > 1 || g.size_in(c) > 1);
        let Some(exit) = obvious else {
            let mut exit = None;
            for i in 0..n {
                let c = g.out(bl, i);
                if g.is_goto_in(c, 0) || g.is_switch_out(c) {
                    return Err(());
                }
                if g.size_out(c) == 1 {
                    if g.is_goto_out(c, 0) || exit.is_some_and(|e| e != g.out(c, 0)) {
                        return Err(());
                    }
                    exit = Some(g.out(c, 0));
                }
            }
            return Ok(exit);
        };
        if (0..g.size_in(exit)).any(|i| g.is_goto_in(exit, i)) || (0..g.size_out(exit)).any(|i| g.is_goto_out(exit, i))
        {
            return Err(());
        }
        for i in 0..n {
            let c = g.out(bl, i);
            if c == exit {
                continue;
            }
            if g.size_in(c) > 1 || g.is_goto_in(c, 0) || g.size_out(c) > 1 {
                return Err(());
            }
            if g.size_out(c) == 1 && (g.is_goto_out(c, 0) || g.out(c, 0) != exit) {
                return Err(());
            }
            if g.is_switch_out(c) {
                return Err(());
            }
        }
        Ok(Some(exit))
    }

    /// `CollapseStructure::ruleBlockSwitch`.
    fn rule_block_switch(&mut self, bl: SId) -> Result<bool> {
        if !self.g.is_switch_out(bl) {
            return Ok(false);
        }
        let Ok(exit) = self.switch_exit(bl) else { return Ok(false) };
        if !self.check_switch_skips(bl, exit)? {
            return Ok(true);
        }
        let mut cases = vec![bl];
        cases.extend((0..self.g.size_out(bl)).map(|i| self.g.out(bl, i)).filter(|&c| Some(c) != exit));
        self.g.new_switch(&cases, exit.is_some());
        Ok(true)
    }

    /// `CollapseStructure::ruleCaseFallthru`.
    fn rule_case_fallthru(&mut self, bl: SId) -> Result<bool> {
        let g = &*self.g;
        if !g.is_switch_out(bl) {
            return Ok(false);
        }
        let mut nonfallthru = 0;
        let mut fallthru = Vec::new();
        for i in 0..g.size_out(bl) {
            let c = g.out(bl, i);
            if c == bl {
                return Ok(false);
            }
            if g.size_in(c) > 2 || g.size_out(c) > 1 {
                nonfallthru += 1;
            } else if g.size_out(c) == 1 {
                let target = g.out(c, 0);
                if g.size_in(target) == 2 && g.size_out(target) <= 1 {
                    let inslot = g.b(c).outs[0].reverse;
                    if g.in_(target, 1 - inslot) == bl {
                        fallthru.push(c);
                    }
                }
            }
            if nonfallthru > 1 {
                return Ok(false);
            }
        }
        if fallthru.is_empty() {
            return Ok(false);
        }
        for c in fallthru {
            self.g.set_goto_branch(c, 0)?;
        }
        Ok(true)
    }

    /// The rules of `collapseInternal`'s inner loop, in order.
    fn apply_rules(&mut self, bl: SId) -> Result<bool> {
        Ok(self.rule_block_goto(bl)?
            || self.rule_block_cat(bl)?
            || self.rule_block_proper_if(bl)?
            || self.rule_block_if_else(bl)?
            || self.rule_block_while_do(bl)?
            || self.rule_block_do_while(bl)?
            || self.rule_block_inf_loop(bl)
            || self.rule_block_switch(bl)?)
    }

    /// `CollapseStructure::collapseInternal`: the number of isolated blocks.
    fn collapse_internal(&mut self, mut targetbl: Option<SId>) -> Result<usize> {
        loop {
            let mut isolated;
            loop {
                let mut change = false;
                let mut index = 0;
                isolated = 0;
                while index < self.g.size() {
                    let bl = match targetbl.take() {
                        Some(t) => {
                            change = true;
                            index = self.g.size();
                            t
                        }
                        None => {
                            index += 1;
                            self.g.get(index - 1)
                        }
                    };
                    if self.g.size_in(bl) == 0 && self.g.size_out(bl) == 0 {
                        isolated += 1;
                        continue;
                    }
                    if self.apply_rules(bl)? {
                        change = true;
                    }
                }
                if !change {
                    break;
                }
            }
            let mut fullchange = false;
            for index in 0..self.g.size() {
                let bl = self.g.get(index);
                if self.rule_block_if_no_exit(bl)? || self.rule_case_fallthru(bl)? {
                    fullchange = true;
                    break;
                }
            }
            if !fullchange {
                return Ok(isolated);
            }
        }
    }

    /// `CollapseStructure::collapseConditions`.
    fn collapse_conditions(&mut self) -> Result<()> {
        loop {
            let mut change = false;
            let mut i = 0;
            while i < self.g.size() {
                if self.rule_block_or(self.g.get(i))? {
                    change = true;
                }
                i += 1;
            }
            if !change {
                return Ok(());
            }
        }
    }
}
