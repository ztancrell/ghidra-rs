//! SSA construction: port of `Heritage` (heritage.cc). Each pass collects the free varnodes of
//! the address spaces whose turn has come, splits the storage into disjoint ranges, guards
//! calls and returns with INDIRECTs and extra inputs, places MULTIEQUALs (phi nodes) where
//! writes meet, and renames every free read to the write that reaches it.
//!
//! Phi placement is the augmented dominator tree algorithm of Bilardi and Pingali that the C++
//! uses (`buildADT`, `visitIncr`, `calcMultiequals`); renaming is the classic dominator-tree walk
//! with a stack of live writes per address (`renameRecurse`).
//!
//! Ported: the passes over the register and unique spaces (pass 0, the one `break start
//! paramdouble` first shows). Spaces heritaged in later passes (ram, the stack) need the
//! main loop's other actions to be reached and fail loudly here, as do the paths only they use
//! (load guards, stack placeholders, revisited markers, overlapping parameter guards).

use super::block::BlockId;
use super::fspec::{Containment, EffectKind};
use super::op::{OpFlags, OpId};
use super::opcode::Opcode;
use super::varnode::{overlap, Space, VarnodeId, VnFlags};
use super::{err, Arch, Funcdata, Result};
use std::collections::BTreeMap;

/// The marks phi placement keeps per block (`Heritage::boundary_node`, `mark_node`,
/// `merged_node`).
#[derive(Debug, Clone, Copy, Default)]
struct NodeMarks {
    /// a boundary node of the augmented dominator tree
    boundary: bool,
    /// queued (or visited) for the current range
    mark: bool,
    /// in the merge list for the current range
    merged: bool,
}

/// The offset mask of a SLEIGH space (`AddrSpace::wrapOffset`), from its address size.
fn space_mask(arch: &Arch, space: Space) -> u64 {
    let size = match space {
        Space::Sleigh(i) => arch.sleigh.spaces.get(i as usize).map_or(8, |s| s.size),
        _ => 8,
    };
    if size >= 8 {
        u64::MAX
    } else {
        (1u64 << (8 * size)) - 1
    }
}

/// Port of `MemRange`: one range of storage to link this pass.
#[derive(Debug, Clone, Copy)]
struct MemRange {
    space: Space,
    off: u64,
    size: u32,
    /// the space's offset mask
    mask: u64,
    /// `new_addresses`: holds storage not heritaged before
    new_addresses: bool,
    /// `old_addresses`: holds storage heritaged in an earlier pass
    old_addresses: bool,
}

/// Port of `LocationMap`: the disjoint ranges heritaged so far and the pass each was first
/// heritaged in, sorted by address.
#[derive(Debug, Clone, Default)]
struct LocationMap {
    /// (space index, offset, size, pass), sorted by space index and offset
    map: Vec<(u32, u64, u32, i32)>,
}

/// How a range added to the [`LocationMap`] meets what was heritaged before (`intersect`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Intersect {
    /// only ranges of this pass
    New,
    /// a partial overlap with an older range
    Partial,
    /// contained in an older range
    Old,
}

impl LocationMap {
    /// Port of `LocationMap::add`: make the range part of one element, merging the elements it
    /// overlaps; returns that element's start, size and how the range met older ones.
    ///
    /// Kept from the C++: when no element starts before the range and the first one starts
    /// after its start, the first element is skipped even if the range overlaps it.
    fn add(&mut self, space: Space, mask: u64, mut off: u64, mut size: u32, mut pass: i32) -> (u64, u32, Intersect) {
        let s = space.index();
        let lower = self.map.partition_point(|e| (e.0, e.1) < (s, off));
        let mut at = lower.saturating_sub(1);
        if self.map.get(at).is_some_and(|e| overlap(space, off, Space::Sleigh(e.0), e.1, e.2, mask).is_none()) {
            at += 1;
        }
        let mut intersect = Intersect::New;
        if let Some(&(es, eoff, esize, epass)) = self.map.get(at) {
            if let Some(w) = overlap(space, off, Space::Sleigh(es), eoff, esize, mask) {
                if w + size <= esize {
                    let i = if epass < pass { Intersect::Old } else { Intersect::New };
                    return (eoff, esize, i);
                }
                off = eoff;
                size += w;
                if epass < pass {
                    intersect = Intersect::Partial;
                    pass = epass;
                }
                self.map.remove(at);
            }
        }
        while let Some(&(es, eoff, esize, epass)) = self.map.get(at) {
            let Some(w) = overlap(Space::Sleigh(es), eoff, space, off, size, mask) else { break };
            size = size.max(w + esize);
            if epass < pass {
                intersect = Intersect::Partial;
                pass = epass;
            }
            self.map.remove(at);
        }
        match self.map.binary_search_by(|e| (e.0, e.1).cmp(&(s, off))) {
            Ok(i) => self.map[i] = (s, off, size, pass),
            Err(i) => self.map.insert(i, (s, off, size, pass)),
        }
        (off, size, intersect)
    }

    /// Port of `LocationMap::find`, returning the element's position.
    fn find(&self, space: Space, mask: u64, off: u64) -> Option<usize> {
        let s = space.index();
        let at = self.map.partition_point(|e| (e.0, e.1) <= (s, off)).checked_sub(1)?;
        let e = self.map[at];
        overlap(space, off, Space::Sleigh(e.0), e.1, e.2, mask).map(|_| at)
    }
}

/// Port of `PriorityQueue`: blocks by dominator-tree depth, deepest first, last in first out.
#[derive(Debug, Clone, Default)]
struct PriorityQueue {
    queue: Vec<Vec<usize>>,
    curdepth: i32,
}

impl PriorityQueue {
    /// Empty the stacks (keeping their storage) and make one per depth up to `maxdepth`.
    fn reset(&mut self, maxdepth: i32) {
        self.queue.iter_mut().for_each(Vec::clear);
        self.queue.resize_with(usize::try_from(maxdepth).unwrap_or(0) + 1, Vec::new);
        self.curdepth = -1;
    }
    fn insert(&mut self, bl: usize, depth: i32) {
        self.queue[depth as usize].push(bl);
        self.curdepth = self.curdepth.max(depth);
    }
    fn extract(&mut self) -> Option<usize> {
        let res = self.queue.get_mut(usize::try_from(self.curdepth).ok()?)?.pop();
        while self.curdepth >= 0 && self.queue[self.curdepth as usize].is_empty() {
            self.curdepth -= 1;
        }
        res
    }
}

/// The free varnodes, writes and inputs of one range (`Heritage::collect`).
#[derive(Debug, Default)]
struct Collected {
    read: Vec<VarnodeId>,
    write: Vec<VarnodeId>,
    input: Vec<VarnodeId>,
    remove: Vec<VarnodeId>,
    /// the largest write
    max: u32,
}

/// Port of `Heritage`: the SSA builder's state, kept across passes.
#[derive(Debug, Clone)]
pub(crate) struct Heritage {
    pass: i32,
    globaldisjoint: LocationMap,
    disjoint: Vec<MemRange>,
    /// by block index: the children in the dominator tree (`domchild`)
    domchild: Vec<Vec<usize>>,
    /// by block index: the blocks of the augmented dominator tree (`augment`)
    augment: Vec<Vec<usize>>,
    /// by block index
    marks: Vec<NodeMarks>,
    depth: Vec<i32>,
    /// the dominator tree's depth; -1 until it is built (`maxdepth`)
    maxdepth: i32,
    merge: Vec<usize>,
    pq: PriorityQueue,
    /// by SLEIGH space index: dead code was removed there (`HeritageInfo::deadremoved`)
    deadremoved: Vec<bool>,
    /// the call placeholders were cleared, at the stack's first pass (`hasCallPlaceholders`)
    placeholders_cleared: bool,
}

impl Default for Heritage {
    fn default() -> Heritage {
        Heritage {
            pass: 0,
            globaldisjoint: LocationMap::default(),
            disjoint: Vec::new(),
            domchild: Vec::new(),
            augment: Vec::new(),
            marks: Vec::new(),
            depth: Vec::new(),
            maxdepth: -1,
            merge: Vec::new(),
            pq: PriorityQueue::default(),
            deadremoved: Vec::new(),
            placeholders_cleared: false,
        }
    }
}

/// The heritage delay of the `stack` space: its base register's space (the register space,
/// delay 0) plus one (`Architecture::addSpacebase`).
const STACK_DELAY: i32 = 1;

impl Heritage {
    /// Port of `Heritage::deadRemovalAllowed`: dead code may go from a space once it has been
    /// heritaged (its dead-code delay is its heritage delay; x86 sets no other).
    pub(crate) fn dead_removal_allowed(&self, arch: &Arch, space: u32) -> bool {
        arch.sleigh.spaces[space as usize].delay.is_some_and(|d| self.pass > d)
    }

    /// Port of `Heritage::seenDeadCode`.
    pub(crate) fn seen_dead_code(&mut self, space: u32) {
        let i = space as usize;
        if self.deadremoved.len() <= i {
            self.deadremoved.resize(i + 1, false);
        }
        self.deadremoved[i] = true;
    }

    fn dead_removed(&self, space: u32) -> bool {
        self.deadremoved.get(space as usize).copied().unwrap_or(false)
    }

    /// Port of `Heritage::forceRestructure`: the dominator tree is rebuilt at the next pass.
    pub(crate) fn force_restructure(&mut self) {
        self.maxdepth = -1;
    }

    /// `Funcdata::isHeritaged` (`Heritage::heritagePass(addr) >= 0`): whether a pass has
    /// heritaged the address.
    pub(crate) fn heritaged(&self, space: Space, off: u64) -> bool {
        self.globaldisjoint.find(space, u64::MAX, off).is_some()
    }

    /// `Funcdata::getHeritagePass`.
    pub(crate) fn pass(&self) -> i32 {
        self.pass
    }
}

/// Port of `Funcdata::opHeritage` (`Heritage::heritage`): one heritage pass.
pub(crate) fn heritage(fd: &mut Funcdata, arch: &Arch) -> Result<()> {
    fd.build_loc();
    if fd.heritage.maxdepth == -1 {
        build_adt(fd);
    }
    // processJoins: no varnode lives in the join space yet; PreferSplitManager: x86 declares
    // no <prefersplit> ranges
    let pass = fd.heritage.pass;
    for (i, sp) in arch.sleigh.spaces.iter().enumerate() {
        // the space's heritage delay from the .sla (`AddrSpace::getDelay`), none if not heritaged
        let Some(delay) = sp.delay else { continue };
        if pass < delay {
            continue;
        }
        // no stack pointer lives in these spaces (discoverIndexedStackPointers)
        let space = Space::Sleigh(i as u32);
        add_space_ranges(fd, arch, space, space_mask(arch, space))?;
    }
    // the stack space comes last in space order: its first pass clears the call placeholders
    // (clearStackPlaceholders). discoverIndexedStackPointers only marks LOADs and STOREs and
    // records guards for stack ranges, and no stack varnode exists without the `stackvars`
    // rules (stage R5), so the stack contributes no range.
    if pass >= STACK_DELAY && !fd.heritage.placeholders_cleared {
        for i in 0..fd.qlst.len() {
            let c = fd.qlst[i];
            abort_spacebase_relative(fd, c)?;
        }
        fd.heritage.placeholders_cleared = true;
    }
    if !fd.heritage.disjoint.is_empty() {
        place_multiequals(fd, arch)?;
        rename(fd, arch)?;
    }
    // analyzeNewLoadGuards and handleNewLoadCopies act on the load guards of stack ranges
    fd.heritage.pass += 1;
    Ok(())
}

/// Port of `FuncCallSpecs::abortSpacebaseRelative`: the call's stack-pointer placeholder input
/// goes, and its LOAD with it.
pub(crate) fn abort_spacebase_relative(fd: &mut Funcdata, c: super::funcdata::CallId) -> Result<()> {
    let Some(slot) = fd.call(c).stack_placeholder_slot else { return Ok(()) };
    let op = fd.call(c).op;
    let vn = fd.input(op, slot)?;
    fd.op_remove_input(op, slot);
    fd.call_mut(c).stack_placeholder_slot = None;
    if let Some(a) = &mut fd.call_mut(c).active_input {
        a.free_placeholder_slot();
    }
    let v = fd.vn(vn);
    let internal = v.space == Space::Sleigh(arch_uniq(fd, vn));
    if v.descend.is_empty() && internal {
        if let Some(def) = v.def {
            fd.op_destroy(def);
        }
    }
    Ok(())
}

/// The unique space, as the placeholder's own space (it is always made there).
fn arch_uniq(fd: &Funcdata, vn: VarnodeId) -> u32 {
    match fd.vn(vn).space {
        Space::Sleigh(s) => s,
        _ => u32::MAX,
    }
}

/// The space loop of `Heritage::heritage`: every varnode of the space that is read, written or
/// an input joins a disjoint range to link.
fn add_space_ranges(fd: &mut Funcdata, arch: &Arch, space: Space, mask: u64) -> Result<()> {
    let pass = fd.heritage.pass;
    let Space::Sleigh(si) = space else { return Ok(()) };
    let deadremoved = fd.heritage.dead_removed(si);
    let mut needwarning = false;
    for vn in fd.loc_range(space, 0, None) {
        let v = fd.vn(vn);
        if v.def.is_none() && v.descend.is_empty() && !v.has(VnFlags::UNAFFECTED) && !v.is_input() {
            continue;
        }
        if v.has(VnFlags::WRITEMASK) {
            continue;
        }
        let (known, nodescend) = (v.is_heritage_known(), v.descend.is_empty());
        let (off, size, intersect) = fd.heritage.globaldisjoint.add(space, mask, v.offset, v.size, pass);
        // (new, old) addresses
        let (new_addresses, old_addresses) = match intersect {
            Intersect::New => (true, false),
            Intersect::Old if known || nodescend => continue,
            Intersect::Old => {
                if !needwarning && deadremoved {
                    needwarning = true;
                    bump_deadcode_delay(arch, si)?;
                }
                (false, true)
            }
            Intersect::Partial => {
                if !needwarning && deadremoved && !known {
                    needwarning = true;
                    bump_deadcode_delay(arch, si)?;
                }
                (true, true)
            }
        };
        let range = MemRange { space, off, size, mask, new_addresses, old_addresses };
        task_add(&mut fd.heritage.disjoint, range);
    }
    if needwarning {
        fd.warning_header("Heritage AFTER dead removal");
    }
    Ok(())
}

/// Port of `Heritage::bumpDeadcodeDelay`: a processor space (not the unique space) gets a
/// longer dead-code delay and the decompile restarts, which is not ported.
fn bump_deadcode_delay(arch: &Arch, space: u32) -> Result<()> {
    if space == arch.sleigh.uniq_space() {
        return Ok(());
    }
    err(format!(
        "heritage after dead-code removal in the {} space: the restart with a longer dead-code delay is not implemented in ghidra-rs yet",
        arch.sleigh.spaces[space as usize].name
    ))
}

/// Port of `TaskList::add`: ranges come sorted; one overlapping the last is merged into it.
fn task_add(list: &mut Vec<MemRange>, r: MemRange) {
    if let Some(last) = list.last_mut() {
        if let Some(over) = overlap(r.space, r.off, last.space, last.off, last.size, r.mask) {
            last.size = last.size.max(r.size + over);
            last.new_addresses |= r.new_addresses;
            last.old_addresses |= r.old_addresses;
            return;
        }
    }
    list.push(r);
}

/// Port of `Heritage::buildADT`: the dominator tree, each block's depth in it, and the
/// augmented edges that let `visitIncr` find dominance frontiers.
fn build_adt(fd: &mut Funcdata) {
    let bb = &fd.blocks;
    let size = bb.list.len();
    let domchild = bb.dom_children();
    let (depth, maxdepth) = bb.dom_depth();
    let idom = |i: usize| bb.block(bb.list[i]).idom.map(|d| bb.block(d).index as usize);
    let index = |b: BlockId| bb.block(b).index as usize;
    let mut a = vec![0i32; size];
    let mut b = vec![0i32; size];
    let mut t = vec![0i32; size];
    let mut z = vec![0i32; size];
    let mut up: Vec<(usize, usize)> = Vec::new();
    let mut marks = vec![NodeMarks::default(); size];
    for x in 0..size {
        for &v in &domchild[x] {
            for e in &bb.block(bb.list[v]).ins {
                let u = index(e.point);
                if Some(u) != idom(v) {
                    up.push((u, v));
                    b[u] += 1;
                    t[x] += 1;
                }
            }
        }
    }
    for i in (0..size).rev() {
        let k: i32 = domchild[i].iter().map(|&c| a[c]).sum();
        let l: i32 = domchild[i].iter().map(|&c| z[c]).sum();
        a[i] = b[i] - t[i] + k;
        z[i] = 1 + l;
        if domchild[i].is_empty() || z[i] > a[i] + 1 {
            marks[i].boundary = true;
            z[i] = 1;
        }
    }
    if let Some(z0) = z.first_mut() {
        *z0 = -1;
    }
    for i in 1..size {
        let j = idom(i).unwrap_or(0);
        z[i] = if marks[j].boundary { j as i32 } else { z[j] };
    }
    let mut augment = vec![Vec::new(); size];
    for &(u, v) in &up {
        let j = idom(v).map_or(-1, |d| d as i32);
        let mut k = u as i32;
        // while idom(v) properly dominates u
        while j < k {
            augment[k as usize].push(v);
            k = z[k as usize];
        }
    }
    let h = &mut fd.heritage;
    h.domchild = domchild;
    h.depth = depth;
    h.maxdepth = maxdepth;
    h.augment = augment;
    h.marks = marks;
}

/// Port of `Heritage::visitIncr`: walk the dominator subtree of `vnode`, adding to the merge
/// list the blocks of the augmented edges whose immediate dominator is above `qnode`.
fn visit_incr(fd: &mut Funcdata, qnode: usize, vnode: usize) {
    // the C++ recurses into each unmarked child in turn; a stack visits them in the same order,
    // testing the mark when the child's turn comes
    let mut todo = vec![(vnode, true)];
    while let Some((i, root)) = todo.pop() {
        let bb = &fd.blocks;
        let h = &mut fd.heritage;
        if !root && h.marks[i].mark {
            continue;
        }
        for &v in &h.augment[i] {
            let vidom = bb.block(bb.list[v]).idom.map_or(-1, |d| bb.block(d).index);
            if vidom >= qnode as i32 {
                break;
            }
            if !h.marks[v].merged {
                h.merge.push(v);
                h.marks[v].merged = true;
            }
            if !h.marks[v].mark {
                h.marks[v].mark = true;
                h.pq.insert(v, h.depth[v]);
            }
        }
        if !h.marks[i].boundary {
            todo.extend(h.domchild[i].iter().rev().map(|&c| (c, false)));
        }
    }
}

/// Port of `Heritage::calcMultiequals`: the blocks needing a MULTIEQUAL for a range written by
/// `write` (left in the merge list).
fn calc_multiequals(fd: &mut Funcdata, write: &[VarnodeId]) {
    let maxdepth = fd.heritage.maxdepth;
    fd.heritage.pq.reset(maxdepth);
    fd.heritage.merge.clear();
    for &w in write {
        let Some(bl) = fd.vn(w).def.and_then(|d| fd.op(d).parent) else { continue };
        let j = fd.blocks.block(bl).index as usize;
        let h = &mut fd.heritage;
        if h.marks[j].mark {
            continue;
        }
        h.pq.insert(j, h.depth[j]);
        h.marks[j].mark = true;
    }
    let h = &mut fd.heritage;
    if h.marks.first().is_some_and(|m| !m.mark) {
        h.pq.insert(0, h.depth[0]);
        h.marks[0].mark = true;
    }
    while let Some(bl) = fd.heritage.pq.extract() {
        visit_incr(fd, bl, bl);
        // a node is not revisited from deeper ones: visitIncr checks the mark, not the queue
    }
    for m in &mut fd.heritage.marks {
        m.mark = false;
        m.merged = false;
    }
}

/// Port of `Heritage::collect`: the varnodes starting in the range, sorted into free reads,
/// writes, inputs and the markers of an earlier pass to remove. A write by a marker or a
/// return COPY covering the range means an earlier pass linked it all.
fn collect(fd: &Funcdata, range: &mut MemRange) -> Collected {
    let end = (range.off + u64::from(range.size)) & range.mask;
    let end = (end >= range.off).then_some(end);
    let mut c = Collected::default();
    for vn in fd.loc_range(range.space, range.off, end) {
        let v = fd.vn(vn);
        if v.has(VnFlags::WRITEMASK) {
            continue;
        }
        if let Some(def) = v.def {
            let op = fd.op(def);
            if op.is_marker() || op.flags.has(OpFlags::RETURN_COPY) {
                if v.size < range.size {
                    c.remove.push(vn);
                    continue;
                }
                range.new_addresses = false;
            }
            c.max = c.max.max(v.size);
            c.write.push(vn);
        } else if !v.is_heritage_known() && !v.descend.is_empty() {
            c.read.push(vn);
        } else if v.is_input() {
            c.input.push(vn);
        }
    }
    c
}

/// Port of `Heritage::placeMultiequals`: for each range, refine it, guard it and put a
/// MULTIEQUAL at the start of every block that needs one.
fn place_multiequals(fd: &mut Funcdata, arch: &Arch) -> Result<()> {
    let mut i = 0;
    while i < fd.heritage.disjoint.len() {
        let mut range = fd.heritage.disjoint[i];
        let mut c = collect(fd, &mut range);
        fd.heritage.disjoint[i] = range;
        if range.size > 4 && c.max < range.size && refinement(fd, arch, i, &c)? {
            range = fd.heritage.disjoint[i];
            c = collect(fd, &mut range);
            fd.heritage.disjoint[i] = range;
        }
        i += 1;
        if c.read.is_empty() {
            let internal = range.space == Space::Sleigh(arch.sleigh.uniq_space());
            if (c.write.is_empty() && c.input.is_empty()) || internal || range.old_addresses {
                continue;
            }
        }
        if !c.remove.is_empty() {
            return err(
                "heritage: revisiting earlier markers is not implemented in ghidra-rs yet (later heritage passes)",
            );
        }
        guard_input(fd, arch, &range, &c.input)?;
        guard(fd, arch, &range, &mut c)?;
        calc_multiequals(fd, &c.write);
        for bl in std::mem::take(&mut fd.heritage.merge) {
            let b = fd.blocks.list[bl];
            let start = fd.blocks.block(b).start;
            let multiop = fd.new_op(Opcode::Multiequal, start);
            let out = fd.new_varnode_out(range.size, range.space, range.off, multiop);
            fd.vn_set(out, VnFlags::ACTIVE_HERITAGE);
            for j in 0..fd.blocks.block(b).ins.len() {
                let vnin = fd.new_varnode(range.size, range.space, range.off);
                fd.op_set_input(multiop, vnin, j)?;
            }
            fd.op_insert_begin(multiop, b);
        }
    }
    Ok(())
}

/// Port of `Heritage::guardInput`: inputs that only partly cover the range are completed and
/// joined into one value for the whole range.
fn guard_input(fd: &mut Funcdata, arch: &Arch, range: &MemRange, input: &[VarnodeId]) -> Result<()> {
    if input.is_empty() || (input.len() == 1 && fd.vn(input[0]).size == range.size) {
        return Ok(());
    }
    let mut cur = range.off;
    let end = cur + u64::from(range.size);
    let mut it = input.iter().peekable();
    let mut newinput = Vec::new();
    while cur < end {
        let vn = match it.peek() {
            Some(&&vn) if fd.vn(vn).offset > cur => {
                let v = fd.new_varnode((fd.vn(vn).offset - cur) as u32, range.space, cur);
                fd.set_input_varnode(v, arch)?
            }
            Some(&&vn) => {
                it.next();
                vn
            }
            None => {
                let v = fd.new_varnode((end - cur) as u32, range.space, cur);
                fd.set_input_varnode(v, arch)?
            }
        };
        newinput.push(vn);
        cur += u64::from(fd.vn(vn).size);
    }
    if newinput.len() > 1 {
        let newout = fd.new_varnode(range.size, range.space, range.off);
        let joined = concat_pieces(fd, arch, &newinput, None, newout)?;
        fd.vn_set(joined, VnFlags::ACTIVE_HERITAGE);
    }
    Ok(())
}

/// Port of `Heritage::guard`: reads and writes smaller than the range are widened, everything
/// is marked for renaming, and a range new to this pass gets its call and return guards.
fn guard(fd: &mut Funcdata, arch: &Arch, range: &MemRange, c: &mut Collected) -> Result<()> {
    for r in &mut c.read {
        let vn = *r;
        let Some(&op) = fd.vn(vn).descend.first() else { continue };
        if fd.vn(vn).descend.len() > 1 {
            return err("Free varnode with multiple reads");
        }
        if fd.vn(vn).size < range.size {
            *r = normalize_read_size(fd, vn, op, range)?;
        }
        fd.vn_set(*r, VnFlags::ACTIVE_HERITAGE);
    }
    for w in &mut c.write {
        if fd.vn(*w).size < range.size {
            *w = normalize_write_size(fd, arch, *w, range)?;
        }
        fd.vn_set(*w, VnFlags::ACTIVE_HERITAGE);
    }
    if range.new_addresses {
        // queryProperties: the global scope owns ram (persist, addrtied); no other space has
        // properties. LOAD guards exist only for stack ranges (guardLoads).
        let global = fd.ram.is_some_and(|r| range.space == Space::Sleigh(r));
        guard_calls(fd, arch, range, &mut c.write, global)?;
        guard_returns(fd, arch, range, global)?;
        guard_stores(fd, range, &mut c.write)?;
    }
    Ok(())
}

/// Port of `Heritage::normalizeReadSize`: a read smaller than the range becomes a SUBPIECE of
/// a new free read of the whole range, which is returned.
fn normalize_read_size(fd: &mut Funcdata, vn: VarnodeId, op: OpId, range: &MemRange) -> Result<VarnodeId> {
    let newop = fd.new_op(Opcode::Subpiece, fd.op(op).seq.addr);
    let vn1 = fd.new_varnode(range.size, range.space, range.off);
    let over = fd.vn(vn).overlap(range.space, range.off, range.size, range.mask).unwrap_or(0);
    let vn2 = fd.new_constant(4, u64::from(over));
    fd.op_set_input(newop, vn1, 0)?;
    fd.op_set_input(newop, vn2, 1)?;
    fd.op_set_output(newop, vn)?;
    fd.vn_set(vn, VnFlags::WRITEMASK);
    fd.op_insert_before(newop, op)?;
    Ok(vn1)
}

/// Port of `Heritage::callOpIndirectEffect`: whether the call `op` may change the range.
fn call_op_indirect_effect(fd: &Funcdata, arch: &Arch, space: Space, off: u64, size: u32, op: OpId) -> bool {
    if !matches!(fd.op(op).opc, Opcode::Call | Opcode::Callind) {
        return false;
    }
    match fd.qlst.iter().find(|&&c| fd.call(c).op == op) {
        Some(&c) => fd.call(c).proto.has_effect(arch, space, off, size) != Some(EffectKind::Unaffected),
        None => true,
    }
}

/// One piece `normalizeWriteSize` fills in around a small write: an INDIRECT creation when
/// the write is a call that may change it, else a SUBPIECE of a new free read of the range.
fn write_piece(
    fd: &mut Funcdata,
    arch: &Arch,
    op: OpId,
    range: &MemRange,
    off: u64,
    size: u32,
    cut: u64,
) -> Result<VarnodeId> {
    if fd.op(op).is_call() && call_op_indirect_effect(fd, arch, range.space, off, size, op) {
        let ind = fd.new_indirect_creation(op, range.space, off, size, false)?;
        return fd.op(ind).out.ok_or_else(|| super::LowlevelError("INDIRECT without output".into()));
    }
    let newop = fd.new_op(Opcode::Subpiece, fd.op(op).seq.addr);
    let piece = fd.new_varnode_out(size, range.space, off, newop);
    let big = fd.new_varnode(range.size, range.space, range.off);
    fd.vn_set(big, VnFlags::ACTIVE_HERITAGE);
    fd.op_set_input(newop, big, 0)?;
    let c = fd.new_constant(4, cut);
    fd.op_set_input(newop, c, 1)?;
    fd.op_insert_before(newop, op)?;
    Ok(piece)
}

/// Port of `Heritage::normalizeWriteSize` (little endian): a write smaller than the range is
/// joined with the rest of the range by PIECE ops into a write of the whole range.
fn normalize_write_size(fd: &mut Funcdata, arch: &Arch, vn: VarnodeId, range: &MemRange) -> Result<VarnodeId> {
    let op = fd.vn(vn).def.ok_or_else(|| super::LowlevelError("normalizeWriteSize: unwritten varnode".into()))?;
    let over = fd.vn(vn).overlap(range.space, range.off, range.size, range.mask).unwrap_or(0);
    let vsize = fd.vn(vn).size;
    let mostsigsize = range
        .size
        .checked_sub(over + vsize)
        .ok_or_else(|| super::LowlevelError("normalizeWriteSize: write larger than its range".into()))?;
    let mostvn = if mostsigsize != 0 {
        let off = range.off + u64::from(over + vsize);
        Some(write_piece(fd, arch, op, range, off, mostsigsize, u64::from(over + vsize))?)
    } else {
        None
    };
    let midvn = if over != 0 {
        let leastvn = write_piece(fd, arch, op, range, range.off, over, 0)?;
        let newop = fd.new_op(Opcode::Piece, fd.op(op).seq.addr);
        let mid = fd.new_varnode_out(over + vsize, range.space, range.off, newop);
        fd.op_set_input(newop, vn, 0)?;
        fd.op_set_input(newop, leastvn, 1)?;
        fd.op_insert_after(newop, op)?;
        mid
    } else {
        vn
    };
    let bigout = match mostvn {
        Some(most) => {
            let newop = fd.new_op(Opcode::Piece, fd.op(op).seq.addr);
            let big = fd.new_varnode_out(range.size, range.space, range.off, newop);
            fd.op_set_input(newop, most, 0)?;
            fd.op_set_input(newop, midvn, 1)?;
            let middef = fd.vn(midvn).def.unwrap_or(op);
            fd.op_insert_after(newop, middef)?;
            big
        }
        None => midvn,
    };
    fd.vn_set(vn, VnFlags::WRITEMASK);
    Ok(bigout)
}

/// Port of `Heritage::guardCalls` for unlocked call prototypes: each call that may change the
/// range gets an INDIRECT (`r = r [] call`), or an INDIRECT creation when it kills it; a
/// range that may be a return value or a parameter becomes a trial, and a possible
/// parameter an extra input of the call.
fn guard_calls(
    fd: &mut Funcdata,
    arch: &Arch,
    range: &MemRange,
    write: &mut Vec<VarnodeId>,
    holdind: bool,
) -> Result<()> {
    let (space, off, size) = (range.space, range.off, range.size);
    // a call leaves the unique space alone (`lookupEffect`) and no parameter list holds it, so
    // no call guards it
    if space == Space::Sleigh(arch.sleigh.uniq_space()) {
        return Ok(());
    }
    for i in 0..fd.qlst.len() {
        let c = fd.qlst[i];
        let op = fd.call(c).op;
        if let Some(out) = fd.op(op).out {
            let v = fd.vn(out);
            if v.space == space && v.offset == off && v.size == size {
                continue;
            }
        }
        let call = fd.call(c);
        let mut effect = call.proto.has_effect(arch, space, off, size);
        let mut possibleoutput = false;
        if call.active_output.is_some() {
            match call.proto.characterize_as_output(arch, space, off, size) {
                Containment::None => {}
                Containment::ContainedBy => {
                    return err("heritage: guarding an output overlap is not implemented in ghidra-rs yet");
                }
                _ => {
                    if effect != Some(EffectKind::KilledByCall) && call.proto.is_auto_killed_by_call(arch) {
                        effect = Some(EffectKind::KilledByCall);
                    }
                    if let Some(active) = &mut fd.call_mut(c).active_output {
                        if !active.has_trial(space, off, size) {
                            active.register_trial(space, off, size);
                            possibleoutput = true;
                        }
                    }
                }
            }
        }
        let call = fd.call(c);
        if call.active_input.is_some() {
            match call.proto.characterize_as_input(arch, space, off, size) {
                Containment::ContainsJustified => {
                    let fresh = match &mut fd.call_mut(c).active_input {
                        Some(active) if !active.has_trial(space, off, size) => {
                            active.register_trial(space, off, size);
                            true
                        }
                        _ => false,
                    };
                    if fresh {
                        let vn = fd.new_varnode(size, space, off);
                        fd.vn_set(vn, VnFlags::ACTIVE_HERITAGE);
                        let slot = fd.op(op).ins.len();
                        fd.op_insert_input(op, vn, slot)?;
                    }
                }
                Containment::ContainedBy => {
                    return err("heritage: guarding an overlapping parameter is not implemented in ghidra-rs yet");
                }
                _ => {}
            }
        }
        match effect {
            None | Some(EffectKind::ReturnAddress) => {
                let ind = fd.new_indirect_op(op, space, off, size, OpFlags::default())?;
                let (in0, out) = (fd.input(ind, 0)?, fd.op(ind).out);
                fd.vn_set(in0, VnFlags::ACTIVE_HERITAGE);
                if let Some(out) = out {
                    fd.vn_set(out, VnFlags::ACTIVE_HERITAGE);
                    if holdind {
                        fd.vn_set(out, VnFlags::ADDRFORCE);
                    }
                    if effect.is_some() {
                        fd.vn_set(out, VnFlags::RETURN_ADDRESS);
                    }
                    write.push(out);
                }
            }
            Some(EffectKind::KilledByCall) => {
                let ind = fd.new_indirect_creation(op, space, off, size, possibleoutput)?;
                if let Some(out) = fd.op(ind).out {
                    fd.vn_set(out, VnFlags::ACTIVE_HERITAGE);
                    write.push(out);
                }
            }
            Some(EffectKind::Unaffected) => {}
        }
    }
    Ok(())
}

/// Port of `Heritage::guardReturns` for an unlocked prototype: a range that may be the return
/// value becomes a trial and an extra input of every RETURN that is not a special halt.
/// (Global, `persist` storage, which gets a COPY at each RETURN, is ram: a later pass.)
fn guard_returns(fd: &mut Funcdata, arch: &Arch, range: &MemRange, persist: bool) -> Result<()> {
    let (space, off, size) = (range.space, range.off, range.size);
    if fd.active_output.is_some() {
        guard_return_trials(fd, arch, range)?;
    }
    if !persist {
        return Ok(());
    }
    for op in fd.ops_created_with(Opcode::Return) {
        if fd.op(op).is_dead() {
            continue;
        }
        let copyop = fd.new_op(Opcode::Copy, fd.op(op).seq.addr);
        let vn = fd.new_varnode_out(size, space, off, copyop);
        fd.vn_set(vn, VnFlags::ADDRFORCE);
        fd.vn_set(vn, VnFlags::ACTIVE_HERITAGE);
        fd.op_mut(copyop).flags.set(OpFlags::RETURN_COPY);
        let invn = fd.new_varnode(size, space, off);
        fd.vn_set(invn, VnFlags::ACTIVE_HERITAGE);
        fd.op_set_input(copyop, invn, 0)?;
        fd.op_insert_before(copyop, op)?;
    }
    Ok(())
}

/// Port of `Heritage::guardStores`: every STORE into the range's space may change it, so an
/// INDIRECT before each (`indirect_store`). (A STORE through the stack pointer guards stack
/// ranges, which do not exist yet.)
fn guard_stores(fd: &mut Funcdata, range: &MemRange, write: &mut Vec<VarnodeId>) -> Result<()> {
    let Space::Sleigh(si) = range.space else { return Ok(()) };
    for op in fd.ops_created_with(Opcode::Store) {
        if fd.op(op).is_dead() {
            continue;
        }
        let Some(&spc) = fd.op(op).ins.first() else { continue };
        if fd.vn(spc).offset != u64::from(si) {
            continue;
        }
        let ind = fd.new_indirect_op(op, range.space, range.off, range.size, OpFlags::INDIRECT_STORE)?;
        let (in0, out) = (fd.input(ind, 0)?, fd.op(ind).out);
        fd.vn_set(in0, VnFlags::ACTIVE_HERITAGE);
        if let Some(out) = out {
            fd.vn_set(out, VnFlags::ACTIVE_HERITAGE);
            write.push(out);
        }
    }
    Ok(())
}

/// The trial part of `Heritage::guardReturns`.
fn guard_return_trials(fd: &mut Funcdata, arch: &Arch, range: &MemRange) -> Result<()> {
    let (space, off, size) = (range.space, range.off, range.size);
    match fd.proto.characterize_as_output(arch, space, off, size) {
        Containment::None => {}
        Containment::ContainedBy => {
            return err("heritage: guarding an overlapping return value is not implemented in ghidra-rs yet")
        }
        _ => {
            if let Some(active) = &mut fd.active_output {
                active.register_trial(space, off, size);
            }
            for op in fd.ops_created_with(Opcode::Return) {
                if fd.op(op).is_dead() || fd.op(op).halt.is_some() {
                    continue;
                }
                let invn = fd.new_varnode(size, space, off);
                fd.vn_set(invn, VnFlags::ACTIVE_HERITAGE);
                let slot = fd.op(op).ins.len();
                fd.op_insert_input(op, invn, slot)?;
            }
        }
    }
    Ok(())
}

/// Where the ops of `concatPieces`/`splitPieces` go: the block, the position of the first one
/// and the address they take.
fn insert_point(fd: &Funcdata, insertop: Option<OpId>, after: bool) -> Result<(BlockId, usize, u64)> {
    match insertop {
        None => {
            let bl = *fd.blocks.list.first().ok_or_else(|| super::LowlevelError("no blocks".into()))?;
            Ok((bl, 0, fd.entry))
        }
        Some(op) => {
            let bl = fd.op(op).parent.ok_or_else(|| super::LowlevelError("insert point outside any block".into()))?;
            let pos = fd.blocks.block(bl).ops.iter().position(|&o| o == op).unwrap_or(0);
            Ok((bl, pos + usize::from(after), fd.op(op).seq.addr))
        }
    }
}

/// Port of `Heritage::concatPieces` (little endian): PIECE ops joining `vnlist` (least
/// significant first: each next piece is the more significant input) into `finalvn`, before `insertop` or at the start of the function.
fn concat_pieces(
    fd: &mut Funcdata,
    arch: &Arch,
    vnlist: &[VarnodeId],
    insertop: Option<OpId>,
    finalvn: VarnodeId,
) -> Result<VarnodeId> {
    let (bl, mut pos, addr) = insert_point(fd, insertop, false)?;
    let mut preexist = vnlist[0];
    for (i, &vn) in vnlist.iter().enumerate().skip(1) {
        let newop = fd.new_op(Opcode::Piece, addr);
        let newvn = if i == vnlist.len() - 1 {
            fd.op_set_output(newop, finalvn)?;
            finalvn
        } else {
            let size = fd.vn(preexist).size + fd.vn(vn).size;
            fd.new_unique_out(size, arch.sleigh.uniq_space(), newop)
        };
        fd.op_set_input(newop, vn, 0)?;
        fd.op_set_input(newop, preexist, 1)?;
        fd.op_insert(newop, bl, pos);
        pos += 1;
        preexist = newvn;
    }
    Ok(preexist)
}

/// Port of `Heritage::splitPieces` (little endian): a SUBPIECE of `startvn` defining each
/// piece of `vnlist`, after `insertop` or at the start of the function.
fn split_pieces(
    fd: &mut Funcdata,
    vnlist: &[VarnodeId],
    insertop: Option<OpId>,
    base: u64,
    startvn: VarnodeId,
) -> Result<()> {
    let (bl, mut pos, addr) = insert_point(fd, insertop, true)?;
    for &vn in vnlist {
        let newop = fd.new_op(Opcode::Subpiece, addr);
        let diff = fd.vn(vn).offset.wrapping_sub(base);
        fd.op_set_input(newop, startvn, 0)?;
        let c = fd.new_constant(4, diff);
        fd.op_set_input(newop, c, 1)?;
        fd.op_set_output(newop, vn)?;
        fd.op_insert(newop, bl, pos);
        pos += 1;
    }
    Ok(())
}

/// Port of `Heritage::splitByRefinement`: new free varnodes covering `vn` along the cut
/// points of `refine` (empty when it is not cut).
fn split_by_refinement(fd: &mut Funcdata, vn: VarnodeId, range: &MemRange, refine: &[u32]) -> Result<Vec<VarnodeId>> {
    let (space, mut cur, mut sz) = (fd.vn(vn).space, fd.vn(vn).offset, fd.vn(vn).size);
    // the piece size at `cur`; every piece starts on a cut point, so it is never 0
    let cut_at = |cur: u64| match refine.get((cur.wrapping_sub(range.off) & range.mask) as usize) {
        Some(&c) if c > 0 => Ok(c),
        _ => err("splitByRefinement: varnode outside its refined range"),
    };
    let mut cutsz = cut_at(cur)?;
    if sz <= cutsz {
        return Ok(Vec::new());
    }
    let mut split = vec![fd.new_varnode(cutsz, space, cur)];
    sz -= cutsz;
    while sz > 0 {
        cur += u64::from(cutsz);
        cutsz = cut_at(cur)?.min(sz);
        split.push(fd.new_varnode(cutsz, space, cur));
        sz -= cutsz;
    }
    Ok(split)
}

/// Port of `Heritage::remove13Refinement`: a 1-3 or 3-1 split of 4 bytes becomes one piece.
fn remove13_refinement(refine: &mut [u32]) {
    let Some(&first) = refine.first() else { return };
    let mut pos = first as usize;
    let mut lastsize = first;
    while pos < refine.len() {
        let cursize = refine[pos];
        if cursize == 0 {
            break;
        }
        if (lastsize == 1 && cursize == 3) || (lastsize == 3 && cursize == 1) {
            refine[pos - lastsize as usize] = 4;
            lastsize = 4;
        } else {
            lastsize = cursize;
        }
        pos += cursize as usize;
    }
}

/// Port of `Heritage::refinement`: a range read and written only in smaller pieces is cut
/// into them; returns whether it was (the pieces replace it in the task list at `at`).
fn refinement(fd: &mut Funcdata, arch: &Arch, at: usize, c: &Collected) -> Result<bool> {
    let range = fd.heritage.disjoint[at];
    let size = range.size as usize;
    if size > 1024 {
        return Ok(false);
    }
    let mut refine = vec![0u32; size + 1];
    for &vn in c.read.iter().chain(&c.write).chain(&c.input) {
        let diff = (fd.vn(vn).offset.wrapping_sub(range.off) & range.mask) as usize;
        let end = diff + fd.vn(vn).size as usize;
        if end > size {
            return err("refinement: varnode outside its range");
        }
        refine[diff] = 1;
        refine[end] = 1;
    }
    refine.pop();
    let mut lastpos = 0;
    for curpos in 1..size {
        if refine[curpos] != 0 {
            refine[lastpos] = (curpos - lastpos) as u32;
            lastpos = curpos;
        }
    }
    if lastpos == 0 {
        return Ok(false);
    }
    refine[lastpos] = (size - lastpos) as u32;
    remove13_refinement(&mut refine);
    for &vn in &c.read {
        refine_read(fd, arch, vn, &range, &refine)?;
    }
    for &vn in &c.write {
        refine_write(fd, arch, vn, &range, &refine)?;
    }
    for &vn in &c.input {
        let pieces = split_by_refinement(fd, vn, &range, &refine)?;
        if !pieces.is_empty() {
            let base = fd.vn(vn).offset;
            split_pieces(fd, &pieces, None, base, vn)?;
            fd.vn_set(vn, VnFlags::WRITEMASK);
        }
    }
    // the cover, here and in the global map, takes the pieces
    let h = &mut fd.heritage;
    h.disjoint.remove(at);
    let cur_pass = match h.globaldisjoint.find(range.space, range.mask, range.off) {
        Some(g) => h.globaldisjoint.map.remove(g).3,
        None => h.pass,
    };
    let mut cut = 0;
    let mut k = at;
    while cut < size {
        let sz = refine[cut];
        let off = range.off + cut as u64;
        if sz == 0 {
            return err("refinement: empty piece");
        }
        h.disjoint.insert(k, MemRange { off, size: sz, ..range });
        h.globaldisjoint.add(range.space, range.mask, off, sz, cur_pass);
        cut += sz as usize;
        k += 1;
    }
    Ok(true)
}

/// Port of `Heritage::refineRead`: a free read cut by the refinement is rebuilt from its
/// pieces by PIECE ops into a new unique varnode its reader takes.
fn refine_read(fd: &mut Funcdata, arch: &Arch, vn: VarnodeId, range: &MemRange, refine: &[u32]) -> Result<()> {
    let pieces = split_by_refinement(fd, vn, range, refine)?;
    if pieces.is_empty() {
        return Ok(());
    }
    let Some(&op) = fd.vn(vn).descend.first() else { return err("Refining non-free varnode") };
    let replacevn = fd.new_unique(fd.vn(vn).size, arch.sleigh.uniq_space());
    let slot = fd.op(op).ins.iter().position(|&v| v == vn).unwrap_or(0);
    concat_pieces(fd, arch, &pieces, Some(op), replacevn)?;
    fd.op_set_input(op, replacevn, slot)?;
    if !fd.vn(vn).descend.is_empty() {
        return err("Refining non-free varnode");
    }
    fd.delete_varnode(vn);
    Ok(())
}

/// Port of `Heritage::refineWrite`: a write cut by the refinement goes to a new unique varnode,
/// SUBPIECEs of which define the pieces.
fn refine_write(fd: &mut Funcdata, arch: &Arch, vn: VarnodeId, range: &MemRange, refine: &[u32]) -> Result<()> {
    let pieces = split_by_refinement(fd, vn, range, refine)?;
    if pieces.is_empty() {
        return Ok(());
    }
    let replacevn = fd.new_unique(fd.vn(vn).size, arch.sleigh.uniq_space());
    let def = fd.vn(vn).def.ok_or_else(|| super::LowlevelError("refineWrite: unwritten varnode".into()))?;
    fd.op_set_output(def, replacevn)?;
    let base = fd.vn(vn).offset;
    split_pieces(fd, &pieces, Some(def), base, replacevn)?;
    fd.total_replace(vn, replacevn)?;
    fd.delete_varnode(vn);
    Ok(())
}

/// The renaming stacks (`VariableStack`, a map by address): the live write of each address,
/// last on top. Keyed by space index and offset; only lookups by key, so the order is free.
type VarStack = BTreeMap<(u32, u64), Vec<VarnodeId>>;

/// The stack key of a varnode's address.
fn stack_key(fd: &Funcdata, vn: VarnodeId) -> (u32, u64) {
    let v = fd.vn(vn);
    (v.space.index(), v.offset)
}

/// A new input of the function at `vn`'s storage.
fn new_input_like(fd: &mut Funcdata, arch: &Arch, vn: VarnodeId) -> Result<VarnodeId> {
    let (space, off, size) = (fd.vn(vn).space, fd.vn(vn).offset, fd.vn(vn).size);
    let v = fd.new_varnode(size, space, off);
    fd.set_input_varnode(v, arch)
}

/// The value a read at `vn`'s address sees: the top of its stack, or a new input of the
/// function when nothing was written on the way.
fn top_or_input(fd: &mut Funcdata, arch: &Arch, stacks: &mut VarStack, vn: VarnodeId) -> Result<VarnodeId> {
    let stack = stacks.entry(stack_key(fd, vn)).or_default();
    if let Some(&top) = stack.last() {
        return Ok(top);
    }
    let v = new_input_like(fd, arch, vn)?;
    stack.push(v);
    Ok(v)
}

/// Port of `Heritage::rename`: the dominator-tree walk of `renameRecurse` from the entry.
fn rename(fd: &mut Funcdata, arch: &Arch) -> Result<()> {
    enum Step {
        Enter(usize),
        /// pop the writes the block pushed
        Leave(Vec<VarnodeId>),
    }
    let mut stacks = VarStack::new();
    let mut todo = vec![Step::Enter(0)];
    while let Some(step) = todo.pop() {
        match step {
            Step::Enter(i) => {
                let writes = rename_block(fd, arch, &mut stacks, i)?;
                todo.push(Step::Leave(writes));
                // children in order, as the C++ recursion visits them
                todo.extend(fd.heritage.domchild[i].iter().rev().map(|&c| Step::Enter(c)));
            }
            Step::Leave(writes) => {
                for w in writes {
                    if let Some(s) = stacks.get_mut(&stack_key(fd, w)) {
                        s.pop();
                    }
                }
            }
        }
    }
    fd.heritage.disjoint.clear();
    Ok(())
}

/// The body of `Heritage::renameRecurse` for block `i`: free reads take the live write, new
/// writes go on the stacks, and the MULTIEQUALs of the successors take their input for the edge
/// from this block. Returns the writes pushed. Renaming adds no ops and no edges, so the block's
/// op and edge lists are walked by position.
fn rename_block(fd: &mut Funcdata, arch: &Arch, stacks: &mut VarStack, i: usize) -> Result<Vec<VarnodeId>> {
    let bl = fd.blocks.list[i];
    let mut writelist = Vec::new();
    for k in 0..fd.blocks.block(bl).ops.len() {
        let op = fd.blocks.block(bl).ops[k];
        if fd.op(op).opc != Opcode::Multiequal {
            for slot in 0..fd.op(op).ins.len() {
                let vnin = fd.op(op).ins[slot];
                let v = fd.vn(vnin);
                if v.is_heritage_known() || !v.has(VnFlags::ACTIVE_HERITAGE) {
                    continue;
                }
                fd.vn_clear(vnin, VnFlags::ACTIVE_HERITAGE);
                let mut vnnew = top_or_input(fd, arch, stacks, vnin)?;
                // an INDIRECT and its op happen at the same time: the op reads what was before
                let ind = fd.vn(vnnew).def.filter(|&d| fd.op(d).opc == Opcode::Indirect);
                if let Some(d) = ind {
                    let iop = fd.input(d, 1)?;
                    if fd.vn(iop).space == Space::Iop && fd.vn(iop).offset == u64::from(op.0) {
                        let key = stack_key(fd, vnin);
                        let depth = stacks.get(&key).map_or(0, Vec::len);
                        if depth == 1 {
                            vnnew = new_input_like(fd, arch, vnin)?;
                            stacks.entry(key).or_default().insert(0, vnnew);
                        } else if let Some(s) = stacks.get(&key) {
                            vnnew = s[s.len() - 2];
                        }
                    }
                }
                fd.op_set_input(op, vnnew, slot)?;
                if fd.vn(vnin).descend.is_empty() {
                    fd.delete_varnode(vnin);
                }
            }
        }
        let Some(out) = fd.op(op).out else { continue };
        if !fd.vn(out).has(VnFlags::ACTIVE_HERITAGE) {
            continue;
        }
        fd.vn_clear(out, VnFlags::ACTIVE_HERITAGE);
        stacks.entry(stack_key(fd, out)).or_default().push(out);
        writelist.push(out);
    }
    for e in 0..fd.blocks.block(bl).outs.len() {
        let edge = fd.blocks.block(bl).outs[e];
        let (sub, slot) = (edge.point, edge.reverse);
        for k in 0..fd.blocks.block(sub).ops.len() {
            let multiop = fd.blocks.block(sub).ops[k];
            if fd.op(multiop).opc != Opcode::Multiequal {
                break;
            }
            let vnin = fd.input(multiop, slot)?;
            if fd.vn(vnin).is_heritage_known() {
                continue;
            }
            let vnnew = top_or_input(fd, arch, stacks, vnin)?;
            fd.op_set_input(multiop, vnnew, slot)?;
            if fd.vn(vnin).descend.is_empty() {
                fd.delete_varnode(vnin);
            }
        }
    }
    Ok(writelist)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A function of empty blocks `0..n` with `edges`, block 0 the entry, and a write of EAX
    /// (register space 4, offset 0) in each block of `writers`; returns the blocks that get a
    /// MULTIEQUAL for EAX, by index in reverse post-order.
    fn phi_blocks(n: u64, edges: &[(usize, usize)], writers: &[usize]) -> Vec<i32> {
        let mut fd = Funcdata::new(0);
        let bl: Vec<_> = (0..n).map(|i| fd.blocks.new_block(i * 0x10)).collect();
        fd.blocks.set_start_block(bl[0]);
        for &(a, b) in edges {
            fd.blocks.add_edge(bl[a], bl[b]);
        }
        fd.blocks.structure_loops().unwrap();
        let writes: Vec<_> = writers
            .iter()
            .map(|&w| {
                let op = fd.new_op(Opcode::Copy, w as u64 * 0x10);
                fd.op_insert(op, bl[w], 0);
                fd.new_varnode_out(4, Space::Sleigh(4), 0, op)
            })
            .collect();
        build_adt(&mut fd);
        calc_multiequals(&mut fd, &writes);
        let mut idx: Vec<i32> = fd.heritage.merge.iter().map(|&i| i as i32).collect();
        idx.sort_unstable();
        idx.into_iter().map(|i| fd.blocks.block(fd.blocks.list[i as usize]).start as i32 / 0x10).collect()
    }

    /// A diamond 0 -> {1, 2} -> 3: a write in one arm meets the entry value at the join.
    #[test]
    fn phi_at_the_join_of_a_diamond() {
        assert_eq!(phi_blocks(4, &[(0, 1), (0, 2), (1, 3), (2, 3)], &[1]), vec![3]);
        // writes in the entry only: one value reaches everywhere
        assert_eq!(phi_blocks(4, &[(0, 1), (0, 2), (1, 3), (2, 3)], &[0]), Vec::<i32>::new());
    }

    /// A loop 0 -> 1 -> 2 -> 1, 2 -> 3: a write in the body, or in the head itself, needs a
    /// phi at the loop head, where it meets the value from before the loop.
    #[test]
    fn phi_at_a_loop_head() {
        let edges = [(0, 1), (1, 2), (2, 1), (2, 3)];
        assert_eq!(phi_blocks(4, &edges, &[2]), vec![1]);
        assert_eq!(phi_blocks(4, &edges, &[1]), vec![1]);
    }

    /// Nested loops 0 -> 1 -> 2 -> 3 -> 2, 3 -> 1, 1 -> 4: a write in the inner body reaches
    /// both loop heads.
    #[test]
    fn phi_at_nested_loop_heads() {
        let edges = [(0, 1), (1, 2), (2, 3), (3, 2), (3, 1), (1, 4)];
        assert_eq!(phi_blocks(5, &edges, &[3]), vec![1, 2]);
    }
}
