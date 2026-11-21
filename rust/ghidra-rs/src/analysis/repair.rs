//! Repair Flow Damage: FindNoReturnFunctionsAnalyzer.repairDamagedLocations with
//! ClearFlowAndRepairCmd (`clearData` true, `clearLabels` false, `repair` true), the block models
//! it walks (SimpleBlockModel, MultEntSubModel) and the ClearCmd it runs, on this model's
//! listing: `insns` (no data code units but the switch tables' bytes and `table_slots`), the
//! references the instructions imply (`refs_to`), and the functions of `bodies`.

use super::{Analysis, Flow, Image, RangeSet};
use crate::sleigh::{Parse, Sleigh};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};

/// ClearFlowAndRepairCmd.FALLTHROUGH_SEARCH_LIMIT
const FALLTHROUGH_SEARCH_LIMIT: u32 = 12;
const OP_LOAD: u8 = 2;
const OP_STORE: u8 = 3;
const OP_CALLOTHER: u8 = 9;
const OP_SEGMENTOP: u8 = 67;

/// The part of a reference's RefType the command asks about.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Ref {
    /// a flow: a call (isCall) or a jump (isJump: direct, conditional or computed)
    Flow { call: bool },
    /// a data reference; `rw`: READ or WRITE
    Data { rw: bool },
    /// EXTERNAL_REF, the reference an external entry point has (no source instruction)
    External,
}

/// What a repair met that is not modelled, counted for `Analysis::warnings`.
#[derive(Default)]
pub(super) struct RepairCounts {
    /// commands run (one per non-returning function with locations to clear)
    pub runs: usize,
    /// instructions cleared
    pub cleared: usize,
    /// functions removed (ClearCmd, repairFunctions)
    pub removed: usize,
    /// addresses re-disassembled (repairFlowsInto)
    pub redisassembled: usize,
    /// referenced non-instruction addresses all of whose references were cleared: Java clears
    /// the data there when it is a pointer or undefined (addDereferencedInstructionStarts);
    /// this model has no data code units there
    pub data: BTreeSet<u32>,
    /// functions whose body kept cleared bytes in Java (no repairFunctions sub reached them);
    /// here a body holds instructions only, so the bytes go
    pub stale: BTreeSet<u32>,
    /// functions whose repaired body overlapped another function (Java: OverlappingFunctionException)
    pub overlap: usize,
}

/// A vertex of findInstructionFlow's block graph: a SimpleBlockModel block (first and last
/// instruction) and its edges, by index.
struct Vertex {
    start: u32,
    last: u32,
    srcs: BTreeSet<usize>,
    dests: BTreeSet<usize>,
}

impl Analysis {
    /// Every reference by destination: from the instructions (flows: direct targets, computed
    /// targets and switch cases; data: memory operands, constant addresses, code constants),
    /// from `table_slots` (pointer data) and the external entry points (`None` source).
    fn refs_to(&self, img: &Image) -> HashMap<u32, Vec<(Option<u32>, Ref)>> {
        let mut to: HashMap<u32, Vec<(Option<u32>, Ref)>> = HashMap::new();
        for &a in self.insns.keys() {
            for (t, r) in self.refs_from(a) {
                to.entry(t).or_default().push((Some(a), r));
            }
        }
        for (&slot, &t) in &self.table_slots {
            to.entry(t).or_default().push((Some(slot), Ref::Data { rw: false }));
        }
        for e in img.exports.iter().map(|e| e.0).chain(img.entry) {
            to.entry(e).or_default().push((None, Ref::External));
        }
        to
    }

    /// The references from the instruction at `a` (Instruction.getReferencesFrom).
    fn refs_from(&self, a: u32) -> Vec<(u32, Ref)> {
        let Some(i) = self.insns.get(&a) else { return Vec::new() };
        let mut out = Vec::new();
        match i.flow {
            Flow::Jump | Flow::CondJump => out.extend(i.target.map(|t| (t, Ref::Flow { call: false }))),
            Flow::Call => out.extend(i.target.map(|t| (t, Ref::Flow { call: true }))),
            Flow::CallInd => out.extend(i.computed.map(|t| (t, Ref::Flow { call: true }))),
            Flow::JumpInd => out.extend(i.computed.map(|t| (t, Ref::Flow { call: false }))),
            Flow::Fall | Flow::Return => {}
        }
        out.extend(self.tables.get(&a).into_iter().flatten().map(|&t| (t, Ref::Flow { call: false })));
        out.extend(i.slot.map(|s| (s, Ref::Data { rw: true })));
        out.extend(i.refs.iter().chain(&i.code_imms).map(|&t| (t, Ref::Data { rw: false })));
        out
    }

    /// Instruction.getFallThrough: none past a jump, a return or a CALL_RETURN call.
    fn fall_through(&self, a: u32) -> Option<u32> {
        let i = self.insns.get(&a)?;
        let calls = matches!(i.flow, Flow::Call | Flow::CallInd);
        (i.falls_through() && !(calls && self.call_return(a, i))).then_some(a + i.len as u32)
    }

    /// Instruction.getFallFrom: the instruction right before `a` when it falls through to `a`.
    fn fall_from(&self, a: u32) -> Option<u32> {
        let (&p, _) = self.insns.range(..a).next_back()?;
        (self.fall_through(p) == Some(a)).then_some(p)
    }

    /// SymbolTable.hasSymbol: a function, a label (the external entries) or a reference.
    fn has_symbol(&self, a: u32, refs: &HashMap<u32, Vec<(Option<u32>, Ref)>>) -> bool {
        self.bodies.contains_key(&a) || refs.contains_key(&a)
    }

    /// SimpleBlockModel.isBlockStart of the instruction at `a`.
    fn block_start(&self, a: u32, refs: &HashMap<u32, Vec<(Option<u32>, Ref)>>) -> bool {
        match self.fall_from(a) {
            None => true,
            Some(p) => self.has_symbol(a, refs) || self.insns[&p].flow != Flow::Fall,
        }
    }

    /// SimpleBlockModel.getCodeBlockAt(instr): the last instruction of the block from `a`.
    fn block_last(&self, mut a: u32, refs: &HashMap<u32, Vec<(Option<u32>, Ref)>>) -> u32 {
        while let Some(i) = self.insns.get(&a).filter(|i| i.flow == Flow::Fall) {
            let next = a + i.len as u32;
            if !self.insns.contains_key(&next) || self.has_symbol(next, refs) {
                break;
            }
            a = next;
        }
        a
    }

    /// SimpleBlockModel.getFirstCodeBlockContaining of the instruction at `a`: (first, last).
    fn block_of(&self, mut a: u32, refs: &HashMap<u32, Vec<(Option<u32>, Ref)>>) -> (u32, u32) {
        while !self.block_start(a, refs) {
            match self.fall_from(a) {
                Some(p) => a = p,
                None => break,
            }
        }
        (a, self.block_last(a, refs))
    }

    /// The instructions of the block (first, last).
    fn block_insns(&self, (start, last): (u32, u32)) -> impl Iterator<Item = u32> + '_ {
        self.insns.range(start..=last).map(|(&a, _)| a)
    }

    /// SimpleDestReferenceIterator: the flow references from the block's instructions (call:
    /// Some(true), jump: Some(false)), then the fallthrough out of its last one (None).
    fn block_dests(&self, block: (u32, u32)) -> Vec<(u32, Option<bool>)> {
        let mut out: Vec<(u32, Option<bool>)> = self
            .block_insns(block)
            .flat_map(|a| self.refs_from(a))
            .filter_map(|(t, r)| match r {
                Ref::Flow { call } => Some((t, Some(call))),
                _ => None,
            })
            .collect();
        if let Some(ft) = self.fall_through(block.1).filter(|ft| self.insns.contains_key(ft)) {
            out.push((ft, None));
        }
        out
    }

    /// ClearFlowAndRepairCmd.adjustBlockForSplitProtectedBlock: a block holding a protected
    /// address past `at` ends before it.
    fn split_protected(&self, block: (u32, u32), at: u32, protected: &BTreeSet<u32>) -> (u32, u32) {
        let end = block.1 + self.insns[&block.1].len as u32 - 1;
        match protected.range(block.0..=end).next() {
            Some(&p) if p != at => {
                let last = self.insns.range(block.0..p).next_back().map_or(block.0, |(&a, _)| a);
                (block.0, last)
            }
            _ => block,
        }
    }

    /// FindNoReturnFunctionsAnalyzer.skipNOPS: past up to 16 fallthrough instructions whose
    /// p-code does nothing but write temporaries.
    fn skip_nops(&self, img: &Image, sl: &Sleigh, p: &mut Parse, mut a: u32) -> u32 {
        for _ in 0..16 {
            let Some(i) = self.insns.get(&a) else { return a };
            if i.flow != Flow::Fall {
                return a;
            }
            let Some(sec) = img.block_of(a) else { return a };
            // an instruction without p-code (none decodes here) does nothing
            let ops = match sl.decode(p, a as u64, &sec.data[(a - sec.addr) as usize..]) {
                Ok(_) => sl.pcode(p).unwrap_or_default(),
                Err(_) => Vec::new(),
            };
            let acts = |o: &crate::sleigh::PcodeOp| {
                matches!(o.opc, OP_LOAD | OP_STORE | OP_CALLOTHER | OP_SEGMENTOP)
                    || o.out.is_some_and(|v| v.space != sl.uniq_space())
            };
            if ops.iter().any(acts) {
                return a;
            }
            match self.fall_through(a) {
                Some(ft) => a = ft,
                None => return a,
            }
        }
        a
    }

    /// FindNoReturnFunctionsAnalyzer.findRepairLocations: the fallthroughs of the calls of
    /// `entry` that hold an instruction no flow refers to (nor to it past NOPs), not `entry`
    /// itself nor an external entry point.
    fn repair_locations(
        &self,
        img: &Image,
        sl: &Sleigh,
        p: &mut Parse,
        refs: &HashMap<u32, Vec<(Option<u32>, Ref)>>,
        entry: u32,
    ) -> BTreeSet<u32> {
        let flow_into = |a: u32| refs.get(&a).into_iter().flatten().any(|r| matches!(r.1, Ref::Flow { .. }));
        let external = |a: u32| img.exports.iter().any(|e| e.0 == a) || img.entry == Some(a);
        let mut out = BTreeSet::new();
        for &(from, r) in refs.get(&entry).into_iter().flatten() {
            let (Some(from), Ref::Flow { call: true }) = (from, r) else { continue };
            let Some(i) = self.insns.get(&from) else { continue };
            // getFallThrough, else getDefaultFallThroughOffset
            let fall = from + i.len as u32;
            if fall == entry {
                continue;
            }
            let check = self.skip_nops(img, sl, p, fall);
            if external(check) || external(fall) {
                continue;
            }
            if !flow_into(fall) && !flow_into(check) && self.insns.contains_key(&fall) {
                out.insert(fall);
            }
        }
        out
    }

    /// FindNoReturnFunctionsAnalyzer.added, the "Repair Flow Damage" step: for each address the
    /// analyzer found (`found`, also the protected set with the analysis manager's protected
    /// locations, none for a PE), ClearFlowAndRepairCmd on its repair locations. Returns the
    /// addresses of instructions cleared or handed to codeDefined, which the instruction
    /// analyzers see again.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn repair_flow_damage(
        &mut self,
        img: &Image,
        sl: &Sleigh,
        p: &mut Parse,
        owner: &mut [u8],
        found: &BTreeSet<u32>,
        allowed: Option<&HashSet<u32>>,
        changed: &mut BTreeSet<u32>,
        counts: &mut RepairCounts,
    ) -> BTreeSet<u32> {
        let mut again = BTreeSet::new();
        let mut refs = self.refs_to(img);
        for &entry in found {
            let starts = self.repair_locations(img, sl, p, &refs, entry);
            if !starts.is_empty() {
                counts.runs += 1;
                self.clear_flow_and_repair(
                    img, sl, p, owner, &refs, &starts, found, allowed, changed, counts, &mut again,
                );
                refs = self.refs_to(img);
            }
        }
        again
    }

    /// ClearFlowAndRepairCmd.applyTo with `clearData` and `repair` (and `repairFunctions`),
    /// without `clearLabels`.
    #[allow(clippy::too_many_arguments)]
    fn clear_flow_and_repair(
        &mut self,
        img: &Image,
        sl: &Sleigh,
        p: &mut Parse,
        owner: &mut [u8],
        refs: &HashMap<u32, Vec<(Option<u32>, Ref)>>,
        starts: &BTreeSet<u32>,
        protected: &BTreeSet<u32>,
        allowed: Option<&HashSet<u32>>,
        changed: &mut BTreeSet<u32>,
        counts: &mut RepairCounts,
        again: &mut BTreeSet<u32>,
    ) {
        // the starts that are no function entry and no fallthrough of another start (every
        // start holds an instruction: findRepairLocations)
        let mut todo: Vec<u32> = starts
            .iter()
            .copied()
            .filter(|&a| !self.bodies.contains_key(&a) && !self.fall_from(a).is_some_and(|f| starts.contains(&f)))
            .collect();
        let ignore = (todo.len() == 1).then(|| todo[0]);
        let mut clear: BTreeSet<u32> = BTreeSet::new();
        while let Some(a) = todo.pop() {
            if clear.contains(&a) || protected.contains(&a) || !self.insns.contains_key(&a) {
                // no instruction: undefined data, skipped (data the command clears is counted
                // in `counts.data`, never pushed here)
                continue;
            }
            let flow = self.instruction_flow(a, starts, &clear, protected, refs);
            clear.extend(&flow);
            self.dereferenced_starts(&mut todo, &clear, &flow, refs, counts);
        }
        for a in protected {
            clear.remove(a);
        }
        // ClearCmd: the code units (with their references and flow overrides), the functions
        // whose entry is cleared
        let mut bytes = RangeSet(BTreeMap::new());
        for &a in &clear {
            bytes.add(a, a + self.insns[&a].len as u32 - 1);
        }
        for f in self.bodies.keys().copied().filter(|f| clear.contains(f)).collect::<Vec<_>>() {
            self.remove_function(f, changed, counts);
        }
        for &a in &clear {
            if let Some(i) = self.insns.remove(&a) {
                let o = (a - self.code_lo) as usize;
                owner[o..o + i.len as usize].fill(0);
            }
            self.tables.remove(&a);
            self.fallthru.remove(&a);
            self.overrides.remove(&a);
            self.slot_jumps_inside.remove(&a);
            if let Some(g) = self.body_owner.remove(&a) {
                if let Some(b) = self.bodies.get_mut(&g) {
                    b.retain(|x| *x != a);
                }
                counts.stale.insert(g);
            }
        }
        counts.cleared += clear.len();
        again.extend(&clear);
        let new = self.repair_flows_into(img, sl, p, owner, &bytes, ignore, again);
        counts.redisassembled += new.len();
        self.repair_functions(&bytes, &clear, &new, img, allowed, changed, counts);
    }

    /// ClearFlowAndRepairCmd.findInstructionFlow: the blocks of the flow from `first` that
    /// nothing outside it (nor `clear`) flows into, as instruction addresses. The offcut checks
    /// never fire: this listing holds no overlapping instructions.
    fn instruction_flow(
        &self,
        first: u32,
        starts: &BTreeSet<u32>,
        clear: &BTreeSet<u32>,
        protected: &BTreeSet<u32>,
        refs: &HashMap<u32, Vec<(Option<u32>, Ref)>>,
    ) -> BTreeSet<u32> {
        let start_block = self.block_of(first, refs);
        let mut block_set: BTreeSet<u32> = self.block_insns(start_block).collect();
        let mut vs =
            vec![Vertex { start: start_block.0, last: start_block.1, srcs: BTreeSet::new(), dests: BTreeSet::new() }];
        let mut map: HashMap<u32, usize> = HashMap::from([(start_block.0, 0)]);
        let mut todo = vec![0];
        let never_snip = starts.contains(&first);
        while let Some(from) = todo.pop() {
            let (start, last) = (vs[from].start, vs[from].last);
            if protected.contains(&start) {
                continue;
            }
            let block = self.split_protected((start, last), start, protected);
            for (to, _) in self.block_dests(block) {
                if protected.contains(&to) || clear.contains(&to) || !self.insns.contains_key(&to) {
                    continue;
                }
                let mut dest = self.block_of(to, refs);
                if to == dest.0 {
                    dest = self.split_protected(dest, to, protected);
                }
                if never_snip && dest == start_block {
                    continue;
                }
                let d = match map.get(&to) {
                    Some(&d) => d,
                    None => {
                        // a function of an imported (or higher) name stops the flow
                        let named = self.bodies.contains_key(&to)
                            && refs.get(&to).into_iter().flatten().any(|r| r.1 == Ref::External);
                        if named {
                            continue;
                        }
                        block_set.extend(self.block_insns(dest));
                        vs.push(Vertex { start: dest.0, last: dest.1, srcs: BTreeSet::new(), dests: BTreeSet::new() });
                        map.insert(to, vs.len() - 1);
                        todo.push(vs.len() - 1);
                        vs.len() - 1
                    }
                };
                vs[from].dests.insert(d);
                vs[d].srcs.insert(from);
            }
        }
        if first != start_block.0 {
            block_set.retain(|&a| !(start_block.0..first).contains(&a));
        }
        // in block order (Java walks a Hashtable; a prune takes every block it reaches, so a
        // later check a prune made true is covered by that prune)
        let mut order: Vec<usize> = (1..vs.len()).collect();
        order.sort_by_key(|&v| vs[v].start);
        for v in order {
            if vs[v].srcs.is_empty() {
                continue;
            }
            let a = vs[v].start;
            let prune = match self.fall_from(a) {
                Some(ff) if !block_set.contains(&ff) => true,
                _ => {
                    let to = refs.get(&a).map_or(&[][..], Vec::as_slice);
                    let func = self.bodies.contains_key(&a);
                    (to.is_empty() && func)
                        || to.iter().any(|&(from, r)| match r {
                            Ref::Flow { .. } => from.is_some_and(|f| !block_set.contains(&f) && !clear.contains(&f)),
                            Ref::External => func,
                            Ref::Data { .. } => false,
                        })
                }
            };
            if prune {
                self.prune(&mut vs, v, &mut block_set);
            }
        }
        block_set
    }

    /// ClearFlowAndRepairCmd.prune: the vertex and every vertex it reaches leave the set.
    fn prune(&self, vs: &mut [Vertex], v: usize, block_set: &mut BTreeSet<u32>) {
        let mut stack = vec![v];
        while let Some(v) = stack.pop() {
            let block = (vs[v].start, vs[v].last);
            for a in self.block_insns(block) {
                block_set.remove(&a);
            }
            for s in std::mem::take(&mut vs[v].srcs) {
                vs[s].dests.remove(&v);
            }
            stack.extend(vs[v].dests.iter().copied());
        }
    }

    /// ClearFlowAndRepairCmd.addDereferencedInstructionStarts: the destinations of references
    /// from `from_set` that only `clear` refers to and nothing falls into.
    fn dereferenced_starts(
        &self,
        todo: &mut Vec<u32>,
        clear: &BTreeSet<u32>,
        from_set: &BTreeSet<u32>,
        refs: &HashMap<u32, Vec<(Option<u32>, Ref)>>,
        counts: &mut RepairCounts,
    ) {
        for &from in from_set {
            for (to, _) in self.refs_from(from) {
                if clear.contains(&to) {
                    continue;
                }
                let only_cleared = refs.get(&to).into_iter().flatten().all(|r| r.0.is_some_and(|f| clear.contains(&f)));
                if !self.insns.contains_key(&to) {
                    if only_cleared {
                        counts.data.insert(to);
                    }
                    continue;
                }
                if only_cleared && self.fall_from(to).is_none() {
                    todo.push(to);
                }
            }
        }
    }

    /// ClearFlowAndRepairCmd.repairFlowsInto (with repairFallThroughsInto): disassembles at the
    /// fallthroughs into the cleared bytes, then at the cleared addresses a flow still refers to
    /// and the external entry points among them. The sources of the data references into what
    /// stays cleared go to codeDefined (`again`). Returns the instructions disassembled.
    #[allow(clippy::too_many_arguments)]
    fn repair_flows_into(
        &mut self,
        img: &Image,
        sl: &Sleigh,
        p: &mut Parse,
        owner: &mut [u8],
        bytes: &RangeSet,
        ignore: Option<u32>,
        again: &mut BTreeSet<u32>,
    ) -> Vec<u32> {
        let mut points = BTreeSet::new();
        for (lo, _) in bytes.ranges() {
            let (mut a, mut n) = (lo, 0);
            while n < FALLTHROUGH_SEARCH_LIMIT && a > 0 {
                a -= 1;
                if img.block_of(a).is_none() {
                    break;
                }
                let code = (self.code_lo..self.code_hi).contains(&a);
                match if code { owner[(a - self.code_lo) as usize] } else { 0 } {
                    2 => continue, // inside an instruction
                    1 => {
                        if let Some(ft) = self.fall_through(a).filter(|&ft| Some(ft) != ignore) {
                            points.insert(ft);
                        }
                        break;
                    }
                    3 => break, // defined data: a switch table
                    _ if self.table_slots.contains_key(&a) => break,
                    _ => n += 1,
                }
            }
        }
        let mut new = self.disassemble_points(img, sl, p, owner, &points);
        let mut rest = RangeSet(bytes.0.clone());
        for &a in &new {
            rest.remove(a, a + self.insns[&a].len as u32 - 1);
        }
        let refs = self.refs_to(img);
        let mut dests: Vec<u32> = refs.keys().copied().filter(|&a| rest.contains(a)).collect();
        dests.sort_unstable();
        let mut points = BTreeSet::new();
        for a in dests {
            let mut data_ref = None;
            for &(from, r) in &refs[&a] {
                match r {
                    Ref::Flow { .. } => {
                        if Some(a) == ignore {
                            continue;
                        }
                        points.insert(a);
                        break;
                    }
                    Ref::Data { rw } if data_ref.is_none() => {
                        if Some(a) == ignore && !rw {
                            continue;
                        }
                        data_ref = Some(from);
                    }
                    Ref::External if data_ref.is_none() => {
                        if Some(a) == ignore {
                            continue;
                        }
                        data_ref = Some(None);
                    }
                    _ => {}
                }
            }
            if let Some(Some(from)) = data_ref.filter(|_| !points.contains(&a)) {
                again.insert(from);
            }
        }
        points.extend(img.exports.iter().map(|e| e.0).chain(img.entry).filter(|&e| rest.contains(e)));
        new.extend(self.disassemble_points(img, sl, p, owner, &points));
        new
    }

    /// DisassembleCommand on `points`, in address order: the discovery's descent (with
    /// Subroutine References' functions at call targets).
    fn disassemble_points(
        &mut self,
        img: &Image,
        sl: &Sleigh,
        p: &mut Parse,
        owner: &mut [u8],
        points: &BTreeSet<u32>,
    ) -> Vec<u32> {
        let mut queue: Vec<u32> = points.iter().rev().copied().collect();
        let mut log = Vec::new();
        self.descend(img, sl, p, owner, &mut queue, &mut log);
        log
    }

    /// MultEntSubModel.getAddressSetContaining from the instruction at `a`: the blocks joined by
    /// jumps and fallthroughs, and its entry points (blocks called, or with no source).
    fn subroutine(&self, a: u32, refs: &HashMap<u32, Vec<(Option<u32>, Ref)>>) -> (BTreeSet<u32>, Vec<u32>) {
        let mut set = BTreeSet::new();
        let mut entries = Vec::new();
        let mut todo = VecDeque::from([a]);
        let mut srcs: VecDeque<(u32, u32)> = VecDeque::new();
        while !todo.is_empty() || !srcs.is_empty() {
            let Some(x) = todo.pop_front() else {
                while todo.is_empty() {
                    let Some(block) = srcs.pop_front() else { break };
                    // addSources
                    let mut source = true;
                    let mut entry = false;
                    for &(from, r) in refs.get(&block.0).into_iter().flatten() {
                        if let (Some(from), Ref::Flow { call }) = (from, r) {
                            source = false;
                            if call {
                                entry = true;
                            } else {
                                todo.push_back(from);
                            }
                        }
                    }
                    if let Some(ff) = self.fall_from(block.0) {
                        source = false;
                        todo.push_back(ff);
                    }
                    if source || entry {
                        entries.push(block.0);
                    }
                }
                continue;
            };
            let Some((&x, _)) = self.insns.range(..=x).next_back().filter(|(&s, i)| x < s + i.len as u32) else {
                continue;
            };
            if set.contains(&x) {
                continue;
            }
            let block = self.block_of(x, refs);
            set.extend(self.block_insns(block));
            // addDestinations: jumps last, the fallthrough first
            for (to, kind) in self.block_dests(block) {
                match kind {
                    Some(false) => todo.push_back(to),
                    None => todo.push_front(to),
                    Some(true) => {}
                }
            }
            srcs.push_back(block);
        }
        if entries.is_empty() {
            entries.extend(set.first());
        }
        (set, entries)
    }

    /// ClearFlowAndRepairCmd.repairFunctions: in each subroutine (MultEntSubModel) holding
    /// code at the cleared bytes, a function not at an entry point is removed, one at an entry
    /// point gets its body less the cleared bytes plus the flow from its entry
    /// (CreateFunctionCmd.getFunctionBody, through other functions), and the other entry
    /// points become functions.
    #[allow(clippy::too_many_arguments)]
    fn repair_functions(
        &mut self,
        bytes: &RangeSet,
        clear: &BTreeSet<u32>,
        new: &[u32],
        img: &Image,
        allowed: Option<&HashSet<u32>>,
        changed: &mut BTreeSet<u32>,
        counts: &mut RepairCounts,
    ) {
        let mut todo: Vec<u32> = new
            .iter()
            .copied()
            .filter(|&a| bytes.contains(a) || bytes.contains(a + self.insns[&a].len as u32 - 1))
            .collect();
        todo.sort_unstable();
        let mut done: HashSet<u32> = HashSet::new();
        for a in todo {
            if done.contains(&a) || !self.insns.contains_key(&a) {
                continue;
            }
            let refs = self.refs_to(img);
            let (sub, entries) = self.subroutine(a, &refs);
            done.extend(&sub);
            let mut starts: BTreeSet<u32> = entries.into_iter().collect();
            let overlapping = |an: &Analysis| -> BTreeSet<u32> {
                sub.iter()
                    .filter_map(|x| an.body_owner.get(x).copied())
                    .chain(sub.iter().copied().filter(|x| an.bodies.contains_key(x)))
                    .collect()
            };
            for f in overlapping(self) {
                if !starts.contains(&f) {
                    self.remove_function(f, changed, counts);
                }
            }
            for f in overlapping(self) {
                if !starts.remove(&f) {
                    continue;
                }
                let mut body: BTreeSet<u32> = self.bodies[&f].iter().copied().filter(|x| !clear.contains(x)).collect();
                body.extend(self.walk(f, |_| false));
                let body: Vec<u32> = body.into_iter().collect();
                if body.iter().any(|x| self.body_owner.get(x).is_some_and(|&g| g != f)) {
                    counts.overlap += 1;
                    continue;
                }
                // Java's old body still held the cleared bytes, so it differs from the new one
                if counts.stale.remove(&f) || self.bodies[&f] != body {
                    self.set_body(f, body, changed);
                }
            }
            for e in starts {
                self.funcs.insert(e);
                self.create_function(e, allowed, &mut Vec::new(), changed);
            }
        }
    }

    /// FunctionManagerDB.removeFunction, with the thunks of the function (doRemoveFunction).
    fn remove_function(&mut self, f: u32, changed: &mut BTreeSet<u32>, counts: &mut RepairCounts) {
        let thunks: Vec<u32> = self.thunk_of.iter().filter(|&(_, &t)| t == f).map(|(&th, _)| th).collect();
        for th in thunks {
            self.remove_function(th, changed, counts);
        }
        if let Some(body) = self.bodies.remove(&f) {
            for a in body {
                if self.body_owner.get(&a) == Some(&f) {
                    self.body_owner.remove(&a);
                }
            }
            counts.removed += 1;
        }
        self.funcs.remove(&f);
        self.thunk_of.remove(&f);
        self.noreturn.remove(&f);
        self.callee_purges.remove(&f);
        self.purge.remove(&f);
        changed.remove(&f);
        counts.stale.remove(&f);
    }
}
