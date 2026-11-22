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
    /// a data reference; `rw`: READ or WRITE (a memory operand), else DATA (an immediate, a pointer)
    Data { rw: bool },
    /// EXTERNAL_REF, the reference an external entry point has (no source instruction)
    External,
}

/// The references by destination: (source, kind); no source for an external entry point.
type RefsTo = HashMap<u32, Vec<(Option<u32>, Ref)>>;

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
    /// pointer data (`table_slots`, switch tables) all of whose references were cleared: Java
    /// clears it (addDereferencedInstructionStarts with `clearData`); here it stays
    pub data: BTreeSet<u32>,
    /// addresses where a code pointer in data that this listing holds no reference for (outside
    /// Create Address Tables' runs) would change the outcome if Java refers from it: a prune, a
    /// dereferenced start or a block start
    pub data_refs: BTreeSet<u32>,
    /// functions whose body kept cleared bytes in Java (no repairFunctions sub reached them);
    /// here a body holds instructions only, so the bytes go
    pub stale: BTreeSet<u32>,
    /// functions whose repaired body overlapped another function (Java: OverlappingFunctionException)
    pub overlap: usize,
    /// subroutines whose entries Java's HashSet walks in a treeified bucket (order not
    /// reproduced; address order here)
    pub unordered: usize,
}

/// What a repair works with besides the listing.
pub(super) struct Repair<'a> {
    img: &'a Image,
    sl: &'a Sleigh,
    p: &'a mut Parse,
    /// `run`'s map of the executable bytes (1: instruction start, 2: inside one, 3: switch table)
    owner: &'a mut [u8],
    allowed: Option<&'a HashSet<u32>>,
    /// the functions made or changed (`run`'s `defined`)
    pub changed: &'a mut BTreeSet<u32>,
    counts: &'a mut RepairCounts,
    /// the targets of code pointers in data that no reference of this listing comes from
    data_ptrs: HashSet<u32>,
}

impl<'a> Repair<'a> {
    pub(super) fn new(
        img: &'a Image,
        sl: &'a Sleigh,
        p: &'a mut Parse,
        owner: &'a mut [u8],
        allowed: Option<&'a HashSet<u32>>,
        changed: &'a mut BTreeSet<u32>,
        counts: &'a mut RepairCounts,
    ) -> Self {
        Repair { img, sl, p, owner, allowed, changed, counts, data_ptrs: HashSet::new() }
    }
}

/// A vertex of findInstructionFlow's block graph: a SimpleBlockModel block (first and last
/// instruction) and its edges, by index.
struct Vertex {
    start: u32,
    last: u32,
    srcs: BTreeSet<usize>,
    dests: BTreeSet<usize>,
}

/// The iteration order of `new HashSet<>(Arrays.asList(addrs))` over ram addresses: java.util
/// HashMap's buckets (GenericAddress.hashCode, `("ram".hashCode() ^ TYPE_RAM) << 16` xor the
/// offset, spread by HashMap.hash; the table sized for the list, doubled when a bucket reaches
/// TREEIFY_THRESHOLD + 1 below MIN_TREEIFY_CAPACITY), the list's order within a bucket. `None`
/// when a bucket becomes a tree.
fn java_hash_set_order(addrs: &[u32]) -> Option<Vec<u32>> {
    const SPACE: i32 = 112_670 ^ 1; // "ram".hashCode() ^ AddressSpace.TYPE_RAM
    let hash = |a: u32| {
        let h = SPACE.wrapping_shl(16) ^ a as i32;
        (h ^ ((h as u32) >> 16) as i32) as u32 as usize
    };
    let mut n = ((addrs.len() as f32 / 0.75) as usize + 1).max(16).next_power_of_two();
    let mut count: HashMap<usize, usize> = HashMap::new();
    for (k, &a) in addrs.iter().enumerate() {
        let c = count.entry(hash(a) & (n - 1)).or_default();
        *c += 1;
        if *c > 8 {
            if n >= 64 {
                return None;
            }
            // treeifyBin below MIN_TREEIFY_CAPACITY resizes (each bucket keeps its order)
            n *= 2;
            count.clear();
            for &b in &addrs[..=k] {
                *count.entry(hash(b) & (n - 1)).or_default() += 1;
            }
        }
    }
    let mut out = addrs.to_vec();
    out.sort_by_key(|&a| hash(a) & (n - 1));
    Some(out)
}

impl Analysis {
    /// Every reference by destination: from the instructions (flows: direct targets, computed
    /// targets and switch cases; data: memory operands, constant addresses, code constants),
    /// from `table_slots` (pointer data) and the external entry points (`None` source).
    fn refs_to(&self, img: &Image) -> RefsTo {
        let mut to = RefsTo::new();
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
        out.extend(i.refs.iter().map(|&t| (t, Ref::Data { rw: i.rw.contains(&t) })));
        out.extend(i.code_imms.iter().map(|&t| (t, Ref::Data { rw: false })));
        out
    }

    /// The targets of the aligned code pointers in the data sections outside `table_slots`:
    /// Java refers from them where it made pointer data there; this listing has no reference.
    fn data_ptr_targets(&self, img: &Image) -> HashSet<u32> {
        let mut out = HashSet::new();
        for sec in img.sections.iter().filter(|s| !s.exec && s.name != "Headers") {
            for (o, b) in sec.data.as_chunks::<4>().0.iter().enumerate() {
                let t = u32::from_le_bytes(*b);
                if self.is_code(img, t) && !self.table_slots.contains_key(&(sec.addr + 4 * o as u32)) {
                    out.insert(t);
                }
            }
        }
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
    fn has_symbol(&self, a: u32, refs: &RefsTo) -> bool {
        self.bodies.contains_key(&a) || refs.contains_key(&a)
    }

    /// SimpleBlockModel.isBlockStart of the instruction at `a`.
    fn block_start(&self, a: u32, refs: &RefsTo) -> bool {
        match self.fall_from(a) {
            None => true,
            Some(p) => self.has_symbol(a, refs) || self.insns[&p].flow != Flow::Fall,
        }
    }

    /// SimpleBlockModel.getCodeBlockAt(instr): the last instruction of the block from `a`.
    fn block_last(&self, mut a: u32, refs: &RefsTo) -> u32 {
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
    fn block_of(&self, mut a: u32, refs: &RefsTo) -> (u32, u32) {
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
    fn skip_nops(&self, cx: &mut Repair, mut a: u32) -> Result<u32, String> {
        for _ in 0..16 {
            let Some(i) = self.insns.get(&a) else { return Ok(a) };
            if i.flow != Flow::Fall {
                return Ok(a);
            }
            let Some(sec) = cx.img.block_of(a) else { return Ok(a) };
            // every instruction of the listing decoded once: a failure here is a bug
            cx.sl
                .decode(cx.p, a as u64, &sec.data[(a - sec.addr) as usize..])
                .map_err(|e| format!("skipNOPS: decoding {a:#x}: {e}"))?;
            let ops = cx.sl.pcode(cx.p).map_err(|e| format!("skipNOPS: p-code of {a:#x}: {e}"))?;
            let acts = |o: &crate::sleigh::PcodeOp| {
                matches!(o.opc, OP_LOAD | OP_STORE | OP_CALLOTHER | OP_SEGMENTOP)
                    || o.out.is_some_and(|v| v.space != cx.sl.uniq_space())
            };
            if ops.iter().any(acts) {
                return Ok(a);
            }
            match self.fall_through(a) {
                Some(ft) => a = ft,
                None => return Ok(a),
            }
        }
        Ok(a)
    }

    /// FindNoReturnFunctionsAnalyzer.findRepairLocations: the fallthroughs of the calls of
    /// `entry` that hold an instruction no flow refers to (nor to it past NOPs), not `entry`
    /// itself nor an external entry point.
    fn repair_locations(&self, cx: &mut Repair, refs: &RefsTo, entry: u32) -> Result<BTreeSet<u32>, String> {
        let flow_into = |a: u32| refs.get(&a).into_iter().flatten().any(|r| matches!(r.1, Ref::Flow { .. }));
        let img = cx.img;
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
            let check = self.skip_nops(cx, fall)?;
            if external(check) || external(fall) {
                continue;
            }
            if !flow_into(fall) && !flow_into(check) && self.insns.contains_key(&fall) {
                out.insert(fall);
            }
        }
        Ok(out)
    }

    /// FindNoReturnFunctionsAnalyzer.added, the "Repair Flow Damage" step: for each address the
    /// analyzer found (`found`, also the protected set with the analysis manager's protected
    /// locations, none for a PE), ClearFlowAndRepairCmd on its repair locations. Returns the
    /// addresses of instructions cleared or handed to codeDefined, which the instruction
    /// analyzers see again.
    pub(super) fn repair_flow_damage(
        &mut self,
        cx: &mut Repair,
        found: &BTreeSet<u32>,
    ) -> Result<BTreeSet<u32>, String> {
        let mut again = BTreeSet::new();
        cx.data_ptrs = self.data_ptr_targets(cx.img);
        let mut refs = self.refs_to(cx.img);
        for &entry in found {
            let starts = self.repair_locations(cx, &refs, entry)?;
            if !starts.is_empty() {
                cx.counts.runs += 1;
                self.clear_flow_and_repair(cx, &refs, &starts, found, &mut again);
                refs = self.refs_to(cx.img);
            }
        }
        Ok(again)
    }

    /// ClearFlowAndRepairCmd.applyTo with `clearData` and `repair` (and `repairFunctions`),
    /// without `clearLabels`.
    fn clear_flow_and_repair(
        &mut self,
        cx: &mut Repair,
        refs: &RefsTo,
        starts: &BTreeSet<u32>,
        protected: &BTreeSet<u32>,
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
                // no instruction: data, skipped (the pointer data the command clears is counted
                // in `counts.data`, never pushed here)
                continue;
            }
            let flow = self.instruction_flow(cx, a, starts, &clear, protected, refs);
            clear.extend(&flow);
            self.dereferenced_starts(cx, &mut todo, &clear, &flow, refs);
        }
        for a in protected {
            clear.remove(a);
        }
        // a data reference Java has would start a block inside the cleared flow
        let unref_start = |a: &&u32| !self.has_symbol(**a, refs) && self.fall_from(**a).is_some();
        cx.counts.data_refs.extend(clear.iter().filter(|a| cx.data_ptrs.contains(a)).filter(unref_start));
        let bytes = self.clear_code(cx, &clear);
        cx.counts.cleared += clear.len();
        again.extend(&clear);
        let new = self.repair_flows_into(cx, &bytes, ignore, again);
        cx.counts.redisassembled += new.len();
        self.repair_functions(cx, &bytes, &clear, &new);
    }

    /// ClearCmd: the code units (with their references and flow overrides), the functions
    /// whose entry is cleared. Returns the bytes cleared.
    fn clear_code(&mut self, cx: &mut Repair, clear: &BTreeSet<u32>) -> RangeSet {
        let mut bytes = RangeSet(BTreeMap::new());
        for &a in clear {
            bytes.add(a, a + self.insns[&a].len as u32 - 1);
        }
        for f in self.bodies.keys().copied().filter(|f| clear.contains(f)).collect::<Vec<_>>() {
            self.remove_function(f, cx);
        }
        for &a in clear {
            if let Some(i) = self.insns.remove(&a) {
                let o = (a - self.code_lo) as usize;
                cx.owner[o..o + i.len as usize].fill(0);
            }
            self.tables.remove(&a);
            self.fallthru.remove(&a);
            self.overrides.remove(&a);
            self.slot_jumps_inside.remove(&a);
            if let Some(g) = self.body_owner.remove(&a) {
                if let Some(b) = self.bodies.get_mut(&g) {
                    b.retain(|x| *x != a);
                }
                cx.counts.stale.insert(g);
            }
        }
        bytes
    }

    /// ClearFlowAndRepairCmd.findInstructionFlow: the blocks of the flow from `first` that
    /// nothing outside it (nor `clear`) flows into, as instruction addresses. The offcut checks
    /// never fire: this listing holds no overlapping instructions.
    fn instruction_flow(
        &self,
        cx: &mut Repair,
        first: u32,
        starts: &BTreeSet<u32>,
        clear: &BTreeSet<u32>,
        protected: &BTreeSet<u32>,
        refs: &RefsTo,
    ) -> BTreeSet<u32> {
        let start_block = self.block_of(first, refs);
        let (mut vs, mut block_set) = self.flow_graph(start_block, starts.contains(&first), clear, protected, refs);
        if first != start_block.0 {
            block_set.retain(|&a| !(start_block.0..first).contains(&a));
        }
        // in block order (Java walks a Hashtable; a prune takes every block it reaches, so a
        // later check a prune made true is covered by that prune)
        let mut order: Vec<usize> = (1..vs.len()).collect();
        order.sort_by_key(|&v| vs[v].start);
        for v in order {
            if !vs[v].srcs.is_empty() && self.flows_in_from_outside(cx, vs[v].start, &block_set, clear, refs) {
                self.prune(&mut vs, v, &mut block_set);
            }
        }
        block_set
    }

    /// The block graph of findInstructionFlow from `start_block`: its vertices (the first is
    /// `start_block`) and their instructions. `never_snip`: no edge back into `start_block`.
    fn flow_graph(
        &self,
        start_block: (u32, u32),
        never_snip: bool,
        clear: &BTreeSet<u32>,
        protected: &BTreeSet<u32>,
        refs: &RefsTo,
    ) -> (Vec<Vertex>, BTreeSet<u32>) {
        let mut block_set: BTreeSet<u32> = self.block_insns(start_block).collect();
        let mut vs =
            vec![Vertex { start: start_block.0, last: start_block.1, srcs: BTreeSet::new(), dests: BTreeSet::new() }];
        let mut map: HashMap<u32, usize> = HashMap::from([(start_block.0, 0)]);
        let mut todo = vec![0];
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
        (vs, block_set)
    }

    /// findInstructionFlow's prune test of the block at `a`: something outside the flow falls
    /// or flows into it, or it is a function nothing refers to or an external entry point's.
    fn flows_in_from_outside(
        &self,
        cx: &mut Repair,
        a: u32,
        block_set: &BTreeSet<u32>,
        clear: &BTreeSet<u32>,
        refs: &RefsTo,
    ) -> bool {
        if let Some(ff) = self.fall_from(a) {
            if !block_set.contains(&ff) {
                return true;
            }
        }
        let to = refs.get(&a).map_or(&[][..], Vec::as_slice);
        let func = self.bodies.contains_key(&a);
        if to.is_empty() && func && cx.data_ptrs.contains(&a) {
            // Java's data reference, where it has one, makes `to` non-empty
            cx.counts.data_refs.insert(a);
        }
        (to.is_empty() && func)
            || to.iter().any(|&(from, r)| match r {
                Ref::Flow { .. } => from.is_some_and(|f| !block_set.contains(&f) && !clear.contains(&f)),
                Ref::External => func,
                Ref::Data { .. } => false,
            })
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
        cx: &mut Repair,
        todo: &mut Vec<u32>,
        clear: &BTreeSet<u32>,
        from_set: &BTreeSet<u32>,
        refs: &RefsTo,
    ) {
        for &from in from_set {
            for (to, _) in self.refs_from(from) {
                if clear.contains(&to) {
                    continue;
                }
                let only_cleared = refs.get(&to).into_iter().flatten().all(|r| r.0.is_some_and(|f| clear.contains(&f)));
                if !self.insns.contains_key(&to) {
                    // Java goes on only at defined pointer (or Undefined) data: here the pointer
                    // data of `table_slots` and the switch tables
                    let code = (self.code_lo..self.code_hi).contains(&to);
                    let table = code && cx.owner[(to - self.code_lo) as usize] == 3;
                    if only_cleared && (table || self.table_slots.contains_key(&to)) {
                        cx.counts.data.insert(to);
                    }
                    continue;
                }
                if only_cleared && self.fall_from(to).is_none() {
                    if cx.data_ptrs.contains(&to) {
                        // a data reference Java has from outside the clear set keeps it
                        cx.counts.data_refs.insert(to);
                    }
                    todo.push(to);
                }
            }
        }
    }

    /// ClearFlowAndRepairCmd.repairFlowsInto (with repairFallThroughsInto): disassembles at the
    /// fallthroughs into the cleared bytes, then at the cleared addresses a flow still refers to
    /// and the external entry points among them. The sources of the data references into what
    /// stays cleared go to codeDefined (`again`). Returns the instructions disassembled.
    fn repair_flows_into(
        &mut self,
        cx: &mut Repair,
        bytes: &RangeSet,
        ignore: Option<u32>,
        again: &mut BTreeSet<u32>,
    ) -> Vec<u32> {
        let points = self.fallthroughs_into(cx, bytes, ignore);
        let mut new = self.disassemble_points(cx, &points);
        let mut rest = RangeSet(bytes.0.clone());
        for &a in &new {
            rest.remove(a, a + self.insns[&a].len as u32 - 1);
        }
        let refs = self.refs_to(cx.img);
        let mut dests: Vec<u32> = refs.keys().copied().filter(|&a| rest.contains(a)).collect();
        dests.sort_unstable();
        let mut points = BTreeSet::new();
        for a in dests {
            match Self::flow_or_data_ref(&refs[&a], Some(a) == ignore) {
                Some(None) => {
                    points.insert(a);
                }
                Some(Some(from)) => {
                    again.insert(from);
                }
                None => {}
            }
        }
        let img = cx.img;
        points.extend(img.exports.iter().map(|e| e.0).chain(img.entry).filter(|&e| rest.contains(e)));
        new.extend(self.disassemble_points(cx, &points));
        new
    }

    /// repairFallThroughsInto: the fallthrough of the instruction before each cleared range,
    /// within FALLTHROUGH_SEARCH_LIMIT undefined bytes, unless it is `ignore`.
    fn fallthroughs_into(&self, cx: &Repair, bytes: &RangeSet, ignore: Option<u32>) -> BTreeSet<u32> {
        let mut points = BTreeSet::new();
        for (lo, _) in bytes.ranges() {
            let (mut a, mut n) = (lo, 0);
            while n < FALLTHROUGH_SEARCH_LIMIT && a > 0 {
                a -= 1;
                if cx.img.block_of(a).is_none() {
                    break;
                }
                let code = (self.code_lo..self.code_hi).contains(&a);
                match if code { cx.owner[(a - self.code_lo) as usize] } else { 0 } {
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
        points
    }

    /// repairFlowsInto on the references to one cleared address: `Some(None)` when a flow
    /// refers to it (a disassembly point), `Some(Some(from))` for the first data reference's
    /// source, `None` otherwise. At `ignoreStart` (`ignored`) flows are skipped, and data
    /// references that neither READ nor WRITE.
    fn flow_or_data_ref(to: &[(Option<u32>, Ref)], ignored: bool) -> Option<Option<u32>> {
        let mut data_ref = None;
        for &(from, r) in to {
            match r {
                Ref::Flow { .. } if !ignored => return Some(None),
                Ref::Data { rw } if data_ref.is_none() && !(ignored && !rw) => data_ref = Some(from),
                Ref::External if data_ref.is_none() && !ignored => data_ref = Some(None),
                _ => {}
            }
        }
        data_ref.flatten().map(Some)
    }

    /// DisassembleCommand on `points`, in address order: the discovery's descent (with
    /// Subroutine References' functions at call targets).
    fn disassemble_points(&mut self, cx: &mut Repair, points: &BTreeSet<u32>) -> Vec<u32> {
        let mut queue: Vec<u32> = points.iter().rev().copied().collect();
        let mut log = Vec::new();
        self.descend(cx.img, cx.sl, cx.p, cx.owner, &mut queue, &mut log);
        log
    }

    /// MultEntSubModel.getAddressSetContaining from the instruction at `a`: the blocks joined by
    /// jumps and fallthroughs, and its entry points (blocks called, or with no source).
    fn subroutine(&self, a: u32, refs: &RefsTo) -> (BTreeSet<u32>, Vec<u32>) {
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
    /// points become functions, in the order of Java's HashSet of them.
    fn repair_functions(&mut self, cx: &mut Repair, bytes: &RangeSet, clear: &BTreeSet<u32>, new: &[u32]) {
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
            let refs = self.refs_to(cx.img);
            let (sub, entries) = self.subroutine(a, &refs);
            done.extend(&sub);
            let mut starts: BTreeSet<u32> = entries.iter().copied().collect();
            let overlapping = |an: &Analysis| -> BTreeSet<u32> {
                sub.iter()
                    .filter_map(|x| an.body_owner.get(x).copied())
                    .chain(sub.iter().copied().filter(|x| an.bodies.contains_key(x)))
                    .collect()
            };
            for f in overlapping(self) {
                if !starts.contains(&f) {
                    self.remove_function(f, cx);
                }
            }
            for f in overlapping(self) {
                if starts.remove(&f) {
                    self.repair_body(cx, f, clear);
                }
            }
            let order = java_hash_set_order(&entries).unwrap_or_else(|| {
                if starts.len() > 1 {
                    cx.counts.unordered += 1;
                }
                entries.clone()
            });
            for e in order.into_iter().filter(|e| starts.contains(e)) {
                self.funcs.insert(e);
                self.create_function(e, cx.allowed, &mut Vec::new(), cx.changed);
            }
        }
    }

    /// repairFunctions on a function at an entry point: its body less the cleared bytes plus
    /// the flow from its entry, unless that overlaps another function.
    fn repair_body(&mut self, cx: &mut Repair, f: u32, clear: &BTreeSet<u32>) {
        let mut body: BTreeSet<u32> = self.bodies[&f].iter().copied().filter(|x| !clear.contains(x)).collect();
        body.extend(self.walk(f, |_| false));
        let body: Vec<u32> = body.into_iter().collect();
        if body.iter().any(|x| self.body_owner.get(x).is_some_and(|&g| g != f)) {
            cx.counts.overlap += 1;
            return;
        }
        // Java's old body still held the cleared bytes, so it differs from the new one
        if cx.counts.stale.remove(&f) || self.bodies[&f] != body {
            self.set_body(f, body, cx.changed);
        }
    }

    /// FunctionManagerDB.removeFunction, with the thunks of the function (doRemoveFunction).
    fn remove_function(&mut self, f: u32, cx: &mut Repair) {
        let thunks: Vec<u32> = self.thunk_of.iter().filter(|&(_, &t)| t == f).map(|(&th, _)| th).collect();
        for th in thunks {
            self.remove_function(th, cx);
        }
        if let Some(body) = self.bodies.remove(&f) {
            for a in body {
                if self.body_owner.get(&a) == Some(&f) {
                    self.body_owner.remove(&a);
                }
            }
            cx.counts.removed += 1;
        }
        self.funcs.remove(&f);
        self.thunk_of.remove(&f);
        self.noreturn.remove(&f);
        self.callee_purges.remove(&f);
        self.purge.remove(&f);
        cx.changed.remove(&f);
        cx.counts.stale.remove(&f);
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::bare;
    use super::super::{Flow, Image, RangeSet, Section};
    use super::{java_hash_set_order, Repair, RepairCounts};
    use std::collections::BTreeSet;

    /// A 0x80-byte `.text` of NOPs holding the instructions of `an`, and the x86 decoder.
    fn image(an: &mut super::Analysis) -> (Image, crate::sleigh::Sleigh, Vec<u8>) {
        an.code_hi = 0x80;
        let mut owner = vec![0u8; 0x80];
        for &a in an.insns.keys() {
            owner[a as usize] = 1;
        }
        let text =
            Section { name: ".text".into(), exec: true, readonly: true, zero_tail: 0, addr: 0, data: vec![0x90; 0x80] };
        let sl = crate::sleigh::Sleigh::load(&crate::sleigh::Sleigh::sla_path("x86")).unwrap();
        (Image { sections: vec![text], ..Image::default() }, sl, owner)
    }

    #[test]
    fn repair_prunes_a_block_flowed_into_from_outside() {
        // the damage after the call of 0x40 jumps to 0x20, which 0x30 jumps to as well
        let (mut an, mut changed) = bare(
            &[
                (0x10, Flow::Call, Some(0x40)),
                (0x11, Flow::Fall, None),
                (0x12, Flow::Jump, Some(0x20)),
                (0x20, Flow::Fall, None),
                (0x21, Flow::Return, None),
                (0x30, Flow::Jump, Some(0x20)),
                (0x40, Flow::Jump, Some(0x40)),
            ],
            &[0x10, 0x30, 0x40],
        );
        an.noreturn.insert(0x40);
        an.fixup_body(0x10, &mut changed);
        let (img, sl, mut owner) = image(&mut an);
        let (mut p, mut counts) = (sl.new_parse(), RepairCounts::default());
        let mut cx = Repair::new(&img, &sl, &mut p, &mut owner, None, &mut changed, &mut counts);
        an.repair_flow_damage(&mut cx, &BTreeSet::from([0x40])).unwrap();
        assert!(!an.insns.contains_key(&0x11) && !an.insns.contains_key(&0x12));
        assert!(an.insns.contains_key(&0x20) && an.insns.contains_key(&0x21));
    }

    #[test]
    fn split_protected_ends_before_the_protected_address() {
        let fall = |a| (a, Flow::Fall, None);
        let (an, _) = bare(&[fall(0x10), fall(0x11), fall(0x12), (0x13, Flow::Return, None)], &[]);
        let protected = BTreeSet::from([0x12]);
        assert_eq!(an.split_protected((0x10, 0x13), 0x10, &protected), (0x10, 0x11));
        assert_eq!(an.split_protected((0x12, 0x13), 0x12, &protected), (0x12, 0x13));
    }

    #[test]
    fn repair_functions_keeps_the_entries_of_the_subroutine() {
        // 0x10..0x12 and 0x20 are one subroutine; its entries are 0x10 (no source) and 0x20
        // (called from 0x30); the function at 0x12 is at no entry
        let (mut an, mut changed) = bare(
            &[
                (0x10, Flow::Fall, None),
                (0x11, Flow::CondJump, Some(0x20)),
                (0x12, Flow::Return, None),
                (0x20, Flow::Return, None),
                (0x30, Flow::Call, Some(0x20)),
                (0x31, Flow::Return, None),
            ],
            &[0x10, 0x12],
        );
        let (img, sl, mut owner) = image(&mut an);
        let refs = an.refs_to(&img);
        assert_eq!(an.subroutine(0x10, &refs), (BTreeSet::from([0x10, 0x11, 0x12, 0x20]), vec![0x10, 0x20]));
        assert!(an.bodies.contains_key(&0x12));
        let (mut p, mut counts) = (sl.new_parse(), RepairCounts::default());
        let mut cx = Repair::new(&img, &sl, &mut p, &mut owner, None, &mut changed, &mut counts);
        let mut bytes = RangeSet::default();
        bytes.add(0x10, 0x12);
        an.repair_functions(&mut cx, &bytes, &BTreeSet::new(), &[0x10]);
        assert!(!an.bodies.contains_key(&0x12) && an.bodies.contains_key(&0x10));
        assert!(an.funcs.contains(&0x20) && !an.funcs.contains(&0x12));
        assert_eq!(counts.removed, 1);
    }

    #[test]
    fn java_hash_set_order_follows_the_buckets() {
        // for a < 0x10000 the bucket of 16 is (a ^ 0xb81f) & 15: the low bits of a, inverted
        assert_eq!(java_hash_set_order(&[0x10, 0x1f, 0x11]), Some(vec![0x1f, 0x11, 0x10]));
        // the same bucket keeps the list's order
        assert_eq!(java_hash_set_order(&[0x20, 0x10]), Some(vec![0x20, 0x10]));
        // orders printed by java.util.HashSet (OpenJDK 25) over GenericAddress's hashCode:
        // ten in one bucket of 16 (resized to 32), and eight spread
        let ten: Vec<u32> = (0..10).map(|k| 0x401000 + k * 0x10).collect();
        let java = [0x401010, 0x401030, 0x401050, 0x401070, 0x401090, 0x401000, 0x401020, 0x401040, 0x401060, 0x401080];
        assert_eq!(java_hash_set_order(&ten), Some(java.to_vec()));
        let eight = [0x9ef1dc, 0x401630, 0x4017b0, 0x6b21e0, 0x4c48d0, 0x2560d0, 0x256cae0, 0x41d560];
        let java = [0x4c48d0, 0x6b21e0, 0x256cae0, 0x2560d0, 0x9ef1dc, 0x41d560, 0x401630, 0x4017b0];
        assert_eq!(java_hash_set_order(&eight), Some(java.to_vec()));
    }
}
