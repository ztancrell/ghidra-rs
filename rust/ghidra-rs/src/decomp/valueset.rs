//! Port of the value-set analysis of rangeutil.cc: `ValueSet`, `ValueSetRead`, `WidenerFull`,
//! `WidenerNone` and `ValueSetSolver`. Given sink varnodes it finds the range of values each
//! varnode flowing into them can take (absolute, or relative to the stack pointer), with the
//! constraints of the conditional branches around them, by iterating in Bourdoncle's order.
//! The stack heritage pass uses it for the range of an indexed LOAD or STORE
//! (`heritage_guard.rs`).
//!
//! The C++ keeps a varnode's set in the varnode and marks the varnodes of the system; here the
//! solver maps a varnode to its set, and a varnode is marked when it has one. A varnode read
//! without a set (the C++ would read a stale pointer) is an error.

use super::block::BlockId;
use super::condconst::{lone_descend, restricted_by_conditional};
use super::op::{OpFlags, OpId};
use super::opcode::Opcode;
use super::rangeutil::{calc_mask, pull_back, CircleRange};
use super::varnode::{VarnodeId, VnFlags};
use super::{err, Funcdata, Result};
use std::collections::{HashMap, HashSet};

/// `ValueSet::MAX_STEP`
const MAX_STEP: u32 = 32;

/// Port of `ValueSet::Equation`: a constraint on the values coming in through `slot`.
#[derive(Debug, Clone, Copy)]
struct Equation {
    slot: usize,
    type_code: i32,
    range: CircleRange,
}

/// Port of `ValueSet`: the values a varnode may hold.
#[derive(Debug, Clone)]
struct ValueSet {
    /// 0 = absolute, 1 = relative to the stack pointer
    type_code: i32,
    num_params: usize,
    /// depth-first number, then the iteration count
    count: i32,
    /// the defining op-code (INDIRECT as COPY), `None` for `CPUI_MAX`
    opc: Option<Opcode>,
    left_is_stable: bool,
    right_is_stable: bool,
    /// `None` for the simulated root
    vn: Option<VarnodeId>,
    range: CircleRange,
    equations: Vec<Equation>,
    /// the partition this set heads
    part_head: Option<usize>,
    next: Option<usize>,
}

/// Port of `Partition`: a component of the iteration order.
#[derive(Debug, Clone, Copy, Default)]
struct Partition {
    start: Option<usize>,
    stop: Option<usize>,
    is_dirty: bool,
}

/// Port of `ValueSetRead`: the values of a varnode as one op reads them.
#[derive(Debug, Clone)]
pub(crate) struct ValueSetRead {
    type_code: i32,
    slot: usize,
    pub(crate) range: CircleRange,
    equation_constraint: CircleRange,
    equation_type_code: i32,
    pub(crate) left_is_stable: bool,
    pub(crate) right_is_stable: bool,
}

/// Port of `Widener`: `WidenerFull` (widen at iteration 2, full at 5) and `WidenerNone` (freeze
/// at iteration 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Widener {
    Full,
    None,
}

const WIDEN_ITERATION: i32 = 2;
const FULL_ITERATION: i32 = 5;
const FREEZE_ITERATION: i32 = 3;

/// `CircleRange::operator==`: two empty ranges are equal whatever their fields hold.
fn same(a: &CircleRange, b: &CircleRange) -> bool {
    (a.isempty && b.isempty) || a == b
}

/// `range ∩ eq`, or `eq` when the intersection is two pieces.
fn constrain(mut range: CircleRange, eq: &CircleRange) -> CircleRange {
    if range.intersect(eq) != 0 {
        range = *eq;
    }
    range
}

impl ValueSet {
    /// `ValueSet::setVarnode`
    fn new(fd: &Funcdata, vn: VarnodeId, type_code: i32) -> ValueSet {
        let v = fd.vn(vn);
        let mut s = ValueSet {
            type_code,
            num_params: 0,
            count: 0,
            opc: None,
            left_is_stable: true,
            right_is_stable: true,
            vn: Some(vn),
            range: CircleRange::default(),
            equations: Vec::new(),
            part_head: None,
            next: None,
        };
        if type_code != 0 {
            s.range = CircleRange::single(0, v.size);
        } else if let Some(def) = v.def {
            let op = fd.op(def);
            (s.opc, s.num_params) =
                if op.opc == Opcode::Indirect { (Some(Opcode::Copy), 1) } else { (Some(op.opc), op.ins.len()) };
            s.left_is_stable = false;
            s.right_is_stable = false;
        } else if v.is_constant() {
            s.range = CircleRange::single(v.offset, v.size);
        } else {
            s.range = CircleRange::full(v.size);
            s.left_is_stable = false;
            s.right_is_stable = false;
        }
        s
    }

    fn set_full(&mut self, fd: &Funcdata) {
        if let Some(vn) = self.vn {
            self.range = CircleRange::full(fd.vn(vn).size);
        }
        self.type_code = 0;
    }

    /// `addEquation`: kept in slot order, a new one after those of its slot
    fn add_equation(&mut self, slot: usize, type_code: i32, range: CircleRange) {
        let at = self.equations.iter().position(|e| e.slot > slot).unwrap_or(self.equations.len());
        self.equations.insert(at, Equation { slot, type_code, range });
    }

    /// `doesEquationApply`
    fn equation(&self, num: usize, slot: usize) -> Option<&CircleRange> {
        self.equations.get(num).filter(|e| e.slot == slot && e.type_code == self.type_code).map(|e| &e.range)
    }

    /// `getLandMark`
    fn landmark(&self) -> Option<CircleRange> {
        self.equations.iter().find(|e| e.type_code == self.type_code).map(|e| e.range)
    }
}

impl Widener {
    /// `determineIterationReset`
    fn iteration_reset(self, count: i32) -> i32 {
        match self {
            Widener::Full if count >= WIDEN_ITERATION => WIDEN_ITERATION,
            Widener::Full => 0,
            Widener::None => count.min(FREEZE_ITERATION),
        }
    }

    /// `checkFreeze`
    fn check_freeze(self, set: &ValueSet) -> bool {
        set.range.is_full() || (self == Widener::None && set.count >= FREEZE_ITERATION)
    }

    /// `doWidening`: the new range of a component head; false to make it full
    fn do_widening(self, set: &ValueSet, range: &mut CircleRange, new: &CircleRange) -> bool {
        if self == Widener::None || set.count < WIDEN_ITERATION {
            *range = *new;
            return true;
        }
        if set.count == WIDEN_ITERATION {
            if let Some(landmark) = set.landmark() {
                let left_is_stable = range.left == new.left;
                *range = *new; // keeps any new step
                if landmark.contains_range(range) {
                    range.widen(&landmark, left_is_stable);
                    return true;
                }
                let mut constraint = landmark;
                constraint.invert();
                if constraint.contains_range(range) {
                    range.widen(&constraint, left_is_stable);
                    return true;
                }
            }
        } else if set.count < FULL_ITERATION {
            *range = *new;
            return true;
        }
        false
    }
}

/// Port of `ValueSetSolver`.
#[derive(Debug, Default)]
pub(crate) struct ValueSetSolver {
    nodes: Vec<ValueSet>,
    /// a marked varnode's set (`Varnode::getValueSet`)
    set_of: HashMap<VarnodeId, usize>,
    /// `readNodes`: a read op is marked when it has an entry
    reads: HashMap<OpId, ValueSetRead>,
    /// `orderPartition.startNode`
    order_start: Option<usize>,
    /// `recordStorage`
    parts: Vec<Partition>,
    roots: Vec<usize>,
    node_stack: Vec<usize>,
    depth_first_index: i32,
}

impl ValueSetSolver {
    fn set(&self, vn: VarnodeId) -> Result<usize> {
        match self.set_of.get(&vn) {
            Some(&i) => Ok(i),
            None => err("value-set analysis: a varnode without a value set is read"),
        }
    }

    /// `newValueSet`, with the mark
    fn new_value_set(&mut self, fd: &Funcdata, vn: VarnodeId, type_code: i32) -> usize {
        self.nodes.push(ValueSet::new(fd, vn, type_code));
        self.set_of.insert(vn, self.nodes.len() - 1);
        self.nodes.len() - 1
    }

    /// `ValueSet::computeTypeCode`: true for a combination that cannot be decided
    fn compute_type_code(&mut self, fd: &Funcdata, i: usize, def: OpId) -> Result<bool> {
        let (mut rel_count, mut last) = (0, 0);
        for &inp in fd.op(def).ins.iter().take(self.nodes[i].num_params) {
            let tc = self.nodes[self.set(inp)?].type_code;
            if tc != 0 {
                rel_count += 1;
                last = tc;
            }
        }
        let s = &mut self.nodes[i];
        if rel_count == 0 {
            s.type_code = 0;
            return Ok(false);
        }
        match s.opc {
            Some(Opcode::Ptrsub | Opcode::Ptradd | Opcode::IntAdd | Opcode::IntSub) if rel_count == 1 => {
                s.type_code = last;
            }
            Some(Opcode::Cast | Opcode::Copy | Opcode::Indirect | Opcode::Multiequal) => s.type_code = last,
            _ => return Ok(true),
        }
        Ok(false)
    }

    /// `ValueSet::iterate`: push the input sets through the defining op; true on a change
    fn iterate(&mut self, fd: &Funcdata, i: usize, widener: Widener) -> Result<bool> {
        let Some(vn) = self.nodes[i].vn else { return Ok(false) };
        let Some(def) = fd.vn(vn).def else { return Ok(false) };
        if widener.check_freeze(&self.nodes[i]) {
            return Ok(false);
        }
        if self.nodes[i].count == 0 && self.compute_type_code(fd, i, def)? {
            self.nodes[i].set_full(fd);
            return Ok(true);
        }
        self.nodes[i].count += 1;
        let out_size = fd.vn(vn).size;
        let ins = &fd.op(def).ins;
        let n = self.nodes[i].num_params;
        // the input sets: range, stable flags and varnode size
        let mut inp = Vec::with_capacity(n.min(3));
        if n <= 3 || self.nodes[i].opc == Some(Opcode::Multiequal) {
            for &v in ins.iter().take(n) {
                let s = &self.nodes[self.set(v)?];
                inp.push((s.range, s.left_is_stable, s.right_is_stable, fd.vn(v).size));
            }
        }
        let s = &mut self.nodes[i];
        let Some(opc) = s.opc else { return Ok(false) };
        let mut res = CircleRange::default();
        let mut eq_pos = 0;
        if opc == Opcode::Multiequal {
            for (slot, &(range, ..)) in inp.iter().enumerate() {
                let pieces = match s.equation(eq_pos, slot) {
                    Some(eq) => {
                        eq_pos += 1;
                        res.circle_union(&constrain(range, eq))
                    }
                    None => res.circle_union(&range),
                };
                if pieces == 2 && res.minimal_container(&range, MAX_STEP) {
                    break;
                }
            }
            if res.circle_union(&s.range) != 0 {
                res.minimal_container(&s.range, MAX_STEP);
            }
            if !s.range.is_empty() && !res.is_empty() {
                s.left_is_stable = s.range.left == res.left;
                s.right_is_stable = s.range.right == res.right;
            }
        } else if n == 1 {
            let (range, l, r, in_size) = inp[0];
            let range = match s.equation(eq_pos, 0) {
                Some(eq) => constrain(range, eq),
                None => range,
            };
            if !res.push_forward_unary(opc, &range, in_size, out_size) {
                s.set_full(fd);
                return Ok(true);
            }
            (s.left_is_stable, s.right_is_stable) = (l, r);
        } else if n == 2 || n == 3 {
            let (mut range1, l1, r1, in_size) = inp[0];
            let (mut range2, l2, r2, _) = inp[1];
            // (with no equation neither applies)
            if let Some(eq) = s.equation(eq_pos, 0) {
                range1 = constrain(range1, eq);
                eq_pos += 1;
            }
            if let Some(eq) = s.equation(eq_pos, 1) {
                range2 = constrain(range2, eq);
            }
            let ok = if n == 2 {
                res.push_forward_binary(opc, &range1, &range2, in_size, out_size, MAX_STEP)
            } else {
                res.push_forward_trinary(opc, [&range1, &range2, &inp[2].0], in_size, out_size, MAX_STEP)
            };
            if !ok {
                s.set_full(fd);
                return Ok(true);
            }
            (s.left_is_stable, s.right_is_stable) = (l1 && l2, r1 && r2);
        } else {
            return Ok(false);
        }
        if same(&res, &s.range) {
            return Ok(false);
        }
        if s.part_head.is_some() {
            let mut range = s.range;
            let widened = widener.do_widening(s, &mut range, &res);
            s.range = range;
            if !widened {
                s.set_full(fd);
            }
        } else {
            s.range = res;
        }
        Ok(true)
    }

    /// `ValueSetEdge`: the sets a node flows into (the roots, for the simulated root)
    fn edges(&self, fd: &Funcdata, vertex: usize) -> Vec<usize> {
        match self.nodes[vertex].vn {
            None => self.roots.clone(),
            Some(vn) => {
                let outs = fd.vn(vn).descend.iter().filter_map(|&op| fd.op(op).out);
                outs.filter_map(|out| self.set_of.get(&out).copied()).collect()
            }
        }
    }

    /// `partitionPrepend(ValueSet *, Partition &)`
    fn prepend(&mut self, vertex: usize, part: &mut Partition) {
        self.nodes[vertex].next = part.start;
        part.start = Some(vertex);
        part.stop = part.stop.or(Some(vertex));
    }

    /// `component`: the partition headed by `vertex`
    fn component(&mut self, fd: &Funcdata, vertex: usize, part: &mut Partition) {
        for succ in self.edges(fd, vertex) {
            if self.nodes[succ].count == 0 {
                self.visit(fd, succ, part);
            }
        }
        self.prepend(vertex, part);
        // partitionSurround
        self.parts.push(*part);
        self.nodes[vertex].part_head = Some(self.parts.len() - 1);
    }

    /// `visit`: the depth-first walk that finds the partitions (recursive, as the C++ is)
    fn visit(&mut self, fd: &Funcdata, vertex: usize, part: &mut Partition) -> i32 {
        self.node_stack.push(vertex);
        self.depth_first_index += 1;
        self.nodes[vertex].count = self.depth_first_index;
        let mut head = self.depth_first_index;
        let mut is_loop = false;
        for succ in self.edges(fd, vertex) {
            let min = if self.nodes[succ].count == 0 { self.visit(fd, succ, part) } else { self.nodes[succ].count };
            if min <= head {
                head = min;
                is_loop = true;
            }
        }
        if head == self.nodes[vertex].count {
            self.nodes[vertex].count = i32::MAX;
            let mut element = self.node_stack.pop();
            if is_loop {
                while let Some(e) = element.filter(|&e| e != vertex) {
                    self.nodes[e].count = 0;
                    element = self.node_stack.pop();
                }
                let mut comp = Partition::default();
                self.component(fd, vertex, &mut comp);
                // partitionPrepend(const Partition &, Partition &)
                if let Some(stop) = comp.stop {
                    self.nodes[stop].next = part.start;
                }
                part.start = comp.start;
                part.stop = part.stop.or(comp.stop);
            } else {
                self.prepend(vertex, part);
            }
        }
        head
    }

    /// `establishTopologicalOrder`
    fn establish_topological_order(&mut self, fd: &Funcdata) {
        for s in &mut self.nodes {
            s.count = 0;
            s.next = None;
            s.part_head = None;
        }
        // the simulated root
        let root = self.nodes.len();
        self.nodes.push(ValueSet {
            type_code: 0,
            num_params: 0,
            count: 0,
            opc: None,
            left_is_stable: false,
            right_is_stable: false,
            vn: None,
            range: CircleRange::default(),
            equations: Vec::new(),
            part_head: None,
            next: None,
        });
        self.depth_first_index = 0;
        let mut order = Partition::default();
        self.visit(fd, root, &mut order);
        self.order_start = self.nodes[root].next;
        self.nodes.pop();
    }

    /// `generateTrueEquation` / `generateFalseEquation` (`range` already inverted for false):
    /// on the output's set, or on the read for a special read site
    fn generate_equation(&mut self, out: Option<VarnodeId>, op: OpId, slot: usize, ty: i32, range: CircleRange) {
        match out.and_then(|v| self.set_of.get(&v)) {
            Some(&i) => self.nodes[i].add_equation(slot, ty, range),
            None => {
                if let Some(r) = self.reads.get_mut(&op).filter(|r| r.slot == slot) {
                    r.equation_type_code = ty;
                    r.equation_constraint = range;
                }
            }
        }
    }

    /// `applyConstraints`: the ops reading `vn` where the constraint of `cbranch` (or its
    /// complement) holds get an equation
    fn apply_constraints(
        &mut self,
        fd: &Funcdata,
        vn: VarnodeId,
        ty: i32,
        range: &CircleRange,
        cbranch: OpId,
    ) -> Result<()> {
        let Some(split) = fd.op(cbranch).parent else { return Ok(()) };
        let outs = &fd.blocks.block(split).outs;
        let (mut true_bl, mut false_bl) = (outs[1].point, outs[0].point);
        if fd.op(cbranch).flags.has(OpFlags::BOOLEAN_FLIP) {
            std::mem::swap(&mut true_bl, &mut false_bl);
        }
        let true_restricted = restricted_by_conditional(fd, true_bl, split)?;
        let false_restricted = restricted_by_conditional(fd, false_bl, split)?;
        let mut false_range = *range;
        false_range.invert();
        if fd.vn(vn).def.is_some() {
            let i = self.set(vn)?;
            let s = &mut self.nodes[i];
            if s.opc == Some(Opcode::Multiequal) {
                s.add_equation(s.num_params, ty, *range); // a landmark for widening
            }
        }
        for &op in fd.vn(vn).descend.iter() {
            let mut out = None;
            if !self.reads.contains_key(&op) {
                out = fd.op(op).out.filter(|o| self.set_of.contains_key(o));
                if out.is_none() {
                    continue;
                }
            }
            let Some(mut cur) = fd.op(op).parent else { continue };
            let Some(slot) = fd.slot_of(op, vn) else { continue };
            if fd.op(op).opc == Opcode::Multiequal {
                let from_split = |bl: BlockId| fd.blocks.block(bl).ins[slot].point == split;
                if cur == true_bl {
                    if true_restricted || from_split(true_bl) {
                        self.generate_equation(out, op, slot, ty, *range);
                    }
                    continue;
                } else if cur == false_bl {
                    if false_restricted || from_split(false_bl) {
                        self.generate_equation(out, op, slot, ty, false_range);
                    }
                    continue;
                }
                cur = fd.blocks.block(cur).ins[slot].point;
            }
            loop {
                if cur == true_bl {
                    if true_restricted {
                        self.generate_equation(out, op, slot, ty, *range);
                    }
                    break;
                } else if cur == false_bl {
                    if false_restricted {
                        self.generate_equation(out, op, slot, ty, false_range);
                    }
                    break;
                } else if cur == split {
                    break;
                }
                match fd.blocks.block(cur).idom {
                    Some(d) => cur = d,
                    None => break,
                }
            }
        }
        Ok(())
    }

    /// `CircleRange::pullBack` without the non-zero masks
    fn pull_back(fd: &Funcdata, vn: VarnodeId, lift: &mut CircleRange) -> Option<VarnodeId> {
        let konst = |v: VarnodeId| fd.vn(v).is_constant().then(|| fd.vn(v).offset);
        let (res, range) = pull_back(fd, vn, *lift, false, konst, |_| 0)?;
        *lift = range;
        Some(res)
    }

    /// `constraintsFromPath`: lift the range from `start` back to `end`, a varnode of the
    /// system, and on while the path stays in it
    fn constraints_from_path(
        &mut self,
        fd: &Funcdata,
        ty: i32,
        mut lift: CircleRange,
        mut start: VarnodeId,
        mut end: VarnodeId,
        cbranch: OpId,
    ) -> Result<()> {
        while start != end {
            match Self::pull_back(fd, start, &mut lift) {
                Some(v) => start = v,
                None => return Ok(()),
            }
        }
        loop {
            self.apply_constraints(fd, end, ty, &lift, cbranch)?;
            let Some(def) = fd.vn(end).def else { break };
            if fd.op(def).is_call() || fd.op(def).is_marker() {
                break;
            }
            match Self::pull_back(fd, end, &mut lift) {
                Some(v) if self.set_of.contains_key(&v) => end = v,
                _ => break,
            }
        }
        Ok(())
    }

    /// `constraintsFromCBranch`
    fn constraints_from_cbranch(&mut self, fd: &Funcdata, cbranch: OpId) -> Result<()> {
        let start = fd.input(cbranch, 1)?;
        let mut vn = start;
        while !self.set_of.contains_key(&vn) {
            let Some(def) = fd.vn(vn).def else { break };
            let op = fd.op(def);
            if op.is_call() || op.is_marker() || op.ins.is_empty() || op.ins.len() > 2 {
                break;
            }
            vn = op.ins[0];
            if op.ins.len() == 2 {
                if fd.vn(vn).is_constant() {
                    vn = op.ins[1];
                } else if !fd.vn(op.ins[1]).is_constant() {
                    return self.generate_relative_constraint(fd, def, cbranch);
                }
            }
        }
        if self.set_of.contains_key(&vn) {
            self.constraints_from_path(fd, 0, CircleRange::boolean(true), start, vn, cbranch)?;
        }
        Ok(())
    }

    /// `generateConstraints`: the conditional branches into the blocks of the system (and
    /// their dominators) give the constraints
    fn generate_constraints(&mut self, fd: &Funcdata, worklist: &[VarnodeId], reads: &[OpId]) -> Result<()> {
        let mut marks: HashSet<BlockId> = HashSet::new();
        let mut block_list = Vec::new();
        let mut climb = |mut bl: Option<BlockId>| {
            while let Some(b) = bl.filter(|&b| marks.insert(b)) {
                block_list.push(b);
                bl = fd.blocks.block(b).idom;
            }
        };
        for &vn in worklist {
            let Some(def) = fd.vn(vn).def else { continue };
            let Some(bl) = fd.op(def).parent else { continue };
            if fd.op(def).opc == Opcode::Multiequal {
                for e in &fd.blocks.block(bl).ins {
                    climb(Some(e.point));
                }
            } else {
                climb(Some(bl));
            }
        }
        for &op in reads {
            climb(fd.op(op).parent);
        }
        let mut final_marks: HashSet<BlockId> = HashSet::new();
        for bl in block_list {
            for e in &fd.blocks.block(bl).ins {
                let split = fd.blocks.block(e.point);
                if final_marks.contains(&e.point) || split.outs.len() != 2 {
                    continue;
                }
                if let Some(&last) = split.ops.last().filter(|&&o| fd.op(o).opc == Opcode::Cbranch) {
                    final_marks.insert(e.point);
                    self.constraints_from_cbranch(fd, last)?;
                }
            }
        }
        Ok(())
    }

    /// `checkRelativeConstant`: the varnode is a relative set plus constants, through COPY,
    /// INDIRECT, INT_ADD and PTRSUB; its type code and offset
    fn check_relative_constant(&self, fd: &Funcdata, mut vn: VarnodeId) -> Option<(i32, u64)> {
        let mut value = 0u64;
        loop {
            if let Some(tc) = self.set_of.get(&vn).map(|&i| self.nodes[i].type_code).filter(|&tc| tc != 0) {
                return Some((tc, value));
            }
            let op = fd.op(fd.vn(vn).def?);
            match op.opc {
                Opcode::Copy | Opcode::Indirect => vn = op.ins[0],
                Opcode::IntAdd | Opcode::Ptrsub => {
                    let c = fd.vn(op.ins[1]);
                    if !c.is_constant() {
                        return None;
                    }
                    value = value.wrapping_add(c.offset) & calc_mask(c.size);
                    vn = op.ins[0];
                }
                _ => return None,
            }
        }
    }

    /// `generateRelativeConstraint`: a comparison against the stack pointer plus a constant
    fn generate_relative_constraint(&mut self, fd: &Funcdata, comp: OpId, cbranch: OpId) -> Result<()> {
        let opc = match fd.op(comp).opc {
            // an unsigned comparison of pointers is taken as signed relative to the base
            Opcode::IntLess => Opcode::IntSless,
            Opcode::IntLessequal => Opcode::IntSlessequal,
            o @ (Opcode::IntSless | Opcode::IntSlessequal | Opcode::IntEqual | Opcode::IntNotequal) => o,
            _ => return Ok(()),
        };
        let (in0, in1) = (fd.input(comp, 0)?, fd.input(comp, 1)?);
        let mut lift = CircleRange::boolean(true);
        let (vn, ty, value, slot) = if let Some((ty, value)) = self.check_relative_constant(fd, in0) {
            (in1, ty, value, 1)
        } else if let Some((ty, value)) = self.check_relative_constant(fd, in1) {
            (in0, ty, value, 0)
        } else {
            return Ok(());
        };
        if !lift.pull_back_binary(opc, value, slot, fd.vn(vn).size) {
            return Ok(());
        }
        let mut end = vn;
        while !self.set_of.contains_key(&end) {
            let Some(def) = fd.vn(end).def else { return Ok(()) };
            let op = fd.op(def);
            match op.opc {
                Opcode::Copy | Opcode::Ptrsub => {}
                Opcode::IntAdd if fd.vn(op.ins[1]).is_constant() => {}
                _ => return Ok(()),
            }
            end = op.ins[0];
        }
        self.constraints_from_path(fd, ty, lift, vn, end, cbranch)
    }

    /// Port of `ValueSetSolver::establishValueSets`: the sets of everything flowing into
    /// `sinks`, the reads of `reads`, the constraints and the iteration order.
    pub(crate) fn establish_value_sets(
        &mut self,
        fd: &Funcdata,
        sinks: &[VarnodeId],
        reads: &[OpId],
        stack_reg: Option<VarnodeId>,
        indirect_as_copy: bool,
    ) -> Result<()> {
        let mut worklist = Vec::new();
        let mut pos = 0;
        if let Some(sp) = stack_reg {
            let i = self.new_value_set(fd, sp, 1);
            worklist.push(sp);
            pos += 1;
            self.roots.push(i);
        }
        for &vn in sinks {
            self.new_value_set(fd, vn, 0);
            worklist.push(vn);
        }
        while pos < worklist.len() {
            let vn = worklist[pos];
            pos += 1;
            let i = self.set(vn)?;
            let v = fd.vn(vn);
            let Some(def) = v.def else {
                // a constant input of a binary op is picked up with the other input; a root
                // only as a spacebase constant (PTRSUB) or the input of a unary op
                let root = !v.is_constant() || v.has(VnFlags::SPACEBASE) || {
                    let Some(op) = lone_descend(fd, vn) else {
                        return err("value-set analysis: a constant without a lone reader");
                    };
                    fd.op(op).ins.len() == 1
                };
                if root {
                    self.roots.push(i);
                }
                continue;
            };
            let op = fd.op(def);
            match op.opc {
                Opcode::Indirect if indirect_as_copy || op.flags.has(OpFlags::INDIRECT_STORE) => {
                    let inp = op.ins[0];
                    if !self.set_of.contains_key(&inp) {
                        self.new_value_set(fd, inp, 0);
                        worklist.push(inp);
                    }
                }
                // ops whose result has no predictable range
                Opcode::Indirect
                | Opcode::Call
                | Opcode::Callind
                | Opcode::Callother
                | Opcode::Load
                | Opcode::New
                | Opcode::Segmentop
                | Opcode::Cpoolref
                | Opcode::FloatAdd
                | Opcode::FloatDiv
                | Opcode::FloatMult
                | Opcode::FloatSub
                | Opcode::FloatNeg
                | Opcode::FloatAbs
                | Opcode::FloatSqrt
                | Opcode::FloatInt2float
                | Opcode::FloatFloat2float
                | Opcode::FloatTrunc
                | Opcode::FloatCeil
                | Opcode::FloatFloor
                | Opcode::FloatRound => {
                    self.nodes[i].set_full(fd);
                    self.roots.push(i);
                }
                _ => {
                    for &inp in &op.ins {
                        if self.set_of.contains_key(&inp) || fd.vn(inp).is_annotation() {
                            continue;
                        }
                        self.new_value_set(fd, inp, 0);
                        worklist.push(inp);
                    }
                }
            }
        }
        for &op in reads {
            // only one read of an op
            if let Some(slot) = fd.op(op).ins.iter().position(|v| self.set_of.contains_key(v)) {
                let empty = CircleRange::default();
                self.reads.insert(
                    op,
                    ValueSetRead {
                        type_code: 0,
                        slot,
                        range: empty,
                        equation_constraint: empty,
                        equation_type_code: -1,
                        left_is_stable: false,
                        right_is_stable: false,
                    },
                );
            }
        }
        self.generate_constraints(fd, &worklist, reads)?;
        self.establish_topological_order(fd);
        Ok(())
    }

    /// Port of `ValueSetSolver::solve`: iterate the sets in order, each component until it is
    /// stable, at most `max` iterations; then the reads.
    pub(crate) fn solve(&mut self, fd: &Funcdata, max: u32, widener: Widener) -> Result<()> {
        for s in &mut self.nodes {
            s.count = 0;
        }
        let mut num_iterations = 0;
        let mut stack: Vec<usize> = Vec::new();
        let mut cur_comp: Option<usize> = None;
        let mut cur_set = self.order_start;
        while let Some(cur) = cur_set {
            num_iterations += 1;
            if num_iterations > max {
                break;
            }
            if let Some(head) = self.nodes[cur].part_head.filter(|&h| Some(h) != cur_comp) {
                stack.push(head);
                cur_comp = Some(head);
                self.parts[head].is_dirty = false;
                // the component's counter is reset on entry
                if let Some(start) = self.parts[head].start {
                    self.nodes[start].count = widener.iteration_reset(self.nodes[start].count);
                }
            }
            let Some(mut comp) = cur_comp else {
                self.iterate(fd, cur, widener)?;
                cur_set = self.nodes[cur].next;
                continue;
            };
            if self.iterate(fd, cur, widener)? {
                self.parts[comp].is_dirty = true;
            }
            if self.parts[comp].stop != Some(cur) {
                cur_set = self.nodes[cur].next;
                continue;
            }
            loop {
                if self.parts[comp].is_dirty {
                    self.parts[comp].is_dirty = false;
                    cur_set = self.parts[comp].start;
                    if stack.len() > 1 {
                        // restarting a dirty child makes its parent dirty
                        let parent = stack[stack.len() - 2];
                        self.parts[parent].is_dirty = true;
                    }
                    break;
                }
                stack.pop();
                let Some(&parent) = stack.last() else {
                    cur_comp = None;
                    cur_set = self.nodes[cur].next;
                    break;
                };
                comp = parent;
                cur_comp = Some(parent);
                if self.parts[comp].stop != Some(cur) {
                    cur_set = self.nodes[cur].next;
                    break;
                }
            }
        }
        // ValueSetRead::compute
        let ops: Vec<OpId> = self.reads.keys().copied().collect();
        for op in ops {
            let slot = self.reads[&op].slot;
            let s = &self.nodes[self.set(fd.input(op, slot)?)?];
            let (tc, range, l, r) = (s.type_code, s.range, s.left_is_stable, s.right_is_stable);
            if let Some(read) = self.reads.get_mut(&op) {
                read.type_code = tc;
                read.range =
                    if tc == read.equation_type_code { constrain(range, &read.equation_constraint) } else { range };
                (read.left_is_stable, read.right_is_stable) = (l, r);
            }
        }
        Ok(())
    }

    /// `getValueSetRead`: the values `op` reads, if it reads a varnode of the system
    pub(crate) fn value_set_read(&self, op: OpId) -> Option<&ValueSetRead> {
        self.reads.get(&op)
    }
}
