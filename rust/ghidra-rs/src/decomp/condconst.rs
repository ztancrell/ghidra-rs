//! `ActionConditionalConst` (coreaction.cc): a variable compared with a constant by a CBRANCH is
//! that constant down the branch where the comparison holds, so its reads there are replaced by
//! the constant.

use super::block::BlockId;
use super::emulate::{eval_binary, eval_unary, EmuError};
use super::merge::dominates;
use super::op::{OpFlags, OpId};
use super::opcode::Opcode;
use super::rangeutil::calc_mask;
use super::varnode::{Space, VarnodeId, VnFlags};
use super::{err, Arch, Funcdata, Result};
use std::collections::{HashSet, VecDeque};

/// Port of `ActionConditionalConst::ConstPoint`.
#[derive(Debug, Clone, Copy)]
struct ConstPoint {
    vn: VarnodeId,
    /// the representative of the constant, if there is one
    const_vn: Option<VarnodeId>,
    value: u64,
    /// the block dominating the reads where `vn` is the constant
    const_block: BlockId,
    /// the input edge of `const_block` from the condition block
    in_slot: usize,
    block_is_dom: bool,
}

/// A `PcodeOpNode`: an op and one of its input slots.
type Edge = (OpId, usize);

/// `Varnode::loneDescend`.
pub(crate) fn lone_descend(fd: &Funcdata, vn: VarnodeId) -> Option<OpId> {
    match fd.vn(vn).descend[..] {
        [op] => Some(op),
        _ => None,
    }
}

/// Port of `FlowBlock::restrictedByConditional`: every path into `bl` comes through its edge
/// from `cond`.
pub(crate) fn restricted_by_conditional(fd: &Funcdata, bl: BlockId, cond: BlockId) -> Result<bool> {
    let b = fd.blocks.block(bl);
    if b.ins.len() == 1 {
        return Ok(true);
    }
    if b.idom != Some(cond) {
        return Ok(false);
    }
    let mut seen_cond = false;
    for e in &b.ins {
        let mut inb = e.point;
        if inb == cond {
            if seen_cond {
                return Ok(false);
            }
            seen_cond = true;
            continue;
        }
        while inb != bl {
            if inb == cond {
                return Ok(false);
            }
            let Some(d) = fd.blocks.block(inb).idom else {
                return err("ActionConditionalConst: restrictedByConditional left the dominator tree");
            };
            inb = d;
        }
    }
    Ok(true)
}

/// Port of `ActionConditionalConst::collectReachable`: the MULTIEQUAL, COPY and INDIRECT ops
/// `vn` flows to without crossing the excised edges (sorted here, as in the C++).
fn collect_reachable(fd: &Funcdata, mut vn: VarnodeId, edges: &mut [Edge]) -> (Vec<OpId>, HashSet<OpId>) {
    edges.sort_by_key(|&(op, slot)| (fd.op(op).seq.time, slot));
    let mut reachable = Vec::new();
    let mut marks = HashSet::new();
    if let Some(d) = fd.vn(vn).def {
        if fd.op(d).opc == Opcode::Multiequal {
            marks.insert(d);
            reachable.push(d);
        }
    }
    let mut count = 0;
    loop {
        for &op in fd.vn(vn).descend.iter() {
            if marks.contains(&op) {
                continue;
            }
            match fd.op(op).opc {
                Opcode::Multiequal => {
                    // not reached when every slot reading `vn` is an excised edge
                    let ins = &fd.op(op).ins;
                    if (0..ins.len()).all(|slot| ins[slot] != vn || edges.contains(&(op, slot))) {
                        continue;
                    }
                }
                Opcode::Copy | Opcode::Indirect => {}
                _ => continue,
            }
            reachable.push(op);
            marks.insert(op);
        }
        let Some(&next) = reachable.get(count) else { break };
        let Some(out) = fd.op(next).out else { break };
        vn = out;
        count += 1;
    }
    (reachable, marks)
}

/// Port of `ActionConditionalConst::flowToAlternatePath`: the output of `op` flows to a marked
/// MULTIEQUAL.
fn flow_to_alternate_path(fd: &Funcdata, op: OpId, marks: &HashSet<OpId>) -> bool {
    if marks.contains(&op) {
        return true;
    }
    let Some(out) = fd.op(op).out else { return false };
    let mut mark_set = vec![out];
    let mut seen: HashSet<VarnodeId> = HashSet::from([out]);
    let mut count = 0;
    while count < mark_set.len() {
        let vn = mark_set[count];
        count += 1;
        for &next in fd.vn(vn).descend.iter() {
            match fd.op(next).opc {
                Opcode::Multiequal => {
                    if marks.contains(&next) {
                        return true;
                    }
                }
                Opcode::Copy | Opcode::Indirect => {}
                _ => continue,
            }
            if let Some(o) = fd.op(next).out {
                if seen.insert(o) {
                    mark_set.push(o);
                }
            }
        }
    }
    false
}

/// Port of `ActionConditionalConst::flowTogether`.
fn flow_together(fd: &Funcdata, edges: &[Edge], i: usize, result: &mut [i32]) -> bool {
    let Some(out) = fd.op(edges[i].0).out else { return false };
    let (_, marks) = collect_reachable(fd, out, &mut []);
    let mut res = false;
    for j in 0..edges.len() {
        if i == j || result[j] == 0 {
            continue;
        }
        if marks.contains(&edges[j].0) {
            result[i] = 2;
            result[j] = 2;
            res = true;
        }
    }
    res
}

/// Port of `ActionConditionalConst::placeCopy`: a COPY of the constant at the end of `bl`
/// (before its branch); its output.
fn place_copy(fd: &mut Funcdata, op: OpId, bl: BlockId, const_vn: VarnodeId) -> Result<VarnodeId> {
    let ops = &fd.blocks.block(bl).ops;
    let (at, addr) = match ops.last() {
        None => (0, fd.op(op).seq.addr),
        Some(&last) if fd.op(last).is_branch() => (ops.len() - 1, fd.op(last).seq.addr),
        Some(&last) => (ops.len(), fd.op(last).seq.addr),
    };
    let Some(uniq) = fd.uniq else { return err("ActionConditionalConst: no unique space") };
    let copy = fd.new_op(Opcode::Copy, addr);
    let out = fd.new_unique_out(fd.vn(const_vn).size, uniq, copy);
    fd.op_set_all_input(copy, &[const_vn])?;
    fd.op_insert(copy, bl, at);
    Ok(out)
}

/// Port of `FlowBlock::findCommonBlock` over a set.
fn find_common_block(fd: &Funcdata, set: &[BlockId]) -> BlockId {
    let mut res = set[0];
    let mut best = fd.blocks.block(res).index;
    let mut marked = HashSet::new();
    let mut bl = Some(res);
    while let Some(b) = bl {
        marked.insert(b);
        bl = fd.blocks.block(b).idom;
    }
    for &start in &set[1..] {
        if best == 0 {
            break;
        }
        let mut b = start;
        while marked.insert(b) {
            match fd.blocks.block(b).idom {
                Some(d) => b = d,
                None => break,
            }
        }
        if fd.blocks.block(b).index < best {
            res = b;
            best = fd.blocks.block(b).index;
        }
    }
    res
}

/// Port of `ActionConditionalConst::placeMultipleConstants`.
fn place_multiple_constants(fd: &mut Funcdata, edges: &[Edge], marks: &[i32], const_vn: VarnodeId) -> Result<()> {
    let together: Vec<Edge> = edges.iter().zip(marks).filter(|&(_, &m)| m == 2).map(|(&e, _)| e).collect();
    let mut blocks = Vec::new();
    for &(op, slot) in &together {
        let Some(parent) = fd.op(op).parent else { return err("ActionConditionalConst: a dead MULTIEQUAL") };
        blocks.push(fd.blocks.block(parent).ins[slot].point);
    }
    let Some(&(last, _)) = together.last() else { return Ok(()) };
    let root = find_common_block(fd, &blocks);
    let out = place_copy(fd, last, root, const_vn)?;
    for (op, slot) in together {
        fd.op_set_input(op, out, slot)?;
    }
    Ok(())
}

/// `PcodeOp::executeSimple` on the ops `pushConstant` lets through. The C++ catches an
/// `EvaluationError` (a division by zero: no new point); an op emulate.rs does not evaluate
/// fails loudly.
fn execute_simple(fd: &Funcdata, op: OpId, ins: &[u64]) -> Result<Option<u64>> {
    let o = fd.op(op);
    let (Some(out), Some(&in0)) = (o.out, o.ins.first()) else { return Ok(None) };
    let (sizeout, sizein) = (fd.vn(out).size, fd.vn(in0).size);
    let r = match (o.opc, ins) {
        // OpBehaviorPtrsub, OpBehaviorPtradd
        (Opcode::Ptrsub, &[a, b]) => Ok(a.wrapping_add(b) & calc_mask(sizeout)),
        (Opcode::Ptradd, &[a, b, c]) => Ok(a.wrapping_add(b.wrapping_mul(c)) & calc_mask(sizeout)),
        (opc, &[a]) => eval_unary(opc, sizeout, sizein, a),
        (opc, &[a, b]) => eval_binary(opc, sizeout, sizein, a, b),
        (opc, _) => return err(format!("ActionConditionalConst: evaluating {opc:?} is not ported")),
    };
    match r {
        Ok(v) => Ok(Some(v)),
        Err(EmuError::Other(m)) if m == "Divide by 0" => Ok(None),
        Err(_) => err(format!("ActionConditionalConst: evaluating {:?} is not ported", o.opc)),
    }
}

/// Port of `ActionConditionalConst::pushConstant`: an op whose other inputs are constants gives
/// a new constant point for its output.
fn push_constant(fd: &Funcdata, points: &mut VecDeque<ConstPoint>, front: &ConstPoint, op: OpId) -> Result<()> {
    let o = fd.op(op);
    // getEvalType() & special (CAST is unary and special)
    let ternary = matches!(o.opc, Opcode::Ptradd | Opcode::Insert | Opcode::Zpull | Opcode::Spull);
    if (!o.opc.is_unary_or_binary() && !ternary) || o.opc == Opcode::Cast {
        return Ok(());
    }
    if super::rules::is_floating_point_op(o.opc) {
        return Ok(());
    }
    let Some(out) = o.out else { return Ok(()) };
    if fd.vn(out).size > 8 {
        return Ok(());
    }
    let slot = fd.slot_of(op, front.vn);
    let mut ins = Vec::with_capacity(o.ins.len());
    for (i, &v) in o.ins.iter().enumerate() {
        if Some(i) == slot {
            ins.push(front.value);
            continue;
        }
        let inv = fd.vn(v);
        if inv.size > 8 || !inv.is_constant() {
            return Ok(());
        }
        ins.push(inv.offset);
    }
    if let Some(value) = execute_simple(fd, op, &ins)? {
        points.push_back(ConstPoint { vn: out, const_vn: None, value, ..*front });
    }
    Ok(())
}

/// Port of `ActionConditionalConst::handlePhiNodes`: the MULTIEQUAL edges the constant reaches
/// get a COPY of the constant where that makes a new variable of it. Returns the change count.
fn handle_phi_nodes(fd: &mut Funcdata, var_vn: VarnodeId, const_vn: VarnodeId, edges: &mut [Edge]) -> Result<i32> {
    let mut results = vec![0; edges.len()];
    let (_, marks) = collect_reachable(fd, var_vn, edges);
    let mut alternate = 0;
    for (i, &(op, _)) in edges.iter().enumerate() {
        if !flow_to_alternate_path(fd, op, &marks) {
            results[i] = 1;
            alternate += 1;
        }
    }
    let mut has_flow_together = false;
    if alternate > 1 {
        for i in 0..results.len() {
            if results[i] != 0 && flow_together(fd, edges, i, &mut results) {
                has_flow_together = true;
            }
        }
    }
    let mut count = 0;
    for (i, &(op, slot)) in edges.iter().enumerate() {
        if results[i] != 1 {
            continue;
        }
        let Some(parent) = fd.op(op).parent else { return err("ActionConditionalConst: a dead MULTIEQUAL") };
        let bl = fd.blocks.block(parent).ins[slot].point;
        let out = place_copy(fd, op, bl, const_vn)?;
        fd.op_set_input(op, out, slot)?;
        count += 1;
    }
    if has_flow_together {
        place_multiple_constants(fd, edges, &results, const_vn)?;
        count += 1;
    }
    Ok(count)
}

/// Port of `ActionConditionalConst::testAlternatePath`.
fn test_alternate_path(fd: &Funcdata, vn: VarnodeId, op: OpId, slot: Option<usize>, depth: i32) -> bool {
    for (i, &inv) in fd.op(op).ins.iter().enumerate() {
        if Some(i) == slot {
            continue;
        }
        if inv == vn {
            return true;
        }
        let Some(cur) = fd.vn(inv).def else { continue };
        let c = fd.op(cur);
        match c.opc {
            Opcode::IntAdd | Opcode::Ptrsub | Opcode::Ptradd if c.ins[0] == vn || c.ins[1] == vn => return true,
            Opcode::Multiequal if depth != 0 && test_alternate_path(fd, vn, cur, None, depth - 1) => return true,
            _ => {}
        }
    }
    false
}

/// `Varnode::getAddr`.
fn addr(fd: &Funcdata, vn: VarnodeId) -> (Space, u64) {
    (fd.vn(vn).space, fd.vn(vn).offset)
}

/// Port of `ActionConditionalConst::propagateConstant`. Returns the change count.
fn propagate_constant(fd: &mut Funcdata, points: &mut VecDeque<ConstPoint>, use_multiequal: bool) -> Result<i32> {
    let mut count = 0;
    let mut phi_edges: Vec<Edge> = Vec::new();
    while let Some(&point) = points.front() {
        let var_vn = point.vn;
        let mut const_vn = point.const_vn;
        let const_block = point.const_block;
        // the descend list as it is now: an op is visited once per run of its entries, and its
        // entries go as its inputs are replaced
        let descend: Vec<OpId> = fd.vn(var_vn).descend.to_vec();
        let mut prev = None;
        for op in descend {
            if prev == Some(op) || fd.slot_of(op, var_vn).is_none() {
                continue;
            }
            prev = Some(op);
            let opc = fd.op(op).opc;
            let Some(parent) = fd.op(op).parent else { continue };
            match opc {
                Opcode::Indirect => continue,
                Opcode::Multiequal => {
                    if !use_multiequal {
                        continue;
                    }
                    let Some(out) = fd.op(op).out else { continue };
                    if fd.vn(var_vn).has(VnFlags::ADDRTIED) && addr(fd, var_vn) == addr(fd, out) {
                        continue;
                    }
                    if parent == const_block {
                        if fd.op(op).ins.get(point.in_slot) == Some(&var_vn) {
                            if point.value > 1
                                || fd.vn(out).has(VnFlags::ADDRTIED)
                                || test_alternate_path(fd, var_vn, op, Some(point.in_slot), 2)
                            {
                                continue;
                            }
                            phi_edges.push((op, point.in_slot));
                        }
                    } else if point.block_is_dom {
                        for slot in 0..fd.op(op).ins.len() {
                            if fd.op(op).ins[slot] == var_vn
                                && dominates(fd, const_block, Some(fd.blocks.block(parent).ins[slot].point))
                            {
                                phi_edges.push((op, slot));
                            }
                        }
                    }
                    continue;
                }
                Opcode::Copy => {
                    // not into a COPY unless it feeds something more interesting
                    let follow = fd.op(op).out.and_then(|o| lone_descend(fd, o));
                    match follow {
                        Some(f) if !fd.op(f).is_marker() && fd.op(f).opc != Opcode::Copy => {}
                        _ => continue,
                    }
                }
                _ => {}
            }
            if !point.block_is_dom {
                continue;
            }
            if dominates(fd, const_block, Some(parent)) {
                let c = match const_vn {
                    Some(c) => c,
                    None => fd.new_constant(fd.vn(var_vn).size, point.value),
                };
                const_vn = Some(c);
                if opc == Opcode::Return {
                    // a RETURN cannot take a constant directly
                    let copy = fd.new_op(Opcode::Copy, fd.op(op).seq.addr);
                    fd.op_set_all_input(copy, &[c])?;
                    let v = fd.vn(var_vn);
                    let (size, space, offset) = (v.size, v.space, v.offset);
                    let out = fd.new_varnode_out(size, space, offset, copy);
                    fd.op_set_input(op, out, 1)?;
                    fd.op_insert_before(copy, op)?;
                } else if let Some(slot) = fd.slot_of(op, var_vn) {
                    fd.op_set_input(op, c, slot)?;
                }
                count += 1;
            } else {
                push_constant(fd, points, &point, op)?;
            }
        }
        if !phi_edges.is_empty() {
            let c = match const_vn {
                Some(c) => c,
                None => fd.new_constant(fd.vn(var_vn).size, point.value),
            };
            count += handle_phi_nodes(fd, var_vn, c, &mut phi_edges)?;
            phi_edges.clear();
        }
        points.pop_front();
    }
    Ok(count)
}

/// Port of `ActionConditionalConst::findConstCompare`: the CBRANCH tests a variable against a
/// constant.
fn find_const_compare(
    fd: &Funcdata,
    points: &mut VecDeque<ConstPoint>,
    mut bool_vn: VarnodeId,
    bl: BlockId,
    block_dom: [bool; 2],
    mut flip_edge: bool,
) {
    let Some(mut comp) = fd.vn(bool_vn).def else { return };
    if fd.op(comp).opc == Opcode::BoolNegate {
        flip_edge = !flip_edge;
        bool_vn = fd.op(comp).ins[0];
        let Some(d) = fd.vn(bool_vn).def else { return };
        comp = d;
    }
    let mut const_edge = match fd.op(comp).opc {
        Opcode::IntEqual => 1,
        Opcode::IntNotequal => 0,
        _ => return,
    };
    let (mut var_vn, mut const_vn) = (fd.op(comp).ins[0], fd.op(comp).ins[1]);
    if !fd.vn(const_vn).is_constant() {
        if !fd.vn(var_vn).is_constant() {
            return;
        }
        std::mem::swap(&mut var_vn, &mut const_vn);
    }
    if lone_descend(fd, var_vn).is_some() {
        return;
    }
    if flip_edge {
        const_edge = 1 - const_edge;
    }
    let e = fd.blocks.block(bl).outs[const_edge];
    points.push_back(ConstPoint {
        vn: var_vn,
        const_vn: Some(const_vn),
        value: fd.vn(const_vn).offset,
        const_block: e.point,
        in_slot: e.reverse,
        block_is_dom: block_dom[const_edge],
    });
}

/// Port of `ActionConditionalConst::apply`.
pub(crate) fn conditional_const(fd: &mut Funcdata, arch: &Arch) -> Result<i32> {
    // not into MULTIEQUALs before the stack is heritaged (`numHeritagePasses(stackSpace) <= 0`)
    let use_multiequal =
        super::heritage::space_delay(arch, Space::Stack).is_none_or(|delay| fd.heritage.pass() - delay > 0);
    let mut count = 0;
    let mut points = VecDeque::new();
    for bl in fd.blocks.list.clone() {
        let b = fd.blocks.block(bl);
        let Some(&cbranch) = b.ops.last() else { continue };
        if fd.op(cbranch).opc != Opcode::Cbranch || b.outs.len() != 2 {
            continue;
        }
        let bool_vn = fd.op(cbranch).ins[1];
        let (out0, out1) = (b.outs[0], b.outs[1]);
        let block_dom =
            [restricted_by_conditional(fd, out0.point, bl)?, restricted_by_conditional(fd, out1.point, bl)?];
        let flip_edge = fd.op(cbranch).flags.has(OpFlags::BOOLEAN_FLIP);
        if lone_descend(fd, bool_vn).is_none() {
            // the boolean itself is 0 down the false branch and 1 down the true branch
            for (e, value, dom) in
                [(out0, u64::from(flip_edge), block_dom[0]), (out1, u64::from(!flip_edge), block_dom[1])]
            {
                points.push_back(ConstPoint {
                    vn: bool_vn,
                    const_vn: None,
                    value,
                    const_block: e.point,
                    in_slot: e.reverse,
                    block_is_dom: dom,
                });
            }
        }
        find_const_compare(fd, &mut points, bool_vn, bl, block_dom, flip_edge);
        count += propagate_constant(fd, &mut points, use_multiequal)?;
    }
    Ok(count)
}
