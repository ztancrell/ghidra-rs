//! Port of `ActionFinalStructure` (blockaction.cc) and the parts of block.cc it runs on the
//! structured hierarchy: `BlockGraph::orderBlocks` (`compareFinalOrder`), `finalizePrinting`
//! (`BlockWhileDo::testTerminal`/`testIterateForm` with `Funcdata::moveRespectingCover` and
//! `HighVariable::markExpression`; `BlockSwitch::finalizePrinting` with `grabCaseBasic`/`addCase`
//! and `CaseOrder::compare`), `scopeBreak`, `markUnstructured` (`markCopyBlock`) and
//! `markLabelBumpUp`, each per block kind.
//!
//! The C++ recursions over the hierarchy are work lists here (deep nesting is input-reachable).
//! The case labels come from the jump table (`JumpTable::recoverLabels`, action `switchnorm`,
//! jumptable.rs). With `switchnorm` off a switch with cases fails loudly in `finalizePrinting`
//! (the reference reads an empty label table there).

use std::collections::HashSet;

use super::block::BlockId;
use super::funcdata::JumpTable;
use super::op::{OpFlags, OpId};
use super::opcode::Opcode;
use super::returnsplit::{front_leaf, goto_prints};
use super::structure::{Kind, SId, Structure, ROOT};
use super::variable::{high, HighId};
use super::varnode::{VarnodeId, VnFlags};
use super::{err, Arch, Funcdata, LowlevelError, Result};

/// `FlowBlock::f_goto_goto`: an unstructured branch.
pub(crate) const F_GOTO_GOTO: u32 = 1;
/// `FlowBlock::f_break_goto`: the branch is a `break`.
pub(crate) const F_BREAK_GOTO: u32 = 2;
/// `FlowBlock::f_unstructured_targ`: the target of an unstructured goto.
pub(crate) const F_UNSTRUCTURED_TARG: u32 = 0x20;
/// `FlowBlock::f_label_bumpup`: the block's label is printed higher up.
pub(crate) const F_LABEL_BUMPUP: u32 = 0x1000;

/// Port of `BlockSwitch::CaseOrder`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CaseOrder {
    /// the structured case block
    pub(crate) block: SId,
    /// the first basic block the case executes (set by `finalizePrinting` here)
    pub(crate) basicblock: Option<BlockId>,
    pub(crate) label: u64,
    pub(crate) depth: i32,
    /// the case it falls through to (an index into the case list)
    pub(crate) chain: Option<usize>,
    /// the switch block's out edge to the case
    pub(crate) outindex: usize,
    /// 0, or the kind of unstructured branch the case is
    pub(crate) gototype: u32,
    pub(crate) isexit: bool,
    pub(crate) isdefault: bool,
}

impl CaseOrder {
    fn new(block: SId, gototype: u32, isexit: bool) -> CaseOrder {
        CaseOrder {
            block,
            basicblock: None,
            label: 0,
            depth: 0,
            chain: None,
            outindex: 0,
            gototype,
            isexit,
            isdefault: false,
        }
    }
}

/// The part of `BlockSwitch::grabCaseBasic` (with `addCase`) that reads the hierarchy, run by
/// `newBlockSwitch` before `identifyInternal` moves the cases' out edges: each case component
/// of `cs` (`cs[0]` is the switch), then each goto edge of a multi-goto switch component.
pub(crate) fn grab_cases(s: &Structure, cs: &[SId]) -> Vec<CaseOrder> {
    let mut cases: Vec<CaseOrder> = cs.iter().skip(1).map(|&b| CaseOrder::new(b, 0, s.size_out(b) == 1)).collect();
    if let Some(Kind::MultiGoto { gotos, .. }) = cs.first().map(|&b| &s.b(b).kind) {
        cases.extend(gotos.iter().map(|&g| CaseOrder::new(g, F_GOTO_GOTO, false)));
    }
    cases
}

/// Port of `ActionFinalStructure::apply`.
pub(crate) fn final_structure(fd: &mut Funcdata, _: &Arch) -> Result<i32> {
    let mut s = std::mem::take(&mut fd.structure);
    let res = finalize_hierarchy(&mut s, fd);
    fd.structure = s;
    res.map(|()| 0)
}

/// The steps of `ActionFinalStructure::apply` on a structured hierarchy.
pub(crate) fn finalize_hierarchy(s: &mut Structure, fd: &mut Funcdata) -> Result<()> {
    if s.blocks.is_empty() {
        return Ok(());
    }
    order_blocks(s, fd);
    finalize_printing(s, fd)?;
    scope_break(s);
    mark_unstructured(s);
    mark_label_bump_up(s);
    Ok(())
}

/// Port of `FlowBlock::compareFinalOrder`: the entry block first, RETURN blocks last, the rest
/// by index. Not a strict order (the entry block is below itself, two RETURN blocks are
/// equal), so the result depends on the sort algorithm.
fn compare_final_order(s: &Structure, fd: &Funcdata, bl1: SId, bl2: SId) -> bool {
    if s.b(bl1).index == 0 {
        return true;
    }
    if s.b(bl2).index == 0 {
        return false;
    }
    let is_return = |b| s.last_op(fd, b).map(|op| fd.op(op).opc == Opcode::Return);
    match (is_return(bl1), is_return(bl2)) {
        (Some(true), _) => return false,
        (Some(false) | None, Some(true)) => return true,
        _ => {}
    }
    s.b(bl1).index < s.b(bl2).index
}

/// `BlockGraph::orderBlocks` on the root, with the C++ `std::sort`.
fn order_blocks(s: &mut Structure, fd: &Funcdata) {
    if s.b(ROOT).list.len() == 1 {
        return;
    }
    let mut list = std::mem::take(&mut s.bm(ROOT).list);
    super::stdsort::sort(&mut list, |&a, &b| compare_final_order(s, fd, a, b));
    s.bm(ROOT).list = list;
}

/// The blocks below `ROOT` in the order of the C++ `finalizePrinting` recursion: each graph's
/// components first, in order, then the graph.
fn post_order(s: &Structure) -> Vec<SId> {
    let mut order = Vec::new();
    let mut stack = vec![(ROOT, false)];
    while let Some((b, done)) = stack.pop() {
        if done {
            order.push(b);
            continue;
        }
        stack.push((b, true));
        stack.extend(s.b(b).list.iter().rev().map(|&c| (c, false)));
    }
    order
}

/// `BlockGraph::finalizePrinting`, recursing; while-do and switch blocks do their own part.
fn finalize_printing(s: &mut Structure, fd: &mut Funcdata) -> Result<()> {
    for b in post_order(s) {
        match s.b(b).kind {
            Kind::WhileDo => finalize_while_do(s, fd, b)?,
            Kind::Switch => finalize_switch(s, fd, b)?,
            _ => {}
        }
    }
    Ok(())
}

/// `PcodeOp::notPrinted`: a marker, a non-printing op (no op carries `noreturn` here).
fn not_printed(fd: &Funcdata, op: OpId) -> bool {
    let o = fd.op(op);
    o.is_marker() || o.flags.has(OpFlags::NONPRINTING)
}

fn is_explicit(fd: &Funcdata, vn: VarnodeId) -> bool {
    fd.vn(vn).has(VnFlags::EXPLICIT)
}

/// `PcodeOp::nextOp`: the op after `op` in its block.
fn next_op(fd: &Funcdata, op: OpId) -> Option<OpId> {
    let ops = &fd.blocks.block(fd.op(op).parent?).ops;
    let i = ops.iter().position(|&o| o == op)?;
    ops.get(i + 1).copied()
}

/// Port of `BlockWhileDo::finalizePrinting`: the for-loop ops `finalTransform` found must be
/// terminal explicit statements reading the loop variable, else the loop prints as a while.
fn finalize_while_do(s: &mut Structure, fd: &mut Funcdata, b: SId) -> Result<()> {
    let fl = s.b(b).for_loop;
    let (Some(iterate), Some(loop_def)) = (fl.iterate, fl.loop_def) else { return Ok(()) };
    let parent = fd.op(iterate).parent.ok_or_else(|| LowlevelError("for-loop iterate op is dead".into()))?;
    let slot = fd
        .blocks
        .block(parent)
        .outs
        .first()
        .ok_or_else(|| LowlevelError("for-loop tail has no out edge".into()))?
        .reverse;
    let iterate = test_terminal(fd, loop_def, slot)?;
    s.bm(b).for_loop.iterate = iterate;
    let Some(iterate) = iterate else { return Ok(()) };
    if !test_iterate_form(fd, loop_def, iterate)? {
        s.bm(b).for_loop.iterate = None;
        return Ok(());
    }
    let mut initialize = fl.initialize;
    if initialize.is_none() {
        let head = fd.op(loop_def).parent.ok_or_else(|| LowlevelError("loop MULTIEQUAL is dead".into()))?;
        initialize = super::blocktransform::find_initializer(fd, head, slot, loop_def).map(|(res, _)| res);
    }
    if initialize.is_some() {
        let other = 1usize
            .checked_sub(slot)
            .ok_or_else(|| LowlevelError("for-loop head with more than two in edges".into()))?;
        initialize = test_terminal(fd, loop_def, other)?;
    }
    s.bm(b).for_loop.initialize = initialize;
    fd.op_mut(iterate).flags.set(OpFlags::NONPRINTING); // opMarkNonPrinting
    if let Some(init) = initialize {
        fd.op_mut(init).flags.set(OpFlags::NONPRINTING);
    }
    Ok(())
}

/// Port of `BlockWhileDo::testTerminal`: the root of the statement writing input `slot` of the
/// loop MULTIEQUAL, if it is explicit, printed and (perhaps after a move) last in its block.
fn test_terminal(fd: &mut Funcdata, loop_def: OpId, slot: usize) -> Result<Option<OpId>> {
    let mut vn = fd.input(loop_def, slot)?;
    let Some(final_op) = fd.vn(vn).def else { return Ok(None) };
    let head = fd.op(loop_def).parent.ok_or_else(|| LowlevelError("loop MULTIEQUAL is dead".into()))?;
    let parent_block = fd.blocks.block(head).ins.get(slot).map(|e| e.point);
    let mut res_op = final_op;
    if fd.op(final_op).opc == Opcode::Copy && not_printed(fd, final_op) {
        vn = fd.input(final_op, 0)?;
        let Some(def) = fd.vn(vn).def else { return Ok(None) };
        res_op = def;
        if fd.op(res_op).parent != parent_block {
            return Ok(None);
        }
    }
    if !is_explicit(fd, vn) || not_printed(fd, res_op) {
        return Ok(None);
    }
    let block = fd.op(final_op).parent.ok_or_else(|| LowlevelError("for-loop op is dead".into()))?;
    let Some(mut last) = fd.blocks.block(block).ops.last().copied() else { return Ok(None) };
    if fd.op(last).is_branch() {
        last = fd.previous_op(last).ok_or_else(|| LowlevelError("no op before the loop branch".into()))?;
    }
    Ok(move_respecting_cover(fd, final_op, last)?.then_some(res_op))
}

/// Port of `BlockWhileDo::testIterateForm`: the loop variable feeds the iterate statement
/// (walking its expression, stopping at explicit varnodes).
fn test_iterate_form(fd: &mut Funcdata, loop_def: OpId, iterate: OpId) -> Result<bool> {
    let target = fd.op(loop_def).out.ok_or_else(|| LowlevelError("loop MULTIEQUAL has no output".into()))?;
    let h = high(fd, target)?;
    let mut path = vec![(iterate, 0usize)];
    while let Some(&mut (op, ref mut slot)) = path.last_mut() {
        let Some(&vn) = fd.op(op).ins.get(*slot) else {
            path.pop();
            continue;
        };
        *slot += 1;
        if fd.vn(vn).is_annotation() {
            continue;
        }
        if high(fd, vn)? == h {
            return Ok(true);
        }
        if is_explicit(fd, vn) {
            continue;
        }
        if let Some(def) = fd.vn(vn).def {
            path.push((def, 0));
        }
    }
    Ok(false)
}

/// Port of `HighVariable::markExpression`: the highs of `vn` and of the explicit varnodes its
/// expression reads, and whether the expression holds a call (1) or a LOAD (2).
fn mark_expression(fd: &mut Funcdata, vn: VarnodeId) -> Result<(HashSet<HighId>, u32)> {
    let mut marks = HashSet::from([high(fd, vn)?]);
    let mut ret = 0;
    let Some(op) = fd.vn(vn).def else { return Ok((marks, ret)) };
    let kind =
        |fd: &Funcdata, op: OpId| u32::from(fd.op(op).is_call()) | (u32::from(fd.op(op).opc == Opcode::Load) << 1);
    ret |= kind(fd, op);
    let mut path = vec![(op, 0usize)];
    while let Some(&mut (op, ref mut slot)) = path.last_mut() {
        let Some(&cur) = fd.op(op).ins.get(*slot) else {
            path.pop();
            continue;
        };
        *slot += 1;
        if fd.vn(cur).is_annotation() {
            continue;
        }
        if is_explicit(fd, cur) {
            marks.insert(high(fd, cur)?);
            continue;
        }
        if let Some(def) = fd.vn(cur).def {
            ret |= kind(fd, def);
            path.push((def, 0));
        }
    }
    Ok((marks, ret))
}

/// Port of `Funcdata::moveRespectingCover`: move `op` (with the op feeding it, for an implied
/// CAST) after `last` if only COPYs and CASTs that cannot interfere lie between.
fn move_respecting_cover(fd: &mut Funcdata, op: OpId, last: OpId) -> Result<bool> {
    if op == last {
        return Ok(true);
    }
    if fd.op(op).is_call() {
        return Ok(false);
    }
    let mut prev = None;
    if fd.op(op).opc == Opcode::Cast {
        let vn = fd.input(op, 0)?;
        if !is_explicit(fd, vn) {
            let Some(def) = fd.vn(vn).def else { return Ok(false) };
            if fd.op(def).is_call() || fd.previous_op(op) != Some(def) {
                return Ok(false);
            }
            prev = Some(def);
        }
    }
    let root = fd.op(op).out.ok_or_else(|| LowlevelError("moving an op without output".into()))?;
    let (marks, type_val) = mark_expression(fd, root)?;
    let mut cur = op;
    loop {
        let next = next_op(fd, cur).ok_or_else(|| LowlevelError("moveRespectingCover ran off the block".into()))?;
        let opc = fd.op(next).opc;
        if (opc != Opcode::Copy && opc != Opcode::Cast) || fd.input(next, 0)? == root {
            break;
        }
        let copy_vn = fd.op(next).out.ok_or_else(|| LowlevelError("COPY without output".into()))?;
        if marks.contains(&high(fd, copy_vn)?) || (type_val != 0 && fd.vn(copy_vn).has(VnFlags::ADDRTIED)) {
            break;
        }
        cur = next;
        if cur == last {
            break;
        }
    }
    if cur != last {
        return Ok(false);
    }
    fd.op_uninsert(op);
    fd.op_insert_after(op, last)?;
    if let Some(p) = prev {
        fd.op_uninsert(p);
        fd.op_insert_after(p, last)?;
    }
    Ok(true)
}

/// Port of `BlockSwitch::finalizePrinting`: the basic-block part of `grabCaseBasic` (each case's
/// first basic block, out edge, default flag and fall-through chain), then the labels and the
/// final order.
fn finalize_switch(s: &mut Structure, fd: &Funcdata, b: SId) -> Result<()> {
    let switchbl = switch_leaf(s, b)?;

    let mut cases = std::mem::take(&mut s.bm(b).cases);
    let mut casemap = vec![None; fd.blocks.block(switchbl).outs.len()];
    for (i, case) in cases.iter_mut().enumerate() {
        let basic = leaf_basic(s, case.block)?;
        case.outindex = in_rev_index(fd, basic, switchbl)
            .ok_or_else(|| LowlevelError("Case block has become detached from switch".into()))?;
        case.basicblock = Some(basic);
        case.isdefault = fd.blocks.is_default_branch(switchbl, case.outindex);
        if case.gototype == 0 {
            if let Some(slot) = casemap.get_mut(case.outindex) {
                *slot = Some(i);
            }
        }
    }
    for case in cases.iter_mut() {
        if case.gototype != 0 {
            continue; // the chains are filled before the goto cases are added
        }
        if let Kind::Goto(target) = s.b(case.block).kind {
            let basic = leaf_basic(s, target)?;
            if let Some(out) = in_rev_index(fd, basic, switchbl) {
                case.chain = casemap.get(out).copied().flatten();
            }
        }
    }
    let res = case_labels(fd, switchbl, &cases).map(|labels| label_cases(&mut cases, &labels));
    s.bm(b).cases = cases;
    res
}

/// The basic block of a switch block's switch component (the block ending in the BRANCHIND).
fn switch_leaf(s: &Structure, b: SId) -> Result<BlockId> {
    let switch_comp = *s.b(b).list.first().ok_or_else(|| LowlevelError("switch without components".into()))?;
    match s.exit_leaf(switch_comp).map(|l| &s.b(l).kind) {
        Some(Kind::Copy(bb)) => Ok(*bb),
        _ => err("Could not get switch leaf"),
    }
}

/// The jump table of the switch block `switchbl` (`BlockSwitch::jump`).
fn switch_table(fd: &Funcdata, switchbl: BlockId) -> Result<&JumpTable> {
    let table = fd.jumptables.iter().find(|jt| fd.op(jt.op).parent == Some(switchbl));
    table.ok_or_else(|| LowlevelError("switch block without a jump table".into()))
}

/// For each case, the label of the first table entry going to its first basic block
/// (`getIndexByBlock(basicblock, 0)`, `getLabelByIndex`); none when no entry does.
fn case_labels(fd: &Funcdata, switchbl: BlockId, cases: &[CaseOrder]) -> Result<Vec<Option<u64>>> {
    if cases.is_empty() {
        return Ok(Vec::new());
    }
    let jt = switch_table(fd, switchbl)?;
    cases.iter().map(|c| Ok(case_label_list(fd, jt, c, 1)?.first().copied())).collect()
}

/// The first `max` labels of a case (`BlockSwitch::getNumLabels`, `getLabel`).
fn case_label_list(fd: &Funcdata, jt: &JumpTable, case: &CaseOrder, max: usize) -> Result<Vec<u64>> {
    let basic = case.basicblock.ok_or_else(|| LowlevelError("switch case without its basic block".into()))?;
    let num = jt.num_indices_by_block(fd, basic)?.min(max);
    let label = |j| {
        let index = jt.index_by_block(fd, basic, j)?;
        // the C++ reads past an empty label table here (the reference's assertion)
        jt.labels.get(index).copied().ok_or_else(|| {
            LowlevelError("switch case labels: the jump table has none (action switchnorm has not run)".into())
        })
    };
    (0..num).map(label).collect()
}

/// The basic block of `getFrontLeaf()->subBlock(0)`.
fn leaf_basic(s: &Structure, b: SId) -> Result<BlockId> {
    match front_leaf(s, b).map(|l| &s.b(l).kind) {
        Some(Kind::Copy(bb)) => Ok(*bb),
        _ => err("case block without a basic block"),
    }
}

/// `basicbl->getInRevIndex(basicbl->getInIndex(switchbl))`: the out edge of `from` reaching `bl`.
fn in_rev_index(fd: &Funcdata, bl: BlockId, from: BlockId) -> Option<usize> {
    fd.blocks.block(bl).ins.iter().find(|e| e.point == from).map(|e| e.reverse)
}

/// The label part of `BlockSwitch::finalizePrinting`: each fall-through chain root takes the
/// label of its first basic block (`labels`, by case: none when the jump table has no entry
/// for it, label 0), its chain the same label at increasing depth; then the stable sort by
/// label and depth (`CaseOrder::compare`).
fn label_cases(cases: &mut [CaseOrder], labels: &[Option<u64>]) {
    for i in 0..cases.len() {
        let mut j = cases[i].chain;
        while let Some(k) = j {
            if cases[k].depth != 0 {
                break;
            }
            cases[k].depth = -1;
            j = cases[k].chain;
        }
    }
    for i in 0..cases.len() {
        let Some(label) = labels.get(i).copied().flatten() else {
            cases[i].label = 0;
            continue;
        };
        if cases[i].depth != 0 {
            continue;
        }
        cases[i].label = label;
        let mut j = cases[i].chain;
        let mut depth = 1;
        while let Some(k) = j {
            if cases[k].depth > 0 {
                break;
            }
            cases[k].depth = depth;
            depth += 1;
            cases[k].label = label;
            j = cases[k].chain;
        }
    }
    cases.sort_by_key(|c| (c.label, c.depth));
}

/// `BlockGraph::scopeBreak(-1, -1)` on the root, per kind: each block learns the index of the
/// block its flow exits to and of the current loop's exit; a goto to the loop exit is a break.
fn scope_break(s: &mut Structure) {
    let mut stack = vec![(ROOT, -1, -1)];
    while let Some((b, curexit, loopexit)) = stack.pop() {
        let list = s.b(b).list.clone();
        let idx = |i: usize| s.b(list[i]).index;
        match s.b(b).kind.clone() {
            Kind::Graph | Kind::List => {
                for (i, &c) in list.iter().enumerate() {
                    let ind = if i + 1 == list.len() { curexit } else { idx(i + 1) };
                    stack.push((c, ind, loopexit));
                }
            }
            Kind::Copy(_) => {}
            Kind::Goto(target) => {
                let t = s.b(target).index;
                stack.push((list[0], t, loopexit));
                if loopexit == t {
                    s.bm(b).goto_type = F_BREAK_GOTO;
                }
            }
            Kind::MultiGoto { .. } => stack.push((list[0], -1, loopexit)),
            Kind::DoWhile => stack.push((list[0], -1, curexit)),
            Kind::Condition(_) => stack.extend([(list[0], -1, loopexit), (list[1], -1, loopexit)]),
            Kind::If => stack.extend([(list[0], -1, loopexit), (list[1], curexit, loopexit)]),
            Kind::IfElse => {
                stack.extend([(list[0], -1, loopexit), (list[1], curexit, loopexit), (list[2], curexit, loopexit)])
            }
            Kind::IfNoExit => {
                stack.extend([(list[0], -1, loopexit), (list[1], idx(2), loopexit), (list[2], curexit, loopexit)])
            }
            Kind::IfGoto(target) => {
                stack.push((list[0], -1, loopexit));
                if s.b(target).index == loopexit {
                    s.bm(b).goto_type = F_BREAK_GOTO;
                }
            }
            Kind::WhileDo => stack.extend([(list[0], -1, curexit), (list[1], idx(0), curexit)]),
            Kind::InfLoop => stack.push((list[0], idx(0), curexit)),
            Kind::Switch => {
                stack.push((list[0], -1, curexit));
                for i in 0..s.b(b).cases.len() {
                    let case = s.b(b).cases[i].block;
                    if s.b(b).cases[i].gototype == 0 {
                        stack.push((case, curexit, curexit));
                    } else if s.b(case).index == curexit {
                        s.bm(b).cases[i].gototype = F_BREAK_GOTO;
                    }
                }
            }
        }
    }
}

/// `BlockGraph::markUnstructured`, per kind: the target of each goto that prints is marked
/// (`markCopyBlock`: on its front leaf).
fn mark_unstructured(s: &mut Structure) {
    let mut targets = Vec::new();
    for b in post_order(s) {
        let bl = s.b(b);
        match bl.kind {
            Kind::Goto(t) if bl.goto_type == F_GOTO_GOTO && goto_prints(s, b, t) => targets.push(t),
            Kind::IfGoto(t) if bl.goto_type == F_GOTO_GOTO => targets.push(t),
            Kind::Switch => targets.extend(bl.cases.iter().filter(|c| c.gototype == F_GOTO_GOTO).map(|c| c.block)),
            _ => {}
        }
    }
    for t in targets {
        if let Some(leaf) = front_leaf(s, t) {
            s.bm(leaf).flags |= F_UNSTRUCTURED_TARG;
        }
    }
}

/// `markLabelBumpUp(false)` on the root: a block passes its `bump` to its first component only;
/// loops pass `true` (they print their first component's label) and keep their own flag only
/// when told to.
fn mark_label_bump_up(s: &mut Structure) {
    let mut stack = vec![(ROOT, false)];
    while let Some((b, bump)) = stack.pop() {
        let is_loop = matches!(s.b(b).kind, Kind::WhileDo | Kind::DoWhile | Kind::InfLoop);
        if bump {
            s.bm(b).flags |= F_LABEL_BUMPUP;
        } else if is_loop {
            s.bm(b).flags &= !F_LABEL_BUMPUP;
        }
        let first = if is_loop { true } else { bump };
        let list = &s.b(b).list;
        stack.extend(list.iter().enumerate().map(|(i, &c)| (c, i == 0 && first)));
    }
}

/// `DECOMP_TREE_EXTRA` (rust/tools/decomp-ref.patch): what `print tree block` adds after a block's
/// header: the unstructured-target and label-bump-up flags, a goto block's goto type, a
/// switch's cases (block index and goto type, in order) and a while-do's for-loop ops.
/// A case label the jump table cannot give is an error, as `printCaseExtra` throws it.
pub(crate) fn tree_extra(s: &Structure, fd: &Funcdata, b: SId) -> Result<String> {
    use std::fmt::Write;
    static EXTRA: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    if !*EXTRA.get_or_init(|| std::env::var_os("DECOMP_TREE_EXTRA").is_some()) {
        return Ok(String::new());
    }
    let bl = s.b(b);
    let mut out = format!(" {{f{:x}", bl.flags & (F_UNSTRUCTURED_TARG | F_LABEL_BUMPUP));
    match &bl.kind {
        Kind::Goto(_) | Kind::IfGoto(_) => {
            let _ = write!(out, " g{}", bl.goto_type);
        }
        Kind::Switch => {
            // once the jump table has labels: the default and exit flags, the chain, the depth
            // and the labels of each case (`printCaseExtra` of the patch)
            let table = switch_leaf(s, b).and_then(|bb| switch_table(fd, bb)).ok().filter(|jt| !jt.labels.is_empty());
            for c in &bl.cases {
                let _ = write!(out, " c{}:{}", s.b(c.block).index, c.gototype);
                let Some(jt) = table else { continue };
                let (d, x) = (if c.isdefault { "d" } else { "" }, if c.isexit { "x" } else { "" });
                let chain = c.chain.map_or(-1, |k| k as i64);
                let labels = case_label_list(fd, jt, c, usize::MAX)?;
                let labels: Vec<String> = labels.iter().map(|l| format!("{l:x}")).collect();
                let _ = write!(out, ":{d}{x}:{chain}:{}:{}", c.depth, labels.join(","));
            }
        }
        Kind::WhileDo => {
            if let Some(op) = bl.for_loop.iterate {
                let _ = write!(out, " it{}", fd.op(op).seq.time);
            }
            if let Some(op) = bl.for_loop.initialize {
                let _ = write!(out, " in{}", fd.op(op).seq.time);
            }
        }
        _ => {}
    }
    out.push('}');
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn case(block: u32, basic: u32, chain: Option<usize>) -> CaseOrder {
        CaseOrder { basicblock: Some(BlockId(basic)), chain, ..CaseOrder::new(SId(block), 0, true) }
    }

    /// Three cases: case 0 (label 7) falls through to case 2, case 1 has label 3. Expected from
    /// the C++ by hand: case 2 is a chain member (depth -1, then 1 with case 0's label), so the
    /// order is case 1 (3), case 0 (7, depth 0), case 2 (7, depth 1).
    #[test]
    fn case_labels_order_chains() {
        let mut cases = vec![case(10, 1, Some(2)), case(11, 2, None), case(12, 3, None)];
        label_cases(&mut cases, &[Some(7), Some(3), Some(1)]);
        let order: Vec<(u32, u64, i32)> = cases.iter().map(|c| (c.block.0, c.label, c.depth)).collect();
        assert_eq!(order, vec![(11, 3, 0), (10, 7, 0), (12, 7, 1)]);
    }

    /// A case without a jump-table entry gets label 0 and sorts first.
    #[test]
    fn case_without_entry_is_label_zero() {
        let mut cases = vec![case(10, 1, None), case(11, 2, None)];
        label_cases(&mut cases, &[Some(5), None]);
        assert_eq!(cases.iter().map(|c| (c.block.0, c.label)).collect::<Vec<_>>(), vec![(11, 0), (10, 5)]);
    }
}
