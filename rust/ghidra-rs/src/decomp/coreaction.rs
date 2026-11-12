//! Stage S4: the main-loop actions of `universalAction` that run with the rule groups off
//! (coreaction.cc, condexe.cc, the block edits of funcdata_block.cc, and the parameter and
//! return-value recovery of fspec.cc and funcdata_varnode.cc).
//!
//! Where an action reaches a path no corpus function needs (or one that needs a later stage:
//! the join space, restarts), it fails loudly instead of differing silently.

use super::block::BlockId;
use super::fspec::{ExtraPop, ParamActive, ParamTrial};
use super::funcdata::CallId;
use super::op::{OpFlags, OpId};
use super::opcode::Opcode;
use super::varnode::{Space, VarnodeId, VnFlags};
use super::{err, Arch, Funcdata, LowlevelError, Result};
use std::collections::HashSet;

/// `Architecture::trim_recurse_max`.
const TRIM_RECURSE_MAX: i32 = 5;

/// `calc_mask`.
fn calc_mask(size: u32) -> u64 {
    if size >= 8 {
        u64::MAX
    } else {
        (1u64 << (8 * size)) - 1
    }
}

/// An action with nothing to do on x86 without locked prototypes, segment ops, lane registers
/// or overrides (`paramdouble`: only stack trials split, and none exist before the `stackvars`
/// rules; `segmentize`, `internalstorage`, `lanedivide`).
pub(crate) fn nothing(_: &mut Funcdata, _: &Arch) -> Result<i32> {
    Ok(0)
}

// ---------------------------------------------------------------------------------------
// ActionDirectWrite

/// Port of `ActionDirectWrite::apply` with `propagateIndirect` true (group `protorecovery_a`;
/// the `protorecovery_b` instance is not in the `decompile` root's groups).
pub(crate) fn direct_write(fd: &mut Funcdata, arch: &Arch) -> Result<i32> {
    let mut worklist = Vec::new();
    for vn in fd.loc_all() {
        fd.vn_clear(vn, VnFlags::DIRECTWRITE);
        let v = fd.vn(vn);
        let mark = if v.is_input() {
            v.has(VnFlags::PERSIST)
                || v.has(VnFlags::SPACEBASE)
                || possible_input_param(fd, arch, v.space, v.offset, v.size)
        } else if let Some(def) = v.def {
            let op = fd.op(def);
            if op.is_marker() {
                false
            } else {
                // a COPY is no direct write unless it was a stack STORE (none before stackvars)
                v.has(VnFlags::PERSIST) || !matches!(op.opc, Opcode::Copy | Opcode::Piece | Opcode::Subpiece)
            }
        } else {
            v.is_constant() && !is_indirect_zero(fd, vn)
        };
        if mark {
            fd.vn_set(vn, VnFlags::DIRECTWRITE);
            worklist.push(vn);
        }
    }
    while let Some(vn) = worklist.pop() {
        for op in fd.vn(vn).descend.to_vec() {
            let Some(out) = fd.op(op).out else { continue };
            if !fd.vn(out).has(VnFlags::DIRECTWRITE) {
                fd.vn_set(out, VnFlags::DIRECTWRITE);
                worklist.push(out);
            }
        }
    }
    Ok(0)
}

/// `Varnode::isIndirectZero`: the constant input of an INDIRECT creation that is no possible
/// output.
fn is_indirect_zero(fd: &Funcdata, vn: VarnodeId) -> bool {
    let v = fd.vn(vn);
    v.is_constant() && v.has(VnFlags::INDIRECT_CREATION)
}

/// Port of `FuncProto::possibleInputParam` for the function's unlocked prototype: an input
/// entry holds the range justified, and the range is at least its minimum size.
fn possible_input_param(fd: &Funcdata, arch: &Arch, space: Space, off: u64, size: u32) -> bool {
    let Some(m) = fd.proto.model else { return false };
    let list = &arch.spec.models.get(m).input;
    (0..list.entries.len())
        .any(|i| list.entries[i].minsize <= size as i32 && list.justified_contain(i, space, off, size) == Some(0))
}

// ---------------------------------------------------------------------------------------
// Parameter and return-value recovery

/// `TraverseNode` flags.
const ACTIONALT: u32 = 1;
const INDIRECT: u32 = 2;
const INDIRECTALT: u32 = 4;
const LSB_TRUNCATED: u32 = 8;
const CONCAT_HIGH: u32 = 0x10;

/// Port of `TraverseNode::isAlternatePathValid` (no incidental COPYs exist without call
/// fixups that declare them).
fn alternate_path_valid(fd: &Funcdata, vn: VarnodeId, flags: u32) -> bool {
    if flags & (INDIRECT | INDIRECTALT) == INDIRECT {
        return true;
    }
    if flags & (INDIRECT | INDIRECTALT) == INDIRECTALT {
        return false;
    }
    if flags & ACTIONALT != 0 {
        return true;
    }
    if fd.vn(vn).descend.len() != 1 {
        return false;
    }
    match fd.vn(vn).def {
        None => true,
        Some(op) => !fd.op(op).is_marker(),
    }
}

/// Port of `Funcdata::checkCallDoubleUse`: no call has parameter trials of its own (calls take
/// `__stdcall`, whose parameters live on the stack, and no stack varnode exists before the
/// `stackvars` rules), so a value reaching a call is a use unless it is the called address.
fn check_call_double_use(fd: &Funcdata, op: OpId, vn: VarnodeId) -> Result<bool> {
    let j = fd.slot_of(op, vn).unwrap_or(0);
    if j == 0 {
        return Ok(false);
    }
    if let Some(c) = fd.call_of(op) {
        if fd.call(c).active_input.as_ref().is_some_and(|a| !a.trials.is_empty()) {
            return err("checkCallDoubleUse with parameter trials: not implemented in ghidra-rs yet");
        }
        if fd.call(c).active_input.is_some() {
            return err("checkCallDoubleUse on a call parameter: not implemented in ghidra-rs yet");
        }
    }
    Ok(false)
}

/// Port of `Funcdata::onlyOpUse`: whether `invn` (and what it flows into) is used only as the
/// trial of `opmatch`.
fn only_op_use(fd: &Funcdata, invn: VarnodeId, opmatch: OpId, trial: &ParamTrial, main: u32) -> Result<bool> {
    let mut varlist = vec![(invn, main)];
    let mut marked: HashSet<VarnodeId> = HashSet::from([invn]);
    let returns_active = fd.active_output.is_some();
    let mut i = 0;
    while i < varlist.len() {
        let (vn, base) = varlist[i];
        i += 1;
        for &op in fd.vn(vn).descend.iter() {
            if op == opmatch && fd.op(op).ins.get(trial.slot) == Some(&vn) {
                continue;
            }
            let o = fd.op(op);
            let mut cur = base;
            match o.opc {
                Opcode::Branch | Opcode::Cbranch | Opcode::Branchind | Opcode::Load | Opcode::Store => {
                    return Ok(false)
                }
                Opcode::Call | Opcode::Callind => {
                    if check_call_double_use(fd, op, vn)? {
                        continue;
                    }
                    return Ok(false);
                }
                Opcode::Indirect => cur |= INDIRECTALT,
                Opcode::Copy => {
                    if !is_internal(fd, o.out) && !incidental(fd, vn) {
                        cur |= ACTIONALT;
                    }
                }
                Opcode::Return => {
                    if fd.op(opmatch).opc == Opcode::Return {
                        if o.ins.get(trial.slot) == Some(&vn) {
                            continue;
                        }
                    } else if returns_active && o.ins.first() != Some(&vn) && !alternate_path_valid(fd, vn, cur) {
                        continue;
                    }
                    return Ok(false);
                }
                Opcode::Multiequal | Opcode::IntSext | Opcode::IntZext | Opcode::Cast => {}
                Opcode::Piece => {
                    if o.ins[0] == vn {
                        if cur & LSB_TRUNCATED != 0 {
                            continue;
                        }
                        cur |= CONCAT_HIGH;
                    }
                }
                Opcode::Subpiece => {
                    if fd.vn(o.ins[1]).offset != 0 && cur & CONCAT_HIGH == 0 {
                        cur |= LSB_TRUNCATED;
                    }
                }
                _ => cur |= ACTIONALT,
            }
            if let Some(sub) = o.out {
                if fd.vn(sub).has(VnFlags::PERSIST) {
                    return Ok(false);
                }
                if marked.insert(sub) {
                    varlist.push((sub, cur));
                }
            }
        }
    }
    Ok(true)
}

/// Whether an op's output lives in the unique space (`IPTR_INTERNAL`).
fn is_internal(fd: &Funcdata, vn: Option<VarnodeId>) -> bool {
    vn.is_some_and(|v| fd.ram.is_some() && is_unique(fd, v))
}

/// `Varnode::isIncidentalCopy` (no op is an incidental COPY without a call fixup declaring it).
fn incidental(fd: &Funcdata, vn: VarnodeId) -> bool {
    fd.vn(vn).has(VnFlags::INCIDENTAL_COPY)
}

fn is_unique(fd: &Funcdata, vn: VarnodeId) -> bool {
    matches!(fd.vn(vn).space, Space::Sleigh(s) if Some(s) == fd.uniq)
}

/// Port of `Funcdata::ancestorOpUse`.
fn ancestor_op_use(
    fd: &Funcdata,
    maxlevel: i32,
    invn: VarnodeId,
    op: OpId,
    trial: &mut ParamTrial,
    offset: u32,
    main: u32,
    marks: &mut HashSet<OpId>,
) -> Result<bool> {
    if maxlevel == 0 {
        return Ok(false);
    }
    let Some(def) = fd.vn(invn).def else {
        // an input is a use only with a locked type, and nothing is typed yet
        return Ok(false);
    };
    let d = fd.op(def);
    match d.opc {
        Opcode::Indirect => {
            if d.flags.has(OpFlags::INDIRECT_CREATION) {
                return Ok(false);
            }
            return ancestor_op_use(fd, maxlevel - 1, d.ins[0], op, trial, offset, main | INDIRECT, marks);
        }
        Opcode::Multiequal => {
            if !marks.insert(def) {
                return Ok(false);
            }
            for i in 0..d.ins.len() {
                if ancestor_op_use(fd, maxlevel - 1, d.ins[i], op, trial, offset, main, marks)? {
                    marks.remove(&def);
                    return Ok(true);
                }
            }
            marks.remove(&def);
            return Ok(false);
        }
        Opcode::Copy => {
            if is_unique(fd, invn) || incidental(fd, d.ins[0]) {
                return ancestor_op_use(fd, maxlevel - 1, d.ins[0], op, trial, offset, main, marks);
            }
        }
        Opcode::Piece => {
            if offset == 0 {
                return ancestor_op_use(fd, maxlevel - 1, d.ins[1], op, trial, 0, main, marks);
            }
            if offset == fd.vn(d.ins[1]).size {
                return ancestor_op_use(fd, maxlevel - 1, d.ins[0], op, trial, 0, main, marks);
            }
            return Ok(false);
        }
        Opcode::Subpiece => {
            let newoff = fd.vn(d.ins[1]).offset as u32;
            if newoff == 0 {
                if let Some(rem) = fd.vn(d.ins[0]).def {
                    if matches!(fd.op(rem).opc, Opcode::IntRem | Opcode::IntSrem) {
                        trial.set(ParamTrial::REM_FORMED);
                    }
                }
            }
            if is_unique(fd, invn) || incidental(fd, d.ins[0]) || vn_overlap(fd, invn, d.ins[0]) == Some(newoff) {
                return ancestor_op_use(fd, maxlevel - 1, d.ins[0], op, trial, offset + newoff, main, marks);
            }
        }
        Opcode::Call | Opcode::Callind => return Ok(false),
        _ => {}
    }
    only_op_use(fd, invn, op, trial, main)
}

/// Port of `Varnode::overlap(const Varnode &)`: where `a` starts within `b`.
fn vn_overlap(fd: &Funcdata, a: VarnodeId, b: VarnodeId) -> Option<u32> {
    let (va, vb) = (fd.vn(a), fd.vn(b));
    if va.space != vb.space || va.is_constant() {
        return None;
    }
    let dist = va.offset.wrapping_sub(vb.offset);
    (dist < u64::from(vb.size)).then_some(dist as u32)
}

/// `AncestorRealistic` commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cmd {
    Enter,
    Success,
    Solid,
    Fail,
    FailKill,
}

/// `AncestorRealistic::State`.
#[derive(Debug, Clone, Copy)]
struct State {
    op: OpId,
    slot: usize,
    flags: u32,
    offset: u32,
}

const SEEN_SOLID0: u32 = 1;
const SEEN_SOLID1: u32 = 2;
const SEEN_KILL: u32 = 4;

/// Port of `AncestorRealistic::execute`: whether the value in input `slot` of `op` could
/// realistically be a parameter (or return value) written for it.
fn ancestor_realistic(fd: &Funcdata, op: OpId, slot: usize, trial: &mut ParamTrial, allow_fail: bool) -> bool {
    let mut marked: HashSet<VarnodeId> = HashSet::new();
    let mut stack = vec![State { op, slot, flags: 0, offset: 0 }];
    let mut multi_depth = 0;
    if fd.vn(fd.op(op).ins[slot]).is_input() && !trial.has(ParamTrial::CONDEXE_EFFECT) {
        return false;
    }
    let mut cmd = Cmd::Enter;
    while !stack.is_empty() {
        cmd = match cmd {
            Cmd::Enter => enter_node(fd, &mut stack, &mut marked, &mut multi_depth, trial),
            _ => upon_pop(fd, &mut stack, &mut multi_depth, cmd, trial, allow_fail),
        };
    }
    match cmd {
        Cmd::Success => {
            trial.set(ParamTrial::ANCESTOR_REALISTIC);
            true
        }
        Cmd::Solid => {
            trial.set(ParamTrial::ANCESTOR_REALISTIC | ParamTrial::ANCESTOR_SOLID);
            true
        }
        _ => false,
    }
}

/// Port of `AncestorRealistic::enterNode`.
fn enter_node(
    fd: &Funcdata,
    stack: &mut Vec<State>,
    marked: &mut HashSet<VarnodeId>,
    multi_depth: &mut i32,
    trial: &mut ParamTrial,
) -> Cmd {
    let state = *stack.last().unwrap();
    let vn = fd.op(state.op).ins[state.slot];
    if marked.contains(&vn) {
        return Cmd::Success;
    }
    let v = fd.vn(vn);
    let Some(def) = v.def else {
        if v.is_input() {
            if v.has(VnFlags::UNAFFECTED) {
                return Cmd::Fail;
            }
            if v.has(VnFlags::PERSIST) {
                return Cmd::Success;
            }
            if !v.has(VnFlags::DIRECTWRITE) {
                return Cmd::Fail;
            }
        }
        return Cmd::Success;
    };
    marked.insert(vn);
    let op = fd.op(def);
    match op.opc {
        Opcode::Indirect => {
            if op.flags.has(OpFlags::INDIRECT_CREATION) {
                trial.set(ParamTrial::INDCREATE_FORMED);
                if is_indirect_zero(fd, op.ins[0]) {
                    return Cmd::FailKill;
                }
                return Cmd::Success;
            }
            if !op.flags.has(OpFlags::INDIRECT_STORE) {
                if v.has(VnFlags::RETURN_ADDRESS) {
                    return Cmd::Fail;
                }
                if trial.has(ParamTrial::KILLEDBYCALL) {
                    return Cmd::Fail;
                }
            }
            stack.push(State { op: def, slot: 0, flags: 0, offset: 0 });
            Cmd::Enter
        }
        Opcode::Subpiece => {
            let suboff = fd.vn(op.ins[1]).offset as u32;
            if is_unique(fd, vn) || incidental(fd, op.ins[0]) || vn_overlap(fd, vn, op.ins[0]) == Some(suboff) {
                stack.push(State { op: def, slot: 0, flags: 0, offset: state.offset + suboff });
                return Cmd::Enter;
            }
            let mut cur = Some(def);
            while let Some(o) = cur {
                let o = fd.op(o);
                if !matches!(o.opc, Opcode::Copy | Opcode::Subpiece) {
                    break;
                }
                let inv = fd.vn(o.ins[0]);
                if !marked.contains(&o.ins[0])
                    && inv.is_input()
                    && (inv.has(VnFlags::UNAFFECTED) || !inv.has(VnFlags::DIRECTWRITE))
                {
                    return Cmd::Fail;
                }
                cur = inv.def;
            }
            Cmd::Solid
        }
        Opcode::Copy => {
            let inv = fd.vn(op.ins[0]);
            if is_unique(fd, vn) || incidental(fd, op.ins[0]) || (inv.space == v.space && inv.offset == v.offset) {
                stack.push(State { op: def, slot: 0, flags: 0, offset: 0 });
                return Cmd::Enter;
            }
            let mut cur = op.ins[0];
            loop {
                let c = fd.vn(cur);
                if !marked.contains(&cur) && c.is_input() && !c.has(VnFlags::DIRECTWRITE) {
                    return Cmd::Fail;
                }
                let Some(o) = c.def else { break };
                let o = fd.op(o);
                cur = match o.opc {
                    Opcode::Copy | Opcode::Subpiece => o.ins[0],
                    Opcode::Piece => o.ins[1],
                    _ => break,
                };
            }
            Cmd::Solid
        }
        Opcode::Multiequal => {
            *multi_depth += 1;
            stack.push(State { op: def, slot: 0, flags: 0, offset: 0 });
            Cmd::Enter
        }
        Opcode::Piece => {
            if v.size > trial.size {
                let (lo, hi) = (fd.vn(op.ins[1]).size, fd.vn(op.ins[0]).size);
                if state.offset == 0 && lo <= trial.size {
                    stack.push(State { op: def, slot: 1, flags: 0, offset: 0 });
                    return Cmd::Enter;
                } else if state.offset == lo && hi <= trial.size {
                    stack.push(State { op: def, slot: 0, flags: 0, offset: 0 });
                    return Cmd::Enter;
                }
                if v.space != Space::Stack {
                    return Cmd::Fail;
                }
            }
            Cmd::Solid
        }
        _ => Cmd::Solid,
    }
}

/// Port of `AncestorRealistic::uponPop`.
fn upon_pop(
    fd: &Funcdata,
    stack: &mut Vec<State>,
    multi_depth: &mut i32,
    cmd: Cmd,
    trial: &mut ParamTrial,
    allow_fail: bool,
) -> Cmd {
    let n = stack.len();
    let state = stack[n - 1];
    if fd.op(state.op).opc != Opcode::Multiequal {
        stack.pop();
        return cmd;
    }
    if cmd == Cmd::Fail {
        *multi_depth -= 1;
        stack.pop();
        return cmd;
    }
    let nin = fd.op(state.op).ins.len();
    if cmd == Cmd::Solid && *multi_depth == 1 && nin == 2 {
        stack[n - 2].flags |= if state.slot == 0 { SEEN_SOLID0 } else { SEEN_SOLID1 };
    } else if cmd == Cmd::FailKill {
        stack[n - 2].flags |= SEEN_KILL;
    }
    stack[n - 1].slot += 1;
    if stack[n - 1].slot < nin {
        return Cmd::Enter;
    }
    let prev = stack[n - 2];
    let mut res;
    if prev.flags & (SEEN_SOLID0 | SEEN_SOLID1) != 0 {
        res = Cmd::Success;
        if prev.flags & SEEN_KILL != 0 {
            if allow_fail {
                // checkConditionalExe
                let bl = fd.op(state.op).parent.expect("live op");
                let b = fd.blocks.block(bl);
                // getSolidSlot reads the MULTIEQUAL's own state, as the C++ does
                let solid = if state.flags & SEEN_SOLID0 != 0 { 0 } else { 1 };
                if b.ins.len() != 2 || fd.blocks.block(b.ins[solid].point).outs.len() != 1 {
                    res = Cmd::Fail;
                } else {
                    trial.set(ParamTrial::CONDEXE_EFFECT);
                }
            } else {
                res = Cmd::Fail;
            }
        }
    } else if prev.flags & SEEN_KILL != 0 {
        res = Cmd::FailKill;
    } else {
        res = Cmd::Success;
    }
    *multi_depth -= 1;
    stack.pop();
    res
}

/// Port of `ActionActiveParam::apply`. Calls have no parameter trials (see
/// [`check_call_double_use`]), so each call's analysis only counts its passes and then
/// rebuilds the inputs from the (no) used trials.
pub(crate) fn active_param(fd: &mut Funcdata, _: &Arch) -> Result<i32> {
    let mut count = 0;
    for i in 0..fd.qlst.len() {
        let c = fd.qlst[i];
        let op = fd.call(c).op;
        let callind = fd.op(op).opc == Opcode::Callind;
        let Some(active) = &mut fd.call_mut(c).active_input else { continue };
        let trimmable = active.numpasses > 0 || !callind;
        if !active.trials.is_empty() {
            return err("parameter trials of a call: not implemented in ghidra-rs yet (stack varnodes, stage R5)");
        }
        // checkInputTrialUse: no trials to check
        active.numpasses += 1;
        if active.numpasses > active.maxpass {
            active.fully_checked = true;
        } else {
            count += 1;
        }
        if trimmable && active.fully_checked {
            if fd.op(op).is_dead() {
                return err("Function call in dead code");
            }
            // finalInputCheck, resolveModel (calls never take a merged model) and
            // deriveInputMap have no trials to work on; buildInputFromTrials keeps input 0
            let in0 = fd.input(op, 0)?;
            fd.op_set_all_input(op, &[in0])?;
            fd.call_mut(c).active_input = None;
            count += 1;
        }
    }
    Ok(count)
}

/// Port of `ActionReturnRecovery::apply`.
pub(crate) fn return_recovery(fd: &mut Funcdata, arch: &Arch) -> Result<i32> {
    let Some(mut active) = fd.active_output.take() else { return Ok(0) };
    let mut count = 0;
    let returns: Vec<OpId> = fd
        .ops_created_with(Opcode::Return)
        .into_iter()
        .filter(|&o| !fd.op(o).is_dead() && fd.op(o).halt.is_none())
        .collect();
    for &op in &returns {
        for i in 0..active.trials.len() {
            if active.trials[i].is_checked() {
                continue;
            }
            let slot = active.trials[i].slot;
            let vn = fd.input(op, slot)?;
            let mut trial = active.trials[i].clone();
            let real = ancestor_realistic(fd, op, slot, &mut trial, false);
            if real {
                let mut marks = HashSet::new();
                if ancestor_op_use(fd, TRIM_RECURSE_MAX, vn, op, &mut trial, 0, 0, &mut marks)? {
                    trial.mark_active();
                }
            }
            active.trials[i] = trial;
            count += 1;
        }
    }
    active.numpasses += 1;
    if active.numpasses > active.maxpass {
        active.fully_checked = true;
    }
    if !active.fully_checked {
        fd.active_output = Some(active);
        return Ok(count);
    }
    let model = fd.proto.model.ok_or_else(|| LowlevelError("return recovery without a model".into()))?;
    arch.spec.models.get(model).output.fillin_map_output(&mut active);
    for &op in &returns {
        build_return_output(fd, &active, op)?;
    }
    fd.proto.output = active.trials.iter().find(|t| t.is_used()).map(|t| (t.space, t.off, t.size));
    Ok(count + 1)
}

/// Port of `ActionReturnRecovery::buildReturnOutput`.
fn build_return_output(fd: &mut Funcdata, active: &ParamActive, retop: OpId) -> Result<()> {
    let mut newparam = vec![fd.input(retop, 0)?];
    for t in &active.trials {
        if !t.is_used() || t.slot >= fd.op(retop).ins.len() {
            break;
        }
        newparam.push(fd.op(retop).ins[t.slot]);
    }
    if newparam.len() <= 2 {
        return fd.op_set_all_input(retop, &newparam);
    }
    if newparam.len() > 3 {
        return err("a return value in more than two pieces: not implemented in ghidra-rs yet");
    }
    // most significant first
    let pieces: Vec<(u32, u64, u32)> = newparam[1..]
        .iter()
        .rev()
        .map(|&v| match fd.vn(v).space {
            Space::Sleigh(s) => Ok((s, fd.vn(v).offset, fd.vn(v).size)),
            _ => err("a return value piece outside a SLEIGH space"),
        })
        .collect::<Result<_>>()?;
    let whole = fd.join_pieces(pieces)?;
    let (lo, hi) = (newparam[1], newparam[2]);
    let size = fd.vn(lo).size + fd.vn(hi).size;
    let addr = fd.op(retop).seq.addr;
    let newop = fd.new_op(Opcode::Piece, addr);
    let newout = fd.new_varnode_out(size, Space::Join, whole, newop);
    fd.vn_set(newout, VnFlags::WRITEMASK);
    fd.op_set_input(newop, hi, 0)?;
    fd.op_set_input(newop, lo, 1)?;
    fd.op_insert_before(newop, retop)?;
    fd.op_set_all_input(retop, &[newparam[0], newout])
}

/// Port of `ActionActiveReturn::apply`: each call's output trials become its output.
pub(crate) fn active_return(fd: &mut Funcdata, arch: &Arch) -> Result<i32> {
    let mut count = 0;
    for i in 0..fd.qlst.len() {
        let c = fd.qlst[i];
        let Some(mut active) = fd.call_mut(c).active_output.take() else { continue };
        let op = fd.call(c).op;
        // collectOutputTrialVarnodes
        if fd.op(op).out.is_some() {
            return err("Output of call was determined prematurely");
        }
        let mut trialvn: Vec<Option<VarnodeId>> = vec![None; active.trials.len()];
        let mut ind = fd.previous_op(op);
        while let Some(io) = ind {
            if fd.op(io).opc != Opcode::Indirect {
                break;
            }
            if fd.op(io).flags.has(OpFlags::INDIRECT_CREATION) {
                if let Some(vn) = fd.op(io).out {
                    let v = fd.vn(vn);
                    if let Some(idx) = active.which_trial(v.space, v.offset, v.size) {
                        trialvn[idx] = Some(vn);
                        let t = &mut active.trials[idx];
                        (t.space, t.off, t.size) = (v.space, v.offset, v.size);
                    }
                }
            }
            ind = fd.previous_op(io);
        }
        // checkOutputTrialUse
        for (t, vn) in active.trials.iter_mut().zip(&trialvn) {
            if t.is_checked() {
                return err("Output trial has been checked prematurely");
            }
            if vn.is_some() {
                t.mark_active();
            } else {
                t.mark_inactive();
            }
        }
        if let Some(m) = fd.call(c).proto.model {
            arch.spec.models.get(m).output.fillin_map_output(&mut active);
        }
        build_output_from_trials(fd, c, &mut active, &trialvn)?;
        count += 1;
    }
    Ok(count)
}

/// Port of `FuncCallSpecs::buildOutputFromTrials`.
fn build_output_from_trials(
    fd: &mut Funcdata,
    c: CallId,
    active: &mut ParamActive,
    trialvn: &[Option<VarnodeId>],
) -> Result<()> {
    let mut finalvn = Vec::new();
    for t in &active.trials {
        if !t.is_used() {
            break;
        }
        finalvn.push(trialvn[t.slot - 1].ok_or_else(|| LowlevelError("used output trial without a varnode".into()))?);
    }
    active.delete_unused_trials();
    if active.trials.is_empty() {
        return Ok(());
    }
    let op = fd.call(c).op;
    let mut deleted = Vec::new();
    if active.trials.len() == 1 {
        let out = finalvn[0];
        deleted.push(fd.vn(out).def.ok_or_else(|| LowlevelError("output trial without its INDIRECT".into()))?);
        fd.op_set_output(op, out)?;
    } else {
        // joinMostSigFirst is false: the trials come least significant first
        finalvn.reverse();
        let mut pieces = Vec::new();
        for &vn in &finalvn {
            let Space::Sleigh(s) = fd.vn(vn).space else { return err("a call output piece outside a SLEIGH space") };
            pieces.push((s, fd.vn(vn).offset, fd.vn(vn).size));
            deleted.push(fd.vn(vn).def.ok_or_else(|| LowlevelError("output trial without its INDIRECT".into()))?);
        }
        let size = pieces.iter().map(|p| p.2).sum();
        let whole = fd.join_pieces(pieces)?;
        let finalout = fd.new_varnode(size, Space::Join, whole);
        fd.op_set_output(op, finalout)?;
        let addr = fd.op(op).seq.addr;
        let mut trunc = 0u64;
        for &vn in finalvn.iter().rev() {
            let subop = fd.new_op(Opcode::Subpiece, addr);
            fd.op_set_input(subop, finalout, 0)?;
            let c = fd.new_constant(4, trunc);
            fd.op_set_input(subop, c, 1)?;
            fd.op_set_output(subop, vn)?;
            fd.op_insert_after(subop, op)?;
            trunc += u64::from(fd.vn(vn).size);
        }
    }
    for dop in deleted {
        let ins = fd.op(dop).ins.clone();
        fd.op_destroy(dop);
        for vn in ins {
            fd.delete_varnode(vn);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------
// ActionDeadCode

/// `coveringmask`.
fn covering_mask(val: u64) -> u64 {
    if val == 0 {
        0
    } else {
        u64::MAX >> val.leading_zeros()
    }
}

/// `minimalmask`.
fn minimal_mask(val: u64) -> u64 {
    if val > 0xffff_ffff {
        u64::MAX
    } else if val > 0xffff {
        0xffff_ffff
    } else if val > 0xff {
        0xffff
    } else {
        0xff
    }
}

/// Port of `ActionDeadCode::pushConsumed`.
fn push_consumed(fd: &mut Funcdata, val: u64, vn: VarnodeId, worklist: &mut Vec<VarnodeId>) {
    let v = fd.vn(vn);
    let newval = (val | v.consume) & calc_mask(v.size);
    if newval == v.consume && v.has(VnFlags::CONSUME_VACUOUS) {
        return;
    }
    let (in_list, written) = (v.has(VnFlags::CONSUME_LIST), v.is_written());
    fd.vn_set(vn, VnFlags::CONSUME_VACUOUS);
    if !in_list {
        fd.vn_set(vn, VnFlags::CONSUME_LIST);
        if written {
            worklist.push(vn);
        }
    }
    fd.vn_mut(vn).consume = newval;
}

/// Port of `ActionDeadCode::propagateConsumed`.
fn propagate_consumed(fd: &mut Funcdata, worklist: &mut Vec<VarnodeId>) -> Result<()> {
    let vn = worklist.pop().unwrap();
    let outc = fd.vn(vn).consume;
    fd.vn_clear(vn, VnFlags::CONSUME_LIST);
    let op = fd.vn(vn).def.unwrap();
    let ins = fd.op(op).ins.clone();
    let opc = fd.op(op).opc;
    let all = |outc: u64| if outc == 0 { 0 } else { u64::MAX };
    let konst = |fd: &Funcdata, i: usize| fd.vn(ins[i]).is_constant().then(|| fd.vn(ins[i]).offset);
    let size = fd.vn(vn).size;
    let mut push = |fd: &mut Funcdata, val: u64, i: usize| push_consumed(fd, val, ins[i], worklist);
    match opc {
        Opcode::IntMult => {
            let b = covering_mask(outc);
            let a = match konst(fd, 1) {
                Some(c) if c != 0 => (calc_mask(size) >> c.trailing_zeros()) & b,
                Some(_) => 0,
                None => b,
            };
            push(fd, a, 0);
            push(fd, b, 1);
        }
        Opcode::IntAdd | Opcode::IntSub => {
            let a = covering_mask(outc);
            push(fd, a, 0);
            push(fd, a, 1);
        }
        Opcode::Subpiece => {
            let sz = fd.vn(ins[1]).offset;
            let mut a = if sz >= 8 { 0 } else { outc << (sz * 8) };
            if a == 0 && outc != 0 && fd.vn(ins[0]).size > 8 {
                a = 1 << 63;
            }
            push(fd, a, 0);
            push(fd, all(outc), 1);
        }
        Opcode::Piece => {
            let sz = fd.vn(ins[1]).size;
            let (a, b) = if size > 8 {
                if sz >= 8 {
                    (u64::MAX, outc)
                } else {
                    let a = (outc >> (sz * 8)) ^ (u64::MAX << (8 * (8 - sz)));
                    (a, outc ^ (a << (sz * 8)))
                }
            } else {
                let a = if sz >= 8 { 0 } else { outc >> (sz * 8) };
                (a, if sz >= 8 { outc } else { outc ^ (a << (sz * 8)) })
            };
            push(fd, a, 0);
            push(fd, b, 1);
        }
        Opcode::Indirect => {
            push(fd, outc, 0);
            if let Some(indop) = fd.iop_target(ins[1]) {
                if fd.op(indop).is_dead() {
                    return err(format!("Hanging INDIRECT at 0x{:08x}", fd.op(op).seq.addr));
                }
                if fd.op(indop).opc == Opcode::Copy {
                    let iout = fd.op(indop).out.unwrap();
                    if characterize_overlap(fd, iout, vn) > 0 {
                        push_consumed(fd, u64::MAX, iout, worklist);
                        fd.op_mut(indop).flags.set(OpFlags::INDIRECT_SOURCE);
                    }
                } else {
                    fd.op_mut(indop).flags.set(OpFlags::INDIRECT_SOURCE);
                }
            }
        }
        Opcode::Copy | Opcode::IntNegate | Opcode::IntZext => push(fd, outc, 0),
        Opcode::IntXor | Opcode::IntOr => {
            push(fd, outc, 0);
            push(fd, outc, 1);
        }
        Opcode::IntAnd => {
            match konst(fd, 1) {
                Some(val) => push(fd, outc & val, 0),
                None => push(fd, outc, 0),
            }
            push(fd, outc, 1);
        }
        Opcode::Multiequal => {
            for i in 0..ins.len() {
                push(fd, outc, i);
            }
        }
        Opcode::IntSext => {
            let b = calc_mask(fd.vn(ins[0]).size);
            let mut a = outc & b;
            if outc > b {
                a |= b ^ (b >> 1);
            }
            push(fd, a, 0);
        }
        Opcode::IntLeft => match konst(fd, 1) {
            Some(sa) => {
                let a = if size > 8 {
                    let mut a = if sa >= 64 {
                        u64::MAX
                    } else if sa == 0 {
                        outc
                    } else {
                        (outc >> sa) ^ (u64::MAX << (64 - sa))
                    };
                    let bits = 8 * u64::from(size) - sa;
                    if bits < 64 {
                        a &= !(u64::MAX << bits);
                    }
                    a
                } else if sa >= 64 {
                    0
                } else {
                    outc >> sa
                };
                push(fd, a, 0);
                push(fd, all(outc), 1);
            }
            None => {
                push(fd, all(outc), 0);
                push(fd, all(outc), 1);
            }
        },
        Opcode::IntRight => match konst(fd, 1) {
            Some(sa) => {
                let mut a = if sa >= 64 { 0 } else { outc << sa };
                if a == 0 && outc != 0 && fd.vn(ins[0]).size > 8 {
                    a = 1 << 63;
                }
                push(fd, a, 0);
                push(fd, all(outc), 1);
            }
            None => {
                push(fd, all(outc), 0);
                push(fd, all(outc), 1);
            }
        },
        Opcode::IntLess | Opcode::IntLessequal | Opcode::IntEqual | Opcode::IntNotequal => {
            let a = if outc == 0 { 0 } else { fd.vn(ins[0]).nzmask() | fd.vn(ins[1]).nzmask() };
            push(fd, a, 0);
            push(fd, a, 1);
        }
        Opcode::Popcount | Opcode::Lzcount => {
            let a = (16 * u64::from(fd.vn(ins[0]).size) - 1) & outc;
            push(fd, all(a), 0);
        }
        Opcode::Call | Opcode::Callind => {}
        Opcode::FloatInt2float => {
            let a = if outc != 0 { covering_mask(fd.vn(ins[0]).nzmask()) } else { 0 };
            push(fd, a, 0);
        }
        Opcode::Insert | Opcode::Zpull | Opcode::Spull => {
            return err("dead code through INSERT/ZPULL/SPULL: not implemented in ghidra-rs yet")
        }
        _ => {
            for i in 0..ins.len() {
                push(fd, all(outc), i);
            }
        }
    }
    Ok(())
}

/// Port of `Varnode::characterizeOverlap`: 0 none, 1 partial, 2 exact.
fn characterize_overlap(fd: &Funcdata, a: VarnodeId, b: VarnodeId) -> i32 {
    let (va, vb) = (fd.vn(a), fd.vn(b));
    if va.space != vb.space {
        return 0;
    }
    if va.offset == vb.offset {
        return if va.size == vb.size { 2 } else { 1 };
    }
    if va.offset < vb.offset {
        let end = va.offset + u64::from(va.size) - 1;
        return i32::from(end >= vb.offset);
    }
    let end = vb.offset + u64::from(vb.size) - 1;
    i32::from(end >= va.offset)
}

/// Port of `ActionDeadCode::apply` (dead ops go, and an op whose output is consumed by nothing
/// but read has the reads replaced by zero).
pub(crate) fn dead_code(fd: &mut Funcdata, arch: &Arch) -> Result<i32> {
    let mut worklist = Vec::new();
    for vn in fd.loc_all() {
        let v = fd.vn_mut(vn);
        v.flags.clear(VnFlags::CONSUME_LIST);
        v.flags.clear(VnFlags::CONSUME_VACUOUS);
        v.consume = 0;
        if v.has(VnFlags::ADDRFORCE) && !v.has(VnFlags::DIRECTWRITE) {
            v.flags.clear(VnFlags::ADDRFORCE);
        }
    }
    let deadcode_spaces: Vec<u32> = (0..arch.sleigh.spaces.len() as u32)
        .filter(|&i| i != 0 && arch.sleigh.spaces[i as usize].delay.is_some())
        .collect();
    for &sp in &deadcode_spaces {
        if fd.heritage.dead_removal_allowed(arch, sp) {
            continue;
        }
        for vn in fd.loc_space(Space::Sleigh(sp)) {
            push_consumed(fd, u64::MAX, vn, &mut worklist);
        }
    }
    // gatherConsumedReturn: the return value is still being recovered, or locked
    let return_consume = if fd.active_output.is_some() {
        u64::MAX
    } else {
        let mut cv = 0;
        for op in fd.ops_created_with(Opcode::Return) {
            if fd.op(op).is_dead() {
                continue;
            }
            if let Some(&vn) = fd.op(op).ins.get(1) {
                cv |= minimal_mask(fd.vn(vn).nzmask());
            }
        }
        cv
    };
    let alive: Vec<OpId> = fd.blocks.ops().collect();
    for op in alive {
        fd.op_mut(op).flags.clear(OpFlags::INDIRECT_SOURCE);
        let o = fd.op(op);
        let ins = o.ins.clone();
        if o.is_call() {
            // isCallWithoutSpec: CALLOTHER and NEW
            if !matches!(o.opc, Opcode::Call | Opcode::Callind) {
                for &vn in &ins {
                    push_consumed(fd, u64::MAX, vn, &mut worklist);
                }
            }
            if fd.op(op).out.is_none() {
                continue;
            }
        } else if o.out.is_none() {
            match o.opc {
                Opcode::Return => {
                    push_consumed(fd, u64::MAX, ins[0], &mut worklist);
                    for &vn in &ins[1..] {
                        push_consumed(fd, return_consume, vn, &mut worklist);
                    }
                }
                // a jump table's switch variable consume: S3 (jumptable.cc) computes it
                _ => {
                    for &vn in &ins {
                        push_consumed(fd, u64::MAX, vn, &mut worklist);
                    }
                }
            }
            continue;
        } else {
            for &vn in &ins {
                if fd.vn(vn).is_auto_live() {
                    push_consumed(fd, u64::MAX, vn, &mut worklist);
                }
            }
        }
        let out = fd.op(op).out.unwrap();
        if fd.vn(out).is_auto_live() {
            push_consumed(fd, u64::MAX, out, &mut worklist);
        }
    }
    // markConsumedParameters
    for i in 0..fd.qlst.len() {
        let c = fd.qlst[i];
        let op = fd.call(c).op;
        let ins = fd.op(op).ins.clone();
        push_consumed(fd, u64::MAX, ins[0], &mut worklist);
        let active = fd.call(c).active_input.is_some();
        for &vn in &ins[1..] {
            let v = fd.vn(vn);
            let val = if active || v.is_auto_live() { u64::MAX } else { minimal_mask(v.nzmask()) };
            push_consumed(fd, val, vn, &mut worklist);
        }
    }
    while !worklist.is_empty() {
        propagate_consumed(fd, &mut worklist)?;
    }
    // lastChanceLoad: only LOADs from an eventual constant address
    if fd.heritage.pass() <= 1 {
        let mut any = false;
        for op in fd.ops_created_with(Opcode::Load) {
            if fd.op(op).is_dead() {
                continue;
            }
            let Some(out) = fd.op(op).out else { continue };
            if fd.vn(out).has(VnFlags::CONSUME_VACUOUS) {
                continue;
            }
            if is_eventual_constant(fd, fd.op(op).ins[1], 3, 1) {
                push_consumed(fd, u64::MAX, out, &mut worklist);
                fd.vn_set(out, VnFlags::AUTOLIVE_HOLD);
                any = true;
            }
        }
        if any {
            while !worklist.is_empty() {
                propagate_consumed(fd, &mut worklist)?;
            }
        }
    }
    for &sp in &deadcode_spaces {
        if !fd.heritage.dead_removal_allowed(arch, sp) {
            continue;
        }
        let mut changes = 0;
        for vn in fd.loc_space(Space::Sleigh(sp)) {
            let v = fd.vn(vn);
            if v.is_dead() || !v.is_written() {
                continue;
            }
            let vac = v.has(VnFlags::CONSUME_VACUOUS);
            fd.vn_clear(vn, VnFlags::CONSUME_LIST);
            fd.vn_clear(vn, VnFlags::CONSUME_VACUOUS);
            let op = fd.vn(vn).def.unwrap();
            if !vac {
                changes += 1;
                if fd.op(op).is_call() {
                    fd.op_unset_output(op);
                } else {
                    fd.op_destroy(op);
                }
            } else if fd.vn(vn).consume == 0 && never_consumed(fd, vn)? {
                changes += 1;
            }
        }
        if changes != 0 {
            fd.heritage.seen_dead_code(sp);
        }
    }
    fd.clear_dead_varnodes();
    fd.clear_dead_ops();
    Ok(0)
}

/// Port of `ActionDeadCode::neverConsumed`: the readers read zero instead, and the op goes.
fn never_consumed(fd: &mut Funcdata, vn: VarnodeId) -> Result<bool> {
    let size = fd.vn(vn).size;
    if size > 8 {
        return Ok(false);
    }
    for op in fd.vn(vn).descend.to_vec() {
        let slot = fd.slot_of(op, vn).unwrap();
        let c = fd.new_constant(size, 0);
        fd.op_set_input(op, c, slot)?;
    }
    let op = fd.vn(vn).def.unwrap();
    if fd.op(op).is_call() {
        fd.op_unset_output(op);
    } else {
        fd.op_destroy(op);
    }
    Ok(true)
}

/// Port of `Varnode::isEventualConstant`.
fn is_eventual_constant(fd: &Funcdata, vn: VarnodeId, mut max_binary: i32, mut max_load: i32) -> bool {
    let mut cur = vn;
    loop {
        let v = fd.vn(cur);
        if v.is_constant() {
            return true;
        }
        let Some(op) = v.def else { return false };
        let o = fd.op(op);
        match o.opc {
            Opcode::Load => {
                if max_load == 0 {
                    return false;
                }
                max_load -= 1;
                cur = o.ins[1];
            }
            Opcode::IntAdd | Opcode::IntSub | Opcode::IntXor | Opcode::IntOr | Opcode::IntAnd => {
                if max_binary == 0 {
                    return false;
                }
                if !is_eventual_constant(fd, o.ins[0], max_binary - 1, max_load) {
                    return false;
                }
                return is_eventual_constant(fd, o.ins[1], max_binary - 1, max_load);
            }
            Opcode::IntZext | Opcode::IntSext | Opcode::Copy => cur = o.ins[0],
            _ => return false,
        }
        max_binary = max_binary.max(0);
    }
}

// ---------------------------------------------------------------------------------------
// ActionSpacebase, ActionStackPtrFlow, ActionDeindirect

/// Port of `ActionSpacebase::apply` (`Funcdata::spacebase`): every written or input stack
/// pointer is marked; one already marked, written by an INT_ADD, has its uses split.
pub(crate) fn spacebase(fd: &mut Funcdata, arch: &Arch) -> Result<i32> {
    let (sp, off, size) = arch.spec.stack_pointer;
    for vn in fd.loc_at(Space::Sleigh(sp), off, size) {
        let v = fd.vn(vn);
        if v.is_dead() || v.is_free() {
            continue;
        }
        if v.has(VnFlags::SPACEBASE) {
            if let Some(op) = v.def {
                if fd.op(op).opc == Opcode::IntAdd {
                    split_uses(fd, vn)?;
                }
            }
        } else {
            fd.vn_set(vn, VnFlags::SPACEBASE);
        }
    }
    Ok(0)
}

/// Port of `Funcdata::splitUses`: each reader gets its own copy of the op writing `vn`
/// (inserted before it), and the op goes.
fn split_uses(fd: &mut Funcdata, vn: VarnodeId) -> Result<()> {
    let op = fd.vn(vn).def.unwrap();
    let readers = fd.vn(vn).descend.to_vec();
    if readers.len() < 2 {
        return Ok(());
    }
    let (opc, addr, ins) = (fd.op(op).opc, fd.op(op).seq.addr, fd.op(op).ins.clone());
    let (space, offset, size) = (fd.vn(vn).space, fd.vn(vn).offset, fd.vn(vn).size);
    for useop in readers {
        let slot = fd.slot_of(useop, vn).unwrap();
        let newop = fd.new_op(opc, addr);
        let newvn = fd.new_varnode(size, space, offset);
        fd.op_set_output(newop, newvn)?;
        for (i, &invn) in ins.iter().enumerate() {
            fd.op_set_input(newop, invn, i)?;
        }
        fd.op_set_input(useop, newvn, slot)?;
        fd.op_insert_before(newop, op)?;
    }
    fd.op_destroy(op);
    Ok(())
}

/// Port of `ActionStackPtrFlow`: once no LOAD of a pushed value clogs the stack pointer
/// (`checkClog`), the stack pointer at each call whose pop is unknown is solved for
/// (`analyzeExtraPop`). The action's `analysis_finished` lives in the function.
pub(crate) fn stack_ptr_flow(fd: &mut Funcdata, arch: &Arch) -> Result<i32> {
    if fd.stackptrflow_done {
        return Ok(0);
    }
    if check_clog(fd, arch)? == 0 {
        analyze_extra_pop(fd, arch)?;
        fd.stackptrflow_done = true;
    }
    Ok(0)
}

/// `ActionStackPtrFlow::isStackRelative`.
fn stack_relative(fd: &Funcdata, spin: VarnodeId, vn: VarnodeId) -> Option<u64> {
    if vn == spin {
        return Some(0);
    }
    let op = fd.vn(vn).def?;
    let o = fd.op(op);
    if o.opc != Opcode::IntAdd || o.ins[0] != spin || !fd.vn(o.ins[1]).is_constant() {
        return None;
    }
    Some(fd.vn(o.ins[1]).offset)
}

/// Port of `ActionStackPtrFlow::checkClog`: a stack pointer computed from a value LOADed off
/// the stack is repaired when a STORE before it gives the value.
fn check_clog(fd: &mut Funcdata, arch: &Arch) -> Result<i32> {
    let (sp, off, size) = arch.spec.stack_pointer;
    let list = fd.loc_at(Space::Sleigh(sp), off, size);
    let Some((&spin, rest)) = list.split_first() else { return Ok(0) };
    if !fd.vn(spin).is_input() {
        return Ok(0);
    }
    let mut count = 0;
    for &outvn in rest {
        let Some(addop) = fd.vn(outvn).def else { continue };
        if fd.op(addop).opc != Opcode::IntAdd {
            continue;
        }
        let (mut x, mut y) = (fd.op(addop).ins[0], fd.op(addop).ins[1]);
        if !fd.vn(y).is_written() {
            continue;
        }
        if stack_relative(fd, spin, x).is_none() {
            std::mem::swap(&mut x, &mut y);
            if stack_relative(fd, spin, x).is_none() {
                continue;
            }
        }
        let mut loadop = fd.vn(y).def.unwrap();
        if fd.op(loadop).opc == Opcode::IntMult {
            let c = fd.op(loadop).ins[1];
            if !fd.vn(c).is_constant() || fd.vn(c).offset != calc_mask(fd.vn(c).size) {
                continue;
            }
            let yy = fd.op(loadop).ins[0];
            let Some(d) = fd.vn(yy).def else { continue };
            loadop = d;
        }
        if fd.op(loadop).opc != Opcode::Load {
            continue;
        }
        let Some(constz) = stack_relative(fd, spin, fd.op(loadop).ins[1]) else { continue };
        count += repair(fd, spin, loadop, constz)?;
    }
    Ok(count)
}

/// Port of `ActionStackPtrFlow::repair`.
fn repair(fd: &mut Funcdata, spin: VarnodeId, loadop: OpId, constz: u64) -> Result<i32> {
    let loadsize = u64::from(fd.vn(fd.op(loadop).out.unwrap()).size);
    let mut bl = fd.op(loadop).parent.unwrap();
    let mut pos = fd.blocks.block(bl).ops.iter().position(|&o| o == loadop).unwrap();
    loop {
        if pos == 0 {
            if fd.blocks.block(bl).ins.len() != 1 {
                return Ok(0);
            }
            bl = fd.blocks.block(bl).ins[0].point;
            pos = fd.blocks.block(bl).ops.len();
            continue;
        }
        pos -= 1;
        let cur = fd.blocks.block(bl).ops[pos];
        let o = fd.op(cur);
        if o.is_call() {
            return Ok(0);
        }
        if o.opc == Opcode::Store {
            let (ptr, data) = (o.ins[1], o.ins[2]);
            let Some(constnew) = stack_relative(fd, spin, ptr) else { return Ok(0) };
            let dsize = u64::from(fd.vn(data).size);
            if constnew == constz && loadsize == dsize {
                // adjustLoad
                let mut vn = data;
                if fd.vn(vn).is_constant() {
                    vn = fd.new_constant(fd.vn(data).size, fd.vn(data).offset);
                } else if fd.vn(vn).is_free() {
                    return Ok(0);
                }
                fd.op_remove_input(loadop, 1);
                fd.op_set_opcode(loadop, Opcode::Copy);
                fd.op_set_input(loadop, vn, 0)?;
                return Ok(1);
            } else if constnew <= constz.wrapping_add(loadsize - 1) && constnew.wrapping_add(dsize - 1) >= constz {
                return Ok(0);
            }
        } else if let Some(out) = o.out {
            if fd.vn(out).space == Space::Stack {
                return Ok(0);
            }
        }
    }
}

/// Port of `ActionStackPtrFlow::analyzeExtraPop` with `StackSolver`: the stack pointer after
/// each call of unknown pop is solved from the equations the stack-pointer ops give.
fn analyze_extra_pop(fd: &mut Funcdata, arch: &Arch) -> Result<()> {
    let models = &arch.spec.models;
    let myfp = models.get(models.eval_called.unwrap_or(models.default));
    if myfp.extrapop != ExtraPop::Unknown {
        return Ok(());
    }
    let (sp, off, size) = arch.spec.stack_pointer;
    // StackSolver::build
    let mut vnlist = Vec::new();
    for vn in fd.loc_at(Space::Sleigh(sp), off, size) {
        if fd.vn(vn).is_free() {
            break;
        }
        vnlist.push(vn);
    }
    if vnlist.is_empty() {
        return Ok(());
    }
    if !fd.vn(vnlist[0]).is_input() {
        fd.warning_header("Stack frame is not setup normally: Input value of stackpointer is not used");
        return Ok(());
    }
    let mut companion = vec![-1i32; vnlist.len()];
    // (var1, var2, rhs): var1 = var2 + rhs
    let mut eqs: Vec<(usize, usize, i32)> = Vec::new();
    let mut guess: Vec<(usize, usize, i32)> = Vec::new();
    let is_sp = |fd: &Funcdata, v: VarnodeId| {
        let v = fd.vn(v);
        v.space == Space::Sleigh(sp) && v.offset == off
    };
    // the C++ finds a variable with lower_bound by pointer on a list in location order; it is
    // meant to find the varnode itself, which this does
    let index = |v: VarnodeId| vnlist.iter().position(|&x| x == v);
    for i in 1..vnlist.len() {
        let op = fd.vn(vnlist[i]).def.unwrap();
        let o = fd.op(op);
        match o.opc {
            Opcode::IntAdd | Opcode::IntAnd => {
                let (mut other, mut c) = (o.ins[0], o.ins[1]);
                if fd.vn(other).is_constant() {
                    std::mem::swap(&mut other, &mut c);
                }
                if !fd.vn(c).is_constant() || !is_sp(fd, other) {
                    continue;
                }
                let rhs = if o.opc == Opcode::IntAdd { fd.vn(c).offset as i32 } else { 0 };
                if let Some(j) = index(other) {
                    eqs.push((i, j, rhs));
                }
            }
            Opcode::Copy => {
                if is_sp(fd, o.ins[0]) {
                    if let Some(j) = index(o.ins[0]) {
                        eqs.push((i, j, 0));
                    }
                }
            }
            Opcode::Indirect => {
                if !is_sp(fd, o.ins[0]) {
                    continue;
                }
                let Some(j) = index(o.ins[0]) else { continue };
                companion[i] = j as i32;
                let call = fd.iop_target(o.ins[1]).and_then(|iop| fd.call_of(iop));
                match call.map(|c| fd.call(c).proto.extrapop) {
                    Some(ExtraPop::Known(pop)) => eqs.push((i, j, pop)),
                    _ => guess.push((i, j, 4)),
                }
            }
            Opcode::Multiequal => {
                for &inv in &o.ins {
                    if is_sp(fd, inv) {
                        if let Some(j) = index(inv) {
                            eqs.push((i, j, 0));
                        }
                    }
                }
            }
            _ => {}
        }
    }
    // StackSolver::solve
    const UNKNOWN: i32 = 65535;
    let mut soln = vec![UNKNOWN; vnlist.len()];
    let n = eqs.len();
    for k in 0..n {
        let (a, b, r) = eqs[k];
        eqs.push((b, a, -r));
    }
    eqs.sort_by_key(|e| e.0);
    let propagate = |soln: &mut Vec<i32>, varnum: usize, val: i32| {
        if soln[varnum] != UNKNOWN {
            return;
        }
        soln[varnum] = val;
        let mut work = vec![varnum];
        while let Some(v) = work.pop() {
            let start = eqs.partition_point(|e| e.0 < v);
            for &(_, var2, rhs) in eqs[start..].iter().take_while(|e| e.0 == v) {
                if soln[var2] == UNKNOWN {
                    soln[var2] = soln[v] - rhs;
                    work.push(var2);
                }
            }
        }
    };
    propagate(&mut soln, 0, 0);
    let mut lastcount = guess.len() + 2;
    loop {
        let mut count = 0;
        for &(v1, v2, rhs) in &guess {
            match (soln[v1] != UNKNOWN, soln[v2] != UNKNOWN) {
                (true, false) => {
                    let val = soln[v1] - rhs;
                    propagate(&mut soln, v2, val)
                }
                (false, true) => {
                    let val = soln[v2] + rhs;
                    propagate(&mut soln, v1, val)
                }
                (false, false) => count += 1,
                _ => {}
            }
        }
        if count == lastcount {
            break;
        }
        lastcount = count;
        if count == 0 {
            break;
        }
    }
    let invn = vnlist[0];
    let mut warned = false;
    for i in 1..vnlist.len() {
        let vn = vnlist[i];
        let s = soln[i];
        if s == UNKNOWN {
            if !warned {
                fd.warning_header("Unable to track spacebase fully for stack");
                warned = true;
            }
            continue;
        }
        let op = fd.vn(vn).def.unwrap();
        let opc = fd.op(op).opc;
        if opc == Opcode::Indirect {
            if let Some(c) = fd.iop_target(fd.op(op).ins[1]).and_then(|iop| fd.call_of(iop)) {
                let s2 = if companion[i] >= 0 { soln[companion[i] as usize] } else { 0 };
                fd.call_mut(c).effective_extrapop = Some(s - s2);
            }
        }
        let c = fd.new_constant(size, (s as i64 as u64) & calc_mask(size));
        fd.op_set_opcode(op, Opcode::IntAdd);
        fd.op_set_all_input(op, &[invn, c])?;
        if opc == Opcode::Multiequal {
            let bb = fd.op(op).parent.unwrap();
            fd.op_uninsert(op);
            fd.op_insert_begin(op, bb);
        }
    }
    Ok(())
}

/// Port of `ActionDeindirect::apply`: an indirect call whose target is a known function (an
/// external-reference slot, or a constant through COPYs) becomes a direct call to it
/// (`FuncCallSpecs::deindirect`). With unlocked prototypes `lateRestriction` always succeeds and
/// only copies the callee's prototype, so no restart is needed. (Type recovery is off, so the
/// typed path does not apply.)
pub(crate) fn deindirect(fd: &mut Funcdata, arch: &Arch) -> Result<i32> {
    let mut count = 0;
    for i in 0..fd.qlst.len() {
        let c = fd.qlst[i];
        let op = fd.call(c).op;
        if fd.op(op).opc != Opcode::Callind {
            continue;
        }
        let mut vn = fd.op(op).ins[0];
        while let Some(d) = fd.vn(vn).def.filter(|&d| fd.op(d).opc == Opcode::Copy) {
            vn = fd.op(d).ins[0];
        }
        let v = fd.vn(vn);
        let target = if v.has(VnFlags::PERSIST) && v.is_free_or_input() {
            arch.externref_target(v.offset)
        } else if v.is_constant() {
            Some(v.offset)
        } else {
            None
        };
        let Some(entry) = target.filter(|e| arch.functions.contains_key(e)) else { continue };
        let callee = arch.functions[&entry].proto.clone();
        let call = fd.call_mut(c);
        call.entry = Some(entry);
        call.known = true;
        // lateRestriction: the call has a model, and neither prototype is locked
        call.proto.copy(&callee);
        if call.proto.model.is_none() {
            let models = &arch.spec.models;
            call.proto.set_model(models, models.default);
        }
        let fspec = fd.new_varnode_callspecs(c);
        fd.op_set_input(op, fspec, 0)?;
        fd.op_set_opcode(op, Opcode::Call);
        count += 1;
    }
    Ok(count)
}

// ---------------------------------------------------------------------------------------
// Block edits: ActionRedundBranch, ActionDeterminedBranch, ActionUnreachable, ActionDoNothing

/// Port of `Funcdata::structureReset`.
fn structure_reset(fd: &mut Funcdata) -> Result<()> {
    fd.blocks.structure_loops()?;
    fd.heritage.force_restructure();
    Ok(())
}

/// Port of `Funcdata::opZeroMulti`.
fn op_zero_multi(fd: &mut Funcdata, arch: &Arch, op: OpId) -> Result<()> {
    match fd.op(op).ins.len() {
        0 => {
            let out = fd.op(op).out.unwrap();
            let (sp, off, size) = (fd.vn(out).space, fd.vn(out).offset, fd.vn(out).size);
            let vn = fd.new_varnode(size, sp, off);
            fd.op_insert_input(op, vn, 0)?;
            fd.set_input_varnode(vn, arch)?;
            fd.op_set_opcode(op, Opcode::Copy);
        }
        1 => fd.op_set_opcode(op, Opcode::Copy),
        _ => {}
    }
    Ok(())
}

/// Port of `Funcdata::branchRemoveInternal`.
fn branch_remove_internal(fd: &mut Funcdata, arch: &Arch, bb: BlockId, num: usize) -> Result<()> {
    if fd.blocks.block(bb).outs.len() == 2 {
        if let Some(&last) = fd.blocks.block(bb).ops.last() {
            fd.op_destroy(last);
        }
    }
    let bbout = fd.blocks.block(bb).outs[num].point;
    let blocknum = fd.blocks.block(bbout).ins.iter().position(|e| e.point == bb).unwrap();
    fd.blocks.remove_edge(bb, bbout);
    for op in fd.blocks.block(bbout).ops.clone() {
        if fd.op(op).opc != Opcode::Multiequal {
            break;
        }
        fd.op_remove_input(op, blocknum);
        op_zero_multi(fd, arch, op)?;
    }
    Ok(())
}

/// Port of `Funcdata::spliceBlockBasic`.
fn splice_block_basic(fd: &mut Funcdata, bl: BlockId) -> Result<()> {
    let outbl = fd.blocks.block(bl).outs[0].point;
    if let Some(&jump) = fd.blocks.block(bl).ops.last() {
        if fd.op(jump).is_branch() {
            fd.op_destroy(jump);
        }
    }
    let moved = fd.blocks.block(outbl).ops.clone();
    if let Some(&first) = moved.first() {
        if fd.op(first).opc == Opcode::Multiequal {
            return err("Splicing block with MULTIEQUAL");
        }
        fd.op_mut(first).flags.clear(OpFlags::START_BASIC);
        for &op in &moved {
            fd.op_mut(op).parent = Some(bl);
        }
        fd.blocks.block_mut(bl).ops.extend(moved);
        fd.blocks.block_mut(outbl).ops.clear();
        fd.set_order(bl);
    }
    // mergeRange
    let (start, stop) = (fd.blocks.block(outbl).start, fd.blocks.block(outbl).stop);
    let b = fd.blocks.block_mut(bl);
    b.start = b.start.min(start);
    b.stop = b.stop.max(stop);
    fd.blocks.splice_block(bl);
    structure_reset(fd)
}

/// Port of `ActionRedundBranch::apply`.
pub(crate) fn redund_branch(fd: &mut Funcdata, arch: &Arch) -> Result<i32> {
    let mut count = 0;
    let mut i = 0;
    while i < fd.blocks.list.len() {
        let bb = fd.blocks.list[i];
        i += 1;
        let outs: Vec<BlockId> = fd.blocks.block(bb).outs.iter().map(|e| e.point).collect();
        let Some(&bl) = outs.first() else { continue };
        if outs.len() == 1 {
            // a switch's block has several outs, so isSwitchOut never holds here
            if fd.blocks.block(bl).ins.len() == 1 && !fd.blocks.is_entry_point(bl) {
                splice_block_basic(fd, bb)?;
                count += 1;
                i = 0;
            }
            continue;
        }
        if outs.iter().any(|&o| o != bl) {
            continue;
        }
        branch_remove_internal(fd, arch, bb, 1)?;
        structure_reset(fd)?;
        count += 1;
    }
    Ok(count)
}

/// Port of `ActionDeterminedBranch::apply`.
pub(crate) fn determined_branch(fd: &mut Funcdata, arch: &Arch) -> Result<i32> {
    let mut count = 0;
    for i in 0..fd.blocks.list.len() {
        let bb = fd.blocks.list[i];
        let Some(&cb) = fd.blocks.block(bb).ops.last() else { continue };
        if fd.op(cb).opc != Opcode::Cbranch {
            continue;
        }
        let cond = fd.op(cb).ins[1];
        if !fd.vn(cond).is_constant() {
            continue;
        }
        let flip = fd.op(cb).flags.has(OpFlags::BOOLEAN_FLIP);
        let num = if (fd.vn(cond).offset != 0) != flip { 0 } else { 1 };
        branch_remove_internal(fd, arch, bb, num)?;
        structure_reset(fd)?;
        count += 1;
    }
    Ok(count)
}

/// Port of `ActionUnreachable::apply` (`removeUnreachableBlocks` with the cached check).
pub(crate) fn unreachable(fd: &mut Funcdata, _: &Arch) -> Result<i32> {
    if !fd.blocks.unreachable {
        return Ok(0);
    }
    err("removing unreachable blocks: not implemented in ghidra-rs yet")
}

/// Port of `ActionDoNothing::apply`: a block holding nothing but markers (and a BRANCH) goes,
/// its predecessors jumping straight to its successor.
pub(crate) fn do_nothing(fd: &mut Funcdata, arch: &Arch) -> Result<i32> {
    for i in 0..fd.blocks.list.len() {
        let bb = fd.blocks.list[i];
        if !is_do_nothing(fd, bb) {
            continue;
        }
        let b = fd.blocks.block(bb);
        if b.outs[0].point == bb {
            continue; // an infinite loop: a warning only
        }
        if !unblocked_multi(fd, bb) {
            continue;
        }
        if !has_no_immediate_copy(fd, bb) {
            continue; // setDelayedDonothing: for ActionLateDoNothing (group blockrecovery)
        }
        remove_do_nothing_block(fd, arch, bb)?;
        return Ok(1);
    }
    Ok(0)
}

/// Port of `BlockBasic::isDoNothing` (no switch exists without S3's switch flags; an indirect
/// jump is never one).
fn is_do_nothing(fd: &Funcdata, bb: BlockId) -> bool {
    let b = fd.blocks.block(bb);
    if b.outs.len() != 1 || b.ins.is_empty() {
        return false;
    }
    if b.ins.iter().any(|e| fd.blocks.block(e.point).outs.len() > 2) {
        return false; // a predecessor that is a switch: S3 decides
    }
    b.ops.iter().all(|&o| {
        let op = fd.op(o);
        op.is_marker() || op.opc == Opcode::Branch
    })
}

/// Port of `BlockBasic::unblockedMulti`: removing `bb` would not merge two different values
/// into one MULTIEQUAL slot of its successor.
fn unblocked_multi(fd: &Funcdata, bb: BlockId) -> bool {
    let blout = fd.blocks.block(bb).outs[0].point;
    let redund: Vec<BlockId> = fd
        .blocks
        .block(bb)
        .ins
        .iter()
        .map(|e| e.point)
        .filter(|&p| fd.blocks.block(p).outs.iter().any(|e| e.point == blout))
        .collect();
    if redund.is_empty() {
        return true;
    }
    let in_this = fd.blocks.block(blout).ins.iter().position(|e| e.point == bb).unwrap();
    for &op in &fd.blocks.block(blout).ops {
        if fd.op(op).opc != Opcode::Multiequal {
            continue;
        }
        for &bl in &redund {
            let mut vnremove = fd.op(op).ins[in_this];
            if let Some(other) = fd.vn(vnremove).def {
                if fd.op(other).opc == Opcode::Multiequal && fd.op(other).parent == Some(bb) {
                    let idx = fd.blocks.block(bb).ins.iter().position(|e| e.point == bl).unwrap();
                    vnremove = fd.op(other).ins[idx];
                }
            }
            let idx = fd.blocks.block(blout).ins.iter().position(|e| e.point == bl).unwrap();
            if vnremove != fd.op(op).ins[idx] {
                return false;
            }
        }
    }
    true
}

/// `BlockBasic::hasNoImmediateCopy`: only copy propagation (`RulePropagateCopy`, stage R1)
/// marks the immediate-copy edges it looks for, so with the rules off there are none.
fn has_no_immediate_copy(_: &Funcdata, _: BlockId) -> bool {
    true
}

/// Port of `Funcdata::pushMultiequals`: a MULTIEQUAL of `bb` read past its successor gets a
/// MULTIEQUAL in the successor, so the value survives `bb`'s removal.
fn push_multiequals(fd: &mut Funcdata, bb: BlockId) -> Result<()> {
    if fd.blocks.block(bb).outs.is_empty() {
        return Ok(());
    }
    let outblock = fd.blocks.block(bb).outs[0].point;
    let outblock_ind = fd.blocks.block(bb).outs[0].reverse;
    for origop in fd.blocks.block(bb).ops.clone() {
        if fd.op(origop).opc != Opcode::Multiequal {
            continue;
        }
        let origvn = fd.op(origop).out.unwrap();
        let mut needreplace = false;
        let mut neednewunique = false;
        for &op in fd.vn(origvn).descend.iter() {
            let o = fd.op(op);
            if o.opc == Opcode::Multiequal && o.parent == Some(outblock) {
                let dead_edge = !o.ins.iter().enumerate().any(|(i, &v)| i != outblock_ind && v == origvn);
                if dead_edge {
                    let out = fd.vn(o.out.unwrap());
                    let ov = fd.vn(origvn);
                    if out.space == ov.space && out.offset == ov.offset && ov.has(VnFlags::ADDRTIED) {
                        neednewunique = true;
                    }
                    continue;
                }
            }
            needreplace = true;
            break;
        }
        if !needreplace {
            continue;
        }
        let (space, offset, size) = (fd.vn(origvn).space, fd.vn(origvn).offset, fd.vn(origvn).size);
        let replacevn = if neednewunique {
            fd.new_unique(size, fd.uniq.unwrap_or(0))
        } else {
            fd.new_varnode(size, space, offset)
        };
        let branches: Vec<VarnodeId> = fd
            .blocks
            .block(outblock)
            .ins
            .iter()
            .map(|e| if e.point == bb { origvn } else { replacevn })
            .collect();
        let start = fd.blocks.block(outblock).start;
        let replaceop = fd.new_op(Opcode::Multiequal, start);
        fd.op_set_output(replaceop, replacevn)?;
        fd.op_set_all_input(replaceop, &branches)?;
        fd.op_insert_begin(replaceop, outblock);
        for op in fd.vn(origvn).descend.to_vec() {
            for i in 0..fd.op(op).ins.len() {
                if fd.op(op).ins[i] != origvn {
                    continue;
                }
                if i == outblock_ind && fd.op(op).parent == Some(outblock) && fd.op(op).opc == Opcode::Multiequal {
                    continue;
                }
                fd.op_set_input(op, replacevn, i)?;
                break;
            }
        }
    }
    Ok(())
}

/// Port of `Funcdata::removeDoNothingBlock` (`blockRemoveInternal` for a reachable block).
fn remove_do_nothing_block(fd: &mut Funcdata, arch: &Arch, bb: BlockId) -> Result<()> {
    push_multiequals(fd, bb)?;
    let nin = fd.blocks.block(bb).ins.len();
    for e in fd.blocks.block(bb).outs.clone() {
        let bbout = e.point;
        let blocknum = e.reverse;
        for op in fd.blocks.block(bbout).ops.clone() {
            if fd.op(op).opc != Opcode::Multiequal {
                continue;
            }
            let deadvn = fd.op(op).ins[blocknum];
            fd.op_remove_input(op, blocknum);
            let deadop = fd.vn(deadvn).def.filter(|&d| fd.op(d).opc == Opcode::Multiequal && fd.op(d).parent == Some(bb));
            for j in 0..nin {
                let v = match deadop {
                    Some(d) => fd.op(d).ins[j],
                    None => deadvn,
                };
                let n = fd.op(op).ins.len();
                fd.op_insert_input(op, v, n)?;
            }
            op_zero_multi(fd, arch, op)?;
        }
    }
    fd.blocks.remove_from_flow(bb);
    for op in fd.blocks.block(bb).ops.clone() {
        if let Some(out) = fd.op(op).out {
            if fd.vn(out).descend.iter().any(|&d| fd.op(d).parent.is_some_and(|p| p != bb)) {
                return err("Deleting op with descendants");
            }
        }
        fd.op_destroy(op);
    }
    fd.blocks.remove_block(bb);
    structure_reset(fd)
}

// ---------------------------------------------------------------------------------------
// ActionLikelyTrash, ActionUnjustifiedParams, ActionNodeJoin, ActionConditionalExe

/// Port of `ActionLikelyTrash::apply`: an input register the model calls likely trash, whose
/// value reaches only INDIRECTs, partial copies and masks, is cut off there.
pub(crate) fn likely_trash(fd: &mut Funcdata, arch: &Arch) -> Result<i32> {
    let Some(m) = fd.proto.model else { return Ok(0) };
    let mut count = 0;
    for st in arch.spec.models.get(m).likelytrash.clone() {
        let super::fspec::Storage::Space { space, offset, size } = st else { continue };
        let Some(vn) = fd.find_covered_input(Space::Sleigh(space), offset, size) else { continue };
        let Some(indlist) = trace_trash(fd, vn) else { continue };
        for op in indlist {
            if fd.op(op).opc == Opcode::Indirect {
                let sz = fd.vn(fd.op(op).out.unwrap()).size;
                let c = fd.new_constant(sz, 0);
                fd.op_set_input(op, c, 0)?;
                // markIndirectCreation(op, false)
                fd.op_mut(op).flags.set(OpFlags::INDIRECT_CREATION);
                let out = fd.op(op).out.unwrap();
                fd.vn_set(out, VnFlags::INDIRECT_CREATION);
                let in0 = fd.op(op).ins[0];
                fd.vn_set(in0, VnFlags::INDIRECT_CREATION);
            } else {
                let sz = fd.vn(fd.op(op).ins[1]).size;
                let c = fd.new_constant(sz, 0);
                fd.op_set_input(op, c, 1)?;
            }
            count += 1;
        }
    }
    Ok(count)
}

/// Port of `ActionLikelyTrash::traceTrash`: the ops to cut, or `None` when the value is used.
fn trace_trash(fd: &Funcdata, vn: VarnodeId) -> Option<Vec<OpId>> {
    let mut indlist = Vec::new();
    let mut allroutes = Vec::new();
    let mut marked: Vec<VarnodeId> = vec![vn];
    let mut opmark: HashSet<OpId> = HashSet::new();
    let mut traced = 0;
    while traced < marked.len() {
        let cur = marked[traced];
        traced += 1;
        for &op in fd.vn(cur).descend.iter() {
            let o = fd.op(op);
            let out = o.out;
            let persist = out.is_some_and(|v| fd.vn(v).has(VnFlags::PERSIST));
            match o.opc {
                Opcode::Indirect => {
                    if persist {
                        return None;
                    } else if o.flags.has(OpFlags::INDIRECT_STORE) {
                        let out = out.unwrap();
                        if !marked.contains(&out) {
                            marked.push(out);
                        }
                    } else {
                        indlist.push(op);
                    }
                }
                Opcode::Subpiece => {
                    if persist {
                        return None;
                    }
                    let out = out.unwrap();
                    if !marked.contains(&out) {
                        marked.push(out);
                    }
                }
                Opcode::Multiequal | Opcode::Piece => {
                    if persist {
                        return None;
                    }
                    if opmark.insert(op) {
                        allroutes.push(op);
                    }
                    let nummark = o.ins.iter().filter(|v| marked.contains(v)).count();
                    if nummark == o.ins.len() {
                        let out = out.unwrap();
                        if !marked.contains(&out) {
                            marked.push(out);
                        }
                    }
                }
                Opcode::IntAnd => {
                    let c = fd.vn(o.ins[1]);
                    let mask = calc_mask(c.size);
                    let wide = |sh: u32| if sh >= 64 { 0 } else { (mask << sh) & mask };
                    if c.is_constant() && (c.offset == wide(8) || c.offset == wide(16) || c.offset == wide(32)) {
                        indlist.push(op);
                    } else {
                        return None;
                    }
                }
                _ => return None,
            }
        }
    }
    for op in allroutes {
        if !marked.contains(&fd.op(op).out.unwrap()) {
            return None;
        }
    }
    Some(indlist)
}

/// Port of `ActionUnjustifiedParams::apply`: an input that sits in a parameter entry but not
/// justified would be widened (`adjustInputVarnodes`), which is not ported; it fails loudly.
pub(crate) fn unjustified_params(fd: &mut Funcdata, arch: &Arch) -> Result<i32> {
    let Some(m) = fd.proto.model else { return Ok(0) };
    let list = &arch.spec.models.get(m).input;
    for vn in fd.loc_all() {
        let v = fd.vn(vn);
        if !v.is_input() {
            continue;
        }
        let Space::Sleigh(_) = v.space else { continue };
        // unjustifiedInputParam: an entry contains it, not at the justified offset
        let unjustified = (0..list.entries.len()).any(|i| {
            list.justified_contain(i, v.space, v.offset, v.size).is_some_and(|o| o != 0)
                && !(0..list.entries.len()).any(|j| list.justified_contain(j, v.space, v.offset, v.size) == Some(0))
        });
        if unjustified {
            return err("unjustified input parameter: adjustInputVarnodes is not implemented in ghidra-rs yet");
        }
    }
    Ok(0)
}

/// `ActionNodeJoin`: two CBRANCHes on the same condition into a shared block are joined
/// (`ConditionalJoin`), which is not ported; finding one fails loudly. (Functionally equal
/// conditions in different varnodes are not looked for.)
pub(crate) fn node_join(fd: &mut Funcdata, _: &Arch) -> Result<i32> {
    for &bb in &fd.blocks.list {
        let b = fd.blocks.block(bb);
        if b.outs.len() != 2 {
            continue;
        }
        let (o1, o2) = (b.outs[0].point, b.outs[1].point);
        let (leastout, inslot) = if fd.blocks.block(o1).ins.len() < fd.blocks.block(o2).ins.len() {
            (o1, b.outs[0].reverse)
        } else {
            (o2, b.outs[1].reverse)
        };
        if fd.blocks.block(leastout).ins.len() == 1 || o1 == o2 {
            continue;
        }
        for (j, e) in fd.blocks.block(leastout).ins.iter().enumerate() {
            let bb2 = e.point;
            if j == inslot || bb2 == bb || fd.blocks.block(bb2).outs.len() != 2 {
                continue;
            }
            let cond = |b: BlockId| {
                let op = *fd.blocks.block(b).ops.last()?;
                (fd.op(op).opc == Opcode::Cbranch).then(|| fd.op(op).ins[1])
            };
            if cond(bb).is_some() && cond(bb) == cond(bb2) {
                return err("ActionNodeJoin: joining two branches on one condition is not implemented in ghidra-rs yet");
            }
        }
    }
    Ok(0)
}

/// `ActionConditionalExe`: a block re-testing the condition of the block that decided how it
/// was reached is removed (condexe.cc), which is not ported; finding a candidate on the same
/// condition varnode fails loudly.
pub(crate) fn conditional_exe(fd: &mut Funcdata, _: &Arch) -> Result<i32> {
    if fd.blocks.unreachable {
        return Ok(0);
    }
    for &ib in &fd.blocks.list {
        let b = fd.blocks.block(ib);
        if b.ins.len() != 2 || b.outs.len() != 2 {
            continue;
        }
        let Some(&cb) = b.ops.last() else { continue };
        if fd.op(cb).opc != Opcode::Cbranch {
            continue;
        }
        let walk = |mut t: BlockId| {
            while fd.blocks.block(t).outs.len() == 1 && fd.blocks.block(t).ins.len() == 1 {
                t = fd.blocks.block(t).ins[0].point;
            }
            t
        };
        let init = walk(b.ins[0].point);
        if fd.blocks.block(init).outs.len() != 2 || walk(b.ins[1].point) != init || init == ib {
            continue;
        }
        let Some(&icb) = fd.blocks.block(init).ops.last() else { continue };
        if fd.op(icb).opc == Opcode::Cbranch && fd.op(icb).ins[1] == fd.op(cb).ins[1] {
            return err("ActionConditionalExe: removing a re-tested condition is not implemented in ghidra-rs yet");
        }
    }
    Ok(0)
}
