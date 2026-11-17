//! Port of `FlowInfo` (flow.cc) and `Funcdata::followFlow` (funcdata_op.cc): decode the
//! function's instructions into p-code with the milestone-1 SLEIGH engine, in Ghidra's order,
//! then split the ops into basic blocks.
//!
//! The order matters: op sequence numbers count creation, and blocks follow the dead list. So
//! the address stack (`addrlist`, last in first out), the per-instruction marking of block
//! starts and the deletion of ops after a branch follow the C++ step by step.

use super::block::BlockId;
use super::fspec::CallSpec;
use super::fspec::Storage;
use super::funcdata::{CallId, Funcdata, JumpTable};
use super::jumptable::{self, Fail};
use super::op::{Halt, OpFlags, OpId, SeqNum};
use super::opcode::Opcode;
use super::varnode::{Space, VarnodeId};
use super::{action, err, Arch, LowlevelError, Result};
use crate::sleigh::{Parse, PcodeError};
use std::collections::BTreeMap;
use std::collections::HashSet;

/// `Architecture::max_instructions`
const MAX_INSTRUCTIONS: u32 = 100_000;
/// `Architecture::max_baddata`
const MAX_BADDATA: u32 = 4;
/// `FlowInfo::eaddr`: the end of the code space (flow is not bounded within it)
const END_ADDR: u64 = u64::MAX;

/// Port of `FlowInfo::VisitStat`: an instruction's length and its first op, if any.
#[derive(Debug, Clone, Copy)]
struct VisitStat {
    size: u64,
    seq: Option<SeqNum>,
}

/// Where a relative (p-code internal) branch goes (`FlowInfo::findRelTarget`).
enum RelTarget {
    Op(OpId),
    /// past the end of the instruction: the fall-through address
    Fallthru(u64),
}

/// Why an instruction produced no p-code.
enum EmitError {
    /// `BadDataError`: no constructor matches
    BadData(String),
    /// `UnimplError`: the constructor has no p-code
    Unimplemented,
    /// an error that ends the decompile (`LowlevelError`)
    Fatal(LowlevelError),
}

struct Flow<'a> {
    fd: &'a mut Funcdata,
    arch: &'a Arch,
    parse: Parse,
    visited: BTreeMap<u64, VisitStat>,
    addrlist: Vec<u64>,
    tablelist: Vec<OpId>,
    /// calls to replace by their call fixup (`FlowInfo::injectlist`)
    injectlist: Vec<CallId>,
    insn_count: u32,
    baddata_count: u32,
    /// `reinterpreted_present`: the overlap warning is in the header
    reinterpreted_present: bool,
}

/// Port of `Funcdata::followFlow` (flow over the whole code space): `FlowInfo::generateOps`
/// then `FlowInfo::generateBlocks`.
pub(crate) fn follow_flow(fd: &mut Funcdata, arch: &Arch) -> Result<()> {
    let mut flow = Flow {
        fd,
        arch,
        parse: arch.sleigh.new_parse(),
        visited: BTreeMap::new(),
        addrlist: Vec::new(),
        tablelist: Vec::new(),
        injectlist: Vec::new(),
        insn_count: 0,
        baddata_count: 0,
        reinterpreted_present: false,
    };
    flow.generate_ops()?;
    flow.generate_blocks()
}

/// What `stageJumpTable` recovers: the table's addresses and the values of its model, or why not.
type Staged = std::result::Result<(Vec<u64>, Option<jumptable::ValueRange>), Fail>;

/// The partial function of jump-table recovery (`stageJumpTable`): not made yet, made and
/// simplified (with the unported error of its stack rules when it was made without them), or
/// made with a failed `jumptable` action.
enum Partial {
    None,
    Ready(Box<Funcdata>, Option<LowlevelError>),
    Failed,
}

/// The varnodes of the data flow into `start` in the partial function `p` (every input of every
/// op on the way).
fn flow_into(p: &Funcdata, start: VarnodeId) -> HashSet<VarnodeId> {
    let mut seen = HashSet::new();
    let mut work = vec![start];
    while let Some(vn) = work.pop() {
        if !seen.insert(vn) {
            continue;
        }
        if let Some(d) = p.vn(vn).def {
            work.extend(p.op(d).ins.iter().copied());
        }
    }
    seen
}

/// Whether `op` is the INDIRECT of a stack varnode that `opCollapseIndirectsForAlias` may remove
/// (through `RuleAliasUpdate`, on a STORE or a call): not an indirect creation.
fn is_stack_indirect(p: &Funcdata, op: OpId) -> bool {
    let o = p.op(op);
    o.opc == Opcode::Indirect
        && !o.flags.has(OpFlags::INDIRECT_CREATION)
        && o.out.is_some_and(|v| p.vn(v).space == Space::Stack)
}

/// A copy of the partial function `p` with every INDIRECT of a stack varnode removed, as if
/// `RuleAliasUpdate` had collapsed them all; `None` when it has none.
fn without_stack_indirects(p: &Funcdata, arch: &Arch) -> Result<Option<Funcdata>> {
    let ops: Vec<OpId> = p
        .ops_created_with(Opcode::Indirect)
        .into_iter()
        .filter(|&o| !p.op(o).is_dead() && is_stack_indirect(p, o))
        .collect();
    if ops.is_empty() {
        return Ok(None);
    }
    let mut q = p.clone();
    for o in ops {
        let (Some(out), inp) = (q.op(o).out, q.op(o).ins[0]) else { continue };
        q.total_replace(out, inp)?;
        q.op_destroy(o);
    }
    jumptable::calc_nz_mask(&mut q, arch);
    Ok(Some(q))
}

/// The LOADs among the defining ops of `flow` whose address depends on a varnode `on_sp` holds
/// for (the stack pointer): the stack reads of the partial function made without the stack rules.
fn stack_loads(p: &Funcdata, flow: &HashSet<VarnodeId>, on_sp: impl Fn(&VarnodeId) -> bool) -> HashSet<OpId> {
    let loads = flow.iter().filter_map(|&v| p.vn(v).def).filter(|&d| p.op(d).opc == Opcode::Load);
    loads.filter(|&d| flow_into(p, p.op(d).ins[1]).iter().any(&on_sp)).collect()
}

fn ram_addr(a: u64) -> String {
    format!("(ram,0x{a:08x})")
}

/// The flow override `kind` of an instruction of the facts (stage S10) on its p-code, as Java
/// applies it before the decompiler sees the ops (`PcodeEmit.dumpCallOverride` with
/// `dumpNullReturn`): `CALL_RETURN` makes the final branch a call and adds `RETURN #0`. The
/// conditional form and the other overrides are not ported.
fn call_return_override(
    ops: &mut Vec<crate::sleigh::PcodeOp>,
    kind: &str,
    ptr_size: u32,
) -> std::result::Result<(), String> {
    let unported = || format!("facts: the flow override {kind} is not ported");
    if kind != "CALL_RETURN" {
        return Err(unported());
    }
    // every other op must leave the flow alone, and a relative branch is not overridden
    let (last, before) = ops.split_last_mut().ok_or_else(unported)?;
    let is = |op: &crate::sleigh::PcodeOp, opc: Opcode| op.opc == opc as u8;
    let flow = [Opcode::Branch, Opcode::Cbranch, Opcode::Branchind, Opcode::Call, Opcode::Callind, Opcode::Return];
    if before.iter().any(|op| flow.iter().any(|&f| is(op, f))) {
        return Err(unported());
    }
    if is(last, Opcode::Branch) {
        if last.ins.first().is_none_or(|v| v.space == 0) {
            return Ok(());
        }
        last.opc = Opcode::Call as u8;
    } else if is(last, Opcode::Branchind) || is(last, Opcode::Return) {
        last.opc = Opcode::Callind as u8;
    } else if !is(last, Opcode::Call) && !is(last, Opcode::Callind) {
        return Err(unported());
    }
    let null = crate::sleigh::Varnode { space: 0, offset: 0, size: ptr_size };
    ops.push(crate::sleigh::PcodeOp { opc: Opcode::Return as u8, out: None, ins: vec![null] });
    Ok(())
}

impl Flow<'_> {
    fn opc(&self, op: OpId) -> Opcode {
        self.fd.op(op).opc
    }
    fn mark(&mut self, op: OpId, f: OpFlags) {
        self.fd.op_mut(op).flags.set(f);
    }

    /// Port of `FlowInfo::generateOps`. (Inlining and multistage tables are not ported: the
    /// console has no inline functions and no jump-table overrides.)
    fn generate_ops(&mut self) -> Result<()> {
        self.addrlist.push(self.fd.entry);
        while !self.addrlist.is_empty() {
            self.fallthru()?;
        }
        self.inject_pcode()?;
        loop {
            while !self.tablelist.is_empty() {
                let tables = self.recover_jump_tables()?;
                for jt in tables {
                    for i in 0..self.fd.jumptables[jt].targets.len() {
                        self.new_address(self.fd.jumptables[jt].targets[i])?;
                    }
                    while !self.addrlist.is_empty() {
                        self.fallthru()?;
                    }
                }
            }
            self.check_contained_call()?;
            self.inject_pcode()?;
            if self.tablelist.is_empty() {
                return Ok(());
            }
        }
    }

    /// Port of `FlowInfo::injectPcode` for call fixups (`injectSubFunction`, `deleteCallSpec`):
    /// each queued call is replaced by its fixup's p-code.
    fn inject_pcode(&mut self) -> Result<()> {
        for call in std::mem::take(&mut self.injectlist) {
            let Some(inject) = self.fd.call(call).proto.inject else { continue };
            let arch = self.arch;
            let payload = arch.spec.injects.payload(inject);
            self.do_injection(&payload.ops, call)?;
            // the injected call's callee is always known: its prototype holds the fixup
            let callee =
                self.fd.call(call).callee().and_then(|e| arch.functions.get(&e)).map_or("", |f| f.name.as_str());
            self.fd.warning_header(format!("Function: {callee} replaced with injection: {}", payload.name));
            self.fd.qlst.retain(|&c| c != call);
        }
        Ok(())
    }

    /// Port of `FlowInfo::doInjection` for a call: the snippet's ops are made at the end of the
    /// dead list, walked for control flow, moved to just after the call, and the call is deleted.
    fn do_injection(&mut self, ops: &[crate::sleigh::PcodeOp], call: CallId) -> Result<()> {
        let op = self.fd.call(call).op;
        let first = self.fd.dead.len();
        self.fd.emit_pcode(self.fd.op(op).seq.addr, ops)?;
        let Some(&firstop) = self.fd.dead.get(first) else {
            return err("Empty injection");
        };
        let mut startbasic = self.fd.op(op).flags.has(OpFlags::START_BASIC);
        self.xref_control_flow(first, &mut startbasic)?;
        let pos = self
            .fd
            .dead
            .iter()
            .position(|&o| o == op)
            .ok_or_else(|| LowlevelError("injected call is not in the dead list".into()))?;
        if startbasic {
            // the injection does not fall through: the op after the call starts a block
            if let Some(&next) = self.fd.dead.get(pos + 1) {
                self.mark(next, OpFlags::START_BASIC);
            }
        }
        // PcodeOpBank::moveSequenceDead, then the call leaves the list (opDestroyRaw)
        let run = self.fd.dead.split_off(first);
        self.fd.dead.splice(pos..=pos, run);
        self.update_target(op, firstop);
        self.fd.op_destroy_raw(op);
        Ok(())
    }

    /// Port of `FlowInfo::updateTarget`: an instruction whose first op was `old` now starts at `new`.
    fn update_target(&mut self, old: OpId, new: OpId) {
        let seq = self.fd.op(old).seq;
        if let Some(stat) = self.visited.get_mut(&seq.addr).filter(|s| s.seq == Some(seq)) {
            stat.seq = Some(self.fd.op(new).seq);
        }
    }

    /// Port of `FlowInfo::fallthru`: decode straight-line code from the top of the address
    /// stack until flow stops or reaches code already decoded.
    fn fallthru(&mut self) -> Result<()> {
        let Some(mut bound) = self.set_fallthru_bound()? else { return Ok(()) };
        let mut startbasic = true;
        while let Some(cur) = self.addrlist.pop() {
            if !self.process_instruction(cur, &mut startbasic)? {
                break;
            }
            let Some(&next) = self.addrlist.last() else { break };
            if bound <= next {
                if bound == next {
                    if startbasic {
                        let op = self.target(next)?;
                        self.mark(op, OpFlags::START_BASIC);
                    }
                    self.addrlist.pop();
                    break;
                }
                match self.set_fallthru_bound()? {
                    Some(b) => bound = b,
                    None => return Ok(()),
                }
            }
        }
        Ok(())
    }

    /// Port of `FlowInfo::setFallthruBound`: `None` when the next address was decoded already
    /// (it then only starts a block); else the next decoded address above it.
    fn set_fallthru_bound(&mut self) -> Result<Option<u64>> {
        let Some(&addr) = self.addrlist.last() else { return Ok(None) };
        if let Some((&start, stat)) = self.visited.range(..=addr).next_back() {
            if start == addr {
                let op = self.target(addr)?;
                self.mark(op, OpFlags::START_BASIC);
                self.addrlist.pop();
                return Ok(None);
            }
            if addr < start + stat.size {
                // FlowInfo::reinterpreted: decoding into the middle of an instruction (the
                // message ends in a newline, as the C++ `endl`)
                let msg = format!("Instruction at {} overlaps instruction at {}\n", ram_addr(addr), ram_addr(start));
                self.count_bad_data(msg.clone())?;
                if !self.reinterpreted_present {
                    self.reinterpreted_present = true;
                    self.fd.warning_header(msg);
                }
            }
        }
        Ok(Some(self.visited.range(addr + 1..).next().map_or(END_ADDR, |(&a, _)| a)))
    }

    /// Port of `FlowInfo::countBadData`.
    fn count_bad_data(&mut self, msg: String) -> Result<()> {
        if self.baddata_count >= MAX_BADDATA {
            return err(format!("Bad instruction count exceeded:\n    ...\n    {msg}"));
        }
        self.baddata_count += 1;
        Ok(())
    }

    /// Port of `FlowInfo::processInstruction`: decode one instruction, wire up its control flow;
    /// `true` when flow falls through to the next instruction.
    fn process_instruction(&mut self, addr: u64, startbasic: &mut bool) -> Result<bool> {
        if self.insn_count >= MAX_INSTRUCTIONS {
            return err("Flow exceeded maximum allowable instructions");
        }
        self.insn_count += 1;
        let first = self.fd.dead.len();
        let step = match self.emit(addr) {
            Ok(len) => len,
            Err(EmitError::Unimplemented) => {
                self.artificial_halt(addr, Some(Halt::Unimplemented))?;
                self.fd.warning("Unimplemented instruction - Truncating control flow here", addr);
                // `unimplemented_present`: the header warning once (`print C` prints it once)
                self.fd.warning_header("Control flow encountered unimplemented instructions");
                1
            }
            Err(EmitError::BadData(msg)) => {
                self.count_bad_data(msg)?;
                self.artificial_halt(addr, Some(Halt::BadInstruction))?;
                self.fd.warning("Bad instruction - Truncating control flow here", addr);
                // `baddata_present`
                self.fd.warning_header("Control flow encountered bad instruction data");
                1
            }
            Err(EmitError::Fatal(e)) => return Err(e),
        };
        // Recorded before the ops are walked: a relative branch to the end of its own
        // instruction (x86 INTO) finds the fall-through address through `visited`.
        let first_op = self.fd.dead.get(first).copied();
        let seq = first_op.map(|op| self.fd.op(op).seq);
        self.visited.insert(addr, VisitStat { size: step, seq });
        let mut isfallthru = true;
        if let Some(op) = first_op {
            self.mark(op, OpFlags::START_INSTRUCTION);
            isfallthru = self.xref_control_flow(first, startbasic)?;
        }
        if isfallthru {
            self.addrlist.push(addr + step);
        }
        Ok(isfallthru)
    }

    /// The SLEIGH translation of one instruction into new ops (`Sleigh::oneInstruction` with
    /// `PcodeEmitFd::dump`); returns the instruction length.
    fn emit(&mut self, addr: u64) -> std::result::Result<u64, EmitError> {
        let sl = &self.arch.sleigh;
        // LoadImageBfd::loadFill: an unmapped address is a DataUnavailError, which ends the decompile;
        // the loader reads 512-byte chunks (`bufsize`), so the message names all 512
        let bytes = self
            .arch
            .bytes_at(addr)
            .ok_or_else(|| EmitError::Fatal(LowlevelError(format!("Unable to load 512 bytes at r0x{addr:08x}"))))?;
        let len = sl.decode(&mut self.parse, addr, bytes).map_err(EmitError::BadData)?;
        let mut ops = sl.pcode(&self.parse).map_err(|e| match e {
            PcodeError::Unimplemented => EmitError::Unimplemented,
            PcodeError::Invalid(e) => EmitError::Fatal(LowlevelError(e)),
        })?;
        if let Some(facts) = &self.arch.facts {
            for kind in facts.overrides(addr) {
                call_return_override(&mut ops, kind, sl.spaces.get(sl.code_space() as usize).map_or(4, |s| s.size))
                    .map_err(|e| EmitError::Fatal(LowlevelError(format!("{e} at r0x{addr:08x}"))))?;
            }
        }
        self.fd.emit_pcode(addr, &ops).map_err(EmitError::Fatal)?;
        Ok(len as u64)
    }

    /// Port of `FlowInfo::xrefControlFlow`: walk the instruction's new ops from dead-list
    /// position `start`, queue branch targets, mark block starts and drop ops after a final
    /// branch; `true` when the instruction falls through.
    fn xref_control_flow(&mut self, start: usize, startbasic: &mut bool) -> Result<bool> {
        let mut maxtime = 0; // the deepest internal relative branch
        let mut isfallthru = false;
        let mut last = None;
        let mut i = start;
        while let Some(&op) = self.fd.dead.get(i) {
            i += 1;
            last = Some(op);
            if *startbasic {
                self.mark(op, OpFlags::START_BASIC);
                *startbasic = false;
            }
            let opc = self.opc(op);
            match opc {
                Opcode::Branch | Opcode::Cbranch => {
                    let dest = self.fd.vn(self.fd.input(op, 0)?);
                    let (dest_const, dest_off) = (dest.is_constant(), dest.offset);
                    if dest_const {
                        match self.find_rel_target(op)? {
                            RelTarget::Op(d) => {
                                self.mark(d, OpFlags::START_BASIC);
                                maxtime = maxtime.max(self.fd.op(d).seq.time);
                            }
                            RelTarget::Fallthru(_) => isfallthru = true,
                        }
                    } else {
                        self.new_address(dest_off)?;
                    }
                    if opc == Opcode::Branch {
                        self.end_instruction_at(op, i, maxtime);
                    }
                    *startbasic = true;
                }
                Opcode::Branchind | Opcode::Return => {
                    if opc == Opcode::Branchind {
                        self.tablelist.push(op);
                    }
                    self.end_instruction_at(op, i, maxtime);
                    *startbasic = true;
                }
                Opcode::Call => {
                    // checkForFlowModification: a callee that does not return is followed by
                    // an artificial halt, which the walk picks up next
                    if self.setup_call_specs(op)? {
                        let addr = self.fd.op(op).seq.addr;
                        self.artificial_halt(addr, Some(Halt::NoReturn))?;
                        if let Some(halt) = self.fd.dead.pop() {
                            self.fd.dead.insert(i, halt);
                        }
                    }
                }
                Opcode::Callind => {
                    self.setup_callind_specs(op);
                }
                _ => {}
            }
        }
        if isfallthru {
            *startbasic = true;
            return Ok(true);
        }
        Ok(last.is_none_or(|op| !matches!(self.opc(op), Opcode::Branch | Opcode::Branchind | Opcode::Return)))
    }

    /// A branch past every internal branch target ends the instruction: the ops after it, from
    /// dead-list position `next`, are deleted (`FlowInfo::deleteRemainingOps`).
    fn end_instruction_at(&mut self, op: OpId, next: usize, maxtime: u32) {
        if self.fd.op(op).seq.time >= maxtime {
            for o in self.fd.dead.split_off(next) {
                self.fd.op_destroy_raw(o);
            }
        }
    }

    /// Port of `FlowInfo::newAddress`: queue `to`, or mark its op as a block start when it was
    /// decoded already.
    fn new_address(&mut self, to: u64) -> Result<()> {
        if self.visited.contains_key(&to) {
            let op = self.target(to)?;
            self.mark(op, OpFlags::START_BASIC);
        } else {
            self.addrlist.push(to);
        }
        Ok(())
    }

    /// Port of `FlowInfo::target`: the first op at `addr`, or of the next instruction when an
    /// instruction produced no p-code.
    fn target(&self, addr: u64) -> Result<OpId> {
        let mut a = addr;
        while let Some(stat) = self.visited.get(&a) {
            if let Some(seq) = stat.seq {
                if let Some(op) = self.fd.find_op(seq) {
                    return Ok(op);
                }
                break;
            }
            a += stat.size;
        }
        err(format!("Could not find op at target address: {}", ram_addr(addr)))
    }

    /// Port of `FlowInfo::findRelTarget`: the op a constant (p-code relative) branch reaches.
    fn find_rel_target(&self, op: OpId) -> Result<RelTarget> {
        let o = self.fd.op(op);
        let id = o.seq.time.wrapping_add(self.fd.vn(self.fd.input(op, 0)?).offset as u32);
        if let Some(t) = self.fd.find_op(SeqNum { addr: o.seq.addr, time: id }) {
            return Ok(RelTarget::Op(t));
        }
        if let Some(last) = self.fd.find_last_op(o.seq.addr).map(|l| self.fd.op(l).seq) {
            if last.time < id {
                if let Some((&start, stat)) = self.visited.range(..=last.addr).next_back() {
                    let res = start + stat.size;
                    if o.seq.addr < res {
                        return Ok(RelTarget::Fallthru(res));
                    }
                }
            }
        }
        err(format!("Bad relative branch at instruction : {}", ram_addr(o.seq.addr)))
    }

    /// Port of `FlowInfo::branchTarget`.
    fn branch_target(&self, op: OpId) -> Result<OpId> {
        let dest = self.fd.vn(self.fd.input(op, 0)?);
        if !dest.is_constant() {
            return self.target(dest.offset);
        }
        match self.find_rel_target(op)? {
            RelTarget::Op(t) => Ok(t),
            RelTarget::Fallthru(a) => self.target(a),
        }
    }

    /// Port of `FlowInfo::fallthruOp`: the op flow reaches after the op at dead-list position `i`.
    fn fallthru_op(&self, i: usize) -> Result<Option<OpId>> {
        if let Some(&next) = self.fd.dead.get(i + 1) {
            if !self.fd.op(next).flags.has(OpFlags::START_INSTRUCTION) {
                return Ok(Some(next));
            }
        }
        let addr = self.fd.op(self.fd.dead[i]).seq.addr;
        match self.visited.range(..=addr).next_back() {
            Some((&start, stat)) if start + stat.size > addr => self.target(start + stat.size).map(Some),
            _ => Ok(None),
        }
    }

    /// Port of `FlowInfo::artificialHalt`: a RETURN that ends flow at `addr`.
    fn artificial_halt(&mut self, addr: u64, halt: Option<Halt>) -> Result<OpId> {
        let op = self.fd.new_op(Opcode::Return, addr);
        let one = self.fd.new_constant(4, 1);
        self.fd.op_set_all_input(op, &[one])?;
        self.fd.op_mut(op).halt = halt;
        Ok(op)
    }

    /// Port of `FlowInfo::setupCallSpecs` with `queryCall` and `checkForFlowModification`: name
    /// the callee, take its flow effects, replace the target with the call's annotation and
    /// queue a call with a fixup for injection. Returns whether the callee does not return
    /// (only the facts of stage S10 say so; the console's prototypes never do), having put the
    /// warning.
    fn setup_call_specs(&mut self, op: OpId) -> Result<bool> {
        let entry = self.fd.vn(self.fd.input(op, 0)?).offset;
        let callee = self.arch.callee_proto(&mut self.fd.types, entry)?;
        let mut spec = CallSpec::new(op, Some(entry), callee.is_some());
        if let Some(p) = &callee {
            spec.proto.copy_flow_effects(p);
        }
        let (inline, no_return) = (spec.proto.inject.is_some(), spec.proto.no_return);
        let call = self.new_call(spec);
        let vn = self.fd.new_varnode_callspecs(call);
        self.fd.op_set_input(op, vn, 0)?;
        if inline {
            self.injectlist.push(call);
        } else if no_return {
            self.fd.warning("Subroutine does not return", self.fd.op(op).seq.addr);
        }
        Ok(no_return)
    }

    /// Port of `FlowInfo::setupCallindSpecs` (without overrides, an indirect call stays one).
    fn setup_callind_specs(&mut self, op: OpId) -> CallId {
        self.new_call(CallSpec::new(op, None, false))
    }

    fn new_call(&mut self, spec: CallSpec) -> CallId {
        let id = CallId(self.fd.calls.len() as u32);
        self.fd.calls.push(spec);
        self.fd.qlst.push(id);
        id
    }

    /// Port of `FlowInfo::recoverJumpTables` and `Funcdata::recoverJumpTable`: the tables of
    /// the queued indirect jumps, recovered on one partial function (a clone of this one,
    /// `stageJumpTable`); a jump without one becomes a call (`truncateIndirectJump`). Returns
    /// the new tables' indices. A table whose switch looks unreachable (`isPartial`) is taken
    /// as complete: the C++ retries it once more flow is in, which needs a guard folded to a
    /// constant, which nothing before the rule stages makes.
    fn recover_jump_tables(&mut self) -> Result<Vec<usize>> {
        let mut tables = Vec::new();
        let mut partial = Partial::None;
        for op in std::mem::take(&mut self.tablelist) {
            let res = match jumptable::early_fail(self.fd, op) {
                Some(f) => Err(f),
                None => self.stage_jump_table(&mut partial, op)?,
            };
            match res {
                Ok((targets, values)) => {
                    if std::env::var_os("GHIDRA_RS_JT_DEBUG").is_some() {
                        eprintln!(
                            "jumptable in 0x{:x} at 0x{:x}: {} targets {:x?}",
                            self.fd.entry,
                            self.fd.op(op).seq.addr,
                            targets.len(),
                            targets
                        );
                    }
                    tables.push(self.fd.jumptables.len());
                    self.fd.jumptables.push(JumpTable::new(op, targets, values));
                }
                Err(f @ (Fail::Normal(_) | Fail::Thunk)) => {
                    if std::env::var_os("GHIDRA_RS_JT_DEBUG").is_some() {
                        let why = if let Fail::Normal(m) = &f { m.as_str() } else { "likely thunk" };
                        eprintln!("jumptable in 0x{:x} at 0x{:x}: {why}", self.fd.entry, self.fd.op(op).seq.addr);
                    }
                    if let Fail::Normal(m) = &f {
                        // a message ghidra-rs makes on a path it does not port is not one the C++
                        // could warn of: the function fails instead
                        if LowlevelError(m.clone()).is_unported() {
                            return Err(LowlevelError(m.clone()));
                        }
                        // stageJumpTable's catch: `warning(err.explain, op->getAddr())`
                        let addr = self.fd.op(op).seq.addr;
                        self.fd.warning(m, addr);
                    }
                    self.truncate_indirect_jump(op, matches!(f, Fail::Normal(_)))?
                }
                Err(Fail::Return) => {
                    // truncateIndirectJump, fail_return
                    self.fd.op_set_opcode(op, Opcode::Return);
                    let addr = self.fd.op(op).seq.addr;
                    self.fd.warning("Treating indirect jump as return", addr);
                }
                Err(Fail::Callother) => {
                    return err("jump table: an address made by a CALLOTHER (fail_callother) is not implemented");
                }
            }
        }
        Ok(tables)
    }

    /// Port of `Funcdata::stageJumpTable`: build the partial function on first use
    /// (`truncatedFlow`, then the `jumptable` root action) and recover the table from it.
    /// The outer `Result` is an error that ends the decompile, the inner one the recovery.
    /// The warnings the partial function added (from `nw` header and `nc` body warnings on):
    /// the C++ writes them, with their `WARNING (jumptable): ` prefix, to the comment database
    /// the function shares, so they print with the function's own.
    fn carry_warnings(&mut self, p: &Funcdata, nw: usize, nc: usize) {
        for w in p.warnings.iter().skip(nw) {
            self.fd.add_header(w.clone());
        }
        for (a, m) in p.comments.iter().skip(nc) {
            self.fd.add_comment(*a, m.clone());
        }
    }

    /// The partial function of `stageJumpTable`: a clone with the flow so far (`truncatedFlow`),
    /// simplified by the `jumptable` root action, and that action's result. `stack`: with the
    /// `stackvars` rules, as in the C++; without them the constant loads are folded by
    /// `jumptable::fold_constants` instead.
    fn build_partial(&mut self, stack: bool) -> Result<(Funcdata, Result<()>)> {
        let mut p = self.fd.clone();
        p.jumptablerecovery_on = true;
        let mut pflow = Flow {
            fd: &mut p,
            arch: self.arch,
            parse: self.arch.sleigh.new_parse(),
            visited: self.visited.clone(),
            addrlist: Vec::new(),
            tablelist: Vec::new(),
            injectlist: Vec::new(),
            insn_count: 0,
            baddata_count: 0,
            // the copy constructor copies `flags`
            reinterpreted_present: self.reinterpreted_present,
        };
        pflow.generate_blocks()?;
        let res = action::jumptable_partial(&mut p, self.arch, stack);
        if res.is_ok() {
            if !stack {
                jumptable::fold_constants(&mut p, self.arch);
            }
            jumptable::calc_nz_mask(&mut p, self.arch);
        }
        Ok((p, res))
    }

    fn stage_jump_table(&mut self, partial: &mut Partial, op: OpId) -> Result<Staged> {
        match partial {
            Partial::Failed => {
                // the C++ marks the partial function before its action runs, so after a failed
                // action a later table skips the action and reads the half-simplified clone
                return err("jump table: a second table after the partial function's action failed is not ported");
            }
            Partial::None => {
                let (nw, nc) = (self.fd.warnings.len(), self.fd.comments.len());
                let (mut p, mut res) = self.build_partial(true)?;
                // The stack heritage of the partial function reached a path ghidra-rs does not
                // port (the value-set ranges of an indexed stack LOAD): the table is recovered
                // from the partial function without the `stackvars` rules instead, and the
                // error is kept for a table that one does not give (below).
                let mut unported = None;
                if let Err(e) = &res {
                    if e.is_unported() {
                        unported = Some(LowlevelError(e.0.clone()));
                        (p, res) = self.build_partial(false)?;
                    }
                }
                self.carry_warnings(&p, nw, nc);
                if let Err(e) = res {
                    // An error of the jumptable action fails the table, as in the C++
                    // (`stageJumpTable` catches `LowlevelError` and warns of it). One from a path
                    // ghidra-rs does not port is not a failure the reference has: it ends the
                    // decompile.
                    if e.is_unported() {
                        return Err(e);
                    }
                    *partial = Partial::Failed;
                    return Ok(Err(Fail::Normal(e.0)));
                }
                *partial = Partial::Ready(Box::new(p), unported);
            }
            Partial::Ready(..) => {}
        }
        let Partial::Ready(p, unported) = partial else { return err("jump table: no partial function") };
        let p: &Funcdata = p;
        if std::env::var("GHIDRA_RS_JT_DEBUG").is_ok_and(|v| v == "2") {
            eprintln!("{}", super::print_raw(p, self.arch).unwrap_or_default());
        }
        let partop = p.op(op);
        if partop.opc != Opcode::Branchind || partop.seq != self.fd.op(op).seq {
            return err("Error recovering jumptable: Bad partial clone");
        }
        if partop.is_dead() {
            return Ok(Ok((Vec::new(), None)));
        }
        // `testForReturnAddress` (fail_return): a target traced back through COPY, INDIRECT and
        // INT_AND with a constant to the input at the spec's `<returnaddress>`
        // (`defaultReturnAddr`; never, when the spec has none)
        let mut vn = p.op(op).ins[0];
        while let Some(d) = p.vn(vn).def {
            let o = p.op(d);
            match o.opc {
                Opcode::Copy | Opcode::Indirect => vn = o.ins[0],
                Opcode::IntAnd if p.vn(o.ins[1]).is_constant() => vn = o.ins[0],
                _ => break,
            }
        }
        let root = p.vn(vn);
        let at_retaddr = match self.arch.spec.return_address {
            Some(Storage::Stack { offset, size }) => {
                (root.space, root.offset, root.size) == (Space::Stack, offset, size)
            }
            Some(Storage::Space { space, offset, size }) => {
                (root.space, root.offset, root.size) == (Space::Sleigh(space), offset, size)
            }
            _ => false,
        };
        if root.def.is_none() && at_retaddr && root.is_input() {
            return Ok(Err(Fail::Return));
        }
        let res = jumptable::recover_addresses(p, self.arch, op);
        let jump = flow_into(p, p.op(op).ins[0]);
        if let Some(e) = unported {
            // The partial function made without the stack rules. Its result stands only where
            // the stack rules could not change it; otherwise the error of the partial function
            // with them. No table: they could, when the jump depends on the stack pointer. A
            // table: they could, when a guard (`analyzeGuards`) reads the stack through a LOAD
            // the jump does not read, since with the stack heritaged that value may be the
            // switch variable.
            let (sp, off, _) = self.arch.spec.stack_pointer;
            let on_sp = |vn: &VarnodeId| p.vn(*vn).space == Space::Sleigh(sp) && p.vn(*vn).offset == off;
            let loud = match &res {
                Err(Fail::Normal(_)) => jump.iter().any(on_sp),
                Ok(_) => {
                    let loads = stack_loads(p, &jump, on_sp);
                    let guards = jumptable::guard_conditions(p, self.arch, op);
                    guards.into_iter().any(|c| !stack_loads(p, &flow_into(p, c), on_sp).is_subset(&loads))
                }
                Err(_) => false,
            };
            if loud {
                return Err(LowlevelError(e.0.clone()));
            }
        } else {
            // In the C++ partial function `ActionRestructureVarnode` and `RuleAliasUpdate`
            // (`opCollapseIndirectsForAlias`: the alias analysis, and the value-set ranges of
            // the STORE guards) remove the INDIRECTs of stack varnodes nothing can alias, at a
            // STORE or a call; neither is ported. The result stands only when it is the same
            // with every such INDIRECT removed (then with any of them removed, taken as given),
            // and a table that fails while the jump reads one is never taken as failed: with
            // them removed the C++ rules may simplify further (`RuleMultiCollapse`).
            // ponytail: one clone of the partial function per jump; cache it per partial
            // function if a function with many tables gets slow
            let same = match without_stack_indirects(p, self.arch)? {
                None => true,
                Some(q) => match (&res, &jumptable::recover_addresses(&q, self.arch, op)) {
                    (Ok(a), Ok(b)) => a.0 == b.0 && a.2 == b.2,
                    (Err(a), Err(b)) => std::mem::discriminant(a) == std::mem::discriminant(b),
                    _ => false,
                },
            };
            let failed_on_one = matches!(res, Err(Fail::Normal(_)))
                && jump.iter().any(|&v| p.vn(v).def.is_some_and(|d| is_stack_indirect(p, d)));
            if !same || failed_on_one {
                return err(
                    "jump table: the table depends on an INDIRECT of a stack varnode that RuleAliasUpdate may collapse (ActionRestructureVarnode in the partial function): not ported",
                );
            }
        }
        if let Ok((.., true)) = res {
            // `fd->warning` on the partial function: its prefix, into the shared database
            let addr = self.fd.op(op).seq.addr;
            self.fd.add_comment(addr, "WARNING (jumptable): Sanity check requires truncation of jumptable".into());
        }
        Ok(res.map(|(t, _partial, values, _)| (t, Some(values))))
    }

    /// Port of `FlowInfo::truncateIndirectJump` for a failed recovery (`fail_normal`,
    /// `fail_thunk`): the jump becomes a call followed by a halt; `bad` (`fail_normal`) marks
    /// the call as a bad jump table (`setBadJumpTable`).
    fn truncate_indirect_jump(&mut self, op: OpId, bad: bool) -> Result<()> {
        self.fd.op_set_opcode(op, Opcode::Callind);
        let call = self.setup_callind_specs(op);
        if bad {
            self.fd.call_mut(call).bad_jump_table = true;
            let addr = self.fd.op(op).seq.addr;
            self.fd.warning("Treating indirect jump as call", addr);
        }
        let halt = self.artificial_halt(self.fd.op(op).seq.addr, None)?;
        self.fd.op_dead_insert_after(halt, op);
        Ok(())
    }

    /// Port of `FlowInfo::checkContainedCall`: a call into the middle of this function's code,
    /// to an address no function starts at, is a branch (a PIC idiom).
    fn check_contained_call(&mut self) -> Result<()> {
        let mut i = 0;
        while let Some(&c) = self.fd.qlst.get(i) {
            i += 1;
            let call = self.fd.call(c);
            let (op, known) = (call.op, call.known);
            let Some(addr) = call.entry.filter(|_| !known && self.opc(op) == Opcode::Call) else { continue };
            let Some((&start, stat)) = self.visited.range(..=addr).next_back() else { continue };
            if start + stat.size <= addr {
                continue;
            }
            let opaddr = self.fd.op(op).seq.addr;
            if start != addr {
                self.fd.warning("Call to offcut address within same function", opaddr);
                continue;
            }
            // `printRaw` of a 4-byte ram address
            let pic = format!("Possible PIC construction at 0x{opaddr:08x}: Changing call to branch");
            self.fd.warning_header(pic);
            self.fd.op_set_opcode(op, Opcode::Branch);
            let targ = self.target(addr)?;
            self.mark(targ, OpFlags::START_BASIC);
            let pos = self.fd.dead.iter().position(|&o| o == op);
            if let Some(&next) = pos.and_then(|p| self.fd.dead.get(p + 1)) {
                self.mark(next, OpFlags::START_BASIC);
            }
            let vn = self.fd.new_varnode(4, Space::Sleigh(self.arch.sleigh.code_space()), addr);
            self.fd.op_set_input(op, vn, 0)?;
            // C++ `iter = qlst.erase(iter)` followed by the loop's `++iter` skips the next call; kept
            self.fd.qlst.remove(i - 1);
            i += 1;
        }
        Ok(())
    }

    /// Port of `FlowInfo::generateBlocks`: block edges, blocks, and a fresh entry block when
    /// something branches back to the first one.
    fn generate_blocks(&mut self) -> Result<()> {
        let edges = self.collect_edges()?;
        self.split_basic()?;
        for (from, to) in edges {
            let (Some(a), Some(b)) = (self.fd.op(from).parent, self.fd.op(to).parent) else {
                return err("edge between ops outside blocks");
            };
            self.fd.blocks.add_edge(a, b);
        }
        let Some(&start) = self.fd.blocks.list.first() else { return Ok(()) };
        if !self.fd.blocks.block(start).ins.is_empty() {
            let front = self.fd.blocks.new_block(self.fd.entry);
            self.fd.blocks.add_edge(front, start);
            self.fd.blocks.set_start_block(front);
        }
        self.switch_over_jump_tables()
    }

    /// Port of `Funcdata::switchOverJumpTables` (`JumpTable::switchOver`): each table entry's
    /// out edge of its switch block. A table without addresses (its BRANCHIND was dead in the
    /// partial function) has none.
    fn switch_over_jump_tables(&mut self) -> Result<()> {
        for i in 0..self.fd.jumptables.len() {
            let jt = &self.fd.jumptables[i];
            let Some(parent) = self.fd.op(jt.op).parent else { continue };
            let mut positions = Vec::with_capacity(jt.targets.len());
            for &addr in &jt.targets {
                let bl = self.fd.op(self.target(addr)?).parent;
                let outs = &self.fd.blocks.block(parent).outs;
                let pos = outs.iter().position(|e| Some(e.point) == bl);
                positions.push(pos.ok_or_else(|| LowlevelError("Jumptable destination not linked".into()))?);
            }
            self.fd.jumptables[i].switch_over(&positions);
        }
        Ok(())
    }

    /// Port of `FlowInfo::collectEdges`: (branching op, target op) pairs in dead-list order.
    fn collect_edges(&mut self) -> Result<Vec<(OpId, OpId)>> {
        let mut edges = Vec::new();
        let no_fallthru =
            |op: OpId| LowlevelError(format!("No fallthru for op at {}", ram_addr(self.fd.op(op).seq.addr)));
        for (i, &op) in self.fd.dead.iter().enumerate() {
            let nextstart = self.fd.dead.get(i + 1).is_none_or(|&n| self.fd.op(n).flags.has(OpFlags::START_BASIC));
            match self.opc(op) {
                Opcode::Branch => edges.push((op, self.branch_target(op)?)),
                Opcode::Branchind => {
                    let Some(jt) = self.fd.jumptables.iter().find(|j| j.op == op) else { continue };
                    let first = edges.len();
                    for &t in &jt.targets {
                        let targ = self.target(t)?;
                        if !edges[first..].iter().any(|&(_, e)| e == targ) {
                            edges.push((op, targ));
                        }
                    }
                }
                Opcode::Return => {}
                Opcode::Cbranch => {
                    edges.push((op, self.fallthru_op(i)?.ok_or_else(|| no_fallthru(op))?));
                    edges.push((op, self.branch_target(op)?));
                }
                _ if nextstart => edges.push((op, self.fallthru_op(i)?.ok_or_else(|| no_fallthru(op))?)),
                _ => {}
            }
        }
        Ok(edges)
    }

    /// Port of `FlowInfo::splitBasic`: cut the dead list into blocks at the marked ops.
    fn split_basic(&mut self) -> Result<()> {
        let dead = std::mem::take(&mut self.fd.dead);
        let Some(&first) = dead.first() else { return Ok(()) };
        if !self.fd.op(first).flags.has(OpFlags::START_BASIC) {
            return err("First op not marked as entry point");
        }
        let mut cur: Option<BlockId> = None;
        for op in dead {
            let addr = self.fd.op(op).seq.addr;
            let bl = match cur {
                Some(b) if !self.fd.op(op).flags.has(OpFlags::START_BASIC) => {
                    let blk = self.fd.blocks.block_mut(b);
                    blk.stop = blk.stop.max(addr);
                    b
                }
                _ => {
                    let b = self.fd.blocks.new_block(addr);
                    if cur.is_none() {
                        self.fd.blocks.set_start_block(b);
                    }
                    cur = Some(b);
                    b
                }
            };
            let at = self.fd.blocks.block(bl).ops.len();
            self.fd.op_insert(op, bl, at);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sleigh::{PcodeOp, Varnode};

    #[test]
    fn call_return_override_of_a_jump() {
        let ram = |offset| Varnode { space: 1, offset, size: 4 };
        let op = |opc: Opcode, ins| PcodeOp { opc: opc as u8, out: None, ins };
        let mut ops = vec![op(Opcode::Branch, vec![ram(0x401000)])];
        call_return_override(&mut ops, "CALL_RETURN", 4).unwrap();
        assert_eq!(ops.len(), 2);
        assert_eq!((ops[0].opc, ops[0].ins[0].offset), (Opcode::Call as u8, 0x401000));
        assert_eq!((ops[1].opc, ops[1].ins[0]), (Opcode::Return as u8, Varnode { space: 0, offset: 0, size: 4 }));
        // a relative branch is left alone; a conditional one and the other overrides fail
        let mut rel = vec![op(Opcode::Branch, vec![Varnode { space: 0, offset: 1, size: 4 }])];
        call_return_override(&mut rel, "CALL_RETURN", 4).unwrap();
        assert_eq!(rel.len(), 1);
        let mut cbr = vec![op(Opcode::Cbranch, vec![ram(0x401000), Varnode { space: 2, offset: 0, size: 1 }])];
        assert!(call_return_override(&mut cbr, "CALL_RETURN", 4).is_err());
        assert!(call_return_override(&mut ops, "BRANCH", 4).is_err());
    }
}
