//! Port of `FlowInfo` (flow.cc) and `Funcdata::followFlow` (funcdata_op.cc): decode the
//! function's instructions into p-code with the milestone-1 SLEIGH engine, in Ghidra's order,
//! then split the ops into basic blocks.
//!
//! The order matters: op sequence numbers count creation, and blocks follow the dead list. So
//! the address stack (`addrlist`, last in first out), the per-instruction marking of block
//! starts and the deletion of ops after a branch follow the C++ step by step.

use super::block::BlockId;
use super::fspec::CallSpec;
use super::funcdata::{CallId, Funcdata, JumpTable};
use super::jumptable::{self, Fail};
use super::op::{Halt, OpFlags, OpId, SeqNum};
use super::opcode::Opcode;
use super::varnode::Space;
use super::{action, err, Arch, LowlevelError, Result};
use crate::sleigh::{Parse, PcodeError};
use std::collections::BTreeMap;

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
    };
    flow.generate_ops()?;
    flow.generate_blocks()
}

fn ram_addr(a: u64) -> String {
    format!("(ram,0x{a:08x})")
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
            self.fd.warnings.push(format!("Function: {callee} replaced with injection: {}", payload.name));
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
                // reinterpreted: decoding into the middle of an instruction
                self.count_bad_data(format!(
                    "Instruction at {} overlaps instruction at {}",
                    ram_addr(addr),
                    ram_addr(start)
                ))?;
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
                1
            }
            Err(EmitError::BadData(msg)) => {
                self.count_bad_data(msg)?;
                self.artificial_halt(addr, Some(Halt::BadInstruction))?;
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
        let ops = sl.pcode(&self.parse).map_err(|e| match e {
            PcodeError::Unimplemented => EmitError::Unimplemented,
            PcodeError::Invalid(e) => EmitError::Fatal(LowlevelError(e)),
        })?;
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
                Opcode::Call => self.setup_call_specs(op)?,
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
    /// queue a call with a fixup for injection. (The console's prototypes never say a function
    /// does not return, so a call never ends flow.)
    fn setup_call_specs(&mut self, op: OpId) -> Result<()> {
        let entry = self.fd.vn(self.fd.input(op, 0)?).offset;
        let callee = self.arch.functions.get(&entry);
        let mut spec = CallSpec::new(op, Some(entry), callee.is_some());
        if let Some(f) = callee {
            spec.proto.copy_flow_effects(&f.proto);
        }
        let inline = spec.proto.inject.is_some();
        let call = self.new_call(spec);
        let vn = self.fd.new_varnode_callspecs(call);
        self.fd.op_set_input(op, vn, 0)?;
        if inline {
            self.injectlist.push(call);
        }
        Ok(())
    }

    /// Port of `FlowInfo::setupCallindSpecs` (without overrides, an indirect call stays one).
    fn setup_callind_specs(&mut self, op: OpId) {
        self.new_call(CallSpec::new(op, None, false));
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
        let mut partial: Option<Funcdata> = None;
        for op in std::mem::take(&mut self.tablelist) {
            let res = match jumptable::early_fail(self.fd, op) {
                Some(f) => Err(f),
                None => self.stage_jump_table(&mut partial, op)?,
            };
            match res {
                Ok(targets) => {
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
                    self.fd.jumptables.push(JumpTable { op, targets });
                }
                Err(f @ (Fail::Normal(_) | Fail::Thunk)) => {
                    if std::env::var_os("GHIDRA_RS_JT_DEBUG").is_some() {
                        let why = if let Fail::Normal(m) = &f { m.as_str() } else { "likely thunk" };
                        eprintln!("jumptable in 0x{:x} at 0x{:x}: {why}", self.fd.entry, self.fd.op(op).seq.addr);
                    }
                    self.truncate_indirect_jump(op)?
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
    fn stage_jump_table(
        &mut self,
        partial: &mut Option<Funcdata>,
        op: OpId,
    ) -> Result<std::result::Result<Vec<u64>, Fail>> {
        if partial.is_none() {
            let mut p = self.fd.clone();
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
            };
            pflow.generate_blocks()?;
            if let Err(e) = action::jumptable_partial(&mut p, self.arch) {
                return Ok(Err(Fail::Normal(e.0)));
            }
            jumptable::calc_nz_mask(&mut p, self.arch);
            *partial = Some(p);
        }
        let p = partial.as_ref().unwrap();
        if std::env::var("GHIDRA_RS_JT_DEBUG").is_ok_and(|v| v == "2") {
            eprintln!("{}", super::print_raw(p, self.arch).unwrap_or_default());
        }
        let partop = p.op(op);
        if partop.opc != Opcode::Branchind || partop.seq != self.fd.op(op).seq {
            return err("Error recovering jumptable: Bad partial clone");
        }
        if partop.is_dead() {
            return Ok(Ok(Vec::new()));
        }
        // `testForReturnAddress` (fail_return) is left out: x86's return address is on the
        // stack, which the ported heritage pass leaves as LOADs, so it cannot match yet.
        Ok(jumptable::recover_addresses(p, self.arch, op).map(|(t, _partial)| t))
    }

    /// Port of `FlowInfo::truncateIndirectJump` for a failed recovery (`fail_normal`,
    /// `fail_thunk`): the jump becomes a call followed by a halt.
    fn truncate_indirect_jump(&mut self, op: OpId) -> Result<()> {
        self.fd.op_mut(op).opc = Opcode::Callind;
        self.setup_callind_specs(op);
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
            if start != addr || start + stat.size <= addr {
                continue; // "Call to offcut address within same function" is only a warning
            }
            self.fd.op_mut(op).opc = Opcode::Branch;
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
