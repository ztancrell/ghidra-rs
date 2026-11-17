//! `ConditionalExecution` and `ActionConditionalExe` (condexe.cc): a block that tests again a
//! condition both its paths have already been split on is removed, and the values it merged
//! flow straight to the matching side.

use super::block::BlockId;
use super::op::OpId;
use super::opcode::Opcode;
use super::varnode::{VarnodeId, VnFlags};
use super::{err, Arch, Funcdata, Result};
use std::collections::HashMap;

/// Port of `ConditionalExecution`, the state of one `trial` that `execute` reads.
struct CondExe {
    /// the block where flow comes together again (unnecessarily)
    iblock: BlockId,
    /// the in slot of `iblock` data flowing to its out edge `POSTA_OUTSLOT` came through
    camethruposta_slot: usize,
    /// the replacement of the current varnode, by the block reading it
    replacement: HashMap<BlockId, VarnodeId>,
    /// the outputs of the ops pulled back out of `iblock` for the current varnode, by in branch
    pullback: Vec<Option<VarnodeId>>,
}

/// `prea_inslot` and `posta_outslot`: `verify` always sets them to 0.
const PREA_INSLOT: usize = 0;
const POSTA_OUTSLOT: usize = 0;

/// `ConditionalExecution::heritageyes`: at least one heritage pass has run on the space of `vn`.
fn heritage_yes(fd: &Funcdata, arch: &Arch, vn: VarnodeId) -> bool {
    super::heritage::space_delay(arch, fd.vn(vn).space).is_some_and(|delay| fd.heritage.pass() - delay > 0)
}

/// Skips back over the blocks with one way in and one way out.
fn walk_back(fd: &Funcdata, mut tmp: BlockId) -> (BlockId, Option<BlockId>) {
    let mut last = None;
    while fd.blocks.block(tmp).outs.len() == 1 && fd.blocks.block(tmp).ins.len() == 1 {
        last = Some(tmp);
        tmp = fd.blocks.block(tmp).ins[0].point;
    }
    (tmp, last)
}

/// Port of `ConditionalExecution::testMultiRead`.
fn test_multi_read(fd: &Funcdata, iblock: BlockId, vn: VarnodeId, op: OpId) -> bool {
    let o = fd.op(op);
    if o.parent == Some(iblock) {
        // the copy-like ops are tested on their own
        return matches!(o.opc, Opcode::Copy | Opcode::Subpiece);
    }
    // only flow through to the return value
    o.opc != Opcode::Return || o.ins.get(1) == Some(&vn)
}

/// Port of `ConditionalExecution::testOpRead`.
fn test_op_read(fd: &Funcdata, iblock: BlockId, vn: VarnodeId, op: OpId) -> bool {
    if fd.op(op).parent == Some(iblock) {
        return true;
    }
    let Some(write_op) = fd.vn(vn).def else { return false };
    let w = fd.op(write_op);
    match w.opc {
        Opcode::Copy | Opcode::Subpiece => {}
        Opcode::IntAdd | Opcode::Ptrsub if fd.vn(w.ins[1]).is_constant() => {}
        _ => return false,
    }
    let invn = fd.vn(w.ins[0]);
    match invn.def {
        Some(upop) => !(fd.op(upop).parent == Some(iblock) && fd.op(upop).opc != Opcode::Multiequal),
        None => !invn.is_free(),
    }
}

/// Port of `ConditionalExecution::testRemovability`.
fn test_removability(fd: &Funcdata, arch: &Arch, iblock: BlockId, op: OpId) -> Result<bool> {
    let o = fd.op(op);
    if o.opc == Opcode::Multiequal {
        let Some(vn) = o.out else { return Ok(true) };
        return Ok(fd.vn(vn).descend.iter().all(|&r| test_multi_read(fd, iblock, vn, r)));
    }
    // isFlowBreak, isCall
    if o.is_branch() || o.opc == Opcode::Return || o.is_call() {
        return Ok(false);
    }
    if matches!(o.opc, Opcode::Load | Opcode::Store | Opcode::Indirect) {
        return Ok(false);
    }
    let Some(vn) = o.out else { return err("ActionConditionalExe: an op without output in the tested block") };
    if fd.vn(vn).has(VnFlags::ADDRTIED) {
        return Ok(false);
    }
    if fd.vn(vn).descend.is_empty() {
        return Ok(heritage_yes(fd, arch, vn));
    }
    Ok(fd.vn(vn).descend.iter().all(|&r| test_op_read(fd, iblock, vn, r)))
}

/// Port of `ConditionalExecution::trial` (`verify`): `ib` tests the condition its two paths in
/// were split on, and every op of it can be removed.
fn trial(fd: &Funcdata, arch: &Arch, ib: BlockId) -> Result<Option<CondExe>> {
    // testIBlock
    let b = fd.blocks.block(ib);
    if b.ins.len() != 2 || b.outs.len() != 2 {
        return Ok(None);
    }
    let Some(&cbranch) = b.ops.last() else { return Ok(None) };
    if fd.op(cbranch).opc != Opcode::Cbranch {
        return Ok(None);
    }
    // findInitPre
    let (initblock, last) = walk_back(fd, b.ins[PREA_INSLOT].point);
    if fd.blocks.block(initblock).outs.len() != 2
        || walk_back(fd, b.ins[1 - PREA_INSLOT].point).0 != initblock
        || initblock == ib
    {
        return Ok(None);
    }
    let mut init2a_true = fd.blocks.block(initblock).outs[1].point == last.unwrap_or(ib);
    // verifySameCondition
    let Some(&init_cbranch) = fd.blocks.block(initblock).ops.last() else { return Ok(None) };
    if fd.op(init_cbranch).opc != Opcode::Cbranch {
        return Ok(None);
    }
    match super::rules::boolean::condition_flip(fd, cbranch, init_cbranch)? {
        None => return Ok(None),
        Some(flip) => init2a_true ^= flip,
    }
    // iblock2posta_true is `posta_outslot == 1`
    let camethruposta_slot = if init2a_true == (POSTA_OUTSLOT == 1) { PREA_INSLOT } else { 1 - PREA_INSLOT };
    // every op but the branch, last first
    for &op in b.ops[..b.ops.len() - 1].iter().rev() {
        if !test_removability(fd, arch, ib, op)? {
            return Ok(None);
        }
    }
    Ok(Some(CondExe { iblock: ib, camethruposta_slot, replacement: HashMap::new(), pullback: Vec::new() }))
}

impl CondExe {
    /// The in branch of `iblock` that flow leaving it by out edge `out_slot` came through.
    fn branch_of(&self, out_slot: usize) -> usize {
        if out_slot == POSTA_OUTSLOT {
            self.camethruposta_slot
        } else {
            1 - self.camethruposta_slot
        }
    }

    /// Port of `ConditionalExecution::pullbackOp`: a copy of `op` on the path into `iblock`.
    fn pullback_op(&mut self, fd: &mut Funcdata, op: OpId, inbranch: usize) -> Result<VarnodeId> {
        if self.pullback.len() <= inbranch {
            self.pullback.resize(inbranch + 1, None);
        }
        if let Some(vn) = self.pullback[inbranch] {
            return Ok(vn);
        }
        let o = fd.op(op).clone();
        let idom = fd.blocks.block(self.iblock).idom;
        let mut invn = o.ins[0];
        let bl = match fd.vn(invn).def.filter(|&d| fd.op(d).parent == Some(self.iblock)) {
            // the defining op must be a MULTIEQUAL
            Some(def_op) => {
                invn = fd.input(def_op, inbranch)?;
                Some(fd.blocks.block(self.iblock).ins[inbranch].point)
            }
            None => idom,
        };
        let Some(bl) = bl else { return err("ActionConditionalExe: the tested block has no dominator") };
        let Some(orig_out) = o.out else { return err("ActionConditionalExe: pulling back an op without output") };
        let new_op = fd.new_op(o.opc, o.seq.addr);
        let ov = fd.vn(orig_out);
        let (size, space, offset) = (ov.size, ov.space, ov.offset);
        let out_vn = fd.new_varnode_out(size, space, offset, new_op);
        fd.op_set_input(new_op, invn, 0)?;
        for (i, &v) in o.ins.iter().enumerate().skip(1) {
            fd.op_set_input(new_op, v, i)?;
        }
        fd.op_insert_end(new_op, bl);
        self.pullback[inbranch] = Some(out_vn);
        Ok(out_vn)
    }

    /// Port of `ConditionalExecution::getNewMulti`: a MULTIEQUAL at the start of `bl` reading the
    /// output of `op` on every edge (those reads are replaced in their turn).
    fn new_multi(&self, fd: &mut Funcdata, op: OpId, bl: BlockId) -> Result<VarnodeId> {
        let Some(outvn) = fd.op(op).out else { return err("ActionConditionalExe: no output to merge") };
        let Some(uniq) = fd.uniq else { return err("ActionConditionalExe: no unique space") };
        let new_op = fd.new_op(Opcode::Multiequal, fd.blocks.block(bl).get_start());
        let newout = fd.new_unique_out(fd.vn(outvn).size, uniq, new_op);
        for i in 0..fd.blocks.block(bl).ins.len() {
            fd.op_set_input(new_op, outvn, i)?;
        }
        fd.op_insert_begin(new_op, bl);
        Ok(newout)
    }

    /// Port of `ConditionalExecution::resolveIblockRead`: the value of `op`'s output for flow
    /// coming into `iblock` through `inbranch`.
    fn resolve_iblock_read(&mut self, fd: &mut Funcdata, mut op: OpId, inbranch: usize) -> Result<VarnodeId> {
        if fd.op(op).opc == Opcode::Copy {
            let vn = fd.op(op).ins[0];
            match fd.vn(vn).def {
                Some(d) if fd.op(d).opc == Opcode::Multiequal && fd.op(d).parent == Some(self.iblock) => op = d,
                _ => return Ok(vn),
            }
        }
        match fd.op(op).opc {
            Opcode::Multiequal => fd.input(op, inbranch),
            Opcode::Subpiece | Opcode::IntAdd | Opcode::Ptrsub => self.pullback_op(fd, op, inbranch),
            _ => err("Conditional execution: Illegal op in iblock"),
        }
    }

    /// Port of `ConditionalExecution::resolveRead`: for a read in `bl`, dominated by `iblock`.
    fn resolve_read(&mut self, fd: &mut Funcdata, op: OpId, bl: BlockId) -> Result<VarnodeId> {
        let ins = &fd.blocks.block(bl).ins;
        if ins.len() == 1 {
            // the one way in is from iblock: which side of it
            let slot = self.branch_of(ins[0].reverse);
            self.resolve_iblock_read(fd, op, slot)
        } else {
            self.new_multi(fd, op, bl)
        }
    }

    /// Port of `ConditionalExecution::getReplacementRead`.
    fn replacement_read(&mut self, fd: &mut Funcdata, op: OpId, bl: BlockId) -> Result<VarnodeId> {
        if let Some(&vn) = self.replacement.get(&bl) {
            return Ok(vn);
        }
        // flow must come through iblock
        let mut curbl = bl;
        loop {
            match fd.blocks.block(curbl).idom {
                Some(d) if d == self.iblock => break,
                Some(d) => curbl = d,
                None => return err("Conditional execution: Could not find dominator"),
            }
        }
        let res = match self.replacement.get(&curbl) {
            Some(&vn) => vn,
            None => {
                let vn = self.resolve_read(fd, op, curbl)?;
                self.replacement.insert(curbl, vn);
                vn
            }
        };
        self.replacement.insert(bl, res);
        Ok(res)
    }

    /// Port of `ConditionalExecution::getMultiequalRead`: for a MULTIEQUAL reading in `slot`.
    fn multiequal_read(&mut self, fd: &mut Funcdata, op: OpId, readop: OpId, slot: usize) -> Result<VarnodeId> {
        let Some(bl) = fd.op(readop).parent else { return err("ActionConditionalExe: a dead reader") };
        let e = fd.blocks.block(bl).ins[slot];
        if e.point != self.iblock {
            return self.replacement_read(fd, op, e.point);
        }
        let s = self.branch_of(e.reverse);
        self.resolve_iblock_read(fd, op, s)
    }

    /// Port of `ConditionalExecution::doReplacement`: every read of `op`'s output gets the value
    /// that reaches it without `iblock`.
    fn do_replacement(&mut self, fd: &mut Funcdata, op: OpId) -> Result<()> {
        self.replacement.clear();
        self.pullback.clear();
        let Some(vn) = fd.op(op).out else { return Ok(()) };
        while let Some(&first) = fd.vn(vn).descend.first() {
            let mut readop = first;
            let Some(mut slot) = fd.slot_of(readop, vn) else { return err("ActionConditionalExe: a stale reader") };
            let Some(bl) = fd.op(readop).parent else { return err("ActionConditionalExe: a dead reader") };
            if bl == self.iblock {
                return err(
                    "ActionConditionalExe: a read inside the removed block (opUnsetInput) is not implemented in ghidra-rs yet",
                );
            }
            let rvn = if fd.op(readop).opc == Opcode::Multiequal {
                self.multiequal_read(fd, op, readop, slot)?
            } else {
                if fd.op(readop).opc == Opcode::Return && slot > 0 {
                    // a RETURN input cannot be replaced directly: a COPY holds it, at the
                    // varnode's storage
                    let newcopy = fd.new_op(Opcode::Copy, fd.op(readop).seq.addr);
                    let v = fd.vn(vn);
                    let (size, space, offset) = (v.size, v.space, v.offset);
                    let outvn = fd.new_varnode_out(size, space, offset, newcopy);
                    fd.op_set_input(readop, outvn, slot)?;
                    fd.op_insert_before(newcopy, readop)?;
                    readop = newcopy;
                    slot = 0;
                }
                self.replacement_read(fd, op, bl)?
            };
            fd.op_set_input(readop, rvn, slot)?;
        }
        Ok(())
    }

    /// Port of `ConditionalExecution::execute`: the ops of `iblock` go, last first, then the
    /// block (`Funcdata::removeFromFlowSplit`).
    fn execute(&mut self, fd: &mut Funcdata) -> Result<()> {
        while let Some(&op) = fd.blocks.block(self.iblock).ops.last() {
            if !fd.op(op).is_branch() {
                self.do_replacement(fd, op)?;
            }
            fd.op_destroy(op);
        }
        fd.blocks.remove_from_flow_split(self.iblock, POSTA_OUTSLOT != self.camethruposta_slot);
        fd.blocks.remove_block(self.iblock);
        super::coreaction::structure_reset(fd)
    }
}

/// Port of `ActionConditionalExe::apply`.
pub(crate) fn conditional_exe(fd: &mut Funcdata, arch: &Arch) -> Result<i32> {
    // the elimination may not work with unreachable blocks
    if fd.blocks.unreachable {
        return Ok(0);
    }
    let mut numhits = 0;
    loop {
        let mut change = false;
        let mut i = 0;
        // the list shrinks as blocks go; the C++ walks it by index all the same
        while let Some(&bb) = fd.blocks.list.get(i) {
            i += 1;
            if let Some(mut condexe) = trial(fd, arch, bb)? {
                condexe.execute(fd)?;
                numhits += 1;
                change = true;
            }
        }
        if !change {
            return Ok(numhits);
        }
    }
}
