//! The rules of group `stackvars` (stage R5 slice 2): `RuleLoadVarnode` and `RuleStoreVarnode`
//! (pool `oppool2`, ruleaction.cc), which turn a LOAD or STORE at a constant address, or at the
//! stack pointer plus a constant, into a COPY from or to a varnode of that space, with
//! `FuncCallSpecs::resolveSpacebaseRelative` (fspec.cc) and
//! `Funcdata::opCollapseIndirectsForCopy` (funcdata_op.cc).
//!
//! Not ported, failing loudly: an INDIRECT of the old STORE that overlaps the new COPY's output
//! only in part (the PIECE/SUBPIECE rebuild of `opCollapseIndirectsForCopy`). Not modelled:
//! `PcodeOp::isStoreUnmapped` (only `ActionInternalStorage` sets it, and no x86 model declares
//! internal storage; superseded: "only `ActionRestructureVarnode` sets it"), word sizes
//! other than 1 (`AddrSpace::addressToByte`).

use super::*;
use crate::decomp::fspec::Storage;
use crate::decomp::funcdata::CallId;

/// Port of `RuleLoadVarnode::correctSpacebase`: the space an active space base `vn` stands for
/// when loading from the SLEIGH space `spc`: `spc` itself for a constant (a global pseudo space
/// base), the stack for the input stack pointer.
fn correct_spacebase(fd: &Funcdata, arch: &Arch, vn: VarnodeId, spc: u32) -> Result<Option<Space>> {
    let v = fd.vn(vn);
    if !v.has(VnFlags::SPACEBASE) {
        return Ok(None);
    }
    if v.is_constant() {
        return Ok(Some(Space::Sleigh(spc)));
    }
    if !v.is_input() {
        return Ok(None);
    }
    // getSpaceBySpacebase: the stack pointer is the only space base register
    let (sp, off, size) = arch.spec.stack_pointer;
    if (v.space, v.offset, v.size) != (Space::Sleigh(sp), off, size) {
        return err("Unable to find entry for spacebase register");
    }
    Ok((arch.spec.stack_container == spc).then_some(Space::Stack))
}

/// Port of `RuleLoadVarnode::vnSpacebase`: `vn` as a space base plus a constant.
fn vn_spacebase(fd: &Funcdata, arch: &Arch, vn: VarnodeId, spc: u32) -> Result<Option<(Space, u64)>> {
    if let Some(s) = correct_spacebase(fd, arch, vn, spc)? {
        return Ok(Some((s, 0)));
    }
    let Some(op) = def_with(fd, vn, IntAdd) else { return Ok(None) };
    let (vn1, vn2) = (inp(fd, op, 0)?, inp(fd, op, 1)?);
    if let Some(s) = correct_spacebase(fd, arch, vn1, spc)? {
        return Ok(is_const(fd, vn2).then(|| (s, off(fd, vn2))));
    }
    if let Some(s) = correct_spacebase(fd, arch, vn2, spc)? {
        if is_const(fd, vn1) {
            return Ok(Some((s, off(fd, vn1))));
        }
    }
    Ok(None)
}

/// Port of `RuleLoadVarnode::checkSpacebase`: the space and offset a LOAD or STORE `op` reads
/// or writes, when its pointer is a constant or a space base plus a constant.
fn check_spacebase(fd: &Funcdata, arch: &Arch, op: OpId) -> Result<Option<(Space, u64)>> {
    let mut offvn = inp(fd, op, 1)?;
    let loadspace = off(fd, inp(fd, op, 0)?) as u32; // getSpaceFromConst
    if let Some(seg) = def_with(fd, offvn, Segmentop) {
        // the base part of the segment is ignored for a space base; a constant inner part is
        // left to RuleSegmentOp
        offvn = inp(fd, seg, 2)?;
        if is_const(fd, offvn) {
            return Ok(None);
        }
    } else if is_const(fd, offvn) {
        return Ok(Some((Space::Sleigh(loadspace), off(fd, offvn))));
    }
    vn_spacebase(fd, arch, offvn, loadspace)
}

/// Port of `FuncCallSpecs::resolveSpacebaseRelative`: the call's stack offset, read from the
/// stack varnode its placeholder `phvn` now copies.
fn resolve_spacebase_relative(fd: &mut Funcdata, arch: &Arch, c: CallId, phvn: VarnodeId) -> Result<()> {
    let d = fd.vn(phvn).def.ok_or_else(|| LowlevelError("stack placeholder without its op".into()))?;
    let refvn = inp(fd, d, 0)?;
    let is_stack = fd.vn(refvn).space == Space::Stack;
    if !is_stack {
        fd.warning_header("This function may have set the stack pointer");
    }
    let mut stackoffset = off(fd, refvn);
    let op = fd.call(c).op;
    if let Some(slot) = fd.call(c).stack_placeholder_slot {
        if ins(fd, op).get(slot) == Some(&phvn) {
            fd.call_mut(c).stack_offset = Some(stackoffset);
            return crate::decomp::heritage::abort_spacebase_relative(fd, c);
        }
    }
    if let Some(locked) = &fd.call(c).proto.locked {
        // a locked prototype with stack parameters: the offset comes from the parameter
        let slot = fd.slot_of(op, phvn).and_then(|s| s.checked_sub(1));
        let Some(param) = slot.and_then(|s| locked.inputs.get(s)) else {
            return err("Stack placeholder does not line up with locked parameter");
        };
        let Some(Storage::Stack { offset, .. }) = param.storage else {
            if is_stack {
                return err("Stack placeholder does not match locked space");
            }
            return err("stack placeholder of a locked parameter outside the stack: not implemented in ghidra-rs yet");
        };
        stackoffset = stackoffset.wrapping_sub(offset) & crate::decomp::heritage_guard::stack_mask(arch);
        fd.call_mut(c).stack_offset = Some(stackoffset);
        return Ok(());
    }
    err("Unresolved stack placeholder")
}

/// Port of `RuleLoadVarnode::applyOp`.
pub(super) fn load_varnode(fd: &mut Funcdata, op: OpId, arch: &Arch) -> Result<i32> {
    let Some((space, offoff)) = check_spacebase(fd, arch, op)? else { return Ok(0) };
    let refvn = out(fd, op)?;
    let newvn = fd.new_varnode(sz(fd, refvn), space, offoff);
    fd.op_set_input(op, newvn, 0)?;
    fd.op_remove_input(op, 1);
    fd.op_set_opcode(op, Copy);
    if fd.vn(refvn).has(VnFlags::SPACEBASE_PLACEHOLDER) {
        fd.vn_clear(refvn, VnFlags::SPACEBASE_PLACEHOLDER); // clear the trigger
        if let Some(c) = lone_descend(fd, refvn).and_then(|p| fd.call_of(p)) {
            resolve_spacebase_relative(fd, arch, c, refvn)?;
        }
    }
    Ok(1)
}

/// Port of `RuleStoreVarnode::applyOp`.
pub(super) fn store_varnode(fd: &mut Funcdata, op: OpId, arch: &Arch) -> Result<i32> {
    let Some((space, offoff)) = check_spacebase(fd, arch, op)? else { return Ok(0) };
    let size = sz(fd, inp(fd, op, 2)?);
    let o = fd.new_varnode_out(size, space, offoff, op);
    fd.vn_set(o, VnFlags::STACK_STORE); // originally a STORE
    fd.op_remove_input(op, 1);
    fd.op_remove_input(op, 0);
    fd.op_set_opcode(op, Copy);
    // isStoreUnmapped is never set (ActionInternalStorage: no model declares internal storage)
    collapse_indirects_for_copy(fd, op)?;
    Ok(1)
}

/// Port of `Funcdata::opCollapseIndirectsForCopy`: the INDIRECTs just before a COPY that was a
/// STORE are its effects; one the COPY overwrites becomes a COPY or SUBPIECE of the COPY's
/// output, one it does not touch goes.
fn collapse_indirects_for_copy(fd: &mut Funcdata, copy_op: OpId) -> Result<()> {
    let vn1 = out(fd, copy_op)?;
    loop {
        let Some(bl) = fd.op(copy_op).parent else { return err("opCollapseIndirectsForCopy: op outside any block") };
        let ops = &fd.blocks.block(bl).ops;
        let pos = ops.iter().position(|&o| o == copy_op);
        let Some(op) = pos.and_then(|p| p.checked_sub(1)).map(|p| ops[p]) else { return Ok(()) };
        if code(fd, op) != Indirect {
            return Ok(());
        }
        let vn2 = out(fd, op)?;
        let (a, b) = (fd.vn(vn1), fd.vn(vn2));
        // the last byte of each, wrapping as the C++ offsets do (characterizeOverlap, contains)
        let last = |off: u64, size: u32| off.wrapping_add(u64::from(size)).wrapping_sub(1);
        let (alast, blast) = (last(a.offset, a.size), last(b.offset, b.size));
        if a.space != b.space || alast < b.offset || blast < a.offset {
            // no effect: the INDIRECT goes
            let i0 = inp(fd, op, 0)?;
            fd.total_replace(vn2, i0)?;
            fd.op_destroy(op);
            continue;
        }
        let exact = a.offset == b.offset && a.size == b.size;
        let contained = b.offset >= a.offset && blast <= alast;
        let trunc = b.offset.wrapping_sub(a.offset);
        fd.op_uninsert(op);
        if exact {
            fd.op_set_input(op, vn1, 0)?;
            fd.op_remove_input(op, 1);
            fd.op_set_opcode(op, Copy);
        } else if contained {
            // properly contained in the COPY's output: a SUBPIECE of it (little endian)
            fd.op_set_input(op, vn1, 0)?;
            let c = fd.new_constant(4, trunc);
            fd.op_set_input(op, c, 1)?;
            fd.op_set_opcode(op, Subpiece);
        } else {
            return err("opCollapseIndirectsForCopy with a partial overlap: not implemented in ghidra-rs yet");
        }
        fd.op_insert_after(op, copy_op)?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decomp::rules::testutil::{input, op};

    /// The INDIRECTs before a COPY that was a STORE: one at the COPY's storage becomes a COPY
    /// of its output, a piece of it a SUBPIECE, one elsewhere goes.
    #[test]
    fn collapse_indirects_before_a_stack_copy() {
        let mut fd = Funcdata::new(0x1000);
        let bl = fd.blocks.new_block(0x1000);
        let x = input(&mut fd, 0);
        let iop = fd.new_constant(4, 0);
        let indirect = |fd: &mut Funcdata, off: u64, size: u32| {
            let o = fd.new_op(Indirect, 0x1000);
            let i = fd.new_varnode(size, Space::Stack, off);
            fd.vn_set(i, VnFlags::INPUT);
            fd.op_set_input(o, i, 0).unwrap();
            fd.op_set_input(o, iop, 1).unwrap();
            let out = fd.new_varnode_out(size, Space::Stack, off, o);
            fd.op_insert_end(o, bl);
            (o, i, out)
        };
        let (same, _, _) = indirect(&mut fd, 8, 4);
        let (piece, _, _) = indirect(&mut fd, 10, 2);
        let (other, other_in, other_out) = indirect(&mut fd, 0x20, 4);
        let copy = fd.new_op(Copy, 0x1000);
        fd.op_set_input(copy, x, 0).unwrap();
        let out = fd.new_varnode_out(4, Space::Stack, 8, copy);
        fd.op_insert_end(copy, bl);
        let (reader, _) = op(&mut fd, Copy, &[other_out], 0x40);
        collapse_indirects_for_copy(&mut fd, copy).unwrap();
        assert_eq!((code(&fd, same), ins(&fd, same)), (Copy, &[out][..]));
        assert_eq!((code(&fd, piece), ins(&fd, piece)[0], off(&fd, ins(&fd, piece)[1])), (Subpiece, out, 2));
        assert!(fd.op(other).is_dead());
        assert_eq!(ins(&fd, reader), &[other_in]);
        assert_eq!(fd.blocks.block(bl).ops, vec![copy, same, piece]);
    }
}
