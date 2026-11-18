//! The rule of group `segment`: `RuleSegment` (ruleaction.cc), with `contiguous_test` and
//! `findContiguousWhole` (varnode.cc).

use super::*;

/// Port of `contiguous_test`: `vn1` and `vn2` are the most and least significant SUBPIECEs of
/// one varnode, which is returned (`findContiguousWhole`).
fn contiguous_whole(fd: &Funcdata, vn1: VarnodeId, vn2: VarnodeId) -> Option<VarnodeId> {
    if fd.vn(vn1).is_input() || fd.vn(vn2).is_input() {
        return None;
    }
    let (op1, op2) = (def_with(fd, vn1, Subpiece)?, def_with(fd, vn2, Subpiece)?);
    let whole = *ins(fd, op1).first()?;
    let least = ins(fd, op2).first() == Some(&whole) && off(fd, *ins(fd, op2).get(1)?) == 0;
    let contiguous = off(fd, *ins(fd, op1).get(1)?) == u64::from(sz(fd, vn2));
    (least && contiguous).then_some(whole)
}

/// Port of `RuleSegment`: a SEGMENTOP of constants becomes the constant its script gives; one
/// that concatenates the two halves of a far pointer becomes a COPY of the pointer.
pub(super) fn rule_segment(fd: &mut Funcdata, op: OpId, arch: &Arch) -> Result<i32> {
    let space = off(fd, inp(fd, op, 0)?) as u32; // getSpaceFromConst
    let Some(segdef) = arch.userops.segment_op(space) else { return err("Segment operand missing definition") };
    let (vn1, vn2) = (inp(fd, op, 1)?, inp(fd, op, 2)?);
    let whole = if is_const(fd, vn1) && is_const(fd, vn2) {
        let val = segdef.execute(arch, &[off(fd, vn1), off(fd, vn2)])?;
        let size = sz(fd, out(fd, op)?);
        fd.new_constant(size, val)
    } else if segdef.far_pointer && segdef.is_concatenation(arch)? {
        match contiguous_whole(fd, vn1, vn2) {
            Some(whole) if !fd.vn(whole).is_free() => whole,
            _ => return Ok(0),
        }
    } else {
        return Ok(0);
    };
    fd.op_remove_input(op, 2);
    fd.op_remove_input(op, 1);
    fd.op_set_input(op, whole, 0)?;
    fd.op_set_opcode(op, Copy);
    Ok(1)
}
