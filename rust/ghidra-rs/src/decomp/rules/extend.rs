//! The rules on zero extension: `RuleZextEliminate`, `RuleZextSless`, `RuleZextCommute`,
//! `RuleZextShiftZext` (ruleaction.cc).

use super::*;

/// The shared front of `RuleZextEliminate` and `RuleZextSless`: a comparison of a ZEXT with a
/// constant. Gives the ZEXT op, its slot and the constant.
fn zext_against_const(fd: &Funcdata, op: OpId) -> Result<Option<(OpId, usize, VarnodeId)>> {
    let (a, b) = (inp(fd, op, 0)?, inp(fd, op, 1)?);
    let zext_of = |v: VarnodeId| def(fd, v).filter(|&d| fd.op(d).opc == IntZext);
    let (zext, slot, other) = if let Some(z) = zext_of(b) {
        (z, 1, a)
    } else if let Some(z) = zext_of(a) {
        (z, 0, b)
    } else {
        return Ok(None);
    };
    if !is_const(fd, other) || !fd.vn(inp(fd, zext, 0)?).is_heritage_known() {
        return Ok(None);
    }
    Ok(Some((zext, slot, other)))
}

/// Port of `RuleZextEliminate`: `zext(V) == c` becomes `V == c` when `c` fits. The shift
/// wraps as the C++ shift does on x86 (`copySymbolIfValid`: constants carry no symbol here).
pub(super) fn zext_eliminate(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let Some((zext, slot, cvn)) = zext_against_const(fd, op)? else { return Ok(0) };
    if lone_descend(fd, inp(fd, op, slot)?) != Some(op) {
        return Ok(0);
    }
    let small = inp(fd, zext, 0)?;
    let smallsize = fd.vn(small).size;
    let val = fd.vn(cvn).offset;
    if val.wrapping_shr(8 * smallsize) != 0 {
        return Ok(0);
    }
    let newvn = fd.new_constant(smallsize, val);
    fd.op_set_input(op, small, slot)?;
    fd.op_set_input(op, newvn, 1 - slot)?;
    Ok(1)
}

/// Port of `RuleZextSless`: `zext(V) s< c` becomes `V < c` when `c` is positive in V's size.
pub(super) fn zext_sless(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let Some((zext, slot, cvn)) = zext_against_const(fd, op)? else { return Ok(0) };
    let small = inp(fd, zext, 0)?;
    let smallsize = fd.vn(small).size;
    let val = fd.vn(cvn).offset;
    if val.wrapping_shr((8 * smallsize).wrapping_sub(1)) != 0 {
        return Ok(0);
    }
    let newvn = fd.new_constant(smallsize, val);
    fd.op_set_input(op, small, slot)?;
    fd.op_set_input(op, newvn, 1 - slot)?;
    let opc = if fd.op(op).opc == IntSless { IntLess } else { IntLessequal };
    fd.op_set_opcode(op, opc);
    Ok(1)
}

/// Port of `RuleZextCommute`: `zext(V) >> W` becomes `zext(V >> W)`.
pub(super) fn zext_commute(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let zextvn = inp(fd, op, 0)?;
    let Some(zextop) = def(fd, zextvn).filter(|&d| fd.op(d).opc == IntZext) else { return Ok(0) };
    let zextin = inp(fd, zextop, 0)?;
    let savn = inp(fd, op, 1)?;
    if fd.vn(zextin).is_free() || (!is_const(fd, savn) && fd.vn(savn).is_free()) {
        return Ok(0);
    }
    let newop = fd.new_op(IntRight, fd.op(op).seq.addr);
    let newout = uniq_out(fd, fd.vn(zextin).size, newop)?;
    fd.op_remove_input(op, 1);
    fd.op_set_input(op, newout, 0)?;
    fd.op_set_opcode(op, IntZext);
    fd.op_set_input(newop, zextin, 0)?;
    fd.op_set_input(newop, savn, 1)?;
    fd.op_insert_before(newop, op)?;
    Ok(1)
}

/// Port of `RuleZextShiftZext`: `zext(zext(V))` becomes `zext(V)`, and
/// `zext(zext(V) << c)` becomes `zext(V) << c` when the shift loses no bit.
pub(super) fn zext_shift_zext(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let invn = inp(fd, op, 0)?;
    let Some(shiftop) = def(fd, invn) else { return Ok(0) };
    if fd.op(shiftop).opc == IntZext {
        let vn = inp(fd, shiftop, 0)?;
        if (fd.vn(vn).is_free() && !is_const(fd, vn)) || lone_descend(fd, invn) != Some(op) {
            return Ok(0);
        }
        fd.op_set_input(op, vn, 0)?;
        return Ok(1);
    }
    if fd.op(shiftop).opc != IntLeft {
        return Ok(0);
    }
    let savn = inp(fd, shiftop, 1)?;
    if !is_const(fd, savn) {
        return Ok(0);
    }
    let Some(zext2op) = def(fd, inp(fd, shiftop, 0)?).filter(|&d| fd.op(d).opc == IntZext) else { return Ok(0) };
    let rootvn = inp(fd, zext2op, 0)?;
    if fd.vn(rootvn).is_free() {
        return Ok(0);
    }
    let sa = fd.vn(savn).offset;
    if sa > 8 * u64::from(fd.vn(out(fd, zext2op)?).size - fd.vn(rootvn).size) {
        return Ok(0);
    }
    let newop = fd.new_op(IntZext, fd.op(op).seq.addr);
    let outvn = uniq_out(fd, fd.vn(out(fd, op)?).size, newop)?;
    fd.op_set_input(newop, rootvn, 0)?;
    fd.op_set_opcode(op, IntLeft);
    fd.op_set_input(op, outvn, 0)?;
    let c = fd.new_constant(4, sa);
    fd.op_insert_input(op, c, 1)?;
    fd.op_insert_before(newop, op)?;
    Ok(1)
}
