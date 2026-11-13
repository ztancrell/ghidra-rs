//! The rules on bit operations and shifts (stage R2): `RuleOrMask`, `RuleAndMask`,
//! `RuleOrConsume`, `RuleOrCollapse`, `RuleAndOrLump`, `RuleShiftBitops`, `RuleRightShiftAnd`,
//! `RuleHighOrderAnd`, `RuleAndDistribute`, `RuleAndCommute`, `RuleAndPiece`, `RuleAndZext`,
//! `RuleAndCompare`, `RuleDoubleShift`, `RuleDoubleArithShift`, `RuleLeftRight`,
//! `RuleShiftCompare`, `RuleSignShift`, `RuleShift2Mult`, `RuleShiftPiece`, `RuleShiftAnd`,
//! `RuleBitUndistribute`, `RuleXorSwap`, `RulePopcountBoolXor`, `RuleLzcountShiftBool`,
//! `RuleOrCompare` (ruleaction.cc) (the helpers the rule files share are in `rules/mod.rs`).
//!
//! The C++ shifts a `uintb` by an `int4` without a range check; on x86-64 the count is taken
//! modulo 64, which [`shl`] and [`shr`] reproduce.

use super::*;
use crate::decomp::rangeutil::{mostsigbit_set, pcode_left, pcode_right};

/// The shift a constant multiplier stands for (`leastsigbit_set`, a power of 2 checked).
fn pow2_shift(val: u64) -> Option<i32> {
    let sa = leastsigbit_set(val);
    (shr(val, sa) == 1).then_some(sa)
}

/// Port of `RuleOrMask`: `V | 0xff..f  =>  0xff..f`.
pub(super) fn or_mask(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let size = sz(fd, out(fd, op)?);
    if size > 8 {
        return Ok(0);
    }
    let c = inp(fd, op, 1)?;
    let mask = calc_mask(size);
    if !is_const(fd, c) || off(fd, c) & mask != mask {
        return Ok(0);
    }
    fd.op_set_opcode(op, Copy);
    fd.op_set_input(op, c, 0)?;
    fd.op_remove_input(op, 1);
    Ok(1)
}

/// Port of `RuleAndMask`: an AND the non-zero masks make 0 or the identity.
pub(super) fn and_mask(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let o = out(fd, op)?;
    let size = sz(fd, o);
    if size > 8 {
        return Ok(0);
    }
    let (a, b) = (inp(fd, op, 0)?, inp(fd, op, 1)?);
    let mask1 = fd.nzmask(a);
    let andmask = if mask1 == 0 { 0 } else { mask1 & fd.nzmask(b) };
    let vn = if andmask == 0 || andmask & fd.vn(o).consume == 0 {
        fd.new_constant(size, 0)
    } else if andmask == mask1 {
        if !is_const(fd, b) {
            return Ok(0);
        }
        a
    } else {
        return Ok(0);
    };
    if !known(fd, vn) {
        return Ok(0);
    }
    fd.op_set_opcode(op, Copy);
    fd.op_remove_input(op, 1);
    fd.op_set_input(op, vn, 0)?;
    Ok(1)
}

/// Port of `RuleOrConsume`: an OR/XOR input none of whose bits are consumed goes.
pub(super) fn or_consume(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let o = out(fd, op)?;
    if sz(fd, o) > 8 {
        return Ok(0);
    }
    let consume = fd.vn(o).consume;
    for slot in 0..2 {
        if consume & fd.nzmask(inp(fd, op, slot)?) == 0 {
            fd.op_remove_input(op, slot);
            fd.op_set_opcode(op, Copy);
            return Ok(1);
        }
    }
    Ok(0)
}

/// Port of `RuleOrCollapse`: `V | c  =>  c` when `V` has no bit outside `c`.
pub(super) fn or_collapse(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let vn = inp(fd, op, 1)?;
    if !is_const(fd, vn) || sz(fd, out(fd, op)?) > 8 {
        return Ok(0);
    }
    let val = off(fd, vn);
    if fd.nzmask(inp(fd, op, 0)?) | val != val {
        return Ok(0);
    }
    fd.op_set_opcode(op, Copy);
    fd.op_remove_input(op, 0);
    Ok(1)
}

/// Port of `RuleAndOrLump`: `(V & c) & d  =>  V & (c & d)`, and for OR and XOR.
pub(super) fn and_or_lump(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let opc = code(fd, op);
    let c = inp(fd, op, 1)?;
    if !is_const(fd, c) {
        return Ok(0);
    }
    let Some(op2) = def_with(fd, inp(fd, op, 0)?, opc) else { return Ok(0) };
    let c2 = inp(fd, op2, 1)?;
    let base = inp(fd, op2, 0)?;
    if !is_const(fd, c2) || is_free(fd, base) {
        return Ok(0);
    }
    let (mut val, val2) = (off(fd, c), off(fd, c2));
    match opc {
        IntAnd => val &= val2,
        IntOr => val |= val2,
        IntXor => val ^= val2,
        _ => {}
    }
    fd.op_set_input(op, base, 0)?;
    let nc = fd.new_constant(sz(fd, base), val);
    fd.op_set_input(op, nc, 1)?;
    Ok(1)
}

/// Port of `RuleShiftBitops`: a shift that clears one side of a bit operation.
pub(super) fn shift_bitops(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let c = inp(fd, op, 1)?;
    let vn = inp(fd, op, 0)?;
    if !is_const(fd, c) {
        return Ok(0);
    }
    let Some(bitop) = def(fd, vn) else { return Ok(0) };
    if sz(fd, vn) > 8 {
        return Ok(0);
    }
    let (sa, leftshift) = match code(fd, op) {
        IntLeft => (off(fd, c) as i32, true),
        IntRight => (off(fd, c) as i32, false),
        Subpiece => ((off(fd, c) as i32).wrapping_mul(8), false),
        IntMult => {
            let sa = leastsigbit_set(off(fd, c));
            if sa == -1 {
                return Ok(0);
            }
            (sa, true)
        }
        _ => return Ok(0),
    };
    let bitopc = code(fd, bitop);
    match bitopc {
        IntAnd | IntOr | IntXor => {}
        IntMult | IntAdd if leftshift => {}
        _ => return Ok(0),
    }
    let mask = calc_mask(sz(fd, out(fd, op)?));
    let shifted = |nzm: u64| if leftshift { pcode_left(nzm, sa as u64) } else { pcode_right(nzm, sa as u64) };
    let Some(i) = ins(fd, bitop).iter().position(|&v| shifted(fd.nzmask(v)) & mask == 0) else { return Ok(0) };
    match bitopc {
        IntMult | IntAnd => {
            let z = fd.new_constant(sz(fd, vn), 0);
            fd.op_set_input(op, z, 0)?;
        }
        _ => {
            let other = inp(fd, bitop, 1 - i)?;
            if !known(fd, other) {
                return Ok(0);
            }
            fd.op_set_input(op, other, 0)?;
        }
    }
    Ok(1)
}

/// Port of `RuleRightShiftAnd`: `(V & 0xf000) >> 24  =>  V >> 24`.
pub(super) fn right_shift_and(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let c = inp(fd, op, 1)?;
    if !is_const(fd, c) {
        return Ok(0);
    }
    let Some(andop) = def_with(fd, inp(fd, op, 0)?, IntAnd) else { return Ok(0) };
    let maskvn = inp(fd, andop, 1)?;
    if !is_const(fd, maskvn) {
        return Ok(0);
    }
    let sa = off(fd, c) as i32;
    let root = inp(fd, andop, 0)?;
    if shr(calc_mask(sz(fd, root)), sa) != shr(off(fd, maskvn), sa) || is_free(fd, root) {
        return Ok(0);
    }
    fd.op_set_input(op, root, 0)?;
    Ok(1)
}

/// Port of `RuleHighOrderAnd`: `(V + c) & 0xfff0  =>  V + (c & 0xfff0)` for an aligned `V`.
pub(super) fn high_order_and(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let cvn1 = inp(fd, op, 1)?;
    if !is_const(fd, cvn1) {
        return Ok(0);
    }
    let Some(addop) = def_with(fd, inp(fd, op, 0)?, IntAdd) else { return Ok(0) };
    let mut val = off(fd, cvn1);
    let size = sz(fd, cvn1);
    if (val.wrapping_sub(1) | val) != calc_mask(size) {
        return Ok(0);
    }
    let cvn2 = inp(fd, addop, 1)?;
    if is_const(fd, cvn2) {
        let xalign = inp(fd, addop, 0)?;
        if is_free(fd, xalign) {
            return Ok(0);
        }
        let mask1 = fd.nzmask(xalign);
        if mask1 & val != mask1 {
            return Ok(0);
        }
        fd.op_set_opcode(op, IntAdd);
        fd.op_set_input(op, xalign, 0)?;
        val &= off(fd, cvn2);
        let nc = fd.new_constant(size, val);
        fd.op_set_input(op, nc, 1)?;
        return Ok(1);
    }
    if lone_descend(fd, out(fd, addop)?) != Some(op) {
        return Ok(0);
    }
    for i in 0..2 {
        let mask2 = fd.nzmask(inp(fd, addop, i)?);
        if mask2 & val != mask2 {
            continue;
        }
        let nonzero = inp(fd, addop, 1 - i)?;
        let Some(addop2) = def_with(fd, nonzero, IntAdd) else { continue };
        if lone_descend(fd, nonzero) != Some(addop) {
            continue;
        }
        let cvn2 = inp(fd, addop2, 1)?;
        if !is_const(fd, cvn2) {
            continue;
        }
        let mask2 = fd.nzmask(inp(fd, addop2, 0)?);
        if mask2 & val != mask2 {
            continue;
        }
        val &= off(fd, cvn2);
        let nc = fd.new_constant(size, val);
        fd.op_set_input(addop2, nc, 1)?;
        fd.op_remove_input(op, 1);
        fd.op_set_opcode(op, Copy);
        return Ok(1);
    }
    Ok(0)
}

/// Port of `RuleAndDistribute`: `(V | W) & X  =>  (V & X) | (W & X)` when a side cancels.
pub(super) fn and_distribute(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let size = sz(fd, out(fd, op)?);
    if size > 8 {
        return Ok(0);
    }
    let fullmask = calc_mask(size);
    let mut found = None;
    for i in 0..2 {
        let other = inp(fd, op, 1 - i)?;
        if !known(fd, other) {
            continue;
        }
        let Some(orop) = def_with(fd, inp(fd, op, i)?, IntOr) else { continue };
        let (o0, o1) = (inp(fd, orop, 0)?, inp(fd, orop, 1)?);
        if !known(fd, o0) || !known(fd, o1) {
            continue;
        }
        let othermask = fd.nzmask(other);
        if othermask == 0 || othermask == fullmask {
            continue;
        }
        let (m1, m2) = (fd.nzmask(o0), fd.nzmask(o1));
        let cancels = m1 & othermask == 0 || m2 & othermask == 0;
        let trivial = is_const(fd, other) && (m1 & othermask == m1 || m2 & othermask == m2);
        if cancels || trivial {
            found = Some((other, o0, o1));
            break;
        }
    }
    let Some((other, o0, o1)) = found else { return Ok(0) };
    let addr = op_addr(fd, op);
    let n1 = insert_new(fd, IntAnd, addr, size, &[o0, other], op)?;
    let n2 = insert_new(fd, IntAnd, addr, size, &[o1, other], op)?;
    fd.op_set_input(op, n1, 0)?;
    fd.op_set_input(op, n2, 1)?;
    fd.op_set_opcode(op, IntOr);
    Ok(1)
}

/// `RuleAndCommute`: whether the AND with mask `othermask` should move above the shift of
/// `orvn`.
fn commute_wins(fd: &Funcdata, orvn: VarnodeId, othermask: u64, other_const: bool) -> Result<bool> {
    let Some(orop) = def(fd, orvn) else { return Ok(false) };
    match code(fd, orop) {
        IntOr => {
            let (m1, m2) = (fd.nzmask(inp(fd, orop, 0)?), fd.nzmask(inp(fd, orop, 1)?));
            Ok(m1 & othermask == 0
                || m2 & othermask == 0
                || (other_const && (m1 & othermask == m1 || m2 & othermask == m2)))
        }
        Piece => {
            let low = inp(fd, orop, 1)?;
            let m1 = fd.nzmask(low);
            let m2 = shl(fd.nzmask(inp(fd, orop, 0)?), (sz(fd, low) * 8) as i32);
            Ok(m1 & othermask == 0 || m2 & othermask == 0)
        }
        _ => Ok(false),
    }
}

/// `RuleAndCommute`: the mask of the other AND input as it will be after the commute with a
/// shift `opc` by `sa`, `None` when the commute gains nothing.
fn commuted_mask(opc: Opcode, fullmask: u64, mut othermask: u64, sa: i32) -> Option<u64> {
    if opc == IntRight {
        if shr(fullmask, sa) == othermask {
            return None;
        }
        othermask = shl(othermask, sa);
    } else {
        // the C++ reads `((fullmask<<sa)&&fullmask)==othermask`, a logical AND
        if u64::from(shl(fullmask, sa) != 0 && fullmask != 0) == othermask {
            return None;
        }
        othermask = shr(othermask, sa);
    }
    (othermask != 0 && othermask != fullmask).then_some(othermask)
}

/// Port of `RuleAndCommute`: `(V << W) & d  =>  (V & (d >> W)) << W`, and for a right shift.
pub(super) fn and_commute(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let size = sz(fd, out(fd, op)?);
    if size > 8 {
        return Ok(0);
    }
    let fullmask = calc_mask(size);
    let mut found = None;
    for i in 0..2 {
        let shiftvn = inp(fd, op, i)?;
        let Some(shiftop) = def(fd, shiftvn) else { continue };
        let opc = code(fd, shiftop);
        if opc != IntLeft && opc != IntRight {
            continue;
        }
        let savn = inp(fd, shiftop, 1)?;
        if !is_const(fd, savn) {
            continue;
        }
        let sa = off(fd, savn) as i32;
        let other = inp(fd, op, 1 - i)?;
        if !known(fd, other) {
            continue;
        }
        let Some(othermask) = commuted_mask(opc, fullmask, fd.nzmask(other), sa) else { continue };
        let orvn = inp(fd, shiftop, 0)?;
        let other_const = is_const(fd, other);
        if (opc == IntLeft && other_const && lone_descend(fd, shiftvn) == Some(op))
            || commute_wins(fd, orvn, othermask, other_const)?
        {
            found = Some((opc, other, savn, orvn));
            break;
        }
    }
    let Some((opc, other, savn, orvn)) = found else { return Ok(0) };
    let addr = op_addr(fd, op);
    let back = if opc == IntLeft { IntRight } else { IntLeft };
    let n1 = insert_new(fd, back, addr, size, &[other, savn], op)?;
    let n2 = insert_new(fd, IntAnd, addr, size, &[orvn, n1], op)?;
    fd.op_set_input(op, n2, 0)?;
    fd.op_set_input(op, savn, 1)?;
    fd.op_set_opcode(op, opc);
    Ok(1)
}

/// Port of `RuleAndPiece`: `PIECE(V,W) & c` with a piece the mask clears.
pub(super) fn and_piece(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let size = sz(fd, out(fd, op)?);
    let mut found = None;
    for i in 0..2 {
        let Some(pieceop) = def_with(fd, inp(fd, op, i)?, Piece) else { continue };
        let othermask = fd.nzmask(inp(fd, op, 1 - i)?);
        if othermask == calc_mask(size) || othermask == 0 {
            continue;
        }
        let (high, low) = (inp(fd, pieceop, 0)?, inp(fd, pieceop, 1)?);
        if !known(fd, high) || !known(fd, low) {
            continue;
        }
        let (maskhigh, masklow) = (fd.nzmask(high), fd.nzmask(low));
        if maskhigh & shr(othermask, (sz(fd, low) * 8) as i32) == 0 {
            if maskhigh == 0 && is_const(fd, high) {
                continue;
            }
            found = Some((i, IntZext, high, low));
            break;
        } else if masklow & othermask == 0 {
            if is_const(fd, low) {
                continue;
            }
            found = Some((i, Piece, high, low));
            break;
        }
    }
    let Some((i, opc, high, low)) = found else { return Ok(0) };
    let newop = fd.new_op(opc, op_addr(fd, op));
    if opc == IntZext {
        fd.op_set_input(newop, low, 0)?;
    } else {
        let z = fd.new_constant(sz(fd, low), 0);
        fd.op_set_input(newop, high, 0)?;
        fd.op_set_input(newop, z, 1)?;
    }
    let newvn = uniq_out(fd, size, newop)?;
    fd.op_insert_before(newop, op)?;
    fd.op_set_input(op, newvn, i)?;
    Ok(1)
}

/// Port of `RuleAndZext`: `sext(X) & 0xffff  =>  zext(X)`, and for the low part of a PIECE.
pub(super) fn and_zext(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let cvn1 = inp(fd, op, 1)?;
    if !is_const(fd, cvn1) {
        return Ok(0);
    }
    let Some(other) = def(fd, inp(fd, op, 0)?) else { return Ok(0) };
    let root = match code(fd, other) {
        IntSext => inp(fd, other, 0)?,
        Piece => inp(fd, other, 1)?,
        _ => return Ok(0),
    };
    if calc_mask(sz(fd, root)) != off(fd, cvn1) || is_free(fd, root) || sz(fd, root) > 8 {
        return Ok(0);
    }
    fd.op_set_opcode(op, IntZext);
    fd.op_remove_input(op, 1);
    fd.op_set_input(op, root, 0)?;
    Ok(1)
}

/// Port of `RuleAndCompare`: `zext(V) & c == 0  =>  V & (c & mask) == 0`, and for SUBPIECE.
pub(super) fn and_compare(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    if !const_match(fd, inp(fd, op, 1)?, 0) {
        return Ok(0);
    }
    let andvn = inp(fd, op, 0)?;
    let Some(andop) = def_with(fd, andvn, IntAnd) else { return Ok(0) };
    let maskvn = inp(fd, andop, 1)?;
    if !is_const(fd, maskvn) {
        return Ok(0);
    }
    let Some(subop) = def(fd, inp(fd, andop, 0)?) else { return Ok(0) };
    let baseconst = off(fd, maskvn);
    let (base, andconst) = match code(fd, subop) {
        Subpiece => {
            let base = inp(fd, subop, 0)?;
            if sz(fd, base) > 8 {
                return Ok(0);
            }
            (base, shl(baseconst, off(fd, inp(fd, subop, 1)?).wrapping_mul(8) as i32))
        }
        IntZext => {
            let base = inp(fd, subop, 0)?;
            (base, baseconst & calc_mask(sz(fd, base)))
        }
        _ => return Ok(0),
    };
    if baseconst == calc_mask(sz(fd, andvn)) || is_free(fd, base) {
        return Ok(0);
    }
    let bsz = sz(fd, base);
    let c = fd.new_constant(bsz, andconst);
    if baseconst == andconst {
        copy_symbol(fd, c, maskvn); // no change but the size: keep the old constant's type
    }
    let newout = insert_new(fd, IntAnd, op_addr(fd, andop), bsz, &[base, c], andop)?;
    fd.op_set_input(op, newout, 0)?;
    let z = fd.new_constant(bsz, 0);
    fd.op_set_input(op, z, 1)?;
    Ok(1)
}

/// `RuleDoubleShift`: the direction and amount of a constant shift or power-of-2 multiply.
fn shift_form(fd: &Funcdata, op: OpId) -> Result<Option<(Opcode, i32)>> {
    let val = off(fd, inp(fd, op, 1)?);
    Ok(match code(fd, op) {
        IntMult => pow2_shift(val).map(|sa| (IntLeft, sa)),
        opc => Some((opc, val as i32)),
    })
}

/// Port of `RuleDoubleShift`: two constant shifts in a row become one, or a mask.
pub(super) fn double_shift(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    if !is_const(fd, inp(fd, op, 1)?) {
        return Ok(0);
    }
    let secvn = inp(fd, op, 0)?;
    let Some(secop) = def(fd, secvn) else { return Ok(0) };
    if !matches!(code(fd, secop), IntLeft | IntRight | IntMult) || !is_const(fd, inp(fd, secop, 1)?) {
        return Ok(0);
    }
    let size = sz(fd, secvn);
    let base = inp(fd, secop, 0)?;
    if !known(fd, base) {
        return Ok(0);
    }
    let Some((opc1, sa1)) = shift_form(fd, op)? else { return Ok(0) };
    let Some((opc2, sa2)) = shift_form(fd, secop)? else { return Ok(0) };
    if opc1 == opc2 {
        if sa1.wrapping_add(sa2) < (8 * size) as i32 {
            let c = fd.new_constant(4, i64::from(sa1.wrapping_add(sa2)) as u64);
            fd.op_set_opcode(op, opc1);
            fd.op_set_input(op, base, 0)?;
            fd.op_set_input(op, c, 1)?;
        } else {
            let c = fd.new_constant(size, 0);
            fd.op_set_opcode(op, Copy);
            fd.op_set_input(op, c, 0)?;
            fd.op_remove_input(op, 1);
        }
        return Ok(1);
    }
    if size > 8 {
        return Ok(0);
    }
    let mut mask = calc_mask(size);
    let diffsa;
    if opc1 == IntLeft {
        if lone_descend(fd, secvn).is_none() {
            return Ok(0);
        }
        mask &= shl(mask, sa2);
        diffsa = sa1.wrapping_sub(sa2);
        if diffsa != 0 {
            return Ok(0);
        }
    } else {
        mask &= shr(mask, sa2);
        diffsa = sa2.wrapping_sub(sa1);
    }
    opposite_shifts(fd, op, base, size, mask, diffsa)
}

/// `RuleDoubleShift`, shifts in opposite directions: a mask, and a shift by what is left
/// (`diffsa` bits to the left).
fn opposite_shifts(fd: &mut Funcdata, op: OpId, base: VarnodeId, size: u32, mask: u64, mut diffsa: i32) -> Result<i32> {
    if diffsa == 0 {
        let c = fd.new_constant(size, mask);
        fd.op_set_opcode(op, IntAnd);
        fd.op_set_input(op, base, 0)?;
        fd.op_set_input(op, c, 1)?;
    } else {
        let c = fd.new_constant(size, mask);
        let newout = insert_new(fd, IntAnd, op_addr(fd, op), size, &[base, c], op)?;
        let mut finalopc = IntLeft;
        if diffsa < 0 {
            finalopc = IntRight;
            diffsa = diffsa.wrapping_neg();
        }
        fd.op_set_opcode(op, finalopc);
        fd.op_set_input(op, newout, 0)?;
        let c = fd.new_constant(4, diffsa as u64);
        fd.op_set_input(op, c, 1)?;
    }
    Ok(1)
}

/// Port of `RuleDoubleArithShift`: `(x s>> c) s>> d  =>  x s>> saturate(c + d)`.
pub(super) fn double_arith_shift(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let cd = inp(fd, op, 1)?;
    if !is_const(fd, cd) {
        return Ok(0);
    }
    let Some(shift2) = def_with(fd, inp(fd, op, 0)?, IntSright) else { return Ok(0) };
    let cc = inp(fd, shift2, 1)?;
    let invn = inp(fd, shift2, 0)?;
    if !is_const(fd, cc) || is_free(fd, invn) {
        return Ok(0);
    }
    let max = (sz(fd, out(fd, op)?) * 8) as i32 - 1;
    let sa = (off(fd, cc) as i32).wrapping_add(off(fd, cd) as i32);
    if sa <= 0 {
        return Ok(0);
    }
    fd.op_set_input(op, invn, 0)?;
    let c = fd.new_constant(4, sa.min(max) as u64);
    fd.op_set_input(op, c, 1)?;
    Ok(1)
}

/// Port of `RuleLeftRight`: `(V << c) s>> c  =>  sext(sub(V, 0))`, and zext for `>>`
/// (little-endian: the truncated varnode keeps the address).
pub(super) fn left_right(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let c = inp(fd, op, 1)?;
    if !is_const(fd, c) {
        return Ok(0);
    }
    let shiftin = inp(fd, op, 0)?;
    let Some(leftshift) = def_with(fd, shiftin, IntLeft) else { return Ok(0) };
    let lc = inp(fd, leftshift, 1)?;
    let sa = off(fd, c);
    if !is_const(fd, lc) || off(fd, lc) != sa || sa & 7 != 0 {
        return Ok(0);
    }
    let tsz = (sz(fd, shiftin) as i32).wrapping_sub((sa >> 3) as i32);
    if !matches!(tsz, 1 | 2 | 4 | 8) || lone_descend(fd, shiftin) != Some(op) {
        return Ok(0);
    }
    let (space, offset) = (fd.vn(shiftin).space, off(fd, shiftin));
    if space == Space::Join {
        return err("RuleLeftRight: truncating a join-space varnode (Address::renormalize) is not ported");
    }
    fd.op_unset_output(leftshift);
    let newvn = fd.new_varnode_out(tsz as u32, space, offset, leftshift);
    fd.op_set_opcode(leftshift, Subpiece);
    let z = fd.new_constant(sz(fd, lc), 0);
    fd.op_set_input(leftshift, z, 1)?;
    fd.op_set_input(op, newvn, 0)?;
    fd.op_remove_input(op, 1);
    fd.op_set_opcode(op, if code(fd, op) == IntSright { IntSext } else { IntZext });
    Ok(1)
}

/// `RuleShiftCompare`: the shift in front of the comparison as (left?, amount), `None` when
/// the form is not handled.
fn compare_shift(fd: &Funcdata, op: OpId, shiftvn: VarnodeId, shiftop: OpId) -> Result<Option<(bool, i32)>> {
    if !matches!(code(fd, shiftop), IntLeft | IntRight | IntMult | IntDiv) {
        return Ok(None);
    }
    let savn = inp(fd, shiftop, 1)?;
    if !is_const(fd, savn) {
        return Ok(None);
    }
    let val = off(fd, savn);
    let lone = lone_descend(fd, shiftvn) == Some(op);
    Ok(match code(fd, shiftop) {
        IntLeft => Some((true, val as i32)),
        IntRight => lone.then_some((false, val as i32)),
        IntMult => pow2_shift(val).map(|sa| (true, sa)),
        IntDiv => pow2_shift(val).filter(|_| lone).map(|sa| (false, sa)),
        _ => None,
    })
}

/// Port of `RuleShiftCompare`: `V << c == d  =>  V == (d >> c)` and the like.
pub(super) fn shift_compare(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let (shiftvn, constvn) = (inp(fd, op, 0)?, inp(fd, op, 1)?);
    if !is_const(fd, constvn) {
        return Ok(0);
    }
    let Some(shiftop) = def(fd, shiftvn) else { return Ok(0) };
    let Some((isleft, mut sa)) = compare_shift(fd, op, shiftvn, shiftop)? else { return Ok(0) };
    if sa == 0 {
        return Ok(0);
    }
    let mainvn = inp(fd, shiftop, 0)?;
    if is_free(fd, mainvn) || sz(fd, mainvn) > 8 {
        return Ok(0);
    }
    let constval = off(fd, constvn);
    let nzmask = fd.nzmask(mainvn);
    let csz = sz(fd, constvn);
    let newconst;
    if isleft {
        newconst = shr(constval, sa);
        if shl(newconst, sa) != constval {
            return Ok(0);
        }
        let tmp = shl(nzmask, sa) & calc_mask(sz(fd, shiftvn));
        if shr(tmp, sa) != nzmask {
            if lone_descend(fd, shiftvn) != Some(op) {
                return Ok(0);
            }
            sa = ((8 * sz(fd, shiftvn)) as i32).wrapping_sub(sa);
            let newmask = fd.new_constant(csz, shl(1, sa).wrapping_sub(1));
            let newtmp = insert_new(fd, IntAnd, op_addr(fd, op), csz, &[mainvn, newmask], shiftop)?;
            fd.op_set_input(op, newtmp, 0)?;
            let c = fd.new_constant(csz, newconst);
            fd.op_set_input(op, c, 1)?;
            return Ok(1);
        }
    } else {
        if shl(shr(nzmask, sa), sa) != nzmask {
            return Ok(0);
        }
        newconst = shl(constval, sa) & calc_mask(sz(fd, shiftvn));
        if shr(newconst, sa) != constval {
            return Ok(0);
        }
    }
    let c = fd.new_constant(csz, newconst);
    fd.op_set_input(op, mainvn, 0)?;
    fd.op_set_input(op, c, 1)?;
    Ok(1)
}

/// Port of `RuleSignShift`: `V >> 31  =>  (V s>> 31) * -1` in arithmetic or comparisons.
pub(super) fn sign_shift(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let constvn = inp(fd, op, 1)?;
    let invn = inp(fd, op, 0)?;
    let size = sz(fd, invn);
    if !is_const(fd, constvn) || off(fd, constvn) != u64::from(8 * size - 1) || is_free(fd, invn) {
        return Ok(0);
    }
    let o = out(fd, op)?;
    let convert = fd.vn(o).descend.iter().any(|&a| match code(fd, a) {
        IntEqual | IntNotequal => fd.op(a).ins.get(1).is_some_and(|&c| is_const(fd, c)),
        IntAdd | IntMult => true,
        _ => false,
    });
    if !convert {
        return Ok(0);
    }
    let shiftop = fd.new_op(IntSright, op_addr(fd, op));
    let uniq = uniq_out(fd, size, shiftop)?;
    fd.op_set_input(op, uniq, 0)?;
    let m = fd.new_constant(size, calc_mask(size));
    fd.op_set_input(op, m, 1)?;
    fd.op_set_opcode(op, IntMult);
    fd.op_set_input(shiftop, invn, 0)?;
    fd.op_set_input(shiftop, constvn, 1)?;
    fd.op_insert_before(shiftop, op)?;
    Ok(1)
}

/// Port of `RuleShift2Mult`: `V << 2  =>  V * 4` next to arithmetic.
pub(super) fn shift_2_mult(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let vn = out(fd, op)?;
    let constvn = inp(fd, op, 1)?;
    if !is_const(fd, constvn) {
        return Ok(0);
    }
    let val = off(fd, constvn) as i32;
    if val >= 32 {
        return Ok(0);
    }
    let arith = |o: OpId| matches!(code(fd, o), IntAdd | IntSub | IntMult);
    if !def(fd, inp(fd, op, 0)?).into_iter().chain(fd.vn(vn).descend.iter().copied()).any(arith) {
        return Ok(0);
    }
    let c = fd.new_constant(sz(fd, vn), shl(1, val));
    fd.op_set_input(op, c, 1)?;
    fd.op_set_opcode(op, IntMult);
    Ok(1)
}

/// `RuleShiftPiece::multPowerOf2`.
fn mult_power_of_2(fd: &Funcdata, op: OpId) -> i32 {
    let opc = code(fd, op);
    let Some(&cvn) = fd.op(op).ins.get(1) else { return -1 };
    if (opc != IntLeft && opc != IntMult) || !is_const(fd, cvn) {
        return -1;
    }
    let val = off(fd, cvn);
    if opc == IntLeft {
        return val as i32;
    }
    let sa = leastsigbit_set(val);
    if sa >= 0 && shr(val, sa) == 1 {
        sa
    } else {
        -1
    }
}

/// `RuleShiftPiece`, the form `V = zext(W); V | (sext(sub(V,0) s>> 31) << 32)  =>  sext(sub)`.
fn shift_piece_sext(fd: &mut Funcdata, op: OpId, vn1: VarnodeId, zextloop: OpId, sa: i32) -> Result<i32> {
    let Some(rshift) = def_with(fd, vn1, IntSright) else { return Ok(0) };
    let rc = inp(fd, rshift, 1)?;
    if !is_const(fd, rc) {
        return Ok(0);
    }
    let vn2 = inp(fd, rshift, 0)?;
    let Some(subop) = def_with(fd, vn2, Subpiece) else { return Ok(0) };
    let big = out(fd, zextloop)?;
    let bits = (sz(fd, vn2) * 8) as i32;
    if off(fd, inp(fd, subop, 1)?) != 0
        || inp(fd, subop, 0)? != big
        || off(fd, rc) as i32 != bits - 1
        || shr(fd.nzmask(big), sa) != 0
        || sa != bits
    {
        return Ok(0);
    }
    fd.op_set_opcode(op, IntSext);
    fd.op_set_input(op, vn2, 0)?;
    fd.op_remove_input(op, 1);
    Ok(1)
}

/// Port of `RuleShiftPiece`: `zext(W) | (zext(V) << 16)  =>  concat(V, W)`.
pub(super) fn shift_piece(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let (Some(mut shiftop), Some(mut zextloop)) = (def(fd, inp(fd, op, 0)?), def(fd, inp(fd, op, 1)?)) else {
        return Ok(0);
    };
    let mut sa = mult_power_of_2(fd, shiftop);
    if sa < 0 {
        sa = mult_power_of_2(fd, zextloop);
        if sa < 0 {
            return Ok(0);
        }
        std::mem::swap(&mut shiftop, &mut zextloop);
    }
    let Some(zexthiop) = def(fd, inp(fd, shiftop, 0)?) else { return Ok(0) };
    let hiopc = code(fd, zexthiop);
    if hiopc != IntZext && hiopc != IntSext {
        return Ok(0);
    }
    let vn1 = inp(fd, zexthiop, 0)?;
    if is_const(fd, vn1) {
        if sz(fd, vn1) < 8 {
            return Ok(0);
        }
    } else if is_free(fd, vn1) {
        return Ok(0);
    }
    let concatsize = sa.wrapping_add((8 * sz(fd, vn1)) as i32);
    let outbits = (sz(fd, out(fd, op)?) * 8) as i32;
    if outbits < concatsize {
        return Ok(0);
    }
    if code(fd, zextloop) != IntZext {
        return shift_piece_sext(fd, op, vn1, zextloop, sa);
    }
    let vn2 = inp(fd, zextloop, 0)?;
    if is_free(fd, vn2) || sa != (8 * sz(fd, vn2)) as i32 {
        return Ok(0);
    }
    if concatsize == outbits {
        fd.op_set_opcode(op, Piece);
        fd.op_set_input(op, vn1, 0)?;
        fd.op_set_input(op, vn2, 1)?;
    } else {
        let newout = insert_new(fd, Piece, op_addr(fd, op), (concatsize / 8) as u32, &[vn1, vn2], op)?;
        fd.op_set_opcode(op, hiopc);
        fd.op_remove_input(op, 1);
        fd.op_set_input(op, newout, 0)?;
    }
    Ok(1)
}

/// Port of `RuleShiftAnd`: `(V & c) << sa  =>  V << sa` when the mask keeps every bit left.
pub(super) fn shift_and(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let cvn = inp(fd, op, 1)?;
    if !is_const(fd, cvn) {
        return Ok(0);
    }
    let Some(andop) = def_with(fd, inp(fd, op, 0)?, IntAnd) else { return Ok(0) };
    let maskvn = inp(fd, andop, 1)?;
    let invn = inp(fd, andop, 0)?;
    if !is_const(fd, maskvn) || is_free(fd, invn) {
        return Ok(0);
    }
    let mut mask = off(fd, maskvn);
    let mut opc = code(fd, op);
    let sa;
    if opc == IntRight || opc == IntLeft {
        sa = off(fd, cvn) as i32;
    } else {
        sa = leastsigbit_set(off(fd, cvn));
        if sa <= 0 || shl(1, sa) != off(fd, cvn) {
            return Ok(0);
        }
        opc = IntLeft;
    }
    let mut nzm = fd.nzmask(invn);
    let fullmask = calc_mask(sz(fd, invn));
    if opc == IntRight {
        nzm = shr(nzm, sa);
        mask = shr(mask, sa);
    } else {
        nzm = shl(nzm, sa) & fullmask;
        mask = shl(mask, sa) & fullmask;
    }
    if mask & nzm != nzm {
        return Ok(0);
    }
    fd.op_set_input(op, invn, 0)?;
    Ok(1)
}

/// Port of `RuleBitUndistribute`: `zext(V) & zext(W)  =>  zext(V & W)`, and for shifts.
pub(super) fn bit_undistribute(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let (Some(d1), Some(d2)) = (def(fd, inp(fd, op, 0)?), def(fd, inp(fd, op, 1)?)) else { return Ok(0) };
    let opc = code(fd, d1);
    if code(fd, d2) != opc {
        return Ok(0);
    }
    if !matches!(opc, IntZext | IntSext | IntLeft | IntRight | IntSright) {
        return Ok(0);
    }
    let (in1, in2) = (inp(fd, d1, 0)?, inp(fd, d2, 0)?);
    match opc {
        IntZext | IntSext => {
            if is_free(fd, in1) || is_free(fd, in2) || sz(fd, in1) != sz(fd, in2) {
                return Ok(0);
            }
            fd.op_remove_input(op, 1);
        }
        _ => {
            let (s1, s2) = (inp(fd, d1, 1)?, inp(fd, d2, 1)?);
            let extra = if is_const(fd, s1) && is_const(fd, s2) {
                if off(fd, s1) != off(fd, s2) {
                    return Ok(0);
                }
                None
            } else if s1 != s2 || is_free(fd, s1) {
                return Ok(0);
            } else {
                Some(s1)
            };
            if is_free(fd, in1) || is_free(fd, in2) {
                return Ok(0);
            }
            let extra = match extra {
                Some(v) => v,
                None => fd.new_constant(sz(fd, s1), off(fd, s1)),
            };
            fd.op_set_input(op, extra, 1)?;
        }
    }
    let newext = fd.new_op(code(fd, op), op_addr(fd, op));
    let small = uniq_out(fd, sz(fd, in1), newext)?;
    fd.op_set_input(newext, in1, 0)?;
    fd.op_set_input(newext, in2, 1)?;
    fd.op_set_opcode(op, opc);
    fd.op_set_input(op, small, 0)?;
    fd.op_insert_before(newext, op)?;
    Ok(1)
}

/// Port of `RuleXorSwap`: `(V ^ W) ^ V  =>  W`.
pub(super) fn xor_swap(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    for i in 0..2 {
        let Some(op2) = def_with(fd, inp(fd, op, i)?, IntXor) else { continue };
        let other = inp(fd, op, 1 - i)?;
        let (vn0, vn1) = (inp(fd, op2, 0)?, inp(fd, op2, 1)?);
        let keep = if other == vn0 && !is_free(fd, vn1) {
            vn1
        } else if other == vn1 && !is_free(fd, vn0) {
            vn0
        } else {
            continue;
        };
        fd.op_remove_input(op, 1);
        fd.op_set_opcode(op, Copy);
        fd.op_set_input(op, keep, 0)?;
        return Ok(1);
    }
    Ok(0)
}

/// `RulePopcountBoolXor::getBooleanResult`, one step: the input of `op` holding bit `bit_pos`
/// (mask `mask`) of its output, with the bit's position and mask there; `None` when the bit
/// cannot be followed.
fn bit_source(fd: &Funcdata, op: OpId, bit_pos: i32, mask: u64) -> Result<Option<(VarnodeId, i32, u64)>> {
    let const_sa = |slot: usize| -> Result<Option<i32>> {
        let v = inp(fd, op, slot)?;
        Ok(is_const(fd, v).then(|| off(fd, v) as i32))
    };
    Ok(match code(fd, op) {
        IntAnd => is_const(fd, inp(fd, op, 1)?).then_some((inp(fd, op, 0)?, bit_pos, mask)),
        IntXor | IntOr => {
            let (vn0, vn1) = (inp(fd, op, 0)?, inp(fd, op, 1)?);
            match (fd.nzmask(vn0) & mask != 0, fd.nzmask(vn1) & mask != 0) {
                (true, false) => Some((vn0, bit_pos, mask)),
                (false, true) => Some((vn1, bit_pos, mask)),
                _ => None, // no unique path
            }
        }
        IntZext | IntSext => {
            let vn = inp(fd, op, 0)?;
            (bit_pos < (sz(fd, vn) * 8) as i32).then_some((vn, bit_pos, mask))
        }
        Subpiece => {
            let sa = (off(fd, inp(fd, op, 1)?) as i32).wrapping_mul(8);
            Some((inp(fd, op, 0)?, bit_pos.wrapping_add(sa), shl(mask, sa)))
        }
        Piece => {
            let (vn0, vn1) = (inp(fd, op, 0)?, inp(fd, op, 1)?);
            let sa = (sz(fd, vn1) * 8) as i32;
            Some(if bit_pos >= sa { (vn0, bit_pos.wrapping_sub(sa), shr(mask, sa)) } else { (vn1, bit_pos, mask) })
        }
        IntLeft => match const_sa(1)? {
            Some(sa) if sa <= bit_pos => Some((inp(fd, op, 0)?, bit_pos.wrapping_sub(sa), shr(mask, sa))),
            _ => None,
        },
        IntRight | IntSright => {
            let Some(sa) = const_sa(1)? else { return Ok(None) };
            let vn = inp(fd, op, 0)?;
            let pos = bit_pos.wrapping_add(sa);
            (pos < (sz(fd, vn) * 8) as i32).then_some((vn, pos, shl(mask, sa)))
        }
        _ => None,
    })
}

/// `RulePopcountBoolXor::getBooleanResult`: the boolean varnode that is bit `bit_pos` of `vn`,
/// or the constant value of the bit (-1 when it is neither).
fn boolean_result(fd: &Funcdata, mut vn: VarnodeId, mut bit_pos: i32) -> Result<(Option<VarnodeId>, i32)> {
    let mut mask = shl(1, bit_pos);
    loop {
        if is_const(fd, vn) {
            return Ok((None, (shr(off(fd, vn), bit_pos) & 1) as i32));
        }
        let Some(op) = def(fd, vn) else { return Ok((None, -1)) };
        if bit_pos == 0 && sz(fd, vn) == 1 && fd.nzmask(vn) == mask {
            return Ok((Some(vn), -1));
        }
        let Some(next) = bit_source(fd, op, bit_pos, mask)? else { return Ok((None, -1)) };
        (vn, bit_pos, mask) = next;
    }
}

/// Port of `RulePopcountBoolXor`: `popcount(b1 << 6 | b2 << 2) & 1  =>  b1 ^ b2`.
pub(super) fn popcount_bool_xor(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let outvn = out(fd, op)?;
    for base in fd.vn(outvn).descend.iter().copied() {
        if code(fd, base) != IntAnd {
            continue;
        }
        let tmp = inp(fd, base, 1)?;
        if !const_match(fd, tmp, 1) || sz(fd, tmp) != 1 {
            continue;
        }
        let invn = inp(fd, op, 0)?;
        if def(fd, invn).is_none() {
            return Ok(0);
        }
        let nzm = fd.nzmask(invn);
        match nzm.count_ones() {
            1 => {
                let (Some(b1), _) = boolean_result(fd, invn, leastsigbit_set(nzm))? else { continue };
                fd.op_set_opcode(base, Copy);
                fd.op_remove_input(base, 1);
                fd.op_set_input(base, b1, 0)?;
                return Ok(1);
            }
            2 => {
                let (b1, c0) = boolean_result(fd, invn, leastsigbit_set(nzm))?;
                if b1.is_none() && c0 != 1 {
                    continue;
                }
                let (b2, c1) = boolean_result(fd, invn, mostsigbit_set(nzm))?;
                if (b2.is_none() && c1 != 1) || (b1.is_none() && b2.is_none()) {
                    continue;
                }
                let b1 = b1.unwrap_or_else(|| fd.new_constant(1, 1));
                let b2 = b2.unwrap_or_else(|| fd.new_constant(1, 1));
                fd.op_set_opcode(base, IntXor);
                fd.op_set_input(base, b1, 0)?;
                fd.op_set_input(base, b2, 1)?;
                return Ok(1);
            }
            _ => {}
        }
    }
    Ok(0)
}

/// Port of `RuleLzcountShiftBool`: `lzcount(X) >> c  =>  X == 0` when `X` has `2^c` bits.
pub(super) fn lzcount_shift_bool(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let outvn = out(fd, op)?;
    let invn = inp(fd, op, 0)?;
    let max_return = u64::from(8 * sz(fd, invn));
    if max_return.count_ones() != 1 {
        return Ok(0);
    }
    for base in fd.vn(outvn).descend.iter().copied() {
        if code(fd, base) != IntRight && code(fd, base) != IntSright {
            continue;
        }
        let vn1 = inp(fd, base, 1)?;
        if !is_const(fd, vn1) || shr(max_return, off(fd, vn1) as i32) != 1 {
            continue;
        }
        let b = fd.new_constant(sz(fd, invn), 0);
        let eq = insert_new(fd, IntEqual, op_addr(fd, base), 1, &[invn, b], base)?;
        fd.op_remove_input(base, 1);
        let one_byte = sz(fd, out(fd, base)?) == 1;
        fd.op_set_opcode(base, if one_byte { Copy } else { IntZext });
        fd.op_set_input(base, eq, 0)?;
        return Ok(1);
    }
    Ok(0)
}

/// Port of `RuleOrCompare`: `(V | W) == 0  =>  V == 0 && W == 0`, and `!=` with `||`.
pub(super) fn or_compare(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let outvn = out(fd, op)?;
    let readers = fd.vn(outvn).descend.to_vec();
    for &comp in &readers {
        if !matches!(code(fd, comp), IntEqual | IntNotequal) || !const_match(fd, inp(fd, comp, 1)?, 0) {
            return Ok(0);
        }
    }
    let (v, w) = (inp(fd, op, 0)?, inp(fd, op, 1)?);
    if readers.is_empty() || is_free(fd, v) || is_free(fd, w) {
        return Ok(0);
    }
    for equal in readers {
        let opc = code(fd, equal);
        let addr = op_addr(fd, equal);
        let zero_v = fd.new_constant(sz(fd, v), 0);
        let zero_w = fd.new_constant(sz(fd, w), 0);
        let eq_v = fd.new_op(opc, addr);
        fd.op_set_input(eq_v, v, 0)?;
        fd.op_set_input(eq_v, zero_v, 1)?;
        let eq_w = fd.new_op(opc, addr);
        fd.op_set_input(eq_w, w, 0)?;
        fd.op_set_input(eq_w, zero_w, 1)?;
        let out_v = uniq_out(fd, 1, eq_v)?;
        let out_w = uniq_out(fd, 1, eq_w)?;
        fd.op_insert_before(eq_v, equal)?;
        fd.op_insert_before(eq_w, equal)?;
        fd.op_set_opcode(equal, if opc == IntEqual { BoolAnd } else { BoolOr });
        fd.op_set_input(equal, out_v, 0)?;
        fd.op_set_input(equal, out_w, 1)?;
    }
    Ok(1)
}
