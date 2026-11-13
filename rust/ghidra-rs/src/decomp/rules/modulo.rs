//! The sign and remainder rules: `RuleSignForm`, `RuleSignForm2`, `RuleSignNearMult`,
//! `RuleModOpt`, `RuleSignMod2nOpt`, `RuleSignMod2nOpt2`, `RuleSignMod2Opt` (ruleaction.cc).

use super::*;

/// Port of `RuleSignForm`: `sub(sext(V),c)` taking only extension bits becomes `V s>> 31`.
pub(super) fn sign_form(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let Some(sextop) = def_with(fd, inp(fd, op, 0)?, IntSext) else { return Ok(0) };
    let a = inp(fd, sextop, 0)?;
    let size = fd.vn(a).size;
    if size != fd.vn(out(fd, op)?).size || int4(fd, inp(fd, op, 1)?) < i64::from(size) || fd.vn(a).is_free() {
        return Ok(0);
    }
    fd.op_set_input(op, a, 0)?;
    let c = fd.new_constant(4, u64::from(8 * size - 1));
    fd.op_set_input(op, c, 1)?;
    fd.op_set_opcode(op, IntSright);
    Ok(1)
}

/// Port of `RuleSignForm2`: `sub(sext(V)*small,c) s>> 31` reads `V` instead. Like the C++ it
/// reports no change (returns 0) after making it.
pub(super) fn sign_form2(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let const_vn = inp(fd, op, 1)?;
    if !is_const(fd, const_vn) {
        return Ok(0);
    }
    let in_vn = inp(fd, op, 0)?;
    let sizeout = fd.vn(in_vn).size;
    if fd.vn(const_vn).offset as i32 != (sizeout * 8) as i32 - 1 {
        return Ok(0);
    }
    let Some(sub_op) = def_with(fd, in_vn, Subpiece) else { return Ok(0) };
    let c = int4(fd, inp(fd, sub_op, 1)?);
    let mult_out = inp(fd, sub_op, 0)?;
    let mult_size = fd.vn(mult_out).size;
    if c + i64::from(sizeout) != i64::from(mult_size) {
        return Ok(0);
    }
    let Some(mult_op) = def_with(fd, mult_out, IntMult) else { return Ok(0) };
    let mut found = None;
    for slot in 0..2 {
        if let Some(sext_op) = def_with(fd, inp(fd, mult_op, slot)?, IntSext) {
            found = Some((slot, sext_op));
            break;
        }
    }
    let Some((slot, sext_op)) = found else { return Ok(0) };
    let a = inp(fd, sext_op, 0)?;
    if fd.vn(a).is_free() || fd.vn(a).size != sizeout {
        return Ok(0);
    }
    let other = inp(fd, mult_op, 1 - slot)?;
    if is_const(fd, other) {
        if fd.vn(other).offset > calc_mask(sizeout) || 2 * sizeout > mult_size {
            return Ok(0);
        }
    } else if let Some(zext_op) = def(fd, other) {
        if fd.op(zext_op).opc != IntZext || fd.vn(inp(fd, zext_op, 0)?).size + sizeout > mult_size {
            return Ok(0);
        }
    } else {
        return Ok(0);
    }
    fd.op_set_input(op, a, 0)?;
    Ok(0)
}

/// Port of `RuleSignNearMult`: `(V + (V s>> 31) >> n) & mask` becomes `(V s/ 2^n) * 2^n`.
pub(super) fn sign_near_mult(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let mask_vn = inp(fd, op, 1)?;
    if !is_const(fd, mask_vn) {
        return Ok(0);
    }
    let Some(addop) = def_with(fd, inp(fd, op, 0)?, IntAdd) else { return Ok(0) };
    let mut found = None;
    for i in 0..2 {
        let shiftvn = inp(fd, addop, i)?;
        if let Some(unshift) = def_with(fd, shiftvn, IntRight) {
            if is_const(fd, inp(fd, unshift, 1)?) {
                found = Some((i, shiftvn, unshift));
                break;
            }
        }
    }
    let Some((i, shiftvn, unshiftop)) = found else { return Ok(0) };
    let x = inp(fd, addop, 1 - i)?;
    if fd.vn(x).is_free() {
        return Ok(0);
    }
    let n = int4(fd, inp(fd, unshiftop, 1)?);
    if n <= 0 {
        return Ok(0);
    }
    let shift_size = fd.vn(shiftvn).size;
    let n = i64::from(shift_size) * 8 - n;
    if n <= 0 {
        return Ok(0);
    }
    // the C++ shifts are by n mod 64 on x86
    let full = calc_mask(shift_size);
    if shl(full, n as i32) & full != fd.vn(mask_vn).offset {
        return Ok(0);
    }
    let Some(sshiftop) = def_with(fd, inp(fd, unshiftop, 0)?, IntSright) else { return Ok(0) };
    let sc = inp(fd, sshiftop, 1)?;
    let xsize = fd.vn(x).size;
    if !is_const(fd, sc) || inp(fd, sshiftop, 0)? != x || int4(fd, sc) != 8 * i64::from(xsize) - 1 {
        return Ok(0);
    }
    let pow = shl(1, n as i32);
    let newdiv = fd.new_op(IntSdiv, fd.op(op).seq.addr);
    let divvn = uniq_out(fd, xsize, newdiv)?;
    fd.op_set_input(newdiv, x, 0)?;
    let c = fd.new_constant(xsize, pow);
    fd.op_set_input(newdiv, c, 1)?;
    fd.op_insert_before(newdiv, op)?;
    fd.op_set_opcode(op, IntMult);
    fd.op_set_input(op, divvn, 0)?;
    let c = fd.new_constant(xsize, pow);
    fd.op_set_input(op, c, 1)?;
    Ok(1)
}

/// Port of `RuleModOpt`: `x + (x / y) * -y` becomes `x % y`.
pub(super) fn mod_opt(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let x = inp(fd, op, 0)?;
    let div = inp(fd, op, 1)?;
    let outvn = out(fd, op)?;
    let readers = fd.vn(outvn).descend.to_vec();
    for multop in readers {
        if fd.op(multop).opc != IntMult {
            continue;
        }
        let mut div2 = inp(fd, multop, 1)?;
        if div2 == outvn {
            div2 = inp(fd, multop, 0)?;
        }
        if is_const(fd, div2) {
            if !is_const(fd, div) {
                continue;
            }
            let mask = calc_mask(fd.vn(div2).size);
            if ((fd.vn(div2).offset ^ mask).wrapping_add(1) & mask) != fd.vn(div).offset {
                continue;
            }
        } else {
            let Some(neg) = def_with(fd, div2, Int2comp) else { continue };
            if inp(fd, neg, 0)? != div {
                continue;
            }
        }
        let outvn2 = out(fd, multop)?;
        let readers = fd.vn(outvn2).descend.to_vec();
        for addop in readers {
            if fd.op(addop).opc != IntAdd {
                continue;
            }
            let mut lvn = inp(fd, addop, 0)?;
            if lvn == outvn2 {
                lvn = inp(fd, addop, 1)?;
            }
            if lvn != x {
                continue;
            }
            fd.op_set_input(addop, x, 0)?;
            let d = if is_const(fd, div) {
                let v = fd.vn(div);
                fd.new_constant(v.size, v.offset)
            } else {
                div
            };
            fd.op_set_input(addop, d, 1)?;
            let opc = if fd.op(op).opc == IntDiv { IntRem } else { IntSrem };
            fd.op_set_opcode(addop, opc);
            return Ok(1);
        }
    }
    Ok(0)
}

/// Port of `RuleSignMod2nOpt::checkSignExtraction`: `V` when `vn` is `V s>> (bits-1)`.
fn check_sign_extraction(fd: &Funcdata, vn: VarnodeId) -> Result<Option<VarnodeId>> {
    let Some(sign_op) = def_with(fd, vn, IntSright) else { return Ok(None) };
    let c = inp(fd, sign_op, 1)?;
    if !is_const(fd, c) {
        return Ok(None);
    }
    let res = inp(fd, sign_op, 0)?;
    Ok((fd.vn(c).offset as i32 == (fd.vn(res).size * 8) as i32 - 1).then_some(res))
}

/// `RuleSignMod2nOpt`'s search for `a` among the inputs of `add_op`, through a SUBPIECE(.,0)
/// on the truncated form.
fn find_a_slot(fd: &Funcdata, add_op: OpId, a: VarnodeId, truncated: bool) -> Result<Option<usize>> {
    for slot in 0..2 {
        let mut vn = inp(fd, add_op, slot)?;
        if truncated {
            let Some(sub_op) = def_with(fd, vn, Subpiece) else { continue };
            if fd.vn(inp(fd, sub_op, 1)?).offset != 0 {
                continue;
            }
            vn = inp(fd, sub_op, 0)?;
        }
        if vn == a {
            return Ok(Some(slot));
        }
    }
    Ok(None)
}

/// `RuleSignMod2nOpt`'s test of one INT_MULT by -1 of the correction: the INT_ADD to turn into
/// the remainder.
fn sign_mod2n_base(
    fd: &Funcdata,
    multop: OpId,
    a: VarnodeId,
    correct_size: u32,
    mask: u64,
    shift_amt: i64,
) -> Result<Option<OpId>> {
    let negone = inp(fd, multop, 1)?;
    if !is_const(fd, negone) || fd.vn(negone).offset != calc_mask(correct_size) {
        return Ok(None);
    }
    let mult_out = out(fd, multop)?;
    let Some(base_op) = lone_descend(fd, mult_out) else { return Ok(None) };
    if fd.op(base_op).opc != IntAdd {
        return Ok(None);
    }
    let Some(mslot) = fd.slot_of(base_op, mult_out) else { return Ok(None) };
    let mut and_out = inp(fd, base_op, 1 - mslot)?;
    let Some(mut and_op) = def(fd, and_out) else { return Ok(None) };
    let mut trunc_size = None;
    if fd.op(and_op).opc == IntZext {
        and_out = inp(fd, and_op, 0)?;
        let Some(d) = def_with(fd, and_out, IntAnd) else { return Ok(None) };
        and_op = d;
        trunc_size = Some(fd.vn(and_out).size);
    } else if fd.op(and_op).opc != IntAnd {
        return Ok(None);
    }
    let c = inp(fd, and_op, 1)?;
    if !is_const(fd, c) || fd.vn(c).offset != mask {
        return Ok(None);
    }
    let Some(add_op) = def_with(fd, inp(fd, and_op, 0)?, IntAdd) else { return Ok(None) };
    let Some(a_slot) = find_a_slot(fd, add_op, a, trunc_size.is_some())? else { return Ok(None) };
    let Some(shift_op) = def_with(fd, inp(fd, add_op, 1 - a_slot)?, IntRight) else { return Ok(None) };
    let c = inp(fd, shift_op, 1)?;
    if !is_const(fd, c) {
        return Ok(None);
    }
    let a_size = i64::from(fd.vn(a).size);
    let mut shiftval = int4(fd, c);
    if let Some(t) = trunc_size {
        shiftval += (a_size - i64::from(t)) * 8;
    }
    if shiftval != shift_amt {
        return Ok(None);
    }
    let Some(mut ext_vn) = check_sign_extraction(fd, inp(fd, shift_op, 0)?)? else { return Ok(None) };
    if let Some(t) = trunc_size {
        let Some(sub_op) = def_with(fd, ext_vn, Subpiece) else { return Ok(None) };
        if int4(fd, inp(fd, sub_op, 1)?) != i64::from(t) {
            return Ok(None);
        }
        ext_vn = inp(fd, sub_op, 0)?;
    }
    Ok((ext_vn == a).then_some(base_op))
}

/// Port of `RuleSignMod2nOpt`: the signed remainder by 2^n compilers emit as
/// `V + -1 * ((V + (V s>> 31) >> 32-n) & (2^n-1))`... recognized from the sign extraction.
pub(super) fn sign_mod2n_opt(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let c = inp(fd, op, 1)?;
    if !is_const(fd, c) {
        return Ok(0);
    }
    let shift_amt = int4(fd, c);
    let Some(a) = check_sign_extraction(fd, inp(fd, op, 0)?)? else { return Ok(0) };
    if fd.vn(a).is_free() {
        return Ok(0);
    }
    let correct_vn = out(fd, op)?;
    let correct_size = fd.vn(correct_vn).size;
    let n = i64::from(fd.vn(a).size) * 8 - shift_amt;
    // the C++ `(1 << n) - 1` shifts by n mod 64 on x86
    let mask = shl(1, n as i32).wrapping_sub(1);
    let readers = fd.vn(correct_vn).descend.to_vec();
    for multop in readers {
        if fd.op(multop).opc != IntMult {
            continue;
        }
        if let Some(base_op) = sign_mod2n_base(fd, multop, a, correct_size, mask, shift_amt)? {
            fd.op_set_opcode(base_op, IntSrem);
            fd.op_set_input(base_op, a, 0)?;
            let c = fd.new_constant(fd.vn(a).size, mask.wrapping_add(1));
            fd.op_set_input(base_op, c, 1)?;
            return Ok(1);
        }
    }
    Ok(0)
}

/// Port of `RuleSignMod2Opt`: `(V + -1*(V s>> 31)) & 1` plus the sign extraction becomes
/// `V s% 2`.
pub(super) fn sign_mod2_opt(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let c = inp(fd, op, 1)?;
    if !is_const(fd, c) || fd.vn(c).offset != 1 {
        return Ok(0);
    }
    let Some(add_op) = def_with(fd, inp(fd, op, 0)?, IntAdd) else { return Ok(0) };
    let mut found = None;
    for mult_slot in 0..2 {
        let Some(mult_op) = def_with(fd, inp(fd, add_op, mult_slot)?, IntMult) else { continue };
        let c = inp(fd, mult_op, 1)?;
        if is_const(fd, c) && fd.vn(c).offset == calc_mask(fd.vn(c).size) {
            found = Some((mult_slot, mult_op));
            break;
        }
    }
    let Some((mult_slot, mult_op)) = found else { return Ok(0) };
    let Some(mut base) = check_sign_extraction(fd, inp(fd, mult_op, 0)?)? else { return Ok(0) };
    let other_base = inp(fd, add_op, 1 - mult_slot)?;
    let mut trunc = false;
    if base != other_base {
        let (Some(sub_op), Some(other_sub)) = (def(fd, base), def(fd, other_base)) else { return Ok(0) };
        if fd.op(sub_op).opc != Subpiece {
            return Ok(0);
        }
        let trunc_amt = int4(fd, inp(fd, sub_op, 1)?);
        let whole = inp(fd, sub_op, 0)?;
        if trunc_amt + i64::from(fd.vn(base).size) != i64::from(fd.vn(whole).size) {
            return Ok(0);
        }
        base = whole;
        if fd.op(other_sub).opc != Subpiece || fd.vn(inp(fd, other_sub, 1)?).offset != 0 {
            return Ok(0);
        }
        if inp(fd, other_sub, 0)? != base {
            return Ok(0);
        }
        trunc = true;
    }
    if fd.vn(base).is_free() {
        return Ok(0);
    }
    let mut and_out = out(fd, op)?;
    if trunc {
        let Some(ext_op) = lone_descend(fd, and_out).filter(|&e| fd.op(e).opc == IntZext) else { return Ok(0) };
        and_out = out(fd, ext_op)?;
    }
    let readers = fd.vn(and_out).descend.to_vec();
    for root_op in readers {
        if fd.op(root_op).opc != IntAdd {
            continue;
        }
        let Some(slot) = fd.slot_of(root_op, and_out) else { continue };
        if check_sign_extraction(fd, inp(fd, root_op, 1 - slot)?)? != Some(base) {
            continue;
        }
        fd.op_set_opcode(root_op, IntSrem);
        fd.op_set_input(root_op, base, 0)?;
        let c = fd.new_constant(fd.vn(base).size, 2);
        fd.op_set_input(root_op, c, 1)?;
        return Ok(1);
    }
    Ok(0)
}

/// Port of `RuleSignMod2nOpt2::checkSignExtForm`: `V` when `op` is `V + -1*(V s>> 31)`.
fn check_sign_ext_form(fd: &Funcdata, op: OpId) -> Result<Option<VarnodeId>> {
    for slot in 0..2 {
        let Some(mult_op) = def_with(fd, inp(fd, op, slot)?, IntMult) else { continue };
        let c = inp(fd, mult_op, 1)?;
        if !is_const(fd, c) || fd.vn(c).offset != calc_mask(fd.vn(c).size) {
            continue;
        }
        let base = inp(fd, op, 1 - slot)?;
        let Some(shift_op) = def_with(fd, inp(fd, mult_op, 0)?, IntSright) else { continue };
        if inp(fd, shift_op, 0)? != base {
            continue;
        }
        let c = inp(fd, shift_op, 1)?;
        if !is_const(fd, c) || fd.vn(c).offset as i32 != 8 * fd.vn(base).size as i32 - 1 {
            continue;
        }
        return Ok(Some(base));
    }
    Ok(None)
}

/// Port of `RuleSignMod2nOpt2::checkMultiequalForm`: `V` when `op` merges `V` and
/// `V + (2^n-1)`, the latter on the path where `V < 0`.
fn check_multiequal_form(fd: &Funcdata, op: OpId, npow: u64) -> Result<Option<VarnodeId>> {
    if ins(fd, op).len() != 2 {
        return Ok(None);
    }
    let npow = npow.wrapping_sub(1);
    let mut found = None;
    for slot in 0..2 {
        let Some(add_op) = def_with(fd, inp(fd, op, slot)?, IntAdd) else { continue };
        let c = inp(fd, add_op, 1)?;
        if !is_const(fd, c) || fd.vn(c).offset != npow {
            continue;
        }
        let base = inp(fd, add_op, 0)?;
        if inp(fd, op, 1 - slot)? == base {
            found = Some((slot, base));
            break;
        }
    }
    let Some((slot, base)) = found else { return Ok(None) };
    let Some(bl) = fd.op(op).parent else { return Ok(None) };
    let g = &fd.blocks;
    let in_of = |b: BlockId, i: usize| g.block(b).ins.get(i).map(|e| e.point);
    let single = |b: BlockId| g.block(b).outs.len() == 1 && g.block(b).ins.len() == 1;
    let mut inner_slot = 0;
    let Some(mut inner) = in_of(bl, 0) else { return Ok(None) };
    if !single(inner) {
        inner_slot = 1;
        let Some(i1) = in_of(bl, 1) else { return Ok(None) };
        inner = i1;
        if !single(inner) {
            return Ok(None);
        }
    }
    let Some(decision) = in_of(inner, 0) else { return Ok(None) };
    if in_of(bl, 1 - inner_slot) != Some(decision) {
        return Ok(None);
    }
    let Some(&cbranch) = g.block(decision).ops.last() else { return Ok(None) };
    if fd.op(cbranch).opc != Cbranch {
        return Ok(None);
    }
    let Some(less_op) = def_with(fd, inp(fd, cbranch, 1)?, IntSless) else { return Ok(None) };
    let c = inp(fd, less_op, 1)?;
    if !is_const(fd, c) || fd.vn(c).offset != 0 {
        return Ok(None);
    }
    // getFalseOut is out edge 0, getTrueOut edge 1
    let neg_edge = if fd.op(cbranch).flags.has(OpFlags::BOOLEAN_FLIP) { 0 } else { 1 };
    let neg_block = g.block(decision).outs.get(neg_edge).map(|e| e.point);
    let neg_slot = if neg_block == Some(inner) { inner_slot } else { 1 - inner_slot };
    Ok((neg_slot == slot).then_some(base))
}

/// Port of `RuleSignMod2nOpt2`: `V + -1*((adjusted V) & -2^n)` becomes `V s% 2^n`.
pub(super) fn sign_mod2n_opt2(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let c = inp(fd, op, 1)?;
    if !is_const(fd, c) {
        return Ok(0);
    }
    let mask = calc_mask(fd.vn(c).size);
    if fd.vn(c).offset != mask {
        return Ok(0);
    }
    let Some(and_op) = def_with(fd, inp(fd, op, 0)?, IntAnd) else { return Ok(0) };
    let c = inp(fd, and_op, 1)?;
    if !is_const(fd, c) {
        return Ok(0);
    }
    let npow = (!fd.vn(c).offset).wrapping_add(1) & mask;
    if npow.count_ones() != 1 || npow == 1 {
        return Ok(0);
    }
    let Some(adj_op) = def(fd, inp(fd, and_op, 0)?) else { return Ok(0) };
    let base = match fd.op(adj_op).opc {
        IntAdd if npow == 2 => check_sign_ext_form(fd, adj_op)?,
        Multiequal => check_multiequal_form(fd, adj_op, npow)?,
        _ => None,
    };
    let Some(base) = base.filter(|&b| !fd.vn(b).is_free()) else { return Ok(0) };
    let mult_out = out(fd, op)?;
    let readers = fd.vn(mult_out).descend.to_vec();
    for root_op in readers {
        if fd.op(root_op).opc != IntAdd {
            continue;
        }
        let Some(slot) = fd.slot_of(root_op, mult_out) else { continue };
        if inp(fd, root_op, 1 - slot)? != base {
            continue;
        }
        if slot == 0 {
            fd.op_set_input(root_op, base, 0)?;
        }
        let c = fd.new_constant(fd.vn(base).size, npow);
        fd.op_set_input(root_op, c, 1)?;
        fd.op_set_opcode(root_op, IntSrem);
        return Ok(1);
    }
    Ok(0)
}
