//! The rules on truncation: `RuleDoubleSub`, `RuleSubExtComm`, `RuleSubCommute`,
//! `RuleSubZext`, `RuleSubCancel`, `RuleShiftSub`, `RuleSubNormal` (ruleaction.cc). The
//! double-precision marks (`isPrecisLo`, `isPrecisHi`) are set by `double.cc` (R5): no varnode
//! has them yet.

use super::*;

/// Port of `RuleDoubleSub`: `sub(sub(V,c),d)` becomes `sub(V,c+d)`.
pub(super) fn double_sub(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let Some(op2) = def_with(fd, inp(fd, op, 0)?, Subpiece) else { return Ok(0) };
    let invn = inp(fd, op2, 0)?;
    if fd.vn(invn).is_free() {
        return Ok(0);
    }
    let offset = int4(fd, inp(fd, op, 1)?) + int4(fd, inp(fd, op2, 1)?);
    fd.op_set_input(op, invn, 0)?;
    let c = fd.new_constant(4, offset as u64);
    fd.op_set_input(op, c, 1)?;
    Ok(1)
}

/// Port of `RuleSubExtComm`: `sub(ext(V),c)` becomes `ext(sub(V,c))`, or reads `V` when the
/// piece lies inside it.
pub(super) fn sub_ext_comm(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let Some(extop) = def(fd, inp(fd, op, 0)?) else { return Ok(0) };
    let extcode = fd.op(extop).opc;
    if !matches!(extcode, IntZext | IntSext) {
        return Ok(0);
    }
    let invn = inp(fd, extop, 0)?;
    if fd.vn(invn).is_free() {
        return Ok(0);
    }
    let cvn = inp(fd, op, 1)?;
    let subcut = int4(fd, cvn);
    let insize = i64::from(fd.vn(invn).size);
    let outsize = i64::from(fd.vn(out(fd, op)?).size);
    if outsize + subcut <= insize {
        fd.op_set_input(op, invn, 0)?;
        if insize == outsize {
            fd.op_remove_input(op, 1);
            fd.op_set_opcode(op, Copy);
        }
        return Ok(1);
    }
    if subcut >= insize {
        return Ok(0);
    }
    let newvn = if subcut != 0 {
        let newop = fd.new_op(Subpiece, fd.op(op).seq.addr);
        let newvn = uniq_out(fd, (insize - subcut) as u32, newop)?;
        let c = fd.new_constant(fd.vn(cvn).size, subcut as u64);
        // the C++ sets slot 1 first; slots here are appended in order
        fd.op_set_input(newop, invn, 0)?;
        fd.op_set_input(newop, c, 1)?;
        fd.op_insert_before(newop, op)?;
        newvn
    } else {
        invn
    };
    fd.op_remove_input(op, 1);
    fd.op_set_opcode(op, extcode);
    fd.op_set_input(op, newvn, 0)?;
    Ok(1)
}

/// Port of `RuleSubCommute::shortenExtension`: the extension writes a shorter output at the
/// same (little-endian) address.
fn shorten_extension(fd: &mut Funcdata, ext_op: OpId, max_size: u32) -> Result<VarnodeId> {
    let orig = fd.vn(out(fd, ext_op)?);
    let (space, offset) = (orig.space, orig.offset);
    fd.op_unset_output(ext_op);
    Ok(fd.new_varnode_out(max_size, space, offset, ext_op))
}

/// Port of `RuleSubCommute::cancelExtensions`: both inputs of `longform` lose their
/// extensions (the longer one is shortened), and the SUBPIECE stays.
fn cancel_extensions(
    fd: &mut Funcdata,
    longform: OpId,
    sub_op: OpId,
    mut ext0: VarnodeId,
    mut ext1: VarnodeId,
) -> Result<bool> {
    if lone_descend(fd, out(fd, longform)?) != Some(sub_op) {
        return Ok(false);
    }
    let blocked = |fd: &Funcdata, v: VarnodeId| fd.vn(v).is_free() && !is_const(fd, v);
    let (s0, s1) = (fd.vn(ext0).size, fd.vn(ext1).size);
    let max_size = s0.max(s1);
    if (s0 >= s1 && blocked(fd, ext0)) || (s0 <= s1 && blocked(fd, ext1)) {
        return Ok(false);
    }
    if s0 != s1 {
        let slot = usize::from(s0 > s1);
        let longin = inp(fd, longform, slot)?;
        if lone_descend(fd, longin) != Some(longform) {
            return Ok(false);
        }
        let ext_op = def(fd, longin).ok_or_else(|| LowlevelError("cancelExtensions: no extension".into()))?;
        let short = shorten_extension(fd, ext_op, max_size)?;
        if slot == 0 {
            ext0 = short;
        } else {
            ext1 = short;
        }
    }
    fd.op_unset_output(longform);
    let outvn = uniq_out(fd, max_size, longform)?;
    fd.op_set_input(longform, ext0, 0)?;
    fd.op_set_input(longform, ext1, 1)?;
    fd.op_set_input(sub_op, outvn, 0)?;
    Ok(true)
}

/// The division and remainder cases of `RuleSubCommute`: they commute only when both inputs
/// are extended by `ext` (INT_ZEXT for the unsigned ops, INT_SEXT for the signed). `Some(n)`
/// is the rule's result; `None` lets the commute go on.
fn div_commute(fd: &mut Funcdata, op: OpId, longform: OpId, offset: i64, ext: Opcode) -> Result<Option<i32>> {
    if offset != 0 {
        return Ok(Some(0));
    }
    let Some(ext0) = def_with(fd, inp(fd, longform, 0)?, ext) else { return Ok(Some(0)) };
    let ext0in = inp(fd, ext0, 0)?;
    let outsize = fd.vn(out(fd, op)?).size;
    let in1 = inp(fd, longform, 1)?;
    if let Some(d1) = def(fd, in1) {
        if fd.op(d1).opc != ext {
            return Ok(Some(0));
        }
        let ext1in = inp(fd, d1, 0)?;
        if fd.vn(ext1in).size > outsize || fd.vn(ext0in).size > outsize {
            // a partial commute: the extensions cancel, some SUBPIECE is left
            return Ok(Some(i32::from(cancel_extensions(fd, longform, op, ext0in, ext1in)?)));
        }
        return Ok(None);
    }
    if is_const(fd, in1) && fd.vn(ext0in).size <= outsize {
        let val = fd.vn(in1).offset;
        let mut smallval = val & calc_mask(outsize);
        if ext == IntSext {
            smallval = sign_extend(smallval, outsize, fd.vn(inp(fd, op, 0)?).size);
        }
        return Ok(if val == smallval { None } else { Some(0) });
    }
    Ok(Some(0))
}

/// Port of `RuleSubCommute`: a SUBPIECE moves before the op it truncates when the op
/// commutes with truncation.
pub(super) fn sub_commute(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let base = inp(fd, op, 0)?;
    let Some(longform) = def(fd, base) else { return Ok(0) };
    let offset = int4(fd, inp(fd, op, 1)?);
    let outvn = out(fd, op)?;
    let insize = fd.vn(base).size;
    let mut skip = None; // the shift amount of INT_LEFT is not truncated
    match fd.op(longform).opc {
        IntLeft => {
            skip = Some(1);
            if offset != 0 {
                return Ok(0);
            }
            let Some(d) = def(fd, inp(fd, longform, 0)?) else { return Ok(0) };
            if !matches!(fd.op(d).opc, IntZext | Piece) {
                return Ok(0);
            }
        }
        IntRem | IntDiv => {
            if let Some(res) = div_commute(fd, op, longform, offset, IntZext)? {
                return Ok(res);
            }
        }
        IntSrem | IntSdiv => {
            if let Some(res) = div_commute(fd, op, longform, offset, IntSext)? {
                return Ok(res);
            }
        }
        IntAdd => {
            // only the least significant piece; a spacebase is RulePtrArith's
            if offset != 0 || fd.vn(inp(fd, longform, 0)?).has(VnFlags::SPACEBASE) {
                return Ok(0);
            }
        }
        IntMult => {
            if offset != 0 {
                return Ok(0);
            }
        }
        IntNegate | IntXor | IntAnd | IntOr => {}
        _ => return Ok(0),
    }
    if lone_descend(fd, base) != Some(op) {
        return Ok(0);
    }
    if offset == 0 {
        // overlap with RuleSubZext
        let next = lone_descend(fd, outvn).filter(|&n| fd.op(n).opc == IntZext);
        if let Some(n) = next {
            if fd.vn(out(fd, n)?).size == insize {
                return Ok(0);
            }
        }
    }
    commute_subpiece(fd, op, longform, skip, offset)
}

/// The tail of `RuleSubCommute`: each input of `longform` (but the shift amount `skip`) is
/// truncated by a new SUBPIECE, and `longform` writes the old SUBPIECE's output.
fn commute_subpiece(fd: &mut Funcdata, op: OpId, longform: OpId, skip: Option<usize>, offset: i64) -> Result<i32> {
    let outvn = out(fd, op)?;
    let outsize = fd.vn(outvn).size;
    let mut last_in = None;
    let mut new_vn: Option<VarnodeId> = None;
    for i in 0..ins(fd, longform).len() {
        let vn = inp(fd, longform, i)?;
        if Some(i) != skip {
            match new_vn {
                // the same input twice shares one SUBPIECE
                Some(v) if last_in == Some(vn) => fd.op_set_input(longform, v, i)?,
                _ => {
                    let newsub = fd.new_op(Subpiece, fd.op(op).seq.addr);
                    let v = uniq_out(fd, outsize, newsub)?;
                    fd.op_set_input(longform, v, i)?;
                    fd.op_set_input(newsub, vn, 0)?;
                    let c = fd.new_constant(4, offset as u64);
                    fd.op_set_input(newsub, c, 1)?;
                    fd.op_insert_before(newsub, longform)?;
                    new_vn = Some(v);
                }
            }
        }
        last_in = Some(vn);
    }
    fd.op_set_output(longform, outvn)?;
    fd.op_destroy(op);
    Ok(1)
}

/// Port of `RuleSubZext`: `zext(sub(V,c))` becomes `(V >> c*8) & mask`.
pub(super) fn sub_zext(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let subvn = inp(fd, op, 0)?;
    let Some(subop) = def(fd, subvn) else { return Ok(0) };
    match fd.op(subop).opc {
        Subpiece => sub_zext_truncation(fd, op, subvn, subop),
        IntRight => sub_zext_shifted(fd, op, subvn, subop),
        _ => Ok(0),
    }
}

/// `RuleSubZext` on `zext(sub(V,c))`: `c` not 0 makes the truncation a shift.
fn sub_zext_truncation(fd: &mut Funcdata, op: OpId, subvn: VarnodeId, subop: OpId) -> Result<i32> {
    let outsize = fd.vn(out(fd, op)?).size;
    let uniq = fd.uniq.map_or_else(|| err("no unique space"), Ok)?;
    let basevn = inp(fd, subop, 0)?;
    let basesize = fd.vn(basevn).size;
    if fd.vn(basevn).is_free() || basesize != outsize || basesize > 8 {
        return Ok(0);
    }
    let constvn = inp(fd, subop, 1)?;
    if fd.vn(constvn).offset != 0 {
        // truncating from the middle: the truncation becomes a shift
        if lone_descend(fd, subvn) != Some(op) {
            return Ok(0);
        }
        let newvn = fd.new_unique(basesize, uniq);
        let right = fd.vn(constvn).offset.wrapping_mul(8);
        fd.op_set_input(op, newvn, 0)?;
        fd.op_set_opcode(subop, IntRight);
        let c = fd.new_constant(fd.vn(constvn).size, right);
        fd.op_set_input(subop, c, 1)?;
        fd.op_set_output(subop, newvn)?;
    } else {
        fd.op_set_input(op, basevn, 0)?;
    }
    let mask = fd.new_constant(basesize, calc_mask(fd.vn(subvn).size));
    fd.op_set_opcode(op, IntAnd);
    fd.op_insert_input(op, mask, 1)?;
    Ok(1)
}

/// `RuleSubZext` on `zext(sub(V,c) >> n)`: one shift of `V` by the combined amount.
fn sub_zext_shifted(fd: &mut Funcdata, op: OpId, subvn: VarnodeId, shiftop: OpId) -> Result<i32> {
    let outsize = fd.vn(out(fd, op)?).size;
    let uniq = fd.uniq.map_or_else(|| err("no unique space"), Ok)?;
    let savn = inp(fd, shiftop, 1)?;
    if !is_const(fd, savn) {
        return Ok(0);
    }
    let midvn = inp(fd, shiftop, 0)?;
    let Some(subop) = def_with(fd, midvn, Subpiece) else { return Ok(0) };
    let basevn = inp(fd, subop, 0)?;
    let basesize = fd.vn(basevn).size;
    if fd.vn(basevn).is_free() || basesize != outsize {
        return Ok(0);
    }
    if lone_descend(fd, midvn) != Some(shiftop) || lone_descend(fd, subvn) != Some(op) {
        return Ok(0);
    }
    let sa = fd.vn(savn).offset;
    let val = calc_mask(fd.vn(midvn).size).wrapping_shr(sa as u32);
    let total = sa.wrapping_add(fd.vn(inp(fd, subop, 1)?).offset.wrapping_mul(8));
    let newvn = fd.new_unique(basesize, uniq);
    fd.op_set_input(op, newvn, 0)?;
    fd.op_set_input(shiftop, basevn, 0)?;
    let c = fd.new_constant(fd.vn(savn).size, total);
    fd.op_set_input(shiftop, c, 1)?;
    fd.op_set_output(shiftop, newvn)?;
    let mask = fd.new_constant(basesize, val);
    fd.op_set_opcode(op, IntAnd);
    fd.op_insert_input(op, mask, 1)?;
    Ok(1)
}

/// Port of `RuleSubCancel`: `sub(ext(V),0)` becomes `V`, a shorter extension or a shorter
/// SUBPIECE; `sub(V & mask,0)` reads `V`.
pub(super) fn sub_cancel(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let base = inp(fd, op, 0)?;
    let Some(extop) = def(fd, base) else { return Ok(0) };
    let mut opc = fd.op(extop).opc;
    if !matches!(opc, IntZext | IntSext | IntAnd) {
        return Ok(0);
    }
    let offset = int4(fd, inp(fd, op, 1)?);
    let outsize = fd.vn(out(fd, op)?).size;
    let mut thruvn = inp(fd, extop, 0)?;
    if opc == IntAnd {
        let cvn = inp(fd, extop, 1)?;
        if offset == 0 && is_const(fd, cvn) && fd.vn(cvn).offset == calc_mask(outsize) && !fd.vn(thruvn).is_free() {
            fd.op_set_input(op, thruvn, 0)?;
            return Ok(1);
        }
        return Ok(0);
    }
    let insize = fd.vn(base).size;
    let farinsize = fd.vn(thruvn).size;
    if offset == 0 {
        if fd.vn(thruvn).is_free() {
            // a constant too big to represent, eliminated as a whole
            if !(is_const(fd, thruvn) && insize > 8 && outsize == farinsize) {
                return Ok(0);
            }
            opc = Copy;
            thruvn = fd.new_constant(farinsize, fd.vn(thruvn).offset);
        } else if outsize == farinsize {
            opc = Copy;
        } else if outsize < farinsize {
            opc = Subpiece;
        }
    } else if opc == IntZext && i64::from(farinsize) <= offset {
        opc = Copy; // nothing but zero comes through
        thruvn = fd.new_constant(outsize, 0);
    } else {
        return Ok(0);
    }
    fd.op_set_opcode(op, opc);
    fd.op_set_input(op, thruvn, 0)?;
    if opc != Subpiece {
        fd.op_remove_input(op, 1);
    }
    Ok(1)
}

/// Port of `RuleShiftSub`: `sub(V << 8*k, c)` becomes `sub(V, c-k)`.
pub(super) fn shift_sub(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let Some(shiftop) = def_with(fd, inp(fd, op, 0)?, IntLeft) else { return Ok(0) };
    let sa = inp(fd, shiftop, 1)?;
    if !is_const(fd, sa) {
        return Ok(0);
    }
    let n = int4(fd, sa);
    if n & 7 != 0 {
        return Ok(0);
    }
    let cvn = inp(fd, op, 1)?;
    let vn = inp(fd, shiftop, 0)?;
    if fd.vn(vn).is_free() {
        return Ok(0);
    }
    let c = int4(fd, cvn) - n / 8;
    if c < 0 || c + i64::from(fd.vn(out(fd, op)?).size) > i64::from(fd.vn(vn).size) {
        return Ok(0);
    }
    fd.op_set_input(op, vn, 0)?;
    let newc = fd.new_constant(fd.vn(cvn).size, c as u64);
    fd.op_set_input(op, newc, 1)?;
    Ok(1)
}

/// A new `sub(a, #c)` of `size` bytes before `op` (the shared tail of `RuleSubNormal`).
fn subpiece_before(fd: &mut Funcdata, op: OpId, a: VarnodeId, c: i64, size: u32) -> Result<VarnodeId> {
    let newop = fd.new_op(Subpiece, fd.op(op).seq.addr);
    let newout = uniq_out(fd, size, newop)?;
    fd.op_set_input(newop, a, 0)?;
    let cvn = fd.new_constant(4, c as u64);
    fd.op_set_input(newop, cvn, 1)?;
    fd.op_insert_before(newop, op)?;
    Ok(newout)
}

/// Port of `RuleSubNormal`: `sub(V >> n, c)` becomes `sub(V, c+k) >> (n-8k)`, an extension
/// when the piece reaches past `V`.
pub(super) fn sub_normal(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let Some(shiftop) = def(fd, inp(fd, op, 0)?) else { return Ok(0) };
    let opc = fd.op(shiftop).opc;
    if !matches!(opc, IntRight | IntSright) {
        return Ok(0);
    }
    let savn = inp(fd, shiftop, 1)?;
    let a = inp(fd, shiftop, 0)?;
    if !is_const(fd, savn) || fd.vn(a).is_free() {
        return Ok(0);
    }
    let mut n = int4(fd, savn);
    let mut c = int4(fd, inp(fd, op, 1)?);
    let mut k = n / 8;
    let insize = i64::from(fd.vn(a).size);
    let outsize = i64::from(fd.vn(out(fd, op)?).size);
    if n + 8 * c + 8 * outsize < 8 * insize && n != k * 8 {
        return Ok(0);
    }
    if k + c + outsize > insize {
        let trunc = insize - c - k;
        if n == k * 8 && trunc > 0 && trunc.count_ones() == 1 {
            let ext = if opc == IntSright { IntSext } else { IntZext };
            let newout = subpiece_before(fd, op, a, c + k, trunc as u32)?;
            fd.op_set_input(op, newout, 0)?;
            fd.op_remove_input(op, 1);
            fd.op_set_opcode(op, ext);
            return Ok(1);
        }
        k = insize - c - outsize; // or the cut shrinks
    }
    c += k;
    n -= k * 8;
    if n == 0 {
        fd.op_set_input(op, a, 0)?;
        let cvn = fd.new_constant(4, c as u64);
        fd.op_set_input(op, cvn, 1)?;
        return Ok(1);
    }
    if n >= outsize * 8 {
        n = outsize * 8 - i64::from(opc == IntSright);
    }
    let newout = subpiece_before(fd, op, a, c, outsize as u32)?;
    fd.op_set_input(op, newout, 0)?;
    let nvn = fd.new_constant(4, n as u64);
    fd.op_set_input(op, nvn, 1)?;
    fd.op_set_opcode(op, opc);
    Ok(1)
}
