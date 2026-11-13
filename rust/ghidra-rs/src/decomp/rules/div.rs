//! The rules recovering division by a constant: `RulePositiveDiv`, `RuleDivTermAdd`,
//! `RuleDivTermAdd2`, `RuleDivOpt`, `RuleSignDiv2`, `RuleDivChain` (ruleaction.cc), with
//! `Varnode::isConstantExtended` and `Funcdata::newExtendedConstant`. The C++ 128-bit
//! arithmetic (`uint8[2]`, multiprecision.cc) is `u128`: additions and shifts wrap as the C++
//! does, a division by zero fails as `udiv128` throws.

use super::*;

/// `signbit_negative`.
pub(super) fn signbit_negative(val: u64, size: u32) -> bool {
    // address.cc: `0x80 << 8*(size-1)`, the shift count taken mod 64 as x86 does
    val & 0x80u64.wrapping_shl(size.wrapping_sub(1).wrapping_mul(8)) != 0
}

/// Port of `Varnode::isConstantExtended`: a constant, or a 9 to 16-byte ZEXT, SEXT or PIECE of
/// constants, as a 128-bit value.
pub(super) fn constant_extended(fd: &Funcdata, vn: VarnodeId) -> Option<u128> {
    let v = fd.vn(vn);
    if v.is_constant() {
        return Some(u128::from(v.offset));
    }
    let d = def(fd, vn)?;
    if v.size <= 8 || v.size > 16 {
        return None;
    }
    let o = fd.op(d);
    match o.opc {
        IntZext => {
            let c = fd.vn(*o.ins.first()?);
            c.is_constant().then_some(u128::from(c.offset))
        }
        IntSext => {
            let c = fd.vn(*o.ins.first()?);
            if !c.is_constant() {
                return None;
            }
            let lo = if c.size < 8 { sign_extend(c.offset, c.size, v.size) } else { c.offset };
            let hi = if signbit_negative(lo, 8) { u64::MAX } else { 0 };
            Some(u128::from(hi) << 64 | u128::from(lo))
        }
        Piece => {
            let (hi, lo) = (fd.vn(*o.ins.first()?), fd.vn(*o.ins.get(1)?));
            if !lo.is_constant() || !hi.is_constant() {
                return None;
            }
            let (mut l, mut h) = (lo.offset, hi.offset);
            if lo.size != 8 {
                l |= h.wrapping_shl(lo.size.wrapping_mul(8));
                // the C++ shifts are undefined past 63; x86 takes them mod 64
                h = h.wrapping_shr(8u32.wrapping_sub(lo.size).wrapping_mul(8));
            }
            Some(u128::from(h) << 64 | u128::from(l))
        }
        _ => None,
    }
}

/// Port of `Funcdata::newExtendedConstant`: a constant of `size` bytes, built by a ZEXT or a
/// PIECE inserted before `op` when it is wider than 8 bytes.
pub(super) fn new_extended_constant(fd: &mut Funcdata, size: u32, val: u128, op: OpId) -> Result<VarnodeId> {
    if size <= 8 {
        return Ok(fd.new_constant(size, val as u64));
    }
    let addr = fd.op(op).seq.addr;
    let hi = (val >> 64) as u64;
    let res = if hi == 0 {
        let ext = fd.new_op(IntZext, addr);
        let res = uniq_out(fd, size, ext)?;
        let c = fd.new_constant(8, val as u64);
        fd.op_set_input(ext, c, 0)?;
        fd.op_insert_before(ext, op)?;
        res
    } else {
        let piece = fd.new_op(Piece, addr);
        let res = uniq_out(fd, size, piece)?;
        let c = fd.new_constant(8, hi);
        fd.op_set_input(piece, c, 0)?;
        let c = fd.new_constant(8, val as u64);
        fd.op_set_input(piece, c, 1)?;
        fd.op_insert_before(piece, op)?;
        res
    };
    Ok(res)
}

/// Builds `SUB(shift(mult(ext, c), n), 0)` from `addop`: the new multiply and shift go before
/// `op` (`RuleDivTermAdd` and `RuleDivTermAdd2` end the same way).
fn rebuild_term(
    fd: &mut Funcdata,
    op: OpId,
    addop: OpId,
    extvn: VarnodeId,
    mult: u128,
    shift: (Opcode, u32),
    const_first: bool,
) -> Result<()> {
    let size = fd.vn(extvn).size;
    let addr = fd.op(op).seq.addr;
    // RuleDivTermAdd makes the constant before the multiply, RuleDivTermAdd2 after its output
    let early = if const_first { Some(new_extended_constant(fd, size, mult, op)?) } else { None };
    let newmultop = fd.new_op(IntMult, addr);
    let newmultvn = uniq_out(fd, size, newmultop)?;
    fd.op_set_input(newmultop, extvn, 0)?;
    let cvn = match early {
        Some(c) => c,
        None => new_extended_constant(fd, size, mult, op)?,
    };
    fd.op_set_input(newmultop, cvn, 1)?;
    fd.op_insert_before(newmultop, op)?;
    let newshiftop = fd.new_op(shift.0, addr);
    let newshiftvn = uniq_out(fd, size, newshiftop)?;
    fd.op_set_input(newshiftop, newmultvn, 0)?;
    let c = fd.new_constant(4, u64::from(shift.1));
    fd.op_set_input(newshiftop, c, 1)?;
    fd.op_insert_before(newshiftop, op)?;
    fd.op_set_opcode(addop, Subpiece);
    fd.op_set_input(addop, newshiftvn, 0)?;
    let c = fd.new_constant(4, 0);
    fd.op_set_input(addop, c, 1)
}

/// The first INT_ADD reading `vn` that also reads `x`.
fn add_reading(fd: &Funcdata, vn: VarnodeId, x: VarnodeId) -> Option<OpId> {
    fd.vn(vn).descend.iter().copied().find(|&a| {
        let ins = ins(fd, a);
        fd.op(a).opc == IntAdd && (ins.first() == Some(&x) || ins.get(1) == Some(&x))
    })
}

/// Port of `RulePositiveDiv`: a signed division or remainder of values known non-negative is
/// unsigned.
pub(super) fn positive_div(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let sa = fd.vn(out(fd, op)?).size;
    if sa > 8 {
        return Ok(0);
    }
    let sa = sa * 8 - 1;
    for slot in 0..2 {
        if (fd.nzmask(inp(fd, op, slot)?) >> sa) & 1 != 0 {
            return Ok(0);
        }
    }
    let opc = if fd.op(op).opc == IntSdiv { IntDiv } else { IntRem };
    fd.op_set_opcode(op, opc);
    Ok(1)
}

/// Port of `RuleDivTermAdd::findSubshift`: `SUB(V,c)` or `SUB(V,c) >> n` taking the high part;
/// the SUBPIECE, the total shift and the shift opcode (`None` for no shift, the C++ CPUI_MAX).
fn find_subshift(fd: &Funcdata, op: OpId) -> Result<Option<(OpId, u32, Option<Opcode>)>> {
    let opc = fd.op(op).opc;
    let (subop, mut n, shiftopc) = if opc != Subpiece {
        let Some(subop) = def_with(fd, inp(fd, op, 0)?, Subpiece) else { return Ok(None) };
        let c = inp(fd, op, 1)?;
        if !is_const(fd, c) {
            return Ok(None);
        }
        (subop, fd.vn(c).offset as u32, Some(opc))
    } else {
        (op, 0, None)
    };
    let c = fd.vn(inp(fd, subop, 1)?).offset as u32;
    if fd.vn(out(fd, subop)?).size.wrapping_add(c) != fd.vn(inp(fd, subop, 0)?).size {
        return Ok(None);
    }
    n = n.wrapping_add(c.wrapping_mul(8));
    Ok(Some((subop, n, shiftopc)))
}

/// Port of `RuleDivTermAdd`: `sub(ext(x)*c,n) + x` becomes `sub(ext(x)*(c+2^n),n)`.
pub(super) fn div_term_add(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let Some((subop, n, shiftopc)) = find_subshift(fd, op)? else { return Ok(0) };
    if n > 127 {
        return Ok(0);
    }
    let Some(multop) = def_with(fd, inp(fd, subop, 0)?, IntMult) else { return Ok(0) };
    let Some(mult) = constant_extended(fd, inp(fd, multop, 1)?) else { return Ok(0) };
    let extvn = inp(fd, multop, 0)?;
    let Some(extop) = def(fd, extvn) else { return Ok(0) };
    match (fd.op(extop).opc, fd.op(op).opc) {
        (IntZext, IntSright) | (IntSext, IntRight) => return Ok(0),
        _ => {}
    }
    let mult = mult.wrapping_add(1u128 << n);
    let x = inp(fd, extop, 0)?;
    let Some(addop) = add_reading(fd, out(fd, op)?, x) else { return Ok(0) };
    rebuild_term(fd, op, addop, extvn, mult, (shiftopc.unwrap_or(IntRight), n), true)?;
    Ok(1)
}

/// Port of `RuleDivTermAdd2`: `(x + z*-1) >> 1 + z` with `z = sub(zext(x)*c,n)` becomes
/// `sub(zext(x)*(c+2^n) >> n+1, 0)`.
pub(super) fn div_term_add2(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let c = inp(fd, op, 1)?;
    if !is_const(fd, c) || fd.vn(c).offset != 1 {
        return Ok(0);
    }
    let Some(subop) = def_with(fd, inp(fd, op, 0)?, IntAdd) else { return Ok(0) };
    let mut found = None;
    for i in 0..2 {
        let compvn = inp(fd, subop, i)?;
        if let Some(compop) = def_with(fd, compvn, IntMult) {
            let invn = inp(fd, compop, 1)?;
            if is_const(fd, invn) && fd.vn(invn).offset == calc_mask(fd.vn(invn).size) {
                found = Some((compop, inp(fd, subop, 1 - i)?));
                break;
            }
        }
    }
    let Some((compop, x)) = found else { return Ok(0) };
    let z = inp(fd, compop, 0)?;
    let Some(subpieceop) = def_with(fd, z, Subpiece) else { return Ok(0) };
    let n = (fd.vn(inp(fd, subpieceop, 1)?).offset.wrapping_mul(8)) as u32;
    let multvn = inp(fd, subpieceop, 0)?;
    let span = 8 * (i64::from(fd.vn(multvn).size) - i64::from(fd.vn(z).size));
    if n > 127 || i64::from(n) != span {
        return Ok(0);
    }
    let Some(multop) = def_with(fd, multvn, IntMult) else { return Ok(0) };
    let Some(mult) = constant_extended(fd, inp(fd, multop, 1)?) else { return Ok(0) };
    let zextvn = inp(fd, multop, 0)?;
    let Some(zextop) = def_with(fd, zextvn, IntZext) else { return Ok(0) };
    if inp(fd, zextop, 0)? != x {
        return Ok(0);
    }
    let Some(addop) = add_reading(fd, out(fd, op)?, z) else { return Ok(0) };
    let mult = mult.wrapping_add(1u128 << n);
    rebuild_term(fd, op, addop, zextvn, mult, (IntRight, n + 1), false)?;
    Ok(1)
}

/// What `RuleDivOpt::findForm` recognizes.
struct DivForm {
    res: VarnodeId,
    n: u32,
    y: u128,
    xsize: u32,
    extopc: Opcode,
}

/// Port of `RuleDivOpt::findForm`: `sub(ext(x)*y, c) >> n` and its variants.
fn find_form(fd: &Funcdata, op: OpId) -> Result<Option<DivForm>> {
    let shiftopc = fd.op(op).opc;
    let (mut cur, mut n, shift) = if matches!(shiftopc, IntRight | IntSright) {
        let vn = inp(fd, op, 0)?;
        let Some(d) = def(fd, vn) else { return Ok(None) };
        let cvn = inp(fd, op, 1)?;
        if !is_const(fd, cvn) {
            return Ok(None);
        }
        (d, fd.vn(cvn).offset as u32, Some(shiftopc))
    } else if shiftopc == Subpiece {
        (op, 0u32, None)
    } else {
        return Ok(None);
    };
    if fd.op(cur).opc == Subpiece {
        let c = int4(fd, inp(fd, cur, 1)?);
        let in_vn = inp(fd, cur, 0)?;
        let Some(d) = def(fd, in_vn) else { return Ok(None) };
        if i64::from(fd.vn(out(fd, cur)?).size) + c != i64::from(fd.vn(in_vn).size) {
            return Ok(None);
        }
        n = n.wrapping_add((8 * c) as u32);
        cur = d;
    }
    if fd.op(cur).opc != IntMult {
        return Ok(None);
    }
    let mut in_vn = inp(fd, cur, 0)?;
    if def(fd, in_vn).is_none() {
        return Ok(None);
    }
    let y = if let Some(y) = constant_extended(fd, in_vn) {
        in_vn = inp(fd, cur, 1)?;
        if def(fd, in_vn).is_none() {
            return Ok(None);
        }
        y
    } else if let Some(y) = constant_extended(fd, inp(fd, cur, 1)?) {
        y
    } else {
        return Ok(None);
    };
    let Some(ext_op) = def(fd, in_vn) else { return Ok(None) };
    let mut extopc = fd.op(ext_op).opc;
    let in_size = fd.vn(in_vn).size;
    let xsize = if extopc != IntSext {
        let nz = if extopc == IntZext { fd.nzmask(inp(fd, ext_op, 0)?) } else { fd.nzmask(in_vn) };
        let xsize = 64 - nz.leading_zeros();
        if xsize == 0 || xsize > 4 * in_size {
            return Ok(None);
        }
        xsize
    } else {
        fd.vn(inp(fd, ext_op, 0)?).size * 8
    };
    let outsize = fd.vn(out(fd, op)?).size;
    let res = if matches!(extopc, IntZext | IntSext) {
        let ext_vn = inp(fd, ext_op, 0)?;
        if fd.vn(ext_vn).is_free() {
            return Ok(None);
        }
        if in_size == outsize {
            in_vn
        } else {
            ext_vn
        }
    } else {
        extopc = IntZext; // treated as an unsigned extension
        in_vn
    };
    let mismatch = (extopc == IntZext && shift == Some(IntSright)) || (extopc == IntSext && shift == Some(IntRight));
    if mismatch && (8 * outsize).wrapping_sub(n) != xsize {
        return Ok(None);
    }
    Ok(Some(DivForm { res, n, y, xsize, extopc }))
}

/// Port of `RuleDivOpt::calcDivisor`: the divisor `x * y >> n` computes for every `x` of
/// `xsize` bits, 0 when there is none.
pub(super) fn calc_divisor(n: u32, y: u128, xsize: u32) -> Result<u64> {
    if n > 127 || xsize > 64 || y <= 1 {
        return Ok(0);
    }
    let y = y - 1;
    let power = 1u128 << n;
    let mut q = power / y;
    let mut r = power % y;
    if q >> 64 != 0 || y < q {
        return Ok(0);
    }
    let mut diff = 0u64;
    if r >= q {
        // y may be 1 too big, giving a q 1 too small
        q = u128::from((q as u64).wrapping_add(1));
        r = r.wrapping_sub(y).wrapping_add(q);
        if r >= q {
            return Ok(0);
        }
        diff = q as u64;
    }
    let maxx = if xsize == 64 { 0u64 } else { 1u64 << xsize }.wrapping_sub(1);
    diff = diff.wrapping_add((q as u64).wrapping_sub(r as u64));
    if diff == 0 {
        return err("divide by 0");
    }
    let tmp = power / u128::from(diff);
    if tmp >> 64 != 0 || tmp as u64 > maxx {
        return Ok(q as u64);
    }
    Ok(0)
}

/// Port of `RuleDivOpt::moveSignBitExtraction`: shifts extracting the sign bit of `first` (or
/// of what it was shifted from, or copies of it) read `replace` instead.
fn move_sign_bit_extraction(fd: &mut Funcdata, first: VarnodeId, replace: VarnodeId) -> Result<()> {
    let mut test = vec![first];
    if let Some(d) = def_with(fd, first, IntSright) {
        test.push(inp(fd, d, 0)?);
    }
    let sa = i64::from(fd.vn(first).size) * 8 - 1;
    let mut i = 0;
    while let Some(&vn) = test.get(i) {
        i += 1;
        // a snapshot visits the ops the C++ live walk does: it advances before changing an op,
        // and the change only drops that op from this list (it reads `replace`, a different
        // varnode, instead)
        let readers = fd.vn(vn).descend.to_vec();
        for op in readers {
            match fd.op(op).opc {
                IntRight | IntSright => {
                    let mut cvn = inp(fd, op, 1)?;
                    if let Some(cop) = def(fd, cvn) {
                        match fd.op(cop).opc {
                            Copy => cvn = inp(fd, cop, 0)?,
                            IntAnd => {
                                cvn = inp(fd, cop, 0)?;
                                let other = inp(fd, cop, 1)?;
                                if !is_const(fd, other) {
                                    continue;
                                }
                                let v = fd.vn(cvn).offset;
                                if v != v & fd.vn(other).offset {
                                    continue;
                                }
                            }
                            _ => {}
                        }
                    }
                    if is_const(fd, cvn) && sa == int4(fd, cvn) {
                        fd.op_set_input(op, replace, 0)?;
                    }
                }
                Copy => test.push(out(fd, op)?),
                _ => {}
            }
        }
    }
    Ok(())
}

/// Port of `RuleDivOpt::checkFormOverlap`: a shift reading this SUBPIECE may itself be the form.
fn check_form_overlap(fd: &Funcdata, op: OpId) -> Result<bool> {
    if fd.op(op).opc != Subpiece {
        return Ok(false);
    }
    for &sup in fd.vn(out(fd, op)?).descend.iter() {
        if !matches!(fd.op(sup).opc, IntRight | IntSright) {
            continue;
        }
        if !is_const(fd, inp(fd, sup, 1)?) || find_form(fd, sup)?.is_some() {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Port of `RuleDivOpt`: a multiply by a reciprocal becomes INT_DIV, or INT_SDIV plus the sign
/// correction.
pub(super) fn div_opt(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let Some(form) = find_form(fd, op)? else { return Ok(0) };
    if check_form_overlap(fd, op)? {
        return Ok(0);
    }
    let xsize = if form.extopc == IntSext { form.xsize.wrapping_sub(1) } else { form.xsize };
    let divisor = calc_divisor(form.n, form.y, xsize)?;
    if divisor == 0 {
        return Ok(0);
    }
    let addr = fd.op(op).seq.addr;
    let mut op = op;
    let mut in_vn = form.res;
    let mut out_size = fd.vn(out(fd, op)?).size;
    let in_size = fd.vn(in_vn).size;
    if in_size < out_size {
        let in_ext = fd.new_op(form.extopc, addr);
        let ext_out = uniq_out(fd, out_size, in_ext)?;
        fd.op_set_input(in_ext, in_vn, 0)?;
        in_vn = ext_out;
        fd.op_insert_before(in_ext, op)?;
    } else if in_size > out_size {
        // the new op holds the division; the original becomes a truncation
        let newop = fd.new_op(IntAdd, addr);
        let res_vn = uniq_out(fd, in_size, newop)?;
        fd.op_insert_before(newop, op)?;
        fd.op_set_opcode(op, Subpiece);
        fd.op_set_input(op, res_vn, 0)?;
        let c = fd.new_constant(4, 0);
        fd.op_set_input(op, c, 1)?;
        op = newop;
        out_size = in_size;
    }
    if form.extopc == IntZext {
        fd.op_set_input(op, in_vn, 0)?;
        let c = fd.new_constant(out_size, divisor);
        fd.op_set_input(op, c, 1)?;
        fd.op_set_opcode(op, IntDiv);
        return Ok(1);
    }
    move_sign_bit_extraction(fd, out(fd, op)?, in_vn)?;
    let divop = fd.new_op(IntSdiv, addr);
    let newout = uniq_out(fd, out_size, divop)?;
    fd.op_set_input(divop, in_vn, 0)?;
    let c = fd.new_constant(out_size, divisor);
    fd.op_set_input(divop, c, 1)?;
    fd.op_insert_before(divop, op)?;
    let sgnop = fd.new_op(IntSright, addr);
    let sgnvn = uniq_out(fd, out_size, sgnop)?;
    fd.op_set_input(sgnop, in_vn, 0)?;
    let c = fd.new_constant(out_size, u64::from(out_size * 8 - 1));
    fd.op_set_input(sgnop, c, 1)?;
    fd.op_insert_before(sgnop, op)?;
    fd.op_set_input(op, newout, 0)?;
    fd.op_set_input(op, sgnvn, 1)?;
    fd.op_set_opcode(op, IntAdd);
    Ok(1)
}

/// Port of `RuleSignDiv2`: `(V + -1*(V s>> 31)) s>> 1` becomes `V s/ 2`.
pub(super) fn sign_div2(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let c = inp(fd, op, 1)?;
    if !is_const(fd, c) || fd.vn(c).offset != 1 {
        return Ok(0);
    }
    let Some(addop) = def_with(fd, inp(fd, op, 0)?, IntAdd) else { return Ok(0) };
    let mut found = None;
    for i in 0..2 {
        let Some(multop) = def_with(fd, inp(fd, addop, i)?, IntMult) else { continue };
        let mc = inp(fd, multop, 1)?;
        if !is_const(fd, mc) || fd.vn(mc).offset != calc_mask(fd.vn(mc).size) {
            continue;
        }
        let Some(shiftop) = def_with(fd, inp(fd, multop, 0)?, IntSright) else { continue };
        let sc = inp(fd, shiftop, 1)?;
        if !is_const(fd, sc) {
            continue;
        }
        let a = inp(fd, shiftop, 0)?;
        if a != inp(fd, addop, 1 - i)? || int4(fd, sc) != 8 * i64::from(fd.vn(a).size) - 1 || fd.vn(a).is_free() {
            continue;
        }
        found = Some(a);
        break;
    }
    let Some(a) = found else { return Ok(0) };
    fd.op_set_input(op, a, 0)?;
    let c = fd.new_constant(fd.vn(a).size, 2);
    fd.op_set_input(op, c, 1)?;
    fd.op_set_opcode(op, IntSdiv);
    Ok(1)
}

/// Port of `RuleDivChain`: `(V / c1) / c2` becomes `V / (c1*c2)` when the product cannot
/// overflow.
pub(super) fn div_chain(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let opc2 = fd.op(op).opc;
    let const_vn2 = inp(fd, op, 1)?;
    if !is_const(fd, const_vn2) {
        return Ok(0);
    }
    let vn = inp(fd, op, 0)?;
    let Some(div_op) = def(fd, vn) else { return Ok(0) };
    let opc1 = fd.op(div_op).opc;
    if opc1 != opc2 && (opc2 != IntDiv || opc1 != IntRight) {
        return Ok(0);
    }
    let const_vn1 = inp(fd, div_op, 1)?;
    if !is_const(fd, const_vn1) || lone_descend(fd, vn).is_none() {
        return Ok(0);
    }
    let off1 = fd.vn(const_vn1).offset;
    // the C++ `val1 <<= sa` on x86 shifts by sa mod 64
    let mut val1 = if opc1 == opc2 { off1 } else { shl(1, off1 as i32) };
    let base_vn = inp(fd, div_op, 0)?;
    if fd.vn(base_vn).is_free() {
        return Ok(0);
    }
    let sz = fd.vn(vn).size;
    let mask = calc_mask(sz);
    let mut val2 = fd.vn(const_vn2).offset;
    let resval = val1.wrapping_mul(val2) & mask;
    if resval == 0 {
        return Ok(0);
    }
    if signbit_negative(val1, sz) {
        val1 = (!val1).wrapping_add(1) & mask;
    }
    if signbit_negative(val2, sz) {
        val2 = (!val2).wrapping_add(1) & mask;
    }
    let bitcount = mostsigbit_set(val1) + mostsigbit_set(val2) + 2;
    let bits = 8 * sz as i32;
    if (opc2 == IntDiv && bitcount > bits) || (opc2 == IntSdiv && bitcount > bits - 2) {
        return Ok(0);
    }
    fd.op_set_input(op, base_vn, 0)?;
    let c = fd.new_constant(sz, resval);
    fd.op_set_input(op, c, 1)?;
    Ok(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calc_divisor_table() {
        // (n, y, xsize, divisor): the multiplier and shift compilers emit for x / d
        let cases: &[(u32, u128, u32, u64)] = &[
            (34, 0xcccc_cccd, 32, 5),   // unsigned x / 5: (x * 0xcccccccd) >> 34
            (32, 0x5555_5556, 31, 3),   // signed x / 3: high word, no shift
            (33, 0xaaaa_aaab, 32, 3),   // unsigned x / 3: shr 1 of the high word
            (33, 0x6666_6667, 31, 5),   // signed x / 5: sar 1 of the high word
            (32, 0x1_0000_0000, 32, 0), // y - 1 == 2^32: q == 1 < y but not a division
            (127, u128::MAX, 64, 0),    // huge multiplier: no divisor
            (40, 1, 32, 0),             // y <= 1
            (200, 0x1234, 8, 0),        // n out of range
        ];
        for &(n, y, xsize, want) in cases {
            assert_eq!(calc_divisor(n, y, xsize).unwrap(), want, "n={n} y={y:#x}");
        }
    }

    #[test]
    fn signbit() {
        // sizes 1-8: the top bit; 9-16: `0x80 << 8*(size-1)` with the count mod 64 (bit 7 .. 63)
        for size in 1..=16u32 {
            let bit = (8 * (size - 1) + 7) % 64;
            assert!(signbit_negative(1 << bit, size), "size {size}");
            assert!(!signbit_negative(!(1u64 << bit), size), "size {size}");
        }
    }

    /// A 16-byte varnode written by `opc` of the given constants.
    fn wide(fd: &mut Funcdata, opc: Opcode, consts: &[(u32, u64)]) -> VarnodeId {
        let op = fd.new_op(opc, 0x1000);
        let out = fd.new_varnode_out(16, Space::Sleigh(3), 0x100, op);
        for (slot, &(size, val)) in consts.iter().enumerate() {
            let c = fd.new_constant(size, val);
            fd.op_set_input(op, c, slot).unwrap();
        }
        out
    }

    #[test]
    fn constant_extended_wide() {
        let mut fd = Funcdata::new(0x1000);
        let c = fd.new_constant(4, 0x1234);
        assert_eq!(constant_extended(&fd, c), Some(0x1234));
        let z = wide(&mut fd, IntZext, &[(8, u64::MAX)]);
        assert_eq!(constant_extended(&fd, z), Some(u128::from(u64::MAX)));
        let s = wide(&mut fd, IntSext, &[(4, 0x8000_0000)]);
        assert_eq!(constant_extended(&fd, s), Some(u128::MAX - 0x7fff_ffff));
        let p = wide(&mut fd, Piece, &[(8, 0x1122), (8, 0x3344)]);
        assert_eq!(constant_extended(&fd, p), Some(0x1122u128 << 64 | 0x3344));
        // a 4-byte low piece: the high constant moves up by 32 bits
        let p4 = wide(&mut fd, Piece, &[(8, 0xaabb_ccdd_0000_0001), (4, 0x5)]);
        assert_eq!(constant_extended(&fd, p4), Some(0xaabb_ccddu128 << 64 | 0x1_0000_0005));
    }
}
