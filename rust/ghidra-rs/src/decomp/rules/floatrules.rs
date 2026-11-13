//! The float rules: `RuleFloatRange`, `RuleFloatSign`, `RuleFloatCast`, `RuleIgnoreNan`,
//! `RuleUnsigned2Float`, `RuleInt2FloatCollapse` (ruleaction.cc). `RuleSubfloatConvert` is in
//! `decomp/subfloat.rs`.

use super::*;

/// Port of `RuleFloatRange`: `f < c || f == c` becomes `f <= c`, `f <= c && f != c` becomes
/// `f < c`.
pub(super) fn float_range(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let (Some(d1), Some(d2)) = (def(fd, inp(fd, op, 0)?), def(fd, inp(fd, op, 1)?)) else { return Ok(0) };
    let (cmp1, cmp2) = if matches!(fd.op(d1).opc, FloatLess | FloatLessequal) { (d1, d2) } else { (d2, d1) };
    let opc = fd.op(op).opc;
    let resultopc = match (fd.op(cmp1).opc, fd.op(cmp2).opc, opc) {
        (FloatLess, FloatEqual, BoolOr) => FloatLessequal,
        (FloatLessequal, FloatNotequal, BoolAnd) => FloatLess,
        _ => return Ok(0),
    };
    let mut slot1 = 0;
    let mut nvn1 = inp(fd, cmp1, 0)?;
    if is_const(fd, nvn1) {
        slot1 = 1;
        nvn1 = inp(fd, cmp1, 1)?;
        if is_const(fd, nvn1) {
            return Ok(0);
        }
    }
    if fd.vn(nvn1).is_free() {
        return Ok(0);
    }
    let cvn1 = inp(fd, cmp1, 1 - slot1)?;
    let slot2 = if nvn1 != inp(fd, cmp2, 0)? {
        if nvn1 != inp(fd, cmp2, 1)? {
            return Ok(0);
        }
        1
    } else {
        0
    };
    let matchvn = inp(fd, cmp2, 1 - slot2)?;
    if is_const(fd, cvn1) {
        if !is_const(fd, matchvn) || fd.vn(matchvn).offset != fd.vn(cvn1).offset {
            return Ok(0);
        }
    } else if cvn1 != matchvn || fd.vn(cvn1).is_free() {
        return Ok(0);
    }
    fd.op_set_opcode(op, resultopc);
    fd.op_set_input(op, nvn1, slot1)?;
    let c = if is_const(fd, cvn1) {
        let v = fd.vn(cvn1);
        fd.new_constant(v.size, v.offset)
    } else {
        cvn1
    };
    fd.op_set_input(op, c, 1 - slot1)?;
    Ok(1)
}

/// Port of `TypeOp::floatSignManipulation`: FLOAT_ABS for an INT_AND clearing the sign bit,
/// FLOAT_NEG for an INT_XOR flipping it.
fn float_sign_manipulation(fd: &Funcdata, op: OpId) -> Result<Option<Opcode>> {
    let opc = fd.op(op).opc;
    if !matches!(opc, IntAnd | IntXor) {
        return Ok(None);
    }
    let cvn = inp(fd, op, 1)?;
    if !is_const(fd, cvn) {
        return Ok(None);
    }
    let mask = calc_mask(fd.vn(cvn).size);
    let (val, res) = if opc == IntAnd { (mask >> 1, FloatAbs) } else { (mask ^ (mask >> 1), FloatNeg) };
    Ok((val == fd.vn(cvn).offset).then_some(res))
}

/// Rewrites `op` as its float sign operation when it is one (`RuleFloatSign`'s inner step).
fn convert_sign_op(fd: &mut Funcdata, op: OpId) -> Result<bool> {
    let Some(opc) = float_sign_manipulation(fd, op)? else { return Ok(false) };
    fd.op_remove_input(op, 1);
    fd.op_set_opcode(op, opc);
    Ok(true)
}

/// Port of `RuleFloatSign`: integer sign manipulations next to float ops become FLOAT_ABS or
/// FLOAT_NEG.
pub(super) fn float_sign(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let mut res = 0;
    let opc = fd.op(op).opc;
    if opc != FloatInt2float {
        let n = ins(fd, op).len().min(2);
        for slot in 0..n {
            if let Some(sign_op) = def(fd, inp(fd, op, slot)?) {
                if convert_sign_op(fd, sign_op)? {
                    res = 1;
                }
            }
        }
    }
    if is_bool_output(opc) || opc == FloatTrunc {
        return Ok(res);
    }
    let readers = fd.vn(out(fd, op)?).descend.to_vec();
    for read_op in readers {
        if convert_sign_op(fd, read_op)? {
            res = 1;
        }
    }
    Ok(res)
}

/// Port of `RuleFloatCast`: two float conversions in a row become one.
pub(super) fn float_cast(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let vn1 = inp(fd, op, 0)?;
    let Some(castop) = def(fd, vn1) else { return Ok(0) };
    let opc2 = fd.op(castop).opc;
    if !matches!(opc2, FloatFloat2float | FloatInt2float) {
        return Ok(0);
    }
    let opc1 = fd.op(op).opc;
    let vn2 = inp(fd, castop, 0)?;
    let insize1 = fd.vn(vn1).size;
    let insize2 = fd.vn(vn2).size;
    let outsize = fd.vn(out(fd, op)?).size;
    if fd.vn(vn2).is_free() {
        return Ok(0);
    }
    match (opc2, opc1) {
        (FloatFloat2float, FloatFloat2float) => {
            if insize1 > outsize {
                fd.op_set_input(op, vn2, 0)?;
                if outsize == insize2 {
                    fd.op_set_opcode(op, Copy);
                }
                return Ok(1);
            }
            if insize2 < insize1 {
                fd.op_set_input(op, vn2, 0)?;
                return Ok(1);
            }
            Ok(0)
        }
        (FloatInt2float, FloatFloat2float) => {
            fd.op_set_input(op, vn2, 0)?;
            fd.op_set_opcode(op, FloatInt2float);
            Ok(1)
        }
        (FloatFloat2float, FloatTrunc) => {
            fd.op_set_input(op, vn2, 0)?;
            Ok(1)
        }
        _ => Ok(0),
    }
}

/// Port of `RuleIgnoreNan::checkBackForCompare`: `root` is a float comparison of `float_var`
/// (maybe negated, or one term of a BOOL_AND / BOOL_OR).
fn check_back_for_compare(fd: &Funcdata, float_var: VarnodeId, root: VarnodeId) -> Result<bool> {
    let Some(mut def1) = def(fd, root) else { return Ok(false) };
    if !is_bool_output(fd.op(def1).opc) {
        return Ok(false);
    }
    if fd.op(def1).opc == BoolNegate {
        let Some(d) = def(fd, inp(fd, def1, 0)?) else { return Ok(false) };
        def1 = d;
    }
    let compares = |d: OpId| {
        let ins = ins(fd, d);
        ins.len() == 2 && (func_equal(fd, float_var, ins[0]) || func_equal(fd, float_var, ins[1]))
    };
    if is_float(fd.op(def1).opc) {
        return Ok(compares(def1));
    }
    if !matches!(fd.op(def1).opc, BoolAnd | BoolOr) {
        return Ok(false);
    }
    for i in 0..2 {
        let Some(def2) = def(fd, inp(fd, def1, i)?) else { continue };
        let opc = fd.op(def2).opc;
        if is_bool_output(opc) && is_float(opc) && compares(def2) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Port of `RuleIgnoreNan::isAnotherNan`.
fn is_another_nan(fd: &Funcdata, vn: VarnodeId) -> Result<bool> {
    let Some(mut op) = def(fd, vn) else { return Ok(false) };
    if fd.op(op).opc == BoolNegate {
        let Some(d) = def(fd, inp(fd, op, 0)?) else { return Ok(false) };
        op = d;
    }
    Ok(fd.op(op).opc == FloatNan)
}

/// Port of `RuleIgnoreNan::testForComparison`: drops the NaN test `op` combines with a
/// comparison of `float_var`; the output to follow when `op` combines it with another NaN test.
fn test_for_comparison(
    fd: &mut Funcdata,
    float_var: VarnodeId,
    op: OpId,
    slot: usize,
    match_code: Opcode,
    count: &mut i32,
) -> Result<Option<VarnodeId>> {
    let opc = fd.op(op).opc;
    let bool_val = if match_code == BoolOr { 0 } else { 1 };
    if opc == match_code {
        let vn = inp(fd, op, 1 - slot.min(1))?;
        if check_back_for_compare(fd, float_var, vn)? {
            fd.op_set_opcode(op, Copy);
            fd.op_remove_input(op, 1);
            fd.op_set_input(op, vn, 0)?;
            *count += 1;
        } else if is_another_nan(fd, vn)? {
            return Ok(Some(out(fd, op)?));
        }
    } else if matches!(opc, IntEqual | IntNotequal) {
        let vn = inp(fd, op, 1 - slot.min(1))?;
        if check_back_for_compare(fd, float_var, vn)? {
            let c = fd.new_constant(1, bool_val);
            fd.op_set_input(op, c, slot)?;
            *count += 1;
        }
    } else if opc == Cbranch {
        let Some(parent) = fd.op(op).parent else { return Ok(None) };
        let mut out_dir = if match_code == BoolOr { 0 } else { 1 };
        if fd.op(op).flags.has(OpFlags::BOOLEAN_FLIP) {
            out_dir = 1 - out_dir;
        }
        let g = &fd.blocks;
        let out_of = |b: BlockId, i: usize| g.block(b).outs.get(i).map(|e| e.point);
        let (Some(out_branch), Some(other)) = (out_of(parent, out_dir), out_of(parent, 1 - out_dir)) else {
            return Ok(None);
        };
        let Some(&last_op) = g.block(out_branch).ops.last() else { return Ok(None) };
        if fd.op(last_op).opc == Cbranch
            && (out_of(out_branch, 0) == Some(other) || out_of(out_branch, 1) == Some(other))
            && check_back_for_compare(fd, float_var, inp(fd, last_op, 1)?)?
        {
            let c = fd.new_constant(1, bool_val);
            fd.op_set_input(op, c, 1)?;
            *count += 1;
        }
    }
    Ok(None)
}

/// Port of `RuleIgnoreNan`: a NaN test combined with a comparison of the same value is dropped
/// (`option nanignore compare`, the default); with `nanignore all` every NaN test is false.
///
/// The reader lists are snapshots: the C++ advances its live iterator before changing a reader,
/// and a change only removes that reader from the list (or adds readers to other varnodes),
/// so the walk visits the same ops.
pub(super) fn ignore_nan(fd: &mut Funcdata, op: OpId, arch: &Arch) -> Result<i32> {
    if arch.nan_ignore_all {
        fd.op_set_opcode(op, Copy);
        let c = fd.new_constant(1, 0);
        fd.op_set_input(op, c, 0)?;
        return Ok(1);
    }
    let float_var = inp(fd, op, 0)?;
    if fd.vn(float_var).is_free() {
        return Ok(0);
    }
    let out1 = out(fd, op)?;
    let mut count = 0;
    let readers = fd.vn(out1).descend.to_vec();
    for read1 in readers {
        let (match_code, out2) = if fd.op(read1).opc == BoolNegate {
            (BoolAnd, Some(out(fd, read1)?))
        } else {
            let Some(slot) = fd.slot_of(read1, out1) else { continue };
            (BoolOr, test_for_comparison(fd, float_var, read1, slot, BoolOr, &mut count)?)
        };
        let Some(out2) = out2 else { continue };
        let readers = fd.vn(out2).descend.to_vec();
        for read2 in readers {
            let Some(slot) = fd.slot_of(read2, out2) else { continue };
            let Some(out3) = test_for_comparison(fd, float_var, read2, slot, match_code, &mut count)? else {
                continue;
            };
            let readers = fd.vn(out3).descend.to_vec();
            for read3 in readers {
                let Some(slot) = fd.slot_of(read3, out3) else { continue };
                test_for_comparison(fd, float_var, read3, slot, match_code, &mut count)?;
            }
        }
    }
    Ok(i32::from(count > 0))
}

/// `TypeOpFloatInt2Float::preferredZextSize`.
fn preferred_zext_size(in_size: u32) -> u32 {
    match in_size {
        0..=3 => 4,
        4..=7 => 8,
        _ => in_size + 1,
    }
}

/// `Varnode::constantMatch`.
fn constant_match(fd: &Funcdata, vn: VarnodeId, val: u64) -> bool {
    is_const(fd, vn) && fd.vn(vn).offset == val
}

/// Port of `RuleUnsigned2Float`: the shift-or-double sequence converting an unsigned integer
/// becomes `FLOAT_INT2FLOAT(ZEXT(V))`.
pub(super) fn unsigned_2_float(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let Some(orop) = def_with(fd, inp(fd, op, 0)?, IntOr) else { return Ok(0) };
    let (Some(d0), Some(d1)) = (def(fd, inp(fd, orop, 0)?), def(fd, inp(fd, orop, 1)?)) else { return Ok(0) };
    let (shiftop, mut andop) = if fd.op(d0).opc != IntRight { (d1, d0) } else { (d0, d1) };
    if fd.op(shiftop).opc != IntRight || !constant_match(fd, inp(fd, shiftop, 1)?, 1) {
        return Ok(0);
    }
    let basevn = inp(fd, shiftop, 0)?;
    if fd.vn(basevn).is_free() {
        return Ok(0);
    }
    if fd.op(andop).opc == IntZext {
        let Some(d) = def(fd, inp(fd, andop, 0)?) else { return Ok(0) };
        andop = d;
    }
    if fd.op(andop).opc != IntAnd || !constant_match(fd, inp(fd, andop, 1)?, 1) {
        return Ok(0);
    }
    let vn = inp(fd, andop, 0)?;
    if basevn != vn {
        let Some(subop) = def_with(fd, vn, Subpiece) else { return Ok(0) };
        if fd.vn(inp(fd, subop, 1)?).offset != 0 || inp(fd, subop, 0)? != basevn {
            return Ok(0);
        }
    }
    let outvn = out(fd, op)?;
    let Some(addop) =
        fd.vn(outvn).descend.iter().copied().find(|&a| {
            fd.op(a).opc == FloatAdd && ins(fd, a).first() == Some(&outvn) && ins(fd, a).get(1) == Some(&outvn)
        })
    else {
        return Ok(0);
    };
    let zextop = fd.new_op(IntZext, fd.op(addop).seq.addr);
    let zextout = uniq_out(fd, preferred_zext_size(fd.vn(basevn).size), zextop)?;
    fd.op_set_opcode(addop, FloatInt2float);
    fd.op_remove_input(addop, 1);
    fd.op_set_input(zextop, basevn, 0)?;
    fd.op_set_input(addop, zextout, 0)?;
    fd.op_insert_before(zextop, addop)?;
    Ok(1)
}

/// Port of `RuleInt2FloatCollapse`: the two conversions of an unsigned integer, signed and
/// corrected, merged by a MULTIEQUAL, become one unsigned FLOAT_INT2FLOAT.
pub(super) fn int2float_collapse(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let Some(zextop) = def_with(fd, inp(fd, op, 0)?, IntZext) else { return Ok(0) };
    let basevn = inp(fd, zextop, 0)?;
    if fd.vn(basevn).is_free() {
        return Ok(0);
    }
    let outvn = out(fd, op)?;
    let Some(multiop) = lone_descend(fd, outvn) else { return Ok(0) };
    if fd.op(multiop).opc != Multiequal || ins(fd, multiop).len() != 2 {
        return Ok(0);
    }
    let Some(slot) = fd.slot_of(multiop, outvn) else { return Ok(0) };
    let Some(op2) = def_with(fd, inp(fd, multiop, 1 - slot)?, FloatInt2float) else { return Ok(0) };
    if basevn != inp(fd, op2, 0)? {
        return Ok(0);
    }
    let Some(outbl) = fd.op(multiop).parent else { return Ok(0) };
    let Some((cond, dir2unsigned)) = fd.blocks.find_condition(outbl, slot, outbl, 1 - slot) else { return Ok(0) };
    let Some(&cbranch) = fd.blocks.block(cond).ops.last() else { return Ok(0) };
    if fd.op(cbranch).opc != Cbranch || fd.op(cbranch).flags.has(OpFlags::BOOLEAN_FLIP) {
        return Ok(0);
    }
    let Some(compare) = def(fd, inp(fd, cbranch, 1)?) else { return Ok(0) };
    if fd.op(compare).opc != IntSless {
        return Ok(0);
    }
    if constant_match(fd, inp(fd, compare, 1)?, 0) {
        if inp(fd, compare, 0)? != basevn || dir2unsigned != 1 {
            return Ok(0);
        }
    } else if constant_match(fd, inp(fd, compare, 0)?, calc_mask(fd.vn(basevn).size)) {
        if inp(fd, compare, 1)? != basevn || dir2unsigned == 1 {
            return Ok(0);
        }
    } else {
        return Ok(0);
    }
    fd.op_uninsert(multiop);
    fd.op_set_opcode(multiop, FloatInt2float);
    fd.op_remove_input(multiop, 0);
    let newzext = fd.new_op(IntZext, fd.op(multiop).seq.addr);
    let newout = uniq_out(fd, preferred_zext_size(fd.vn(basevn).size), newzext)?;
    fd.op_set_input(newzext, basevn, 0)?;
    fd.op_set_input(multiop, newout, 0)?;
    fd.op_insert_begin(multiop, outbl);
    fd.op_insert_before(newzext, multiop)?;
    Ok(1)
}
