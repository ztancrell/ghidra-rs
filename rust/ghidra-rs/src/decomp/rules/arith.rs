//! The rules on constants and arithmetic: `RuleTermOrder`, `RuleCollectTerms`, `RuleTrivial*`,
//! `RuleIdentityEl`, `Rule2Comp2Mult`, `RuleSub2Add`, `RuleCarryElim`, `RuleAddMultCollapse`,
//! `RuleCollapseConstants`, `RuleNegateIdentity`, `RuleNegateNegate` (ruleaction.cc).

use super::*;

/// Port of `RuleTermOrder`: a constant goes to slot 1 (`opSwapInput`).
pub(super) fn term_order(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let (a, b) = (inp(fd, op, 0)?, inp(fd, op, 1)?);
    if is_const(fd, a) && !is_const(fd, b) {
        fd.op_swap_input(op, 0, 1);
        return Ok(1);
    }
    Ok(0)
}

/// `RuleCollectTerms::getMultCoeff`.
pub(super) fn mult_coeff(fd: &Funcdata, vn: VarnodeId) -> (VarnodeId, u64) {
    if let Some(d) = def(fd, vn) {
        let o = fd.op(d);
        if o.opc == IntMult && o.ins.get(1).is_some_and(|&c| is_const(fd, c)) {
            return (o.ins[0], fd.vn(o.ins[1]).offset);
        }
    }
    (vn, 1)
}

/// Port of `RuleCollectTerms`.
pub(super) fn collect_terms(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let o = out(fd, op)?;
    if lone_descend(fd, o).is_some_and(|n| fd.op(n).opc == IntAdd) {
        return Ok(0);
    }
    let order = collect_additive(fd, op);
    let vn = |fd: &Funcdata, t: &Term| fd.op(t.op).ins[t.slot];
    let mut i = 0;
    if !order.is_empty() && !is_const(fd, vn(fd, &order[0])) {
        i = 1;
        while i < order.len() {
            let (a, b) = (vn(fd, &order[i - 1]), vn(fd, &order[i]));
            if is_const(fd, b) {
                break;
            }
            let (vn1, c1) = mult_coeff(fd, a);
            let (vn2, c2) = mult_coeff(fd, b);
            if vn1 == vn2 {
                if let Some(m) = order[i - 1].mult {
                    return Ok(i32::from(fd.distribute_int_mult_add(m)?));
                }
                if let Some(m) = order[i].mult {
                    return Ok(i32::from(fd.distribute_int_mult_add(m)?));
                }
                let sz = fd.vn(vn1).size;
                let coef = c1.wrapping_add(c2) & calc_mask(sz);
                let newcoeff = fd.new_constant(sz, coef);
                let zero = fd.new_constant(sz, 0);
                fd.op_set_input(order[i - 1].op, zero, order[i - 1].slot)?;
                if coef == 0 {
                    fd.op_set_input(order[i].op, newcoeff, order[i].slot)?;
                } else {
                    let next = fd.new_op(IntMult, fd.op(order[i].op).seq.addr);
                    let uniq = fd.uniq.ok_or_else(|| LowlevelError("no unique space".into()))?;
                    let v2 = fd.new_unique_out(sz, uniq, next);
                    fd.op_set_input(next, vn1, 0)?;
                    fd.op_set_input(next, newcoeff, 1)?;
                    fd.op_insert_before(next, order[i].op)?;
                    fd.op_set_input(order[i].op, v2, order[i].slot)?;
                }
                return Ok(1);
            }
            i += 1;
        }
    }
    let mut coef: u64 = 0;
    let mut nonzero = 0;
    let mut lastconst = 0;
    for j in (i..order.len()).rev() {
        if order[j].mult.is_some() {
            continue;
        }
        let val = fd.vn(vn(fd, &order[j])).offset;
        if val != 0 {
            nonzero += 1;
            coef = coef.wrapping_add(val);
            lastconst = j;
        }
    }
    if nonzero <= 1 {
        return Ok(0);
    }
    let sz = fd.vn(vn(fd, &order[lastconst])).size;
    coef &= calc_mask(sz);
    for t in &order[lastconst + 1..] {
        if t.mult.is_none() {
            let z = fd.new_constant(sz, 0);
            fd.op_set_input(t.op, z, t.slot)?;
        }
    }
    let c = fd.new_constant(sz, coef);
    fd.op_set_input(order[lastconst].op, c, order[lastconst].slot)?;
    Ok(1)
}

/// Port of `RuleTrivialArith`.
pub(super) fn trivial_arith(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    if ins(fd, op).len() != 2 {
        return Ok(0);
    }
    let (a, b) = (inp(fd, op, 0)?, inp(fd, op, 1)?);
    if a != b {
        let (Some(da), Some(db)) = (def(fd, a), def(fd, b)) else { return Ok(0) };
        if !fd.is_cse_match(da, db) {
            return Ok(0);
        }
    }
    let vn = match fd.op(op).opc {
        IntNotequal | IntSless | IntLess | BoolXor | FloatNotequal | FloatLess => Some(fd.new_constant(1, 0)),
        IntEqual | IntSlessequal | IntLessequal | FloatEqual | FloatLessequal => Some(fd.new_constant(1, 1)),
        IntXor => Some(fd.new_constant(fd.vn(out(fd, op)?).size, 0)),
        BoolAnd | BoolOr | IntAnd | IntOr => None,
        _ => return Ok(0),
    };
    fd.op_remove_input(op, 1);
    fd.op_set_opcode(op, Copy);
    if let Some(v) = vn {
        fd.op_set_input(op, v, 0)?;
    }
    Ok(1)
}

/// Port of `RuleTrivialBool`.
pub(super) fn trivial_bool(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let c = inp(fd, op, 1)?;
    if !is_const(fd, c) {
        return Ok(0);
    }
    let val = fd.vn(c).offset;
    let in0 = inp(fd, op, 0)?;
    let (opc, vn) = match fd.op(op).opc {
        BoolXor => (if val == 1 { BoolNegate } else { Copy }, in0),
        BoolAnd => (Copy, if val == 1 { in0 } else { fd.new_constant(1, 0) }),
        BoolOr => (Copy, if val == 1 { fd.new_constant(1, 1) } else { in0 }),
        _ => return Ok(0),
    };
    fd.op_remove_input(op, 1);
    fd.op_set_opcode(op, opc);
    fd.op_set_input(op, vn, 0)?;
    Ok(1)
}

/// Port of `RuleTrivialShift`.
pub(super) fn trivial_shift(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let c = inp(fd, op, 1)?;
    if !is_const(fd, c) {
        return Ok(0);
    }
    let val = fd.vn(c).offset;
    if val != 0 {
        let size = fd.vn(inp(fd, op, 0)?).size;
        if val < 8 * u64::from(size) || fd.op(op).opc == IntSright {
            return Ok(0);
        }
        let z = fd.new_constant(size, 0);
        fd.op_set_input(op, z, 0)?;
    }
    fd.op_remove_input(op, 1);
    fd.op_set_opcode(op, Copy);
    Ok(1)
}

/// Port of `RuleIdentityEl`.
pub(super) fn identity_el(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let c = inp(fd, op, 1)?;
    if !is_const(fd, c) {
        return Ok(0);
    }
    let val = fd.vn(c).offset;
    let mult = fd.op(op).opc == IntMult;
    let remove = match (val, mult) {
        (0, false) | (1, true) => 1,
        (0, true) => 0,
        _ => return Ok(0),
    };
    fd.op_set_opcode(op, Copy);
    fd.op_remove_input(op, remove);
    Ok(1)
}

/// Port of `Rule2Comp2Mult`.
pub(super) fn two_comp_2_mult(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    fd.op_set_opcode(op, IntMult);
    let size = fd.vn(inp(fd, op, 0)?).size;
    let negone = fd.new_constant(size, calc_mask(size));
    fd.op_insert_input(op, negone, 1)?;
    Ok(1)
}

/// Port of `RuleSub2Add`.
pub(super) fn sub_2_add(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let vn = inp(fd, op, 1)?;
    let size = fd.vn(vn).size;
    let newop = fd.new_op(IntMult, fd.op(op).seq.addr);
    let uniq = fd.uniq.ok_or_else(|| LowlevelError("no unique space".into()))?;
    let newvn = fd.new_unique_out(size, uniq, newop);
    fd.op_set_input(op, newvn, 1)?;
    fd.op_set_input(newop, vn, 0)?;
    let c = fd.new_constant(size, calc_mask(size));
    fd.op_set_input(newop, c, 1)?;
    fd.op_set_opcode(op, IntAdd);
    fd.op_insert_before(newop, op)?;
    Ok(1)
}

/// Port of `RuleCarryElim`.
pub(super) fn carry_elim(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let vn2 = inp(fd, op, 1)?;
    if !is_const(fd, vn2) {
        return Ok(0);
    }
    let vn1 = inp(fd, op, 0)?;
    if fd.vn(vn1).is_free() {
        return Ok(0);
    }
    let off = fd.vn(vn2).offset;
    if off == 0 {
        fd.op_remove_input(op, 1);
        let f = fd.new_constant(1, 0);
        fd.op_set_input(op, f, 0)?;
        fd.op_set_opcode(op, Copy);
        return Ok(1);
    }
    let off = off.wrapping_neg() & calc_mask(fd.vn(vn2).size);
    fd.op_set_opcode(op, IntLessequal);
    fd.op_set_input(op, vn1, 1)?;
    let c = fd.new_constant(fd.vn(vn1).size, off);
    fd.op_set_input(op, c, 0)?;
    Ok(1)
}

pub(super) fn eval2(opc: Opcode, size: u32, a: u64, b: u64) -> Result<u64> {
    eval_binary(opc, size, size, a, b).map_err(|e| LowlevelError(format!("{e:?}")))
}

/// Port of `RuleAddMultCollapse`.
pub(super) fn add_mult_collapse(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let opc = fd.op(op).opc;
    let c0 = inp(fd, op, 1)?;
    if !is_const(fd, c0) {
        return Ok(0);
    }
    let sub = inp(fd, op, 0)?;
    let Some(subop) = def(fd, sub) else { return Ok(0) };
    if fd.op(subop).opc != opc {
        return Ok(0);
    }
    let size = fd.vn(c0).size;
    let c1 = inp(fd, subop, 1)?;
    if !is_const(fd, c1) {
        if opc != IntAdd {
            return Ok(0);
        }
        for i in 0..2 {
            let other = inp(fd, subop, i)?;
            if is_const(fd, other) || fd.vn(other).is_free() {
                continue;
            }
            let sub2 = inp(fd, subop, 1 - i)?;
            let Some(baseop) = def(fd, sub2) else { continue };
            if fd.op(baseop).opc != IntAdd {
                continue;
            }
            let c1 = inp(fd, baseop, 1)?;
            if !is_const(fd, c1) {
                continue;
            }
            let base = inp(fd, baseop, 0)?;
            if !fd.vn(base).has(VnFlags::SPACEBASE) || !fd.vn(base).is_input() {
                continue;
            }
            let val = eval2(opc, size, fd.vn(c0).offset, fd.vn(c1).offset)?;
            let newvn = fd.new_constant(size, val);
            let newop = fd.new_op(IntAdd, fd.op(op).seq.addr);
            let uniq = fd.uniq.ok_or_else(|| LowlevelError("no unique space".into()))?;
            let newout = fd.new_unique_out(size, uniq, newop);
            fd.op_set_input(newop, base, 0)?;
            fd.op_set_input(newop, newvn, 1)?;
            fd.op_insert_before(newop, op)?;
            fd.op_set_input(op, newout, 0)?;
            fd.op_set_input(op, other, 1)?;
            return Ok(1);
        }
        return Ok(0);
    }
    let sub2 = inp(fd, subop, 0)?;
    if fd.vn(sub2).is_free() {
        return Ok(0);
    }
    let val = eval2(opc, size, fd.vn(c0).offset, fd.vn(c1).offset)?;
    let newvn = fd.new_constant(size, val);
    fd.op_set_input(op, newvn, 1)?;
    fd.op_set_input(op, sub2, 0)?;
    Ok(1)
}

/// Port of `RuleCollapseConstants` (`PcodeOp::isCollapsible`, `PcodeOp::collapse`).
pub(super) fn collapse_constants(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let o = fd.op(op);
    let Some(outvn) = o.out else { return Ok(0) };
    if o.ins.is_empty() || o.ins.iter().any(|&v| !is_const(fd, v)) || fd.vn(outvn).size > 8 {
        return Ok(0);
    }
    let osize = fd.vn(outvn).size;
    let v0 = fd.vn(o.ins[0]);
    let val = match o.ins[..] {
        _ if is_float(o.opc) => eval_float(fd, op)
            .ok_or_else(|| crate::decomp::emulate::EmuError::Other(format!("float op {:?} not folded", o.opc))),
        [_] => eval_unary(o.opc, osize, v0.size, v0.offset),
        [_, b] => eval_binary(o.opc, osize, v0.size, v0.offset, fd.vn(b).offset),
        _ => return err("Invalid constant collapse"),
    }
    .map_err(|e| LowlevelError(format!("{e:?}")))?;
    let vn = fd.new_constant(osize, val);
    for i in (1..ins(fd, op).len()).rev() {
        fd.op_remove_input(op, i);
    }
    fd.op_set_input(op, vn, 0)?;
    fd.op_set_opcode(op, Copy);
    Ok(1)
}

/// Port of `RuleNegateIdentity`.
pub(super) fn negate_identity(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let vn = inp(fd, op, 0)?;
    let outvn = out(fd, op)?;
    let readers = fd.vn(outvn).descend.to_vec();
    for logic in readers {
        let opc = fd.op(logic).opc;
        if !matches!(opc, IntAnd | IntOr | IntXor) {
            continue;
        }
        let Some(slot) = fd.slot_of(logic, outvn) else { continue };
        if fd.op(logic).ins.get(1 - slot) != Some(&vn) {
            continue;
        }
        let size = fd.vn(vn).size;
        let value = if opc == IntAnd { 0 } else { calc_mask(size) };
        let c = fd.new_constant(size, value);
        fd.op_set_input(logic, c, 0)?;
        fd.op_remove_input(logic, 1);
        fd.op_set_opcode(logic, Copy);
        return Ok(1);
    }
    Ok(0)
}

/// Port of `RuleNegateNegate`.
pub(super) fn negate_negate(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let vn1 = inp(fd, op, 0)?;
    let Some(neg2) = def(fd, vn1) else { return Ok(0) };
    if fd.op(neg2).opc != IntNegate {
        return Ok(0);
    }
    let vn2 = inp(fd, neg2, 0)?;
    if fd.vn(vn2).is_free() {
        return Ok(0);
    }
    fd.op_set_input(op, vn2, 0)?;
    fd.op_set_opcode(op, Copy);
    Ok(1)
}
