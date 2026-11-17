//! The rules on comparisons (stage R2): `RuleIntLessEqual`, `RuleSborrow`, `RuleScarry`,
//! `RuleTestSign`, `RuleLess2Zero`, `RuleLessEqual2Zero`, `RuleSLess2Zero`, `RuleEqual2Zero`,
//! `RuleEqual2Constant`, `RuleXorCollapse`, `RuleSlessToLess`, `RuleLessEqual`,
//! `RuleLessNotEqual`, `RuleLessOne`, `RuleRangeMeld` (ruleaction.cc), with
//! `Funcdata::replaceLessequal` (funcdata_op.cc) and `AddExpression` (expression.cc).
//!
//! `copySymbol` carries a constant's data-type and type lock to its replacement (`copy_symbol`);
//! symbols and equates are not modelled yet, so `copySymbolIfValid` (which copies only for an
//! equate) has nothing to carry.

use super::*;
use crate::decomp::opcode::is_bool_output;
use crate::decomp::rangeutil::{self, CircleRange};

/// `Varnode::operator==`: the same storage, and the same defining op when written.
fn vn_eq(fd: &Funcdata, a: VarnodeId, b: VarnodeId) -> bool {
    let (x, y) = (fd.vn(a), fd.vn(b));
    x.space == y.space
        && x.offset == y.offset
        && x.size == y.size
        && x.is_input() == y.is_input()
        && match (x.def, y.def) {
            (None, None) => true,
            (Some(p), Some(q)) => fd.op(p).seq == fd.op(q).seq,
            _ => false,
        }
}

/// `op` becomes a COPY of the boolean constant `val`.
fn to_bool_const(fd: &mut Funcdata, op: OpId, val: bool) -> Result<i32> {
    fd.op_set_opcode(op, Copy);
    fd.op_remove_input(op, 1);
    let c = fd.new_constant(1, u64::from(val));
    fd.op_set_input(op, c, 0)?;
    Ok(1)
}

/// Port of `Funcdata::replaceLessequal`: `V <= c  =>  V < (c+1)`, and for the other forms.
pub(crate) fn replace_lessequal(fd: &mut Funcdata, op: OpId) -> Result<bool> {
    let (a, b) = (inp(fd, op, 0)?, inp(fd, op, 1)?);
    let (vn, i, down) = if is_const(fd, a) {
        (a, 0, true)
    } else if is_const(fd, b) {
        (b, 1, false)
    } else {
        return Ok(false);
    };
    let (val, size) = (off(fd, vn), sz(fd, vn));
    let mask = calc_mask(size);
    let (min, max, opc) =
        if code(fd, op) == IntSlessequal { (mask ^ (mask >> 1), mask >> 1, IntSless) } else { (0, mask, IntLess) };
    if (down && val == min) || (!down && val == max) {
        return Ok(false);
    }
    fd.op_set_opcode(op, opc);
    let res = if down { val.wrapping_sub(1) } else { val.wrapping_add(1) } & mask;
    let newvn = fd.new_constant(size, res);
    fd.copy_symbol(newvn, vn);
    fd.op_set_input(op, newvn, i)?;
    Ok(true)
}

/// Port of `RuleIntLessEqual`.
pub(super) fn int_less_equal(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    Ok(i32::from(replace_lessequal(fd, op)?))
}

/// Port of `AddExpression`: a sum of at most two terms with coefficients, and a constant.
#[derive(Debug, Default)]
struct AddExpr {
    constval: u64,
    terms: Vec<(VarnodeId, u64)>,
}

impl AddExpr {
    /// `AddExpression::gather`.
    fn gather(&mut self, fd: &Funcdata, vn: VarnodeId, mut coeff: u64, mut depth: i32) -> Result<()> {
        let mask = calc_mask(sz(fd, vn));
        if is_const(fd, vn) {
            self.constval = self.constval.wrapping_add(coeff.wrapping_mul(off(fd, vn))) & mask;
            return Ok(());
        }
        if let Some(op) = def(fd, vn) {
            if code(fd, op) == IntAdd {
                if !is_const(fd, inp(fd, op, 1)?) {
                    depth -= 1;
                }
                if depth >= 0 {
                    self.gather(fd, inp(fd, op, 0)?, coeff, depth)?;
                    return self.gather(fd, inp(fd, op, 1)?, coeff, depth);
                }
            } else if code(fd, op) == IntMult && is_const(fd, inp(fd, op, 1)?) {
                coeff = coeff.wrapping_mul(off(fd, inp(fd, op, 1)?)) & mask;
                return self.gather(fd, inp(fd, op, 0)?, coeff, depth);
            }
        }
        if self.terms.len() < 2 {
            self.terms.push((vn, coeff));
        }
        Ok(())
    }

    /// `gatherTwoTermsSubtract` (`negate`) and `gatherTwoTermsAdd`.
    fn two_terms(fd: &Funcdata, a: VarnodeId, b: VarnodeId, negate: bool) -> Result<AddExpr> {
        let mut e = AddExpr::default();
        let depth = i32::from(is_const(fd, a) || is_const(fd, b));
        e.gather(fd, a, 1, depth)?;
        e.gather(fd, b, if negate { calc_mask(sz(fd, b)) } else { 1 }, depth)?;
        Ok(e)
    }

    /// `gatherTwoTermsRoot`.
    fn root(fd: &Funcdata, vn: VarnodeId) -> Result<AddExpr> {
        let mut e = AddExpr::default();
        e.gather(fd, vn, 1, 1)?;
        Ok(e)
    }

    /// `AddExpression::isEquivalent`.
    fn is_equivalent(&self, fd: &Funcdata, o: &AddExpr) -> bool {
        let eq = |x: &(VarnodeId, u64), y: &(VarnodeId, u64)| x.1 == y.1 && func_equal(fd, x.0, y.0);
        if self.constval != o.constval {
            return false;
        }
        match (&self.terms[..], &o.terms[..]) {
            ([a], [b]) => eq(a, b),
            ([a, b], [c, d]) => (eq(a, c) && eq(b, d)) || (eq(a, d) && eq(b, c)),
            _ => false,
        }
    }
}

/// `RuleSborrow`/`RuleScarry`: a comparison of the flag `svn` with the sign of the expression
/// `expr`: the comparison and the slot of the zero in the sign test.
fn overflow_compare(fd: &Funcdata, svn: VarnodeId, expr: &AddExpr) -> Result<Option<(OpId, usize)>> {
    for &compop in fd.vn(svn).descend.iter() {
        if !matches!(code(fd, compop), IntEqual | IntNotequal) {
            continue;
        }
        let cvn = if inp(fd, compop, 0)? == svn { inp(fd, compop, 1)? } else { inp(fd, compop, 0)? };
        let Some(signop) = def_with(fd, cvn, IntSless) else { continue };
        let zside = if const_match(fd, inp(fd, signop, 0)?, 0) {
            0
        } else if const_match(fd, inp(fd, signop, 1)?, 0) {
            1
        } else {
            continue;
        };
        let xvn = inp(fd, signop, 1 - zside)?;
        if def(fd, xvn).is_some() && expr.is_equivalent(fd, &AddExpr::root(fd, xvn)?) {
            return Ok(Some((compop, zside)));
        }
    }
    Ok(None)
}

/// The comparison `compop` (see [`overflow_compare`]) becomes `a s< b` or its complement.
fn set_signed_compare(fd: &mut Funcdata, compop: OpId, zside: usize, a: VarnodeId, b: VarnodeId) -> Result<i32> {
    if code(fd, compop) == IntNotequal {
        fd.op_set_opcode(compop, IntSless);
        fd.op_set_input(compop, a, 1 - zside)?;
        fd.op_set_input(compop, b, zside)?;
    } else {
        fd.op_set_opcode(compop, IntSlessequal);
        fd.op_set_input(compop, a, zside)?;
        fd.op_set_input(compop, b, 1 - zside)?;
    }
    Ok(1)
}

/// `op` (an overflow flag with a zero operand) becomes a COPY of 0.
fn flag_is_zero(fd: &mut Funcdata, op: OpId) -> Result<i32> {
    fd.op_set_opcode(op, Copy);
    let c = fd.new_constant(1, 0);
    fd.op_set_input(op, c, 0)?;
    fd.op_remove_input(op, 1);
    Ok(1)
}

/// Port of `RuleSborrow`: `sborrow(V,W) != (V - W s< 0)  =>  V s< W`.
pub(super) fn sborrow(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let svn = out(fd, op)?;
    let (avn, bvn) = (inp(fd, op, 0)?, inp(fd, op, 1)?);
    if const_match(fd, bvn, 0) {
        return flag_is_zero(fd, op);
    }
    let expr = AddExpr::two_terms(fd, avn, bvn, true)?;
    match overflow_compare(fd, svn, &expr)? {
        Some((compop, zside)) => set_signed_compare(fd, compop, zside, avn, bvn),
        None => Ok(0),
    }
}

/// Port of `RuleScarry`: `scarry(V,c) != (V + c s< 0)  =>  V s< -c`.
pub(super) fn scarry(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let svn = out(fd, op)?;
    let (mut avn, mut bvn) = (inp(fd, op, 0)?, inp(fd, op, 1)?);
    if const_match(fd, bvn, 0) || const_match(fd, avn, 0) {
        return flag_is_zero(fd, op);
    }
    if !is_const(fd, bvn) {
        if !is_const(fd, avn) {
            return Ok(0);
        }
        std::mem::swap(&mut avn, &mut bvn);
        let val = calc_mask(sz(fd, bvn));
        if val ^ (val >> 1) == off(fd, bvn) {
            return Ok(0);
        }
    }
    let expr = AddExpr::two_terms(fd, avn, bvn, false)?;
    let Some((compop, zside)) = overflow_compare(fd, svn, &expr)? else { return Ok(0) };
    let size = sz(fd, bvn);
    let newconst = fd.new_constant(size, off(fd, bvn).wrapping_neg() & calc_mask(size));
    set_signed_compare(fd, compop, zside, avn, newconst)
}

/// Port of `RuleTestSign`: `(V s>> 31) == 0  =>  0 s<= V`, and the other sign tests.
pub(super) fn test_sign(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let constvn = inp(fd, op, 1)?;
    let invn = inp(fd, op, 0)?;
    let size = sz(fd, invn);
    if !is_const(fd, constvn) || off(fd, constvn) != u64::from(8 * size - 1) || is_free(fd, invn) {
        return Ok(0);
    }
    let outvn = out(fd, op)?;
    let compares: Vec<OpId> = fd.vn(outvn).descend.to_vec();
    let mut res = 0;
    for comp in compares {
        if !matches!(code(fd, comp), IntEqual | IntNotequal) || !is_const(fd, inp(fd, comp, 1)?) {
            continue;
        }
        let offset = off(fd, inp(fd, comp, 1)?);
        let mut positive = if offset == 0 {
            true
        } else if offset == calc_mask(sz(fd, inp(fd, comp, 0)?)) {
            false
        } else {
            continue;
        };
        if code(fd, comp) == IntNotequal {
            positive = !positive;
        }
        let zero = fd.new_constant(size, 0);
        if positive {
            fd.op_set_input(comp, invn, 1)?;
            fd.op_set_input(comp, zero, 0)?;
            fd.op_set_opcode(comp, IntSlessequal);
        } else {
            fd.op_set_input(comp, invn, 0)?;
            fd.op_set_input(comp, zero, 1)?;
            fd.op_set_opcode(comp, IntSless);
        }
        res = 1;
    }
    Ok(res)
}

/// Port of `RuleLess2Zero`: `0 < V  =>  0 != V`, `V < 0  =>  false`, and for 0xff..f.
pub(super) fn less_2_zero(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let (l, r) = (inp(fd, op, 0)?, inp(fd, op, 1)?);
    let all_ones = |v: VarnodeId| off(fd, v) == calc_mask(sz(fd, v));
    let noteq = if is_const(fd, l) {
        match off(fd, l) {
            0 => true,
            _ if all_ones(l) => false,
            _ => return Ok(0),
        }
    } else if is_const(fd, r) {
        match off(fd, r) {
            0 => false,
            _ if all_ones(r) => true,
            _ => return Ok(0),
        }
    } else {
        return Ok(0);
    };
    if noteq {
        fd.op_set_opcode(op, IntNotequal);
        return Ok(1);
    }
    to_bool_const(fd, op, false)
}

/// Port of `RuleLessEqual2Zero`: `0 <= V  =>  true`, `V <= 0  =>  V == 0`, and for 0xff..f.
pub(super) fn less_equal_2_zero(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let (l, r) = (inp(fd, op, 0)?, inp(fd, op, 1)?);
    let all_ones = |v: VarnodeId| off(fd, v) == calc_mask(sz(fd, v));
    let equal = if is_const(fd, l) {
        match off(fd, l) {
            0 => false,
            _ if all_ones(l) => true,
            _ => return Ok(0),
        }
    } else if is_const(fd, r) {
        match off(fd, r) {
            0 => true,
            _ if all_ones(r) => false,
            _ => return Ok(0),
        }
    } else {
        return Ok(0);
    };
    if equal {
        fd.op_set_opcode(op, IntEqual);
        return Ok(1);
    }
    to_bool_const(fd, op, true)
}

/// `RuleSLess2Zero::getHiBit`: the input of an ADD, OR or XOR that is only the sign bit.
fn hi_bit(fd: &Funcdata, op: OpId) -> Result<Option<VarnodeId>> {
    if !matches!(code(fd, op), IntAdd | IntOr | IntXor) {
        return Ok(None);
    }
    let (vn1, vn2) = (inp(fd, op, 0)?, inp(fd, op, 1)?);
    let mask = calc_mask(sz(fd, vn1));
    let mask = mask ^ (mask >> 1);
    let (nz1, nz2) = (fd.nzmask(vn1), fd.nzmask(vn2));
    if (nz1 != mask && nz1 & mask != 0) || (nz2 != mask && nz2 & mask != 0) {
        return Ok(None);
    }
    Ok(if nz1 == mask {
        Some(vn1)
    } else if nz2 == mask {
        Some(vn2)
    } else {
        None
    })
}

/// `hibit` itself, or a fresh constant of its value (`RuleSLess2Zero`).
fn hi_bit_input(fd: &mut Funcdata, hibit: VarnodeId) -> VarnodeId {
    if is_const(fd, hibit) {
        fd.new_constant(sz(fd, hibit), off(fd, hibit))
    } else {
        hibit
    }
}

/// Port of `RuleSLess2Zero`: sign tests of an expression (`-1 s< X` when `negative` is false,
/// `X s< 0` when it is true) become tests of the part that holds the sign.
pub(super) fn sless_2_zero(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let (lvn, rvn) = (inp(fd, op, 0)?, inp(fd, op, 1)?);
    // the tested varnode, its slot, and whether the test is `X s< 0`
    let (xvn, xslot, negative) = if is_const(fd, lvn) {
        if def(fd, rvn).is_none() || off(fd, lvn) != calc_mask(sz(fd, lvn)) {
            return Ok(0);
        }
        (rvn, 1, false)
    } else if is_const(fd, rvn) {
        if def(fd, lvn).is_none() || off(fd, rvn) != 0 {
            return Ok(0);
        }
        (lvn, 0, true)
    } else {
        return Ok(0);
    };
    let Some(feed) = def(fd, xvn) else { return Ok(0) };
    if let Some(hibit) = hi_bit(fd, feed)? {
        let h = hi_bit_input(fd, hibit);
        fd.op_set_input(op, h, xslot)?;
        if negative {
            fd.op_set_opcode(op, IntNotequal);
        } else {
            fd.op_set_opcode(op, IntEqual);
            let z = fd.new_constant(sz(fd, hibit), 0);
            fd.op_set_input(op, z, 0)?;
        }
        return Ok(1);
    }
    sign_through(fd, op, feed, xvn, xslot, negative)
}

/// `RuleSLess2Zero`, the forms that move the sign test of `xvn` (slot `xslot` of `op`; `X s< 0`
/// when `negative`, else `-1 s< X`) to an input of the op `feed` defining it.
fn sign_through(fd: &mut Funcdata, op: OpId, feed: OpId, xvn: VarnodeId, xslot: usize, negative: bool) -> Result<i32> {
    let Some(&avn) = ins(fd, feed).first() else { return Ok(0) };
    let asz = sz(fd, avn);
    // `X s< 0` holds when `avn s< 0` (`same`), else when `-1 s< avn`
    let retest = |fd: &mut Funcdata, same: bool| -> Result<i32> {
        if negative == same {
            fd.op_set_input(op, avn, 0)?;
            let z = fd.new_constant(asz, 0);
            fd.op_set_input(op, z, 1)?;
        } else {
            fd.op_set_input(op, avn, 1)?;
            let m = fd.new_constant(asz, calc_mask(asz));
            fd.op_set_input(op, m, 0)?;
        }
        Ok(1)
    };
    match code(fd, feed) {
        Subpiece => {
            if is_free(fd, avn) || asz > 8 {
                return Ok(0);
            }
            if (sz(fd, xvn) as i32).wrapping_add(off(fd, inp(fd, feed, 1)?) as i32) == asz as i32 {
                return retest(fd, true);
            }
            Ok(0)
        }
        IntNegate => {
            if is_free(fd, avn) {
                return Ok(0);
            }
            retest(fd, false)
        }
        IntAnd => {
            if is_free(fd, avn) || lone_descend(fd, xvn).is_none() {
                return Ok(0);
            }
            let maskvn = inp(fd, feed, 1)?;
            if is_const(fd, maskvn) && signbit_negative(off(fd, maskvn), asz) {
                fd.op_set_input(op, avn, xslot)?;
                return Ok(1);
            }
            Ok(0)
        }
        Piece => {
            if is_free(fd, avn) {
                return Ok(0);
            }
            retest(fd, true)
        }
        IntLeft if !negative => {
            let coeff = inp(fd, feed, 1)?;
            if !const_match(fd, coeff, u64::from(sz(fd, xvn) * 8 - 1)) {
                return Ok(0);
            }
            if !def(fd, avn).is_some_and(|d| is_bool_output(code(fd, d))) {
                return Ok(0);
            }
            fd.op_set_opcode(op, BoolNegate);
            fd.op_remove_input(op, 1);
            fd.op_set_input(op, avn, 0)?;
            Ok(1)
        }
        _ => Ok(0),
    }
}

/// Port of `RuleEqual2Zero`: `0 == V + W * -1  =>  V == W`, `0 == V + c  =>  V == -c`.
pub(super) fn equal_2_zero(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let (a, b) = (inp(fd, op, 0)?, inp(fd, op, 1)?);
    let addvn = if const_match(fd, a, 0) {
        b
    } else if const_match(fd, b, 0) {
        a
    } else {
        return Ok(0);
    };
    if !fd.vn(addvn).descend.iter().all(|&d| is_bool_output(code(fd, d))) {
        return Ok(0);
    }
    let Some(addop) = def_with(fd, addvn, IntAdd) else { return Ok(0) };
    let (vn, vn2) = (inp(fd, addop, 0)?, inp(fd, addop, 1)?);
    let mult_neg_one = |v: VarnodeId| -> Result<Option<VarnodeId>> {
        let Some(m) = def_with(fd, v, IntMult) else { return Ok(None) };
        let c = inp(fd, m, 1)?;
        Ok(if const_match(fd, c, calc_mask(sz(fd, c))) { Some(inp(fd, m, 0)?) } else { None })
    };
    let (posvn, unnegvn) = if is_const(fd, vn2) {
        let size = sz(fd, vn2);
        (vn, fd.new_constant(size, !off(fd, vn2).wrapping_sub(1) & calc_mask(size)))
    } else if let Some(u) = mult_neg_one(vn)? {
        (vn2, u)
    } else if let Some(u) = mult_neg_one(vn2)? {
        (vn, u)
    } else {
        return Ok(0);
    };
    if !known(fd, posvn) || !known(fd, unnegvn) {
        return Ok(0);
    }
    fd.op_set_input(op, posvn, 0)?;
    fd.op_set_input(op, unnegvn, 1)?;
    Ok(1)
}

/// Port of `RuleEqual2Constant`: `V + c == d  =>  V == (d - c)`, and for `* -1` and `~`.
pub(super) fn equal_2_constant(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let cvn = inp(fd, op, 1)?;
    if !is_const(fd, cvn) {
        return Ok(0);
    }
    let lhs = inp(fd, op, 0)?;
    let Some(leftop) = def(fd, lhs) else { return Ok(0) };
    let newconst = match code(fd, leftop) {
        IntAdd => {
            let other = inp(fd, leftop, 1)?;
            if !is_const(fd, other) {
                return Ok(0);
            }
            off(fd, cvn).wrapping_sub(off(fd, other)) & calc_mask(sz(fd, cvn))
        }
        IntMult => {
            let other = inp(fd, leftop, 1)?;
            if !const_match(fd, other, calc_mask(sz(fd, other))) {
                return Ok(0);
            }
            off(fd, cvn).wrapping_neg() & calc_mask(sz(fd, other))
        }
        IntNegate => !off(fd, cvn) & calc_mask(sz(fd, lhs)),
        _ => return Ok(0),
    };
    let a = inp(fd, leftop, 0)?;
    if is_free(fd, a) {
        return Ok(0);
    }
    for &dop in fd.vn(lhs).descend.iter() {
        if dop == op {
            continue;
        }
        if !matches!(code(fd, dop), IntEqual | IntNotequal) || !is_const(fd, inp(fd, dop, 1)?) {
            return Ok(0);
        }
    }
    fd.op_set_input(op, a, 0)?;
    let c = fd.new_constant(sz(fd, a), newconst);
    fd.op_set_input(op, c, 1)?;
    Ok(1)
}

/// Port of `RuleXorCollapse`: `V ^ W == 0  =>  V == W`, `V ^ c == d  =>  V == (c ^ d)`.
pub(super) fn xor_collapse(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let c = inp(fd, op, 1)?;
    if !is_const(fd, c) {
        return Ok(0);
    }
    let x = inp(fd, op, 0)?;
    let Some(xorop) = def_with(fd, x, IntXor) else { return Ok(0) };
    if lone_descend(fd, x).is_none() {
        return Ok(0);
    }
    let coeff1 = off(fd, c);
    let (base, xorvn) = (inp(fd, xorop, 0)?, inp(fd, xorop, 1)?);
    if is_free(fd, base) {
        return Ok(0);
    }
    if !is_const(fd, xorvn) {
        if coeff1 != 0 || is_free(fd, xorvn) {
            return Ok(0);
        }
        fd.op_set_input(op, xorvn, 1)?;
        fd.op_set_input(op, base, 0)?;
        return Ok(1);
    }
    let coeff2 = off(fd, xorvn);
    if coeff2 == 0 {
        return Ok(0);
    }
    let nc = fd.new_constant(sz(fd, c), coeff1 ^ coeff2);
    fd.op_set_input(op, nc, 1)?;
    fd.op_set_input(op, base, 0)?;
    Ok(1)
}

/// Port of `RuleSlessToLess`: a signed comparison of values without a sign bit is unsigned.
pub(super) fn sless_to_less(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let vn = inp(fd, op, 0)?;
    let size = sz(fd, vn);
    if signbit_negative(fd.nzmask(vn), size) || signbit_negative(fd.nzmask(inp(fd, op, 1)?), size) {
        return Ok(0);
    }
    fd.op_set_opcode(op, if code(fd, op) == IntSless { IntLess } else { IntLessequal });
    Ok(1)
}

/// `RuleLessEqual`/`RuleLessNotEqual`: the less-than (one of `less`) and the other op feeding
/// the boolean `op`, when they compare the same two varnodes: (less, equal, V, W).
fn less_and_equal(fd: &Funcdata, op: OpId, less: [Opcode; 2]) -> Result<Option<(OpId, OpId, VarnodeId, VarnodeId)>> {
    let (Some(d1), Some(d2)) = (def(fd, inp(fd, op, 0)?), def(fd, inp(fd, op, 1)?)) else { return Ok(None) };
    let (op_less, op_equal) = if less.contains(&code(fd, d1)) {
        (d1, d2)
    } else if less.contains(&code(fd, d2)) {
        (d2, d1)
    } else {
        return Ok(None);
    };
    if !matches!(code(fd, op_equal), IntEqual | IntNotequal) {
        return Ok(None);
    }
    let (c1, c2) = (inp(fd, op_less, 0)?, inp(fd, op_less, 1)?);
    if !known(fd, c1) || !known(fd, c2) {
        return Ok(None);
    }
    let (e0, e1) = (inp(fd, op_equal, 0)?, inp(fd, op_equal, 1)?);
    if !(vn_eq(fd, c1, e0) && vn_eq(fd, c2, e1)) && !(vn_eq(fd, c1, e1) && vn_eq(fd, c2, e0)) {
        return Ok(None);
    }
    Ok(Some((op_less, op_equal, c1, c2)))
}

/// Port of `RuleLessEqual`: `V < W || V == W  =>  V <= W`.
pub(super) fn less_equal(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let Some((op_less, op_equal, c1, c2)) = less_and_equal(fd, op, [IntLess, IntSless])? else { return Ok(0) };
    if code(fd, op_equal) == IntNotequal {
        fd.op_set_opcode(op, Copy);
        fd.op_remove_input(op, 1);
        let o = out(fd, op_equal)?;
        fd.op_set_input(op, o, 0)?;
    } else {
        fd.op_set_input(op, c1, 0)?;
        fd.op_set_input(op, c2, 1)?;
        fd.op_set_opcode(op, if code(fd, op_less) == IntSless { IntSlessequal } else { IntLessequal });
    }
    Ok(1)
}

/// Port of `RuleLessNotEqual`: `V <= W && V != W  =>  V < W`.
pub(super) fn less_not_equal(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let Some((op_less, op_equal, c1, c2)) = less_and_equal(fd, op, [IntLessequal, IntSlessequal])? else {
        return Ok(0);
    };
    if code(fd, op_equal) != IntNotequal {
        return Ok(0);
    }
    fd.op_set_input(op, c1, 0)?;
    fd.op_set_input(op, c2, 1)?;
    fd.op_set_opcode(op, if code(fd, op_less) == IntSlessequal { IntSless } else { IntLess });
    Ok(1)
}

/// Port of `RuleLessOne`: `V < 1  =>  V == 0`, `V <= 0  =>  V == 0`.
pub(super) fn less_one(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let constvn = inp(fd, op, 1)?;
    if !is_const(fd, constvn) {
        return Ok(0);
    }
    let val = off(fd, constvn);
    if (code(fd, op) == IntLess && val != 1) || (code(fd, op) == IntLessequal && val != 0) {
        return Ok(0);
    }
    fd.op_set_opcode(op, IntEqual);
    if val != 0 {
        let z = fd.new_constant(sz(fd, constvn), 0);
        fd.op_set_input(op, z, 1)?;
    }
    Ok(1)
}

/// `CircleRange::pullBack` (without the non-zero masks) on literal constants.
fn pull_back(fd: &Funcdata, vn: VarnodeId, rng: CircleRange) -> Option<(VarnodeId, CircleRange)> {
    rangeutil::pull_back(fd, vn, rng, false, |v| is_const(fd, v).then(|| off(fd, v)), |v| fd.nzmask(v))
}

/// `RuleRangeMeld`: the varnode a boolean (the output of `sub`) tests, and the range of its
/// values for which the boolean holds.
fn bool_range(fd: &Funcdata, vn: VarnodeId, sub: OpId) -> Option<(VarnodeId, CircleRange)> {
    let (a, range) = pull_back(fd, vn, CircleRange::boolean(true))?;
    if code(fd, sub) == BoolNegate {
        return pull_back(fd, a, range);
    }
    Some((a, range))
}

/// Port of `RuleRangeMeld`: two range tests of one variable, ANDed or ORed, become one test.
pub(super) fn range_meld(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let (vn1, vn2) = (inp(fd, op, 0)?, inp(fd, op, 1)?);
    let (Some(sub1), Some(sub2)) = (def(fd, vn1), def(fd, vn2)) else { return Ok(0) };
    if !is_bool_output(code(fd, sub1)) || !is_bool_output(code(fd, sub2)) {
        return Ok(0);
    }
    let Some((mut a1, mut range1)) = bool_range(fd, vn1, sub1) else { return Ok(0) };
    let Some((mut a2, mut range2)) = bool_range(fd, vn2, sub2) else { return Ok(0) };
    if !func_equal(fd, a1, a2) {
        match pull_back(fd, a1, range1) {
            Some((a, r)) if a == a2 => (a1, range1) = (a, r),
            _ => {
                if def(fd, a2).is_some() {
                    let Some(back) = pull_back(fd, a2, range2) else { return Ok(0) };
                    (a2, range2) = back;
                }
                if a1 != a2 {
                    return Ok(0);
                }
            }
        }
    }
    if !known(fd, a1) {
        return Ok(0);
    }
    let mut restype = if code(fd, op) == BoolAnd { range1.intersect(&range2) } else { range1.circle_union(&range2) };
    if restype == 0 {
        let (res, opc, resc, slot) = range1.translate_2_op();
        restype = res;
        if restype == 0 {
            let c = fd.new_constant(sz(fd, a1), resc);
            fd.op_set_opcode(op, opc);
            fd.op_set_input(op, a1, 1 - slot)?;
            fd.op_set_input(op, c, slot)?;
            return Ok(1);
        }
    }
    match restype {
        2 => Ok(0),
        1 => to_bool_const(fd, op, true),
        3 => to_bool_const(fd, op, false),
        _ => Ok(1),
    }
}

/// Port of `RuleThreeWayCompare::testCompareEquivalence`: `lessop` and `lessequalop` compare the
/// same two values as `<` and `<=` (or as two `<` whose constants differ by one). 0 they do, 1
/// they do with the two swapped, none they do not.
fn three_way_equivalence(fd: &Funcdata, lessop: OpId, lessequalop: OpId) -> Option<bool> {
    let mut two_less_than = match (code(fd, lessop), code(fd, lessequalop)) {
        (IntLess, IntLessequal) | (IntSless, IntSlessequal) | (FloatLess, FloatLessequal) => false,
        (IntLess, IntLess) | (IntSless, IntSless) => true,
        _ => return None,
    };
    let (a1, a2) = (fd.op(lessop).ins[0], fd.op(lessequalop).ins[0]);
    let (b1, b2) = (fd.op(lessop).ins[1], fd.op(lessequalop).ins[1]);
    let mut swap = false;
    if a1 != a2 {
        if !is_const(fd, a1) || !is_const(fd, a2) {
            return None;
        }
        let (o1, o2) = (off(fd, a1), off(fd, a2));
        if o1 != o2 && two_less_than {
            if o2.wrapping_add(1) == o1 {
                two_less_than = false; // `lessequalop` is a less-than equivalent to a less-equal
            } else if o1.wrapping_add(1) == o2 {
                two_less_than = false; // `lessop` is the one
                swap = true;
            } else {
                return None;
            }
        }
    }
    if b1 != b2 {
        if !is_const(fd, b1) || !is_const(fd, b2) {
            return None;
        }
        let (o1, o2) = (off(fd, b1), off(fd, b2));
        if o1 != o2 && two_less_than {
            if o1.wrapping_add(1) == o2 {
                two_less_than = false;
            } else if o2.wrapping_add(1) == o1 {
                two_less_than = false;
                swap = true;
            }
        } else {
            return None;
        }
    }
    (!two_less_than).then_some(swap)
}

/// Port of `RuleThreeWayCompare::detectThreeWay`: `op` (an INT_ADD) is `zext(a < b) + zext(a <=
/// b) - 1` in one of its forms; the less-than op and whether the `- 1` is missing (the partial
/// form).
fn detect_three_way(fd: &Funcdata, op: OpId) -> Option<(OpId, bool)> {
    let written = |vn: VarnodeId, opc: Opcode| def(fd, vn).filter(|&d| code(fd, d) == opc);
    let minus_one = |vn: VarnodeId| is_const(fd, vn) && off(fd, vn) == calc_mask(fd.vn(vn).size);
    let (vn1, vn2) = (fd.op(op).ins[0], fd.op(op).ins[1]);
    let mut partial = false;
    let (zext1, zext2) = if is_const(fd, vn2) {
        // form 1: (z + z) - 1
        if !minus_one(vn2) {
            return None;
        }
        let addop = written(vn1, IntAdd)?;
        (written(fd.op(addop).ins[0], IntZext)?, written(fd.op(addop).ins[1], IntZext)?)
    } else {
        let tmpop = def(fd, vn2)?;
        match code(fd, tmpop) {
            IntZext => {
                // form 2: (z - 1) + z
                let addop = def(fd, vn1)?;
                if code(fd, addop) != IntAdd {
                    // the partial form: z + z
                    if code(fd, addop) != IntZext {
                        return None;
                    }
                    partial = true;
                    (addop, tmpop)
                } else {
                    if !minus_one(fd.op(addop).ins[1]) {
                        return None;
                    }
                    (written(fd.op(addop).ins[0], IntZext)?, tmpop)
                }
            }
            IntAdd => {
                // form 3: z + (z - 1)
                let zext1 = written(vn1, IntZext)?;
                if !minus_one(fd.op(tmpop).ins[1]) {
                    return None;
                }
                (zext1, written(fd.op(tmpop).ins[0], IntZext)?)
            }
            _ => return None,
        }
    };
    let mut lessop = def(fd, fd.op(zext1).ins[0])?;
    let mut lessequalop = def(fd, fd.op(zext2).ins[0])?;
    if !matches!(code(fd, lessop), IntLess | IntSless | FloatLess) {
        std::mem::swap(&mut lessop, &mut lessequalop);
    }
    if three_way_equivalence(fd, lessop, lessequalop)? {
        lessop = lessequalop;
    }
    Some((lessop, partial))
}

/// Port of `RuleThreeWayCompare`: a comparison of a three-way compare (-1, 0 or 1) with a
/// constant becomes the comparison of the two values.
pub(super) fn three_way_compare(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    three_way(fd, op)
}

fn three_way(fd: &mut Funcdata, op: OpId) -> Result<i32> {
    let mut const_slot = 0;
    if !is_const(fd, inp(fd, op, 0)?) {
        const_slot = 1;
        if !is_const(fd, inp(fd, op, 1)?) {
            return Ok(0);
        }
    }
    let c = inp(fd, op, const_slot)?;
    // the constant (-1, 0, 1, 2) is the highest three bits of the form
    let val = off(fd, c);
    let mut form: u32 = if val <= 2 {
        val as u32 + 1
    } else if val == calc_mask(fd.vn(c).size) {
        0
    } else {
        return Ok(0);
    };
    let Some(addop) = def(fd, inp(fd, op, 1 - const_slot)?).filter(|&d| code(fd, d) == IntAdd) else { return Ok(0) };
    let Some((lessop, partial)) = detect_three_way(fd, addop) else { return Ok(0) };
    if partial {
        if form == 0 {
            return Ok(0); // -1 is out of range now
        }
        form -= 1; // subtract 1 from both sides to complete the three-way form
    }
    // then the constant's position, then the op (SLESS, SLESSEQUAL, EQUAL, NOTEQUAL)
    form = (form << 1) + const_slot as u32;
    form = (form << 2)
        + match code(fd, op) {
            IntSlessequal => 1,
            IntEqual => 2,
            IntNotequal => 3,
            _ => 0,
        };
    let lessform = code(fd, lessop);
    let lessequalform = match lessform {
        IntLess => IntLessequal,
        IntSless => IntSlessequal,
        _ => FloatLessequal,
    };
    // the first input of the less-than is the second parameter of the three-way compare
    let (bvn, avn) = (fd.op(lessop).ins[0], fd.op(lessop).ins[1]);
    if (!is_const(fd, avn) && fd.vn(avn).is_free()) || (!is_const(fd, bvn) && fd.vn(bvn).is_free()) {
        return Ok(0);
    }
    let float = lessform == FloatLess;
    let (opc, first, second) = match form {
        // always true, always false
        1 | 21 | 4 | 16 => {
            fd.op_set_opcode(op, if matches!(form, 1 | 21) { IntEqual } else { IntNotequal });
            for slot in 0..2 {
                let zero = fd.new_constant(1, 0);
                fd.op_set_input(op, zero, slot)?;
            }
            return Ok(1);
        }
        2 | 5 | 6 | 12 => (lessform, avn, bvn),         // a < b
        13 | 19 | 20 | 23 => (lessequalform, avn, bvn), // a <= b
        8 | 17 | 18 | 22 => (lessform, bvn, avn),       // a > b
        0 | 3 | 7 | 9 => (lessequalform, bvn, avn),     // a >= b
        10 | 14 => (if float { FloatEqual } else { IntEqual }, avn, bvn),
        11 | 15 => (if float { FloatNotequal } else { IntNotequal }, avn, bvn),
        _ => return Ok(0),
    };
    fd.op_set_opcode(op, opc);
    fd.op_set_input(op, first, 0)?;
    fd.op_set_input(op, second, 1)?;
    Ok(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `x <opc> c` (or `c <opc> x` with `const_first`) in a fresh function.
    fn compare_op(fd: &mut Funcdata, opc: Opcode, c: u64, const_first: bool) -> OpId {
        let op = fd.new_op(opc, 0x1000);
        let x = fd.new_varnode(4, Space::Sleigh(1), 0x10);
        let k = fd.new_constant(4, c);
        let (a, b) = if const_first { (k, x) } else { (x, k) };
        fd.op_set_input(op, a, 0).unwrap();
        fd.op_set_input(op, b, 1).unwrap();
        op
    }

    /// `out = opc(ins)` with a written output of `size` bytes.
    fn written(fd: &mut Funcdata, opc: Opcode, size: u32, ins: &[VarnodeId]) -> VarnodeId {
        let op = fd.new_op(opc, 0x1000);
        let off = 0x100 + 0x10 * u64::from(op.0);
        let out = fd.new_varnode_out(size, Space::Sleigh(1), off, op);
        for (i, &v) in ins.iter().enumerate() {
            fd.op_set_input(op, v, i).unwrap();
        }
        out
    }

    #[test]
    fn three_way_compare_forms() {
        // (zext(a s< b) + zext(a s<= b)) - 1 is 1, 0 or -1 for a < b, a == b, a > b
        // comparison of it with a constant, constant first, result: (opcode, a first)
        let cases = [
            (IntSless, 0, false, Some((IntSless, false))),        // tw s< 0: b s< a
            (IntEqual, 0, false, Some((IntEqual, false))),        // tw == 0: equal (inputs b, a)
            (IntNotequal, 1, true, Some((IntSlessequal, false))), // 1 != tw: b s<= a
            (IntSless, 0, true, Some((IntSless, true))),          // 0 s< tw: a s< b
            (IntEqual, 5, false, None),
        ];
        for (opc, c, const_first, want) in cases {
            let mut fd = Funcdata::new(0x1000);
            let k = fd.new_constant(4, 7);
            let a = written(&mut fd, Copy, 4, &[k]);
            let b = written(&mut fd, Copy, 4, &[k]);
            let less = written(&mut fd, IntSless, 1, &[a, b]);
            let lesseq = written(&mut fd, IntSlessequal, 1, &[a, b]);
            let z1 = written(&mut fd, IntZext, 4, &[less]);
            let z2 = written(&mut fd, IntZext, 4, &[lesseq]);
            let sum = written(&mut fd, IntAdd, 4, &[z1, z2]);
            let m1 = fd.new_constant(4, 0xffff_ffff);
            let tw = written(&mut fd, IntAdd, 4, &[sum, m1]);
            let kc = fd.new_constant(4, c);
            let ins = if const_first { [kc, tw] } else { [tw, kc] };
            let res = written(&mut fd, opc, 1, &ins);
            let op = fd.vn(res).def.unwrap();
            let changed = three_way(&mut fd, op).unwrap();
            let got = (changed == 1).then(|| (code(&fd, op), fd.op(op).ins[0] == a));
            assert_eq!(got, want, "{opc:?} {c} const_first={const_first}");
            if got.is_some() {
                let mut both = fd.op(op).ins.clone();
                both.sort_by_key(|v| v.0);
                assert_eq!(both, vec![a, b]);
            }
        }
    }

    #[test]
    fn replace_lessequal_table() {
        // opcode, constant, constant first, result: (new opcode, new constant) or unchanged
        let cases = [
            (IntLessequal, 5, false, Some((IntLess, 6))),
            (IntLessequal, 5, true, Some((IntLess, 4))),
            (IntLessequal, 0xffff_ffff, false, None),
            (IntLessequal, 0, true, None),
            (IntSlessequal, 0x7fff_ffff, false, None),
            (IntSlessequal, 0x8000_0000, true, None),
            (IntSlessequal, 0xffff_ffff, false, Some((IntSless, 0))),
            (IntSlessequal, 0, true, Some((IntSless, 0xffff_ffff))),
        ];
        for (opc, c, first, want) in cases {
            let mut fd = Funcdata::new(0x1000);
            let op = compare_op(&mut fd, opc, c, first);
            let changed = replace_lessequal(&mut fd, op).unwrap();
            let slot = usize::from(!first);
            let got = changed.then(|| (code(&fd, op), off(&fd, fd.op(op).ins[slot])));
            assert_eq!(got, want, "{opc:?} {c:#x} first={first}");
        }
    }
}
