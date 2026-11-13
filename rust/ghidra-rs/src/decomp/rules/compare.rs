//! The rules on comparisons (stage R2): `RuleIntLessEqual`, `RuleSborrow`, `RuleScarry`,
//! `RuleTestSign`, `RuleLess2Zero`, `RuleLessEqual2Zero`, `RuleSLess2Zero`, `RuleEqual2Zero`,
//! `RuleEqual2Constant`, `RuleXorCollapse`, `RuleSlessToLess`, `RuleLessEqual`,
//! `RuleLessNotEqual`, `RuleLessOne`, `RuleRangeMeld` (ruleaction.cc), with
//! `Funcdata::replaceLessequal` (funcdata_op.cc) and `AddExpression` (expression.cc).
//!
//! Constants hold no symbol yet, so `copySymbol`/`copySymbolIfValid` (markup carried to a new
//! constant) have nothing to carry.

use super::*;
use crate::decomp::jumptable::{is_bool_output, pull_back};
use crate::decomp::rangeutil::CircleRange;

/// `signbit_negative`.
pub(super) fn signbit_negative(val: u64, size: u32) -> bool {
    shr(val, (8 * size) as i32 - 1) & 1 != 0
}

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
        let Some(signop) = def_opc(fd, cvn, IntSless) else { continue };
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
            if !const_match(fd, coeff, u64::from(sz(fd, lvn) * 8 - 1)) {
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
    let Some(addop) = def_opc(fd, addvn, IntAdd) else { return Ok(0) };
    let (vn, vn2) = (inp(fd, addop, 0)?, inp(fd, addop, 1)?);
    let mult_neg_one = |v: VarnodeId| -> Result<Option<VarnodeId>> {
        let Some(m) = def_opc(fd, v, IntMult) else { return Ok(None) };
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
    let Some(xorop) = def_opc(fd, x, IntXor) else { return Ok(0) };
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

/// `RuleRangeMeld`: the varnode a boolean (the output of `sub`) tests, and the range of its
/// values for which the boolean holds.
fn bool_range(fd: &Funcdata, arch: &Arch, vn: VarnodeId, sub: OpId) -> Option<(VarnodeId, CircleRange)> {
    let (a, range) = pull_back(fd, arch, vn, CircleRange::boolean(true), false)?;
    if code(fd, sub) == BoolNegate {
        return pull_back(fd, arch, a, range, false);
    }
    Some((a, range))
}

/// Port of `RuleRangeMeld`: two range tests of one variable, ANDed or ORed, become one test.
pub(super) fn range_meld(fd: &mut Funcdata, op: OpId, arch: &Arch) -> Result<i32> {
    let (vn1, vn2) = (inp(fd, op, 0)?, inp(fd, op, 1)?);
    let (Some(sub1), Some(sub2)) = (def(fd, vn1), def(fd, vn2)) else { return Ok(0) };
    if !is_bool_output(code(fd, sub1)) || !is_bool_output(code(fd, sub2)) {
        return Ok(0);
    }
    let Some((mut a1, mut range1)) = bool_range(fd, arch, vn1, sub1) else { return Ok(0) };
    let Some((mut a2, mut range2)) = bool_range(fd, arch, vn2, sub2) else { return Ok(0) };
    if !func_equal(fd, a1, a2) {
        match pull_back(fd, arch, a1, range1, false) {
            Some((a, r)) if a == a2 => (a1, range1) = (a, r),
            _ => {
                if def(fd, a2).is_some() {
                    let Some(back) = pull_back(fd, arch, a2, range2, false) else { return Ok(0) };
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
