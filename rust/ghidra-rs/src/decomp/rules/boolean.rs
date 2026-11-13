//! The rules on booleans (stage R2): `RuleBxor2NotEqual`, `RuleNotDistribute`,
//! `RuleBooleanUndistribute`, `RuleBooleanDedup`, `RuleBooleanNegate`, `RuleBoolZext`,
//! `RuleLogic2Bool`, `RuleCondNegate`, `RuleBoolNegate` (ruleaction.cc), with `BooleanMatch`
//! (expression.cc), `Funcdata::opBoolNegate`, `opNormalizeFlip`, `opFlipCondition`
//! (funcdata_op.cc) and the boolean flips of the opcodes (`TypeOp::getBooleanFlip`).

use super::*;
use crate::decomp::jumptable::is_bool_output;
use crate::decomp::types::Meta;

/// `TypeOp::getBooleanFlip` and `isBooleanFlipReorder`: the opcode of the complement and
/// whether the inputs swap; `None` is `CPUI_MAX`.
pub(crate) fn boolean_flip(opc: Opcode) -> Option<(Opcode, bool)> {
    Some(match opc {
        IntEqual => (IntNotequal, false),
        IntNotequal => (IntEqual, false),
        IntSless => (IntSlessequal, true),
        IntSlessequal => (IntSless, true),
        IntLess => (IntLessequal, true),
        IntLessequal => (IntLess, true),
        BoolNegate => (Copy, false),
        FloatEqual => (FloatNotequal, false),
        FloatNotequal => (FloatEqual, false),
        FloatLess => (FloatLessequal, true),
        FloatLessequal => (FloatLess, true),
        _ => return None,
    })
}

/// `PcodeOp::isCalculatedBool`.
fn is_calculated_bool(fd: &Funcdata, op: OpId) -> bool {
    fd.op(op).flags.has(OpFlags::CALCULATED_BOOL) || is_bool_output(code(fd, op))
}

/// `Varnode::isBooleanValue(data.isTypeRecoveryOn())`: written by a boolean op, or (with the
/// `typerecovery` group on) an input locked to `bool`.
fn is_boolean_value(fd: &Funcdata, vn: VarnodeId) -> bool {
    if let Some(d) = def(fd, vn) {
        return is_calculated_bool(fd, d);
    }
    let v = fd.vn(vn);
    fd.typerecovery_on
        && v.has(VnFlags::INPUT)
        && v.has(VnFlags::TYPELOCK)
        && v.size == 1
        && v.ty.is_some_and(|t| fd.types.meta(t) == Meta::Bool)
}

/// Port of `Funcdata::opBoolNegate` (inserting before `op`): the negation of `vn`.
fn op_bool_negate(fd: &mut Funcdata, vn: VarnodeId, op: OpId) -> Result<VarnodeId> {
    insert_new(fd, BoolNegate, op_addr(fd, op), 1, &[vn], op)
}

/// `PcodeOp::flipFlag`.
fn flip_flag(fd: &mut Funcdata, op: OpId, f: OpFlags) {
    let flags = &mut fd.op_mut(op).flags;
    if flags.has(f) {
        flags.clear(f);
    } else {
        flags.set(f);
    }
}

/// Port of `Funcdata::opNormalizeFlip`: the flip of a CBRANCH goes into the comparison that
/// only it reads.
pub(crate) fn op_normalize_flip(fd: &mut Funcdata, cbranch: OpId) -> Result<bool> {
    let boolvn = inp(fd, cbranch, 1)?;
    let Some(cond) = def(fd, boolvn) else { return Ok(false) };
    if lone_descend(fd, boolvn) != Some(cbranch) {
        return Ok(false);
    }
    let Some((opc, reorder)) = boolean_flip(code(fd, cond)) else { return Ok(false) };
    fd.op_set_opcode(cond, opc);
    if reorder {
        fd.op_swap_input(cond, 0, 1);
    }
    flip_flag(fd, cbranch, OpFlags::BOOLEAN_FLIP);
    if opc == IntLessequal || opc == IntSlessequal {
        replace_lessequal(fd, cond)?;
    }
    Ok(true)
}

/// Port of `BooleanMatch`: how two boolean varnodes relate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Match {
    Same,
    Complementary,
    Uncorrelated,
}

impl Match {
    fn flipped(self) -> Match {
        match self {
            Match::Same => Match::Complementary,
            Match::Complementary => Match::Same,
            Match::Uncorrelated => Match::Uncorrelated,
        }
    }
}

/// `BooleanMatch::varnodeSame`.
fn varnode_same(fd: &Funcdata, a: VarnodeId, b: VarnodeId) -> bool {
    a == b || (is_const(fd, a) && is_const(fd, b) && off(fd, a) == off(fd, b))
}

/// `BooleanMatch::sameOpComplement`: `V < c` against `c' < V` with `c' + 1 == c`.
fn same_op_complement(fd: &Funcdata, op1: OpId, op2: OpId) -> Result<bool> {
    let opc = code(fd, op1);
    if opc != IntSless && opc != IntLess {
        return Ok(false);
    }
    let cs = usize::from(is_const(fd, inp(fd, op1, 1)?));
    let (c1, c2) = (inp(fd, op1, cs)?, inp(fd, op2, 1 - cs)?);
    if !is_const(fd, c1) || !is_const(fd, c2) || !varnode_same(fd, inp(fd, op1, 1 - cs)?, inp(fd, op2, cs)?) {
        return Ok(false);
    }
    let (mut val1, mut val2) = (off(fd, c1), off(fd, c2));
    if cs != 0 {
        std::mem::swap(&mut val1, &mut val2);
    }
    if val1.wrapping_add(1) != val2 || (val2 == 0 && opc == IntLess) {
        return Ok(false);
    }
    let size = sz(fd, c1);
    Ok(!(opc == IntSless && signbit_negative(val2, size) && !signbit_negative(val1, size)))
}

/// `BooleanMatch::evaluate`, the pairing of two AND/OR/XOR ops.
fn evaluate_pair(fd: &Funcdata, op1: OpId, op2: OpId, depth: i32) -> Result<Match> {
    let (opc1, opc2) = (code(fd, op1), code(fd, op2));
    let logic = |o: Opcode| matches!(o, BoolAnd | BoolOr | BoolXor);
    if !logic(opc2) || !(opc1 == opc2 || (opc1 != BoolXor && opc2 != BoolXor)) {
        return Ok(Match::Uncorrelated);
    }
    let (a0, a1, b0, b1) = (inp(fd, op1, 0)?, inp(fd, op1, 1)?, inp(fd, op2, 0)?, inp(fd, op2, 1)?);
    let mut pair1 = evaluate(fd, a0, b0, depth - 1)?;
    let pair2 = if pair1 == Match::Uncorrelated {
        pair1 = evaluate(fd, a0, b1, depth - 1)?;
        if pair1 == Match::Uncorrelated {
            return Ok(Match::Uncorrelated);
        }
        evaluate(fd, a1, b0, depth - 1)?
    } else {
        evaluate(fd, a1, b1, depth - 1)?
    };
    if pair2 == Match::Uncorrelated {
        return Ok(Match::Uncorrelated);
    }
    let both = |m: Match| pair1 == m && pair2 == m;
    Ok(if opc1 == opc2 {
        if both(Match::Same) {
            Match::Same
        } else if opc1 == BoolXor {
            if both(Match::Complementary) {
                Match::Same
            } else {
                Match::Complementary
            }
        } else {
            Match::Uncorrelated
        }
    } else if both(Match::Complementary) {
        Match::Complementary // De Morgan
    } else {
        Match::Uncorrelated
    })
}

/// Port of `BooleanMatch::evaluate`.
fn evaluate(fd: &Funcdata, vn1: VarnodeId, vn2: VarnodeId, depth: i32) -> Result<Match> {
    if vn1 == vn2 {
        return Ok(Match::Same);
    }
    let op1 = def(fd, vn1);
    if let Some(o) = op1.filter(|&o| code(fd, o) == BoolNegate) {
        return Ok(evaluate(fd, inp(fd, o, 0)?, vn2, depth)?.flipped());
    }
    let Some(op2) = def(fd, vn2) else { return Ok(Match::Uncorrelated) };
    if code(fd, op2) == BoolNegate {
        return Ok(evaluate(fd, vn1, inp(fd, op2, 0)?, depth)?.flipped());
    }
    let Some(op1) = op1 else { return Ok(Match::Uncorrelated) };
    let (opc1, opc2) = (code(fd, op1), code(fd, op2));
    if !is_bool_output(opc1) || !is_bool_output(opc2) {
        return Ok(Match::Uncorrelated);
    }
    if depth != 0 && matches!(opc1, BoolAnd | BoolOr | BoolXor) {
        return evaluate_pair(fd, op1, op2, depth);
    }
    if opc1 == opc2 {
        let same = ins(fd, op1).iter().zip(ins(fd, op2)).all(|(&a, &b)| varnode_same(fd, a, b));
        return Ok(if same {
            Match::Same
        } else if same_op_complement(fd, op1, op2)? {
            Match::Complementary
        } else {
            Match::Uncorrelated
        });
    }
    let Some((flip, reorder)) = boolean_flip(opc2) else { return Ok(Match::Uncorrelated) };
    let slot2 = usize::from(reorder);
    Ok(
        if opc1 == flip
            && varnode_same(fd, inp(fd, op1, 0)?, inp(fd, op2, slot2)?)
            && varnode_same(fd, inp(fd, op1, 1)?, inp(fd, op2, 1 - slot2)?)
        {
            Match::Complementary
        } else {
            Match::Uncorrelated
        },
    )
}

/// The inputs of the two AND/OR ops feeding `op` (`RuleBooleanUndistribute`,
/// `RuleBooleanDedup`): the two opcodes and the four inputs, none free.
fn two_logic_ops(fd: &Funcdata, op: OpId) -> Result<Option<(Opcode, Opcode, [VarnodeId; 4])>> {
    let (Some(op0), Some(op1)) = (def(fd, inp(fd, op, 0)?), def(fd, inp(fd, op, 1)?)) else { return Ok(None) };
    let (opc0, opc1) = (code(fd, op0), code(fd, op1));
    if !matches!(opc0, BoolAnd | BoolOr) || !matches!(opc1, BoolAnd | BoolOr) {
        return Ok(None);
    }
    let vns = [inp(fd, op0, 0)?, inp(fd, op0, 1)?, inp(fd, op1, 0)?, inp(fd, op1, 1)?];
    Ok(if vns.iter().any(|&v| is_free(fd, v)) { None } else { Some((opc0, opc1, vns)) })
}

/// The pairings of a left input with a right input, in the order the C++ tries them.
const PAIRINGS: [(usize, usize); 4] = [(0, 2), (0, 3), (1, 2), (1, 3)];

/// Port of `RuleBxor2NotEqual`: `V ^^ W  =>  V != W`.
pub(super) fn bxor_2_notequal(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    fd.op_set_opcode(op, IntNotequal);
    Ok(1)
}

/// Port of `RuleNotDistribute`: `!(V && W)  =>  !V || !W`, and for OR.
pub(super) fn not_distribute(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let Some(compop) = def(fd, inp(fd, op, 0)?) else { return Ok(0) };
    let opc = match code(fd, compop) {
        BoolAnd => BoolOr,
        BoolOr => BoolAnd,
        _ => return Ok(0),
    };
    let (a, b) = (inp(fd, compop, 0)?, inp(fd, compop, 1)?);
    let n1 = op_bool_negate(fd, a, op)?;
    let n2 = op_bool_negate(fd, b, op)?;
    fd.op_set_opcode(op, opc);
    fd.op_set_input(op, n1, 0)?;
    fd.op_insert_input(op, n2, 1)?;
    Ok(1)
}

/// Port of `RuleBooleanUndistribute`: `A && B != A && C  =>  A && (B != C)` and its variants.
pub(super) fn boolean_undistribute(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let Some((opc0, opc1, vns)) = two_logic_ops(fd, op)? else { return Ok(0) };
    let mut flipped = [opc0 == BoolOr, opc0 == BoolOr, opc1 == BoolOr, opc1 == BoolOr];
    let mut central_equal = (code(fd, op) == IntEqual) ^ (opc0 == BoolOr) ^ (opc1 == BoolOr);
    let mut found = None;
    for (l, r) in PAIRINGS {
        match evaluate(fd, vns[l], vns[r], 1)? {
            Match::Same => {}
            Match::Complementary => flipped[r] = !flipped[r],
            Match::Uncorrelated => continue,
        }
        found = Some((l, r));
        break;
    }
    let Some((l, r)) = found else { return Ok(0) };
    if flipped[l] != flipped[r] {
        return Ok(0);
    }
    let combine = if central_equal {
        flipped[l] = !flipped[l];
        BoolOr
    } else {
        BoolAnd
    };
    let mut final_a = vns[l];
    if flipped[l] {
        final_a = op_bool_negate(fd, final_a, op)?;
    }
    central_equal ^= flipped[1 - l] ^ flipped[5 - r];
    let eq = if central_equal { IntEqual } else { IntNotequal };
    let tmp = insert_new(fd, eq, op_addr(fd, op), 1, &[vns[1 - l], vns[5 - r]], op)?;
    fd.op_set_opcode(op, combine);
    fd.op_set_input(op, tmp, 1)?;
    fd.op_set_input(op, final_a, 0)?;
    Ok(1)
}

/// Port of `RuleBooleanDedup`: `(A && B) || (A && C)  =>  A && (B || C)` and its variants.
pub(super) fn boolean_dedup(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let Some((opc0, opc1, vns)) = two_logic_ops(fd, op)? else { return Ok(0) };
    let mut found = None;
    for (l, r) in PAIRINGS {
        let m = evaluate(fd, vns[l], vns[r], 1)?;
        if m != Match::Uncorrelated {
            found = Some((l, r, m == Match::Complementary));
            break;
        }
    }
    let Some((l, r, isflipped)) = found else { return Ok(0) };
    let (left_a, right_a, left_o, right_o) = (vns[l], vns[r], vns[1 - l], vns[5 - r]);
    let central = code(fd, op);
    let (final_a, final_opc, bc_opc) = if isflipped {
        if central == opc0 && central == opc1 {
            // A && B && !A && C is false; A || B || !A || C is true
            fd.op_set_opcode(op, Copy);
            fd.op_remove_input(op, 1);
            let c = fd.new_constant(1, u64::from(central == BoolOr));
            fd.op_set_input(op, c, 0)?;
            return Ok(1);
        }
        if central != BoolOr || opc0 == opc1 {
            return Ok(0);
        }
        (if opc0 == BoolOr { left_a } else { right_a }, BoolOr, BoolOr)
    } else if central == opc0 && central == opc1 {
        (left_a, central, central)
    } else if opc0 == opc1 {
        (left_a, opc0, central)
    } else {
        return Ok(0);
    };
    let tmp = insert_new(fd, bc_opc, op_addr(fd, op), 1, &[left_o, right_o], op)?;
    fd.op_set_opcode(op, final_opc);
    fd.op_set_input(op, final_a, 0)?;
    fd.op_set_input(op, tmp, 1)?;
    Ok(1)
}

/// Port of `RuleBooleanNegate`: `V == false  =>  !V`, `V == true  =>  V`, and for `!=`.
pub(super) fn boolean_negate(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let (subbool, constvn) = (inp(fd, op, 0)?, inp(fd, op, 1)?);
    if !is_const(fd, constvn) {
        return Ok(0);
    }
    let val = off(fd, constvn);
    if val > 1 {
        return Ok(0);
    }
    let negate = (code(fd, op) == IntNotequal) ^ (val == 0);
    if !is_boolean_value(fd, subbool) {
        return Ok(0);
    }
    fd.op_remove_input(op, 1);
    fd.op_set_input(op, subbool, 0)?;
    fd.op_set_opcode(op, if negate { BoolNegate } else { Copy });
    Ok(1)
}

/// `RuleBoolZext`, the form `(zext(V) * -1) & (zext(W) * -1)  =>  zext(V && W) * -1`.
fn bool_zext_logic(
    fd: &mut Funcdata,
    bool1: VarnodeId,
    multop1: OpId,
    actionop: OpId,
    opc: Opcode,
    size: u32,
) -> Result<i32> {
    let (a0, a1) = (inp(fd, actionop, 0)?, inp(fd, actionop, 1)?);
    let other = if def(fd, a0) == Some(multop1) { a1 } else { a0 };
    let Some(multop2) = def_opc(fd, other, IntMult) else { return Ok(0) };
    let c2 = inp(fd, multop2, 1)?;
    let coeff = off(fd, c2);
    if !is_const(fd, c2) || coeff != calc_mask(size) {
        return Ok(0);
    }
    let Some(zextop2) = def_opc(fd, inp(fd, multop2, 0)?, IntZext) else { return Ok(0) };
    let bool2 = inp(fd, zextop2, 0)?;
    if !is_boolean_value(fd, bool2) {
        return Ok(0);
    }
    let addr = op_addr(fd, actionop);
    let newres = insert_new(fd, opc, addr, 1, &[bool1, bool2], actionop)?;
    let newzout = insert_new(fd, IntZext, addr, size, &[newres], actionop)?;
    fd.op_set_opcode(actionop, IntMult);
    fd.op_set_input(actionop, newzout, 0)?;
    let c = fd.new_constant(size, coeff);
    fd.op_set_input(actionop, c, 1)?;
    Ok(1)
}

/// Port of `RuleBoolZext`: arithmetic on `zext(V) * -1` for a boolean `V`.
pub(super) fn bool_zext(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let bool1 = inp(fd, op, 0)?;
    if !is_boolean_value(fd, bool1) {
        return Ok(0);
    }
    let zout = out(fd, op)?;
    let Some(multop1) = lone_descend(fd, zout).filter(|&m| code(fd, m) == IntMult) else { return Ok(0) };
    let c1 = inp(fd, multop1, 1)?;
    let coeff = off(fd, c1);
    if !is_const(fd, c1) || coeff != calc_mask(sz(fd, c1)) {
        return Ok(0);
    }
    let mout = out(fd, multop1)?;
    let size = sz(fd, mout);
    let Some(actionop) = lone_descend(fd, mout) else { return Ok(0) };
    let opc = match code(fd, actionop) {
        IntAdd => {
            if !const_match(fd, inp(fd, actionop, 1)?, 1) {
                return Ok(0);
            }
            let vn = op_bool_negate(fd, bool1, op)?;
            fd.op_set_input(op, vn, 0)?;
            fd.op_remove_input(actionop, 1);
            fd.op_set_opcode(actionop, Copy);
            fd.op_set_input(actionop, zout, 0)?;
            return Ok(1);
        }
        IntEqual | IntNotequal => {
            let c = inp(fd, actionop, 1)?;
            if !is_const(fd, c) {
                return Ok(0);
            }
            let val = match off(fd, c) {
                v if v == coeff => 1,
                0 => 0,
                _ => return Ok(0),
            };
            fd.op_set_input(actionop, bool1, 0)?;
            let nc = fd.new_constant(1, val);
            fd.op_set_input(actionop, nc, 1)?;
            return Ok(1);
        }
        IntAnd => BoolAnd,
        IntOr => BoolOr,
        IntXor => BoolXor,
        _ => return Ok(0),
    };
    bool_zext_logic(fd, bool1, multop1, actionop, opc, size)
}

/// Port of `RuleLogic2Bool`: `V & W  =>  V && W` for booleans, and for OR and XOR.
pub(super) fn logic_2_bool(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    if !is_boolean_value(fd, inp(fd, op, 0)?) {
        return Ok(0);
    }
    let in1 = inp(fd, op, 1)?;
    if is_const(fd, in1) {
        if off(fd, in1) > 1 {
            return Ok(0);
        }
    } else if !is_boolean_value(fd, in1) {
        return Ok(0);
    }
    let opc = match code(fd, op) {
        IntAnd => BoolAnd,
        IntOr => BoolOr,
        IntXor => BoolXor,
        _ => return Ok(0),
    };
    fd.op_set_opcode(op, opc);
    Ok(1)
}

/// Port of `RuleCondNegate`: a flipped CBRANCH gets its flip into the condition, or a
/// BOOL_NEGATE in front of it (`opFlipCondition`).
pub(super) fn cond_negate(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    if !fd.op(op).flags.has(OpFlags::BOOLEAN_FLIP) {
        return Ok(0);
    }
    if op_normalize_flip(fd, op)? {
        return Ok(1);
    }
    let vn = inp(fd, op, 1)?;
    let outvn = op_bool_negate(fd, vn, op)?;
    fd.op_set_input(op, outvn, 1)?;
    flip_flag(fd, op, OpFlags::BOOLEAN_FLIP);
    flip_flag(fd, op, OpFlags::FALLTHRU_TRUE);
    Ok(1)
}

/// Port of `RuleBoolNegate`: `!(V == W)  =>  V != W` when every reader of the comparison
/// negates it.
pub(super) fn bool_negate(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let vn = inp(fd, op, 0)?;
    let Some(flip_op) = def(fd, vn) else { return Ok(0) };
    let readers = fd.vn(vn).descend.to_vec();
    if readers.iter().any(|&d| code(fd, d) != BoolNegate) {
        return Ok(0);
    }
    let Some((opc, reorder)) = boolean_flip(code(fd, flip_op)) else { return Ok(0) };
    fd.op_set_opcode(flip_op, opc);
    if reorder {
        fd.op_swap_input(flip_op, 0, 1);
    }
    for d in readers {
        fd.op_set_opcode(d, Copy);
    }
    Ok(1)
}
