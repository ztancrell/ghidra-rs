//! The rules on booleans (stage R2): `RuleBxor2NotEqual`, `RuleNotDistribute`,
//! `RuleBooleanUndistribute`, `RuleBooleanDedup`, `RuleBooleanNegate`, `RuleBoolZext`,
//! `RuleLogic2Bool`, `RuleCondNegate`, `RuleBoolNegate` (ruleaction.cc), with `BooleanMatch`
//! (expression.cc), `Funcdata::opBoolNegate`, `opNormalizeFlip`, `opFlipCondition` (which flips `boolean_flip` only)
//! (funcdata_op.cc) and the boolean flips of the opcodes (`TypeOp::getBooleanFlip`).

use super::*;
use crate::decomp::opcode::is_bool_output;
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

/// `RuleConditionalMove::checkBoolean`: the boolean `vn` holds (itself, or the constant 0 or 1
/// it is a COPY of).
fn cmove_check_boolean(fd: &Funcdata, vn: VarnodeId) -> Option<VarnodeId> {
    let d = def(fd, vn)?;
    if is_bool_output(code(fd, d)) {
        return Some(vn);
    }
    if code(fd, d) == Copy {
        let c = fd.op(d).ins[0];
        if is_const(fd, c) && fd.vn(c).offset & !1 == 0 {
            return Some(c);
        }
    }
    None
}

/// `RuleConditionalMove::gatherExpression`: whether the expression making `vn` can move out of
/// `branch` (its ops there, at most four, go to `ops`).
fn cmove_gather(fd: &Funcdata, vn: VarnodeId, ops: &mut Vec<OpId>, root: BlockId, branch: BlockId) -> bool {
    let v = fd.vn(vn);
    if v.is_constant() {
        return true;
    }
    if v.is_free() || v.has(VnFlags::ADDRTIED) {
        return false;
    }
    if root == branch {
        return true;
    }
    let Some(d) = v.def else { return true };
    if fd.op(d).parent != Some(branch) {
        return true;
    }
    ops.push(d);
    let mut pos = 0;
    while pos < ops.len() {
        let op = ops[pos];
        pos += 1;
        let o = fd.op(op);
        // getEvalType() == special
        if !o.opc.is_unary_or_binary() && !matches!(o.opc, Ptradd | Insert | Zpull | Spull) {
            return false;
        }
        for &in0 in &o.ins {
            let iv = fd.vn(in0);
            if iv.is_free() && !iv.is_constant() {
                return false;
            }
            let Some(dd) = iv.def else { continue };
            if fd.op(dd).parent == Some(branch) {
                if iv.has(VnFlags::ADDRTIED) || lone_descend(fd, in0) != Some(op) || ops.len() >= 4 {
                    return false;
                }
                ops.push(dd);
            }
        }
    }
    true
}

/// `RuleConditionalMove::constructBool`: the expression of `ops` cloned before `insertop`.
fn cmove_construct(fd: &mut Funcdata, vn: VarnodeId, insertop: OpId, ops: &mut [OpId]) -> Result<VarnodeId> {
    if ops.is_empty() {
        return Ok(vn);
    }
    ops.sort_by_key(|&o| fd.op(o).order);
    crate::decomp::returnsplit::clone_expression(fd, ops, insertop)
}

/// Port of `RuleConditionalMove`: a MULTIEQUAL of two booleans chosen by a CBRANCH becomes a
/// boolean expression of the condition.
pub(super) fn conditional_move(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    if fd.op(op).ins.len() != 2 {
        return Ok(0);
    }
    let (in0, in1) = (inp(fd, op, 0)?, inp(fd, op, 1)?);
    let Some(bool0) = cmove_check_boolean(fd, in0) else { return Ok(0) };
    let Some(bool1) = cmove_check_boolean(fd, in1) else { return Ok(0) };
    let Some(bb) = fd.op(op).parent else { return Ok(0) };
    // the block the two paths split at
    let root_of = |inblock: BlockId| -> Option<BlockId> {
        let b = fd.blocks.block(inblock);
        if b.outs.len() != 1 {
            return Some(inblock);
        }
        (b.ins.len() == 1).then(|| b.ins[0].point)
    };
    let (inblock0, inblock1) = (fd.blocks.block(bb).ins[0].point, fd.blocks.block(bb).ins[1].point);
    let (Some(root0), Some(root1)) = (root_of(inblock0), root_of(inblock1)) else { return Ok(0) };
    if root0 != root1 {
        return Ok(0);
    }
    let Some(&cbranch) = fd.blocks.block(root0).ops.last() else { return Ok(0) };
    if code(fd, cbranch) != Cbranch {
        return Ok(0);
    }
    let (mut list0, mut list1) = (Vec::new(), Vec::new());
    if !cmove_gather(fd, bool0, &mut list0, root0, inblock0) || !cmove_gather(fd, bool1, &mut list1, root0, inblock1) {
        return Ok(0);
    }
    let true_out = fd.blocks.block(root0).outs[1].point;
    let mut path0istrue = if root0 != inblock0 { true_out == inblock0 } else { true_out != inblock1 };
    if fd.op(cbranch).flags.has(OpFlags::BOOLEAN_FLIP) {
        path0istrue = !path0istrue;
    }
    let cond = inp(fd, cbranch, 1)?;
    if !is_const(fd, bool0) && !is_const(fd, bool1) {
        // one input is the condition itself: an AND or an OR with the other
        let (same, mut andorselect, first) = if inblock0 == root0 {
            (in0, path0istrue, true)
        } else if inblock1 == root0 {
            (in1, !path0istrue, false)
        } else {
            return Ok(0);
        };
        if cond != same {
            let Some(negop) = def(fd, cond) else { return Ok(0) };
            if code(fd, negop) != BoolNegate || fd.op(negop).ins[0] != same {
                return Ok(0);
            }
            andorselect = !andorselect;
        }
        fd.op_uninsert(op);
        fd.op_set_opcode(op, if andorselect { BoolOr } else { BoolAnd });
        fd.op_insert_begin(op, bb);
        let (firstvn, secondvn) = if first {
            let a = cmove_construct(fd, bool0, op, &mut list0)?;
            (a, cmove_construct(fd, bool1, op, &mut list1)?)
        } else {
            let a = cmove_construct(fd, bool1, op, &mut list1)?;
            (a, cmove_construct(fd, bool0, op, &mut list0)?)
        };
        fd.op_set_input(op, firstvn, 0)?;
        fd.op_set_input(op, secondvn, 1)?;
        return Ok(1);
    }
    // below here some change is made
    fd.op_uninsert(op);
    let sz = fd.vn(out(fd, op)?).size;
    let (c0, c1) = (fd.vn(bool0).offset, fd.vn(bool1).offset);
    if is_const(fd, bool0) && is_const(fd, bool1) {
        fd.op_remove_input(op, 1);
        if c0 == c1 {
            fd.op_set_opcode(op, Copy);
            let c = fd.new_constant(sz, c0);
            fd.op_set_input(op, c, 0)?;
            fd.op_insert_begin(op, bb);
        } else {
            let needcomplement = (c0 == 0) == path0istrue;
            if sz == 1 {
                fd.op_set_opcode(op, if needcomplement { BoolNegate } else { Copy });
                fd.op_insert_begin(op, bb);
                fd.op_set_input(op, cond, 0)?;
            } else {
                fd.op_set_opcode(op, IntZext);
                fd.op_insert_begin(op, bb);
                let boolvn = if needcomplement { op_bool_negate(fd, cond, op)? } else { cond };
                fd.op_set_input(op, boolvn, 0)?;
            }
        }
        return Ok(1);
    }
    // exactly one input is a constant: the condition ANDed or ORed with the other
    let (cval, needcomplement, body, list) = if is_const(fd, bool0) {
        (c0, path0istrue != (c0 != 0), bool1, &mut list1)
    } else {
        (c1, path0istrue == (c1 != 0), bool0, &mut list0)
    };
    fd.op_set_opcode(op, if cval != 0 { BoolOr } else { BoolAnd });
    fd.op_insert_begin(op, bb);
    let boolvn = if needcomplement { op_bool_negate(fd, cond, op)? } else { cond };
    let bodyvn = cmove_construct(fd, body, op, list)?;
    fd.op_set_input(op, boolvn, 0)?;
    fd.op_set_input(op, bodyvn, 1)?;
    Ok(1)
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

/// `BooleanExpressionMatch::verifyCondition`'s test of two CBRANCH conditions: the same or
/// complementary, to its `maxDepth` of 1.
pub(crate) fn correlated(fd: &Funcdata, vn1: VarnodeId, vn2: VarnodeId) -> Result<bool> {
    Ok(evaluate(fd, vn1, vn2, 1)? != Match::Uncorrelated)
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
    let Some(multop2) = def_with(fd, other, IntMult) else { return Ok(0) };
    let c2 = inp(fd, multop2, 1)?;
    let coeff = off(fd, c2);
    if !is_const(fd, c2) || coeff != calc_mask(size) {
        return Ok(0);
    }
    let Some(zextop2) = def_with(fd, inp(fd, multop2, 0)?, IntZext) else { return Ok(0) };
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

/// `RuleOrPredicate::MultiPredicate` after `discoverZeroSlot`: a MULTIEQUAL one of whose two
/// inputs is a COPY of zero.
#[derive(Clone, Copy)]
struct ZeroSet {
    op: OpId,
    zero_slot: usize,
    /// the value set on the other path
    other_vn: VarnodeId,
}

/// The rest of `MultiPredicate`, after `discoverCbranch`.
#[derive(Clone, Copy)]
struct ZeroCond {
    /// the last block of the path setting zero
    zero_block: BlockId,
    /// the block whose CBRANCH decides whether zero is set
    cond_block: BlockId,
    cbranch: OpId,
}

/// `MultiPredicate::discoverZeroSlot`.
fn orpred_zero_slot(fd: &Funcdata, vn: VarnodeId) -> Option<ZeroSet> {
    let op = def(fd, vn)?;
    let o = fd.op(op);
    if o.opc != Multiequal || o.ins.len() != 2 {
        return None;
    }
    for zero_slot in 0..2 {
        let Some(copyop) = def(fd, o.ins[zero_slot]) else { continue };
        if code(fd, copyop) != Copy {
            continue;
        }
        let zerovn = fd.op(copyop).ins[0];
        if !is_const(fd, zerovn) || off(fd, zerovn) != 0 {
            continue;
        }
        let other_vn = o.ins[1 - zero_slot];
        return (!fd.vn(other_vn).is_free()).then_some(ZeroSet { op, zero_slot, other_vn });
    }
    None
}

/// `MultiPredicate::discoverCbranch`.
fn orpred_cbranch(fd: &Funcdata, z: &ZeroSet) -> Option<ZeroCond> {
    let base = fd.blocks.block(fd.op(z.op).parent?);
    let zero_block = base.ins[z.zero_slot].point;
    let other_block = base.ins[1 - z.zero_slot].point;
    let (zb, ob) = (fd.blocks.block(zero_block), fd.blocks.block(other_block));
    let cond_block = match zb.outs.len() {
        1 if zb.ins.len() == 1 => zb.ins[0].point,
        2 => zero_block,
        _ => return None,
    };
    if fd.blocks.block(cond_block).outs.len() != 2 {
        return None;
    }
    let other_ok = match ob.outs.len() {
        1 => ob.ins.len() == 1 && ob.ins[0].point == cond_block,
        2 => other_block == cond_block,
        _ => false,
    };
    if !other_ok {
        return None;
    }
    let &cbranch = fd.blocks.block(cond_block).ops.last()?;
    (code(fd, cbranch) == Cbranch).then_some(ZeroCond { zero_block, cond_block, cbranch })
}

/// `MultiPredicate::discoverPathIsTrue`: the path setting zero is the true path out of the
/// condition block.
fn orpred_path_is_true(fd: &Funcdata, z: &ZeroSet, c: &ZeroCond) -> bool {
    let outs = &fd.blocks.block(c.cond_block).outs;
    if outs[1].point == c.zero_block {
        true
    } else if outs[0].point == c.zero_block {
        false
    } else {
        // the condition block is the zero block
        Some(outs[1].point) == fd.op(z.op).parent
    }
}

/// `MultiPredicate::discoverConditionalZero`: the CBRANCH compares `vn` with zero; the path
/// flag adjusted for the comparison, none without that form.
fn orpred_conditional_zero(fd: &Funcdata, c: &ZeroCond, vn: VarnodeId, mut path_is_true: bool) -> Option<bool> {
    let compareop = def(fd, fd.op(c.cbranch).ins[1])?;
    match code(fd, compareop) {
        IntNotequal => path_is_true = !path_is_true,
        IntEqual => {}
        _ => return None,
    }
    let (a1, a2) = (fd.op(compareop).ins[0], fd.op(compareop).ins[1]);
    let zerovn = if a1 == vn {
        a2
    } else if a2 == vn {
        a1
    } else {
        return None;
    };
    if !is_const(fd, zerovn) || off(fd, zerovn) != 0 {
        return None;
    }
    if fd.op(c.cbranch).flags.has(OpFlags::BOOLEAN_FLIP) {
        path_is_true = !path_is_true;
    }
    Some(path_is_true)
}

/// `RuleOrPredicate::checkSingle`: `vn | (vn == 0 ? other : 0)`.
fn orpred_check_single(fd: &mut Funcdata, vn: VarnodeId, z: ZeroSet, op: OpId) -> Result<i32> {
    if fd.vn(vn).is_free() {
        return Ok(0);
    }
    let Some(c) = orpred_cbranch(fd, &z) else { return Ok(0) };
    let multi_out = out(fd, z.op)?;
    if lone_descend(fd, multi_out) != Some(op) {
        return Ok(0); // the MULTIEQUAL is rewritten, so this must be its only use
    }
    let path = orpred_path_is_true(fd, &z, &c);
    // the true condition (vn == 0) must not go to the zero set
    if orpred_conditional_zero(fd, &c, vn, path) != Some(false) {
        return Ok(0);
    }
    fd.op_set_input(z.op, vn, z.zero_slot)?;
    fd.op_remove_input(op, 1);
    fd.op_set_opcode(op, Copy);
    fd.op_set_input(op, multi_out, 0)?;
    Ok(1)
}

/// Port of `RuleOrPredicate` (condexe.cc): an OR or XOR of two values, each zero down one path
/// of the same condition, becomes one MULTIEQUAL.
pub(super) fn or_predicate(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let (in0, in1) = (inp(fd, op, 0)?, inp(fd, op, 1)?);
    let (b0, b1) = match (orpred_zero_slot(fd, in0), orpred_zero_slot(fd, in1)) {
        (None, None) => return Ok(0),
        (None, Some(b1)) => return orpred_check_single(fd, in0, b1, op),
        (Some(b0), None) => return orpred_check_single(fd, in1, b0, op),
        (Some(b0), Some(b1)) => (b0, b1),
    };
    let Some(c0) = orpred_cbranch(fd, &b0) else { return Ok(0) };
    let Some(c1) = orpred_cbranch(fd, &b1) else { return Ok(0) };
    if c0.cond_block == c1.cond_block {
        if c0.zero_block == c1.zero_block {
            return Ok(0); // the zero sets must be along different paths
        }
    } else {
        // the CBRANCHs share a condition, and the zero sets have complementary paths
        let m = evaluate(fd, inp(fd, c0.cbranch, 1)?, inp(fd, c1.cbranch, 1)?, 1)?;
        if m == Match::Uncorrelated {
            return Ok(0);
        }
        let flip = (m == Match::Complementary)
            ^ fd.op(c0.cbranch).flags.has(OpFlags::BOOLEAN_FLIP)
            ^ fd.op(c1.cbranch).flags.has(OpFlags::BOOLEAN_FLIP);
        let both = orpred_path_is_true(fd, &b0, &c0) == orpred_path_is_true(fd, &b1, &c1);
        if both != flip {
            return Ok(0); // one path hits both zero sets
        }
    }
    let order = crate::decomp::merge::compare_order(fd, b0.op, b1.op);
    if order == 0 {
        return Ok(0);
    }
    // the later MULTIEQUAL's block, and whether branch0's non-zero value flows through slot 0
    let (later, slot0_sets_branch0) = if order < 0 { (b1.op, b1.zero_slot == 0) } else { (b0.op, b0.zero_slot == 1) };
    let Some(final_block) = fd.op(later).parent else { return Ok(0) };
    let new_multi = fd.new_op(Multiequal, fd.blocks.block(final_block).get_start());
    let (first, second) = if slot0_sets_branch0 { (b0.other_vn, b1.other_vn) } else { (b1.other_vn, b0.other_vn) };
    fd.op_set_input(new_multi, first, 0)?;
    fd.op_set_input(new_multi, second, 1)?;
    let newvn = uniq_out(fd, fd.vn(b0.other_vn).size, new_multi)?;
    fd.op_insert_begin(new_multi, final_block);
    fd.op_remove_input(op, 1);
    fd.op_set_input(op, newvn, 0)?;
    fd.op_set_opcode(op, Copy);
    Ok(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `x <opc> c` or `c <opc> x` on the shared varnode `x`.
    fn cmp(fd: &mut Funcdata, x: VarnodeId, opc: Opcode, c: u64, const_first: bool) -> OpId {
        let op = fd.new_op(opc, 0x1000);
        let k = fd.new_constant(4, c);
        let (a, b) = if const_first { (k, x) } else { (x, k) };
        fd.op_set_input(op, a, 0).unwrap();
        fd.op_set_input(op, b, 1).unwrap();
        op
    }

    #[test]
    fn same_op_complement_table() {
        // `x < c1` against `c2 < x` is complementary when c2 + 1 == c1, but for the wrap corners
        let cases = [
            (IntLess, 5, 4, true),
            (IntLess, 5, 5, false),
            (IntLess, 0, 0xffff_ffff_ffff_ffff, false), // unsigned corner: val2 == 0
            (IntSless, 5, 4, true),
            (IntSless, 0x8000_0000, 0x7fff_ffff, false), // signed corner: crosses the minimum
            (IntEqual, 5, 4, false),
        ];
        for (opc, c1, c2, want) in cases {
            let mut fd = Funcdata::new(0x1000);
            let d = fd.new_op(Copy, 0x1000);
            let x = fd.new_varnode_out(4, Space::Sleigh(1), 0x10, d);
            let op1 = cmp(&mut fd, x, opc, c1, false);
            let op2 = cmp(&mut fd, x, opc, c2, true);
            assert_eq!(same_op_complement(&fd, op1, op2).unwrap(), want, "{opc:?} {c1:#x} {c2:#x}");
        }
    }

    #[test]
    fn boolean_flip_table() {
        for opc in [IntEqual, IntNotequal, IntSless, IntSlessequal, IntLess, IntLessequal, FloatEqual, FloatLess] {
            let (flip, reorder) = boolean_flip(opc).unwrap();
            assert_eq!(boolean_flip(flip), Some((opc, reorder)), "{opc:?}");
        }
        assert_eq!(boolean_flip(BoolNegate), Some((Copy, false)));
        assert_eq!(boolean_flip(IntAdd), None);
    }
}
