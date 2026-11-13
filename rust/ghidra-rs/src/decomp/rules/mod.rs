//! Rule pools: port of `ActionPool` (action.cc) and the rules of stage R1 (ruleaction.cc:
//! copies, constants, arithmetic), with the helpers they use from funcdata_op.cc,
//! expression.cc and op.cc. Also the main loop's `ActionNonzeroMask` (group `analysis`, on
//! once the R1 rules are).
//!
//! The pool table [`OPPOOL1`] lists the ported rules of `oppool1` in the C++ order; a rule not
//! listed is switched off on the reference side by the check (`rust/tools/corpus/r1-options.txt`).
//! x86 is little-endian, so the big-endian address arithmetic of the rules is left out.

use std::collections::HashSet;

use super::block::BlockId;
use super::emulate::{eval_binary, eval_unary};
use super::op::{OpFlags, OpId};
use super::opcode::Opcode;
use super::rangeutil::calc_mask;
use super::varnode::{Space, VarnodeId, VnFlags};
use super::{err, stdsort, Arch, Funcdata, LowlevelError, Result};

/// A rule's `applyOp`: the changes it made to the function at `op`.
pub(crate) type RuleFn = fn(&mut Funcdata, OpId, &Arch) -> Result<i32>;

/// One rule: its name (`togglerule`), its group, the opcodes it is tried on (`getOpList`).
#[derive(Debug)]
pub(crate) struct Rule {
    pub(crate) name: &'static str,
    pub(crate) group: &'static str,
    ops: &'static [Opcode],
    apply: RuleFn,
}

const fn r(name: &'static str, group: &'static str, ops: &'static [Opcode], apply: RuleFn) -> Rule {
    Rule { name, group, ops, apply }
}

use Opcode::*;

/// The ported rules of `oppool1`, in `universalAction`'s order.
#[rustfmt::skip]
pub(crate) const OPPOOL1: &[Rule] = &[
    r("earlyremoval", "deadcode", &[
        Copy, Load, Callother, IntEqual, IntNotequal, IntSless, IntSlessequal, IntLess, IntLessequal,
        IntZext, IntSext, IntAdd, IntSub, IntCarry, IntScarry, IntSborrow, Int2comp, IntNegate, IntXor,
        IntAnd, IntOr, IntLeft, IntRight, IntSright, IntMult, IntDiv, IntSdiv, IntRem, IntSrem,
        BoolNegate, BoolXor, BoolAnd, BoolOr, FloatEqual, FloatNotequal, FloatLess, FloatLessequal,
        FloatNan, FloatAdd, FloatDiv, FloatMult, FloatSub, FloatNeg, FloatAbs, FloatSqrt,
        FloatInt2float, FloatFloat2float, FloatTrunc, FloatCeil, FloatFloor, FloatRound,
        Multiequal, Piece, Subpiece, Cast, Ptradd, Ptrsub, Segmentop, Cpoolref, New, Insert, Zpull,
        Popcount, Lzcount, Spull], early_removal),
    r("termorder", "analysis", &[
        IntEqual, IntNotequal, IntAdd, IntCarry, IntScarry, IntXor, IntAnd, IntOr, IntMult, BoolXor,
        BoolAnd, BoolOr, FloatEqual, FloatNotequal, FloatAdd, FloatMult], term_order),
    r("selectcse", "analysis", &[Subpiece, IntSright], select_cse),
    r("collect_terms", "analysis", &[IntAdd], collect_terms),
    r("pullsub_multi", "analysis", &[Subpiece], pullsub_multi),
    r("push_multi", "nodejoin", &[Multiequal], push_multi),
    r("trivialarith", "analysis", &[
        IntNotequal, IntSless, IntLess, BoolXor, BoolAnd, BoolOr, IntEqual, IntSlessequal,
        IntLessequal, IntXor, IntAnd, IntOr, FloatEqual, FloatNotequal, FloatLess, FloatLessequal],
        trivial_arith),
    r("trivialbool", "analysis", &[BoolAnd, BoolOr, BoolXor], trivial_bool),
    r("trivialshift", "analysis", &[IntLeft, IntRight, IntSright], trivial_shift),
    r("identityel", "analysis", &[IntAdd, IntXor, IntOr, BoolXor, BoolOr, IntMult], identity_el),
    r("multicollapse", "analysis", &[Multiequal], multi_collapse),
    r("2comp2mult", "analysis", &[Int2comp], two_comp_2_mult),
    r("sub2add", "analysis", &[IntSub], sub_2_add),
    r("carryelim", "analysis", &[IntCarry], carry_elim),
    r("addmultcollapse", "analysis", &[IntAdd, IntMult], add_mult_collapse),
    r("collapseconstants", "analysis", &[
        IntEqual, IntNotequal, IntSless, IntSlessequal, IntLess, IntLessequal, IntZext, IntSext,
        IntAdd, IntSub, IntCarry, IntScarry, IntSborrow, Int2comp, IntNegate, IntXor, IntAnd, IntOr,
        IntLeft, IntRight, IntSright, IntMult, IntDiv, IntSdiv, IntRem, IntSrem, BoolNegate, BoolXor,
        BoolAnd, BoolOr, FloatEqual, FloatNotequal, FloatLess, FloatLessequal, FloatNan, FloatAdd,
        FloatDiv, FloatMult, FloatSub, FloatNeg, FloatAbs, FloatSqrt, FloatInt2float,
        FloatFloat2float, FloatTrunc, FloatCeil, FloatFloor, FloatRound, Piece, Subpiece, Popcount,
        Lzcount], collapse_constants),
    r("propagatecopy", "analysis", &[Copy], propagate_copy),
    r("negateidentity", "analysis", &[IntNegate], negate_identity),
    r("negatenegate", "analysis", &[IntNegate], negate_negate),
];

/// The rules of `pool` the action keeps (its groups on, not switched off by `togglerule`).
pub(crate) fn select(pool: &'static [Rule], on: impl Fn(&Rule) -> bool) -> Vec<&'static Rule> {
    pool.iter().filter(|rl| on(rl)).collect()
}

/// Port of `ActionPool::apply`: every op in sequence-number order (ops made on the way are
/// visited when they sort after the current one), the dead ones freed (`opDeadAndGone`).
pub(crate) fn pool_apply(fd: &mut Funcdata, arch: &Arch, rules: &[&'static Rule]) -> Result<i32> {
    let mut count = 0;
    let mut cur = fd.op_after(None);
    while let Some(op) = cur {
        let seq = fd.op(op).seq;
        if fd.op(op).is_dead() {
            fd.op_dead_and_gone(op);
        } else {
            count += process_op(fd, arch, rules, op)?;
        }
        cur = fd.op_after(Some(seq));
    }
    Ok(count)
}

/// Port of `ActionPool::processOp`: the rules for the op's opcode in order, from the first
/// again when one changes the opcode.
fn process_op(fd: &mut Funcdata, arch: &Arch, rules: &[&'static Rule], op: OpId) -> Result<i32> {
    let for_opc =
        |opc: Opcode| -> Vec<&'static Rule> { rules.iter().copied().filter(|rl| rl.ops.contains(&opc)).collect() };
    let mut count = 0;
    let mut opc = fd.op(op).opc;
    let mut list = for_opc(opc);
    let mut i = 0;
    while let Some(&rl) = list.get(i) {
        i += 1;
        let res = (rl.apply)(fd, op, arch)?;
        if res > 0 {
            count += res;
            if fd.op(op).is_dead() {
                break;
            }
            if opc != fd.op(op).opc {
                opc = fd.op(op).opc;
                list = for_opc(opc);
                i = 0;
            }
        }
    }
    Ok(count)
}

/// Port of `ActionNonzeroMask::apply` (`Funcdata::calcNZMask`).
pub(crate) fn nonzero_mask(fd: &mut Funcdata, arch: &Arch) -> Result<i32> {
    super::jumptable::calc_nz_mask(fd, arch);
    Ok(0)
}

// ---- helpers on ops and varnodes ----

fn ins(fd: &Funcdata, op: OpId) -> &[VarnodeId] {
    &fd.op(op).ins
}

fn inp(fd: &Funcdata, op: OpId, slot: usize) -> Result<VarnodeId> {
    fd.input(op, slot)
}

fn out(fd: &Funcdata, op: OpId) -> Result<VarnodeId> {
    fd.op(op).out.ok_or_else(|| LowlevelError(format!("op at 0x{:08x} has no output", fd.op(op).seq.addr)))
}

fn def(fd: &Funcdata, vn: VarnodeId) -> Option<OpId> {
    fd.vn(vn).def
}

fn is_const(fd: &Funcdata, vn: VarnodeId) -> bool {
    fd.vn(vn).is_constant()
}

/// `Varnode::loneDescend`.
fn lone_descend(fd: &Funcdata, vn: VarnodeId) -> Option<OpId> {
    match fd.vn(vn).descend[..] {
        [op] => Some(op),
        _ => None,
    }
}

/// `Varnode::getAddr` ordering (`Address::operator<`).
fn addr(fd: &Funcdata, vn: VarnodeId) -> (u32, u64) {
    let v = fd.vn(vn);
    (v.space.index(), v.offset)
}

/// `PcodeOp::getEvalType` is `unary` or `binary`: every op with an `OpBehavior` that folds.
fn is_unary_or_binary(opc: Opcode) -> bool {
    !matches!(
        opc,
        Load | Store
            | Branch
            | Cbranch
            | Branchind
            | Call
            | Callind
            | Callother
            | Return
            | Multiequal
            | Indirect
            | Cast
            | Ptradd
            | Segmentop
            | Cpoolref
            | New
            | Insert
            | Zpull
            | Spull
            | Unused1
    )
}

/// `PcodeOp::isCommutative`.
fn is_commutative(opc: Opcode) -> bool {
    matches!(
        opc,
        IntEqual
            | IntNotequal
            | IntAdd
            | IntCarry
            | IntScarry
            | IntXor
            | IntAnd
            | IntOr
            | IntMult
            | BoolXor
            | BoolAnd
            | BoolOr
            | FloatEqual
            | FloatNotequal
            | FloatAdd
            | FloatMult
    )
}

/// Port of `PcodeOp::getCseHash`.
fn cse_hash(fd: &Funcdata, op: OpId) -> u32 {
    let o = fd.op(op);
    let Some(outvn) = o.out else { return 0 };
    if !is_unary_or_binary(o.opc) || o.opc == Copy {
        return 0;
    }
    let mut hash = (fd.vn(outvn).size << 8) | u32::from(o.opc as u8);
    for &vn in &o.ins {
        hash = hash.rotate_left(8);
        let v = fd.vn(vn);
        hash ^= if v.is_constant() { v.offset as u32 } else { vn.0 };
    }
    hash
}

/// Port of `PcodeOp::isCseMatch`.
fn is_cse_match(fd: &Funcdata, a: OpId, b: OpId) -> bool {
    let (oa, ob) = (fd.op(a), fd.op(b));
    if !is_unary_or_binary(oa.opc) || !is_unary_or_binary(ob.opc) {
        return false;
    }
    let (Some(xa), Some(xb)) = (oa.out, ob.out) else { return false };
    if fd.vn(xa).size != fd.vn(xb).size || oa.opc != ob.opc || oa.opc == Copy || oa.ins.len() != ob.ins.len() {
        return false;
    }
    oa.ins
        .iter()
        .zip(&ob.ins)
        .all(|(&v1, &v2)| v1 == v2 || (is_const(fd, v1) && is_const(fd, v2) && fd.vn(v1).offset == fd.vn(v2).offset))
}

/// `functionalEqualityLevel0` (expression.cc).
fn func_eq0(fd: &Funcdata, a: VarnodeId, b: VarnodeId) -> i32 {
    if a == b {
        return 0;
    }
    let (va, vb) = (fd.vn(a), fd.vn(b));
    if va.size != vb.size {
        return -1;
    }
    if va.is_constant() {
        return if vb.is_constant() && va.offset == vb.offset { 0 } else { -1 };
    }
    if va.is_free() || vb.is_free() {
        return -1;
    }
    1
}

/// Port of `functionalEqualityLevel`: 0 equal, 1 or 2 equal up to that many pairs of inputs
/// (returned), -1 different.
fn func_eq_level(fd: &Funcdata, a: VarnodeId, b: VarnodeId) -> (i32, [Option<VarnodeId>; 2], [Option<VarnodeId>; 2]) {
    let mut r1 = [None; 2];
    let mut r2 = [None; 2];
    let t = func_eq0(fd, a, b);
    if t != 1 {
        return (t, r1, r2);
    }
    let (Some(op1), Some(op2)) = (def(fd, a), def(fd, b)) else { return (-1, r1, r2) };
    let (o1, o2) = (fd.op(op1), fd.op(op2));
    let opc = o1.opc;
    if opc != o2.opc {
        return (-1, r1, r2);
    }
    let mut num = o1.ins.len();
    if num != o2.ins.len() || o1.is_marker() || o2.is_call() {
        return (-1, r1, r2);
    }
    if opc == Load && o1.seq.addr != o2.seq.addr {
        return (-1, r1, r2);
    }
    if num >= 3 {
        if opc != Ptradd || fd.vn(o1.ins[2]).offset != fd.vn(o2.ins[2]).offset {
            return (-1, r1, r2);
        }
        num = 2;
    }
    if num == 0 {
        return (-1, r1, r2);
    }
    for i in 0..num {
        r1[i] = Some(o1.ins[i]);
        r2[i] = Some(o2.ins[i]);
    }
    let g = |r: &[Option<VarnodeId>; 2], i: usize| r[i].unwrap_or(VarnodeId(0));
    let t = func_eq0(fd, g(&r1, 0), g(&r2, 0));
    if t == 0 {
        if num == 1 {
            return (0, r1, r2);
        }
        let t2 = func_eq0(fd, g(&r1, 1), g(&r2, 1));
        if t2 == 0 {
            return (0, r1, r2);
        }
        if t2 < 0 {
            return (-1, r1, r2);
        }
        r1[0] = r1[1];
        r2[0] = r2[1];
        return (1, r1, r2);
    }
    if num == 1 {
        return (t, r1, r2);
    }
    let t2 = func_eq0(fd, g(&r1, 1), g(&r2, 1));
    if t2 == 0 {
        return (t, r1, r2);
    }
    let unmatch = if t == 1 && t2 == 1 { 2 } else { -1 };
    if !is_commutative(opc) {
        return (unmatch, r1, r2);
    }
    let c1 = func_eq0(fd, g(&r1, 0), g(&r2, 1));
    let c2 = func_eq0(fd, g(&r1, 1), g(&r2, 0));
    if c1 == 0 && c2 == 0 {
        return (0, r1, r2);
    }
    if c1 < 0 || c2 < 0 {
        return (unmatch, r1, r2);
    }
    if c1 == 0 {
        r1[0] = r1[1];
        return (1, r1, r2);
    }
    if c2 == 0 {
        r2[0] = r2[1];
        return (1, r1, r2);
    }
    if unmatch == 2 {
        return (2, r1, r2);
    }
    r2.swap(0, 1);
    (2, r1, r2)
}

/// `functionalEquality`.
fn func_equal(fd: &Funcdata, a: VarnodeId, b: VarnodeId) -> bool {
    func_eq_level(fd, a, b).0 == 0
}

/// Port of `BlockBasic::earliestUse`.
fn earliest_use(fd: &Funcdata, bl: BlockId, vn: VarnodeId) -> Option<OpId> {
    let mut res: Option<OpId> = None;
    for &op in fd.vn(vn).descend.iter() {
        if fd.op(op).parent != Some(bl) {
            continue;
        }
        if res.is_none_or(|r| fd.op(op).order < fd.op(r).order) {
            res = Some(op);
        }
    }
    res
}

/// Port of `Funcdata::cseFindInBlock`.
fn cse_find_in_block(fd: &Funcdata, op: OpId, vn: VarnodeId, bl: BlockId, earliest: Option<OpId>) -> Option<OpId> {
    for &res in fd.vn(vn).descend.iter() {
        if res == op || fd.op(res).parent != Some(bl) {
            continue;
        }
        if let Some(e) = earliest {
            if fd.op(e).order < fd.op(res).order {
                continue;
            }
        }
        let (Some(o1), Some(o2)) = (fd.op(op).out, fd.op(res).out) else { continue };
        if func_eq_level(fd, o1, o2).0 == 0 {
            return Some(res);
        }
    }
    None
}

/// Port of `FlowBlock::findCommonBlock`: the nearest block dominating both.
fn find_common_block(fd: &Funcdata, b1: BlockId, b2: BlockId) -> Option<BlockId> {
    let mut up = HashSet::new();
    let mut b = Some(b1);
    while let Some(x) = b {
        up.insert(x);
        b = fd.blocks.block(x).idom;
    }
    let mut b = Some(b2);
    while let Some(x) = b {
        if up.contains(&x) {
            return Some(x);
        }
        b = fd.blocks.block(x).idom;
    }
    None
}

/// Port of `Funcdata::opInsertEnd`: at the end of `bl`, before a final branch or return.
pub(crate) fn op_insert_end(fd: &mut Funcdata, op: OpId, bl: BlockId) {
    let ops = &fd.blocks.block(bl).ops;
    let mut at = ops.len();
    if let Some(&last) = ops.last() {
        let o = fd.op(last);
        if o.is_branch() || o.opc == Return {
            at -= 1;
        }
    }
    fd.op_insert(op, bl, at);
}

/// Port of `Funcdata::cseElimination`: one op computes what both did.
fn cse_elimination(fd: &mut Funcdata, op1: OpId, op2: OpId) -> Result<OpId> {
    let (p1, p2) = (fd.op(op1).parent, fd.op(op2).parent);
    let (Some(b1), Some(b2)) = (p1, p2) else { return err("cseElimination: op outside any block") };
    let replace = if b1 == b2 {
        if fd.op(op1).order < fd.op(op2).order {
            op1
        } else {
            op2
        }
    } else {
        let common = find_common_block(fd, b1, b2).ok_or_else(|| LowlevelError("cse: no common block".into()))?;
        if common == b1 {
            op1
        } else if common == b2 {
            op2
        } else {
            let rep = fd.new_op(fd.op(op1).opc, fd.blocks.block(common).stop);
            let o1 = out(fd, op1)?;
            let (size, space, offset) = (fd.vn(o1).size, fd.vn(o1).space, fd.vn(o1).offset);
            fd.new_varnode_out(size, space, offset, rep);
            for (i, vn) in ins(fd, op1).to_vec().into_iter().enumerate() {
                let v = if is_const(fd, vn) { fd.new_constant(fd.vn(vn).size, fd.vn(vn).offset) } else { vn };
                fd.op_set_input(rep, v, i)?;
            }
            op_insert_end(fd, rep, common);
            rep
        }
    };
    let rout = out(fd, replace)?;
    for o in [op1, op2] {
        if replace != o {
            let ov = out(fd, o)?;
            fd.total_replace(ov, rout)?;
            fd.op_destroy(o);
        }
    }
    Ok(replace)
}

/// `Funcdata::isHeritaged`.
fn is_heritaged(fd: &Funcdata, vn: VarnodeId) -> bool {
    let v = fd.vn(vn);
    fd.heritage.heritaged(v.space, v.offset)
}

/// Port of `Funcdata::cseEliminateList`: the pairs with equal hashes that match are merged;
/// whether any was.
fn cse_eliminate_list(fd: &mut Funcdata, mut list: Vec<(u32, OpId)>) -> Result<bool> {
    list.sort_by_key(|e| e.0);
    let mut any = false;
    for w in 1..list.len() {
        let ((h1, op1), (h2, op2)) = (list[w - 1], list[w]);
        if h1 != h2 || fd.op(op1).is_dead() || fd.op(op2).is_dead() || !is_cse_match(fd, op1, op2) {
            continue;
        }
        let ok = |o: OpId| fd.op(o).out.is_none_or(|v| is_heritaged(fd, v));
        if ok(op1) && ok(op2) {
            cse_elimination(fd, op1, op2)?;
            any = true;
        }
    }
    Ok(any)
}

/// `Funcdata::deadRemovalAllowedSeen` for the space of `vn` (only spaces that do dead code
/// elimination are checked: `AddrSpace::doesDeadcode`).
fn dead_removal_allowed_seen(fd: &mut Funcdata, arch: &Arch, vn: VarnodeId) -> bool {
    match fd.vn(vn).space {
        Space::Sleigh(s) if s != 0 && arch.sleigh.spaces[s as usize].delay.is_some() => {
            let ok = fd.heritage.dead_removal_allowed(arch, s);
            if ok {
                fd.heritage.seen_dead_code(s);
            }
            ok
        }
        // the stack's dead-code delay is its heritage delay, 1
        Space::Stack => fd.heritage.pass() > 1,
        _ => true,
    }
}

// ---- the rules ----

/// Port of `RuleEarlyRemoval`.
fn early_removal(fd: &mut Funcdata, op: OpId, arch: &Arch) -> Result<i32> {
    let o = fd.op(op);
    if o.is_call() || o.flags.has(OpFlags::INDIRECT_SOURCE) {
        return Ok(0);
    }
    let Some(vn) = o.out else { return Ok(0) };
    let v = fd.vn(vn);
    if !v.descend.is_empty() || v.is_auto_live() {
        return Ok(0);
    }
    if !dead_removal_allowed_seen(fd, arch, vn) {
        return Ok(0);
    }
    fd.op_destroy(op);
    Ok(1)
}

/// Port of `RuleTermOrder`: a constant goes to slot 1 (`opSwapInput`).
fn term_order(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let (a, b) = (inp(fd, op, 0)?, inp(fd, op, 1)?);
    if is_const(fd, a) && !is_const(fd, b) {
        fd.op_mut(op).ins.swap(0, 1);
        return Ok(1);
    }
    Ok(0)
}

/// Port of `RuleSelectCse`.
fn select_cse(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let vn = inp(fd, op, 0)?;
    let opc = fd.op(op).opc;
    let list: Vec<(u32, OpId)> = fd
        .vn(vn)
        .descend
        .iter()
        .filter(|&&o| fd.op(o).opc == opc)
        .map(|&o| (cse_hash(fd, o), o))
        .filter(|e| e.0 != 0)
        .collect();
    if list.len() <= 1 {
        return Ok(0);
    }
    Ok(i32::from(cse_eliminate_list(fd, list)?))
}

/// `Varnode::termOrder`: constants last, then by address (looking through a multiply by a
/// constant).
fn term_cmp(fd: &Funcdata, a: VarnodeId, b: VarnodeId) -> i32 {
    match (is_const(fd, a), is_const(fd, b)) {
        (true, true) => 0,
        (true, false) => 1,
        (false, true) => -1,
        (false, false) => {
            let strip = |vn: VarnodeId| match def(fd, vn) {
                Some(d) if fd.op(d).opc == IntMult && fd.op(d).ins.get(1).is_some_and(|&c| is_const(fd, c)) => {
                    fd.op(d).ins[0]
                }
                _ => vn,
            };
            let (x, y) = (addr(fd, strip(a)), addr(fd, strip(b)));
            match x.cmp(&y) {
                std::cmp::Ordering::Less => -1,
                std::cmp::Ordering::Greater => 1,
                std::cmp::Ordering::Equal => 0,
            }
        }
    }
}

/// An `AdditiveEdge`: input `slot` of `op`, under the multiply `mult` if any.
#[derive(Debug, Clone, Copy)]
struct Term {
    op: OpId,
    slot: usize,
    mult: Option<OpId>,
}

/// Port of `TermOrder::collect` and `sortTerms` (`std::sort`).
fn collect_additive(fd: &Funcdata, root: OpId) -> Vec<Term> {
    let mut terms = Vec::new();
    let mut stack = vec![(root, None)];
    while let Some((cur, mult)) = stack.pop() {
        for (i, &vn) in fd.op(cur).ins.iter().enumerate() {
            let term = Term { op: cur, slot: i, mult };
            let Some(sub) = def(fd, vn) else {
                terms.push(term);
                continue;
            };
            if lone_descend(fd, vn).is_none() {
                terms.push(term);
                continue;
            }
            let s = fd.op(sub);
            if s.opc != IntAdd {
                if s.opc == IntMult && s.ins.get(1).is_some_and(|&c| is_const(fd, c)) {
                    if let Some(add) = def(fd, s.ins[0]) {
                        if fd.op(add).opc == IntAdd && fd.op(add).out.is_some_and(|o| lone_descend(fd, o).is_some()) {
                            stack.push((add, Some(sub)));
                            continue;
                        }
                    }
                }
                terms.push(term);
                continue;
            }
            stack.push((sub, mult));
        }
    }
    let vn = |t: &Term| fd.op(t.op).ins[t.slot];
    stdsort::sort(&mut terms, |a, b| term_cmp(fd, vn(a), vn(b)) == -1);
    terms
}

/// `RuleCollectTerms::getMultCoeff`.
fn mult_coeff(fd: &Funcdata, vn: VarnodeId) -> (VarnodeId, u64) {
    if let Some(d) = def(fd, vn) {
        let o = fd.op(d);
        if o.opc == IntMult && o.ins.get(1).is_some_and(|&c| is_const(fd, c)) {
            return (o.ins[0], fd.vn(o.ins[1]).offset);
        }
    }
    (vn, 1)
}

/// Port of `Funcdata::distributeIntMultAdd`.
fn distribute_int_mult_add(fd: &mut Funcdata, op: OpId) -> Result<bool> {
    let addop = def(fd, inp(fd, op, 0)?).ok_or_else(|| LowlevelError("distributeIntMultAdd: no add".into()))?;
    let (v0, v1) = (inp(fd, addop, 0)?, inp(fd, addop, 1)?);
    for v in [v0, v1] {
        if fd.vn(v).is_free() && !is_const(fd, v) {
            return Ok(false);
        }
    }
    let coeff = fd.vn(inp(fd, op, 1)?).offset;
    let sz = fd.vn(out(fd, op)?).size;
    let addr = fd.op(op).seq.addr;
    let uniq = fd.uniq.ok_or_else(|| LowlevelError("no unique space".into()))?;
    let mut newvn = [v0, v1];
    for (i, v) in [v0, v1].into_iter().enumerate() {
        newvn[i] = if is_const(fd, v) {
            let val = coeff.wrapping_mul(fd.vn(v).offset) & calc_mask(sz);
            fd.new_constant(sz, val)
        } else {
            let m = fd.new_op(IntMult, addr);
            let o = fd.new_unique_out(sz, uniq, m);
            fd.op_set_input(m, v, 0)?;
            let c = fd.new_constant(sz, coeff);
            fd.op_set_input(m, c, 1)?;
            fd.op_insert_before(m, op)?;
            o
        };
    }
    fd.op_set_input(op, newvn[0], 0)?;
    fd.op_set_input(op, newvn[1], 1)?;
    fd.op_set_opcode(op, IntAdd);
    Ok(true)
}

/// Port of `RuleCollectTerms`.
fn collect_terms(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
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
                    return Ok(i32::from(distribute_int_mult_add(fd, m)?));
                }
                if let Some(m) = order[i].mult {
                    return Ok(i32::from(distribute_int_mult_add(fd, m)?));
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

/// `RulePullsubMulti::minMaxUse`: the bytes of `vn` its readers use.
fn min_max_use(fd: &Funcdata, vn: VarnodeId) -> (i32, i32) {
    let in_size = fd.vn(vn).size as i32;
    let (mut max, mut min) = (-1, in_size);
    for &op in fd.vn(vn).descend.iter() {
        let o = fd.op(op);
        if o.opc != Subpiece {
            return (in_size - 1, 0);
        }
        let lo = fd.vn(o.ins[1]).offset as i32;
        let hi = lo + o.out.map_or(0, |v| fd.vn(v).size as i32) - 1;
        min = min.min(lo);
        max = max.max(hi);
    }
    (max, min)
}

/// `RulePullsubMulti::replaceDescendants`.
fn replace_descendants(fd: &mut Funcdata, orig: VarnodeId, newvn: VarnodeId, min: i32) -> Result<()> {
    let fail = || err("Could not perform -replaceDescendants-");
    let readers = fd.vn(orig).descend.to_vec();
    for op in readers {
        if fd.op(op).opc != Subpiece {
            return fail();
        }
        let trunc = fd.vn(inp(fd, op, 1)?).offset as i32;
        let out_size = fd.vn(out(fd, op)?).size;
        fd.op_set_input(op, newvn, 0)?;
        let nsize = fd.vn(newvn).size;
        if nsize == out_size {
            if trunc != min {
                return fail();
            }
            fd.op_set_opcode(op, Copy);
            fd.op_remove_input(op, 1);
        } else if nsize > out_size {
            let nt = trunc - min;
            if nt < 0 {
                return fail();
            }
            if nt != trunc {
                let c = fd.new_constant(4, nt as u64);
                fd.op_set_input(op, c, 1)?;
            }
        } else {
            return fail();
        }
    }
    Ok(())
}

/// `RulePullsubMulti::acceptableSize`.
fn acceptable_size(size: i32) -> bool {
    size != 0 && (size >= 8 || matches!(size, 1 | 2 | 4))
}

/// `RulePullsubMulti::findSubpiece`.
fn find_subpiece(fd: &Funcdata, base: VarnodeId, outsize: u32, shift: u64) -> Option<VarnodeId> {
    let b = fd.vn(base);
    for &prev in b.descend.iter() {
        let p = fd.op(prev);
        if p.opc != Subpiece {
            continue;
        }
        let pb = p.parent.map(|bl| fd.blocks.block(bl).index);
        if b.is_input() && pb != Some(0) {
            continue;
        }
        let Some(d) = b.def else { continue };
        if fd.op(d).parent != p.parent {
            continue;
        }
        if p.ins[0] == base && p.out.is_some_and(|o| fd.vn(o).size == outsize) && fd.vn(p.ins[1]).offset == shift {
            return p.out;
        }
    }
    None
}

/// `RulePullsubMulti::buildSubpiece`: a SUBPIECE of `base` right after its definition.
fn build_subpiece(fd: &mut Funcdata, base: VarnodeId, outsize: u32, shift: u32) -> Result<VarnodeId> {
    let b = fd.vn(base).clone();
    let first = *fd.blocks.list.first().ok_or_else(|| LowlevelError("no blocks".into()))?;
    let newaddr = if b.is_input() {
        fd.blocks.block(first).start
    } else {
        let d = b.def.ok_or_else(|| LowlevelError("Undefined pullsub".into()))?;
        fd.op(d).seq.addr
    };
    let mut small = None;
    if b.space == Space::Join {
        let pieces = fd.joins.get(b.offset as usize).cloned().unwrap_or_default();
        if pieces.len() > 1 {
            let mut skip = shift;
            for &(sp, off, size) in pieces.iter().rev() {
                if skip >= size {
                    skip -= size;
                } else {
                    if skip + outsize <= size {
                        small = Some((Space::Sleigh(sp), off + u64::from(skip)));
                    }
                    break;
                }
            }
        }
    } else {
        small = Some((b.space, b.offset + u64::from(shift)));
    }
    let new_op = fd.new_op(Subpiece, newaddr);
    let outvn = match small {
        Some((sp, off)) => fd.new_varnode_out(outsize, sp, off, new_op),
        None => {
            let uniq = fd.uniq.ok_or_else(|| LowlevelError("no unique space".into()))?;
            fd.new_unique_out(outsize, uniq, new_op)
        }
    };
    fd.op_set_input(new_op, base, 0)?;
    let c = fd.new_constant(4, u64::from(shift));
    fd.op_set_input(new_op, c, 1)?;
    match b.def {
        Some(d) if !b.is_input() => fd.op_insert_after(new_op, d)?,
        _ => fd.op_insert_begin(new_op, first),
    }
    Ok(outvn)
}

/// Port of `RulePullsubMulti`. (`isPrecisLo`/`isPrecisHi` are set by the double-precision
/// rules of R5; nothing sets them yet.)
fn pullsub_multi(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let vn = inp(fd, op, 0)?;
    let Some(mult) = def(fd, vn) else { return Ok(0) };
    if fd.op(mult).opc != Multiequal {
        return Ok(0);
    }
    let Some(mbl) = fd.op(mult).parent else { return Ok(0) };
    if (0..fd.blocks.block(mbl).ins.len()).any(|i| fd.blocks.is_loop_in(mbl, i)) {
        return Ok(0);
    }
    let (max, min) = min_max_use(fd, vn);
    let new_size = max - min + 1;
    if max < min || new_size >= fd.vn(vn).size as i32 || !acceptable_size(new_size) {
        return Ok(0);
    }
    if min > 8 {
        return Ok(0);
    }
    let consume = !(if min < 8 { calc_mask(new_size as u32) << (8 * min) } else { 0 });
    for &in_vn in &fd.op(mult).ins {
        if consume & fd.vn(in_vn).consume != 0 {
            if min == 0 {
                if let Some(d) = def(fd, in_vn) {
                    let o = fd.op(d);
                    if matches!(o.opc, IntZext | IntSext) && new_size == fd.vn(o.ins[0]).size as i32 {
                        continue;
                    }
                }
            }
            return Ok(0);
        }
    }
    let v = fd.vn(vn);
    if v.space == Space::Join {
        return err("RulePullsubMulti on a join varnode: Address::renormalize not ported yet");
    }
    let (space, small_off) = (v.space, v.offset + min as u64);
    let mut params = Vec::new();
    for in_vn in fd.op(mult).ins.clone() {
        let sub = match find_subpiece(fd, in_vn, new_size as u32, min as u64) {
            Some(s) => s,
            None => build_subpiece(fd, in_vn, new_size as u32, min as u32)?,
        };
        params.push(sub);
    }
    let new_multi = fd.new_op(Multiequal, fd.op(mult).seq.addr);
    let new_vn = fd.new_varnode_out(new_size as u32, space, small_off, new_multi);
    fd.op_set_all_input(new_multi, &params)?;
    fd.op_insert_begin(new_multi, mbl);
    replace_descendants(fd, vn, new_vn, min)?;
    Ok(1)
}

/// `RulePushMulti::findSubstitute`.
fn find_substitute(fd: &Funcdata, in1: VarnodeId, in2: VarnodeId, bb: BlockId, earliest: Option<OpId>) -> Option<OpId> {
    for &op in fd.vn(in1).descend.iter() {
        let o = fd.op(op);
        if o.parent == Some(bb) && o.opc == Multiequal && o.ins.first() == Some(&in1) && o.ins.get(1) == Some(&in2) {
            return Some(op);
        }
    }
    if in1 == in2 || func_eq_level(fd, in1, in2).0 != 0 {
        return None;
    }
    let (op1, op2) = (def(fd, in1)?, def(fd, in2)?);
    for (i, &vn) in fd.op(op1).ins.iter().enumerate() {
        if is_const(fd, vn) {
            continue;
        }
        if fd.op(op2).ins.get(i) == Some(&vn) {
            return cse_find_in_block(fd, op1, vn, bb, earliest);
        }
    }
    None
}

/// Port of `RulePushMulti`.
fn push_multi(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    if ins(fd, op).len() != 2 {
        return Ok(0);
    }
    let (in1, in2) = (inp(fd, op, 0)?, inp(fd, op, 1)?);
    let (Some(op1), Some(op2)) = (def(fd, in1), def(fd, in2)) else { return Ok(0) };
    if fd.vn(in1).has(VnFlags::SPACEBASE) || fd.vn(in2).has(VnFlags::SPACEBASE) {
        return Ok(0);
    }
    let (res, b1, b2) = func_eq_level(fd, in1, in2);
    if !(0..=1).contains(&res) {
        return Ok(0);
    }
    if fd.op(op1).opc == Subpiece {
        return Ok(0);
    }
    let Some(bl) = fd.op(op).parent else { return Ok(0) };
    let outvn = out(fd, op)?;
    let earliest = earliest_use(fd, bl, outvn);
    if fd.op(op1).opc == Copy {
        if res == 0 {
            return Ok(0);
        }
        let (Some(x), Some(y)) = (b1[0], b2[0]) else { return Ok(0) };
        let Some(sub) = find_substitute(fd, x, y, bl, earliest) else { return Ok(0) };
        let so = out(fd, sub)?;
        fd.total_replace(outvn, so)?;
        fd.op_destroy(op);
        return Ok(1);
    }
    if lone_descend(fd, in1) != Some(op) || lone_descend(fd, in2) != Some(op) {
        return Ok(0);
    }
    fd.op_set_output(op1, outvn)?;
    fd.op_uninsert(op1);
    if res == 1 {
        let (Some(x), Some(y)) = (b1[0], b2[0]) else { return err("push_multi: no unmatched pair") };
        let slot1 = fd.slot_of(op1, x).ok_or_else(|| LowlevelError("push_multi: slot".into()))?;
        let sub = match find_substitute(fd, x, y, bl, earliest) {
            Some(s) => s,
            None => {
                let s = fd.new_op(Multiequal, fd.op(op).seq.addr);
                let (vx, vy) = (fd.vn(x), fd.vn(y));
                if (vx.space, vx.offset) == (vy.space, vy.offset) && !vx.has(VnFlags::ADDRTIED) {
                    let (size, space, offset) = (vx.size, vx.space, vx.offset);
                    fd.new_varnode_out(size, space, offset, s);
                } else {
                    let uniq = fd.uniq.ok_or_else(|| LowlevelError("no unique space".into()))?;
                    fd.new_unique_out(vx.size, uniq, s);
                }
                fd.op_set_input(s, x, 0)?;
                fd.op_set_input(s, y, 1)?;
                fd.op_insert_begin(s, bl);
                s
            }
        };
        let so = out(fd, sub)?;
        fd.op_set_input(op1, so, slot1)?;
        fd.op_insert_after(op1, sub)?;
    } else {
        fd.op_insert_begin(op1, bl);
    }
    fd.op_destroy(op);
    fd.op_destroy(op2);
    Ok(1)
}

/// Port of `RuleTrivialArith`.
fn trivial_arith(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    if ins(fd, op).len() != 2 {
        return Ok(0);
    }
    let (a, b) = (inp(fd, op, 0)?, inp(fd, op, 1)?);
    if a != b {
        let (Some(da), Some(db)) = (def(fd, a), def(fd, b)) else { return Ok(0) };
        if !is_cse_match(fd, da, db) {
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
fn trivial_bool(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
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
fn trivial_shift(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
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
fn identity_el(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
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

/// Port of `RuleMultiCollapse`.
fn multi_collapse(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    if ins(fd, op).iter().any(|&v| !fd.vn(v).is_heritage_known()) {
        return Ok(0);
    }
    let mut func_eq = false;
    let mut nofunc = false;
    let mut matchlist = ins(fd, op).to_vec();
    let mut defcopyr = matchlist.iter().copied().find(|&c| def(fd, c).is_none_or(|d| fd.op(d).opc != Multiequal));
    let opout = out(fd, op)?;
    let mut mark: HashSet<VarnodeId> = HashSet::from([opout]);
    let mut skiplist = vec![opout];
    let mut j = 0;
    while j < matchlist.len() {
        let copyr = matchlist[j];
        j += 1;
        if mark.contains(&copyr) {
            continue;
        }
        match defcopyr {
            None => {
                defcopyr = Some(copyr);
                match def(fd, copyr) {
                    Some(d) if fd.op(d).opc != Multiequal => {}
                    _ => nofunc = true,
                }
            }
            Some(dc) if dc == copyr => {}
            Some(dc) if !nofunc && func_equal(fd, dc, copyr) => func_eq = true,
            _ => match def(fd, copyr) {
                Some(d) if fd.op(d).opc == Multiequal => {
                    skiplist.push(copyr);
                    mark.insert(copyr);
                    matchlist.extend(fd.op(d).ins.iter().copied());
                }
                _ => return Ok(0),
            },
        }
    }
    let Some(dc) = defcopyr else { return Ok(0) };
    for copyr in skiplist {
        let Some(cop) = def(fd, copyr) else { continue };
        if func_eq {
            let bl = fd.op(cop).parent.ok_or_else(|| LowlevelError("multicollapse: dead op".into()))?;
            let earliest = earliest_use(fd, bl, copyr);
            let newop = def(fd, dc).ok_or_else(|| LowlevelError("multicollapse: unwritten".into()))?;
            let substitute = fd
                .op(newop)
                .ins
                .iter()
                .find(|&&v| !is_const(fd, v))
                .and_then(|&v| cse_find_in_block(fd, newop, v, bl, earliest));
            if let Some(s) = substitute {
                let so = out(fd, s)?;
                fd.total_replace(copyr, so)?;
                fd.op_destroy(cop);
            } else {
                let reinsert = fd.op(cop).opc == Multiequal;
                let parms = fd.op(newop).ins.clone();
                fd.op_set_all_input(cop, &parms)?;
                fd.op_set_opcode(cop, fd.op(newop).opc);
                if reinsert {
                    fd.op_uninsert(cop);
                    fd.op_insert_begin(cop, bl);
                }
            }
        } else {
            fd.total_replace(copyr, dc)?;
            fd.op_destroy(cop);
        }
    }
    Ok(1)
}

/// Port of `Rule2Comp2Mult`.
fn two_comp_2_mult(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    fd.op_set_opcode(op, IntMult);
    let size = fd.vn(inp(fd, op, 0)?).size;
    let negone = fd.new_constant(size, calc_mask(size));
    fd.op_insert_input(op, negone, 1)?;
    Ok(1)
}

/// Port of `RuleSub2Add`.
fn sub_2_add(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
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
fn carry_elim(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
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

fn eval2(opc: Opcode, size: u32, a: u64, b: u64) -> Result<u64> {
    eval_binary(opc, size, size, a, b).map_err(|e| LowlevelError(format!("{e:?}")))
}

/// Port of `RuleAddMultCollapse`.
fn add_mult_collapse(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
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
fn collapse_constants(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let o = fd.op(op);
    let Some(outvn) = o.out else { return Ok(0) };
    if o.ins.is_empty() || o.ins.iter().any(|&v| !is_const(fd, v)) || fd.vn(outvn).size > 8 {
        return Ok(0);
    }
    let osize = fd.vn(outvn).size;
    let v0 = fd.vn(o.ins[0]);
    let val = match o.ins[..] {
        _ if is_float(o.opc) => eval_float(fd, op)
            .ok_or_else(|| super::emulate::EmuError::Other(format!("float op {:?} not folded", o.opc))),
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

/// Port of `RulePropagateCopy`.
fn propagate_copy(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let vn = out(fd, op)?;
    let invn = inp(fd, op, 0)?;
    if invn == vn {
        return err("Self-defined varnode");
    }
    if !fd.vn(invn).is_heritage_known() {
        return Ok(0);
    }
    let mut count = 0;
    let readers = fd.vn(vn).descend.to_vec();
    for other in readers {
        let o = fd.op(other);
        // `isReturnCopy`: the flag, or a RETURN (TypeOpReturn has it)
        if o.flags.has(OpFlags::RETURN_COPY) || o.opc == Return {
            continue;
        }
        let Some(slot) = o.ins.iter().position(|&v| v == vn) else { continue };
        if o.is_marker() {
            let iv = fd.vn(invn);
            if iv.is_constant() || fd.vn(vn).has(VnFlags::ADDRFORCE) {
                continue;
            }
            if let Some(oo) = o.out {
                let ov = fd.vn(oo);
                if iv.has(VnFlags::ADDRTIED)
                    && ov.has(VnFlags::ADDRTIED)
                    && (ov.space, ov.offset) != (iv.space, iv.offset)
                {
                    continue;
                }
            }
            // setCopyImmed: the COPY's block is the MULTIEQUAL's input block for this slot
            if let (Multiequal, Some(pb)) = (o.opc, o.parent) {
                let e = &fd.blocks.block(pb).ins[slot];
                let (inbl, rev) = (e.point, e.reverse);
                if fd.op(op).parent == Some(inbl) {
                    fd.blocks.set_immed_copy_edge(inbl, rev);
                    fd.op_mut(other).flags.set(OpFlags::IMMED_COPY);
                }
            }
        }
        fd.op_set_input(other, invn, slot)?;
        count += 1;
    }
    Ok(count)
}

/// Port of `RuleNegateIdentity`.
fn negate_identity(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
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
fn negate_negate(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
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

/// The float ops (`TypeOpFloat*`), folded through `FloatFormat` (IEEE single and double).
fn is_float(opc: Opcode) -> bool {
    matches!(
        opc,
        FloatEqual
            | FloatNotequal
            | FloatLess
            | FloatLessequal
            | FloatNan
            | FloatAdd
            | FloatDiv
            | FloatMult
            | FloatSub
            | FloatNeg
            | FloatAbs
            | FloatSqrt
            | FloatInt2float
            | FloatFloat2float
            | FloatTrunc
            | FloatCeil
            | FloatFloor
            | FloatRound
    )
}

/// `FloatFormat::getHostFloat`.
fn host_float(size: u32, enc: u64) -> Option<f64> {
    match size {
        4 => Some(f64::from(f32::from_bits(enc as u32))),
        8 => Some(f64::from_bits(enc)),
        _ => None,
    }
}

/// `FloatFormat::getEncoding` (a double rounds to the nearest single).
fn float_encoding(size: u32, val: f64) -> Option<u64> {
    match size {
        4 => Some(u64::from((val as f32).to_bits())),
        8 => Some(val.to_bits()),
        _ => None,
    }
}

/// `evaluateUnary`/`evaluateBinary` of the float ops on constants; `None` where the C++
/// has no float format for the size.
fn eval_float(fd: &Funcdata, op: OpId) -> Option<u64> {
    let o = fd.op(op);
    let sout = fd.vn(o.out?).size;
    let a = fd.vn(*o.ins.first()?);
    let (sin, x) = (a.size, a.offset);
    let fa = || host_float(sin, x);
    let fb = || o.ins.get(1).and_then(|&b| host_float(sin, fd.vn(b).offset));
    let cmp = |f: fn(f64, f64) -> bool| Some(u64::from(f(fa()?, fb()?)));
    let enc = |v: f64| float_encoding(sout, v);
    match o.opc {
        FloatEqual => cmp(|p, q| p == q),
        FloatNotequal => cmp(|p, q| p != q),
        FloatLess => cmp(|p, q| p < q),
        FloatLessequal => cmp(|p, q| p <= q),
        FloatNan => Some(u64::from(fa()?.is_nan())),
        FloatAdd => enc(fa()? + fb()?),
        FloatSub => enc(fa()? - fb()?),
        FloatMult => enc(fa()? * fb()?),
        FloatDiv => enc(fa()? / fb()?),
        FloatNeg => enc(-fa()?),
        FloatAbs => enc(fa()?.abs()),
        FloatSqrt => enc(fa()?.sqrt()),
        FloatCeil => enc(fa()?.ceil()),
        FloatFloor => enc(fa()?.floor()),
        FloatRound => enc(fa()?.round()),
        FloatFloat2float => enc(fa()?),
        FloatInt2float => {
            let sh = 64 - 8 * sin.min(8);
            enc((((x << sh) as i64) >> sh) as f64)
        }
        FloatTrunc => Some((fa()? as i64 as u64) & calc_mask(sout)),
        _ => None,
    }
}

/// Port of `Funcdata::totalReplaceConstant`: every read of `vn` reads the constant `val`; a
/// marker reads one COPY of it made after `vn`'s definition (or at the function's start).
pub(crate) fn total_replace_constant(fd: &mut Funcdata, vn: VarnodeId, val: u64) -> Result<()> {
    let size = fd.vn(vn).size;
    let uniq = fd.uniq.ok_or_else(|| LowlevelError("no unique space".into()))?;
    let mut copy_out: Option<VarnodeId> = None;
    let readers = fd.vn(vn).descend.to_vec();
    for op in readers {
        let slot = fd.slot_of(op, vn).ok_or_else(|| LowlevelError("totalReplaceConstant: reader".into()))?;
        let newrep = if fd.op(op).is_marker() {
            if let Some(c) = copy_out {
                c
            } else {
                let (addr, after) = match fd.vn(vn).def {
                    Some(d) => (fd.op(d).seq.addr, Some(d)),
                    None => {
                        let bb = *fd.blocks.list.first().ok_or_else(|| LowlevelError("no blocks".into()))?;
                        (fd.blocks.block(bb).start, None)
                    }
                };
                let copyop = fd.new_op(Copy, addr);
                let out = fd.new_unique_out(size, uniq, copyop);
                let k = fd.new_constant(size, val);
                fd.op_set_input(copyop, k, 0)?;
                match after {
                    Some(d) => fd.op_insert_after(copyop, d)?,
                    None => fd.op_insert_begin(copyop, fd.blocks.list[0]),
                }
                copy_out = Some(out);
                out
            }
        } else {
            fd.new_constant(size, val)
        };
        fd.op_set_input(op, newrep, slot)?;
    }
    Ok(())
}
