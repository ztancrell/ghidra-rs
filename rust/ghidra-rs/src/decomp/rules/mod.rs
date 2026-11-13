//! Rule pools: the rules of `oppool1` ported so far (stage R1: copies, constants,
//! arithmetic; ruleaction.cc) and the pool walk ([`pool`]). The rules are in families
//! ([`copy`], [`arith`]) with the expression helpers they share ([`cse`]) and float constant
//! folding ([`float`]); the `Funcdata` methods they need (`cseEliminateList`,
//! `distributeIntMultAdd`, `totalReplaceConstant`, ...) are in `funcdata.rs`.
//!
//! The pool table [`OPPOOL1`] lists the ported rules of `oppool1` in the C++ order; a rule not
//! listed is switched off on the reference side by the check (`rust/tools/corpus/r1-options.txt`,
//! written by `rust/tools/r1-options.sh` from this table). x86 is little-endian, so the
//! big-endian address arithmetic of the rules is left out.

mod arith;
mod copy;
mod cse;
mod float;
mod pool;

pub(crate) use pool::{nonzero_mask, pool_apply, select, Pool};

use arith::*;
use copy::*;
use cse::*;
use float::*;

use std::collections::HashSet;

use super::block::BlockId;
use super::emulate::{eval_binary, eval_unary};
use super::op::{OpFlags, OpId};
use super::opcode::Opcode;
use super::rangeutil::calc_mask;
use super::varnode::{Space, VarnodeId, VnFlags, CONST_SPACE};
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
