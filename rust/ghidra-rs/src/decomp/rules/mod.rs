//! Rule pools: the rules of `oppool1` ported so far (stage R1: copies, constants,
//! arithmetic; stage R3: extension, concat and sub-pieces in [`extend`], [`piece`],
//! [`subpiece`]; ruleaction.cc) and the pool walk ([`pool`]). The rules are in families
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
mod extend;
mod float;
mod piece;
mod pool;
mod subpiece;
mod subvar;

pub(crate) use pool::{nonzero_mask, pool_apply, select, Pool};

use arith::*;
use copy::*;
use cse::*;
use extend::*;
use float::*;
use piece::*;
use subpiece::*;
use subvar::*;

use std::collections::HashSet;

use super::block::BlockId;
use super::emulate::{eval_binary, eval_unary};
use super::op::{OpFlags, OpId};
use super::opcode::Opcode;
use super::rangeutil::{calc_mask, sign_extend};
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
    r("doublesub", "analysis", &[Subpiece], double_sub),
    r("concatshift", "analysis", &[IntRight, IntSright], concat_shift),
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
    r("zexteliminate", "analysis", &[IntEqual, IntNotequal, IntLess, IntLessequal], zext_eliminate),
    r("zextsless", "analysis", &[IntSless, IntSlessequal], zext_sless),
    r("subextcomm", "analysis", &[Subpiece], sub_ext_comm),
    r("subcommute", "analysis", &[Subpiece], sub_commute),
    r("concatcommute", "analysis", &[Piece], concat_commute),
    r("concatzext", "analysis", &[Piece], concat_zext),
    r("zextcommute", "analysis", &[IntRight], zext_commute),
    r("zextshiftzext", "analysis", &[IntZext], zext_shift_zext),
    r("concatzero", "analysis", &[Piece], concat_zero),
    r("concatleftshift", "analysis", &[Piece], concat_left_shift),
    r("subzext", "analysis", &[IntZext], sub_zext),
    r("subcancel", "analysis", &[Subpiece], sub_cancel),
    r("shiftsub", "analysis", &[Subpiece], shift_sub),
    r("humptydumpty", "analysis", &[Piece], humpty_dumpty),
    r("dumptyhump", "analysis", &[Subpiece], dumpty_hump),
    r("humptyor", "analysis", &[IntOr], humpty_or),
    r("negateidentity", "analysis", &[IntNegate], negate_identity),
    r("subnormal", "analysis", &[Subpiece], sub_normal),
    r("piece2zext", "analysis", &[Piece], piece_2_zext),
    r("piece2sext", "analysis", &[Piece], piece_2_sext),
    r("subvar_and", "subvar", &[IntAnd], subvar_and),
    r("subvar_subpiece", "subvar", &[Subpiece], subvar_subpiece),
    r("splitflow", "subvar", &[Subpiece], split_flow),
    r("subvar_compzero", "subvar", &[IntNotequal, IntEqual], subvar_comp_zero),
    r("subvar_shift", "subvar", &[IntRight], subvar_shift),
    r("subvar_zext", "subvar", &[IntZext], subvar_ext),
    r("subvar_sext", "subvar", &[IntSext], subvar_ext),
    r("negatenegate", "analysis", &[IntNegate], negate_negate),
    r("piecepathology", "protorecovery", &[Piece], piece_pathology),
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

/// The op defining `vn` when its opcode is `opc`.
fn def_with(fd: &Funcdata, vn: VarnodeId, opc: Opcode) -> Option<OpId> {
    def(fd, vn).filter(|&d| fd.op(d).opc == opc)
}

/// A constant's value as the C++ `int4` it is read into.
fn int4(fd: &Funcdata, vn: VarnodeId) -> i64 {
    i64::from(fd.vn(vn).offset as i32)
}

/// `Funcdata::newUniqueOut`: a new unique-space varnode of `size` bytes written by `op`.
fn uniq_out(fd: &mut Funcdata, size: u32, op: OpId) -> Result<VarnodeId> {
    let uniq = fd.uniq.ok_or_else(|| LowlevelError("no unique space".into()))?;
    Ok(fd.new_unique_out(size, uniq, op))
}
