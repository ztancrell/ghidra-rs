//! Rule pools: the rules of `oppool1` and of the `cleanup` pool ported so far (stage R1: copies,
//! constants, arithmetic in [`copy`], [`arith`]; stage R2: bit operations, comparisons, booleans
//! in [`bits`], [`compare`], [`boolean`], [`cleanup`]; stage R3: extension, concat and sub-pieces
//! in [`extend`], [`piece`], [`subpiece`]; stage R4: division, remainder, sign and float rules in
//! [`div`], [`modulo`], [`floatrules`] and `RuleSubfloatConvert` in `decomp/subfloat.rs`; the
//! `subvar` group and `RulePiecePathology` of stage R3b in [`subvar`], [`piece`]; ruleaction.cc),
//! the double-precision rules of stage R5 slice 3 in [`double`] (double.cc), and the pool walk ([`pool`]), with the expression helpers they share ([`cse`]) and float constant
//! folding ([`float`]); the `Funcdata` methods they need (`cseEliminateList`,
//! `distributeIntMultAdd`, `totalReplaceConstant`, ...) are in `funcdata.rs`.
//!
//! The pool tables [`OPPOOL1`], [`OPPOOL2`] and [`CLEANUP`] list every rule of the C++ pools in
//! the C++ order (a test compares them with coreaction.cc): a ported rule as `r(...)`, one not
//! ported as `u(...)`. The `decompile` root fails while a `u` rule is on, so the checks switch
//! it off on both engines (`rust/tools/corpus/r1-options.txt` and the other options files,
//! written by `rust/tools/r1-options.sh` from these tables). The script also keeps `aliasupdate`
//! off in the older rule checks: it is ported, but in the function itself it fails on a guarded
//! stack STORE. x86 is little-endian, so the big-endian address arithmetic of the rules is left
//! out.

mod arith;
mod bitfield;
mod bits;
pub(crate) mod boolean;
mod cleanup;
mod compare;
mod constseq;
mod copy;
mod cse;
mod div;
mod double;
mod extend;
mod float;
mod floatrules;
mod modulo;
mod piece;
mod pool;
pub(crate) mod ptrarith;
mod segment;
mod split;
mod stackvars;
mod subpiece;
mod subvar;
mod typecleanup;

pub(crate) use boolean::{boolean_flip, op_normalize_flip};
pub(crate) use compare::replace_lessequal;
pub(crate) use cse::func_eq_level;
pub(crate) use cse::func_equal;
pub(crate) use double::{is_floating_point_op, param_double};
pub(crate) use pool::{nonzero_mask, pool_apply, select, Pool};

use arith::*;
use bitfield::*;
use bits::*;
use boolean::*;
use cleanup::*;
use compare::*;
use constseq::*;
use copy::*;
use cse::*;
use div::*;
use double::*;
use extend::*;
use float::*;
use floatrules::*;
use modulo::*;
use piece::*;
use ptrarith::*;
use segment::*;
use split::*;
use stackvars::*;
use subpiece::*;
use subvar::*;
use typecleanup::*;

use std::collections::HashSet;

use super::block::BlockId;
use super::emulate::{eval_binary, eval_unary};
use super::infertypes::float_sign_manipulation;
use super::op::{OpFlags, OpId};
use super::opcode::{is_bool_output, Opcode};
use super::rangeutil::{calc_mask, leastsigbit_set, mostsigbit_set, sign_extend};
use super::subfloat::subfloat_convert;
use super::subflow::preferred_zext_size;
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

/// A rule of the C++ pool that is not ported. The `decompile` root refuses to run while one is
/// on (`pool::select`); in the `jumptable` root, which no option reaches, it fails on the first op
/// it would be tried on. No table has one now (`segment` and `ptrsubcharconstant` were the last
/// two): only the test below uses it, until the C++ pools gain a rule.
#[cfg_attr(not(test), allow(dead_code))]
const fn u(name: &'static str, group: &'static str, ops: &'static [Opcode]) -> Rule {
    Rule { name, group, ops, apply: rule_not_ported }
}

fn rule_not_ported(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let o = fd.op(op);
    err(format!(
        "a pool rule tried on {:?} at 0x{:08x} is not ported (rules/mod.rs: the `u` entries)",
        o.opc, o.seq.addr
    ))
}

impl Rule {
    /// A `u` entry.
    fn unported(&self) -> bool {
        std::ptr::fn_addr_eq(self.apply, rule_not_ported as RuleFn)
    }
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
    r("pullsub_indirect", "analysis", &[Subpiece], pullsub_indirect),
    r("push_multi", "nodejoin", &[Multiequal], push_multi),
    r("sborrow", "analysis", &[IntSborrow], sborrow),
    r("scarry", "analysis", &[IntScarry], scarry),
    r("intlessequal", "analysis", &[IntLessequal, IntSlessequal], int_less_equal),
    r("trivialarith", "analysis", &[
        IntNotequal, IntSless, IntLess, BoolXor, BoolAnd, BoolOr, IntEqual, IntSlessequal,
        IntLessequal, IntXor, IntAnd, IntOr, FloatEqual, FloatNotequal, FloatLess, FloatLessequal],
        trivial_arith),
    r("trivialbool", "analysis", &[BoolAnd, BoolOr, BoolXor], trivial_bool),
    r("trivialshift", "analysis", &[IntLeft, IntRight, IntSright], trivial_shift),
    r("signshift", "analysis", &[IntRight], sign_shift),
    r("testsign", "analysis", &[IntSright], test_sign),
    r("identityel", "analysis", &[IntAdd, IntXor, IntOr, BoolXor, BoolOr, IntMult], identity_el),
    r("ormask", "analysis", &[IntOr], or_mask),
    r("andmask", "analysis", &[IntAnd], and_mask),
    r("orconsume", "analysis", &[IntOr, IntXor], or_consume),
    r("orcollapse", "analysis", &[IntOr], or_collapse),
    r("andorlump", "analysis", &[IntAnd, IntOr, IntXor], and_or_lump),
    r("shiftbitops", "analysis", &[IntLeft, IntRight, Subpiece, IntMult], shift_bitops),
    r("rightshiftand", "analysis", &[IntRight, IntSright], right_shift_and),
    r("notdistribute", "analysis", &[BoolNegate], not_distribute),
    r("highorderand", "analysis", &[IntAnd], high_order_and),
    r("anddistribute", "analysis", &[IntAnd], and_distribute),
    r("andcommute", "analysis", &[IntAnd], and_commute),
    r("andpiece", "analysis", &[IntAnd], and_piece),
    r("andzext", "analysis", &[IntAnd], and_zext),
    r("andcompare", "analysis", &[IntEqual, IntNotequal], and_compare),
    r("doublesub", "analysis", &[Subpiece], double_sub),
    r("doubleshift", "analysis", &[IntLeft, IntRight, IntMult], double_shift),
    r("doublearithshift", "analysis", &[IntSright], double_arith_shift),
    r("concatshift", "analysis", &[IntRight, IntSright], concat_shift),
    r("leftright", "analysis", &[IntRight, IntSright], left_right),
    r("shiftcompare", "analysis", &[IntEqual, IntNotequal], shift_compare),
    r("shift2mult", "analysis", &[IntLeft], shift_2_mult),
    r("shiftpiece", "analysis", &[IntOr, IntXor, IntAdd], shift_piece),
    r("multicollapse", "analysis", &[Multiequal], multi_collapse),
    r("aliasupdate", "analysis", &[Store, Call, Callind, Callother], alias_update),
    r("2comp2mult", "analysis", &[Int2comp], two_comp_2_mult),
    r("sub2add", "analysis", &[IntSub], sub_2_add),
    r("carryelim", "analysis", &[IntCarry], carry_elim),
    r("bxor2notequal", "analysis", &[BoolXor], bxor_2_notequal),
    r("less2zero", "analysis", &[IntLess], less_2_zero),
    r("lessequal2zero", "analysis", &[IntLessequal], less_equal_2_zero),
    r("sless2zero", "analysis", &[IntSless], sless_2_zero),
    r("equal2zero", "analysis", &[IntEqual, IntNotequal], equal_2_zero),
    r("equal2constant", "analysis", &[IntEqual, IntNotequal], equal_2_constant),
    r("threewaycomp", "analysis", &[IntSless, IntSlessequal, IntEqual, IntNotequal], three_way_compare),
    r("xorcollapse", "analysis", &[IntEqual, IntNotequal], xor_collapse),
    r("addmultcollapse", "analysis", &[IntAdd, IntMult], add_mult_collapse),
    r("collapseconstants", "analysis", &[
        IntEqual, IntNotequal, IntSless, IntSlessequal, IntLess, IntLessequal, IntZext, IntSext,
        IntAdd, IntSub, IntCarry, IntScarry, IntSborrow, Int2comp, IntNegate, IntXor, IntAnd, IntOr,
        IntLeft, IntRight, IntSright, IntMult, IntDiv, IntSdiv, IntRem, IntSrem, BoolNegate, BoolXor,
        BoolAnd, BoolOr, FloatEqual, FloatNotequal, FloatLess, FloatLessequal, FloatNan, FloatAdd,
        FloatDiv, FloatMult, FloatSub, FloatNeg, FloatAbs, FloatSqrt, FloatInt2float,
        FloatFloat2float, FloatTrunc, FloatCeil, FloatFloor, FloatRound, Piece, Subpiece, Popcount,
        Lzcount], collapse_constants),
    r("transformcpool", "analysis", &[Cpoolref], transform_cpool),
    r("propagatecopy", "analysis", &[Copy], propagate_copy),
    r("zexteliminate", "analysis", &[IntEqual, IntNotequal, IntLess, IntLessequal], zext_eliminate),
    r("slesstoless", "analysis", &[IntSless, IntSlessequal], sless_to_less),
    r("zextsless", "analysis", &[IntSless, IntSlessequal], zext_sless),
    r("bitundistribute", "analysis", &[IntAnd, IntOr, IntXor], bit_undistribute),
    r("booleanundistribute", "analysis", &[IntEqual, IntNotequal], boolean_undistribute),
    r("booleandedup", "analysis", &[BoolAnd, BoolOr], boolean_dedup),
    r("boolzext", "analysis", &[IntZext], bool_zext),
    r("booleannegate", "analysis", &[IntNotequal, IntEqual], boolean_negate),
    r("logic2bool", "analysis", &[IntAnd, IntOr, IntXor], logic_2_bool),
    r("subextcomm", "analysis", &[Subpiece], sub_ext_comm),
    r("subcommute", "analysis", &[Subpiece], sub_commute),
    r("concatcommute", "analysis", &[Piece], concat_commute),
    r("concatzext", "analysis", &[Piece], concat_zext),
    r("zextcommute", "analysis", &[IntRight], zext_commute),
    r("zextshiftzext", "analysis", &[IntZext], zext_shift_zext),
    r("shiftand", "analysis", &[IntRight, IntLeft, IntMult], shift_and),
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
    r("positivediv", "analysis", &[IntSdiv, IntSrem], positive_div),
    r("divtermadd", "analysis", &[Subpiece, IntRight, IntSright], div_term_add),
    r("divtermadd2", "analysis", &[IntRight], div_term_add2),
    r("divopt", "analysis", &[Subpiece, IntRight, IntSright], div_opt),
    r("signform", "analysis", &[Subpiece], sign_form),
    r("signform2", "analysis", &[IntSright], sign_form2),
    r("signdiv2", "analysis", &[IntSright], sign_div2),
    r("divchain", "analysis", &[IntDiv, IntSdiv], div_chain),
    r("signnearmult", "analysis", &[IntAnd], sign_near_mult),
    r("modopt", "analysis", &[IntDiv, IntSdiv], mod_opt),
    r("signmod2nopt", "analysis", &[IntRight], sign_mod2n_opt),
    r("signmod2nopt2", "analysis", &[IntMult], sign_mod2n_opt2),
    r("signmod2opt", "analysis", &[IntAnd], sign_mod2_opt),
    r("switchsingle", "analysis", &[Branchind], switch_single),
    r("condnegate", "analysis", &[Cbranch], cond_negate),
    r("boolnegate", "analysis", &[BoolNegate], bool_negate),
    r("lessequal", "analysis", &[BoolOr], less_equal),
    r("lessnotequal", "analysis", &[BoolAnd], less_not_equal),
    r("lessone", "analysis", &[IntLess, IntLessequal], less_one),
    r("rangemeld", "analysis", &[BoolOr, BoolAnd], range_meld),
    r("floatrange", "analysis", &[BoolOr, BoolAnd], float_range),
    r("piece2zext", "analysis", &[Piece], piece_2_zext),
    r("piece2sext", "analysis", &[Piece], piece_2_sext),
    r("popcountboolxor", "analysis", &[Popcount], popcount_bool_xor),
    r("xorswap", "analysis", &[IntXor], xor_swap),
    r("lzcountshiftbool", "analysis", &[Lzcount], lzcount_shift_bool),
    r("floatsign", "analysis", &[
        FloatEqual, FloatNotequal, FloatLess, FloatLessequal, FloatNan, FloatAdd, FloatDiv, FloatMult,
        FloatSub, FloatNeg, FloatAbs, FloatSqrt, FloatFloat2float, FloatCeil, FloatFloor, FloatRound,
        FloatInt2float, FloatTrunc], float_sign),
    r("orcompare", "analysis", &[IntOr], or_compare),
    r("subvar_and", "subvar", &[IntAnd], subvar_and),
    r("subvar_subpiece", "subvar", &[Subpiece], subvar_subpiece),
    r("splitflow", "subvar", &[Subpiece], split_flow),
    r("ptrflow", "subvar", &[], ptr_flow),
    r("subvar_compzero", "subvar", &[IntNotequal, IntEqual], subvar_comp_zero),
    r("subvar_shift", "subvar", &[IntRight], subvar_shift),
    r("subvar_zext", "subvar", &[IntZext], subvar_ext),
    r("subvar_sext", "subvar", &[IntSext], subvar_ext),
    r("negatenegate", "analysis", &[IntNegate], negate_negate),
    r("conditionalmove", "conditionalexe", &[Multiequal], conditional_move),
    r("orpredicate", "conditionalexe", &[IntOr, IntXor], or_predicate),
    r("funcptrencoding", "analysis", &[Callind], funcptr_encoding),
    r("subfloat_convert", "floatprecision", &[FloatFloat2float], subfloat_convert),
    r("floatcast", "floatprecision", &[FloatFloat2float, FloatTrunc], float_cast),
    r("ignorenan", "floatprecision", &[FloatNan], ignore_nan),
    r("unsigned2float", "analysis", &[FloatInt2float], unsigned_2_float),
    r("int2floatcollapse", "analysis", &[FloatInt2float], int2float_collapse),
    r("ptraddundo", "typerecovery", &[Ptradd], ptradd_undo),
    r("ptrsubundo", "typerecovery", &[Ptrsub], ptrsub_undo),
    r("segment", "segment", &[Segmentop], rule_segment),
    r("piecepathology", "protorecovery", &[Piece], piece_pathology),
    r("doubleload", "doubleload", &[Piece], double_load),
    r("doublestore", "doubleprecis", &[Store], double_store),
    r("doublein", "doubleprecis", &[Subpiece], double_in),
    r("doubleout", "doubleprecis", &[Piece], double_out),
];

/// The ported rules of `oppool2`, in `universalAction`'s order (stage R5).
#[rustfmt::skip]
pub(crate) const OPPOOL2: &[Rule] = &[
    r("pushptr", "typerecovery", &[IntAdd], push_ptr),
    r("structoffset0", "typerecovery", &[Load, Store], struct_offset0),
    r("ptrarith", "typerecovery", &[IntAdd], ptr_arith),
    r("loadvarnode", "stackvars", &[Load], load_varnode),
    r("storevarnode", "stackvars", &[Store], store_varnode),
];

/// The ported rules of the `cleanup` pool, in `universalAction`'s order.
#[rustfmt::skip]
pub(crate) const CLEANUP: &[Rule] = &[
    r("multnegone", "cleanup", &[IntMult], mult_neg_one),
    r("addunsigned", "cleanup", &[IntAdd], add_unsigned),
    r("2comp2sub", "cleanup", &[Int2comp], two_comp_2_sub),
    r("dumptyhumplate", "cleanup", &[Subpiece], dumpty_hump_late),
    r("subright", "cleanup", &[Subpiece], sub_right),
    r("floatsigncleanup", "cleanup", &[IntAnd, IntXor], float_sign_cleanup),
    r("expandload", "cleanup", &[Load], expand_load),
    r("ptrsubcharconstant", "cleanup", &[Ptrsub], ptrsub_char_constant),
    r("extensionpush", "cleanup", &[IntZext, IntSext], extension_push),
    r("piecestructure", "cleanup", &[Piece, IntZext], piece_structure),
    r("andstructure", "cleanup", &[IntAnd], and_structure),
    r("splitcopy", "splitcopy", &[Copy], split_copy),
    r("splitload", "splitpointer", &[Load], split_load),
    r("splitstore", "splitpointer", &[Store], split_store),
    r("stringcopy", "constsequence", &[Copy], string_copy),
    r("stringstore", "constsequence", &[Store], string_store),
    r("bitfield_store", "bitfields", &[Store], bitfield_transform),
    r("bitfield_out", "bitfields", &[
        Copy, IntEqual, IntNotequal, IntSless, IntSlessequal, IntLess, IntLessequal, IntZext, IntSext, IntAdd,
        IntCarry, IntScarry, IntXor, IntAnd, IntOr, IntLeft, IntRight, IntSright, IntMult, BoolNegate, BoolXor,
        BoolAnd, BoolOr, FloatEqual, FloatNotequal, FloatLess, FloatLessequal, FloatNan, Subpiece], bitfield_transform),
    r("bitfield_load", "bitfields", &[Load], bitfield_transform),
    r("bitfield_in", "bitfields", &[
        Copy, IntEqual, IntNotequal, IntSless, IntSlessequal, IntLess, IntLessequal, IntZext, IntSext, IntAdd,
        IntNegate, IntAnd, IntLeft, IntRight, IntSright, IntMult, Subpiece], bitfield_transform),
    r("pull_absorb", "bitfields", &[Zpull, Spull], bitfield_absorb),
    r("insert_absorb", "bitfields", &[Insert], bitfield_absorb),
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

/// `RuleTransformCpool`: the constant pool (`CPoolRecord`) is not ported, so a CPOOLREF fails.
fn transform_cpool(_: &mut Funcdata, _: OpId, _: &Arch) -> Result<i32> {
    err("RuleTransformCpool: a CPOOLREF (the constant pool) is not implemented in ghidra-rs yet")
}

/// `RuleFuncPtrEncoding`: a CALLIND through `V & mask`, the mask clearing only the encoding bits
/// of a function pointer (`<funcptr align=..>`), calls `V`: the AND becomes a COPY.
fn funcptr_encoding(fd: &mut Funcdata, op: OpId, arch: &Arch) -> Result<i32> {
    let align = arch.spec.funcptr_align;
    if align == 0 {
        return Ok(0);
    }
    let Some(andop) = fd.vn(fd.op(op).ins[0]).def.filter(|&d| fd.op(d).opc == Opcode::IntAnd) else { return Ok(0) };
    let mask = fd.vn(fd.op(andop).ins[1]);
    if !mask.is_constant() || (calc_mask(mask.size) & (u64::MAX << align)) != mask.offset {
        return Ok(0);
    }
    fd.op_remove_input(andop, 1);
    fd.op_set_opcode(andop, Opcode::Copy);
    Ok(1)
}

/// `RulePtrFlow`: its op list is empty unless the default data space is truncated
/// (`<truncate_space>` of the `.ldefs`), and the console refuses a language that has one
/// (`Sleigh::refuse_truncated`).
fn ptr_flow(_: &mut Funcdata, _: OpId, _: &Arch) -> Result<i32> {
    Ok(0)
}

/// Port of `RuleSwitchSingle`: a BRANCHIND whose block has one out edge becomes a BRANCH to the
/// table's one destination, and the table goes (`Funcdata::removeJumpTable`).
fn switch_single(fd: &mut Funcdata, op: OpId, arch: &Arch) -> Result<i32> {
    let Some(bb) = fd.op(op).parent else { return Ok(0) };
    if fd.blocks.block(bb).outs.len() != 1 {
        return Ok(0);
    }
    let Some(jt) = fd.jumptables.iter().find(|jt| jt.op == op) else { return Ok(0) };
    // labels must be recovered (`isLabelled`)
    let (Some(&target), false) = (jt.targets.first(), jt.labels.is_empty()) else { return Ok(0) };
    let n = jt.targets.len();
    let all_match = n != 1 && jt.targets.iter().all(|&t| t == target);
    if n != 1 || !is_const(fd, inp(fd, op, 0)?) {
        // `printRaw` of the op's code address
        let size = arch.sleigh.spaces[arch.sleigh.code_space() as usize].size;
        let mut msg = format!(
            "Switch with 1 destination removed at {}",
            crate::decomp::printc::raw_offset(size, fd.op(op).seq.addr)
        );
        if all_match {
            msg.push_str(&format!(" : {n} cases all go to same destination"));
        }
        fd.warning_header(msg);
    }
    fd.op_set_opcode(op, Branch);
    // newCodeRef: a one-byte annotation at the destination
    let cref = fd.new_varnode(1, Space::Sleigh(arch.sleigh.code_space()), target);
    fd.vn_set(cref, VnFlags::CODEREF);
    fd.vn_clear(cref, VnFlags::PERSIST);
    fd.vn_clear(cref, VnFlags::ADDRTIED);
    fd.op_set_input(op, cref, 0)?;
    fd.jumptables.retain(|jt| jt.op != op);
    fd.structure.clear();
    Ok(1)
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

/// A new op at `addr` with a unique output of `size` bytes and the inputs `ins` (`newOp`,
/// `newUniqueOut`, `opSetInput`), inserted before `follow` (`opInsertBefore`): its output.
pub(crate) fn insert_new(
    fd: &mut Funcdata,
    opc: Opcode,
    addr: u64,
    size: u32,
    ins: &[VarnodeId],
    follow: OpId,
) -> Result<VarnodeId> {
    let n = fd.new_op(opc, addr);
    let o = uniq_out(fd, size, n)?;
    for (i, &v) in ins.iter().enumerate() {
        fd.op_set_input(n, v, i)?;
    }
    fd.op_insert_before(n, follow)?;
    Ok(o)
}

fn off(fd: &Funcdata, vn: VarnodeId) -> u64 {
    fd.vn(vn).offset
}

fn sz(fd: &Funcdata, vn: VarnodeId) -> u32 {
    fd.vn(vn).size
}

fn code(fd: &Funcdata, op: OpId) -> Opcode {
    fd.op(op).opc
}

fn op_addr(fd: &Funcdata, op: OpId) -> u64 {
    fd.op(op).seq.addr
}

fn is_free(fd: &Funcdata, vn: VarnodeId) -> bool {
    fd.vn(vn).is_free()
}

fn known(fd: &Funcdata, vn: VarnodeId) -> bool {
    fd.vn(vn).is_heritage_known()
}

/// `Varnode::constantMatch`.
fn const_match(fd: &Funcdata, vn: VarnodeId, val: u64) -> bool {
    is_const(fd, vn) && off(fd, vn) == val
}

/// `uintb << int4` as x86-64 computes it (the count modulo 64; the C++ has no range check).
fn shl(v: u64, sa: i32) -> u64 {
    v.wrapping_shl(sa as u32)
}

/// `uintb >> int4` as x86-64 computes it.
fn shr(v: u64, sa: i32) -> u64 {
    v.wrapping_shr(sa as u32)
}

/// Hand-built ops for the rule tests.
#[cfg(test)]
pub(super) mod testutil {
    use super::*;

    /// A register input of 4 bytes at `off`.
    pub(crate) fn input(fd: &mut Funcdata, off: u64) -> VarnodeId {
        let v = fd.new_varnode(4, Space::Sleigh(1), off);
        fd.vn_set(v, VnFlags::INPUT);
        v
    }

    /// A new op `opc` with inputs `ins` and a 4-byte register output at `off`.
    pub(crate) fn op(fd: &mut Funcdata, opc: Opcode, ins: &[VarnodeId], off: u64) -> (OpId, VarnodeId) {
        op_sized(fd, opc, ins, off, 4)
    }

    /// A new op `opc` with inputs `ins` and a register output of `size` bytes at `off`.
    pub(crate) fn op_sized(
        fd: &mut Funcdata,
        opc: Opcode,
        ins: &[VarnodeId],
        off: u64,
        size: u32,
    ) -> (OpId, VarnodeId) {
        let o = fd.new_op(opc, 0x1000);
        let out = fd.new_varnode_out(size, Space::Sleigh(1), off, o);
        for (i, &v) in ins.iter().enumerate() {
            fd.op_set_input(o, v, i).unwrap();
        }
        (o, out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The three tables hold every rule of the C++ pools (`universalAction`, coreaction.cc), in
    /// its order and with its group: a rule missing from a table would be silently absent from
    /// a run, so it must be listed, ported (`r`) or not (`u`).
    #[test]
    fn tables_list_every_rule_of_the_cpp_pools() {
        let cpp =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Ghidra/Features/Decompiler/src/decompile/cpp");
        // class -> rule name, from the constructors `RuleX(const string &g) : Rule(g, 0, "name")`
        // (RulePtrFlow's is in ruleaction.cc: it takes the architecture too)
        let mut names = std::collections::HashMap::from([("RulePtrFlow".to_string(), "ptrflow".to_string())]);
        for file in std::fs::read_dir(&cpp).unwrap().map(|e| e.unwrap().path()) {
            if file.extension().is_none_or(|x| x != "hh") {
                continue;
            }
            for line in std::fs::read_to_string(&file).unwrap().lines() {
                let l = line.trim_start();
                let Some((class, rest)) = l.split_once("(const string &g") else { continue };
                let Some((_, rule)) = rest.split_once(": Rule(") else { continue };
                if let Some(name) = rule.split('"').nth(1) {
                    names.insert(class.to_string(), name.to_string());
                }
            }
        }
        let core = std::fs::read_to_string(cpp.join("coreaction.cc")).unwrap();
        let pool = |var: &str| -> Vec<(String, String)> {
            let (first, last) = (format!("{var} = new ActionPool"), format!("addAction( {var} )"));
            core.lines()
                .skip_while(|l| !l.contains(&first))
                .take_while(|l| !l.contains(&last))
                .filter(|l| !l.trim_start().starts_with("//"))
                .filter_map(|l| l.split_once("new Rule"))
                .map(|(_, r)| {
                    let class = format!("Rule{}", r.split('(').next().unwrap());
                    let name = names.get(&class).unwrap_or_else(|| panic!("no rule name for {class}"));
                    (name.clone(), r.split('"').nth(1).unwrap().to_string())
                })
                .collect()
        };
        for (var, table) in [("actprop", OPPOOL1), ("actprop2", OPPOOL2), ("actcleanup", CLEANUP)] {
            let ours: Vec<_> = table.iter().map(|rl| (rl.name.to_string(), rl.group.to_string())).collect();
            assert_eq!(ours, pool(var), "{var}");
        }
    }

    /// The `decompile` root refuses to apply a pool while a rule that is not ported is on; the
    /// `jumptable` root files the rule, which fails on an op of its list.
    #[test]
    fn an_unported_rule_that_is_on_fails_the_pool() {
        static TABLE: &[Rule] = &[u("segment", "segment", &[Segmentop])];
        let strict = select(TABLE, |_| true, true);
        assert_eq!(strict.missing, ["segment"]);
        assert!(select(TABLE, |_| false, true).missing.is_empty());
        assert!(select(TABLE, |_| true, false).missing.is_empty());
    }

    #[test]
    fn shift_helpers_table() {
        // shift counts are taken modulo 64, as x86-64 does for the C++
        for (v, sa, l, r) in [(1u64, 0, 1u64, 1u64), (1, 4, 16, 0), (0xf0, 64, 0xf0, 0xf0), (0xf0, -1, 0, 0)] {
            assert_eq!((shl(v, sa), shr(v, sa)), (l, r), "{v:#x} by {sa}");
        }
    }
}
