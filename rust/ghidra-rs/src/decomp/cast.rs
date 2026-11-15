//! Port of `cast.cc` (`CastStrategy`, `CastStrategyC`) and `ActionSetCasts` (coreaction.cc),
//! with the `TypeOp::getInputCast` / `getOutputToken` overrides of typeop.cc they call (stage
//! S9). `setcasts` walks the ops block by block and inserts the CAST ops (and the PTRSUB #0 field
//! accesses) the C printer needs, marks constants printed as unsigned or long, undoes PTRADDs and
//! PTRSUBs that no longer fit their pointer, and warns about LOAD/STORE sizes.
//!
//! What is left out, and why it changes nothing or fails loudly:
//! - Union resolution (`ResolvedUnion`, `setUnionField`, `resolveInFlow`, `forceFacingType`,
//!   `inheritUnionField`, `setImpliedField`): every place that would resolve a data-type that
//!   `needsResolution` (a union, a struct whose one field fills it, an array of one element, a
//!   pointer to one) fails loudly.
//! - The pointer `space` attribute of `checkPointerIssues`: no ported pointer type has one.
//! - `TypeCode` prototypes, `isVariableLength`, the partial types: none is ported, so the
//!   branches that test them reduce to the code here.
//! - `CastStrategyJava`. The printer-only `isExtensionCastImplied`, `isSubpieceCast`,
//!   `isSextCast` and `isZextCast` are at the end (S9 printer, slice 2); `isSubpieceCastEndian`
//!   is left out (only `pushPartialSymbol` calls it, not ported). Superseded: "only the printer
//!   calls them", left out.
//! - `Funcdata::startCastPhase` sets `cast_phase_index`, which nothing reads.
//! - SEGMENTOP, INSERT, ZPULL and SPULL have their own cast rules: they fail loudly.

use super::funcdata::Funcdata;
use super::infertypes::{down_chain, input_local, output_local, vn_type};
use super::op::{OpFlags, OpId};
use super::opcode::{is_bool_output, Opcode};
use super::rangeutil::{calc_mask, mostsigbit_set};
use super::rules::ptrarith::{is_ptrsub_matching, op_undo_ptradd};
use super::types::{Meta, TypeFactory, TypeId};
use super::variable::{h_type, high};
use super::varnode::{VarnodeId, VnFlags};
use super::{err, Arch, LowlevelError, Result};

/// ponytail: every x86 space has word size 1; read `AddrSpace::getWordSize` for other targets.
const WS: u32 = 1;
/// `CastStrategy::promoteSize`: `TypeFactory::getSizeOfInt`, 4 in x86's data organization.
/// ponytail: read the `.cspec`'s `integer_size` for other targets.
const PROMOTE_SIZE: u32 = 4;

/// `CastStrategy::IntPromotionCode`.
const NO_PROMOTION: i32 = -1;
const UNKNOWN_PROMOTION: i32 = 0;
const UNSIGNED_EXTENSION: i32 = 1;
const SIGNED_EXTENSION: i32 = 2;
const EITHER_EXTENSION: i32 = 3;

fn unresolved<T>() -> Result<T> {
    err("setcasts: a data-type needing resolution (union, one-field struct, one-element array) is not implemented in ghidra-rs yet")
}

/// `vn->getHigh()->getType()`.
fn high_type(fd: &mut Funcdata, vn: VarnodeId) -> Result<TypeId> {
    let h = high(fd, vn)?;
    Ok(h_type(fd, h).0)
}

/// `Varnode::getHighTypeReadFacing` / `getHighTypeDefFacing`: the high's type, which must not
/// need resolution.
fn facing(fd: &mut Funcdata, vn: VarnodeId) -> Result<TypeId> {
    let t = high_type(fd, vn)?;
    if fd.types.needs_resolution(t) {
        return unresolved();
    }
    Ok(t)
}

/// `Varnode::getTypeReadFacing`.
fn vn_facing(fd: &mut Funcdata, vn: VarnodeId) -> Result<TypeId> {
    let t = vn_type(fd, vn);
    if fd.types.needs_resolution(t) {
        return unresolved();
    }
    Ok(t)
}

/// `Varnode::updateType(ct)`: unless locked or already `ct`.
fn update_type(fd: &mut Funcdata, vn: VarnodeId, ct: TypeId) -> bool {
    if vn_type(fd, vn) == ct || fd.vn(vn).has(VnFlags::TYPELOCK) {
        return false;
    }
    fd.vn_mut(vn).ty = Some(ct);
    true
}

/// `Varnode::loneDescend`.
fn lone_descend(fd: &Funcdata, vn: VarnodeId) -> Option<OpId> {
    match fd.vn(vn).descend[..] {
        [op] => Some(op),
        _ => None,
    }
}

fn input(fd: &Funcdata, op: OpId, slot: usize) -> Result<VarnodeId> {
    fd.input(op, slot)
}

fn output(fd: &Funcdata, op: OpId) -> Result<VarnodeId> {
    fd.op(op).out.ok_or_else(|| LowlevelError("setcasts: op without output".into()))
}

fn opc_of(fd: &Funcdata, vn: VarnodeId) -> Option<Opcode> {
    fd.vn(vn).def.map(|d| fd.op(d).opc)
}

fn is_explicit(fd: &Funcdata, vn: VarnodeId) -> bool {
    fd.vn(vn).has(VnFlags::EXPLICIT)
}

fn is_implied(fd: &Funcdata, vn: VarnodeId) -> bool {
    fd.vn(vn).has(VnFlags::IMPLIED)
}

/// `signbit_negative`.
fn signbit_negative(val: u64, size: u32) -> bool {
    size > 0 && size <= 8 && (val >> (size * 8 - 1)) & 1 != 0
}

/// `TypeOp::inheritsSign` (the `inherits_sign` flag of the TypeOp constructors).
fn inherits_sign(opc: Opcode) -> bool {
    use Opcode::*;
    matches!(
        opc,
        IntEqual
            | IntNotequal
            | IntSless
            | IntSlessequal
            | IntLess
            | IntLessequal
            | IntAdd
            | IntSub
            | Int2comp
            | IntNegate
            | IntXor
            | IntAnd
            | IntOr
            | IntLeft
            | IntRight
            | IntSright
            | IntMult
            | IntDiv
            | IntSdiv
            | IntRem
            | IntSrem
    )
}

/// `TypeOp::inheritsSignFirstParamOnly` (`inherits_sign_zero`).
fn inherits_sign_first_only(opc: Opcode) -> bool {
    use Opcode::*;
    matches!(opc, IntLeft | IntRight | IntSright | IntRem | IntSrem)
}

/// `TypeOp::isShiftOp`.
fn is_shift(opc: Opcode) -> bool {
    matches!(opc, Opcode::IntLeft | Opcode::IntRight | Opcode::IntSright)
}

/// Port of `CastStrategyC::castStandard`: the type to cast `cur` to, if `req` needs a cast.
pub(crate) fn cast_standard(
    t: &TypeFactory,
    req: TypeId,
    cur: TypeId,
    mut care_uint_int: bool,
    care_ptr_uint: bool,
) -> Option<TypeId> {
    if cur == req {
        return None;
    }
    if t.meta(cur) == Meta::Void {
        return Some(req);
    }
    let (mut reqbase, mut curbase, mut isptr) = (req, cur, false);
    while let (Some(r), Some(c)) = (t.ptr_to(reqbase), t.ptr_to(curbase)) {
        if pointer_wordsize(t, reqbase) != pointer_wordsize(t, curbase) {
            return Some(req);
        }
        // ponytail: no ported pointer has an address space, so the space test never casts
        reqbase = r;
        curbase = c;
        care_uint_int = true;
        isptr = true;
    }
    let (reqbase, curbase) = (t.strip_typedefs(reqbase), t.strip_typedefs(curbase));
    if curbase == reqbase {
        return None;
    }
    if t.meta(reqbase) == Meta::Void || t.meta(curbase) == Meta::Void {
        return None;
    }
    if t.size(reqbase) != t.size(curbase) {
        // isVariableLength: no ported type has a variable length
        return Some(req);
    }
    let cm = t.meta(curbase);
    match t.meta(reqbase) {
        Meta::Unknown => return None,
        m @ (Meta::Uint | Meta::Int) => {
            if !care_uint_int {
                if matches!(cm, Meta::Unknown | Meta::Int | Meta::Uint | Meta::Bool) {
                    return None;
                }
            } else {
                if cm == m || cm == Meta::Bool {
                    return None;
                }
                if isptr && cm == Meta::Unknown {
                    return None;
                }
            }
            if m == Meta::Uint && !care_ptr_uint && cm == Meta::Ptr {
                return None;
            }
        }
        // a TypeCode with no prototype on either side (no ported code type has one)
        Meta::Code if cm == Meta::Code => return None,
        _ => {}
    }
    Some(req)
}

fn pointer_wordsize(t: &TypeFactory, id: TypeId) -> u32 {
    match t.get(id).kind {
        super::types::Kind::Pointer { wordsize, .. } => wordsize,
        _ => 0,
    }
}

/// Port of `ActionSetCasts::testStructOffset0`: a pointer to the first field of `cur`'s struct
/// (or element of its array) would match `req`.
pub(crate) fn test_struct_offset0(t: &TypeFactory, req: TypeId, cur: TypeId) -> bool {
    let (Some(to), Some(mut req)) = (t.ptr_to(cur), t.ptr_to(req)) else { return false };
    let mut cur = match t.meta(to) {
        Meta::Struct => {
            let Some((0, first)) = t.first_field(to) else { return false };
            first
        }
        Meta::Array => match t.first_field(to) {
            Some((_, elem)) => elem,
            None => return false,
        },
        _ => return false,
    };
    if t.meta(to) == Meta::Struct {
        if t.meta(req) == Meta::Array {
            req = t.first_field(req).map_or(req, |f| f.1);
        }
        if t.meta(cur) == Meta::Array {
            cur = t.first_field(cur).map_or(cur, |f| f.1);
        }
    }
    if t.meta(req) == Meta::Void {
        return false;
    }
    cast_standard(t, req, cur, true, true).is_none()
}

/// Port of `ActionSetCasts::isOpIdentical`.
pub(crate) fn is_op_identical(t: &TypeFactory, mut a: TypeId, mut b: TypeId) -> bool {
    while let (Some(x), Some(y)) = (t.ptr_to(a), t.ptr_to(b)) {
        a = x;
        b = y;
    }
    t.strip_typedefs(a) == t.strip_typedefs(b)
}

/// Port of `CastStrategy::markExplicitUnsigned`.
fn mark_explicit_unsigned(fd: &mut Funcdata, op: OpId, slot: usize) -> Result<bool> {
    let opc = fd.op(op).opc;
    if !inherits_sign(opc) {
        return Ok(false);
    }
    let first_only = inherits_sign_first_only(opc);
    if slot == 1 && first_only {
        return Ok(false);
    }
    let vn = input(fd, op, slot)?;
    if !fd.vn(vn).is_constant() {
        return Ok(false);
    }
    let dt = facing(fd, vn)?;
    if !matches!(fd.types.meta(dt), Meta::Uint | Meta::Unknown) || fd.types.is_char_print(dt) || fd.types.is_enum(dt) {
        return Ok(false);
    }
    if fd.op(op).ins.len() == 2 && !first_only {
        let other = input(fd, op, 1 - slot)?;
        let ot = facing(fd, other)?;
        if matches!(fd.types.meta(ot), Meta::Uint | Meta::Unknown) {
            return Ok(false);
        }
    }
    if let Some(out) = fd.op(op).out {
        if is_explicit(fd, out) {
            return Ok(false);
        }
        if lone_descend(fd, out).is_some_and(|l| !inherits_sign(fd.op(l).opc)) {
            return Ok(false);
        }
    }
    fd.vn_set(vn, VnFlags::UNSIGNED_PRINT);
    Ok(true)
}

/// Port of `CastStrategy::markExplicitLongSize`.
fn mark_explicit_long_size(fd: &mut Funcdata, op: OpId, slot: usize) -> Result<bool> {
    if !is_shift(fd.op(op).opc) || slot != 0 {
        return Ok(false);
    }
    let vn = input(fd, op, slot)?;
    let (is_const, size, mut off) = {
        let v = fd.vn(vn);
        (v.is_constant(), v.size, v.offset)
    };
    if !is_const || size <= PROMOTE_SIZE {
        return Ok(false);
    }
    let ht = high_type(fd, vn)?;
    let meta = fd.types.meta(ht);
    if !matches!(meta, Meta::Uint | Meta::Int | Meta::Unknown) {
        return Ok(false);
    }
    let limit = if meta == Meta::Int && signbit_negative(off, size) {
        off = off.wrapping_neg() & calc_mask(size);
        PROMOTE_SIZE * 8 - 1
    } else {
        PROMOTE_SIZE * 8
    };
    if mostsigbit_set(off) >= limit as i32 {
        return Ok(false);
    }
    fd.vn_set(vn, VnFlags::LONG_PRINT);
    Ok(true)
}

/// Port of `CastStrategyC::localExtensionType`.
fn local_extension_type(fd: &mut Funcdata, vn: VarnodeId) -> Result<i32> {
    let ft = facing(fd, vn)?;
    let natural = match fd.types.meta(ft) {
        Meta::Uint | Meta::Bool | Meta::Unknown => UNSIGNED_EXTENSION,
        Meta::Int => SIGNED_EXTENSION,
        _ => return Ok(UNKNOWN_PROMOTION),
    };
    let v = fd.vn(vn);
    if v.is_constant() {
        return Ok(if signbit_negative(v.offset, v.size) { natural } else { EITHER_EXTENSION });
    }
    if is_explicit(fd, vn) {
        return Ok(natural);
    }
    let Some(def) = v.def else { return Ok(UNKNOWN_PROMOTION) };
    let d = fd.op(def);
    if is_bool_output(d.opc) {
        return Ok(EITHER_EXTENSION);
    }
    if matches!(d.opc, Opcode::Cast | Opcode::Load) || d.is_call() {
        return Ok(natural);
    }
    if d.opc == Opcode::IntAnd {
        let c = fd.vn(input(fd, def, 1)?);
        if c.is_constant() {
            return Ok(if signbit_negative(c.offset, c.size) { natural } else { EITHER_EXTENSION });
        }
    }
    Ok(UNKNOWN_PROMOTION)
}

/// Port of `CastStrategyC::intPromotionType`.
fn int_promotion_type(fd: &mut Funcdata, vn: VarnodeId) -> Result<i32> {
    let v = fd.vn(vn);
    if v.size >= PROMOTE_SIZE {
        return Ok(NO_PROMOTION);
    }
    if v.is_constant() {
        return local_extension_type(fd, vn);
    }
    if is_explicit(fd, vn) {
        return Ok(NO_PROMOTION);
    }
    let Some(op) = v.def else { return Ok(UNKNOWN_PROMOTION) };
    let (in0, in1) = (fd.op(op).ins.first().copied(), fd.op(op).ins.get(1).copied());
    let ext = |fd: &mut Funcdata, v: Option<VarnodeId>| -> Result<i32> {
        local_extension_type(fd, v.ok_or_else(|| LowlevelError("intPromotionType: missing input".into()))?)
    };
    use Opcode::*;
    Ok(match fd.op(op).opc {
        IntAnd => {
            if ext(fd, in1)? & UNSIGNED_EXTENSION != 0 || ext(fd, in0)? & UNSIGNED_EXTENSION != 0 {
                return Ok(UNSIGNED_EXTENSION);
            }
            UNKNOWN_PROMOTION
        }
        IntRight => {
            let val = ext(fd, in0)?;
            if val & UNSIGNED_EXTENSION != 0 {
                val
            } else {
                UNKNOWN_PROMOTION
            }
        }
        IntSright => {
            let val = ext(fd, in0)?;
            if val & SIGNED_EXTENSION != 0 {
                val
            } else {
                UNKNOWN_PROMOTION
            }
        }
        IntXor | IntOr | IntDiv | IntRem => {
            if ext(fd, in0)? & UNSIGNED_EXTENSION == 0 || ext(fd, in1)? & UNSIGNED_EXTENSION == 0 {
                UNKNOWN_PROMOTION
            } else {
                UNSIGNED_EXTENSION
            }
        }
        IntSdiv | IntSrem => {
            if ext(fd, in0)? & SIGNED_EXTENSION == 0 || ext(fd, in1)? & SIGNED_EXTENSION == 0 {
                UNKNOWN_PROMOTION
            } else {
                SIGNED_EXTENSION
            }
        }
        IntNegate | Int2comp => {
            if ext(fd, in0)? & SIGNED_EXTENSION != 0 {
                SIGNED_EXTENSION
            } else {
                UNKNOWN_PROMOTION
            }
        }
        IntAdd | IntSub | IntLeft | IntMult => UNKNOWN_PROMOTION,
        _ => NO_PROMOTION,
    })
}

/// Port of `CastStrategyC::checkIntPromotionForCompare`.
fn check_int_promotion_for_compare(fd: &mut Funcdata, op: OpId, slot: usize) -> Result<bool> {
    let e1 = int_promotion_type(fd, input(fd, op, slot)?)?;
    if e1 == NO_PROMOTION {
        return Ok(false);
    }
    if e1 == UNKNOWN_PROMOTION {
        return Ok(true);
    }
    let e2 = int_promotion_type(fd, input(fd, op, 1 - slot)?)?;
    Ok(e1 & e2 == 0 && e2 != NO_PROMOTION)
}

/// Port of `CastStrategyC::checkIntPromotionForExtension`.
fn check_int_promotion_for_extension(fd: &mut Funcdata, op: OpId) -> Result<bool> {
    let e = int_promotion_type(fd, input(fd, op, 0)?)?;
    let opc = fd.op(op).opc;
    Ok(match e {
        NO_PROMOTION => false,
        UNKNOWN_PROMOTION => true,
        _ if e & UNSIGNED_EXTENSION != 0 && opc == Opcode::IntZext => false,
        _ if e & SIGNED_EXTENSION != 0 && opc == Opcode::IntSext => false,
        _ => true,
    })
}

/// Port of `CastStrategyC::arithmeticOutputStandard`.
fn arithmetic_output_standard(fd: &mut Funcdata, op: OpId) -> Result<TypeId> {
    let ins = fd.op(op).ins.clone();
    let first = *ins.first().ok_or_else(|| LowlevelError("arithmeticOutputStandard: no inputs".into()))?;
    let mut res1 = facing(fd, first)?;
    if fd.types.meta(res1) == Meta::Bool {
        res1 = fd.types.base(fd.types.size(res1), Meta::Int);
    }
    for &vn in &ins[1..] {
        let res2 = facing(fd, vn)?;
        if fd.types.meta(res2) != Meta::Bool && fd.types.order(res2, res1) < 0 {
            res1 = res2;
        }
    }
    Ok(res1)
}

fn not_ported_op<T>(opc: Opcode) -> Result<T> {
    err(format!("setcasts: the cast rules of {opc:?} are not implemented in ghidra-rs yet"))
}

/// Port of `TypeOp::getInputCast` and its overrides: the type input `slot` must be cast to.
fn input_cast(fd: &mut Funcdata, op: OpId, slot: usize) -> Result<Option<TypeId>> {
    use Opcode::*;
    let opc = fd.op(op).opc;
    let vn = input(fd, op, slot)?;
    let promo_case = |fd: &mut Funcdata, need: i32| -> Result<Option<TypeId>> {
        let req = input_local(fd, op, slot);
        let cur = facing(fd, vn)?;
        let p = int_promotion_type(fd, vn)?;
        if p != NO_PROMOTION && p & need == 0 {
            return Ok(Some(req));
        }
        Ok(cast_standard(&fd.types, req, cur, true, true))
    };
    match opc {
        Copy => {
            let req = facing(fd, output(fd, op)?)?;
            let cur = facing(fd, vn)?;
            Ok(cast_standard(&fd.types, req, cur, false, true))
        }
        Load => {
            if slot != 1 {
                return Ok(None);
            }
            let req = facing(fd, output(fd, op)?)?;
            let size = fd.vn(vn).size;
            let cur = facing(fd, vn)?;
            let Some(cur) = fd.types.ptr_to(cur) else { return Ok(Some(fd.types.pointer(size, req, WS))) };
            if cur != req
                && fd.types.size(cur) == fd.types.size(req)
                && !matches!(fd.types.meta(cur), Meta::Struct | Meta::Array | Meta::Spacebase | Meta::Union)
                && !(is_implied(fd, vn) && opc_of(fd, vn) == Some(Cast))
            {
                return Ok(None);
            }
            Ok(cast_standard(&fd.types, req, cur, false, true).map(|r| fd.types.pointer(size, r, WS)))
        }
        Store => {
            if slot == 0 || fd.op(op).flags.has(OpFlags::SPECIAL_PRINT) {
                return Ok(None);
            }
            let ptr_vn = input(fd, op, 1)?;
            let ptr_type = facing(fd, ptr_vn)?;
            let value_type = facing(fd, input(fd, op, 2)?)?;
            let ptr_size = fd.vn(ptr_vn).size;
            let pointed = fd.types.ptr_to(ptr_type);
            if pointed.map(|p| fd.types.size(p)) != Some(fd.types.size(value_type)) {
                return Ok((slot == 1).then(|| fd.types.pointer(ptr_size, value_type, WS)));
            }
            if slot == 1 {
                if opc_of(fd, ptr_vn) == Some(Cast) && is_implied(fd, ptr_vn) && lone_descend(fd, ptr_vn) == Some(op) {
                    let new_type = fd.types.pointer(ptr_size, value_type, WS);
                    if ptr_type != new_type {
                        return Ok(Some(new_type));
                    }
                }
                return Ok(None);
            }
            Ok(pointed.and_then(|p| cast_standard(&fd.types, p, value_type, false, true)))
        }
        IntEqual | IntNotequal => {
            let mut req = facing(fd, input(fd, op, 0)?)?;
            let other = facing(fd, input(fd, op, 1)?)?;
            if fd.types.order(other, req) < 0 {
                req = other;
            }
            if check_int_promotion_for_compare(fd, op, slot)? {
                return Ok(Some(req));
            }
            let cur = facing(fd, vn)?;
            Ok(cast_standard(&fd.types, req, cur, false, false))
        }
        IntSless | IntSlessequal | IntLess | IntLessequal => {
            let req = input_local(fd, op, slot);
            if check_int_promotion_for_compare(fd, op, slot)? {
                return Ok(Some(req));
            }
            let cur = facing(fd, vn)?;
            Ok(cast_standard(&fd.types, req, cur, true, matches!(opc, IntSless | IntSlessequal)))
        }
        IntZext | IntSext => {
            let req = input_local(fd, op, slot);
            if check_int_promotion_for_extension(fd, op)? {
                return Ok(Some(req));
            }
            let cur = facing(fd, vn)?;
            Ok(cast_standard(&fd.types, req, cur, true, false))
        }
        IntRight if slot == 0 => promo_case(fd, UNSIGNED_EXTENSION),
        IntSright if slot == 0 => promo_case(fd, SIGNED_EXTENSION),
        IntDiv | IntRem => promo_case(fd, UNSIGNED_EXTENSION),
        IntSdiv | IntSrem => promo_case(fd, SIGNED_EXTENSION),
        FloatInt2float => {
            // absorbZext: no cast when the input is an implied INT_ZEXT
            if is_implied(fd, vn) && opc_of(fd, vn) == Some(IntZext) {
                return Ok(None);
            }
            let req = input_local(fd, op, slot);
            let cur = facing(fd, vn)?;
            let size = fd.vn(vn).size;
            let care = size > 8 || (fd.nzmask(vn) >> (8 * size - 1)) & 1 != 0;
            Ok(cast_standard(&fd.types, req, cur, care, true))
        }
        Piece | Subpiece => Ok(None),
        Ptradd | Ptrsub if slot == 0 => {
            let req = vn_facing(fd, vn)?;
            let cur = facing(fd, vn)?;
            if opc == Ptrsub && cur == req {
                return Ok(None);
            }
            let (Some(mut rb), Some(mut cb)) = (fd.types.ptr_to(req), fd.types.ptr_to(cur)) else {
                return Ok(Some(req));
            };
            if opc == Ptradd {
                return Ok((fd.types.align_size(rb) != fd.types.align_size(cb)).then_some(req));
            }
            if fd.types.meta(cb) == Meta::Array && fd.types.meta(rb) == Meta::Array {
                cb = fd.types.first_field(cb).map_or(cb, |f| f.1);
                rb = fd.types.first_field(rb).map_or(rb, |f| f.1);
            }
            Ok((fd.types.strip_typedefs(cb) != fd.types.strip_typedefs(rb)).then_some(req))
        }
        // TypeOpCpoolref and TypeOpNew: never cast (typeop.hh)
        Cpoolref | New => Ok(None),
        Segmentop | Insert | Zpull | Spull => not_ported_op(opc),
        _ => {
            if fd.vn(vn).is_annotation() {
                return Ok(None);
            }
            let req = input_local(fd, op, slot);
            let cur = facing(fd, vn)?;
            Ok(cast_standard(&fd.types, req, cur, false, true))
        }
    }
}

/// Port of `TypeOp::getOutputToken` and its overrides: the type the op produces.
fn output_token(fd: &mut Funcdata, arch: &Arch, op: OpId) -> Result<TypeId> {
    use Opcode::*;
    let opc = fd.op(op).opc;
    let out = output(fd, op)?;
    let out_size = fd.vn(out).size;
    match opc {
        Copy | Ptradd => facing(fd, input(fd, op, 0)?),
        Load => {
            let ct = facing(fd, input(fd, op, 1)?)?;
            match fd.types.ptr_to(ct) {
                Some(to) if fd.types.size(to) == out_size => Ok(to),
                _ => facing(fd, out),
            }
        }
        IntAdd | IntSub | Int2comp | IntNegate | IntXor | IntAnd | IntOr | IntMult => {
            arithmetic_output_standard(fd, op)
        }
        IntLeft | IntRight | IntSright => {
            let res = facing(fd, input(fd, op, 0)?)?;
            Ok(if fd.types.meta(res) == Meta::Bool { fd.types.base(fd.types.size(res), Meta::Int) } else { res })
        }
        Piece => {
            let dt = facing(fd, out)?;
            Ok(if matches!(fd.types.meta(dt), Meta::Int | Meta::Uint) {
                dt
            } else {
                fd.types.base(out_size, Meta::Uint)
            })
        }
        Subpiece => {
            let ct = facing(fd, input(fd, op, 0)?)?;
            if matches!(fd.types.meta(ct), Meta::Struct | Meta::Union) {
                return err(
                    "setcasts: findTruncation of a SUBPIECE of a struct or union is not implemented in ghidra-rs yet",
                );
            }
            let dt = facing(fd, out)?;
            Ok(if fd.types.meta(dt) != Meta::Unknown { dt } else { fd.types.base(out_size, Meta::Int) })
        }
        Ptrsub => {
            let ptype = facing(fd, input(fd, op, 0)?)?;
            if fd.types.meta(ptype) != Meta::Ptr {
                return output_local(fd, op);
            }
            let offset = fd.vn(input(fd, op, 1)?).offset as i64 * i64::from(WS);
            if let Some((ret, 0)) = down_chain(fd, arch, ptype, offset, false)? {
                return Ok(ret);
            }
            let u1 = fd.types.base(1, Meta::Unknown);
            Ok(fd.types.pointer(out_size, u1, WS))
        }
        Segmentop | Insert | Zpull | Spull => not_ported_op(opc),
        _ => output_local(fd, op),
    }
}

/// Port of `ActionSetCasts::tryResolutionAdjustment` up to the resolution, which fails.
fn try_resolution_adjustment(fd: &mut Funcdata, dt: TypeId, vn: VarnodeId) -> Result<bool> {
    if fd.types.needs_resolution(dt) {
        return Ok(false);
    }
    let cur = high_type(fd, vn)?;
    if !fd.types.needs_resolution(cur) {
        return Ok(false);
    }
    unresolved()
}

/// Port of `ActionSetCasts::tryResolutionCopy` up to the resolution, which fails.
fn try_resolution_copy(fd: &mut Funcdata, op: OpId) -> Result<bool> {
    let Some(out) = fd.op(op).out else { return Ok(false) };
    let out_type = high_type(fd, out)?;
    let in_type = high_type(fd, input(fd, op, 0)?)?;
    if !fd.types.needs_resolution(in_type) && !fd.types.needs_resolution(out_type) {
        return Ok(false);
    }
    unresolved()
}

/// Port of `ActionSetCasts::resolveUnion` up to the resolution, which fails.
fn resolve_union(fd: &mut Funcdata, op: OpId, slot: usize) -> Result<i32> {
    let vn = input(fd, op, slot)?;
    if fd.vn(vn).is_annotation() {
        return Ok(0);
    }
    let dt = high_type(fd, vn)?;
    if fd.types.needs_resolution(dt) {
        return unresolved();
    }
    Ok(0)
}

fn uniq(fd: &Funcdata) -> Result<u32> {
    fd.uniq.ok_or_else(|| LowlevelError("no unique space".into()))
}

/// Port of `ActionSetCasts::insertPtrsubZero`.
fn insert_ptrsub_zero(fd: &mut Funcdata, op: OpId, slot: usize, ct: TypeId) -> Result<OpId> {
    let vn = input(fd, op, slot)?;
    let size = fd.vn(vn).size;
    let newop = fd.new_op(Opcode::Ptrsub, fd.op(op).seq.addr);
    let vnout = fd.new_unique_out(size, uniq(fd)?, newop);
    update_type(fd, vnout, ct);
    fd.vn_set(vnout, VnFlags::IMPLIED);
    fd.op_set_input(newop, vn, 0)?;
    let zero = fd.new_constant(4, 0);
    fd.op_set_input(newop, zero, 1)?;
    fd.op_set_input(op, vnout, slot)?;
    fd.op_insert_before(newop, op)?;
    Ok(newop)
}

/// Port of `ActionSetCasts::castOutput`.
fn cast_output(fd: &mut Funcdata, arch: &Arch, op: OpId) -> Result<i32> {
    let tokenct = output_token(fd, arch, op)?;
    let outvn = output(fd, op)?;
    let out_high = high_type(fd, outvn)?;
    if tokenct == out_high {
        if fd.types.needs_resolution(tokenct) {
            return unresolved();
        }
        return Ok(0);
    }
    let mut out_res = facing(fd, outvn)?;
    let mut force = false;
    if is_implied(fd, outvn) {
        if fd.vn(outvn).has(VnFlags::TYPELOCK) {
            // the input of a RETURN is implied, but casts as if it were explicit
            if lone_descend(fd, outvn).is_none_or(|o| fd.op(o).opc != Opcode::Return) {
                force = !is_op_identical(&fd.types, out_res, tokenct);
            }
        } else if fd.types.meta(out_res) != Meta::Ptr {
            update_type(fd, outvn, tokenct);
            out_res = facing(fd, outvn)?;
        } else if fd.types.meta(tokenct) == Meta::Ptr {
            let to = fd.types.ptr_to(out_res).map(|t| fd.types.meta(t));
            if !matches!(to, Some(Meta::Array | Meta::Struct | Meta::Union)) {
                update_type(fd, outvn, tokenct);
                out_res = facing(fd, outvn)?;
            }
        }
    }
    let mut opc = Opcode::Cast;
    if !force {
        if fd.types.meta(out_res) == Meta::Ptr && test_struct_offset0(&fd.types, out_res, tokenct) {
            opc = Opcode::Ptrsub;
        } else if cast_standard(&fd.types, out_res, tokenct, false, true).is_none() {
            return Ok(0);
        }
        if try_resolution_adjustment(fd, tokenct, outvn)? {
            return Ok(0);
        }
    }
    let vn = fd.new_unique(fd.vn(outvn).size, uniq(fd)?);
    update_type(fd, vn, tokenct);
    fd.vn_set(vn, VnFlags::IMPLIED);
    let newop = fd.new_op(opc, fd.op(op).seq.addr);
    fd.op_set_output(newop, outvn)?;
    fd.op_set_input(newop, vn, 0)?;
    if opc != Opcode::Cast {
        let zero = fd.new_constant(4, 0);
        fd.op_set_input(newop, zero, 1)?;
    }
    fd.op_set_output(op, vn)?;
    fd.op_insert_after(newop, op)?;
    if fd.types.needs_resolution(tokenct) || fd.types.needs_resolution(out_high) {
        return unresolved();
    }
    Ok(1)
}

/// Port of `ActionSetCasts::castInput`.
fn cast_input(fd: &mut Funcdata, op: OpId, slot: usize) -> Result<i32> {
    let Some(ct) = input_cast(fd, op, slot)? else {
        let unsigned = mark_explicit_unsigned(fd, op, slot)?;
        let sized = mark_explicit_long_size(fd, op, slot)?;
        return Ok(i32::from(unsigned || sized));
    };
    let vn = input(fd, op, slot)?;
    let mut vnin = vn;
    let opc = fd.op(op).opc;
    if opc_of(fd, vn) == Some(Opcode::Cast) {
        // no double cast
        if is_implied(fd, vn) {
            if lone_descend(fd, vn) == Some(op) {
                update_type(fd, vn, ct);
                if vn_type(fd, vn) == ct {
                    return Ok(1);
                }
            }
            let def = fd.vn(vn).def.ok_or_else(|| LowlevelError("setcasts: CAST output without op".into()))?;
            vnin = input(fd, def, 0)?;
            if vn_type(fd, vnin) == ct {
                fd.op_set_input(op, vnin, slot)?;
                return Ok(1);
            }
        }
    } else if fd.vn(vn).is_constant() {
        update_type(fd, vn, ct);
        if vn_type(fd, vn) == ct {
            return Ok(1);
        }
    } else if fd.types.meta(ct) == Meta::Ptr && {
        let cur = facing(fd, vn)?;
        test_struct_offset0(&fd.types, ct, cur)
    } {
        insert_ptrsub_zero(fd, op, slot, ct)?;
        let ht = high_type(fd, vn)?;
        if fd.types.needs_resolution(ht) {
            return unresolved();
        }
        return Ok(1);
    } else if (opc != Opcode::Copy && try_resolution_adjustment(fd, ct, vn)?)
        || (opc == Opcode::Copy && try_resolution_copy(fd, op)?)
    {
        return Ok(1);
    }
    let newop = fd.new_op(Opcode::Cast, fd.op(op).seq.addr);
    let vnout = fd.new_unique_out(fd.vn(vnin).size, uniq(fd)?, newop);
    update_type(fd, vnout, ct);
    fd.vn_set(vnout, VnFlags::IMPLIED);
    fd.op_set_input(newop, vnin, 0)?;
    fd.op_set_input(op, vnout, slot)?;
    fd.op_insert_before(newop, op)?;
    let ht = high_type(fd, vn)?;
    if fd.types.needs_resolution(ct) || fd.types.needs_resolution(ht) {
        return unresolved();
    }
    Ok(1)
}

/// Port of `ActionSetCasts::checkPointerIssues`: warn when a LOAD or STORE's pointer does not
/// point to a value of its size.
fn check_pointer_issues(fd: &mut Funcdata, op: OpId, vn: VarnodeId) -> Result<()> {
    if fd.op(op).flags.has(OpFlags::SPECIAL_PRINT) {
        return Ok(());
    }
    let ptype = facing(fd, input(fd, op, 1)?)?;
    let valsize = fd.vn(vn).size;
    if fd.types.ptr_to(ptype).is_none_or(|to| fd.types.size(to) != valsize) {
        let name = if fd.op(op).opc == Opcode::Load { "Load" } else { "Store" };
        fd.warning(&format!("{name} size is inaccurate"), fd.op(op).seq.addr);
    }
    Ok(())
}

/// `PcodeOp::notPrinted`: a marker or a non-printing op. `PcodeOp::noreturn` is left out because
/// the Rust never creates a noreturn halt: `fail_callother` fails loudly (flow.rs, the jump-table
/// recovery) and no console prototype says a call does not return (`setup_call_specs`).
fn not_printed(fd: &Funcdata, op: OpId) -> bool {
    let o = fd.op(op);
    o.is_marker() || o.flags.has(OpFlags::NONPRINTING)
}

/// The PTRADD and PTRSUB checks of `ActionSetCasts::apply`: undo one that no longer fits the
/// pointer it reads.
fn check_pointer_op(fd: &mut Funcdata, arch: &Arch, op: OpId) -> Result<()> {
    match fd.op(op).opc {
        Opcode::Ptradd => {
            let sz = i64::from(fd.vn(input(fd, op, 2)?).offset as i32);
            let ct = facing(fd, input(fd, op, 0)?)?;
            let fits = fd.types.ptr_to(ct).is_some_and(|to| i64::from(fd.types.align_size(to)) == sz * i64::from(WS));
            if !fits {
                op_undo_ptradd(fd, op, true)?;
            }
        }
        Opcode::Ptrsub => {
            let ct = vn_facing(fd, input(fd, op, 0)?)?;
            let off = fd.vn(input(fd, op, 1)?).offset;
            if !is_ptrsub_matching(fd, arch, ct, off as i64, 0, 0)? {
                if off == 0 {
                    fd.op_remove_input(op, 1);
                    fd.op_set_opcode(op, Opcode::Copy);
                } else {
                    fd.op_set_opcode(op, Opcode::IntAdd);
                }
            }
        }
        _ => {}
    }
    Ok(())
}

/// Port of `ActionSetCasts::apply`.
pub(crate) fn set_casts(fd: &mut Funcdata, arch: &Arch) -> Result<i32> {
    for bl in fd.blocks.list.clone() {
        let mut at = 0;
        while let Some(&op) = fd.blocks.block(bl).ops.get(at) {
            cast_op(fd, arch, op)?;
            // ops inserted before `op` move it; a CAST inserted after it is skipped next
            at = fd.blocks.block(bl).ops.iter().position(|&o| o == op).unwrap_or(at) + 1;
        }
    }
    Ok(0)
}

/// One op of `ActionSetCasts::apply`.
fn cast_op(fd: &mut Funcdata, arch: &Arch, op: OpId) -> Result<()> {
    if not_printed(fd, op) {
        return Ok(());
    }
    let opc = fd.op(op).opc;
    if opc == Opcode::Cast {
        return Ok(());
    }
    check_pointer_op(fd, arch, op)?;
    for i in 0..fd.op(op).ins.len() {
        resolve_union(fd, op, i)?;
    }
    let out = fd.op(op).out;
    if let Some(o) = out {
        let ht = high_type(fd, o)?;
        if fd.types.needs_resolution(ht) {
            return unresolved();
        }
    }
    let mut i = 0;
    while i < fd.op(op).ins.len() {
        cast_input(fd, op, i)?;
        i += 1;
    }
    match opc {
        Opcode::Load => check_pointer_issues(fd, op, output(fd, op)?)?,
        Opcode::Store => check_pointer_issues(fd, op, input(fd, op, 2)?)?,
        _ => {}
    }
    if out.is_some() {
        cast_output(fd, arch, op)?;
    }
    Ok(())
}

/// `Varnode::getHighTypeReadFacing` / `getHighTypeDefFacing` for the printer (a type that needs
/// resolution fails loudly).
pub(crate) fn print_facing(fd: &mut Funcdata, vn: VarnodeId) -> Result<TypeId> {
    facing(fd, vn)
}

/// Port of `CastStrategyC::isExtensionCastImplied`: whether the extension `op`, read by
/// `read_op`, is an integer promotion C does on its own (then printed hidden).
pub(crate) fn is_extension_cast_implied(fd: &mut Funcdata, op: OpId, read_op: Option<OpId>) -> Result<bool> {
    let out = output(fd, op)?;
    if is_explicit(fd, out) {
        return Ok(false);
    }
    let Some(read_op) = read_op else { return Ok(false) };
    let outtype = facing(fd, out)?;
    let metatype = fd.types.meta(outtype);
    use Opcode::*;
    match fd.op(read_op).opc {
        Ptradd => {}
        IntAdd | IntSub | IntMult | IntDiv | IntAnd | IntOr | IntXor | IntEqual | IntNotequal | IntLess
        | IntLessequal | IntSless | IntSlessequal => {
            let slot =
                fd.slot_of(read_op, out).ok_or_else(|| LowlevelError("PcodeOp::getSlot: not an input".into()))?;
            let other = input(fd, read_op, 1 - slot)?;
            if fd.vn(other).is_constant() {
                // a constant bigger than the promotion size is not extended naturally
                if fd.vn(other).size > PROMOTE_SIZE {
                    return Ok(false);
                }
            } else if !is_explicit(fd, other) {
                return Ok(false);
            }
            let othertype = facing(fd, other)?;
            if fd.types.meta(othertype) != metatype {
                return Ok(false);
            }
        }
        _ => return Ok(false),
    }
    Ok(true)
}

/// Port of `CastStrategyC::isSubpieceCast`: a SUBPIECE of the low bytes that prints as a cast
/// (the partial struct and union metatypes are not ported).
pub(crate) fn is_subpiece_cast(t: &TypeFactory, outtype: TypeId, intype: TypeId, offset: u64) -> bool {
    if offset != 0 {
        return false;
    }
    let inmeta = t.meta(intype);
    if !matches!(inmeta, Meta::Int | Meta::Uint | Meta::Unknown | Meta::Ptr) {
        return false;
    }
    let outmeta = t.meta(outtype);
    if !matches!(outmeta, Meta::Int | Meta::Uint | Meta::Unknown | Meta::Ptr | Meta::Float) {
        return false;
    }
    if inmeta == Meta::Ptr {
        if outmeta == Meta::Ptr && t.size(outtype) < t.size(intype) {
            return true; // a far pointer to a near pointer
        }
        if !matches!(outmeta, Meta::Int | Meta::Uint) {
            return false;
        }
    }
    true
}

/// Port of `CastStrategyC::isSextCast`: the input must be signed (or boolean).
pub(crate) fn is_sext_cast(t: &TypeFactory, outtype: TypeId, intype: TypeId) -> bool {
    matches!(t.meta(outtype), Meta::Uint | Meta::Int) && matches!(t.meta(intype), Meta::Int | Meta::Bool)
}

/// Port of `CastStrategyC::isZextCast`: the input must be unsigned (or boolean).
pub(crate) fn is_zext_cast(t: &TypeFactory, outtype: TypeId, intype: TypeId) -> bool {
    matches!(t.meta(outtype), Meta::Uint | Meta::Int) && matches!(t.meta(intype), Meta::Uint | Meta::Bool)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cast_standard_rules() {
        let mut t = TypeFactory::new();
        let (i4, u4, x4, b1, i1) = (
            t.base(4, Meta::Int),
            t.base(4, Meta::Uint),
            t.base(4, Meta::Unknown),
            t.base(1, Meta::Bool),
            t.base(1, Meta::Int),
        );
        let void = t.base(1, Meta::Void);
        // equal types, unknown targets and sign changes without care need no cast
        assert_eq!(cast_standard(&t, i4, i4, true, true), None);
        assert_eq!(cast_standard(&t, x4, i4, true, true), None);
        assert_eq!(cast_standard(&t, i4, u4, false, true), None);
        // with care the sign matters, and a size change always casts
        assert_eq!(cast_standard(&t, i4, u4, true, true), Some(i4));
        assert_eq!(cast_standard(&t, i4, i1, false, true), Some(i4));
        assert_eq!(cast_standard(&t, i4, void, false, true), Some(i4));
        assert_eq!(cast_standard(&t, b1, i1, false, true), Some(b1));
        // pointers: compared through what they point to, void pointers never cast
        let (pi, pu, px, pv) = (t.pointer(4, i4, 1), t.pointer(4, u4, 1), t.pointer(4, x4, 1), t.pointer(4, void, 1));
        assert_eq!(cast_standard(&t, pi, pu, false, true), Some(pi));
        assert_eq!(cast_standard(&t, pi, px, false, true), None);
        assert_eq!(cast_standard(&t, pv, pi, false, true), None);
        // a pointer into uint is a cast only when the pointer side matters
        assert_eq!(cast_standard(&t, u4, pi, false, false), None);
        assert_eq!(cast_standard(&t, u4, pi, false, true), Some(u4));
        // typedefs of one type are the same type
        let td = t.typedef(i4, "myint");
        assert_eq!(cast_standard(&t, td, i4, true, true), None);
        let ptd = t.pointer(4, td, 1);
        assert!(is_op_identical(&t, ptd, pi));
    }

    #[test]
    fn struct_offset0() {
        let mut t = TypeFactory::new();
        let (i4, c) = (t.base(4, Meta::Int), t.base(1, Meta::Int));
        let s = t.aggregate("s", false, vec![("a".into(), i4), ("c".into(), c)]).unwrap();
        let (ps, pi, pc) = (t.pointer(4, s, 1), t.pointer(4, i4, 1), t.pointer(4, c, 1));
        assert!(test_struct_offset0(&t, pi, ps));
        assert!(!test_struct_offset0(&t, pc, ps));
        let arr = t.array_of(c, 4).unwrap();
        let pa = t.pointer(4, arr, 1);
        assert!(test_struct_offset0(&t, pc, pa));
        assert!(!test_struct_offset0(&t, pi, pi));
    }

    #[test]
    fn sign_flags() {
        assert!(inherits_sign(Opcode::IntAdd) && !inherits_sign(Opcode::IntZext));
        assert!(inherits_sign_first_only(Opcode::IntSrem) && !inherits_sign_first_only(Opcode::IntSdiv));
        assert!(is_shift(Opcode::IntSright) && !is_shift(Opcode::IntMult));
        assert!(signbit_negative(0x80, 1) && !signbit_negative(0x7f, 1) && !signbit_negative(1, 0));
    }

    /// The printer-only casts: an extension is a cast when the input's sign matches it, a
    /// SUBPIECE when it keeps the low bytes of an integer or pointer.
    #[test]
    fn printer_casts() {
        let mut t = TypeFactory::new();
        let (i4, u4, x4, b1, i1, u1) = (
            t.base(4, Meta::Int),
            t.base(4, Meta::Uint),
            t.base(4, Meta::Unknown),
            t.base(1, Meta::Bool),
            t.base(1, Meta::Int),
            t.base(1, Meta::Uint),
        );
        let f4 = t.base(4, Meta::Float);
        assert!(is_zext_cast(&t, u4, u1) && is_zext_cast(&t, i4, b1) && !is_zext_cast(&t, u4, i1));
        assert!(is_sext_cast(&t, i4, i1) && is_sext_cast(&t, u4, b1) && !is_sext_cast(&t, i4, u1));
        assert!(!is_zext_cast(&t, x4, u1) && !is_sext_cast(&t, x4, i1));
        assert!(is_subpiece_cast(&t, i1, i4, 0) && !is_subpiece_cast(&t, i1, i4, 1));
        assert!(is_subpiece_cast(&t, f4, x4, 0) && !is_subpiece_cast(&t, b1, i4, 0));
        let (p4, p2) = (t.pointer(4, i4, 1), t.pointer(2, i4, 1));
        assert!(is_subpiece_cast(&t, p2, p4, 0) && is_subpiece_cast(&t, u1, p4, 0));
        assert!(!is_subpiece_cast(&t, f4, p4, 0));
    }
}
