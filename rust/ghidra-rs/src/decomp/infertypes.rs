//! Type inference (stage S6): `ActionStartTypes`, `ActionInferTypes` and
//! `ActionConstantPtr` (coreaction.cc), the local types and propagation rules of `typeop.cc`
//! they read, `Funcdata::spacebaseConstant`, and the global-scope lookups they need
//! (`Scope::queryContainer` over the console's `map function` and `map externalref` symbols).
//! Propagation order and conditions follow the C++ exactly.

use super::funcdata::Funcdata;
use super::op::OpId;
use super::opcode::Opcode;
use super::rangeutil::{bit_transitions, calc_mask};
use super::types::{Kind, Meta, TypeId, GLOBAL_SCOPE, LOCAL_SCOPE};
use super::varnode::{Space, VarnodeId, VnFlags, CONST_SPACE};
use super::{err, Arch, Result};

/// ponytail: every x86 space has word size 1; read `AddrSpace::getWordSize` for other targets.
const WS: u32 = 1;

/// The varnode's data-type (`Varnode::getType`): every varnode starts as
/// `getBase(size, TYPE_UNKNOWN)`.
pub(crate) fn vn_type(fd: &mut Funcdata, vn: VarnodeId) -> TypeId {
    let v = fd.vn(vn);
    match v.ty {
        Some(t) => t,
        None => {
            let size = v.size;
            fd.types.base(size, Meta::Unknown)
        }
    }
}

/// Port of `Varnode::updateType(ct, lock, override)`.
pub(crate) fn update_type(fd: &mut Funcdata, vn: VarnodeId, ct: TypeId, mut lock: bool, overrid: bool) -> bool {
    if fd.types.meta(ct) == Meta::Unknown {
        lock = false;
    }
    let locked = fd.vn(vn).has(VnFlags::TYPELOCK);
    if locked && !overrid {
        return false;
    }
    if vn_type(fd, vn) == ct && locked == lock {
        return false;
    }
    let v = fd.vn_mut(vn);
    v.flags.clear(VnFlags::TYPELOCK);
    if lock {
        v.flags.set(VnFlags::TYPELOCK);
    }
    v.ty = Some(ct);
    true
}

/// The output and input metatypes of the `TypeOpBinary`, `TypeOpUnary` and `TypeOpFunc` ops
/// (their constructors in typeop.cc).
fn op_meta(opc: Opcode) -> Option<(Meta, Meta)> {
    use Meta::*;
    use Opcode as O;
    Some(match opc {
        O::IntEqual | O::IntNotequal | O::IntSless | O::IntSlessequal | O::IntScarry | O::IntSborrow => (Bool, Int),
        O::IntLess | O::IntLessequal | O::IntCarry => (Bool, Uint),
        O::IntZext | O::IntNegate | O::IntXor | O::IntAnd | O::IntOr | O::IntRight | O::IntDiv | O::IntRem => {
            (Uint, Uint)
        }
        O::IntSext
        | O::IntAdd
        | O::IntSub
        | O::Int2comp
        | O::IntLeft
        | O::IntSright
        | O::IntMult
        | O::IntSdiv
        | O::IntSrem => (Int, Int),
        O::BoolNegate | O::BoolXor | O::BoolAnd | O::BoolOr => (Bool, Bool),
        O::FloatEqual | O::FloatNotequal | O::FloatLess | O::FloatLessequal | O::FloatNan => (Bool, Float),
        O::FloatAdd
        | O::FloatDiv
        | O::FloatMult
        | O::FloatSub
        | O::FloatNeg
        | O::FloatAbs
        | O::FloatSqrt
        | O::FloatFloat2float
        | O::FloatCeil
        | O::FloatFloor
        | O::FloatRound => (Float, Float),
        O::FloatInt2float => (Float, Int),
        O::FloatTrunc => (Int, Float),
        O::Insert => (Unknown, Int),
        O::Zpull => (Uint, Int),
        O::Popcount => (Int, Unknown),
        _ => return None,
    })
}

/// A pointer of `size` bytes to `code` (`getTypePointer(size, getTypeCode(), ws)`).
fn code_ptr(fd: &mut Funcdata, size: u32) -> TypeId {
    let code = fd.types.code();
    fd.types.pointer(size, code, WS)
}

/// A pointer of `size` bytes to `xunknown1`: what a space-base register propagates as.
fn unknown_ptr(fd: &mut Funcdata, size: u32) -> TypeId {
    let u1 = fd.types.base(1, Meta::Unknown);
    fd.types.pointer(size, u1, WS)
}

/// Port of `TypeOp::getOutputLocal` and its overrides (`PcodeOp::outputTypeLocal`); a call
/// with a locked output gives its type.
pub(crate) fn output_local(fd: &mut Funcdata, op: OpId) -> Result<TypeId> {
    if let Some(t) = locked_output_type(fd, op) {
        return Ok(t);
    }
    let o = fd.op(op);
    let Some(out) = o.out else { return err("outputTypeLocal: op without output") };
    let size = fd.vn(out).size;
    let meta = match o.opc {
        Opcode::Ptrsub | Opcode::Ptradd => Meta::Int,
        opc => op_meta(opc).map_or(Meta::Unknown, |m| m.0),
    };
    Ok(fd.types.base(size, meta))
}

/// Port of `TypeOp::getInputLocal` and its overrides (`PcodeOp::inputTypeLocal`).
pub(crate) fn input_local(fd: &mut Funcdata, op: OpId, slot: usize) -> TypeId {
    if let Some(t) = locked_input_type(fd, op, slot) {
        return t;
    }
    let o = fd.op(op);
    let opc = o.opc;
    let size = fd.vn(o.ins[slot]).size;
    let in0 = fd.vn(o.ins[0]).size;
    match opc {
        Opcode::Cbranch if slot == 1 => fd.types.base(size, Meta::Bool),
        Opcode::Cbranch | Opcode::Callind if slot == 0 => code_ptr(fd, size),
        Opcode::Indirect if slot == 1 => code_ptr(fd, in0),
        Opcode::IntLeft | Opcode::IntRight | Opcode::IntSright if slot == 1 => fd.types.base_nochar(size, Meta::Int),
        Opcode::Ptrsub | Opcode::Ptradd => fd.types.base(size, Meta::Int),
        opc => fd.types.base(size, op_meta(opc).map_or(Meta::Unknown, |m| m.1)),
    }
}

/// Port of `Varnode::getLocalType`. No `stopsTypePropagation`/`stopsUpPropagation` check: the
/// flag is set only by `RulePtrArith`, `RuleStructOffset0` and `RulePushPtr` (stage R5, toggled off
/// in every check); none of R1's rules sets it or makes a PTRSUB/PTRADD. Port both checks with R5.
fn local_type(fd: &mut Funcdata, vn: VarnodeId) -> Result<TypeId> {
    if fd.vn(vn).has(VnFlags::TYPELOCK) {
        return Ok(vn_type(fd, vn));
    }
    let mut ct = match fd.vn(vn).def {
        Some(def) => Some(output_local(fd, def)?),
        None => None,
    };
    let readers = fd.vn(vn).descend.to_vec();
    for op in readers {
        let slot = fd.slot_of(op, vn).unwrap_or(0);
        let newct = input_local(fd, op, slot);
        ct = match ct {
            Some(c) if fd.types.order(newct, c) >= 0 => Some(c),
            _ => Some(newct),
        };
    }
    ct.map_or_else(|| err("NULL local type"), Ok)
}

/// The temporary types and marks of one `ActionInferTypes` pass (`Varnode::temp`, `mark`).
struct Infer {
    temp: Vec<Option<TypeId>>,
    mark: Vec<bool>,
}

impl Infer {
    fn temp(&self, fd: &mut Funcdata, vn: VarnodeId) -> TypeId {
        match self.temp.get(vn.0 as usize).copied().flatten() {
            Some(t) => t,
            None => vn_type(fd, vn),
        }
    }
    fn set_temp(&mut self, vn: VarnodeId, t: TypeId) {
        let i = vn.0 as usize;
        if i >= self.temp.len() {
            self.temp.resize(i + 1, None);
            self.mark.resize(i + 1, false);
        }
        self.temp[i] = Some(t);
    }
}

/// Whether type inference skips `vn`: an annotation, or neither written nor read.
fn skipped(fd: &Funcdata, vn: VarnodeId) -> bool {
    let v = fd.vn(vn);
    v.is_annotation() || (!v.is_written() && v.descend.is_empty())
}

/// Port of `TypeOp::propagateToPointer`.
fn to_pointer(fd: &mut Funcdata, dt: TypeId, size: u32) -> TypeId {
    let dt = if fd.types.meta(dt) == Meta::Ptr { fd.types.base(fd.types.size(dt), Meta::Unknown) } else { dt };
    fd.types.pointer(size, dt, WS)
}

/// Port of `TypeOp::propagateFromPointer`.
fn from_pointer(fd: &Funcdata, dt: TypeId, size: u32) -> Result<Option<TypeId>> {
    let Some(to) = fd.types.ptr_to(dt) else { return Ok(None) };
    if fd.types.size(to) == size {
        return Ok(Some(to));
    }
    if matches!(fd.types.get(to).kind, Kind::Enum(_)) {
        return err("type propagation to a partial enum: not implemented in ghidra-rs yet");
    }
    Ok(None)
}

/// Port of `Datatype::getSubType`, with `TypeSpacebase::getSubType` answered from the scopes.
fn sub_type(fd: &mut Funcdata, arch: &Arch, t: TypeId, off: i64) -> Result<Option<(TypeId, i64)>> {
    if matches!(fd.types.get(t).kind, Kind::Fields(_) | Kind::Enum(_)) {
        return err("type propagation into a struct, union or enum: not implemented in ghidra-rs yet");
    }
    if let Kind::Spacebase { scope, .. } = fd.types.get(t).kind {
        let addr = off as u64 & calc_mask(arch.spec.stack_pointer.2);
        if scope == GLOBAL_SCOPE {
            if let Some(e) = query_global(arch, addr) {
                let ty = e.symbol_type(fd, arch);
                return Ok(Some((ty, (addr - e.addr) as i64)));
            }
        }
        // the local scope holds no symbols before `localrecovery`; its range
        // (`ScopeLocal::resetLocalWindow`) is the prototype's local range, the default
        // `ProtoModel::defaultLocalRange` (the upper half of the stack), and its parameter
        // range. ponytail: the parameter range is x86win.cspec's stack `<pentry>` (offset 4,
        // maxsize 500); read it from the model when another `.cspec` is used.
        let highest = calc_mask(arch.spec.stack_pointer.2);
        let local_first = highest - (highest >> 1).min(0x7fff_ffff);
        if scope != GLOBAL_SCOPE && addr < local_first && !(4..504).contains(&addr) {
            return Ok(None);
        }
        return Ok(Some((fd.types.base(1, Meta::Unknown), 0)));
    }
    Ok(fd.types.sub_type(t, off))
}

fn sign_extend(v: u64, bit: u32) -> i64 {
    let sh = 63 - bit;
    ((v << sh) as i64) >> sh
}

/// Port of `TypePointer::downChain`. Returns the new pointer and the remaining offset.
fn down_chain(
    fd: &mut Funcdata,
    arch: &Arch,
    ptr: TypeId,
    mut off: i64,
    allow_wrap: bool,
) -> Result<Option<(TypeId, i64)>> {
    let Some(to) = fd.types.ptr_to(ptr) else { return Ok(None) };
    let size = fd.types.size(ptr);
    let to_size = i64::from(fd.types.align_size(to));
    if (off < 0 || off >= to_size) && to_size != 0 {
        if !allow_wrap {
            return Ok(None);
        }
        let mut s = sign_extend(off as u64, size * 8 - 1) % to_size;
        if s < 0 {
            s += to_size;
        }
        off = s;
        if off == 0 {
            return Ok(Some((ptr, 0)));
        }
    }
    // downChain: an array or struct parent makes a TypePointerRel, an enum a pointer to uint1,
    // a union needs resolution: none of them is ported yet
    if matches!(fd.types.meta(to), Meta::Array | Meta::Struct | Meta::Union)
        || matches!(fd.types.get(to).kind, Kind::Enum(_))
    {
        return err(
            "type propagation into an array, struct, union or enum (downChain): not implemented in ghidra-rs yet",
        );
    }
    let Some((pt, newoff)) = sub_type(fd, arch, to, off)? else { return Ok(None) };
    Ok(Some((fd.types.pointer_strip_array(size, pt, WS), newoff)))
}

/// Port of `TypeOpIntAdd::propagateAddPointer`: 0 a zero offset, 1 a constant offset, 2 not a
/// pointer add, 3 an unknown offset.
fn add_pointer(fd: &mut Funcdata, st: &Infer, op: OpId, slot: usize, sz: u32) -> (i32, u64) {
    let o = fd.op(op).clone();
    let constant = |fd: &Funcdata, v: VarnodeId| fd.vn(v).is_constant();
    match o.opc {
        Opcode::Ptradd => {
            if slot != 0 {
                return (2, 0);
            }
            let (c, mult) = (o.ins[1], fd.vn(o.ins[2]).offset);
            if constant(fd, c) {
                let off = fd.vn(c).offset.wrapping_mul(mult) & calc_mask(fd.vn(c).size);
                return (i32::from(off != 0), off);
            }
            if sz != 0 && !mult.is_multiple_of(u64::from(sz)) {
                return (2, 0);
            }
            (3, 0)
        }
        Opcode::Ptrsub => {
            if slot != 0 {
                return (2, 0);
            }
            let off = fd.vn(o.ins[1]).offset;
            (i32::from(off != 0), off)
        }
        Opcode::IntAdd => {
            let other = o.ins[1 - slot];
            if !constant(fd, other) {
                if let Some(def) = fd.vn(other).def {
                    let m = fd.op(def);
                    if m.opc == Opcode::IntMult {
                        let c = fd.vn(m.ins[1]);
                        if c.is_constant() {
                            let mult = c.offset;
                            if mult == calc_mask(c.size) || (sz != 0 && !mult.is_multiple_of(u64::from(sz))) {
                                return (2, 0);
                            }
                        }
                        return (3, 0);
                    }
                }
                return if sz == 1 { (3, 0) } else { (2, 0) };
            }
            let t = st.temp(fd, other);
            if fd.types.meta(t) == Meta::Ptr {
                return (2, 0);
            }
            let off = fd.vn(other).offset;
            (i32::from(off != 0), off)
        }
        _ => (2, 0),
    }
}

/// Port of `TypeOpIntAdd::propagateAddIn2Out`.
fn add_in2out(
    fd: &mut Funcdata,
    arch: &Arch,
    st: &Infer,
    alt: TypeId,
    op: OpId,
    inslot: usize,
) -> Result<Option<TypeId>> {
    let Some(to) = fd.types.ptr_to(alt) else { return Ok(None) };
    let align = fd.types.align_size(to);
    let (command, offset) = add_pointer(fd, st, op, inslot, align);
    if command == 2 {
        return Ok(None);
    }
    let mut pointer = Some(alt);
    if command != 3 {
        let mut type_off = (offset.wrapping_mul(u64::from(WS))) as i64;
        let allow_wrap = fd.op(op).opc != Opcode::Ptrsub;
        loop {
            match down_chain(fd, arch, pointer.unwrap_or(alt), type_off, allow_wrap)? {
                None => {
                    pointer = None;
                    break;
                }
                Some((p, o)) => {
                    pointer = Some(p);
                    type_off = o;
                }
            }
            if type_off == 0 {
                break;
            }
        }
    }
    let Some(mut p) = pointer else { return Ok((command == 0).then_some(alt)) };
    if fd.vn(fd.op(op).ins[inslot]).has(VnFlags::SPACEBASE) {
        if let Some(to) = fd.types.ptr_to(p) {
            if fd.types.meta(to) == Meta::Spacebase {
                p = unknown_ptr(fd, fd.types.size(p));
            }
        }
    }
    Ok(Some(p))
}

/// Port of `TypeOp::propagateType` and its overrides (the ops reachable with the rules off).
#[allow(clippy::too_many_arguments)]
fn propagate_type(
    fd: &mut Funcdata,
    arch: &Arch,
    st: &Infer,
    alt: TypeId,
    op: OpId,
    invn: VarnodeId,
    outvn: VarnodeId,
    inslot: i32,
    outslot: i32,
) -> Result<Option<TypeId>> {
    let opc = fd.op(op).opc;
    let in_sb = fd.vn(invn).has(VnFlags::SPACEBASE);
    let alt_meta = fd.types.meta(alt);
    let alt_size = fd.types.size(alt);
    // the common tail: a space-base register propagates as a pointer to unknown bytes
    let pass = |fd: &mut Funcdata| if in_sb { unknown_ptr(fd, alt_size) } else { alt };
    Ok(match opc {
        Opcode::Copy | Opcode::Multiequal => {
            if inslot != -1 && outslot != -1 {
                return Ok(None);
            }
            Some(pass(fd))
        }
        Opcode::Indirect => {
            if fd.op(op).flags.has(super::op::OpFlags::INDIRECT_CREATION) || inslot == 1 || outslot == 1 {
                return Ok(None);
            }
            if inslot != -1 && outslot != -1 {
                return Ok(None);
            }
            Some(pass(fd))
        }
        Opcode::Load | Opcode::Store => {
            if inslot == 0 || outslot == 0 || in_sb {
                return Ok(None);
            }
            let to_ptr = if opc == Opcode::Load { inslot == -1 } else { inslot == 2 };
            let size = fd.vn(outvn).size;
            if to_ptr {
                Some(to_pointer(fd, alt, size))
            } else {
                from_pointer(fd, alt, size)?
            }
        }
        Opcode::IntEqual | Opcode::IntNotequal | Opcode::IntLess | Opcode::IntLessequal => {
            if inslot == -1 || outslot == -1 {
                return Ok(None);
            }
            Some(pass(fd))
        }
        Opcode::IntSless | Opcode::IntSlessequal => {
            if inslot == -1 || outslot == -1 || alt_meta != Meta::Int {
                return Ok(None);
            }
            Some(alt)
        }
        Opcode::IntAdd => {
            if alt_meta != Meta::Ptr {
                if alt_meta != Meta::Int && alt_meta != Meta::Uint {
                    return Ok(None);
                }
                if outslot != 1 || !fd.vn(fd.op(op).ins[1]).is_constant() {
                    return Ok(None);
                }
            } else if inslot != -1 && outslot != -1 {
                return Ok(None);
            }
            if fd.vn(outvn).is_constant() && alt_meta != Meta::Ptr {
                Some(alt)
            } else if inslot == -1 {
                None
            } else {
                add_in2out(fd, arch, st, alt, op, inslot as usize)?
            }
        }
        Opcode::Ptrsub => {
            if (inslot != -1 && outslot != -1) || alt_meta != Meta::Ptr || inslot == -1 {
                return Ok(None);
            }
            add_in2out(fd, arch, st, alt, op, inslot as usize)?
        }
        Opcode::IntXor | Opcode::IntAnd => {
            if alt_meta != Meta::Float || !float_sign_manipulation(fd, op) {
                return Ok(None);
            }
            Some(pass(fd))
        }
        Opcode::Piece => {
            if inslot != -1 {
                return Ok(None);
            }
            // little-endian: input 0 is the most significant piece
            let off = if outslot == 0 { fd.vn(fd.op(op).ins[1]).size } else { 0 };
            narrow(fd, arch, alt, i64::from(off), fd.vn(outvn).size)?
        }
        Opcode::Subpiece => {
            if inslot != 0 || outslot != -1 {
                return Ok(None);
            }
            let off = fd.vn(fd.op(op).ins[1]).offset as i64;
            narrow(fd, arch, alt, off, fd.vn(outvn).size)?
        }
        Opcode::Ptradd => return err("type propagation through PTRADD: not implemented in ghidra-rs yet"),
        _ => None,
    })
}

/// The loop of `TypeOpPiece/TypeOpSubpiece::propagateType`: descend into `alt` until a
/// sub-type of `size` bytes sits at offset 0.
fn narrow(fd: &mut Funcdata, arch: &Arch, alt: TypeId, mut off: i64, size: u32) -> Result<Option<TypeId>> {
    let mut t = alt;
    while off != 0 || fd.types.size(t) != size {
        let Some((n, o)) = sub_type(fd, arch, t, off)? else { return Ok(None) };
        t = n;
        off = o;
    }
    Ok(Some(t))
}

/// Port of `TypeOp::floatSignManipulation` (true for FLOAT_ABS or FLOAT_NEG done with bits).
fn float_sign_manipulation(fd: &Funcdata, op: OpId) -> bool {
    let o = fd.op(op);
    let c = fd.vn(o.ins[1]);
    if !c.is_constant() {
        return false;
    }
    let m = calc_mask(c.size);
    match o.opc {
        Opcode::IntAnd => c.offset == m >> 1,
        Opcode::IntXor => c.offset == m ^ (m >> 1),
        _ => false,
    }
}

/// Port of `ActionInferTypes::propagateTypeEdge`.
fn propagate_edge(fd: &mut Funcdata, arch: &Arch, st: &mut Infer, op: OpId, inslot: i32, outslot: i32) -> Result<bool> {
    if inslot == outslot {
        return Ok(false);
    }
    let o = fd.op(op);
    let slot_vn = |s: i32| if s == -1 { o.out } else { o.ins.get(s as usize).copied() };
    let (Some(invn), Some(outvn)) = (slot_vn(inslot), slot_vn(outslot)) else { return Ok(false) };
    let alt = st.temp(fd, invn);
    let ov = fd.vn(outvn);
    if (outslot >= 0 && ov.is_annotation()) || ov.has(VnFlags::TYPELOCK) {
        return Ok(false);
    }
    if fd.types.meta(alt) == Meta::Bool && fd.nzmask(outvn) > 1 {
        return Ok(false);
    }
    let Some(newtype) = propagate_type(fd, arch, st, alt, op, invn, outvn, inslot, outslot)? else { return Ok(false) };
    let cur = st.temp(fd, outvn);
    if fd.types.order(newtype, cur) < 0 {
        st.set_temp(outvn, newtype);
        return Ok(!st.mark[outvn.0 as usize]);
    }
    Ok(false)
}

/// Port of `PropagationState`: the edges of one varnode still to try.
struct State {
    vn: VarnodeId,
    readers: Vec<OpId>,
    next: usize,
    op: Option<OpId>,
    inslot: i32,
    slot: i32,
}

impl State {
    fn new(fd: &Funcdata, vn: VarnodeId) -> State {
        let readers = fd.vn(vn).descend.to_vec();
        let mut s = State { vn, readers, next: 0, op: None, inslot: -1, slot: 0 };
        if !s.next_reader(fd) {
            s.op = fd.vn(vn).def;
            s.inslot = -1;
            s.slot = 0;
        }
        s
    }
    fn next_reader(&mut self, fd: &Funcdata) -> bool {
        let Some(&op) = self.readers.get(self.next) else { return false };
        self.next += 1;
        self.op = Some(op);
        self.slot = if fd.op(op).out.is_some() { -1 } else { 0 };
        self.inslot = fd.slot_of(op, self.vn).map_or(0, |s| s as i32);
        true
    }
    fn step(&mut self, fd: &Funcdata) {
        self.slot += 1;
        if let Some(op) = self.op {
            if (self.slot as usize) < fd.op(op).ins.len() {
                return;
            }
        }
        if self.next_reader(fd) {
            return;
        }
        self.op = if self.inslot == -1 { None } else { fd.vn(self.vn).def };
        self.inslot = -1;
        self.slot = 0;
    }
}

/// Port of `ActionInferTypes::propagateOneType`.
fn propagate_one(fd: &mut Funcdata, arch: &Arch, st: &mut Infer, vn: VarnodeId) -> Result<()> {
    let mut stack = vec![State::new(fd, vn)];
    st.mark[vn.0 as usize] = true;
    while let Some(top) = stack.last_mut() {
        let Some(op) = top.op else {
            st.mark[top.vn.0 as usize] = false;
            stack.pop();
            continue;
        };
        let (inslot, slot) = (top.inslot, top.slot);
        let next = if propagate_edge(fd, arch, st, op, inslot, slot)? {
            let o = fd.op(op);
            if slot == -1 {
                o.out
            } else {
                o.ins.get(slot as usize).copied()
            }
        } else {
            None
        };
        // step before pushing the next state
        if let Some(top) = stack.last_mut() {
            top.step(fd);
        }
        if let Some(n) = next {
            stack.push(State::new(fd, n));
            st.mark[n.0 as usize] = true;
        }
    }
    Ok(())
}

/// Port of `ActionInferTypes::canonicalReturnOp` and `propagateAcrossReturns` (nothing to do
/// when the function's output is locked).
fn propagate_across_returns(fd: &mut Funcdata, arch: &Arch, st: &mut Infer) -> Result<()> {
    if fd.proto.locked.is_some() {
        return Ok(());
    }
    let rets: Vec<OpId> = fd
        .ops_created_with(Opcode::Return)
        .into_iter()
        .filter(|&r| !fd.op(r).is_dead() && fd.op(r).halt.is_none() && fd.op(r).ins.len() > 1)
        .collect();
    let mut best: Option<(OpId, TypeId)> = None;
    for &r in &rets {
        let ct = st.temp(fd, fd.op(r).ins[1]);
        match best {
            Some((_, b)) if fd.types.order(ct, b) >= 0 => {}
            _ => best = Some((r, ct)),
        }
    }
    let Some((canon, ct)) = best else { return Ok(()) };
    let base_size = fd.vn(fd.op(canon).ins[1]).size;
    let is_bool = fd.types.meta(ct) == Meta::Bool;
    for r in rets {
        if r == canon {
            continue;
        }
        let vn = fd.op(r).ins[1];
        if fd.vn(vn).size != base_size || (is_bool && fd.nzmask(vn) > 1) || st.temp(fd, vn) == ct {
            continue;
        }
        st.set_temp(vn, ct);
        propagate_one(fd, arch, st, vn)?;
    }
    Ok(())
}

/// Port of `ActionInferTypes::propagateSpacebaseRef`/`propagateRef`: types of stack varnodes
/// reached through the stack pointer. No stack-space varnode exists before the `stackvars`
/// rules (stage R5), so there is nothing to reach yet.
fn propagate_spacebase_ref(fd: &Funcdata) -> Result<()> {
    if fd.loc_space(Space::Stack).is_empty() {
        return Ok(());
    }
    err("type propagation into stack varnodes (propagateRef): not implemented in ghidra-rs yet")
}

/// Port of `ActionStartTypes::apply`.
pub(crate) fn start_types(fd: &mut Funcdata, _: &Arch) -> Result<i32> {
    if fd.typerecovery_start {
        return Ok(0);
    }
    fd.typerecovery_start = true;
    Ok(1)
}

/// Port of `ActionInferTypes::apply` (no type recommendations: `localrecovery` maps none).
pub(crate) fn infer_types(fd: &mut Funcdata, arch: &Arch) -> Result<i32> {
    symbol_types(fd, arch);
    if !fd.typerecovery_start {
        return Ok(0);
    }
    if fd.infer_passes >= 7 {
        if fd.infer_passes == 7 {
            fd.warning_header("Type propagation algorithm not settling");
            fd.typerecovery_exceeded = true;
            fd.infer_passes += 1;
        }
        return Ok(0);
    }
    let n = fd.vns.len();
    let mut st = Infer { temp: vec![None; n], mark: vec![false; n] };
    let locs = fd.loc_all();
    // buildLocaltypes (no symbol entries before `localrecovery`)
    for &vn in &locs {
        if !skipped(fd, vn) {
            let ct = local_type(fd, vn)?;
            st.set_temp(vn, ct);
        }
    }
    for &vn in &locs {
        if !skipped(fd, vn) {
            propagate_one(fd, arch, &mut st, vn)?;
        }
    }
    propagate_across_returns(fd, arch, &mut st)?;
    propagate_spacebase_ref(fd)?;
    // writeBack
    let mut change = false;
    for vn in locs {
        if skipped(fd, vn) {
            continue;
        }
        let ct = st.temp(fd, vn);
        if !fd.vn(vn).has(VnFlags::TYPELOCK) && vn_type(fd, vn) != ct {
            fd.vn_mut(vn).ty = Some(ct);
            change = true;
        }
    }
    if change {
        fd.infer_passes += 1;
    }
    Ok(0)
}

/// A symbol of the global scope a pointer constant can name (`MapEntry`).
struct Entry {
    addr: u64,
    externref: bool,
}

impl Entry {
    /// The symbol's type: `code` for a function (`FunctionSymbol::buildType`), a pointer to
    /// `code` for an external reference (`ExternRefSymbol::buildNameType`). Both are type-locked.
    fn symbol_type(&self, fd: &mut Funcdata, arch: &Arch) -> TypeId {
        if self.externref {
            code_ptr(fd, arch.spec.stack_pointer.2)
        } else {
            fd.types.code()
        }
    }
}

/// Port of `Scope::queryContainer(addr, 1)` on the global scope: a function covers its entry
/// byte, an external reference its pointer-sized slot.
fn query_global(arch: &Arch, addr: u64) -> Option<Entry> {
    if arch.functions.contains_key(&addr) {
        return Some(Entry { addr, externref: false });
    }
    let size = u64::from(arch.spec.stack_pointer.2);
    (0..size)
        .filter_map(|d| addr.checked_sub(d))
        .find(|s| arch.externrefs.contains_key(s))
        .map(|s| Entry { addr: s, externref: true })
}

fn set_symcheck(fd: &mut Funcdata, vn: VarnodeId, complete: bool) {
    let f = &mut fd.vn_mut(vn).flags;
    f.clear(VnFlags::SYMCHECK_COMPLETE);
    f.clear(VnFlags::SYMCHECK_INCOMPLETE);
    f.set(if complete { VnFlags::SYMCHECK_COMPLETE } else { VnFlags::SYMCHECK_INCOMPLETE });
}

/// Port of `ActionConstantPtr::isPointer` (ram is the only space pointers are inferred in;
/// `infer_pointers` is on and no call input or function output is locked in the console).
fn is_pointer(fd: &mut Funcdata, arch: &Arch, vn: VarnodeId, op: OpId, slot: usize) -> Option<Entry> {
    set_symcheck(fd, vn, true);
    let ty = vn_type(fd, vn);
    let (off, size) = (fd.vn(vn).offset, fd.vn(vn).size);
    // a constant already typed as a pointer need not hit a symbol exactly (isPointer)
    let mut needexact = fd.types.meta(ty) != Meta::Ptr;
    if fd.types.meta(ty) != Meta::Ptr {
        if fd.vn(vn).has(VnFlags::TYPELOCK) {
            return None;
        }
        let o = fd.op(op);
        match o.opc {
            Opcode::Call | Opcode::Callind if slot == 0 => return None,
            Opcode::Call | Opcode::Callind
                if locked_param_meta(fd, op, slot).is_some_and(|m| !matches!(m, Meta::Ptr | Meta::Unknown)) =>
            {
                return None
            }
            Opcode::Copy if copy_blocked(fd, op) => return None,
            Opcode::Call
            | Opcode::Callind
            | Opcode::Copy
            | Opcode::Piece
            | Opcode::IntEqual
            | Opcode::IntNotequal
            | Opcode::IntLess
            | Opcode::IntLessequal => {}
            Opcode::IntAdd => {
                let (out, other) = (o.out?, o.ins[1 - slot]);
                let out_t = vn_type(fd, out);
                if fd.types.meta(out_t) == Meta::Ptr {
                    let other_t = vn_type(fd, other);
                    if fd.types.meta(other_t) == Meta::Ptr {
                        return None;
                    }
                    needexact = false;
                }
            }
            Opcode::Store if slot == 2 => {}
            _ => return None,
        }
        // AddrSpace::calcScaleMask: a 0x1000 buffer at both ends of the space
        let highest = calc_mask(arch.spec.stack_pointer.2);
        if off < 0x1000 || off > highest - 0x1000 || bit_transitions(off, size) < 3 {
            return None;
        }
    }
    let entry = query_global(arch, off)?;
    if needexact && entry.addr != off {
        set_symcheck(fd, vn, false);
        return None;
    }
    Some(entry)
}

/// Port of `Funcdata::spacebaseConstant` (the constant has the size of a ram address).
fn spacebase_constant(
    fd: &mut Funcdata,
    arch: &Arch,
    op: OpId,
    slot: usize,
    entry: &Entry,
    rampoint: u64,
) -> Result<()> {
    let ram = fd.ram.ok_or_else(|| super::LowlevelError("spacebaseConstant: no ram space".into()))?;
    let uniq = fd.uniq.ok_or_else(|| super::LowlevelError("spacebaseConstant: no unique space".into()))?;
    let sz = arch.spec.stack_pointer.2;
    let sb = fd.types.spacebase(Space::Sleigh(ram), GLOBAL_SCOPE);
    let sb_ptr = fd.types.pointer(sz, sb, WS);
    let extra = rampoint - entry.addr;
    let addr = fd.op(op).seq.addr;
    let is_copy = fd.op(op).opc == Opcode::Copy;
    let (mut add_op, mut extra_op) = (None, None);
    if is_copy {
        if extra != 0 {
            extra_op = Some(op);
        } else {
            add_op = Some(op);
        }
    }
    let base = fd.new_constant(sz, 0);
    update_type(fd, base, sb_ptr, true, true);
    fd.vn_set(base, VnFlags::SPACEBASE);
    let add_op = match add_op {
        Some(a) => {
            fd.op_set_opcode(a, Opcode::Ptrsub);
            a
        }
        None => {
            let a = fd.new_op(Opcode::Ptrsub, addr);
            fd.new_unique_out(sz, uniq, a);
            fd.op_insert_before(a, op)?;
            a
        }
    };
    let mut outvn = fd.op(add_op).out.ok_or_else(|| super::LowlevelError("PTRSUB without output".into()))?;
    let newconst = fd.new_constant(sz, rampoint - extra);
    set_symcheck(fd, newconst, true);
    fd.op_set_input(add_op, base, 0)?;
    fd.op_set_input(add_op, newconst, 1)?;
    let entry_type = entry.symbol_type(fd, arch);
    let ptr_entry = fd.types.pointer_strip_array(sz, entry_type, WS);
    update_type(fd, outvn, ptr_entry, true, false);
    if extra != 0 {
        let e = match extra_op {
            Some(e) => {
                fd.op_set_opcode(e, Opcode::IntAdd);
                e
            }
            None => {
                let e = fd.new_op(Opcode::IntAdd, addr);
                fd.new_unique_out(sz, uniq, e);
                fd.op_insert_before(e, op)?;
                e
            }
        };
        let c = fd.new_constant(sz, extra);
        set_symcheck(fd, c, true);
        fd.op_set_input(e, outvn, 0)?;
        fd.op_set_input(e, c, 1)?;
        outvn = fd.op(e).out.ok_or_else(|| super::LowlevelError("INT_ADD without output".into()))?;
    }
    if !is_copy {
        fd.op_set_input(op, outvn, slot)?;
    }
    Ok(())
}

/// Port of `ActionConstantPtr::apply` (at most 4 passes once type recovery starts).
pub(crate) fn constant_ptr(fd: &mut Funcdata, arch: &Arch) -> Result<i32> {
    if !fd.typerecovery_start || fd.constptr_passes >= 4 {
        return Ok(0);
    }
    fd.constptr_passes += 1;
    let addr_size = arch.spec.stack_pointer.2;
    let mut count = 0;
    for vn in fd.loc_space(CONST_SPACE) {
        let v = fd.vn(vn);
        if v.is_dead() || v.offset == 0 || v.has(VnFlags::SYMCHECK_COMPLETE) {
            continue;
        }
        let incomplete = v.has(VnFlags::SYMCHECK_INCOMPLETE);
        if incomplete {
            let t = vn_type(fd, vn);
            if fd.types.meta(t) != Meta::Ptr {
                continue;
            }
        }
        let v = fd.vn(vn);
        if v.descend.is_empty() || v.has(VnFlags::SPACEBASE) || v.descend.to_vec().len() != 1 {
            continue;
        }
        let op = v.descend.to_vec()[0];
        // selectInferSpace: ram, for constants of its address size
        if v.size != addr_size {
            continue;
        }
        let Some(slot) = fd.slot_of(op, vn) else { continue };
        let opc = fd.op(op).opc;
        match opc {
            Opcode::IntAdd if fd.vn(fd.op(op).ins[1 - slot]).has(VnFlags::SPACEBASE) => continue,
            Opcode::Ptrsub | Opcode::Ptradd | Opcode::Segmentop => continue,
            _ => {}
        }
        let rampoint = fd.vn(vn).offset;
        if let Some(entry) = is_pointer(fd, arch, vn, op, slot) {
            spacebase_constant(fd, arch, op, slot, &entry, rampoint)?;
            if opc == Opcode::IntAdd && slot == 1 {
                fd.op_mut(op).ins.swap(0, 1);
            }
            count += 1;
        }
    }
    Ok(count)
}

/// The stack pointer's type once `ActionSpacebase` marks it (`Funcdata::spacebase`): a
/// pointer to the local scope's space-base type, locked.
pub(crate) fn stack_pointer_type(fd: &mut Funcdata, size: u32) -> TypeId {
    let sb = fd.types.spacebase(Space::Stack, LOCAL_SCOPE);
    fd.types.pointer(size, sb, WS)
}

/// The type a global symbol forces on a new ram varnode exactly covering it
/// (`Funcdata::newVarnode` -> `Varnode::setSymbolProperties` -> `SymbolEntry::updateType`): both
/// symbol kinds are type-locked. `Funcdata::new_varnode` has no architecture to ask, so this
/// runs over the ram varnodes before each inference pass instead; nothing reads a varnode's
/// type before then.
fn symbol_types(fd: &mut Funcdata, arch: &Arch) {
    let Some(ram) = fd.ram else { return };
    let ptr_size = arch.spec.stack_pointer.2;
    for vn in fd.loc_space(Space::Sleigh(ram)) {
        let v = fd.vn(vn);
        if v.has(VnFlags::TYPELOCK) {
            continue;
        }
        let (off, size) = (v.offset, v.size);
        let ty = if size == ptr_size && arch.externrefs.contains_key(&off) {
            code_ptr(fd, size)
        } else if size == 1 && arch.functions.contains_key(&off) {
            fd.types.code()
        } else {
            continue;
        };
        update_type(fd, vn, ty, true, true);
    }
}

/// `TypeOpCall`/`TypeOpCallind::getOutputLocal` with a locked output (stage S6).
fn locked_output_type(fd: &Funcdata, op: OpId) -> Option<TypeId> {
    if !matches!(fd.op(op).opc, Opcode::Call | Opcode::Callind) {
        return None;
    }
    let l = fd.call(fd.call_of(op)?).proto.locked.as_ref()?;
    (fd.types.meta(l.output.ty) != Meta::Void).then_some(l.output.ty)
}

/// The locked-prototype cases of `TypeOpCall`/`TypeOpCallind`/`TypeOpReturn::getInputLocal`:
/// a call's locked parameter type, the function's locked output type on a RETURN.
fn locked_input_type(fd: &Funcdata, op: OpId, slot: usize) -> Option<TypeId> {
    let o = fd.op(op);
    let size = fd.vn(*o.ins.get(slot)?).size;
    let t = match o.opc {
        Opcode::Call | Opcode::Callind if slot > 0 => {
            let t = fd.call(fd.call_of(op)?).proto.locked.as_ref()?.inputs.get(slot - 1)?.ty;
            if o.opc == Opcode::Call && fd.types.size(t) > size {
                return None;
            }
            t
        }
        Opcode::Return if slot == 1 => {
            let t = fd.proto.locked.as_ref()?.output.ty;
            if fd.types.size(t) != size {
                return None;
            }
            t
        }
        _ => return None,
    };
    (fd.types.meta(t) != Meta::Void).then_some(t)
}

/// `ActionConstantPtr::isPointer` on a call: the metatype of the locked parameter in the slot
/// (`fc->isInputLocked() && fc->numParams() > slot-1`).
fn locked_param_meta(fd: &Funcdata, op: OpId, slot: usize) -> Option<Meta> {
    let l = fd.call(fd.call_of(op)?).proto.locked.as_ref()?;
    let p = l.inputs.get(slot.checked_sub(1)?)?;
    Some(fd.types.meta(p.ty))
}

/// `ActionConstantPtr::checkCopy` false: the COPY feeds only a RETURN of a locked output that
/// cannot be a pointer.
fn copy_blocked(fd: &Funcdata, op: OpId) -> bool {
    let Some(out) = fd.op(op).out else { return false };
    let readers = fd.vn(out).descend.to_vec();
    let [ret] = readers[..] else { return false };
    if fd.op(ret).opc != Opcode::Return {
        return false;
    }
    fd.proto.locked.as_ref().is_some_and(|l| !matches!(fd.types.meta(l.output.ty), Meta::Ptr | Meta::Unknown))
}
