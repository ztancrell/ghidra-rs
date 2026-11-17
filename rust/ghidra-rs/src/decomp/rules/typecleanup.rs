//! The rules of the `cleanup` pool that read data-types or rewrite pieces (stage R5, slice 4):
//! `RuleAddUnsigned`, `RuleSubRight`, `RuleExtensionPush`,
//! `RulePieceStructure`, `RuleAndStructure`, `RuleFloatSignCleanup`, `RuleExpandLoad`
//! (ruleaction.cc) and `RuleDumptyHumpLate` (subflow.cc), with `Funcdata::opDestroyRecursive`,
//! `opUnlink` and `Datatype::findSmallestContainer`.
//!
//! `RulePtrsubCharConstant` came with stage S10 (the strings of the facts, `load facts`); the
//! option files of the checks against `decomp_dbg` switch it off, so none of them runs it.
//! Failing loudly where reached: the tree rewrite of
//! `RulePieceStructure` (`PieceNode::gatherPieces` onward: proto-partial varnodes, which only
//! `VariablePiece` groups); join addresses in `RuleAndStructure`; struct sub-types (`TypeStruct::getSubType`, through
//! `infertypes::sub_type`); unions. Symbols are not modelled, so a varnode's symbol entry is
//! always null: no equate stops `RuleAddUnsigned`, and `getStructuredType` is the varnode's type.

use super::*;
use crate::decomp::infertypes::{sub_type, vn_type};
use crate::decomp::types::{Kind, Meta, TypeId};
use crate::decomp::varnode::overlap;

/// `Datatype::isPieceStructured`: metatype at most `TYPE_ARRAY` (array, struct, union).
fn piece_structured(fd: &Funcdata, t: TypeId) -> bool {
    matches!(fd.types.meta(t), Meta::Array | Meta::Struct | Meta::Union)
}

/// `Funcdata::newUnique(size, ct)` before `assignhigh` (no high to give it).
fn new_unique_typed(fd: &mut Funcdata, size: u32, ct: TypeId) -> Result<VarnodeId> {
    let uniq = fd.uniq.ok_or_else(|| LowlevelError("no unique space".into()))?;
    let vn = fd.new_unique(size, uniq);
    fd.vn_mut(vn).ty = Some(ct);
    Ok(vn)
}

/// A new constant carrying `ct` (`newConstant` + `updateType`).
fn typed_constant(fd: &mut Funcdata, size: u32, val: u64, ct: TypeId) -> VarnodeId {
    let c = fd.new_constant(size, val);
    fd.vn_mut(c).ty = Some(ct);
    c
}

/// Port of `Funcdata::opDestroyRecursive`: `op` and the ops whose only reader it was.
fn op_destroy_recursive(fd: &mut Funcdata, op: OpId) {
    let mut scratch = vec![op];
    let mut pos = 0;
    while let Some(&cur) = scratch.get(pos) {
        pos += 1;
        for i in 0..ins(fd, cur).len() {
            let vn = ins(fd, cur)[i];
            let Some(d) = def(fd, vn) else { continue };
            if fd.vn(vn).is_auto_live() || lone_descend(fd, vn).is_none() {
                continue;
            }
            if fd.op(d).is_call() || fd.op(d).flags.has(OpFlags::INDIRECT_SOURCE) {
                continue;
            }
            scratch.push(d);
        }
        fd.op_destroy(cur);
    }
}

/// Port of `RuleAddUnsigned`: `V + 0xff...  =>  V - 0x00...`.
pub(super) fn add_unsigned(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let constvn = inp(fd, op, 1)?;
    if !is_const(fd, constvn) {
        return Ok(0);
    }
    let dt = vn_type(fd, constvn);
    if fd.types.meta(dt) != Meta::Uint || fd.types.is_char_print(dt) {
        return Ok(0);
    }
    let size = sz(fd, constvn);
    let (val, mask) = (off(fd, constvn), calc_mask(size));
    let sa = size * 6;
    let quarter = shl(shr(mask, sa as i32), sa as i32);
    if val & quarter != quarter {
        return Ok(0);
    }
    // getSymbolEntry() is always null (no equates)
    let negated = val.wrapping_neg() & mask;
    if let Kind::Enum(values) = &fd.types.get(dt).kind {
        let named = |v: u64| values.iter().any(|(_, x)| *x == v);
        if !named(negated) && named(!val & mask) {
            return Ok(0);
        }
    }
    fd.op_set_opcode(op, IntSub);
    let cvn = fd.new_constant(size, negated);
    fd.copy_symbol(cvn, constvn);
    fd.op_set_input(op, cvn, 1)?;
    Ok(1)
}

/// Port of `RuleSubRight`: `sub(a,#c)  =>  sub(a >> c*8, #0)`.
pub(super) fn sub_right(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    sub_right_op(fd, op)
}

fn sub_right_op(fd: &mut Funcdata, mut op: OpId) -> Result<i32> {
    if fd.op(op).flags.has(OpFlags::SPECIAL_PRINT) {
        return Ok(0);
    }
    let a = inp(fd, op, 0)?;
    let at = vn_type(fd, a);
    if piece_structured(fd, at) {
        fd.op_mut(op).flags.set(OpFlags::SPECIAL_PRINT);
        return Ok(0);
    }
    let c = off(fd, inp(fd, op, 1)?) as i32;
    if c == 0 {
        return Ok(0);
    }
    let outvn = out(fd, op)?;
    let (ov, av) = (fd.vn(outvn), fd.vn(a));
    if ov.has(VnFlags::ADDRTIED) && av.has(VnFlags::ADDRTIED) {
        // ponytail: the offsets are compared without the space's wrap mask (no address-tied pair
        // sits at the top of a space)
        if overlap(ov.space, ov.offset, av.space, av.offset, av.size, u64::MAX) == Some(c as u32) {
            return Ok(0);
        }
    }
    let asize = sz(fd, a);
    let mut opc = IntRight;
    let mut d = c * 8;
    if let Some(lone) = lone_descend(fd, outvn) {
        let opc2 = code(fd, lone);
        let sa = if matches!(opc2, IntRight | IntSright) { Some(inp(fd, lone, 1)?) } else { None };
        if let Some(sa) = sa.filter(|&sa| is_const(fd, sa) && sz(fd, outvn) + c as u32 == asize) {
            d = d.wrapping_add(off(fd, sa) as i32);
            if d >= (asize * 8) as i32 {
                if opc2 == IntRight {
                    return Ok(0);
                }
                d = (asize * 8 - 1) as i32;
            }
            op_unlink(fd, op);
            op = lone;
            fd.op_set_opcode(op, Subpiece);
            opc = opc2;
        }
    }
    let ct = fd.types.base(asize, if opc == IntRight { Meta::Uint } else { Meta::Int });
    let shiftop = fd.new_op(opc, op_addr(fd, op));
    let newout = new_unique_typed(fd, asize, ct)?;
    fd.op_set_output(shiftop, newout)?;
    fd.op_set_input(shiftop, a, 0)?;
    let dc = fd.new_constant(4, d as u32 as u64);
    fd.op_set_input(shiftop, dc, 1)?;
    fd.op_insert_before(shiftop, op)?;
    fd.op_set_input(op, newout, 0)?;
    let zero = fd.new_constant(4, 0);
    fd.op_set_input(op, zero, 1)?;
    Ok(1)
}

/// Port of `Funcdata::opUnlink`: out of the data-flow and its block, not destroyed.
fn op_unlink(fd: &mut Funcdata, op: OpId) {
    fd.op_unset_output(op);
    fd.op_clear_inputs(op);
    if fd.op(op).parent.is_some() {
        fd.op_uninsert(op);
    }
}

/// Port of `RuleDumptyHumpLate`: a SUBPIECE of a PIECE reads the component it truncates.
pub(super) fn dumpty_hump_late(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    dumpty_hump_late_op(fd, op)
}

fn dumpty_hump_late_op(fd: &mut Funcdata, op: OpId) -> Result<i32> {
    let vn0 = inp(fd, op, 0)?;
    let Some(mut piece_op) = def(fd, vn0) else { return Ok(0) };
    if code(fd, piece_op) == Subpiece {
        let base = inp(fd, piece_op, 0)?;
        fd.op_set_input(op, base, 0)?;
        let cur = off(fd, inp(fd, op, 1)?);
        let trunc = cur.wrapping_add(off(fd, inp(fd, piece_op, 1)?));
        if trunc != cur {
            let c = fd.new_constant(4, trunc);
            fd.op_set_input(op, c, 1)?;
        }
        if fd.vn(vn0).descend.is_empty() && !fd.vn(vn0).is_auto_live() {
            op_destroy_recursive(fd, piece_op);
        }
        return Ok(1);
    }
    if code(fd, piece_op) != Piece {
        return Ok(0);
    }
    let outv = out(fd, op)?;
    let out_size = sz(fd, outv);
    let mut trunc = off(fd, inp(fd, op, 1)?) as i32;
    let mut vn = vn0;
    loop {
        let mut trial = inp(fd, piece_op, 1)?;
        let mut trial_trunc = trunc;
        if trunc >= sz(fd, trial) as i32 {
            trial_trunc -= sz(fd, trial) as i32;
            trial = inp(fd, piece_op, 0)?;
        }
        if out_size as i32 + trial_trunc > sz(fd, trial) as i32 {
            break;
        }
        vn = trial;
        trunc = trial_trunc;
        if sz(fd, vn) == out_size {
            break;
        }
        match def_with(fd, vn, Piece) {
            Some(p) => piece_op = p,
            None => break,
        }
    }
    if vn == vn0 {
        return Ok(0);
    }
    if let Some(c) = def_with(fd, vn, Copy) {
        vn = inp(fd, c, 0)?;
    }
    let remove_op = if out_size != sz(fd, vn) {
        let r = def_op(fd, vn0)?;
        if off(fd, inp(fd, op, 1)?) != trunc as u64 {
            let c = fd.new_constant(4, trunc as u32 as u64);
            fd.op_set_input(op, c, 1)?;
        }
        fd.op_set_input(op, vn, 0)?;
        r
    } else if fd.vn(outv).is_auto_live() {
        let r = def_op(fd, vn0)?;
        fd.op_remove_input(op, 1);
        fd.op_set_opcode(op, Copy);
        fd.op_set_input(op, vn, 0)?;
        r
    } else {
        fd.total_replace(outv, vn)?;
        op
    };
    let rout = out(fd, remove_op)?;
    if fd.vn(rout).descend.is_empty() && !fd.vn(rout).is_auto_live() {
        op_destroy_recursive(fd, remove_op);
    }
    Ok(1)
}

fn def_op(fd: &Funcdata, vn: VarnodeId) -> Result<OpId> {
    def(fd, vn).ok_or_else(|| LowlevelError("cleanup rule: varnode has no defining op".into()))
}

/// Port of `RuleFloatSignCleanup`: sign-bit manipulation of a float becomes FLOAT_NEG/FLOAT_ABS.
pub(super) fn float_sign_cleanup(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let o = out(fd, op)?;
    let t = vn_type(fd, o);
    if fd.types.meta(t) != Meta::Float {
        return Ok(0);
    }
    let Some(opc) = float_sign_manipulation(fd, op)? else { return Ok(0) };
    fd.op_remove_input(op, 1);
    fd.op_set_opcode(op, opc);
    Ok(1)
}

/// Port of `RuleExpandLoad::checkAndComparison`.
fn check_and_comparison(fd: &Funcdata, vn: VarnodeId) -> Result<bool> {
    for &op in fd.vn(vn).descend.iter() {
        if code(fd, op) != IntAnd || !is_const(fd, inp(fd, op, 1)?) {
            return Ok(false);
        }
        let Some(comp) = lone_descend(fd, out(fd, op)?) else { return Ok(false) };
        if !matches!(code(fd, comp), IntEqual | IntNotequal) || !is_const(fd, inp(fd, comp, 1)?) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Port of `RuleExpandLoad::modifyAndComparison`.
fn modify_and_comparison(fd: &mut Funcdata, old: VarnodeId, new: VarnodeId, dt: TypeId, offset: i32) -> Result<()> {
    let shift = 8 * offset;
    let size = fd.types.size(dt);
    while let Some(&and_op) = fd.vn(old).descend.first() {
        let comp = lone_descend(fd, out(fd, and_op)?)
            .ok_or_else(|| LowlevelError("RuleExpandLoad: comparison gone".into()))?;
        let v = typed_constant(fd, size, shl(off(fd, inp(fd, and_op, 1)?), shift), dt);
        fd.op_set_input(and_op, new, 0)?;
        fd.op_set_input(and_op, v, 1)?;
        let v = typed_constant(fd, size, shl(off(fd, inp(fd, comp, 1)?), shift), dt);
        fd.op_set_input(comp, v, 1)?;
    }
    Ok(())
}

/// Port of `RuleExpandLoad`: a LOAD of part of a primitive pointee loads the whole and truncates.
pub(super) fn expand_load(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let out_vn = out(fd, op)?;
    let out_size = sz(fd, out_vn);
    let mut root = inp(fd, op, 1)?;
    let mut add_op = None;
    let mut offset = 0i32;
    if let Some(d) = def_with(fd, root, IntAdd).filter(|&d| ins(fd, d).get(1).is_some_and(|&c| is_const(fd, c))) {
        add_op = Some(d);
        root = inp(fd, d, 0)?;
        let o = off(fd, inp(fd, d, 1)?);
        if o > 16 {
            return Ok(0);
        }
        offset = o as i32;
        if lone_descend(fd, out(fd, d)?).is_none() {
            return Ok(0);
        }
    }
    let pt = vn_type(fd, root);
    let Some(el) = fd.types.ptr_to(pt) else { return Ok(0) };
    let el_size = fd.types.size(el);
    if el_size <= out_size || el_size < out_size + offset as u32 {
        return Ok(0);
    }
    let meta = fd.types.meta(el);
    if matches!(meta, Meta::Unknown | Meta::Struct | Meta::Array | Meta::Union) {
        return Ok(0);
    }
    let add_form = check_and_comparison(fd, out_vn)?;
    if !add_form {
        if !matches!(meta, Meta::Int | Meta::Uint) {
            return Ok(0);
        }
        let ot = vn_type(fd, out_vn);
        if !matches!(fd.types.meta(ot), Meta::Int | Meta::Uint | Meta::Unknown | Meta::Bool) || offset != 0 {
            return Ok(0);
        }
    }
    let new_out = new_unique_typed(fd, el_size, el)?;
    fd.op_set_output(op, new_out)?;
    if let Some(a) = add_op {
        fd.op_set_input(op, root, 1)?;
        fd.op_destroy(a);
    }
    if add_form {
        let dt = if matches!(meta, Meta::Int | Meta::Uint) { el } else { fd.types.base(el_size, Meta::Uint) };
        modify_and_comparison(fd, out_vn, new_out, dt, offset)?;
    } else {
        let sub = fd.new_op(Subpiece, op_addr(fd, op));
        fd.op_set_input(sub, new_out, 0)?;
        let zero = fd.new_constant(4, 0);
        fd.op_set_input(sub, zero, 1)?;
        fd.op_set_output(sub, out_vn)?;
        fd.op_insert_after(sub, op)?;
    }
    Ok(1)
}

/// Port of `RulePtrsubCharConstant::pushConstFurther`: a PTRADD of a constant to the collapsed
/// string pointer becomes a COPY of the sum.
fn push_const_further(fd: &mut Funcdata, outtype: TypeId, op: OpId, slot: usize, val: u64) -> Result<bool> {
    if fd.op(op).opc != Ptradd || slot != 0 {
        return Ok(false);
    }
    let vn = inp(fd, op, 1)?;
    if !fd.vn(vn).is_constant() {
        return Ok(false);
    }
    let addval = off(fd, vn).wrapping_mul(off(fd, inp(fd, op, 2)?));
    let size = sz(fd, vn);
    let newconst = fd.new_constant(size, val.wrapping_add(addval));
    fd.vn_mut(newconst).ty = Some(outtype);
    fd.op_remove_input(op, 2);
    fd.op_remove_input(op, 1);
    fd.op_set_opcode(op, Copy);
    fd.op_set_input(op, newconst, 0)?;
    Ok(true)
}

/// Port of `RulePtrsubCharConstant`: a PTRSUB off the global space-base whose output points at
/// characters, to a string in read-only memory (`StringManager::isString`), becomes the
/// constant pointer, which prints as the string. Only a symbol with a character data-type
/// gives such a PTRSUB: the data symbols of the facts (stage S10). (The read-facing and
/// def-facing types are the varnodes' own: no union is involved.)
pub(super) fn ptrsub_char_constant(fd: &mut Funcdata, op: OpId, arch: &Arch) -> Result<i32> {
    let sb = inp(fd, op, 0)?;
    let sb_type = vn_type(fd, sb);
    let Some(dt) = fd.types.ptr_to(sb_type) else { return Ok(0) };
    let Kind::Spacebase { space, .. } = fd.types.get(dt).kind else { return Ok(0) };
    let vn1 = inp(fd, op, 1)?;
    if !fd.vn(vn1).is_constant() {
        return Ok(0);
    }
    let outvn = out(fd, op)?;
    let outtype = vn_type(fd, outvn);
    let Some(basetype) = fd.types.ptr_to(outtype) else { return Ok(0) };
    if !fd.types.is_char_print(basetype) {
        return Ok(0);
    }
    // the local scope holds nothing read-only
    let val = off(fd, vn1);
    if Some(space) != fd.ram.map(Space::Sleigh) || !arch.is_readonly(val, 1) {
        return Ok(0);
    }
    if !crate::decomp::is_string(arch, val, fd.types.size(basetype))? {
        return Ok(0);
    }
    let mut remove_copy = false;
    if !fd.vn(outvn).has(VnFlags::ADDRFORCE) {
        remove_copy = true;
        let readers: Vec<OpId> = fd.vn(outvn).descend.iter().copied().collect();
        for sub in readers {
            let Some(slot) = fd.slot_of(sub, outvn) else { continue };
            if !push_const_further(fd, outtype, sub, slot, val)? {
                remove_copy = false;
            }
        }
    }
    if remove_copy {
        fd.op_destroy(op);
    } else {
        let size = sz(fd, outvn);
        let newvn = fd.new_constant(size, val);
        fd.vn_mut(newvn).ty = Some(outtype);
        fd.op_remove_input(op, 1);
        fd.op_set_input(op, newvn, 0)?;
        fd.op_set_opcode(op, Copy);
    }
    Ok(1)
}

/// Port of `RuleExtensionPush`: an extension read by several pointer additions is duplicated.
pub(super) fn extension_push(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let in_vn = inp(fd, op, 0)?;
    let iv = fd.vn(in_vn);
    if iv.is_constant() || iv.has(VnFlags::ADDRFORCE) || iv.has(VnFlags::ADDRTIED) {
        return Ok(0);
    }
    let out_vn = out(fd, op)?;
    let ov = fd.vn(out_vn);
    // isNameLock: no symbols, never set
    if ov.has(VnFlags::TYPELOCK) || ov.has(VnFlags::ADDRFORCE) || ov.has(VnFlags::ADDRTIED) {
        return Ok(0);
    }
    let (mut addcount, mut ptrcount) = (0, 0);
    for &dec in fd.vn(out_vn).descend.iter() {
        match code(fd, dec) {
            Ptradd => ptrcount += 1,
            IntAdd => {
                let sub = lone_descend(fd, out(fd, dec)?);
                if !sub.is_some_and(|s| code(fd, s) == Ptradd) {
                    return Ok(0);
                }
                addcount += 1;
            }
            _ => return Ok(0),
        }
    }
    if addcount + ptrcount <= 1 || (addcount > 0 && lone_descend(fd, in_vn).is_some()) {
        return Ok(0);
    }
    duplicate_need(fd, op)?;
    Ok(1)
}

/// Port of `RulePieceStructure`, up to the tree rewrite, which is not ported. With no symbols,
/// `getStructuredType` is the varnode's own type, so the varnode is never a partial.
pub(super) fn piece_structure(fd: &mut Funcdata, op: OpId, arch: &Arch) -> Result<i32> {
    let outvn = out(fd, op)?;
    let ct = vn_type(fd, outvn);
    if !piece_structured(fd, ct) {
        return Ok(0);
    }
    if code(fd, op) == IntZext {
        return convert_zext_to_piece(fd, arch, op, ct, 0).map(i32::from);
    }
    if let Some(z) = lone_descend(fd, outvn) {
        match code(fd, z) {
            Piece => return Ok(0),
            IntZext => {
                let zt = vn_type(fd, out(fd, z)?);
                return convert_zext_to_piece(fd, arch, z, zt, 0).map(i32::from);
            }
            _ => {}
        }
    }
    err("RulePieceStructure: the CONCAT tree rewrite (PieceNode, proto-partials) is not implemented in ghidra-rs yet")
}

/// Port of `RulePieceStructure::convertZextToPiece`.
fn convert_zext_to_piece(fd: &mut Funcdata, arch: &Arch, zext: OpId, ct: TypeId, offset: i64) -> Result<bool> {
    let outvn = out(fd, zext)?;
    let invn = inp(fd, zext, 0)?;
    if is_const(fd, invn) {
        return Ok(false);
    }
    // `int4 sz` against `sizeof(uintb)`: a negative difference compares as huge
    let Some(size) = sz(fd, outvn).checked_sub(sz(fd, invn)).filter(|&s| s <= 8) else { return Ok(false) };
    let mut new_off = offset + i64::from(sz(fd, invn)); // little-endian
    let mut cur = Some(ct);
    while let Some(t) = cur.filter(|&t| fd.types.size(t) > size) {
        cur = sub_type(fd, arch, t, new_off)?.map(|(s, o)| {
            new_off = o;
            s
        });
    }
    let zero = fd.new_constant(size, 0);
    if let Some(t) = cur.filter(|&t| fd.types.size(t) == size) {
        fd.vn_mut(zero).ty = Some(t);
    }
    fd.op_set_opcode(zext, Piece);
    fd.op_insert_input(zext, zero, 0)?;
    let it = vn_type(fd, invn);
    if fd.types.meta(it) == Meta::Union || fd.types.ptr_to(it).is_some_and(|t| fd.types.meta(t) == Meta::Union) {
        return err("RulePieceStructure: union resolution not implemented in ghidra-rs yet");
    }
    Ok(true)
}

/// Port of `Datatype::findSmallestContainer`.
fn find_smallest_container(
    fd: &mut Funcdata,
    arch: &Arch,
    t: TypeId,
    mut off: i64,
    size: i64,
) -> Result<(TypeId, i64)> {
    let (mut res, mut next, mut cur) = (t, t, off);
    while let Some((n, o)) = sub_type(fd, arch, next, cur)? {
        next = n;
        cur = o;
        if cur + size > i64::from(fd.types.size(next)) {
            break;
        }
        res = next;
        off = cur;
    }
    Ok((res, off))
}

/// Port of `RuleAndStructure`: masking a struct or array keeps one field as a SUBPIECE.
pub(super) fn and_structure(fd: &mut Funcdata, op: OpId, arch: &Arch) -> Result<i32> {
    let cvn = inp(fd, op, 1)?;
    if !is_const(fd, cvn) {
        return Ok(0);
    }
    let vn = inp(fd, op, 0)?;
    let base = vn_type(fd, vn);
    let meta = fd.types.meta(base);
    if !matches!(meta, Meta::Struct | Meta::Array) {
        return Ok(0);
    }
    let offv = off(fd, cvn);
    let count = 64 - offv.leading_zeros();
    let size = count.div_ceil(8);
    let vsize = sz(fd, vn);
    let (ct, struct_off) = find_smallest_container(fd, arch, base, 0, i64::from(size))?;
    if fd.types.size(ct) >= vsize || struct_off != 0 {
        return Ok(0);
    }
    if fd.types.meta(ct) == Meta::Unknown
        && fd.types.size(ct) == 1
        && matches!(fd.types.get(base).kind, Kind::Array { elem, .. } if elem == ct)
    {
        return Ok(0);
    }
    let sub = fd.new_op(Subpiece, op_addr(fd, op));
    // the C++ sets slot 1 first; the constant is made here, read once slot 0 exists
    let zero = fd.new_constant(4, 0);
    fd.op_mut(sub).flags.set(OpFlags::SPECIAL_PRINT);
    let o = out(fd, op)?;
    let (space, offset) = (fd.vn(o).space, fd.vn(o).offset);
    if space == Space::Join {
        return err("RuleAndStructure: join address (renormalize) not implemented in ghidra-rs yet");
    }
    let ctsize = fd.types.size(ct);
    let outvn = fd.new_varnode_out(ctsize, space, offset, sub);
    fd.vn_mut(outvn).ty = Some(ct);
    if calc_mask(size) == offv && size == ctsize {
        fd.op_remove_input(op, 1);
        fd.op_set_input(op, outvn, 0)?;
        fd.op_set_opcode(op, IntZext);
        set_sub_inputs(fd, sub, vn, zero)?;
        fd.op_insert_before(sub, op)?;
    } else {
        let nz = fd.new_op(IntZext, op_addr(fd, op));
        let outz = uniq_out(fd, vsize, nz)?;
        let oct = vn_type(fd, o);
        if fd.types.meta(oct) == Meta::Uint && !fd.vn(outz).has(VnFlags::TYPELOCK) {
            fd.vn_mut(outz).ty = Some(oct);
        }
        fd.op_set_input(op, outz, 0)?;
        set_sub_inputs(fd, sub, vn, zero)?;
        fd.op_set_input(nz, outvn, 0)?;
        fd.op_insert_before(nz, op)?;
        fd.op_insert_before(sub, nz)?;
    }
    Ok(1)
}

/// The two inputs of a new SUBPIECE (the Rust op has no preallocated slots).
fn set_sub_inputs(fd: &mut Funcdata, sub: OpId, vn: VarnodeId, c: VarnodeId) -> Result<()> {
    fd.op_set_input(sub, vn, 0)?;
    fd.op_set_input(sub, c, 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decomp::rules::testutil::{input, op_sized};

    #[test]
    fn dumpty_hump_late_folds_nested_subpieces() {
        // SUB(SUB(x,#2),#1) => SUB(x,#3); the inner SUBPIECE, now unread, is destroyed
        let mut fd = Funcdata::new(0x1000);
        let i = input(&mut fd, 0);
        let (_, x) = op_sized(&mut fd, Copy, &[i], 0x20, 8);
        let c2 = fd.new_constant(4, 2);
        let (inner, s) = op_sized(&mut fd, Subpiece, &[x, c2], 0x30, 4);
        let c1 = fd.new_constant(4, 1);
        let (outer, _) = op_sized(&mut fd, Subpiece, &[s, c1], 0x40, 2);
        assert_eq!(dumpty_hump_late_op(&mut fd, outer).unwrap(), 1);
        assert_eq!(ins(&fd, outer)[0], x);
        assert_eq!(off(&fd, ins(&fd, outer)[1]), 3);
        assert!(fd.op(inner).is_dead());
    }

    #[test]
    fn sub_right_shifts_then_truncates() {
        // SUB(x,#4) of an 8-byte x: x >> 32 into a new unique, then SUB(.., #0)
        let mut fd = Funcdata::new(0x1000);
        fd.uniq = Some(5);
        let i = input(&mut fd, 0);
        let (_, x) = op_sized(&mut fd, Copy, &[i], 0x20, 8);
        let c4 = fd.new_constant(4, 4);
        let (sub, _) = op_sized(&mut fd, Subpiece, &[x, c4], 0x30, 4);
        // the shift is inserted before the SUBPIECE: give it a block
        let bl = fd.blocks.new_block(0x1000);
        fd.op_insert_end(sub, bl);
        assert_eq!(sub_right_op(&mut fd, sub).unwrap(), 1);
        let sh = def(&fd, ins(&fd, sub)[0]).unwrap();
        assert_eq!((code(&fd, sh), ins(&fd, sh)[0], off(&fd, ins(&fd, sh)[1])), (IntRight, x, 32));
        assert_eq!(off(&fd, ins(&fd, sub)[1]), 0);
        let t = fd.vn(ins(&fd, sub)[0]).ty.unwrap();
        assert_eq!((fd.types.meta(t), fd.types.size(t)), (Meta::Uint, 8));
    }

    #[test]
    fn piece_structured_is_array_struct_union() {
        let mut fd = Funcdata::new(0x1000);
        let arr = fd.types.base(16, Meta::Unknown); // more than 10 bytes: an array of xunknown1
        let u4 = fd.types.base(4, Meta::Uint);
        assert!(piece_structured(&fd, arr));
        assert!(!piece_structured(&fd, u4));
    }
}
