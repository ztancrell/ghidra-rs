//! Port of `SplitDatatype` with `RuleSplitCopy`, `RuleSplitLoad` and `RuleSplitStore`
//! (subflow.cc): a COPY, LOAD or STORE of a structure or array becomes one op per component.
//!
//! Ported for the data-types ghidra-rs has (types.rs): structures, arrays and primitives, with
//! the default `split_datatype_config` (structures and arrays; `option splitdatatypes` is not a
//! console option here). Each of these fails with an error that names it:
//! - a data-type that needs resolution (`getTypeReadFacing`: unionresolve.cc is not ported),
//!   but a pointer to anything other than a union, which resolves to itself. So the
//!   `ResolveCache` of the C++ is always empty here and left out;
//! - a piece of a union or an enumeration (`TypePartialUnion`, `TypePartialEnum`, from
//!   `getExactPiece`; a piece of a structure or array is ported, superseded: "a piece of a
//!   structure");
//! - the CONCAT of the split outputs (`buildOutConcats`) on a big-endian target. Superseded:
//!   "a COPY or LOAD is split only when nothing reads its output": the PIECE ops, the
//!   proto-partial pieces and the partial root are built, and `Merge::groupPartials` groups them;
//! - a value in the join space (`Address::renormalize`).
//!
//! `TypePointerRel` is not a ghidra-rs type, so `getValueDatatype` reads plain pointers only.

use super::*;
use crate::decomp::infertypes::vn_type;
use crate::decomp::merge::register_proto_partial_root;
use crate::decomp::types::{Kind, Meta, TypeFactory, TypeId};

/// `SplitDatatype::Component`: the data-types of one piece on the way in and out, and its byte
/// offset.
struct Component {
    in_type: TypeId,
    out_type: TypeId,
    offset: i32,
}

/// `SplitDatatype` (`splitStructures` and `splitArrays` are on).
#[derive(Default)]
struct Split {
    pieces: Vec<Component>,
    is_load_store: bool,
}

/// `SplitDatatype::RootPointer`.
struct RootPointer {
    ptr_type: TypeId,
    first_pointer: VarnodeId,
    pointer: VarnodeId,
    base_offset: i32,
}

fn unresolved<T>() -> Result<T> {
    err("SplitDatatype: a data-type that needs resolution (unionresolve.cc) is not implemented in ghidra-rs yet")
}

/// `Varnode::getTypeReadFacing` and `getTypeDefFacing`: the type, unless it needs resolution.
fn facing(fd: &mut Funcdata, vn: VarnodeId) -> Result<TypeId> {
    let t = vn_type(fd, vn);
    if !fd.types.resolves_to_self(t) {
        return unresolved();
    }
    Ok(t)
}

/// `Varnode::updateType(ct)`: unless locked or already `ct`.
fn update_type(fd: &mut Funcdata, vn: VarnodeId, ct: TypeId) {
    if vn_type(fd, vn) != ct && !fd.vn(vn).has(VnFlags::TYPELOCK) {
        fd.vn_mut(vn).ty = Some(ct);
    }
}

/// The fields of a structure, by offset.
fn struct_fields(t: &TypeFactory, id: TypeId) -> Option<&[(String, u32, TypeId)]> {
    match &t.get(id).kind {
        Kind::Fields(fs) if t.meta(id) == Meta::Struct => Some(fs),
        _ => None,
    }
}

/// `Datatype::getSubType` of a structure (`TypeStruct::getFieldIter`: the field holding the
/// offset), an array, and the types without components.
fn sub_type(t: &TypeFactory, id: TypeId, off: i64) -> Option<(TypeId, i64)> {
    match struct_fields(t, id) {
        Some(fs) => {
            let &(_, fo, ft) = fs.iter().rev().find(|f| i64::from(f.1) <= off)?;
            (off < i64::from(fo) + i64::from(t.size(ft))).then_some((ft, off - i64::from(fo)))
        }
        None => t.sub_type(id, off),
    }
}

/// `Datatype::getHoleSize` (`TypeArray`, `TypeStruct`; 0 for the others).
fn hole_size(t: &TypeFactory, id: TypeId, off: i32) -> i32 {
    if let Kind::Array { elem, .. } = t.get(id).kind {
        return hole_size(t, elem, off % (t.align_size(elem).max(1) as i32));
    }
    // TypePartialStruct::getHoleSize (type.cc:2781-2790)
    if let Kind::PartialStruct { container, offset, .. } = t.get(id).kind {
        return hole_size(t, container, off + offset).min(t.size(id) as i32 - off);
    }
    let Some(fs) = struct_fields(t, id) else { return 0 };
    // getLowerBoundField: the last field starting at or before the offset
    let lower = fs.iter().rposition(|f| f.1 as i32 <= off);
    if let Some(&(_, fo, ft)) = lower.map(|i| &fs[i]) {
        let new_off = off - fo as i32;
        if new_off < t.size(ft) as i32 {
            return hole_size(t, ft, new_off);
        }
    }
    match fs.get(lower.map_or(0, |i| i + 1)) {
        Some(next) => next.1 as i32 - off,
        None => t.size(id) as i32 - off,
    }
}

/// Port of `TypeFactory::getExactPiece` at offset 0 (type.cc:4607-4639); a piece of an array
/// is a partial struct, a piece of a structure, union or enum is not ported.
fn exact_piece(t: &mut TypeFactory, mut ct: TypeId, size: u32) -> Result<Option<TypeId>> {
    let mut cur_off = 0i64;
    let mut last = None;
    loop {
        if i64::from(t.size(ct)) < i64::from(size) + cur_off {
            break;
        }
        if t.size(ct) == size {
            return Ok(Some(ct));
        }
        last = Some((ct, cur_off));
        match sub_type(t, ct, cur_off) {
            Some((sub, off)) => (ct, cur_off) = (sub, off),
            None => break,
        }
    }
    match last {
        Some((l, o)) if matches!(t.meta(l), Meta::Array | Meta::Struct | Meta::PartialStruct) => {
            Ok(Some(t.partial_struct(l, o as i32, size)))
        }
        Some((l, _)) if t.meta(l) == Meta::Union || t.is_enum(l) => {
            err("SplitDatatype: a piece of a union or enum (getExactPiece, TypePartialUnion) is not implemented in ghidra-rs yet")
        }
        _ => Ok(None),
    }
}

/// Port of `SplitDatatype::getValueDatatype`: the data-type of the `size` bytes a LOAD or STORE
/// points at, when it could be split.
fn value_datatype(fd: &mut Funcdata, load_store: OpId, size: u32) -> Result<Option<TypeId>> {
    let ptr = inp(fd, load_store, 1)?;
    let ptr_type = facing(fd, ptr)?;
    let Some(res) = fd.types.ptr_to(ptr_type) else { return Ok(None) };
    let meta = fd.types.meta(res);
    let align = fd.types.align_size(res);
    if align < size {
        let primitive = matches!(meta, Meta::Int | Meta::Uint | Meta::Bool | Meta::Float | Meta::Ptr);
        if primitive && size.is_multiple_of(align) {
            return fd.types.array_of(res, size / align).map(Some).map_err(LowlevelError);
        }
    } else if matches!(meta, Meta::Struct | Meta::Array) {
        return exact_piece(&mut fd.types, res, size);
    }
    Ok(None)
}

/// `TypeOp::isArithmeticOp`.
fn is_arithmetic(opc: Opcode) -> bool {
    matches!(
        opc,
        IntAdd
            | IntSub
            | IntCarry
            | IntScarry
            | IntSborrow
            | Int2comp
            | IntMult
            | IntDiv
            | IntSdiv
            | IntRem
            | IntSrem
            | Ptradd
            | Ptrsub
    )
}

/// `SplitDatatype::isArithmeticInput`.
fn is_arithmetic_input(fd: &Funcdata, vn: VarnodeId) -> bool {
    fd.vn(vn).descend.iter().any(|&op| is_arithmetic(code(fd, op)))
}

/// `SplitDatatype::isArithmeticOutput`.
fn is_arithmetic_output(fd: &Funcdata, vn: VarnodeId) -> bool {
    def(fd, vn).is_some_and(|d| is_arithmetic(code(fd, d)))
}

/// The address of a root varnode the pieces are laid out from (`Address::renormalize` only
/// changes a join address).
fn root_addr(fd: &Funcdata, vn: VarnodeId) -> Result<(Space, u64)> {
    let v = fd.vn(vn);
    if v.space == Space::Join {
        return err(
            "SplitDatatype: a value in the join space (Address::renormalize) is not implemented in ghidra-rs yet",
        );
    }
    Ok((v.space, v.offset))
}

/// Port of `SplitDatatype::buildOutConcats` (little-endian): when something reads the root,
/// PIECE ops after `previous` put the split outputs back together into it, most significant
/// first; the pieces of a root that is not address-tied are proto-partial, and the root is
/// registered for `Merge::groupPartials`.
fn out_concats(
    fd: &mut Funcdata,
    big_endian: bool,
    root: VarnodeId,
    previous: OpId,
    out_vns: &[VarnodeId],
) -> Result<()> {
    if fd.vn(root).descend.is_empty() {
        return Ok(());
    }
    if big_endian {
        return err(
            "SplitDatatype: the CONCAT of split outputs (buildOutConcats) on a big-endian target is not ported",
        );
    }
    let Some((&last, rest)) = out_vns.split_last().filter(|(_, rest)| !rest.is_empty()) else {
        return err("SplitDatatype::buildOutConcats: fewer than two pieces");
    };
    let (space, base) = root_addr(fd, root)?;
    let root_size = sz(fd, root);
    let tied = fd.vn(root).has(VnFlags::ADDRTIED);
    if !tied {
        for &o in out_vns {
            fd.vn_set(o, VnFlags::PROTO_PARTIAL);
        }
    }
    let addr = op_addr(fd, previous);
    let (mut vn, mut pre) = (last, previous);
    let mut concat = previous;
    for (i, &piece) in rest.iter().enumerate().rev() {
        concat = fd.new_op(Piece, addr);
        fd.op_set_input(concat, vn, 0)?; // most significant
        fd.op_set_input(concat, piece, 1)?; // least significant
        fd.op_insert_after(concat, pre)?;
        if i == 0 {
            break;
        }
        pre = concat;
        let size = sz(fd, vn) + sz(fd, piece);
        vn = fd.new_varnode_out(size, space, base.wrapping_add(u64::from(root_size - size)), concat);
        if !tied {
            fd.vn_set(vn, VnFlags::PROTO_PARTIAL);
        }
    }
    fd.op_mut(concat).flags.set(OpFlags::PARTIAL_ROOT);
    fd.op_set_output(concat, root)?;
    if !tied {
        register_proto_partial_root(fd, concat);
    }
    Ok(())
}

/// Port of `Funcdata::buildCopyTemp`: a COPY of `vn` into a temporary that is defined at
/// `point`, reusing a COPY into a temporary that `vn` already has when it dominates `point`.
fn build_copy_temp(fd: &mut Funcdata, vn: VarnodeId, point: OpId) -> Result<VarnodeId> {
    let uniq = fd.uniq.map(Space::Sleigh);
    let other_op = fd.vn(vn).descend.iter().copied().find(|&op| {
        code(fd, op) == Copy
            && fd.op(op).out.is_some_and(|o| Some(fd.vn(o).space) == uniq && !fd.vn(o).has(VnFlags::TYPELOCK))
    });
    let size = sz(fd, vn);
    let new_copy = |fd: &mut Funcdata, addr: u64| -> Result<OpId> {
        let c = fd.new_op(Copy, addr);
        uniq_out(fd, size, c)?;
        fd.op_set_input(c, vn, 0)?;
        Ok(c)
    };
    let parent = |fd: &Funcdata, op: OpId| {
        fd.op(op).parent.ok_or_else(|| LowlevelError("buildCopyTemp: an op outside the blocks".into()))
    };
    let mut used_copy = None;
    if let Some(other) = other_op {
        let (pb, ob) = (parent(fd, point)?, parent(fd, other)?);
        if pb == ob {
            if fd.op(point).order >= fd.op(other).order {
                used_copy = Some(other);
            }
        } else {
            let common = fd
                .find_common_block(pb, ob)
                .ok_or_else(|| LowlevelError("buildCopyTemp: no common dominator".into()))?;
            if common == ob {
                used_copy = Some(other);
            } else if common != pb {
                // neither op is an ancestor of the other
                let c = new_copy(fd, fd.blocks.block(common).stop)?;
                fd.op_insert_end(c, common);
                used_copy = Some(c);
            }
        }
    }
    let used_copy = match used_copy {
        Some(c) => c,
        None => {
            let c = new_copy(fd, op_addr(fd, point))?;
            fd.op_insert_before(c, point)?;
            c
        }
    };
    let used_out = out(fd, used_copy)?;
    if let Some(other) = other_op.filter(|&o| o != used_copy) {
        let other_out = out(fd, other)?;
        fd.total_replace(other_out, used_out)?;
        fd.op_destroy(other);
    }
    Ok(used_out)
}

impl RootPointer {
    /// Port of `RootPointer::backUpPointer`.
    fn back_up(&mut self, fd: &mut Funcdata, implied_base: Option<TypeId>) -> Result<bool> {
        let Some(add_op) = def(fd, self.pointer) else { return Ok(false) };
        let opc = code(fd, add_op);
        let mut offset = match opc {
            Ptrsub | IntAdd | Ptradd => {
                let cvn = inp(fd, add_op, 1)?;
                if !is_const(fd, cvn) {
                    return Ok(false);
                }
                off(fd, cvn) as i32
            }
            Copy => 0,
            _ => return Ok(false),
        };
        let tmp = inp(fd, add_op, 0)?;
        let ct = facing(fd, tmp)?;
        let Some(parent) = fd.types.ptr_to(ct) else { return Ok(false) };
        if !matches!(fd.types.meta(parent), Meta::Struct | Meta::Array)
            && ((opc != Ptradd && opc != Copy) || Some(parent) != implied_base)
        {
            return Ok(false);
        }
        self.ptr_type = ct;
        if opc == Ptradd {
            offset = offset.wrapping_mul(off(fd, inp(fd, add_op, 2)?) as i32);
        }
        // addressToByteInt: every x86 space has word size 1
        self.base_offset = self.base_offset.wrapping_add(offset);
        self.pointer = tmp;
        Ok(true)
    }

    /// Port of `RootPointer::find`: the pointer to `value_type` a LOAD or STORE goes through,
    /// backed up through the structures and arrays holding it.
    fn find(fd: &mut Funcdata, op: OpId, mut value_type: TypeId) -> Result<Option<RootPointer>> {
        let mut implied_base = None;
        // a partial is stripped to the structure or array holding it (subflow.cc:2146-2147)
        if let Kind::PartialStruct { container, .. } = fd.types.get(value_type).kind {
            value_type = container;
        }
        if let Kind::Array { elem, .. } = fd.types.get(value_type).kind {
            value_type = elem;
            implied_base = Some(elem); // an implied array (a pointer to the element) matches
        }
        let pointer = inp(fd, op, 1)?;
        let ct = facing(fd, pointer)?;
        let Some(to) = fd.types.ptr_to(ct) else { return Ok(None) };
        let mut root = RootPointer { ptr_type: ct, first_pointer: pointer, pointer, base_offset: 0 };
        if to != value_type {
            if implied_base.is_some() || !root.back_up(fd, implied_base)? {
                return Ok(None);
            }
            if fd.types.ptr_to(root.ptr_type) != Some(value_type) {
                return Ok(None);
            }
        }
        for _ in 0..3 {
            if fd.vn(root.pointer).has(VnFlags::ADDRTIED) || lone_descend(fd, root.pointer).is_none() {
                break;
            }
            if !root.back_up(fd, implied_base)? {
                break;
            }
        }
        Ok(Some(root))
    }

    /// Port of `RootPointer::freePointerChain`.
    fn free_pointer_chain(&mut self, fd: &mut Funcdata) -> Result<()> {
        while self.first_pointer != self.pointer
            && !fd.vn(self.first_pointer).has(VnFlags::ADDRTIED)
            && fd.vn(self.first_pointer).descend.is_empty()
        {
            let Some(tmp) = def(fd, self.first_pointer) else {
                return err("SplitDatatype: a pointer of the chain to the root is not written");
            };
            self.first_pointer = inp(fd, tmp, 0)?;
            fd.op_destroy(tmp);
        }
        Ok(())
    }
}

impl Split {
    /// Port of `SplitDatatype::getComponent`: the component starting exactly at `offset`, or
    /// an unknown type of a hole's size (and `true`).
    fn component(fd: &mut Funcdata, ct: TypeId, offset: i32) -> (Option<TypeId>, bool) {
        let (mut cur, mut cur_off) = (ct, i64::from(offset));
        loop {
            match sub_type(&fd.types, cur, cur_off) {
                Some((sub, off)) => (cur, cur_off) = (sub, off),
                None => {
                    let hole = hole_size(&fd.types, ct, offset);
                    if hole > 0 {
                        return (Some(fd.types.base(hole.min(8) as u32, Meta::Unknown)), true);
                    }
                    return (None, false);
                }
            }
            if cur_off == 0 && fd.types.meta(cur) != Meta::Array {
                return (Some(cur), false);
            }
        }
    }

    /// Port of `SplitDatatype::categorizeDatatype`: -1 not splittable, 0 a structure, 1 an
    /// array, 2 a primitive that can be split any way.
    fn categorize(t: &TypeFactory, ct: TypeId) -> i32 {
        // a piece is categorized as the structure or array holding it (subflow.cc:2258-2272)
        let ct = match t.get(ct).kind {
            Kind::PartialStruct { container, .. } => match t.meta(container) {
                Meta::Array => container,
                Meta::Struct => return 0,
                _ => return -1,
            },
            _ => ct,
        };
        match t.get(ct).kind {
            Kind::Array { elem, .. } => {
                // an array of unknown1 acts as a (large) primitive
                if t.meta(elem) != Meta::Unknown || t.size(elem) != 1 {
                    1
                } else {
                    2
                }
            }
            _ => match t.meta(ct) {
                Meta::Struct if struct_fields(t, ct).is_some_and(|fs| fs.len() > 1) => 0,
                Meta::Int | Meta::Uint | Meta::Unknown => 2,
                _ => -1,
            },
        }
    }

    /// Port of `SplitDatatype::testDatatypeCompatibility`: fills `pieces` when the two types
    /// split into components of matching size and offset.
    fn compatible(&mut self, fd: &mut Funcdata, in_base: TypeId, out_base: TypeId, in_constant: bool) -> bool {
        let in_cat = Self::categorize(&fd.types, in_base);
        let out_cat = Self::categorize(&fd.types, out_base);
        if in_cat < 0 || out_cat < 0 || (out_cat == 2 && in_cat == 2) {
            return false;
        }
        // a whole structure is split only when a constant initializes it
        if !in_constant && in_base == out_base && fd.types.meta(in_base) == Meta::Struct {
            return false;
        }
        if self.is_load_store
            && ((out_cat == 2 && in_cat == 1)
                || (in_cat == 2 && !in_constant && out_cat == 1)
                || (in_cat == 1 && out_cat == 1 && !in_constant))
        {
            return false;
        }
        let mut cur_off = 0i32;
        let mut size_left = fd.types.size(in_base) as i32;
        // a hole first, or as one of two pieces (likely padding), does not split
        let bad_hole = |n: usize, size_left: i32| n == 1 || (size_left == 0 && n == 2);
        if in_cat == 2 {
            while size_left > 0 {
                let (Some(cur_out), hole) = Self::component(fd, out_base, cur_off) else { return false };
                let size = fd.types.size(cur_out);
                // a constant takes the component's type
                let cur_in = if in_constant { cur_out } else { fd.types.base(size, Meta::Unknown) };
                self.pieces.push(Component { in_type: cur_in, out_type: cur_out, offset: cur_off });
                size_left -= size as i32;
                cur_off += size as i32;
                if hole && bad_hole(self.pieces.len(), size_left) {
                    return false;
                }
            }
        } else if out_cat == 2 {
            while size_left > 0 {
                let (Some(cur_in), hole) = Self::component(fd, in_base, cur_off) else { return false };
                let size = fd.types.size(cur_in);
                let cur_out = fd.types.base(size, Meta::Unknown);
                self.pieces.push(Component { in_type: cur_in, out_type: cur_out, offset: cur_off });
                size_left -= size as i32;
                cur_off += size as i32;
                if hole && bad_hole(self.pieces.len(), size_left) {
                    return false;
                }
            }
        } else {
            while size_left > 0 {
                let (Some(mut cur_in), mut in_hole) = Self::component(fd, in_base, cur_off) else { return false };
                let (Some(mut cur_out), mut out_hole) = Self::component(fd, out_base, cur_off) else { return false };
                while fd.types.size(cur_in) != fd.types.size(cur_out) {
                    let (in_size, out_size) = (fd.types.size(cur_in), fd.types.size(cur_out));
                    if in_size > out_size {
                        cur_in = if in_hole {
                            fd.types.base(out_size, Meta::Unknown)
                        } else {
                            let (Some(c), hole) = Self::component(fd, cur_in, 0) else { return false };
                            in_hole = hole;
                            c
                        };
                    } else {
                        cur_out = if out_hole {
                            fd.types.base(in_size, Meta::Unknown)
                        } else {
                            let (Some(c), hole) = Self::component(fd, cur_out, 0) else { return false };
                            out_hole = hole;
                            c
                        };
                    }
                }
                self.pieces.push(Component { in_type: cur_in, out_type: cur_out, offset: cur_off });
                size_left -= fd.types.size(cur_in) as i32;
                cur_off += fd.types.size(cur_in) as i32;
            }
        }
        self.pieces.len() > 1
    }

    /// Port of `SplitDatatype::testCopyConstraints`: no function input, no hidden COPY.
    fn copy_constraints(fd: &Funcdata, copy_op: OpId) -> Result<bool> {
        let in_vn = inp(fd, copy_op, 0)?;
        let v = fd.vn(in_vn);
        if v.is_input() {
            return Ok(false);
        }
        if v.has(VnFlags::ADDRTIED) {
            let o = fd.vn(out(fd, copy_op)?);
            if o.has(VnFlags::ADDRTIED) && (o.space, o.offset) == (v.space, v.offset) {
                return Ok(false);
            }
        } else if def_with(fd, in_vn, Load).is_some() && lone_descend(fd, in_vn) == Some(copy_op) {
            return Ok(false); // splitLoad handles it
        }
        Ok(true)
    }

    /// Port of `SplitDatatype::generateConstants`: the pieces of `ZEXT(c)` or `CONCAT(c1,c2)`
    /// as constants, when `vn` is one of those. The shifts are the C++'s (it shifts `hi` by a
    /// byte count); a shift of 64 bits or more, undefined there, fails.
    fn generate_constants(&self, fd: &mut Funcdata, vn: VarnodeId) -> Result<Option<Vec<VarnodeId>>> {
        if lone_descend(fd, vn).is_none() {
            return Ok(None);
        }
        let Some(op) = def(fd, vn) else { return Ok(None) };
        let (hi, lo_vn) = match code(fd, op) {
            IntZext if is_const(fd, inp(fd, op, 0)?) => (0, inp(fd, op, 0)?),
            Piece if is_const(fd, inp(fd, op, 0)?) && is_const(fd, inp(fd, op, 1)?) => {
                (off(fd, inp(fd, op, 0)?), inp(fd, op, 1)?)
            }
            _ => return Ok(None),
        };
        let (lo, lo_size) = (off(fd, lo_vn), sz(fd, lo_vn) as i32);
        let shift = |v: u64, sa: i32, left: bool| -> Result<u64> {
            let r = u32::try_from(sa).ok().and_then(|sa| if left { v.checked_shl(sa) } else { v.checked_shr(sa) });
            r.ok_or_else(|| LowlevelError("SplitDatatype::generateConstants: a shift the C++ leaves undefined".into()))
        };
        let mut in_vns = Vec::new();
        for p in &self.pieces {
            let size = fd.types.size(p.in_type);
            if size > 8 {
                return Ok(None);
            }
            let sa = p.offset;
            let mut val = if sa >= lo_size {
                shift(hi, sa - lo_size, false)?
            } else {
                let mut v = shift(lo, sa * 8, false)?;
                if sa + size as i32 > lo_size {
                    v |= shift(hi, (lo_size - sa) * 8, true)?;
                }
                v
            };
            val &= calc_mask(size);
            let c = fd.new_constant(size, val);
            update_type(fd, c, p.in_type);
            in_vns.push(c);
        }
        fd.op_destroy(op);
        Ok(Some(in_vns))
    }

    /// Port of `SplitDatatype::buildInConstants`: the pieces of a constant.
    fn in_constants(&self, fd: &mut Funcdata, root: VarnodeId) -> Vec<VarnodeId> {
        let base = off(fd, root);
        let mut in_vns = Vec::new();
        for p in &self.pieces {
            let size = fd.types.size(p.in_type);
            let val = base.checked_shr(8 * p.offset as u32).unwrap_or(0) & calc_mask(size);
            let c = fd.new_constant(size, val);
            update_type(fd, c, p.in_type);
            in_vns.push(c);
        }
        in_vns
    }

    /// Port of `SplitDatatype::buildInSubpieces`: a SUBPIECE of the root per piece, before
    /// `follow`.
    fn in_subpieces(&self, fd: &mut Funcdata, root: VarnodeId, follow: OpId) -> Result<Vec<VarnodeId>> {
        if let Some(consts) = self.generate_constants(fd, root)? {
            return Ok(consts);
        }
        let (space, base) = root_addr(fd, root)?;
        let mut in_vns = Vec::new();
        for p in &self.pieces {
            let size = fd.types.size(p.in_type);
            let sub = fd.new_op(Subpiece, op_addr(fd, follow));
            fd.op_set_input(sub, root, 0)?;
            let c = fd.new_constant(4, p.offset as u64);
            fd.op_set_input(sub, c, 1)?;
            let o = fd.new_varnode_out(size, space, base.wrapping_add(p.offset as u64), sub);
            update_type(fd, o, p.in_type);
            in_vns.push(o);
            fd.op_insert_before(sub, follow)?;
        }
        Ok(in_vns)
    }

    /// Port of `SplitDatatype::buildOutVarnodes`: a free varnode per piece in the root's storage.
    fn out_varnodes(&self, fd: &mut Funcdata, root: VarnodeId) -> Result<Vec<VarnodeId>> {
        let (space, base) = root_addr(fd, root)?;
        let mut out_vns = Vec::new();
        for p in &self.pieces {
            let o = fd.new_varnode(fd.types.size(p.out_type), space, base.wrapping_add(p.offset as u64));
            // newVarnode(size, addr, type): a symbol's locked type wins
            if fd.vn(o).ty.is_none() {
                fd.vn_mut(o).ty = Some(p.out_type);
            }
            out_vns.push(o);
        }
        Ok(out_vns)
    }

    /// Port of `SplitDatatype::buildPointers`: a chain of PTRSUB and PTRADD from the root
    /// pointer to each piece, before `follow`.
    fn pointers(&self, fd: &mut Funcdata, root: &RootPointer, follow: OpId, is_input: bool) -> Result<Vec<VarnodeId>> {
        let Kind::Pointer { to: base_type, wordsize } = fd.types.get(root.ptr_type).kind else {
            return err("SplitDatatype::buildPointers: the root is not a pointer");
        };
        let ptr_size = fd.types.size(root.ptr_type);
        let addr = op_addr(fd, follow);
        let mut ptrs = Vec::new();
        for p in &self.pieces {
            let match_type = if is_input { p.in_type } else { p.out_type };
            let mut cur_off = i64::from(root.base_offset) + i64::from(p.offset);
            let mut tmp_type = base_type;
            let mut in_ptr = root.pointer;
            loop {
                let tmp_size = i64::from(fd.types.size(tmp_type));
                let res_size = |t: TypeId| match i64::from(fd.types.size(t)) {
                    0 => err("SplitDatatype::buildPointers: a component of size 0"),
                    n => Ok(n),
                };
                // an offset outside the type means an array of it
                let (new_type, new_off) = if cur_off < 0 || cur_off >= tmp_size {
                    (tmp_type, cur_off.rem_euclid(res_size(tmp_type)?))
                } else {
                    // none: a hole in a structure, which has the piece's type
                    sub_type(&fd.types, tmp_type, cur_off).unwrap_or((match_type, 0))
                };
                // `resolver.resolve`: the cache is empty (see the module comment)
                let res_type = new_type;
                let in_size = sz(fd, in_ptr);
                let new_op = if tmp_type == res_type || fd.types.meta(tmp_type) == Meta::Array {
                    let el = res_size(res_type)?;
                    let n = fd.new_op(Ptradd, addr);
                    fd.op_set_input(n, in_ptr, 0)?;
                    let index = fd.new_constant(in_size, ((cur_off - new_off) / el) as u64);
                    fd.op_set_input(n, index, 1)?;
                    let el_vn = fd.new_constant(in_size, el as u64);
                    fd.op_set_input(n, el_vn, 2)?;
                    let index_type = fd.types.base(in_size, Meta::Int);
                    update_type(fd, index, index_type);
                    n
                } else {
                    let n = fd.new_op(Ptrsub, addr);
                    fd.op_set_input(n, in_ptr, 0)?;
                    let c = fd.new_constant(in_size, (cur_off - new_off) as u64);
                    fd.op_set_input(n, c, 1)?;
                    n
                };
                in_ptr = uniq_out(fd, in_size, new_op)?;
                let tmp_ptr = fd.types.pointer_strip_array(ptr_size, new_type, wordsize);
                update_type(fd, in_ptr, tmp_ptr);
                fd.op_insert_before(new_op, follow)?;
                tmp_type = res_type;
                cur_off = new_off;
                if fd.types.size(tmp_type) <= fd.types.size(match_type) {
                    break;
                }
            }
            ptrs.push(in_ptr);
        }
        Ok(ptrs)
    }

    /// Port of `SplitDatatype::splitCopy`.
    fn split_copy(
        &mut self,
        fd: &mut Funcdata,
        big_endian: bool,
        copy_op: OpId,
        in_type: TypeId,
        out_type: TypeId,
    ) -> Result<bool> {
        if !Self::copy_constraints(fd, copy_op)? {
            return Ok(false);
        }
        let in_vn = inp(fd, copy_op, 0)?;
        if !self.compatible(fd, in_type, out_type, is_const(fd, in_vn)) || is_arithmetic_output(fd, in_vn) {
            return Ok(false);
        }
        let out_vn = out(fd, copy_op)?;
        if is_arithmetic_input(fd, out_vn) {
            return Ok(false);
        }
        let in_vns =
            if is_const(fd, in_vn) { self.in_constants(fd, in_vn) } else { self.in_subpieces(fd, in_vn, copy_op)? };
        let out_vns = self.out_varnodes(fd, out_vn)?;
        out_concats(fd, big_endian, out_vn, copy_op, &out_vns)?;
        for (&i, &o) in in_vns.iter().zip(&out_vns) {
            let n = fd.new_op(Copy, op_addr(fd, copy_op));
            fd.op_set_input(n, i, 0)?;
            fd.op_set_output(n, o)?;
            fd.op_insert_before(n, copy_op)?;
        }
        fd.op_destroy(copy_op);
        Ok(true)
    }

    /// Port of `SplitDatatype::splitLoad`: also splits the COPY that alone reads the LOAD.
    fn split_load(&mut self, fd: &mut Funcdata, big_endian: bool, load_op: OpId, in_type: TypeId) -> Result<bool> {
        self.is_load_store = true;
        let mut out_vn = out(fd, load_op)?;
        let mut copy_op = None;
        if !fd.vn(out_vn).has(VnFlags::ADDRTIED) {
            copy_op = lone_descend(fd, out_vn);
        }
        match copy_op.map(|c| code(fd, c)) {
            Some(Store | Zpull | Spull) => return Ok(false), // a STORE: RuleSplitStore handles it
            Some(Copy) | None => {}
            Some(_) => copy_op = None,
        }
        if let Some(c) = copy_op {
            out_vn = out(fd, c)?;
        }
        let out_type = facing(fd, out_vn)?;
        if !self.compatible(fd, in_type, out_type, false) || is_arithmetic_input(fd, out_vn) {
            return Ok(false);
        }
        let Some(mut root) = RootPointer::find(fd, load_op, in_type)? else { return Ok(false) };
        let insert_point = copy_op.unwrap_or(load_op);
        let ptrs = self.pointers(fd, &root, load_op, true)?;
        let out_vns = self.out_varnodes(fd, out_vn)?;
        out_concats(fd, big_endian, out_vn, insert_point, &out_vns)?;
        let spc = off(fd, inp(fd, load_op, 0)?) as u32; // getSpaceFromConst
        for (&p, &o) in ptrs.iter().zip(&out_vns) {
            let n = fd.new_op(Load, op_addr(fd, insert_point));
            let s = fd.new_varnode_space(spc);
            fd.op_set_input(n, s, 0)?;
            fd.op_set_input(n, p, 1)?;
            fd.op_set_output(n, o)?;
            fd.op_insert_before(n, insert_point)?;
        }
        if let Some(c) = copy_op {
            fd.op_destroy(c);
        }
        fd.op_destroy(load_op);
        root.free_pointer_chain(fd)?;
        Ok(true)
    }

    /// Port of `SplitDatatype::splitStore`: also splits the LOAD whose value alone is stored.
    fn split_store(&mut self, fd: &mut Funcdata, store_op: OpId, out_type: TypeId) -> Result<bool> {
        self.is_load_store = true;
        let in_vn = inp(fd, store_op, 2)?;
        let mut load_op = None;
        let mut in_type = None;
        if let Some(l) = def_with(fd, in_vn, Load).filter(|_| lone_descend(fd, in_vn) == Some(store_op)) {
            in_type = value_datatype(fd, l, sz(fd, in_vn))?;
            load_op = in_type.map(|_| l);
        }
        let mut in_type = match in_type {
            Some(t) => t,
            None => facing(fd, in_vn)?,
        };
        let in_constant = is_const(fd, in_vn);
        if !self.compatible(fd, in_type, out_type, in_constant) {
            // not with the LOAD: again without it
            if load_op.take().is_none() {
                return Ok(false);
            }
            in_type = facing(fd, in_vn)?;
            self.pieces.clear();
            if !self.compatible(fd, in_type, out_type, in_constant) {
                return Ok(false);
            }
        }
        if is_arithmetic_output(fd, in_vn) {
            return Ok(false);
        }
        let Some(mut store_root) = RootPointer::find(fd, store_op, out_type)? else { return Ok(false) };
        let mut load_root = None;
        if let Some(l) = load_op {
            match RootPointer::find(fd, l, in_type)? {
                Some(r) => load_root = Some((l, r)),
                None => return Ok(false),
            }
        }
        let store_space = off(fd, inp(fd, store_op, 0)?) as u32; // getSpaceFromConst
        let in_vns = if in_constant {
            self.in_constants(fd, in_vn)
        } else if let Some((l, root)) = &load_root {
            let load_ptrs = self.pointers(fd, root, *l, true)?;
            let load_space = off(fd, inp(fd, *l, 0)?) as u32;
            let mut vns = Vec::new();
            for (&ptr, p) in load_ptrs.iter().zip(&self.pieces) {
                let n = fd.new_op(Load, op_addr(fd, *l));
                let s = fd.new_varnode_space(load_space);
                fd.op_set_input(n, s, 0)?;
                fd.op_set_input(n, ptr, 1)?;
                let vn = uniq_out(fd, fd.types.size(p.in_type), n)?;
                update_type(fd, vn, p.in_type);
                vns.push(vn);
                fd.op_insert_before(n, *l)?;
            }
            vns
        } else {
            self.in_subpieces(fd, in_vn, store_op)?
        };
        if fd.vn(store_root.pointer).has(VnFlags::ADDRTIED) {
            // RootPointer::duplicateToTemp: the STOREs must not change the root pointer
            let new_root = build_copy_temp(fd, store_root.pointer, store_op)?;
            update_type(fd, new_root, store_root.ptr_type);
            store_root.pointer = new_root;
        }
        let store_ptrs = self.pointers(fd, &store_root, store_op, false)?;
        // the STORE stays, as the first of the smaller ones, so its INDIRECTs stay valid
        fd.op_set_input(store_op, store_ptrs[0], 1)?;
        fd.op_set_input(store_op, in_vns[0], 2)?;
        let mut last_store = store_op;
        for (&ptr, &vn) in store_ptrs.iter().zip(&in_vns).skip(1) {
            let n = fd.new_op(Store, op_addr(fd, store_op));
            let s = fd.new_varnode_space(store_space);
            fd.op_set_input(n, s, 0)?;
            fd.op_set_input(n, ptr, 1)?;
            fd.op_set_input(n, vn, 2)?;
            fd.op_insert_after(n, last_store)?;
            last_store = n;
        }
        if let Some((l, mut root)) = load_root {
            fd.op_destroy(l);
            root.free_pointer_chain(fd)?;
        }
        store_root.free_pointer_chain(fd)?;
        Ok(true)
    }
}

/// Port of `RuleSplitCopy`.
pub(super) fn split_copy(fd: &mut Funcdata, op: OpId, arch: &Arch) -> Result<i32> {
    let in_type = facing(fd, inp(fd, op, 0)?)?;
    let out_type = facing(fd, out(fd, op)?)?;
    let splittable = |t: TypeId| matches!(fd.types.meta(t), Meta::Array | Meta::Struct | Meta::PartialStruct);
    if !splittable(in_type) && !splittable(out_type) {
        return Ok(0);
    }
    Ok(i32::from(Split::default().split_copy(fd, arch.sleigh.big_endian, op, in_type, out_type)?))
}

/// Port of `RuleSplitLoad`.
pub(super) fn split_load(fd: &mut Funcdata, op: OpId, arch: &Arch) -> Result<i32> {
    let size = sz(fd, out(fd, op)?);
    let Some(in_type) = value_datatype(fd, op, size)? else { return Ok(0) };
    if !matches!(fd.types.meta(in_type), Meta::Struct | Meta::Array | Meta::PartialStruct) {
        return Ok(0);
    }
    Ok(i32::from(Split::default().split_load(fd, arch.sleigh.big_endian, op, in_type)?))
}

/// Port of `RuleSplitStore`.
pub(super) fn split_store(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let size = sz(fd, inp(fd, op, 2)?);
    let Some(out_type) = value_datatype(fd, op, size)? else { return Ok(0) };
    if !matches!(fd.types.meta(out_type), Meta::Struct | Meta::Array | Meta::PartialStruct) {
        return Ok(0);
    }
    Ok(i32::from(Split::default().split_store(fd, op, out_type)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `struct { int4 a; int1 b; <3 bytes>; int4 c[2]; }`: components at exact offsets, the
    /// hole after `b`, the element of the array, and the categories.
    #[test]
    fn components_holes_and_categories() {
        let mut fd = Funcdata::new(0);
        let (i4, i1) = (fd.types.base(4, Meta::Int), fd.types.base(1, Meta::Int));
        let arr = fd.types.array_of(i4, 2).unwrap();
        let st = fd.types.aggregate("s", false, vec![("a".into(), i4), ("b".into(), i1), ("c".into(), arr)]).unwrap();
        assert_eq!(fd.types.size(st), 16);
        assert_eq!(Split::component(&mut fd, st, 0), (Some(i4), false));
        assert_eq!(Split::component(&mut fd, st, 4), (Some(i1), false));
        let hole = fd.types.base(3, Meta::Unknown);
        assert_eq!(Split::component(&mut fd, st, 5), (Some(hole), true));
        assert_eq!(Split::component(&mut fd, st, 12), (Some(i4), false));
        assert_eq!(Split::component(&mut fd, st, 2), (None, false));
        assert_eq!((hole_size(&fd.types, st, 5), hole_size(&fd.types, st, 9), hole_size(&fd.types, st, 16)), (3, 0, 0));
        let u1 = fd.types.base(1, Meta::Unknown);
        let bytes = fd.types.array_of(u1, 8).unwrap();
        let cats = [st, arr, bytes, i4, fd.types.base(4, Meta::Float)].map(|t| Split::categorize(&fd.types, t));
        assert_eq!(cats, [0, 1, 2, 2, -1]);
        // a 16-byte unknown constant against the structure: a, b, the hole, c[0], c[1]
        let mut s = Split::default();
        let u16 = fd.types.base(16, Meta::Unknown);
        assert!(s.compatible(&mut fd, u16, st, true));
        assert_eq!(s.pieces.iter().map(|p| p.offset).collect::<Vec<_>>(), [0, 4, 5, 8, 12]);
        // a structure is not split into itself, and two primitives never
        assert!(!Split::default().compatible(&mut fd, st, st, false));
        assert!(!Split::default().compatible(&mut fd, u16, u16, true));
    }

    /// An 8-byte root read by another op, split into pieces of 4, 2 and 2 bytes: two PIECEs
    /// after the COPY rebuild it from the most significant piece down, the inner one at the
    /// root's upper half, and nothing is built for a root nobody reads.
    #[test]
    fn out_concats_from_the_top() {
        let mut fd = Funcdata::new(0x1000);
        let bl = fd.blocks.new_block(0x1000);
        fd.blocks.set_start_block(bl);
        let ram = Space::Sleigh(1);
        let copy = fd.new_op(Copy, 0x1000);
        let root = fd.new_varnode_out(8, ram, 0x100, copy);
        let c = fd.new_constant(8, 0);
        fd.op_set_input(copy, c, 0).unwrap();
        fd.op_insert_end(copy, bl);
        let pieces = [(4, 0x100), (2, 0x104), (2, 0x106)].map(|(s, o)| fd.new_varnode(s, ram, o));
        out_concats(&mut fd, false, root, copy, &pieces).unwrap();
        assert_eq!(fd.vn(root).def, Some(copy), "an unread root keeps its COPY");
        let reader = fd.new_op(Copy, 0x1004);
        fd.op_set_input(reader, root, 0).unwrap();
        fd.op_insert_end(reader, bl);
        out_concats(&mut fd, false, root, copy, &pieces).unwrap();
        let top = fd.vn(root).def.unwrap();
        assert!(top != copy && code(&fd, top) == Piece && fd.op(top).flags.has(OpFlags::PARTIAL_ROOT));
        let inner = inp(&fd, top, 0).unwrap();
        assert_eq!((fd.vn(inner).offset, fd.vn(inner).size, inp(&fd, top, 1).unwrap()), (0x104, 4, pieces[0]));
        let low = fd.vn(inner).def.unwrap();
        assert_eq!((inp(&fd, low, 0).unwrap(), inp(&fd, low, 1).unwrap()), (pieces[2], pieces[1]));
        assert_eq!(fd.blocks.block(bl).ops, [copy, low, top, reader]);
        assert!(pieces.iter().chain([&inner]).all(|&v| fd.vn(v).has(VnFlags::PROTO_PARTIAL)));
        assert_eq!(fd.highs.proto_partial, [top]);
        assert!(out_concats(&mut fd, true, root, top, &pieces).is_err());
    }
}
