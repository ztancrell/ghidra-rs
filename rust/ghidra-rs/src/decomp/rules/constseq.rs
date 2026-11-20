//! The `constsequence` rules (stage R5, slice 5): `RuleStringCopy`, `RuleStringStore`
//! (constseq.cc), up to their sequences. `RuleStringCopy` needs a local symbol holding the
//! copied-to storage (`ScopeLocal::queryContainer`): a locked parameter of the function or a
//! symbol of `restructure_varnode` (superseded: "the local scope's symbols are the locked
//! parameters of the function (`localrecovery` is not ported)"). `StringSequence` is
//! ported up to its validity (the constructor): a COPY that roots no sequence of four characters
//! in an array of the symbol is left alone, a valid sequence and a symbol of a struct or union
//! fail loudly (`StringSequence::transform` is not ported). Superseded: "a character copied into
//! one fails loudly". `RuleStringStore`'s `HeapSequence` is
//! ported up to its validity (the constructor): a STORE that roots no sequence of four
//! characters is left alone, a valid sequence fails loudly (`HeapSequence::transform`, the
//! built-in string copy user-op and its internal string, is not ported). Superseded: "reaching
//! `HeapSequence` fails loudly". No type is an opaque string (`isOpaqueString`) here.

use super::*;
use crate::decomp::infertypes::vn_type_facing;
use crate::decomp::locked::param_symbol;
use crate::decomp::types::{Meta, TypeId};

/// Port of `RuleStringCopy`, up to `StringSequence::transform`, which is not ported.
pub(super) fn string_copy(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    if !is_const(fd, inp(fd, op, 0)?) {
        return Ok(0);
    }
    let outvn = out(fd, op)?;
    let ct = vn_type_facing(fd, outvn, "RuleStringCopy")?;
    if !fd.types.is_char_print(ct) || !fd.vn(outvn).has(VnFlags::ADDRTIED) {
        return Ok(0);
    }
    // ScopeLocal::queryContainer: a piece of a locked stack parameter fails in heritage, so the
    // entry holding the varnode is the parameter exactly at it
    // (or a symbol of `restructure_varnode` holding it)
    let v = fd.vn(outvn);
    let (space, root_off) = (v.space, v.offset);
    let entry = match param_symbol(fd, outvn) {
        Some(i) => fd.proto.locked.as_ref().map(|l| (v.offset, v.size, l.inputs[i].ty)),
        None if v.space == Space::Stack => fd
            .localmap
            .find_container(v.offset, v.size)
            .and_then(|s| fd.symtab.symbol(s.id).ty.map(|t| (s.off, (s.last - s.off + 1) as u32, t))),
        None => None,
    };
    let Some(entry) = entry else { return Ok(0) };
    if string_sequence_valid(fd, ct, entry, op, space, root_off)? {
        return err("RuleStringCopy: StringSequence::transform (the string copy user-op, constseq.cc) not implemented in ghidra-rs yet");
    }
    Ok(0)
}

/// Port of the `StringSequence` constructor (`collectCopyOps`, `checkInterference`,
/// `formByteArray`): whether the COPYs of constant characters into the array of the symbol
/// `entry` (first offset, size, data-type) holding the root's output fill a run of at least
/// four characters starting at the root.
fn string_sequence_valid(
    fd: &Funcdata,
    ct: TypeId,
    (first, size, sym_ty): (u64, u32, TypeId),
    root: OpId,
    space: Space,
    root_off: u64,
) -> Result<bool> {
    let mut sub = root_off.wrapping_sub(first) as i64;
    if sub >= i64::from(size) || off(fd, inp(fd, root, 0)?) == 0 {
        return Ok(false);
    }
    // the array holding the root: walk the symbol's data-type down to the character
    let (mut parent, mut array, mut last_off) = (Some(sym_ty), None, 0i64);
    while let Some(p) = parent {
        if p == ct {
            break;
        }
        array = Some(p);
        last_off = sub;
        if fd.types.needs_resolution(p) || matches!(fd.types.meta(p), Meta::Struct | Meta::Union) {
            return err(
                "StringSequence: a character in a struct or union (getSubType, resolveTruncation) is not ported",
            );
        }
        parent = fd.types.sub_type(p, sub).map(|(t, o)| {
            sub = o;
            t
        });
    }
    let Some(array) = array.filter(|&a| parent == Some(ct) && fd.types.meta(a) == Meta::Array) else {
        return Ok(false);
    };
    let start = root_off.wrapping_sub(last_off as u64);
    // collectCopyOps
    let (el_size, align) = (fd.types.size(ct), u64::from(fd.types.align_size(ct)));
    let arr_size = u64::from(fd.types.size(array));
    let end = start.wrapping_add(arr_size - 1);
    let begin = if start != root_off { root_off.wrapping_sub(align) } else { start };
    let block = fd.op(root).parent;
    let mut diff = root_off.wrapping_sub(start) as i64;
    let mut moves = Vec::new();
    for vn in fd.loc_range(space, begin, Some(end.wrapping_add(1))) {
        let Some(op) = def(fd, vn) else { continue };
        if code(fd, op) != Copy || fd.op(op).parent != block || !is_const(fd, inp(fd, op, 0)?) {
            continue;
        }
        let v = fd.vn(vn);
        if v.size != el_size {
            return Ok(false); // the wrong size (has yet to be split)
        }
        let tmp = v.offset.wrapping_sub(start) as i64;
        let a = align as i64;
        if tmp < diff {
            if tmp + a == diff {
                return Ok(false); // a COPY to the previous element: the root is not the first
            }
            continue;
        } else if tmp > diff {
            if tmp - diff < a {
                continue;
            }
            if tmp - diff > a {
                break; // a gap
            }
            diff = tmp;
        }
        moves.push((v.offset, op));
    }
    if moves.len() < MINIMUM_SEQUENCE_LENGTH {
        return Ok(false);
    }
    // checkInterference
    moves.sort_by_key(|&(_, op)| fd.op(op).order);
    let Some(pos) = moves.iter().position(|&(_, op)| op == root) else { return Ok(false) };
    let (mut lo, mut hi) = (pos, pos + 1);
    while lo > 0 && interfere_between(fd, moves[lo - 1].1, moves[lo].1)? {
        lo -= 1;
    }
    while hi < moves.len() && interfere_between(fd, moves[hi - 1].1, moves[hi].1)? {
        hi += 1;
    }
    if hi - lo < MINIMUM_SEQUENCE_LENGTH {
        return Ok(false);
    }
    // formByteArray: the characters from the root on, up to one null terminator
    let sz = arr_size.wrapping_sub(root_off.wrapping_sub(start)) as i64;
    let mut used = vec![0u8; sz.max(0) as usize];
    for &(o, op) in &moves[lo..hi] {
        let pos = o.wrapping_sub(root_off) as i64;
        if pos < 0 || pos + i64::from(el_size) > sz {
            continue;
        }
        used[pos as usize] = if off(fd, inp(fd, op, 0)?) == 0 { 2 } else { 1 };
    }
    let mut count = 0;
    while count < used.len() / align as usize {
        match used[count * align as usize] {
            1 => count += 1,
            2 => {
                count += 1;
                break;
            }
            _ => break,
        }
    }
    Ok(count >= MINIMUM_SEQUENCE_LENGTH)
}

/// Port of `RuleStringStore`, up to `HeapSequence::transform`, which is not ported.
pub(super) fn string_store(fd: &mut Funcdata, op: OpId, arch: &Arch) -> Result<i32> {
    if !is_const(fd, inp(fd, op, 2)?) {
        return Ok(0);
    }
    let pt = vn_type_facing(fd, inp(fd, op, 1)?, "RuleStringStore")?;
    match fd.types.ptr_to(pt) {
        Some(ct) if fd.types.is_char_print(ct) && heap_sequence_valid(fd, arch, ct, op)? => {
            err("RuleStringStore: HeapSequence::transform (the string copy user-op, constseq.cc) not implemented in ghidra-rs yet")
        }
        _ => Ok(0),
    }
}

/// `ArraySequence::MINIMUM_SEQUENCE_LENGTH`, `MAXIMUM_SEQUENCE_LENGTH`
const MINIMUM_SEQUENCE_LENGTH: usize = 4;
const MAXIMUM_SEQUENCE_LENGTH: u64 = 0x20000;

fn is_ptr_step(opc: Opcode) -> bool {
    matches!(opc, Ptrsub | IntAdd | Ptradd)
}

/// The constant a PTRSUB, INT_ADD or PTRADD adds, in bytes.
fn step_offset(fd: &Funcdata, op: OpId) -> Result<u64> {
    let o = off(fd, inp(fd, op, 1)?);
    Ok(if code(fd, op) == Ptradd { o.wrapping_mul(off(fd, inp(fd, op, 2)?)) } else { o })
}

/// Port of `HeapSequence::findDuplicateBases`: the varnodes reached from an earlier root of
/// `base` by the same constant offsets (`base` among them).
fn find_duplicate_bases(fd: &Funcdata, base: VarnodeId) -> Result<Vec<VarnodeId>> {
    let Some(mut op) = def(fd, base) else { return Ok(vec![base]) };
    if !is_ptr_step(code(fd, op)) || !is_const(fd, inp(fd, op, 1)?) {
        return Ok(vec![base]);
    }
    let mut offset = Vec::new();
    let copy_root = loop {
        offset.push(step_offset(fd, op)?);
        let root = inp(fd, op, 0)?;
        match def(fd, root) {
            Some(d) if is_ptr_step(code(fd, d)) && is_const(fd, inp(fd, d, 1)?) => op = d,
            _ => break root,
        }
    };
    let mut dup = vec![copy_root];
    for &want in offset.iter().rev() {
        let mid = std::mem::take(&mut dup);
        for vn in mid {
            for &op in fd.vn(vn).descend.iter() {
                if !is_ptr_step(code(fd, op)) || inp(fd, op, 0)? != vn || !is_const(fd, inp(fd, op, 1)?) {
                    continue;
                }
                if step_offset(fd, op)? == want {
                    dup.push(out(fd, op)?);
                }
            }
        }
    }
    Ok(dup)
}

/// Port of `HeapSequence::findInitialStores`: the STOREs in the block of `root` (less `root`)
/// through pointers derived from `base`.
fn find_initial_stores(fd: &Funcdata, base: VarnodeId, root: OpId, mult: u64) -> Result<Vec<OpId>> {
    let mut ptradds = find_duplicate_bases(fd, base)?;
    let mut stores = Vec::new();
    let mut pos = 0;
    while pos < ptradds.len() {
        let vn = ptradds[pos];
        pos += 1;
        for &op in fd.vn(vn).descend.iter() {
            match code(fd, op) {
                Ptradd if inp(fd, op, 0)? == vn && off(fd, inp(fd, op, 2)?) == mult => ptradds.push(out(fd, op)?),
                Copy => ptradds.push(out(fd, op)?),
                Store if fd.op(op).parent == fd.op(root).parent && op != root && inp(fd, op, 1)? == vn => {
                    stores.push(op);
                }
                _ => {}
            }
        }
    }
    Ok(stores)
}

/// Port of `HeapSequence::calcAddElements`.
fn calc_add_elements(fd: &Funcdata, vn: VarnodeId, non_const: &mut Vec<VarnodeId>, max_depth: i32) -> Result<u64> {
    if is_const(fd, vn) {
        return Ok(off(fd, vn));
    }
    match def_with(fd, vn, IntAdd).filter(|_| max_depth != 0) {
        Some(add) => Ok(calc_add_elements(fd, inp(fd, add, 0)?, non_const, max_depth - 1)?
            .wrapping_add(calc_add_elements(fd, inp(fd, add, 1)?, non_const, max_depth - 1)?)),
        None => {
            non_const.push(vn);
            Ok(0)
        }
    }
}

/// Port of `HeapSequence::calcPtraddOffset` (word size 1): the constant byte offset of `vn`
/// from the base pointer and the non-constant terms on the way.
fn calc_ptradd_offset(fd: &Funcdata, mut vn: VarnodeId, mult: u64) -> Result<(u64, Vec<VarnodeId>)> {
    let (mut res, mut non_const) = (0u64, Vec::new());
    while let Some(op) = def(fd, vn) {
        match code(fd, op) {
            Ptradd if off(fd, inp(fd, op, 2)?) == mult => {
                res = res.wrapping_add(calc_add_elements(fd, inp(fd, op, 1)?, &mut non_const, 3)?.wrapping_mul(mult));
            }
            Copy => {}
            _ => break,
        }
        vn = inp(fd, op, 0)?;
    }
    Ok((res, non_const))
}

/// Port of `ArraySequence::interfereBetween`: no LOAD, STORE, call or branch after `start`
/// and before `end`, a later op of the same block.
fn interfere_between(fd: &Funcdata, start: OpId, end: OpId) -> Result<bool> {
    let bl = fd.op(start).parent.ok_or_else(|| LowlevelError("HeapSequence: a STORE without a block".into()))?;
    let ops = &fd.blocks.block(bl).ops;
    let from = ops.iter().position(|&o| o == start).map_or(ops.len(), |i| i + 1);
    for &op in &ops[from..] {
        if op == end {
            return Ok(true);
        }
        let opc = code(fd, op);
        if crate::decomp::blocktransform::is_special(opc)
            && !matches!(opc, Indirect | Callother | Segmentop | Cpoolref | New)
        {
            return Ok(false);
        }
    }
    err("HeapSequence: the STOREs of a sequence are out of block order")
}

/// Port of the `HeapSequence` constructor (`findBasePointer`, `collectStoreOps`,
/// `checkInterference`, `formByteArray`): whether the STOREs of constants through the pointer
/// of `root`, in its block, fill a run of at least four characters starting at `root`.
fn heap_sequence_valid(fd: &Funcdata, arch: &Arch, ct: TypeId, root: OpId) -> Result<bool> {
    let (el_size, align) = (u64::from(fd.types.size(ct)), u64::from(fd.types.align_size(ct)));
    // findBasePointer (ptrAddMult is the element size: every x86 space has word size 1)
    let mut base = inp(fd, root, 1)?;
    while let Some(op) = def(fd, base) {
        match code(fd, op) {
            Ptradd if off(fd, inp(fd, op, 2)?) == align => {}
            Copy => {}
            _ => break,
        }
        base = inp(fd, op, 0)?;
    }
    // collectStoreOps
    let init = find_initial_stores(fd, base, root, align)?;
    if init.len() + 1 < MINIMUM_SEQUENCE_LENGTH {
        return Ok(false);
    }
    let max_size = MAXIMUM_SEQUENCE_LENGTH * align;
    let space = arch
        .sleigh
        .spaces
        .get(off(fd, inp(fd, root, 0)?) as usize) // getSpaceFromConst
        .ok_or_else(|| LowlevelError("HeapSequence: a STORE into an unknown space".into()))?;
    let wrap = calc_mask(space.size);
    let (base_off, adds) = calc_ptradd_offset(fd, inp(fd, root, 1)?, align)?;
    let mut moves = Vec::with_capacity(init.len() + 1);
    for op in init {
        let (cur, comp) = calc_ptradd_offset(fd, inp(fd, op, 1)?, align)?;
        let diff = cur.wrapping_sub(base_off) & wrap;
        if comp == adds {
            let val = inp(fd, op, 2)?;
            // an offset from the root's within the maximum, and a constant character (testValue)
            if diff >= max_size || !is_const(fd, val) || u64::from(sz(fd, val)) != el_size {
                return Ok(false);
            }
            moves.push((diff, op));
        }
    }
    moves.push((0, root));
    // checkInterference: the ops in block order, cut at the first gap with an interfering op
    moves.sort_by_key(|&(_, op)| fd.op(op).order);
    let pos = moves.iter().position(|&(_, op)| op == root).unwrap_or(0);
    let (mut start, mut end) = (pos, pos + 1);
    while start > 0 && interfere_between(fd, moves[start - 1].1, moves[start].1)? {
        start -= 1;
    }
    while end < moves.len() && interfere_between(fd, moves[end - 1].1, moves[end].1)? {
        end += 1;
    }
    if end - start < MINIMUM_SEQUENCE_LENGTH {
        return Ok(false);
    }
    let moves = &moves[start..end];
    // formByteArray: the characters from offset 0 on, up to one null terminator
    let size = moves.len() as u64 * align;
    let mut used = vec![0u8; size as usize];
    for &(offset, op) in moves {
        if offset + el_size <= size {
            used[offset as usize] = if off(fd, inp(fd, op, 2)?) == 0 { 2 } else { 1 };
        }
    }
    let mut count = 0;
    while count < moves.len() {
        match used[count * align as usize] {
            1 => count += 1,
            2 => {
                count += 1;
                break;
            }
            _ => break,
        }
    }
    Ok(count >= MINIMUM_SEQUENCE_LENGTH)
}
