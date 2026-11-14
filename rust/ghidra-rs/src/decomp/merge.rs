//! Port of `merge.cc` and the merge actions of `coreaction.cc` (stage S7): SSA varnodes are
//! merged into high variables, first the merges the IR forces (address-tied storage,
//! MULTIEQUAL and INDIRECT), then speculative ones (COPY, adjacent ops, same data-type). Where
//! a forced merge would make a variable live twice at once, a COPY is put in to split it
//! (`snipReads`, `trimOpInput`, `trimOpOutput`); these COPYs and the order the ops and
//! varnodes are visited in decide sequence numbers, so both follow the C++ exactly.
//!
//! Edits go through the wrappers here, which mark the varnode covers dirty where the C++
//! `Varnode::setFlags(coverdirty)` does (descendants and definitions changing).
//!
//! Not ported (each fails loudly or cannot arise): `VariablePiece` groups (`groupWith`, from
//! address-tied overlaps of different sizes and proto-partial PIECEs), symbols other than the
//! locked parameters of the function (`high_symbol`; multi-entry symbols, `mergeMultiEntry` has
//! none), union data-types needing resolution, join padding
//! records (`markPurePaddingCopies` has none).

use std::collections::HashSet;

use super::block::BlockId;
use super::cover::{add_def_point, add_ref_point, contain_varnode_def, op_block_index, op_uindex, Cover};
use super::funcdata::Funcdata;
use super::op::{OpFlags, OpId};
use super::opcode::Opcode;
use super::types::{Meta, TypeId};
use super::variable::{
    assign_high, copy_shadow, h_extra_out, h_has_cover, h_is, h_type, high, high_merge, high_remove, input_varnode,
    intersection, partial_copy_shadow, set_high_level, tied_varnode, update_high, update_internal_cover, vn_cover,
    vn_cover_dirty, vn_has_cover, vn_implied, HighId,
};
use super::varnode::{Space, VarnodeId, VnFlags};
use super::Arch;
use super::{err, Result};

// ---- edits that keep covers in step (Varnode::setFlags(coverdirty)) ----

/// `Funcdata::opSetInput`: both the old and the new input change their reads.
fn set_input(fd: &mut Funcdata, op: OpId, vn: VarnodeId, slot: usize) -> Result<()> {
    let old = fd.op(op).ins.get(slot).copied();
    if old == Some(vn) {
        return Ok(());
    }
    fd.op_set_input(op, vn, slot)?;
    if let Some(o) = old {
        vn_cover_dirty(fd, o);
    }
    let now = fd.op(op).ins[slot];
    assign_high(fd, now);
    vn_cover_dirty(fd, now);
    Ok(())
}

/// `Funcdata::opSetOutput` with `setVarnodeProperties`' `calcCover`.
fn set_output(fd: &mut Funcdata, op: OpId, vn: VarnodeId) -> Result<()> {
    let olds = [fd.op(op).out, fd.vn(vn).def.and_then(|d| fd.op(d).out)];
    fd.op_set_output(op, vn)?;
    for o in olds.into_iter().flatten() {
        vn_cover_dirty(fd, o);
    }
    super::variable::calc_cover(fd, vn);
    vn_cover_dirty(fd, vn);
    Ok(())
}

/// `Funcdata::opDestroy`: the output leaves its high (the `Varnode` destructor), the inputs
/// lose a read.
fn destroy(fd: &mut Funcdata, op: OpId) {
    if let Some(out) = fd.op(op).out {
        high_remove(fd, out);
    }
    let ins = fd.op(op).ins.clone();
    fd.op_destroy(op);
    for vn in ins {
        vn_cover_dirty(fd, vn);
    }
}

/// `Funcdata::totalReplace`
fn total_replace(fd: &mut Funcdata, vn: VarnodeId, newvn: VarnodeId) -> Result<()> {
    let readers = fd.vn(vn).descend.to_vec();
    for op in readers {
        if let Some(slot) = fd.slot_of(op, vn) {
            set_input(fd, op, newvn, slot)?;
        }
    }
    Ok(())
}

/// `Funcdata::newUnique(size, ct)`, with its high (`assignHigh`).
fn new_unique(fd: &mut Funcdata, size: u32, ct: TypeId) -> Result<VarnodeId> {
    let Some(uniq) = fd.uniq else { return err("newUnique: no unique space") };
    let vn = fd.new_unique(size, uniq);
    fd.vn_mut(vn).ty = Some(ct);
    assign_high(fd, vn);
    Ok(vn)
}

/// `Datatype::needsResolution`: a union, or a pointer to one, needs a field chosen; union
/// resolution (`unionresolve`) is not ported.
fn check_resolution(fd: &Funcdata, ct: TypeId) -> Result<()> {
    let is_union = |t| fd.types.meta(t) == Meta::Union;
    if is_union(ct) || fd.types.ptr_to(ct).is_some_and(is_union) {
        return err("merge: a COPY of a union data-type needs union resolution, not ported");
    }
    Ok(())
}

/// `PcodeOp::getOpFromConst(op->getIn(1)->getAddr())`: the op an INDIRECT is for.
fn indirect_effect(fd: &Funcdata, indop: OpId) -> Result<OpId> {
    match fd.op(indop).ins.get(1).and_then(|&i| fd.iop_target(i)) {
        Some(op) => Ok(op),
        None => err("INDIRECT without its effect op"),
    }
}

/// The live ops in the order of the C++ alive list (`beginOpAlive`): by when they last went
/// into a block.
fn alive_ops(fd: &Funcdata) -> Vec<OpId> {
    let mut ops: Vec<OpId> = fd.blocks.ops().collect();
    ops.sort_by_key(|&o| fd.op(o).alive_key);
    ops
}

/// The varnodes in `VarnodeDefSet` order: inputs by address, then written ones by their op's
/// sequence number (free ones are left out).
fn def_order(fd: &Funcdata) -> Vec<VarnodeId> {
    let mut v: Vec<VarnodeId> = fd.loc_all().into_iter().filter(|&vn| !fd.vn(vn).is_free()).collect();
    v.sort_by_key(|&vn| {
        let x = fd.vn(vn);
        let seq = x.def.map_or((0, 0), |d| (fd.op(d).seq.addr, fd.op(d).seq.time));
        (x.is_written(), seq, x.space.index(), x.offset, x.size)
    });
    v
}

/// `FlowBlock::dominates`
fn dominates(fd: &Funcdata, dom: BlockId, mut sub: Option<BlockId>) -> bool {
    let index = fd.blocks.block(dom).index;
    while let Some(s) = sub {
        if index > fd.blocks.block(s).index {
            break;
        }
        if s == dom {
            return true;
        }
        sub = fd.blocks.block(s).idom;
    }
    false
}

// ---- merge tests ----

/// Port of `Merge::mergeTestRequired`: no structural reason forbids the merge.
fn test_required(fd: &mut Funcdata, hout: HighId, hin: HighId) -> Result<bool> {
    if hin == hout {
        return Ok(true);
    }
    let (tin, lin) = h_type(fd, hin);
    let (tout, lout) = h_type(fd, hout);
    if lin && lout && tin != tout {
        return Ok(false);
    }
    let tied = |fd: &Funcdata, h| h_is(fd, h, VnFlags::ADDRTIED);
    let (pin, pout) = (h_is(fd, hin, VnFlags::PERSIST), h_is(fd, hout, VnFlags::PERSIST));
    if tied(fd, hout) && tied(fd, hin) {
        let (a, b) = (tied_varnode(fd, hin)?, tied_varnode(fd, hout)?);
        if (fd.vn(a).space, fd.vn(a).offset) != (fd.vn(b).space, fd.vn(b).offset) {
            return Ok(false);
        }
    }
    for (x, y, py) in [(hin, hout, pout), (hout, hin, pin)] {
        if h_is(fd, x, VnFlags::INPUT) {
            if py || (tied(fd, y) && !tied(fd, x)) {
                return Ok(false);
            }
        } else if h_extra_out(fd, x) {
            return Ok(false);
        }
    }
    // the symbols (`HighVariable::getSymbol`; the symbol offsets are equal: a piece of a locked
    // parameter fails in heritage)
    if let (Some((a, _)), Some((b, _))) = (high_symbol(fd, hin), high_symbol(fd, hout)) {
        if a != b {
            return Ok(false);
        }
    }
    Ok(true)
}

/// The local symbol a high maps to (`HighVariable::setSymbol`), as the index of a locked
/// parameter of the function, the only local symbols, and whether it is name-locked
/// (`ParameterSymbol::setTypeLock`: a parameter declared with a name). A stack parameter's
/// entry is address-tied, so every varnode exactly at it maps to it; a register parameter's
/// holds at the entry only, so its input varnode does (`SymbolEntry::inUse`). A `join`
/// parameter is not looked for.
fn high_symbol(fd: &Funcdata, h: HighId) -> Option<(usize, bool)> {
    use super::fspec::Storage;
    let l = fd.proto.locked.as_ref()?;
    let at = |vn: &VarnodeId| {
        let v = fd.vn(*vn);
        l.inputs.iter().position(|p| match p.storage {
            Some(Storage::Stack { offset, size }) => v.space == Space::Stack && v.offset == offset && v.size == size,
            Some(Storage::Space { space, offset, size }) => {
                v.has(VnFlags::LOCKED_INPUT) && v.space == Space::Sleigh(space) && v.offset == offset && v.size == size
            }
            _ => false,
        })
    };
    let i = fd.highs.get(h).inst.iter().find_map(at)?;
    Some((i, !l.inputs[i].name.is_empty()))
}

/// `Varnode::isIllegalInput() && !isIndirectOnly()` of the high's input.
fn illegal_input(fd: &Funcdata, h: HighId) -> Result<bool> {
    if !h_is(fd, h, VnFlags::INPUT) {
        return Ok(false);
    }
    let v = fd.vn(input_varnode(fd, h)?);
    Ok(!v.has(VnFlags::DIRECTWRITE) && !v.has(VnFlags::INDIRECTONLY))
}

/// Port of `Merge::mergeTestAdjacent`.
fn test_adjacent(fd: &mut Funcdata, hout: HighId, hin: HighId) -> Result<bool> {
    if !test_required(fd, hout, hin)? {
        return Ok(false);
    }
    // `isNameLock` on both: the name lock comes from the symbols (nothing sets
    // `Symbol::isIsolated`, tested below in the C++)
    if matches!((high_symbol(fd, hin), high_symbol(fd, hout)), (Some((_, true)), Some((_, true)))) {
        return Ok(false);
    }
    if h_type(fd, hout).0 != h_type(fd, hin).0 {
        return Ok(false);
    }
    Ok(!illegal_input(fd, hout)? && !illegal_input(fd, hin)?)
}

/// Port of `Merge::mergeTestSpeculative`.
fn test_speculative(fd: &mut Funcdata, hout: HighId, hin: HighId) -> Result<bool> {
    if !test_adjacent(fd, hout, hin)? {
        return Ok(false);
    }
    let bad = VnFlags::PERSIST.with(VnFlags::INPUT).with(VnFlags::ADDRTIED);
    Ok(!super::variable::hflags(fd, hout).has(bad) && !super::variable::hflags(fd, hin).has(bad))
}

/// Port of `Merge::mergeTestMust`.
fn test_must(fd: &Funcdata, vn: VarnodeId) -> Result<()> {
    if vn_has_cover(fd, vn) && !vn_implied(fd, vn) {
        return Ok(());
    }
    err("Cannot force merge of range")
}

/// Port of `Merge::mergeTestBasic`.
fn test_basic(fd: &Funcdata, vn: Option<VarnodeId>) -> bool {
    vn.is_some_and(|vn| vn_has_cover(fd, vn) && !vn_implied(fd, vn) && !fd.vn(vn).has(VnFlags::SPACEBASE))
}

/// Port of `Merge::merge`: merge unless the covers intersect.
fn merge(fd: &mut Funcdata, h1: HighId, h2: HighId, speculative: bool) -> Result<bool> {
    if h1 == h2 {
        return Ok(true);
    }
    if intersection(fd, h1, h2)? {
        return Ok(false);
    }
    high_merge(fd, h1, h2, true, speculative)?;
    update_internal_cover(fd, h1);
    Ok(true)
}

/// Port of `Merge::mergeTest`: `high` intersects none of `list`; it is added if so.
fn merge_test(fd: &mut Funcdata, h: HighId, list: &mut Vec<HighId>) -> Result<bool> {
    if !h_has_cover(fd, h) {
        return Ok(false);
    }
    for &a in list.iter() {
        if intersection(fd, a, h)? {
            return Ok(false);
        }
    }
    list.push(h);
    Ok(true)
}

/// `Merge::compareHighByBlock`
fn compare_high_by_block(fd: &Funcdata, a: HighId, b: HighId) -> bool {
    use std::cmp::Ordering;
    let ord = super::variable::h_cover(fd, a).compare_to(super::variable::h_cover(fd, b));
    if ord != Ordering::Equal {
        return ord == Ordering::Less;
    }
    let (v1, v2) = (fd.highs.get(a).inst[0], fd.highs.get(b).inst[0]);
    let addr = |v: VarnodeId| (fd.vn(v).space.index(), fd.vn(v).offset);
    if addr(v1) != addr(v2) {
        return addr(v1) < addr(v2);
    }
    match (fd.vn(v1).def, fd.vn(v2).def) {
        (None, d2) => d2.is_some(),
        (Some(_), None) => false,
        (Some(d1), Some(d2)) => fd.op(d1).seq.addr < fd.op(d2).seq.addr,
    }
}

/// Port of `Merge::mergeLinear`: speculative merges among highs of one data-type.
fn merge_linear(fd: &mut Funcdata, mut highs: Vec<HighId>) -> Result<()> {
    if highs.len() <= 1 {
        return Ok(());
    }
    for &h in &highs {
        update_high(fd, h);
    }
    super::stdsort::sort(&mut highs, |&a, &b| compare_high_by_block(fd, a, b));
    let mut stack: Vec<HighId> = Vec::new();
    for h in highs {
        let mut merged = false;
        for &out in &stack {
            if test_speculative(fd, out, h)? && merge(fd, out, h, true)? {
                merged = true;
                break;
            }
        }
        if !merged {
            stack.push(h);
        }
    }
    Ok(())
}

/// Port of `Merge::mergeRangeMust`: the varnodes must all merge.
fn merge_range_must(fd: &mut Funcdata, range: &[VarnodeId]) -> Result<()> {
    let Some((&first, rest)) = range.split_first() else { return Ok(()) };
    test_must(fd, first)?;
    let h = high(fd, first)?;
    for &vn in rest {
        let hv = high(fd, vn)?;
        if hv == h {
            continue;
        }
        test_must(fd, vn)?;
        if !merge(fd, h, hv, false)? {
            return err("Forced merge caused intersection");
        }
    }
    Ok(())
}

// ---- COPYs that split a variable ----

/// Port of `Merge::allocateCopyTrim`: a COPY of `in_vn` into a new temporary, not inserted.
fn allocate_copy_trim(fd: &mut Funcdata, in_vn: VarnodeId, addr: u64) -> Result<OpId> {
    let op = fd.new_op(Opcode::Copy, addr);
    let ct = super::infertypes::vn_type(fd, in_vn);
    check_resolution(fd, ct)?;
    let out = new_unique(fd, fd.vn(in_vn).size, ct)?;
    set_output(fd, op, out)?;
    set_input(fd, op, in_vn, 0)?;
    fd.highs.copy_trims.push(op);
    Ok(op)
}

/// The output of an op made here.
fn out_of(fd: &Funcdata, op: OpId) -> Result<VarnodeId> {
    fd.op(op).out.map_or_else(|| err("merge: op without output"), Ok)
}

/// Port of `Merge::snipReads`: the reads in `marked` go through a COPY made right after `vn`
/// is defined.
fn snip_reads(fd: &mut Funcdata, vn: VarnodeId, marked: &[OpId]) -> Result<()> {
    if marked.is_empty() {
        return Ok(());
    }
    let (bl, pc, after) = match fd.vn(vn).def {
        None => {
            let Some(&bl) = fd.blocks.list.first() else { return err("snipReads: no blocks") };
            (bl, fd.blocks.block(bl).start, None)
        }
        Some(def) => {
            let after = if fd.op(def).opc == Opcode::Indirect { indirect_effect(fd, def)? } else { def };
            let Some(bl) = fd.op(def).parent else { return err("snipReads: dead definition") };
            (bl, fd.op(def).seq.addr, Some(after))
        }
    };
    let copy = allocate_copy_trim(fd, vn, pc)?;
    match after {
        None => fd.op_insert_begin(copy, bl),
        Some(a) => fd.op_insert_after(copy, a)?,
    }
    let out = out_of(fd, copy)?;
    for &op in marked {
        if let Some(slot) = fd.slot_of(op, vn) {
            set_input(fd, op, out, slot)?;
        }
    }
    Ok(())
}

/// `Varnode::characterizeOverlap`: 0 disjoint, 1 partial, 2 the same storage.
fn characterize_overlap(fd: &Funcdata, a: VarnodeId, b: VarnodeId) -> i32 {
    let (x, y) = (fd.vn(a), fd.vn(b));
    if x.space != y.space {
        return 0;
    }
    if x.offset == y.offset {
        return if x.size == y.size { 2 } else { 1 };
    }
    let disjoint = if x.offset < y.offset {
        x.offset.wrapping_add(u64::from(x.size) - 1) < y.offset
    } else {
        y.offset.wrapping_add(u64::from(y.size) - 1) < x.offset
    };
    i32::from(!disjoint)
}

/// The varnode and block index of `BlockVarnode`, sorted by block.
type BlockSort = Vec<(i32, VarnodeId)>;

/// Port of `Merge::eliminateIntersect`: the reads of `vn` that another varnode at the same
/// storage is live across get a COPY of `vn` instead.
fn eliminate_intersect(fd: &mut Funcdata, vn: VarnodeId, blocksort: &BlockSort) -> Result<()> {
    let mut marked = Vec::new();
    for op in fd.vn(vn).descend.iter().copied().collect::<Vec<_>>() {
        let mut single = Cover::default();
        add_def_point(fd, &mut single, vn);
        add_ref_point(fd, &mut single, op, vn);
        if read_intersects(fd, vn, op, &single, blocksort)? {
            marked.push(op);
        }
    }
    snip_reads(fd, vn, &marked)
}

/// The inner loops of `eliminateIntersect` for one read `op` of `vn` with cover `single`.
fn read_intersects(fd: &Funcdata, vn: VarnodeId, op: OpId, single: &Cover, blocksort: &BlockSort) -> Result<bool> {
    for &blocknum in single.blocks.keys() {
        let mut slot = blocksort.partition_point(|&(i, _)| i < blocknum);
        while slot < blocksort.len() && blocksort[slot].0 == blocknum {
            let vn2 = blocksort[slot].1;
            slot += 1;
            if vn2 == vn {
                continue;
            }
            let boundtype = contain_varnode_def(fd, single, vn2);
            if boundtype == 0 {
                continue;
            }
            let overlap = characterize_overlap(fd, vn, vn2);
            if overlap == 0 {
                continue;
            }
            let off = fd.vn(vn).offset.wrapping_sub(fd.vn(vn2).offset) as i32;
            if overlap == 1 && partial_copy_shadow(fd, vn, vn2, off) {
                continue;
            }
            let (d1, d2) = (fd.vn(vn).def, fd.vn(vn2).def);
            if boundtype == 2 {
                match (d1, d2) {
                    // ponytail: two inputs at one point are ordered by pointer in the C++; by
                    // creation here
                    (None, None) if vn < vn2 => continue,
                    (Some(_), None) => continue,
                    (Some(a), Some(b)) if fd.op(b).order < fd.op(a).order => continue,
                    _ => {}
                }
            } else if boundtype == 3 {
                let Some(indop) = d2 else { continue };
                if !fd.vn(vn2).has(VnFlags::ADDRFORCE) || fd.op(indop).opc != Opcode::Indirect {
                    continue;
                }
                if op != indirect_effect(fd, indop)? {
                    continue;
                }
                let in0 = fd.input(indop, 0)?;
                let shadow =
                    if overlap != 1 { copy_shadow(fd, vn, in0) } else { partial_copy_shadow(fd, vn, in0, off) };
                if shadow {
                    continue;
                }
            }
            return Ok(true);
        }
    }
    Ok(false)
}

/// Port of `Merge::unifyAddress`.
fn unify_address(fd: &mut Funcdata, range: &[VarnodeId]) -> Result<()> {
    let isect: Vec<VarnodeId> = range.iter().copied().filter(|&v| !fd.vn(v).is_free()).collect();
    let mut blocksort: BlockSort =
        isect.iter().map(|&v| (fd.vn(v).def.map_or(0, |d| op_block_index(fd, d)), v)).collect();
    blocksort.sort_by_key(|&(i, _)| i);
    for vn in isect {
        eliminate_intersect(fd, vn, &blocksort)?;
    }
    Ok(())
}

/// The index after the run of varnodes at `loc[i]`'s address and size, free ones included or
/// not (`endLoc(size, addr, 0 | written)`).
fn end_loc(fd: &Funcdata, loc: &[VarnodeId], i: usize, with_free: bool) -> usize {
    let key = |v: VarnodeId| (fd.vn(v).space, fd.vn(v).offset, fd.vn(v).size);
    let k = key(loc[i]);
    let mut j = i;
    while j < loc.len() && key(loc[j]) == k && (with_free || !fd.vn(loc[j]).is_free()) {
        j += 1;
    }
    j
}

/// Port of `VarnodeBank::overlapLoc`: the runs of overlapping varnodes from `loc[i]` on.
fn overlap_loc(fd: &Funcdata, loc: &[VarnodeId], mut i: usize) -> (Vec<usize>, VnFlags) {
    let v = fd.vn(loc[i]);
    let (space, mut max_off, mut flags) = (v.space, v.offset.wrapping_add(u64::from(v.size) - 1), v.flags);
    let mut bounds = vec![i];
    i = end_loc(fd, loc, i, false);
    bounds.push(i);
    while i < loc.len() {
        let v = fd.vn(loc[i]);
        if v.space != space || v.offset > max_off {
            break;
        }
        if v.is_free() {
            i = end_loc(fd, loc, i, true);
            continue;
        }
        max_off = max_off.max(v.offset.wrapping_add(u64::from(v.size) - 1));
        flags.set(v.flags);
        bounds.push(i);
        i = end_loc(fd, loc, i, false);
        bounds.push(i);
    }
    bounds.push(i);
    (bounds, flags)
}

/// Whether merging works on the space (`IPTR_PROCESSOR` or `IPTR_SPACEBASE`).
fn is_tied_space(fd: &Funcdata, space: Space) -> bool {
    match space {
        Space::Sleigh(i) => i != 0 && Some(i) != fd.uniq,
        Space::Stack => true,
        Space::Iop | Space::Fspec | Space::Join => false,
    }
}

/// Port of `Merge::mergeAddrTied`: the varnodes at one address-tied storage merge.
fn merge_addr_tied(fd: &mut Funcdata) -> Result<()> {
    let loc = fd.loc_all();
    let mut i = 0;
    while i < loc.len() {
        let space = fd.vn(loc[i]).space;
        let send = i + loc[i..].iter().take_while(|&&v| fd.vn(v).space == space).count();
        if !is_tied_space(fd, space) {
            i = send;
            continue;
        }
        while i < send {
            if fd.vn(loc[i]).is_free() {
                i = end_loc(fd, &loc, i, true);
                continue;
            }
            let (bounds, flags) = overlap_loc(fd, &loc, i);
            let max = bounds.len() - 1;
            if flags.has(VnFlags::ADDRTIED) {
                unify_address(fd, &loc[i..bounds[max]])?;
                for k in (0..max).step_by(2) {
                    merge_range_must(fd, &loc[bounds[k]..bounds[k + 1]])?;
                }
                if max > 2 {
                    return err("mergeAddrTied: overlapping address-tied varnodes need VariablePiece, not ported");
                }
            }
            i = bounds[max];
        }
    }
    Ok(())
}

/// Port of `Merge::trimOpOutput`: the op writes a temporary, copied to its old output after it.
fn trim_op_output(fd: &mut Funcdata, op: OpId) -> Result<()> {
    let after = if fd.op(op).opc == Opcode::Indirect { indirect_effect(fd, op)? } else { op };
    let vn = out_of(fd, op)?;
    let ct = super::infertypes::vn_type(fd, vn);
    let copy = fd.new_op(Opcode::Copy, fd.op(op).seq.addr);
    check_resolution(fd, ct)?;
    let uniq = new_unique(fd, fd.vn(vn).size, ct)?;
    set_output(fd, op, uniq)?;
    set_output(fd, copy, vn)?;
    set_input(fd, copy, uniq, 0)?;
    fd.op_insert_after(copy, after)
}

/// Port of `Merge::trimOpInput`: the input in `slot` is read through a new COPY.
fn trim_op_input(fd: &mut Funcdata, op: OpId, slot: usize) -> Result<()> {
    let multi = fd.op(op).opc == Opcode::Multiequal;
    let pred = match fd.op(op).parent {
        Some(bl) if multi => fd.blocks.block(bl).ins.get(slot).map(|e| e.point),
        _ => None,
    };
    let pc = match pred {
        Some(bb) => fd.blocks.block(bb).stop,
        None if multi => return err("trimOpInput: MULTIEQUAL without the block"),
        None => fd.op(op).seq.addr,
    };
    let vn = fd.input(op, slot)?;
    let copy = allocate_copy_trim(fd, vn, pc)?;
    set_input(fd, op, out_of(fd, copy)?, slot)?;
    match pred {
        Some(bb) => fd.op_insert_end(copy, bb),
        None => fd.op_insert_before(copy, op)?,
    }
    Ok(())
}

/// The high of input `i` of `op`.
fn in_high(fd: &mut Funcdata, op: OpId, i: usize) -> Result<HighId> {
    let vn = fd.input(op, i)?;
    high(fd, vn)
}

/// The inputs `0..max` of `op` and its output merge without intersecting (`mergeTest` loop).
fn all_mergeable(fd: &mut Funcdata, op: OpId, max: usize) -> Result<bool> {
    let mut list = Vec::new();
    let out = high(fd, out_of(fd, op)?)?;
    merge_test(fd, out, &mut list)?;
    for i in 0..max {
        let h = in_high(fd, op, i)?;
        if !merge_test(fd, h, &mut list)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Port of `Merge::mergeOp`: a MULTIEQUAL's (or INDIRECT's) inputs and output merge, with
/// COPYs trimmed in where they cannot.
fn merge_op(fd: &mut Funcdata, op: OpId) -> Result<()> {
    let max = if fd.op(op).opc == Opcode::Indirect { 1 } else { fd.op(op).ins.len() };
    let hout = high(fd, out_of(fd, op)?)?;
    for i in 0..max {
        let hin = in_high(fd, op, i)?;
        if !test_required(fd, hout, hin)? {
            trim_op_input(fd, op, i)?;
            continue;
        }
        for j in 0..i {
            let hj = in_high(fd, op, j)?;
            if !test_required(fd, hj, hin)? {
                trim_op_input(fd, op, i)?;
                break;
            }
        }
    }
    if !all_mergeable(fd, op, max)? {
        let mut next = 0;
        while next < max {
            trim_op_input(fd, op, next)?;
            if all_mergeable(fd, op, max)? {
                break;
            }
            next += 1;
        }
        if next == max {
            trim_op_output(fd, op)?;
        }
    }
    for i in 0..max {
        let hout = high(fd, out_of(fd, op)?)?;
        let hin = in_high(fd, op, i)?;
        if !test_required(fd, hout, hin)? {
            return err("Non-cover related merge restriction violated, despite trims");
        }
        if !merge(fd, hout, hin, false)? {
            let s = fd.op(op).seq;
            return err(format!("Unable to force merge of op at {:#x}:{}", s.addr, s.time));
        }
    }
    Ok(())
}

/// Port of `Merge::collectInputs`: the reads of `high` by `op` and the INDIRECTs before it.
fn collect_inputs(fd: &mut Funcdata, h: HighId, mut op: OpId) -> Result<Vec<(OpId, usize)>> {
    let mut res = Vec::new();
    loop {
        for (i, vn) in fd.op(op).ins.clone().into_iter().enumerate() {
            if fd.vn(vn).is_annotation() {
                continue;
            }
            if high(fd, vn)? == h {
                res.push((op, i));
            }
        }
        match fd.previous_op(op) {
            Some(p) if fd.op(p).opc == Opcode::Indirect => op = p,
            _ => return Ok(res),
        }
    }
}

/// Port of `Merge::snipOutputInterference`.
fn snip_output_interference(fd: &mut Funcdata, indop: OpId) -> Result<bool> {
    let op = indirect_effect(fd, indop)?;
    let hout = high(fd, out_of(fd, indop)?)?;
    let mut correctable = collect_inputs(fd, hout, op)?;
    if correctable.is_empty() {
        return Ok(false);
    }
    // ponytail: PcodeOpNode::compareByHigh orders by HighVariable pointer; HighIds count
    // creation, which is allocation order
    let mut keyed = Vec::with_capacity(correctable.len());
    for &(o, s) in &correctable {
        keyed.push((in_high(fd, o, s)?, o, s));
    }
    super::stdsort::sort(&mut keyed, |a, b| a.0 < b.0);
    correctable = keyed.iter().map(|&(_, o, s)| (o, s)).collect();
    let mut snip: Option<(OpId, HighId)> = None;
    for (insert, slot) in correctable {
        let vn = fd.input(insert, slot)?;
        let h = high(fd, vn)?;
        let copy = match snip {
            Some((c, cur)) if cur == h => c,
            _ => {
                let c = allocate_copy_trim(fd, vn, fd.op(insert).seq.addr)?;
                fd.op_insert_before(c, insert)?;
                snip = Some((c, h));
                c
            }
        };
        set_input(fd, insert, out_of(fd, copy)?, slot)?;
    }
    Ok(true)
}

/// The required-then-actual merge of an INDIRECT's input into its output.
fn try_indirect(fd: &mut Funcdata, indop: OpId) -> Result<bool> {
    let hout = high(fd, out_of(fd, indop)?)?;
    let hin = in_high(fd, indop, 0)?;
    Ok(test_required(fd, hout, hin)? && merge(fd, hin, hout, false)?)
}

/// Port of `Merge::mergeIndirect`.
fn merge_indirect(fd: &mut Funcdata, indop: OpId) -> Result<()> {
    let out = out_of(fd, indop)?;
    if !fd.vn(out).has(VnFlags::ADDRFORCE) {
        return merge_op(fd, indop);
    }
    if try_indirect(fd, indop)? {
        return Ok(());
    }
    if snip_output_interference(fd, indop)? && try_indirect(fd, indop)? {
        return Ok(());
    }
    let in0 = fd.input(indop, 0)?;
    let copy = allocate_copy_trim(fd, in0, fd.op(indop).seq.addr)?;
    set_input(fd, indop, out_of(fd, copy)?, 0)?;
    fd.op_insert_before(copy, indop)?;
    if !try_indirect(fd, indop)? {
        return err("Unable to merge address forced indirect");
    }
    Ok(())
}

/// Port of `Merge::mergeMarker`.
fn merge_marker(fd: &mut Funcdata) -> Result<()> {
    for op in alive_ops(fd) {
        let o = fd.op(op);
        if !o.is_marker() || o.flags.has(OpFlags::INDIRECT_CREATION) {
            continue;
        }
        if o.opc == Opcode::Indirect {
            merge_indirect(fd, op)?;
        } else {
            merge_op(fd, op)?;
        }
    }
    Ok(())
}

/// Port of `Merge::mergeOpcode`: inputs and output of every op with opcode `opc`, in block order.
fn merge_opcode(fd: &mut Funcdata, opc: Opcode) -> Result<()> {
    for bl in fd.blocks.list.clone() {
        for op in fd.blocks.block(bl).ops.clone() {
            if fd.op(op).opc != opc || !test_basic(fd, fd.op(op).out) {
                continue;
            }
            let out = out_of(fd, op)?;
            for vn2 in fd.op(op).ins.clone() {
                if !test_basic(fd, Some(vn2)) {
                    continue;
                }
                let (h1, h2) = (high(fd, out)?, high(fd, vn2)?);
                if test_required(fd, h1, h2)? {
                    merge(fd, h1, h2, false)?;
                }
            }
        }
    }
    Ok(())
}

/// Port of `Merge::mergeByDatatype` over every varnode.
fn merge_by_datatype(fd: &mut Funcdata) -> Result<()> {
    let mut list: Vec<HighId> = Vec::new();
    let mut seen = HashSet::new();
    for vn in fd.loc_all() {
        if fd.vn(vn).is_free() {
            continue;
        }
        let h = high(fd, vn)?;
        if seen.contains(&h) || !test_basic(fd, Some(vn)) {
            continue;
        }
        seen.insert(h);
        list.push(h);
    }
    while let Some(&first) = list.first() {
        let ct = h_type(fd, first).0;
        let mut same = Vec::new();
        let mut rest = Vec::new();
        for h in list {
            if h_type(fd, h).0 == ct {
                same.push(h);
            } else {
                rest.push(h);
            }
        }
        list = rest;
        merge_linear(fd, same)?;
    }
    Ok(())
}

/// Port of `Merge::mergeAdjacent`: an op's output and inputs of the same local type.
fn merge_adjacent(fd: &mut Funcdata) -> Result<()> {
    for op in alive_ops(fd) {
        if fd.op(op).is_call() || !test_basic(fd, fd.op(op).out) {
            continue;
        }
        let vn1 = out_of(fd, op)?;
        let hout = high(fd, vn1)?;
        let ct = super::infertypes::output_local(fd, op)?;
        for i in 0..fd.op(op).ins.len() {
            if ct != super::infertypes::input_local(fd, op, i) {
                continue;
            }
            let vn2 = fd.input(op, i)?;
            let v2 = fd.vn(vn2);
            if !test_basic(fd, Some(vn2)) || fd.vn(vn1).size != v2.size || (v2.def.is_none() && !v2.is_input()) {
                continue;
            }
            let hin = high(fd, vn2)?;
            if test_adjacent(fd, hout, hin)? && !intersection(fd, hin, hout)? {
                merge(fd, hout, hin, true)?;
            }
        }
    }
    Ok(())
}

// ---- hiding shadows and redundant COPYs ----

/// `Merge::findSingleCopy`: members written by a COPY from another high.
fn find_single_copy(fd: &mut Funcdata, h: HighId) -> Result<Vec<Option<VarnodeId>>> {
    let mut res = Vec::new();
    for vn in fd.highs.get(h).inst.clone() {
        let Some(def) = fd.vn(vn).def else { continue };
        if fd.op(def).opc != Opcode::Copy || in_high(fd, def, 0)? == h {
            continue;
        }
        res.push(Some(vn));
    }
    Ok(res)
}

/// Port of `Merge::hideShadows`: of two COPYs of one value into the high, the later reads the
/// earlier.
fn hide_shadows(fd: &mut Funcdata, h: HighId) -> Result<bool> {
    let mut list = find_single_copy(fd, h)?;
    let mut res = false;
    for i in 0..list.len().saturating_sub(1) {
        let Some(vn1) = list[i] else { continue };
        for item in list[i + 1..].iter_mut() {
            let Some(vn2) = *item else { continue };
            if !copy_shadow(fd, vn1, vn2) {
                continue;
            }
            let (d1, d2) = (fd.vn(vn1).def, fd.vn(vn2).def);
            let (Some(d1), Some(d2)) = (d1, d2) else { continue };
            let c2 = vn_cover(fd, vn2);
            if contain_varnode_def(fd, &c2, vn1) == 1 {
                set_input(fd, d1, vn2, 0)?;
                res = true;
                break;
            }
            let c1 = vn_cover(fd, vn1);
            if contain_varnode_def(fd, &c1, vn2) == 1 {
                set_input(fd, d2, vn1, 0)?;
                *item = None;
                res = true;
            }
        }
    }
    Ok(res)
}

/// `Merge::compareCopyByInVarnode`
fn compare_copy_by_in(fd: &Funcdata, a: OpId, b: OpId) -> bool {
    let (i1, i2) = (fd.op(a).ins[0], fd.op(b).ins[0]);
    if i1 != i2 {
        return i1 < i2;
    }
    let (b1, b2) = (op_block_index(fd, a), op_block_index(fd, b));
    if b1 != b2 {
        return b1 < b2;
    }
    fd.op(a).order < fd.op(b).order
}

/// Port of `Merge::findAllIntoCopies`.
fn find_all_into_copies(fd: &mut Funcdata, h: HighId, temps: bool) -> Result<Vec<OpId>> {
    let mut res = Vec::new();
    for vn in fd.highs.get(h).inst.clone() {
        let Some(op) = fd.vn(vn).def else { continue };
        if fd.op(op).opc != Opcode::Copy || in_high(fd, op, 0)? == h {
            continue;
        }
        if temps && !super::variable::is_internal(fd, fd.vn(vn).space) {
            continue;
        }
        res.push(op);
    }
    super::stdsort::sort(&mut res, |&a, &b| compare_copy_by_in(fd, a, b));
    Ok(res)
}

/// The runs of COPYs with the same input in a sorted list, as `(start, len)` with len > 1.
fn copy_groups(fd: &Funcdata, copies: &[OpId]) -> Vec<(usize, usize)> {
    let mut res = Vec::new();
    let mut pos = 0;
    while pos < copies.len() {
        let inv = fd.op(copies[pos]).ins[0];
        let sz = copies[pos..].iter().take_while(|&&c| fd.op(c).ins[0] == inv).count();
        if sz > 1 {
            res.push((pos, sz));
        }
        pos += sz;
    }
    res
}

/// Port of `Merge::buildDominantCopy`: COPYs of one value into `high` are replaced by one COPY
/// in the block dominating them all, where that does not intersect the rest of the high.
fn build_dominant_copy(fd: &mut Funcdata, h: HighId, copy: &[OpId]) -> Result<()> {
    let parents: Vec<BlockId> = copy.iter().filter_map(|&c| fd.op(c).parent).collect();
    let Some(mut dom_bl) = parents.first().copied() else { return err("buildDominantCopy: dead COPY") };
    for &b in &parents[1..] {
        dom_bl = fd
            .find_common_block(dom_bl, b)
            .ok_or_else(|| super::LowlevelError("buildDominantCopy: no common dominator".into()))?;
    }
    let mut dom_copy = copy[0];
    let root = fd.input(dom_copy, 0)?;
    let mut dom_vn = out_of(fd, dom_copy)?;
    let is_new = fd.op(dom_copy).parent != Some(dom_bl);
    if is_new {
        dom_copy = fd.new_op(Opcode::Copy, fd.blocks.block(dom_bl).stop);
        let ct = super::infertypes::vn_type(fd, root);
        check_resolution(fd, ct)?;
        dom_vn = new_unique(fd, fd.vn(root).size, ct)?;
        set_output(fd, dom_copy, dom_vn)?;
        set_input(fd, dom_copy, root, 0)?;
        fd.op_insert_end(dom_copy, dom_bl);
    }
    let mut bcover = Cover::default();
    for vn in fd.highs.get(h).inst.clone() {
        if let Some(op) = fd.vn(vn).def {
            if fd.op(op).opc == Opcode::Copy && copy_shadow(fd, fd.input(op, 0)?, root) {
                continue;
            }
        }
        let c = vn_cover(fd, vn);
        bcover.merge(&c, &|o| op_uindex(fd, o));
    }
    let mut count = copy.len();
    let mut marked = HashSet::new();
    for &op in copy {
        if op == dom_copy {
            continue;
        }
        let out = out_of(fd, op)?;
        let mut acover = Cover::default();
        add_def_point(fd, &mut acover, dom_vn);
        for r in fd.vn(out).descend.iter().copied().collect::<Vec<_>>() {
            add_ref_point(fd, &mut acover, r, out);
        }
        if bcover.intersect(&acover, &|o| op_uindex(fd, o)) > 1 {
            count -= 1;
            marked.insert(op);
        }
    }
    if count <= 1 {
        marked.extend(copy.iter().copied());
        count = 0;
        if is_new {
            destroy(fd, dom_copy);
        }
    }
    for &op in copy {
        if marked.contains(&op) {
            continue;
        }
        let out = out_of(fd, op)?;
        if out != dom_vn {
            high_remove(fd, out);
            total_replace(fd, out, dom_vn)?;
            destroy(fd, op);
        }
    }
    if count > 0 && is_new {
        let hd = high(fd, dom_vn)?;
        high_merge(fd, h, hd, false, true)?;
    }
    Ok(())
}

/// Port of `Merge::checkCopyPair`: `sub_op` repeats `dom_op` with nothing in between writing
/// the high.
fn check_copy_pair(fd: &mut Funcdata, h: HighId, dom_op: OpId, sub_op: OpId) -> Result<bool> {
    let (Some(db), sb) = (fd.op(dom_op).parent, fd.op(sub_op).parent) else { return Ok(false) };
    if !dominates(fd, db, sb) {
        return Ok(false);
    }
    let mut range = Cover::default();
    add_def_point(fd, &mut range, out_of(fd, dom_op)?);
    add_ref_point(fd, &mut range, sub_op, fd.input(sub_op, 0)?);
    let inv = fd.input(dom_op, 0)?;
    let ui = |o| op_uindex(fd, o);
    for &vn in &fd.highs.get(h).inst {
        let Some(op) = fd.vn(vn).def else { continue };
        if fd.op(op).opc == Opcode::Copy && fd.input(op, 0)? == inv {
            continue;
        }
        if range.contain(op_block_index(fd, op), op, 1, &ui) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Port of `Merge::markRedundantCopies`.
fn mark_redundant_copies(fd: &mut Funcdata, h: HighId, copy: &[OpId]) -> Result<()> {
    for i in (1..copy.len()).rev() {
        let sub = copy[i];
        if fd.op(sub).is_dead() {
            continue;
        }
        for j in (0..i).rev() {
            let dom = copy[j];
            if !fd.op(dom).is_dead() && check_copy_pair(fd, h, dom, sub)? {
                fd.op_mut(sub).flags.set(OpFlags::NONPRINTING);
                break;
            }
        }
    }
    Ok(())
}

/// Port of `Merge::processCopyTrims` (`ActionDominantCopy`).
fn process_copy_trims(fd: &mut Funcdata) -> Result<()> {
    let mut multi = Vec::new();
    for op in std::mem::take(&mut fd.highs.copy_trims) {
        let h = high(fd, out_of(fd, op)?)?;
        let hv = fd.highs.get_mut(h);
        if !hv.copy_in1 {
            hv.copy_in1 = true;
            multi.push(h);
        } else {
            hv.copy_in2 = true;
        }
    }
    for h in multi {
        if fd.highs.get(h).copy_in2 {
            let copies = find_all_into_copies(fd, h, true)?;
            for (pos, sz) in copy_groups(fd, &copies) {
                build_dominant_copy(fd, h, &copies[pos..pos + sz])?;
            }
        }
        let hv = fd.highs.get_mut(h);
        hv.copy_in1 = false;
        hv.copy_in2 = false;
    }
    Ok(())
}

/// Port of `Merge::shadowedVarnode`.
fn shadowed_varnode(fd: &mut Funcdata, vn: VarnodeId) -> Result<bool> {
    let h = high(fd, vn)?;
    let c = vn_cover(fd, vn);
    for other in fd.highs.get(h).inst.clone() {
        if other != vn && c.intersect(&vn_cover(fd, other), &|o| op_uindex(fd, o)) == 2 {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Port of `Merge::markInternalCopies` (`ActionCopyMarker`). The PIECE and SUBPIECE cases need
/// `VariablePiece`s on all their varnodes, which never exist here.
fn mark_internal_copies(fd: &mut Funcdata) -> Result<()> {
    let mut multi = Vec::new();
    for op in alive_ops(fd) {
        if fd.op(op).opc != Opcode::Copy {
            continue;
        }
        let v1 = out_of(fd, op)?;
        let h1 = high(fd, v1)?;
        if h1 == in_high(fd, op, 0)? {
            fd.op_mut(op).flags.set(OpFlags::NONPRINTING);
            continue;
        }
        let hv = fd.highs.get_mut(h1);
        if !hv.copy_in1 {
            hv.copy_in1 = true;
            multi.push(h1);
        } else {
            hv.copy_in2 = true;
        }
        if fd.vn(v1).descend.is_empty() && shadowed_varnode(fd, v1)? {
            fd.op_mut(op).flags.set(OpFlags::NONPRINTING);
        }
    }
    for h in multi {
        if fd.highs.get(h).copy_in2 {
            let copies = find_all_into_copies(fd, h, false)?;
            for (pos, sz) in copy_groups(fd, &copies) {
                mark_redundant_copies(fd, h, &copies[pos..pos + sz])?;
            }
        }
        let hv = fd.highs.get_mut(h);
        hv.copy_in1 = false;
        hv.copy_in2 = false;
    }
    Ok(())
}

// ---- implied and explicit varnodes ----

/// Port of `Merge::inflateTest`: whether `high` grown by `a`'s cover would intersect `a`'s high.
fn inflate_test(fd: &mut Funcdata, a: VarnodeId, h: HighId) -> Result<bool> {
    let ahigh = high(fd, a)?;
    update_high(fd, h);
    let hc = super::variable::h_cover(fd, h).clone();
    for b in fd.highs.get(ahigh).inst.clone() {
        if copy_shadow(fd, b, a) {
            continue;
        }
        if vn_cover(fd, b).intersect(&hc, &|o| op_uindex(fd, o)) == 2 {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Port of `Merge::markImplied`.
fn mark_implied(fd: &mut Funcdata, vn: VarnodeId) {
    fd.vn_set(vn, VnFlags::IMPLIED);
    if let Some(op) = fd.vn(vn).def {
        for d in fd.op(op).ins.clone() {
            if vn_has_cover(fd, d) {
                vn_cover_dirty(fd, d);
            }
        }
    }
}

/// `ActionMarkImplied::isPossibleAliasStep`
fn possible_alias_step(fd: &Funcdata, vn1: VarnodeId, vn2: VarnodeId) -> bool {
    for (cur, other) in [(vn1, vn2), (vn2, vn1)] {
        let Some(op) = fd.vn(cur).def else { continue };
        let o = fd.op(op);
        if !matches!(o.opc, Opcode::IntAdd | Opcode::Ptrsub | Opcode::Ptradd | Opcode::IntXor) || o.ins[0] != other {
            continue;
        }
        if fd.vn(o.ins[1]).is_constant() {
            return false;
        }
    }
    true
}

/// Port of `ActionMarkImplied::isPossibleAlias`.
fn possible_alias(fd: &Funcdata, vn1: VarnodeId, vn2: VarnodeId, mut depth: i32) -> bool {
    use super::rules::func_equal as eq;
    if vn1 == vn2 {
        return true;
    }
    let (Some(op1), Some(op2)) = (fd.vn(vn1).def, fd.vn(vn2).def) else {
        if fd.vn(vn1).is_constant() && fd.vn(vn2).is_constant() {
            return fd.vn(vn1).offset == fd.vn(vn2).offset;
        }
        return possible_alias_step(fd, vn1, vn2);
    };
    if !possible_alias_step(fd, vn1, vn2) {
        return false;
    }
    let norm = |op: OpId| {
        let o = fd.op(op);
        match o.opc {
            Opcode::Ptrsub => (Opcode::IntAdd, 1u64),
            Opcode::Ptradd => (Opcode::IntAdd, fd.vn(o.ins[2]).offset as i32 as i64 as u64),
            opc => (opc, 1),
        }
    };
    let ((opc1, mult1), (opc2, mult2)) = (norm(op1), norm(op2));
    if opc1 != opc2 || depth == 0 {
        return true;
    }
    depth -= 1;
    let (a, b) = (&fd.op(op1).ins, &fd.op(op2).ins);
    match opc1 {
        Opcode::Copy | Opcode::IntZext | Opcode::IntSext | Opcode::Int2comp | Opcode::IntNegate => {
            possible_alias(fd, a[0], b[0], depth)
        }
        Opcode::IntAdd => {
            let (c1, c2) = (fd.vn(a[1]), fd.vn(b[1]));
            if c1.is_constant() && c2.is_constant() {
                if mult1.wrapping_mul(c1.offset) == mult2.wrapping_mul(c2.offset) {
                    return possible_alias(fd, a[0], b[0], depth);
                }
                return !eq(fd, a[0], b[0]);
            }
            if mult1 != mult2 {
                return true;
            }
            for (x, y, p, q) in [(0, 0, 1, 1), (1, 1, 0, 0), (0, 1, 1, 0), (1, 0, 0, 1)] {
                if eq(fd, a[x], b[y]) {
                    return possible_alias(fd, a[p], b[q], depth);
                }
            }
            true
        }
        _ => true,
    }
}

/// Port of `ActionMarkImplied::checkImpliedCover`: `vn` can be printed inside the expressions
/// reading it.
fn check_implied_cover(fd: &mut Funcdata, vn: VarnodeId) -> Result<bool> {
    let Some(op) = fd.vn(vn).def else { return err("checkImpliedCover: free varnode") };
    let opc = fd.op(op).opc;
    let cover = vn_cover(fd, vn);
    let ui = |o| op_uindex(fd, o);
    if opc == Opcode::Load {
        for st in fd.ops_created_with(Opcode::Store) {
            if fd.op(st).is_dead() || !cover.contain(op_block_index(fd, st), st, 2, &ui) {
                continue;
            }
            let (s, l) = (&fd.op(st).ins, &fd.op(op).ins);
            if fd.vn(s[0]).offset == fd.vn(l[0]).offset && possible_alias(fd, s[1], l[1], 2) {
                return Ok(false);
            }
        }
    }
    if fd.op(op).is_call() || opc == Opcode::Load {
        for &c in &fd.qlst {
            let call = fd.call(c).op;
            if cover.contain(op_block_index(fd, call), call, 2, &ui) {
                return Ok(false);
            }
        }
    }
    let h = high(fd, vn)?;
    for d in fd.op(op).ins.clone() {
        if !fd.vn(d).is_constant() && inflate_test(fd, d, h)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Whether `vn` is already marked explicit or implied.
fn decided(fd: &Funcdata, vn: VarnodeId) -> bool {
    fd.vn(vn).has(VnFlags::EXPLICIT) || fd.vn(vn).has(VnFlags::IMPLIED)
}

/// Port of `ActionMarkImplied::apply`: depth first from each undecided varnode through its
/// readers' outputs, each marked implied or explicit after its descendants.
pub(crate) fn mark_implied_action(fd: &mut Funcdata, _: &Arch) -> Result<i32> {
    let mut count = 0;
    for vn in fd.loc_all() {
        if fd.vn(vn).is_free() || decided(fd, vn) {
            continue;
        }
        let mut stack = vec![(vn, 0usize)];
        while let Some(&(cur, i)) = stack.last() {
            match fd.vn(cur).descend.get(i).copied() {
                None => {
                    count += 1;
                    if check_implied_cover(fd, cur)? {
                        mark_implied(fd, cur);
                    } else {
                        fd.vn_set(cur, VnFlags::EXPLICIT);
                    }
                    stack.pop();
                }
                Some(op) => {
                    if let Some(top) = stack.last_mut() {
                        top.1 += 1;
                    }
                    if let Some(out) = fd.op(op).out {
                        if !decided(fd, out) {
                            stack.push((out, 0));
                        }
                    }
                }
            }
        }
    }
    Ok(count)
}

/// `PieceNode::findRoot`: the PIECE output this address-tied varnode is the piece of, by its
/// storage, upward.
fn piece_root(fd: &Funcdata, mut vn: VarnodeId) -> Result<VarnodeId> {
    while fd.vn(vn).has(VnFlags::ADDRTIED) {
        let mut piece: Option<OpId> = None;
        for &op in fd.vn(vn).descend.iter() {
            let o = fd.op(op);
            if o.opc != Opcode::Piece {
                continue;
            }
            let Some(slot) = fd.slot_of(op, vn) else { continue };
            let Some(out) = o.out else { continue };
            let ov = fd.vn(out);
            if ov.space == Space::Join {
                return err("PieceNode::findRoot: join address, not ported");
            }
            // little endian: the most significant piece (slot 0) sits above the other
            let mut off = ov.offset;
            if slot == 0 {
                off = off.wrapping_add(u64::from(fd.vn(o.ins[1]).size));
            }
            if (ov.space, off) == (fd.vn(vn).space, fd.vn(vn).offset) {
                piece = match piece {
                    Some(p) if compare_order(fd, op, p) == 0 => Some(p),
                    _ => Some(op),
                };
            }
        }
        match piece.and_then(|p| fd.op(p).out) {
            Some(out) => vn = out,
            None => break,
        }
    }
    Ok(vn)
}

/// `PcodeOp::compareOrder` (the caller tests it as a boolean, as the C++ does).
fn compare_order(fd: &Funcdata, a: OpId, b: OpId) -> i32 {
    let (pa, pb) = (fd.op(a).parent, fd.op(b).parent);
    if pa == pb {
        return if fd.op(a).order < fd.op(b).order { -1 } else { 1 };
    }
    let (Some(x), Some(y)) = (pa, pb) else { return 0 };
    match fd.find_common_block(x, y) {
        Some(c) if c == x => -1,
        Some(c) if c == y => 1,
        _ => 0,
    }
}

/// `ActionMarkExplicit::baseExplicit`: -1 explicit, -2 explicit with special printing, else the
/// number of readers (it may be implied).
fn base_explicit(fd: &Funcdata, vn: VarnodeId, mut maxref: usize) -> Result<i32> {
    let v = fd.vn(vn);
    let Some(def) = v.def else { return Ok(-1) };
    let d = fd.op(def);
    if d.is_marker() {
        return Ok(-1);
    }
    if d.is_call() {
        return Ok(if d.opc == Opcode::New && d.ins.len() == 1 { -2 } else { -1 });
    }
    if fd.highs.of(vn).is_some_and(|h| fd.highs.get(h).inst.len() > 1) {
        return Ok(-1);
    }
    if v.has(VnFlags::ADDRTIED) {
        if d.opc == Opcode::Subpiece {
            let vin = fd.vn(d.ins[0]);
            if vin.has(VnFlags::ADDRTIED) {
                if v.space == Space::Join || vin.space == Space::Join {
                    return err("baseExplicit: join overlap not ported");
                }
                let over = super::varnode::overlap(v.space, v.offset, vin.space, vin.offset, vin.size, u64::MAX);
                if over.map(u64::from) == Some(fd.vn(d.ins[1]).offset) {
                    return Ok(-1);
                }
            }
        }
        let use_op = match v.descend[..] {
            [op] => op,
            _ => return Ok(-1),
        };
        match fd.op(use_op).opc {
            Opcode::IntZext => {
                let out = fd.op(use_op).out.map(|o| fd.vn(o));
                let contains = out.is_some_and(|o| {
                    o.has(VnFlags::ADDRTIED)
                        && o.space == v.space
                        && v.offset >= o.offset
                        && v.offset.wrapping_add(u64::from(v.size)) <= o.offset.wrapping_add(u64::from(o.size))
                });
                if !contains {
                    return Ok(-1);
                }
            }
            // proto-partial roots (`isPartialRoot`) are never made here
            Opcode::Piece if piece_root(fd, vn)? == vn => return Ok(-1),
            Opcode::Piece => {}
            _ => return Ok(-1),
        }
    }
    if v.descend.is_empty() {
        return Ok(-1);
    }
    if d.opc == Opcode::Insert {
        let store = d.out.and_then(|o| match fd.vn(o).descend[..] {
            [op] => Some(op),
            _ => None,
        });
        if store.is_none_or(|s| fd.op(s).opc != Opcode::Store) {
            return Ok(-1);
        }
    }
    if d.opc == Opcode::Ptrsub {
        let base = fd.vn(d.ins[0]);
        if base.has(VnFlags::SPACEBASE) && (base.is_constant() || base.is_input()) {
            maxref = 1_000_000;
        }
    }
    let mut count = 0;
    for &op in v.descend.iter() {
        if fd.op(op).is_marker() {
            return Ok(-1);
        }
        count += 1;
        if count > maxref {
            return Ok(-1);
        }
    }
    Ok(count as i32)
}

/// Port of `ActionMarkExplicit::multipleInteraction`: of a boolean, extension or PTRADD and an
/// input both with several readers, the input is made explicit.
fn multiple_interaction(fd: &mut Funcdata, list: &[VarnodeId], marks: &mut HashSet<VarnodeId>) -> i32 {
    let mut purge = Vec::new();
    for &vn in list {
        let Some(op) = fd.vn(vn).def else { continue };
        let opc = fd.op(op).opc;
        if !(super::opcode::is_bool_output(opc) || matches!(opc, Opcode::IntZext | Opcode::IntSext | Opcode::Ptradd)) {
            continue;
        }
        for &top in fd.op(op).ins.iter().take(2) {
            if !marks.contains(&top) {
                continue;
            }
            let topopc = match fd.vn(top).def {
                Some(d) if super::opcode::is_bool_output(fd.op(d).opc) => continue,
                Some(d) => fd.op(d).opc,
                None => Opcode::Copy,
            };
            if opc != Opcode::Ptradd || topopc == Opcode::Ptradd {
                purge.push(top);
            }
        }
    }
    for &vn in &purge {
        fd.vn_set(vn, VnFlags::EXPLICIT);
        fd.vn_clear(vn, VnFlags::IMPLIED);
        marks.remove(&vn);
    }
    purge.len() as i32
}

/// Port of `ActionMarkExplicit::processMultiplier`: an expression with several readers and
/// more than `max` terms is made explicit.
fn process_multiplier(fd: &mut Funcdata, vn: VarnodeId, max: i32, marks: &HashSet<VarnodeId>) {
    // (varnode, next slot, end slot): OpStackElement
    let element = |fd: &Funcdata, v: VarnodeId| -> (VarnodeId, usize, usize) {
        match fd.vn(v).def.map(|d| fd.op(d)) {
            None => (v, 0, 0),
            Some(o) => match o.opc {
                Opcode::Load => (v, 1, 2),
                Opcode::Ptradd => (v, 0, 1),
                Opcode::Segmentop => (v, 2, 3),
                _ => (v, 0, o.ins.len()),
            },
        }
    };
    let mut stack = vec![element(fd, vn)];
    let mut finalcount = 0;
    while let Some(&(cur, slot, back)) = stack.last() {
        let term = fd.vn(cur).has(VnFlags::EXPLICIT) || !fd.vn(cur).is_written();
        if term || back <= slot {
            if term && !fd.vn(cur).has(VnFlags::SPACEBASE) {
                finalcount += 1;
            }
            if finalcount > max {
                fd.vn_set(vn, VnFlags::EXPLICIT);
                fd.vn_clear(vn, VnFlags::IMPLIED);
                return;
            }
            stack.pop();
        } else {
            let Some(def) = fd.vn(cur).def else { return };
            let newvn = fd.op(def).ins[slot];
            if let Some(top) = stack.last_mut() {
                top.1 += 1;
            }
            if marks.contains(&newvn) {
                fd.vn_set(vn, VnFlags::EXPLICIT);
                fd.vn_clear(vn, VnFlags::IMPLIED);
            }
            stack.push(element(fd, newvn));
        }
    }
}

/// Port of `ActionMarkExplicit::checkNewToConstructor`.
fn check_new_to_constructor(fd: &mut Funcdata, vn: VarnodeId) {
    let Some(op) = fd.vn(vn).def else { return };
    let bb = fd.op(op).parent;
    let mut first: Option<OpId> = None;
    for &cur in fd.vn(vn).descend.iter() {
        if fd.op(cur).parent != bb {
            continue;
        }
        match first {
            None => first = Some(cur),
            Some(f) if fd.op(cur).order < fd.op(f).order => first = Some(cur),
            Some(f) if fd.op(cur).opc == Opcode::Callind => {
                let ptr = fd.op(cur).ins[0];
                if fd.vn(ptr).def == Some(f) {
                    first = Some(cur);
                }
            }
            _ => {}
        }
    }
    let Some(f) = first else { return };
    let o = fd.op(f);
    if !o.is_call() || o.out.is_some() || o.ins.len() < 2 || o.ins[1] != vn {
        return;
    }
    fd.op_mut(f).flags.set(OpFlags::SPECIAL_PRINT);
    fd.op_mut(op).flags.set(OpFlags::NONPRINTING);
}

/// `Architecture::max_implied_ref` and `max_term_duplication` (their defaults).
const MAX_IMPLIED_REF: usize = 2;
const MAX_TERM_DUPLICATION: i32 = 2;

/// Port of `ActionMarkExplicit::apply`.
pub(crate) fn mark_explicit(fd: &mut Funcdata, _: &Arch) -> Result<i32> {
    let mut count = 0;
    let mut multi = Vec::new();
    let mut marks = HashSet::new();
    for vn in def_order(fd) {
        let desc = base_explicit(fd, vn, MAX_IMPLIED_REF)?;
        if desc < 0 {
            fd.vn_set(vn, VnFlags::EXPLICIT);
            count += 1;
            if desc < -1 {
                check_new_to_constructor(fd, vn);
            }
        } else if desc > 1 {
            marks.insert(vn);
            multi.push(vn);
        }
    }
    count += multiple_interaction(fd, &multi, &mut marks);
    for &vn in &multi {
        if marks.contains(&vn) {
            process_multiplier(fd, vn, MAX_TERM_DUPLICATION, &marks);
        }
    }
    Ok(count)
}

/// Port of `Funcdata::checkIndirectUse`: the input is only read by INDIRECTs (through
/// MULTIEQUALs and STORE INDIRECTs).
fn check_indirect_use(fd: &Funcdata, vn: VarnodeId) -> bool {
    let mut list = vec![vn];
    let mut seen: HashSet<VarnodeId> = HashSet::from([vn]);
    let mut i = 0;
    while i < list.len() {
        let cur = list[i];
        i += 1;
        for &op in fd.vn(cur).descend.iter() {
            let o = fd.op(op);
            let follow = match o.opc {
                Opcode::Indirect => o.flags.has(OpFlags::INDIRECT_STORE),
                Opcode::Multiequal => true,
                _ => return false,
            };
            if let Some(out) = o.out.filter(|_| follow) {
                if seen.insert(out) {
                    list.push(out);
                }
            }
        }
    }
    true
}

// ---- the actions ----

/// `ActionAssignHigh`
pub(crate) fn assign_high_action(fd: &mut Funcdata, arch: &Arch) -> Result<i32> {
    // the C++ gives a ram varnode its global symbol's type when it is made
    // (`setSymbolProperties`); ghidra-rs applies it before each inference pass, which do not run
    // with `typerecovery` off, so once more here, before anything merging reads types
    super::infertypes::symbol_types(fd, arch);
    set_high_level(fd);
    Ok(0)
}

/// `ActionMergeRequired`: `mergeAddrTied`, `groupPartials`, `mergeMarker`.
pub(crate) fn merge_required(fd: &mut Funcdata, _: &Arch) -> Result<i32> {
    merge_addr_tied(fd)?;
    group_partials(fd)?;
    merge_marker(fd)?;
    Ok(0)
}

/// `Merge::registerProtoPartialRoot`: for the rules that make proto-partial PIECEs.
#[allow(dead_code)] // ponytail: its callers, SplitDatatype::buildOutConcats (RuleSplitCopy/Load/Store) and RulePieceStructure, are not ported
pub(crate) fn register_proto_partial_root(fd: &mut Funcdata, piece: OpId) {
    fd.highs.proto_partial.push(piece);
}

/// `Merge::groupPartials`: grouping the pieces needs `VariablePiece`, not ported, so a live
/// registered root fails loudly.
fn group_partials(fd: &Funcdata) -> Result<()> {
    if fd.highs.proto_partial.iter().any(|&op| !fd.op(op).is_dead()) {
        return err("groupPartials: proto-partial pieces need VariablePiece, not ported");
    }
    Ok(())
}

/// `ActionMergeMultiEntry`: the local scope holds no symbols (`localrecovery` is not ported),
/// so none has several entries.
pub(crate) fn merge_multi_entry(_: &mut Funcdata, _: &Arch) -> Result<i32> {
    Ok(0)
}

/// `ActionMergeCopy`
pub(crate) fn merge_copy(fd: &mut Funcdata, _: &Arch) -> Result<i32> {
    merge_opcode(fd, Opcode::Copy)?;
    Ok(0)
}

/// `ActionDominantCopy`
pub(crate) fn dominant_copy(fd: &mut Funcdata, _: &Arch) -> Result<i32> {
    process_copy_trims(fd)?;
    Ok(0)
}

/// `ActionMarkIndirectOnly` (`Funcdata::markIndirectOnly`).
pub(crate) fn mark_indirect_only(fd: &mut Funcdata, _: &Arch) -> Result<i32> {
    for vn in fd.loc_all() {
        let v = fd.vn(vn);
        if v.is_input() && !v.has(VnFlags::DIRECTWRITE) && check_indirect_use(fd, vn) {
            fd.vn_set(vn, VnFlags::INDIRECTONLY);
        }
    }
    Ok(0)
}

/// `ActionMergeAdjacent`
pub(crate) fn merge_adjacent_action(fd: &mut Funcdata, _: &Arch) -> Result<i32> {
    merge_adjacent(fd)?;
    Ok(0)
}

/// `ActionMergeType`
pub(crate) fn merge_type(fd: &mut Funcdata, _: &Arch) -> Result<i32> {
    merge_by_datatype(fd)?;
    Ok(0)
}

/// `ActionHideShadow`: each high once, in `VarnodeDefSet` order of its members.
pub(crate) fn hide_shadow(fd: &mut Funcdata, _: &Arch) -> Result<i32> {
    let mut done = HashSet::new();
    let mut count = 0;
    for vn in def_order(fd) {
        let h = high(fd, vn)?;
        if done.insert(h) && hide_shadows(fd, h)? {
            count += 1;
        }
    }
    Ok(count)
}

/// `ActionCopyMarker`: `markInternalCopies` (`markPurePaddingCopies` has no join padding
/// records: none are made).
pub(crate) fn copy_marker(fd: &mut Funcdata, _: &Arch) -> Result<i32> {
    mark_internal_copies(fd)?;
    Ok(0)
}
