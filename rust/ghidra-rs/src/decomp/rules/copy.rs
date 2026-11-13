//! The rules on copies and data flow: `RuleEarlyRemoval`, `RuleSelectCse`, `RulePullsubMulti`,
//! `RulePushMulti`, `RuleMultiCollapse`, `RulePropagateCopy` (ruleaction.cc).

use super::*;

/// `Funcdata::deadRemovalAllowedSeen` for the space of `vn` (only spaces that do dead code
/// elimination are checked: `AddrSpace::doesDeadcode`).
pub(super) fn dead_removal_allowed_seen(fd: &mut Funcdata, arch: &Arch, vn: VarnodeId) -> bool {
    match fd.vn(vn).space {
        Space::Sleigh(s) if s != 0 && arch.sleigh.spaces[s as usize].delay.is_some() => {
            let ok = fd.heritage.dead_removal_allowed(arch, s);
            if ok {
                fd.heritage.seen_dead_code(s);
            }
            ok
        }
        // the stack's dead-code delay is its heritage delay, 1. `seenDeadCode` is not recorded:
        // ghidra-rs keeps that flag per SLEIGH space, and nothing reads it for the stack (the
        // stack's heritage after dead-code removal is not checked yet)
        Space::Stack => fd.heritage.pass() > 1,
        _ => true,
    }
}

/// Port of `RuleEarlyRemoval`.
pub(super) fn early_removal(fd: &mut Funcdata, op: OpId, arch: &Arch) -> Result<i32> {
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

/// Port of `RuleSelectCse`.
pub(super) fn select_cse(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let vn = inp(fd, op, 0)?;
    let opc = fd.op(op).opc;
    let list: Vec<(u32, OpId)> = fd
        .vn(vn)
        .descend
        .iter()
        .filter(|&&o| fd.op(o).opc == opc)
        .map(|&o| (fd.cse_hash(o), o))
        .filter(|e| e.0 != 0)
        .collect();
    if list.len() <= 1 {
        return Ok(0);
    }
    Ok(i32::from(fd.cse_eliminate_list(list)?))
}

/// `RulePullsubMulti::minMaxUse`: the bytes of `vn` its readers use.
pub(super) fn min_max_use(fd: &Funcdata, vn: VarnodeId) -> (i32, i32) {
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
pub(super) fn replace_descendants(fd: &mut Funcdata, orig: VarnodeId, newvn: VarnodeId, min: i32) -> Result<()> {
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
pub(super) fn acceptable_size(size: i32) -> bool {
    size != 0 && (size >= 8 || matches!(size, 1 | 2 | 4))
}

/// `RulePullsubMulti::findSubpiece`.
pub(super) fn find_subpiece(fd: &Funcdata, base: VarnodeId, outsize: u32, shift: u64) -> Option<VarnodeId> {
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
pub(super) fn build_subpiece(fd: &mut Funcdata, base: VarnodeId, outsize: u32, shift: u32) -> Result<VarnodeId> {
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
        let Some(pieces) = fd.joins.get(b.offset as usize).cloned() else {
            return err("pullsub: join varnode without a join record");
        };
        if pieces.len() > 1 {
            let mut skip = shift;
            for &(sp, off, size) in pieces.iter().rev() {
                if Space::Sleigh(sp) == CONST_SPACE {
                    return err("Join space padding is propagating");
                }
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
pub(super) fn pullsub_multi(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
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
pub(super) fn find_substitute(
    fd: &Funcdata,
    in1: VarnodeId,
    in2: VarnodeId,
    bb: BlockId,
    earliest: Option<OpId>,
) -> Option<OpId> {
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
pub(super) fn push_multi(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
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

/// Port of `RuleMultiCollapse`.
pub(super) fn multi_collapse(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
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

/// Port of `RulePropagateCopy`.
pub(super) fn propagate_copy(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
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
