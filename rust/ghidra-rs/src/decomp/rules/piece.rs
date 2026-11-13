//! The rules on concatenation: `RuleConcatShift`, `RuleConcatCommute`, `RuleConcatZext`,
//! `RuleConcatZero`, `RuleConcatLeftShift`, `RuleHumptyDumpty`, `RuleDumptyHump`,
//! `RuleHumptyOr`, `RulePiece2Zext`, `RulePiece2Sext`, `RulePiecePathology` (ruleaction.cc).

use super::*;

/// Port of `RuleConcatShift`: `concat(V,W) >> c` becomes an extension of `V` (shifted by the
/// rest) when the shift drops all of `W`.
pub(super) fn concat_shift(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let savn = inp(fd, op, 1)?;
    if !is_const(fd, savn) {
        return Ok(0);
    }
    let shiftin = inp(fd, op, 0)?;
    let Some(concat) = def_with(fd, shiftin, Piece) else { return Ok(0) };
    let leastsize = i64::from(fd.vn(inp(fd, concat, 1)?).size) * 8;
    let sa = int4(fd, savn);
    if sa < leastsize {
        return Ok(0);
    }
    let mainin = inp(fd, concat, 0)?;
    if fd.vn(mainin).is_free() {
        return Ok(0);
    }
    let sa = sa - leastsize;
    let extcode = if fd.op(op).opc == IntRight { IntZext } else { IntSext };
    if sa == 0 {
        fd.op_remove_input(op, 1);
        fd.op_set_opcode(op, extcode);
        fd.op_set_input(op, mainin, 0)?;
    } else {
        let extop = fd.new_op(extcode, fd.op(op).seq.addr);
        let newvn = uniq_out(fd, fd.vn(shiftin).size, extop)?;
        fd.op_set_input(extop, mainin, 0)?;
        fd.op_set_input(op, newvn, 0)?;
        let c = fd.new_constant(fd.vn(savn).size, sa as u64);
        fd.op_set_input(op, c, 1)?;
        fd.op_insert_before(extop, op)?;
    }
    Ok(1)
}

/// Port of `RuleConcatCommute`: a logical op with a constant on one side of a PIECE moves
/// after the PIECE.
pub(super) fn concat_commute(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let outsz = fd.vn(out(fd, op)?).size;
    if outsz > 8 {
        return Ok(0);
    }
    for i in 0..2 {
        let Some(logicop) = def(fd, inp(fd, op, i)?) else { continue };
        let opc = fd.op(logicop).opc;
        if !matches!(opc, IntOr | IntXor | IntAnd) {
            continue;
        }
        let cvn = inp(fd, logicop, 1)?;
        if !is_const(fd, cvn) {
            continue;
        }
        let (hi, lo) =
            if i == 0 { (inp(fd, logicop, 0)?, inp(fd, op, 1)?) } else { (inp(fd, op, 0)?, inp(fd, logicop, 0)?) };
        let (hisz, losz) = (fd.vn(hi).size, fd.vn(lo).size);
        let mut val = fd.vn(cvn).offset;
        if i == 0 {
            val = val.wrapping_shl(8 * losz);
        }
        if opc == IntAnd {
            val |= if i == 0 { calc_mask(losz) } else { calc_mask(hisz).wrapping_shl(8 * losz) };
        }
        if fd.vn(hi).is_free() || fd.vn(lo).is_free() {
            continue;
        }
        let newconcat = fd.new_op(Piece, fd.op(op).seq.addr);
        let newvn = uniq_out(fd, outsz, newconcat)?;
        fd.op_set_input(newconcat, hi, 0)?;
        fd.op_set_input(newconcat, lo, 1)?;
        fd.op_insert_before(newconcat, op)?;
        fd.op_set_opcode(op, opc);
        fd.op_set_input(op, newvn, 0)?;
        let c = fd.new_constant(outsz, val);
        fd.op_set_input(op, c, 1)?;
        return Ok(1);
    }
    Ok(0)
}

/// Port of `RuleConcatZext`: `concat(zext(V),W)` becomes `zext(concat(V,W))`.
pub(super) fn concat_zext(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let Some(zextop) = def_with(fd, inp(fd, op, 0)?, IntZext) else { return Ok(0) };
    let (hi, lo) = (inp(fd, zextop, 0)?, inp(fd, op, 1)?);
    if fd.vn(hi).is_free() || fd.vn(lo).is_free() {
        return Ok(0);
    }
    let newconcat = fd.new_op(Piece, fd.op(op).seq.addr);
    let newvn = uniq_out(fd, fd.vn(hi).size + fd.vn(lo).size, newconcat)?;
    fd.op_set_input(newconcat, hi, 0)?;
    fd.op_set_input(newconcat, lo, 1)?;
    fd.op_insert_before(newconcat, op)?;
    fd.op_remove_input(op, 1);
    fd.op_set_input(op, newvn, 0)?;
    fd.op_set_opcode(op, IntZext);
    Ok(1)
}

/// Port of `RuleConcatZero`: `concat(V,0)` becomes `zext(V) << c`.
pub(super) fn concat_zero(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let lo = inp(fd, op, 1)?;
    if !is_const(fd, lo) || fd.vn(lo).offset != 0 {
        return Ok(0);
    }
    let sa = 8 * fd.vn(lo).size;
    let highvn = inp(fd, op, 0)?;
    if is_const(fd, highvn) && fd.vn(highvn).offset == 0 {
        return Ok(0);
    }
    let newop = fd.new_op(IntZext, fd.op(op).seq.addr);
    let outvn = uniq_out(fd, fd.vn(out(fd, op)?).size, newop)?;
    fd.op_set_opcode(op, IntLeft);
    fd.op_set_input(op, outvn, 0)?;
    let c = fd.new_constant(4, u64::from(sa));
    fd.op_set_input(op, c, 1)?;
    fd.op_set_input(newop, highvn, 0)?;
    fd.op_insert_before(newop, op)?;
    Ok(1)
}

/// Port of `RuleConcatLeftShift`: `concat(V, zext(W) << c)` becomes `concat(concat(V,W), 0)`.
pub(super) fn concat_left_shift(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let Some(shiftop) = def_with(fd, inp(fd, op, 1)?, IntLeft) else { return Ok(0) };
    let savn = inp(fd, shiftop, 1)?;
    if !is_const(fd, savn) {
        return Ok(0);
    }
    let sa = int4(fd, savn);
    if sa & 7 != 0 {
        return Ok(0);
    }
    let tmpvn = inp(fd, shiftop, 0)?;
    let Some(zextop) = def_with(fd, tmpvn, IntZext) else { return Ok(0) };
    let b = inp(fd, zextop, 0)?;
    let vn1 = inp(fd, op, 0)?;
    if fd.vn(b).is_free() || fd.vn(vn1).is_free() {
        return Ok(0);
    }
    if sa / 8 + i64::from(fd.vn(b).size) != i64::from(fd.vn(tmpvn).size) {
        return Ok(0);
    }
    let newsize = fd.vn(vn1).size + fd.vn(b).size;
    let newop = fd.new_op(Piece, fd.op(op).seq.addr);
    let newout = uniq_out(fd, newsize, newop)?;
    fd.op_set_input(newop, vn1, 0)?;
    fd.op_set_input(newop, b, 1)?;
    fd.op_insert_before(newop, op)?;
    fd.op_set_input(op, newout, 0)?;
    let zero = fd.new_constant(fd.vn(out(fd, op)?).size - newsize, 0);
    fd.op_set_input(op, zero, 1)?;
    Ok(1)
}

/// Port of `RuleHumptyDumpty`: `concat(sub(V,c), sub(V,0))` becomes `V`, or one SUBPIECE when
/// the pieces are adjacent parts.
pub(super) fn humpty_dumpty(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let (vn1, vn2) = (inp(fd, op, 0)?, inp(fd, op, 1)?);
    let Some(sub1) = def_with(fd, vn1, Subpiece) else { return Ok(0) };
    let Some(sub2) = def_with(fd, vn2, Subpiece) else { return Ok(0) };
    let root = inp(fd, sub1, 0)?;
    if root != inp(fd, sub2, 0)? {
        return Ok(0);
    }
    let pos1 = fd.vn(inp(fd, sub1, 1)?).offset;
    let pos2vn = inp(fd, sub2, 1)?;
    let pos2 = fd.vn(pos2vn).offset;
    let (size1, size2) = (fd.vn(vn1).size, fd.vn(vn2).size);
    if pos1 != pos2.wrapping_add(u64::from(size2)) {
        return Ok(0);
    }
    if pos2 == 0 && size1 + size2 == fd.vn(root).size {
        fd.op_remove_input(op, 1);
        fd.op_set_input(op, root, 0)?;
        fd.op_set_opcode(op, Copy);
    } else {
        fd.op_set_input(op, root, 0)?;
        let c = fd.new_constant(fd.vn(pos2vn).size, pos2);
        fd.op_set_input(op, c, 1)?;
        fd.op_set_opcode(op, Subpiece);
    }
    Ok(1)
}

/// Port of `RuleDumptyHump`: a SUBPIECE of a PIECE that draws from one input reads that
/// input.
pub(super) fn dumpty_hump(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let Some(pieceop) = def_with(fd, inp(fd, op, 0)?, Piece) else { return Ok(0) };
    let mut offset = int4(fd, inp(fd, op, 1)?);
    let outsize = i64::from(fd.vn(out(fd, op)?).size);
    let (vn1, vn2) = (inp(fd, pieceop, 0)?, inp(fd, pieceop, 1)?);
    let size2 = i64::from(fd.vn(vn2).size);
    let vn = if offset < size2 {
        if offset + outsize > size2 {
            return Ok(0);
        }
        vn2
    } else {
        offset -= size2;
        vn1
    };
    if fd.vn(vn).is_free() && !is_const(fd, vn) {
        return Ok(0);
    }
    if offset == 0 && outsize == i64::from(fd.vn(vn).size) {
        fd.op_set_opcode(op, Copy);
        fd.op_remove_input(op, 1);
        fd.op_set_input(op, vn, 0)?;
    } else {
        fd.op_set_input(op, vn, 0)?;
        let c = fd.new_constant(4, offset as u64);
        fd.op_set_input(op, c, 1)?;
    }
    Ok(1)
}

/// Port of `RuleHumptyOr`: `(V & W) | (V & X)` becomes `V & (W | X)`.
pub(super) fn humpty_or(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let Some(and1) = def(fd, inp(fd, op, 0)?) else { return Ok(0) };
    let Some(and2) = def(fd, inp(fd, op, 1)?) else { return Ok(0) };
    if fd.op(and1).opc != IntAnd || fd.op(and2).opc != IntAnd {
        return Ok(0);
    }
    let (a, b) = (inp(fd, and1, 0)?, inp(fd, and1, 1)?);
    let (c, d) = (inp(fd, and2, 0)?, inp(fd, and2, 1)?);
    // the shared varnode, then the two that differ
    let (a, b, c) = if a == c {
        (a, b, d)
    } else if a == d {
        (a, b, c)
    } else if b == c {
        (c, a, d)
    } else if b == d {
        (d, a, c)
    } else {
        return Ok(0);
    };
    let asize = fd.vn(a).size;
    if is_const(fd, b) && is_const(fd, c) {
        let totalbits = fd.vn(b).offset | fd.vn(c).offset;
        if totalbits == calc_mask(asize) {
            fd.op_set_opcode(op, Copy);
            fd.op_remove_input(op, 1);
            fd.op_set_input(op, a, 0)?;
        } else {
            fd.op_set_opcode(op, IntAnd);
            fd.op_set_input(op, a, 0)?;
            let newconst = fd.new_constant(asize, totalbits);
            fd.op_set_input(op, newconst, 1)?;
        }
        return Ok(1);
    }
    if !fd.vn(b).is_heritage_known() || !fd.vn(c).is_heritage_known() {
        return Ok(0);
    }
    let amask = fd.nzmask(a);
    if fd.nzmask(b) & amask == 0 || fd.nzmask(c) & amask == 0 {
        return Ok(0); // RuleAndDistribute would reverse it
    }
    let new_or = fd.new_op(IntOr, fd.op(op).seq.addr);
    let orvn = uniq_out(fd, asize, new_or)?;
    fd.op_set_input(new_or, b, 0)?;
    fd.op_set_input(new_or, c, 1)?;
    fd.op_insert_before(new_or, op)?;
    fd.op_set_input(op, a, 0)?;
    fd.op_set_input(op, orvn, 1)?;
    fd.op_set_opcode(op, IntAnd);
    Ok(1)
}

/// Port of `RulePiece2Zext`: `concat(#0,W)` becomes `zext(W)`.
pub(super) fn piece_2_zext(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let constvn = inp(fd, op, 0)?;
    if !is_const(fd, constvn) || fd.vn(constvn).offset != 0 {
        return Ok(0);
    }
    fd.op_remove_input(op, 0);
    fd.op_set_opcode(op, IntZext);
    Ok(1)
}

/// Port of `RulePiece2Sext`: `concat(V s>> #0x1f, V)` becomes `sext(V)`.
pub(super) fn piece_2_sext(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let Some(shiftop) = def_with(fd, inp(fd, op, 0)?, IntSright) else { return Ok(0) };
    let savn = inp(fd, shiftop, 1)?;
    if !is_const(fd, savn) {
        return Ok(0);
    }
    let x = inp(fd, shiftop, 0)?;
    if x != inp(fd, op, 1)? || int4(fd, savn) != 8 * i64::from(fd.vn(x).size) - 1 {
        return Ok(0);
    }
    fd.op_remove_input(op, 0);
    fd.op_set_opcode(op, IntSext);
    Ok(1)
}

/// Port of `RulePiecePathology::isPathology`: whether `vn`, through COPYs and MULTIEQUALs,
/// comes from an unmapped input or from a call whose output is not being recovered: bytes a
/// PIECE takes from there are not a real value.
fn is_pathology(fd: &Funcdata, start: VarnodeId) -> Result<bool> {
    let silent_call = |call: OpId| fd.call_of(call).is_some_and(|c| fd.call(c).active_output.is_none());
    let mut worklist: Vec<OpId> = Vec::new();
    let mut marked = HashSet::new();
    let (mut pos, mut slot, mut vn) = (0, 0, start);
    loop {
        if fd.vn(vn).is_input() && !fd.vn(vn).has(VnFlags::PERSIST) {
            return Ok(true);
        }
        let mut cur = def(fd, vn);
        while let Some(op) = cur {
            cur = None;
            match fd.op(op).opc {
                Copy => {
                    vn = inp(fd, op, 0)?;
                    cur = def(fd, vn);
                }
                Multiequal if marked.insert(op) => worklist.push(op),
                Indirect => {
                    let target = fd.iop_target(inp(fd, op, 1)?);
                    if target.is_some_and(|t| fd.op(t).is_call() && silent_call(t)) {
                        return Ok(true);
                    }
                }
                Call | Callind if silent_call(op) => return Ok(true),
                // the C++ loop does not leave this op
                Call | Callind => {
                    return err("piecepathology: a call without a call spec or with an active output is not ported")
                }
                _ => {}
            }
        }
        let Some(&multi) = worklist.get(pos) else { return Ok(false) };
        if slot < ins(fd, multi).len() {
            vn = inp(fd, multi, slot)?;
            slot += 1;
        } else {
            pos += 1;
            let Some(&next) = worklist.get(pos) else { return Ok(false) };
            vn = inp(fd, next, 0)?;
            slot = 1;
        }
    }
}

/// Port of `RulePiecePathology::tracePathologyForward`: the calls and RETURNs the PIECE `op`
/// flows into, through COPY, INDIRECT and MULTIEQUAL, consume only its least significant
/// part (`setInputBytesConsumed`, `setReturnBytesConsumed`). Returns the records changed.
fn trace_pathology_forward(fd: &mut Funcdata, op: OpId) -> Result<i32> {
    let bytes = fd.vn(inp(fd, op, 1)?).size;
    let mut count = 0;
    let mut worklist = vec![op];
    let mut marked = HashSet::from([op]);
    let mut pos = 0;
    while let Some(&cur) = worklist.get(pos) {
        pos += 1;
        let out_vn = out(fd, cur)?;
        let readers: Vec<OpId> = fd.vn(out_vn).descend.iter().copied().collect();
        for reader in readers {
            let opc = fd.op(reader).opc;
            match opc {
                Copy | Indirect | Multiequal if marked.insert(reader) => worklist.push(reader),
                Call | Callind => {
                    let Some(c) = fd.call_of(reader) else { continue };
                    if fd.call(c).active_input.is_some() || fd.call(c).proto.locked.is_some() {
                        continue;
                    }
                    for slot in 1..ins(fd, reader).len() {
                        if inp(fd, reader, slot)? == out_vn && fd.call_mut(c).set_input_bytes_consumed(slot, bytes) {
                            count += 1;
                        }
                    }
                }
                Return if fd.proto.locked.is_none() && fd.proto.set_return_bytes_consumed(bytes) => count += 1,
                _ => {}
            }
        }
    }
    Ok(count)
}

/// Port of `RulePiecePathology`: a PIECE whose high part is pathological (a SUBPIECE of an
/// unmapped input or of a dead call output, or an indirect creation next to a real low part).
pub(super) fn piece_pathology(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let vn = inp(fd, op, 0)?;
    let Some(sub_op) = def(fd, vn) else { return Ok(0) };
    match fd.op(sub_op).opc {
        Subpiece => {
            if fd.vn(inp(fd, sub_op, 1)?).offset == 0 || !is_pathology(fd, inp(fd, sub_op, 0)?)? {
                return Ok(0);
            }
        }
        Indirect if fd.op(sub_op).flags.has(OpFlags::INDIRECT_CREATION) => {
            let lsb_vn = inp(fd, op, 1)?;
            let Some(lsb_op) = def(fd, lsb_vn) else { return Ok(0) };
            // from a unary or binary operation, or a call with a locked output
            if !fd.op(lsb_op).opc.is_unary_or_binary() {
                let locked = fd.call_of(lsb_op).is_some_and(|c| fd.call(c).proto.locked.is_some());
                if !fd.op(lsb_op).is_call() || !locked {
                    return Ok(0);
                }
            }
            // into a contiguous register
            let (lsb, hi) = (fd.vn(lsb_vn), fd.vn(vn));
            if (lsb.space, lsb.offset.wrapping_add(u64::from(lsb.size))) != (hi.space, hi.offset) {
                return Ok(0);
            }
        }
        _ => return Ok(0),
    }
    trace_pathology_forward(fd, op)
}
