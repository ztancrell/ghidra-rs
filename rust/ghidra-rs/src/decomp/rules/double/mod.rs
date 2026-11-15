//! Port of double.cc (stage R5 slice 3): double-precision recovery. A value too wide for one
//! register is computed as two pieces (`precislo` / `precishi`, [`VnFlags::PRECIS_LO`],
//! [`VnFlags::PRECIS_HI`]); the rules recognise the piecewise operations and rebuild them on
//! a whole varnode ([`split::SplitVarnode`], the forms in [`forms`] and [`less`]).
//!
//! The rules: `RuleDoubleIn` ([`double_in`]), `RuleDoubleOut` ([`double_out`]),
//! `RuleDoubleLoad` ([`double_load`]), `RuleDoubleStore` ([`double_store`]). `RuleDoubleIn::reset`
//! sets `Funcdata::doublePrecisRecovery` ([`Funcdata::double_precis_on`]) from
//! `ActionTree::perform`. `ActionParamDouble`, which reads that flag, is
//! [`param_double`]. Not modelled: big-endian spaces.

mod forms;
mod less;
mod split;

use forms::*;
use less::*;
use split::*;

use super::*;

/// `SplitVarnode::applyRuleIn`: try every form on the readers of the high, then the low piece.
fn apply_rule_in(inv: &SplitVarnode, fd: &mut Funcdata, arch: &Arch) -> Result<i32> {
    for (vn, workishi) in [(inv.hi, true), (inv.lo, false)] {
        let Some(vn) = vn else { continue };
        for workop in readers(fd, vn) {
            if fd.op(workop).is_dead() {
                continue; // not reachable in the C++: a form changes nothing unless it succeeds
            }
            if try_forms(inv, workop, workishi, fd, arch)? {
                return Ok(1);
            }
        }
    }
    Ok(0)
}

/// The `switch` of `applyRuleIn` on one reader.
fn try_forms(inv: &SplitVarnode, op: OpId, hi: bool, fd: &mut Funcdata, arch: &Arch) -> Result<bool> {
    Ok(match code(fd, op) {
        IntAdd => AddForm::apply_rule(inv, op, hi, fd)? || SubForm::apply_rule(inv, op, hi, fd)?,
        IntAnd => Equal3Form::apply_rule(inv, op, hi, fd)? || LogicalForm::apply_rule(inv, op, hi, fd)?,
        IntOr | IntXor => LogicalForm::apply_rule(inv, op, hi, fd)?,
        IntEqual | IntNotequal => {
            LessThreeWay::apply_rule(inv, op, hi, fd)?
                || Equal1Form::apply_rule(inv, op, hi, fd)?
                || Equal2Form::apply_rule(inv, op, hi, fd)?
        }
        IntLess | IntLessequal => {
            LessThreeWay::apply_rule(inv, op, hi, fd)? || LessConstForm::apply_rule(inv, op, hi, fd)?
        }
        IntSless | IntSlessequal => LessConstForm::apply_rule(inv, op, hi, fd)?,
        IntLeft => ShiftForm::apply_rule(inv, op, hi, fd, true)?,
        IntRight | IntSright => ShiftForm::apply_rule(inv, op, hi, fd, false)?,
        IntMult => MultForm::apply_rule(inv, op, hi, fd)?,
        Multiequal => PhiForm::apply_rule(inv, op, hi, fd)?,
        Indirect => IndirectForm::apply_rule(inv, op, hi, fd, arch)?,
        Copy => {
            let forced = fd.op(op).out.is_some_and(|o| fd.vn(o).flags.has(VnFlags::ADDRFORCE));
            forced && CopyForceForm::apply_rule(inv, op, hi, fd, arch)?
        }
        _ => false,
    })
}

/// `TypeOp::isArithmeticOp`.
fn is_arithmetic_op(opc: Opcode) -> bool {
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

/// `TypeOp::isFloatingPointOp`.
fn is_floating_point_op(opc: Opcode) -> bool {
    matches!(
        opc,
        FloatEqual
            | FloatNotequal
            | FloatLess
            | FloatLessequal
            | FloatNan
            | FloatAdd
            | FloatDiv
            | FloatMult
            | FloatSub
            | FloatNeg
            | FloatAbs
            | FloatSqrt
            | FloatInt2float
            | FloatFloat2float
            | FloatTrunc
            | FloatCeil
            | FloatFloor
            | FloatRound
    )
}

/// Port of `Datatype::isPrimitiveWhole`. The C++ looks into a struct or array whose first
/// component fills it; that case is not ported and errors.
fn primitive_whole(fd: &Funcdata, ty: super::super::types::TypeId) -> Result<bool> {
    use super::super::types::Meta;
    match fd.types.meta(ty) {
        Meta::Array | Meta::Struct => err("isPrimitiveWhole of a struct or array not implemented in ghidra-rs yet"),
        Meta::Union => Ok(false),
        _ => Ok(true),
    }
}

/// The `isTypeLock() && !getType()->isPrimitiveWhole()` test of the `attemptMarking`s: a
/// locked aggregate refuses.
fn locked_non_primitive(fd: &Funcdata, whole: VarnodeId) -> Result<bool> {
    let v = fd.vn(whole);
    match v.ty {
        Some(ty) if v.flags.has(VnFlags::TYPELOCK) => Ok(!primitive_whole(fd, ty)?),
        _ => Ok(false),
    }
}

/// `RuleDoubleIn::attemptMarking`: `vn`, the high SUBPIECE of an arithmetic result, and its
/// low sibling are marked as pieces.
fn double_in_marking(fd: &mut Funcdata, vn: VarnodeId, subpiece_op: OpId) -> Result<i32> {
    let whole = inp(fd, subpiece_op, 0)?;
    if locked_non_primitive(fd, whole)? {
        return Ok(0);
    }
    let offset = int4(fd, inp(fd, subpiece_op, 1)?);
    if offset != i64::from(sz(fd, vn)) || offset * 2 != i64::from(sz(fd, whole)) {
        return Ok(0); // not exactly half
    }
    if fd.vn(whole).is_input() {
        if !fd.vn(whole).flags.has(VnFlags::TYPELOCK) {
            return Ok(0);
        }
    } else {
        let Some(d) = def(fd, whole) else { return Ok(0) };
        if !is_arithmetic_op(code(fd, d)) && !is_floating_point_op(code(fd, d)) {
            return Ok(0);
        }
    }
    let mut vn_lo = None;
    for op in readers(fd, whole) {
        if code(fd, op) != Subpiece || off(fd, inp(fd, op, 1)?) != 0 {
            continue;
        }
        let o = out(fd, op)?;
        if sz(fd, o) == sz(fd, vn) {
            vn_lo = Some(o);
            break;
        }
    }
    let Some(vn_lo) = vn_lo else { return Ok(0) };
    fd.vn_set(vn_lo, VnFlags::PRECIS_LO);
    fd.vn_set(vn, VnFlags::PRECIS_HI);
    Ok(1)
}

/// Port of `RuleDoubleIn` (SUBPIECE): mark the pieces of a whole, then rebuild the operations
/// reading them.
pub(in super::super) fn double_in(fd: &mut Funcdata, op: OpId, arch: &Arch) -> Result<i32> {
    let outvn = out(fd, op)?;
    if !fd.vn(outvn).is_precis_lo() {
        if fd.vn(outvn).is_precis_hi() {
            return Ok(0);
        }
        return double_in_marking(fd, outvn, op);
    }
    if fd.blocks.unreachable {
        return Ok(0);
    }
    for inv in whole_list(fd, inp(fd, op, 0)?)? {
        let res = apply_rule_in(&inv, fd, arch)?;
        if res != 0 {
            return Ok(res);
        }
    }
    Ok(0)
}

/// `RuleDoubleOut::attemptMarking`.
fn double_out_marking(fd: &mut Funcdata, arch: &Arch, vnhi: VarnodeId, vnlo: VarnodeId, piece_op: OpId) -> Result<i32> {
    let whole = out(fd, piece_op)?;
    if locked_non_primitive(fd, whole)? || sz(fd, vnhi) != sz(fd, vnlo) || !same_symbol(fd, arch, vnhi, vnlo) {
        return Ok(0);
    }
    let is_whole =
        fd.vn(whole).descend.iter().any(|&r| is_arithmetic_op(code(fd, r)) || is_floating_point_op(code(fd, r)));
    if !is_whole {
        return Ok(0);
    }
    fd.vn_set(vnhi, VnFlags::PRECIS_HI);
    fd.vn_set(vnlo, VnFlags::PRECIS_LO);
    Ok(1)
}

/// Port of `RuleDoubleOut` (PIECE): two global inputs concatenated into an arithmetic whole
/// become one input.
pub(in super::super) fn double_out(fd: &mut Funcdata, op: OpId, arch: &Arch) -> Result<i32> {
    let (vnhi, vnlo) = (inp(fd, op, 0)?, inp(fd, op, 1)?);
    let (h, l) = (fd.vn(vnhi), fd.vn(vnlo));
    if !h.is_input() || !l.is_input() || !h.flags.has(VnFlags::PERSIST) || !l.flags.has(VnFlags::PERSIST) {
        return Ok(0);
    }
    if !h.is_precis_hi() || !l.is_precis_lo() {
        return double_out_marking(fd, arch, vnhi, vnlo, op);
    }
    if fd.blocks.unreachable || is_addr_tied_contiguous(fd, arch, vnlo, vnhi).is_none() {
        return Ok(0);
    }
    fd.combine_input_varnodes(vnhi, vnlo, arch)?;
    Ok(1)
}

/// `RuleDoubleLoad::noWriteConflict`: the later of two LOADs or STOREs in one block when nothing
/// between them may write `spc` (the INDIRECTs they cause go to `indirects`).
fn no_write_conflict(
    fd: &Funcdata,
    mut op1: OpId,
    mut op2: OpId,
    spc: u32,
    mut indirects: Option<&mut Vec<OpId>>,
) -> Result<Option<OpId>> {
    let bb = parent(fd, op1);
    if bb.is_none() || bb != parent(fd, op2) {
        return Ok(None);
    }
    if order(fd, op2) < order(fd, op1) {
        std::mem::swap(&mut op1, &mut op2);
    }
    let mut startop = op1;
    if code(fd, op1) == Store {
        while let Some(prev) = fd.previous_op(startop).filter(|&p| code(fd, p) == Indirect) {
            startop = prev;
        }
    }
    let ops = &fd.blocks.block(bb.ok_or_else(|| LowlevelError("no block".into()))?).ops;
    let start = ops.iter().position(|&o| o == startop).ok_or_else(|| LowlevelError("op not in its block".into()))?;
    let space = Space::Sleigh(spc);
    for &curop in ops[start..].iter().take_while(|&&o| o != op2) {
        if curop == op1 {
            continue;
        }
        match code(fd, curop) {
            Store => {
                if space_from_const(fd, curop)? == spc {
                    return Ok(None); // a STORE to the same space
                }
            }
            Indirect => {
                let affector = fd.iop_target(inp(fd, curop, 1)?);
                if affector == Some(op1) || affector == Some(op2) {
                    if let Some(list) = indirects.as_deref_mut() {
                        list.push(curop);
                    }
                } else if fd.vn(out(fd, curop)?).space == space {
                    return Ok(None);
                }
            }
            Call | Callind | Callother | Return | Branch | Cbranch | Branchind => return Ok(None),
            _ => {
                if fd.op(curop).out.is_some_and(|o| fd.vn(o).space == space) {
                    return Ok(None);
                }
            }
        }
    }
    Ok(Some(op2))
}

/// Port of `RuleDoubleLoad` (PIECE): two adjacent LOADs concatenated become one LOAD.
pub(in super::super) fn double_load(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let (piece0, piece1) = (inp(fd, op, 0)?, inp(fd, op, 1)?);
    let (Some(mut load0), Some(load1)) = (def(fd, piece0), def(fd, piece1)) else { return Ok(0) };
    if code(fd, load1) != Load {
        return Ok(0);
    }
    if code(fd, load0) == Subpiece {
        if off(fd, inp(fd, load0, 1)?) != 0 {
            return Ok(0);
        }
        // the offset of the piece only matters on a big-endian space
        let Some(d) = def(fd, inp(fd, load0, 0)?) else { return Ok(0) };
        load0 = d;
    }
    if code(fd, load0) != Load {
        return Ok(0);
    }
    let Some((loadlo, loadhi, spc)) = test_contiguous_pointers(fd, load0, load1)? else { return Ok(0) };
    let size = sz(fd, piece0) + sz(fd, piece1);
    let Some(latest) = no_write_conflict(fd, loadlo, loadhi, spc, None)? else { return Ok(0) };
    let newload = fd.new_op(Load, op_addr(fd, latest));
    let vnout = uniq_out(fd, size, newload)?;
    let spcvn = fd.new_varnode_space(spc);
    fd.op_set_input(newload, spcvn, 0)?;
    let addrvn = inp(fd, loadlo, 1)?;
    fd.op_set_input(newload, addrvn, 1)?;
    fd.op_insert_after(newload, latest)?;
    fd.op_remove_input(op, 1);
    fd.op_set_opcode(op, Copy);
    fd.op_set_input(op, vnout, 0)?;
    Ok(1)
}

/// `RuleDoubleStore::testIndirectUse`: the INDIRECTs caused by the two STOREs are read only
/// outside the range between them, or once by an INDIRECT of the later STORE.
fn test_indirect_use(fd: &Funcdata, mut op1: OpId, mut op2: OpId, indirects: &[OpId]) -> Result<bool> {
    if order(fd, op2) < order(fd, op1) {
        std::mem::swap(&mut op1, &mut op2);
    }
    for &ind in indirects {
        let (mut usecount, mut usebyop2) = (0, 0);
        for op in readers(fd, out(fd, ind)?) {
            usecount += 1;
            if parent(fd, op) != parent(fd, op1) || order(fd, op) < order(fd, op1) || order(fd, op) > order(fd, op2) {
                continue;
            }
            if code(fd, op) == Indirect && fd.iop_target(inp(fd, op, 1)?) == Some(op2) {
                usebyop2 += 1;
                continue;
            }
            return Ok(false);
        }
        if (usebyop2 > 0 && usecount != usebyop2) || usebyop2 > 1 {
            return Ok(false);
        }
    }
    Ok(true)
}

/// `RuleDoubleStore::reassignIndirects`: the INDIRECTs of the two STOREs move before the new one.
fn reassign_indirects(fd: &mut Funcdata, new_store: OpId, indirects: &[OpId]) -> Result<()> {
    let marked: HashSet<OpId> = indirects.iter().copied().collect(); // setMark
    for &op in indirects {
        let Some(earlyop) = def(fd, inp(fd, op, 0)?) else { continue };
        if marked.contains(&earlyop) {
            let v = inp(fd, earlyop, 0)?;
            fd.op_set_input(op, v, 0)?;
            fd.op_destroy(earlyop);
        }
    }
    for &op in indirects {
        if fd.op(op).is_dead() {
            continue;
        }
        fd.op_uninsert(op);
        fd.op_insert_before(op, new_store)?;
        let iop = fd.new_varnode_iop(new_store);
        fd.op_set_input(op, iop, 1)?;
    }
    Ok(())
}

/// The other STORE, the INDIRECTs between the two, the later STORE and the space.
type StorePair = (OpId, Vec<OpId>, OpId, u32);

/// The STORE of the high piece pairing with `op` (the STORE of the low piece `vnlo` of
/// `whole`): (the other STORE, least, most, space).
fn find_store_pair(
    fd: &Funcdata,
    op: OpId,
    vnlo: VarnodeId,
    sub_lo: OpId,
    whole: VarnodeId,
) -> Result<Option<StorePair>> {
    for sub_hi in readers(fd, whole) {
        if code(fd, sub_hi) != Subpiece || sub_hi == sub_lo {
            continue;
        }
        let offset = int4(fd, inp(fd, sub_hi, 1)?);
        let Some(vnhi) = fd.op(sub_hi).out else { continue };
        if offset != i64::from(sz(fd, vnlo)) || !fd.vn(vnhi).is_precis_hi() {
            continue;
        }
        if i64::from(sz(fd, vnhi)) != i64::from(sz(fd, whole)) - offset {
            continue;
        }
        for store2 in readers(fd, vnhi) {
            if code(fd, store2) != Store || inp(fd, store2, 2)? != vnhi {
                continue;
            }
            let Some((storelo, storehi, spc)) = test_contiguous_pointers(fd, store2, op)? else { continue };
            let mut indirects = Vec::new();
            let Some(latest) = no_write_conflict(fd, storelo, storehi, spc, Some(&mut indirects))? else { continue };
            if !test_indirect_use(fd, storelo, storehi, &indirects)? {
                continue;
            }
            return Ok(Some((store2, indirects, latest, spc)));
        }
    }
    Ok(None)
}

/// Port of `RuleDoubleStore` (STORE): STOREs of both pieces to adjacent memory become one STORE
/// of the whole.
pub(in super::super) fn double_store(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let vnlo = inp(fd, op, 2)?;
    if !fd.vn(vnlo).is_precis_lo() {
        return Ok(0);
    }
    let Some(sub_lo) = def_with(fd, vnlo, Subpiece) else { return Ok(0) };
    if off(fd, inp(fd, sub_lo, 1)?) != 0 {
        return Ok(0);
    }
    let whole = inp(fd, sub_lo, 0)?;
    if is_free(fd, whole) {
        return Ok(0);
    }
    let Some((store2, indirects, latest, spc)) = find_store_pair(fd, op, vnlo, sub_lo, whole)? else { return Ok(0) };
    // storelo is the STORE of the lower address: the low piece's on a little-endian space
    let storelo = op;
    let newstore = fd.new_op(Store, op_addr(fd, latest));
    let spcvn = fd.new_varnode_space(spc);
    fd.op_set_input(newstore, spcvn, 0)?;
    let mut addrvn = inp(fd, storelo, 1)?;
    if is_const(fd, addrvn) {
        addrvn = fd.new_constant(sz(fd, addrvn), off(fd, addrvn));
    }
    fd.op_set_input(newstore, addrvn, 1)?;
    fd.op_set_input(newstore, whole, 2)?;
    fd.op_insert_after(newstore, latest)?;
    fd.op_destroy(op);
    fd.op_destroy(store2);
    reassign_indirects(fd, newstore, &indirects)?;
    Ok(1)
}

/// The adjacent call inputs `j`, `j+1` that are the high and low (or low and high) pieces of
/// one whole (the matching of `ActionParamDouble` for an unlocked call).
fn param_pair(fd: &Funcdata, op: OpId, j: usize) -> Result<bool> {
    let (vn1, vn2) = (inp(fd, op, j)?, inp(fd, op, j + 1)?);
    let mut whole = SplitVarnode::default();
    if whole.in_hand_hi(fd, vn1)? {
        return Ok(whole.lo == Some(vn2));
    }
    if whole.in_hand_lo(fd, vn1)? {
        return Ok(whole.hi == Some(vn2));
    }
    Ok(false)
}

/// Port of `ActionParamDouble::apply` (group `protorecovery`).
///
/// - A call with active trials: a stack trial whose varnode is a PIECE would be split in two
///   (`checkInputSplit`, `ParamActive::splitTrial`). Not ported: it errors where the C++ would
///   ask `checkInputSplit`.
/// - A call with neither trials nor a locked prototype, double precision on: two adjacent inputs
///   that are the pieces of one whole would be joined (`checkInputJoin` / `doInputJoin`). Not
///   ported: that errors.
/// - The function's own prototype locked, double precision on: the half-size SUBPIECEs of a
///   primitive parameter of at least the default size are marked `precislo` / `precishi`, when
///   the parameter is read through such halves only.
pub(crate) fn param_double(fd: &mut Funcdata, arch: &Arch) -> Result<i32> {
    for c in fd.qlst.clone() {
        let call = fd.call(c);
        let op = call.op;
        if let Some(active) = &call.active_input {
            for t in &active.trials {
                if t.has(crate::decomp::fspec::ParamTrial::CHECKED)
                    || t.has(crate::decomp::fspec::ParamTrial::UNREF)
                    || t.space != Space::Stack
                {
                    continue;
                }
                let vn = inp(fd, op, t.slot)?;
                let is_piece = fd.vn(vn).def.is_some_and(|d| code(fd, d) == Opcode::Piece);
                if is_piece && call.proto.model.is_some() {
                    return err(
                        "ActionParamDouble: splitting a stack trial that is a PIECE not implemented in ghidra-rs yet",
                    );
                }
            }
        } else if call.proto.locked.is_none() && fd.double_precis_on {
            let n = fd.op(op).ins.len();
            for j in 1..n.saturating_sub(1) {
                if param_pair(fd, op, j)? {
                    return err(
                        "ActionParamDouble: joining double-precision call inputs not implemented in ghidra-rs yet",
                    );
                }
            }
        }
    }
    let mut count = 0;
    let Some(locked) = fd.proto.locked.clone().filter(|_| fd.double_precis_on) else { return Ok(0) };
    let min_double_size = arch.pointer_size();
    for p in &locked.inputs {
        if !primitive_whole(fd, p.ty)? {
            continue;
        }
        let Some(st) = &p.storage else { continue };
        // findVarnodeInput(tp->getSize(), param->getAddress())
        let (space, poff, _) = crate::decomp::locked::location(fd, st)?;
        let Some(vn) = fd.loc_at(space, poff, fd.types.size(p.ty)).into_iter().find(|&v| fd.vn(v).is_input()) else {
            continue;
        };
        if sz(fd, vn) < min_double_size {
            continue;
        }
        let half = u64::from(sz(fd, vn) / 2);
        let (mut lovec, mut hivec) = (Vec::new(), Vec::new());
        let mut other_use = false;
        for &subop in fd.vn(vn).descend.iter() {
            if code(fd, subop) != Opcode::Subpiece {
                continue;
            }
            let outvn = out(fd, subop)?;
            if u64::from(sz(fd, outvn)) != half {
                continue;
            }
            match off(fd, inp(fd, subop, 1)?) {
                0 => lovec.push(outvn),
                o if o == half => hivec.push(outvn),
                _ => {
                    other_use = true;
                    break;
                }
            }
        }
        if other_use || lovec.is_empty() || hivec.is_empty() {
            continue;
        }
        for (vec, flag) in [(lovec, VnFlags::PRECIS_LO), (hivec, VnFlags::PRECIS_HI)] {
            for piece in vec {
                if !fd.vn(piece).has(flag) {
                    fd.vn_set(piece, flag);
                    count += 1;
                }
            }
        }
    }
    Ok(count)
}

#[cfg(test)]
mod tests;
