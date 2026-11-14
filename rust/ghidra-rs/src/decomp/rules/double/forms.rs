//! The arithmetic, logical, equality, shift, multiply and data-flow forms of double.cc
//! (`AddForm`, `SubForm`, `LogicalForm`, `Equal1Form`, `Equal2Form`, `Equal3Form`, `ShiftForm`,
//! `MultForm`, `PhiForm`, `IndirectForm`, `CopyForceForm`). Each recognises the piecewise
//! p-code of one double-precision operation starting from a reader of a piece and replaces it
//! with the operation on the whole. The forms keep the C++ member state: later matching steps
//! read what earlier ones set.

use super::split::*;
use super::*;

/// `PcodeOp::verifyMultNegOne`.
fn verify_mult_neg_one(fd: &Funcdata, op: OpId) -> Result<bool> {
    if code(fd, op) != IntMult {
        return Ok(false);
    }
    let in1 = inp(fd, op, 1)?;
    Ok(is_const(fd, in1) && off(fd, in1) == calc_mask(sz(fd, in1)))
}

/// `AddForm`: `lo1 + lo2` with the carry into `hi1 + hi2`.
#[derive(Debug, Default)]
pub(super) struct AddForm {
    hi1: Option<VarnodeId>,
    lo1: Option<VarnodeId>,
    hi2: Option<VarnodeId>,
    lo2: Option<VarnodeId>,
    reshi: Option<VarnodeId>,
    reslo: Option<VarnodeId>,
    negconst: u64,
}

impl AddForm {
    fn lo1(&self) -> Result<VarnodeId> {
        self.lo1.ok_or_else(|| LowlevelError("AddForm without lo1".into()))
    }

    /// `AddForm::checkForCarry`.
    fn check_for_carry(&mut self, fd: &Funcdata, op: OpId) -> Result<bool> {
        if code(fd, op) != IntZext {
            return Ok(false);
        }
        let Some(carryop) = def(fd, inp(fd, op, 0)?) else { return Ok(false) };
        let lo1 = self.lo1()?;
        if !matches!(code(fd, carryop), IntCarry | IntLess | IntNotequal) {
            return Ok(false);
        }
        let (c0, c1) = (inp(fd, carryop, 0)?, inp(fd, carryop, 1)?);
        match code(fd, carryop) {
            IntCarry => {
                let lo2 = if c0 == lo1 {
                    c1
                } else if c1 == lo1 {
                    c0
                } else {
                    return Ok(false);
                };
                self.lo2 = Some(lo2);
                Ok(!is_const(fd, lo2))
            }
            IntLess => self.carry_from_less(fd, c0, c1, lo1),
            IntNotequal => {
                if !is_const(fd, c1) || c0 != lo1 || off(fd, c1) != 0 {
                    return Ok(false);
                }
                self.negconst = calc_mask(sz(fd, lo1));
                self.lo2 = None;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    /// The INT_LESS case of `checkForCarry` (`tmpvn < c1`).
    fn carry_from_less(&mut self, fd: &Funcdata, tmpvn: VarnodeId, relvn: VarnodeId, lo1: VarnodeId) -> Result<bool> {
        if is_const(fd, tmpvn) {
            if relvn != lo1 {
                return Ok(false);
            }
            self.negconst = !off(fd, tmpvn) & calc_mask(sz(fd, lo1));
            self.lo2 = None;
            return Ok(true);
        }
        let Some(loadd_op) = def(fd, tmpvn) else { return Ok(false) };
        if code(fd, loadd_op) != IntAdd {
            return Ok(false);
        }
        let (a0, a1) = (inp(fd, loadd_op, 0)?, inp(fd, loadd_op, 1)?);
        let othervn = if a0 == lo1 {
            a1
        } else if a1 == lo1 {
            a0
        } else {
            return Ok(false);
        };
        if is_const(fd, othervn) {
            self.negconst = off(fd, othervn);
            self.lo2 = None;
            if relvn == lo1 {
                return Ok(true);
            }
            return Ok(is_const(fd, relvn) && off(fd, relvn) == self.negconst);
        }
        self.lo2 = Some(othervn);
        Ok(relvn == othervn || relvn == lo1)
    }

    /// The (reshi, hizext1, hizext2) of pass `i` of `AddForm::verify`.
    fn hi_add_shape(
        fd: &Funcdata,
        op: OpId,
        slot1: usize,
        i: usize,
    ) -> Result<Option<(VarnodeId, VarnodeId, Option<VarnodeId>)>> {
        let opout = out(fd, op)?;
        Ok(match i {
            0 => {
                let Some(add2) = lone_descend(fd, opout).filter(|&a| code(fd, a) == IntAdd) else { return Ok(None) };
                Some((out(fd, add2)?, inp(fd, op, 1 - slot1)?, Some(other_in(fd, add2, opout)?)))
            }
            1 => {
                let Some(add2) = def_with(fd, inp(fd, op, 1 - slot1)?, IntAdd) else { return Ok(None) };
                Some((opout, inp(fd, add2, 0)?, Some(inp(fd, add2, 1)?)))
            }
            _ => Some((opout, inp(fd, op, 1 - slot1)?, None)),
        })
    }

    /// `AddForm::verify`.
    fn verify(&mut self, fd: &Funcdata, h: VarnodeId, l: VarnodeId, op: OpId) -> Result<bool> {
        self.hi1 = Some(h);
        self.lo1 = Some(l);
        let slot1 = slot(fd, op, h)?.min(1);
        for i in 0..3 {
            let Some((reshi, hizext1, hizext2)) = Self::hi_add_shape(fd, op, slot1, i)? else { continue };
            self.reshi = Some(reshi);
            for j in 0..2 {
                let (zsrc, hi2) = match (i, j, hizext2) {
                    (2, _, _) => (hizext1, None),
                    (_, 0, z2) => (hizext1, z2),
                    (_, _, Some(z2)) => (z2, Some(hizext1)),
                    _ => continue,
                };
                let Some(zextop) = def(fd, zsrc) else { continue };
                self.hi2 = hi2;
                if !self.check_for_carry(fd, zextop)? {
                    continue;
                }
                if self.find_lo_add(fd, l)? {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// The loop over `lo1`'s INT_ADD readers ending `AddForm::verify`.
    fn find_lo_add(&mut self, fd: &Funcdata, lo1: VarnodeId) -> Result<bool> {
        for loadd in readers(fd, lo1) {
            if code(fd, loadd) != IntAdd {
                continue;
            }
            let tmpvn = other_in(fd, loadd, lo1)?;
            match self.lo2 {
                None => {
                    if !is_const(fd, tmpvn) || off(fd, tmpvn) != self.negconst {
                        continue;
                    }
                    self.lo2 = Some(tmpvn);
                }
                Some(lo2) if is_const(fd, lo2) => {
                    if !is_const(fd, tmpvn) || off(fd, lo2) != off(fd, tmpvn) {
                        continue;
                    }
                }
                Some(lo2) => {
                    if tmpvn != lo2 {
                        continue;
                    }
                }
            }
            self.reslo = Some(out(fd, loadd)?);
            return Ok(true);
        }
        Ok(false)
    }

    /// `AddForm::applyRule`.
    pub(super) fn apply_rule(i: &SplitVarnode, op: OpId, workishi: bool, fd: &mut Funcdata) -> Result<bool> {
        let mut f = AddForm::default();
        if !workishi {
            return Ok(false);
        }
        let Some((lo, hi)) = i.pieces() else { return Ok(false) };
        if !f.verify(fd, hi, lo, op)? {
            return Ok(false);
        }
        apply_binary(fd, i, f.lo2, f.hi2, f.reslo, f.reshi, IntAdd)
    }
}

/// The tail shared by the binary forms: `in OP (lo2, hi2)` makes `(reslo, reshi)`.
fn apply_binary(
    fd: &mut Funcdata,
    i: &SplitVarnode,
    lo2: Option<VarnodeId>,
    hi2: Option<VarnodeId>,
    reslo: Option<VarnodeId>,
    reshi: Option<VarnodeId>,
    opc: Opcode,
) -> Result<bool> {
    let missing = || LowlevelError("double precision form matched without its pieces".into());
    let mut inv = i.clone();
    let mut indoub = SplitVarnode::default();
    indoub.init_partial(fd, i.wholesize, lo2.ok_or_else(missing)?, hi2);
    if indoub.exceeds_const_precision() {
        return Ok(false);
    }
    let mut outdoub = SplitVarnode::default();
    outdoub.init_partial(fd, i.wholesize, reslo.ok_or_else(missing)?, reshi);
    let Some(existop) = prepare_binary_op(fd, &mut outdoub, &mut inv, &mut indoub)? else { return Ok(false) };
    create_binary_op(fd, &mut outdoub, &mut inv, &mut indoub, existop, opc)?;
    Ok(true)
}

/// `SubForm`: `lo1 - lo2` with the borrow out of `hi1 - hi2` (as multiplications by -1).
#[derive(Debug, Default)]
pub(super) struct SubForm {
    hi2: Option<VarnodeId>,
    lo2: Option<VarnodeId>,
    reshi: Option<VarnodeId>,
    reslo: Option<VarnodeId>,
}

impl SubForm {
    /// The (reshi, hineg1, hineg2) of pass `i` of `SubForm::verify`.
    fn hi_add_shape(
        fd: &Funcdata,
        op: OpId,
        slot1: usize,
        i: usize,
    ) -> Result<Option<(VarnodeId, VarnodeId, VarnodeId)>> {
        let opout = out(fd, op)?;
        if i == 0 {
            let Some(add2) = lone_descend(fd, opout).filter(|&a| code(fd, a) == IntAdd) else { return Ok(None) };
            return Ok(Some((out(fd, add2)?, inp(fd, op, 1 - slot1)?, other_in(fd, add2, opout)?)));
        }
        let Some(add2) = def_with(fd, inp(fd, op, 1 - slot1)?, IntAdd) else { return Ok(None) };
        Ok(Some((opout, inp(fd, add2, 0)?, inp(fd, add2, 1)?)))
    }

    /// The input of the `-1 *` op defining `vn`.
    fn neg_of(fd: &Funcdata, vn: VarnodeId) -> Result<Option<VarnodeId>> {
        let Some(d) = def(fd, vn) else { return Ok(None) };
        Ok(if verify_mult_neg_one(fd, d)? { Some(inp(fd, d, 0)?) } else { None })
    }

    /// `SubForm::verify`.
    fn verify(&mut self, fd: &Funcdata, hi1: VarnodeId, lo1: VarnodeId, op: OpId) -> Result<bool> {
        let slot1 = slot(fd, op, hi1)?.min(1);
        for i in 0..2 {
            let Some((reshi, hineg1, hineg2)) = Self::hi_add_shape(fd, op, slot1, i)? else { continue };
            self.reshi = Some(reshi);
            if !fd.vn(hineg1).is_written() || !fd.vn(hineg2).is_written() {
                continue;
            }
            let (Some(hizext1), Some(hizext2)) = (Self::neg_of(fd, hineg1)?, Self::neg_of(fd, hineg2)?) else {
                continue;
            };
            for (zsrc, hi2) in [(hizext1, hizext2), (hizext2, hizext1)] {
                let Some(zextop) = def_with(fd, zsrc, IntZext) else { continue };
                self.hi2 = Some(hi2);
                let Some(lessop) = def_with(fd, inp(fd, zextop, 0)?, IntLess) else { continue };
                if inp(fd, lessop, 0)? != lo1 {
                    continue;
                }
                let lo2 = inp(fd, lessop, 1)?;
                self.lo2 = Some(lo2);
                for loadd in readers(fd, lo1) {
                    if code(fd, loadd) != IntAdd {
                        continue;
                    }
                    if Self::neg_of(fd, other_in(fd, loadd, lo1)?)? != Some(lo2) {
                        continue;
                    }
                    self.reslo = Some(out(fd, loadd)?);
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// `SubForm::applyRule`.
    pub(super) fn apply_rule(i: &SplitVarnode, op: OpId, workishi: bool, fd: &mut Funcdata) -> Result<bool> {
        let mut f = SubForm::default();
        if !workishi {
            return Ok(false);
        }
        let Some((lo, hi)) = i.pieces() else { return Ok(false) };
        if !f.verify(fd, hi, lo, op)? {
            return Ok(false);
        }
        apply_binary(fd, i, f.lo2, f.hi2, f.reslo, f.reshi, IntSub)
    }
}

/// `LogicalForm`: the same AND, OR or XOR on both pieces.
pub(super) struct LogicalForm;

impl LogicalForm {
    /// `LogicalForm::findHiMatch`: the op on the high piece matching `loop_` on the low one.
    pub(super) fn find_hi_match(
        fd: &Funcdata,
        inv: &SplitVarnode,
        loop_: OpId,
        hi1: VarnodeId,
    ) -> Result<Option<OpId>> {
        let lo1 = inv.lo.ok_or_else(|| LowlevelError("LogicalForm without lo".into()))?;
        let vn2 = other_in(fd, loop_, lo1)?;
        let opc = code(fd, loop_);
        let mut out = SplitVarnode::default();
        if out.in_hand_lo_out(fd, lo1)? {
            if let Some(maybeop) = out.hi.and_then(|h| def(fd, h)).filter(|&m| code(fd, m) == opc) {
                let (m0, m1) = (inp(fd, maybeop, 0)?, inp(fd, maybeop, 1)?);
                if m0 == hi1 {
                    if is_const(fd, m1) == is_const(fd, vn2) {
                        return Ok(Some(maybeop));
                    }
                } else if m1 == hi1 && is_const(fd, m0) == is_const(fd, vn2) {
                    return Ok(Some(maybeop));
                }
            }
        }
        if !is_const(fd, vn2) {
            let mut in2 = SplitVarnode::default();
            if in2.in_hand_lo(fd, vn2)? {
                let h2 = in2.hi.ok_or_else(|| LowlevelError("inHandLo without hi".into()))?;
                for maybeop in readers(fd, h2) {
                    if code(fd, maybeop) == opc && (inp(fd, maybeop, 0)? == hi1 || inp(fd, maybeop, 1)? == hi1) {
                        return Ok(Some(maybeop));
                    }
                }
            }
            return Ok(None);
        }
        let mut found = Vec::new();
        for maybeop in readers(fd, hi1) {
            if code(fd, maybeop) == opc && is_const(fd, inp(fd, maybeop, 1)?) {
                found.push(maybeop);
                if found.len() > 1 {
                    break;
                }
            }
        }
        Ok(if found.len() == 1 { found.first().copied() } else { None })
    }

    /// `LogicalForm::applyRule` (with `verify`).
    pub(super) fn apply_rule(i: &SplitVarnode, lop: OpId, workishi: bool, fd: &mut Funcdata) -> Result<bool> {
        if workishi {
            return Ok(false);
        }
        let Some((lo1, hi1)) = i.pieces() else { return Ok(false) };
        let Some(hiop) = Self::find_hi_match(fd, i, lop, hi1)? else { return Ok(false) };
        let lo2 = other_in(fd, lop, lo1)?;
        let hi2 = other_in(fd, hiop, hi1)?;
        if lo2 == lo1 || lo2 == hi1 || hi2 == hi1 || hi2 == lo1 || lo2 == hi2 {
            return Ok(false);
        }
        let mut inv = i.clone();
        let mut outdoub = SplitVarnode::default();
        outdoub.init_partial(fd, i.wholesize, out(fd, lop)?, Some(out(fd, hiop)?));
        let mut indoub = SplitVarnode::default();
        indoub.init_partial(fd, i.wholesize, lo2, Some(hi2));
        if indoub.exceeds_const_precision() {
            return Ok(false);
        }
        let Some(existop) = prepare_binary_op(fd, &mut outdoub, &mut inv, &mut indoub)? else { return Ok(false) };
        let opc = code(fd, lop);
        create_binary_op(fd, &mut outdoub, &mut inv, &mut indoub, existop, opc)?;
        Ok(true)
    }
}

/// `Equal1Form`: `hi1 == hi2` and `lo1 == lo2` as two branches.
pub(super) struct Equal1Form;

impl Equal1Form {
    /// `Equal1Form::applyRule`.
    pub(super) fn apply_rule(i: &SplitVarnode, hiop: OpId, workishi: bool, fd: &mut Funcdata) -> Result<bool> {
        if !workishi {
            return Ok(false);
        }
        let Some((lo1, hi1)) = i.pieces() else { return Ok(false) };
        let hi2 = other_in(fd, hiop, hi1)?;
        let notequalformhi = code(fd, hiop) == IntNotequal;
        for loop_ in readers(fd, lo1) {
            let notequalformlo = match code(fd, loop_) {
                IntEqual => false,
                IntNotequal => true,
                _ => continue,
            };
            let lo2 = other_in(fd, loop_, lo1)?;
            for hibool in readers(fd, out(fd, hiop)?) {
                for lobool in readers(fd, out(fd, loop_)?) {
                    let mut in2 = SplitVarnode::default();
                    in2.init_partial(fd, i.wholesize, lo2, Some(hi2));
                    if in2.exceeds_const_precision() {
                        continue;
                    }
                    if code(fd, hibool) != Cbranch || code(fd, lobool) != Cbranch {
                        continue;
                    }
                    let mut in1 = i.clone();
                    let (hitrue, hifalse) = get_true_false(fd, hibool, notequalformhi);
                    let (lotrue, lofalse) = get_true_false(fd, lobool, notequalformlo);
                    if hitrue == parent(fd, lobool) && hifalse == lofalse && otherwise_empty(fd, lobool)? {
                        if prepare_bool_op(fd, &mut in1, &mut in2, hibool)? {
                            let opc = if notequalformhi { IntNotequal } else { IntEqual };
                            create_bool_op(fd, hibool, &mut in1, &mut in2, opc)?;
                            let c = fd.new_constant(1, if notequalformlo { 0 } else { 1 });
                            fd.op_set_input(lobool, c, 1)?;
                            return Ok(true);
                        }
                    } else if lotrue == parent(fd, hibool)
                        && hifalse == lofalse
                        && otherwise_empty(fd, hibool)?
                        && prepare_bool_op(fd, &mut in1, &mut in2, lobool)?
                    {
                        let opc = if notequalformlo { IntNotequal } else { IntEqual };
                        create_bool_op(fd, lobool, &mut in1, &mut in2, opc)?;
                        let c = fd.new_constant(1, if notequalformhi { 0 } else { 1 });
                        fd.op_set_input(hibool, c, 1)?;
                        return Ok(true);
                    }
                }
            }
        }
        Ok(false)
    }
}

/// `Equal2Form`: `hi1 == hi2 && lo1 == lo2` (or `!=` with `||`).
pub(super) struct Equal2Form;

impl Equal2Form {
    /// `Equal2Form::replace`: the second operand, when the whole comparison is feasible.
    fn replace(
        fd: &Funcdata,
        inv: &mut SplitVarnode,
        lo2: VarnodeId,
        hi2: VarnodeId,
        bool_and_or: OpId,
    ) -> Result<Option<SplitVarnode>> {
        let mut param2 = SplitVarnode::default();
        if is_const(fd, hi2) && is_const(fd, lo2) {
            let lo1 = inv.lo.ok_or_else(|| LowlevelError("Equal2Form without lo".into()))?;
            let val = shl(off(fd, hi2), (8 * sz(fd, lo1)) as i32) | off(fd, lo2);
            param2.init_constant(inv.wholesize, val);
        } else if is_const(fd, hi2) || is_const(fd, lo2) {
            return Ok(None); // mixed constant and non-constant
        } else {
            param2.init_partial(fd, inv.wholesize, lo2, Some(hi2));
        }
        Ok(prepare_bool_op(fd, inv, &mut param2, bool_and_or)?.then_some(param2))
    }

    /// `Equal2Form::applyRule`.
    pub(super) fn apply_rule(i: &SplitVarnode, op: OpId, workishi: bool, fd: &mut Funcdata) -> Result<bool> {
        if !workishi {
            return Ok(false);
        }
        let Some((lo1, hi1)) = i.pieces() else { return Ok(false) };
        let eq_code = code(fd, op);
        let hi2 = other_in(fd, op, hi1)?;
        let outvn = out(fd, op)?;
        for bool_and_or in readers(fd, outvn) {
            let want = if eq_code == IntEqual { BoolAnd } else { BoolOr };
            if matches!(eq_code, IntEqual | IntNotequal) && code(fd, bool_and_or) != want {
                continue;
            }
            let Some(equal_lo) = def_with(fd, other_in(fd, bool_and_or, outvn)?, eq_code) else { continue };
            let (e0, e1) = (inp(fd, equal_lo, 0)?, inp(fd, equal_lo, 1)?);
            let lo2 = if e0 == lo1 {
                e1
            } else if e1 == lo1 {
                e0
            } else {
                continue;
            };
            let mut inv = i.clone();
            let Some(mut param2) = Self::replace(fd, &mut inv, lo2, hi2, bool_and_or)? else { continue };
            if param2.exceeds_const_precision() {
                continue;
            }
            replace_bool_op(fd, bool_and_or, &mut inv, &mut param2, eq_code)?;
            return Ok(true);
        }
        Ok(false)
    }
}

/// `Equal3Form`: `(hi & lo) == -1` tests the whole against all ones.
pub(super) struct Equal3Form;

impl Equal3Form {
    /// `Equal3Form::verify`: the comparison op.
    fn verify(fd: &Funcdata, hi: VarnodeId, lo: VarnodeId, andop: OpId) -> Result<Option<OpId>> {
        if code(fd, andop) != IntAnd || other_in(fd, andop, hi)? != lo {
            return Ok(None);
        }
        let Some(compareop) = lone_descend(fd, out(fd, andop)?) else { return Ok(None) };
        if !matches!(code(fd, compareop), IntEqual | IntNotequal) {
            return Ok(None);
        }
        let smallc = inp(fd, compareop, 1)?;
        Ok((is_const(fd, smallc) && off(fd, smallc) == calc_mask(sz(fd, lo))).then_some(compareop))
    }

    /// `Equal3Form::applyRule`.
    pub(super) fn apply_rule(i: &SplitVarnode, op: OpId, workishi: bool, fd: &mut Funcdata) -> Result<bool> {
        if !workishi {
            return Ok(false);
        }
        let Some((lo, hi)) = i.pieces() else { return Ok(false) };
        let Some(compareop) = Self::verify(fd, hi, lo, op)? else { return Ok(false) };
        let mut inv = i.clone();
        let mut in2 = SplitVarnode::constant(i.wholesize, calc_mask(i.wholesize));
        if in2.exceeds_const_precision() || !prepare_bool_op(fd, &mut inv, &mut in2, compareop)? {
            return Ok(false);
        }
        let opc = code(fd, compareop);
        replace_bool_op(fd, compareop, &mut inv, &mut in2, opc)?;
        Ok(true)
    }
}

/// `ShiftForm`: a double-precision shift as shifts of the pieces combined with OR.
#[derive(Debug, Default)]
pub(super) struct ShiftForm {
    opc: Option<Opcode>,
    lo: Option<VarnodeId>,
    hi: Option<VarnodeId>,
    salo: Option<VarnodeId>,
    sahi: Option<VarnodeId>,
    samid: Option<VarnodeId>,
    reslo: Option<VarnodeId>,
    reshi: Option<VarnodeId>,
}

impl ShiftForm {
    /// A form with only the shift amounts set (unit tests of `verifyShiftAmount`).
    #[cfg(test)]
    pub(super) fn with_amounts(lo: VarnodeId, salo: VarnodeId, sahi: VarnodeId, samid: VarnodeId) -> ShiftForm {
        ShiftForm { lo: Some(lo), salo: Some(salo), sahi: Some(sahi), samid: Some(samid), ..Default::default() }
    }

    /// The two inputs of the OR-like op defining `vn`, written.
    fn or_inputs(fd: &Funcdata, vn: VarnodeId) -> Result<Option<(VarnodeId, VarnodeId)>> {
        let Some(orop) = def(fd, vn).filter(|&o| matches!(code(fd, o), IntOr | IntXor | IntAdd)) else {
            return Ok(None);
        };
        let (a, b) = (inp(fd, orop, 0)?, inp(fd, orop, 1)?);
        Ok((fd.vn(a).is_written() && fd.vn(b).is_written()).then_some((a, b)))
    }

    /// `ShiftForm::mapLeft`.
    fn map_left(&mut self, fd: &Funcdata) -> Result<bool> {
        let (Some(reslo), Some(reshi)) = (self.reslo, self.reshi) else { return Ok(false) };
        let Some(loshift) = def(fd, reslo) else { return Ok(false) };
        if !fd.vn(reshi).is_written() {
            return Ok(false);
        }
        self.opc = Some(code(fd, loshift));
        if code(fd, loshift) != IntLeft {
            return Ok(false);
        }
        let Some((mut midlo, mut midhi)) = Self::or_inputs(fd, reshi)? else { return Ok(false) };
        if def_with(fd, midhi, IntLeft).is_none() {
            std::mem::swap(&mut midlo, &mut midhi);
        }
        let (Some(midshift), Some(hishift)) = (def_with(fd, midlo, IntRight), def_with(fd, midhi, IntLeft)) else {
            return Ok(false);
        };
        if self.lo != Some(inp(fd, loshift, 0)?)
            || self.hi != Some(inp(fd, hishift, 0)?)
            || self.lo != Some(inp(fd, midshift, 0)?)
        {
            return Ok(false);
        }
        self.salo = Some(inp(fd, loshift, 1)?);
        self.sahi = Some(inp(fd, hishift, 1)?);
        self.samid = Some(inp(fd, midshift, 1)?);
        Ok(true)
    }

    /// `ShiftForm::mapRight`.
    fn map_right(&mut self, fd: &Funcdata) -> Result<bool> {
        let (Some(reslo), Some(reshi)) = (self.reslo, self.reshi) else { return Ok(false) };
        if !fd.vn(reslo).is_written() {
            return Ok(false);
        }
        let Some(hishift) = def(fd, reshi) else { return Ok(false) };
        let opc = code(fd, hishift);
        self.opc = Some(opc);
        if !matches!(opc, IntRight | IntSright) {
            return Ok(false);
        }
        let Some((mut midlo, mut midhi)) = Self::or_inputs(fd, reslo)? else { return Ok(false) };
        if def_with(fd, midlo, IntRight).is_none() {
            std::mem::swap(&mut midlo, &mut midhi);
        }
        let (Some(midshift), Some(loshift)) = (def_with(fd, midhi, IntLeft), def_with(fd, midlo, IntRight)) else {
            return Ok(false);
        };
        if self.lo != Some(inp(fd, loshift, 0)?)
            || self.hi != Some(inp(fd, hishift, 0)?)
            || self.hi != Some(inp(fd, midshift, 0)?)
        {
            return Ok(false);
        }
        self.salo = Some(inp(fd, loshift, 1)?);
        self.sahi = Some(inp(fd, hishift, 1)?);
        self.samid = Some(inp(fd, midshift, 1)?);
        Ok(true)
    }

    /// `ShiftForm::verifyShiftAmount`.
    pub(super) fn verify_shift_amount(&self, fd: &Funcdata) -> bool {
        let (Some(salo), Some(samid), Some(sahi), Some(lo)) = (self.salo, self.samid, self.sahi, self.lo) else {
            return false;
        };
        if !is_const(fd, salo) || !is_const(fd, samid) || !is_const(fd, sahi) {
            return false;
        }
        let val = off(fd, salo);
        let bits = 8 * u64::from(sz(fd, lo));
        val == off(fd, sahi) && val < bits && off(fd, samid) == bits - val
    }

    /// The loops of `verifyLeft` / `verifyRight`: a reader `first` of `start` with opcode
    /// `firstopc`, and a reader of its output whose output completes the form.
    fn search(&mut self, fd: &Funcdata, start: VarnodeId, firstopc: Opcode, left: bool) -> Result<bool> {
        for first in readers(fd, start) {
            if code(fd, first) != firstopc {
                continue;
            }
            for midshift in readers(fd, out(fd, first)?) {
                let Some(tmpvn) = fd.op(midshift).out else { continue };
                let mapped = if left {
                    self.reshi = Some(tmpvn);
                    self.map_left(fd)?
                } else {
                    self.reslo = Some(tmpvn);
                    self.map_right(fd)?
                };
                if mapped && self.verify_shift_amount(fd) {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// `ShiftForm::applyRuleLeft` (with `verifyLeft`) and `applyRuleRight` (with
    /// `verifyRight`): `op` is the shift of the low piece (left) or of the high piece (right).
    pub(super) fn apply_rule(
        i: &SplitVarnode,
        op: OpId,
        workishi: bool,
        fd: &mut Funcdata,
        left: bool,
    ) -> Result<bool> {
        if workishi == left {
            return Ok(false);
        }
        let Some((lo, hi)) = i.pieces() else { return Ok(false) };
        let mut f = ShiftForm { lo: Some(lo), hi: Some(hi), ..Default::default() };
        let found = if left {
            f.reslo = Some(out(fd, op)?);
            f.search(fd, hi, IntLeft, true)?
        } else {
            f.reshi = Some(out(fd, op)?);
            f.search(fd, lo, IntRight, false)?
        };
        if !found {
            return Ok(false);
        }
        let (Some(reslo), Some(salo), Some(opc)) = (f.reslo, f.salo, f.opc) else { return Ok(false) };
        let mut inv = i.clone();
        let mut outdoub = SplitVarnode::default();
        outdoub.init_partial(fd, i.wholesize, reslo, f.reshi);
        let Some(existop) = prepare_shift_op(fd, &mut outdoub, &mut inv)? else { return Ok(false) };
        create_shift_op(fd, &mut outdoub, &mut inv, salo, existop, opc)?;
        Ok(true)
    }
}

/// `MultForm`: the schoolbook double-precision multiply.
#[derive(Debug, Default)]
pub(super) struct MultForm {
    subhi: Option<OpId>,
    multlo: Option<OpId>,
    multhi1: Option<OpId>,
    multhi2: Option<OpId>,
    midtmp: Option<VarnodeId>,
    lo1zext: Option<VarnodeId>,
    lo2zext: Option<VarnodeId>,
    hi1: Option<VarnodeId>,
    lo1: Option<VarnodeId>,
    hi2: Option<VarnodeId>,
    lo2: Option<VarnodeId>,
    reslo: Option<VarnodeId>,
    reshi: Option<VarnodeId>,
}

/// A missing piece of a matched form.
fn gone() -> LowlevelError {
    LowlevelError("MultForm: unset piece".into())
}

impl MultForm {
    /// The tail of `mapResHi` / `mapResHiSmallConst`: the low multiply behind `subhi`.
    fn map_mult_lo(&mut self, fd: &Funcdata) -> Result<bool> {
        let subhi = self.subhi.ok_or_else(gone)?;
        let midtmp = inp(fd, subhi, 0)?;
        self.midtmp = Some(midtmp);
        let Some(multlo) = def_with(fd, midtmp, IntMult) else { return Ok(false) };
        self.multlo = Some(multlo);
        self.lo1zext = Some(inp(fd, multlo, 0)?);
        self.lo2zext = Some(inp(fd, multlo, 1)?);
        Ok(true)
    }

    /// `MultForm::mapResHiSmallConst`.
    fn map_res_hi_small_const(&mut self, fd: &Funcdata, rhi: VarnodeId) -> Result<bool> {
        self.reshi = Some(rhi);
        let Some(add1) = def_with(fd, rhi, IntAdd) else { return Ok(false) };
        let (Some(d1), Some(d2)) = (def(fd, inp(fd, add1, 0)?), def(fd, inp(fd, add1, 1)?)) else { return Ok(false) };
        let (multhi1, subhi) = if code(fd, d1) != IntMult { (d2, d1) } else { (d1, d2) };
        self.multhi1 = Some(multhi1);
        self.subhi = Some(subhi);
        if code(fd, multhi1) != IntMult || code(fd, subhi) != Subpiece {
            return Ok(false);
        }
        self.map_mult_lo(fd)
    }

    /// `MultForm::mapResHi`.
    fn map_res_hi(&mut self, fd: &Funcdata, rhi: VarnodeId) -> Result<bool> {
        self.reshi = Some(rhi);
        let Some(add1) = def_with(fd, rhi, IntAdd) else { return Ok(false) };
        let (mut ad1, mut ad2) = (inp(fd, add1, 0)?, inp(fd, add1, 1)?);
        let (Some(d1), Some(d2)) = (def(fd, ad1), def(fd, ad2)) else { return Ok(false) };
        let ad3;
        if code(fd, d1) == IntAdd {
            ad1 = inp(fd, d1, 0)?;
            ad3 = inp(fd, d1, 1)?;
        } else {
            if code(fd, d2) != IntAdd {
                return Ok(false);
            }
            ad2 = inp(fd, d2, 0)?;
            ad3 = inp(fd, d2, 1)?;
        }
        let (Some(o1), Some(o2), Some(o3)) = (def(fd, ad1), def(fd, ad2), def(fd, ad3)) else { return Ok(false) };
        let (subhi, m1, m2) = if code(fd, o1) == Subpiece {
            (o1, o2, o3)
        } else if code(fd, o2) == Subpiece {
            (o2, o1, o3)
        } else if code(fd, o3) == Subpiece {
            (o3, o1, o2)
        } else {
            return Ok(false);
        };
        self.subhi = Some(subhi);
        self.multhi1 = Some(m1);
        self.multhi2 = Some(m2);
        if code(fd, m1) != IntMult || code(fd, m2) != IntMult {
            return Ok(false);
        }
        self.map_mult_lo(fd)
    }

    /// The other input of `op` when one of them is `vn`.
    fn other_of(fd: &Funcdata, op: OpId, vn: Option<VarnodeId>) -> Result<Option<VarnodeId>> {
        let (v1, v2) = (inp(fd, op, 0)?, inp(fd, op, 1)?);
        Ok(if Some(v1) == vn {
            Some(v2)
        } else if Some(v2) == vn {
            Some(v1)
        } else {
            None
        })
    }

    /// `MultForm::findLoFromInSmallConst`.
    fn find_lo_from_in_small_const(&mut self, fd: &Funcdata) -> Result<bool> {
        let Some(lo2) = Self::other_of(fd, self.multhi1.ok_or_else(gone)?, self.hi1)? else { return Ok(false) };
        self.lo2 = Some(lo2);
        if !is_const(fd, lo2) {
            return Ok(false);
        }
        self.hi2 = None;
        Ok(true)
    }

    /// `MultForm::findLoFromIn`.
    fn find_lo_from_in(&mut self, fd: &Funcdata) -> Result<bool> {
        let m1 = self.multhi1.ok_or_else(gone)?;
        if Self::other_of(fd, m1, self.lo1)?.is_none() {
            std::mem::swap(&mut self.multhi1, &mut self.multhi2);
        }
        let Some(hi2) = Self::other_of(fd, self.multhi1.ok_or_else(gone)?, self.lo1)? else { return Ok(false) };
        self.hi2 = Some(hi2);
        let Some(lo2) = Self::other_of(fd, self.multhi2.ok_or_else(gone)?, self.hi1)? else { return Ok(false) };
        self.lo2 = Some(lo2);
        Ok(true)
    }

    /// `MultForm::zextOf`.
    fn zext_of(fd: &Funcdata, big: VarnodeId, small: VarnodeId) -> Result<bool> {
        if is_const(fd, small) {
            return Ok(is_const(fd, big) && off(fd, big) == off(fd, small));
        }
        let Some(op) = def(fd, big) else { return Ok(false) };
        match code(fd, op) {
            IntZext => Ok(inp(fd, op, 0)? == small),
            IntAnd => {
                let c = inp(fd, op, 1)?;
                if !is_const(fd, c) || off(fd, c) != calc_mask(sz(fd, small)) {
                    return Ok(false);
                }
                let whole = inp(fd, op, 0)?;
                let Some(sub) = def_with(fd, small, Subpiece) else { return Ok(false) };
                Ok(inp(fd, sub, 0)? == whole)
            }
            _ => Ok(false),
        }
    }

    /// `MultForm::verifyLo`.
    fn verify_lo(&self, fd: &Funcdata) -> Result<bool> {
        let (lo1, lo2) = (self.lo1.ok_or_else(gone)?, self.lo2.ok_or_else(gone)?);
        let (z1, z2) = (self.lo1zext.ok_or_else(gone)?, self.lo2zext.ok_or_else(gone)?);
        if off(fd, inp(fd, self.subhi.ok_or_else(gone)?, 1)?) != u64::from(sz(fd, lo1)) {
            return Ok(false);
        }
        if Self::zext_of(fd, z1, lo1)? {
            return Self::zext_of(fd, z2, lo2);
        }
        if Self::zext_of(fd, z1, lo2)? {
            return Self::zext_of(fd, z2, lo1);
        }
        Ok(false)
    }

    /// `MultForm::findResLo`.
    fn find_res_lo(&mut self, fd: &Funcdata) -> Result<bool> {
        let (lo1, lo2) = (self.lo1.ok_or_else(gone)?, self.lo2.ok_or_else(gone)?);
        for op in readers(fd, self.midtmp.ok_or_else(gone)?) {
            if code(fd, op) != Subpiece || off(fd, inp(fd, op, 1)?) != 0 {
                continue;
            }
            let reslo = out(fd, op)?;
            self.reslo = Some(reslo);
            if sz(fd, reslo) != sz(fd, lo1) {
                continue;
            }
            return Ok(true);
        }
        for op in readers(fd, lo1) {
            if code(fd, op) != IntMult {
                continue;
            }
            let (vn1, vn2) = (inp(fd, op, 0)?, inp(fd, op, 1)?);
            let matches = if is_const(fd, lo2) {
                const_match(fd, vn1, off(fd, lo2)) || const_match(fd, vn2, off(fd, lo2))
            } else {
                vn1 == lo2 || vn2 == lo2
            };
            if !matches {
                continue;
            }
            self.reslo = Some(out(fd, op)?);
            return Ok(true);
        }
        Ok(false)
    }

    /// `MultForm::mapFromIn`.
    fn map_from_in(&mut self, fd: &Funcdata, rhi: VarnodeId) -> Result<bool> {
        Ok(self.map_res_hi(fd, rhi)? && self.find_lo_from_in(fd)? && self.verify_lo(fd)? && self.find_res_lo(fd)?)
    }

    /// `MultForm::mapFromInSmallConst`.
    fn map_from_in_small_const(&mut self, fd: &Funcdata, rhi: VarnodeId) -> Result<bool> {
        Ok(self.map_res_hi_small_const(fd, rhi)?
            && self.find_lo_from_in_small_const(fd)?
            && self.verify_lo(fd)?
            && self.find_res_lo(fd)?)
    }

    /// `MultForm::verify`.
    fn verify(&mut self, fd: &Funcdata, hop: OpId) -> Result<bool> {
        for add1 in readers(fd, out(fd, hop)?) {
            if code(fd, add1) != IntAdd {
                continue;
            }
            let add1out = out(fd, add1)?;
            for add2 in readers(fd, add1out) {
                if code(fd, add2) == IntAdd && self.map_from_in(fd, out(fd, add2)?)? {
                    return Ok(true);
                }
            }
            if self.map_from_in(fd, add1out)? || self.map_from_in_small_const(fd, add1out)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// `MultForm::applyRule` (with `replace`).
    pub(super) fn apply_rule(i: &SplitVarnode, hop: OpId, workishi: bool, fd: &mut Funcdata) -> Result<bool> {
        if !workishi {
            return Ok(false);
        }
        let Some((lo, hi)) = i.pieces() else { return Ok(false) };
        let mut f = MultForm { hi1: Some(hi), lo1: Some(lo), ..Default::default() };
        if !f.verify(fd, hop)? {
            return Ok(false);
        }
        apply_binary(fd, i, f.lo2, f.hi2, f.reslo, f.reshi, IntMult)
    }
}

/// `PhiForm`: MULTIEQUALs of the pieces in the same block.
pub(super) struct PhiForm;

impl PhiForm {
    /// `PhiForm::verify`: the MULTIEQUAL of the low pieces.
    fn verify(fd: &Funcdata, hibase: VarnodeId, lobase: VarnodeId, hiphi: OpId) -> Result<Option<OpId>> {
        let inslot = slot(fd, hiphi, hibase)?;
        if fd.vn(out(fd, hiphi)?).descend.is_empty() {
            return Ok(None);
        }
        let blbase = parent(fd, hiphi);
        for lophi in readers(fd, lobase) {
            if code(fd, lophi) == Multiequal
                && parent(fd, lophi) == blbase
                && fd.op(lophi).ins.get(inslot) == Some(&lobase)
            {
                return Ok(Some(lophi));
            }
        }
        Ok(None)
    }

    /// `PhiForm::applyRule`.
    pub(super) fn apply_rule(i: &SplitVarnode, hiphi: OpId, workishi: bool, fd: &mut Funcdata) -> Result<bool> {
        if !workishi {
            return Ok(false);
        }
        let Some((lo, hi)) = i.pieces() else { return Ok(false) };
        let Some(lophi) = Self::verify(fd, hi, lo, hiphi)? else { return Ok(false) };
        let mut inlist = Vec::new();
        for j in 0..fd.op(hiphi).ins.len() {
            inlist.push(SplitVarnode::from_pieces(fd, inp(fd, lophi, j)?, inp(fd, hiphi, j)?));
        }
        let mut outvn = SplitVarnode::default();
        outvn.init_partial(fd, i.wholesize, out(fd, lophi)?, Some(out(fd, hiphi)?));
        let Some(existop) = prepare_phi_op(fd, &outvn, &mut inlist)? else { return Ok(false) };
        create_phi_op(fd, &mut outvn, &mut inlist, existop)?;
        Ok(true)
    }
}

/// `IndirectForm`: INDIRECTs of both pieces caused by the same op.
pub(super) struct IndirectForm;

impl IndirectForm {
    /// Whether `vn` is in the unique space (`IPTR_INTERNAL`).
    fn is_internal(fd: &Funcdata, vn: VarnodeId) -> bool {
        fd.uniq.is_some_and(|u| fd.vn(vn).space == Space::Sleigh(u))
    }

    /// `IndirectForm::verify`: (affector, reslo, reshi).
    fn verify(fd: &Funcdata, lo: VarnodeId, indhi: OpId) -> Result<Option<(OpId, VarnodeId, VarnodeId)>> {
        let Some(affector) = fd.iop_target(inp(fd, indhi, 1)?) else { return Ok(None) };
        if fd.op(affector).is_dead() {
            return Ok(None);
        }
        let reshi = out(fd, indhi)?;
        if Self::is_internal(fd, reshi) {
            return Ok(None); // a unique varnode should not be an INDIRECT output
        }
        for indlo in readers(fd, lo) {
            if code(fd, indlo) != Indirect || fd.iop_target(inp(fd, indlo, 1)?) != Some(affector) {
                continue;
            }
            let reslo = out(fd, indlo)?;
            if Self::is_internal(fd, reslo) {
                return Ok(None);
            }
            let tied = |v: VarnodeId| fd.vn(v).flags.has(VnFlags::ADDRTIED);
            if (tied(reslo) || tied(reshi)) && is_addr_tied_contiguous(fd, reslo, reshi).is_none() {
                return Ok(None);
            }
            return Ok(Some((affector, reslo, reshi)));
        }
        Ok(None)
    }

    /// `IndirectForm::applyRule`.
    pub(super) fn apply_rule(i: &SplitVarnode, ind: OpId, workishi: bool, fd: &mut Funcdata) -> Result<bool> {
        if !workishi {
            return Ok(false);
        }
        let Some((lo, _)) = i.pieces() else { return Ok(false) };
        let Some((affector, reslo, reshi)) = Self::verify(fd, lo, ind)? else { return Ok(false) };
        let mut inv = i.clone();
        let mut outvn = SplitVarnode::default();
        outvn.init_partial(fd, i.wholesize, reslo, Some(reshi));
        if !inv.is_whole_feasible(fd, affector)? {
            return Ok(false); // prepareIndirectOp
        }
        replace_indirect_op(fd, &mut outvn, &mut inv, affector)?;
        Ok(true)
    }
}

/// `CopyForceForm`: address-forced COPYs of both pieces into contiguous storage.
pub(super) struct CopyForceForm;

impl CopyForceForm {
    /// Whether `vn` is address-forced and unread.
    fn forced_unread(fd: &Funcdata, vn: VarnodeId) -> bool {
        fd.vn(vn).flags.has(VnFlags::ADDRFORCE) && fd.vn(vn).descend.is_empty()
    }

    /// `CopyForceForm::verify`: (copylo, the storage address).
    fn verify(
        fd: &Funcdata,
        h: VarnodeId,
        l: VarnodeId,
        w: VarnodeId,
        copyhi: OpId,
    ) -> Result<Option<(OpId, (Space, u64))>> {
        if inp(fd, copyhi, 0)? != h {
            return Ok(None);
        }
        let reshi = out(fd, copyhi)?;
        if !Self::forced_unread(fd, reshi) {
            return Ok(None);
        }
        for copylo in readers(fd, l) {
            if code(fd, copylo) != Copy || parent(fd, copylo) != parent(fd, copyhi) {
                continue;
            }
            let reslo = out(fd, copylo)?;
            if !Self::forced_unread(fd, reslo) {
                continue;
            }
            let Some(addr_out) = is_addr_tied_contiguous(fd, reslo, reshi) else { continue };
            if fd.op(copyhi).flags.has(OpFlags::RETURN_COPY) && !Self::return_form_ok(fd, h, l, w, addr_out) {
                continue;
            }
            return Ok(Some((copylo, addr_out)));
        }
        Ok(None)
    }

    /// The return-copy conditions of `CopyForceForm::verify`.
    fn return_form_ok(fd: &Funcdata, h: VarnodeId, l: VarnodeId, w: VarnodeId, addr_out: (Space, u64)) -> bool {
        if lone_descend(fd, h).is_none() || lone_descend(fd, l).is_none() {
            return false;
        }
        if (fd.vn(w).space, fd.vn(w).offset) == addr_out {
            return true;
        }
        let (Some(other_lo), Some(other_hi)) = (def(fd, l), def(fd, h)) else { return false };
        code(fd, other_lo) == Copy && code(fd, other_hi) == Copy && parent(fd, other_lo) == parent(fd, other_hi)
    }

    /// `CopyForceForm::applyRule`.
    pub(super) fn apply_rule(i: &SplitVarnode, cpy: OpId, workishi: bool, fd: &mut Funcdata) -> Result<bool> {
        if !workishi {
            return Ok(false);
        }
        let Some((lo, hi)) = i.pieces() else { return Ok(false) };
        let Some(w) = i.whole else { return Ok(false) };
        let Some((copylo, addr_out)) = Self::verify(fd, hi, lo, w, cpy)? else { return Ok(false) };
        replace_copy_force(fd, addr_out, i, copylo, cpy)?;
        Ok(true)
    }
}
