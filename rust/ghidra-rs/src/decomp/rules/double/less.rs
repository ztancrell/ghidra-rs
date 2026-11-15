//! The double-precision comparison forms of double.cc: `LessThreeWay` (three branches: high
//! less, high equal, low less) and `LessConstForm` (the high piece against a constant).

use super::split::*;
use super::*;

/// `LessThreeWay`: its members (the C++ names).
#[derive(Debug, Default)]
pub(super) struct LessThreeWay {
    inv: SplitVarnode,
    in2: SplitVarnode,
    hilessbl: Option<BlockId>,
    lolessbl: Option<BlockId>,
    hieqbl: Option<BlockId>,
    hilessbool: Option<OpId>,
    lolessbool: Option<OpId>,
    hieqbool: Option<OpId>,
    hiless: Option<OpId>,
    hiequal: Option<OpId>,
    loless: Option<OpId>,
    vnhil1: Option<VarnodeId>,
    vnhil2: Option<VarnodeId>,
    vnhie1: Option<VarnodeId>,
    vnhie2: Option<VarnodeId>,
    vnlo1: Option<VarnodeId>,
    vnlo2: Option<VarnodeId>,
    hi2: Option<VarnodeId>,
    lo2: Option<VarnodeId>,
    hislot: usize,
    hiflip: bool,
    equalflip: bool,
    loflip: bool,
    lolessiszerocomp: bool,
    lolessequalform: bool,
    hilessequalform: bool,
    signcompare: bool,
    midlessform: bool,
    midlessequal: bool,
    midsigncompare: bool,
    hiconstform: bool,
    midconstform: bool,
    loconstform: bool,
    hival: u64,
    midval: u64,
    loval: u64,
    finalopc: Option<Opcode>,
}

/// An unset member of a matched `LessThreeWay`.
fn unset() -> LowlevelError {
    LowlevelError("LessThreeWay: unset member".into())
}

impl LessThreeWay {
    fn losize(&self, fd: &Funcdata) -> Result<u32> {
        Ok(sz(fd, self.inv.lo.ok_or_else(unset)?))
    }

    /// `LessThreeWay::mapBlocksFromLow`.
    fn map_blocks_from_low(&mut self, fd: &Funcdata, lobl: BlockId) -> bool {
        let g = &fd.blocks;
        self.lolessbl = Some(lobl);
        let b = g.block(lobl);
        if b.ins.len() != 1 || b.outs.len() != 2 {
            return false;
        }
        let hieqbl = b.ins[0].point;
        self.hieqbl = Some(hieqbl);
        let b = g.block(hieqbl);
        if b.ins.len() != 1 || b.outs.len() != 2 {
            return false;
        }
        let hilessbl = b.ins[0].point;
        self.hilessbl = Some(hilessbl);
        g.block(hilessbl).outs.len() == 2
    }

    /// The CBRANCH ending `bl` and the op making its condition.
    fn branch_of(fd: &Funcdata, bl: Option<BlockId>) -> Result<Option<(OpId, OpId)>> {
        let Some(&last) = bl.and_then(|b| fd.blocks.block(b).ops.last()) else { return Ok(None) };
        if code(fd, last) != Cbranch {
            return Ok(None);
        }
        Ok(def(fd, inp(fd, last, 1)?).map(|d| (last, d)))
    }

    /// `LessThreeWay::mapOpsFromBlocks`.
    fn map_ops_from_blocks(&mut self, fd: &Funcdata) -> Result<bool> {
        let Some(&lb) = self.lolessbl.and_then(|b| fd.blocks.block(b).ops.last()) else { return Ok(false) };
        if code(fd, lb) != Cbranch {
            return Ok(false);
        }
        self.lolessbool = Some(lb);
        let (Some(_), Some(_)) = (Self::last_cbranch(fd, self.hieqbl), Self::last_cbranch(fd, self.hilessbl)) else {
            return Ok(false);
        };
        self.hiflip = false;
        self.equalflip = false;
        self.loflip = false;
        self.midlessform = false;
        self.lolessiszerocomp = false;
        let Some((hieqbool, hiequal)) = Self::branch_of(fd, self.hieqbl)? else { return Ok(false) };
        self.hieqbool = Some(hieqbool);
        self.hiequal = Some(hiequal);
        if !self.set_mid_form(code(fd, hiequal)) {
            return Ok(false);
        }
        let Some((_, loless)) = Self::branch_of(fd, self.lolessbl)? else { return Ok(false) };
        self.loless = Some(loless);
        if !self.set_lo_form(fd, loless)? {
            return Ok(false);
        }
        let Some((hilessbool, hiless)) = Self::branch_of(fd, self.hilessbl)? else { return Ok(false) };
        self.hilessbool = Some(hilessbool);
        self.hiless = Some(hiless);
        let (eq, sign) = match code(fd, hiless) {
            IntLess => (false, false),
            IntLessequal => (true, false),
            IntSless => (false, true),
            IntSlessequal => (true, true),
            _ => return Ok(false),
        };
        self.hilessequalform = eq;
        self.signcompare = sign;
        Ok(true)
    }

    /// The last op of `bl` when it is a CBRANCH.
    fn last_cbranch(fd: &Funcdata, bl: Option<BlockId>) -> Option<OpId> {
        bl.and_then(|b| fd.blocks.block(b).ops.last().copied()).filter(|&o| code(fd, o) == Cbranch)
    }

    /// The `hiequal` switch of `mapOpsFromBlocks`.
    fn set_mid_form(&mut self, opc: Opcode) -> bool {
        let (eq, sign) = match opc {
            IntEqual | IntNotequal => {
                self.midlessform = false;
                return true;
            }
            IntLess => (false, false),
            IntLessequal => (true, false),
            IntSless => (false, true),
            IntSlessequal => (true, true),
            _ => return false,
        };
        self.midlessequal = eq;
        self.midsigncompare = sign;
        self.midlessform = true;
        true
    }

    /// The `loless` switch of `mapOpsFromBlocks`.
    fn set_lo_form(&mut self, fd: &Funcdata, loless: OpId) -> Result<bool> {
        match code(fd, loless) {
            IntLess => self.lolessequalform = false,
            IntLessequal => self.lolessequalform = true,
            opc @ (IntEqual | IntNotequal) => {
                if !const_match(fd, inp(fd, loless, 1)?, 0) {
                    return Ok(false);
                }
                self.lolessiszerocomp = true;
                self.lolessequalform = opc == IntEqual;
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    /// `LessThreeWay::checkSignedness`.
    fn check_signedness(&self) -> bool {
        !self.midlessform || self.midsigncompare == self.signcompare
    }

    /// `LessThreeWay::normalizeHi`.
    fn normalize_hi(&mut self, fd: &Funcdata) -> Result<bool> {
        let hiless = self.hiless.ok_or_else(unset)?;
        let (mut v1, mut v2) = (inp(fd, hiless, 0)?, inp(fd, hiless, 1)?);
        if is_const(fd, v1) {
            self.hiflip = !self.hiflip;
            self.hilessequalform = !self.hilessequalform;
            std::mem::swap(&mut v1, &mut v2);
        }
        self.hiconstform = false;
        if is_const(fd, v2) {
            if self.inv.wholesize > 8 {
                return Ok(false); // must have a constant that fits in precision
            }
            self.hiconstform = true;
            self.hival = off(fd, v2);
            let (_, hilessfalse) = get_true_false(fd, self.hilessbool.ok_or_else(unset)?, self.hiflip);
            let mut inc = 1u64;
            if hilessfalse != self.hieqbl {
                self.hiflip = !self.hiflip;
                self.hilessequalform = !self.hilessequalform;
                std::mem::swap(&mut v1, &mut v2);
                inc = u64::MAX; // -1
            }
            if self.hilessequalform {
                self.hival = self.hival.wrapping_add(inc) & calc_mask(self.inv.wholesize);
                self.hilessequalform = false;
            }
            self.hival = shr(self.hival, (self.losize(fd)? * 8) as i32);
        } else if self.hilessequalform {
            self.hilessequalform = false;
            self.hiflip = !self.hiflip;
            std::mem::swap(&mut v1, &mut v2);
        }
        self.vnhil1 = Some(v1);
        self.vnhil2 = Some(v2);
        Ok(true)
    }

    /// `LessThreeWay::normalizeMid`.
    fn normalize_mid(&mut self, fd: &Funcdata) -> Result<bool> {
        let hiequal = self.hiequal.ok_or_else(unset)?;
        let (mut v1, mut v2) = (inp(fd, hiequal, 0)?, inp(fd, hiequal, 1)?);
        if is_const(fd, v1) {
            std::mem::swap(&mut v1, &mut v2);
            if self.midlessform {
                self.equalflip = !self.equalflip;
                self.midlessequal = !self.midlessequal;
            }
        }
        self.vnhie1 = Some(v1);
        self.vnhie2 = Some(v2);
        self.midconstform = false;
        if is_const(fd, v2) {
            if !self.hiconstform {
                return Ok(false); // if mid is constant, both mid and hi must be constant
            }
            self.midconstform = true;
            self.midval = off(fd, v2);
            let losize = self.losize(fd)?;
            if sz(fd, v2) == self.inv.wholesize {
                let lopart = self.midval & calc_mask(losize);
                self.midval = shr(self.midval, (losize * 8) as i32);
                if !self.midlessform {
                    return Ok(false);
                }
                let want = if self.midlessequal { calc_mask(losize) } else { 0 };
                if lopart != want {
                    return Ok(false);
                }
            }
            if self.midval != self.hival {
                if !self.midlessform {
                    return Ok(false);
                }
                let inc = if self.midlessequal { 1 } else { u64::MAX };
                self.midval = self.midval.wrapping_add(inc) & calc_mask(losize);
                self.midlessequal = !self.midlessequal;
                if self.midval != self.hival {
                    return Ok(false);
                }
            }
        }
        if self.midlessform {
            if !self.midlessequal {
                self.equalflip = !self.equalflip;
            }
        } else if code(fd, hiequal) == IntNotequal {
            self.equalflip = !self.equalflip;
        }
        Ok(true)
    }

    /// `LessThreeWay::normalizeLo`.
    fn normalize_lo(&mut self, fd: &Funcdata) -> Result<bool> {
        let loless = self.loless.ok_or_else(unset)?;
        let (mut v1, mut v2) = (inp(fd, loless, 0)?, inp(fd, loless, 1)?);
        self.vnlo1 = Some(v1);
        self.vnlo2 = Some(v2);
        if self.lolessiszerocomp {
            self.loconstform = true;
            if self.lolessequalform {
                self.lolessequalform = false; // lo == 0 is lo < 1
            } else {
                self.loflip = !self.loflip; // lo != 0 is !(lo < 1)
            }
            self.loval = 1;
            return Ok(true);
        }
        if is_const(fd, v1) {
            self.loflip = !self.loflip;
            self.lolessequalform = !self.lolessequalform;
            std::mem::swap(&mut v1, &mut v2);
        }
        self.loconstform = false;
        if is_const(fd, v2) {
            self.loconstform = true;
            self.loval = off(fd, v2);
            if self.lolessequalform {
                self.loval = self.loval.wrapping_add(1) & calc_mask(sz(fd, v2));
                self.lolessequalform = false;
            }
        } else if self.lolessequalform {
            self.lolessequalform = false;
            self.loflip = !self.loflip;
            std::mem::swap(&mut v1, &mut v2);
        }
        self.vnlo1 = Some(v1);
        self.vnlo2 = Some(v2);
        Ok(true)
    }

    /// `LessThreeWay::checkBlockForm`.
    fn check_block_form(&self, fd: &Funcdata) -> Result<bool> {
        let (hb, lb, eb) =
            (self.hilessbool.ok_or_else(unset)?, self.lolessbool.ok_or_else(unset)?, self.hieqbool.ok_or_else(unset)?);
        let (hilesstrue, hilessfalse) = get_true_false(fd, hb, self.hiflip);
        let (lolesstrue, lolessfalse) = get_true_false(fd, lb, self.loflip);
        let (hieqtrue, hieqfalse) = get_true_false(fd, eb, self.equalflip);
        if hilesstrue == lolesstrue
            && hieqfalse == lolessfalse
            && hilessfalse == self.hieqbl
            && hieqtrue == self.lolessbl
        {
            return Ok(otherwise_empty(fd, eb)? && otherwise_empty(fd, lb)?);
        }
        Ok(false)
    }

    /// Swaps the low comparison's operands so that `lo` is operand `want` (`checkOpForm`).
    fn orient_lo(&mut self, lo: VarnodeId, want_first: bool) -> bool {
        let at = |s: &Self| if want_first { s.vnlo1 } else { s.vnlo2 };
        if at(self) != Some(lo) {
            std::mem::swap(&mut self.vnlo1, &mut self.vnlo2);
            if at(self) != Some(lo) {
                return false;
            }
            self.loflip = !self.loflip;
            self.lolessequalform = !self.lolessequalform;
        }
        true
    }

    /// `LessThreeWay::checkOpForm`.
    fn check_op_form(&mut self, fd: &Funcdata) -> Result<bool> {
        let lo = self.inv.lo.ok_or_else(unset)?;
        let hi = self.inv.hi;
        let (hil1, hil2) = (self.vnhil1.ok_or_else(unset)?, self.vnhil2.ok_or_else(unset)?);
        let (hie1, hie2) = (self.vnhie1, self.vnhie2.ok_or_else(unset)?);
        if self.midconstform {
            if !self.hiconstform {
                return Ok(false);
            }
            if sz(fd, hie2) == self.inv.wholesize {
                if hie1 != Some(hil1) && hie1 != Some(hil2) {
                    return Ok(false);
                }
            } else if hie1 != hi {
                return Ok(false);
            }
        } else {
            if Some(hil1) != hie1 && hil1 != hie2 {
                return Ok(false);
            }
            if Some(hil2) != hie1 && hil2 != hie2 {
                return Ok(false);
            }
        }
        if hi.is_some() && hi == Some(hil1) {
            if self.hiconstform {
                return Ok(false);
            }
            self.hislot = 0;
            self.hi2 = Some(hil2);
            if !self.orient_lo(lo, true) {
                return Ok(false);
            }
            self.lo2 = self.vnlo2;
        } else if hi.is_some() && hi == Some(hil2) {
            if self.hiconstform {
                return Ok(false);
            }
            self.hislot = 1;
            self.hi2 = Some(hil1);
            if !self.orient_lo(lo, false) {
                return Ok(false);
            }
            self.lo2 = self.vnlo1;
        } else if self.inv.whole == Some(hil1) {
            if !self.hiconstform || !self.loconstform || self.vnlo1 != Some(lo) {
                return Ok(false);
            }
            self.hislot = 0;
        } else if self.inv.whole == Some(hil2) {
            if !self.hiconstform || !self.loconstform {
                return Ok(false);
            }
            if self.vnlo2 != Some(lo) {
                self.loflip = !self.loflip;
                self.loval = self.loval.wrapping_sub(1) & calc_mask(sz(fd, lo));
                if self.vnlo1 != Some(lo) {
                    return Ok(false);
                }
            }
            self.hislot = 1;
        } else {
            return Ok(false);
        }
        Ok(true)
    }

    /// `LessThreeWay::setOpCode`.
    fn set_op_code(&mut self) {
        self.finalopc = Some(match (self.lolessequalform != self.hiflip, self.signcompare) {
            (true, true) => IntSlessequal,
            (true, false) => IntLessequal,
            (false, true) => IntSless,
            (false, false) => IntLess,
        });
        if self.hiflip {
            self.hislot = 1 - self.hislot;
            self.hiflip = false;
        }
    }

    /// `LessThreeWay::setBoolOp`.
    fn set_bool_op(&mut self, fd: &Funcdata) -> Result<bool> {
        let hb = self.hilessbool.ok_or_else(unset)?;
        if self.hislot == 0 {
            prepare_bool_op(fd, &mut self.inv, &mut self.in2, hb)
        } else {
            prepare_bool_op(fd, &mut self.in2, &mut self.inv, hb)
        }
    }

    /// `LessThreeWay::mapFromLow`.
    fn map_from_low(&mut self, fd: &Funcdata, op: OpId) -> Result<bool> {
        let Some(loop_) = lone_descend(fd, out(fd, op)?) else { return Ok(false) };
        let Some(bl) = parent(fd, loop_) else { return Ok(false) };
        Ok(self.map_blocks_from_low(fd, bl)
            && self.map_ops_from_blocks(fd)?
            && self.check_signedness()
            && self.normalize_hi(fd)?
            && self.normalize_mid(fd)?
            && self.normalize_lo(fd)?
            && self.check_op_form(fd)?
            && self.check_block_form(fd)?)
    }

    /// `LessThreeWay::testReplace`.
    fn test_replace(&mut self, fd: &Funcdata) -> Result<bool> {
        self.set_op_code();
        if self.hiconstform {
            let val = shl(self.hival, (8 * self.losize(fd)?) as i32) | self.loval;
            self.in2.init_constant(self.inv.wholesize, val);
        } else {
            let lo2 = self.lo2.ok_or_else(unset)?;
            self.in2.init_partial(fd, self.inv.wholesize, lo2, self.hi2);
        }
        self.set_bool_op(fd)
    }

    /// `LessThreeWay::applyRule`.
    pub(super) fn apply_rule(i: &SplitVarnode, loop_: OpId, workishi: bool, fd: &mut Funcdata) -> Result<bool> {
        if workishi || i.lo.is_none() {
            return Ok(false);
        }
        let mut f = LessThreeWay { inv: i.clone(), ..Default::default() };
        if !f.map_from_low(fd, loop_)? {
            return Ok(false);
        }
        let res = f.test_replace(fd)?;
        if res {
            if f.in2.exceeds_const_precision() {
                return Ok(false);
            }
            let (hb, eb, opc) =
                (f.hilessbool.ok_or_else(unset)?, f.hieqbool.ok_or_else(unset)?, f.finalopc.ok_or_else(unset)?);
            if f.hislot == 0 {
                create_bool_op(fd, hb, &mut f.inv, &mut f.in2, opc)?;
            } else {
                create_bool_op(fd, hb, &mut f.in2, &mut f.inv, opc)?;
            }
            let c = fd.new_constant(1, u64::from(f.equalflip));
            fd.op_set_input(eb, c, 1)?;
        }
        Ok(res)
    }
}

/// `LessConstForm`: the high piece compared with a constant decides the whole comparison.
pub(super) struct LessConstForm;

impl LessConstForm {
    /// `LessConstForm::applyRule`.
    pub(super) fn apply_rule(i: &SplitVarnode, op: OpId, workishi: bool, fd: &mut Funcdata) -> Result<bool> {
        if !workishi {
            return Ok(false);
        }
        let Some(vn) = i.hi else { return Ok(false) };
        let inslot = slot(fd, op, vn)?.min(1);
        let cvn = inp(fd, op, 1 - inslot)?;
        let losize = i.wholesize.wrapping_sub(sz(fd, vn));
        if !is_const(fd, cvn) {
            return Ok(false);
        }
        let opc = code(fd, op);
        let hilessequalform = matches!(opc, IntSlessequal | IntLessequal);
        let mut val = shl(off(fd, cvn), (8 * losize) as i32);
        if hilessequalform != (inslot == 1) {
            val |= calc_mask(losize);
        }
        let Some(desc) = lone_descend(fd, out(fd, op)?) else { return Ok(false) };
        if code(fd, desc) != Cbranch {
            return Ok(false);
        }
        let mut constin = SplitVarnode::constant(i.wholesize, val);
        if constin.exceeds_const_precision() {
            return Ok(false);
        }
        let mut inv = i.clone();
        let (a, b) = if inslot == 0 { (&mut inv, &mut constin) } else { (&mut constin, &mut inv) };
        if prepare_bool_op(fd, a, b, op)? {
            replace_bool_op(fd, op, a, b, opc)?;
            return Ok(true);
        }
        Ok(false)
    }
}
