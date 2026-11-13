//! Port of `SubfloatFlow` and `RuleSubfloatConvert` (subflow.cc, group `floatprecision`), with
//! the encoding conversion of `FloatFormat` (float.cc) they need: a float value carried in a
//! wider format (an x87 10-byte register, a double) whose data-flow never needs more than the
//! precision it came in with is rewritten at that precision. In its own file, not with
//! `SubvariableFlow` (`subflow.rs`), so the two ports do not touch the same file.
//!
//! The varnode and op marks of the trace are sets in the trace, not flags.

use std::collections::{HashMap, HashSet};

use super::op::OpId;
use super::opcode::Opcode::{self, *};
use super::transform::{TVarId, TransformManager};
use super::varnode::{VarnodeId, VnFlags};
use super::{err, Arch, Funcdata, LowlevelError, Result};

/// The IEEE formats of `FloatFormat` the x86 translator has (`setDefaultFloatFormats`: sizes 4
/// and 8 only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FloatFormat {
    signbit_pos: u32,
    frac_size: i32,
    exp_pos: u32,
    exp_size: u32,
    bias: i32,
    maxexponent: i32,
}

impl FloatFormat {
    /// `Translate::getFloatFormat`.
    pub(crate) fn of(size: u32) -> Option<FloatFormat> {
        match size {
            4 => Some(FloatFormat {
                signbit_pos: 31,
                frac_size: 23,
                exp_pos: 23,
                exp_size: 8,
                bias: 127,
                maxexponent: 255,
            }),
            8 => Some(FloatFormat {
                signbit_pos: 63,
                frac_size: 52,
                exp_pos: 52,
                exp_size: 11,
                bias: 1023,
                maxexponent: 2047,
            }),
            _ => None,
        }
    }

    fn extract_fractional_code(&self, x: u64) -> u64 {
        x << (64 - self.frac_size)
    }

    fn extract_sign(&self, x: u64) -> bool {
        (x >> self.signbit_pos) & 1 != 0
    }

    fn extract_exponent_code(&self, x: u64) -> i32 {
        ((x >> self.exp_pos) & ((1u64 << self.exp_size) - 1)) as i32
    }

    fn set_fractional_code(&self, x: u64, code: u64) -> u64 {
        x | (code >> (64 - self.frac_size))
    }

    fn set_sign(&self, x: u64, sign: bool) -> u64 {
        if sign {
            x | 1u64 << self.signbit_pos
        } else {
            x
        }
    }

    fn set_exponent_code(&self, x: u64, code: u64) -> u64 {
        x | code << self.exp_pos
    }

    fn zero_encoding(&self, sgn: bool) -> u64 {
        self.set_sign(0, sgn)
    }

    fn infinity_encoding(&self, sgn: bool) -> u64 {
        self.set_sign(self.set_exponent_code(0, self.maxexponent as u64), sgn)
    }

    fn nan_encoding(&self, sgn: bool) -> u64 {
        let res = self.set_fractional_code(0, 1u64 << 63);
        self.set_sign(self.set_exponent_code(res, self.maxexponent as u64), sgn)
    }

    /// Port of `FloatFormat::roundToNearestEven`.
    fn round_to_nearest_even(signif: &mut u64, lowbitpos: i32) -> bool {
        let lowbitmask = if lowbitpos < 64 { 1u64 << lowbitpos } else { 0 };
        let midbitmask = 1u64.wrapping_shl((lowbitpos - 1) as u32);
        let epsmask = midbitmask.wrapping_sub(1);
        let odd = *signif & lowbitmask != 0;
        if *signif & midbitmask != 0 && (*signif & epsmask != 0 || odd) {
            *signif = signif.wrapping_add(midbitmask);
            return true;
        }
        false
    }

    /// Port of `FloatFormat::convertEncoding`: `encoding` in `formin` re-encoded in this format
    /// (both IEEE with an implied j-bit).
    pub(crate) fn convert_encoding(&self, encoding: u64, formin: &FloatFormat) -> u64 {
        let sgn = formin.extract_sign(encoding);
        let mut signif = formin.extract_fractional_code(encoding);
        let mut exp = formin.extract_exponent_code(encoding);
        if exp == formin.maxexponent {
            return if signif != 0 { self.nan_encoding(sgn) } else { self.infinity_encoding(sgn) };
        }
        if exp == 0 {
            if signif == 0 {
                return self.zero_encoding(sgn);
            }
            let lz = signif.leading_zeros();
            signif <<= lz;
            exp = -formin.bias - lz as i32;
        } else {
            exp -= formin.bias;
            signif = 1u64 << 63 | signif >> 1;
        }
        exp += self.bias;
        if exp < -self.frac_size {
            return self.zero_encoding(sgn);
        }
        if exp < 1 {
            if Self::round_to_nearest_even(&mut signif, 64 - self.frac_size - exp) && signif >> 63 == 0 {
                signif = 1u64 << 63;
                exp += 1;
            }
            return self.set_fractional_code(self.zero_encoding(sgn), signif >> (-exp));
        }
        if Self::round_to_nearest_even(&mut signif, 64 - self.frac_size - 1) && signif >> 63 == 0 {
            signif = 1u64 << 63;
            exp += 1;
        }
        if exp >= self.maxexponent {
            return self.infinity_encoding(sgn);
        }
        if exp != 0 {
            signif <<= 1;
        }
        let res = self.set_exponent_code(self.set_fractional_code(0, signif), exp as u64);
        self.set_sign(res, sgn)
    }
}

/// `SubfloatFlow::State`: an op on the `maxPrecision` walk.
struct State {
    op: OpId,
    slot: usize,
    max_precision: u32,
}

impl State {
    fn incorporate(&mut self, sz: u32) {
        self.max_precision = self.max_precision.max(sz);
    }
}

/// The ops whose output precision is the largest of their inputs' (`maxPrecision`'s first case).
fn passes_precision(opc: Opcode) -> bool {
    matches!(opc, Multiequal | FloatNeg | FloatAbs | FloatSqrt | FloatCeil | FloatFloor | FloatRound | Copy)
}

fn is_float_arith(opc: Opcode) -> bool {
    matches!(opc, FloatAdd | FloatSub | FloatMult | FloatDiv)
}

/// Port of `SubfloatFlow`.
struct SubfloatFlow<'a> {
    fd: &'a Funcdata,
    arch: &'a Arch,
    tm: TransformManager,
    precision: u32,
    terminator_count: i32,
    format: Option<FloatFormat>,
    worklist: Vec<TVarId>,
    max_precision_map: HashMap<OpId, u32>,
    /// the varnodes seen (`Varnode::setMark`)
    marks: HashSet<VarnodeId>,
}

impl<'a> SubfloatFlow<'a> {
    /// Port of `SubfloatFlow::SubfloatFlow`.
    fn new(fd: &'a Funcdata, arch: &'a Arch, root: VarnodeId, precision: u32) -> Result<SubfloatFlow<'a>> {
        let mut flow = SubfloatFlow {
            fd,
            arch,
            tm: TransformManager::default(),
            precision,
            terminator_count: 0,
            format: FloatFormat::of(precision),
            worklist: Vec::new(),
            max_precision_map: HashMap::new(),
            marks: HashSet::new(),
        };
        if flow.format.is_some() {
            flow.set_replacement(root)?;
        }
        Ok(flow)
    }

    fn def(&self, vn: VarnodeId) -> Option<OpId> {
        self.fd.vn(vn).def
    }

    /// Port of `SubfloatFlow::maxPrecision`: the most bytes of precision reaching `vn`, 0 when a
    /// binary float op is in the way (checked separately).
    fn max_precision(&mut self, vn: VarnodeId) -> Result<u32> {
        let fd = self.fd;
        let size = fd.vn(vn).size;
        let Some(op) = self.def(vn) else { return Ok(size) };
        let opc = fd.op(op).opc;
        if is_float_arith(opc) {
            return Ok(0);
        }
        if matches!(opc, FloatFloat2float | FloatInt2float) {
            return Ok(fd.vn(fd.input(op, 0)?).size.min(size));
        }
        if !passes_precision(opc) {
            return Ok(size);
        }
        if let Some(&p) = self.max_precision_map.get(&op) {
            return Ok(p);
        }
        let mut op_marks = HashSet::from([op]);
        let mut stack = vec![State { op, slot: 0, max_precision: 0 }];
        let mut max = 0;
        while let Some(state) = stack.last_mut() {
            let ins = &fd.op(state.op).ins;
            let Some(&next_vn) = ins.get(state.slot) else {
                max = state.max_precision;
                op_marks.remove(&state.op);
                self.max_precision_map.insert(state.op, max);
                stack.pop();
                if let Some(top) = stack.last_mut() {
                    top.incorporate(max);
                }
                continue;
            };
            state.slot += 1;
            let next_size = fd.vn(next_vn).size;
            let Some(next_op) = self.def(next_vn) else {
                state.incorporate(next_size);
                continue;
            };
            if op_marks.contains(&next_op) {
                continue; // the cycle edge
            }
            let nopc = fd.op(next_op).opc;
            if passes_precision(nopc) {
                match self.max_precision_map.get(&next_op) {
                    Some(&p) => state.incorporate(p),
                    None => {
                        op_marks.insert(next_op);
                        stack.push(State { op: next_op, slot: 0, max_precision: 0 });
                    }
                }
            } else if matches!(nopc, FloatFloat2float | FloatInt2float) {
                state.incorporate(fd.vn(fd.input(next_op, 0)?).size.min(next_size));
            } else if !is_float_arith(nopc) {
                state.incorporate(next_size);
            }
        }
        Ok(max)
    }

    /// Port of `SubfloatFlow::exceedsPrecision`.
    fn exceeds_precision(&mut self, op: OpId) -> Result<bool> {
        let val1 = self.max_precision(self.fd.input(op, 0)?)?;
        let val2 = self.max_precision(self.fd.input(op, 1)?)?;
        Ok(val1.min(val2) > self.precision)
    }

    /// Port of `SubfloatFlow::setReplacement`: `None` is the C++ null (abort).
    fn set_replacement(&mut self, vn: VarnodeId) -> Result<Option<TVarId>> {
        let fd = self.fd;
        let bits = self.precision * 8;
        let v = fd.vn(vn);
        if self.marks.contains(&vn) {
            return self.tm.get_piece(vn, bits, 0, v.is_input()).map(Some);
        }
        if v.is_constant() {
            let (Some(form2), Some(format)) = (FloatFormat::of(v.size), self.format) else { return Ok(None) };
            return Ok(Some(self.tm.new_constant(self.precision, format.convert_encoding(v.offset, &form2))));
        }
        if v.is_free() || (v.has(VnFlags::ADDRFORCE) && v.size != self.precision) {
            return Ok(None);
        }
        // a locked varnode without a recorded type has the default one, of its own size
        // (no partial-structure metatype is ported)
        if v.has(VnFlags::TYPELOCK) && v.ty.map_or(v.size, |t| self.arch.types.size(t)) != self.precision {
            return Ok(None);
        }
        if v.is_input() && v.size != self.precision {
            return Ok(None);
        }
        self.marks.insert(vn);
        if v.size == self.precision {
            return Ok(Some(self.tm.new_preexisting_varnode(fd, vn)));
        }
        // SubfloatFlow::preserveAddress: only an input keeps its storage
        let res = self.tm.new_piece(vn, bits, 0, v.is_input());
        self.worklist.push(res);
        Ok(Some(res))
    }

    /// `PcodeOp::getRepeatSlot`: the slot of the `count`-th read of `vn` by `op`, where `before`
    /// is the part of `vn`'s descendant list ahead of the current read.
    fn repeat_slot(&self, op: OpId, vn: VarnodeId, first: usize, before: &[OpId]) -> Result<usize> {
        let count = 1 + before.iter().filter(|&&o| o == op).count();
        if count == 1 {
            return Ok(first);
        }
        let ins = &self.fd.op(op).ins;
        let mut recount = 1;
        for (i, &v) in ins.iter().enumerate().skip(first + 1) {
            if v == vn {
                recount += 1;
                if recount == count {
                    return Ok(i);
                }
            }
        }
        err("getRepeatSlot: no repeated slot")
    }

    fn slot(&self, op: OpId, vn: VarnodeId) -> Result<usize> {
        self.fd.slot_of(op, vn).ok_or_else(|| LowlevelError("descendant does not read its varnode".into()))
    }

    /// Port of `SubfloatFlow::traceForward`.
    fn trace_forward(&mut self, rvn: TVarId) -> Result<bool> {
        let fd = self.fd;
        let Some(vn) = self.tm.original(rvn) else { return err("subfloat placeholder without varnode") };
        let desc = fd.vn(vn).descend.to_vec();
        for (idx, &op) in desc.iter().enumerate() {
            let o = fd.op(op);
            if o.out.is_some_and(|out| self.marks.contains(&out)) {
                continue;
            }
            let opc = o.opc;
            match opc {
                FloatAdd | FloatSub | FloatMult | FloatDiv | Multiequal | Copy | FloatCeil | FloatFloor
                | FloatRound | FloatNeg | FloatAbs | FloatSqrt => {
                    if is_float_arith(opc) && self.exceeds_precision(op)? {
                        return Ok(false);
                    }
                    let rop = self.tm.new_op_replace(o.ins.len(), opc, op);
                    let Some(outvn) = o.out else { return err("float op without output") };
                    let Some(outrvn) = self.set_replacement(outvn)? else { return Ok(false) };
                    self.tm.set_input(rop, rvn, self.slot(op, vn)?)?;
                    self.tm.set_output(rop, outrvn)?;
                }
                FloatFloat2float => {
                    let Some(outvn) = o.out else { return err("float op without output") };
                    let outsize = fd.vn(outvn).size;
                    if outsize < self.precision {
                        return Ok(false);
                    }
                    let nopc = if outsize == self.precision { Copy } else { FloatFloat2float };
                    let rop = self.tm.new_preexisting_op(1, nopc, op);
                    self.tm.set_input(rop, rvn, 0)?;
                    self.terminator_count += 1;
                }
                FloatEqual | FloatNotequal | FloatLess | FloatLessequal => {
                    if self.exceeds_precision(op)? {
                        return Ok(false);
                    }
                    let mut slot = self.slot(op, vn)?;
                    let Some(rvn2) = self.set_replacement(fd.input(op, 1 - slot.min(1))?)? else { return Ok(false) };
                    if rvn == rvn2 {
                        slot = self.repeat_slot(op, vn, slot, &desc[..idx])?;
                    }
                    if self.tm.preexisting_guard(slot, rvn2) {
                        let rop = self.tm.new_preexisting_op(2, opc, op);
                        self.tm.set_input(rop, rvn, slot)?;
                        self.tm.set_input(rop, rvn2, 1 - slot.min(1))?;
                        self.terminator_count += 1;
                    }
                }
                FloatTrunc | FloatNan => {
                    let rop = self.tm.new_preexisting_op(1, opc, op);
                    self.tm.set_input(rop, rvn, 0)?;
                    self.terminator_count += 1;
                }
                _ => return Ok(false),
            }
        }
        Ok(true)
    }

    /// Port of `SubfloatFlow::traceBackward`.
    fn trace_backward(&mut self, rvn: TVarId) -> Result<bool> {
        let fd = self.fd;
        let Some(vn) = self.tm.original(rvn) else { return err("subfloat placeholder without varnode") };
        let Some(op) = self.def(vn) else { return Ok(true) };
        let o = fd.op(op);
        match o.opc {
            FloatAdd | FloatSub | FloatMult | FloatDiv | Copy | FloatCeil | FloatFloor | FloatRound | FloatNeg
            | FloatAbs | FloatSqrt | Multiequal => {
                if is_float_arith(o.opc) && self.exceeds_precision(op)? {
                    return Ok(false);
                }
                let rop = match self.tm.var_def(rvn) {
                    Some(rop) => rop,
                    None => {
                        let rop = self.tm.new_op_replace(o.ins.len(), o.opc, op);
                        self.tm.set_output(rop, rvn)?;
                        rop
                    }
                };
                for (i, &invn) in o.ins.iter().enumerate() {
                    if self.tm.op_input(rop, i).is_none() {
                        let Some(newvar) = self.set_replacement(invn)? else { return Ok(false) };
                        self.tm.set_input(rop, newvar, i)?;
                    }
                }
                Ok(true)
            }
            FloatInt2float => {
                let invn = fd.input(op, 0)?;
                let v = fd.vn(invn);
                if !v.is_constant() && v.is_free() {
                    return Ok(false);
                }
                let rop = self.tm.new_op_replace(1, FloatInt2float, op);
                self.tm.set_output(rop, rvn)?;
                let newvar = self.tm.get_preexisting_varnode(fd, invn);
                self.tm.set_input(rop, newvar, 0)?;
                Ok(true)
            }
            FloatFloat2float => {
                let invn = fd.input(op, 0)?;
                let v = fd.vn(invn);
                let (opc, newvar) = if v.is_constant() {
                    let newvar = if v.size == self.precision {
                        self.tm.new_constant(self.precision, v.offset)
                    } else {
                        match self.set_replacement(invn)? {
                            Some(nv) => nv,
                            None => return Ok(false), // unsupported float format
                        }
                    };
                    (Copy, newvar)
                } else {
                    if v.is_free() {
                        return Ok(false);
                    }
                    let opc = if v.size == self.precision { Copy } else { FloatFloat2float };
                    (opc, self.tm.get_preexisting_varnode(fd, invn))
                };
                let rop = self.tm.new_op_replace(1, opc, op);
                self.tm.set_output(rop, rvn)?;
                self.tm.set_input(rop, newvar, 0)?;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    /// Port of `SubfloatFlow::doTrace` (`processNextWork` inlined).
    fn do_trace(&mut self) -> Result<bool> {
        if self.format.is_none() {
            return Ok(false);
        }
        self.terminator_count = 0;
        let mut retval = true;
        while let Some(rvn) = self.worklist.pop() {
            if !self.trace_backward(rvn)? || !self.trace_forward(rvn)? {
                retval = false;
                break;
            }
        }
        self.marks.clear();
        Ok(retval && self.terminator_count != 0)
    }
}

/// Port of `RuleSubfloatConvert::applyOp` (FLOAT_FLOAT2FLOAT).
pub(crate) fn subfloat_convert(fd: &mut Funcdata, op: OpId, arch: &Arch) -> Result<i32> {
    let invn = fd.input(op, 0)?;
    let Some(outvn) = fd.op(op).out else { return err("FLOAT2FLOAT without output") };
    let (insize, outsize) = (fd.vn(invn).size, fd.vn(outvn).size);
    let (root, precision) = if outsize > insize { (outvn, insize) } else { (invn, outsize) };
    let tm = {
        let mut flow = SubfloatFlow::new(fd, arch, root, precision)?;
        if !flow.do_trace()? {
            return Ok(0);
        }
        flow.tm
    };
    tm.apply(fd, arch)?;
    Ok(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn convert_encoding_table() {
        let (f4, f8) = (FloatFormat::of(4).unwrap(), FloatFormat::of(8).unwrap());
        // (to, from, input, expected)
        let cases: &[(&FloatFormat, &FloatFormat, u64, u64)] = &[
            (&f8, &f4, 0x3f80_0000, 0x3ff0_0000_0000_0000), // 1.0f -> 1.0
            (&f8, &f4, 0xc020_0000, 0xc004_0000_0000_0000), // -2.5f
            (&f4, &f8, 0x3fb9_9999_9999_999a, 0x3dcc_cccd), // 0.1 rounds to nearest
            (&f4, &f8, 0x3ff0_0000_1000_0000, 0x3f80_0000), // a tie rounds to even
            (&f4, &f8, 0x7e37_e43c_8800_759c, 0x7f80_0000), // 1e300 overflows to inf
            (&f4, &f8, 0x8000_0000_0000_0000, 0x8000_0000), // -0
            (&f4, &f8, 0x7ff8_0000_0000_0001, 0x7fc0_0000), // NaN: the quiet NaN
            (&f8, &f4, 0xff80_0000, 0xfff0_0000_0000_0000), // -inf
            (&f8, &f4, 0x0000_0001, 0x36a0_0000_0000_0000), // smallest single denormal
            (&f4, &f8, 0x3800_0000_0000_0000, 0x0040_0000), // 2^-127: a single denormal
            (&f4, &f8, 0x0000_0000_0000_0001, 0x0000_0000), // too small: zero
        ];
        for &(to, from, enc, want) in cases {
            assert_eq!(to.convert_encoding(enc, from), want, "{enc:#x}");
        }
    }
}
