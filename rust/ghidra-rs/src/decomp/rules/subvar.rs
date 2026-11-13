//! The rules of group `subvar` that shrink or split a varnode along its data-flow:
//! `RuleSubvarAnd`, `RuleSubvarSubpiece`, `RuleSplitFlow`, `RuleSubvarCompZero`,
//! `RuleSubvarShift`, `RuleSubvarZext`, `RuleSubvarSext` (subflow.cc), on
//! [`SubvariableFlow`] and [`SplitFlow`].
//!
//! `Varnode::isPtrFlow` is false everywhere: only `RulePtrFlow` (not ported, switched off in
//! the checks) and locked pointer parameters of a truncated space (none on x86) set it. So is
//! `Architecture::aggressive_ext_trim`: `CompilerSpec::parse` rejects a `.cspec` with
//! `<aggressivetrim>` (mips64, AARCH64 ilp32, ...; no x86 one has it), so `RuleSubvarSext`
//! cannot run non-aggressively where Ghidra is aggressive. No trace here is aggressive.

use super::*;
use crate::decomp::rangeutil::leastsigbit_set;
use crate::decomp::splitflow::SplitFlow;
use crate::decomp::subflow::{FlowKind, SubvariableFlow};

/// The tail of every `RuleSubvar*`: trace the bits `mask` of `vn` and, if they are a logical
/// value, rebuild the flow on it. `sext`: the value is sign-extended into its containers;
/// `big`: it may be 8 bytes.
fn shrink(fd: &mut Funcdata, arch: &Arch, vn: VarnodeId, mask: u64, sext: bool, big: bool) -> Result<i32> {
    let kind = FlowKind { aggressive: false, sext, big };
    match SubvariableFlow::new(fd, arch, vn, mask, kind)?.do_trace()? {
        Some(replacement) => {
            replacement.apply(fd, arch)?;
            Ok(1)
        }
        None => Ok(0),
    }
}

/// Port of `RuleSubvarAnd`: `V & mask`, all of it consumed, where the mask is one bit or the
/// low bytes.
pub(super) fn subvar_and(fd: &mut Funcdata, op: OpId, arch: &Arch) -> Result<i32> {
    let c = inp(fd, op, 1)?;
    if !is_const(fd, c) {
        return Ok(0);
    }
    let vn = inp(fd, op, 0)?;
    let outvn = out(fd, op)?;
    let consume = fd.vn(outvn).consume;
    if consume != fd.vn(c).offset || consume & 1 == 0 {
        return Ok(0);
    }
    let mut cmask = 1;
    if consume != 1 {
        cmask = calc_mask(fd.vn(vn).size) >> 8;
        while cmask != 0 && cmask != consume {
            cmask >>= 8;
        }
    }
    if cmask == 0 || fd.vn(outvn).descend.is_empty() {
        return Ok(0);
    }
    shrink(fd, arch, vn, cmask, false, false)
}

/// Port of `RuleSubvarSubpiece`: a SUBPIECE of a varnode consumed nowhere else.
pub(super) fn subvar_subpiece(fd: &mut Funcdata, op: OpId, arch: &Arch) -> Result<i32> {
    let vn = inp(fd, op, 0)?;
    let outvn = out(fd, op)?;
    let flowsize = fd.vn(outvn).size;
    let sa = int4(fd, inp(fd, op, 1)?);
    // the mask must fit in the precision. A negative offset (never on a real SUBPIECE) is
    // refused here; the C++ refuses it only when `flowsize + sa` wraps and else shifts by a
    // negative amount, which is undefined
    if !(0..=8 - i64::from(flowsize)).contains(&sa) {
        return Ok(0);
    }
    let mask = calc_mask(flowsize) << (8 * sa);
    let v = fd.vn(vn);
    if v.consume & mask != v.consume || fd.vn(outvn).descend.is_empty() {
        return Ok(0);
    }
    let big = flowsize >= 8 && v.is_input() && lone_descend(fd, vn) == Some(op);
    shrink(fd, arch, vn, mask, false, big)
}

/// The piece of `RuleSplitFlow` that looks for the PIECE making `vn`, through INDIRECTs and
/// one MULTIEQUAL (a PIECE that directly defines `vn` does not count).
fn concat_of(fd: &Funcdata, vn: VarnodeId) -> Result<Option<OpId>> {
    let Some(first) = def(fd, vn) else { return Ok(None) };
    let mut multi = first;
    while fd.op(multi).opc == Indirect {
        let Some(d) = def(fd, inp(fd, multi, 0)?) else { return Ok(None) };
        multi = d;
    }
    Ok(match fd.op(multi).opc {
        Piece => (multi != first).then_some(multi),
        Multiequal => ins(fd, multi).iter().filter_map(|&i| def_with(fd, i, Piece)).next(),
        _ => None,
    })
}

/// Port of `RuleSplitFlow`: a SUBPIECE taking the high part of a varnode concatenated from
/// that part and a low one.
pub(super) fn split_flow(fd: &mut Funcdata, op: OpId, arch: &Arch) -> Result<i32> {
    let lo_size = int4(fd, inp(fd, op, 1)?);
    let vn = inp(fd, op, 0)?;
    if lo_size == 0 || i64::from(fd.vn(out(fd, op)?).size) + lo_size != i64::from(fd.vn(vn).size) {
        return Ok(0);
    }
    let Some(concat) = concat_of(fd, vn)? else { return Ok(0) };
    if i64::from(fd.vn(inp(fd, concat, 1)?).size) != lo_size {
        return Ok(0);
    }
    match SplitFlow::new(fd, vn, lo_size as u32)?.do_trace()? {
        Some(tm) => {
            tm.apply(fd, arch)?;
            Ok(1)
        }
        None => Ok(0),
    }
}

/// Port of `RuleSubvarCompZero`: a comparison of a varnode with one possible non-zero bit
/// against 0 or that bit.
pub(super) fn subvar_comp_zero(fd: &mut Funcdata, op: OpId, arch: &Arch) -> Result<i32> {
    let c = inp(fd, op, 1)?;
    if !is_const(fd, c) {
        return Ok(0);
    }
    let vn = inp(fd, op, 0)?;
    let mask = fd.nzmask(vn);
    let bitnum = leastsigbit_set(mask);
    if bitnum == -1 || mask >> bitnum != 1 {
        return Ok(0);
    }
    let cval = fd.vn(c).offset;
    if (cval != mask && cval != 0) || fd.vn(out(fd, op)?).descend.is_empty() {
        return Ok(0);
    }
    if let Some(andop) = def(fd, vn) {
        let Some(&vn0) = ins(fd, andop).first() else { return Ok(0) };
        if matches!(fd.op(andop).opc, IntAnd | IntOr | IntRight) {
            // not when the flag is cut from a value with 8 or more live bits
            let v0 = fd.vn(vn0);
            let wholemask = calc_mask(v0.size) & v0.consume & fd.nzmask(vn0);
            if v0.is_constant() || wholemask.count_ones() >= 8 {
                return Ok(0);
            }
        }
    }
    shrink(fd, arch, vn, mask, false, false)
}

/// Port of `RuleSubvarShift`: a right shift pulling the one possible non-zero bit out of a
/// byte.
pub(super) fn subvar_shift(fd: &mut Funcdata, op: OpId, arch: &Arch) -> Result<i32> {
    let vn = inp(fd, op, 0)?;
    let c = inp(fd, op, 1)?;
    if fd.vn(vn).size != 1 || !is_const(fd, c) {
        return Ok(0);
    }
    let sa = fd.vn(c).offset as u32; // wraps as the C++ shift does on x86
    let mask = fd.nzmask(vn);
    if mask.wrapping_shr(sa) != 1 || fd.vn(out(fd, op)?).descend.is_empty() {
        return Ok(0);
    }
    shrink(fd, arch, vn, mask.wrapping_shr(sa).wrapping_shl(sa), false, false)
}

/// Port of `RuleSubvarZext` and `RuleSubvarSext`: the output of an extension carries the
/// extended value as a logical one.
pub(super) fn subvar_ext(fd: &mut Funcdata, op: OpId, arch: &Arch) -> Result<i32> {
    let mask = calc_mask(fd.vn(inp(fd, op, 0)?).size);
    let sext = fd.op(op).opc == IntSext;
    shrink(fd, arch, out(fd, op)?, mask, sext, false)
}
