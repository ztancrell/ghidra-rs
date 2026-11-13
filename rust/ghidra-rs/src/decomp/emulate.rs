//! P-code emulation over a function's data flow, as jump-table recovery uses it: the integer and
//! boolean op behaviors of opbehavior.cc (`evaluateUnary`/`evaluateBinary`), the dispatch of
//! `Emulate::executeCurrentOp` (emulate.cc) and `EmulatePcodeOp` (emulateutil.cc), with the
//! jump-table `EmulateFunction` (jumptable.cc) on top.
//!
//! Not ported: `memstate.cc` and the rest of emulate.cc (memory banks, break tables, the
//! p-code cache emulator). `EmulateFunction` keeps its values per varnode and its STORE is a
//! no-op (as `EmulatePcodeOp::executeStore`), so no memory state is needed. Float ops fail the
//! emulation (`opbehavior.cc` evaluates them through `FloatFormat`, not ported; no switch
//! calculation in the corpora uses one).

use super::op::OpId;
use super::opcode::Opcode;
use super::rangeutil::calc_mask;
use super::varnode::VarnodeId;
use super::{Arch, Funcdata};
use std::collections::HashMap;

/// Why an emulation stopped: `DataUnavailError` (memory not in the image) or any other
/// `LowlevelError`.
#[derive(Debug)]
pub(crate) enum EmuError {
    DataUnavail,
    Other(String),
}

fn sext(v: u64, size: u32) -> i64 {
    let sh = 64 - 8 * size.min(8);
    ((v << sh) as i64) >> sh
}

/// `OpBehavior::evaluateUnary` for `opc`.
pub(crate) fn eval_unary(opc: Opcode, sizeout: u32, sizein: u32, in1: u64) -> Result<u64, EmuError> {
    let m = calc_mask(sizeout);
    Ok(match opc {
        Opcode::Copy | Opcode::IntZext => in1,
        Opcode::IntSext => (sext(in1, sizein) as u64) & m,
        Opcode::Int2comp => in1.wrapping_neg() & m,
        Opcode::IntNegate => !in1 & m,
        Opcode::BoolNegate => in1 ^ 1,
        Opcode::Popcount => u64::from(in1.count_ones()),
        Opcode::Lzcount => u64::from((in1 & calc_mask(sizein)).leading_zeros() - (64 - 8 * sizein.min(8))),
        _ => return Err(EmuError::Other(format!("Unsupported op in emulation: {opc:?}"))),
    })
}

/// `OpBehavior::evaluateBinary` for `opc`.
pub(crate) fn eval_binary(opc: Opcode, sizeout: u32, sizein: u32, in1: u64, in2: u64) -> Result<u64, EmuError> {
    let m = calc_mask(sizeout);
    let mi = calc_mask(sizein);
    let div0 = || EmuError::Other("Divide by 0".into());
    Ok(match opc {
        Opcode::IntEqual => (in1 == in2) as u64,
        Opcode::IntNotequal => (in1 != in2) as u64,
        Opcode::IntSless => (sext(in1, sizein) < sext(in2, sizein)) as u64,
        Opcode::IntSlessequal => (sext(in1, sizein) <= sext(in2, sizein)) as u64,
        Opcode::IntLess => (in1 < in2) as u64,
        Opcode::IntLessequal => (in1 <= in2) as u64,
        Opcode::IntAdd => in1.wrapping_add(in2) & m,
        Opcode::IntSub => in1.wrapping_sub(in2) & m,
        Opcode::IntCarry => (in1 > (in1.wrapping_add(in2) & mi)) as u64,
        Opcode::IntScarry => {
            let res = in1.wrapping_add(in2);
            let top = 8 * sizein - 1;
            let (a, b, r) = ((in1 >> top) & 1, (in2 >> top) & 1, (res >> top) & 1);
            (a == b && r != a) as u64
        }
        Opcode::IntSborrow => {
            let res = in1.wrapping_sub(in2);
            let top = 8 * sizein - 1;
            let (a, b, r) = ((in1 >> top) & 1, (in2 >> top) & 1, (res >> top) & 1);
            (a != b && r != a) as u64
        }
        Opcode::IntXor | Opcode::BoolXor => in1 ^ in2,
        Opcode::IntAnd | Opcode::BoolAnd => in1 & in2,
        Opcode::IntOr | Opcode::BoolOr => in1 | in2,
        Opcode::IntLeft => {
            if in2 >= u64::from(sizeout) * 8 {
                0
            } else {
                (in1 << in2) & m
            }
        }
        Opcode::IntRight => {
            if in2 >= u64::from(sizeout) * 8 {
                0
            } else {
                (in1 >> in2) & m
            }
        }
        Opcode::IntSright => {
            if in2 >= 8 * u64::from(sizein) {
                if sext(in1, sizein) < 0 {
                    m
                } else {
                    0
                }
            } else {
                ((sext(in1, sizein) >> in2) as u64) & m
            }
        }
        Opcode::IntMult => in1.wrapping_mul(in2) & m,
        Opcode::IntDiv => in1.checked_div(in2).ok_or_else(div0)? & m,
        Opcode::IntRem => in1.checked_rem(in2).ok_or_else(div0)? & m,
        Opcode::IntSdiv => {
            if in2 == 0 {
                return Err(div0());
            }
            (sext(in1, sizein).wrapping_div(sext(in2, sizein)) as u64) & m
        }
        Opcode::IntSrem => {
            if in2 == 0 {
                return Err(div0());
            }
            (sext(in1, sizein).wrapping_rem(sext(in2, sizein)) as u64) & m
        }
        Opcode::Piece => {
            let sh = u64::from(sizeout - sizein) * 8;
            (if sh >= 64 { 0 } else { in1 << sh }) | in2
        }
        Opcode::Subpiece => {
            if in2 >= 8 {
                0
            } else {
                (in1 >> (in2 * 8)) & m
            }
        }
        _ => return Err(EmuError::Other(format!("Unsupported op in emulation: {opc:?}"))),
    })
}

/// Port of `EmulateFunction` (and the `EmulatePcodeOp` it extends): executes ops of a
/// function's data flow, keeping a value per varnode.
pub(crate) struct EmulateFunction<'a> {
    fd: &'a Funcdata,
    arch: &'a Arch,
    values: HashMap<VarnodeId, u64>,
    last_op: Option<OpId>,
}

impl<'a> EmulateFunction<'a> {
    pub(crate) fn new(fd: &'a Funcdata, arch: &'a Arch) -> EmulateFunction<'a> {
        EmulateFunction { fd, arch, values: HashMap::new(), last_op: None }
    }

    /// `EmulatePcodeOp::getLoadImageValue`: `size` bytes (little endian) read as 8 through
    /// `loadFill`. As the C++ loader, it reads the offset whatever the space.
    fn load_image_value(&self, off: u64, size: u32) -> Result<u64, EmuError> {
        let mut buf = [0u8; 8];
        self.arch.fill_bytes(off, &mut buf).ok_or(EmuError::DataUnavail)?;
        Ok(u64::from_le_bytes(buf) & calc_mask(size))
    }

    /// `getVarnodeValue`
    pub(crate) fn get(&self, vn: VarnodeId) -> Result<u64, EmuError> {
        let v = self.fd.vn(vn);
        if v.is_constant() {
            return Ok(v.offset);
        }
        if let Some(&x) = self.values.get(&vn) {
            return Ok(x);
        }
        self.load_image_value(v.offset, v.size)
    }

    /// `setVarnodeValue`
    pub(crate) fn set(&mut self, vn: VarnodeId, val: u64) {
        self.values.insert(vn, val);
    }

    /// `Emulate::executeCurrentOp` with `EmulateFunction`'s overrides: calls are skipped,
    /// branches fail, STORE does nothing.
    pub(crate) fn execute(&mut self, op: OpId) -> Result<(), EmuError> {
        let o = self.fd.op(op);
        let out = o.out;
        let size = |v: VarnodeId| self.fd.vn(v).size;
        match o.opc {
            Opcode::Load => {
                let off = self.get(o.ins[1])?;
                let out = out.ok_or_else(|| EmuError::Other("LOAD without output".into()))?;
                let val = self.load_image_value(off, size(out))?;
                self.set(out, val);
            }
            Opcode::Store | Opcode::Call | Opcode::Callind | Opcode::Callother | Opcode::New | Opcode::Cpoolref => {}
            Opcode::Branch | Opcode::Cbranch => {
                return Err(EmuError::Other("Branch encountered emulating jumptable calculation".into()))
            }
            Opcode::Branchind | Opcode::Return => {
                return Err(EmuError::Other("Indirect branch encountered emulating jumptable calculation".into()))
            }
            Opcode::Multiequal => {
                let fd = self.fd;
                let bl = o.parent.ok_or_else(|| EmuError::Other("Could not execute MULTIEQUAL".into()))?;
                let last = self.last_op.and_then(|l| fd.op(l).parent);
                let i = fd.blocks.block(bl).ins.iter().position(|e| Some(e.point) == last);
                let i = i.ok_or_else(|| EmuError::Other("Could not execute MULTIEQUAL".into()))?;
                let val = self.get(o.ins[i])?;
                self.set(out.unwrap(), val);
            }
            Opcode::Indirect => {
                let val = self.get(o.ins[0])?;
                self.set(out.unwrap(), val);
            }
            Opcode::Segmentop => return Err(EmuError::Other("Segment operand missing definition".into())),
            opc => {
                let out = out.ok_or_else(|| EmuError::Other("op without output".into()))?;
                let a = self.get(o.ins[0])?;
                let val = if o.ins.len() == 1 {
                    eval_unary(opc, size(out), size(o.ins[0]), a)?
                } else {
                    let b = self.get(o.ins[1])?;
                    eval_binary(opc, size(out), size(o.ins[0]), a, b)?
                };
                self.set(out, val);
            }
        }
        self.last_op = Some(op);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn behaviors() {
        assert_eq!(eval_binary(Opcode::IntSborrow, 1, 4, 0x8000_0000, 1).unwrap(), 1);
        assert_eq!(eval_binary(Opcode::IntSless, 1, 4, 0xffff_ffff, 0).unwrap(), 1);
        assert_eq!(eval_binary(Opcode::Piece, 4, 2, 0x1234, 0x5678).unwrap(), 0x1234_5678);
        assert_eq!(eval_binary(Opcode::Subpiece, 1, 4, 0x1234_5678, 1).unwrap(), 0x56);
        assert_eq!(eval_unary(Opcode::IntSext, 4, 1, 0x80).unwrap(), 0xffff_ff80);
        assert_eq!(eval_unary(Opcode::Lzcount, 1, 4, 1).unwrap(), 31);
    }
}
