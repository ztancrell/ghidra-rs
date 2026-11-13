//! Port of `SplitFlow` (subflow.cc): a varnode made by concatenating two pieces, whose
//! data-flow only moves the pieces side by side, is split into a low and a high varnode. The
//! trace builds [`TransformManager`] placeholders, lane 0 the low piece and lane 1 the high.
//!
//! The double-precision marks (`isPrecisLo`, `isPrecisHi`) come with `double.cc` (R5): no
//! varnode has them yet. Partial structure types are not ported, so any locked type refuses.

use std::collections::HashSet;

use super::op::OpId;
use super::opcode::Opcode;
use super::transform::{LaneDescription, TOpId, TVarId, TransformManager, INSERT_BEFORE};
use super::varnode::{VarnodeId, VnFlags};
use super::{Funcdata, Result};

/// Port of `SplitFlow`.
pub(crate) struct SplitFlow<'a> {
    fd: &'a Funcdata,
    tm: TransformManager,
    desc: LaneDescription,
    work: Vec<TVarId>,
    /// the varnodes seen (`Varnode::setMark`)
    marks: HashSet<VarnodeId>,
}

impl<'a> SplitFlow<'a> {
    /// Port of the `SplitFlow` constructor: `root` splits into its low `low_size` bytes and
    /// the rest.
    pub(crate) fn new(fd: &'a Funcdata, root: VarnodeId, low_size: u32) -> Result<SplitFlow<'a>> {
        let size = fd.vn(root).size as i32;
        let desc = LaneDescription::two(size, low_size as i32, size - low_size as i32);
        let mut flow = SplitFlow { fd, tm: TransformManager::default(), desc, work: Vec::new(), marks: HashSet::new() };
        flow.set_replacement(root)?;
        Ok(flow)
    }

    /// Port of `SplitFlow::setReplacement`: the two pieces of `vn`; `None` for a locked
    /// varnode, an input, or a free varnode that is no constant.
    fn set_replacement(&mut self, vn: VarnodeId) -> Result<Option<TVarId>> {
        let fd = self.fd;
        if self.marks.contains(&vn) {
            return self.tm.get_split(fd, vn, &self.desc, 2, 0).map(Some);
        }
        let v = fd.vn(vn);
        if v.has(VnFlags::TYPELOCK) || v.is_input() || (v.is_free() && !v.is_constant()) {
            return Ok(None);
        }
        let res = self.tm.new_split(fd, vn, &self.desc, 2, 0)?;
        self.marks.insert(vn);
        if !v.is_constant() {
            self.work.push(res);
        }
        Ok(Some(res))
    }

    /// Port of `SplitFlow::addOp`: `op` is done once on the low pieces and once on the high.
    /// `rvn` is the traced varnode, in input `slot` or (no slot) the output.
    fn add_op(&mut self, op: OpId, rvn: TVarId, slot: Option<usize>) -> Result<bool> {
        let fd = self.fd;
        let outvn = match (slot, fd.op(op).out) {
            (None, _) => rvn,
            (Some(_), Some(out)) => match self.set_replacement(out)? {
                Some(o) => o,
                None => return Ok(false),
            },
            (Some(_), None) => return Ok(false),
        };
        if self.tm.has_def(outvn) {
            return Ok(true); // already traversed
        }
        let o = fd.op(op);
        let (lo_op, hi_op, num) = if o.opc == Opcode::Indirect {
            (self.tm.new_indirect_replace(fd, op)?, self.tm.new_indirect_replace(fd, op)?, 1)
        } else {
            let n = o.ins.len();
            (self.tm.new_op_replace(n, o.opc, op), self.tm.new_op_replace(n, o.opc, op), n)
        };
        for i in 0..num {
            let invn = if Some(i) == slot {
                rvn
            } else {
                match self.set_replacement(fd.input(op, i)?)? {
                    Some(v) => v,
                    None => return Ok(false),
                }
            };
            self.tm.set_input(lo_op, invn, i)?;
            self.tm.set_input(hi_op, invn.lane(1), i)?;
        }
        self.tm.set_output(lo_op, outvn)?;
        self.tm.set_output(hi_op, outvn.lane(1))?;
        Ok(true)
    }

    /// `op` stays, as `opc` of `input` (a piece, or its extension to the whole size shifted
    /// by `shift`): the tails of the shift cases of `traceForward`.
    fn keep_shift(&mut self, op: OpId, ext: Opcode, piece: TVarId, shift: Option<u64>) -> Result<()> {
        let fd = self.fd;
        let Some(shift) = shift else {
            let rop = self.tm.new_preexisting_op(1, ext, op);
            return self.tm.set_input(rop, piece, 0);
        };
        let rop = self.tm.new_preexisting_op(2, fd.op(op).opc, op);
        let extrop: TOpId = self.tm.new_op(1, ext, rop, INSERT_BEFORE);
        self.tm.set_input(extrop, piece, 0)?;
        let whole = self.tm.new_unique(self.desc.whole_size() as u32);
        self.tm.set_output(extrop, whole)?;
        self.tm.set_input(rop, whole, 0)?;
        let c = self.tm.new_constant(fd.vn(fd.input(op, 1)?).size, shift);
        self.tm.set_input(rop, c, 1)
    }

    /// The SUBPIECE and shift readers of `SplitFlow::traceForward`: they must take exactly
    /// one piece.
    fn forward_piece(&mut self, op: OpId, rvn: TVarId) -> Result<bool> {
        let fd = self.fd;
        let (lo, hi) = (self.desc.size(0)? as u64, self.desc.size(1)? as u64);
        let cvn = fd.vn(fd.input(op, 1)?);
        let val = cvn.offset;
        let opc = fd.op(op).opc;
        match opc {
            Opcode::Subpiece => {
                let out_size = fd.op(op).out.map_or(0, |o| u64::from(fd.vn(o).size));
                let piece = if val == 0 && out_size == lo {
                    rvn
                } else if val == lo && out_size == hi {
                    rvn.lane(1)
                } else {
                    return Ok(false);
                };
                self.keep_shift(op, Opcode::Copy, piece, None)?;
            }
            // the shift must obliterate all high bits: the low piece, extended, keeps its shift
            Opcode::IntLeft if cvn.is_constant() && val >= hi * 8 => {
                self.keep_shift(op, Opcode::IntZext, rvn, Some(val))?;
            }
            Opcode::IntRight | Opcode::IntSright if cvn.is_constant() && val >= lo * 8 => {
                let ext = if opc == Opcode::IntRight { Opcode::IntZext } else { Opcode::IntSext };
                let remain = val - lo * 8;
                self.keep_shift(op, ext, rvn.lane(1), (remain != 0).then_some(remain))?;
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    /// Port of `SplitFlow::traceForward`.
    fn trace_forward(&mut self, rvn: TVarId) -> Result<bool> {
        use Opcode::*;
        let fd = self.fd;
        let Some(orig) = self.tm.original(rvn) else { return Ok(false) };
        for &op in fd.vn(orig).descend.iter() {
            if fd.op(op).out.is_some_and(|o| self.marks.contains(&o)) {
                continue;
            }
            let ok = match fd.op(op).opc {
                Copy | Multiequal | Indirect | IntAnd | IntOr | IntXor => self.add_op(op, rvn, fd.slot_of(op, orig))?,
                Subpiece | IntLeft | IntRight | IntSright => self.forward_piece(op, rvn)?,
                _ => false,
            };
            if !ok {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Two COPYs replacing `op`: `lo` into the low piece of `rvn`, `hi` into the high one
    /// (`None`: a zero constant of the piece's size).
    fn copy_pieces(&mut self, op: OpId, rvn: TVarId, lo: Option<VarnodeId>, hi: Option<VarnodeId>) -> Result<()> {
        let lo_op = self.tm.new_op_replace(1, Opcode::Copy, op);
        let hi_op = self.tm.new_op_replace(1, Opcode::Copy, op);
        for (rop, src, lane) in [(lo_op, lo, 0), (hi_op, hi, 1)] {
            let invn = match src {
                Some(vn) => self.tm.get_preexisting_varnode(self.fd, vn),
                None => self.tm.new_constant(self.desc.size(lane)? as u32, 0),
            };
            self.tm.set_input(rop, invn, 0)?;
            self.tm.set_output(rop, rvn.lane(lane))?;
        }
        Ok(())
    }

    /// The INT_LEFT case of `SplitFlow::traceBackward`: `zext(V) << 8*lowsize` is zero in the
    /// low piece and `V` in the high one.
    fn shifted_high(&self, op: OpId) -> Result<Option<VarnodeId>> {
        let fd = self.fd;
        let cvn = fd.vn(fd.input(op, 1)?);
        if !cvn.is_constant() || cvn.offset != self.desc.size(0)? as u64 * 8 {
            return Ok(None);
        }
        let Some(zext) = fd.vn(fd.input(op, 0)?).def.filter(|&d| fd.op(d).opc == Opcode::IntZext) else {
            return Ok(None);
        };
        let invn = fd.input(zext, 0)?;
        let v = fd.vn(invn);
        Ok((v.size as i32 == self.desc.size(1)? && !v.is_free()).then_some(invn))
    }

    /// Port of `SplitFlow::traceBackward`.
    fn trace_backward(&mut self, rvn: TVarId) -> Result<bool> {
        use Opcode::*;
        let fd = self.fd;
        let Some(op) = self.tm.original(rvn).and_then(|v| fd.vn(v).def) else { return Ok(true) };
        let (lo, hi) = (self.desc.size(0)?, self.desc.size(1)?);
        let size = |vn: VarnodeId| fd.vn(vn).size as i32;
        match fd.op(op).opc {
            Copy | Multiequal | IntAnd | IntOr | IntXor | Indirect => return self.add_op(op, rvn, None),
            Piece => {
                let (most, least) = (fd.input(op, 0)?, fd.input(op, 1)?);
                if size(most) != hi || size(least) != lo {
                    return Ok(false);
                }
                self.copy_pieces(op, rvn, Some(least), Some(most))?;
            }
            IntZext => {
                let invn = fd.input(op, 0)?;
                if size(invn) != lo || fd.op(op).out.map(size) != Some(self.desc.whole_size()) {
                    return Ok(false);
                }
                self.copy_pieces(op, rvn, Some(invn), None)?;
            }
            IntLeft => {
                let Some(invn) = self.shifted_high(op)? else { return Ok(false) };
                self.copy_pieces(op, rvn, None, Some(invn))?;
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    /// Port of `SplitFlow::doTrace`: the transform, if every varnode reached splits.
    pub(crate) fn do_trace(mut self) -> Result<Option<TransformManager>> {
        if self.work.is_empty() {
            return Ok(None);
        }
        while let Some(rvn) = self.work.pop() {
            if !self.trace_backward(rvn)? || !self.trace_forward(rvn)? {
                return Ok(None);
            }
        }
        Ok(Some(self.tm))
    }
}
