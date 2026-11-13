//! Port of `ActionLaneDivide` (coreaction.cc) and `LaneDivide` (subflow.cc): a laned register
//! (x86: XMM, YMM, ZMM) whose data-flow only moves whole lanes is split into one varnode per
//! lane. The trace builds [`TransformManager`] placeholders; a trace that succeeds is applied.
//!
//! Little-endian only: `Arch::new` rejects a big-endian processor, so the big-endian lane
//! order of `buildStore`/`buildLoad` is left out.

use std::collections::HashSet;
use std::ops::Bound;

use super::op::OpId;
use super::opcode::Opcode;
use super::transform::{LaneDescription, LanedRegister, TOpId, TVarId, TransformManager, INSERT_AFTER, INSERT_BEFORE};
use super::types::{Meta, TypeFactory};
use super::varnode::{VarnodeId, VnFlags};
use super::{Arch, Funcdata, Result};

/// One varnode left to trace (`LaneDivide::WorkNode`).
struct WorkNode {
    lanes: TVarId,
    num_lanes: i32,
    skip_lanes: i32,
}

/// Port of `LaneDivide`.
struct LaneDivide<'a> {
    fd: &'a Funcdata,
    types: &'a TypeFactory,
    tm: TransformManager,
    desc: LaneDescription,
    work: Vec<WorkNode>,
    allow_subpiece_terminator: bool,
    /// the varnodes seen (`Varnode::setMark`)
    marks: HashSet<VarnodeId>,
}

impl<'a> LaneDivide<'a> {
    /// Port of `LaneDivide::LaneDivide`: the root's split is not checked, as in the C++ (a
    /// refused root leaves the work list empty and `doTrace` fails).
    fn new(
        fd: &'a Funcdata,
        types: &'a TypeFactory,
        root: VarnodeId,
        desc: LaneDescription,
        allow_downcast: bool,
    ) -> Result<LaneDivide<'a>> {
        let num_lanes = desc.num_lanes();
        let mut ld = LaneDivide {
            fd,
            types,
            tm: TransformManager::default(),
            work: Vec::new(),
            allow_subpiece_terminator: allow_downcast,
            marks: HashSet::new(),
            desc,
        };
        ld.set_replacement(root, num_lanes, 0)?;
        Ok(ld)
    }

    /// Port of `LaneDivide::setReplacement`: the lanes of `vn`; `None` (the C++ null) for a
    /// type-locked varnode unless its type is an array (a metatype above `TYPE_ARRAY`, a
    /// structure or a union is not split; enumerations have an integer metatype).
    fn set_replacement(&mut self, vn: VarnodeId, num_lanes: i32, skip_lanes: i32) -> Result<Option<TVarId>> {
        let fd = self.fd;
        if self.marks.contains(&vn) {
            return self.tm.get_split(fd, vn, &self.desc, num_lanes, skip_lanes).map(Some);
        }
        let v = fd.vn(vn);
        if v.is_constant() {
            return self.tm.new_split(fd, vn, &self.desc, num_lanes, skip_lanes).map(Some);
        }
        // a locked varnode without a recorded type has the default (unknown) one
        if v.has(VnFlags::TYPELOCK) && v.ty.map(|t| self.types.meta(t)) != Some(Meta::Array) {
            return Ok(None);
        }
        self.marks.insert(vn);
        let res = self.tm.new_split(fd, vn, &self.desc, num_lanes, skip_lanes)?;
        if !v.is_free() {
            self.work.push(WorkNode { lanes: res, num_lanes, skip_lanes });
        }
        Ok(Some(res))
    }

    /// One `newOpReplace` op `out = opc in` (a COPY of a lane, mostly).
    fn unary(&mut self, opc: Opcode, op: OpId, input: TVarId, out: TVarId) -> Result<()> {
        let rop = self.tm.new_op_replace(1, opc, op);
        self.tm.set_output(rop, out)?;
        self.tm.set_input(rop, input, 0)
    }

    /// Port of `LaneDivide::buildUnaryOp`.
    fn build_unary(&mut self, opc: Opcode, op: OpId, ins: TVarId, outs: TVarId, num_lanes: i32) -> Result<()> {
        (0..num_lanes).try_for_each(|i| self.unary(opc, op, ins.lane(i), outs.lane(i)))
    }

    /// Port of `LaneDivide::buildBinaryOp`.
    fn build_binary(&mut self, op: OpId, in0: TVarId, in1: TVarId, outs: TVarId, num_lanes: i32) -> Result<()> {
        let opc = self.fd.op(op).opc;
        for i in 0..num_lanes {
            let rop = self.tm.new_op_replace(2, opc, op);
            self.tm.set_output(rop, outs.lane(i))?;
            self.tm.set_input(rop, in0.lane(i), 0)?;
            self.tm.set_input(rop, in1.lane(i), 1)?;
        }
        Ok(())
    }

    /// A COPY of the zero constant into lane `out` (`size` bytes).
    fn zero_lane(&mut self, op: OpId, out: TVarId, size: i32) -> Result<()> {
        let rop = self.tm.new_op_replace(1, Opcode::Copy, op);
        self.tm.set_output(rop, out)?;
        let c = self.tm.new_constant(size as u32, 0);
        self.tm.set_input(rop, c, 0)
    }

    /// The input of a PIECE or ZEXT covering `lanes` lanes from `skip` (one lane: the varnode
    /// itself), copied into the lanes from `out_start` of `outs` (`buildPiece`, `buildZext`).
    /// False when the input refuses to split.
    fn copy_part(
        &mut self,
        op: OpId,
        vn: VarnodeId,
        (lanes, skip): (i32, i32),
        outs: TVarId,
        out_start: i32,
    ) -> Result<bool> {
        if lanes == 1 {
            let rvn = self.tm.get_preexisting_varnode(self.fd, vn);
            let rop = self.tm.new_op_replace(1, Opcode::Copy, op);
            self.tm.set_input(rop, rvn, 0)?;
            self.tm.set_output(rop, outs.lane(out_start))?;
            return Ok(true);
        }
        let Some(rvn) = self.set_replacement(vn, lanes, skip)? else { return Ok(false) };
        for i in 0..lanes {
            let rop = self.tm.new_op_replace(1, Opcode::Copy, op);
            self.tm.set_input(rop, rvn.lane(i), 0)?;
            self.tm.set_output(rop, outs.lane(out_start + i))?;
        }
        Ok(true)
    }

    /// Port of `LaneDivide::buildPiece`.
    fn build_piece(&mut self, op: OpId, outs: TVarId, num_lanes: i32, skip_lanes: i32) -> Result<bool> {
        let (high, low) = (self.fd.input(op, 0)?, self.fd.input(op, 1)?);
        let (hs, ls) = (self.fd.vn(high).size as i32, self.fd.vn(low).size as i32);
        let Some(h) = self.desc.restriction(skip_lanes, ls, hs)? else { return Ok(false) };
        let Some(l) = self.desc.restriction(skip_lanes, 0, ls)? else { return Ok(false) };
        Ok(self.copy_part(op, high, h, outs, num_lanes - h.0)? && self.copy_part(op, low, l, outs, 0)?)
    }

    /// Port of `LaneDivide::buildMultiequal`.
    fn build_multiequal(&mut self, op: OpId, outs: TVarId, num_lanes: i32, skip_lanes: i32) -> Result<bool> {
        let mut ins = Vec::new();
        for vn in self.fd.op(op).ins.clone() {
            let Some(inv) = self.set_replacement(vn, num_lanes, skip_lanes)? else { return Ok(false) };
            ins.push(inv);
        }
        for i in 0..num_lanes {
            let rop = self.tm.new_op_replace(ins.len(), Opcode::Multiequal, op);
            self.tm.set_output(rop, outs.lane(i))?;
            for (j, &inv) in ins.iter().enumerate() {
                self.tm.set_input(rop, inv.lane(i), j)?;
            }
        }
        Ok(true)
    }

    /// Port of `LaneDivide::buildIndirect`.
    fn build_indirect(&mut self, op: OpId, outs: TVarId, num_lanes: i32, skip_lanes: i32) -> Result<bool> {
        let Some(inv) = self.set_replacement(self.fd.input(op, 0)?, num_lanes, skip_lanes)? else { return Ok(false) };
        for i in 0..num_lanes {
            let rop = self.tm.new_indirect_replace(self.fd, op)?;
            self.tm.set_output(rop, outs.lane(i))?;
            self.tm.set_input(rop, inv.lane(i), 0)?;
        }
        Ok(true)
    }

    /// The pointer `base + byte_pos` for the lane access `rop` (`buildStore`, `buildLoad`).
    fn lane_pointer(&mut self, rop: TOpId, base: TVarId, ptr_size: u32, byte_pos: i64) -> Result<TVarId> {
        if byte_pos == 0 {
            return Ok(base);
        }
        let ptr = self.tm.new_unique(ptr_size);
        let add = self.tm.new_op(2, Opcode::IntAdd, rop, INSERT_BEFORE);
        self.tm.set_output(add, ptr)?;
        self.tm.set_input(add, base, 0)?;
        let c = self.tm.new_constant(ptr_size, byte_pos as u64);
        self.tm.set_input(add, c, 1)?;
        Ok(ptr)
    }

    /// The space constant and the base pointer of a LOAD or STORE, unless the pointer is free
    /// and not a constant.
    fn access_base(&mut self, op: OpId) -> Result<Option<(u32, u64, TVarId, u32)>> {
        let (spc, ptr) = (self.fd.input(op, 0)?, self.fd.input(op, 1)?);
        let p = self.fd.vn(ptr);
        if p.is_free() && !p.is_constant() {
            return Ok(None);
        }
        let ptr_size = p.size;
        let base = self.tm.get_preexisting_varnode(self.fd, ptr);
        let s = self.fd.vn(spc);
        Ok(Some((s.size, s.offset, base, ptr_size)))
    }

    /// Port of `LaneDivide::buildStore`.
    fn build_store(&mut self, op: OpId, num_lanes: i32, skip_lanes: i32) -> Result<bool> {
        let Some(ins) = self.set_replacement(self.fd.input(op, 2)?, num_lanes, skip_lanes)? else { return Ok(false) };
        let Some((spc_size, spc, base, ptr_size)) = self.access_base(op)? else { return Ok(false) };
        let mut byte_pos = 0i64;
        let mut last: Option<TOpId> = None;
        for i in 0..num_lanes {
            let store = match last {
                None => self.tm.new_preexisting_op(3, Opcode::Store, op),
                Some(l) => self.tm.new_op(3, Opcode::Store, l, INSERT_AFTER),
            };
            let ptr = self.lane_pointer(store, base, ptr_size, byte_pos)?;
            let c = self.tm.new_constant(spc_size, spc);
            self.tm.set_input(store, c, 0)?;
            self.tm.set_input(store, ptr, 1)?;
            self.tm.set_input(store, ins.lane(i), 2)?;
            byte_pos += i64::from(self.desc.size(skip_lanes + i)?);
            last = Some(store);
        }
        Ok(true)
    }

    /// Port of `LaneDivide::buildLoad`.
    fn build_load(&mut self, op: OpId, outs: TVarId, num_lanes: i32, skip_lanes: i32) -> Result<bool> {
        let Some((spc_size, spc, base, ptr_size)) = self.access_base(op)? else { return Ok(false) };
        let mut byte_pos = 0i64;
        for i in 0..num_lanes {
            let load = self.tm.new_op_replace(2, Opcode::Load, op);
            let ptr = self.lane_pointer(load, base, ptr_size, byte_pos)?;
            let c = self.tm.new_constant(spc_size, spc);
            self.tm.set_input(load, c, 0)?;
            self.tm.set_input(load, ptr, 1)?;
            self.tm.set_output(load, outs.lane(i))?;
            byte_pos += i64::from(self.desc.size(skip_lanes + i)?);
        }
        Ok(true)
    }

    /// The lane where a constant byte shift of the lanes from `skip_lanes` starts, if the
    /// shift is by whole lanes (`buildRightShift`, `buildLeftShift`).
    fn shift_lane(&self, op: OpId, skip_lanes: i32) -> Result<Option<i32>> {
        let sa = self.fd.vn(self.fd.input(op, 1)?);
        if !sa.is_constant() {
            return Ok(None);
        }
        let shift = sa.offset as i32;
        if shift & 7 != 0 {
            return Ok(None);
        }
        let start = self.desc.boundary(shift / 8 + self.desc.position(skip_lanes)?);
        Ok((start >= 0).then_some(start))
    }

    /// Whether the `count` lanes from `a` and from `b` have the same sizes.
    fn same_sizes(&self, a: i32, b: i32, count: i32) -> Result<bool> {
        for i in 0..count {
            if self.desc.size(a + i)? != self.desc.size(b + i)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Port of `LaneDivide::buildRightShift`.
    fn build_right_shift(&mut self, op: OpId, outs: TVarId, num_lanes: i32, skip_lanes: i32) -> Result<bool> {
        let Some(start) = self.shift_lane(op, skip_lanes)? else { return Ok(false) };
        let moved = num_lanes - (start - skip_lanes);
        if !self.same_sizes(start, skip_lanes, moved)? {
            return Ok(false);
        }
        let Some(ins) = self.set_replacement(self.fd.input(op, 0)?, num_lanes, skip_lanes)? else { return Ok(false) };
        self.build_unary(Opcode::Copy, op, ins.lane(start - skip_lanes), outs, moved)?;
        for z in moved..num_lanes {
            // the C++ takes the size of lane `z` of the whole description
            self.zero_lane(op, outs.lane(z), self.desc.size(z)?)?;
        }
        Ok(true)
    }

    /// Port of `LaneDivide::buildLeftShift`.
    fn build_left_shift(&mut self, op: OpId, outs: TVarId, num_lanes: i32, skip_lanes: i32) -> Result<bool> {
        let Some(start) = self.shift_lane(op, skip_lanes)? else { return Ok(false) };
        let moved = num_lanes - (start - skip_lanes);
        if !self.same_sizes(skip_lanes, start, moved)? {
            return Ok(false);
        }
        let Some(ins) = self.set_replacement(self.fd.input(op, 0)?, num_lanes, skip_lanes)? else { return Ok(false) };
        for z in 0..start - skip_lanes {
            self.zero_lane(op, outs.lane(z), self.desc.size(z)?)?;
        }
        self.build_unary(Opcode::Copy, op, ins, outs.lane(start - skip_lanes), moved)?;
        Ok(true)
    }

    /// Port of `LaneDivide::buildZext`.
    fn build_zext(&mut self, op: OpId, outs: TVarId, num_lanes: i32, skip_lanes: i32) -> Result<bool> {
        let invn = self.fd.input(op, 0)?;
        let v = self.fd.vn(invn);
        let mut in_lanes = 0;
        if !v.is_constant() || v.offset != 0 {
            let Some(r) = self.desc.restriction(skip_lanes, 0, v.size as i32)? else { return Ok(false) };
            in_lanes = r.0;
            if !self.copy_part(op, invn, r, outs, 0)? {
                return Ok(false);
            }
        }
        for i in in_lanes..num_lanes {
            self.zero_lane(op, outs.lane(i), self.desc.size(skip_lanes + i)?)?;
        }
        Ok(true)
    }

    /// The output of a traced op takes `lanes` (count, skip), if any and if it may split
    /// (the placeholder ops are left to `traceBackward`).
    fn split_out(&mut self, outvn: VarnodeId, lanes: Option<(i32, i32)>) -> Result<bool> {
        let Some((l, s)) = lanes else { return Ok(false) };
        Ok(self.set_replacement(outvn, l, s)?.is_some())
    }

    /// The SUBPIECE case of `LaneDivide::traceForward`: whole lanes of `rvn`, one lane (a
    /// COPY), or, when allowed, a piece inside one lane, which ends the trace.
    fn forward_subpiece(&mut self, op: OpId, outvn: VarnodeId, rvn: TVarId, skip_lanes: i32) -> Result<bool> {
        let fd = self.fd;
        let byte_pos = fd.vn(fd.input(op, 1)?).offset as i32;
        let out_size = fd.vn(outvn).size as i32;
        match self.desc.restriction(skip_lanes, byte_pos, out_size)? {
            None => {
                if !self.allow_subpiece_terminator {
                    return Ok(false);
                }
                let lane = self.desc.boundary(byte_pos + self.desc.position(skip_lanes)?);
                if lane < 0 || lane >= self.desc.num_lanes() || self.desc.size(lane)? <= out_size {
                    return Ok(false);
                }
                let rop = self.tm.new_preexisting_op(2, Opcode::Subpiece, op);
                self.tm.set_input(rop, rvn.lane(lane - skip_lanes), 0)?;
                let c = self.tm.new_constant(4, 0);
                self.tm.set_input(rop, c, 1)?;
                Ok(true)
            }
            Some((1, out_skip)) => {
                let rop = self.tm.new_preexisting_op(1, Opcode::Copy, op);
                self.tm.set_input(rop, rvn.lane(out_skip - skip_lanes), 0)?;
                Ok(true)
            }
            lanes => self.split_out(outvn, lanes),
        }
    }

    /// One reading op with an output in `LaneDivide::traceForward`.
    fn forward_op(
        &mut self,
        op: OpId,
        (orig, rvn): (VarnodeId, TVarId),
        outvn: VarnodeId,
        num_lanes: i32,
        skip_lanes: i32,
    ) -> Result<bool> {
        let fd = self.fd;
        let out_size = fd.vn(outvn).size as i32;
        match fd.op(op).opc {
            Opcode::Subpiece => self.forward_subpiece(op, outvn, rvn, skip_lanes),
            Opcode::Piece => {
                let byte_pos = if fd.input(op, 0)? == orig { fd.vn(fd.input(op, 1)?).size as i32 } else { 0 };
                let lanes = self.desc.extension(skip_lanes, byte_pos, out_size)?;
                self.split_out(outvn, lanes)
            }
            Opcode::Copy
            | Opcode::IntNegate
            | Opcode::IntAnd
            | Opcode::IntOr
            | Opcode::IntXor
            | Opcode::Multiequal
            | Opcode::Indirect => self.split_out(outvn, Some((num_lanes, skip_lanes))),
            // the trace must come through input 0
            Opcode::IntRight | Opcode::IntLeft => {
                Ok(fd.vn(fd.input(op, 1)?).is_constant() && self.split_out(outvn, Some((num_lanes, skip_lanes)))?)
            }
            Opcode::IntZext => {
                let lanes = self.desc.extension(skip_lanes, 0, out_size)?;
                self.split_out(outvn, lanes)
            }
            _ => Ok(false),
        }
    }

    /// Port of `LaneDivide::traceForward`.
    fn trace_forward(&mut self, rvn: TVarId, num_lanes: i32, skip_lanes: i32) -> Result<bool> {
        let fd = self.fd;
        let Some(orig) = self.tm.original(rvn) else { return Ok(false) };
        for &op in fd.vn(orig).descend.iter() {
            let out = fd.op(op).out;
            if out.is_some_and(|o| self.marks.contains(&o)) {
                continue;
            }
            let ok = match (fd.op(op).opc, out) {
                // only the stored value propagates
                (Opcode::Store, _) => fd.input(op, 2)? == orig && self.build_store(op, num_lanes, skip_lanes)?,
                (_, Some(outvn)) => self.forward_op(op, (orig, rvn), outvn, num_lanes, skip_lanes)?,
                (_, None) => false,
            };
            if !ok {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Port of `LaneDivide::traceBackward`.
    fn trace_backward(&mut self, rvn: TVarId, num_lanes: i32, skip_lanes: i32) -> Result<bool> {
        let fd = self.fd;
        let Some(op) = self.tm.original(rvn).and_then(|v| fd.vn(v).def) else { return Ok(true) };
        let opc = fd.op(op).opc;
        match opc {
            Opcode::IntNegate | Opcode::Copy => {
                let Some(ins) = self.set_replacement(fd.input(op, 0)?, num_lanes, skip_lanes)? else {
                    return Ok(false);
                };
                self.build_unary(opc, op, ins, rvn, num_lanes)?;
            }
            Opcode::IntAnd | Opcode::IntOr | Opcode::IntXor => {
                let Some(in0) = self.set_replacement(fd.input(op, 0)?, num_lanes, skip_lanes)? else {
                    return Ok(false);
                };
                let Some(in1) = self.set_replacement(fd.input(op, 1)?, num_lanes, skip_lanes)? else {
                    return Ok(false);
                };
                self.build_binary(op, in0, in1, rvn, num_lanes)?;
            }
            Opcode::Subpiece => {
                let invn = fd.input(op, 0)?;
                let byte_pos = fd.vn(fd.input(op, 1)?).offset as i32;
                let Some((l, s)) = self.desc.extension(skip_lanes, byte_pos, fd.vn(invn).size as i32)? else {
                    return Ok(false);
                };
                let Some(ins) = self.set_replacement(invn, l, s)? else { return Ok(false) };
                self.build_unary(Opcode::Copy, op, ins.lane(skip_lanes - s), rvn, num_lanes)?;
            }
            Opcode::Multiequal => return self.build_multiequal(op, rvn, num_lanes, skip_lanes),
            Opcode::Indirect => return self.build_indirect(op, rvn, num_lanes, skip_lanes),
            Opcode::Piece => return self.build_piece(op, rvn, num_lanes, skip_lanes),
            Opcode::Load => return self.build_load(op, rvn, num_lanes, skip_lanes),
            Opcode::IntRight => return self.build_right_shift(op, rvn, num_lanes, skip_lanes),
            Opcode::IntLeft => return self.build_left_shift(op, rvn, num_lanes, skip_lanes),
            Opcode::IntZext => return self.build_zext(op, rvn, num_lanes, skip_lanes),
            _ => return Ok(false),
        }
        Ok(true)
    }

    /// Port of `LaneDivide::doTrace`: the transform, if every varnode reached splits.
    fn do_trace(mut self) -> Result<Option<TransformManager>> {
        if self.work.is_empty() {
            return Ok(None);
        }
        while let Some(w) = self.work.pop() {
            if !self.trace_backward(w.lanes, w.num_lanes, w.skip_lanes)?
                || !self.trace_forward(w.lanes, w.num_lanes, w.skip_lanes)?
            {
                return Ok(None);
            }
        }
        Ok(Some(self.tm))
    }
}

/// Port of `ActionLaneDivide::addPieceLaneSize`.
fn add_piece_lane_size(size: i32, offset: i32, allowed: LanedRegister, check: &mut LanedRegister) {
    if allowed.allowed(size) {
        check.add(size);
        return;
    }
    let mut best = 0;
    for lane in allowed.sizes() {
        if lane * 2 > size {
            break;
        }
        if size % lane == 0 && offset % lane == 0 {
            best = lane;
        }
    }
    if best > 0 {
        check.add(best);
    }
}

/// Port of `ActionLaneDivide::collectLaneSizes`.
fn collect_lane_sizes(fd: &Funcdata, vn: VarnodeId, allowed: LanedRegister, check: &mut LanedRegister) -> Result<()> {
    for &op in fd.vn(vn).descend.iter() {
        let o = fd.op(op);
        if o.opc != Opcode::Subpiece {
            continue;
        }
        let Some(out) = o.out else { continue };
        let off = fd.vn(fd.input(op, 1)?).offset as i32;
        add_piece_lane_size(fd.vn(out).size as i32, off, allowed, check);
    }
    let Some(op) = fd.vn(vn).def else { return Ok(()) };
    match fd.op(op).opc {
        Opcode::Piece => {
            let lo = fd.vn(fd.input(op, 1)?).size as i32;
            add_piece_lane_size(lo, 0, allowed, check);
            add_piece_lane_size(fd.vn(fd.input(op, 0)?).size as i32, lo, allowed, check);
        }
        Opcode::IntZext => {
            let in_size = fd.vn(fd.input(op, 0)?).size as i32;
            if !allowed.allowed(in_size) {
                add_piece_lane_size(in_size, 0, allowed, check);
            }
        }
        _ => {}
    }
    Ok(())
}

/// The passes of `ActionLaneDivide::apply` (its `mode` 0, 1, 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// lane sizes from the pieces the register is cut into or made of
    Pieces,
    /// the same, and a SUBPIECE inside one lane may end the trace
    PiecesOrTerminator,
    /// the default lane size (the pointer size), with the terminator
    DefaultSize,
}

/// Port of `ActionLaneDivide::processVarnode`: whether `vn` was split.
fn process_varnode(fd: &mut Funcdata, arch: &Arch, vn: VarnodeId, laned: LanedRegister, mode: Mode) -> Result<bool> {
    let mut check = LanedRegister::default();
    if mode != Mode::DefaultSize {
        collect_lane_sizes(fd, vn, laned, &mut check)?;
    } else {
        let default_size = arch.pointer_size() as i32;
        if default_size == 4 && laned.allowed(4) {
            check.add(4);
        } else if laned.allowed(8) {
            check.add(8);
        } else if laned.allowed(4) {
            check.add(4);
        }
    }
    for size in check.sizes() {
        let desc = LaneDescription::new(laned.whole_size as i32, size);
        let trace = LaneDivide::new(fd, &arch.types, vn, desc, mode != Mode::Pieces)?;
        if let Some(tm) = trace.do_trace()? {
            tm.apply(fd, arch)?;
            return Ok(true);
        }
    }
    Ok(false)
}

/// Port of `ActionLaneDivide::apply`: the laned accesses recorded since the last run, pass by
/// pass ([`Mode`]) until every varnode is split or no pass is left.
pub(crate) fn lane_divide(fd: &mut Funcdata, arch: &Arch) -> Result<i32> {
    let mut count = 0;
    for mode in [Mode::Pieces, Mode::PiecesOrTerminator, Mode::DefaultSize] {
        let mut all_storage = true;
        let mut cur = None;
        loop {
            let lower = cur.map_or(Bound::Unbounded, Bound::Excluded);
            let Some((&key, &(space, laned))) = fd.lane_access.range((lower, Bound::Unbounded)).next() else { break };
            cur = Some(key);
            let (off, size) = (key.1, laned.whole_size);
            let mut vns = fd.loc_at(space, off, size);
            let (mut i, mut all_vns) = (0, true);
            while i < vns.len() {
                let vn = vns[i];
                if fd.vn(vn).descend.is_empty() {
                    i += 1;
                    continue;
                }
                if process_varnode(fd, arch, vn, laned, mode)? {
                    count += 1;
                    vns = fd.loc_at(space, off, size);
                    i = 0;
                    all_vns = true;
                } else {
                    i += 1;
                    all_vns = false;
                }
            }
            all_storage &= all_vns;
        }
        if all_storage {
            break;
        }
    }
    fd.lane_access.clear();
    Ok(count)
}
