//! Port of `SubvariableFlow` (subflow.cc): a logical value that lives in some bits of larger
//! varnodes (a flag in a byte, a byte in a register) is traced through the data-flow, and if
//! every use fits, the flow is rebuilt on varnodes of the logical size. The trace reads the
//! function and builds placeholders ([`RVar`], [`ROp`], [`Patch`]) in arenas with typed ids; a
//! trace that succeeds gives a [`Replacement`], which then edits the function.
//!
//! The marks of the trace (`Varnode::setMark`) are the keys of `varmap`. Shifts by an amount
//! the C++ does not bound wrap as its shifts do on x86. Little-endian only (`Arch::new`
//! rejects a big-endian processor). `copySymbolIfValid` is left out as in `rules/extend.rs`.

use std::collections::{HashMap, VecDeque};

use super::jumptable::is_bool_output;
use super::op::OpId;
use super::opcode::Opcode;
use super::rangeutil::{calc_mask, leastsigbit_set, mostsigbit_set, sign_extend};
use super::varnode::{Space, VarnodeId, VnFlags};
use super::{err, Arch, Funcdata, Result};

/// How a trace treats its logical value (the flags of the `SubvariableFlow` constructor).
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct FlowKind {
    /// the seed is known to be a sub-variable (`aggressive`)
    pub(crate) aggressive: bool,
    /// the value is always sign-extended into its container (`sextrestrictions`)
    pub(crate) sext: bool,
    /// the value may be 8 bytes (`big`)
    pub(crate) big: bool,
}

/// Index of an [`RVar`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RVarId(usize);

/// Index of an [`ROp`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ROpId(usize);

/// Port of `SubvariableFlow::ReplaceVarnode`.
#[derive(Debug)]
struct RVar {
    /// the varnode being shrunk; none for a new constant or temporary
    vn: Option<VarnodeId>,
    replacement: Option<VarnodeId>,
    /// the bits of the logical value within `vn`
    mask: u64,
    /// the value of a constant
    val: u64,
    def: Option<ROpId>,
}

/// Port of `SubvariableFlow::ReplaceOp`.
#[derive(Debug)]
struct ROp {
    /// the op paralleled
    op: OpId,
    opc: Opcode,
    output: Option<RVarId>,
    input: Vec<Option<RVarId>>,
}

/// `SubvariableFlow::PatchRecord::patchtype`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PatchKind {
    /// the op becomes a COPY of the logical value
    Copy,
    /// both inputs of a comparison become logical values
    Compare,
    /// one input of the op becomes the logical value
    Parameter,
    /// the op becomes a zero extension (and shift) of the logical value
    Extension,
    /// the op writes the logical value, which a new ZEXT extends
    Push,
    /// a ZEXT of the logical value feeds an INT2FLOAT
    Int2Float,
}

/// Port of `SubvariableFlow::PatchRecord`.
#[derive(Debug)]
struct Patch {
    kind: PatchKind,
    op: OpId,
    in1: RVarId,
    in2: Option<RVarId>,
    /// the slot patched, or the shift of an extension
    slot: i32,
}

/// What became of one reader in a forward trace.
enum Flow {
    /// the logical value cannot be traced through the reader: the trace fails
    Abort,
    /// the reader is dealt with (`hcount`)
    Handled,
    /// the flow ends at the reader, which keeps reading the container
    Unhandled,
}

/// `Varnode::isZeroExtended`.
fn is_zero_extended(fd: &Funcdata, vn: VarnodeId, base_size: u32) -> bool {
    let v = fd.vn(vn);
    if base_size >= v.size {
        return false;
    }
    if v.size > 8 {
        return v.def.is_some_and(|d| {
            let o = fd.op(d);
            o.opc == Opcode::IntZext && o.ins.first().is_some_and(|&i| fd.vn(i).size <= base_size)
        });
    }
    fd.nzmask(vn) >> (8 * base_size) == 0
}

/// `SubvariableFlow::doesOrSet` / `doesAndClear`: the slot of the constant of a logical op,
/// if it has one.
fn const_slot(fd: &Funcdata, op: OpId) -> Result<Option<(usize, u64)>> {
    let index = usize::from(fd.vn(fd.input(op, 1)?).is_constant());
    let c = fd.vn(fd.input(op, index)?);
    Ok(c.is_constant().then_some((index, c.offset)))
}

/// Port of `SubvariableFlow::doesOrSet`: the slot of a constant setting every bit of `mask`.
fn does_or_set(fd: &Funcdata, op: OpId, mask: u64) -> Result<Option<usize>> {
    Ok(const_slot(fd, op)?.filter(|&(_, val)| mask & !val == 0).map(|(i, _)| i))
}

/// Port of `SubvariableFlow::doesAndClear`: the slot of a constant clearing every bit of `mask`.
fn does_and_clear(fd: &Funcdata, op: OpId, mask: u64) -> Result<Option<usize>> {
    Ok(const_slot(fd, op)?.filter(|&(_, val)| mask & val == 0).map(|(i, _)| i))
}

/// Port of `PcodeOp::getRepeatSlot`: the slot of the read at position `pos` of `vn`'s readers
/// when `op` reads `vn` more than once.
pub(crate) fn repeat_slot(fd: &Funcdata, op: OpId, vn: VarnodeId, first_slot: usize, pos: usize) -> Result<usize> {
    let count = 1 + fd.vn(vn).descend.iter().take(pos).filter(|&&o| o == op).count();
    let slots = fd.op(op).ins.iter().enumerate().skip(first_slot).filter(|&(_, &v)| v == vn);
    match slots.map(|(i, _)| i).nth(count - 1) {
        Some(slot) => Ok(slot),
        None => err("getRepeatSlot: a reader without its slot"),
    }
}

/// The placeholders a trace builds, shared by the trace and the replacement.
#[derive(Debug, Default)]
struct Graph {
    vars: Vec<RVar>,
    /// the replacement ops, in creation order (`oplist`)
    ops: Vec<ROp>,
    /// `patchlist`: push patches at the front
    patches: VecDeque<Patch>,
}

impl Graph {
    fn new_var(&mut self, vn: Option<VarnodeId>, mask: u64, val: u64) -> RVarId {
        self.vars.push(RVar { vn, replacement: None, mask, val, def: None });
        RVarId(self.vars.len() - 1)
    }

    /// `rop->input[slot] = rvn`, growing the inputs.
    fn set_input(&mut self, rop: ROpId, slot: usize, rvn: RVarId) {
        let input = &mut self.ops[rop.0].input;
        if input.len() <= slot {
            input.resize(slot + 1, None);
        }
        input[slot] = Some(rvn);
    }

    fn patch(&mut self, kind: PatchKind, op: OpId, in1: RVarId, slot: i32) {
        self.patches.push_back(Patch { kind, op, in1, in2: None, slot });
    }
}

/// Port of `SubvariableFlow`: the trace.
pub(crate) struct SubvariableFlow<'a> {
    fd: &'a Funcdata,
    arch: &'a Arch,
    /// the size of the logical value in bytes
    flowsize: u32,
    /// its size in bits
    bitsize: i32,
    returns_traversed: bool,
    /// the seed is known to be a sub-variable
    aggressive: bool,
    /// the logical value is always sign-extended into its container
    sext: bool,
    /// false when the mask gives no logical size (the C++ clears `fd`)
    valid: bool,
    g: Graph,
    /// `varmap`, and the varnode marks
    varmap: HashMap<VarnodeId, RVarId>,
    worklist: Vec<RVarId>,
    /// the ops pulling the logical value out
    pullcount: i32,
}

/// A successful trace: the transform to perform (`SubvariableFlow::doReplacement`).
#[derive(Debug)]
pub(crate) struct Replacement {
    g: Graph,
    flowsize: u32,
    bitsize: i32,
    aggressive: bool,
}

impl<'a> SubvariableFlow<'a> {
    /// Port of the `SubvariableFlow` constructor: the logical value is the bits `mask` of
    /// `root`.
    pub(crate) fn new(
        fd: &'a Funcdata,
        arch: &'a Arch,
        root: VarnodeId,
        mask: u64,
        kind: FlowKind,
    ) -> Result<SubvariableFlow<'a>> {
        let FlowKind { aggressive, sext, big } = kind;
        let bitsize = if mask == 0 { 0 } else { mostsigbit_set(mask) - leastsigbit_set(mask) + 1 };
        let flowsize = match bitsize {
            1..=32 => (bitsize as u32).div_ceil(8),
            33..=64 if big => 8,
            _ => 0,
        };
        let mut flow = SubvariableFlow {
            fd,
            arch,
            flowsize,
            bitsize,
            returns_traversed: false,
            aggressive,
            sext,
            valid: flowsize != 0,
            g: Graph::default(),
            varmap: HashMap::new(),
            worklist: Vec::new(),
            pullcount: 0,
        };
        if flow.valid {
            flow.create_link(None, mask, Some(0), root)?;
        }
        Ok(flow)
    }

    fn mask(&self, rvn: RVarId) -> u64 {
        self.g.vars[rvn.0].mask
    }

    /// The original varnode of a traced placeholder.
    fn orig(&self, rvn: RVarId) -> Result<VarnodeId> {
        self.g.vars[rvn.0].vn.map_or_else(|| err("subflow: a traced placeholder without a varnode"), Ok)
    }

    /// Whether more of `rvn`'s container than the logical value is consumed, when that matters
    /// (`!aggressive && (consume & ~mask) != 0`).
    fn consumed_outside(&self, rvn: RVarId) -> Result<bool> {
        Ok(!self.aggressive && self.fd.vn(self.orig(rvn)?).consume & !self.mask(rvn) != 0)
    }

    /// Port of `SubvariableFlow::setReplacement`: the placeholder of `vn` for the logical bits
    /// `mask`, and whether it still has to be traced; `None` when `vn` cannot hold the value.
    fn set_replacement(&mut self, vn: VarnodeId, mask: u64) -> Option<(RVarId, bool)> {
        if let Some(&res) = self.varmap.get(&vn) {
            return (self.mask(res) == mask).then_some((res, false));
        }
        let v = self.fd.vn(vn);
        if v.is_constant() {
            // under sign-extension the constant must be the extension of its logical part
            if self.sext && sign_extend(v.offset & mask, self.flowsize, v.size) != v.offset {
                return None;
            }
            return Some((self.add_constant(None, mask, 0, vn), false));
        }
        if v.is_free() || (v.has(VnFlags::ADDRFORCE) && v.size != self.flowsize) {
            return None;
        }
        // a locked varnode without a recorded type has the default one, of its own size
        let locked_other_size =
            v.has(VnFlags::TYPELOCK) && v.ty.map_or(v.size, |t| self.arch.types.size(t)) != self.flowsize;
        if self.sext {
            // an input or a global cannot be assumed sign-extended
            let unknown_ext = (!self.aggressive && v.is_input()) || v.has(VnFlags::PERSIST);
            if (v.size != self.flowsize && unknown_ext) || locked_other_size {
                return None;
            }
        } else {
            // not a flag: a use outside the logical value means the whole is the variable
            if self.bitsize >= 8 && ((!self.aggressive && v.consume & !mask != 0) || locked_other_size) {
                return None;
            }
            // no input flag, no input off the least significant end
            if v.is_input() && (self.bitsize < 8 || mask & 1 == 0) {
                return None;
            }
        }
        let res = self.g.new_var(Some(vn), mask, 0);
        self.varmap.insert(vn, res);
        let is_logical =
            mask == calc_mask(self.flowsize) || (mask == 1 && v.def.is_some_and(|d| is_bool_output(self.fd.op(d).opc)));
        if v.size == self.flowsize && is_logical {
            self.g.vars[res.0].replacement = Some(vn);
            return Some((res, false));
        }
        Some((res, true))
    }

    /// Port of `SubvariableFlow::createOp`: the op defining `outrvn`, made once.
    fn create_op(&mut self, opc: Opcode, outrvn: RVarId) -> Result<ROpId> {
        if let Some(d) = self.g.vars[outrvn.0].def {
            return Ok(d);
        }
        let Some(op) = self.fd.vn(self.orig(outrvn)?).def else { return err("subflow: createOp on an input") };
        self.g.ops.push(ROp { op, opc, output: Some(outrvn), input: Vec::new() });
        let rop = ROpId(self.g.ops.len() - 1);
        self.g.vars[outrvn.0].def = Some(rop);
        Ok(rop)
    }

    /// Port of `SubvariableFlow::createOpDown`: a replacement of `op` reading `inrvn`.
    fn create_op_down(&mut self, opc: Opcode, op: OpId, inrvn: RVarId, slot: usize) -> ROpId {
        self.g.ops.push(ROp { op, opc, output: None, input: Vec::new() });
        let rop = ROpId(self.g.ops.len() - 1);
        self.g.set_input(rop, slot, inrvn);
        rop
    }

    /// Port of `SubvariableFlow::createLink`: `vn` with `mask` becomes input `slot` of `rop`,
    /// or its output for no slot. False when `vn` cannot hold the logical value.
    fn create_link(&mut self, rop: Option<ROpId>, mask: u64, slot: Option<usize>, vn: VarnodeId) -> Result<bool> {
        let Some((rep, inworklist)) = self.set_replacement(vn, mask) else { return Ok(false) };
        match (rop, slot) {
            (Some(rop), None) => {
                self.g.ops[rop.0].output = Some(rep);
                self.g.vars[rep.0].def = Some(rop);
            }
            (Some(rop), Some(slot)) => self.g.set_input(rop, slot, rep),
            (None, _) => {}
        }
        if inworklist {
            self.worklist.push(rep);
        }
        Ok(true)
    }

    /// `createLink` for each (mask, slot, varnode), stopping at the first that fails.
    fn links(&mut self, rop: ROpId, items: &[(u64, usize, VarnodeId)]) -> Result<bool> {
        for &(mask, slot, vn) in items {
            if !self.create_link(Some(rop), mask, Some(slot), vn)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Port of `SubvariableFlow::createCompareBridge`: the other side of a comparison joins
    /// the logical flow.
    fn create_compare_bridge(&mut self, op: OpId, inrvn: RVarId, slot: usize, othervn: VarnodeId) -> Flow {
        let Some((rep, inworklist)) = self.set_replacement(othervn, self.mask(inrvn)) else { return Flow::Abort };
        let (in1, in2) = if slot == 0 { (inrvn, rep) } else { (rep, inrvn) };
        self.g.patches.push_back(Patch { kind: PatchKind::Compare, op, in1, in2: Some(in2), slot: 0 });
        self.pullcount += 1;
        if inworklist {
            self.worklist.push(rep);
        }
        Flow::Handled
    }

    /// Port of `SubvariableFlow::addConstant`: the logical part of the constant `constvn`.
    fn add_constant(&mut self, rop: Option<ROpId>, mask: u64, slot: usize, constvn: VarnodeId) -> RVarId {
        let sa = leastsigbit_set(mask);
        let val = (mask & self.fd.vn(constvn).offset).wrapping_shr(sa as u32);
        let res = self.g.new_var(Some(constvn), mask, val);
        if let Some(rop) = rop {
            self.g.set_input(rop, slot, res);
        }
        res
    }

    /// Port of `SubvariableFlow::addNewConstant` (a zero, always in slot 0).
    fn add_new_zero(&mut self, rop: ROpId) {
        let res = self.g.new_var(None, 0, 0);
        self.g.set_input(rop, 0, res);
    }

    /// Port of `SubvariableFlow::addTerminalPatch`.
    fn add_terminal_patch(&mut self, op: OpId, rvn: RVarId) -> Flow {
        self.g.patch(PatchKind::Copy, op, rvn, 0);
        self.pullcount += 1;
        Flow::Handled
    }

    /// Port of `SubvariableFlow::addTerminalPatchSameOp` (and the parameter patches of the
    /// `try*Pull` functions).
    fn add_parameter_patch(&mut self, op: OpId, rvn: RVarId, slot: usize) -> Flow {
        self.g.patch(PatchKind::Parameter, op, rvn, slot as i32);
        self.pullcount += 1;
        Flow::Handled
    }

    /// Port of `SubvariableFlow::addExtensionPatch`; no `sa`: the position of the mask.
    fn add_extension_patch(&mut self, rvn: RVarId, op: OpId, sa: Option<i32>) -> Flow {
        let sa = sa.unwrap_or_else(|| leastsigbit_set(self.mask(rvn)));
        self.g.patch(PatchKind::Extension, op, rvn, sa);
        Flow::Handled
    }

    /// Port of `SubvariableFlow::addPush`.
    fn add_push(&mut self, op: OpId, rvn: RVarId) {
        self.g.patches.push_front(Patch { kind: PatchKind::Push, op, in1: rvn, in2: None, slot: 0 });
    }

    /// Port of `SubvariableFlow::tryCallPull`.
    fn try_call_pull(&mut self, op: OpId, rvn: RVarId, slot: usize) -> Result<Flow> {
        if slot == 0 || self.consumed_outside(rvn)? {
            return Ok(Flow::Abort);
        }
        let Some(c) = self.fd.call_of(op) else { return Ok(Flow::Abort) };
        let fc = self.fd.call(c);
        // not while the parameters are being worked out, nor into a locked parameter list
        if fc.active_input.is_some() || fc.proto.locked.as_ref().is_some_and(|l| !l.dotdotdot) {
            return Ok(Flow::Abort);
        }
        Ok(self.add_parameter_patch(op, rvn, slot))
    }

    /// Port of `SubvariableFlow::tryReturnPull`: every RETURN takes the logical value.
    fn try_return_pull(&mut self, op: OpId, rvn: RVarId, slot: usize) -> Result<Flow> {
        if slot == 0 || self.fd.proto.locked.is_some() || self.consumed_outside(rvn)? {
            return Ok(Flow::Abort);
        }
        if !self.returns_traversed {
            for retop in self.fd.ops_created_with(Opcode::Return) {
                if self.fd.op(retop).halt.is_some() {
                    continue;
                }
                let retvn = self.fd.input(retop, slot)?;
                let Some((rep, inworklist)) = self.set_replacement(retvn, self.mask(rvn)) else {
                    return Ok(Flow::Abort);
                };
                if inworklist {
                    self.worklist.push(rep);
                } else if self.fd.vn(retvn).is_constant() && retop != op {
                    // the trace does not come back to this RETURN
                    self.add_parameter_patch(retop, rep, slot);
                }
            }
            self.returns_traversed = true;
        }
        Ok(self.add_parameter_patch(op, rvn, slot))
    }

    /// Port of `SubvariableFlow::tryCallReturnPush`.
    fn try_call_return_push(&mut self, op: OpId, rvn: RVarId) -> Result<bool> {
        if self.consumed_outside(rvn)? || self.mask(rvn) & 1 == 0 || self.bitsize < 8 {
            return Ok(false);
        }
        let Some(c) = self.fd.call_of(op) else { return Ok(false) };
        let fc = self.fd.call(c);
        if fc.proto.locked.is_some() || fc.active_output.is_some() {
            return Ok(false);
        }
        self.add_push(op, rvn);
        Ok(true)
    }

    /// Port of `SubvariableFlow::trySwitchPull`.
    fn try_switch_pull(&mut self, op: OpId, rvn: RVarId) -> Result<Flow> {
        let mask = self.mask(rvn);
        if mask & 1 == 0 || self.fd.vn(self.orig(rvn)?).consume & !mask != 0 {
            return Ok(Flow::Abort);
        }
        Ok(self.add_parameter_patch(op, rvn, 0))
    }

    /// Port of `SubvariableFlow::tryInt2FloatPull`.
    fn try_int2float_pull(&mut self, op: OpId, rvn: RVarId) -> Result<Flow> {
        let (fd, mask, vn) = (self.fd, self.mask(rvn), self.orig(rvn)?);
        let v = fd.vn(vn);
        if mask & 1 == 0 || fd.nzmask(vn) & !mask != 0 || v.size == self.flowsize {
            return Ok(Flow::Abort);
        }
        // a ZEXT of the preferred size read by this op alone already has the right form
        let in_form = v.def.is_some_and(|d| fd.op(d).opc == Opcode::IntZext)
            && v.size == preferred_zext_size(self.flowsize)
            && v.descend[..] == [op];
        self.g.patch(PatchKind::Int2Float, op, rvn, 0);
        if !in_form {
            self.pullcount += 1;
        }
        Ok(Flow::Handled)
    }

    /// A replacement of `op` reading `rvn` in `slot` and writing `op`'s output with `newmask`.
    fn link_down(&mut self, opc: Opcode, op: OpId, rvn: RVarId, slot: usize, newmask: u64) -> Result<Flow> {
        let Some(outvn) = self.fd.op(op).out else { return err("subflow: a traced op without output") };
        let rop = self.create_op_down(opc, op, rvn, slot);
        Ok(if self.create_link(Some(rop), newmask, None, outvn)? { Flow::Handled } else { Flow::Abort })
    }

    /// The comparison cases of `traceForward`: everything but the logical value must be zero
    /// on both sides (unless aggressive).
    fn forward_compare(&mut self, op: OpId, rvn: RVarId, vn: VarnodeId, slot: usize) -> Result<Flow> {
        let (fd, mask) = (self.fd, self.mask(rvn));
        let other = fd.input(op, 1 - slot)?;
        if !self.aggressive && fd.nzmask(vn) | mask != mask {
            return Ok(Flow::Abort);
        }
        let o = fd.vn(other);
        let other_bits = if o.is_constant() {
            o.offset
        } else if self.aggressive {
            0
        } else {
            fd.nzmask(other)
        };
        if mask | other_bits != mask {
            return Ok(Flow::Abort);
        }
        Ok(self.create_compare_bridge(op, rvn, slot, other))
    }

    /// The single-bit case of INT_EQUAL / INT_NOTEQUAL in `traceForward`: the comparison of a
    /// flag with 0 or with its bit is the flag or its negation.
    fn forward_bool_compare(&mut self, op: OpId, rvn: RVarId, vn: VarnodeId, slot: usize) -> Result<Flow> {
        let fd = self.fd;
        let other = fd.vn(fd.input(op, 1 - slot)?);
        let newmask = fd.nzmask(vn);
        if !other.is_constant() || newmask != self.mask(rvn) {
            return Ok(Flow::Abort);
        }
        let mut booldir = match other.offset {
            0 => true,
            c if c == newmask => false,
            _ => return Ok(Flow::Abort),
        };
        if fd.op(op).opc == Opcode::IntEqual {
            booldir = !booldir;
        }
        if booldir {
            return Ok(self.add_terminal_patch(op, rvn));
        }
        let rop = self.create_op_down(Opcode::BoolNegate, op, rvn, 0);
        // createNewOut
        let out = self.g.new_var(None, 1, 0);
        self.g.ops[rop.0].output = Some(out);
        self.g.vars[out.0].def = Some(rop);
        Ok(self.add_terminal_patch(op, out))
    }

    /// The INT_AND case of `traceForward`.
    fn forward_and(&mut self, op: OpId, rvn: RVarId, slot: usize) -> Result<Flow> {
        let (fd, mask) = (self.fd, self.mask(rvn));
        let c = fd.vn(fd.input(op, 1)?);
        let Some(outvn) = fd.op(op).out else { return err("INT_AND without output") };
        let out = fd.vn(outvn);
        if c.is_constant() && c.offset == mask {
            if out.size == self.flowsize && mask & 1 != 0 {
                return Ok(self.add_terminal_patch(op, rvn));
            }
            // the small variable is zero padded into something consumed beyond it
            if !self.aggressive && out.consume & mask != out.consume {
                return Ok(self.add_extension_patch(rvn, op, None));
            }
        }
        if does_and_clear(fd, op, mask)?.is_some() {
            return Ok(Flow::Unhandled);
        }
        self.link_down(Opcode::IntAnd, op, rvn, slot, mask)
    }

    /// The shift-amount case of the shifts in `traceForward`.
    fn forward_shift_amount(&mut self, op: OpId, rvn: RVarId) -> Flow {
        if self.mask(rvn) & 1 == 0 || self.bitsize < 8 {
            return Flow::Abort;
        }
        self.add_parameter_patch(op, rvn, 1)
    }

    /// The constant shift of `op`, as the C++ `int4`.
    fn shift_amount(&self, op: OpId) -> Result<Option<i32>> {
        let c = self.fd.vn(self.fd.input(op, 1)?);
        Ok(c.is_constant().then_some(c.offset as i32))
    }

    /// The INT_LEFT case of `traceForward`.
    fn forward_left(&mut self, op: OpId, rvn: RVarId, slot: usize) -> Result<Flow> {
        if slot == 1 {
            return Ok(self.forward_shift_amount(op, rvn));
        }
        let (fd, mask) = (self.fd, self.mask(rvn));
        let Some(sa) = self.shift_amount(op)? else { return Ok(Flow::Abort) };
        if !(0..64).contains(&sa) {
            // beyond the precision of the mask (a negative amount wraps as the C++ comparison)
            return Ok(Flow::Abort);
        }
        let Some(outvn) = fd.op(op).out else { return err("INT_LEFT without output") };
        let out = fd.vn(outvn);
        let newmask = (mask << sa) & calc_mask(out.size);
        if newmask == 0 {
            return Ok(Flow::Unhandled);
        }
        if mask != newmask >> sa {
            return Ok(Flow::Abort);
        }
        if mask & 1 != 0 && sa + self.bitsize == 8 * out.size as i32 && out.consume & !newmask != 0 {
            return Ok(self.add_extension_patch(rvn, op, Some(sa)));
        }
        self.link_down(Opcode::Copy, op, rvn, 0, newmask)
    }

    /// The INT_RIGHT / INT_SRIGHT case of `traceForward`.
    fn forward_right(&mut self, op: OpId, rvn: RVarId, slot: usize) -> Result<Flow> {
        if slot == 1 {
            return Ok(self.forward_shift_amount(op, rvn));
        }
        let (fd, mask) = (self.fd, self.mask(rvn));
        let Some(sa) = self.shift_amount(op)? else { return Ok(Flow::Abort) };
        let newmask = if (0..64).contains(&sa) { mask >> sa } else { 0 };
        if newmask == 0 {
            // an unsigned shift loses the value: the flow ends
            return Ok(if fd.op(op).opc == Opcode::IntRight { Flow::Unhandled } else { Flow::Abort });
        }
        if mask != newmask << sa {
            return Ok(Flow::Abort);
        }
        let Some(outvn) = fd.op(op).out else { return err("shift without output") };
        let out = fd.vn(outvn);
        if out.size == self.flowsize && newmask & 1 == 1 && fd.nzmask(fd.input(op, 0)?) == mask {
            return Ok(self.add_terminal_patch(op, rvn));
        }
        if newmask & 1 == 1 && sa + self.bitsize == 8 * out.size as i32 && out.consume & !newmask != 0 {
            return Ok(self.add_extension_patch(rvn, op, Some(0)));
        }
        self.link_down(Opcode::Copy, op, rvn, 0, newmask)
    }

    /// The SUBPIECE case of `traceForward`.
    fn forward_subpiece(&mut self, op: OpId, rvn: RVarId) -> Result<Flow> {
        let (fd, mask) = (self.fd, self.mask(rvn));
        let sa = (fd.vn(fd.input(op, 1)?).offset as i32).wrapping_mul(8);
        if !(0..64).contains(&sa) {
            return Ok(Flow::Unhandled);
        }
        let Some(outvn) = fd.op(op).out else { return err("SUBPIECE without output") };
        let out = fd.vn(outvn);
        let newmask = (mask >> sa) & calc_mask(out.size);
        if newmask == 0 {
            return Ok(Flow::Unhandled);
        }
        if mask != newmask << sa {
            // a truncation of the logical value: only a piece of it remains
            if self.flowsize as i32 > sa / 8 + out.size as i32 && mask & 1 != 0 {
                return Ok(self.add_parameter_patch(op, rvn, 0));
            }
            return Ok(Flow::Abort);
        }
        let whole = self.bitsize >= 8 || !newmask & fd.nzmask(outvn) == 0;
        if newmask & 1 != 0 && out.size == self.flowsize && whole {
            return Ok(self.add_terminal_patch(op, rvn));
        }
        self.link_down(Opcode::Copy, op, rvn, 0, newmask)
    }

    /// The INT_MULT case of `traceForward`.
    fn forward_mult(&mut self, op: OpId, rvn: RVarId, vn: VarnodeId, slot: usize) -> Result<Flow> {
        let (fd, mask) = (self.fd, self.mask(rvn));
        if mask & 1 == 0 {
            return Ok(Flow::Abort); // cannot account for carry
        }
        // the nearest multiple of 8 below the other factor's lowest bit
        let sa = leastsigbit_set(fd.nzmask(fd.input(op, 1 - slot)?)) & !7;
        if self.bitsize + sa > 8 * fd.vn(vn).size as i32 {
            return Ok(Flow::Abort);
        }
        self.link_down(Opcode::IntMult, op, rvn, slot, mask.wrapping_shl(sa as u32))
    }

    /// Whether INT_DIV / INT_REM `op` can act on the logical value: whole bytes at the least
    /// significant end, both inputs zero-extended from it.
    fn division_fits(&self, op: OpId, mask: u64) -> Result<bool> {
        let fd = self.fd;
        Ok(mask & 1 != 0
            && self.bitsize & 7 == 0
            && is_zero_extended(fd, fd.input(op, 0)?, self.flowsize)
            && is_zero_extended(fd, fd.input(op, 1)?, self.flowsize))
    }

    /// One reader of `vn` in `SubvariableFlow::traceForward`.
    fn forward_op(&mut self, op: OpId, rvn: RVarId, vn: VarnodeId, slot: usize) -> Result<Flow> {
        use Opcode::*;
        let (fd, mask) = (self.fd, self.mask(rvn));
        let opc = fd.op(op).opc;
        match opc {
            Copy | Multiequal | IntNegate | IntXor => self.link_down(opc, op, rvn, slot, mask),
            // the sub-variable set to ones: the flow ends
            IntOr if does_or_set(fd, op, mask)?.is_some() => Ok(Flow::Unhandled),
            IntOr => self.link_down(IntOr, op, rvn, slot, mask),
            IntAnd => self.forward_and(op, rvn, slot),
            IntZext | IntSext => self.link_down(Copy, op, rvn, 0, mask),
            IntMult => self.forward_mult(op, rvn, vn, slot),
            IntDiv | IntRem if self.division_fits(op, mask)? => self.link_down(opc, op, rvn, slot, mask),
            IntAdd if mask & 1 != 0 => self.link_down(IntAdd, op, rvn, slot, mask),
            IntLeft => self.forward_left(op, rvn, slot),
            IntRight | IntSright => self.forward_right(op, rvn, slot),
            Subpiece => self.forward_subpiece(op, rvn),
            Piece => {
                let high = fd.input(op, 0)? == vn;
                let sa = if high { 8 * fd.vn(fd.input(op, 1)?).size } else { 0 };
                self.link_down(Copy, op, rvn, 0, mask.wrapping_shl(sa))
            }
            IntLess | IntLessequal => self.forward_compare(op, rvn, vn, slot),
            IntNotequal | IntEqual if self.bitsize != 1 => self.forward_compare(op, rvn, vn, slot),
            IntNotequal | IntEqual => self.forward_bool_compare(op, rvn, vn, slot),
            Call | Callind => self.try_call_pull(op, rvn, slot),
            Return => self.try_return_pull(op, rvn, slot),
            Branchind => self.try_switch_pull(op, rvn),
            // the patch leaves the reader counted as not dealt with, as in the C++
            BoolNegate | BoolAnd | BoolOr | BoolXor if self.bitsize == 1 && mask == 1 => {
                self.g.patch(PatchKind::Parameter, op, rvn, slot as i32);
                Ok(Flow::Unhandled)
            }
            FloatInt2float => self.try_int2float_pull(op, rvn),
            Cbranch if self.bitsize == 1 && slot == 1 && mask == 1 => {
                self.g.patch(PatchKind::Parameter, op, rvn, 1);
                Ok(Flow::Handled)
            }
            _ => Ok(Flow::Abort),
        }
    }

    /// One reader of `vn` in `SubvariableFlow::traceForwardSext`.
    fn forward_sext_op(&mut self, op: OpId, rvn: RVarId, slot: usize) -> Result<Flow> {
        use Opcode::*;
        let (fd, mask) = (self.fd, self.mask(rvn));
        let opc = fd.op(op).opc;
        match opc {
            Copy | Multiequal | IntNegate | IntXor | IntOr | IntAnd => self.link_down(opc, op, rvn, slot, mask),
            IntSext => self.link_down(Copy, op, rvn, 0, mask),
            IntSright => {
                let savn = fd.input(op, 1)?;
                if !fd.vn(savn).is_constant() {
                    return Ok(Flow::Abort);
                }
                let Some(outvn) = fd.op(op).out else { return err("INT_SRIGHT without output") };
                let rop = self.create_op_down(IntSright, op, rvn, 0);
                if !self.create_link(Some(rop), mask, None, outvn)? {
                    return Ok(Flow::Abort);
                }
                self.add_constant(Some(rop), calc_mask(fd.vn(savn).size), 1, savn);
                Ok(Flow::Handled)
            }
            Subpiece => {
                let outsize = fd.op(op).out.map_or(0, |o| fd.vn(o).size);
                if fd.vn(fd.input(op, 1)?).offset != 0 || outsize > self.flowsize {
                    return Ok(Flow::Abort);
                }
                Ok(if outsize == self.flowsize {
                    self.add_terminal_patch(op, rvn)
                } else {
                    self.add_parameter_patch(op, rvn, 0)
                })
            }
            IntLess | IntLessequal | IntSless | IntSlessequal | IntEqual | IntNotequal => {
                Ok(self.create_compare_bridge(op, rvn, slot, fd.input(op, 1 - slot)?))
            }
            Call | Callind => self.try_call_pull(op, rvn, slot),
            Return => self.try_return_pull(op, rvn, slot),
            Branchind => self.try_switch_pull(op, rvn),
            _ => Ok(Flow::Abort),
        }
    }

    /// Port of `SubvariableFlow::traceForward` and `traceForwardSext`: every reader of the
    /// container takes the logical value, ends the flow, or fails the trace.
    fn trace_forward(&mut self, rvn: RVarId) -> Result<bool> {
        let fd = self.fd;
        let vn = self.orig(rvn)?;
        let (mut dcount, mut hcount, mut callcount) = (0, 0, 0);
        for (pos, &op) in fd.vn(vn).descend.iter().enumerate() {
            let o = fd.op(op);
            if o.out.is_some_and(|out| self.varmap.contains_key(&out)) && !o.is_call() {
                continue;
            }
            dcount += 1;
            let Some(mut slot) = fd.slot_of(op, vn) else { return err("subflow: a reader without the varnode") };
            if matches!(o.opc, Opcode::Call | Opcode::Callind) {
                callcount += 1;
                if callcount > 1 {
                    slot = repeat_slot(fd, op, vn, slot, pos)?;
                }
            }
            let flow =
                if self.sext { self.forward_sext_op(op, rvn, slot)? } else { self.forward_op(op, rvn, vn, slot)? };
            match flow {
                Flow::Abort => return Ok(false),
                Flow::Handled => hcount += 1,
                Flow::Unhandled => {}
            }
        }
        // an input must be replaced as a whole
        Ok(dcount == hcount || !fd.vn(vn).is_input())
    }

    /// The INT_LEFT case of `traceBackward`.
    fn backward_left(&mut self, op: OpId, rvn: RVarId) -> Result<bool> {
        let (fd, mask) = (self.fd, self.mask(rvn));
        let Some(sa) = self.shift_amount(op)? else { return Ok(false) };
        let newmask = if (0..64).contains(&sa) { mask >> sa } else { 0 };
        let (in0, in1) = (fd.input(op, 0)?, fd.input(op, 1)?);
        if newmask == 0 {
            // filled with shifted-in zeros
            let rop = self.create_op(Opcode::Copy, rvn)?;
            self.add_new_zero(rop);
            return Ok(true);
        }
        if newmask << sa == mask {
            let rop = self.create_op(Opcode::Copy, rvn)?;
            return self.links(rop, &[(newmask, 0, in0)]);
        }
        if mask & 1 == 0 {
            return Ok(false); // zeros are not known to be shifted into the low bits
        }
        let rop = self.create_op(Opcode::IntLeft, rvn)?;
        if !self.links(rop, &[(mask, 0, in0)])? {
            return Ok(false);
        }
        self.add_constant(Some(rop), calc_mask(fd.vn(in1).size), 1, in1);
        Ok(true)
    }

    /// The INT_RIGHT / INT_SRIGHT cases of `traceBackward`.
    fn backward_right(&mut self, op: OpId, rvn: RVarId) -> Result<bool> {
        let (fd, mask) = (self.fd, self.mask(rvn));
        let Some(sa) = self.shift_amount(op)? else { return Ok(false) };
        if !(0..64).contains(&sa) {
            return Ok(false);
        }
        let in0 = fd.input(op, 0)?;
        let newmask = (mask << sa) & calc_mask(fd.vn(in0).size);
        if newmask == 0 && fd.op(op).opc == Opcode::IntRight {
            let rop = self.create_op(Opcode::Copy, rvn)?;
            self.add_new_zero(rop);
            return Ok(true);
        }
        if newmask >> sa != mask {
            return Ok(false); // truncated by the shift
        }
        let rop = self.create_op(Opcode::Copy, rvn)?;
        self.links(rop, &[(newmask, 0, in0)])
    }

    /// The INT_MULT case of `traceBackward`.
    fn backward_mult(&mut self, op: OpId, rvn: RVarId) -> Result<bool> {
        let (fd, mask) = (self.fd, self.mask(rvn));
        let (in0, in1) = (fd.input(op, 0)?, fd.input(op, 1)?);
        let sa = leastsigbit_set(mask);
        if sa != 0 {
            if leastsigbit_set(fd.nzmask(in1)) < sa {
                return Ok(false); // carries into the logical multiply
            }
            let rop = self.create_op(Opcode::IntMult, rvn)?;
            return self.links(rop, &[(mask.wrapping_shr(sa as u32), 0, in0), (mask, 1, in1)]);
        }
        // a single bit multiply is an AND
        let rop = self.create_op(if mask == 1 { Opcode::IntAnd } else { Opcode::IntMult }, rvn)?;
        self.links(rop, &[(mask, 0, in0), (mask, 1, in1)])
    }

    /// The INT_AND and INT_OR cases of `traceBackward`: a constant that clears (sets) the
    /// logical bits gives a COPY of it.
    fn backward_logical(&mut self, op: OpId, rvn: RVarId) -> Result<bool> {
        let (fd, mask) = (self.fd, self.mask(rvn));
        let opc = fd.op(op).opc;
        let fixed = if opc == Opcode::IntAnd { does_and_clear(fd, op, mask)? } else { does_or_set(fd, op, mask)? };
        if let Some(slot) = fixed {
            let rop = self.create_op(Opcode::Copy, rvn)?;
            self.add_constant(Some(rop), mask, 0, fd.input(op, slot)?);
            return Ok(true);
        }
        let rop = self.create_op(opc, rvn)?;
        self.links(rop, &[(mask, 0, fd.input(op, 0)?), (mask, 1, fd.input(op, 1)?)])
    }

    /// The INT_ZEXT / INT_SEXT case of `traceBackward`.
    fn backward_ext(&mut self, op: OpId, rvn: RVarId) -> Result<bool> {
        let (fd, mask) = (self.fd, self.mask(rvn));
        let in0 = fd.input(op, 0)?;
        let insize = fd.vn(in0).size;
        if mask & calc_mask(insize) != mask {
            // the logical value is wider than the extended one
            if mask & 1 != 0 && self.flowsize > insize {
                self.add_push(op, rvn);
                return Ok(true);
            }
            return Ok(false);
        }
        let rop = self.create_op(Opcode::Copy, rvn)?;
        self.links(rop, &[(mask, 0, in0)])
    }

    /// The PIECE case of `traceBackward`.
    fn backward_piece(&mut self, op: OpId, rvn: RVarId) -> Result<bool> {
        let (fd, mask) = (self.fd, self.mask(rvn));
        let (hi, lo) = (fd.input(op, 0)?, fd.input(op, 1)?);
        let losize = fd.vn(lo).size;
        let (newmask, src) = if mask & calc_mask(losize) == mask {
            (mask, lo)
        } else {
            let newmask = mask.wrapping_shr(8 * losize);
            if newmask.wrapping_shl(8 * losize) != mask {
                return Ok(false);
            }
            (newmask, hi)
        };
        let rop = self.create_op(Opcode::Copy, rvn)?;
        self.links(rop, &[(newmask, 0, src)])
    }

    /// Port of `SubvariableFlow::traceBackward`: the op writing the container writes the
    /// logical value from the logical parts of its inputs.
    fn trace_backward(&mut self, rvn: RVarId) -> Result<bool> {
        use Opcode::*;
        let (fd, mask) = (self.fd, self.mask(rvn));
        let Some(op) = fd.vn(self.orig(rvn)?).def else { return Ok(true) };
        let opc = fd.op(op).opc;
        match opc {
            Copy | Multiequal | IntNegate | IntXor => self.backward_same(op, rvn),
            IntAnd | IntOr => self.backward_logical(op, rvn),
            IntZext | IntSext => self.backward_ext(op, rvn),
            IntAdd if mask & 1 != 0 => {
                // a single bit add is an XOR
                let rop = self.create_op(if mask == 1 { IntXor } else { IntAdd }, rvn)?;
                self.links(rop, &[(mask, 0, fd.input(op, 0)?), (mask, 1, fd.input(op, 1)?)])
            }
            IntLeft => self.backward_left(op, rvn),
            IntRight | IntSright => self.backward_right(op, rvn),
            IntMult => self.backward_mult(op, rvn),
            IntDiv | IntRem if self.division_fits(op, mask)? => {
                let rop = self.create_op(opc, rvn)?;
                self.links(rop, &[(mask, 0, fd.input(op, 0)?), (mask, 1, fd.input(op, 1)?)])
            }
            Subpiece => {
                let sa = (fd.vn(fd.input(op, 1)?).offset as u32).wrapping_mul(8);
                let rop = self.create_op(Copy, rvn)?;
                self.links(rop, &[(mask.wrapping_shl(sa), 0, fd.input(op, 0)?)])
            }
            Piece => self.backward_piece(op, rvn),
            Call | Callind => self.try_call_return_push(op, rvn),
            // a boolean writes nothing above its lowest bit
            IntEqual | IntNotequal | IntSless | IntSlessequal | IntLess | IntLessequal | IntCarry | IntScarry
            | IntSborrow | BoolNegate | BoolXor | BoolAnd | BoolOr | FloatEqual | FloatNotequal | FloatLessequal
            | FloatNan
                if mask & 1 == 0 =>
            {
                let rop = self.create_op(Copy, rvn)?;
                self.add_new_zero(rop);
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    /// The ops that act on the logical value as on the container: every input with the mask.
    fn backward_same(&mut self, op: OpId, rvn: RVarId) -> Result<bool> {
        let mask = self.mask(rvn);
        let rop = self.create_op(self.fd.op(op).opc, rvn)?;
        let items: Vec<_> = self.fd.op(op).ins.iter().enumerate().map(|(i, &vn)| (mask, i, vn)).collect();
        self.links(rop, &items)
    }

    /// Port of `SubvariableFlow::traceBackwardSext`.
    fn trace_backward_sext(&mut self, rvn: RVarId) -> Result<bool> {
        use Opcode::*;
        let (fd, mask) = (self.fd, self.mask(rvn));
        let Some(op) = fd.vn(self.orig(rvn)?).def else { return Ok(true) };
        match fd.op(op).opc {
            Copy | Multiequal | IntNegate | IntXor | IntAnd | IntOr => self.backward_same(op, rvn),
            IntZext if fd.vn(fd.input(op, 0)?).size < self.flowsize => {
                self.add_push(op, rvn);
                Ok(true)
            }
            IntSext if fd.vn(fd.input(op, 0)?).size == self.flowsize => {
                let rop = self.create_op(Copy, rvn)?;
                self.links(rop, &[(mask, 0, fd.input(op, 0)?)])
            }
            IntSright => {
                let savn = fd.input(op, 1)?;
                if !fd.vn(savn).is_constant() {
                    return Ok(false);
                }
                let rop = self.create_op(IntSright, rvn)?;
                if !self.links(rop, &[(mask, 0, fd.input(op, 0)?)])? {
                    return Ok(false);
                }
                if self.g.ops[rop.0].input.len() == 1 {
                    self.add_constant(Some(rop), calc_mask(fd.vn(savn).size), 1, savn);
                }
                Ok(true)
            }
            Call | Callind => self.try_call_return_push(op, rvn),
            _ => Ok(false),
        }
    }

    /// Port of `SubvariableFlow::doTrace`: the transform, if the logical value traces through
    /// and at least one op pulls it out.
    pub(crate) fn do_trace(mut self) -> Result<Option<Replacement>> {
        if !self.valid {
            return Ok(None);
        }
        while let Some(rvn) = self.worklist.pop() {
            let back = if self.sext { self.trace_backward_sext(rvn)? } else { self.trace_backward(rvn)? };
            if !back || !self.trace_forward(rvn)? {
                return Ok(None);
            }
        }
        if self.pullcount == 0 {
            return Ok(None);
        }
        Ok(Some(Replacement { g: self.g, flowsize: self.flowsize, bitsize: self.bitsize, aggressive: self.aggressive }))
    }
}

/// `TypeOpFloatInt2Float::preferredZextSize`.
pub(crate) fn preferred_zext_size(in_size: u32) -> u32 {
    match in_size {
        0..=3 => 4,
        4..=7 => 8,
        _ => in_size + 1,
    }
}

impl Replacement {
    /// Port of `SubvariableFlow::useSameAddress`: whether the logical varnode can live at the
    /// container's storage.
    fn use_same_address(&self, fd: &Funcdata, vn: VarnodeId, mask: u64) -> bool {
        let v = fd.vn(vn);
        if v.is_input() {
            return true;
        }
        if v.has(VnFlags::ADDRTIED) || mask & 1 == 0 {
            return false;
        }
        if self.bitsize >= 8 || self.aggressive {
            return true;
        }
        // a flag: not when more of the varnode is consumed than this flow
        v.consume | ((1u64 << self.bitsize) - 1) == mask
    }

    /// Port of `SubvariableFlow::replaceInput`: an input being shrunk moves to a temporary,
    /// so the new input does not overlap it.
    fn replace_input(fd: &mut Funcdata, arch: &Arch, vn: VarnodeId, uniq: u32) -> Result<VarnodeId> {
        let newvn = fd.new_unique(fd.vn(vn).size, uniq);
        let newvn = fd.set_input_varnode(newvn, arch)?;
        fd.total_replace(vn, newvn)?;
        fd.delete_varnode(vn);
        Ok(newvn)
    }

    /// Port of `SubvariableFlow::getReplaceVarnode`: the varnode of the logical size standing
    /// for a placeholder, made on first use.
    fn replace_varnode(&mut self, fd: &mut Funcdata, arch: &Arch, rvn: RVarId) -> Result<VarnodeId> {
        let r = &self.g.vars[rvn.0];
        if let Some(repl) = r.replacement {
            return Ok(repl);
        }
        let Some(uniq) = fd.uniq else { return err("no unique space") };
        let (mask, val) = (r.mask, r.val);
        let Some(vn) = r.vn else {
            if r.def.is_none() {
                return Ok(fd.new_constant(self.flowsize, val)); // a constant with no original
            }
            let repl = fd.new_unique(self.flowsize, uniq);
            self.g.vars[rvn.0].replacement = Some(repl);
            return Ok(repl);
        };
        if fd.vn(vn).is_constant() {
            return Ok(fd.new_constant(self.flowsize, val));
        }
        let is_input = fd.vn(vn).is_input();
        let mut repl = if self.use_same_address(fd, vn, mask) {
            // getReplacementAddress: the bytes of the logical value within the container
            let v = fd.vn(vn);
            if v.space == Space::Join {
                return err("subflow: a logical value in a join varnode is not ported");
            }
            let (space, off) = (v.space, v.offset + (leastsigbit_set(mask) / 8) as u64);
            if is_input {
                self.g.vars[rvn.0].vn = Some(Self::replace_input(fd, arch, vn, uniq)?);
            }
            fd.new_varnode(self.flowsize, space, off)
        } else {
            fd.new_unique(self.flowsize, uniq)
        };
        if is_input {
            repl = fd.set_input_varnode(repl, arch)?;
        }
        self.g.vars[rvn.0].replacement = Some(repl);
        Ok(repl)
    }

    /// The push patches of `doReplacement`: the op writes the logical value, and a new ZEXT
    /// after it writes the old output.
    fn apply_push(&mut self, fd: &mut Funcdata, arch: &Arch, p: &Patch) -> Result<()> {
        let new_vn = self.replace_varnode(fd, arch, p.in1)?;
        let Some(old_vn) = fd.op(p.op).out else { return err("subflow: push op without output") };
        fd.op_set_output(p.op, new_vn)?;
        let zext = fd.new_op(Opcode::IntZext, fd.op(p.op).seq.addr);
        fd.op_set_input(zext, new_vn, 0)?;
        fd.op_set_output(zext, old_vn)?;
        fd.op_insert_after(zext, p.op)
    }

    /// The replacement ops of `doReplacement`: each made after the op it parallels, with its
    /// output; then every input.
    fn apply_ops(&mut self, fd: &mut Funcdata, arch: &Arch) -> Result<()> {
        let mut new_ops = Vec::with_capacity(self.g.ops.len());
        for i in 0..self.g.ops.len() {
            let (op, opc, output) = (self.g.ops[i].op, self.g.ops[i].opc, self.g.ops[i].output);
            let newop = fd.new_op(opc, fd.op(op).seq.addr);
            let Some(rout) = output else { return err("subflow: replacement op without output") };
            let outvn = self.replace_varnode(fd, arch, rout)?;
            fd.op_set_output(newop, outvn)?;
            fd.op_insert_after(newop, op)?;
            new_ops.push(newop);
        }
        for (i, &newop) in new_ops.iter().enumerate() {
            for slot in 0..self.g.ops[i].input.len() {
                let Some(rin) = self.g.ops[i].input[slot] else {
                    return err("subflow: replacement op misses an input");
                };
                let invn = self.replace_varnode(fd, arch, rin)?;
                fd.op_set_input(newop, invn, slot)?;
            }
        }
        Ok(())
    }

    /// The extension patch of `doReplacement`: the op becomes a zero extension of the logical
    /// value, shifted left by `sa` bits.
    fn apply_extension(fd: &mut Funcdata, pullop: OpId, in_vn: VarnodeId, sa: i32) -> Result<()> {
        let Some(out) = fd.op(pullop).out else { return err("subflow: extension op without output") };
        let out_size = fd.vn(out).size;
        let same_size = fd.vn(in_vn).size == out_size;
        if sa == 0 {
            fd.op_set_opcode(pullop, if same_size { Opcode::Copy } else { Opcode::IntZext });
            return fd.op_set_all_input(pullop, &[in_vn]);
        }
        let first = if same_size {
            in_vn
        } else {
            let Some(uniq) = fd.uniq else { return err("no unique space") };
            let zextop = fd.new_op(Opcode::IntZext, fd.op(pullop).seq.addr);
            let zextout = fd.new_unique_out(out_size, uniq, zextop);
            fd.op_set_input(zextop, in_vn, 0)?;
            fd.op_insert_before(zextop, pullop)?;
            zextout
        };
        let c = fd.new_constant(4, sa as u64);
        fd.op_set_all_input(pullop, &[first, c])?;
        fd.op_set_opcode(pullop, Opcode::IntLeft);
        Ok(())
    }

    /// One patch of `doReplacement` other than a push.
    fn apply_patch(&mut self, fd: &mut Funcdata, arch: &Arch, p: &Patch) -> Result<()> {
        match p.kind {
            PatchKind::Copy => {
                while fd.op(p.op).ins.len() > 1 {
                    fd.op_remove_input(p.op, fd.op(p.op).ins.len() - 1);
                }
                let in1 = self.replace_varnode(fd, arch, p.in1)?;
                fd.op_set_input(p.op, in1, 0)?;
                fd.op_set_opcode(p.op, Opcode::Copy);
            }
            PatchKind::Compare => {
                let in1 = self.replace_varnode(fd, arch, p.in1)?;
                fd.op_set_input(p.op, in1, 0)?;
                let Some(rin2) = p.in2 else { return err("subflow: compare patch without second input") };
                let in2 = self.replace_varnode(fd, arch, rin2)?;
                fd.op_set_input(p.op, in2, 1)?;
            }
            PatchKind::Parameter => {
                let in1 = self.replace_varnode(fd, arch, p.in1)?;
                fd.op_set_input(p.op, in1, p.slot as usize)?;
            }
            PatchKind::Extension => {
                let in1 = self.replace_varnode(fd, arch, p.in1)?;
                Self::apply_extension(fd, p.op, in1, p.slot)?;
            }
            PatchKind::Push => {} // handled first
            PatchKind::Int2Float => {
                let Some(uniq) = fd.uniq else { return err("no unique space") };
                let zext = fd.new_op(Opcode::IntZext, fd.op(p.op).seq.addr);
                let in1 = self.replace_varnode(fd, arch, p.in1)?;
                fd.op_set_input(zext, in1, 0)?;
                let outvn = fd.new_unique_out(preferred_zext_size(fd.vn(in1).size), uniq, zext);
                fd.op_insert_before(zext, p.op)?;
                fd.op_set_input(p.op, outvn, 0)?;
            }
        }
        Ok(())
    }

    /// Port of `SubvariableFlow::doReplacement`: the push patches, the replacement ops, then
    /// the patches pulling the logical value out.
    pub(crate) fn apply(mut self, fd: &mut Funcdata, arch: &Arch) -> Result<()> {
        let patches = std::mem::take(&mut self.g.patches);
        let npush = patches.iter().take_while(|p| p.kind == PatchKind::Push).count();
        for p in patches.iter().take(npush) {
            self.apply_push(fd, arch, p)?;
        }
        self.apply_ops(fd, arch)?;
        for p in patches.iter().skip(npush) {
            self.apply_patch(fd, arch, p)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn int2float_zext_sizes() {
        // TypeOpFloatInt2Float::preferredZextSize
        assert_eq!([1, 3, 4, 7, 8].map(preferred_zext_size), [4, 4, 8, 8, 9]);
    }
}
