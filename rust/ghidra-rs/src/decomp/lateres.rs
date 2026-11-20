//! `FuncCallSpecs::lateRestriction` for a locked prototype (stage S6), with
//! `transferLockedInput/Output` and `commitNewInputs/Outputs`: when `ActionDeindirect` resolves
//! an indirect call to a function whose prototype is locked, the call's inputs and output are
//! redone from the locked parameters, reusing the varnodes its trials found.

use super::fspec::{Containment, ExtraPop, FuncProto, ParamActive, ParamTrial, Storage};
use super::funcdata::{CallId, Funcdata};
use super::locked::{containment, Locked};
use super::op::OpFlags;
use super::opcode::Opcode;
use super::varnode::{Space, VarnodeId, VnFlags};
use super::{err, Arch, LowlevelError, Result};

/// The single-space range of a storage (`None` for a join).
fn range(st: &Storage) -> Option<(Space, u64, u32)> {
    match st {
        Storage::Space { space, offset, size } => Some((Space::Sleigh(*space), *offset, *size)),
        Storage::Stack { offset, size } => Some((Space::Stack, *offset, *size)),
        Storage::Join(_) => None,
    }
}

/// Port of `FuncCallSpecs::getSpacebaseRelative`: the pointer the stack placeholder loads
/// through.
fn spacebase_relative(fd: &Funcdata, c: CallId) -> Option<VarnodeId> {
    let call = fd.call(c);
    let ph = *fd.op(call.op).ins.get(call.stack_placeholder_slot?)?;
    if !fd.vn(ph).has(VnFlags::SPACEBASE_PLACEHOLDER) {
        return None;
    }
    let load = fd.vn(ph).def?;
    if fd.op(load).opc != Opcode::Load {
        return None;
    }
    fd.op(load).ins.get(1).copied()
}

/// Port of `FuncCallSpecs::transferLockedInputParam`: the slot of the trial holding the
/// parameter (marked used), -1 for a stack parameter without one, 0 when it cannot be had.
fn transfer_input_param(fd: &mut Funcdata, c: CallId, space: Space, off: u64, size: u32) -> i32 {
    if let Some(a) = &mut fd.call_mut(c).active_input {
        for t in &mut a.trials {
            if t.space != space || off < t.off || t.off + u64::from(t.size) < off + u64::from(size) {
                continue;
            }
            if t.has(ParamTrial::DEFNOUSE) {
                return 0;
            }
            t.set(ParamTrial::USED);
            return t.slot as i32;
        }
    }
    if space == Space::Stack {
        -1
    } else {
        0
    }
}

/// `FuncProto::copy` onto the call. A prototype without a model stands for one with the default
/// model (the C++ model pointer is never null).
fn copy_proto(fd: &mut Funcdata, arch: &Arch, c: CallId, newproto: &FuncProto) {
    let proto = &mut fd.call_mut(c).proto;
    proto.copy(newproto);
    if proto.model.is_none() {
        let models = &arch.spec.models;
        proto.set_model(models, models.default);
    }
}

/// The address of a parameter's storage (`ProtoParameter::getAddress`; none for `void`).
fn param_addr(st: &Option<Storage>) -> Result<Option<(Space, u64)>> {
    match st {
        None => Ok(None),
        Some(s) => {
            let (space, off, _) =
                range(s).ok_or_else(|| LowlevelError("isCompatible: a join output is not ported".into()))?;
            Ok(Some((space, off)))
        }
    }
}

/// Port of `FuncProto::isCompatible` (`cur` is the call's prototype, which has a model). No
/// prototype has an effect list or likely-trash list of its own (facts.rs refuses them), and no
/// prototype is inline (facts.rs refuses the flag), so those lists and `is_inline` compare equal.
fn is_compatible(arch: &Arch, cur: &FuncProto, op2: &FuncProto) -> Result<bool> {
    let models = &arch.spec.models;
    let (Some(m1), m2) = (cur.model, op2.model.unwrap_or(models.default)) else {
        return err("isCompatible: a call prototype without a model");
    };
    if !models.is_compatible(m1, m2) {
        return Ok(false);
    }
    // both outputs locked (a prototype here locks its inputs and output together): operator==
    // compares the storage address and the data-type
    if let (Some(l1), Some(l2)) = (&cur.locked, &op2.locked) {
        if param_addr(&l1.output.storage)? != param_addr(&l2.output.storage)? || l1.output.ty != l2.output.ty {
            return Ok(false);
        }
    }
    if cur.extrapop != ExtraPop::Unknown && cur.extrapop != op2.extrapop {
        return Ok(false);
    }
    let dots = |p: &FuncProto| p.locked.as_ref().is_some_and(|l| l.dotdotdot);
    if dots(cur) != dots(op2) && (!dots(op2) || cur.locked.is_some()) {
        // a generic (unlocked) prototype still recovers varargs, so it may take a varargs one
        return Ok(false);
    }
    Ok(cur.inject == op2.inject && cur.no_return == op2.no_return)
}

/// Port of `FuncCallSpecs::lateRestriction` + `commitNewInputs` + `commitNewOutputs` (which do
/// their work only for a locked prototype). Returns false when the call cannot take the
/// prototype (`FuncCallSpecs::deindirect` then restarts the function).
pub(crate) fn late_restriction(fd: &mut Funcdata, arch: &Arch, c: CallId, newproto: &FuncProto) -> Result<bool> {
    let cur = &fd.call(c).proto;
    if cur.model.is_none() {
        copy_proto(fd, arch, c, newproto);
        return Ok(true);
    }
    if !is_compatible(arch, cur, newproto)? {
        return Ok(false);
    }
    let Some(locked) = newproto.locked.clone() else {
        copy_proto(fd, arch, c, newproto);
        return Ok(true);
    };
    if locked.dotdotdot {
        if fd.call(c).active_input.is_none() {
            return Ok(false); // !isinputactive
        }
        // the unlocked trials after the locked parameters (collectUnlockedTrials, reregisterTrial)
        return err("lateRestriction of a varargs prototype onto a call recovering its inputs (collectUnlockedTrials): not implemented in ghidra-rs yet");
    }
    let op = fd.call(c).op;
    let ins = fd.op(op).ins.clone();
    // transferLockedInput
    let mut newinput: Vec<Option<VarnodeId>> = vec![Some(ins[0])];
    let mut stackref = None;
    for p in &locked.inputs {
        let Some(st) = &p.storage else {
            newinput.push(None);
            continue;
        };
        let Some((space, off, size)) = range(st) else { return Ok(false) };
        match transfer_input_param(fd, c, space, off, size) {
            0 => return Ok(false),
            r if r > 0 => newinput.push(ins.get(r as usize).copied()),
            _ => {
                if stackref.is_none() {
                    stackref = spacebase_relative(fd, c);
                }
                if stackref.is_none() {
                    return Ok(false);
                }
                newinput.push(None);
            }
        }
    }
    // transferLockedOutput
    let mut newoutput = Vec::new();
    if let Some(st) = &locked.output.storage {
        let near = |fd: &Funcdata, vn: VarnodeId| {
            let v = fd.vn(vn);
            containment(st, v.space, v.offset, v.size) != Containment::None
        };
        if let Some(out) = fd.op(op).out.filter(|&o| near(fd, o)) {
            newoutput.push(out);
        }
        let mut prev = fd.previous_op(op);
        while let Some(ind) = prev.filter(|&p| fd.op(p).opc == Opcode::Indirect) {
            if fd.op(ind).flags.has(OpFlags::INDIRECT_CREATION) {
                if let Some(out) = fd.op(ind).out.filter(|&o| near(fd, o)) {
                    newoutput.push(out);
                }
            }
            prev = fd.previous_op(ind);
        }
    }
    copy_proto(fd, arch, c, newproto);
    commit_new_inputs(fd, arch, c, &locked, newinput, stackref)?;
    commit_new_outputs(fd, c, &locked, newoutput)?;
    Ok(true)
}

/// Port of `FuncCallSpecs::commitNewInputs` (no varargs, so no unlocked trials survive).
fn commit_new_inputs(
    fd: &mut Funcdata,
    arch: &Arch,
    c: CallId,
    locked: &Locked,
    mut newinput: Vec<Option<VarnodeId>>,
    stackref: Option<VarnodeId>,
) -> Result<()> {
    let op = fd.call(c).op;
    let mut placeholder = fd.call(c).stack_placeholder_slot.and_then(|s| fd.op(op).ins.get(s).copied());
    let mut noplacehold = true;
    fd.call_mut(c).stack_placeholder_slot = None;
    let spec = &arch.spec;
    let uniq = arch.sleigh.uniq_space();
    // activeinput.clear(), then one active trial per parameter with storage
    let mut trials = ParamActive::subcall(0);
    for (i, p) in locked.inputs.iter().enumerate() {
        let Some(st) = &p.storage else {
            let size = fd.types.size(p.ty);
            newinput[i + 1] = Some(fd.new_constant(size, 0));
            continue;
        };
        let (space, off, size) = range(st).ok_or_else(|| LowlevelError("commitNewInputs: a join parameter".into()))?;
        // buildParam
        let vn = match newinput[i + 1] {
            None => {
                let r = stackref.ok_or_else(|| LowlevelError("buildParam: no stack reference".into()))?;
                fd.op_stack_load(spec.stack_pointer, arch.stack_segment(), uniq, off, size, op, Some(r))?
            }
            Some(v) if fd.vn(v).size == size => v,
            Some(_) => {
                return err("buildParam: truncating a trial to a locked parameter is not implemented in ghidra-rs yet")
            }
        };
        newinput[i + 1] = Some(vn);
        trials.register_trial(space, off, size);
        if let Some(t) = trials.trials.last_mut() {
            t.mark_active();
        }
        if noplacehold && matches!(st, Storage::Stack { .. }) {
            fd.vn_set(vn, VnFlags::SPACEBASE_PLACEHOLDER);
            noplacehold = false;
            placeholder = None;
        }
    }
    let mut all: Vec<VarnodeId> = newinput.into_iter().flatten().collect();
    if let Some(ph) = placeholder {
        all.push(ph);
        fd.call_mut(c).stack_placeholder_slot = Some(all.len() - 1);
        // setStackPlaceholderSlot while the recovery is still on
        trials.set_placeholder_slot();
    }
    fd.op_set_all_input(op, &all)?;
    // clearActiveInput: the trials stay
    let call = fd.call_mut(c);
    call.active_input = None;
    call.kept_input = Some(trials);
    Ok(())
}

/// Whether a locked output is a boolean.
fn arch_meta_bool(fd: &Funcdata, locked: &Locked) -> bool {
    fd.types.meta(locked.output.ty) == super::types::Meta::Bool
}

/// Port of `FuncCallSpecs::commitNewOutputs` (the exact-size case; resizing another output is
/// not ported).
fn commit_new_outputs(fd: &mut Funcdata, c: CallId, locked: &Locked, newoutput: Vec<VarnodeId>) -> Result<()> {
    // the output trials are cleared and recovery ends (`clearActiveOutput`): the output is known
    fd.call_mut(c).active_output = None;
    if newoutput.is_empty() {
        return Ok(());
    }
    let st = locked.output.storage.as_ref().ok_or_else(|| LowlevelError("commitNewOutputs without storage".into()))?;
    let (space, off, size) = range(st).ok_or_else(|| LowlevelError("commitNewOutputs: a join output".into()))?;
    let op = fd.call(c).op;
    // opMarkCalculatedBool (type recovery is always on in the console)
    if size == 1 && arch_meta_bool(fd, locked) {
        fd.op_mut(op).flags.set(OpFlags::CALCULATED_BOOL);
    }
    let exact = newoutput.iter().copied().find(|&v| fd.vn(v).size == size);
    if newoutput.iter().any(|&v| Some(v) != exact) {
        return err(
            "commitNewOutputs: resizing an output to a locked return value is not implemented in ghidra-rs yet",
        );
    }
    match exact {
        Some(v) => {
            let ind = fd.vn(v).def;
            if ind != Some(op) {
                fd.op_set_output(op, v)?;
                if let Some(ind) = ind {
                    fd.op_destroy(ind);
                }
            }
        }
        None => {
            fd.op_unset_output(op);
            fd.new_varnode_out(size, space, off, op);
        }
    }
    Ok(())
}
