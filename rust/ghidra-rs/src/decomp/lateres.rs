//! `FuncCallSpecs::lateRestriction` for a locked prototype (stage S6), with
//! `transferLockedInput/Output` and `commitNewInputs/Outputs`: when `ActionDeindirect` resolves
//! an indirect call to a function whose prototype is locked, the call's inputs and output are
//! redone from the locked parameters, reusing the varnodes its trials found.

use super::fspec::{Containment, ExtraPop, FuncProto, ParamTrial, Storage};
use super::funcdata::{CallId, Funcdata};
use super::locked::{containment, Locked};
use super::op::OpFlags;
use super::opcode::Opcode;
use super::varnode::{Space, VarnodeId};
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

/// Port of `FuncCallSpecs::lateRestriction` + `commitNewInputs` + `commitNewOutputs`. Returns
/// false when the call cannot take the prototype (the C++ then restarts the function).
pub(crate) fn late_restriction(fd: &mut Funcdata, arch: &Arch, c: CallId, newproto: &FuncProto) -> Result<bool> {
    let Some(locked) = newproto.locked.clone() else { return Ok(false) };
    let cur = &fd.call(c).proto;
    if cur.model.is_none() {
        fd.call_mut(c).proto.copy(newproto);
        return Ok(true);
    }
    // FuncProto::isCompatible (no prototype here has effects or likely-trash of its own)
    if cur.model != newproto.model
        || cur.inject != newproto.inject
        || (cur.extrapop != ExtraPop::Unknown && cur.extrapop != newproto.extrapop)
        || locked.dotdotdot
    {
        return Ok(false);
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
    fd.call_mut(c).proto.copy(newproto);
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
    for (i, p) in locked.inputs.iter().enumerate() {
        let Some(st) = &p.storage else {
            let size = arch.types.size(p.ty);
            newinput[i + 1] = Some(fd.new_constant(size, 0));
            continue;
        };
        let (_, off, size) = range(st).ok_or_else(|| LowlevelError("commitNewInputs: a join parameter".into()))?;
        // buildParam
        let vn = match newinput[i + 1] {
            None => {
                let r = stackref.ok_or_else(|| LowlevelError("buildParam: no stack reference".into()))?;
                fd.op_stack_load_ref(spec.stack_pointer, spec.stack_container, uniq, off, size, op, r)?
            }
            Some(v) if fd.vn(v).size == size => v,
            Some(_) => {
                return err("buildParam: truncating a trial to a locked parameter is not implemented in ghidra-rs yet")
            }
        };
        newinput[i + 1] = Some(vn);
        if noplacehold && matches!(st, Storage::Stack { .. }) {
            fd.call_mut(c).stack_placeholder_slot = Some(i + 1);
            noplacehold = false;
            placeholder = None;
        }
    }
    let mut all: Vec<VarnodeId> = newinput.into_iter().flatten().collect();
    if let Some(ph) = placeholder {
        all.push(ph);
        fd.call_mut(c).stack_placeholder_slot = Some(all.len() - 1);
    }
    fd.op_set_all_input(op, &all)?;
    fd.call_mut(c).active_input = None;
    Ok(())
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
