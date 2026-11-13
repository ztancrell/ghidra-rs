//! Locked prototypes (stage S6): what `parse line extern` gives a function
//! (`FuncProto::setPieces`: input, output and model locked), parameter storage assigned by the
//! model (`ParamListStandard::assignMap`, the fallback assignment of `assignAddressFallback` and
//! `ParamEntry::getAddrBySlot`; x86's specs have no `<modelrule>`), and the locked paths of the
//! actions that read a prototype: `ActionPrototypeTypes`, `ActionFuncLink` (`funcLinkInput`,
//! `funcLinkOutput`) and `FuncProto::characterizeAs*`/`possible*Param`.

use super::fspec::{Containment, FuncProto, ModelId, ParamList, Storage, TypeClass};
use super::funcdata::{CallId, Funcdata};
use super::infertypes::update_type;
use super::opcode::Opcode;
use super::types::{Meta, TypeFactory, TypeId};
use super::varnode::{Space, VarnodeId, VnFlags};
use super::{err, Arch, LowlevelError, Result};

/// A parameter or return value of a locked prototype (`ProtoParameter`).
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Param {
    pub(crate) name: String,
    /// none for a `void` output (`hasStorage`)
    pub(crate) storage: Option<Storage>,
    pub(crate) ty: TypeId,
}

/// The locked part of a prototype: every parameter, the output and the model are locked
/// (`setInputLock`, `setOutputLock`, `setModelLock`); no inputs is `voidinputlock`.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Locked {
    pub(crate) inputs: Vec<Param>,
    pub(crate) output: Param,
    pub(crate) dotdotdot: bool,
}

fn type_class(types: &TypeFactory, ty: TypeId) -> TypeClass {
    match types.meta(ty) {
        Meta::Float => TypeClass::Float,
        Meta::Ptr => TypeClass::Ptr,
        _ => TypeClass::General,
    }
}

/// Port of `ParamEntry::getAddrBySlot` (little-endian, left-justified, no reverse stack).
fn addr_by_slot(list: &ParamList, i: usize, slot: &mut i32, sz: i32, talign: i32) -> Option<Storage> {
    let e = &list.entries[i];
    if sz < e.minsize {
        return None;
    }
    if e.align == 0 {
        if *slot != 0 || sz > e.size {
            return None;
        }
        return Some(match &e.storage {
            Storage::Space { space, offset, .. } => Storage::Space { space: *space, offset: *offset, size: sz as u32 },
            Storage::Stack { offset, .. } => Storage::Stack { offset: *offset, size: sz as u32 },
            Storage::Join(p) => Storage::Join(p.clone()),
        });
    }
    if talign > e.align {
        let tmp = (*slot * e.align) % talign;
        if tmp != 0 {
            *slot += (talign - tmp) / e.align;
        }
    }
    let used = (sz + e.align - 1) / e.align;
    if *slot + used > e.size / e.align {
        return None;
    }
    let off = u64::from((*slot * e.align) as u32);
    *slot += used;
    Some(match &e.storage {
        Storage::Space { space, offset, .. } => Storage::Space { space: *space, offset: offset + off, size: sz as u32 },
        Storage::Stack { offset, .. } => Storage::Stack { offset: offset + off, size: sz as u32 },
        Storage::Join(_) => return None,
    })
}

/// Port of `ParamListStandard::assignAddressFallback` (`matchExact` false; every entry is its
/// own group, and one without alignment is exclusive).
fn assign(list: &ParamList, types: &TypeFactory, ty: TypeId, status: &mut [i32]) -> Option<Storage> {
    let class = type_class(types, ty);
    let (sz, talign) = (types.align_size(ty) as i32, types.alignment(ty) as i32);
    for (grp, e) in list.entries.iter().enumerate() {
        if status[grp] < 0 || (class != e.class && e.class != TypeClass::General) {
            continue;
        }
        let Some(st) = addr_by_slot(list, grp, &mut status[grp], sz, talign) else { continue };
        if e.align == 0 {
            status[grp] = -1;
        }
        return Some(st);
    }
    None
}

/// Port of `FuncProto::setPieces` for a `parse line extern` declaration: storage from the
/// model (`assignParameterStorage`), everything locked.
pub(crate) fn lock_prototype(
    arch: &Arch,
    model: Option<&str>,
    output: (String, TypeId),
    inputs: Vec<(String, TypeId)>,
    dotdotdot: bool,
) -> Result<FuncProto> {
    let models = &arch.spec.models;
    let id: ModelId = match model {
        Some(n) => models.find(n)?,
        None => models.default,
    };
    let m = models.get(id);
    let types = &arch.types;
    let out_storage = if types.meta(output.1) == Meta::Void {
        None
    } else {
        let mut status = vec![0; m.output.entries.len()];
        let st = assign(&m.output, types, output.1, &mut status);
        Some(st.ok_or_else(|| {
            LowlevelError("a return value passed through a hidden pointer: not implemented in ghidra-rs yet".into())
        })?)
    };
    let mut status = vec![0; m.input.entries.len()];
    let mut params = Vec::new();
    for (name, ty) in inputs {
        let st = assign(&m.input, types, ty, &mut status)
            .ok_or_else(|| LowlevelError(format!("Cannot assign parameter address for {}", types.print_raw(ty))))?;
        params.push(Param { name, storage: Some(st), ty });
    }
    let mut proto = FuncProto::default();
    proto.set_model(models, id);
    proto.model_locked = true;
    proto.locked = Some(Box::new(Locked {
        inputs: params,
        output: Param { name: output.0, storage: out_storage, ty: output.1 },
        dotdotdot,
    }));
    Ok(proto)
}

/// The varnode location of a storage: a SLEIGH space or the stack, or a join made in `fd`.
fn location(fd: &mut Funcdata, st: &Storage) -> Result<(Space, u64, u32)> {
    Ok(match st {
        Storage::Space { space, offset, size } => (Space::Sleigh(*space), *offset, *size),
        Storage::Stack { offset, size } => (Space::Stack, *offset, *size),
        Storage::Join(p) => {
            let size = p.iter().map(|x| x.2).sum();
            (Space::Join, fd.join_pieces(p.clone())?, size)
        }
    })
}

/// Port of `Address::justifiedContain(sz, addr, size, false)` (little-endian) and
/// `containedBy`, between a storage and a varnode range.
pub(crate) fn containment(st: &Storage, space: Space, off: u64, size: u32) -> Containment {
    let (s, base, sz) = match st {
        Storage::Space { space, offset, size } => (Space::Sleigh(*space), *offset, *size),
        Storage::Stack { offset, size } => (Space::Stack, *offset, *size),
        Storage::Join(_) => return Containment::None,
    };
    if s != space {
        return Containment::None;
    }
    if off >= base && off - base + u64::from(size) <= u64::from(sz) {
        return if off == base { Containment::ContainsJustified } else { Containment::ContainsUnjustified };
    }
    if base >= off && base - off + u64::from(sz) <= u64::from(size) {
        return Containment::ContainedBy;
    }
    Containment::None
}

impl Locked {
    /// Port of `FuncProto::characterizeAsOutput` for a locked output.
    pub(crate) fn characterize_output(&self, space: Space, off: u64, size: u32) -> Containment {
        self.output.storage.as_ref().map_or(Containment::None, |st| containment(st, space, off, size))
    }

    /// Port of `FuncProto::characterizeAsInputParam` for locked inputs; `None` when the model
    /// decides (varargs).
    pub(crate) fn characterize_input(&self, space: Space, off: u64, size: u32) -> Option<Containment> {
        if self.dotdotdot {
            return None;
        }
        let (mut contains, mut contained) = (false, false);
        for p in &self.inputs {
            match p.storage.as_ref().map(|st| containment(st, space, off, size)) {
                Some(Containment::ContainsJustified) => return Some(Containment::ContainsJustified),
                Some(Containment::ContainsUnjustified) => contains = true,
                Some(Containment::ContainedBy) => contained = true,
                _ => {}
            }
        }
        Some(if contains {
            Containment::ContainsUnjustified
        } else if contained {
            Containment::ContainedBy
        } else {
            Containment::None
        })
    }

    /// Port of `FuncProto::possibleInputParam` for locked inputs (`None`: ask the model).
    pub(crate) fn possible_input(&self, space: Space, off: u64, size: u32) -> Option<bool> {
        (!self.dotdotdot).then(|| {
            self.inputs.iter().any(|p| {
                p.storage.as_ref().is_some_and(|st| containment(st, space, off, size) == Containment::ContainsJustified)
            })
        })
    }
}

/// The locked part of `fd`'s own prototype at `ActionPrototypeTypes`: return values in the
/// output storage on every RETURN (typed, locked) and the parameters as inputs. Returns whether
/// the output is locked (no return value is recovered then).
pub(crate) fn prototype_types(fd: &mut Funcdata, arch: &Arch) -> Result<bool> {
    let Some(locked) = fd.proto.locked.clone() else { return Ok(false) };
    if let Some(st) = &locked.output.storage {
        let rets = fd.ops_created_with(Opcode::Return);
        for op in rets {
            if fd.op(op).is_dead() || fd.op(op).halt.is_some() {
                continue;
            }
            let (space, off, size) = location(fd, st)?;
            let vn = fd.new_varnode(size, space, off);
            let slot = fd.op(op).ins.len();
            fd.op_insert_input(op, vn, slot)?;
            update_type(fd, vn, locked.output.ty, true, true);
        }
    }
    for p in &locked.inputs {
        let Some(st) = &p.storage else { continue };
        if matches!(st, Storage::Stack { .. }) {
            return err("a locked stack parameter of the function itself needs stack heritage: not implemented in ghidra-rs yet");
        }
        let (space, off, size) = location(fd, st)?;
        let vn = fd.new_varnode(size, space, off);
        let vn = fd.set_input_varnode(vn, arch)?;
        fd.vn_set(vn, VnFlags::LOCKED_INPUT);
        // the parameter symbol of the local scope types it (setSymbolProperties)
        update_type(fd, vn, p.ty, true, true);
    }
    Ok(true)
}

/// Port of `funcLinkInput`/`funcLinkOutput` for a call with a locked prototype. Returns false
/// for an unlocked one (the caller runs the unlocked path).
pub(crate) fn func_link(fd: &mut Funcdata, arch: &Arch, c: CallId) -> Result<bool> {
    let Some(locked) = fd.call(c).proto.locked.clone() else { return Ok(false) };
    if locked.dotdotdot {
        return err("a call to a locked varargs prototype: not implemented in ghidra-rs yet");
    }
    let op = fd.call(c).op;
    let model = fd.call(c).proto.model;
    let mut spacebase = model.is_some_and(|m| arch.spec.models.get(m).input.has_stack());
    let mut setplaceholder = false;
    let spec = &arch.spec;
    let uniq = arch.sleigh.uniq_space();
    for p in &locked.inputs {
        let slot = fd.op(op).ins.len();
        let vn: VarnodeId = match &p.storage {
            None => {
                let size = arch.types.size(p.ty);
                fd.new_constant(size, 0)
            }
            Some(Storage::Stack { offset, size }) => {
                let v = fd.op_stack_load(spec.stack_pointer, spec.stack_container, uniq, *offset, *size, op)?;
                if !setplaceholder {
                    setplaceholder = true;
                    fd.call_mut(c).stack_placeholder_slot = Some(slot);
                    spacebase = false;
                }
                v
            }
            Some(Storage::Join(_)) => {
                return err("a locked join parameter of a call: not implemented in ghidra-rs yet")
            }
            Some(st) => {
                let (space, off, size) = location(fd, st)?;
                fd.new_varnode(size, space, off)
            }
        };
        fd.op_insert_input(op, vn, slot)?;
    }
    if spacebase {
        super::action::create_placeholder(fd, arch, c)?;
    }
    // funcLinkOutput (SLEIGH CALLs have no output to remove)
    if let Some(st) = &locked.output.storage {
        if matches!(st, Storage::Stack { .. }) {
            return err("a locked stack return value: not implemented in ghidra-rs yet");
        }
        if type_class(&arch.types, locked.output.ty) == TypeClass::Float && arch.types.size(locked.output.ty) != 10 {
            return err("a locked float return value needing an extension: not implemented in ghidra-rs yet");
        }
        let (space, off, size) = location(fd, st)?;
        fd.new_varnode_out(size, space, off, op);
    }
    Ok(true)
}
