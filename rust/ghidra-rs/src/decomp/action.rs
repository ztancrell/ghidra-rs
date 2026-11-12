//! The action framework (port of the parts of `action.cc` used so far) and the actions of
//! `ActionDatabase::universalAction` (coreaction.cc) that run before `heritage`, as the
//! `decompile` root action has them (its groups leave out `normalizesetup` and
//! `funclinkoutonly`).
//!
//! The universal action is run from the start up to a `break start` breakpoint. The
//! repeat/restart groups and the rule pools of `action.cc` come with the main loop (stage S2 on):
//! here the groups `fullloop` and `mainloop` are entered once, and an action past the ported
//! prefix fails loudly.

use super::fspec::ExtraPop;
use super::funcdata::CallId;
use super::opcode::Opcode;
use super::varnode::Space;
use super::{err, Arch, Funcdata, Result};

/// One action of the universal action: the groups it sits in (as `Break at` prints them), its
/// name (as `break start` names it) and its `apply`.
struct Action {
    groups: &'static str,
    name: &'static str,
    apply: fn(&mut Funcdata, &Arch) -> Result<()>,
}

/// The ported prefix of `universalAction`, in order. `heritage` is listed so that a run can
/// stop before it; its body is not ported yet.
const UNIVERSAL: &[Action] = &[
    Action { groups: "", name: "start", apply: start },
    Action { groups: "", name: "constbase", apply: constbase },
    Action { groups: "", name: "defaultparams", apply: default_params },
    Action { groups: "", name: "extrapopsetup", apply: extrapop_setup },
    Action { groups: "", name: "prototypetypes", apply: prototype_types },
    Action { groups: "", name: "funclink", apply: funclink },
    Action { groups: "fullloop:mainloop:", name: "unreachable", apply: unreachable },
    Action { groups: "fullloop:mainloop:", name: "varnodeprops", apply: varnode_props },
    Action { groups: "fullloop:mainloop:", name: "heritage", apply: not_ported },
];

/// The name of the root action, as `Break at universal:<action> start` prints it.
const ROOT: &str = "universal";

/// Run the universal action on `fd` until just before the action named `stop`
/// (`break start <stop>`); returns the breakpoint's path as `Break at <path> start` prints it.
/// Without a breakpoint the run reaches an unported action and fails.
pub fn perform(fd: &mut Funcdata, arch: &Arch, stop: Option<&str>) -> Result<Option<String>> {
    if let Some(s) = stop.filter(|s| !UNIVERSAL.iter().any(|a| a.name == *s)) {
        return err(format!("break start {s}: action not ported yet (stage S1b ends at heritage)"));
    }
    for a in UNIVERSAL {
        if Some(a.name) == stop {
            return Ok(Some(format!("{ROOT}:{}{}", a.groups, a.name)));
        }
        (a.apply)(fd, arch)?;
    }
    Ok(None)
}

/// `ActionStart`: `Funcdata::startProcessing`.
fn start(fd: &mut Funcdata, arch: &Arch) -> Result<()> {
    fd.start_processing(arch)
}

fn not_ported(_: &mut Funcdata, _: &Arch) -> Result<()> {
    err("action heritage: not implemented in ghidra-rs yet (milestone 3, stage S2)")
}

/// Port of `ActionConstbase::apply`: a COPY of each tracked register's value (x86: `DF = 0`) at
/// the start of the entry block. (The x86 models declare no `uponentry` injection.)
fn constbase(fd: &mut Funcdata, arch: &Arch) -> Result<()> {
    let Some(&bb) = fd.blocks.list.first() else { return Ok(()) };
    let start = fd.blocks.block(bb).start;
    for &(space, off, size, val) in &arch.tracked {
        let op = fd.new_op(Opcode::Copy, start);
        fd.new_varnode_out(size, Space::Sleigh(space), off, op);
        let c = fd.new_constant(size, val);
        fd.op_mut(op).ins = vec![c];
        fd.op_insert_begin(op, bb);
    }
    Ok(())
}

/// Port of `ActionDefaultParams::apply`: each call without a model takes the callee's
/// prototype, evaluated with the `evalfp_called` model (else the default) unless its model is
/// locked; a call to an unknown function gets that model. (`insertPcode` injects only the
/// models' `uponreturn` p-code, which the x86 specs do not declare.)
fn default_params(fd: &mut Funcdata, arch: &Arch) -> Result<()> {
    let models = &arch.spec.models;
    let evalfp = models.eval_called.unwrap_or(models.default);
    for i in 0..fd.qlst.len() {
        let c = fd.qlst[i];
        let callee = fd.call(c).callee().and_then(|e| arch.functions.get(&e));
        let proto = &mut fd.call_mut(c).proto;
        if proto.model.is_some() {
            continue;
        }
        match callee {
            Some(f) => {
                proto.copy(&f.proto);
                if !proto.model_locked && !proto.has_matching_model(evalfp) {
                    proto.set_model(models, evalfp);
                }
            }
            // FuncCallSpecs::setInternal (the void output type is not kept yet)
            None => proto.set_model(models, evalfp),
        }
    }
    Ok(())
}

/// Port of `ActionExtraPopSetup::apply`: after a call whose stack effect is known,
/// `SP = SP + extrapop`; before one whose effect is unknown (the `__stdcall` default),
/// `SP = SP [] <call>`.
fn extrapop_setup(fd: &mut Funcdata, arch: &Arch) -> Result<()> {
    let (space, off, size) = arch.spec.stack_pointer;
    let sp = Space::Sleigh(space);
    for i in 0..fd.qlst.len() {
        let c = fd.qlst[i];
        let call = fd.call(c).op;
        let addr = fd.op(call).seq.addr;
        match fd.call(c).proto.extrapop {
            ExtraPop::Known(0) => {}
            ExtraPop::Known(pop) => {
                let op = fd.new_op(Opcode::IntAdd, addr);
                fd.new_varnode_out(size, sp, off, op);
                let base = fd.new_varnode(size, sp, off);
                let amount = fd.new_constant(size, i64::from(pop) as u64);
                fd.op_mut(op).ins = vec![base, amount];
                fd.op_insert_after(op, call)?;
            }
            ExtraPop::Unknown => {
                let op = fd.new_op(Opcode::Indirect, addr);
                fd.new_varnode_out(size, sp, off, op);
                let base = fd.new_varnode(size, sp, off);
                let iop = fd.new_varnode_iop(call);
                fd.op_mut(op).ins = vec![base, iop];
                fd.op_insert_before(op, call)?;
            }
        }
    }
    Ok(())
}

/// Port of `ActionPrototypeTypes::apply` for an unlocked prototype (the console locks none):
/// the function takes the `evalfp_current` model (else the default), and the indirect return
/// address leaves the RETURN ops (`return(#0x0)`). Gathering return-value trials
/// (`initActiveOutput`) is parameter recovery (stage S4); x86-32's code space is not truncated,
/// and a merged model has no `this` pointer to prepare.
fn prototype_types(fd: &mut Funcdata, arch: &Arch) -> Result<()> {
    let models = &arch.spec.models;
    let evalfp = models.eval_current.unwrap_or(models.default);
    if !fd.proto.model_locked && !fd.proto.has_matching_model(evalfp) {
        fd.proto.set_model(models, evalfp);
    }
    for op in fd.ops_with(Opcode::Return) {
        let Some(&in0) = fd.op(op).ins.first() else { continue };
        if !fd.vn(in0).is_constant() {
            let size = fd.vn(in0).size;
            let c = fd.new_constant(size, 0);
            fd.op_mut(op).ins[0] = c;
        }
    }
    Ok(())
}

/// Port of `ActionFuncLink::apply` for unlocked call prototypes: a call whose model passes
/// parameters on the stack gets the stack-pointer placeholder as its last input
/// (`funcLinkInput`, `FuncCallSpecs::createPlaceholder`). The parameter and return trials
/// (`initActiveInput`, `initActiveOutput`) are parameter recovery (stage S4); CALL ops from
/// SLEIGH never have an output for `funcLinkOutput` to remove.
fn funclink(fd: &mut Funcdata, arch: &Arch) -> Result<()> {
    for i in 0..fd.qlst.len() {
        let c = fd.qlst[i];
        let Some(model) = fd.call(c).proto.model else { continue };
        if arch.spec.models.get(model).input.has_stack() {
            create_placeholder(fd, arch, c)?;
        }
    }
    Ok(())
}

/// Port of `FuncCallSpecs::createPlaceholder`: a 1-byte LOAD at stack offset 0, appended to
/// the call's inputs; heritage later reads the stack offset at the call from it.
fn create_placeholder(fd: &mut Funcdata, arch: &Arch, c: CallId) -> Result<()> {
    let op = fd.call(c).op;
    let slot = fd.op(op).ins.len();
    let spec = &arch.spec;
    let uniq = arch.sleigh.uniq_space();
    let loadval = fd.op_stack_load(spec.stack_pointer, spec.stack_container, uniq, 0, 1, op)?;
    fd.op_insert_input(op, loadval, slot);
    fd.call_mut(c).stack_placeholder_slot = Some(slot);
    Ok(())
}

/// `ActionUnreachable` (`removeUnreachableBlocks`): flow builds only blocks reachable from the
/// entry, so on the first pass there is nothing to remove; it matters once later actions cut
/// edges (stage S4).
fn unreachable(_: &mut Funcdata, _: &Arch) -> Result<()> {
    Ok(())
}

/// Port of `ActionVarnodeProps::apply` on the first pass (before heritage): with
/// `option readonly on`, each free read of read-only memory becomes the constant the image
/// holds there (`Funcdata::fillinReadOnly`). The rest of the action needs later passes
/// (auto-live holds) or masks that are all ones before heritage; x86 declares no volatile memory.
fn varnode_props(fd: &mut Funcdata, arch: &Arch) -> Result<()> {
    if !arch.readonly_propagate {
        return Ok(());
    }
    let ram = Space::Sleigh(arch.sleigh.code_space());
    let ops: Vec<_> = fd.blocks.ops().collect();
    for op in ops {
        for slot in 0..fd.op(op).ins.len() {
            let v = *fd.vn(fd.op(op).ins[slot]);
            // a written read-only varnode only gets a warning
            if v.space != ram || v.def.is_some() || !arch.is_readonly(v.offset, v.size) {
                continue;
            }
            // larger than a uintb, or not loaded: the C++ leaves it (and clears its read-only flag)
            let Some(bytes) = arch.bytes_at(v.offset).and_then(|b| b.get(..v.size as usize)).filter(|_| v.size <= 8)
            else {
                continue;
            };
            let value = bytes.iter().rev().fold(0u64, |acc, &b| acc << 8 | u64::from(b));
            match fd.op(op).opc {
                // only the first input of an INDIRECT, which then becomes a COPY
                Opcode::Indirect => {
                    let out = fd.op(op).out.map(|o| *fd.vn(o));
                    if slot != 0 || out.is_some_and(|o| o.space == v.space && o.offset == v.offset) {
                        continue;
                    }
                    fd.op_mut(op).ins.truncate(1);
                    fd.op_mut(op).opc = Opcode::Copy;
                }
                Opcode::Multiequal => continue,
                _ => {}
            }
            let c = fd.new_constant(v.size, value);
            fd.op_mut(op).ins[slot] = c;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::{Image, Section};
    use crate::sleigh::Sleigh;

    /// mercs2's `__onexit` (0x9ee37a), rebuilt from its bytes, at `break start heritage` with
    /// the console's `fixup apply SEH_prolog4 __SEH_prolog4` and
    /// `fixup apply EH_epilog3 __SEH_epilog4`, its import slots mapped as external references in
    /// read-only `.rdata` and `option readonly on`, against decomp_dbg's output for the same
    /// script on the whole binary. Covers call fixups (their temporaries and op order), the
    /// read-only lookup skipping external-reference slots, and placeholders on direct and
    /// indirect calls.
    fn arch(img: Image) -> Arch {
        let path = Sleigh::sla_path("x86");
        assert!(path.exists(), "{} is missing: run rust/build-sla.sh first", path.display());
        let cspec = std::fs::read_to_string(path.with_file_name("x86win.cspec")).unwrap();
        Arch::new(Sleigh::load(&path).unwrap(), img, &cspec).unwrap()
    }

    fn section(name: &str, exec: bool, addr: u32, data: Vec<u8>) -> Section {
        Section { name: name.into(), exec, readonly: true, addr, data }
    }

    fn raw_at_heritage(arch: &Arch, entry: u64) -> String {
        let mut fd = Funcdata::new(entry);
        let brk = perform(&mut fd, arch, Some("heritage")).unwrap();
        assert_eq!(brk.as_deref(), Some("universal:fullloop:mainloop:heritage"));
        crate::decomp::print_raw(&fd, arch).unwrap()
    }

    /// `MOVSS XMM0, dword ptr [0x402000]; RET` with 1.0f read-only at 0x402000: the read becomes
    /// the constant with `option readonly on`, and stays a ram varnode without it.
    #[test]
    fn readonly_reads_become_constants() {
        let text = vec![0xf3, 0x0f, 0x10, 0x05, 0x00, 0x20, 0x40, 0x00, 0xc3];
        let img = Image {
            sections: vec![
                section(".text", true, 0x401000, text),
                section(".rdata", false, 0x402000, 1.0f32.to_le_bytes().to_vec()),
            ],
            ..Image::default()
        };
        let mut arch = arch(img);
        assert!(raw_at_heritage(&arch, 0x401000).contains("XMM0_Da(0x00401000:0) = r0x00402000(free)\n"));
        arch.readonly_propagate = true;
        assert!(raw_at_heritage(&arch, 0x401000).contains("XMM0_Da(0x00401000:0) = #0x3f800000\n"));
    }

    #[test]
    fn print_raw_at_heritage_with_callfixups() {
        let text = vec![
            0x6a, 0x14, 0x68, 0xd8, 0x22, 0xbf, 0x00, 0xe8, 0xa2, 0x09, 0x00, 0x00, 0xff, 0x35, 0x18, 0x80, 0x9f, 0x01,
            0x8b, 0x35, 0x10, 0x52, 0xb0, 0x00, 0xff, 0xd6, 0x59, 0x89, 0x45, 0xe4, 0x83, 0xf8, 0xff, 0x75, 0x0c, 0xff,
            0x75, 0x08, 0xff, 0x15, 0x14, 0x52, 0xb0, 0x00, 0x59, 0xeb, 0x67, 0x6a, 0x08, 0xe8, 0x72, 0x09, 0x00, 0x00,
            0x59, 0x83, 0x65, 0xfc, 0x00, 0xff, 0x35, 0x18, 0x80, 0x9f, 0x01, 0xff, 0xd6, 0x89, 0x45, 0xe4, 0xff, 0x35,
            0x14, 0x80, 0x9f, 0x01, 0xff, 0xd6, 0x59, 0x59, 0x89, 0x45, 0xe0, 0x8d, 0x45, 0xe0, 0x50, 0x8d, 0x45, 0xe4,
            0x50, 0xff, 0x75, 0x08, 0x8b, 0x35, 0x1c, 0x52, 0xb0, 0x00, 0xff, 0xd6, 0x59, 0x50, 0xe8, 0x35, 0x09, 0x00,
            0x00, 0x89, 0x45, 0xdc, 0xff, 0x75, 0xe4, 0xff, 0xd6, 0xa3, 0x18, 0x80, 0x9f, 0x01, 0xff, 0x75, 0xe0, 0xff,
            0xd6, 0x83, 0xc4, 0x14, 0xa3, 0x14, 0x80, 0x9f, 0x01, 0xc7, 0x45, 0xfc, 0xfe, 0xff, 0xff, 0xff, 0xe8, 0x09,
            0x00, 0x00, 0x00, 0x8b, 0x45, 0xdc, 0xe8, 0x58, 0x09, 0x00, 0x00, 0xc3,
        ];
        let img = Image {
            sections: vec![section(".text", true, 0x9ee37a, text), section(".rdata", false, 0xb05210, vec![0; 16])],
            ..Image::default()
        };
        let mut arch = arch(img);
        arch.readonly_propagate = true;
        for slot in [0xb05210, 0xb05214, 0xb0521c] {
            arch.add_externref(slot);
        }
        arch.add_function(0x9eed28, "__SEH_prolog4".into());
        arch.add_function(0x9eed6d, "__SEH_epilog4".into());
        arch.apply_fixup("SEH_prolog4", 0x9eed28).unwrap();
        arch.apply_fixup("EH_epilog3", 0x9eed6d).unwrap();
        assert_eq!(raw_at_heritage(&arch, 0x9ee37a), include_str!("../../tests/data/raw-heritage-onexit.txt"));
    }
}
