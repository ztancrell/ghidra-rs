//! The actions of `ActionDatabase::universalAction` (coreaction.cc) ported so far, in the tree
//! the `decompile` root action has them in (its groups leave out `normalizesetup` and
//! `funclinkoutonly`), run by the framework of [`super::actiontree`].
//!
//! Stage S2 ends at `paramdouble`, the first action of the main loop after `heritage`: it and
//! everything after it fail loudly, so a run stops at a `break start` up to `paramdouble`.

pub use super::actiontree::{ActionTree, Outcome};
use super::fspec::{ExtraPop, ParamActive};
use super::funcdata::CallId;
use super::opcode::Opcode;
use super::varnode::Space;
use super::{err, heritage, Arch, Funcdata, Result};

/// The ported part of `universalAction`: the root `universal` (restart group, once per
/// function), its first actions, and the repeating groups `fullloop` and `mainloop` up to
/// `paramdouble`.
pub fn universal() -> ActionTree {
    let mut t = ActionTree::default();
    let root: Vec<_> = [
        ("start", start as super::actiontree::ApplyFn),
        ("constbase", constbase),
        ("defaultparams", default_params),
        ("extrapopsetup", extrapop_setup),
        ("prototypetypes", prototype_types),
        ("funclink", funclink),
    ]
    .into_iter()
    .map(|(name, f)| t.leaf(name, f))
    .collect();
    let mainloop = vec![
        t.leaf("unreachable", unreachable),
        t.leaf("varnodeprops", varnode_props),
        t.leaf("heritage", heritage_pass),
        t.leaf("paramdouble", not_ported),
    ];
    let mainloop = t.group("mainloop", mainloop, true);
    let fullloop = t.group("fullloop", vec![mainloop], true);
    let mut kids = root;
    kids.push(fullloop);
    t.restart_group("universal", kids);
    t
}

/// `ActionStart`: `Funcdata::startProcessing`.
fn start(fd: &mut Funcdata, arch: &Arch) -> Result<i32> {
    fd.start_processing(arch)?;
    Ok(0)
}

/// The main loop past `heritage` (`paramdouble` on) is not ported.
fn not_ported(_: &mut Funcdata, _: &Arch) -> Result<i32> {
    err("action paramdouble: not implemented in ghidra-rs yet (milestone 3, stage S4)")
}

/// `ActionHeritage`: one heritage pass. It counts no change.
fn heritage_pass(fd: &mut Funcdata, arch: &Arch) -> Result<i32> {
    heritage::heritage(fd, arch)?;
    Ok(0)
}

/// Port of `ActionConstbase::apply`: a COPY of each tracked register's value (x86: `DF = 0`) at
/// the start of the entry block. (The x86 models declare no `uponentry` injection.)
fn constbase(fd: &mut Funcdata, arch: &Arch) -> Result<i32> {
    let Some(&bb) = fd.blocks.list.first() else { return Ok(0) };
    let start = fd.blocks.block(bb).start;
    for &(space, off, size, val) in &arch.tracked {
        let op = fd.new_op(Opcode::Copy, start);
        fd.new_varnode_out(size, Space::Sleigh(space), off, op);
        let c = fd.new_constant(size, val);
        fd.op_set_all_input(op, &[c])?;
        fd.op_insert_begin(op, bb);
    }
    Ok(0)
}

/// Port of `ActionDefaultParams::apply`: each call without a model takes the callee's
/// prototype, evaluated with the `evalfp_called` model (else the default) unless its model is
/// locked; a call to an unknown function gets that model. (`insertPcode` injects only the
/// models' `uponreturn` p-code, which the x86 specs do not declare.)
fn default_params(fd: &mut Funcdata, arch: &Arch) -> Result<i32> {
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
    Ok(0)
}

/// Port of `ActionExtraPopSetup::apply`: after a call whose stack effect is known,
/// `SP = SP + extrapop`; before one whose effect is unknown (the `__stdcall` default),
/// `SP = SP [] <call>`.
fn extrapop_setup(fd: &mut Funcdata, arch: &Arch) -> Result<i32> {
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
                fd.op_set_all_input(op, &[base, amount])?;
                fd.op_insert_after(op, call)?;
            }
            ExtraPop::Unknown => {
                let op = fd.new_op(Opcode::Indirect, addr);
                fd.new_varnode_out(size, sp, off, op);
                let base = fd.new_varnode(size, sp, off);
                let iop = fd.new_varnode_iop(call);
                fd.op_set_all_input(op, &[base, iop])?;
                fd.op_insert_before(op, call)?;
            }
        }
    }
    Ok(0)
}

/// Port of `ActionPrototypeTypes::apply` for an unlocked prototype (the console locks none):
/// the function takes the `evalfp_current` model (else the default), and the indirect return
/// address leaves the RETURN ops (`return(#0x0)`), and return-value trials begin
/// (`initActiveOutput`; heritage registers them). x86-32's code space is not truncated,
/// and a merged model has no `this` pointer to prepare.
fn prototype_types(fd: &mut Funcdata, arch: &Arch) -> Result<i32> {
    let models = &arch.spec.models;
    let evalfp = models.eval_current.unwrap_or(models.default);
    if !fd.proto.model_locked && !fd.proto.has_matching_model(evalfp) {
        fd.proto.set_model(models, evalfp);
    }
    fd.active_output = Some(ParamActive::default());
    for op in fd.ops_with(Opcode::Return) {
        let Some(&in0) = fd.op(op).ins.first() else { continue };
        if !fd.vn(in0).is_constant() {
            let size = fd.vn(in0).size;
            let c = fd.new_constant(size, 0);
            fd.op_set_input(op, c, 0)?;
        }
    }
    Ok(0)
}

/// Port of `ActionFuncLink::apply` for unlocked call prototypes: a call whose model passes
/// parameters on the stack gets the stack-pointer placeholder as its last input
/// (`funcLinkInput`, `FuncCallSpecs::createPlaceholder`); parameter and return trials begin
/// for every call (`initActiveInput`, `initActiveOutput`; heritage registers them). CALL ops from
/// SLEIGH never have an output for `funcLinkOutput` to remove.
fn funclink(fd: &mut Funcdata, arch: &Arch) -> Result<i32> {
    for i in 0..fd.qlst.len() {
        let c = fd.qlst[i];
        let call = fd.call_mut(c);
        call.active_input = Some(ParamActive::default());
        call.active_output = Some(ParamActive::default());
        let Some(model) = call.proto.model else { continue };
        if arch.spec.models.get(model).input.has_stack() {
            create_placeholder(fd, arch, c)?;
        }
    }
    Ok(0)
}

/// Port of `FuncCallSpecs::createPlaceholder`: a 1-byte LOAD at stack offset 0, appended to
/// the call's inputs; heritage later reads the stack offset at the call from it.
fn create_placeholder(fd: &mut Funcdata, arch: &Arch, c: CallId) -> Result<()> {
    let op = fd.call(c).op;
    let slot = fd.op(op).ins.len();
    let spec = &arch.spec;
    let uniq = arch.sleigh.uniq_space();
    let loadval = fd.op_stack_load(spec.stack_pointer, spec.stack_container, uniq, 0, 1, op)?;
    fd.op_insert_input(op, loadval, slot)?;
    fd.call_mut(c).stack_placeholder_slot = Some(slot);
    Ok(())
}

/// `ActionUnreachable` (`Funcdata::removeUnreachableBlocks`). Flow builds only blocks reachable
/// from the entry, so on the first pass there is nothing to remove; block removal is not ported
/// (stage S4), so an unreachable block is an error rather than a silent difference.
fn unreachable(fd: &mut Funcdata, _: &Arch) -> Result<i32> {
    let Some(&entry) = fd.blocks.list.first() else { return Ok(0) };
    let mut seen = vec![false; fd.blocks.list.len()];
    let mut stack = vec![entry];
    while let Some(b) = stack.pop() {
        let i = fd.blocks.block(b).index as usize;
        if std::mem::replace(&mut seen[i], true) {
            continue;
        }
        stack.extend(fd.blocks.block(b).outs.iter().map(|e| e.point));
    }
    if seen.contains(&false) {
        return err("action unreachable: removing unreachable blocks is not implemented in ghidra-rs yet (stage S4)");
    }
    Ok(0)
}

/// Port of `ActionVarnodeProps::apply` on the first pass (before heritage): with
/// `option readonly on`, each free read of read-only memory becomes the constant the image
/// holds there (`Funcdata::fillinReadOnly`). The rest of the action needs later passes
/// (auto-live holds) or masks that are all ones before heritage; x86 declares no volatile memory.
///
/// The C++ walks the varnodes in location order (`beginLoc`: address, size, then creation for
/// free ones) and makes one constant per read; before heritage each free varnode has one
/// reader, so the reads are visited in that order and the constants made in it.
fn varnode_props(fd: &mut Funcdata, arch: &Arch) -> Result<i32> {
    if !arch.readonly_propagate {
        return Ok(0);
    }
    let ram = Space::Sleigh(arch.sleigh.code_space());
    let mut reads = Vec::new();
    let mut changes = 0;
    for op in fd.blocks.ops() {
        for (slot, &vn) in fd.op(op).ins.iter().enumerate() {
            let v = fd.vn(vn);
            // a written read-only varnode only gets a warning
            if v.space == ram && v.def.is_none() && arch.is_readonly(v.offset, v.size) {
                reads.push((v.offset, v.size, vn.0, op, slot));
            }
        }
    }
    reads.sort_unstable_by_key(|r| (r.0, r.1, r.2));
    for (offset, size, _, op, slot) in reads {
        // larger than a uintb, or not loaded: the C++ leaves it (and clears its read-only flag)
        let mut bytes = [0u8; 8];
        let Some(buf) = bytes.get_mut(..size as usize) else { continue };
        if arch.fill_bytes(offset, buf).is_none() {
            continue;
        }
        let value = buf.iter().rev().fold(0u64, |acc, &b| acc << 8 | u64::from(b));
        match fd.op(op).opc {
            // only the first input of an INDIRECT, which then becomes a COPY
            Opcode::Indirect => {
                let out = fd.op(op).out.map(|o| (fd.vn(o).space, fd.vn(o).offset));
                if slot != 0 || out == Some((ram, offset)) {
                    continue;
                }
                fd.op_remove_input(op, 1);
                fd.op_mut(op).opc = Opcode::Copy;
            }
            Opcode::Multiequal => continue,
            _ => {}
        }
        let c = fd.new_constant(size, value);
        fd.op_set_input(op, c, slot)?;
        changes += 1;
    }
    Ok(changes)
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
        Section { name: name.into(), exec, readonly: true, zero_tail: 0, addr, data }
    }

    fn raw_at_heritage(arch: &Arch, entry: u64) -> String {
        let mut fd = Funcdata::new(entry);
        let mut t = universal();
        t.set_break_start("heritage").unwrap();
        let brk = t.perform(&mut fd, arch).unwrap();
        assert_eq!(brk, Outcome::Break("universal:fullloop:mainloop:heritage start".into()));
        crate::decomp::print_raw(&fd, arch).unwrap()
    }

    /// `MOVSD XMM0, qword ptr [0x4020fc]; MOVSS XMM1, dword ptr [0x4020fe]; RET` with read-only
    /// bytes `00 00 00 00 11 22 33 44` at 0x4020f8 and nothing after: with `option readonly on`
    /// the reads become constants, zero-filled past the end (`LoadImage::loadFill`), against
    /// decomp_dbg on the same image as a `load test file`; without the option they stay varnodes.
    #[test]
    fn readonly_reads_become_constants() {
        let text =
            vec![0xf2, 0x0f, 0x10, 0x05, 0xfc, 0x20, 0x40, 0x00, 0xf3, 0x0f, 0x10, 0x0d, 0xfe, 0x20, 0x40, 0x00, 0xc3];
        let rdata = vec![0, 0, 0, 0, 0x11, 0x22, 0x33, 0x44];
        let img = Image {
            sections: vec![section(".text", true, 0x401000, text), section(".rdata", false, 0x4020f8, rdata)],
            ..Image::default()
        };
        let mut arch = arch(img);
        assert!(raw_at_heritage(&arch, 0x401000).contains("XMM1_Da(0x00401008:2) = r0x004020fe(free)\n"));
        arch.readonly_propagate = true;
        let raw = raw_at_heritage(&arch, 0x401000);
        assert_eq!(raw, include_str!("../../tests/data/raw-heritage-readonly-tail.txt"));
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
