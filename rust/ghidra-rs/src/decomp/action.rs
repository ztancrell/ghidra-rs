//! The action framework (port of the parts of `action.cc` S1a uses) and the actions of
//! `ActionDatabase::universalAction` (coreaction.cc) that run before `funclink`.
//!
//! The universal action is a sequence; S1a runs it from the start up to a `break start`
//! breakpoint. The repeat/restart groups and the rule pools of `action.cc` come with the main
//! loop (stage S2 on), so an action past the ported prefix fails loudly.

use super::opcode::Opcode;
use super::varnode::Space;
use super::{err, Arch, Funcdata, Result};

/// One action of the universal action: its name (as `break start` names it) and its `apply`.
struct Action {
    name: &'static str,
    apply: fn(&mut Funcdata, &Arch) -> Result<()>,
}

/// The ported prefix of `universalAction`, in order. `funclink` is listed so that a run can
/// stop before it; its body is not ported yet.
const UNIVERSAL: &[Action] = &[
    Action { name: "start", apply: start },
    Action { name: "constbase", apply: constbase },
    Action { name: "normalizesetup", apply: no_effect },
    Action { name: "defaultparams", apply: no_effect },
    Action { name: "extrapopsetup", apply: extrapop_setup },
    Action { name: "prototypetypes", apply: prototype_types },
    Action { name: "funclink", apply: not_ported },
];

/// The name of the root action, as `Break at universal:<action> start` prints it.
pub const ROOT: &str = "universal";

/// Run the universal action on `fd` until just before the action named `stop`
/// (`break start <stop>`). Without a breakpoint the run reaches an unported action and fails.
pub fn perform(fd: &mut Funcdata, arch: &Arch, stop: Option<&str>) -> Result<()> {
    if let Some(s) = stop.filter(|s| !UNIVERSAL.iter().any(|a| a.name == *s)) {
        return err(format!("break start {s}: action not ported yet (stage S1a ends at funclink)"));
    }
    for a in UNIVERSAL {
        if Some(a.name) == stop {
            return Ok(());
        }
        (a.apply)(fd, arch)?;
    }
    Ok(())
}

/// `ActionStart`: `Funcdata::startProcessing`.
fn start(fd: &mut Funcdata, arch: &Arch) -> Result<()> {
    fd.start_processing(arch)
}

/// `ActionNormalizeSetup` and `ActionDefaultParams` change only prototypes, which `print raw`
/// does not show; the console's functions have no call fixups for `insertPcode` to add.
fn no_effect(_: &mut Funcdata, _: &Arch) -> Result<()> {
    Ok(())
}

fn not_ported(_: &mut Funcdata, _: &Arch) -> Result<()> {
    err("action funclink: not implemented in ghidra-rs yet (milestone 3, stage S1b)")
}

/// Port of `ActionConstbase::apply`: a COPY of each tracked register's value (x86: `DF = 0`) at
/// the start of the entry block.
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

/// Port of `ActionExtraPopSetup::apply`. Every call's stack effect is unknown here (the
/// default `__stdcall` model has `extrapop="unknown"` and the console knows no prototypes), so
/// each call gets `ESP = ESP [] <call>` just before it.
fn extrapop_setup(fd: &mut Funcdata, arch: &Arch) -> Result<()> {
    let (space, off, size) = arch.stack_pointer;
    for i in 0..fd.qlst.len() {
        let call = fd.call(fd.qlst[i]).op;
        let op = fd.new_op(Opcode::Indirect, fd.op(call).seq.addr);
        fd.new_varnode_out(size, Space::Sleigh(space), off, op);
        let sp = fd.new_varnode(size, Space::Sleigh(space), off);
        let iop = fd.new_varnode_iop(call);
        fd.op_mut(op).ins = vec![sp, iop];
        fd.op_insert_before(op, call)?;
    }
    Ok(())
}

/// Port of `ActionPrototypeTypes::apply`, the part `print raw` shows: the indirect return
/// address leaves the RETURN ops (`return(#0x0)`).
fn prototype_types(fd: &mut Funcdata, _: &Arch) -> Result<()> {
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
