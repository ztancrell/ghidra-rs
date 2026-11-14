//! Stack-pointer tracing for the stack heritage pass (heritage.cc): the LOADs and STOREs that may
//! reach the stack through the stack pointer. Ports `Heritage::discoverIndexedStackPointers`,
//! `protectFreeStores`, `reprocessFreeStores`, `generateLoadGuard`/`generateStoreGuard` and
//! `guardLoads`.
//!
//! Not ported: the value-set analysis of the guards (`analyzeNewLoadGuards`, `LoadGuard::
//! establishRange`/`finalizeRange`, rangeutil.cc's `ValueSetSolver`). A guard keeps only the
//! offset its pointer was traced from; `guardLoads`, the one reader of the analysed range during
//! heritage, fails when it would need it. With no load-guard COPYs, `handleNewLoadCopies` has
//! nothing to do. The other readers of the analysed ranges, none ported yet, must fail while
//! [`has_valid_guards`] is true: `StackAffectingOps::populate`/`affectsTest` (merge.cc, stage
//! S7), `Funcdata::opCollapseIndirectsForAlias` (funcdata_op.cc, through `RuleAliasUpdate`)
//! and `MapState::gatherOpen` / the alias checker (varmap.cc, `ActionRestructureVarnode`).

use super::op::{OpFlags, OpId};
use super::opcode::Opcode;
use super::varnode::{Space, VarnodeId};
use super::{err, Arch, Funcdata, Result};
use std::collections::HashSet;

/// Port of `LoadGuard` before analysis: an indexed LOAD or STORE through the stack pointer.
#[derive(Debug, Clone, Copy)]
pub(crate) struct LoadGuard {
    pub(crate) op: OpId,
    /// the stack offset the pointer was traced from (`pointerBase`)
    pub(crate) pointer_base: u64,
}

/// `StackNode::traversals` bits: the path went through a non-constant ADD or a MULTIEQUAL.
const NONCONSTANT_INDEX: u8 = 1;
const MULTIEQUAL: u8 = 2;

/// Port of `StackNode`: a varnode on the path from the stack pointer, its offset from it and
/// the index of the next reader to visit.
struct StackNode {
    vn: VarnodeId,
    offset: u64,
    traversals: u8,
    next: usize,
}

/// The input stack-pointer varnode (`Funcdata::findVarnodeInput` of the space's spacebase).
fn stack_pointer_input(fd: &Funcdata, arch: &Arch) -> Option<VarnodeId> {
    let (sp, off, size) = arch.spec.stack_pointer;
    fd.loc_at(Space::Sleigh(sp), off, size).into_iter().find(|&v| fd.vn(v).is_input())
}

/// The stack space's offset mask (`AddrSpace::wrapOffset`).
pub(crate) fn stack_mask(arch: &Arch) -> u64 {
    let size = arch.sleigh.spaces.get(arch.spec.stack_container as usize).map_or(8, |s| s.size);
    if size >= 8 {
        u64::MAX
    } else {
        (1u64 << (8 * size)) - 1
    }
}

/// Port of `Heritage::discoverIndexedStackPointers`: walk the stack pointer's data-flow through
/// COPY, INDIRECT, MULTIEQUAL, SEGMENTOP and ADD; an indexed LOAD or STORE gets a guard record,
/// a STORE through the stack pointer plus a constant the `spacebase_ptr` mark. Returns the
/// free STOREs that may write the stack (when `check_free_stores`), `None` if there are none.
pub(crate) fn discover_indexed_stack_pointers(
    fd: &mut Funcdata,
    arch: &Arch,
    check_free_stores: bool,
) -> Result<Option<Vec<OpId>>> {
    let Some(sp) = stack_pointer_input(fd, arch) else { return Ok(None) };
    let mask = stack_mask(arch);
    let mut marked: HashSet<VarnodeId> = HashSet::new();
    let mut unknown_storage = false;
    let mut path = vec![StackNode { vn: sp, offset: 0, traversals: 0, next: 0 }];
    while let Some(cur) = path.last_mut() {
        let Some(&op) = fd.vn(cur.vn).descend.get(cur.next) else {
            path.pop();
            continue;
        };
        cur.next += 1;
        let (cvn, coff, ctrav) = (cur.vn, cur.offset, cur.traversals);
        let o = fd.op(op);
        if o.out.is_some_and(|v| marked.contains(&v)) {
            continue;
        }
        let next = match o.opc {
            Opcode::IntAdd => {
                let slot = usize::from(o.ins.first() != Some(&cvn));
                let other = fd.input(op, 1 - slot)?;
                if fd.vn(other).is_constant() {
                    Some((coff.wrapping_add(fd.vn(other).offset) & mask, ctrav))
                } else {
                    Some((coff, ctrav | NONCONSTANT_INDEX))
                }
            }
            Opcode::Segmentop if o.ins.get(2) != Some(&cvn) => None,
            Opcode::Segmentop | Opcode::Indirect | Opcode::Copy => Some((coff, ctrav)),
            Opcode::Multiequal => Some((coff, ctrav | MULTIEQUAL)),
            Opcode::Load => {
                if ctrav != 0 {
                    generate_guard(fd, op, coff, false);
                }
                None
            }
            Opcode::Store => {
                if o.ins.get(1) == Some(&cvn) {
                    if ctrav != 0 {
                        generate_guard(fd, op, coff, true);
                    } else {
                        fd.op_mut(op).flags.set(OpFlags::SPACEBASE_PTR);
                    }
                }
                None
            }
            _ => None,
        };
        let (Some((offset, traversals)), Some(out)) = (next, fd.op(op).out) else { continue };
        if !fd.vn(out).descend.is_empty() {
            marked.insert(out);
            path.push(StackNode { vn: out, offset, traversals, next: 0 });
        } else if fd.vn(out).space == Space::Stack {
            unknown_storage = true;
        }
    }
    if unknown_storage && check_free_stores {
        return Ok(protect_free_stores(fd));
    }
    Ok(None)
}

/// Port of `Heritage::generateLoadGuard` / `generateStoreGuard`.
fn generate_guard(fd: &mut Funcdata, op: OpId, pointer_base: u64, store: bool) {
    if fd.op(op).flags.has(OpFlags::SPACEBASE_PTR) {
        return;
    }
    let g = LoadGuard { op, pointer_base };
    if store {
        fd.heritage.store_guards.push(g);
    } else {
        fd.heritage.load_guards.push(g);
    }
    fd.op_mut(op).flags.set(OpFlags::SPACEBASE_PTR);
}

/// Port of `Heritage::protectFreeStores`: STOREs whose pointer is a free stack varnode (plus
/// constants) are marked as stack STOREs for now.
fn protect_free_stores(fd: &mut Funcdata) -> Option<Vec<OpId>> {
    let mut free = Vec::new();
    for op in fd.ops_created_with(Opcode::Store) {
        if fd.op(op).is_dead() {
            continue;
        }
        let Some(&(mut vn)) = fd.op(op).ins.get(1) else { continue };
        while let Some(def) = fd.vn(vn).def {
            let d = fd.op(def);
            match (d.opc, d.ins.first(), d.ins.get(1)) {
                (Opcode::Copy, Some(&a), _) => vn = a,
                (Opcode::IntAdd, Some(&a), Some(&b)) if fd.vn(b).is_constant() => vn = a,
                _ => break,
            }
        }
        if fd.vn(vn).is_free() && fd.vn(vn).space == Space::Stack {
            fd.op_mut(op).flags.set(OpFlags::SPACEBASE_PTR);
            free.push(op);
        }
    }
    (!free.is_empty()).then_some(free)
}

/// Port of `Heritage::reprocessFreeStores`: after the pass, a free STORE the stack pointer does
/// not reach after all loses its mark and the stack INDIRECTs it caused.
pub(crate) fn reprocess_free_stores(fd: &mut Funcdata, arch: &Arch, free: &[OpId]) -> Result<()> {
    for &op in free {
        fd.op_mut(op).flags.clear(OpFlags::SPACEBASE_PTR);
    }
    discover_indexed_stack_pointers(fd, arch, false)?;
    for &op in free {
        if fd.op(op).flags.has(OpFlags::SPACEBASE_PTR) {
            continue;
        }
        let mut ind = fd.previous_op(op);
        while let Some(i) = ind {
            if fd.op(i).opc != Opcode::Indirect {
                break;
            }
            let iop = fd.input(i, 1)?;
            if fd.iop_target(iop) != Some(op) {
                break;
            }
            let prev = fd.previous_op(i);
            if let Some(out) = fd.op(i).out.filter(|&o| fd.vn(o).space == Space::Stack) {
                let in0 = fd.input(i, 0)?;
                fd.total_replace(out, in0)?;
                fd.op_destroy(i);
            }
            ind = prev;
        }
    }
    Ok(())
}

/// Whether a store guard (`store`) or a load guard is still valid (`LoadGuard::isValid`: its op
/// is alive and still a STORE or LOAD): a reader of the unanalysed guard ranges must then fail.
pub(crate) fn has_valid_guards(fd: &Funcdata, store: bool) -> bool {
    let (list, opc) =
        if store { (&fd.heritage.store_guards, Opcode::Store) } else { (&fd.heritage.load_guards, Opcode::Load) };
    list.iter().any(|g| !fd.op(g.op).is_dead() && fd.op(g.op).opc == opc)
}

/// Port of `Heritage::guardLoads`: an address-tied stack range would get a COPY guard at each
/// indexed LOAD whose analysed range holds it. Guards whose LOAD is gone are dropped.
pub(crate) fn guard_loads(fd: &mut Funcdata, space: Space, addrtied: bool) -> Result<()> {
    if !addrtied {
        return Ok(());
    }
    let guards = std::mem::take(&mut fd.heritage.load_guards);
    let live: Vec<LoadGuard> =
        guards.into_iter().filter(|g| !fd.op(g.op).is_dead() && fd.op(g.op).opc == Opcode::Load).collect();
    let first = live.first().map(|g| g.pointer_base);
    fd.heritage.load_guards = live;
    match first {
        Some(base) if space == Space::Stack => err(format!(
            "heritage: an indexed stack LOAD (from stack offset {base:#x}) may read an address-tied stack range; its range needs the value-set analysis of LoadGuard (ValueSetSolver): not implemented in ghidra-rs yet"
        )),
        _ => Ok(()),
    }
}
