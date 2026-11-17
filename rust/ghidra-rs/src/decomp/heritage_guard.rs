//! Stack-pointer tracing for the stack heritage pass (heritage.cc): the LOADs and STOREs that may
//! reach the stack through the stack pointer. Ports `Heritage::discoverIndexedStackPointers`,
//! `protectFreeStores`, `reprocessFreeStores`, `generateLoadGuard`/`generateStoreGuard`,
//! `guardLoads`, `analyzeNewLoadGuards` with `LoadGuard::establishRange`/`finalizeRange` (the
//! value-set analysis of `valueset.rs`), and `handleNewLoadCopies` with `findAddressForces` and
//! `propagateCopyAway`.
//!
//! The readers of the analysed ranges outside heritage: `StackAffectingOps` (merge.cc, in
//! `variable.rs`), `Funcdata::opCollapseIndirectsForAlias` and `MapState::addGuard` (both in
//! `mapstate.rs`).
//! (Superseded: "Not ported: the value-set analysis of the guards"; a guard kept only its
//! pointer offset, and each reader failed while a valid guard existed.)

use super::op::{OpFlags, OpId};
use super::opcode::Opcode;
use super::valueset::{ValueSetRead, ValueSetSolver, Widener};
use super::varnode::{Space, VarnodeId, VnFlags};
use super::{err, Arch, Funcdata, Result};
use std::collections::HashSet;

/// Port of `LoadGuard`: an indexed LOAD or STORE through the stack pointer and the stack range
/// it may reach.
#[derive(Debug, Clone, Copy)]
pub(crate) struct LoadGuard {
    pub(crate) op: OpId,
    /// the stack offset the pointer was traced from (`pointerBase`)
    pointer_base: u64,
    pub(crate) minimum: u64,
    pub(crate) maximum: u64,
    /// the step of the accesses, 0 if unknown
    pub(crate) step: u32,
    /// 0 = unanalysed, 1 = analysed (partial result), 2 = analysed (full result)
    analysis_state: u8,
}

impl LoadGuard {
    /// `isGuarded`: the guard covers the address
    pub(crate) fn is_guarded(&self, space: Space, off: u64) -> bool {
        space == Space::Stack && off >= self.minimum && off <= self.maximum
    }
    /// `isRangeLocked`
    pub(crate) fn is_range_locked(&self) -> bool {
        self.analysis_state == 2
    }
    /// `isValid`: the op is alive and still the LOAD or STORE
    pub(crate) fn is_valid(&self, fd: &Funcdata, opc: Opcode) -> bool {
        !fd.op(self.op).is_dead() && fd.op(self.op).opc == opc
    }

    /// Port of `LoadGuard::establishRange`: what the partial analysis (no widening) gives.
    /// `highest` is the stack space's highest offset.
    fn establish_range(&mut self, read: &ValueSetRead, highest: u64) {
        let range = &read.range;
        let range_size = range.get_size();
        let mut size = 0x1000;
        if range.is_empty() {
            self.minimum = self.pointer_base;
        } else if range.is_full() || range_size > 0xff_ffff {
            self.minimum = self.pointer_base;
            self.analysis_state = 1; // no more analysis
        } else {
            self.step = if range_size == 3 { range.step } else { 0 };
            if read.left_is_stable {
                self.minimum = range.left;
            } else if read.right_is_stable {
                if self.pointer_base < range.right {
                    self.minimum = self.pointer_base;
                    size = range.right - self.pointer_base;
                } else {
                    self.minimum = range.left;
                    size = range_size.wrapping_mul(u64::from(range.step));
                }
            } else {
                self.minimum = self.pointer_base;
            }
        }
        if self.minimum > highest {
            self.minimum = highest;
            self.maximum = highest;
        } else {
            size = size.min((highest - self.minimum).wrapping_add(1));
            self.maximum = self.minimum.wrapping_add(size).wrapping_sub(1);
        }
    }

    /// Port of `LoadGuard::finalizeRange`: what the full analysis gives.
    fn finalize_range(&mut self, read: &ValueSetRead, highest: u64) {
        self.analysis_state = 1;
        let range = &read.range;
        let mut range_size = range.get_size();
        // these sizes are likely the storage size of the index: only with signs of iteration
        if (range_size == 0x100 || range_size == 0x10000) && self.step == 0 {
            range_size = 0;
        }
        if range_size > 1 && range_size < 0xff_ffff {
            self.analysis_state = 2;
            if range_size > 2 {
                self.step = range.step;
            }
            self.minimum = range.left;
            self.maximum = range.right.wrapping_sub(1) & range.mask;
            if self.maximum < self.minimum {
                // the values reach what is usually the stack parameters
                self.maximum = highest;
                self.analysis_state = 1;
            }
        }
        self.minimum = self.minimum.min(highest);
        self.maximum = self.maximum.min(highest);
    }
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
pub(crate) fn stack_pointer_input(fd: &Funcdata, arch: &Arch) -> Option<VarnodeId> {
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
                    generate_guard(fd, op, coff, mask, false);
                }
                None
            }
            Opcode::Store => {
                if o.ins.get(1) == Some(&cvn) {
                    if ctrav != 0 {
                        generate_guard(fd, op, coff, mask, true);
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
fn generate_guard(fd: &mut Funcdata, op: OpId, pointer_base: u64, highest: u64, store: bool) {
    if fd.op(op).flags.has(OpFlags::SPACEBASE_PTR) {
        return;
    }
    // `LoadGuard::set`: unanalysed, it guards everything
    let g = LoadGuard { op, pointer_base, minimum: 0, maximum: highest, step: 0, analysis_state: 0 };
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

/// Port of `Heritage::guardLoads`: an address-tied range gets a COPY to itself (`addrforce`)
/// before each indexed LOAD whose range holds its first byte, so the value is kept in place
/// there. Guards whose LOAD is gone are dropped.
pub(crate) fn guard_loads(fd: &mut Funcdata, space: Space, off: u64, size: u32, addrtied: bool) -> Result<()> {
    if !addrtied {
        return Ok(());
    }
    let mut guards = std::mem::take(&mut fd.heritage.load_guards);
    guards.retain(|g| g.is_valid(fd, Opcode::Load));
    for g in guards.iter().filter(|g| g.is_guarded(space, off)) {
        let copy = fd.new_op(Opcode::Copy, fd.op(g.op).seq.addr);
        let out = fd.new_varnode_out(size, space, off, copy);
        fd.vn_set(out, VnFlags::ACTIVE_HERITAGE.with(VnFlags::ADDRFORCE));
        let inp = fd.new_varnode(size, space, off);
        fd.vn_set(inp, VnFlags::ACTIVE_HERITAGE);
        fd.op_set_input(copy, inp, 0)?;
        fd.op_insert_before(copy, g.op)?;
        fd.heritage.load_copy_ops.push(copy);
    }
    fd.heritage.load_guards = guards;
    Ok(())
}

/// Port of `Heritage::analyzeNewLoadGuards`: the value-set analysis of the pointers of the new
/// guards gives each its range, first without widening, then (when one is still open) with it.
pub(crate) fn analyze_new_load_guards(fd: &mut Funcdata, arch: &Arch) -> Result<()> {
    let new_from = |list: &[LoadGuard]| list.iter().rposition(|g| g.analysis_state != 0).map_or(0, |i| i + 1);
    let (load_from, store_from) = (new_from(&fd.heritage.load_guards), new_from(&fd.heritage.store_guards));
    // only the last guard of each list is looked at
    let unanalysed = |list: &[LoadGuard]| list.last().is_some_and(|g| g.analysis_state == 0);
    if !unanalysed(&fd.heritage.load_guards) && !unanalysed(&fd.heritage.store_guards) {
        return Ok(());
    }
    if load_from != 0 || store_from != 0 {
        // the C++ loops would start at the last analysed guard, which has no value set
        return err("heritage: new load or store guards after analysed ones (analyzeNewLoadGuards) is not ported");
    }
    let mut loads = std::mem::take(&mut fd.heritage.load_guards);
    let mut stores = std::mem::take(&mut fd.heritage.store_guards);
    let mut reads = Vec::new();
    let mut sinks = Vec::new();
    for g in loads.iter().rev().chain(stores.iter().rev()) {
        reads.push(g.op);
        sinks.push(fd.input(g.op, 1)?); // the pointer
    }
    let highest = stack_mask(arch);
    let mut solver = ValueSetSolver::default();
    solver.establish_value_sets(fd, &sinks, &reads, stack_pointer_input(fd, arch), false)?;
    solver.solve(fd, 10000, Widener::None)?;
    let read = |solver: &ValueSetSolver, g: &LoadGuard| match solver.value_set_read(g.op) {
        Some(r) => Ok(r.clone()),
        None => err("heritage: a load or store guard without a value set"),
    };
    let mut run_full = false;
    for g in loads.iter_mut().chain(stores.iter_mut()) {
        g.establish_range(&read(&solver, g)?, highest);
        run_full |= g.analysis_state == 0;
    }
    for g in &stores {
        // the alias information of the STORE has changed
        fd.op_mut(g.op).flags.set(OpFlags::ALIAS_UPDATE);
    }
    if run_full {
        solver.solve(fd, 10000, Widener::Full)?;
        for g in loads.iter_mut().chain(stores.iter_mut()) {
            g.finalize_range(&read(&solver, g)?, highest);
        }
    }
    // GHIDRA_RS_GUARD_DEBUG=<file>: append one line per analysed guard (the console output before
    // `load function` is cut by decomp-diff.sh, and a partial function is made there)
    if let Some(path) = std::env::var_os("GHIDRA_RS_GUARD_DEBUG") {
        use std::io::Write;
        let mut lines = String::new();
        for (name, g) in loads.iter().map(|g| ("load", g)).chain(stores.iter().map(|g| ("store", g))) {
            let seq = fd.op(g.op).seq;
            lines += &format!(
                "{:#x} {name} guard at {:#x}:{:x}: [{:#x}, {:#x}] step {} state {}\n",
                fd.entry, seq.addr, seq.time, g.minimum, g.maximum, g.step, g.analysis_state
            );
        }
        let file = std::fs::OpenOptions::new().create(true).append(true).open(path);
        if file.and_then(|mut f| f.write_all(lines.as_bytes())).is_err() {
            return err("GHIDRA_RS_GUARD_DEBUG: cannot write the guard file");
        }
    }
    fd.heritage.load_guards = loads;
    fd.heritage.store_guards = stores;
    Ok(())
}

/// Port of `Heritage::findAddressForces`: from the COPY sinks back through artificial ops (a
/// COPY or MULTIEQUAL within one address, an INDIRECT of a STORE), which join `sinks`, to the
/// last real writes of the address, which are returned.
fn find_address_forces(fd: &Funcdata, sinks: &mut Vec<OpId>) -> Vec<OpId> {
    let mut forces = Vec::new();
    let mut marked: HashSet<OpId> = sinks.iter().copied().collect();
    let addr = |vn: VarnodeId| (fd.vn(vn).space, fd.vn(vn).offset);
    let mut pos = 0;
    while let Some(&op) = sinks.get(pos) {
        pos += 1;
        let Some(to) = fd.op(op).out.map(addr) else { continue };
        for &vn in &fd.op(op).ins {
            let Some(def) = fd.vn(vn).def else { continue };
            if fd.vn(vn).has(VnFlags::ADDRFORCE) || !marked.insert(def) {
                continue;
            }
            let d = fd.op(def);
            let artificial = match d.opc {
                Opcode::Copy | Opcode::Multiequal => d.ins.iter().all(|&i| addr(i) == to),
                Opcode::Indirect if d.flags.has(OpFlags::INDIRECT_STORE) => addr(d.ins[0]) == to,
                _ => false,
            };
            if artificial {
                sinks.push(def);
            } else {
                forces.push(def);
            }
        }
    }
    forces
}

/// Port of `Heritage::handleNewLoadCopies`: after renaming, the last real writes flowing to a
/// load-guard COPY are marked `addrforce` when a guard's range holds them, and the COPYs go
/// (`propagateCopyAway`).
pub(crate) fn handle_new_load_copies(fd: &mut Funcdata) -> Result<()> {
    let copies = std::mem::take(&mut fd.heritage.load_copy_ops);
    let mut sinks = copies.clone();
    for op in find_address_forces(fd, &mut sinks) {
        let Some(out) = fd.op(op).out else { continue };
        let (space, off) = (fd.vn(out).space, fd.vn(out).offset);
        if fd.heritage.load_guards.iter().any(|g| g.is_guarded(space, off)) {
            fd.vn_set(out, VnFlags::ADDRFORCE);
        }
    }
    for op in copies {
        // follow the COPY chain within the address to its earliest input
        let Some(out) = fd.op(op).out else { continue };
        let mut inp = fd.input(op, 0)?;
        while let Some(d) = fd.vn(inp).def.map(|d| fd.op(d)).filter(|d| d.opc == Opcode::Copy) {
            let next = d.ins[0];
            if (fd.vn(next).space, fd.vn(next).offset) != (fd.vn(inp).space, fd.vn(inp).offset) {
                break;
            }
            inp = next;
        }
        fd.total_replace(out, inp)?;
        fd.op_destroy(op);
    }
    Ok(())
}
