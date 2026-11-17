//! Port of `ActionNameVars` (coreaction.cc): every high variable that gets a name is linked to a
//! symbol of the local scope (`Funcdata::linkSymbol` with `detectSymbolConflicts`,
//! `linkSymbolReference` for the stack), and the symbols without a name get Ghidra's default
//! ones (`Scope::buildDefaultName`, `ScopeInternal::assignDefaultNames`; the scheme itself is
//! `scope.rs`). With it: `HighVariable::getNameRepresentative`, `hasName`, `getSymbol`,
//! `getSymbolOffset` and `finalizeDatatype`.
//!
//! What is left out, and why it changes nothing or fails loudly:
//! - A persistent varnode links to a symbol of the global scope. A data symbol of
//!   `ActionMapGlobals` is linked (`mapentry`): it has a name, is not size-locked and is global,
//!   so the action does nothing more with it; the printer reads the link. A function or an
//!   external reference (kept in `Arch`, not in the scope) is not linked, and the printer fails
//!   on such a variable. Superseded: "the link itself is read by the printer only (S9)" with no
//!   link made. A PTRSUB offset off a space base is linked to the container in the stack's or the
//!   global scope (`linkSymbolReference`, kept in `Funcdata::symref`), a function or external
//!   reference included. Superseded: "`PTRSUB(#0, offset)` into a global only marks the offset".
//! - Name recommendations (`recoverNameRecommendationsForSymbols`): the scope collects them
//!   from name-locked symbols when it is cleared, and it holds none.
//! - CAST ops (`setcasts` runs after this action) and proto-partial varnodes do not exist.
//! - `VariablePiece` groups (`isSameGroup`) are not ported; merging fails loudly on them.
//! - `finalizeDatatype` of a piece of a symbol that is a partial type (a partial struct, array,
//!   union or enum piece: `getTypePartialStruct`) fails loudly in `getExactPiece`
//!   (`infertypes.rs`). (Superseded: "of a piece of a symbol (`getExactPiece`) fails loudly",
//!   "giving a variable a data-type other than its own fails loudly".)

use std::collections::BTreeMap;

use super::funcdata::Funcdata;
use super::opcode::Opcode;
use super::scope::{NameFlags, NameRequest, StackNaming, SymbolEntry, SymbolId, UseLimit, GLOBAL, LOCAL};
use super::types::{Kind, Meta, TypeId};
use super::variable::{h_is, h_type, high, input_varnode, is_internal, vn_has_cover, HighId};
use super::varnode::{Space, VarnodeId, VnFlags, CONST_SPACE};
use super::{err, Arch, LowlevelError, Result};

/// What `linkSymbols` records for a default name: a varnode whose high maps a whole symbol, or
/// the symbol a PTRSUB offset refers to (the C++ records the constant offset varnode).
#[derive(Debug, Clone, Copy)]
enum Rec {
    Vn(VarnodeId),
    Ref(SymbolId),
}

/// Port of `ActionNameVars::apply`.
pub(crate) fn name_vars(fd: &mut Funcdata, arch: &Arch) -> Result<i32> {
    // The C++ keeps locked parameters as symbols of the local scope (`ProtoStoreSymbol`,
    // type-locked, name-locked when named); `linkSymbol` and `compareName` read them.
    if fd.proto.locked.as_ref().is_some_and(|l| !l.inputs.is_empty()) {
        return err("namevars: the parameter symbols of a locked prototype are not ported");
    }
    let mut namerec = Vec::new();
    link_symbols(fd, arch, &mut namerec)?;
    recover_name_recommendations(fd)?;
    look_for_bad_jump_tables(fd)?;
    look_for_func_param_names(fd, &namerec)?;
    let mut base = 1;
    for rec in &namerec {
        let (sym, vn) = match *rec {
            Rec::Vn(vn) => {
                let h = high(fd, vn)?;
                let sym =
                    high_symbol(fd, h).ok_or_else(|| LowlevelError("namevars: a linked high has no symbol".into()))?;
                (sym.0, Some(vn))
            }
            Rec::Ref(sym) => (sym, None),
        };
        if fd.symtab.symbol(sym).is_name_undefined() {
            let name = build_default_name(fd, arch, sym, &mut base, vn)?;
            fd.symtab.rename_symbol(sym, &name);
        }
    }
    // ScopeInternal::assignDefaultNames: the symbols still unnamed, in name order
    for sym in fd.symtab.undefined_symbols(LOCAL) {
        let name = build_default_name(fd, arch, sym, &mut base, None)?;
        fd.symtab.rename_symbol(sym, &name);
    }
    Ok(0)
}

/// Port of `ScopeLocal::recoverNameRecommendationsForSymbols` for the recommendations the facts
/// of stage S10 make (`Funcdata::name_recs`: stack variables, without a use point): the
/// address-tied symbol starting at the recommended storage, when its name is undefined, takes
/// the name and is name-locked. (`remapVarnode` of the linked varnode changes nothing for a
/// symbol mapped at that address without a use point.)
fn recover_name_recommendations(fd: &mut Funcdata) -> Result<()> {
    for rec in std::mem::take(&mut fd.name_recs) {
        let super::fspec::Storage::Stack { offset, size } = rec.storage else {
            return err("namevars: a name recommended for a variable outside the stack is not ported");
        };
        // findOverlap: the first entry overlapping the storage, whatever its use point
        let Some((sym, e)) = fd.symtab.find_overlap(LOCAL, Space::Stack, offset, size) else { continue };
        let s = fd.symtab.symbol(sym);
        if s.entries[e].offset != offset || !s.flags.addr_tied || !s.is_name_undefined() {
            continue;
        }
        let name = fd.symtab.make_name_unique(LOCAL, &rec.name)?;
        fd.symtab.rename_symbol(sym, &name);
        fd.symtab.lock_symbol(sym, false, true);
    }
    Ok(())
}

/// `HighVariable::getSymbol`: the symbol and entry of the first member linked to one, and that
/// member.
pub(crate) fn high_symbol(fd: &Funcdata, h: HighId) -> Option<(SymbolId, usize, VarnodeId)> {
    fd.highs.get(h).inst.iter().find_map(|vn| fd.mapentry.get(vn).map(|&(s, e)| (s, e, *vn)))
}

/// `HighVariable::getSymbolOffset` (`setSymbol`): -1 when the linked member is the whole symbol,
/// else its offset into it (`Address::overlapJoin` from the entry, plus the entry's own offset
/// when it maps a piece of a join).
pub(crate) fn symbol_offset(fd: &Funcdata, arch: &Arch, h: HighId) -> Result<i32> {
    let Some((sym, e, vn)) = high_symbol(fd, h) else { return Ok(-1) };
    let (s, v) = (fd.symtab.symbol(sym), fd.vn(vn));
    let entry =
        s.entries.get(e).ok_or_else(|| LowlevelError("namevars: a varnode mapped to a missing entry".into()))?;
    let size = s.ty.map_or(0, |t| fd.types.size(t));
    if size == v.size && entry.space == v.space && entry.offset == v.offset && entry.piece.is_none() {
        return Ok(-1);
    }
    if entry.space == Space::Join {
        return err("namevars: a variable overlapping a join symbol (JoinSpace::overlapJoin) is not ported");
    }
    // AddrSpace::overlapJoin: the distance from the entry's start wrapped to the space
    // (`wrapOffset`), within the symbol's size
    let dist = v.offset.wrapping_sub(entry.offset) & super::heritage::space_mask(arch, entry.space);
    let overlap = if entry.space != v.space || dist >= u64::from(size) { -1 } else { dist as i32 };
    Ok(overlap.wrapping_add(entry.piece.unwrap_or(0) as i32))
}

/// `Varnode::isNameLock`: set by `setSymbolEntry` for a name-locked symbol.
fn name_locked(fd: &Funcdata, vn: VarnodeId) -> bool {
    fd.mapentry.get(&vn).is_some_and(|&(s, _)| fd.symtab.symbol(s).flags.name_locked)
}

/// Port of `HighVariable::compareName`: whether `vn2` names the variable better than `vn1`.
fn compare_name(fd: &Funcdata, vn1: VarnodeId, vn2: VarnodeId) -> bool {
    if name_locked(fd, vn1) {
        return false;
    }
    if name_locked(fd, vn2) {
        return true;
    }
    let (a, b) = (fd.vn(vn1), fd.vn(vn2));
    for f in [VnFlags::UNAFFECTED, VnFlags::PERSIST, VnFlags::INPUT, VnFlags::ADDRTIED] {
        if a.has(f) != b.has(f) {
            return b.has(f);
        }
    }
    let (ia, ib) = (is_internal(fd, a.space), is_internal(fd, b.space));
    if ia != ib {
        return ia;
    }
    match (a.def, b.def) {
        (Some(d1), Some(d2)) => fd.op(d2).seq.time < fd.op(d1).seq.time,
        (None, Some(_)) => true,
        _ => false,
    }
}

/// Port of `HighVariable::getNameRepresentative`.
pub(crate) fn name_representative(fd: &Funcdata, h: HighId) -> Result<VarnodeId> {
    let mut inst = fd.highs.get(h).inst.iter().copied();
    let first = inst.next().ok_or_else(|| LowlevelError("namevars: a high variable without members".into()))?;
    Ok(inst.fold(first, |rep, vn| if compare_name(fd, rep, vn) { vn } else { rep }))
}

/// Port of `HighVariable::hasName`.
fn has_name(fd: &Funcdata, h: HighId) -> Result<bool> {
    let inst = &fd.highs.get(h).inst;
    let mut indirectonly = true;
    for &vn in inst {
        if !vn_has_cover(fd, vn) {
            if inst.len() > 1 {
                return err("Non-coverable varnode has been merged");
            }
            return Ok(false);
        }
        if fd.vn(vn).has(VnFlags::IMPLIED) {
            if inst.len() > 1 {
                return err("Implied varnode has been merged");
            }
            return Ok(false);
        }
        if !fd.vn(vn).has(VnFlags::INDIRECTONLY) {
            indirectonly = false;
        }
    }
    if h_is(fd, h, VnFlags::UNAFFECTED) {
        if !h_is(fd, h, VnFlags::INPUT) || indirectonly {
            return Ok(false);
        }
        let v = fd.vn(input_varnode(fd, h)?);
        // isIllegalInput: an input no direct write reaches
        if v.has(VnFlags::DIRECTWRITE) && v.has(VnFlags::SPACEBASE) {
            return Ok(false); // the stack pointer
        }
    }
    Ok(true)
}

/// `Varnode::getUsePoint`: the address of the defining op, else just before the entry.
fn use_point(fd: &Funcdata, arch: &Arch, vn: VarnodeId) -> (Space, u64) {
    let code = Space::Sleigh(arch.sleigh.code_space());
    match fd.vn(vn).def {
        Some(d) => (code, fd.op(d).seq.addr),
        None => (code, fd.entry.wrapping_sub(1)),
    }
}

/// Port of `Funcdata::detectSymbolConflicts`: another variable is written to storage meeting
/// `vn`'s by an op at the same address, so an entry limited to that address cannot tell them
/// apart. (The C++ walks the neighbours in the definition tree, which sorts by the defining
/// op's sequence number: all the varnodes written at one address.)
fn detect_symbol_conflicts(fd: &mut Funcdata, vn: VarnodeId, h: HighId) -> Result<bool> {
    let v = fd.vn(vn);
    let Some(def) = v.def.filter(|_| !v.has(VnFlags::ADDRTIED)) else { return Ok(false) };
    if is_internal(fd, v.space) {
        return Ok(true); // temporaries are assumed to be in conflict
    }
    let (space, first, last) = (v.space, v.offset, v.offset.wrapping_add(u64::from(v.size)).wrapping_sub(1));
    for op in fd.ops_at(fd.op(def).seq.addr) {
        let Some(other) = fd.op(op).out.filter(|&o| o != vn) else { continue };
        let o = fd.vn(other);
        if o.def != Some(op) || o.space != space {
            continue;
        }
        // Varnode::intersects
        if o.offset <= last
            && first <= o.offset.wrapping_add(u64::from(o.size)).wrapping_sub(1)
            && high(fd, other)? != h
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Port of `Funcdata::linkSymbol`: the symbol of `vn`'s high, an entry of the local scope
/// holding its first byte at its use point, or a new local symbol. For a persistent varnode, the
/// global data symbol holding its first byte, `None` otherwise (see the module comment).
fn link_symbol(fd: &mut Funcdata, arch: &Arch, vn: VarnodeId) -> Result<Option<SymbolId>> {
    let h = high(fd, vn)?;
    if let Some((sym, _, _)) = high_symbol(fd, h) {
        return Ok(Some(sym));
    }
    let v = fd.vn(vn);
    let (space, offset, persist) = (v.space, v.offset, v.has(VnFlags::PERSIST));
    let usepoint = use_point(fd, arch, vn);
    if persist {
        // queryProperties: the global scope owns the storage; a variable a function or an external
        // reference holds stays unlinked here and the printer fails on it
        super::facts::query_symbol(fd, arch, space, offset)?;
        if let Some(GlobalHit::Data(sym, e)) = global_container(fd, arch, space, offset, Some(usepoint))? {
            if !fd.symtab.symbol(sym).entries[e].conflict {
                fd.mapentry.insert(vn, (sym, e));
                return Ok(Some(sym));
            }
        }
        return Ok(None);
    }
    // queryProperties(addr, 1, usepoint): the local scope, then (for storage it does not own)
    // the global one, which holds nothing outside its ranges. The reference (Ghidra 12.3) links
    // any entry that is not a conflict; it has no `handleSymbolConflict`.
    if let Some((sym, e)) = fd.symtab.find_container(LOCAL, space, offset, 1, Some(usepoint))? {
        if !fd.symtab.symbol(sym).entries[e].conflict {
            fd.mapentry.insert(vn, (sym, e));
            return Ok(Some(sym));
        }
    }
    let ty = h_type(fd, h).0;
    let size = fd.types.size(ty);
    let entry = if detect_symbol_conflicts(fd, vn, h)? {
        // Scope::addSymbolWithConflict, MapEntryConflict: in use at the defining op only
        SymbolEntry {
            space,
            offset,
            size,
            uselimit: UseLimit(vec![(usepoint.0, usepoint.1, usepoint.1)]),
            conflict: true,
            piece: None,
        }
    } else if fd.vn(vn).has(VnFlags::ADDRTIED) {
        SymbolEntry { space, offset, size, uselimit: UseLimit::default(), conflict: false, piece: None }
    } else {
        SymbolEntry {
            space,
            offset,
            size,
            uselimit: UseLimit(vec![(usepoint.0, usepoint.1, usepoint.1)]),
            conflict: false,
            piece: None,
        }
    };
    let uselimit = entry.uselimit.clone();
    let sym = fd.symtab.add_symbol(LOCAL, "", Some(ty), None, Some(entry))?;
    if space == Space::Join {
        // Scope::addMap: each piece of the join is mapped too, from the least significant
        let pieces = usize::try_from(offset).ok().and_then(|i| fd.joins.get(i)).cloned();
        let pieces = pieces.ok_or_else(|| LowlevelError("join address without a record".into()))?;
        let mut off = 0;
        for &(s, o, z) in pieces.iter().rev() {
            if Space::Sleigh(s) != CONST_SPACE {
                let piece = SymbolEntry {
                    space: Space::Sleigh(s),
                    offset: o,
                    size: z,
                    uselimit: uselimit.clone(),
                    conflict: false,
                    piece: Some(off),
                };
                fd.symtab.add_piece(sym, piece)?;
            }
            off += z;
        }
    }
    fd.mapentry.insert(vn, (sym, 0));
    Ok(Some(sym))
}

/// What the offset of a space-base PTRSUB refers to (`Varnode::setSymbolReference`, the
/// constant's high's symbol and offset), read by the printer: a symbol and the offset into it,
/// or the function or external reference the global scope holds there (kept in `Arch`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SymRef {
    Sym(SymbolId, i64),
    Function(u64),
    ExternRef,
}

/// The container `findContainer` takes in the global scope: a data symbol (and its entry) of
/// `ActionMapGlobals`, or a function (one byte) or an external reference (a pointer), the two kept
/// in `Arch`.
enum GlobalHit {
    Data(SymbolId, usize),
    Function,
    ExternRef,
}

/// `Scope::queryContainer(addr, 1, usepoint)` on the global scope: the smallest entry holding
/// byte `offset` among the data symbols, the functions and the external references; a data
/// symbol the size of a function or external reference at the same address fails loudly.
fn global_container(
    fd: &Funcdata,
    arch: &Arch,
    space: Space,
    offset: u64,
    usepoint: Option<(Space, u64)>,
) -> Result<Option<GlobalHit>> {
    let other = (space == Space::Sleigh(arch.spec.stack_container))
        .then(|| super::infertypes::query_global(arch, offset, 1))
        .flatten()
        .map(
            |e| if e.externref { (arch.spec.stack_pointer.2, GlobalHit::ExternRef) } else { (1, GlobalHit::Function) },
        );
    let data = fd.symtab.find_container(GLOBAL, space, offset, 1, usepoint)?;
    Ok(match (data, other) {
        (Some((sym, e)), Some((osize, hit))) => {
            let size = fd.symtab.symbol(sym).entries[e].size;
            if osize == size {
                return err("namevars: a global data symbol the size of a function or external reference at the same address is not ported");
            }
            Some(if osize < size { hit } else { GlobalHit::Data(sym, e) })
        }
        (Some((sym, e)), None) => Some(GlobalHit::Data(sym, e)),
        (None, other) => other.map(|(_, hit)| hit),
    })
}

/// Port of `Funcdata::linkSymbolReference` for one PTRSUB off a spacebase: the container of the
/// address the offset `off` refers to (`queryContainer` without a use point) in the stack's
/// local scope or the global scope, kept for `off` in `Funcdata::symref`
/// (`Varnode::setSymbolReference`) with the offset into it; the symbol is returned.
fn link_symbol_reference(fd: &mut Funcdata, arch: &Arch, in0: VarnodeId, off: VarnodeId) -> Result<Option<SymbolId>> {
    let h = high(fd, in0)?;
    let ptype = h_type(fd, h).0;
    let Some(sb) = fd.types.ptr_to(ptype).filter(|_| fd.types.meta(ptype) == Meta::Ptr) else { return Ok(None) };
    let Kind::Spacebase { space, .. } = fd.types.get(sb).kind else { return Ok(None) };
    // TypeSpacebase::getAddress: the offset wrapped to the space (`resolveConstant`)
    let addr = fd.vn(off).offset
        & if space == Space::Stack { fd.localmap.highest() } else { super::heritage::space_mask(arch, space) };
    let hit = if space == Space::Stack {
        fd.symtab.find_container(LOCAL, Space::Stack, addr, 1, None)?.map(|(s, e)| GlobalHit::Data(s, e))
    } else {
        super::facts::query_symbol(fd, arch, space, addr)?;
        global_container(fd, arch, space, addr, None)?
    };
    let r = match hit {
        None => return Ok(None),
        Some(GlobalHit::Data(sym, e)) => {
            let entry = &fd.symtab.symbol(sym).entries[e];
            let at = i64::from(addr.wrapping_sub(entry.offset) as i32) + i64::from(entry.piece.unwrap_or(0) as i32);
            SymRef::Sym(sym, at)
        }
        Some(GlobalHit::Function) => SymRef::Function(addr),
        Some(GlobalHit::ExternRef) => SymRef::ExternRef,
    };
    fd.symref.insert(off, r);
    Ok(match r {
        SymRef::Sym(sym, _) => Some(sym),
        _ => None,
    })
}

/// Port of `ActionNameVars::linkSpacebaseSymbol`.
fn link_spacebase_symbol(fd: &mut Funcdata, arch: &Arch, vn: VarnodeId, namerec: &mut Vec<Rec>) -> Result<()> {
    let v = fd.vn(vn);
    if !v.is_constant() && !v.is_input() {
        return Ok(());
    }
    let readers: Vec<_> = v.descend.iter().copied().collect();
    for op in readers {
        if fd.op(op).opc != Opcode::Ptrsub {
            continue;
        }
        let (in0, off) = (fd.op(op).ins[0], fd.op(op).ins[1]);
        if let Some(sym) = link_symbol_reference(fd, arch, in0, off)? {
            if fd.symtab.symbol(sym).is_name_undefined() {
                namerec.push(Rec::Ref(sym));
            }
        }
    }
    Ok(())
}

/// Port of `HighVariable::finalizeDatatype`: the piece of the symbol's data-type the variable
/// covers (`getExactPiece`, `infertypes.rs`; the whole type for a whole symbol) becomes the
/// variable's, when there is one and it is not unknown. It stays (`type_finalized`, read by
/// `variable::h_type`). A piece that is a partial type fails. (Superseded: "Nothing ported
/// reads `type_finalized`, so a type that would change, or a piece of the symbol, fails".)
fn finalize_datatype(fd: &mut Funcdata, arch: &Arch, h: HighId, sym: SymbolId) -> Result<()> {
    let Some(cur) = fd.symtab.symbol(sym).ty else { return Ok(()) };
    let sz = fd.vn(fd.highs.get(h).inst[0]).size;
    let off = symbol_offset(fd, arch, h)?.max(0);
    let Some(tp) = super::infertypes::exact_piece(fd, arch, cur, off as u64, sz)? else { return Ok(()) };
    if fd.types.meta(tp) != Meta::Unknown {
        fd.highs.get_mut(h).type_finalized = Some(tp);
    }
    Ok(())
}

/// Port of `ActionNameVars::linkSymbols`.
fn link_symbols(fd: &mut Funcdata, arch: &Arch, namerec: &mut Vec<Rec>) -> Result<()> {
    // constants: no equate symbols exist; a spacebase constant is the base of a global pointer
    for vn in fd.loc_space(CONST_SPACE) {
        if fd.vn(vn).has(VnFlags::SPACEBASE) {
            link_spacebase_symbol(fd, arch, vn, namerec)?;
        }
    }
    // the other spaces in index order, each in location order
    for vn in fd.loc_all() {
        let v = fd.vn(vn);
        if v.space == CONST_SPACE || v.is_free() {
            continue;
        }
        if v.has(VnFlags::SPACEBASE) {
            link_spacebase_symbol(fd, arch, vn, namerec)?;
        }
        let h = high(fd, vn)?;
        if name_representative(fd, h)? != vn || !has_name(fd, h)? {
            continue; // each high once
        }
        let Some(sym) = link_symbol(fd, arch, vn)? else { continue };
        let s = fd.symtab.symbol(sym);
        let global = s.scope == GLOBAL;
        if s.is_name_undefined() && symbol_offset(fd, arch, h)? < 0 {
            namerec.push(Rec::Vn(vn));
        }
        if s.flags.size_type_locked && s.ty.is_some_and(|t| fd.types.size(t) == fd.vn(vn).size) {
            let old = s.ty;
            let ty = h_type(fd, h).0;
            let same = old.is_some_and(|t| fd.types.size(t) == fd.types.size(ty));
            fd.symtab.override_size_lock_type(sym, ty, same)?;
        }
        if fd.vn(vn).has(VnFlags::ADDRTIED) && !global {
            finalize_datatype(fd, arch, h, sym)?;
        }
    }
    Ok(())
}

/// Port of `ActionNameVars::lookForBadJumpTables`: the target of an indirect jump that could
/// not be recovered as a switch is named `UNRECOVERED_JUMPTABLE`.
fn look_for_bad_jump_tables(fd: &mut Funcdata) -> Result<()> {
    for i in 0..fd.qlst.len() {
        let call = fd.call(fd.qlst[i]);
        if !call.bad_jump_table {
            continue;
        }
        let vn = fd.op(call.op).ins[0];
        if fd.vn(vn).is_free() {
            continue;
        }
        let h = high(fd, vn)?;
        let Some((sym, _, _)) = high_symbol(fd, h) else { continue };
        let s = fd.symtab.symbol(sym);
        if s.flags.name_locked || s.scope != LOCAL {
            continue; // only a symbol of the local scope is renamed (a global is linked too)
        }
        let name = fd.symtab.make_name_unique(LOCAL, "UNRECOVERED_JUMPTABLE")?;
        fd.symtab.rename_symbol(sym, &name);
    }
    Ok(())
}

/// Port of `ActionNameVars::lookForFuncParamNames` (with `makeRec`): a variable passed to a
/// call takes the name of the locked, named parameter it is passed as.
fn look_for_func_param_names(fd: &mut Funcdata, namerec: &[Rec]) -> Result<()> {
    let mut recmap: BTreeMap<HighId, (TypeId, String)> = BTreeMap::new();
    for i in 0..fd.qlst.len() {
        let call = fd.call(fd.qlst[i]);
        let Some(locked) = &call.proto.locked else { continue };
        let op = call.op;
        let params: Vec<(String, TypeId)> = locked.inputs.iter().map(|p| (p.name.clone(), p.ty)).collect();
        let numparam = params.len().min(fd.op(op).ins.len().saturating_sub(1));
        for (j, (name, ct)) in params.into_iter().take(numparam).enumerate() {
            // makeRec: a name-locked parameter of the varnode's size. `FuncProto::setPieces` locks
            // the inputs (`setInputLock`), and `ParameterSymbol::setTypeLock` name-locks every
            // parameter declared with a name
            let vn = fd.op(op).ins[j + 1];
            if name.is_empty() || fd.vn(vn).size != fd.types.size(ct) {
                continue;
            }
            let h = high(fd, vn)?;
            if h_is(fd, h, VnFlags::ADDRTIED) || name.starts_with("param_") {
                continue;
            }
            match recmap.get(&h) {
                Some(&(old, _)) if fd.types.order(old, ct) <= 0 => {} // the old type is more specified
                _ => {
                    recmap.insert(h, (ct, name));
                }
            }
        }
    }
    if recmap.is_empty() {
        return Ok(());
    }
    for rec in namerec {
        let Rec::Vn(vn) = *rec else { continue }; // a constant offset is free
        if fd.vn(vn).is_free() || fd.vn(vn).is_input() {
            continue;
        }
        let h = high(fd, vn)?;
        if fd.highs.get(h).num_merge_classes() > 1 {
            continue; // no inherited name for a speculative merge
        }
        let Some((sym, _, _)) = high_symbol(fd, h) else { continue };
        if !fd.symtab.symbol(sym).is_name_undefined() {
            continue;
        }
        if let Some((_, name)) = recmap.get(&h) {
            let name = fd.symtab.make_name_unique(LOCAL, name)?;
            fd.symtab.rename_symbol(sym, &name);
        }
    }
    Ok(())
}

/// Port of `Scope::buildDefaultName`: the default name of `sym`, from the varnode it was linked
/// through (`vn`, unless a constant) or from its first entry.
fn build_default_name(
    fd: &mut Funcdata,
    arch: &Arch,
    sym: SymbolId,
    base: &mut i32,
    vn: Option<VarnodeId>,
) -> Result<String> {
    let s = fd.symtab.symbol(sym);
    let ty = s.ty;
    let param = (s.category == Some(0)).then_some(s.cat_index as i32 + 1);
    let entry = s.entries.first().map(|e| (e.space, e.offset, e.uselimit.0.is_empty()));
    let mut index = param;
    let (addr, flags) = match vn.filter(|&v| !fd.vn(v).is_constant()) {
        Some(vn) => {
            let h = high(fd, vn)?;
            let v = fd.vn(vn);
            let mut flags = NameFlags {
                unaffected: v.has(VnFlags::UNAFFECTED),
                return_address: v.has(VnFlags::RETURN_ADDRESS),
                persist: v.has(VnFlags::PERSIST),
                input: v.has(VnFlags::INPUT),
                addr_tied: v.has(VnFlags::ADDRTIED),
                indirect_creation: v.has(VnFlags::INDIRECT_CREATION),
            };
            if param.is_some() || h_is(fd, h, VnFlags::INPUT) {
                flags.input = true;
                index = Some(param.unwrap_or(-1));
            }
            (Some((v.space, v.offset)), flags)
        }
        None => match entry {
            Some((space, offset, everywhere)) => (
                Some((space, offset)),
                NameFlags { addr_tied: everywhere, input: param.is_some(), ..NameFlags::default() },
            ),
            None => (None, NameFlags::default()),
        },
    };
    let (space_name, addr_size) = match addr {
        Some((sp, _)) => super::scope::space_info(arch, sp)?,
        None => (String::new(), 0),
    };
    let name_base = ty.map_or(String::new(), |t| fd.types.print_name_base(t));
    let size = ty.map_or(1, |t| fd.types.size(t));
    let reg = match addr {
        Some((Space::Sleigh(sp), off)) => arch.register_name(sp, off, size).map_or("", |r| r.0),
        _ => "",
    };
    let req = NameRequest {
        addr,
        space_name: &space_name,
        addr_size,
        name_base: &name_base,
        reg,
        flags,
        in_local_range: addr.is_some_and(|(sp, off)| sp == Space::Stack && fd.localmap.in_local_range(off)),
        stack: Some(StackNaming {
            space: Space::Stack,
            grows_negative: true,
            min_param: fd.localmap.min_param(),
            max_param: fd.localmap.max_param(),
            addr_size: super::scope::space_info(arch, Space::Stack)?.1,
        }),
    };
    match index.as_mut() {
        Some(i) => fd.symtab.build_variable_name(LOCAL, &req, i),
        None => fd.symtab.build_variable_name(LOCAL, &req, base),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decomp::facts::NameRec;
    use crate::decomp::fspec::Storage;

    #[test]
    fn name_recommendations_for_stack_variables() {
        let mut fd = Funcdata::new(0x1000);
        let entry = |offset| SymbolEntry {
            space: Space::Stack,
            offset,
            size: 4,
            uselimit: UseLimit::default(),
            conflict: false,
            piece: None,
        };
        let a = fd.symtab.add_symbol(LOCAL, "", None, None, Some(entry(0xffffff44))).unwrap();
        let b = fd.symtab.add_symbol(LOCAL, "", None, None, Some(entry(0xffffff48))).unwrap();
        let c = fd.symtab.add_symbol(LOCAL, "named", None, None, Some(entry(0xffffff50))).unwrap();
        let rec = |offset, size, name: &str| NameRec { storage: Storage::Stack { offset, size }, name: name.into() };
        // at a symbol's start; inside one (not its address); at one that has a name; at none
        fd.name_recs = vec![
            rec(0xffffff44, 4, "local_bc"),
            rec(0xffffff4a, 2, "local_b6"),
            rec(0xffffff50, 4, "local_b0"),
            rec(0xffffff60, 4, "local_a0"),
        ];
        recover_name_recommendations(&mut fd).unwrap();
        let s = |id| fd.symtab.symbol(id);
        assert_eq!((s(a).name.as_str(), s(a).flags.name_locked), ("local_bc", true));
        assert!(s(b).is_name_undefined() && !s(b).flags.name_locked);
        assert_eq!(s(c).name, "named");
        assert!(fd.name_recs.is_empty());
        // a recommendation outside the stack is not ported
        fd.name_recs = vec![NameRec { storage: Storage::Space { space: 2, offset: 0, size: 4 }, name: "x".into() }];
        assert!(recover_name_recommendations(&mut fd).is_err());
    }
}
