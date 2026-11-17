//! The symbol-table core of database.cc (`Symbol`, `SymbolEntry`, `ScopeInternal`) and the
//! default-name scheme of `ScopeInternal::buildVariableName` / `ScopeLocal::buildVariableName`
//! (varmap.cc), `buildUndefinedName` and `makeNameUnique`. Wired as `Funcdata::symtab`: `ActionInputPrototype`
//! keeps the parameters here (`ProtoStoreSymbol`), `ActionMapGlobals` the global data symbols;
//! `ActionNameVars` (namevars.rs) the local symbols of the named variables; `print map` prints
//! the local scope.
//!
//! Scopes and symbols live in one arena ([`Database`]) addressed by [`ScopeId`] and
//! [`SymbolId`]. A scope's name tree is the C++ `SymbolNameTree` (by name, then `nameDedup`).
//! Its map is one [`RangeMap`] per space (`maptable`, rangemap.rs), so `printEntries` and
//! [`Database::find_container`] meet the entries in the order the C++ does. The local scope's
//! stack ranges are `Funcdata::localmap` (`LocalMap`, varmap.rs).
//!
//! Known limit: one [`Database`] belongs to one function, where the C++ has one global scope
//! per process, so global symbols of an earlier decompilation in the same process are not seen.

use std::collections::BTreeMap;

use super::rangemap::{RangeMap, Subsort, SUB_FIRST, SUB_LAST};
use super::varnode::Space;
use super::{LowlevelError, Result};

/// The global scope of a function's [`Database`] ([`Database::for_function`]).
pub(crate) const GLOBAL: ScopeId = ScopeId(0);
/// The function's local scope (`Funcdata::localmap`).
pub(crate) const LOCAL: ScopeId = ScopeId(1);

/// Index of a scope in the [`Database`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct ScopeId(pub(crate) u32);

/// Index of a symbol in the [`Database`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct SymbolId(pub(crate) u32);

/// `Symbol::flags` that naming reads (the `Varnode` bits the C++ stores there).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct SymFlags {
    pub(crate) name_locked: bool,
    pub(crate) type_locked: bool,
    pub(crate) size_type_locked: bool,
    /// `Varnode::addrtied`: every entry is valid throughout the scope (`SymbolEntry::inUse`)
    pub(crate) addr_tied: bool,
}

/// `Symbol::category`: `function_parameter` (0), `equate` (1), `union_facet` (2),
/// `fake_input` (3); `None` is `no_category` (-1).
pub(crate) type Category = Option<u32>;

/// `RangeList` of a use limit: inclusive offset ranges, by space.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct UseLimit(pub(crate) Vec<(Space, u64, u64)>);

impl UseLimit {
    /// `RangeList::inRange(usepoint, 1)`.
    fn contains(&self, space: Space, off: u64) -> bool {
        self.0.iter().any(|&(s, first, last)| s == space && first <= off && off <= last)
    }
}

/// Port of `SymbolEntry` (a `MapEntry`: storage plus where it is in use).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SymbolEntry {
    pub(crate) space: Space,
    pub(crate) offset: u64,
    pub(crate) size: u32,
    pub(crate) uselimit: UseLimit,
    /// a `MapEntryConflict`: another variable is written to the storage at the same address
    pub(crate) conflict: bool,
    /// `SymbolEntry::piece`: the entry maps one piece of a symbol stored in a join, at this
    /// offset into the symbol (`Scope::addMap`)
    pub(crate) piece: Option<u32>,
}

impl SymbolEntry {
    /// `getLast`
    fn last(&self) -> u64 {
        self.offset.wrapping_add(u64::from(self.size)).wrapping_sub(1)
    }

    /// `SymbolRange::getSubsort`: the first range of the use limit, unless the symbol is
    /// address-tied.
    fn subsort(&self, addr_tied: bool) -> Result<Subsort> {
        if addr_tied {
            return Ok(SUB_FIRST);
        }
        let first = self.uselimit.0.iter().map(|&(s, first, _)| (s.index(), first)).min();
        first.ok_or_else(|| LowlevelError("Map entry with empty uselimit".into()))
    }
}

/// Port of `Symbol`.
#[derive(Debug, Clone)]
pub(crate) struct Symbol {
    pub(crate) name: String,
    pub(crate) dedup: u32,
    pub(crate) scope: ScopeId,
    pub(crate) ty: Option<super::types::TypeId>,
    pub(crate) flags: SymFlags,
    pub(crate) category: Category,
    pub(crate) cat_index: u32,
    pub(crate) entries: Vec<SymbolEntry>,
    /// `Symbol::is_this_ptr` (`FuncProto::updateThisPointer`)
    pub(crate) this_ptr: bool,
}

impl Symbol {
    /// `Symbol::isNameUndefined`: a `$$undefXXXXXXXX` placeholder.
    pub(crate) fn is_name_undefined(&self) -> bool {
        self.name.len() == 15 && self.name.starts_with("$$undef")
    }
}

/// Port of `ScopeInternal`.
#[derive(Debug, Clone, Default)]
pub(crate) struct Scope {
    /// `nametree`
    names: BTreeMap<(String, u32), SymbolId>,
    /// `maptable`: the entries (symbol, entry index) of each space, by space index
    maps: BTreeMap<u32, RangeMap<(SymbolId, usize)>>,
    /// `category`
    categories: Vec<Vec<Option<SymbolId>>>,
}

/// What `ScopeLocal::buildVariableName` reads about the stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StackNaming {
    pub(crate) space: Space,
    pub(crate) grows_negative: bool,
    pub(crate) min_param: u64,
    pub(crate) max_param: u64,
    /// the address size in bytes (for the sign extension of an offset)
    pub(crate) addr_size: u32,
}

/// The `Varnode` flags `buildVariableName` tests.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct NameFlags {
    pub(crate) unaffected: bool,
    pub(crate) return_address: bool,
    pub(crate) persist: bool,
    pub(crate) input: bool,
    pub(crate) addr_tied: bool,
    pub(crate) indirect_creation: bool,
}

/// One `buildVariableName` request. `name_base` is `Datatype::printNameBase` of the type
/// (`i`, `u`, `pi`, ...; empty without a type), `reg` the register name of the storage
/// (`Translate::getRegisterName`, empty if none) and `space_name` its space's name.
#[derive(Debug, Clone, Copy)]
pub(crate) struct NameRequest<'a> {
    /// none: `Address()` (an invalid address)
    pub(crate) addr: Option<(Space, u64)>,
    pub(crate) space_name: &'a str,
    pub(crate) addr_size: u32,
    pub(crate) name_base: &'a str,
    pub(crate) reg: &'a str,
    pub(crate) flags: NameFlags,
    /// the address is inside the prototype's local range (`getLocalRange().inRange`)
    pub(crate) in_local_range: bool,
    /// `ScopeLocal`'s stack data, for a name in the local scope
    pub(crate) stack: Option<StackNaming>,
}

/// The scopes and symbols of a program and its functions (`Database`).
#[derive(Debug, Clone, Default)]
pub(crate) struct Database {
    scopes: Vec<Scope>,
    symbols: Vec<Symbol>,
}

/// `spacename[0] = toupper(spacename[0])`.
fn capitalized(name: &str) -> String {
    let mut c = name.chars();
    c.next().map(|f| f.to_ascii_uppercase().to_string() + c.as_str()).unwrap_or_default()
}

impl Database {
    pub(crate) fn scope(&self, id: ScopeId) -> &Scope {
        &self.scopes[id.0 as usize]
    }
    pub(crate) fn symbol(&self, id: SymbolId) -> &Symbol {
        &self.symbols[id.0 as usize]
    }

    /// A new empty scope.
    pub(crate) fn new_scope(&mut self) -> ScopeId {
        let id = ScopeId(self.scopes.len() as u32);
        self.scopes.push(Scope::default());
        id
    }

    /// `ScopeInternal::findFirstByName`.
    pub(crate) fn find_first_by_name(&self, scope: ScopeId, name: &str) -> Option<SymbolId> {
        let names = &self.scope(scope).names;
        names.range((name.to_string(), 0)..).next().filter(|((n, _), _)| n == name).map(|(_, &s)| s)
    }

    /// `ScopeInternal::insertNameTree`: a taken name gets the next dedup number.
    fn insert_name(&mut self, sym: SymbolId) {
        let s = &self.symbols[sym.0 as usize];
        let (scope, name) = (s.scope, s.name.clone());
        let names = &mut self.scopes[scope.0 as usize].names;
        let dedup =
            names.range((name.clone(), 0)..=(name.clone(), u32::MAX)).next_back().map_or(0, |((_, d), _)| d + 1);
        names.insert((name, dedup), sym);
        self.symbols[sym.0 as usize].dedup = dedup;
    }

    /// `ScopeInternal::addSymbolInternal` with `addMapPoint`/`addMapEntry`: an empty name becomes
    /// [`Self::build_undefined_name`]; a category above 0 takes the next index in its list.
    pub(crate) fn add_symbol(
        &mut self,
        scope: ScopeId,
        name: &str,
        ty: Option<super::types::TypeId>,
        category: Category,
        entry: Option<SymbolEntry>,
    ) -> Result<SymbolId> {
        let name = if name.is_empty() { self.build_undefined_name(scope)? } else { name.to_string() };
        let id = SymbolId(self.symbols.len() as u32);
        let mut cat_index = 0;
        if let Some(c) = category {
            let cats = &mut self.scopes[scope.0 as usize].categories;
            if cats.len() <= c as usize {
                cats.resize(c as usize + 1, Vec::new());
            }
            let list = &mut cats[c as usize];
            if c > 0 {
                cat_index = list.len() as u32;
            }
            if list.len() <= cat_index as usize {
                list.resize(cat_index as usize + 1, None);
            }
            list[cat_index as usize] = Some(id);
        }
        self.symbols.push(Symbol {
            name,
            dedup: 0,
            scope,
            ty,
            flags: SymFlags::default(),
            category,
            cat_index,
            entries: Vec::new(),
            this_ptr: false,
        });
        self.insert_name(id);
        if let Some(e) = entry {
            let s = &mut self.symbols[id.0 as usize];
            // Scope::addMap: an entry without a use limit holds everywhere
            if e.uselimit.0.is_empty() {
                s.flags.addr_tied = true;
            }
            // ScopeInternal::addMapInternal
            if e.last() < e.offset {
                return Err(LowlevelError(format!("Symbol {} extends beyond the end of the address space", s.name)));
            }
            let sub = e.subsort(s.flags.addr_tied)?;
            let map = self.scopes[scope.0 as usize].maps.entry(e.space.index()).or_default();
            map.insert((id, 0), e.offset, e.last(), sub);
            s.entries.push(e);
        }
        Ok(id)
    }

    /// `ScopeInternal::addMapInternal` for one more entry of `sym`: a piece of a symbol stored
    /// in a join (`Scope::addMap` maps each piece of the join too).
    pub(crate) fn add_piece(&mut self, sym: SymbolId, e: SymbolEntry) -> Result<()> {
        let s = &mut self.symbols[sym.0 as usize];
        if e.last() < e.offset {
            return Err(LowlevelError(format!("Symbol {} extends beyond the end of the address space", s.name)));
        }
        let sub = e.subsort(s.flags.addr_tied)?;
        let map = self.scopes[s.scope.0 as usize].maps.entry(e.space.index()).or_default();
        map.insert((sym, s.entries.len()), e.offset, e.last(), sub);
        s.entries.push(e);
        Ok(())
    }

    /// `ScopeInternal::renameSymbol`.
    pub(crate) fn rename_symbol(&mut self, sym: SymbolId, name: &str) {
        let s = &self.symbols[sym.0 as usize];
        let key = (s.name.clone(), s.dedup);
        self.scopes[s.scope.0 as usize].names.remove(&key);
        self.symbols[sym.0 as usize].name = name.to_string();
        self.insert_name(sym);
    }

    /// `SymbolEntry::inUse`.
    fn in_use(&self, sym: SymbolId, e: &SymbolEntry, usepoint: Option<(Space, u64)>) -> bool {
        if self.symbol(sym).flags.addr_tied {
            return true;
        }
        usepoint.is_some_and(|(s, o)| e.uselimit.contains(s, o))
    }

    /// Port of `ScopeInternal::findContainer`: the smallest entry in use at `usepoint` holding
    /// the whole range, walking the pieces at the point from the last (those sub-sorted after
    /// the use point are left out); an exact size stops the search.
    pub(crate) fn find_container(
        &self,
        scope: ScopeId,
        space: Space,
        off: u64,
        size: u32,
        usepoint: Option<(Space, u64)>,
    ) -> Result<Option<(SymbolId, usize)>> {
        let end = off.wrapping_add(u64::from(size)).wrapping_sub(1);
        let mut best = None;
        let mut oldsize: Option<u32> = None;
        let Some(map) = self.scope(scope).maps.get(&space.index()) else { return Ok(None) };
        let bound = usepoint.map_or(SUB_LAST, |(s, o)| (s.index(), o));
        for (sym, ei) in map.find(off, SUB_FIRST, bound).into_iter().rev() {
            let e = self
                .symbol(sym)
                .entries
                .get(ei)
                .ok_or_else(|| LowlevelError("a map record without its entry".into()))?;
            if e.last() >= end && oldsize.is_none_or(|o| e.size < o) && self.in_use(sym, e, usepoint) {
                best = Some((sym, ei));
                if e.size == size {
                    break;
                }
                oldsize = Some(e.size);
            }
        }
        Ok(best)
    }

    /// Port of `ScopeInternal::buildUndefinedName`: one more than the highest `$$undef` name.
    pub(crate) fn build_undefined_name(&self, scope: ScopeId) -> Result<String> {
        let names = &self.scope(scope).names;
        let below = names.range(..("$$undefz".to_string(), 0)).next_back();
        if let Some(((name, _), _)) = below {
            if name.len() == 15 && name.starts_with("$$undef") {
                let uniq = u32::from_str_radix(&name[7..], 16)
                    .map_err(|_| LowlevelError("Error creating undefined name".into()))?;
                return Ok(format!("$$undef{:08x}", uniq.wrapping_add(1)));
            }
        }
        Ok("$$undef00000000".into())
    }

    /// Port of `ScopeInternal::makeNameUnique`: `nm`, or `nm_NN` / `nm_xNNNNN` one past the
    /// highest such suffix in use.
    pub(crate) fn make_name_unique(&self, scope: ScopeId, nm: &str) -> Result<String> {
        if self.find_first_by_name(scope, nm).is_none() {
            return Ok(nm.to_string());
        }
        let names = &self.scope(scope).names;
        let bound = (format!("{nm}_x99999"), u32::MAX);
        let mut uniqid = None;
        // the names after the first `nm` up to the bound, from the last
        for ((bname, _), _) in names.range((nm.to_string(), 0)..=bound).rev() {
            if bname == nm {
                break;
            }
            uniqid = suffix_id(nm, bname);
            if uniqid.is_some() {
                break;
            }
        }
        let res = match uniqid {
            None => format!("{nm}_00"),
            Some(u) if u + 1 < 100 => format!("{nm}_{:02}", u + 1),
            Some(u) => format!("{nm}_x{:05}", u + 1),
        };
        if self.find_first_by_name(scope, &res).is_some() {
            return Err(LowlevelError(format!("Unable to uniquify name: {res}")));
        }
        Ok(res)
    }

    /// Port of `ScopeLocal::buildVariableName` (stack locals) falling back to
    /// `ScopeInternal::buildVariableName`. `index` is the running `Var` counter.
    pub(crate) fn build_variable_name(&self, scope: ScopeId, r: &NameRequest, index: &mut i32) -> Result<String> {
        if let (Some(st), Some((space, off))) = (r.stack, r.addr) {
            if r.flags.addr_tied && !r.flags.persist && space == st.space && r.in_local_range {
                return self.make_name_unique(scope, &stack_name(&st, r, off));
            }
        }
        let hex_addr = |off: u64| {
            format!("{}{}{:0w$x}", r.name_base, capitalized(r.space_name), off, w = 2 * r.addr_size as usize)
        };
        let Some((_, off)) = r.addr else { return self.make_name_unique(scope, "unassigned_") };
        let f = r.flags;
        let name = if f.unaffected {
            match (f.return_address, r.reg.is_empty()) {
                (true, _) => "unaff_retaddr".to_string(),
                (false, true) => format!("unaff_{off:08x}"),
                (false, false) => format!("unaff_{}", r.reg),
            }
        } else if f.persist {
            if r.reg.is_empty() {
                hex_addr(off)
            } else {
                r.reg.to_string()
            }
        } else if f.input && *index < 0 {
            if r.reg.is_empty() {
                format!("in_{}_{off:08x}", r.space_name)
            } else {
                format!("in_{}", r.reg)
            }
        } else if f.input {
            format!("param_{index}")
        } else if f.addr_tied {
            hex_addr(off)
        } else if f.indirect_creation {
            format!("extraout_{}", if r.reg.is_empty() { "var" } else { r.reg })
        } else {
            return self.local_var_name(scope, r.name_base, index);
        };
        self.make_name_unique(scope, &name)
    }

    /// The `Var` branch of `ScopeInternal::buildVariableName`: `<base>Var<index>`, trying ten
    /// more indices before `makeNameUnique` when the name is taken.
    fn local_var_name(&self, scope: ScopeId, base: &str, index: &mut i32) -> Result<String> {
        let first = format!("{base}Var{index}");
        *index += 1;
        if self.find_first_by_name(scope, &first).is_some() {
            for _ in 0..10 {
                let s2 = format!("{base}Var{index}");
                *index += 1;
                if self.find_first_by_name(scope, &s2).is_none() {
                    return Ok(s2);
                }
            }
        }
        self.make_name_unique(scope, &first)
    }
}

/// The stack name of `ScopeLocal::buildVariableName`: `<base>Stack_<hex>` for a parameter,
/// `<base>StackX_<hex>` for the caller's area, `Y` for an unusual region.
fn stack_name(st: &StackNaming, r: &NameRequest, off: u64) -> String {
    let bits = 8 * st.addr_size;
    let mut start = if bits >= 64 { off as i64 } else { ((off << (64 - bits)) as i64) >> (64 - bits) };
    if st.grows_negative {
        start = start.wrapping_neg();
    }
    let mut s = format!("{}{}", r.name_base, capitalized(r.space_name));
    if start <= 0 {
        s.push('X');
        start = start.wrapping_neg();
    } else if st.min_param < st.max_param && (if st.grows_negative { off < st.min_param } else { off > st.max_param }) {
        s.push('Y');
    }
    s + &format!("_{start:x}")
}

/// The id of a `makeNameUnique` suffix: `nm_DD` (two digits) or `nm_xDDDDD` (five).
fn suffix_id(nm: &str, bname: &str) -> Option<u32> {
    let rest = bname.strip_prefix(nm)?.strip_prefix('_')?;
    if bname.len() < nm.len() + 3 {
        return None;
    }
    let (digits, want) = match rest.strip_prefix('x') {
        Some(d) => (d, 5),
        None => (rest, 2),
    };
    (digits.len() == want && digits.bytes().all(|b| b.is_ascii_digit())).then(|| digits.parse().ok()).flatten()
}

impl Database {
    /// The scopes one decompilation starts with: the global scope and the function's local
    /// scope ([`GLOBAL`], [`LOCAL`]).
    pub(crate) fn for_function() -> Database {
        let mut db = Database::default();
        db.new_scope();
        db.new_scope();
        db
    }

    /// `Scope::getCategorySymbol` over a whole category, in index order.
    pub(crate) fn category(&self, scope: ScopeId, cat: u32) -> Vec<SymbolId> {
        self.scope(scope).categories.get(cat as usize).map_or(Vec::new(), |l| l.iter().flatten().copied().collect())
    }

    /// The live symbols of `scope` with an entry overlapping `[first, first + sz)` of `space`
    /// (what `findOverlap` can return), in arena order.
    pub(crate) fn overlapping(&self, scope: ScopeId, space: Space, first: u64, sz: u32) -> Vec<SymbolId> {
        let end = u128::from(first) + u128::from(sz);
        (0..self.symbols.len())
            .filter(|&i| {
                let s = &self.symbols[i];
                s.scope == scope
                    && s.entries.iter().any(|e| {
                        e.space == space
                            && u128::from(e.offset) < end
                            && u128::from(first) < u128::from(e.offset) + u128::from(e.size)
                    })
            })
            .map(|i| SymbolId(i as u32))
            .collect()
    }

    /// `ScopeInternal::removeSymbol`: out of the name tree, the map and its category list (the
    /// arena keeps the slot, so ids stay valid).
    pub(crate) fn remove_symbol(&mut self, sym: SymbolId) {
        let s = &self.symbols[sym.0 as usize];
        let (scope, key, cat, idx) = (s.scope, (s.name.clone(), s.dedup), s.category, s.cat_index as usize);
        let sc = &mut self.scopes[scope.0 as usize];
        sc.names.remove(&key);
        for (i, e) in self.symbols[sym.0 as usize].entries.iter().enumerate() {
            if let Some(map) = sc.maps.get_mut(&e.space.index()) {
                map.erase((sym, i), e.offset, e.last());
            }
        }
        if let Some(list) = cat.and_then(|c| sc.categories.get_mut(c as usize)) {
            if list.get(idx) == Some(&Some(sym)) {
                list[idx] = None;
            }
            while list.last() == Some(&None) {
                list.pop();
            }
        }
        self.symbols[sym.0 as usize].entries.clear();
    }

    /// `ScopeInternal::clearCategory` for a category of its own (not -1).
    pub(crate) fn clear_category(&mut self, scope: ScopeId, cat: u32) {
        for sym in self.category(scope, cat) {
            self.remove_symbol(sym);
        }
    }

    /// `ScopeInternal::printEntries` after the `Scope <name>` line: one line per map entry
    /// (`MapEntry::printEntry`), the spaces in index order and each space's records in list
    /// order. `addr` prints an address (its shortcut, then `Address::printRaw`), `ty` a type
    /// (its size and `Datatype::printRaw`) and `space` names a space. With `attributes`
    /// (`DECOMP_MAP_EXTRA`, rust/tools/decomp-ref.patch) an `attributes` line follows each entry.
    pub(crate) fn print_entries(&self, scope: ScopeId, p: &EntryPrinter, attributes: bool) -> Result<String> {
        let mut s = String::new();
        let records = || self.scope(scope).maps.values().flat_map(|m| m.records());
        for &(id, e) in records() {
            let sym = self.symbol(id);
            let e = &sym.entries[e];
            let (size, tname) = (p.ty)(sym.ty);
            s += &format!("{} : {}:{} {} : ", sym.name, (p.addr)(e.space, e.offset)?, size, tname);
            if e.uselimit.0.is_empty() {
                s += "all\n";
            }
            for &(sp, first, last) in &e.uselimit.0 {
                s += &format!("{}: {:x}-{:x}\n", (p.space)(sp)?, first, last);
            }
            if e.conflict {
                s += " (conflicts)"; // MapEntryConflict::printEntry, after the bounds' line end
            }
            if attributes && scope == GLOBAL {
                s += &self.attributes(id);
            }
        }
        if attributes && scope != GLOBAL {
            for &(id, _) in records() {
                s += &self.attributes(id);
            }
        }
        Ok(s)
    }

    /// The map entries of `scope` (symbol, entry index) in `MapIterator` order: by space,
    /// then by address.
    pub(crate) fn map_records(&self, scope: ScopeId) -> Vec<(SymbolId, usize)> {
        self.scope(scope).maps.values().flat_map(|m| m.records()).copied().collect()
    }

    /// The `attributes` line of the reference patch (`printSymbolAttributes`).
    fn attributes(&self, id: SymbolId) -> String {
        let sym = self.symbol(id);
        let mut s = format!("attributes {} :", sym.name);
        for (on, name) in [
            (sym.flags.addr_tied, " addrtied"),
            (sym.flags.type_locked, " typelock"),
            (sym.flags.name_locked, " namelock"),
            (sym.this_ptr, " this"),
        ] {
            if on {
                s += name;
            }
        }
        if let Some(c) = sym.category {
            s += &format!(" category {c}:{}", sym.cat_index);
        }
        s + "\n"
    }
}

/// How `print map` writes addresses, types and space names.
pub(crate) struct EntryPrinter<'a> {
    pub(crate) addr: &'a dyn Fn(Space, u64) -> Result<String>,
    pub(crate) ty: &'a dyn Fn(Option<super::types::TypeId>) -> (u32, String),
    pub(crate) space: &'a dyn Fn(Space) -> Result<String>,
}

impl Database {
    /// Port of `ScopeInternal::setCategory`: the symbol leaves its category list and joins
    /// `cat` at `index` (a category above 0 appends instead).
    pub(crate) fn set_category(&mut self, sym: SymbolId, cat: u32, index: u32) {
        let s = &self.symbols[sym.0 as usize];
        let (scope, old, old_idx) = (s.scope, s.category, s.cat_index as usize);
        let cats = &mut self.scopes[scope.0 as usize].categories;
        if let Some(list) = old.and_then(|c| cats.get_mut(c as usize)) {
            if let Some(slot) = list.get_mut(old_idx) {
                *slot = None;
            }
            while list.last() == Some(&None) {
                list.pop();
            }
        }
        if cats.len() <= cat as usize {
            cats.resize(cat as usize + 1, Vec::new());
        }
        let list = &mut cats[cat as usize];
        let index = if cat > 0 { list.len() } else { index as usize };
        if list.len() <= index {
            list.resize(index + 1, None);
        }
        list[index] = Some(sym);
        let s = &mut self.symbols[sym.0 as usize];
        s.category = Some(cat);
        s.cat_index = index as u32;
    }

    /// Port of `Scope::overrideSizeLockType`: a size-locked symbol takes a data-type of its size
    /// (`same_size`: the new type has the size of the symbol's type).
    pub(crate) fn override_size_lock_type(
        &mut self,
        sym: SymbolId,
        ty: super::types::TypeId,
        same_size: bool,
    ) -> Result<()> {
        let s = &mut self.symbols[sym.0 as usize];
        if !same_size {
            return super::err("Overriding symbol with different type size");
        }
        if !s.flags.size_type_locked {
            return super::err("Overriding symbol that is not size locked");
        }
        s.ty = Some(ty);
        Ok(())
    }

    /// The symbols `ScopeInternal::assignDefaultNames` walks: those with an undefined name,
    /// in name order.
    pub(crate) fn undefined_symbols(&self, scope: ScopeId) -> Vec<SymbolId> {
        let names = &self.scope(scope).names;
        let from = ("$$undef".to_string(), u32::MAX);
        names.range(from..).map(|(_, &s)| s).take_while(|&s| self.symbol(s).is_name_undefined()).collect()
    }

    /// `Scope::setThisPointer`.
    pub(crate) fn set_this_pointer(&mut self, sym: SymbolId) {
        self.symbols[sym.0 as usize].this_ptr = true;
    }

    /// `Scope::setAttribute` of the type lock and the name lock (`Symbol::decodeHeader` sets
    /// them from a symbol's record; `recoverNameRecommendationsForSymbols` locks a name).
    pub(crate) fn lock_symbol(&mut self, sym: SymbolId, type_locked: bool, name_locked: bool) {
        let f = &mut self.symbols[sym.0 as usize].flags;
        f.type_locked |= type_locked;
        f.name_locked |= name_locked;
    }
}

/// A space's name and address size (the stack space has its container's size).
pub(crate) fn space_info(arch: &super::Arch, sp: Space) -> Result<(String, u32)> {
    match sp {
        Space::Sleigh(i) => arch.sleigh.spaces.get(i as usize).map(|s| (s.name.clone(), s.size)),
        Space::Stack => arch.sleigh.spaces.get(arch.spec.stack_container as usize).map(|s| ("stack".into(), s.size)),
        Space::Join => Some(("join".into(), 4)), // JoinSpace: sizeof(uintm)
        _ => None,
    }
    .ok_or_else(|| LowlevelError("a symbol in a space without a name".into()))
}

/// `print map` of the function's local scope (`IfcPrintMap`, `Scope::printBounds`,
/// `ScopeInternal::printEntries`). With `DECOMP_MAP_EXTRA` set (rust/tools/decomp-ref.patch) the
/// prototype comes first (`FuncProto::printRaw`, then each parameter with its name, storage
/// and attributes and the return storage), each symbol gets an `attributes` line, and the data
/// symbols of the global scope follow.
pub(crate) fn print_map(fd: &super::Funcdata, arch: &super::Arch, name: &str) -> Result<String> {
    if fd.proto.locked.is_some() {
        return super::err("print map: the symbols of a locked prototype are not ported");
    }
    let space = |sp: Space| space_info(arch, sp);
    let space_name = |sp: Space| space(sp).map(|(n, _)| n);
    // `Address::getShortcut` and `AddrSpace::printRaw`: the offset padded to the address size
    let addr = |sp: Space, off: u64| {
        if sp == Space::Join {
            return super::print::join_raw(fd, arch, off); // JoinSpace::printRaw
        }
        let (n, size) = space(sp)?;
        Ok(format!("{}0x{off:0w$x}", super::print::shortcut(&n), w = 2 * size as usize))
    };
    let ty =
        |t: Option<super::types::TypeId>| t.map_or((0, "?".to_string()), |t| (fd.types.size(t), fd.types.print_raw(t)));
    let p = EntryPrinter { addr: &addr, ty: &ty, space: &space_name };
    let extra = std::env::var_os("DECOMP_MAP_EXTRA").is_some();
    let mut s = String::new();
    if extra {
        let model = fd.proto.model.map_or("(no model)", |m| arch.spec.models.get(m).name.as_str());
        let out = fd.proto.out_param.map_or("void".to_string(), |(_, _, t)| fd.types.print_raw(t));
        let params = fd.symtab.category(LOCAL, 0);
        let types: Vec<String> = params.iter().map(|&p| ty(fd.symtab.symbol(p).ty).1).collect();
        let pop = match fd.proto.extrapop {
            super::fspec::ExtraPop::Unknown => 0x8000,
            super::fspec::ExtraPop::Known(n) => n,
        };
        s += &format!("{model} {out} {name}({}) extrapop={pop}\n", types.join(","));
        for (i, &id) in params.iter().enumerate() {
            let sym = fd.symtab.symbol(id);
            let e =
                sym.entries.first().ok_or_else(|| LowlevelError("print map: a parameter without storage".into()))?;
            s += &format!("param {i}: {} : {}:{}", sym.name, addr(e.space, e.offset)?, ty(sym.ty).0);
            for (on, name) in
                [(sym.flags.type_locked, " typelock"), (sym.flags.name_locked, " namelock"), (sym.this_ptr, " this")]
            {
                if on {
                    s += name;
                }
            }
            s += "\n";
        }
        s += &match fd.proto.out_param {
            None => "output: none\n".to_string(),
            Some((sp, off, t)) => format!("output: {}:{}\n", addr(sp, off)?, fd.types.size(t)),
        };
    }
    s += &format!("{name}\n");
    for &(first, last) in fd.localmap.ranges() {
        s += &format!("stack: {first:x}-{last:x}\n");
    }
    s += &format!("Scope {name}\n");
    s += &fd.symtab.print_entries(LOCAL, &p, extra)?;
    if extra {
        // the data symbols of the global scope (functions and external references live in `Arch`)
        s += "Global data\n";
        s += &fd.symtab.print_entries(GLOBAL, &p, true)?;
    }
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    const RAM: Space = Space::Sleigh(1);
    const REG: Space = Space::Sleigh(2);

    fn req<'a>(addr: Option<(Space, u64)>, base: &'a str, reg: &'a str, flags: NameFlags) -> NameRequest<'a> {
        NameRequest {
            addr,
            space_name: "register",
            addr_size: 4,
            name_base: base,
            reg,
            flags,
            in_local_range: false,
            stack: None,
        }
    }

    #[test]
    fn undefined_names_count_up() {
        let mut db = Database::default();
        let sc = db.new_scope();
        assert_eq!(db.build_undefined_name(sc).unwrap(), "$$undef00000000");
        let a = db.add_symbol(sc, "", None, None, None).unwrap();
        assert!(db.symbol(a).is_name_undefined());
        db.add_symbol(sc, "", None, None, None).unwrap();
        assert_eq!(db.build_undefined_name(sc).unwrap(), "$$undef00000002");
    }

    /// `iVar1` taken: the ten retries give `iVar2`; `nm` taken with `nm_00` and `nm_01` gives
    /// `nm_02`; a same-name symbol gets dedup 1.
    #[test]
    fn var_names_and_uniqueness() {
        let mut db = Database::default();
        let sc = db.new_scope();
        let mut index = 1;
        let r = req(Some((REG, 0)), "i", "EAX", NameFlags::default());
        assert_eq!(db.build_variable_name(sc, &r, &mut index).unwrap(), "iVar1");
        assert_eq!(index, 2);
        db.add_symbol(sc, "uVar3", None, None, None).unwrap();
        let mut index = 3;
        let r = req(Some((REG, 0)), "u", "EAX", NameFlags::default());
        assert_eq!(db.build_variable_name(sc, &r, &mut index).unwrap(), "uVar4");
        for n in ["local", "local_00", "local_01"] {
            db.add_symbol(sc, n, None, None, None).unwrap();
        }
        assert_eq!(db.make_name_unique(sc, "local").unwrap(), "local_02");
        let d = db.add_symbol(sc, "local", None, None, None).unwrap();
        assert_eq!(db.symbol(d).dedup, 1);
        db.rename_symbol(d, "other");
        assert_eq!(db.find_first_by_name(sc, "other"), Some(d));
    }

    #[test]
    fn register_and_param_names() {
        let db = {
            let mut db = Database::default();
            db.new_scope();
            db
        };
        let sc = ScopeId(0);
        let mut ix = -1;
        let input = NameFlags { input: true, ..NameFlags::default() };
        assert_eq!(db.build_variable_name(sc, &req(Some((REG, 0)), "", "EAX", input), &mut ix).unwrap(), "in_EAX");
        let mut ix = 2;
        assert_eq!(db.build_variable_name(sc, &req(Some((REG, 0)), "", "EAX", input), &mut ix).unwrap(), "param_2");
        let unaff = NameFlags { unaffected: true, ..NameFlags::default() };
        assert_eq!(
            db.build_variable_name(sc, &req(Some((REG, 0x18)), "", "ESI", unaff), &mut ix).unwrap(),
            "unaff_ESI"
        );
        let extra = NameFlags { indirect_creation: true, ..NameFlags::default() };
        assert_eq!(
            db.build_variable_name(sc, &req(Some((REG, 0)), "", "EAX", extra), &mut ix).unwrap(),
            "extraout_EAX"
        );
        let tied = NameFlags { addr_tied: true, ..NameFlags::default() };
        let mut r = req(Some((RAM, 0x9eec5e)), "u", "", tied);
        r.space_name = "ram";
        assert_eq!(db.build_variable_name(sc, &r, &mut ix).unwrap(), "uRam009eec5e");
    }

    /// x86: the stack grows down, parameters at positive offsets.
    #[test]
    fn stack_names() {
        let mut db = Database::default();
        let st = StackNaming { space: Space::Stack, grows_negative: true, min_param: 4, max_param: 0x40, addr_size: 4 };
        let sc = db.new_scope();
        let tied = NameFlags { addr_tied: true, ..NameFlags::default() };
        let mut r = req(Some((Space::Stack, 0xffff_ffec)), "i", "", tied);
        r.space_name = "stack";
        r.in_local_range = true;
        r.stack = Some(st);
        let mut ix = 1;
        assert_eq!(db.build_variable_name(sc, &r, &mut ix).unwrap(), "iStack_14");
        r.addr = Some((Space::Stack, 8));
        assert_eq!(db.build_variable_name(sc, &r, &mut ix).unwrap(), "iStackX_8");
    }

    #[test]
    fn container_prefers_smallest_in_use() {
        let mut db = Database::default();
        let sc = db.new_scope();
        let entry =
            |offset, size, uselimit| SymbolEntry { space: REG, offset, size, uselimit, conflict: false, piece: None };
        let whole = db.add_symbol(sc, "a", None, None, Some(entry(0, 4, UseLimit(vec![(RAM, 0x10, 0x40)])))).unwrap();
        let low = db.add_symbol(sc, "b", None, None, Some(entry(0, 2, UseLimit(vec![(RAM, 0x10, 0x20)])))).unwrap();
        assert_eq!(db.find_container(sc, REG, 0, 2, Some((RAM, 0x18))).unwrap(), Some((low, 0)));
        assert_eq!(db.find_container(sc, REG, 0, 2, Some((RAM, 0x30))).unwrap(), Some((whole, 0)));
        assert_eq!(db.find_container(sc, REG, 0, 4, None).unwrap(), None);
    }

    /// `assignDefaultNames` walks the unnamed symbols in name order; a conflict entry prints
    /// its mark after the line end of its bounds, as the C++ does.
    #[test]
    fn undefined_symbols_and_conflict_entries() {
        let mut db = Database::default();
        let sc = db.new_scope();
        let e = |offset, conflict| SymbolEntry {
            space: REG,
            offset,
            size: 4,
            uselimit: UseLimit(vec![(RAM, 0x10, 0x10)]),
            conflict,
            piece: None,
        };
        let a = db.add_symbol(sc, "", None, None, Some(e(0, true))).unwrap();
        let b = db.add_symbol(sc, "", None, None, Some(e(4, false))).unwrap();
        db.add_symbol(sc, "named", None, None, None).unwrap();
        assert_eq!(db.undefined_symbols(sc), vec![a, b]);
        db.rename_symbol(a, "iVar1");
        assert_eq!(db.undefined_symbols(sc), vec![b]);
        let p = EntryPrinter {
            addr: &|_, o| Ok(format!("%0x{o:08x}")),
            ty: &|_| (4, "int4".into()),
            space: &|_| Ok("ram".into()),
        };
        assert_eq!(
            db.print_entries(sc, &p, false).unwrap(),
            "iVar1 : %0x00000000:4 int4 : ram: 10-10\n (conflicts)$$undef00000001 : %0x00000004:4 int4 : ram: 10-10\n"
        );
    }
}
