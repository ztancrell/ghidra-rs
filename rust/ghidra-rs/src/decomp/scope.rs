//! The symbol-table core of database.cc (`Symbol`, `SymbolEntry`, `ScopeInternal`) and the
//! default-name scheme of `ScopeInternal::buildVariableName` / `ScopeLocal::buildVariableName`
//! (varmap.cc), `buildUndefinedName` and `makeNameUnique`. Wired as `Funcdata::symtab`: `ActionInputPrototype`
//! keeps the parameters here (`ProtoStoreSymbol`), `ActionMapGlobals` the global data symbols;
//! `print map` prints the local scope. `ActionNameVars` is not ported, so the local default
//! names are only unit tested.
//!
//! Scopes and symbols live in one arena ([`Database`]) addressed by [`ScopeId`] and
//! [`SymbolId`]. A scope's name tree is the C++ `SymbolNameTree` (by name, then `nameDedup`).
//! Its map is a list of entries per space; [`Database::find_container`] walks the entries
//! containing the point in the order of the C++ `rangemap` (first offset, then the use-point
//! subsort, then insertion) from the last, with `findContainer`'s conditions. The stack
//! branch (`m3-stack`, `LocalMap` in `varmap.rs`) is meant to hold its local scope here.

use std::collections::BTreeMap;

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
    /// the first use point (the rangemap subsort); `None` for an entry valid everywhere
    pub(crate) first_use: Option<u64>,
    pub(crate) uselimit: UseLimit,
}

impl SymbolEntry {
    /// `getLast`
    fn last(&self) -> u64 {
        self.offset.wrapping_add(u64::from(self.size)).wrapping_sub(1)
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

/// Port of `ScopeInternal` (with `ScopeLocal`'s stack naming data).
#[derive(Debug, Clone, Default)]
pub(crate) struct Scope {
    pub(crate) name: String,
    pub(crate) parent: Option<ScopeId>,
    /// `nametree`
    names: BTreeMap<(String, u32), SymbolId>,
    /// `maptable`: (symbol, entry index) per space, in insertion order
    map: Vec<(Space, SymbolId, usize)>,
    /// `category`
    categories: Vec<Vec<Option<SymbolId>>>,
    /// `ScopeLocal`: the stack space, whether it grows down, the parameter range
    /// (`minParamOffset`, `maxParamOffset`) and the local range test of the prototype
    pub(crate) stack: Option<StackNaming>,
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
    pub(crate) fn new_scope(&mut self, name: &str, parent: Option<ScopeId>, stack: Option<StackNaming>) -> ScopeId {
        let id = ScopeId(self.scopes.len() as u32);
        self.scopes.push(Scope { name: name.into(), parent, stack, ..Scope::default() });
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
            let space = e.space;
            self.symbols[id.0 as usize].entries.push(e);
            self.scopes[scope.0 as usize].map.push((space, id, 0));
        }
        Ok(id)
    }

    /// `ScopeInternal::renameSymbol`.
    pub(crate) fn rename_symbol(&mut self, sym: SymbolId, name: &str) {
        let s = &self.symbols[sym.0 as usize];
        let key = (s.name.clone(), s.dedup);
        self.scopes[s.scope.0 as usize].names.remove(&key);
        self.symbols[sym.0 as usize].name = name.to_string();
        self.insert_name(sym);
    }

    /// The entries of `scope` in `space` containing `off`, in rangemap order (first offset,
    /// first use, insertion).
    fn entries_at(&self, scope: ScopeId, space: Space, off: u64) -> Vec<(SymbolId, usize)> {
        let mut v: Vec<(usize, SymbolId, usize)> = self
            .scope(scope)
            .map
            .iter()
            .enumerate()
            .filter(|&(_, &(s, sym, e))| {
                let en = &self.symbol(sym).entries[e];
                s == space && en.offset <= off && off <= en.last()
            })
            .map(|(i, &(_, sym, e))| (i, sym, e))
            .collect();
        v.sort_by_key(|&(i, sym, e)| {
            let en = &self.symbol(sym).entries[e];
            (en.offset, en.first_use.is_some(), en.first_use, i)
        });
        v.into_iter().map(|(_, sym, e)| (sym, e)).collect()
    }

    /// `SymbolEntry::inUse`.
    fn in_use(&self, sym: SymbolId, e: &SymbolEntry, usepoint: Option<(Space, u64)>) -> bool {
        if self.symbol(sym).flags.addr_tied {
            return true;
        }
        usepoint.is_some_and(|(s, o)| e.uselimit.contains(s, o))
    }

    /// Port of `ScopeInternal::findContainer`: the smallest entry in use at `usepoint` holding
    /// the whole range, preferring the last in map order; an exact size stops the search.
    pub(crate) fn find_container(
        &self,
        scope: ScopeId,
        space: Space,
        off: u64,
        size: u32,
        usepoint: Option<(Space, u64)>,
    ) -> Option<(SymbolId, usize)> {
        let end = off.wrapping_add(u64::from(size)).wrapping_sub(1);
        let mut best = None;
        let mut oldsize: Option<u32> = None;
        for (sym, ei) in self.entries_at(scope, space, off).into_iter().rev() {
            let e = &self.symbol(sym).entries[ei];
            if usepoint.is_some_and(|(_, u)| e.first_use.is_some_and(|f| f > u)) {
                continue; // after the use point in the subsort
            }
            if e.last() >= end && oldsize.is_none_or(|o| e.size < o) && self.in_use(sym, e, usepoint) {
                best = Some((sym, ei));
                if e.size == size {
                    break;
                }
                oldsize = Some(e.size);
            }
        }
        best
    }

    /// Port of `ScopeInternal::findOverlap`: some entry intersecting the range.
    pub(crate) fn find_overlap(&self, scope: ScopeId, space: Space, off: u64, size: u32) -> Option<(SymbolId, usize)> {
        let last = off.wrapping_add(u64::from(size)).wrapping_sub(1);
        self.scope(scope).map.iter().find_map(|&(s, sym, e)| {
            let en = &self.symbol(sym).entries[e];
            (s == space && en.offset <= last && off <= en.last()).then_some((sym, e))
        })
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
        if let (Some(st), Some((space, off))) = (self.scope(scope).stack, r.addr) {
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
        db.new_scope("", None, None);
        db.new_scope("", Some(GLOBAL), None);
        db
    }

    /// `Scope::getCategorySymbol` over a whole category, in index order.
    pub(crate) fn category(&self, scope: ScopeId, cat: u32) -> Vec<SymbolId> {
        self.scope(scope).categories.get(cat as usize).map_or(Vec::new(), |l| l.iter().flatten().copied().collect())
    }

    /// `ScopeInternal::removeSymbol`: out of the name tree, the map and its category list (the
    /// arena keeps the slot, so ids stay valid).
    pub(crate) fn remove_symbol(&mut self, sym: SymbolId) {
        let s = &self.symbols[sym.0 as usize];
        let (scope, key, cat, idx) = (s.scope, (s.name.clone(), s.dedup), s.category, s.cat_index as usize);
        let sc = &mut self.scopes[scope.0 as usize];
        sc.names.remove(&key);
        sc.map.retain(|&(_, id, _)| id != sym);
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

    /// `ScopeInternal::printEntries` after the `Scope <name>` line: one line per map entry, the
    /// spaces in index order and each space's entries in rangemap order (first offset, first
    /// use, insertion). `addr` prints an address (`Address::printRaw` after its shortcut),
    /// `ty` a type (`Datatype::printRaw`, its size first) and `space` names a space.
    pub(crate) fn print_entries(
        &self,
        scope: ScopeId,
        addr: &dyn Fn(Space, u64) -> String,
        ty: &dyn Fn(Option<super::types::TypeId>) -> (u32, String),
        space: &dyn Fn(Space) -> String,
    ) -> String {
        let mut rows: Vec<(usize, &SymbolEntry, &Symbol)> = self
            .scope(scope)
            .map
            .iter()
            .enumerate()
            .map(|(i, &(_, sym, e))| (i, &self.symbol(sym).entries[e], self.symbol(sym)))
            .collect();
        rows.sort_by_key(|&(i, e, _)| (e.space.index(), e.offset, e.first_use.is_some(), e.first_use, i));
        let mut s = String::new();
        for (_, e, sym) in rows {
            let (size, tname) = ty(sym.ty);
            s += &format!("{} : {}:{} {} : ", sym.name, addr(e.space, e.offset), size, tname);
            if e.uselimit.0.is_empty() {
                s += "all\n";
            }
            for &(sp, first, last) in &e.uselimit.0 {
                s += &format!("{}: {:x}-{:x}\n", space(sp), first, last);
            }
        }
        s
    }
}

impl Database {
    /// A symbol valid everywhere (`Varnode::addrtied`, what an entry without a use limit gets).
    pub(crate) fn set_addr_tied(&mut self, sym: SymbolId) {
        self.symbols[sym.0 as usize].flags.addr_tied = true;
    }

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

    /// `Scope::setThisPointer`.
    pub(crate) fn set_this_pointer(&mut self, sym: SymbolId) {
        self.symbols[sym.0 as usize].this_ptr = true;
    }
}

/// The stack ranges the local scope owns (`ScopeLocal::resetLocalWindow`): the parameter range
/// of the function's model (the stack entries of the model it starts with) and the default
/// local range (`ProtoModel::defaultLocalRange`, a stack growing down), in order.
/// ponytail: touching ranges are not merged as `RangeList::insertRange` would; x86's do not touch.
pub(crate) fn local_ranges(arch: &super::Arch) -> Vec<(u64, u64)> {
    let models = &arch.spec.models;
    let model = models.get(models.eval_current.unwrap_or(models.default));
    let bits = 8 * arch.spec.stack_pointer.2.min(8);
    let highest = if bits >= 64 { u64::MAX } else { (1u64 << bits) - 1 };
    let mut ranges = model.input.stack_ranges();
    ranges.push((highest - (highest >> 1).min(0x7fff_ffff), highest));
    ranges.sort_unstable();
    ranges
}

/// `print map` of the function's local scope (`IfcPrintMap`, `Scope::printBounds`,
/// `ScopeInternal::printEntries`). With `DECOMP_MAP_EXTRA` set (rust/tools/decomp-ref.patch) the
/// prototype comes first, as `FuncProto::printRaw` writes it.
pub(crate) fn print_map(fd: &super::Funcdata, arch: &super::Arch, name: &str) -> Result<String> {
    if fd.proto.locked.is_some() {
        return super::err("print map: the symbols of a locked prototype are not ported");
    }
    let space_name = |sp: Space| match sp {
        Space::Sleigh(i) => arch.sleigh.spaces.get(i as usize).map_or("?", |s| s.name.as_str()).to_string(),
        Space::Stack => "stack".to_string(),
        _ => "?".to_string(),
    };
    let addr = |sp: Space, off: u64| {
        let shortcut = match space_name(sp).as_str() {
            "register" => '%',
            "unique" => 'u',
            n => n.chars().next().unwrap_or('x').to_ascii_lowercase(),
        };
        format!("{shortcut}0x{off:08x}")
    };
    let ty =
        |t: Option<super::types::TypeId>| t.map_or((0, "?".to_string()), |t| (fd.types.size(t), fd.types.print_raw(t)));
    let mut s = String::new();
    if std::env::var_os("DECOMP_MAP_EXTRA").is_some() {
        let model = fd.proto.model.map_or("(no model)", |m| arch.spec.models.get(m).name.as_str());
        let out = fd.proto.out_param.map_or("void".to_string(), |(_, _, t)| fd.types.print_raw(t));
        let params: Vec<String> = fd.symtab.category(LOCAL, 0).iter().map(|&p| ty(fd.symtab.symbol(p).ty).1).collect();
        let pop = match fd.proto.extrapop {
            super::fspec::ExtraPop::Unknown => 0x8000,
            super::fspec::ExtraPop::Known(n) => n,
        };
        s += &format!("{model} {out} {name}({}) extrapop={pop}\n", params.join(","));
    }
    s += &format!("{name}\n");
    for (first, last) in local_ranges(arch) {
        s += &format!("stack: {first:x}-{last:x}\n");
    }
    s += &format!("Scope {name}\n");
    s += &fd.symtab.print_entries(LOCAL, &addr, &ty, &space_name);
    if std::env::var_os("DECOMP_MAP_EXTRA").is_some() {
        // the data symbols of the global scope (functions and external references live in `Arch`)
        s += "Global data\n";
        s += &fd.symtab.print_entries(GLOBAL, &addr, &ty, &space_name);
    }
    Ok(s)
}
#[cfg(test)]
mod tests {
    use super::*;

    const RAM: Space = Space::Sleigh(1);
    const REG: Space = Space::Sleigh(2);

    fn req<'a>(addr: Option<(Space, u64)>, base: &'a str, reg: &'a str, flags: NameFlags) -> NameRequest<'a> {
        NameRequest { addr, space_name: "register", addr_size: 4, name_base: base, reg, flags, in_local_range: false }
    }

    #[test]
    fn undefined_names_count_up() {
        let mut db = Database::default();
        let sc = db.new_scope("f", None, None);
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
        let sc = db.new_scope("f", None, None);
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
            db.new_scope("f", None, None);
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
        let sc = db.new_scope("f", None, Some(st));
        let tied = NameFlags { addr_tied: true, ..NameFlags::default() };
        let mut r = req(Some((Space::Stack, 0xffff_ffec)), "i", "", tied);
        r.space_name = "stack";
        r.in_local_range = true;
        let mut ix = 1;
        assert_eq!(db.build_variable_name(sc, &r, &mut ix).unwrap(), "iStack_14");
        r.addr = Some((Space::Stack, 8));
        assert_eq!(db.build_variable_name(sc, &r, &mut ix).unwrap(), "iStackX_8");
    }

    #[test]
    fn container_prefers_smallest_in_use() {
        let mut db = Database::default();
        let sc = db.new_scope("f", None, None);
        let entry = |offset, size, first_use, uselimit| SymbolEntry { space: REG, offset, size, first_use, uselimit };
        let whole = db
            .add_symbol(sc, "a", None, None, Some(entry(0, 4, Some(0x10), UseLimit(vec![(RAM, 0x10, 0x40)]))))
            .unwrap();
        let low = db
            .add_symbol(sc, "b", None, None, Some(entry(0, 2, Some(0x10), UseLimit(vec![(RAM, 0x10, 0x20)]))))
            .unwrap();
        assert_eq!(db.find_container(sc, REG, 0, 2, Some((RAM, 0x18))), Some((low, 0)));
        assert_eq!(db.find_container(sc, REG, 0, 2, Some((RAM, 0x30))), Some((whole, 0)));
        assert_eq!(db.find_container(sc, REG, 0, 4, None), None);
        assert_eq!(db.find_overlap(sc, REG, 3, 2), Some((whole, 0)));
    }
}
