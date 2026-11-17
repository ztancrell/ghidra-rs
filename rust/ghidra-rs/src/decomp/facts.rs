//! Stage S10: the facts of a Ghidra program (`load facts <file>`), which stand in for the
//! Java side of Ghidra's decompiler. The file is written by `tools/ghidra/ExportFacts.java`:
//! each record is an answer `DecompileCallback` gives the C++ decompiler, as the XML it sends
//! (`getMappedSymbols`, `getExternalRef`, `getDataType`, `getComments`, `getTrackedRegisters`,
//! `getCodeLabel`), recorded once for the whole program. This module ports the readers of that
//! XML (`ScopeGhidra`, `Scope::addMapSym`, `Symbol::decode`, `Funcdata::decode`,
//! `FuncProto::decode`, `TypeFactory::decodeType`) as far as the rest of the port can honour
//! them; a record it cannot honour is an error when a decompile reads it, never at load.
//!
//! The file is indexed by address at load; a record's XML is parsed when it is asked for.

use super::fspec::{ExtraPop, FuncProto, ModelId, Storage};
use super::funcdata::Funcdata;
use super::infertypes::update_type;
use super::locked::{Locked, Param};
use super::scope::{SymbolEntry, UseLimit, GLOBAL};
use super::types::{CoreType, Meta, TypeFactory, TypeId};
use super::varnode::{Space, VnFlags};
use super::{err, Arch, LowlevelError, Result};
use crate::xml::{self, Element};
use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::ops::Range;

/// `DecompileCallback.MAX_FUNCTION_OFFCUT`: how far past a function's entry a query still
/// gives the function's symbol.
const MAX_FUNCTION_OFFCUT: u64 = 8;

/// What a `data` record holds, read off its first element without parsing it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DataKind {
    /// `<symbol>`: a data symbol with a data-type
    Symbol,
    /// `<labelsym>`: a label without data
    Label,
    /// `<externrefsymbol>`: a pointer to an external location
    ExternRef,
}

/// One `data` record: its text and the attributes the properties need.
#[derive(Debug, Clone)]
struct DataRec {
    xml: Range<usize>,
    len: u64,
    kind: DataKind,
    readonly: bool,
    volatile: bool,
}

/// A data symbol of the global scope (`Symbol` with one `MapEntry`).
#[derive(Debug, Clone)]
pub(crate) struct DataSym {
    pub(crate) addr: u64,
    pub(crate) size: u32,
    pub(crate) name: String,
    pub(crate) ty: TypeId,
    /// `typelock`, or `merge="false"` (`Symbol::isIsolated`, which locks the type too; Java
    /// sends both for every data symbol)
    pub(crate) type_locked: bool,
}

/// A symbol of a function's local scope that is name-locked and not type-locked: what
/// `ScopeLocal::collectNameRecs` turns into a name recommendation (`NameRecommend`).
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct NameRec {
    pub(crate) storage: Storage,
    pub(crate) name: String,
}

/// A function as its `func` (or `extref`) record gives it.
#[derive(Debug, Clone)]
pub(crate) struct FuncFact {
    pub(crate) proto: FuncProto,
    /// the name recommendations of the function's own decompile
    pub(crate) name_recs: Vec<NameRec>,
}

/// A comment of the listing (`Comment`): its type (`header`, `user2`, ...), address and text.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ListingComment {
    pub(crate) kind: String,
    pub(crate) addr: u64,
    pub(crate) text: String,
}

/// The indexed facts file.
pub(crate) struct Facts {
    text: String,
    /// memory blocks: first, last, writable
    blocks: Vec<(u64, u64, bool)>,
    /// addresses of non-writable blocks with a write reference
    wrefs: HashSet<u64>,
    /// function body ranges: first -> (last, entry)
    bodies: BTreeMap<u64, (u64, u64)>,
    funcs: HashMap<u64, Range<usize>>,
    extrefs: HashMap<u64, Range<usize>>,
    data: BTreeMap<u64, DataRec>,
    labels: HashMap<u64, Range<usize>>,
    comments: HashMap<u64, Range<usize>>,
    /// tracked registers from an entry on (the export writes them when they change)
    tracked: BTreeMap<u64, Range<usize>>,
    /// instructions with an override: address -> kinds
    overrides: HashMap<u64, Vec<Range<usize>>>,
    /// the data-types of the `type` records and the core types, by Ghidra's id; an error is
    /// kept for the decompile that reads the type
    types: TypeIds,
    /// `TypeCode` with a prototype: the port's `code` types carry none, so a call through a
    /// pointer to one fails
    code_protos: HashSet<TypeId>,
    /// `Architecture::createUnknownModel("unknown")`
    unknown_model: ModelId,
    /// namespaces by id (`getNamespacePath`): the names from the outermost in, each with `::`
    ns: HashMap<u64, String>,
}

fn hex(s: &str) -> Result<u64> {
    u64::from_str_radix(s.trim_start_matches("0x"), 16).map_err(|e| LowlevelError(format!("facts: {s}: {e}")))
}

fn facts_err(msg: String) -> LowlevelError {
    LowlevelError(format!("facts: {msg}"))
}

fn parse(text: &str) -> Result<Element> {
    xml::parse(text).map_err(facts_err)
}

fn meta_of(name: &str) -> Option<Meta> {
    Some(match name {
        "void" => Meta::Void,
        "unknown" => Meta::Unknown,
        "int" => Meta::Int,
        "uint" => Meta::Uint,
        "bool" => Meta::Bool,
        "code" => Meta::Code,
        "float" => Meta::Float,
        _ => return None,
    })
}

/// Decoder of the type elements, over the `type` records still to read.
struct TypeDecoder<'a> {
    records: HashMap<u64, &'a str>,
    /// the data-types read so far, by id (borrowed from the loaded facts after the load)
    done: Cow<'a, TypeIds>,
    code_protos: HashSet<TypeId>,
}

/// Data-types by Ghidra's id; an error is kept for the decompile that reads the type.
type TypeIds = HashMap<u64, std::result::Result<TypeId, String>>;

impl TypeDecoder<'_> {
    /// Port of `TypeFactory::decodeType`: a `<typeref>`, `<void>`, `<def>` or `<type>`.
    fn decode(&mut self, types: &mut TypeFactory, el: &Element) -> std::result::Result<TypeId, String> {
        if let Some(id) = el.attr("id") {
            let id = u64::from_str_radix(id.trim_start_matches("0x"), 16).map_err(|e| e.to_string())?;
            if let Some(t) = self.done.get(&id) {
                return t.clone();
            }
            let t = if el.name == "typeref" {
                if el.attr("size").is_some() {
                    return Err("a variable-length data-type is not ported".into());
                }
                let rec = self.records.get(&id).copied().ok_or_else(|| format!("no data-type with id {id:#x}"))?;
                xml::parse(rec).and_then(|r| self.decode_new(types, &r, Some(id)))
            } else {
                self.decode_new(types, el, Some(id))
            };
            self.done.to_mut().entry(id).or_insert(t.clone());
            return t;
        }
        self.decode_new(types, el, None)
    }

    /// Port of `TypeFactory::decodeTypeNoRef`. `id` is the id the result is kept under; an
    /// aggregate is registered before its fields are read, so they can point back at it.
    fn decode_new(
        &mut self,
        types: &mut TypeFactory,
        el: &Element,
        id: Option<u64>,
    ) -> std::result::Result<TypeId, String> {
        let name = el.attr("name").unwrap_or("");
        let size = || el.int("size").map(|v| v as u32);
        let one = |d: &mut Self, types: &mut TypeFactory| match el.kids.as_slice() {
            [k] => d.decode(types, k),
            _ => Err(format!("<{}> {name}: expected one data-type", el.name)),
        };
        match (el.name.as_str(), el.attr("metatype")) {
            ("void", _) => Ok(types.base(1, Meta::Void)),
            ("def", _) => {
                if el.attr("format").is_some() {
                    return Err(format!("typedef {name}: a display format is not ported"));
                }
                let of = one(self, types)?;
                Ok(types.typedef(of, name))
            }
            ("type", Some("ptr")) => {
                if el.attr("space").is_some() {
                    return Err("a pointer with an address space is not ported".into());
                }
                let wordsize = el.attr("wordsize").map_or(Ok(1), |_| el.int("wordsize").map(|v| v as u32))?;
                let to = one(self, types)?;
                let p = types.pointer(size()?, to, wordsize);
                Ok(if name.is_empty() { p } else { types.typedef(p, name) })
            }
            ("type", Some("array")) => {
                let elem = one(self, types)?;
                let t = types.array_of(elem, el.int("arraysize")? as u32)?;
                if types.size(t) != size()? {
                    return Err("an array whose size is not its elements' is not ported".into());
                }
                Ok(t)
            }
            ("type", Some(m @ ("struct" | "union"))) => {
                let t = types.declare_aggregate(name, m == "union", size()?);
                if let Some(id) = id {
                    self.done.to_mut().insert(id, Ok(t));
                }
                let mut fields = Vec::new();
                for f in &el.kids {
                    if f.name != "field" || f.attr_names().any(|a| !matches!(a, "name" | "offset" | "id")) {
                        return Err(format!("{m} {name}: a <{}> of this form is not ported", f.name));
                    }
                    let [k] = f.kids.as_slice() else { return Err(format!("{m} {name}: bad field")) };
                    fields.push((f.req("name")?.to_string(), f.int("offset")? as u32, self.decode(types, k)?));
                }
                types.set_fields(t, fields);
                Ok(t)
            }
            ("type", Some("enum_uint")) => {
                let vals = el.kids.iter().map(|v| Ok((v.req("name")?.to_string(), v.int("value")? as u64)));
                let vals = vals.collect::<std::result::Result<Vec<_>, String>>()?;
                Ok(types.enumeration_sized(name, size()?, vals))
            }
            ("type", Some("code")) => {
                let t = types.named_base(name, 1, Meta::Code);
                if el.kid("prototype").is_some() {
                    self.code_protos.insert(t);
                }
                Ok(t)
            }
            ("type", Some(m)) => {
                let meta = meta_of(m).ok_or_else(|| format!("a data-type of metatype {m} is not ported"))?;
                if el.flag("char") || el.flag("utf") {
                    return Err(format!("the character data-type {name} outside the core types is not ported"));
                }
                Ok(types.named_base(name, size()?, meta))
            }
            _ => Err(format!("<{}>: not a data-type", el.name)),
        }
    }
}

/// The storage of an `<addr>` (Java writes offsets unsigned): none for an empty one.
fn storage(arch: &Arch, el: &Element) -> std::result::Result<Option<Storage>, String> {
    let Some(space) = el.attr("space") else { return Ok(None) };
    if space == "join" {
        return Err("a join storage is not ported".into());
    }
    let (offset, size) = (el.int("offset")? as u64, el.attr("size").map_or(Ok(0), |_| el.int("size"))? as u32);
    Ok(Some(match space {
        "stack" => Storage::Stack { offset, size },
        name => {
            let space = arch.sleigh.spaces.iter().position(|s| s.name == name);
            Storage::Space { space: space.ok_or_else(|| format!("Unknown space name: {name}"))? as u32, offset, size }
        }
    }))
}

impl Facts {
    /// The `<mapsym>` of a record (`<doc id><mapsym>...`) and what `PrintC::pushSymbolScope`
    /// prints before the symbol's name in a function of the global namespace: the names of
    /// its namespaces (`Symbol::getResolutionDepth`: every scope down from the first the
    /// function is not in), empty for a global symbol.
    // ponytail: a local variable named like the outermost namespace would add one more scope
    // (`isNameUsed`); not looked for
    fn mapsym<'a>(&self, doc: &'a Element) -> Result<(&'a Element, &str)> {
        if doc.name != "doc" {
            return err(format!("facts: <{}> where a symbol was expected", doc.name));
        }
        let id = doc.int("id").map_err(facts_err)? as u64;
        let prefix = match id {
            0 => "",
            _ => self.ns.get(&id).ok_or_else(|| facts_err(format!("no namespace with id {id:#x}")))?,
        };
        Ok((doc.kid("mapsym").ok_or_else(|| facts_err("<doc> without <mapsym>".into()))?, prefix))
    }

    /// Index the records of `text` and decode its core types into `arch` (in place of the
    /// console's) and its `type` records after them.
    pub(crate) fn load(arch: &mut Arch, text: String) -> Result<Facts> {
        let mut lines = text.lines();
        if lines.next() != Some("ghidra-rs-facts 1") {
            return err("facts: not a facts file of version 1");
        }
        let at = |s: &str| {
            let start = s.as_ptr() as usize - text.as_ptr() as usize;
            start..start + s.len()
        };
        let models = &mut arch.spec.models;
        let mut unknown = models.get(models.default).clone();
        unknown.name = "unknown".into();
        models.list.push(unknown);
        let mut f = Facts {
            text: String::new(),
            blocks: Vec::new(),
            wrefs: HashSet::new(),
            bodies: BTreeMap::new(),
            funcs: HashMap::new(),
            extrefs: HashMap::new(),
            data: BTreeMap::new(),
            labels: HashMap::new(),
            comments: HashMap::new(),
            tracked: BTreeMap::new(),
            overrides: HashMap::new(),
            types: HashMap::new(),
            code_protos: HashSet::new(),
            unknown_model: ModelId(models.list.len() as u32 - 1),
            ns: HashMap::new(),
        };
        // functions in a namespace: entry and namespace id, named once the `ns` records are read
        let mut scoped = Vec::new();
        let scope_id = |x: &str| attr_of(x, "<doc", "id").map_or(Ok(0), |id| hex(&id));
        let mut dec =
            TypeDecoder { records: HashMap::new(), done: Cow::Owned(HashMap::new()), code_protos: HashSet::new() };
        let bad = |line: &str| facts_err(format!("bad record: {}", line.chars().take(60).collect::<String>()));
        for line in lines {
            let mut it = line.splitn(4, '\t');
            let (kind, a, b, c) = (it.next().unwrap_or(""), it.next(), it.next(), it.next());
            match (kind, a, b, c) {
                ("coretypes", Some(x), None, None) => {
                    let root = parse(x)?;
                    let mut core = Vec::new();
                    for t in &root.kids {
                        let meta = t.req("metatype").map_err(facts_err)?;
                        core.push(CoreType {
                            name: t.req("name").map_err(facts_err)?,
                            size: t.int("size").map_err(facts_err)? as u32,
                            meta: meta_of(meta).ok_or_else(|| facts_err(format!("core metatype {meta}")))?,
                            ascii: t.flag("char"),
                            utf: t.flag("utf"),
                            id: hex(t.req("id").map_err(facts_err)?)?,
                        });
                    }
                    dec.done =
                        Cow::Owned(arch.types.set_core(&mut core).into_iter().map(|(id, t)| (id, Ok(t))).collect());
                }
                ("block", Some(first), Some(last), Some(flags)) => {
                    if flags.contains('v') {
                        return err("facts: a volatile memory block is not ported");
                    }
                    f.blocks.push((hex(first)?, hex(last)?, flags.contains('w')));
                }
                ("wref", Some(a), None, None) => {
                    f.wrefs.insert(hex(a)?);
                }
                ("func", Some(a), Some(x), None) => {
                    let entry = hex(a)?;
                    f.funcs.insert(entry, at(x));
                    arch.add_function(entry, function_name(x).ok_or_else(|| bad(line))?);
                    scoped.push((entry, scope_id(x)?));
                }
                ("body", Some(a), ..) => {
                    let entry = hex(a)?;
                    for r in line.split('\t').skip(2) {
                        let (first, last) = r.split_once('-').ok_or_else(|| bad(line))?;
                        f.bodies.insert(hex(first)?, (hex(last)?, entry));
                    }
                }
                ("tracked", Some(a), Some(x), None) => {
                    f.tracked.insert(hex(a)?, at(x));
                }
                ("comments", Some(a), Some(x), None) => {
                    f.comments.insert(hex(a)?, at(x));
                }
                ("data", Some(a), Some(len), Some(x)) => {
                    let head = x.get(..x.find("</").unwrap_or(x.len()).min(400)).unwrap_or(x);
                    let kind = if head.contains("<mapsym><externrefsymbol") {
                        DataKind::ExternRef
                    } else if head.contains("<mapsym><labelsym") {
                        DataKind::Label
                    } else {
                        DataKind::Symbol
                    };
                    let tag = head.split("<mapsym>").nth(1).and_then(|t| t.split('>').next()).unwrap_or("");
                    f.data.insert(
                        hex(a)?,
                        DataRec {
                            xml: at(x),
                            len: len.parse().map_err(|_| bad(line))?,
                            kind,
                            readonly: tag.contains(" readonly=\"true\""),
                            volatile: tag.contains(" volatile=\"true\""),
                        },
                    );
                }
                ("extref", Some(a), Some(x), None) => {
                    // the function an external reference resolves to is hung on the pointer's
                    // address (`DecompileCallback.encodeExternalRef`), as the prelude's
                    // `map function <slot> <name> nocode` and `map externalref <slot> <slot>`
                    let slot = hex(a)?;
                    f.extrefs.insert(slot, at(x));
                    arch.add_function(slot, function_name(x).ok_or_else(|| bad(line))?);
                    arch.add_externref(slot, slot);
                    scoped.push((slot, scope_id(x)?));
                }
                ("label", Some(a), Some(name), None) => {
                    f.labels.insert(hex(a)?, at(name));
                }
                ("override", Some(a), Some(kind), None) => {
                    f.overrides.entry(hex(a)?).or_default().push(at(kind));
                }
                ("type", Some(id), Some(x), None) => {
                    dec.records.insert(hex(id)?, x);
                }
                ("ns", Some(id), Some(x), None) => {
                    let path = parse(x)?;
                    let names = path.kids.iter().filter(|v| !v.text.is_empty()).map(|v| format!("{}::", v.text));
                    f.ns.insert(hex(id)?, names.collect());
                }
                _ => return Err(bad(line)),
            }
        }
        for (entry, id) in scoped.into_iter().filter(|s| s.1 != 0) {
            let prefix = f.ns.get(&id).ok_or_else(|| facts_err(format!("no namespace with id {id:#x}")))?;
            if let Some(func) = arch.functions.get_mut(&entry) {
                func.name.insert_str(0, prefix);
            }
        }
        let ids: Vec<u64> = dec.records.keys().copied().collect();
        for id in ids {
            if !dec.done.contains_key(&id) {
                let t = xml::parse(dec.records[&id]).and_then(|r| dec.decode_new(&mut arch.types, &r, Some(id)));
                dec.done.to_mut().entry(id).or_insert(t);
            }
        }
        let TypeDecoder { done, code_protos, .. } = dec;
        f.types = done.into_owned();
        f.code_protos = code_protos;
        // an external reference's symbol is named by its record (`<name>_exref`)
        let named: Vec<(u64, String)> = f
            .data
            .iter()
            .filter(|(_, r)| r.kind == DataKind::ExternRef)
            .filter_map(|(&a, r)| Some((a, attr_of(&text[r.xml.clone()], "<externrefsymbol", "name")?)))
            .collect();
        for (slot, name) in named {
            arch.name_externref(slot, name);
        }
        f.text = text;
        Ok(f)
    }

    fn xml(&self, r: &Range<usize>) -> &str {
        &self.text[r.clone()]
    }

    fn decoder(&self) -> TypeDecoder<'_> {
        TypeDecoder { records: HashMap::new(), done: Cow::Borrowed(&self.types), code_protos: HashSet::new() }
    }

    /// The `data` record holding `addr`.
    fn data_at(&self, addr: u64) -> Option<(u64, &DataRec)> {
        let (&first, rec) = self.data.range(..=addr).next_back()?;
        (addr - first < rec.len).then_some((first, rec))
    }

    /// The function whose body holds `addr`: its entry and the last address of that range.
    fn body_at(&self, addr: u64) -> Option<(u64, u64, u64)> {
        let (&first, &(last, entry)) = self.bodies.range(..=addr).next_back()?;
        (addr <= last).then_some((first, last, entry))
    }

    /// Whether Java answers a query at `addr` with the function containing it
    /// (`DecompileCallback.lookupSymbol`: an external reference at the address comes first).
    fn in_function(&self, addr: u64) -> bool {
        self.body_at(addr).is_some() && !self.data.get(&addr).is_some_and(|r| r.kind == DataKind::ExternRef)
    }

    /// The read-only property of `addr` after a query there (`ScopeGhidra::dump2Cache`,
    /// `decodeHole`): a data symbol's flag over the symbol; in a function, read-only past the
    /// first `MAX_FUNCTION_OFFCUT` bytes after the entry (a hole to the end of the range) and
    /// before the entry; else the hole's (`MappedEntry.getMutabilityOfAddress`: a block that
    /// is not writable, unless the address has a write reference).
    pub(crate) fn readonly(&self, addr: u64) -> bool {
        if !self.data.get(&addr).is_some_and(|r| r.kind == DataKind::ExternRef) {
            if let Some((first, last, entry)) = self.body_at(addr) {
                let in_entry_range = first <= entry && entry <= last;
                return !(in_entry_range && addr >= entry && addr - entry < MAX_FUNCTION_OFFCUT);
            }
        }
        if let Some((_, rec)) = self.data_at(addr) {
            return rec.readonly;
        }
        self.blocks.iter().any(|&(first, last, write)| first <= addr && addr <= last && !write)
            && !self.wrefs.contains(&addr)
    }

    /// The data symbol holding `addr` (`ScopeGhidra::removeQuery` answered with a `<symbol>`),
    /// its data-type decoded into `types`. None for a hole, a function or an external
    /// reference.
    pub(crate) fn data_symbol(&self, types: &mut TypeFactory, addr: u64) -> Result<Option<DataSym>> {
        if self.in_function(addr) {
            return Ok(None);
        }
        let Some((first, rec)) = self.data_at(addr) else { return Ok(None) };
        if rec.kind == DataKind::ExternRef {
            return Ok(None);
        }
        if rec.volatile {
            return err(format!("facts: the volatile symbol at {first:#x} is not ported"));
        }
        let doc = parse(self.xml(&rec.xml))?;
        let (sym, prefix) = self.mapsym(&doc)?;
        let (Some(head), Some(addr_el)) = (sym.kids.first(), sym.kid("addr")) else {
            return err(format!("facts: bad symbol at {first:#x}"));
        };
        let name = format!("{prefix}{}", head.req("name").map_err(facts_err)?);
        let size = addr_el.int("size").map_err(facts_err)? as u32;
        let ty = match rec.kind {
            // LabSymbol::buildType
            DataKind::Label => types.base(1, Meta::Unknown),
            _ => {
                let [t] = head.kids.as_slice() else { return err(format!("facts: symbol {name} without a data-type")) };
                self.decoder()
                    .decode(types, t)
                    .map_err(|e| LowlevelError(format!("facts: the data-type of {name}: {e}")))?
            }
        };
        if head.attr_names().any(|a| matches!(a, "format" | "hiddenretparm" | "indirectstorage" | "thisptr")) {
            return err(format!("facts: an attribute of symbol {name} is not ported"));
        }
        // Symbol::decodeHeader: `merge="false"` isolates the symbol and locks its type
        let isolated = head.attr("merge").is_some() && !head.flag("merge");
        Ok(Some(DataSym { addr: first, size, name, ty, type_locked: head.flag("typelock") || isolated }))
    }

    /// The function at `entry` as a caller sees it, or as its own decompile starts (`own`):
    /// `FuncProto::decode` of its `<prototype>` over the parameters of its `<localdb>`
    /// (`ProtoStoreSymbol`).
    pub(crate) fn function(&self, arch: &Arch, types: &mut TypeFactory, entry: u64, own: bool) -> Result<FuncFact> {
        let rec =
            if arch.externref_target(entry).is_some() { self.extrefs.get(&entry) } else { self.funcs.get(&entry) };
        let rec = rec.ok_or_else(|| LowlevelError(format!("facts: no function at {entry:#x}")))?;
        let doc = parse(self.xml(rec))?;
        let (sym, prefix) = self.mapsym(&doc)?;
        let func = sym.kid("function").ok_or_else(|| facts_err("no <function>".into()))?;
        let name = func.attr("name").unwrap_or("");
        let unported = |what: &str| LowlevelError(format!("facts: function {name}: {what} is not ported"));
        if own && !prefix.is_empty() {
            // its declaration and the scope every other name resolves from
            return Err(unported("the decompile of a function in a namespace"));
        }
        if func.flag("inline") || func.kid("jumptablelist").is_some() || func.kid("override").is_some() {
            return Err(unported("an inline flag, jump-table override or prototype override"));
        }
        let e = |m: String| LowlevelError(format!("facts: function {name}: {m}"));
        let mut dec = self.decoder();
        // the local scope: parameters (category 0, by index) and name recommendations
        let (mut params, mut name_recs) = (Vec::new(), Vec::new());
        for m in func.find("symbollist").map_or(&[][..], |l| l.kids.as_slice()) {
            let is_param = m.kid("symbol").is_some_and(|s| s.attr("cat") == Some("0"));
            if !own && !is_param {
                continue; // a caller reads the prototype only
            }
            let (Some(sym), Some(addr)) = (m.kid("symbol"), m.kids.get(1)) else {
                return Err(unported("a local symbol that is no <symbol>"));
            };
            if addr.name != "addr" {
                return Err(unported("a dynamic (hash) local symbol"));
            }
            if sym.attr_names().any(|a| matches!(a, "format" | "hiddenretparm" | "indirectstorage")) {
                return Err(unported("a hidden return parameter or a display format"));
            }
            let storage = storage(arch, addr).map_err(e)?.ok_or_else(|| unported("a symbol without storage"))?;
            let sname = sym.req("name").map_err(e)?.to_string();
            let locked = sym.flag("typelock") || (sym.attr("merge").is_some() && !sym.flag("merge"));
            if is_param {
                if !locked {
                    return Err(unported("a parameter without a locked data-type"));
                }
                let [t] = sym.kids.as_slice() else { return Err(e("bad parameter".into())) };
                let ty = dec.decode(types, t).map_err(e)?;
                params.push((sym.int("index").map_err(e)?, Param { name: sname, storage: Some(storage), ty }));
            } else if locked {
                return Err(unported("a local variable with a locked data-type"));
            } else if sym.flag("namelock") {
                if m.kid("rangelist").is_some_and(|r| !r.kids.is_empty()) {
                    return Err(unported("a name for a variable with a use point"));
                }
                name_recs.push(NameRec { storage, name: sname });
            }
        }
        params.sort_by_key(|p| p.0);
        let p = func.kid("prototype").ok_or_else(|| e("no <prototype>".into()))?;
        if p.flag("custom") || p.flag("constructor") || p.flag("destructor") || p.flag("inline") {
            return Err(unported("custom storage, a constructor or destructor, or an inline prototype"));
        }
        let models = &arch.spec.models;
        let mut proto = FuncProto::default();
        // FuncProto::decode: the model first (an unrecognized name makes an unknown model)
        let model = match p.attr("model") {
            None | Some("" | "default") => models.default,
            Some(n) => models.find(n).unwrap_or(self.unknown_model),
        };
        proto.set_model(models, model);
        match p.attr("extrapop") {
            Some("unknown") => proto.extrapop = ExtraPop::Unknown,
            Some(_) => proto.extrapop = ExtraPop::Known(p.int("extrapop").map_err(e)? as i32),
            None => {}
        }
        proto.no_return = p.flag("noreturn") || func.flag("noreturn");
        if let Some(inject) = p.kid("inject") {
            let id = arch.spec.injects.callfixup_id(inject.text.trim());
            proto.inject = Some(id.ok_or_else(|| e(format!("unknown call fixup {}", inject.text)))?);
        }
        let ret = p.kid("returnsym").ok_or_else(|| e("Missing <returnsym> tag".into()))?;
        let [raddr, rtype] = ret.kids.as_slice() else { return Err(e("bad <returnsym>".into())) };
        let output_locked = ret.flag("typelock");
        let input_locked = !params.is_empty() || p.flag("voidlock");
        proto.model_locked = p.flag("modellock") || p.flag("voidlock") || output_locked;
        if p.kid("internallist").is_some() {
            return Err(unported("an <internallist>"));
        }
        if input_locked != output_locked {
            return Err(unported("a prototype with only its inputs or only its output locked"));
        }
        if input_locked {
            let ty = dec.decode(types, rtype).map_err(e)?;
            let storage = storage(arch, raddr).map_err(e)?;
            if storage.is_none() && types.meta(ty) != Meta::Void {
                return Err(unported("a locked return value without storage"));
            }
            proto.locked = Some(Box::new(Locked {
                inputs: params.into_iter().map(|p| p.1).collect(),
                output: Param { name: String::new(), storage: storage.filter(|_| types.meta(ty) != Meta::Void), ty },
                dotdotdot: p.flag("dotdotdot"),
            }));
        } else if p.flag("dotdotdot") {
            return Err(unported("an unlocked varargs prototype"));
        }
        Ok(FuncFact { proto, name_recs })
    }

    /// The range (first address, length) of the data symbol or label holding `addr`, without
    /// reading it.
    pub(crate) fn data_range(&self, addr: u64) -> Option<(u64, u64)> {
        let (first, rec) = self.data_at(addr).filter(|_| !self.in_function(addr))?;
        (rec.kind != DataKind::ExternRef).then_some((first, rec.len))
    }

    /// Whether a data symbol of a composite data-type lies where
    /// `TypeSpacebase::nearestArrayedComponentForward` and `Backward` look from `addr`: up to
    /// `MAX_ARRAY_SLACK_BACKWARD` (8) bytes before and `MAX_ARRAY_SLACK_FORWARD` (128) after,
    /// in the 8-byte steps of `ScopeGhidra::findSymbolBefore`/`After` (so 8 more each way).
    pub(crate) fn composite_near(&self, types: &mut TypeFactory, addr: u64) -> Result<bool> {
        let (lo, hi) = (addr.saturating_sub(16), addr.saturating_add(136));
        let start = self.data_at(lo).map_or(lo, |(first, _)| first);
        for (&a, _) in self.data.range(start..=hi) {
            let Some(d) = self.data_symbol(types, a)? else { continue };
            let base = types.strip_typedefs(d.ty);
            if matches!(types.meta(base), Meta::Struct | Meta::Union | Meta::Array) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// `getCodeLabel`: the listing's label at an address inside a function.
    pub(crate) fn label(&self, addr: u64) -> Option<&str> {
        self.labels.get(&addr).map(|r| self.xml(r))
    }

    /// `getComments` of the function at `entry`.
    pub(crate) fn comments(&self, entry: u64) -> Result<Vec<ListingComment>> {
        let Some(r) = self.comments.get(&entry) else { return Ok(Vec::new()) };
        let root = parse(self.xml(r))?;
        let mut out = Vec::new();
        for c in root.kids_named("comment") {
            let [_, addr, text] = c.kids.as_slice() else { return err("facts: bad <comment>") };
            out.push(ListingComment {
                kind: c.req("type").map_err(facts_err)?.to_string(),
                addr: addr.int("offset").map_err(facts_err)? as u64,
                text: text.text.clone(),
            });
        }
        Ok(out)
    }

    /// `getTrackedRegisters` at the entry of a function: space, offset, size, value.
    pub(crate) fn tracked(&self, arch: &Arch, entry: u64) -> Result<Vec<(u32, u64, u32, u64)>> {
        let Some((_, r)) = self.tracked.range(..=entry).next_back() else { return Ok(Vec::new()) };
        let root = parse(self.xml(r))?;
        let mut out = Vec::new();
        for s in root.kids_named("set") {
            let name = s.req("space").map_err(facts_err)?;
            let space = arch.sleigh.spaces.iter().position(|sp| sp.name == name);
            let space = space.ok_or_else(|| facts_err(format!("Unknown space name: {name}")))? as u32;
            let int = |n| s.int(n).map_err(facts_err);
            out.push((space, int("offset")? as u64, int("size")? as u32, int("val")? as u64));
        }
        Ok(out)
    }

    /// The overrides of the instruction at `addr` (`CALL_RETURN`, ...).
    pub(crate) fn overrides(&self, addr: u64) -> impl Iterator<Item = &str> {
        self.overrides.get(&addr).into_iter().flatten().map(|r| self.xml(r))
    }

    /// Whether `ty` is a `code` data-type with a prototype (which the port does not keep).
    pub(crate) fn code_with_prototype(&self, ty: TypeId) -> bool {
        self.code_protos.contains(&ty)
    }
}

/// Port of `ScopeGhidra::removeQuery` answered with a data symbol: the symbol holding `addr`
/// joins the function's global scope (the cache of `ScopeGhidra`), unless one holds the address
/// already. Nothing without facts or outside ram.
pub(crate) fn query_symbol(fd: &mut Funcdata, arch: &Arch, space: Space, addr: u64) -> Result<()> {
    let Some(facts) = &arch.facts else { return Ok(()) };
    if space != Space::Sleigh(arch.spec.stack_container)
        || fd.symtab.find_container(GLOBAL, space, addr, 1, None)?.is_some()
    {
        return Ok(());
    }
    let Some(d) = facts.data_symbol(&mut fd.types, addr)? else { return Ok(()) };
    let entry = SymbolEntry {
        space,
        offset: d.addr,
        size: d.size,
        uselimit: UseLimit::default(),
        conflict: false,
        piece: None,
    };
    let sym = fd.symtab.add_symbol(GLOBAL, &d.name, Some(d.ty), None, Some(entry))?;
    fd.symtab.lock_symbol(sym, d.type_locked, true);
    Ok(())
}

/// What a data symbol of the facts gives the ram varnodes it holds when they are made
/// (`Varnode::setSymbolProperties`): its data-type, locked, when the symbol's is locked and
/// known (`SymbolEntry::updateType`; `Varnode::updateType` takes an unknown type as not
/// locked), and the link to the symbol, which every data symbol of Java Ghidra isolates from
/// speculative merging ([`Funcdata::isolated`]). Runs where
/// [`super::infertypes::symbol_types`] does. A varnode inside a symbol of a composite
/// data-type would need `TypeFactory::getExactPiece` and the partial types: not ported.
pub(crate) fn symbol_types(fd: &mut Funcdata, arch: &Arch) -> Result<()> {
    let (Some(facts), Some(ram)) = (&arch.facts, fd.ram) else { return Ok(()) };
    for vn in fd.loc_space(Space::Sleigh(ram)) {
        let v = fd.vn(vn);
        let (off, size, locked) = (v.offset, v.size, v.has(VnFlags::TYPELOCK));
        if !arch.data_holds(off, size) {
            continue;
        }
        fd.isolated.insert(vn);
        if locked {
            continue;
        }
        let Some(d) = facts.data_symbol(&mut fd.types, off)? else { continue };
        let base = fd.types.strip_typedefs(d.ty);
        if matches!(fd.types.meta(base), Meta::Struct | Meta::Union | Meta::Array) || fd.types.is_enum(base) {
            return err(format!("facts: a variable in {}, a symbol of a composite data-type, is not ported", d.name));
        }
        // Symbol::getSizedType: the symbol's type for the whole symbol; a primitive has no pieces
        if d.type_locked && off == d.addr && size == d.size && fd.types.meta(d.ty) != Meta::Unknown {
            update_type(fd, vn, d.ty, true, true);
        }
    }
    Ok(())
}

/// The value of attribute `attr` of the first `tag` element of `xml`, unescaped: a scan, for
/// the load, which parses no record.
fn attr_of(xml: &str, tag: &str, attr: &str) -> Option<String> {
    let rest = &xml[xml.find(tag)? + tag.len()..];
    let rest = &rest[..rest.find('>')?];
    let pat = format!(" {attr}=\"");
    let v = &rest[rest.find(&pat)? + pat.len()..];
    let v = &v[..v.find('"')?];
    Some(
        v.replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&apos;", "'")
            .replace("&amp;", "&"),
    )
}

/// The name of the `<function>` of a record.
fn function_name(xml: &str) -> Option<String> {
    attr_of(xml, "<function", "name")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attribute_scan() {
        let x =
            r#"<doc id="0x0"><mapsym><function id="0x1" name="a&lt;b&gt;" size="2"><addr/></function></mapsym></doc>"#;
        assert_eq!(function_name(x).as_deref(), Some("a<b>"));
        assert_eq!(attr_of(x, "<function", "size").as_deref(), Some("2"));
        assert_eq!(attr_of(x, "<function", "label"), None);
    }
}
