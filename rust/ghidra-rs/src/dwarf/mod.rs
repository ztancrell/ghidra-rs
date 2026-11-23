//! Ghidra 12.3's DWARF importer (`ghidra.app.util.bin.format.dwarf`), the parts that make data
//! types and function signatures: `DWARFProgram` (names), `DIEAggregate`, `DIEContainer`,
//! `DWARFDataTypeManager`, `DWARFDataTypeImporter`, `DWARFFunctionImporter` / `DWARFFunction`
//! (signatures, the `this` and parameter-name fixups) and `DWARFImporter.moveTypesIntoSourceFolders`,
//! with the default `DWARFImportOptions`. The raw reader is `read`, the data-type model `dtm`.
//! Not ported: line tables beyond the file names, local and global variables, storage and
//! location expressions, source maps, macros, comments and bookmarks, Go and Rust special cases.
pub mod dtm;
pub mod read;

use dtm::{Composite, Dtm, Handler, Id, Kind, Param, B};
use read::*;
use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;

#[derive(Debug)]
pub enum Error {
    Dwarf(String),
    Object(object::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Dwarf(s) => write!(f, "DWARF: {s}"),
            Error::Object(e) => write!(f, "ELF: {e}"),
        }
    }
}

impl std::error::Error for Error {}

type Result<T> = std::result::Result<T, Error>;

/// `SymbolType` of a name (`DWARFTag.getSymbolType`)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Sym {
    None,
    Function,
    Class,
    Namespace,
    Parameter,
    LocalVar,
}

/// A `NamespacePath` node; `cat` is its category under `_UNCATEGORIZED_`.
struct Ns {
    parent: u32,
    name: String,
    cat: u32,
}

/// `DWARFName`: a namespace node and the original name (`None` = anonymous).
#[derive(Debug, Clone)]
struct DName {
    ns: u32,
    orig: Option<String>,
}

/// `DWARFSourceInfo`
#[derive(Debug, Clone)]
struct Dsi {
    file: String,
}

/// `DWARFDataTypeImporter.DWARFDataType`
struct Ddt {
    dt: Id,
    dsi: Option<Dsi>,
    offsets: Vec<u32>,
}

/// One `DWARFDataTypeImporter`: the state of one `doGetDataType`.
struct Imp {
    ddts: Vec<Ddt>,
    by_die: HashMap<u32, usize>,
    by_inst: HashMap<Id, usize>,
    rec: HashMap<u32, i32>,
}

const VOID_DDT: usize = 0;

/// A function the import gives a signature (`DWARFFunction` after its fixups).
pub struct Func {
    pub addr: u64,
    pub name: String,
    pub cc: Option<String>,
    pub ret: Id,
    pub params: Vec<(String, Id)>,
    pub varargs: bool,
    pub noreturn: bool,
    /// the plate comment `decorateFunctionWithDWARFInfo` gives it (`None`: none); `Err` where it
    /// is not derived: a local variable or label below the function (an `Unresolved local var`
    /// PRE comment may go there), a body of more than one range, or another DIE at its address
    /// (`decorateFunctionWithAlternateInfo`)
    pub plate: std::result::Result<Option<String>, ()>,
}

/// The import's result: the program's data types and the functions with signatures.
pub struct Import {
    pub dtm: Dtm,
    pub funcs: Vec<Func>,
    pub dies: usize,
    pub units: usize,
    /// what Java logs and skips (`Msg.error`): unit rests, types and functions that failed
    pub warnings: Vec<String>,
}

/// The aggregate of a DIE (`DIEAggregate.createFromHead`): fragments, head first.
type Agg = Vec<u32>;

struct Prog<'a> {
    dw: Dwarf<'a>,
    dtm: Dtm,
    ns: Vec<Ns>,
    ns_index: HashMap<(u32, String, Sym), u32>,
    dni_cache: HashMap<u32, DName>,
    type_referers: HashMap<u32, Vec<u32>>,
    offset_to_dt: HashMap<u32, Id>,
    src: HashMap<u32, Dsi>,
    src_order: Vec<u32>,
    base: HashMap<String, Id>,
    dwarf_cat: u32,
    uncat: u32,
    exec: Vec<(u64, u64)>,
    fixup: u64,
    /// the depth of `dwarf_name` calls
    name_depth: u32,
}

/// The bound of `dwarf_name`'s recursion (far above real nesting)
const NAME_DEPTH: u32 = 256;

const CONTAINER_NAMES: [(u16, &str); 8] = [
    (DW_TAG_STRUCTURE, "struct"),
    (DW_TAG_CLASS, "class"),
    (DW_TAG_ENUMERATION, "enum"),
    (DW_TAG_UNION, "union"),
    (DW_TAG_LEXICAL_BLOCK, "lexical_block"),
    (DW_TAG_SUBPROGRAM, "subprogram"),
    (DW_TAG_SUBROUTINE_TYPE, "subr"),
    (DW_TAG_VARIABLE, "var"),
];
fn container_name(t: u16) -> &'static str {
    CONTAINER_NAMES.iter().find(|(x, _)| *x == t).map(|(_, n)| *n).unwrap_or("unknown")
}
fn is_structure(t: u16) -> bool {
    matches!(t, DW_TAG_CLASS | DW_TAG_INTERFACE | DW_TAG_STRUCTURE | DW_TAG_UNION)
}
fn is_type(t: u16) -> bool {
    matches!(
        t,
        DW_TAG_BASE_TYPE
            | DW_TAG_ARRAY
            | DW_TAG_TYPEDEF
            | DW_TAG_CLASS
            | DW_TAG_INTERFACE
            | DW_TAG_STRUCTURE
            | DW_TAG_UNION
            | DW_TAG_ENUMERATION
            | DW_TAG_POINTER
            | DW_TAG_REFERENCE
            | DW_TAG_RVALUE_REFERENCE
            | DW_TAG_CONST
            | DW_TAG_VOLATILE
            | DW_TAG_PTR_TO_MEMBER
            | DW_TAG_UNSPECIFIED_TYPE
            | DW_TAG_SUBROUTINE_TYPE
    )
}
fn is_named_type(t: u16) -> bool {
    matches!(
        t,
        DW_TAG_BASE_TYPE
            | DW_TAG_TYPEDEF
            | DW_TAG_NAMESPACE
            | DW_TAG_SUBPROGRAM
            | DW_TAG_CLASS
            | DW_TAG_INTERFACE
            | DW_TAG_STRUCTURE
            | DW_TAG_UNION
            | DW_TAG_ENUMERATION
            | DW_TAG_SUBROUTINE_TYPE
            | DW_TAG_UNSPECIFIED_TYPE
    )
}
fn is_ns_container(t: u16) -> bool {
    matches!(
        t,
        DW_TAG_NAMESPACE
            | DW_TAG_SUBPROGRAM
            | DW_TAG_LEXICAL_BLOCK
            | DW_TAG_CLASS
            | DW_TAG_INTERFACE
            | DW_TAG_STRUCTURE
            | DW_TAG_UNION
            | DW_TAG_ENUMERATION
    )
}
fn sym_type(t: u16) -> Sym {
    match t {
        DW_TAG_SUBPROGRAM => Sym::Function,
        DW_TAG_STRUCTURE | DW_TAG_INTERFACE | DW_TAG_CLASS | DW_TAG_UNION | DW_TAG_ENUMERATION => Sym::Class,
        DW_TAG_NAMESPACE => Sym::Namespace,
        DW_TAG_FORMAL_PARAMETER => Sym::Parameter,
        DW_TAG_VARIABLE => Sym::LocalVar,
        _ => Sym::None,
    }
}

/// Java's `String.hashCode` (over UTF-16 code units)
fn java_hash(s: &str) -> i32 {
    s.encode_utf16().fold(0i32, |h, c| h.wrapping_mul(31).wrapping_add(c as i32))
}

/// `SymbolUtilities.replaceInvalidChars(s, true)`: whitespace and control characters to '_'
fn replace_invalid(s: &str) -> String {
    if !s.chars().any(invalid_char) {
        return s.to_string();
    }
    s.chars().map(|c| if invalid_char(c) { '_' } else { c }).collect()
}
fn invalid_char(c: char) -> bool {
    // ponytail: Unicode general categories approximated by Rust's whitespace/control classes and
    // the format characters below; full category tables if a binary needs them
    c.is_whitespace() || c.is_control() || matches!(c, '\u{200b}'..='\u{200f}' | '\u{feff}' | '\u{e000}'..='\u{f8ff}')
}

const MAX_SYMBOL_NAME_LENGTH: usize = 2000;
const NAME_HASH_REPLACEMENT_SIZE: usize = 10;
const ELLIPSES_STR: &str = "...";

/// `DWARFProgram.ensureSafeNameLength` (lengths in UTF-16 units, as Java)
fn ensure_safe_name_length(s: &str) -> String {
    let u: Vec<u16> = s.encode_utf16().collect();
    if u.len() <= MAX_SYMBOL_NAME_LENGTH {
        return s.to_string();
    }
    let mut s = abbrev_template_name(s);
    let u2: Vec<u16> = s.encode_utf16().collect();
    if u2.len() <= MAX_SYMBOL_NAME_LENGTH {
        return s;
    }
    let keep = MAX_SYMBOL_NAME_LENGTH - ELLIPSES_STR.len() - NAME_HASH_REPLACEMENT_SIZE;
    let h = java_hash(&s);
    s = format!("{}{ELLIPSES_STR}${:x}$", String::from_utf16_lossy(&u2[..keep]), h);
    s
}
fn abbrev_template_name(s: &str) -> String {
    let (Some(a), Some(b)) = (s.find('<'), s.rfind('>')) else { return s.to_string() };
    let (ua, ub) = (s[..a].encode_utf16().count(), s[..b].encode_utf16().count());
    if ua + NAME_HASH_REPLACEMENT_SIZE < ub {
        format!("{}${:x}${}", &s[..a + 1], java_hash(&s[a..b]), &s[b..])
    } else {
        s.to_string()
    }
}

/// `DWARFUtil.parseMangledNestings`: the `N<len><name>...` parts of a mangled name
fn parse_mangled_nestings(s: &str) -> Vec<String> {
    let b = s.as_bytes();
    let is_n = |i: usize| b.get(i) == Some(&b'N') && b.get(i + 1).is_some_and(|c| c.is_ascii_digit());
    // (.*_Z)?N([0-9]+.*): the last "_Z" followed by N<digit>, else N<digit> at the start
    let start = (0..b.len().saturating_sub(2))
        .rev()
        .find(|&i| &b[i..i + 2] == b"_Z" && is_n(i + 2))
        .map(|i| i + 3)
        .or(if is_n(0) { Some(1) } else { None });
    let Some(start) = start else { return Vec::new() };
    let s = &b[start..];
    let mut out = Vec::new();
    let mut cp = 0;
    while cp < s.len() {
        let st = cp;
        while cp < s.len() && s[cp].is_ascii_digit() {
            cp += 1;
        }
        if st == cp || cp == s.len() {
            // ponytail: Java reads one char past the end here and throws; stopping keeps the rest
            break;
        }
        let Ok(len) = std::str::from_utf8(&s[st..cp]).unwrap_or("x").parse::<usize>() else { break };
        if cp + len <= s.len() {
            out.push(String::from_utf8_lossy(&s[cp..cp + len]).into_owned());
        }
        cp = cp.saturating_add(len);
    }
    out
}

/// `DWARFDataTypeManager.FIXED_SIZED_TYPE_NAME_PATTERN` (`\D+(8|16|32|64|128)\D*`)
fn explicit_size_from_name(name: Option<&str>) -> i32 {
    let Some(n) = name else { return -1 };
    let Some(i) = n.find(|c: char| c.is_ascii_digit()) else { return -1 };
    if i == 0 {
        return -1;
    }
    let j = n[i..].find(|c: char| !c.is_ascii_digit()).map(|j| i + j).unwrap_or(n.len());
    if n[j..].chars().any(|c| c.is_ascii_digit()) {
        return -1;
    }
    match &n[i..j] {
        "8" | "16" | "32" | "64" | "128" => n[i..j].parse().unwrap_or(-1),
        _ => -1,
    }
}

impl<'a> Prog<'a> {
    // ---- aggregates (DIEAggregate)

    fn agg(&self, die: u32) -> Agg {
        let mut frags = vec![die];
        while let Some(t) = self.find(&frags, DW_AT_ABSTRACT_ORIGIN).and_then(|a| self.dw.ref_target(&a)) {
            if frags.contains(&t) || frags.len() >= 20 {
                break;
            }
            frags.insert(0, t);
        }
        if let Some(t) = self.find(&frags, DW_AT_SPECIFICATION).and_then(|a| self.dw.ref_target(&a)) {
            frags.insert(0, t);
        }
        frags.reverse();
        frags
    }
    fn find(&self, frags: &[u32], at: u16) -> Option<Attr<'a>> {
        frags.iter().find_map(|&d| self.dw.attr(d, at))
    }
    fn has(&self, g: &Agg, at: u16) -> bool {
        self.find(g, at).is_some()
    }
    fn get_bool(&self, g: &Agg, at: u16) -> bool {
        matches!(self.find(g, at).map(|a| a.val), Some(Val::Bool(true)))
    }
    fn get_unsigned(&self, g: &Agg, at: u16, def: i64) -> i64 {
        self.find(g, at).and_then(|a| a.val.unsigned()).map(|v| v as i64).unwrap_or(def)
    }
    fn get_string(&self, g: &Agg, at: u16) -> Option<String> {
        self.find(g, at).and_then(|a| self.dw.string(&a))
    }
    fn name_of(&self, g: &Agg) -> Option<String> {
        self.get_string(g, DW_AT_NAME)
    }
    fn tag(&self, g: &Agg) -> u16 {
        self.dw.tags[g[0] as usize]
    }
    fn off(&self, die: u32) -> u64 {
        self.dw.offsets[die as usize]
    }
    fn type_ref(&self, g: &Agg) -> Option<Agg> {
        self.ref_agg(g, DW_AT_TYPE)
    }
    fn ref_agg(&self, g: &Agg, at: u16) -> Option<Agg> {
        let a = self.find(g, at)?;
        if !matches!(a.val, Val::Num { .. }) {
            return None;
        }
        self.dw.ref_target(&a).map(|t| self.agg(t))
    }
    fn parent_agg(&self, g: &Agg) -> Option<Agg> {
        self.dw.parent(g[0]).map(|p| self.agg(p))
    }
    fn decl_parent(&self, g: &Agg) -> Option<Agg> {
        self.dw.parent(*g.last().unwrap()).map(|p| self.agg(p))
    }
    fn children(&self, g: &Agg, tag: u16) -> Vec<u32> {
        self.dw.children(g[0]).filter(|&c| self.dw.tags[c as usize] == tag).collect()
    }
    fn addr_size(&self, g: &Agg) -> u8 {
        self.dw.cus[self.dw.cu_of(g[0])].addr_size
    }
    /// `parseInt`: numeric (signed value) or an evaluated expression
    fn parse_int(&self, g: &Agg, at: u16, def: i32) -> Result<i32> {
        let Some(a) = self.find(g, at) else { return Ok(def) };
        let v = match a.val {
            Val::Num { .. } => a.val.value().unwrap_or(0),
            Val::Blob(b) => eval_const(b, self.addr_size(g))?,
            _ => return Err(Error::Dwarf(format!("Not integer attribute 0x{at:x}"))),
        };
        i32::try_from(v).map_err(|_| Error::Dwarf(format!("Value out of allowed range: {v}")))
    }
    fn parse_unsigned_long(&self, g: &Agg, at: u16, def: i64) -> Result<i64> {
        let Some(a) = self.find(g, at) else { return Ok(def) };
        match a.val {
            Val::Num { .. } => Ok(a.val.unsigned().unwrap_or(0) as i64),
            Val::Blob(b) => eval_const(b, self.addr_size(g)),
            _ => Err(Error::Dwarf("Not integer attribute".into())),
        }
    }
    fn parse_member_offset(&self, g: &Agg) -> Result<i32> {
        let Some(a) = self.find(g, DW_AT_DATA_MEMBER_LOCATION) else { return Ok(0) };
        let v = match a.val {
            Val::Num { .. } => a.val.unsigned().unwrap_or(0) as i64,
            Val::Blob(b) => eval_const(b, self.addr_size(g))?,
            _ => return Err(Error::Dwarf("DWARF attribute form not valid for data member offset".into())),
        };
        if !(0..=i32::MAX as i64).contains(&v) {
            return Err(Error::Dwarf(format!("Value out of allowed range: {v}")));
        }
        Ok(v as i32)
    }
    /// `getFunctionParamList`
    fn param_list(&self, g: &Agg) -> Vec<Agg> {
        let mut params: Vec<Agg> = self.children(g, DW_TAG_FORMAL_PARAMETER).into_iter().map(|d| self.agg(d)).collect();
        if let Some(abs) = self.abstract_instance(g) {
            let mut newp = Vec::new();
            for pd in self.children(&abs, DW_TAG_FORMAL_PARAMETER) {
                if let Some(i) = params.iter().position(|p| p.contains(&pd)) {
                    newp.push(params.remove(i));
                } else {
                    newp.push(self.agg(pd));
                }
            }
            newp.append(&mut params);
            params = newp;
        }
        params
    }
    fn abstract_instance(&self, g: &Agg) -> Option<Agg> {
        let a = self.find(g, DW_AT_ABSTRACT_ORIGIN)?;
        let i = g.iter().position(|&d| d == a.die)?;
        Some(g[i + 1..].to_vec())
    }
    /// `getSourceFile`
    fn source_file(&self, g: &Agg) -> Option<String> {
        let a = self.find(g, DW_AT_DECL_FILE)?;
        let n = a.val.unsigned()? as i64;
        if !(0..=i32::MAX as i64).contains(&n) {
            return None;
        }
        let cu = &self.dw.cus[self.dw.cu_of(a.die)];
        let files = cu.files.as_ref()?;
        let n = n as usize;
        if cu.files_v5 {
            files.get(n).cloned()
        } else if n > 0 {
            files.get(n - 1).cloned()
        } else {
            None
        }
    }
    /// `DWARFSourceInfo.create`
    fn source_info(&self, g: &Agg) -> Option<Dsi> {
        let mut cur = Some(g.clone());
        let mut file = None;
        while let Some(c) = cur {
            file = self.source_file(&c);
            if file.is_some() {
                break;
            }
            cur = self.parent_agg(&c);
        }
        let file = file?;
        // findAttributeInChildren(DW_AT_decl_line, DW_TAG_formal_parameter)
        let line = self.find(g, DW_AT_DECL_LINE).filter(|a| matches!(a.val, Val::Num { .. })).or_else(|| {
            self.children(g, DW_TAG_FORMAL_PARAMETER)
                .into_iter()
                .find_map(|c| self.find(&self.agg(c), DW_AT_DECL_LINE).filter(|a| matches!(a.val, Val::Num { .. })))
        });
        line.map(|_| Dsi { file })
    }

    // ---- names (DWARFProgram.getName / DWARFName / NamespacePath)

    fn ns_child(&mut self, parent: u32, name: &str, sym: Sym) -> u32 {
        let name = replace_invalid(name);
        if let Some(&i) = self.ns_index.get(&(parent, name.clone(), sym)) {
            return i;
        }
        let pc = self.ns[parent as usize].cat;
        let cat = self.dtm.cat(pc, &name);
        self.ns.push(Ns { parent, name: name.clone(), cat });
        let i = self.ns.len() as u32 - 1;
        self.ns_index.insert((parent, name, sym), i);
        i
    }
    fn ns_from_list(&mut self, parent: u32, names: &[String]) -> u32 {
        names.iter().fold(parent, |p, s| self.ns_child(p, s, Sym::Namespace))
    }
    fn dni_name(&self, d: &DName) -> &str {
        &self.ns[d.ns as usize].name
    }
    fn parent_cp(&self, d: &DName) -> u32 {
        self.ns[self.ns[d.ns as usize].parent as usize].cat
    }
    fn replace_name(&mut self, d: &DName, new: &str, orig: Option<String>, sym: Sym) -> DName {
        let parent = self.ns[d.ns as usize].parent;
        DName { ns: self.ns_child(parent, new, sym), orig }
    }

    fn get_name(&mut self, g: &Agg) -> Result<DName> {
        if let Some(d) = self.dni_cache.get(&g[0]) {
            return Ok(d.clone());
        }
        let d = self.dwarf_name(g)?;
        self.dni_cache.insert(g[0], d.clone());
        Ok(d)
    }

    fn entry_name(&self, g: &Agg) -> Option<String> {
        self.name_of(g)
            .or_else(|| self.get_string(g, DW_AT_LINKAGE_NAME))
            .or_else(|| self.get_string(g, DW_AT_MIPS_LINKAGE_NAME))
    }

    /// `DWARFProgram.getDWARFName` with the `_UNCATEGORIZED_` root
    /// `getDWARFName` recurses through declaration parents, nameless typedefs and member parents.
    /// A cycle (a nameless typedef of itself, or two of each other) overflows Java's stack, and
    /// the `catch (Throwable)` of the type or function import (DWARFDataTypeManager.java:592,
    /// DWARFFunctionImporter.java:138) fails that one: here a depth bound fails it.
    fn dwarf_name(&mut self, g: &Agg) -> Result<DName> {
        if self.name_depth >= NAME_DEPTH {
            return Err(Error::Dwarf(format!("name of DIE 0x{:x}: recursion too deep (a cycle)", self.off(g[0]))));
        }
        self.name_depth += 1;
        let r = self.dwarf_name_inner(g);
        self.name_depth -= 1;
        r
    }
    fn dwarf_name_inner(&mut self, g: &Agg) -> Result<DName> {
        let mut parent = 0u32;
        let decl_parent = self.decl_parent(g);
        if let Some(dp) = &decl_parent {
            if self.tag(dp) != DW_TAG_COMPILE_UNIT {
                parent = match self.dni_cache.get(&dp[0]) {
                    Some(d) => d.ns,
                    None => {
                        let d = self.dwarf_name(dp)?;
                        self.dni_cache.insert(dp[0], d.clone());
                        d.ns
                    }
                };
            }
        }
        let tag = self.tag(g);
        let mut name = self.entry_name(g);
        if let Some(n) = name.clone() {
            if n.contains("_Z") && !n.starts_with("_GLOBAL_") {
                let mut nest: Vec<String> =
                    parse_mangled_nestings(&n).iter().map(|s| ensure_safe_name_length(s)).collect();
                if let Some(last) = nest.pop() {
                    name = Some(last);
                    if parent == 0 && !nest.is_empty() {
                        parent = self.ns_from_list(0, &nest);
                    }
                }
            }
        }
        if parent == 0 {
            let mut nest = self.linkage_in_children(g[0]);
            if !nest.is_empty() {
                nest.pop();
                parent = self.ns_from_list(0, &nest);
            }
        }
        if name.is_none() {
            let refs = self.referers(g, DW_TAG_TYPEDEF);
            if refs.len() == 1 {
                let r = self.agg(refs[0]);
                return self.dwarf_name(&r);
            }
        }
        if name.is_none() && is_structure(tag) {
            let fp = self.struct_fingerprint(g);
            let members = self.referers(g, DW_TAG_MEMBER);
            let mut names = self.referring_member_names(&members)?;
            if !names.is_empty() {
                // a member at a unit's root has no parent: Java's NullPointerException, caught
                // by the same `catch (Throwable)`
                let p = self
                    .parent_agg(&self.agg(members[0]))
                    .ok_or_else(|| Error::Dwarf(format!("member 0x{:x} has no parent", self.off(members[0]))))?;
                parent = self.get_name(&p)?.ns;
                names = format!("_for_{names}");
            }
            let n = format!("anon_{}_{fp}{names}", container_name(tag));
            return Ok(DName { ns: self.ns_child(parent, &n, sym_type(tag)), orig: None });
        }
        let mut anon = false;
        if name.is_none() {
            match tag {
                DW_TAG_BASE_TYPE => {
                    let size = self.parse_int(g, DW_AT_BYTE_SIZE, 0);
                    let enc = self.get_unsigned(g, DW_AT_ENCODING, -1) as i32;
                    name = Some(match size {
                        Ok(s) => format!("anon_basetype_{}_{s}", encoding_name(enc)),
                        Err(_) => format!("anon_basetype_unknown.dwarf_{:x}", self.off(g[0])),
                    });
                    anon = true;
                }
                DW_TAG_ENUMERATION => {
                    let size = (self.get_unsigned(g, DW_AT_BYTE_SIZE, 1) as i32).max(1);
                    name = Some(format!("anon_enum_{}", size.wrapping_mul(8)));
                    anon = true;
                }
                DW_TAG_SUBROUTINE_TYPE => {
                    name = Some("anon_subr".into());
                    anon = true;
                }
                DW_TAG_LEXICAL_BLOCK => name = Some(format!("lexical_block{}", self.lexical_block_name(g[0]))),
                DW_TAG_FORMAL_PARAMETER => {
                    name = Some(format!("param_{}", self.position_in_parent(g[0], |t| t == DW_TAG_FORMAL_PARAMETER)));
                    anon = true;
                }
                DW_TAG_SUBPROGRAM | DW_TAG_INLINED_SUBROUTINE => {
                    if decl_parent.as_ref().is_some_and(|dp| is_structure(self.tag(dp)))
                        && self.get_bool(g, DW_AT_ARTIFICIAL)
                    {
                        name = Some(self.ns[parent as usize].name.clone());
                    } else {
                        name = Some("anon_func".into());
                        anon = true;
                    }
                }
                _ => {
                    if decl_parent.as_ref().is_some_and(|dp| is_ns_container(self.tag(dp))) {
                        name = self.anon_name_from_parent2(g);
                    }
                }
            }
        }
        if name.as_deref().is_none_or(|n| n.starts_with("._") || n.starts_with("<anonymous")) {
            name = Some(format!("anon_{}.dwarf_{:x}", container_name(tag), self.off(g[0])));
            anon = true;
        }
        let name = name.unwrap();
        let orig = if anon { None } else { Some(name.clone()) };
        let working = ensure_safe_name_length(&name);
        Ok(DName { ns: self.ns_child(parent, &working, sym_type(tag)), orig })
    }

    fn referers(&self, g: &Agg, tag: u16) -> Vec<u32> {
        self.type_referers
            .get(&g[0])
            .map(|v| v.iter().copied().filter(|&d| self.dw.tags[d as usize] == tag).collect())
            .unwrap_or_default()
    }

    fn position_in_parent(&self, die: u32, f: impl Fn(u16) -> bool) -> i32 {
        let Some(p) = self.dw.parent(die) else { return -1 };
        let mut pos = 0;
        for c in self.dw.children(p) {
            if c == die {
                return pos;
            }
            if f(self.dw.tags[c as usize]) {
                pos += 1;
            }
        }
        -1
    }

    /// `DWARFUtil.getLexicalBlockName`: "_<position>" for each enclosing lexical block or inlined
    /// subroutine, outermost first (Java recurses per level; iterated here)
    fn lexical_block_name(&self, die: u32) -> String {
        let is_block = |t: u16| t == DW_TAG_LEXICAL_BLOCK || t == DW_TAG_INLINED_SUBROUTINE;
        let mut parts = Vec::new();
        let mut d = Some(die);
        while let Some(x) = d.filter(|&x| is_block(self.dw.tags[x as usize])) {
            parts.push(self.position_in_parent(x, is_block));
            d = self.dw.parent(x);
        }
        parts.iter().rev().map(|p| format!("_{p}")).collect()
    }

    /// `DWARFUtil.findLinkageNameInChildren` (the nestings without the last)
    fn linkage_in_children(&self, die: u32) -> Vec<String> {
        for c in self.dw.children(die).filter(|&c| self.dw.tags[c as usize] == DW_TAG_SUBPROGRAM).collect::<Vec<_>>() {
            let g = self.agg(c);
            let l = self.get_string(&g, DW_AT_LINKAGE_NAME).or_else(|| self.get_string(&g, DW_AT_MIPS_LINKAGE_NAME));
            if let Some(l) = l {
                let mut n = parse_mangled_nestings(&l);
                if !n.is_empty() {
                    n.pop();
                    return n;
                }
            }
        }
        Vec::new()
    }

    /// `DWARFUtil.getStructLayoutFingerprint`
    fn struct_fingerprint(&self, g: &Agg) -> String {
        let size = self.get_unsigned(g, DW_AT_BYTE_SIZE, 0);
        let mut count = 0;
        let mut names = Vec::new();
        for c in self.dw.children(g[0]) {
            let t = self.dw.tags[c as usize];
            if t != DW_TAG_MEMBER && t != DW_TAG_INHERITANCE {
                continue;
            }
            let cg = self.agg(c);
            if self.has(&cg, DW_AT_EXTERNAL) {
                continue;
            }
            count += 1;
            let off = self.parse_member_offset(&cg).unwrap_or(0);
            let n = self.name_of(&cg).unwrap_or_else(|| format!("UNNAMED_MEMBER_{count}"));
            names.push(format!("{off:04x}_{n}"));
        }
        names.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
        let h = names.iter().fold(1i32, |h, s| h.wrapping_mul(31).wrapping_add(java_hash(s)));
        format!("{size}_{count}_{:08x}", h as u32)
    }

    fn referring_member_names(&mut self, members: &[u32]) -> Result<String> {
        if members.is_empty() {
            return Ok(String::new());
        }
        let common = self.dw.parent(members[0]);
        let mut out = String::new();
        for &m in members {
            if self.dw.parent(m) != common {
                return Ok(String::new());
            }
            let mg = self.agg(m);
            let name = match self.name_of(&mg) {
                Some(n) => n,
                None => {
                    let pos = self.position_in_parent(m, |_| true);
                    if pos == -1 {
                        continue;
                    }
                    let cp = self.agg(common.unwrap());
                    let pd = self.get_name(&cp)?;
                    format!("{}_{pos}", self.dni_name(&pd))
                }
            };
            if !out.is_empty() {
                out.push('_');
            }
            out.push_str(&name);
        }
        Ok(out)
    }

    /// `DWARFUtil.getAnonNameForMeFromParentContext2`
    fn anon_name_from_parent2(&self, g: &Agg) -> Option<String> {
        let p = self.dw.parent(g[0])?;
        let mut users: Vec<String> = Vec::new();
        for c in self.dw.children(p) {
            let cg = self.agg(c);
            if let (Some(n), Some(t)) = (self.name_of(&cg), self.type_ref(&cg)) {
                if t[0] == g[0] {
                    users.push(n);
                }
            }
        }
        users.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
        if users.is_empty() {
            let mut count = 0;
            for c in self.dw.children(p) {
                let cg = self.agg(c);
                if cg[0] == g[0] {
                    return Some(format!("anon_{}_{count}", container_name(self.tag(&cg))));
                }
                if is_named_type(self.tag(&cg)) {
                    count += 1;
                }
            }
            return None;
        }
        Some(format!("anon_{}_for_{}", container_name(self.tag(g)), users.join("_")))
    }

    // ---- DWARFDataTypeManager

    fn init_base_types(&mut self) {
        use dtm::*;
        let put = |p: &mut Self, n: &str, b: B| {
            let id = p.dtm.builtin(b);
            p.base.insert(n.to_string(), id);
        };
        put(self, "void", VOID);
        put(self, "undefined1", B::Undefined(1));
        let void = self.dtm.builtin(VOID);
        let nullptr = self.dtm.db_pointer(void, -1);
        self.base.insert("nullptr".into(), nullptr);
        self.base.insert("decltype(nullptr)".into(), nullptr);
        for (n, b) in [
            ("char", CHAR),
            ("signed char", CHAR),
            ("unsigned char", UCHAR),
            ("short", SHORT),
            ("short int", SHORT),
            ("signed short int", SHORT),
            ("unsigned short int", USHORT),
            ("short unsigned int", USHORT),
            ("int", INT),
            ("signed int", INT),
            ("unsigned int", UINT),
            ("long", LONG),
            ("long int", LONG),
            ("signed long int", LONG),
            ("unsigned long int", ULONG),
            ("long unsigned int", ULONG),
            ("long long", LONGLONG),
            ("long long int", LONGLONG),
            ("signed long long int", LONGLONG),
            ("unsigned long long int", ULONGLONG),
            ("long long unsigned int", ULONGLONG),
            ("double", DOUBLE),
            ("long double", LONGDOUBLE),
            ("float", FLOAT),
            ("bool", B::Bool),
            ("wchar_t", WCHAR_T),
        ] {
            put(self, n, b);
        }
    }

    fn untyped(&mut self, size: i32) -> Option<Id> {
        let b = match size {
            0 => B::Void,
            1 => B::Fixed("byte", 1, false),
            2 => B::Fixed("word", 2, false),
            4 => B::Fixed("dword", 4, false),
            8 => B::Fixed("qword", 8, false),
            _ => return None,
        };
        Some(self.dtm.builtin(b))
    }

    /// `DWARFDataTypeManager.getBaseType(name, size, encoding, ...)`
    fn base_type(&mut self, name: Option<&str>, size: i32, enc: i32) -> Id {
        let mut mangled = None;
        if let Some(n) = name {
            if let Some(&dt) = self.base.get(n) {
                let sig = self.dtm.dt(dt).kind.clone();
                let compat = match (&sig, enc) {
                    (Kind::Builtin(b), 5) => b.int_signed().is_none_or(|s| s),
                    (Kind::Builtin(b), 7) => b.int_signed().is_none_or(|s| !s),
                    _ => true,
                };
                if self.dtm.aligned_len(dt) == size && compat {
                    return dt;
                }
            }
            let m = format!("{n}__MANGLE___{size}_{enc}");
            if let Some(&dt) = self.base.get(&m) {
                return dt;
            }
            mangled = Some(m);
        }
        let org = !(explicit_size_from_name(name) != -1 && explicit_size_from_name(name) / 8 == size);
        let b: Option<B> = match enc {
            1 => Some(B::Void),
            2 => (size == 1).then_some(B::Bool),
            4 => Some(dtm::float_type(size, org)),
            5 => dtm::int_type(size, true, org),
            7 => dtm::int_type(size, false, org),
            6 => Some(dtm::CHAR),
            8 => Some(dtm::UCHAR),
            0x10 => {
                [(1, dtm::CHAR), (2, dtm::WCHAR16), (4, dtm::WCHAR32)].iter().find(|(s, _)| *s == size).map(|(_, b)| *b)
            }
            _ => None,
        };
        let mut dt = match b {
            Some(b) => self.dtm.builtin(b),
            None if enc == 5 && size > 8 => {
                let sb = self.dtm.builtin(B::Fixed("sbyte", 1, true));
                self.dtm.new_pre(String::new(), 0, Kind::Array { elem: sb, count: size, elem_len: 1 })
            }
            None => match self.untyped(size) {
                Some(d) => d,
                None => {
                    let d = self.dtm.builtin(B::Default);
                    self.dtm.new_pre(String::new(), 0, Kind::Array { elem: d, count: size, elem_len: 1 })
                }
            },
        };
        if let (Some(n), Some(m)) = (name, mangled) {
            let td = self.dtm.new_pre(n.to_string(), self.dwarf_cat, Kind::Typedef { base: dt });
            let r = self.typedef_replacement(td);
            dt = self.dtm.resolve(r, Handler::Default);
            self.base.insert(m, dt);
        }
        dt
    }

    /// `DataTypeUtilities.getTypedefReplacement(typedef, true)`
    fn typedef_replacement(&mut self, td: Id) -> Id {
        let (name, cat, refd) = match &self.dtm.dt(td).kind {
            Kind::Typedef { base } => (self.dtm.dt(td).name.clone(), self.dtm.dt(td).cat, *base),
            _ => return td,
        };
        let direct = dtm::typedef_remap(&name).filter(|b| {
            if self.dtm.len(td) != b.len() {
                return false;
            }
            let base = self.dtm.base_of(refd);
            match (b.int_signed(), &self.dtm.dt(base).kind) {
                (Some(s), Kind::Builtin(x)) => x.int_signed() == Some(s),
                (Some(_), _) => false,
                (None, _) => matches!(b, B::Char(..)),
            }
        });
        if let Some(b) = direct {
            if b.name() == name {
                return self.dtm.builtin(b);
            }
        }
        if let Kind::Typedef { .. } = self.dtm.dt(refd).kind {
            let r = self.typedef_replacement(refd);
            if r != refd {
                return self.dtm.new_pre(name, cat, Kind::Typedef { base: refd });
            }
        }
        if let Some(b) = direct {
            let bid = self.dtm.builtin(b);
            if bid != refd {
                return self.dtm.new_pre(name, cat, Kind::Typedef { base: bid });
            }
        }
        td
    }

    fn cache_offset(&mut self, die: u32, dt: Id) {
        if let Id::Db(_) = dt {
            self.offset_to_dt.insert(die, dt);
        }
    }
    fn save_src(&mut self, dt: Id, dsi: &Option<Dsi>) {
        let (Id::Db(i), Some(d)) = (dt, dsi) else { return };
        if d.file.is_empty() || d.file.contains("built-in") || self.src.contains_key(&i) {
            return;
        }
        self.src.insert(i, d.clone());
        self.src_order.push(i);
    }

    /// `DWARFDataTypeManager.getDataType(diea, default)`
    fn data_type(&mut self, g: Option<&Agg>, def: Option<Id>) -> Result<Option<Id>> {
        let Some(g) = g else { return Ok(def) };
        if let Some(&d) = self.offset_to_dt.get(&g[0]) {
            return Ok(Some(d));
        }
        Ok(self.do_get_data_type(g)?.or(def))
    }
    fn data_type_for_variable(&mut self, g: Option<&Agg>) -> Result<Id> {
        let void = self.dtm.builtin(B::Void);
        let t = self.data_type(g, Some(void))?.unwrap_or(void);
        Ok(if let Kind::FuncDef { .. } = self.dtm.dt(t).kind { self.dtm.db_pointer(t, -1) } else { t })
    }

    /// `doGetDataType`: import one DIE's type and resolve it into the program
    fn do_get_data_type(&mut self, g: &Agg) -> Result<Option<Id>> {
        let void = self.dtm.builtin(B::Void);
        let mut imp = Imp {
            ddts: vec![Ddt { dt: void, dsi: None, offsets: vec![u32::MAX] }],
            by_die: HashMap::new(),
            by_inst: HashMap::new(),
            rec: HashMap::new(),
        };
        let r = self.get_dt(&mut imp, Some(g), None);
        let pre = match r {
            Ok(Some(p)) => p,
            Ok(None) => {
                self.dtm.clear_pre();
                return Ok(None);
            }
            Err(e) => {
                self.dtm.clear_pre();
                return Err(e);
            }
        };
        let pre_dt = imp.ddts[pre].dt;
        let post = self.dtm.resolve(pre_dt, Handler::Dwarf);
        if let Id::Pre(_) = pre_dt {
            let mut pairs = Vec::new();
            self.graph_pairs(pre_dt, post, &mut HashSet::new(), &mut pairs);
            for (a, b) in pairs {
                if let Some(&k) = imp.by_inst.get(&a) {
                    if imp.ddts[k].dt == a {
                        for o in imp.ddts[k].offsets.clone() {
                            if o != u32::MAX {
                                self.cache_offset(o, b);
                            }
                        }
                    }
                    let dsi = imp.ddts[k].dsi.clone();
                    self.save_src(b, &dsi);
                }
            }
        }
        self.cache_offset(g[0], post);
        let dsi = imp.ddts[pre].dsi.clone();
        self.save_src(post, &dsi);
        self.dtm.clear_pre();
        Ok(Some(post))
    }

    /// `DataTypeGraphComparator.compare(pre, post)`: the pairs of matching parts
    fn graph_pairs(&self, a: Id, b: Id, seen: &mut HashSet<(Id, Id)>, out: &mut Vec<(Id, Id)>) {
        if !matches!(a, Id::Pre(_)) || !seen.insert((a, b)) {
            return;
        }
        out.push((a, b));
        match (&self.dtm.dt(a).kind, &self.dtm.dt(b).kind) {
            (Kind::Pointer { to: x, .. }, Kind::Pointer { to: y, .. }) => self.graph_pairs(*x, *y, seen, out),
            (Kind::Array { elem: x, .. }, Kind::Array { elem: y, .. }) => self.graph_pairs(*x, *y, seen, out),
            (Kind::Typedef { base: x }, Kind::Typedef { base: y }) => self.graph_pairs(*x, *y, seen, out),
            (Kind::Composite(x), Kind::Composite(y)) if x.comps.len() == y.comps.len() => {
                for (p, q) in x.comps.iter().zip(&y.comps) {
                    self.graph_pairs(p.ty, q.ty, seen, out);
                }
            }
            (Kind::FuncDef { ret: r1, params: p1, .. }, Kind::FuncDef { ret: r2, params: p2, .. }) => {
                self.graph_pairs(*r1, *r2, seen, out);
                if p1.len() == p2.len() {
                    for (p, q) in p1.iter().zip(p2) {
                        self.graph_pairs(p.ty, q.ty, seen, out);
                    }
                }
            }
            _ => {}
        }
    }

    // ---- DWARFDataTypeImporter

    fn record(&self, imp: &mut Imp, k: usize) {
        let dt = imp.ddts[k].dt;
        if let Id::Db(_) = dt {
            return;
        }
        imp.by_inst.insert(dt, k);
        for &o in &imp.ddts[k].offsets {
            imp.by_die.insert(o, k);
        }
    }
    fn push(&self, imp: &mut Imp, dt: Id, die: u32) -> usize {
        imp.ddts.push(Ddt { dt, dsi: None, offsets: vec![die] });
        imp.ddts.len() - 1
    }

    /// `DWARFDataTypeImporter.getDataType`
    fn get_dt(&mut self, imp: &mut Imp, g: Option<&Agg>, def: Option<usize>) -> Result<Option<usize>> {
        let Some(g) = g else { return Ok(def) };
        let die = g[0];
        if let Some(&k) = imp.by_die.get(&die) {
            return Ok(Some(k));
        }
        if let Some(&d) = self.offset_to_dt.get(&die) {
            if !self.dtm.not_yet_defined(d) {
                return Ok(Some(self.push(imp, d, die)));
            }
        }
        let c = imp.rec.entry(die).or_insert(0);
        *c += 1;
        if *c == 3 {
            *c -= 1;
            return Ok(def);
        }
        let r = match self.tag(g) {
            DW_TAG_POINTER | DW_TAG_REFERENCE | DW_TAG_RVALUE_REFERENCE => self.make_pointer(imp, g)?,
            DW_TAG_PTR_TO_MEMBER => self.make_ptr_to_member(g)?.map(|(dt, _)| self.push(imp, dt, die)),
            DW_TAG_BASE_TYPE => {
                let dni = self.get_name(g)?;
                Some(self.make_named_base(imp, dni, g, g)?)
            }
            DW_TAG_TYPEDEF => Some(self.make_typedef(imp, g)?),
            DW_TAG_UNSPECIFIED_TYPE => {
                let dni = self.get_name(g)?;
                Some(match dni.orig.as_ref().and_then(|n| self.base.get(n)).copied() {
                    Some(dt) => self.push(imp, dt, die),
                    None => VOID_DDT,
                })
            }
            DW_TAG_CONST | DW_TAG_VOLATILE | DW_TAG_RESTRICT | DW_TAG_SHARED | DW_TAG_APPLE_PTRAUTH | DW_TAG_ATOMIC => {
                let t = self.type_ref(g);
                let k = self.get_dt(imp, t.as_ref(), Some(VOID_DDT))?.unwrap_or(VOID_DDT);
                imp.ddts[k].offsets.push(die);
                Some(k)
            }
            DW_TAG_ENUMERATION => Some(self.make_enum(imp, g)?),
            DW_TAG_ARRAY => Some(self.make_array(imp, g)?),
            DW_TAG_STRUCTURE | DW_TAG_CLASS | DW_TAG_UNION => {
                let k = self.make_struct(imp, g)?;
                self.record(imp, k);
                self.finish_struct(imp, g, k)?;
                Some(k)
            }
            DW_TAG_SUBROUTINE_TYPE => self.make_funcdef(imp, g)?,
            _ => None,
        };
        if let Some(c) = imp.rec.get_mut(&die) {
            *c -= 1;
        }
        let Some(k) = r else { return Ok(def) };
        if imp.ddts[k].dsi.is_none() {
            imp.ddts[k].dsi = self.source_info(g);
        }
        self.record(imp, k);
        Ok(Some(k))
    }

    fn fixup(&mut self, imp: &Imp, k: Option<usize>) -> Option<Id> {
        let dt = imp.ddts[k?].dt;
        Some(if let Kind::FuncDef { .. } = self.dtm.dt(dt).kind { self.pointer_to(dt, -1) } else { dt })
    }
    fn pointer_to(&mut self, dt: Id, len: i32) -> Id {
        match dt {
            Id::Pre(_) => self.dtm.new_pre(String::new(), 0, Kind::Pointer { to: dt, len }),
            Id::Db(_) => self.dtm.db_pointer(dt, len),
        }
    }

    fn make_named_base(&mut self, imp: &mut Imp, dni: DName, name_src: &Agg, g: &Agg) -> Result<usize> {
        let size = self.parse_int(g, DW_AT_BYTE_SIZE, 0)?;
        let enc = self.get_unsigned(g, DW_AT_ENCODING, -1) as i32;
        let dt = self.base_type(dni.orig.as_deref(), size, enc);
        Ok(self.push(imp, dt, name_src[0]))
    }

    fn make_pointer(&mut self, imp: &mut Imp, g: &Agg) -> Result<Option<usize>> {
        let t = self.type_ref(g);
        let k = self.get_dt(imp, t.as_ref(), Some(VOID_DDT))?.unwrap_or(VOID_DDT);
        let mut size = self.parse_int(g, DW_AT_BYTE_SIZE, self.addr_size(g) as i32)?;
        if let Some(&s) = imp.by_die.get(&g[0]) {
            return Ok(Some(s));
        }
        if size == 8 {
            size = -1;
        }
        let to = imp.ddts[k].dt;
        let p = match to {
            Id::Pre(_) => self.dtm.new_pre(String::new(), 0, Kind::Pointer { to, len: size }),
            Id::Db(_) if matches!(self.dtm.dt(to).kind, Kind::Builtin(_)) => {
                self.dtm.new_pre(String::new(), 0, Kind::Pointer { to, len: size })
            }
            Id::Db(_) => self.dtm.db_pointer(to, size),
        };
        Ok(Some(self.push(imp, p, g[0])))
    }

    fn make_ptr_to_member(&mut self, g: &Agg) -> Result<Option<(Id, DName)>> {
        let dni = self.get_name(g)?;
        let (Some(t), Some(ct)) = (self.type_ref(g), self.ref_agg(g, DW_AT_CONTAINING_TYPE)) else { return Ok(None) };
        let size = self.parse_int(g, DW_AT_BYTE_SIZE, self.addr_size(g) as i32)?;
        let Some(off_t) = self.untyped(size) else {
            return Err(Error::Dwarf(format!("no offset type of size {size}")));
        };
        let target = self.name_of(&t).unwrap_or_else(|| container_name(self.tag(&t)).to_string());
        let x = format!("offset_in_{}_to_{target}", self.name_of(&ct).unwrap_or_else(|| "null".into()));
        let pcp = self.parent_cp(&dni);
        let mut dt = self.dtm.new_pre(x.clone(), pcp, Kind::Typedef { base: off_t });
        if dni.orig.is_some() {
            dt = self.dtm.new_pre(self.dni_name(&dni).to_string(), pcp, Kind::Typedef { base: dt });
        }
        Ok(Some((dt, dni)))
    }

    fn make_typedef(&mut self, imp: &mut Imp, g: &Agg) -> Result<usize> {
        let dni = self.get_name(g)?;
        let refd = self.type_ref(g);
        if let Some(r) = &refd {
            if self.tag(r) == DW_TAG_BASE_TYPE {
                return self.make_named_base(imp, dni, g, r);
            }
        }
        let k = self.get_dt(imp, refd.as_ref(), Some(VOID_DDT))?.unwrap_or(VOID_DDT);
        if let Some(&s) = imp.by_die.get(&g[0]) {
            return Ok(s);
        }
        let my_path = format!("{}/{}", self.dtm.cat_path(self.parent_cp(&dni)), self.dni_name(&dni));
        let refd_dt = imp.ddts[k].dt;
        let mut same = dtm::eq_ignore_conflict(&my_path, &self.dtm.path(refd_dt));
        if !same {
            if let Kind::Pointer { to, .. } = self.dtm.dt(refd_dt).kind {
                let mut to = to;
                if let Kind::Pointer { to: t2, .. } = self.dtm.dt(to).kind {
                    to = t2;
                }
                if let Kind::FuncDef { .. } = self.dtm.dt(to).kind {
                    same = dtm::eq_ignore_conflict(&my_path, &self.dtm.path(to));
                }
            }
        }
        if same {
            imp.ddts[k].offsets.push(g[0]);
            return Ok(k);
        }
        let pcp = self.parent_cp(&dni);
        let td = self.dtm.new_pre(self.dni_name(&dni).to_string(), pcp, Kind::Typedef { base: refd_dt });
        let r = self.typedef_replacement(td);
        Ok(self.push(imp, r, g[0]))
    }

    fn make_enum(&mut self, imp: &mut Imp, g: &Agg) -> Result<usize> {
        let dni = self.get_name(g)?;
        let mut size = self.get_unsigned(g, DW_AT_BYTE_SIZE, -1) as i32;
        if size == 0 || size == -1 {
            size = 1;
        }
        // EnumDataType.java:57-59: IllegalArgumentException, the type fails
        if !(1..=8).contains(&size) {
            return Err(Error::Dwarf(format!("unsupported enum length: {size}")));
        }
        let mut vals: Vec<(String, i64)> = Vec::new();
        for c in self.children(g, DW_TAG_ENUMERATOR) {
            let cg = self.agg(c);
            let name = self.name_of(&cg);
            let Some(v) = self
                .find(&cg, DW_AT_CONST_VALUE)
                .filter(|a| matches!(a.val, Val::Num { .. }))
                .and_then(|a| a.val.with_hint(false))
            else {
                continue;
            };
            let Some(name) = name else { continue };
            if enum_add_ok(&vals, &name, v, size) {
                vals.push((name, v));
            }
        }
        let pcp = self.parent_cp(&dni);
        let name = self.dni_name(&dni).to_string();
        for prev in self.dtm.by_base_name(pcp, &name) {
            let Kind::Enum { len, vals: pv } = self.dtm.dt(prev).kind.clone() else { continue };
            if len != size || !vals.iter().all(|(n, v)| pv.iter().find(|(m, _)| m == n).is_none_or(|(_, w)| w == v)) {
                continue;
            }
            // mergeEnumValues(prevEnum, enumDT)
            let mut merged = pv.clone();
            for (n, v) in &vals {
                match merged.iter().find(|(m, _)| m == n) {
                    Some((_, w)) if w == v => {}
                    Some(_) => break,
                    None => {
                        if !enum_add_ok(&merged, n, *v, len) {
                            break;
                        }
                        merged.push((n.clone(), *v));
                    }
                }
            }
            if let Kind::Enum { vals: dv, .. } = &mut self.dtm.dt_mut(prev).kind {
                *dv = merged;
            }
            return Ok(self.push(imp, prev, g[0]));
        }
        let r = self.dtm.add(name, pcp, Kind::Enum { len: size, vals }, Handler::Dwarf);
        Ok(self.push(imp, r, g[0]))
    }

    fn make_struct(&mut self, imp: &mut Imp, g: &Agg) -> Result<usize> {
        let dni = self.get_name(g)?;
        let size = self.get_unsigned(g, DW_AT_BYTE_SIZE, 0);
        let orig = size;
        let size = if !(0..=i32::MAX as i64).contains(&size) { 0 } else { size as i32 };
        let union = self.tag(g) == DW_TAG_UNION;
        let decl = self.get_bool(g, DW_AT_DECLARATION);
        let pcp = self.parent_cp(&dni);
        let c = Composite {
            union,
            len: if union { 0 } else { size },
            packed: false,
            align: 1,
            comps: Vec::new(),
            description: String::new(),
        };
        let s = self.dtm.new_pre(self.dni_name(&dni).to_string(), pcp, Kind::Composite(c));
        if !decl && orig == 0 {
            self.dtm.pack(s);
        }
        let k = self.push(imp, s, g[0]);
        imp.ddts[k].dsi = self.source_info(g);
        Ok(k)
    }

    fn finish_struct(&mut self, imp: &mut Imp, g: &Agg, k: usize) -> Result<()> {
        let s = imp.ddts[k].dt;
        let union = matches!(&self.dtm.dt(s).kind, Kind::Composite(c) if c.union);
        if union {
            self.populate_union(imp, g, s)?;
        } else {
            let size = self.get_unsigned(g, DW_AT_BYTE_SIZE, 0);
            if !(0..=i32::MAX as i64).contains(&size) {
                return Ok(());
            }
            self.populate_struct(imp, g, s, DW_TAG_MEMBER)?;
            self.populate_struct(imp, g, s, DW_TAG_INHERITANCE)?;
            self.remove_shrinkage(s);
        }
        self.pack_if_possible(s);
        Ok(())
    }

    fn populate_union(&mut self, imp: &mut Imp, g: &Agg, u: Id) -> Result<()> {
        let usize_ = self.get_unsigned(g, DW_AT_BYTE_SIZE, -1);
        for c in self.children(g, DW_TAG_MEMBER) {
            let cg = self.agg(c);
            if self.has(&cg, DW_AT_EXTERNAL) {
                continue;
            }
            let bits = self.parse_int(&cg, DW_AT_BIT_SIZE, -1)?;
            let ncomps = match &self.dtm.dt(u).kind {
                Kind::Composite(x) => x.comps.len(),
                _ => 0,
            };
            let name = self.name_of(&cg).unwrap_or_else(|| format!("field_{ncomps}"));
            let t = self.type_ref(&cg);
            let ck = self.get_dt(imp, t.as_ref(), None)?;
            let Some(mut dt) = self.fixup(imp, ck) else { continue };
            let mut comment = None;
            let len = self.dtm.len(dt);
            if usize_ != -1 && bits == -1 && len as i64 > usize_ {
                if len > 1 {
                    comment = Some(format!("Data type larger than union's declared size: {}", self.dtm.name(dt)));
                    dt = self.dtm.builtin(B::Undefined(1));
                } else {
                    continue;
                }
            }
            if bits != -1 {
                if !self.dtm.valid_bitfield_base(dt) {
                    continue;
                }
                self.dtm.union_add(u, dt, Some(bits), Some(name), None);
            } else {
                self.dtm.union_add(u, dt, None, Some(name), comment);
            }
        }
        let len = self.dtm.len(u);
        if (len as i64) < usize_ {
            let n = usize_ as i32;
            let pad = match dtm::undefined(n) {
                B::Default if n > 8 => {
                    let d = self.dtm.builtin(B::Undefined(1));
                    self.dtm.new_pre(String::new(), 0, Kind::Array { elem: d, count: n, elem_len: 1 })
                }
                b => self.dtm.builtin(b),
            };
            self.dtm.union_add(
                u,
                pad,
                None,
                None,
                Some("Automatically generated padding to match DWARF declared size".into()),
            );
        }
        Ok(())
    }

    fn unpadded_len(&self, dt: Id) -> i32 {
        let b = self.dtm.base_of(dt);
        if let Kind::Composite(c) = &self.dtm.dt(b).kind {
            if !c.union {
                if let Some(l) = c.comps.last() {
                    return l.offset + l.len;
                }
            }
        }
        if self.dtm.zero_len(b) {
            0
        } else {
            self.dtm.len(b)
        }
    }

    fn populate_struct(&mut self, imp: &mut Imp, g: &Agg, s: Id, tag: u16) -> Result<()> {
        for c in self.children(g, tag) {
            let cg = self.agg(c);
            if self.has(&cg, DW_AT_EXTERNAL) {
                continue;
            }
            let bits = self.parse_int(&cg, DW_AT_BIT_SIZE, -1)?;
            let t = self.type_ref(&cg);
            let ck = self.get_dt(imp, t.as_ref(), None)?;
            let Some(dt) = self.fixup(imp, ck) else { continue };
            let ndef = match &self.dtm.dt(s).kind {
                Kind::Composite(x) => x.comps.len(),
                _ => 0,
            };
            let name = self.name_of(&cg).unwrap_or_else(|| {
                if self.tag(&cg) == DW_TAG_INHERITANCE {
                    format!("super_{}", self.dtm.name(dt))
                } else {
                    format!("field_{ndef}")
                }
            });
            let has_off = self.has(&cg, DW_AT_DATA_MEMBER_LOCATION);
            let off = if has_off {
                match self.parse_member_offset(&cg) {
                    Ok(o) => o,
                    Err(_) => continue,
                }
            } else {
                0
            };
            let slen = match &self.dtm.dt(s).kind {
                Kind::Composite(x) => x.len,
                _ => 0,
            };
            if bits != -1 {
                if !self.dtm.valid_bitfield_base(dt) {
                    continue;
                }
                let container = if has_off {
                    let bs = self.parse_int(&cg, DW_AT_BYTE_SIZE, -1)?;
                    if bs <= 0 {
                        self.dtm.len(dt)
                    } else {
                        bs
                    }
                } else {
                    slen
                };
                // int arithmetic, which wraps in Java (DWARFDataTypeImporter.populateStubStruct)
                let cbits = container.wrapping_mul(8);
                let mut bo = self.parse_int(&cg, DW_AT_DATA_BIT_OFFSET, -1)?;
                let gbo = if bo == -1 {
                    bo = self.parse_int(&cg, DW_AT_BIT_OFFSET, -1)?;
                    cbits.wrapping_sub(bo).wrapping_sub(bits)
                } else {
                    bo.wrapping_sub(off.wrapping_mul(8))
                };
                if bo < 0 || gbo < 0 || gbo >= cbits {
                    continue;
                }
                self.dtm.struct_insert_bitfield(s, off, container, gbo, dt, bits, Some(name));
            } else {
                let clen = self.unpadded_len(dt);
                if off.wrapping_add(clen) > slen {
                    continue;
                }
                // DataTypeComponent.usesZeroLengthComponent: not a not-yet-defined composite
                if self.dtm.zero_len(dt) && !self.dtm.not_yet_defined(dt) {
                    if !self.dtm.undefined_or_zero_at(s, off) {
                        continue;
                    }
                    self.dtm.struct_insert_zero(s, off, dt, Some(name));
                } else {
                    if !self.dtm.undefined_at(s, off) {
                        continue;
                    }
                    self.dtm.struct_replace(s, off, dt, clen, Some(name));
                }
            }
        }
        Ok(())
    }

    fn remove_shrinkage(&mut self, s: Id) {
        let Kind::Composite(c) = self.dtm.dt(s).kind.clone() else { return };
        let mut comps = c.comps.clone();
        for i in 0..comps.len() {
            let x = &comps[i];
            if x.bf.is_some() || self.dtm.zero_len(x.ty) {
                continue;
            }
            let next = if i + 1 < comps.len() { comps[i + 1].offset } else { c.len };
            let empty = next - (x.offset + x.len);
            let dl = self.dtm.len(x.ty);
            if x.len < dl && empty > 0 {
                comps[i].len = (next - comps[i].offset).min(dl);
            }
        }
        if let Kind::Composite(c) = &mut self.dtm.dt_mut(s).kind {
            c.comps = comps;
        }
    }

    /// `DWARFUtil.packCompositeIfPossible`
    fn pack_if_possible(&mut self, s: Id) {
        let Kind::Composite(c) = self.dtm.dt(s).kind.clone() else { return };
        if self.dtm.zero_len(s) || c.comps.is_empty() {
            return;
        }
        let copy = self.dtm.new_pre(String::new(), 0, Kind::Composite(c.clone()));
        self.dtm.pack(copy);
        let Kind::Composite(p) = self.dtm.dt(copy).kind.clone() else { return };
        if self.dtm.len(copy) != self.dtm.len(s) || p.comps.len() != c.comps.len() {
            return;
        }
        for (a, b) in c.comps.iter().zip(&p.comps) {
            if a.offset != b.offset || a.len != b.len || a.bf.is_some() != b.bf.is_some() {
                return;
            }
            if let (Some(x), Some(y)) = (a.bf, b.bf) {
                if x.bit_offset != y.bit_offset || x.bit_size != y.bit_size {
                    return;
                }
            }
        }
        self.dtm.pack(s);
    }

    fn make_array(&mut self, imp: &mut Imp, g: &Agg) -> Result<usize> {
        let t = self.type_ref(g);
        let ek = self.get_dt(imp, t.as_ref(), Some(VOID_DDT))?.unwrap_or(VOID_DDT);
        if let Some(&s) = imp.by_die.get(&g[0]) {
            return Ok(s);
        }
        if ek == VOID_DDT {
            let u = self.unknown_array();
            return Ok(self.push(imp, u, g[0]));
        }
        let elem = self.fixup(imp, Some(ek)).unwrap();
        let explicit = self.get_unsigned(g, DW_AT_BYTE_SIZE, -1);
        let edt = imp.ddts[ek].dt;
        if self.zero_byte(edt) || explicit == 0 {
            let el = self.elem_len(elem);
            let a = self.dtm.new_pre(String::new(), 0, Kind::Array { elem, count: 0, elem_len: el });
            return Ok(self.push(imp, a, g[0]));
        }
        let mut dims = Vec::new();
        for sr in self.children(g, DW_TAG_SUBRANGE) {
            let sg = self.agg(sr);
            let mut n: i64 = -1;
            if self.has(&sg, DW_AT_COUNT) {
                n = self.parse_unsigned_long(&sg, DW_AT_COUNT, 0xbadbeef).unwrap_or(-1);
            } else if self.has(&sg, DW_AT_UPPER_BOUND) {
                match self.parse_unsigned_long(&sg, DW_AT_UPPER_BOUND, 0xbadbeef) {
                    Ok(ub) if ub == 0xffff_ffff || ub == -1 => {}
                    Ok(ub) => n = ub.wrapping_add(1),
                    Err(_) => {}
                }
            }
            if n == -1 {
                n = 0;
            } else if n > i32::MAX as i64 || n < -1 {
                n = 1;
            }
            dims.push(n as i32);
        }
        let mut dt = elem;
        for &n in dims.iter().rev() {
            let el = self.elem_len(dt);
            dt = self.dtm.new_pre(String::new(), 0, Kind::Array { elem: dt, count: n, elem_len: el });
        }
        Ok(self.push(imp, dt, g[0]))
    }

    fn elem_len(&self, dt: Id) -> i32 {
        if self.dtm.zero_len(dt) {
            0
        } else {
            self.dtm.aligned_len(dt)
        }
    }

    /// `DWARFUtil.isZeroByteDataType`
    fn zero_byte(&self, dt: Id) -> bool {
        if matches!(self.dtm.dt(dt).kind, Kind::Builtin(B::Void)) {
            return true;
        }
        let mut d = dt;
        if !self.dtm.zero_len(d) {
            while let Kind::Array { elem, .. } = self.dtm.dt(d).kind {
                d = elem;
            }
        }
        self.dtm.zero_len(d)
    }

    /// `getUnspecifiedArrayType`: `/DWARF/.unknown_array`
    fn unknown_array(&mut self) -> Id {
        if let Some(d) = self.dtm.lookup(self.dwarf_cat, ".unknown_array") {
            return d;
        }
        let c =
            Composite { union: false, len: 0, packed: false, align: 1, comps: Vec::new(), description: String::new() };
        let p = self.dtm.new_pre(".unknown_array".into(), self.dwarf_cat, Kind::Composite(c));
        self.dtm.pack(p);
        self.dtm.resolve(p, Handler::Default)
    }

    fn make_funcdef(&mut self, imp: &mut Imp, g: &Agg) -> Result<Option<usize>> {
        let dni = self.get_name(g)?;
        let pcp = self.parent_cp(&dni);
        let void = self.dtm.builtin(B::Void);
        let f = self.dtm.new_pre(
            self.dni_name(&dni).to_string(),
            pcp,
            Kind::FuncDef { ret: void, params: Vec::new(), varargs: false, noreturn: false, cc: None },
        );
        let k = self.push(imp, f, g[0]);
        self.record(imp, k);
        let t = self.type_ref(g);
        let rk = self.get_dt(imp, t.as_ref(), Some(VOID_DDT))?.unwrap_or(VOID_DDT);
        let mut this = false;
        let mut params = Vec::new();
        for p in self.param_list(g) {
            let name = self.name_of(&p);
            let t = self.type_ref(&p);
            let pk = self.get_dt(imp, t.as_ref(), None)?;
            let dt = self.fixup(imp, pk);
            let Some(dt) = dt.filter(|&d| self.dtm.len(d) > 0) else { return Ok(None) };
            params.push(Param { name, ty: dt });
            this |= self.is_this_param(&p);
        }
        let ret = imp.ddts[rk].dt;
        let noreturn = self.get_bool(g, DW_AT_NORETURN);
        let varargs = !self.children(g, DW_TAG_UNSPECIFIED_PARAMETERS).is_empty();
        let cc = this.then(|| "__thiscall".to_string());
        let anon = dni.orig.is_none();
        if let Kind::FuncDef { ret: r, params: ps, varargs: v, noreturn: n, cc: c } = &mut self.dtm.dt_mut(f).kind {
            *r = ret;
            *ps = params;
            *v = varargs;
            *n = noreturn;
            *c = cc;
        }
        if anon {
            let m = self.mangled_signature(f);
            self.dtm.dt_mut(f).name = m;
        }
        Ok(Some(k))
    }

    /// `DataTypeNamingUtil.generateMangledSignature`
    fn mangled_signature(&self, f: Id) -> String {
        let Kind::FuncDef { ret, params, varargs, noreturn, cc } = &self.dtm.dt(f).kind else { return String::new() };
        let m = |id: Id| dtm::strip_conflict(&self.dtm.name(id)).replace(' ', "_").replace('*', "ptr");
        let mut s = String::from("_func");
        if *noreturn {
            s.push_str("_noreturn");
        }
        if let Some(c) = cc {
            s.push('_');
            s.push_str(c);
        }
        s.push('_');
        s.push_str(&m(*ret));
        for p in params {
            s.push('_');
            s.push_str(&m(p.ty));
        }
        if *varargs {
            s.push_str("_varargs");
        }
        s
    }

    /// `DWARFUtil.isThisParam`
    fn is_this_param(&self, p: &Agg) -> bool {
        let name = self.name_of(p);
        if self.get_bool(p, DW_AT_ARTIFICIAL) || name.as_deref() == Some("this") {
            return true;
        }
        let Some(func) = self.parent_agg(p) else { return false };
        if let Some(op) = self.find(&func, DW_AT_OBJECT_POINTER).and_then(|a| a.val.unsigned()) {
            if p.iter().any(|&d| self.off(d) == op) {
                return true;
            }
        }
        let class = self.parent_agg(&func);
        if name.is_none() {
            if let Some(c) = class.filter(|c| is_structure(self.tag(c))) {
                if let Some(t) = self.type_ref(p) {
                    return self.tag(&t) == DW_TAG_POINTER && self.type_ref(&t).is_some_and(|x| x[0] == c[0]);
                }
            }
        }
        false
    }

    // ---- DWARFFunctionImporter

    fn pc_ranges(&self, g: &Agg) -> Result<Vec<(u64, u64)>> {
        if let Some(lo) = self.find(g, DW_AT_LOW_PC) {
            if let Some(low) = lo.val.unsigned() {
                if !(low == 0 && self.addr0_tombstone()) {
                    let high = match self.find(g, DW_AT_HIGH_PC) {
                        Some(h) if h.form == 0x01 => h.val.unsigned().unwrap_or(low),
                        Some(h) => match h.val.unsigned() {
                            Some(v) => low.wrapping_add(v),
                            None => low,
                        },
                        None => low,
                    };
                    if high != low {
                        return Ok(vec![(low, high)]);
                    }
                }
            }
        }
        if let Some(r) = self.find(g, DW_AT_RANGES) {
            let off = r.val.unsigned().ok_or(Error::Dwarf("bad DW_AT_ranges".into()))?;
            let cu = self.dw.cu_of(r.die);
            if self.dw.cus[cu].version >= 5 {
                return Err(Error::Dwarf("DWARF 5 range lists not ported".into()));
            }
            return self.dw.ranges_v4(off, cu);
        }
        Ok(Vec::new())
    }
    fn addr0_tombstone(&self) -> bool {
        !self.is_exec(self.fixup)
    }
    fn is_exec(&self, a: u64) -> bool {
        self.exec.iter().any(|&(s, e)| s <= a && a < e)
    }

    /// `markAllChildrenAsProcessed` (recursive in Java; iterated here)
    fn mark_children(&self, die: u32, done: &mut HashSet<u32>) {
        let mut stack = vec![die];
        while let Some(d) = stack.pop() {
            for c in self.dw.children(d) {
                done.insert(c);
                stack.push(c);
            }
        }
    }

    fn import_functions(&mut self) -> Vec<Func> {
        let mut done: HashSet<u32> = HashSet::new();
        let mut addrs: HashSet<u64> = HashSet::new();
        let mut dups: HashSet<u64> = HashSet::new();
        let mut funcs = Vec::new();
        for i in 0..self.dw.offsets.len() as u32 {
            if self.dw.has_ref[i as usize] {
                continue;
            }
            let g = match self.dw.tags[i as usize] {
                DW_TAG_SUBPROGRAM => self.agg(i),
                DW_TAG_CALL_SITE | DW_TAG_GNU_CALL_SITE => {
                    let g = self.agg(i);
                    if g.len() == 1 {
                        continue;
                    }
                    g[1..].to_vec()
                }
                _ => continue,
            };
            // DWARFFunctionImporter.java:109-143: a function that fails is logged and skipped
            match self.process_subprogram(&g, &mut done, &mut addrs, &mut dups) {
                Ok(Some(f)) => funcs.push(f),
                Ok(None) => {}
                Err(e) => self
                    .dw
                    .warnings
                    .push(format!("Error when processing DWARF information for DIE {:x}: {e}", self.off(g[0]))),
            }
        }
        // a later DIE at a function's address may append `DWARF alternate signature: `
        // (DWARFFunctionImporter.java:169-176, 223-235), which compares with the program's signature
        for f in &mut funcs {
            if dups.contains(&f.addr) {
                f.plate = Err(());
            }
        }
        funcs
    }

    fn process_subprogram(
        &mut self,
        g: &Agg,
        done: &mut HashSet<u32>,
        addrs: &mut HashSet<u64>,
        dups: &mut HashSet<u64>,
    ) -> Result<Option<Func>> {
        if !done.insert(g[0]) {
            return Ok(None);
        }
        // DWARFFunction.read
        if self.has(g, DW_AT_DECLARATION) && g.len() == 1 {
            self.mark_children(g[0], done);
            return Ok(None);
        }
        let body = self.pc_ranges(g)?;
        let Some(&(first, _)) = body.first() else {
            self.mark_children(g[0], done);
            return Ok(None);
        };
        let addr = first.wrapping_add(self.fixup);
        let dni = self.get_name(g)?;
        let noreturn = self.get_bool(g, DW_AT_NORETURN);
        let t = self.type_ref(g);
        let ret = self.data_type_for_variable(t.as_ref())?;
        let mut params = Vec::new();
        for (i, p) in self.param_list(g).into_iter().enumerate() {
            let pd = self.get_name(&p)?;
            let t = self.type_ref(&p);
            let ty = self.data_type_for_variable(t.as_ref())?;
            let this = i == 0 && self.is_this_param(&p);
            params.push((pd, ty, this));
        }
        let varargs = !self.children(g, DW_TAG_UNSPECIFIED_PARAMETERS).is_empty();
        if !addrs.insert(addr) {
            dups.insert(addr);
            self.mark_children(g[0], done);
            return Ok(None);
        }
        // processFuncChildren: only call sites start other functions; locals are not ported
        self.func_children(g[0], done, addrs, dups)?;
        if !self.is_exec(addr) {
            return Ok(None);
        }
        // origFuncDef = asFunctionDefinition(true) before the fixups (DWARFFunctionImporter.java:168)
        let orig_params: Vec<(String, Id)> =
            params.iter().map(|(pd, ty, _)| (self.dni_name(pd).to_string(), *ty)).collect();
        // fixups: ThisCallingConvention, then ParamName (NameDeduper)
        let mut cc = None;
        if let Some((pd, _, true)) = params.first() {
            let pd = pd.clone();
            params[0].0 = self.replace_name(&pd, "this", Some("this".into()), Sym::Parameter);
            cc = Some("__thiscall".to_string());
        }
        let reserved: HashSet<String> =
            params.iter().filter(|p| p.0.orig.is_some()).map(|p| self.dni_name(&p.0).to_string()).collect();
        let mut used: HashSet<String> = HashSet::new();
        let mut names = Vec::new();
        for (pd, ..) in &params {
            let n = self.dni_name(pd).to_string();
            if used.insert(n.clone()) {
                names.push(n);
                continue;
            }
            let mut k = 0;
            let mut m = n.clone();
            while used.contains(&m) || reserved.contains(&m) {
                k += 1;
                m = format!("{n}_{k}");
            }
            used.insert(m.clone());
            names.push(m);
        }
        // decorateFunctionWithDWARFInfo (DWARFFunctionImporter.java:238-323) with the default
        // options: the original name if it changed, the original prototype if the fixups changed
        // it, and the body ranges of a function of more than one (not written here)
        let plate = if body.len() > 1 || self.has_below(g[0], &[DW_TAG_VARIABLE, DW_TAG_LABEL]) {
            Err(())
        } else {
            let name = self.dni_name(&dni).to_string();
            let mut plate: Option<String> = None;
            if let Some(o) = dni.orig.as_deref().filter(|o| *o != name) {
                append_comment(&mut plate, "DWARF original name: ", o);
            }
            let new_params: Vec<(String, Id)> = names.iter().cloned().zip(params.iter().map(|p| p.1)).collect();
            let orig = self.prototype_string(None, ret, &name, &orig_params, varargs, noreturn);
            if self.prototype_string(cc.as_deref(), ret, &name, &new_params, varargs, noreturn) != orig {
                append_comment(&mut plate, "DWARF original prototype: ", &orig);
            }
            // a type renamed `.conflict` here: on Hatred Java's comment has the plain name (11 of
            // 11), when Java names it so was not traced
            match orig.contains(".conflict") {
                true => Err(()),
                false => Ok(plate),
            }
        };
        // createFuncSignatures: the function definition data type
        let pcp = self.parent_cp(&dni);
        let fparams =
            params.iter().zip(&names).map(|((_, ty, _), n)| Param { name: Some(n.clone()), ty: *ty }).collect();
        let fd = self.dtm.add(
            self.dni_name(&dni).to_string(),
            pcp,
            Kind::FuncDef { ret, params: fparams, varargs, noreturn, cc: None },
            Handler::Dwarf,
        );
        self.dtm.clear_pre();
        self.cache_offset(g[0], fd);
        let mut dsi = self.source_info(g);
        if dsi.is_none() {
            if let Some(dp) = self.decl_parent(g) {
                dsi = self.source_info(&dp);
            }
        }
        self.save_src(fd, &dsi);
        let mut qual: Vec<String> = Vec::new();
        let mut n = self.ns[dni.ns as usize].parent;
        while n != 0 {
            qual.push(self.ns[n as usize].name.clone());
            n = self.ns[n as usize].parent;
        }
        qual.reverse();
        qual.push(self.dni_name(&dni).to_string());
        let mut fparams: Vec<(String, Id)> = names.into_iter().zip(params).map(|(n, (_, t, _))| (n, t)).collect();
        // The return's storage is always dynamic (DWARF gives none, `updateFunctionSignature`):
        // x86-64-gcc.cspec's default prototype (`__thiscall` is not in it) has two output rules
        // (x86-64-gcc.cspec:105-112): up to 16 bytes `join_dual_class`, else `hidden_return`
        // (`__return_storage_ptr__` first).
        // ponytail: the parameters' `convert_to_ptr` needs the FORMAL commit mode, which needs
        // storage (not ported)
        let mut ret = ret;
        let rl = self.dtm.len(ret);
        let void = matches!(self.dtm.dt(self.dtm.base_of(ret)).kind, Kind::Builtin(B::Void));
        if rl > 16 || (!void && !self.join_dual_class(ret)) {
            ret = self.dtm.db_pointer(ret, -1);
            fparams.insert(0, ("__return_storage_ptr__".into(), ret));
        }
        // a default parameter name (`param_<n>`) is shown as the default name of its ordinal,
        // counted after the auto-parameters (`this`, `__return_storage_ptr__`)
        let autos = fparams.iter().take_while(|p| p.0 == "this" || p.0 == "__return_storage_ptr__").count();
        for (i, p) in fparams.iter_mut().enumerate().skip(autos) {
            if p.0.strip_prefix("param_").is_some_and(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit())) {
                p.0 = format!("param_{}", i - autos + 1);
            }
        }
        Ok(Some(Func { addr, name: qual.join("::"), cc, ret, params: fparams, varargs, noreturn, plate }))
    }

    /// `MultiSlotDualAssign.assignAddress` for x86-64-gcc.cspec's output (MultiSlotDualAssign.java:236-304:
    /// tiles of 8 bytes, RAX/RDX and XMM0_Qa/XMM1_Qa, no stack, not `fillalternate`): whether a
    /// return of up to 16 bytes binds to registers. With two registers of each class and at most
    /// two tiles, it fails only on the primitives: invalid, none, holes, or a tile no primitive
    /// fits (`getTileClass`).
    fn join_dual_class(&self, dt: Id) -> bool {
        let Some(prims) = self.primitives(dt, 0, 1024) else { return false };
        if prims.p.is_empty() || prims.holes {
            return false;
        }
        let (size, tile) = (self.dtm.len(dt), 8);
        let (mut left, mut i) = (size, 0);
        while left > 0 {
            // getTileClass (MultiSlotDualAssign.java:181-216)
            let (off, mut count) = (size - left, 0);
            while let Some(e) = prims.p.get(i) {
                if e.off < off {
                    return false;
                }
                if e.off >= off + tile {
                    break;
                }
                if e.off + e.len > off + tile {
                    return false;
                }
                count += 1;
                i += 1;
            }
            if count == 0 {
                return false;
            }
            left -= tile;
        }
        true
    }

    /// `PrimitiveExtractor(dt, false, false, offset, max)` (PrimitiveExtractor.java): `None` =
    /// not valid.
    fn primitives(&self, dt: Id, offset: i32, max: usize) -> Option<Prims> {
        let mut r = Prims { p: Vec::new(), holes: false };
        self.extract(dt, max, offset, &mut r).then_some(r)
    }
    fn extract(&self, dt: Id, max: usize, mut offset: i32, r: &mut Prims) -> bool {
        // TypeDef.getBaseDataType follows the chain of typedefs
        let dt = self.dtm.base_of(dt);
        let prim = |r: &mut Prims, off: i32, len: i32, alen: i32, float: bool| {
            if r.p.len() >= max {
                return false;
            }
            r.p.push(Prim { off, len, alen, float });
            true
        };
        match &self.dtm.dt(dt).kind {
            Kind::Builtin(_)
            | Kind::Pointer { .. }
            | Kind::Enum { .. }
            | Kind::FuncDef { .. }
            | Kind::Typedef { .. } => {
                let float = matches!(self.dtm.dt(dt).kind, Kind::Builtin(B::Float(..)));
                prim(r, offset, self.dtm.len(dt), self.dtm.aligned_len(dt), float)
            }
            Kind::Array { elem, count, .. } => {
                for _ in 0..*count {
                    if !self.extract(*elem, max, offset, r) {
                        return false;
                    }
                    offset = offset.wrapping_add(self.dtm.aligned_len(*elem));
                }
                true
            }
            Kind::Composite(c) if c.union => {
                // handleUnion
                let Some(first) = c.comps.first() else { return false };
                let Some(mut common) = self.primitives(first.ty, offset + first.offset, max) else { return false };
                for f in &c.comps[1..] {
                    let Some(next) = self.primitives(f.ty, offset + f.offset, max) else { return false };
                    match common_refinement(&common.p, &next.p) {
                        Some(p) => common.p = p,
                        None => return false,
                    }
                }
                if r.p.len() + common.p.len() > max {
                    return false;
                }
                r.p.extend(common.p);
                true
            }
            Kind::Composite(c) => {
                let mut expected = offset;
                for comp in &c.comps {
                    let cur = comp.offset + offset;
                    // a bitfield's BitFieldDataType: TYPE_UNKNOWN, its storage size, its base's alignment
                    let (alen, align) = match comp.bf {
                        Some(_) => (comp.len, self.dtm.alignment(comp.ty)),
                        None => (self.dtm.aligned_len(comp.ty), self.dtm.alignment(comp.ty)),
                    };
                    if !c.packed {
                        let rem = expected % align;
                        if rem != 0 {
                            expected += align - rem;
                        }
                        if expected != cur {
                            r.holes = true;
                        }
                    }
                    let ok = match comp.bf {
                        Some(_) => prim(r, cur, comp.len, comp.len, false),
                        None => self.extract(comp.ty, max, cur, r),
                    };
                    if !ok {
                        return false;
                    }
                    expected = cur + alen;
                }
                true
            }
        }
    }

    /// `processFuncChildren` with `processLexicalBlock` / `processInlinedSubroutine`, in Java's
    /// order (Java recurses per nesting level; iterated here). A call site's failure fails the
    /// enclosing function, as Java's exception does.
    fn func_children(
        &mut self,
        die: u32,
        done: &mut HashSet<u32>,
        addrs: &mut HashSet<u64>,
        dups: &mut HashSet<u64>,
    ) -> Result<()> {
        let mut stack = vec![(die, self.dw.children(die).collect::<Vec<_>>().into_iter())];
        while let Some((parent, it)) = stack.last_mut() {
            let parent = *parent;
            let Some(c) = it.next() else {
                stack.pop();
                continue;
            };
            match self.dw.tags[c as usize] {
                DW_TAG_LEXICAL_BLOCK | DW_TAG_INLINED_SUBROUTINE => {
                    if done.insert(c) {
                        stack.push((c, self.dw.children(c).collect::<Vec<_>>().into_iter()));
                    }
                }
                DW_TAG_CALL_SITE | DW_TAG_GNU_CALL_SITE => {
                    // Java passes the enclosing function's aggregate without its head here
                    let g = self.agg(parent);
                    if g.len() > 1 {
                        self.process_subprogram(&g[1..].to_vec(), done, addrs, dups)?;
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Whether a DIE below `die` has one of `tags`.
    fn has_below(&self, die: u32, tags: &[u16]) -> bool {
        let mut stack: Vec<u32> = self.dw.children(die).collect();
        while let Some(c) = stack.pop() {
            if tags.contains(&self.dw.tags[c as usize]) {
                return true;
            }
            stack.extend(self.dw.children(c));
        }
        false
    }

    /// `FunctionDefinitionDataType.getPrototypeString(true)` (FunctionDefinitionDataType.java:261-295;
    /// no calling convention is `unknown`, not shown)
    fn prototype_string(
        &self,
        cc: Option<&str>,
        ret: Id,
        name: &str,
        params: &[(String, Id)],
        varargs: bool,
        noreturn: bool,
    ) -> String {
        let mut s = String::new();
        if noreturn {
            s.push_str("noreturn ");
        }
        s.push_str(&self.dtm.name(ret));
        s.push(' ');
        if let Some(cc) = cc {
            s.push_str(cc);
            s.push(' ');
        }
        s.push_str(name);
        s.push('(');
        for (i, (n, t)) in params.iter().enumerate() {
            let _ = write!(s, "{} {n}", self.dtm.name(*t));
            if i + 1 < params.len() || varargs {
                s.push_str(", ");
            }
        }
        if varargs {
            s.push_str("...");
        } else if params.is_empty() {
            s.push_str("void");
        }
        s.push(')');
        s
    }

    // ---- DWARFImporter.moveTypesIntoSourceFolders

    fn move_types(&mut self) {
        let order = self.src_order.clone();
        for id in order {
            let dt = Id::Db(id);
            if matches!(self.dtm.dt(dt).kind, Kind::Pointer { .. } | Kind::Array { .. } | Kind::Builtin(_)) {
                continue;
            }
            let file = self.src[&id].file.clone();
            let new_root = self.dtm.cat(self.dwarf_cat, &file);
            let orig = self.dtm.dt(dt).cat;
            let Some(new_cp) = self.rehome(self.uncat, new_root, orig) else { continue };
            if !self.dtm.move_to(id, new_cp) {
                continue;
            }
            if let Kind::Composite(c) = self.dtm.dt(dt).kind.clone() {
                let name = self.dtm.dt(dt).name.clone();
                let orig_ns = self.dtm.cat(orig, &name);
                let dest_ns = self.dtm.cat(new_cp, &name);
                for x in &c.comps {
                    if x.bf.is_some() {
                        continue;
                    }
                    let mut t = x.ty;
                    while let Kind::Pointer { to: n, .. } | Kind::Array { elem: n, .. } = self.dtm.dt(t).kind {
                        t = n;
                    }
                    if let Id::Db(ti) = t {
                        if !matches!(self.dtm.dt(t).kind, Kind::Builtin(_))
                            && self.dtm.dt(t).cat == orig_ns
                            && !self.src.contains_key(&ti)
                        {
                            self.dtm.move_to(ti, dest_ns);
                        }
                    }
                }
            }
        }
    }
    fn rehome(&mut self, root: u32, new_root: u32, cp: u32) -> Option<u32> {
        if cp == root {
            return Some(new_root);
        }
        let mut chain = Vec::new();
        let mut c = cp;
        while c != root {
            if c == 0 {
                return None;
            }
            chain.push(self.dtm.cat_name(c).to_string());
            c = self.dtm.cat_parent(c);
        }
        Some(chain.iter().rev().fold(new_root, |p, n| self.dtm.cat(p, n)))
    }
}

/// `EnumDataType.add`: a new name, and a value the enum's size holds
fn enum_add_ok(vals: &[(String, i64)], name: &str, v: i64, len: i32) -> bool {
    if vals.iter().any(|(n, _)| n == name) {
        return false;
    }
    if len >= 8 {
        return true;
    }
    let bits = len * 8;
    let min = -(1i64 << (bits - 1));
    let max = (1i64 << bits) - 1;
    (min..=max).contains(&v)
}

/// `DWARFEncoding.getTypeName`
fn encoding_name(e: i32) -> String {
    match e {
        1 => "address".into(),
        2 => "boolean".into(),
        3 => "complex_float".into(),
        4 => "float".into(),
        5 => "signed".into(),
        6 => "signed_char".into(),
        7 => "unsigned".into(),
        8 => "unsigned_char".into(),
        0x10 => "UTF".into(),
        _ => format!("unknown_{e:x}"),
    }
}

/// Reads an ELF's DWARF and runs the import (`DWARFAnalyzer.added` with the default options).
pub fn import(data: &[u8]) -> Result<Import> {
    use object::{Object, ObjectSection, ObjectSegment};
    let file = object::File::parse(data).map_err(Error::Object)?;
    let sec = |n: &str| -> Result<std::borrow::Cow<'_, [u8]>> {
        match file.section_by_name(n) {
            Some(s) => s.uncompressed_data().map_err(Error::Object),
            None => Ok(std::borrow::Cow::Borrowed(&[][..])),
        }
    };
    let (info, abbrev, strs, line, ranges) =
        (sec(".debug_info")?, sec(".debug_abbrev")?, sec(".debug_str")?, sec(".debug_line")?, sec(".debug_ranges")?);
    if info.is_empty() {
        return Err(Error::Dwarf("no .debug_info".into()));
    }
    let dw = Dwarf::new(&info, &abbrev, &strs, &line, &ranges)?;
    // Ghidra loads an ELF whose lowest load address is 0 at 0x100000 (x86-64), and the
    // importer adds that difference to DWARF addresses (programBaseAddressFixup)
    let min_load = file.segments().map(|s| s.address()).min().unwrap_or(0);
    let fixup = if matches!(file.kind(), object::ObjectKind::Dynamic) && min_load == 0 { 0x100000 } else { 0 };
    let mut exec = Vec::new();
    for s in file.sections() {
        if let object::SectionFlags::Elf { sh_flags } = s.flags() {
            if sh_flags & 0x2 != 0 && sh_flags & 0x4 != 0 && s.size() > 0 {
                exec.push((s.address().wrapping_add(fixup), s.address().wrapping_add(fixup).wrapping_add(s.size())));
            }
        }
    }
    Ok(run(dw, fixup, exec))
}

/// The import over read sections: `fixup` = `programBaseAddressFixup`, `exec` = the executable
/// memory ranges (after the fixup).
fn run(dw: Dwarf<'_>, fixup: u64, exec: Vec<(u64, u64)>) -> Import {
    let mut dtm = Dtm::new();
    let dwarf_cat = dtm.cat(0, "DWARF");
    let uncat = dtm.cat(dwarf_cat, "_UNCATEGORIZED_");
    let mut p = Prog {
        dw,
        dtm,
        ns: vec![Ns { parent: 0, name: String::new(), cat: uncat }],
        ns_index: HashMap::new(),
        dni_cache: HashMap::new(),
        type_referers: HashMap::new(),
        offset_to_dt: HashMap::new(),
        src: HashMap::new(),
        src_order: Vec::new(),
        base: HashMap::new(),
        dwarf_cat,
        uncat,
        exec,
        fixup,
        name_depth: 0,
    };
    p.init_base_types();
    // indexDIEATypeRefs
    for i in 0..p.dw.offsets.len() as u32 {
        if p.dw.has_ref[i as usize] {
            continue;
        }
        let g = p.agg(i);
        if let Some(t) = p.type_ref(&g) {
            p.type_referers.entry(t[0]).or_default().push(i);
        }
    }
    // importAllDataTypes
    for i in 0..p.dw.offsets.len() as u32 {
        if p.dw.has_ref[i as usize] || !is_type(p.dw.tags[i as usize]) {
            continue;
        }
        let g = p.agg(i);
        // DWARFDataTypeManager.java:578-598: a type that fails is logged and skipped
        if let Err(e) = p.do_get_data_type(&g) {
            p.dw.warnings.push(format!("Error when processing DWARF information for DIE {:x}: {e}", p.off(i)));
        }
    }
    let funcs = p.import_functions();
    p.move_types();
    let warnings = std::mem::take(&mut p.dw.warnings);
    Import { dies: p.dw.offsets.len(), units: p.dw.cus.len(), dtm: p.dtm, funcs, warnings }
}

/// The dump `DumpDwarf.java` writes: one line per data type under `/DWARF` (not pointers or
/// arrays), one per function with a signature, sorted.
pub fn dump(imp: &Import) -> String {
    let d = &imp.dtm;
    let mut lines = Vec::new();
    for i in 0..d.db.len() as u32 {
        let id = Id::Db(i);
        if matches!(d.dt(id).kind, Kind::Pointer { .. } | Kind::Array { .. } | Kind::Builtin(_))
            || !d.cat_path(d.category(id)).starts_with("/DWARF")
        {
            continue;
        }
        let mut s = format!("T {}\t", d.path(id));
        match &d.dt(id).kind {
            Kind::Composite(c) => {
                let _ = write!(s, "{} len={}", if c.union { "union" } else { "struct" }, d.len(id));
                if c.packed {
                    let _ = write!(s, " packed align={}", c.align);
                }
                for x in &c.comps {
                    let _ = write!(s, " | {}:{}:{}:", x.offset, x.len, x.name.as_deref().unwrap_or("null"));
                    match x.bf {
                        Some(b) => {
                            let _ = write!(s, "{}:bf{},{}", d.path(b.base), b.bit_offset, b.bit_size);
                        }
                        None => s.push_str(&d.path(x.ty)),
                    }
                }
            }
            Kind::Typedef { base } => {
                let _ = write!(s, "typedef -> {}", d.path(*base));
            }
            Kind::Enum { len, vals } => {
                let mut v = vals.clone();
                v.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.encode_utf16().cmp(b.0.encode_utf16())));
                let _ = write!(
                    s,
                    "enum len={len} vals={}",
                    v.iter().map(|(n, x)| format!("{n}={x}")).collect::<Vec<_>>().join(",")
                );
            }
            Kind::FuncDef { ret, params, varargs, noreturn, cc } => {
                s.push_str("funcdef ");
                s.push_str(&sig(d, cc.as_deref(), *ret, *varargs, *noreturn));
                for p in params {
                    let _ = write!(s, " | {}:{}", p.name.as_deref().unwrap_or(""), d.path(p.ty));
                }
            }
            _ => {}
        }
        lines.push(s);
    }
    for f in &imp.funcs {
        let mut s = format!("F {:08x}\t{} {}", f.addr, f.name, sig(d, f.cc.as_deref(), f.ret, f.varargs, f.noreturn));
        for (n, t) in &f.params {
            let _ = write!(s, " | {n}:{}", d.path(*t));
        }
        lines.push(s);
    }
    lines.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
    let mut out = lines.join("\n");
    out.push('\n');
    out
}

/// `DWARFUtil.appendComment` with the separator `\n` (DWARFUtil.java:343-359, AppendCommentCmd):
/// a blank comment or one the comment already holds is not added.
fn append_comment(plate: &mut Option<String>, prefix: &str, comment: &str) {
    if comment.trim().is_empty() || plate.as_deref().is_some_and(|p| p.contains(comment)) {
        return;
    }
    match plate {
        Some(p) => {
            p.push('\n');
            p.push_str(prefix);
            p.push_str(comment);
        }
        None => *plate = Some(format!("{prefix}{comment}")),
    }
}

fn sig(d: &Dtm, cc: Option<&str>, ret: Id, varargs: bool, noreturn: bool) -> String {
    format!(
        "cc={} ret={}{}{}",
        cc.unwrap_or("unknown"),
        d.path(ret),
        if varargs { " varargs" } else { "" },
        if noreturn { " noreturn" } else { "" }
    )
}

#[cfg(test)]
mod tests;

/// `PrimitiveExtractor.Primitive`: offset, length, aligned length, `TYPE_FLOAT`
#[derive(Clone, Copy)]
struct Prim {
    off: i32,
    len: i32,
    alen: i32,
    float: bool,
}
/// `PrimitiveExtractor`'s list and `containsHoles`
struct Prims {
    p: Vec<Prim>,
    holes: bool,
}

/// `PrimitiveExtractor.checkOverlap`
fn check_overlap(res: &mut Vec<Prim>, small: &[Prim], mut point: usize, big: Prim) -> Option<usize> {
    let end = big.off + big.alen;
    let use_small = big.float;
    while let Some(s) = small.get(point) {
        if s.off >= end {
            break;
        }
        if s.off + s.alen > end {
            return None;
        }
        if use_small {
            res.push(*s);
        }
        point += 1;
    }
    if !use_small {
        res.push(big);
    }
    Some(point)
}

/// `PrimitiveExtractor.commonRefinement`: the refinement that replaces `first`
fn common_refinement(first: &[Prim], second: &[Prim]) -> Option<Vec<Prim>> {
    let (mut i, mut j) = (0, 0);
    let mut common = Vec::new();
    while i < first.len() && j < second.len() {
        let (a, b) = (first[i], second[j]);
        if a.off < b.off && a.off + a.alen <= b.off {
            common.push(a);
            i += 1;
        } else if b.off < a.off && b.off + b.alen <= a.off {
            common.push(b);
            j += 1;
        } else if a.alen >= b.alen {
            j = check_overlap(&mut common, second, j, a)?;
            i += 1;
        } else {
            i = check_overlap(&mut common, first, i, b)?;
            j += 1;
        }
    }
    common.extend_from_slice(&first[i..]);
    common.extend_from_slice(&second[j..]);
    Some(common)
}
