//! The part of Ghidra's data-type model the DWARF importer drives: built-ins with the x86-64
//! GCC data organization (`x86-64-gcc.cspec`), pointers, arrays, typedefs, structures and unions
//! (non-packed placement as `StructureDataType`, packing as `AlignedComponentPacker`), enums
//! and function definitions; and the program's manager (`DataTypeManagerDB.resolve` with
//! `resolveDataTypeNoSource`, `findEquivalentDataTypeSameLocation`, `resolveNoEquivalentFound`
//! and `.conflict` names, `DWARFDataTypeConflictHandler`).
//!
//! Types live in two arenas: `db` (resolved, in the program) and `pre` (the importer's
//! `DataTypeImpl` graph of one `doGetDataType`, dropped after it is resolved). Pointer and
//! array names and categories are derived from what they refer to, as in Ghidra.
use std::collections::{HashMap, HashSet};

/// A data type: `Id::Db` in the program, `Id::Pre` in the importer's not yet resolved graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Id {
    Db(u32),
    Pre(u32),
}

/// Built-in data types (`BuiltInDataTypeManager`) the importer uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum B {
    Void,
    /// `DataType.DEFAULT`, "undefined"
    Default,
    /// `undefined<n>`
    Undefined(u8),
    /// fixed-size integers by name (`byte`, `sdword`, `int3`, `int16`, `int8_t`, ...): name,
    /// length, signed
    Fixed(&'static str, u8, bool),
    /// the data organization's C types: name, length, signed
    C(&'static str, u8, bool),
    /// floats: name, raw length
    Float(&'static str, u8),
    Bool,
    /// `wchar_t`, `wchar16`, `wchar32`: name, length
    Char(&'static str, u8),
}

#[allow(clippy::len_without_is_empty)]
impl B {
    pub fn name(&self) -> String {
        match self {
            B::Void => "void".into(),
            B::Default => "undefined".into(),
            B::Undefined(n) => format!("undefined{n}"),
            B::Fixed(s, ..) | B::C(s, ..) | B::Float(s, _) | B::Char(s, _) => (*s).into(),
            B::Bool => "bool".into(),
        }
    }
    pub fn len(&self) -> i32 {
        match *self {
            B::Void => 0,
            B::Default | B::Bool => 1,
            B::Undefined(n) => n as i32,
            B::Fixed(_, n, _) | B::C(_, n, _) | B::Float(_, n) | B::Char(_, n) => n as i32,
        }
    }
    /// `AbstractIntegerDataType` and its signedness
    pub fn int_signed(&self) -> Option<bool> {
        match *self {
            B::Fixed(_, _, s) | B::C(_, _, s) => Some(s),
            B::Bool => Some(false),
            _ => None,
        }
    }
}

pub const VOID: B = B::Void;
pub const CHAR: B = B::C("char", 1, true);
pub const UCHAR: B = B::C("uchar", 1, false);
pub const SHORT: B = B::C("short", 2, true);
pub const USHORT: B = B::C("ushort", 2, false);
pub const INT: B = B::C("int", 4, true);
pub const UINT: B = B::C("uint", 4, false);
pub const LONG: B = B::C("long", 8, true);
pub const ULONG: B = B::C("ulong", 8, false);
pub const LONGLONG: B = B::C("longlong", 8, true);
pub const ULONGLONG: B = B::C("ulonglong", 8, false);
pub const FLOAT: B = B::Float("float", 4);
pub const DOUBLE: B = B::Float("double", 8);
pub const LONGDOUBLE: B = B::Float("longdouble", 10);
pub const WCHAR_T: B = B::Char("wchar_t", 4);
pub const WCHAR16: B = B::Char("wchar16", 2);
pub const WCHAR32: B = B::Char("wchar32", 4);
const SIGNED_FIXED: [B; 9] = [
    B::Fixed("sbyte", 1, true),
    B::Fixed("sword", 2, true),
    B::Fixed("int3", 3, true),
    B::Fixed("sdword", 4, true),
    B::Fixed("int5", 5, true),
    B::Fixed("int6", 6, true),
    B::Fixed("int7", 7, true),
    B::Fixed("sqword", 8, true),
    B::Fixed("int16", 16, true),
];
const UNSIGNED_FIXED: [B; 9] = [
    B::Fixed("byte", 1, false),
    B::Fixed("word", 2, false),
    B::Fixed("uint3", 3, false),
    B::Fixed("dword", 4, false),
    B::Fixed("uint5", 5, false),
    B::Fixed("uint6", 6, false),
    B::Fixed("uint7", 7, false),
    B::Fixed("qword", 8, false),
    B::Fixed("uint16", 16, false),
];

/// `AbstractIntegerDataType.getSignedDataType` / `getUnsignedDataType`; `org` = a data type
/// manager is given (its organization's C types first). `None` = an array of `sbyte` (signed,
/// > 8 bytes) or `Undefined` (unsigned).
pub fn int_type(size: i32, signed: bool, org: bool) -> Option<B> {
    if size < 1 {
        return Some(B::Default);
    }
    if size == 16 {
        return Some(if signed { SIGNED_FIXED[8] } else { UNSIGNED_FIXED[8] });
    }
    if size > 8 {
        return if signed { None } else { Some(undefined(size)) };
    }
    if org {
        // integer 4, short 2, long 8, long long 8: the first that matches
        for (s, sd, ud) in [(4, INT, UINT), (2, SHORT, USHORT), (8, LONG, ULONG)] {
            if size == s {
                return Some(if signed { sd } else { ud });
            }
        }
    }
    Some(if signed { SIGNED_FIXED[size as usize - 1] } else { UNSIGNED_FIXED[size as usize - 1] })
}

/// `Undefined.getUndefinedDataType`
pub fn undefined(size: i32) -> B {
    if (1..=8).contains(&size) {
        B::Undefined(size as u8)
    } else {
        B::Default
    }
}

/// `AbstractFloatDataType.getFloatDataType`
pub fn float_type(size: i32, org: bool) -> B {
    if size < 1 {
        return B::Default;
    }
    if org {
        match size {
            4 => return FLOAT,
            8 => return DOUBLE,
            10 => return LONGDOUBLE,
            _ => {}
        }
    }
    match size {
        2 => B::Float("float2", 2),
        4 => B::Float("float4", 4),
        8 => B::Float("float8", 8),
        10 => B::Float("float10", 10),
        16 => B::Float("float16", 16),
        _ => undefined(size),
    }
}

/// `DataTypeUtilities.cTypedefBuiltInNameRemap`
pub fn typedef_remap(name: &str) -> Option<B> {
    let f = |n: &'static str, l: u8, s: bool| Some(B::Fixed(n, l, s));
    match name {
        "int8_t" | "__int8_t" | "__int8" | "int_fast8_t" => f("int8_t", 1, true),
        "uint8_t" | "__uint8_t" | "__uint8" | "uint_fast8_t" | "u_int8_t" => f("uint8_t", 1, false),
        "int16_t" | "__int16_t" | "__int16" | "int_fast16_t" | "_G_int16_t" => f("int16_t", 2, true),
        "uint16_t" | "__uint16_t" | "__uint16" | "uint_fast16_t" | "u_int16_t" | "_G_uint16_t" => {
            f("uint16_t", 2, false)
        }
        "int32_t" | "__int32_t" | "__int32" | "int_fast32_t" | "_G_int32_t" => f("int32_t", 4, true),
        "uint32_t" | "__uint32_t" | "__uint32" | "uint_fast32_t" | "u_int32_t" | "_G_uint32_t" => {
            f("uint32_t", 4, false)
        }
        "int64_t" | "__int64_t" | "__int64" | "int_fast64_t" => f("int64_t", 8, true),
        "uint64_t" | "__uint64_t" | "__uint64" | "uint_fast64_t" | "u_int64_t" => f("uint64_t", 8, false),
        "intptr_t" | "__intptr_t" => f("intptr_t", 8, true),
        "uintptr_t" | "__uintptr_t" => f("uintptr_t", 8, false),
        "wchar_t" | "wchar" => Some(WCHAR_T),
        "char16_t" => Some(WCHAR16),
        "char32_t" => Some(WCHAR32),
        _ => None,
    }
}

/// x86-64 GCC `size_alignment_map` (1, 2, 4, 8, 16) with `floorEntry`; default alignment 1.
pub fn size_alignment(size: i32) -> i32 {
    match size {
        i32::MIN..=0 => 1,
        1 => 1,
        2..=3 => 2,
        4..=7 => 4,
        8..=15 => 8,
        _ => 16,
    }
}

fn aligned_offset(align: i32, off: i32) -> i32 {
    if align <= 0 {
        return off;
    }
    let m = off % align;
    if m == 0 {
        off
    } else {
        off + align - m
    }
}

fn lcm(a: i32, b: i32) -> i32 {
    fn gcd(a: i32, b: i32) -> i32 {
        if b == 0 {
            a
        } else {
            gcd(b, a % b)
        }
    }
    if a == 0 || b == 0 {
        return 0;
    }
    a / gcd(a, b) * b
}

/// A bitfield (`BitFieldDataType`): base type, declared bit size, bit offset in its storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bitfield {
    pub base: Id,
    pub bit_size: i32,
    pub bit_offset: i32,
}

#[derive(Debug, Clone)]
pub struct Comp {
    pub offset: i32,
    pub len: i32,
    pub name: Option<String>,
    pub comment: Option<String>,
    pub ty: Id,
    pub bf: Option<Bitfield>,
}

#[derive(Debug, Clone)]
pub struct Composite {
    pub union: bool,
    /// declared length (non-packed structure) or computed length
    pub len: i32,
    pub packed: bool,
    pub align: i32,
    /// defined components, by offset (non-packed) or in order (packed, unions)
    pub comps: Vec<Comp>,
    pub description: String,
}

#[derive(Debug, Clone)]
pub struct Param {
    pub name: Option<String>,
    pub ty: Id,
}

#[derive(Debug, Clone)]
pub enum Kind {
    Builtin(B),
    /// `len` -1 = the default pointer size
    Pointer {
        to: Id,
        len: i32,
    },
    Array {
        elem: Id,
        count: i32,
        elem_len: i32,
    },
    Typedef {
        base: Id,
    },
    Composite(Composite),
    Enum {
        len: i32,
        vals: Vec<(String, i64)>,
    },
    FuncDef {
        ret: Id,
        params: Vec<Param>,
        varargs: bool,
        noreturn: bool,
        cc: Option<String>,
    },
}

/// A category path, interned: root is 0.
#[derive(Debug, Clone)]
struct Cat {
    parent: u32,
    name: String,
}

#[derive(Debug, Clone)]
pub struct Dt {
    /// named types only; pointers and arrays derive theirs
    pub name: String,
    pub cat: u32,
    pub kind: Kind,
}

/// `DataTypeConflictHandler.ConflictResult`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Conflict {
    RenameAndAdd,
    UseExisting,
    ReplaceExisting,
}

/// Which handler resolves: `DEFAULT_HANDLER` (rename) or `DWARFDataTypeConflictHandler`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Handler {
    Default,
    Dwarf,
}

pub struct Dtm {
    pub db: Vec<Dt>,
    pub pre: Vec<Dt>,
    cats: Vec<Cat>,
    cat_index: HashMap<(u32, String), u32>,
    /// named db types by (category, name)
    by_name: HashMap<(u32, String), u32>,
    /// the same by (category, name without `.conflict<n>`)
    by_base: HashMap<(u32, String), Vec<u32>>,
    /// db pointers and arrays by what they are made of
    derived: HashMap<(u8, Id, i32), u32>,
    builtins: HashMap<B, u32>,
    resolved: HashMap<u32, Id>,
    handler: Handler,
}

const CONFLICT: &str = ".conflict";

impl Default for Dtm {
    fn default() -> Self {
        Self::new()
    }
}

impl Dtm {
    pub fn new() -> Dtm {
        Dtm {
            db: Vec::new(),
            pre: Vec::new(),
            cats: vec![Cat { parent: 0, name: String::new() }],
            cat_index: HashMap::new(),
            by_name: HashMap::new(),
            by_base: HashMap::new(),
            derived: HashMap::new(),
            builtins: HashMap::new(),
            resolved: HashMap::new(),
            handler: Handler::Default,
        }
    }

    pub fn dt(&self, id: Id) -> &Dt {
        match id {
            Id::Db(i) => &self.db[i as usize],
            Id::Pre(i) => &self.pre[i as usize],
        }
    }
    pub fn dt_mut(&mut self, id: Id) -> &mut Dt {
        match id {
            Id::Db(i) => &mut self.db[i as usize],
            Id::Pre(i) => &mut self.pre[i as usize],
        }
    }

    // ---- categories

    pub fn cat(&mut self, parent: u32, name: &str) -> u32 {
        if let Some(&c) = self.cat_index.get(&(parent, name.to_string())) {
            return c;
        }
        self.cats.push(Cat { parent, name: name.to_string() });
        let c = self.cats.len() as u32 - 1;
        self.cat_index.insert((parent, name.to_string()), c);
        c
    }
    pub fn cat_parts(&self, mut c: u32) -> Vec<&str> {
        let mut v = Vec::new();
        while c != 0 {
            v.push(self.cats[c as usize].name.as_str());
            c = self.cats[c as usize].parent;
        }
        v.reverse();
        v
    }
    pub fn cat_parent(&self, c: u32) -> u32 {
        self.cats[c as usize].parent
    }
    pub fn cat_name(&self, c: u32) -> &str {
        &self.cats[c as usize].name
    }
    /// `CategoryPath.getPath`: elements joined by '/', a '/' in an element escaped
    pub fn cat_path(&self, c: u32) -> String {
        if c == 0 {
            return "/".into();
        }
        self.cat_parts(c).iter().map(|p| format!("/{}", p.replace('/', "\\/"))).collect()
    }

    // ---- names, lengths, alignment

    /// `getName`: pointers "T *" (or "T *N"), arrays "T[n]" (outer count first)
    pub fn name(&self, id: Id) -> String {
        let d = self.dt(id);
        match &d.kind {
            Kind::Pointer { to, len } => {
                let n = self.name(*to);
                if *len == -1 {
                    format!("{n} *")
                } else {
                    format!("{n} *{}", len * 8)
                }
            }
            Kind::Array { elem, count, .. } => {
                let mut dims = vec![*count];
                let mut e = *elem;
                while let Kind::Array { elem, count, .. } = &self.dt(e).kind {
                    dims.push(*count);
                    e = *elem;
                }
                let mut s = self.name(e);
                for c in dims {
                    s.push_str(&format!("[{c}]"));
                }
                s
            }
            Kind::Builtin(b) => b.name(),
            _ => d.name.clone(),
        }
    }
    /// `getCategoryPath`: built-ins at the root, pointers and arrays where their base is
    pub fn category(&self, id: Id) -> u32 {
        match &self.dt(id).kind {
            Kind::Pointer { to, .. } => self.category(*to),
            Kind::Array { elem, .. } => self.category(*elem),
            Kind::Builtin(_) => 0,
            _ => self.dt(id).cat,
        }
    }
    /// `getPathName`
    pub fn path(&self, id: Id) -> String {
        let c = self.category(id);
        let n = self.name(id);
        if c == 0 {
            format!("/{n}")
        } else {
            format!("{}/{n}", self.cat_path(c))
        }
    }
    /// `BitFieldDataType.getPrimitiveBaseDataType` (BitFieldDataType.java:241-253): typedefs
    /// stripped, an enum as the unsigned integer of its length; then `isEquivalent`
    /// (DWARFDataTypeConflictHandler.java:316-323)
    fn prim_equivalent(&self, a: Id, b: Id) -> bool {
        let prim = |mut x: Id| loop {
            match self.dt(x).kind {
                Kind::Typedef { base } => x = base,
                Kind::Enum { len, .. } => return Err(int_type(len, false, true)),
                Kind::Builtin(b) => return Err(Some(b)),
                _ => return Ok(x),
            }
        };
        match (prim(a), prim(b)) {
            (Err(x), Err(y)) => x == y,
            (Ok(x), Ok(y)) => self.equivalent(x, y, None, &mut HashSet::new()),
            _ => false,
        }
    }
    /// `getLength` (1 for a zero-length composite, -1 for a function definition)
    pub fn len(&self, id: Id) -> i32 {
        match &self.dt(id).kind {
            Kind::Builtin(b) => b.len(),
            Kind::Pointer { len, .. } => {
                if *len == -1 {
                    8
                } else {
                    *len
                }
            }
            // ArrayDataType.getLength: an int product, which wraps
            Kind::Array { count, elem_len, .. } => count.wrapping_mul(*elem_len),
            Kind::Typedef { base } => self.len(*base),
            Kind::Composite(c) => c.len.max(1),
            Kind::Enum { len, .. } => *len,
            Kind::FuncDef { .. } => -1,
        }
    }
    /// `isZeroLength`
    pub fn zero_len(&self, id: Id) -> bool {
        match &self.dt(id).kind {
            Kind::Builtin(b) => b.len() == 0,
            Kind::Array { count, elem_len, .. } => *count == 0 || *elem_len == 0,
            Kind::Typedef { base } => self.zero_len(*base),
            Kind::Composite(c) => c.len == 0,
            _ => false,
        }
    }
    /// `getAlignedLength`
    pub fn aligned_len(&self, id: Id) -> i32 {
        match &self.dt(id).kind {
            Kind::Typedef { base } => self.aligned_len(*base),
            Kind::Composite(_) | Kind::Array { .. } | Kind::Pointer { .. } => self.len(id),
            _ => {
                let l = self.len(id);
                if l <= 0 {
                    return l;
                }
                aligned_offset(size_alignment(l), l)
            }
        }
    }
    /// `DataOrganizationImpl.getAlignment`
    pub fn alignment(&self, id: Id) -> i32 {
        let sz = self.aligned_len(id);
        if sz <= 0 && !matches!(self.dt(id).kind, Kind::Composite(_)) {
            return 1;
        }
        match &self.dt(id).kind {
            Kind::Typedef { base } => self.alignment(*base),
            Kind::Array { elem, .. } => self.alignment(*elem),
            Kind::Composite(c) => c.align,
            Kind::Pointer { .. } if ![1, 2, 4, 8, 16].contains(&sz) => 8,
            _ => size_alignment(sz),
        }
    }
    /// `isNotYetDefined`
    pub fn not_yet_defined(&self, id: Id) -> bool {
        matches!(&self.dt(self.base_of(id)).kind, Kind::Composite(c) if !c.packed && c.comps.is_empty() && c.len == 0)
    }
    /// typedefs followed to what they name
    pub fn base_of(&self, mut id: Id) -> Id {
        while let Kind::Typedef { base } = self.dt(id).kind {
            id = base;
        }
        id
    }
    /// `BitFieldDataType.isValidBaseDataType`
    pub fn valid_bitfield_base(&self, id: Id) -> bool {
        let b = self.base_of(id);
        match &self.dt(b).kind {
            Kind::Enum { .. } => true,
            Kind::Builtin(x) => x.int_signed().is_some() || matches!(x, B::Char(..)),
            _ => false,
        }
    }

    // ---- creating

    pub fn builtin(&mut self, b: B) -> Id {
        if let Some(&i) = self.builtins.get(&b) {
            return Id::Db(i);
        }
        self.db.push(Dt { name: String::new(), cat: 0, kind: Kind::Builtin(b) });
        let i = self.db.len() as u32 - 1;
        self.builtins.insert(b, i);
        Id::Db(i)
    }
    pub fn new_pre(&mut self, name: String, cat: u32, kind: Kind) -> Id {
        self.pre.push(Dt { name, cat, kind });
        Id::Pre(self.pre.len() as u32 - 1)
    }
    /// `dataTypeManager.getPointer(dt, size)` on a db type: the program's pointer
    pub fn db_pointer(&mut self, to: Id, len: i32) -> Id {
        let to = self.resolve(to, Handler::Default);
        self.derived_db(0, to, len, Kind::Pointer { to, len })
    }
    fn derived_db(&mut self, k: u8, base: Id, n: i32, kind: Kind) -> Id {
        if let Some(&i) = self.derived.get(&(k, base, n)) {
            return Id::Db(i);
        }
        self.db.push(Dt { name: String::new(), cat: 0, kind });
        let i = self.db.len() as u32 - 1;
        self.derived.insert((k, base, n), i);
        Id::Db(i)
    }

    /// `getDataType(category, name)`
    pub fn lookup(&self, cat: u32, name: &str) -> Option<Id> {
        self.by_name.get(&(cat, name.to_string())).map(|&i| Id::Db(i))
    }
    /// `CategoryDB.getDataTypesByBaseName` (CategoryDB.java:575-588): the base name's type, then
    /// the `.conflict<n>` types in the order of the conflict map's `HashMap<String, DataType>`
    /// (`java_hashmap_order`; filled as they are added, CategoryDB.java:636-646).
    pub fn by_base_name(&self, cat: u32, name: &str) -> Vec<Id> {
        let base = strip_conflict(name);
        let mut out: Vec<Id> = self.lookup(cat, base).into_iter().collect();
        let conflicts: Vec<u32> = self
            .by_base
            .get(&(cat, base.to_string()))
            .into_iter()
            .flatten()
            .copied()
            .filter(|&i| self.db[i as usize].name != base)
            .collect();
        let names: Vec<&str> = conflicts.iter().map(|&i| self.db[i as usize].name.as_str()).collect();
        out.extend(java_hashmap_order(&names).into_iter().map(|k| Id::Db(conflicts[k])));
        out
    }
    fn unused_conflict_name(&self, cat: u32, name: &str) -> String {
        let base = strip_conflict(name);
        let mut test = base.to_string();
        let mut count = 0;
        while self.lookup(cat, &test).is_some() {
            test = format!("{base}{CONFLICT}");
            if count > 0 {
                test.push_str(&count.to_string());
            }
            count += 1;
        }
        test
    }

    /// Moves a db type to another category (`setCategoryPath`); false if the name is taken.
    pub fn move_to(&mut self, id: u32, cat: u32) -> bool {
        let name = self.db[id as usize].name.clone();
        if self.lookup(cat, &name).is_some() {
            return false;
        }
        let old = self.db[id as usize].cat;
        self.by_name.remove(&(old, name.clone()));
        let base = strip_conflict(&name).to_string();
        if let Some(v) = self.by_base.get_mut(&(old, base.clone())) {
            v.retain(|&x| x != id);
        }
        self.by_base.entry((cat, base)).or_default().push(id);
        self.by_name.insert((cat, name), id);
        self.db[id as usize].cat = cat;
        true
    }

    // ---- composites

    /// `StructureDataType.getComponentsContaining` for a non-packed structure, as offsets of
    /// defined components; `None` in the list = the undefined byte at `off`.
    fn comps_containing(c: &Composite, off: i32) -> Vec<Option<usize>> {
        let mut v = Vec::new();
        let mut covered = false;
        for (i, x) in c.comps.iter().enumerate() {
            if x.offset == off && x.len == 0 {
                v.push(Some(i));
            } else if x.offset <= off && off < x.offset + x.len {
                v.push(Some(i));
                covered = true;
            }
        }
        if !covered && off < c.len.max(1) && off >= 0 && c.len > 0 {
            v.push(None);
        }
        v
    }
    /// `getUndefinedOrdinalAt` (true = the last thing at `off` is an undefined byte there)
    pub fn undefined_at(&self, s: Id, off: i32) -> bool {
        let Kind::Composite(c) = &self.dt(s).kind else { return false };
        matches!(Self::comps_containing(c, off).last(), Some(None))
    }
    /// `isUndefinedOrZeroLenAtOffset`
    pub fn undefined_or_zero_at(&self, s: Id, off: i32) -> bool {
        let Kind::Composite(c) = &self.dt(s).kind else { return false };
        match Self::comps_containing(c, off).last() {
            None => true,
            Some(None) => true,
            Some(Some(i)) => c.comps[*i].offset == off && self.zero_len(c.comps[*i].ty),
        }
    }
    /// the name of the defined component containing `off`, if any
    pub fn comp_containing_name(&self, s: Id, off: i32) -> Option<Option<String>> {
        let Kind::Composite(c) = &self.dt(s).kind else { return None };
        c.comps.iter().find(|x| x.offset <= off && off < x.offset + x.len.max(1)).map(|x| x.name.clone())
    }
    /// `replace(ordinal of the undefined byte at off, dt, len, ...)` in a non-packed
    /// structure: needs the bytes it covers undefined (`IllegalArgumentException` otherwise).
    pub fn struct_replace(&mut self, s: Id, off: i32, ty: Id, len: i32, name: Option<String>) -> bool {
        // getPreferredComponentLength: a length of 0 takes the type's own
        let len = if len <= 0 { self.len(ty) } else { len };
        let Kind::Composite(c) = &mut self.dt_mut(s).kind else { return false };
        let end = off + len.max(1);
        if end > c.len || c.comps.iter().any(|x| x.len > 0 && x.offset < end && off < x.offset + x.len) {
            return false;
        }
        let at = c.comps.partition_point(|x| x.offset < off || (x.offset == off && x.len == 0));
        c.comps.insert(at, Comp { offset: off, len, name, comment: None, ty, bf: None });
        true
    }
    /// `insertAtOffset(off, dt, 0, ...)` of a zero-length component
    pub fn struct_insert_zero(&mut self, s: Id, off: i32, ty: Id, name: Option<String>) {
        let Kind::Composite(c) = &mut self.dt_mut(s).kind else { return };
        let at = c.comps.partition_point(|x| x.offset < off || (x.offset == off && x.len == 0));
        c.comps.insert(at, Comp { offset: off, len: 0, name, comment: None, ty, bf: None });
    }
    /// `StructureDataType.insertBitFieldAt` (little-endian), with its conflict shift
    #[allow(clippy::too_many_arguments)]
    pub fn struct_insert_bitfield(
        &mut self,
        s: Id,
        byte_off: i32,
        byte_width: i32,
        bit_off: i32,
        base: Id,
        bit_size: i32,
        name: Option<String>,
    ) -> bool {
        let base_len = self.len(base);
        let eff = bit_size.min(base_len * 8);
        if byte_width < (eff + bit_off + 7) / 8 {
            return false;
        }
        let start_bit = byte_off * 8 + bit_off;
        let Kind::Composite(c) = &mut self.dt_mut(s).kind else { return false };
        let bits = |x: &Comp| match x.bf {
            Some(b) => (x.offset * 8 + b.bit_offset, x.offset * 8 + b.bit_offset + (b.bit_size.max(1)) - 1),
            None => (x.offset * 8, x.offset * 8 + (x.len * 8).max(1) - 1),
        };
        let find = |c: &Composite, bit: i32| -> Result<usize, usize> {
            match c.comps.iter().position(|x| {
                let (a, b) = bits(x);
                a <= bit && bit <= b
            }) {
                Some(i) => Ok(i),
                None => Err(c.comps.partition_point(|x| bits(x).1 < bit)),
            }
        };
        let mut conflict = false;
        let mut shift = 0;
        let start = match find(c, start_bit) {
            Ok(i) => {
                conflict = true;
                let x = &c.comps[i];
                let zero_bf = matches!(x.bf, Some(b) if b.bit_size == 0);
                if bit_size == 0 || zero_bf {
                    conflict = x.offset != start_bit / 8;
                }
                if conflict {
                    shift = byte_off - x.offset;
                }
                i
            }
            Err(i) => i,
        };
        let mut end = start;
        if start < c.comps.len() {
            let end_bit = start_bit + if eff != 0 { eff - 1 } else { 0 };
            end = match find(c, end_bit) {
                Ok(i) => {
                    if eff != 0 {
                        conflict = true;
                    }
                    i
                }
                Err(i) => i,
            };
        }
        if start != end {
            conflict = true;
        }
        if conflict {
            let by = byte_width + shift;
            for x in &mut c.comps[start..] {
                x.offset += by;
            }
            c.len += by;
        }
        c.len = c.len.max(byte_off + byte_width);
        let storage = ((eff + bit_off % 8 + 7) / 8).max(1);
        let off = byte_off + bit_off / 8;
        c.comps.insert(
            start,
            Comp {
                offset: off,
                len: storage,
                name,
                comment: None,
                ty: base,
                bf: Some(Bitfield { base, bit_size, bit_offset: bit_off % 8 }),
            },
        );
        true
    }
    /// `UnionDataType.add` / `addBitField`
    pub fn union_add(&mut self, u: Id, ty: Id, bf: Option<i32>, name: Option<String>, comment: Option<String>) {
        let len = match bf {
            Some(bs) => ((bs.min(self.len(ty) * 8) + 7) / 8).max(1),
            None => self.len(ty),
        };
        let Kind::Composite(c) = &mut self.dt_mut(u).kind else { return };
        c.comps.push(Comp {
            offset: 0,
            len,
            name,
            comment,
            ty,
            bf: bf.map(|bs| Bitfield { base: ty, bit_size: bs, bit_offset: 0 }),
        });
        c.len = c.len.max(len);
    }

    /// `setToDefaultPacking` and the repack (`AlignedStructurePacker`, union packing)
    pub fn pack(&mut self, id: Id) {
        let Kind::Composite(mut c) = self.dt(id).kind.clone() else { return };
        c.packed = true;
        if c.union {
            let mut align = 1;
            let mut len = 0;
            for x in &mut c.comps {
                let a = self.alignment(x.bf.map(|b| b.base).unwrap_or(x.ty));
                x.len = match x.bf {
                    Some(b) => ((b.bit_size.min(self.len(b.base) * 8) + 7) / 8).max(1),
                    None => self.aligned_len(x.ty),
                };
                if let Some(b) = &mut x.bf {
                    b.bit_offset = 0;
                }
                align = lcm(align, a);
                len = len.max(x.len);
            }
            c.align = align.max(1);
            c.len = aligned_offset(c.align, len);
        } else {
            let mut p = Packer::default();
            let n = c.comps.len();
            for i in 0..n {
                self.pack_add(&mut p, &mut c.comps, i, i + 1 == n);
            }
            let len = p.length(&c.comps, self);
            c.align = p.default_align.max(1);
            c.len = aligned_offset(c.align, len);
        }
        self.dt_mut(id).kind = Kind::Composite(c);
    }

    // ---- equivalence and conflicts

    /// `DataTypeUtilities.isSameDataType` / identity
    fn same(&self, a: Id, b: Id) -> bool {
        a == b || matches!((&self.dt(a).kind, &self.dt(b).kind), (Kind::Builtin(x), Kind::Builtin(y)) if x == y)
    }

    /// `DataTypeDB.isEquivalent(existing, dt, handler)`
    pub fn equivalent(&self, a: Id, b: Id, h: Option<Handler>, seen: &mut HashSet<(Id, Id)>) -> bool {
        if self.same(a, b) {
            return true;
        }
        if !seen.insert((a, b)) {
            return true; // being compared further up: assume equal, as the resolving check does
        }
        if h == Some(Handler::Dwarf) {
            let ka = &self.dt(a).kind;
            let kb = &self.dt(b).kind;
            let shortcut = matches!(
                (ka, kb),
                (Kind::Composite(_), Kind::Composite(_))
                    | (Kind::Typedef { .. }, Kind::Typedef { .. })
                    | (Kind::Enum { .. }, Kind::Enum { .. })
                    | (Kind::FuncDef { .. }, Kind::FuncDef { .. })
            );
            if shortcut && self.strict(b, a, &mut HashSet::new()) == Conflict::UseExisting {
                return true;
            }
        }
        match (&self.dt(a).kind, &self.dt(b).kind) {
            (Kind::Builtin(x), Kind::Builtin(y)) => x == y,
            (Kind::Pointer { to: t1, len: l1 }, Kind::Pointer { to: t2, len: l2 }) => {
                self.len(a) == self.len(b)
                    && (l1 == l2 || self.len(a) == self.len(b))
                    && self.equivalent(*t1, *t2, h, seen)
            }
            (Kind::Array { elem: e1, count: c1, .. }, Kind::Array { elem: e2, count: c2, .. }) => {
                c1 == c2 && self.equivalent(*e1, *e2, h, seen)
            }
            (Kind::Typedef { base: b1 }, Kind::Typedef { base: b2 }) => {
                eq_ignore_conflict(&self.dt(a).name, &self.dt(b).name)
                    && (self.same(*b1, *b2) || self.equivalent(*b1, *b2, h, seen))
            }
            (Kind::Enum { len: l1, vals: v1 }, Kind::Enum { len: l2, vals: v2 }) => {
                eq_ignore_conflict(&self.dt(a).name, &self.dt(b).name)
                    && l1 == l2
                    && v1.len() == v2.len()
                    && v1.iter().all(|(n, v)| v2.iter().any(|(n2, v2)| n == n2 && v == v2))
            }
            (Kind::Composite(x), Kind::Composite(y)) => {
                if x.union != y.union || x.packed != y.packed {
                    return false;
                }
                let ylen = if self.zero_len(b) { 0 } else { y.len.max(1) };
                let xlen = if self.zero_len(a) { 0 } else { x.len.max(1) };
                if !x.packed && !x.union && xlen != ylen {
                    return false;
                }
                if x.comps.len() != y.comps.len() {
                    return false;
                }
                let sub = h; // getSubsequentHandler of both handlers is itself
                x.comps.iter().zip(&y.comps).all(|(p, q)| {
                    if (!x.packed && p.offset != q.offset) || p.name != q.name || p.comment != q.comment {
                        return false;
                    }
                    match (p.bf, q.bf) {
                        (Some(m), Some(n)) => {
                            m.bit_size == n.bit_size
                                && m.bit_offset == n.bit_offset
                                && self.equivalent(m.base, n.base, sub, seen)
                        }
                        (None, None) => self.same(p.ty, q.ty) || self.equivalent(p.ty, q.ty, sub, seen),
                        _ => false,
                    }
                })
            }
            (
                Kind::FuncDef { ret: r1, params: p1, varargs: v1, noreturn: n1, cc: c1 },
                Kind::FuncDef { ret: r2, params: p2, varargs: v2, noreturn: n2, cc: c2 },
            ) => {
                eq_ignore_conflict(&self.dt(a).name, &self.dt(b).name)
                    && v1 == v2
                    && n1 == n2
                    && c1 == c2
                    && p1.len() == p2.len()
                    && self.equivalent(*r1, *r2, h, seen)
                    && p1.iter().zip(p2).all(|(x, y)| self.equivalent(x.ty, y.ty, h, seen))
            }
            _ => false,
        }
    }

    fn composite_default(&self, id: Id) -> bool {
        self.not_yet_defined(id) || matches!(&self.dt(id).kind, Kind::Composite(c) if c.comps.is_empty())
    }
    fn size_compatible(&self, src: Id, target: Id) -> bool {
        self.not_yet_defined(target) || self.len(src) == self.len(target)
    }

    /// `DWARFDataTypeConflictHandler.doStrictCompare(added, existing)`
    pub fn strict(&self, added: Id, existing: Id, seen: &mut HashSet<(Id, Id)>) -> Conflict {
        if self.same(added, existing) || !seen.insert((existing, added)) {
            return Conflict::UseExisting;
        }
        match (&self.dt(existing).kind, &self.dt(added).kind) {
            (Kind::Composite(_), Kind::Composite(_)) => {
                if self.composite_default(added) && self.size_compatible(existing, added) {
                    return Conflict::UseExisting;
                }
                if self.composite_default(existing) && self.size_compatible(added, existing) {
                    return Conflict::ReplaceExisting;
                }
                if self.composite_part(existing, added, seen) {
                    return Conflict::UseExisting;
                }
                if self.composite_part(added, existing, seen) {
                    return Conflict::ReplaceExisting;
                }
                Conflict::RenameAndAdd
            }
            (Kind::Typedef { base: e }, Kind::Typedef { base: a }) => self.relaxed(*a, *e, seen),
            (Kind::Array { elem: e, count: ec, elem_len: el }, Kind::Array { elem: a, count: ac, elem_len: al }) => {
                if ec != ac || el != al {
                    Conflict::RenameAndAdd
                } else {
                    self.relaxed(*a, *e, seen)
                }
            }
            (Kind::Pointer { to: e, .. }, Kind::Pointer { to: a, .. }) => self.relaxed(*a, *e, seen),
            (Kind::FuncDef { ret: er, params: ep, .. }, Kind::FuncDef { ret: ar, params: ap, .. }) => {
                if self.relaxed(*ar, *er, seen) == Conflict::RenameAndAdd || ap.len() != ep.len() {
                    return Conflict::RenameAndAdd;
                }
                for (x, y) in ap.iter().zip(ep) {
                    if self.relaxed(x.ty, y.ty, seen) == Conflict::RenameAndAdd {
                        return Conflict::RenameAndAdd;
                    }
                }
                Conflict::UseExisting
            }
            _ => {
                if self.equivalent(existing, added, None, &mut HashSet::new()) {
                    Conflict::UseExisting
                } else {
                    Conflict::RenameAndAdd
                }
            }
        }
    }
    fn relaxed(&self, added: Id, existing: Id, seen: &mut HashSet<(Id, Id)>) -> Conflict {
        if let Kind::Typedef { base } = self.dt(added).kind {
            return self.relaxed(base, existing, seen);
        }
        if let Kind::Typedef { base } = self.dt(existing).kind {
            return self.relaxed(added, base, seen);
        }
        self.strict(added, existing, seen)
    }
    fn composite_part(&self, full: Id, part: Id, seen: &mut HashSet<(Id, Id)>) -> bool {
        let (Kind::Composite(f), Kind::Composite(p)) = (&self.dt(full).kind, &self.dt(part).kind) else { return false };
        if f.union != p.union {
            return false;
        }
        if f.union {
            if self.len(full) < self.len(part) {
                return false;
            }
            let fname = |x: &Comp, i: usize| x.name.clone().unwrap_or_else(|| format!("field_{i}"));
            let by: HashMap<String, &Comp> = f.comps.iter().enumerate().map(|(i, x)| (fname(x, i), x)).collect();
            return p.comps.iter().enumerate().all(|(i, x)| match by.get(&fname(x, i)) {
                None => false,
                Some(y) => self.relaxed(x.ty, y.ty, seen) != Conflict::RenameAndAdd,
            });
        }
        if self.len(full) != self.len(part) {
            return false;
        }
        for pc in &p.comps {
            if self.zero_len(pc.ty) && pc.bf.is_none() {
                continue;
            }
            let fc = match pc.bf {
                Some(pb) => f.comps.iter().find(|x| {
                    x.offset == pc.offset
                        && matches!(x.bf, Some(b) if b.bit_offset == pb.bit_offset && b.bit_size == pb.bit_size)
                }),
                None => f.comps.iter().find(|x| x.offset == pc.offset && x.bf.is_none() && !self.zero_len(x.ty)),
            };
            let Some(fc) = fc else { return false };
            if fc.name != pc.name {
                return false;
            }
            let r = match (pc.bf, fc.bf) {
                (Some(a), Some(b)) => {
                    if a.bit_size != b.bit_size || !self.prim_equivalent(b.base, a.base) {
                        Conflict::RenameAndAdd
                    } else {
                        Conflict::UseExisting
                    }
                }
                _ => self.relaxed(pc.ty, fc.ty, seen),
            };
            match r {
                Conflict::RenameAndAdd => return false,
                Conflict::ReplaceExisting if fc.len < pc.len => return false,
                _ => {}
            }
        }
        true
    }

    // ---- resolve

    /// `DataTypeManagerDB.resolve(dt, handler)`: the program's type for `id`.
    pub fn resolve(&mut self, id: Id, h: Handler) -> Id {
        let Id::Pre(p) = id else { return id };
        if let Some(&r) = self.resolved.get(&p) {
            return r;
        }
        let prev = self.handler;
        self.handler = h;
        let r = self.resolve_pre(p);
        self.handler = prev;
        r
    }

    fn resolve_pre(&mut self, p: u32) -> Id {
        let id = Id::Pre(p);
        let kind = self.pre[p as usize].kind.clone();
        match kind {
            Kind::Builtin(b) => {
                let r = self.builtin(b);
                self.resolved.insert(p, r);
                r
            }
            Kind::Pointer { to, len } => {
                let t = self.resolve(to, self.handler);
                let r = self.derived_db(0, t, len, Kind::Pointer { to: t, len });
                self.resolved.insert(p, r);
                r
            }
            Kind::Array { elem, count, elem_len } => {
                let e = self.resolve(elem, self.handler);
                let r = self.derived_db(1, e, count, Kind::Array { elem: e, count, elem_len });
                self.resolved.insert(p, r);
                r
            }
            _ => {
                let cat = self.pre[p as usize].cat;
                let name = self.pre[p as usize].name.clone();
                // findEquivalentDataTypeSameLocation
                let existing = self.lookup(cat, &name);
                let hh = Some(self.handler);
                if let Some(e) = existing {
                    if self.equivalent(e, id, hh, &mut HashSet::new()) {
                        self.resolved.insert(p, e);
                        return e;
                    }
                }
                for c in self.by_base_name(cat, &name) {
                    if Some(c) != existing && self.equivalent(c, id, hh, &mut HashSet::new()) {
                        self.resolved.insert(p, c);
                        return c;
                    }
                }
                // resolveNoEquivalentFound
                let same_kind = |s: &Self, x: Id| {
                    std::mem::discriminant(&s.dt(x).kind) == std::mem::discriminant(&s.dt(id).kind)
                        && matches!((&s.dt(x).kind, &s.dt(id).kind), (Kind::Composite(a), Kind::Composite(b)) if a.union == b.union)
                            | !matches!(s.dt(x).kind, Kind::Composite(_))
                };
                let mut found = existing.filter(|&e| same_kind(self, e));
                if found.is_none() {
                    let list = self.by_base_name(cat, &name);
                    found = list.iter().copied().find(|&x| same_kind(self, x)).or(existing).or(list.first().copied());
                }
                let Some(e) = found else {
                    let n = if existing.is_some() { self.unused_conflict_name(cat, &name) } else { name };
                    return self.create(p, n, cat);
                };
                let c = match self.handler {
                    Handler::Default => Conflict::RenameAndAdd,
                    Handler::Dwarf => self.strict(id, e, &mut HashSet::new()),
                };
                match c {
                    Conflict::UseExisting => {
                        self.resolved.insert(p, e);
                        e
                    }
                    Conflict::ReplaceExisting if same_kind(self, e) => {
                        // updateExistingDataType: the existing type takes the new content
                        let Id::Db(ei) = e else { unreachable!() };
                        self.resolved.insert(p, e);
                        let k = self.resolve_kind(kind_of(&self.pre[p as usize].kind));
                        self.db[ei as usize].kind = k;
                        e
                    }
                    _ => {
                        let n = self.unused_conflict_name(cat, &name);
                        self.create(p, n, cat)
                    }
                }
            }
        }
    }

    /// `createDataType`: a new db type for a pre type, registered before its parts resolve
    fn create(&mut self, p: u32, name: String, cat: u32) -> Id {
        let placeholder = match &self.pre[p as usize].kind {
            Kind::Composite(c) => Kind::Composite(Composite { comps: Vec::new(), ..c.clone() }),
            k => k.clone(),
        };
        self.db.push(Dt { name: name.clone(), cat, kind: placeholder });
        let i = self.db.len() as u32 - 1;
        self.by_base.entry((cat, strip_conflict(&name).to_string())).or_default().push(i);
        self.by_name.insert((cat, name), i);
        self.resolved.insert(p, Id::Db(i));
        let k = self.resolve_kind(kind_of(&self.pre[p as usize].kind));
        self.db[i as usize].kind = k;
        Id::Db(i)
    }

    fn resolve_kind(&mut self, k: Kind) -> Kind {
        let h = self.handler;
        match k {
            Kind::Typedef { base } => Kind::Typedef { base: self.resolve(base, h) },
            Kind::Composite(mut c) => {
                for x in &mut c.comps {
                    x.ty = self.resolve(x.ty, h);
                    if let Some(b) = &mut x.bf {
                        b.base = x.ty;
                    }
                }
                Kind::Composite(c)
            }
            Kind::FuncDef { ret, params, varargs, noreturn, cc } => {
                let ret = self.resolve(ret, h);
                let params = params.into_iter().map(|q| Param { name: q.name, ty: self.resolve(q.ty, h) }).collect();
                Kind::FuncDef { ret, params, varargs, noreturn, cc }
            }
            k => k,
        }
    }

    /// what `id` resolved to, if it is a pre type that was resolved
    pub fn resolved_of(&self, id: Id) -> Option<Id> {
        match id {
            Id::Db(_) => Some(id),
            Id::Pre(p) => self.resolved.get(&p).copied(),
        }
    }

    /// Drops the pre graph after a top-level resolve.
    pub fn clear_pre(&mut self) {
        self.pre.clear();
        self.resolved.clear();
    }

    /// Adds a db type directly (`addDataType` of a type built on db parts only).
    pub fn add(&mut self, name: String, cat: u32, kind: Kind, h: Handler) -> Id {
        let p = self.new_pre(name, cat, kind);
        self.resolve(p, h)
    }
}

fn kind_of(k: &Kind) -> Kind {
    k.clone()
}

/// `DataTypeUtilities.getNameWithoutConflict`
pub fn strip_conflict(n: &str) -> &str {
    match n.find(CONFLICT) {
        Some(i) if n[i + CONFLICT.len()..].chars().all(|c| c.is_ascii_digit()) => &n[..i],
        _ => n,
    }
}

/// `DataTypeUtilities.equalsIgnoreConflict`
pub fn eq_ignore_conflict(a: &str, b: &str) -> bool {
    strip_conflict(a) == strip_conflict(b)
}

/// `AlignedComponentPacker` with GCC's bitfield packing (`BitFieldPackingImpl` defaults: not
/// the MS convention, type alignment on, no zero-length boundary), default packing.
#[derive(Default)]
struct Packer {
    next_ordinal: usize,
    zero_alignment: i32,
    last_alignment: i32,
    group_offset: i32,
    last: Option<usize>,
    default_align: i32,
    started: bool,
}

impl Dtm {
    fn is_bf(c: &Comp) -> bool {
        c.bf.is_some()
    }
    fn is_zero_bf(c: &Comp) -> bool {
        matches!(c.bf, Some(b) if b.bit_size == 0)
    }

    fn pack_add(&self, p: &mut Packer, comps: &mut [Comp], i: usize, is_last: bool) {
        if !p.started {
            p.started = true;
            p.group_offset = -1;
            p.default_align = 1;
        }
        if !self.pack_component(p, comps, i) {
            self.init_group(p, comps, i, is_last);
        }
        p.last = Some(i);
        p.next_ordinal += 1;
        // getComponentAlignmentLCM
        if p.last_alignment != 0 {
            p.default_align = lcm(p.default_align, p.last_alignment);
        } else {
            p.default_align = 0;
        }
    }

    fn init_group(&self, p: &mut Packer, comps: &mut [Comp], i: usize, is_last: bool) {
        p.group_offset = p.length(comps, self);
        p.last_alignment = 1;
        if Self::is_bf(&comps[i]) {
            if Self::is_zero_bf(&comps[i]) {
                let base = comps[i].bf.unwrap().base;
                let alignment = self.alignment(base); // getZeroBitFieldAlignment: type alignment, no pack
                if let Some(b) = &mut comps[i].bf {
                    b.bit_offset = 0;
                }
                comps[i].len = 1;
                if is_last {
                    let off = aligned_offset(self.alignment(base), p.group_offset);
                    self.update(p, &mut comps[i], off, 0, alignment.max(1));
                    p.group_offset = -1;
                } else {
                    p.zero_alignment = alignment;
                }
            } else {
                p.last = None;
                self.pack_bitfield(p, comps, i);
            }
        } else {
            p.last = None;
            let g = p.group_offset;
            self.pack_plain(p, comps, i, g);
        }
    }

    fn adjust_zero(&self, p: &mut Packer, comps: &mut [Comp], min_align: i32) {
        let min_off = aligned_offset(min_align, p.group_offset);
        let zoff = aligned_offset(p.zero_alignment, p.group_offset);
        p.group_offset = min_off.max(zoff);
        if let Some(l) = p.last {
            let g = p.group_offset;
            self.update(p, &mut comps[l], g, 0, min_align);
        }
    }

    fn pack_component(&self, p: &mut Packer, comps: &mut [Comp], i: usize) -> bool {
        let Some(l) = p.last else { return false };
        if Self::is_zero_bf(&comps[i]) {
            return false;
        }
        if Self::is_bf(&comps[i]) {
            self.pack_bitfield(p, comps, i);
            return true;
        }
        let off = if Self::is_zero_bf(&comps[l]) { p.group_offset } else { comps[l].offset + comps[l].len };
        self.pack_plain(p, comps, i, off);
        true
    }

    fn pack_plain(&self, p: &mut Packer, comps: &mut [Comp], i: usize, min_off: i32) {
        let ty = comps[i].ty;
        let mut size = if self.zero_len(ty) { 0 } else { self.aligned_len(ty) };
        if size < 0 {
            size = comps[i].len;
        }
        let alignment = self.alignment(ty);
        let off;
        if matches!(p.last, Some(l) if Self::is_zero_bf(&comps[l])) {
            self.adjust_zero(p, comps, alignment);
            off = p.group_offset;
        } else {
            off = aligned_offset(alignment, min_off);
            if p.last.is_none() {
                p.group_offset = off;
            }
        }
        self.update(p, &mut comps[i], off, size, alignment);
    }

    fn pack_bitfield(&self, p: &mut Packer, comps: &mut [Comp], i: usize) {
        let bf = comps[i].bf.unwrap();
        if matches!(p.last, Some(l) if Self::is_zero_bf(&comps[l])) {
            let za = p.zero_alignment;
            self.adjust_zero(p, comps, za);
        }
        let prim = self.base_of(bf.base);
        let base_size = self.len(bf.base);
        let mut alignment = self.alignment(prim);
        p.last_alignment = p.last_alignment.max(alignment);
        let (mut off, mut consumed);
        match p.last {
            None => {
                off = aligned_offset(alignment, p.group_offset);
                consumed = 0;
                p.group_offset = off;
            }
            Some(l) if Self::is_zero_bf(&comps[l]) => {
                off = p.group_offset;
                consumed = 0;
            }
            Some(l) => {
                alignment = self.alignment(bf.base);
                let last = &comps[l];
                let mut last_bf = None;
                if let Some(lb) = last.bf {
                    last_bf = Some(lb);
                    off = last.offset + last.len - 1;
                    consumed = (lb.bit_size.min(self.len(lb.base) * 8) + lb.bit_offset) % 8;
                    if consumed == 8 || consumed == 0 {
                        consumed = 0;
                        off += 1;
                    }
                } else {
                    off = last.offset + last.len;
                    consumed = 0;
                }
                let eff = bf.bit_size.min(base_size * 8);
                let byte_size = (eff + consumed + 7) / 8;
                let mut end = off + byte_size - 1;
                if off % alignment != 0 || byte_size > base_size {
                    let aligned_base = aligned_offset(alignment, off) - alignment;
                    if end >= aligned_base + base_size {
                        off = aligned_offset(alignment, off + 1);
                        end = off + byte_size - 1;
                        consumed = 0;
                    }
                }
                if let Some(lb) = last_bf {
                    if p.group_offset >= 0 && end >= p.group_offset + self.len(lb.base) {
                        p.group_offset = -1;
                    }
                }
            }
        }
        let eff = bf.bit_size.min(base_size * 8);
        let byte_size = (eff + consumed + 7) / 8;
        if let Some(b) = &mut comps[i].bf {
            b.bit_offset = consumed;
        }
        self.update(p, &mut comps[i], off, byte_size, alignment);
    }

    fn update(&self, p: &mut Packer, c: &mut Comp, off: i32, len: i32, alignment: i32) {
        c.offset = off;
        c.len = len;
        p.last_alignment = p.last_alignment.max(alignment);
    }
}

impl Packer {
    fn length(&self, comps: &[Comp], d: &Dtm) -> i32 {
        let Some(l) = self.last else { return 0 };
        let c = &comps[l];
        let mut off = c.offset + c.len;
        if Dtm::is_zero_bf(c) {
            off = aligned_offset(d.alignment(c.bf.unwrap().base), off);
        }
        off
    }
}

/// The iteration order of a `java.util.HashMap<String, V>` filled by `put` in the order of
/// `keys` (distinct): buckets of `HashMap.hash(String.hashCode)` over the table the puts grew
/// (16, doubled past 3/4 full or, below 64, when a bucket passes TREEIFY_THRESHOLD), each bucket
/// in put order. Returns indexes into `keys`.
/// ponytail: removals (a type moved out) do not shrink Java's table, and a bucket turned into a
/// tree (64 buckets or more) is walked in put order here; both need far more conflicts of one
/// name than seen.
fn java_hashmap_order(keys: &[&str]) -> Vec<usize> {
    let hash = |s: &str| {
        let h = super::java_hash(s);
        (h ^ ((h as u32) >> 16) as i32) as u32 as usize
    };
    let mut n = 16usize;
    let mut count: HashMap<usize, usize> = HashMap::new();
    for (k, key) in keys.iter().enumerate() {
        let c = count.entry(hash(key) & (n - 1)).or_default();
        *c += 1;
        let grow = (*c > 8 && n < 64) || k + 1 > n * 3 / 4;
        if grow {
            n *= 2;
            count.clear();
            for b in &keys[..=k] {
                *count.entry(hash(b) & (n - 1)).or_default() += 1;
            }
        }
    }
    let mut out: Vec<usize> = (0..keys.len()).collect();
    out.sort_by_key(|&k| hash(keys[k]) & (n - 1));
    out
}
