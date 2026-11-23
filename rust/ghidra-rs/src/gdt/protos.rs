//! The prototype file of `tools/ghidra/ExportArchiveProtos.java` (`ghidra-rs-protos 1`), made
//! from an archive without Java: each function definition applied to a new external function of
//! a fresh x86:LE:32:default:windows program as `ApplyFunctionSignatureCmd` does, then encoded as
//! `DecompileCallback.getExternalRef` answers, then every data type those answers name
//! (`DecompileCallback.getDataType`). What the program would hold is simulated, not stored:
//! the keys its `DataTypeManagerDB` gives the types it resolves (`resolve`, the post-resolve
//! queue of pointers in composites and function definitions), the ids of the symbols of each
//! function and its parameters, the parameter storage of `x86win.cspec`'s models
//! (`ParamListStandard`, `ParamEntry`), and the encoders (`PcodeDataTypeManager`,
//! `FunctionPrototype`, `LocalSymbolMap`, `HighSymbol`). `export_elf64` does the same for a function
//! in memory of an x86:LE:64:default:gcc program, for the part of `x86-64-gcc.cspec` that is ported.
use super::db::Result;
use super::{kind, Archive, Kind, DEFAULT_ID, POINTER};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fmt::Write;

const CORE_TYPES: &str = include_str!("../facts_coretypes.xml");
/// `PcodeDataTypeManager.DEFAULT_DECOMPILER_ID`: "undefined".
const DEFAULT_DECOMPILER_ID: u64 = 0xc000_0000_0000_0000;
/// `HighSymbol.ID_BASE`: ids the decompiler is not sent.
const ID_BASE: u64 = 0x4000_0000_0000_0000;
/// Built-in ids (`BuiltInDataTypeManager.getID | BUILTIN_ID_HEADER`, the order of Ghidra
/// 12.3's class search) of the archive's built-ins that the core-type list lacks (the core list
/// has one type per size: `int`, `uint`): as Java's export writes them. They depend on that
/// order (the `DataType` classes Ghidra 12.3's `ClassSearcher` finds, in the order it finds
/// them): another Ghidra version or plugin set can number them differently, and the export
/// would then differ from Java's in these three ids.
const EXTRA_BUILTIN_IDS: [(&str, u64); 3] =
    [("long", 0xc000_0000_0000_009b), ("uchar", 0xc000_0000_0000_00c7), ("ulong", 0xc000_0000_0000_00cf)];
/// The core types of x86:LE:64 gcc (a built-in has the same id in both lists).
const CORE_TYPES64: &str = include_str!("../facts_coretypes64.xml");

/// A data type as the program holds it: an archive type, or a pointer the program made
/// (`settleCDataType`, the hidden return pointer).
#[derive(Clone, Copy, PartialEq)]
enum Ty {
    Arch(i64),
    PtrTo(i64),
    Void,
}

/// `ParamEntry` storage classes (`StorageClass`).
#[derive(Clone, Copy, PartialEq)]
enum Class {
    General,
    Float,
    Ptr,
}

/// A storage location: a register or stack offset and size, or ST0 holding a smaller float.
#[derive(Clone, Copy)]
enum Storage {
    Register {
        offset: u64,
        size: i32,
    },
    Stack {
        offset: u64,
        size: i32,
    },
    /// a join of EDX:EAX (`piece1` high)
    Join8,
    /// ST0 (10 bytes) holding `size` bytes (`SMALLSIZE_FLOAT`)
    St0Small,
}

/// One `<pentry>` of a model (`ParamEntry`): its storage class and slots.
struct Entry {
    class: Class,
    minsize: i32,
    size: i32,
    /// 0: a register (one slot), else the slot alignment of a stack entry
    alignment: i32,
    storage: fn(u64, i32) -> Storage,
}

fn eax(_: u64, size: i32) -> Storage {
    Storage::Register { offset: 0x0, size }
}
fn ecx(_: u64, size: i32) -> Storage {
    Storage::Register { offset: 0x4, size }
}
fn edx(_: u64, size: i32) -> Storage {
    Storage::Register { offset: 0x8, size }
}
fn st0(_: u64, size: i32) -> Storage {
    if size == 10 {
        Storage::Register { offset: 0x1100, size }
    } else {
        Storage::St0Small
    }
}
fn join8(_: u64, _: i32) -> Storage {
    Storage::Join8
}
fn stack(offset: u64, size: i32) -> Storage {
    Storage::Stack { offset, size }
}

// ponytail: the models of x86win.cspec written out (registers EAX 0x0, ECX 0x4, EDX 0x8,
// ST0 0x1100 of x86.sla); reading them from the .cspec is the upgrade for other languages.
const STACK: Entry = Entry { class: Class::General, minsize: 1, size: 500, alignment: 4, storage: stack };
const OUTPUT: [Entry; 3] = [
    Entry { class: Class::Float, minsize: 4, size: 10, alignment: 0, storage: st0 },
    Entry { class: Class::General, minsize: 1, size: 4, alignment: 0, storage: eax },
    Entry { class: Class::General, minsize: 5, size: 8, alignment: 0, storage: join8 },
];
const FASTCALL_INPUT: [Entry; 3] = [
    Entry { class: Class::General, minsize: 1, size: 4, alignment: 0, storage: ecx },
    Entry { class: Class::General, minsize: 1, size: 4, alignment: 0, storage: edx },
    STACK,
];

fn reg64<const OFFSET: u64>(_: u64, size: i32) -> Storage {
    Storage::Register { offset: OFFSET, size }
}
const fn general64(storage: fn(u64, i32) -> Storage) -> Entry {
    Entry { class: Class::General, minsize: 1, size: 8, alignment: 0, storage }
}
// ponytail: of x86-64-gcc.cspec's `__stdcall`, the general registers and the stack only (RDI
// 0x38, RSI 0x30, RDX 0x10, RCX 0x8, R8 0x80, R9 0x88, RAX 0x0 of x86-64.sla). A float, a
// composite and anything over 8 bytes fail by name (`assign_address`), so the cspec's `<rule>`s
// (join_dual_class, goto_stack, hidden_return) never decide; reading the .cspec is the upgrade.
const SYSV_INPUT: [Entry; 7] = [
    general64(reg64::<0x38>),
    general64(reg64::<0x30>),
    general64(reg64::<0x10>),
    general64(reg64::<0x8>),
    general64(reg64::<0x80>),
    general64(reg64::<0x88>),
    Entry { class: Class::General, minsize: 1, size: 500, alignment: 8, storage: stack },
];
const SYSV_OUTPUT: [Entry; 1] = [general64(reg64::<0x0>)];

/// The program an archive is applied to: its compiler spec and data organization.
#[derive(Clone, Copy, PartialEq)]
enum Target {
    /// x86:LE:32:default:windows (`x86win.cspec`)
    Win32,
    /// x86:LE:64:default:gcc (`x86-64-gcc.cspec`)
    Elf64,
}

impl Target {
    /// The data organization's pointer size; the offset of the first stack parameter too.
    fn pointer_size(self) -> i32 {
        match self {
            Target::Win32 => 4,
            Target::Elf64 => 8,
        }
    }

    /// A model of the cspec: name, its extrapop (`None`: unknown) and inputs. `default` is the
    /// cspec's `<default_proto>`, `__stdcall` (`getCallingConvention("default")`); x86win's
    /// `__thiscall` (ECX, `thisbeforeretpointer`) is not ported.
    fn model(self, name: &str) -> Result<(Option<i32>, &'static [Entry])> {
        const STD: [Entry; 1] = [STACK];
        match (self, name) {
            (Target::Win32, "__stdcall" | "default") => Ok((None, &STD)),
            (Target::Win32, "__cdecl") => Ok((Some(4), &STD)),
            (Target::Win32, "__fastcall") => Ok((None, &FASTCALL_INPUT)),
            (Target::Elf64, "__stdcall" | "default") => Ok((Some(8), &SYSV_INPUT)),
            (_, n) => Err(format!("calling convention {n} not ported")),
        }
    }

    fn output(self) -> &'static [Entry] {
        match self {
            Target::Win32 => &OUTPUT,
            Target::Elf64 => &SYSV_OUTPUT,
        }
    }

    /// `CompilerSpec.getCallingConvention`: a model the cspec has (or `default`), else none
    /// (`unknown`). A definition naming a model of x86-64-gcc.cspec is not ported
    /// (`generic_clib_64` has none).
    fn known_model(self, name: &str) -> Result<Option<&str>> {
        match self {
            Target::Win32 => {
                Ok(["__stdcall", "__cdecl", "__fastcall", "__thiscall", "default"].contains(&name).then_some(name))
            }
            Target::Elf64
                if ["__stdcall", "__thiscall", "MSABI", "syscall", "processEntry", "default"].contains(&name) =>
            {
                Err(format!("calling convention {name} of a definition not ported on x86-64"))
            }
            Target::Elf64 => Ok(None),
        }
    }
}

/// The display name, metatype and size of a built-in class (`getDecompilerDisplayName`);
/// `inline` for `AbstractIntegerDataType` (encoded in place, not by reference).
struct BuiltIn {
    name: &'static str,
    meta: &'static str,
    size: i32,
    inline: bool,
    extra: &'static str,
}

fn builtin(class: &str) -> Result<BuiltIn> {
    let b = |name, meta, size, inline, extra| Ok(BuiltIn { name, meta, size, inline, extra });
    match class {
        "UnsignedIntegerDataType" => b("uint", "uint", 4, true, ""),
        "CharDataType" => b("char", "int", 1, true, " char=\"true\""),
        "IntegerDataType" => b("int", "int", 4, true, ""),
        "WideCharDataType" => b("wchar_t", "int", 2, false, " utf=\"true\""),
        "UnsignedShortDataType" => b("ushort", "uint", 2, true, ""),
        "LongDataType" => b("long", "int", 4, true, ""),
        "LongLongDataType" => b("longlong", "int", 8, true, ""),
        "VoidDataType" => b("void", "void", 0, false, ""),
        "UnsignedCharDataType" => b("uchar", "uint", 1, true, " char=\"true\""),
        "UnsignedLongDataType" => b("ulong", "uint", 4, true, ""),
        "ShortDataType" => b("short", "int", 2, true, ""),
        "UnsignedLongLongDataType" => b("ulonglong", "uint", 8, true, ""),
        "FloatDataType" => b("float", "float", 4, false, ""),
        "DoubleDataType" => b("double", "float", 8, false, ""),
        "SignedByteDataType" => b("sbyte", "int", 1, true, ""),
        "ByteDataType" => b("byte", "uint", 1, true, ""),
        c => Err(format!("built-in data type {c} not ported")),
    }
}

/// `SpecXmlUtils.xmlEscape`.
fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&apos;"),
            c => o.push(c),
        }
    }
    o
}

/// `ExportArchiveProtos.line`.
fn line(xml: &str) -> String {
    xml.replace('\r', "&#13;").replace('\n', "&#10;").replace('\t', "&#9;")
}

/// The program the archive is applied to: its data-type keys and symbol ids.
struct Exporter<'a> {
    ar: &'a Archive,
    core: HashMap<String, u64>,
    /// archive id -> program id (`DataTypeManagerDB.getID` of the resolved type)
    prog: HashMap<i64, i64>,
    by_prog: HashMap<i64, i64>,
    next_key: HashMap<i64, i64>,
    /// `resolveQueue`: program key -> archive type with pointers to resolve
    queue: BTreeMap<i64, i64>,
    resolving: bool,
    next_symbol: u64,
    target: Target,
}

impl<'a> Exporter<'a> {
    fn new(ar: &'a Archive, target: Target) -> Result<Exporter<'a>> {
        let re =
            regex_lite::Regex::new(r#"<type name="([^"]*)"[^>]* id="0x([0-9a-f]+)""#).map_err(|e| e.to_string())?;
        // x86-64: its own list over the 32-bit one, which has `longlong` and `ulonglong`
        let core64 = if target == Target::Elf64 { CORE_TYPES64 } else { "" };
        let core = re
            .captures_iter(CORE_TYPES)
            .chain(re.captures_iter(core64))
            .filter_map(|c| Some((c[1].to_string(), u64::from_str_radix(&c[2], 16).ok()?)))
            .chain(EXTRA_BUILTIN_IDS.iter().map(|(n, id)| (n.to_string(), *id)))
            .collect();
        // SymbolTable: 1 is the library ARCHIVE
        Ok(Exporter {
            ar,
            core,
            prog: HashMap::new(),
            by_prog: HashMap::new(),
            next_key: HashMap::new(),
            queue: BTreeMap::new(),
            resolving: false,
            next_symbol: 2,
            target,
        })
    }

    /// A built-in class in the target's data organization: gcc's x86-64 has an 8-byte `long`
    /// and a 4-byte `wchar_t`.
    fn builtin(&self, class: &str) -> Result<BuiltIn> {
        let mut b = builtin(class)?;
        if self.target == Target::Elf64 {
            match class {
                "LongDataType" | "UnsignedLongDataType" => b.size = 8,
                "WideCharDataType" => b.size = 4,
                _ => {}
            }
        }
        Ok(b)
    }

    fn ptr_len(&self, length: i8) -> i32 {
        if length < 0 {
            self.target.pointer_size()
        } else {
            length as i32
        }
    }

    // ---- the program's data types (DataTypeManagerDB.resolve) ----

    fn assign(&mut self, a: i64) {
        let k = kind(a);
        let n = self.next_key.entry(k).or_insert(0);
        let p = (k << 56) | *n;
        *n += 1;
        self.prog.insert(a, p);
        self.by_prog.insert(p, a);
    }

    /// `resolve`: a top-level resolve owns the resolve queue and empties it at its end
    /// (`processResolveQueue`, smallest key first).
    fn resolve(&mut self, t: Ty) -> Result<()> {
        let owner = !self.resolving;
        self.resolving = true;
        match t {
            Ty::Arch(a) | Ty::PtrTo(a) => self.resolve_inner(a)?,
            Ty::Void => {}
        }
        if owner {
            while let Some((_, a)) = self.queue.pop_first() {
                self.post_pointer_resolve(a)?;
            }
            self.resolving = false;
        }
        Ok(())
    }

    /// `doCheckedResolve` of a composite or function definition: a pointer is resolved as a
    /// pointer to DEFAULT now and for real after (`queuePostResolve`).
    fn checked(&mut self, t: i64) -> Result<bool> {
        if t != DEFAULT_ID && kind(t) == POINTER {
            return Ok(true);
        }
        self.resolve_inner(t)?;
        Ok(false)
    }

    fn resolve_inner(&mut self, a: i64) -> Result<()> {
        if a == DEFAULT_ID || self.prog.contains_key(&a) {
            return Ok(());
        }
        let dt = self.ar.get(a)?;
        match &dt.kind {
            Kind::BuiltIn(_) => {}
            Kind::Pointer { to, .. } => self.resolve_inner(*to)?,
            Kind::Array { element, .. } => self.resolve_inner(*element)?,
            Kind::Typedef { base } => {
                // createTypeDef: the base first
                self.resolve_inner(*base)?;
                self.assign(a);
            }
            Kind::Enum { .. } => self.assign(a),
            Kind::Composite { components, .. } => {
                // createStructure / createUnion: the record, then doReplaceWith
                self.assign(a);
                let mut post = false;
                for c in components {
                    match c.bitfield {
                        Some(b) => self.resolve_inner(b.base)?,
                        None => post |= self.checked(c.ty)?,
                    }
                }
                if post {
                    self.queue.insert(self.prog[&a], a);
                }
            }
            Kind::FunctionDef { ret, params, .. } => {
                // createFunctionDefinition: the record, then arguments, then return type
                self.assign(a);
                let mut post = false;
                for p in params {
                    post |= self.checked(p.ty)?;
                }
                post |= self.checked(*ret)?;
                if post {
                    self.queue.insert(self.prog[&a], a);
                }
            }
        }
        Ok(())
    }

    /// `CompositeDB.postPointerResolve`, `FunctionDefinitionDB.postPointerResolve`.
    fn post_pointer_resolve(&mut self, a: i64) -> Result<()> {
        let ptrs: Vec<i64> = match &self.ar.get(a)?.kind {
            Kind::Composite { components, .. } => {
                components.iter().filter(|c| c.bitfield.is_none()).map(|c| c.ty).collect()
            }
            Kind::FunctionDef { ret, params, .. } => params.iter().map(|p| p.ty).chain([*ret]).collect(),
            _ => Vec::new(),
        };
        for t in ptrs {
            if t != DEFAULT_ID && kind(t) == POINTER {
                self.resolve_inner(t)?;
            }
        }
        Ok(())
    }

    // ---- sizes (DataType.getLength, getAlignment of the windows data organization) ----

    fn length(&self, t: Ty) -> Result<i32> {
        let a = match t {
            Ty::Void => return Ok(0),
            Ty::PtrTo(_) => return Ok(self.target.pointer_size()),
            Ty::Arch(a) => a,
        };
        if a == DEFAULT_ID {
            return Ok(1);
        }
        Ok(match &self.ar.get(a)?.kind {
            Kind::BuiltIn(c) => self.builtin(c)?.size,
            Kind::Pointer { length, .. } => self.ptr_len(*length),
            Kind::Array { element, count, element_length } => count * self.elem_len(*element, *element_length)?,
            Kind::Typedef { base } => self.length(Ty::Arch(*base))?,
            // CompositeDB.getLength: an empty composite is 1 byte
            Kind::Composite { length, .. } => (*length).max(1),
            Kind::Enum { size, .. } => *size as i32,
            Kind::FunctionDef { .. } => -1,
        })
    }

    fn elem_len(&self, element: i64, element_length: i32) -> Result<i32> {
        if element_length > 0 {
            Ok(element_length)
        } else {
            self.length(Ty::Arch(element))
        }
    }

    fn alignment(&self, t: Ty) -> Result<i32> {
        let a = match t {
            Ty::Void => return Ok(1),
            Ty::PtrTo(_) => return Ok(self.target.pointer_size()),
            Ty::Arch(a) => a,
        };
        if a == DEFAULT_ID {
            return Ok(1);
        }
        Ok(match &self.ar.get(a)?.kind {
            Kind::BuiltIn(c) => self.builtin(c)?.size.max(1),
            Kind::Pointer { length, .. } => self.ptr_len(*length),
            Kind::Array { element, .. } => self.alignment(Ty::Arch(*element))?,
            Kind::Typedef { base } => self.alignment(Ty::Arch(*base))?,
            Kind::Composite { alignment, .. } => *alignment,
            Kind::Enum { size, .. } => *size as i32,
            Kind::FunctionDef { .. } => 1,
        })
    }

    /// `TypeDef.getBaseDataType`: through every typedef.
    fn base(&self, t: Ty) -> Result<Ty> {
        let mut t = t;
        while let Ty::Arch(a) = t {
            match &self.ar.types.get(&a).map(|d| &d.kind) {
                Some(Kind::Typedef { base }) => t = Ty::Arch(*base),
                _ => break,
            }
        }
        Ok(t)
    }

    /// `ParamEntry.getBasicTypeClass`.
    fn class(&self, t: Ty) -> Result<Class> {
        Ok(match self.base(t)? {
            Ty::PtrTo(_) => Class::Ptr,
            Ty::Arch(a) if a != DEFAULT_ID => match &self.ar.get(a)?.kind {
                Kind::BuiltIn(c) if self.builtin(c)?.meta == "float" => Class::Float,
                Kind::Pointer { .. } => Class::Ptr,
                _ => Class::General,
            },
            _ => Class::General,
        })
    }

    fn is_void(&self, t: Ty) -> bool {
        match t {
            Ty::Void => true,
            Ty::Arch(a) => {
                matches!(self.ar.types.get(&a).map(|d| &d.kind), Some(Kind::BuiltIn(c)) if c == "VoidDataType")
            }
            Ty::PtrTo(_) => false,
        }
    }

    // ---- storage (ParamListStandard.assignAddressFallback, ParamEntry.getAddrBySlot) ----

    /// `None`: no entry fits (FAIL); `Some(None)`: NO_ASSIGNMENT.
    fn assign_address(&self, t: Ty, entries: &[Entry], status: &mut [i32]) -> Result<Option<Option<Storage>>> {
        if let Ty::Arch(a) = self.base(t)? {
            if a == DEFAULT_ID && self.target == Target::Win32 {
                return Ok(Some(None));
            }
        }
        if self.target == Target::Elf64 {
            // only what a general register or the stack holds whole (`SYSV_INPUT`)
            let plain = match self.base(t)? {
                Ty::PtrTo(_) => true,
                Ty::Arch(a) => match &self.ar.get(a)?.kind {
                    Kind::Pointer { .. } | Kind::Enum { .. } => true,
                    Kind::BuiltIn(c) => self.builtin(c)?.meta != "float",
                    _ => false,
                },
                Ty::Void => false,
            };
            if !plain || !(1..=8).contains(&self.length(t)?) {
                return Err("the x86-64 storage of a float, a composite or a type over 8 bytes not ported".into());
            }
        }
        let class = self.class(t)?;
        let sz = self.length(t)?;
        let align = self.alignment(t)?;
        for (grp, e) in entries.iter().enumerate() {
            if status[grp] < 0 || (class != e.class && e.class != Class::General) {
                continue;
            }
            if sz < e.minsize {
                continue;
            }
            if e.alignment == 0 {
                if status[grp] != 0 || sz > e.size {
                    continue;
                }
                status[grp] = -1; // an exclusion entry
                return Ok(Some(Some((e.storage)(0, sz))));
            }
            let mut slot = status[grp];
            if align > e.alignment {
                let tmp = (slot * e.alignment) % align;
                if tmp != 0 {
                    slot += (align - tmp) / e.alignment;
                }
            }
            let used = (sz + e.alignment - 1) / e.alignment;
            if slot + used > e.size / e.alignment {
                continue;
            }
            status[grp] = slot + used;
            return Ok(Some(Some((e.storage)((self.target.pointer_size() + slot * e.alignment) as u64, sz))));
        }
        Ok(None)
    }

    // ---- encoders (PcodeDataTypeManager) ----

    fn core_id(&self, name: &str) -> Result<u64> {
        self.core.get(name).copied().ok_or_else(|| format!("no core type {name}"))
    }

    fn name_id(&self, a: i64) -> Result<String> {
        let dt = self.ar.get(a)?;
        if let Kind::BuiltIn(c) = &dt.kind {
            let b = self.builtin(c)?;
            return Ok(format!(" name=\"{}\" id=\"{:#x}\"", b.name, self.core_id(b.name)?));
        }
        let p = self.prog.get(&a).ok_or_else(|| format!("{} ({a:#x}) was not resolved", dt.name))?;
        Ok(format!(" name=\"{}\" id=\"{:#x}\"", esc(&dt.name), p))
    }

    /// `encodeTypeRef`.
    fn type_ref(&self, o: &mut String, t: Ty, size: i32) -> Result<()> {
        let a = match t {
            Ty::Void | Ty::PtrTo(_) => return self.type_xml(o, t, size),
            Ty::Arch(a) => a,
        };
        if a == DEFAULT_ID {
            write!(o, "<typeref name=\"undefined\" id=\"{DEFAULT_DECOMPILER_ID:#x}\"/>").map_err(|e| e.to_string())?;
            return Ok(());
        }
        match &self.ar.get(a)?.kind {
            Kind::BuiltIn(c) if self.builtin(c)?.inline || c == "VoidDataType" => return self.type_xml(o, t, size),
            Kind::Pointer { .. } | Kind::Array { .. } => return self.type_xml(o, t, size),
            Kind::FunctionDef { .. } => {}
            _ if self.length(t)? <= 0 => return self.type_xml(o, t, size),
            _ => {}
        }
        o.push_str("<typeref");
        o.push_str(&self.name_id(a)?);
        // a function definition (length -1) is referenced with size 1
        if self.length(t)? <= 0 {
            o.push_str(" size=\"1\"");
        }
        o.push_str("/>");
        Ok(())
    }

    /// `encodeType`.
    fn type_xml(&self, o: &mut String, t: Ty, size: i32) -> Result<()> {
        let a = match t {
            Ty::Void => {
                o.push_str("<void/>");
                return Ok(());
            }
            Ty::PtrTo(to) => return self.pointer_xml(o, to, self.target.pointer_size()),
            Ty::Arch(a) => a,
        };
        if a == DEFAULT_ID {
            // encodeOpaqueDataType of DataType.DEFAULT
            o.push_str("<type name=\"undefined\" id=\"0xc000000000000000\" metatype=\"unknown\" size=\"1\"/>");
            return Ok(());
        }
        let dt = self.ar.get(a)?;
        match &dt.kind {
            Kind::BuiltIn(c) => {
                let b = self.builtin(c)?;
                if c == "VoidDataType" {
                    o.push_str("<void/>");
                } else {
                    write!(o, "<type{} metatype=\"{}\" size=\"{}\"{}/>", self.name_id(a)?, b.meta, b.size, b.extra)
                        .map_err(|e| e.to_string())?;
                }
            }
            Kind::Typedef { base } => {
                let sz = match self.length(Ty::Arch(*base))? {
                    n if n <= 0 => size,
                    n => n,
                };
                write!(o, "<def{}>", self.name_id(a)?).map_err(|e| e.to_string())?;
                self.type_ref(o, Ty::Arch(*base), sz)?;
                o.push_str("</def>");
            }
            Kind::Pointer { to, length } => self.pointer_xml(o, *to, self.ptr_len(*length))?,
            Kind::Array { element, count, element_length } => {
                if *count == 0 {
                    return Err(format!("zero-length array {a:#x} not ported"));
                }
                let el = self.elem_len(*element, *element_length)?;
                write!(o, "<type name=\"\" metatype=\"array\" size=\"{}\" arraysize=\"{count}\">", count * el)
                    .map_err(|e| e.to_string())?;
                self.type_ref(o, Ty::Arch(*element), el)?;
                o.push_str("</type>");
            }
            Kind::Composite { union, length, alignment, components } => {
                let (meta, sz, al) = (if *union { "union" } else { "struct" }, (*length).max(1), *alignment);
                write!(o, "<type{} metatype=\"{meta}\" size=\"{sz}\" alignment=\"{al}\">", self.name_id(a)?)
                    .map_err(|e| e.to_string())?;
                let start = o.len();
                for c in components.iter().filter(|c| c.length != 0) {
                    let name = match &c.name {
                        Some(n) if !n.is_empty() => esc(n),
                        _ if *union => format!("field{}", c.ordinal),
                        _ => format!("field{}_0x{:x}", c.ordinal, c.offset),
                    };
                    if let Some(b) = c.bitfield {
                        write!(
                            o,
                            "<bitfield name=\"{name}\" id=\"{}\" offset=\"{}\" first=\"{}\" size=\"{}\">",
                            c.ordinal, c.offset, b.bit_offset, b.bit_size
                        )
                        .map_err(|e| e.to_string())?;
                        self.type_ref(o, Ty::Arch(b.base), self.length(Ty::Arch(b.base))?)?;
                        o.push_str("</bitfield>");
                    } else if *union {
                        write!(o, "<field name=\"{name}\" offset=\"{}\" id=\"{}\">", c.offset, c.ordinal)
                            .map_err(|e| e.to_string())?;
                        self.type_ref(o, Ty::Arch(c.ty), c.length)?;
                        o.push_str("</field>");
                    } else {
                        write!(o, "<field name=\"{name}\" offset=\"{}\">", c.offset).map_err(|e| e.to_string())?;
                        self.type_ref(o, Ty::Arch(c.ty), c.length)?;
                        o.push_str("</field>");
                    }
                }
                close(o, start);
            }
            Kind::Enum { size, values } => {
                let mut vals = values.clone();
                vals.sort_by(|x, y| x.1.cmp(&y.1).then_with(|| x.0.cmp(&y.0)));
                let signed = vals.iter().any(|v| v.1 < 0);
                let meta = if signed { "enum_int" } else { "enum_uint" };
                write!(o, "<type{} metatype=\"{meta}\" size=\"{size}\">", self.name_id(a)?)
                    .map_err(|e| e.to_string())?;
                let start = o.len();
                for (n, v) in vals {
                    write!(o, "<val name=\"{}\" value=\"{v}\"/>", esc(&n)).map_err(|e| e.to_string())?;
                }
                close(o, start);
            }
            Kind::FunctionDef { ret, params, varargs, noreturn, convention } => {
                write!(o, "<type{} metatype=\"code\" size=\"1\">", self.name_id(a)?).map_err(|e| e.to_string())?;
                // FunctionPrototype(FunctionSignature): cspec.matchConvention (default: __stdcall)
                let extrapop = self.target.model(self.target.known_model(convention)?.unwrap_or("__stdcall"))?.0;
                let mut p = Proto {
                    extrapop,
                    model: convention.clone(),
                    modellock: true,
                    dotdotdot: *varargs,
                    voidlock: params.is_empty(),
                    noreturn: *noreturn,
                    ret: Ty::Arch(*ret),
                    ret_storage: None,
                    outputlock: true,
                };
                // voidInputIsVarargs (on unless the output language is not C): no parameters is varargs
                p.dotdotdot |= p.voidlock;
                self.prototype_xml(o, &p, Some(params))?;
                o.push_str("</type>");
            }
        }
        Ok(())
    }

    /// `encodePointer`.
    fn pointer_xml(&self, o: &mut String, to: i64, len: i32) -> Result<()> {
        write!(o, "<type name=\"\" metatype=\"ptr\" size=\"{len}\">").map_err(|e| e.to_string())?;
        let pointee = Ty::Arch(to);
        if to != DEFAULT_ID && matches!(self.ar.get(to)?.kind, Kind::FunctionDef { .. }) {
            self.type_ref(o, pointee, -1)?;
        } else if self.length(pointee)? < 0 {
            write!(o, "<typeref name=\"undefined1\" id=\"{:#x}\"/>", self.core_id("undefined1")?)
                .map_err(|e| e.to_string())?;
        } else {
            self.type_ref(o, pointee, self.length(pointee)?)?;
        }
        o.push_str("</type>");
        Ok(())
    }

    /// `FunctionPrototype.encodePrototype`.
    fn prototype_xml(&self, o: &mut String, p: &Proto, params: Option<&Vec<super::Param>>) -> Result<()> {
        match p.extrapop {
            Some(n) => write!(o, "<prototype extrapop=\"{n}\"").map_err(|e| e.to_string())?,
            None => o.push_str("<prototype extrapop=\"unknown\""),
        }
        write!(o, " model=\"{}\"", esc(&p.model)).map_err(|e| e.to_string())?;
        for (on, attr) in
            [(p.modellock, "modellock"), (p.dotdotdot, "dotdotdot"), (p.voidlock, "voidlock"), (p.noreturn, "noreturn")]
        {
            if on {
                write!(o, " {attr}=\"true\"").map_err(|e| e.to_string())?;
            }
        }
        o.push_str(if p.outputlock { "><returnsym typelock=\"true\">" } else { "><returnsym>" });
        let sz = match self.length(p.ret)? {
            n if n < 0 => 1,
            n => n,
        };
        match p.ret_storage {
            Some(s) => addr_xml(o, s, sz),
            None => o.push_str("<addr/>"),
        }
        self.type_ref(o, p.ret, sz)?;
        o.push_str("</returnsym>");
        if let Some(params) = params {
            if params.is_empty() {
                o.push_str("<internallist/>");
            } else {
                o.push_str("<internallist>");
                for prm in params {
                    o.push_str("<param");
                    let named = prm.name.as_deref().is_some_and(|n| !n.is_empty());
                    if let Some(n) = prm.name.as_deref().filter(|_| named) {
                        write!(o, " name=\"{}\"", esc(n)).map_err(|e| e.to_string())?;
                    }
                    write!(o, " typelock=\"true\" namelock=\"{named}\"><addr/>").map_err(|e| e.to_string())?;
                    let sz = match self.length(Ty::Arch(prm.ty))? {
                        n if n < 0 => 1,
                        n => n,
                    };
                    self.type_ref(o, Ty::Arch(prm.ty), sz)?;
                    o.push_str("</param>");
                }
                o.push_str("</internallist>");
            }
        }
        o.push_str("</prototype>");
        Ok(())
    }

    // ---- one function definition applied (ApplyFunctionSignatureCmd) and encoded ----

    fn function(&mut self, a: i64) -> Result<String> {
        let dt = self.ar.get(a)?;
        let name = dt.name.clone();
        let Kind::FunctionDef { ret, params, varargs, noreturn, convention } = dt.kind.clone() else {
            return Err(format!("{a:#x} is not a function definition"));
        };
        let func_id = self.next_symbol;
        self.next_symbol += 1;
        // getCallingConvention: a name the cspec lacks gives none (unknown, default model)
        let conv = self.target.known_model(&convention)?;
        let (extrapop_model, inputs) = self.target.model(conv.unwrap_or("__stdcall"))?;
        let output = self.target.output();
        // createParameters
        let mut ret_ty = Ty::Arch(ret);
        let mut args: Vec<(Option<String>, Ty)> = Vec::new();
        for p in &params {
            let mut t = Ty::Arch(p.ty);
            if p.name.as_deref() == Some("__return_storage_ptr__") {
                return Err(format!("{name}: a __return_storage_ptr__ parameter not ported"));
            }
            // settleCDataType: an array (or a typedef of one) becomes a pointer to its element
            if let Ty::Arch(b) = self.base(t)? {
                if b != DEFAULT_ID {
                    if let Kind::Array { element, .. } = self.ar.get(b)?.kind {
                        t = Ty::PtrTo(element);
                    }
                }
            }
            args.push((p.name.clone(), t));
        }
        if self.is_void(ret_ty) {
            ret_ty = Ty::Void;
        }
        // FunctionDB.updateFunction: the return type, then the parameters
        self.resolve(ret_ty)?;
        for (_, t) in &args {
            self.resolve(*t)?;
        }
        // PrototypeModel.getStorageLocations: output, then inputs (hidden return pointer first)
        let mut ret_storage = None;
        let mut unassigned_ret = false;
        let mut hidden = None;
        if ret_ty != Ty::Void {
            let mut status = [0; 3];
            match self.assign_address(ret_ty, output, &mut status)? {
                Some(Some(s)) => ret_storage = Some(s),
                // NO_ASSIGNMENT (DEFAULT): invalid storage, an unlocked void (grabFromFunction)
                Some(None) => {
                    ret_ty = Ty::Void;
                    unassigned_ret = true;
                }
                None => {
                    let Ty::Arch(r) = ret_ty else { return Err("hidden return of a made pointer".into()) };
                    let mut status = [0; 3];
                    ret_storage = self.assign_address(Ty::PtrTo(r), output, &mut status)?.flatten();
                    hidden = Some(r);
                }
            }
        }
        let mut status = vec![0; inputs.len()];
        let mut slots: Vec<Slot> = Vec::new();
        if let Some(r) = hidden {
            let s = self.assign_address(Ty::PtrTo(r), inputs, &mut status)?.flatten();
            slots.push(("__return_storage_ptr__".into(), Ty::PtrTo(r), s, ID_BASE));
        }
        let mut failed = false;
        for (n, t) in &args {
            let ordinal = slots.len() - usize::from(hidden.is_some());
            let s = if failed {
                None
            } else {
                match self.assign_address(*t, inputs, &mut status)? {
                    Some(Some(s)) => Some(s),
                    _ => {
                        failed = true;
                        None
                    }
                }
            };
            let n = n.clone().filter(|n| !n.is_empty()).unwrap_or_else(|| format!("param_{}", ordinal + 1));
            slots.push((n, *t, s, self.next_symbol));
            self.next_symbol += 1;
        }
        // updateStackPurgeSize, then FunctionPrototype.grabFromFunction's extrapop
        let extrapop = match extrapop_model {
            Some(n) => Some(n),
            None if failed => None,
            None => {
                let stack: Vec<(u64, i32)> = slots
                    .iter()
                    .filter_map(|s| {
                        if let Some(Storage::Stack { offset, size }) = s.2 {
                            Some((offset, size))
                        } else {
                            None
                        }
                    })
                    .collect();
                let min = stack.iter().map(|s| s.0).min().unwrap_or(0);
                let max = stack.iter().map(|s| s.0 + s.1 as u64).max().unwrap_or(0);
                let diff = if max > min { (max - min).div_ceil(4) * 4 } else { 0 };
                Some(diff as i32 + 4)
            }
        };
        let mut o = String::new();
        write!(o, "<doc id=\"0x0\"><mapsym><function id=\"{func_id:#x}\" name=\"{}\" size=\"@SIZE@\"", esc(&name))
            .map_err(|e| e.to_string())?;
        if noreturn {
            o.push_str(" noreturn=\"true\"");
        }
        write!(
            o,
            "><addr space=\"ram\" offset=\"@ADDR@\"/><localdb lock=\"false\" main=\"stack\"><scope name=\"{}\"><parent id=\"0x0\"/><rangelist/>",
            esc(&name)
        )
        .map_err(|e| e.to_string())?;
        // LocalSymbolMap.grabFromFunction: parameters up to the first without storage
        let kept: Vec<_> = slots.iter().enumerate().take_while(|(_, s)| s.2.is_some()).collect();
        let typelock = kept.len() == slots.len();
        if kept.is_empty() {
            o.push_str("<symbollist/>");
        } else {
            o.push_str("<symbollist>");
            for (index, (n, t, s, id)) in java_hashmap_order(kept) {
                o.push_str("<mapsym><symbol");
                if id >> 56 != ID_BASE >> 56 {
                    write!(o, " id=\"{id:#x}\"").map_err(|e| e.to_string())?;
                }
                // an x86-64 program's parameter is name-locked whatever its name: Java's facts have
                // `param_1` of `isspace` so (the rule in Java was not traced)
                let namelock = self.target == Target::Elf64 || !is_default_param_name(n);
                write!(o, " name=\"{}\" typelock=\"{typelock}\" namelock=\"{namelock}\"", esc(n))
                    .map_err(|e| e.to_string())?;
                // HighSymbol.isIsolated: a type-locked symbol is not merged
                if typelock {
                    o.push_str(" merge=\"false\"");
                }
                if id >> 56 == ID_BASE >> 56 {
                    o.push_str(" hiddenretparm=\"true\"");
                }
                write!(o, " cat=\"0\" index=\"{index:#x}\">").map_err(|e| e.to_string())?;
                let sz = self.length(*t)?;
                self.type_ref(&mut o, *t, sz)?;
                o.push_str("</symbol>");
                let s = s.ok_or("no storage")?;
                // MappedEntry.encode: a logical size only for a float smaller than its storage
                let logical = if self.class(*t)? == Class::Float { sz } else { storage_size(s) };
                addr_xml(&mut o, s, logical);
                // a register parameter of a function in memory holds from the address before
                // its entry, `@PC@` (the x86 export's functions are external: no range)
                if self.target == Target::Elf64 && matches!(s, Storage::Register { .. }) {
                    o.push_str("<rangelist><range space=\"ram\" first=\"@PC@\" last=\"@PC@\"/></rangelist></mapsym>");
                } else {
                    o.push_str("<rangelist/></mapsym>");
                }
            }
            o.push_str("</symbollist>");
        }
        o.push_str("</scope></localdb>");
        let p = Proto {
            extrapop,
            model: conv.unwrap_or("unknown").to_string(),
            modellock: conv.is_some(),
            dotdotdot: varargs,
            voidlock: slots.is_empty(),
            noreturn,
            ret: match hidden {
                Some(r) => Ty::PtrTo(r),
                None => ret_ty,
            },
            ret_storage,
            outputlock: ret != DEFAULT_ID && !unassigned_ret,
        };
        self.prototype_xml(&mut o, &p, None)?;
        o.push_str("</function><addr space=\"ram\" offset=\"@ADDR@\" size=\"@SIZE@\"/><rangelist/></mapsym></doc>");
        Ok(o)
    }

    /// `DecompileCallback.getDataType` of a program id: the type encoded whole.
    fn data_type(&self, id: u64) -> Result<String> {
        let mut o = String::new();
        if id == DEFAULT_DECOMPILER_ID {
            self.type_xml(&mut o, Ty::Arch(DEFAULT_ID), 0)?;
            return Ok(o);
        }
        let t = match self.by_prog.get(&(id as i64)) {
            Some(a) => *a,
            None => {
                let name = self
                    .core
                    .iter()
                    .find(|c| *c.1 == id)
                    .map(|c| c.0.clone())
                    .ok_or_else(|| format!("no type {id:#x}"))?;
                if name == "undefined1" {
                    // encodeOpaqueDataType of Undefined1DataType (pointers to function definitions)
                    write!(o, "<type name=\"undefined1\" id=\"{id:#x}\" metatype=\"unknown\" size=\"1\"/>")
                        .map_err(|e| e.to_string())?;
                    return Ok(o);
                }
                *self
                    .ar
                    .types
                    .iter()
                    .find(|(_, d)| matches!(&d.kind, Kind::BuiltIn(c) if self.builtin(c).is_ok_and(|b| b.name == name)))
                    .ok_or_else(|| format!("built-in {name} is not in the archive"))?
                    .0
            }
        };
        self.type_xml(&mut o, Ty::Arch(t), 0)?;
        Ok(o)
    }
}

fn storage_size(s: Storage) -> i32 {
    match s {
        Storage::Register { size, .. } | Storage::Stack { size, .. } => size,
        Storage::Join8 => 8,
        Storage::St0Small => 10,
    }
}

/// `AddressXML.encode(varnodes, logicalsize)`: `logical` is the data type's size, written when
/// it differs from the storage.
fn addr_xml(o: &mut String, s: Storage, logical: i32) {
    let _ = match s {
        Storage::Register { offset, size } if logical != size && logical > 0 => {
            write!(o, "<addr space=\"join\" piece1=\"register:{offset:#x}:{size}\" logicalsize=\"{logical:#x}\"/>")
        }
        Storage::Register { offset, size } => {
            write!(o, "<addr space=\"register\" offset=\"{offset:#x}\" size=\"{size}\"/>")
        }
        Storage::Stack { offset, size } => write!(o, "<addr space=\"stack\" offset=\"{offset:#x}\" size=\"{size}\"/>"),
        Storage::Join8 if logical != 8 => {
            write!(o, "<addr space=\"join\" piece1=\"register:0x8:4\" piece2=\"register:0x0:4\" logicalsize=\"{logical:#x}\"/>")
        }
        Storage::Join8 => write!(o, "<addr space=\"join\" piece1=\"register:0x8:4\" piece2=\"register:0x0:4\"/>"),
        Storage::St0Small => {
            write!(o, "<addr space=\"join\" piece1=\"register:0x1100:10\" logicalsize=\"{logical:#x}\"/>")
        }
    };
}

/// `SymbolUtilities.isDefaultParameterName`: `param_<n>`.
fn is_default_param_name(n: &str) -> bool {
    n.strip_prefix("param_").is_some_and(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()))
}

/// A parameter: name, type, storage (none: unassigned) and symbol id.
type Slot = (String, Ty, Option<Storage>, u64);

/// The iteration order of `LocalSymbolMap.symbolMap` (a `java.util.HashMap<Long, HighSymbol>`):
/// by bucket of the final table size, insertion order within a bucket.
fn java_hashmap_order(items: Vec<(usize, &Slot)>) -> Vec<(usize, &Slot)> {
    let mut cap = 16usize;
    while items.len() > cap * 3 / 4 {
        cap *= 2;
    }
    let bucket = |id: u64| {
        let h = (id ^ (id >> 32)) as u32;
        ((h ^ (h >> 16)) as usize) & (cap - 1)
    };
    let mut v: Vec<_> = items.into_iter().enumerate().map(|(i, (ix, s))| (bucket(s.3), i, ix, s)).collect();
    v.sort_by_key(|x| (x.0, x.1));
    v.into_iter().map(|(_, _, ix, s)| (ix, s)).collect()
}

/// What `FunctionPrototype` encodes.
struct Proto {
    extrapop: Option<i32>,
    model: String,
    modellock: bool,
    dotdotdot: bool,
    voidlock: bool,
    noreturn: bool,
    ret: Ty,
    ret_storage: Option<Storage>,
    outputlock: bool,
}

/// `ExportArchiveProtos.run` without Java: `proto` lines for each function definition (the
/// analyzer skips a name given twice or holding a tab), then `type` lines for every type they
/// name, breadth first.
pub fn export(ar: &Archive) -> Result<String> {
    let mut ex = Exporter::new(ar, Target::Win32)?;
    let typeref = regex_lite::Regex::new(r#"<typeref name="([^"]*)" id="(0x[0-9a-f]+)""#).map_err(|e| e.to_string())?;
    let mut out = String::from("ghidra-rs-protos 1\n");
    let mut names = HashSet::new();
    let mut seen = HashSet::new();
    let mut queue = VecDeque::new();
    let mut scan = |xml: &str, queue: &mut VecDeque<String>| {
        for c in typeref.captures_iter(xml) {
            if seen.insert(c[2].to_string()) {
                queue.push_back(c[2].to_string());
            }
        }
    };
    for &f in &ar.function_defs {
        let name = &ar.get(f)?.name;
        if name.contains('\t') || !names.insert(name.clone()) {
            continue;
        }
        let xml = ex.function(f).map_err(|e| format!("{name}: {e}"))?;
        scan(&xml, &mut queue);
        out.push_str(&format!("proto\t{name}\t{}\n", line(&xml)));
    }
    while let Some(id) = queue.pop_front() {
        let v = u64::from_str_radix(&id[2..], 16).map_err(|e| e.to_string())?;
        let xml = ex.data_type(v).map_err(|e| format!("type {id}: {e}"))?;
        scan(&xml, &mut queue);
        out.push_str(&format!("type\t{}\t{}\n", &id[2..], line(&xml)));
    }
    Ok(out)
}

/// The prototypes Java's Apply Data Archives analyzer gives the functions of an
/// x86:LE:64:default:gcc program (`ApplyFunctionSignatureCmd` on a function in memory), in
/// `export`'s format, with `@PC@` for the address before the function's entry. Left out, for
/// the caller to fail on by name: a definition whose storage or types are not ported, and a name
/// two definitions have (ApplyFunctionDataTypesCmd.collectFunctionDefinitions applies one of two
/// equivalent definitions and neither of two others; `isEquivalent` is not ported). The ids are
/// those of a program that resolved every definition in table order, not Java's.
pub fn export_elf64(ar: &Archive) -> Result<String> {
    let mut ex = Exporter::new(ar, Target::Elf64)?;
    // the ids of the types `xml` names
    let ids = |xml: &str| -> Vec<String> {
        let refs = xml.split("<typeref ").skip(1);
        refs.filter_map(|r| Some(r.split(" id=\"0x").nth(1)?.split('"').next()?.to_string())).collect()
    };
    let mut given: HashMap<&str, u32> = HashMap::new();
    for &f in &ar.function_defs {
        *given.entry(ar.get(f)?.name.as_str()).or_insert(0) += 1;
    }
    let mut out = String::from("ghidra-rs-protos 1\n");
    // id -> its `type` record and the ids that names; `None`: not ported
    let mut types: BTreeMap<String, Option<(String, Vec<String>)>> = BTreeMap::new();
    let mut named: HashSet<String> = HashSet::new();
    for &f in &ar.function_defs {
        let name = &ar.get(f)?.name;
        if name.contains('\t') || given[name.as_str()] != 1 {
            continue;
        }
        let Ok(xml) = ex.function(f) else { continue };
        // every type the prototype names, and those they name
        let (mut todo, mut seen) = (ids(&xml), HashSet::new());
        let mut ported = true;
        while let Some(id) = todo.pop().filter(|_| ported) {
            if !seen.insert(id.clone()) {
                continue;
            }
            let rec = types.entry(id.clone()).or_insert_with(|| {
                let rec = u64::from_str_radix(&id, 16).ok().and_then(|v| ex.data_type(v).ok())?;
                let named = ids(&rec);
                Some((rec, named))
            });
            match rec {
                Some((_, named)) => todo.extend(named.iter().cloned()),
                None => ported = false,
            }
        }
        if ported {
            out.push_str(&format!("proto\t{name}\t{}\n", line(&xml)));
            named.extend(seen);
        }
    }
    for (id, rec) in types.iter().filter(|(id, _)| named.contains(*id)) {
        if let Some((rec, _)) = rec {
            out.push_str(&format!("type\t{id}\t{}\n", line(rec)));
        }
    }
    Ok(out)
}

/// `XmlEncode.closeElement` of a `<type>` whose children start at `start`: `/>` without any.
fn close(o: &mut String, start: usize) {
    if o.len() == start {
        o.pop();
        o.push_str("/>");
    } else {
        o.push_str("</type>");
    }
}
