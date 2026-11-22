//! The Ghidra side of the GNU demangler: `GnuDemanglerParser` (with the standard replacements of
//! `default.gnu.demangler.replacements.txt`, `useStandardReplacements` true) and the wrapping of
//! `GnuDemangler.demangle` around it (skip rules, `_GLOBAL_` / `__Z` / `._Z` / `DW.ref.` prefixes,
//! the failure checks), with `demangleOnlyKnownPatterns` false (the analyzer's default). The
//! native demangler's text comes from the caller.
//!
//! The parser works on the `Demangled*` objects it builds (`DemangledFunction`, `DemangledLambda`,
//! `DemangledVariable`, `DemangledString`, `DemangledThunk`, `DemangledAddressTable`,
//! `DemangledLabel`, `DemangledType`, `DemangledDataType`, `DemangledFunctionPointer`,
//! `DemangledTemplate`); [`GnuDemangled`] is the result's names, namespace and signature. Only the
//! fields this parser sets are kept: the Microsoft-only ones (`__ptr64`, `__unaligned`, based
//! names, trailing qualifiers, visibility ...) stay at their defaults and are left out.
//!
//! Java exceptions the parser lets through (`GnuDemangler` does not catch them) are an `Err`
//! whose text starts with the exception's simple class name; a case this port does not convert
//! is an `Err` starting "not ported". The Java strings are UTF-16; non-ASCII text is not ported.
//! `DemangledFunctionPointer`'s name (`FuncDef` and a JVM-wide counter) is "FuncDef" here: it is
//! never printed or compared.

use crate::mdmang::{java_trim, safe_name, strip_superfluous_spaces, Error, NsNode};
use regex_lite::{Captures, Regex};
use std::sync::OnceLock;

type R<T> = Result<T, Error>;

fn jerr<T>(class: &str, msg: impl std::fmt::Display) -> R<T> {
    Err(Error(format!("{class}: {msg}")))
}

fn sioobe<T>() -> R<T> {
    jerr("StringIndexOutOfBoundsException", "index out of range")
}

fn npe<T>(what: &str) -> R<T> {
    jerr("NullPointerException", what)
}

// ---------------------------------------------------------------------------------------------
// Java string helpers (the text is ASCII, so a byte index is a UTF-16 index)

/// `s.substring(b, e)`.
fn sub(s: &str, b: i64, e: i64) -> R<&str> {
    if b < 0 || e > s.len() as i64 || b > e {
        return sioobe();
    }
    // a byte index inside a non-ASCII character: not ported (Java indexes UTF-16 units), not a panic
    s.get(b as usize..e as usize).ok_or_else(|| Error("not ported: non-ASCII text (Java indexes UTF-16 units)".into()))
}

/// `s.substring(b)`.
fn sub_from(s: &str, b: i64) -> R<&str> {
    sub(s, b, s.len() as i64)
}

fn char_at(s: &str, i: i64) -> R<u8> {
    if i < 0 || i >= s.len() as i64 {
        return sioobe();
    }
    Ok(s.as_bytes()[i as usize])
}

/// `s.indexOf(c, from)`.
fn index_of_char(s: &str, c: u8, from: i64) -> i64 {
    let from = from.max(0) as usize;
    if from >= s.len() {
        return -1;
    }
    s.as_bytes()[from..].iter().position(|&b| b == c).map_or(-1, |p| (p + from) as i64)
}

fn index_of(s: &str, pat: &str) -> i64 {
    s.find(pat).map_or(-1, |p| p as i64)
}

fn last_index_of(s: &str, pat: &str) -> i64 {
    s.rfind(pat).map_or(-1, |p| p as i64)
}

/// `Character.isWhitespace` (exact for ASCII).
fn is_java_ws(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\x0B' | '\x0C' | '\r' | '\x1C'..='\x1F' | ' ')
}

/// `StringUtils.isBlank`.
fn is_blank(s: &str) -> bool {
    s.chars().all(is_java_ws)
}

fn is_letter_or_digit(c: u8) -> bool {
    c.is_ascii_alphanumeric()
}

/// `DemangledType.setName`'s safe name (no trim, unlike `DemangledObject`'s).
fn type_safe_name(name: &str) -> String {
    strip_superfluous_spaces(name).replace(' ', "_")
}

// ---------------------------------------------------------------------------------------------
// The patterns

struct Pats {
    unnecessary_parens: Regex,
    varargs_in_parens: Regex,
    array_ptr_ref: Regex,
    array_ptr_ref_piece: Regex,
    cast: Regex,
    cast_full: Regex,
    overload: Regex,
    conversion: Regex,
    new_delete: Regex,
    lambda: Regex,
    unnamed_type: Regex,
    array_data: Regex,
    descriptive_prefix: Regex,
    global_ctor_dtor: Regex,
    decltype: Regex,
    literal: Regex,
    rust_legacy: Regex,
    cold: Regex,
    array_subscript: Regex,
    member_strip: Regex,
}

fn pats() -> &'static Pats {
    static P: OnceLock<Pats> = OnceLock::new();
    P.get_or_init(|| {
        let re = |s: &str| Regex::new(s).expect("pattern");
        // `Matcher.matches()`: the whole text
        let full = |s: &str| re(&format!("^(?:{s})$"));
        let cast = r"\((?:\w+\s)*\w+[*]*(?:::\w+[*]*)*\)\s*-{0,1}\w+";
        Pats {
            unnecessary_parens: full(r"\s*(?:const){0,1}\((.*)\)\s*"),
            varargs_in_parens: full(r"\((.*)\)\.\.\."),
            array_ptr_ref: re(r"\s(?:const[\[\]\d\*&]{0,4}\s)*\(([&*])\)\s*((?:\[.*?\])+)"),
            array_ptr_ref_piece: re(r"\([&*]\)\s*\[.*?\]"),
            cast: re(cast),
            cast_full: full(cast),
            overload: full(&overload_pattern()),
            conversion: full(r"(.*operator) (.*)\(\).*"),
            new_delete: full(r"(.*operator) (new|delete)(\[\])?\((.*)\).*"),
            lambda: full(r".*(\{lambda\((.*)\)(#\d+)\})(.*)"),
            unnamed_type: re(r"(\{unnamed type#\d+\})"),
            array_data: full(r"(.+)\{(.+)\[\d*\]\{.*\}\}"),
            descriptive_prefix: full(r"((.+ )(for|to) )(.+)"),
            global_ctor_dtor: full(r"(global (constructors|destructors) keyed to )(.+)"),
            decltype: full(r"decltype \(.*\)"),
            literal: full(r"-*\d+[ul]{0,1}"),
            rust_legacy: full(r"(.*)::h[0-9a-f]{16}"),
            cold: full(r".+\.cold((\.[0-9]+)?)"),
            array_subscript: re(r"\[\d*\]"),
            member_strip: re(r"const|\*|&|\s"),
        }
    })
}

/// `createOverloadedOperatorNamePattern`.
fn overload_pattern() -> String {
    let ops = [
        "++", "--", ">>=", "<<=", "->*", "->", "==", "!=", ">=", "<=", "&&", "||", ">>", "<<", "+=", "-=", "*=", "/=",
        "%=", "&=", "|=", "^=", "+", "-", "*", "/", "%", "~", "^", "&", "|", "!", "<", ">", "=", ",", "()",
    ];
    let mut alternated: Vec<String> = ops.iter().map(|o| regex_lite::escape(o)).collect();
    alternated.push(r#"""\s_.+"#.to_string());
    format!(r"(.*operator({})\s*(<.+>){{0,1}})\s*(\(.*\))(.*)", alternated.join("|"))
}

/// `loadStandardReplacements` of the one replacements file Ghidra ships: (find, replace).
fn replacements() -> &'static [(String, String)] {
    static REP: OnceLock<Vec<(String, String)>> = OnceLock::new();
    REP.get_or_init(|| {
        let text = include_str!("../../../Ghidra/Features/GnuDemangler/data/default.gnu.demangler.replacements.txt");
        let mut out = Vec::new();
        for line in text.lines().filter(|l| !l.starts_with("//") && !is_blank(l)).map(java_trim) {
            // parseReplacement (a line without whitespace is skipped with a warning)
            let Some(i) = line.find(is_java_ws) else { continue };
            let mut replace = java_trim(&line[..i]);
            if replace == "\"\"" {
                replace = "";
            }
            let find = java_trim(&line[i..]);
            out.push((find.to_string(), replace.to_string()));
            for alt in ["std::__cxx11::", "__gnu_cxx::"] {
                if find.starts_with("std::") && replace.starts_with("std::") {
                    out.push((find.replacen("std::", alt, 1), replace.replacen("std::", alt, 1)));
                }
            }
        }
        out
    })
}

// ---------------------------------------------------------------------------------------------
// The Demangled objects

/// `DemangledType` / `DemangledDataType` / `DemangledFunctionPointer`.
#[derive(Debug, Clone, Default)]
struct DataType {
    name: String,
    demangled: String,
    namespace: Option<Box<DataType>>,
    template: Option<Vec<DataType>>,
    is_const: bool,
    is_class: bool,
    is_enum: bool,
    is_struct: bool,
    is_unsigned: bool,
    lref: bool,
    rref: bool,
    varargs: bool,
    pointer_levels: u32,
    array_dims: i64,
    /// a `DemangledFunctionPointer`
    func: Option<Box<FuncPtr>>,
}

#[derive(Debug, Clone)]
struct FuncPtr {
    ret: DataType,
    params: Vec<DataType>,
    /// `displayFunctionPointerSyntax`
    display: bool,
}

impl DataType {
    fn new(name: &str) -> R<DataType> {
        let mut dt = DataType::default();
        dt.set_name(name)?;
        Ok(dt)
    }

    fn set_name(&mut self, name: &str) -> R<()> {
        if is_blank(name) {
            return jerr("IllegalArgumentException", "Name cannot be blank");
        }
        self.demangled = name.to_string();
        self.name = type_safe_name(name);
        Ok(())
    }

    fn is_reference(&self) -> bool {
        self.lref || self.rref
    }

    fn set_lref(&mut self) {
        self.lref = true;
        self.rref = false;
    }

    /// `DemangledType.getNamespaceString`.
    fn namespace_string(&self) -> String {
        let mut b = String::new();
        if let Some(ns) = &self.namespace {
            b.push_str(&ns.namespace_string());
            b.push_str("::");
        }
        b.push_str(&self.demangled);
        if let Some(t) = &self.template {
            b.push_str(&to_template(t));
        }
        b
    }

    /// `DemangledDataType.getSignature` (`toSignature(null)` for a function pointer).
    fn signature(&self) -> String {
        if self.func.is_some() {
            return self.to_signature(None);
        }
        let mut b = String::new();
        if self.is_struct {
            b.push_str("struct ");
        }
        if self.is_enum {
            b.push_str("enum ");
        }
        if self.is_class {
            b.push_str("class ");
        }
        if self.is_unsigned {
            b.push_str("unsigned ");
        }
        if let Some(ns) = &self.namespace {
            b.push_str(&ns.namespace_string());
            b.push_str("::");
        }
        b.push_str(&self.demangled);
        if let Some(t) = &self.template {
            b.push_str(&to_template(t));
        }
        if self.is_const {
            b.push_str(" const");
        }
        if self.pointer_levels >= 1 {
            b.push_str(" *");
        }
        if self.lref {
            b.push_str(" &");
        } else if self.rref {
            b.push_str(" &&");
        }
        for _ in 1..self.pointer_levels {
            b.push_str(" *");
        }
        if self.array_dims > 0 && pats().array_subscript.find(&self.name).is_none() {
            for _ in 0..self.array_dims {
                b.push_str("[]");
            }
        }
        b
    }

    /// `AbstractDemangledFunctionDefinitionDataType.toSignature`.
    fn to_signature(&self, name: Option<&str>) -> String {
        let f = self.func.as_ref().expect("a function pointer");
        let mut b1 = String::new();
        // getConventionPointerNameString (no calling convention, parent name or modifier)
        let mut s = String::new();
        if self.pointer_levels > 0 || self.is_reference() {
            for _ in 0..self.pointer_levels {
                s.push('*');
            }
            if self.lref {
                s.push_str(" &");
            } else if self.rref {
                s.push_str(" &&");
            }
        }
        if is_blank(&s) {
            s.clear();
        }
        if let Some(name) = name {
            if !s.is_empty() && !s.ends_with(' ') {
                s.push(' ');
            }
            s.push_str(name);
        }
        if f.display {
            b1.push('(');
            b1.push_str(&s);
            b1.push(')');
        }
        b1.push('(');
        b1.push_str(&f.params.iter().map(DataType::signature).collect::<Vec<_>>().join(","));
        b1.push(')');
        let mut b = if f.ret.func.is_some() {
            f.ret.to_signature(Some(&b1)) + " "
        } else {
            format!("{} {b1}", f.ret.signature())
        };
        if self.is_const {
            if b.len() > 2 {
                b.push(' ');
            }
            b.push_str("const");
        }
        b
    }
}

/// `DemangledTemplate.toTemplate`.
fn to_template(t: &[DataType]) -> String {
    format!("<{}>", t.iter().map(DataType::signature).collect::<Vec<_>>().join(","))
}

/// Which `DemangledObject` subclass the parser made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GnuKind {
    Function,
    Lambda,
    Variable,
    String,
    Thunk,
    AddressTable,
    Label,
}

impl GnuKind {
    /// The Java class's simple name.
    pub fn java_name(self) -> &'static str {
        match self {
            GnuKind::Function => "DemangledFunction",
            GnuKind::Lambda => "DemangledLambda",
            GnuKind::Variable => "DemangledVariable",
            GnuKind::String => "DemangledString",
            GnuKind::Thunk => "DemangledThunk",
            GnuKind::AddressTable => "DemangledAddressTable",
            GnuKind::Label => "DemangledLabel",
        }
    }

    fn is_function(self) -> bool {
        matches!(self, GnuKind::Function | GnuKind::Lambda)
    }
}

/// A `Demangled` namespace: a `DemangledType`, or an object (the namespace of `__tls_init`).
#[derive(Debug, Clone)]
enum Ns {
    Type(Box<DataType>),
    Obj(Box<Object>),
}

impl Ns {
    fn namespace_name(&self) -> String {
        match self {
            Ns::Type(t) => t.name.clone(),
            Ns::Obj(o) => o.namespace_name(),
        }
    }

    fn demangled_name(&self) -> String {
        match self {
            Ns::Type(t) => t.demangled.clone(),
            Ns::Obj(o) => o.demangled_name.clone().unwrap_or_else(|| "null".into()),
        }
    }

    fn namespace_string(&self) -> String {
        match self {
            Ns::Type(t) => t.namespace_string(),
            Ns::Obj(o) => o.namespace_string(),
        }
    }
}

/// A `DemangledObject`.
#[derive(Debug, Clone)]
struct Object {
    kind: GnuKind,
    original: String,
    raw: String,
    demangled_name: Option<String>,
    name: Option<String>,
    special_prefix: Option<String>,
    namespace: Option<Ns>,
    is_const: bool,
    /// `setBackupPlateComment`
    plate: Option<String>,
    // DemangledFunction
    ret: Option<DataType>,
    cc: Option<String>,
    params: Vec<DataType>,
    template: Option<Vec<DataType>>,
    overloaded: bool,
    // DemangledString: the string and its length
    string: Option<(String, i32)>,
    // DemangledThunk
    thunked: Option<Box<Object>>,
    signature_prefix: Option<String>,
    covariant: bool,
}

impl Object {
    fn new(kind: GnuKind, original: &str, name: Option<&str>) -> R<Object> {
        let mut o = Object {
            kind,
            original: original.to_string(),
            raw: original.to_string(),
            demangled_name: None,
            name: None,
            special_prefix: None,
            namespace: None,
            is_const: false,
            plate: None,
            ret: None,
            cc: None,
            params: Vec::new(),
            template: None,
            overloaded: false,
            string: None,
            thunked: None,
            signature_prefix: None,
            covariant: false,
        };
        o.set_name(name)?;
        Ok(o)
    }

    /// `DemangledObject.setName`.
    fn set_name(&mut self, name: Option<&str>) -> R<()> {
        if self.kind == GnuKind::Variable && name == Some("") {
            // DemangledVariable.getName then answers SymbolUtilities.replaceInvalidChars of the
            // signature
            return Err(Error("not ported: a DemangledVariable with an empty name".into()));
        }
        self.demangled_name = name.map(str::to_string);
        self.name = name.map(safe_name);
        Ok(())
    }

    fn name_or_null(&self) -> &str {
        self.name.as_deref().unwrap_or("null")
    }

    /// `DemangledFunction.getParameterString`.
    fn parameter_string(&self) -> String {
        format!("({})", self.params.iter().map(DataType::signature).collect::<Vec<_>>().join(","))
    }

    /// `getNamespaceName`.
    fn namespace_name(&self) -> String {
        match self.kind {
            GnuKind::Function => format!("{}{}", self.name_or_null(), self.parameter_string()),
            _ => self.name_or_null().to_string(),
        }
    }

    /// `DemangledObject.getNamespaceString`.
    fn namespace_string(&self) -> String {
        match &self.namespace {
            Some(ns) => format!("{}::{}", ns.namespace_string(), self.namespace_name()),
            None => self.namespace_name(),
        }
    }

    /// `getSignature(false)`; `None` where Java throws a `NullPointerException`.
    fn signature(&self) -> Option<String> {
        let prefix = self.special_prefix.as_deref();
        Some(match self.kind {
            GnuKind::Function | GnuKind::Lambda => self.function_signature(),
            GnuKind::Variable => {
                let mut b = prefix.map(|p| format!("{p} ")).unwrap_or_default();
                let has_name = self.demangled_name.as_deref().is_some_and(|n| !is_blank(n));
                let mut spacer = "";
                if self.is_const {
                    b.push_str("const");
                    spacer = " ";
                }
                if let Some(ns) = &self.namespace {
                    b.push_str(spacer);
                    spacer = "";
                    b.push_str(&ns.namespace_string());
                    if has_name {
                        b.push_str("::");
                    }
                }
                if has_name {
                    b.push_str(spacer);
                    b.push_str(self.name_or_null());
                }
                b
            }
            GnuKind::String => {
                format!("{}{}", prefix.unwrap_or(""), self.string.as_ref().map_or("null", |s| s.0.as_str()))
            }
            GnuKind::Thunk => {
                let f = self.thunked.as_ref()?;
                format!("{}{}", self.signature_prefix.as_deref().unwrap_or("thunk "), f.function_signature())
            }
            GnuKind::AddressTable => {
                let mut b = prefix.map(|p| format!("{p} ")).unwrap_or_default();
                let ns = self.namespace.as_ref()?.namespace_string();
                b.push_str(&ns);
                if !ns.ends_with("::") {
                    b.push_str("::");
                }
                b.push_str(self.demangled_name.as_deref().unwrap_or("null"));
                b
            }
            GnuKind::Label => self.name_or_null().to_string(),
        })
    }

    /// `DemangledFunction.getSignature(false)` (none of the trailing qualifiers is set).
    fn function_signature(&self) -> String {
        let fptr_ret = self.ret.as_ref().filter(|r| r.func.is_some());
        let mut b = String::new();
        if fptr_ret.is_none() {
            if let Some(p) = &self.special_prefix {
                b.push_str(p);
                b.push(' ');
            }
            if let Some(r) = &self.ret {
                b.push_str(&r.signature());
                b.push(' ');
            }
        }
        if let Some(cc) = &self.cc {
            b.push_str(cc);
            b.push(' ');
        }
        if let Some(ns) = &self.namespace {
            b.push_str(&ns.namespace_string());
            b.push_str("::");
        }
        b.push_str(self.demangled_name.as_deref().unwrap_or("null"));
        if let Some(t) = &self.template {
            b.push_str(&to_template(t));
        }
        if self.kind != GnuKind::Lambda {
            b.push('(');
            if self.params.is_empty() {
                b.push_str("void");
            }
            b.push_str(&self.params.iter().map(DataType::signature).collect::<Vec<_>>().join(","));
            b.push(')');
        }
        if let Some(r) = fptr_ret {
            let partial = r.to_signature(Some(&b));
            b = self.special_prefix.as_ref().map(|p| format!("{p} ")).unwrap_or_default();
            b.push_str(&partial);
        }
        b
    }
}

// ---------------------------------------------------------------------------------------------
// The result

/// What the GNU demangler makes of a symbol: the parts of the `DemangledObject` the Demangler
/// analyzer and the signature use.
#[derive(Debug, Clone)]
pub struct GnuDemangled {
    pub kind: GnuKind,
    /// `getOriginalDemangled()`: the plate comment the Demangler analyzer writes
    pub original: String,
    /// `getRawDemangled()`: the demangled text before the replacements
    pub raw: String,
    /// `getName()`: the safe name
    pub name: Option<String>,
    /// `getDemangledName()`
    pub demangled_name: Option<String>,
    /// `getNamespace()`, innermost first (`getNamespaceName()`, `getDemangledName()`)
    pub namespace: Vec<NsNode>,
    /// `getSignature(false)`; `None` where Java throws a `NullPointerException`
    pub signature: Option<String>,
    pub special_prefix: Option<String>,
    pub is_const: bool,
    /// `setBackupPlateComment`
    pub plate_comment: Option<String>,
    /// `DemangledFunction.getCallingConvention()`
    pub calling_convention: Option<String>,
    /// a function's return type's signature
    pub return_type: Option<String>,
    /// a function's parameters' signatures
    pub parameters: Vec<String>,
    /// a function's `getTemplate().toTemplate()`
    pub template: Option<String>,
    pub overloaded_operator: bool,
    /// a `DemangledString`'s string and length
    pub string: Option<(String, i32)>,
    namespace_str: Option<String>,
}

impl GnuDemangled {
    fn from_object(o: &Object) -> GnuDemangled {
        let mut namespace = Vec::new();
        let mut ns = o.namespace.clone();
        while let Some(n) = ns {
            namespace.push(NsNode { name: n.namespace_name(), demangled: n.demangled_name() });
            ns = match n {
                Ns::Type(t) => t.namespace.map(Ns::Type),
                Ns::Obj(o) => o.namespace,
            };
        }
        let f = o.kind.is_function();
        GnuDemangled {
            kind: o.kind,
            original: o.original.clone(),
            raw: o.raw.clone(),
            name: o.name.clone(),
            demangled_name: o.demangled_name.clone(),
            namespace,
            signature: o.signature(),
            special_prefix: o.special_prefix.clone(),
            is_const: o.is_const,
            plate_comment: o.plate.clone(),
            calling_convention: o.cc.clone().filter(|_| f),
            return_type: o.ret.as_ref().map(DataType::signature),
            parameters: o.params.iter().map(DataType::signature).collect(),
            template: o.template.as_deref().map(to_template),
            overloaded_operator: o.overloaded,
            string: o.string.clone(),
            namespace_str: o.namespace.as_ref().map(Ns::namespace_string),
        }
    }

    /// The namespace's `getNamespaceString()` (outermost first, demangled names).
    pub fn namespace_string(&self) -> Option<String> {
        self.namespace_str.clone()
    }

    /// The symbol's `getName(true)` once the Demangler analyzer applied it: the namespaces' names
    /// (`createNamespace`) and the safe name.
    pub fn qualified_name(&self) -> Option<String> {
        let mut parts: Vec<&str> = self.namespace.iter().rev().map(|n| n.name.as_str()).collect();
        parts.push(self.name.as_deref()?);
        Some(parts.join("::"))
    }
}

// ---------------------------------------------------------------------------------------------
// GnuDemangler

/// `GnuDemangler.demangle` with the analyzer's options; `native` is the native demangler's
/// answer for the (prefix-stripped) mangled name (`Ok(None)`: no answer). `Ok(None)` where Java
/// returns `null` or throws a `DemangledException`.
pub fn demangle(mangled: &str, native: impl FnOnce(&str) -> R<Option<String>>) -> R<Option<GnuDemangled>> {
    // skip
    if mangled.find('@').is_some_and(|p| p > 0) || mangled.starts_with("___") {
        return Ok(None);
    }
    let original_mangled = mangled;
    let mut mangled = mangled;
    let mut global_prefix = None;
    if mangled.starts_with("_GLOBAL_") {
        if let Some(i) = mangled.find("_Z").filter(|&i| i > 0) {
            global_prefix = Some(&mangled[..i]);
            mangled = &mangled[i..];
        }
    } else if mangled.starts_with("__Z") || mangled.starts_with("._Z") {
        mangled = &mangled[1..];
    }
    let mut is_dwarf = false;
    if let Some(rest) = mangled.strip_prefix("DW.ref.") {
        mangled = rest;
        is_dwarf = true;
    }
    let Some(text) = native(mangled)? else { return Ok(None) };
    let demangled = java_trim(&text);
    if demangled.is_empty() || mangled == demangled {
        return Ok(None);
    }
    let mut d = Parser::default().parse_object(original_mangled, demangled)?;
    if let Some(gp) = global_prefix {
        let prefix = match gp {
            "_GLOBAL__sub_I_" => "global_init_constructor_",
            "_GLOBAL__sub_D_" => "global_destructor_",
            p => p,
        };
        let mut f = Object::new(GnuKind::Function, demangled, Some(&format!("{prefix}{}", d.name_or_null())))?;
        f.namespace = d.namespace.take();
        d = f;
    }
    if is_dwarf {
        let mut t = Object::new(GnuKind::AddressTable, demangled, None)?;
        t.special_prefix = Some("DWARF Debug ".into());
        t.set_name(d.name.as_deref())?;
        t.namespace = d.namespace.take();
        d = t;
    }
    Ok(Some(GnuDemangled::from_object(&d)))
}

/// `GnuDemanglerParser.parse(mangled, demangled)` (with the standard replacements).
pub fn parse(mangled: &str, demangled: &str) -> R<GnuDemangled> {
    Ok(GnuDemangled::from_object(&Parser::default().parse_object(mangled, demangled)?))
}

/// One line of `ghidra-rs gnu-parse` (the format of tools/ghidra/GnuParseDump.java) for a
/// mangled name and the native demangler's text.
pub fn dump_line(mangled: &str, text: &str) -> String {
    let esc = |s: &str| s.replace('\\', "\\\\").replace('\t', "\\t").replace('\n', "\\n").replace('\r', "\\r");
    let col = |b: &mut String, s: Option<&str>| {
        b.push('\t');
        b.push_str(&s.map_or("<null>".into(), esc));
    };
    let mut b = esc(mangled);
    let d = match demangle(mangled, |_| Ok(Some(text.to_string()))) {
        Ok(None) => return b + "\tNONE",
        Err(e) if e.is_not_ported() => return format!("{b}\tNOTPORTED\t{}", esc(&e.0)),
        Err(e) => return format!("{b}\tERR {}", e.0.split(':').next().unwrap_or_default()),
        Ok(Some(d)) => d,
    };
    b.push_str("\tOK");
    col(&mut b, Some(d.kind.java_name()));
    col(&mut b, d.name.as_deref());
    col(&mut b, d.demangled_name.as_deref());
    col(&mut b, Some(d.original.as_str()));
    col(&mut b, Some(d.raw.as_str()));
    let ns: Vec<String> = d.namespace.iter().map(|n| format!("{} = {}", n.name, n.demangled)).collect();
    col(&mut b, Some(ns.join(" | ").as_str()));
    col(&mut b, d.namespace_string().as_deref());
    col(&mut b, Some(d.signature.as_deref().unwrap_or("<ERR NullPointerException>")));
    col(&mut b, d.special_prefix.as_deref());
    col(&mut b, Some(if d.is_const { "10000" } else { "00000" }));
    col(&mut b, d.plate_comment.as_deref());
    if d.kind.is_function() {
        col(&mut b, d.calling_convention.as_deref());
        col(&mut b, d.return_type.as_deref());
        col(&mut b, Some(d.parameters.join(" , ").as_str()));
        col(&mut b, d.template.as_deref());
        col(&mut b, Some(if d.overloaded_operator { "1" } else { "0" }));
    } else if let Some((s, len)) = &d.string {
        col(&mut b, Some(s.as_str()));
        col(&mut b, Some(len.to_string().as_str()));
    }
    b
}

// ---------------------------------------------------------------------------------------------
// GnuDemanglerParser

const LAMBDA_START: &str = "{lambda";
const TYPEINFO_NAME_FOR: &str = "typeinfo name for ";
const TLS_INIT_FOR: &str = "TLS init function for ";
const ADDRESS_TABLE_PREFIXES: [&str; 5] =
    ["construction vtable for ", "VTT for ", "vtable for ", "typeinfo fn for ", "typeinfo for "];
const PLACEHOLDER: &str = "REPLACEDSTRINGTEMPNAMEPLACEHOLDERVALUE";

#[derive(Default)]
struct Parser {
    mangled_source: String,
    demangled_source: String,
}

/// `ReplacedString`: a text with parts replaced by a placeholder.
struct Replaced {
    placeholder: String,
    replaced: String,
    modified: String,
}

impl Replaced {
    fn restore(&self, s: &str) -> String {
        s.replace(&self.placeholder, &self.replaced)
    }

    /// `CustomReplacedString`.
    fn custom(input: &str, text: &str) -> Replaced {
        let placeholder = format!("CUSTOMREPLACEDSTRING{PLACEHOLDER}");
        Replaced { modified: input.replace(text, &placeholder), replaced: text.to_string(), placeholder }
    }

    /// `TemplatedString`: every top-level template is the placeholder, and the placeholder
    /// restores to all templates' text together.
    fn templated(input: &str) -> Replaced {
        let placeholder = format!("TEMPLATEDSTRING{PLACEHOLDER}");
        let (mut buffy, mut templates) = (String::new(), String::new());
        let mut depth = 0i64;
        for c in input.chars() {
            if c == '<' {
                if depth == 0 {
                    buffy.push_str(&placeholder);
                }
                templates.push(c);
                depth += 1;
                continue;
            } else if c == '>' {
                templates.push(c);
                depth -= 1;
                continue;
            }
            if depth == 0 {
                buffy.push(c);
            } else {
                templates.push(c);
            }
        }
        Replaced { placeholder, replaced: templates, modified: buffy }
    }

    /// `LambdaReplacedString`: each "lambda" but the first is the placeholder.
    fn lambda(input: &str) -> Replaced {
        let placeholder = format!("LAMBDAREPLACEDSTRING{PLACEHOLDER}");
        let mut modified = String::new();
        let mut rest = input;
        if let Some(p) = rest.find("lambda") {
            modified.push_str(&rest[..p + 6]);
            rest = &rest[p + 6..];
            modified.push_str(&rest.replace("lambda", &placeholder));
        } else {
            modified.push_str(rest);
        }
        Replaced { placeholder, replaced: "lambda".into(), modified }
    }
}

/// `FunctionSignatureParts`.
struct SignatureParts {
    return_type: Option<String>,
    name: String,
    raw_prefix: String,
    params: Vec<DataType>,
}

impl Parser {
    fn parse_object(&mut self, mangled: &str, demangled: &str) -> R<Object> {
        if !mangled.is_ascii() || !demangled.is_ascii() {
            return Err(Error("not ported: non-ASCII text (Java indexes UTF-16 units)".into()));
        }
        let p = pats();
        let demangled = match p.rust_legacy.captures(demangled) {
            Some(c) => c[1].to_string(),
            None => demangled.to_string(),
        };
        let raw = demangled.clone();
        let mut d = demangled;
        for (find, replace) in replacements() {
            if !find.is_empty() {
                d = d.replace(find.as_str(), replace);
            }
        }
        self.mangled_source = mangled.to_string();
        self.demangled_source = d.clone();
        let mut o = match self.specialized(&d)? {
            Some(o) => o,
            None => self.function_or_variable(&d)?,
        };
        o.raw = raw;
        Ok(o)
    }

    /// `getSpecializedBuilder(...).build()`.
    fn specialized(&self, d: &str) -> R<Option<Object>> {
        if pats().cold.is_match(&self.mangled_source) {
            return Ok(Some(Object::new(GnuKind::Label, &self.demangled_source, Some(d))?));
        }
        if let Some(o) = self.special_prefix(d)? {
            return Ok(Some(o));
        }
        if let Some(o) = self.operator(d)? {
            return Ok(Some(o));
        }
        if self.mangled_source.starts_with("_ZZ") || self.mangled_source.starts_with("__ZZ") {
            return self.item_in_namespace_handler(d).map(Some);
        }
        Ok(None)
    }

    /// `getSpecialPrefixHandler(...).build()`.
    fn special_prefix(&self, d: &str) -> R<Option<Object>> {
        let p = pats();
        let Some(c) = p.descriptive_prefix.captures(d) else { return Ok(None) };
        let (prefix, ty) = (&c[1], &c[4]);
        if prefix.contains("thunk") {
            return self.thunk(prefix, ty).map(Some);
        }
        if ADDRESS_TABLE_PREFIXES.contains(&prefix) {
            let pos = last_index_of(java_trim(prefix), " ");
            let name = sub(prefix, 0, pos)?.replace(' ', "-");
            let ns = self.function_or_variable(ty)?;
            let mut t = Object::new(GnuKind::AddressTable, d, Some(&name))?;
            t.namespace = Some(Ns::Type(Box::new(self.namespace_type(&ns)?)));
            return Ok(Some(t));
        }
        if prefix.starts_with(TYPEINFO_NAME_FOR) {
            let ty = java_trim(sub_from(d, TYPEINFO_NAME_FOR.len() as i64)?);
            self.function_or_variable(ty)?;
            let mut s = Object::new(GnuKind::String, &self.demangled_source, Some("typeinfo-name"))?;
            s.string = Some((ty.to_string(), -1));
            s.special_prefix = Some(TYPEINFO_NAME_FOR.into());
            s.namespace = self.to_namespaces(&symbol_path(&self.remove_bad_spaces(ty))?)?.map(Ns::Type);
            return Ok(Some(s));
        }
        if prefix.starts_with(TLS_INIT_FOR) {
            let ns = self.function_or_variable(ty)?;
            let mut f = Object::new(GnuKind::Function, &self.demangled_source, Some("__tls_init"))?;
            f.original = d.to_string();
            f.namespace = Some(Ns::Obj(Box::new(ns)));
            return Ok(Some(f));
        }
        if let Some(a) = p.array_data.captures(ty) {
            return self.array(d, prefix, &a[1], java_trim(&a[2])).map(Some);
        }
        if let Some(g) = p.global_ctor_dtor.captures(d) {
            return self.global_ctor_dtor(d, &g[1], &g[3]).map(Some);
        }
        self.item_in_namespace_handler(ty).map(Some)
    }

    /// `ItemInNamespaceHandler(demangled).build()`.
    fn item_in_namespace_handler(&self, d: &str) -> R<Object> {
        let o = self.function_or_variable(d)?;
        Ok(self.item_in_namespace(d)?.unwrap_or(o))
    }

    /// `ThunkHandler.build()`.
    fn thunk(&self, prefix: &str, ty: &str) -> R<Object> {
        let mut f = self.function_or_variable(ty)?;
        if !f.kind.is_function() {
            return jerr("ClassCastException", "DemangledVariable to DemangledFunction");
        }
        f.cc = Some("__thiscall".into());
        let mut t = Object::new(GnuKind::Thunk, &self.demangled_source, f.name.as_deref())?;
        t.namespace = f.namespace.clone();
        t.covariant = prefix.contains("covariant return thunk");
        t.signature_prefix = Some(prefix.to_string());
        t.thunked = Some(Box::new(f));
        Ok(t)
    }

    /// `ArrayHandler.build()`.
    fn array(&self, d: &str, prefix: &str, ty: &str, array_type: &str) -> R<Object> {
        self.function_or_variable(ty)?;
        let Some(o) = self.item_in_namespace(ty)? else { return npe("parseItemInNamespace returned null") };
        if o.kind == GnuKind::Variable && array_type == "char" && ty.contains("StringLiteral") {
            let mut s = Object::new(GnuKind::String, d, Some(ty))?;
            s.string = Some((ty.to_string(), -1));
            s.special_prefix = Some(prefix.to_string());
            return Ok(s);
        }
        Ok(o)
    }

    /// `GlobalCtorDtorHandler.build()`.
    fn global_ctor_dtor(&self, d: &str, prefix: &str, ty: &str) -> R<Object> {
        self.function_or_variable(ty)?;
        let name = if ty.contains('(') { ty.to_string() } else { format!("{ty}()") };
        let mut f = self.function_or_variable(&name)?;
        f.original = d.to_string();
        let full = format!("{}{}", prefix.replace(' ', "."), f.name_or_null());
        f.set_name(Some(&full))?;
        f.plate = Some(d.to_string());
        Ok(f)
    }

    /// `createNamespaceDemangledType`.
    fn namespace_type(&self, o: &Object) -> R<DataType> {
        let mut t = DataType::new(&self.remove_bad_spaces(&o.namespace_name()))?;
        t.namespace = match &o.namespace {
            None => None,
            Some(Ns::Type(n)) => Some(n.clone()),
            Some(Ns::Obj(_)) => return Err(Error("not ported: a DemangledType in an object's namespace".into())),
        };
        Ok(t)
    }

    /// `parseItemInNamespace`.
    fn item_in_namespace(&self, text: &str) -> R<Option<Object>> {
        let pos = last_index_of(text, "::");
        if pos == -1 {
            return Ok(None);
        }
        let parent = self.function_or_variable(sub(text, 0, pos)?)?;
        let mut item = self.function_or_variable(sub_from(text, pos + 2)?)?;
        item.namespace = Some(Ns::Type(Box::new(self.namespace_type(&parent)?)));
        Ok(Some(item))
    }

    /// `getOperatorHandler(...).build()`.
    fn operator(&self, d: &str) -> R<Option<Object>> {
        let p = pats();
        if let Some(c) = p.overload.captures(d) {
            let op = c.get(2).expect("group 2");
            let leaf_start = find_namespace_start(d, d.len() as i64 - 1, op.start() as i64)?;
            if leaf_start <= op.start() as i64 {
                return self.overload(d, &c).map(Some);
            }
        }
        if let Some(c) = p.conversion.captures(d) {
            return self.conversion(&c[1], &c[2]).map(Some);
        }
        if let Some(c) = p.new_delete.captures(d) {
            return self.new_delete(&c[1], &c[2], c.get(3).is_some(), &c[4]).map(Some);
        }
        Ok(None)
    }

    /// `OverloadOperatorHandler.build()`.
    fn overload(&self, d: &str, c: &Captures) -> R<Object> {
        let op = c.get(2).expect("group 2");
        let (start, mut end) = (op.start() as i64, op.end() as i64);
        // getTemplates
        let mut templates = "";
        if next_char_is(d, end, b'<')? {
            let template_end = find_balanced_end(d, end, b'<', b'>')?;
            if template_end != -1 {
                templates = sub(d, end, template_end + 1)?;
            }
        }
        end += templates.len() as i64;
        let base = format!("operator{}", sub(d, start, end)?);
        let fixed = d.replace(&base, "TEMPNAMEPLACEHOLDERVALUE");
        let mut f = self.function_or_variable(&fixed)?;
        if !f.kind.is_function() {
            return jerr("ClassCastException", "DemangledVariable to DemangledFunction");
        }
        f.overloaded = true;
        let simple = format!("operator{}", op.as_str());
        if !is_blank(templates) {
            f.template = Some(self.parse_template(&self.remove_bad_spaces(templates))?);
        }
        f.set_name(Some(&simple))?;
        Ok(f)
    }

    /// `ConversionOperatorHandler.build()`.
    fn conversion(&self, full_name: &str, full_return_type: &str) -> R<Object> {
        let mut rt = full_return_type.to_string();
        let is_const = rt.contains(" const");
        if is_const {
            rt = rt.replace(" const", "");
        }
        let mut m = Object::new(GnuKind::Function, &self.demangled_source, None)?;
        let mut ret = self.parse_data_type(&rt)?;
        if is_const {
            ret.is_const = true;
        }
        m.ret = Some(ret);
        let op_index = last_index_of(full_name, "::operator");
        let ns = strip_off_templates(sub(full_name, 0, op_index)?);
        m.namespace = self.to_namespaces(&symbol_path(&ns)?)?.map(Ns::Type);
        let path = symbol_path(&strip_off_templates(&rt))?;
        let mut short = path.last().expect("a path").as_str();
        if short.contains('(') {
            short = "function.pointer";
        }
        m.set_name(Some(&format!("operator.cast.to.{short}")))?;
        m.plate = Some(format!("{full_name} {rt}()"));
        m.overloaded = true;
        Ok(m)
    }

    /// `NewOrDeleteOperatorHandler.build()`.
    fn new_delete(&self, operator_text: &str, operator_name: &str, array: bool, params: &str) -> R<Object> {
        let mut f = Object::new(GnuKind::Function, &self.demangled_source, None)?;
        f.overloaded = true;
        let mut ret = DataType::new("void")?;
        if operator_name.starts_with("new") {
            ret.pointer_levels += 1;
        }
        f.ret = Some(ret);
        self.set_name_and_namespace(&mut f, operator_text)?;
        f.params = self.parse_parameters(params)?;
        let name = if array { format!("{operator_name}[]") } else { operator_name.to_string() };
        f.set_name(Some(&format!("operator.{name}")))?;
        f.plate = Some(format!("{operator_text} {operator_name}"));
        Ok(f)
    }

    /// `parseFunctionOrVariable`.
    fn function_or_variable(&self, d: &str) -> R<Object> {
        let Some(parts) = self.signature_parts(d)? else { return self.variable(d) };
        let mut f = Object::new(GnuKind::Function, d, None)?;
        let mut simple = parts.name.clone();
        if simple.ends_with(LAMBDA_START) {
            let lambda_start = parts.raw_prefix.len() as i64 - LAMBDA_START.len() as i64;
            let Some(full) = self.lambda_name(sub_from(d, lambda_start)?)? else {
                return npe("getLambdaName returned null");
            };
            simple = simple.replace(LAMBDA_START, &self.remove_bad_spaces(&full));
            f = Object::new(GnuKind::Lambda, d, None)?;
            f.plate = Some(full);
        }
        self.set_name_and_namespace(&mut f, &simple)?;
        f.params = parts.params;
        // setReturnType
        let rt = parts.return_type.filter(|r| !pats().decltype.is_match(r));
        f.ret = Some(match rt {
            Some(r) => self.parse_data_type(&r)?,
            None => DataType::new("undefined")?,
        });
        if d.ends_with(" const") {
            f.is_const = true;
        }
        Ok(f)
    }

    /// `parseVariable`.
    fn variable(&self, d: &str) -> R<Object> {
        let name = java_trim(&self.remove_bad_spaces(d)).to_string();
        let mut v = Object::new(GnuKind::Variable, &self.demangled_source, None)?;
        self.set_name_and_namespace(&mut v, &name)?;
        Ok(v)
    }

    /// `new FunctionSignatureParts(...)`; `None` when not a function.
    fn signature_parts(&self, sig: &str) -> R<Option<SignatureParts>> {
        let Some((start, end)) = locate_parameters(sig)? else { return Ok(None) };
        let params = self.parse_parameters(java_trim(sub(sig, start + 1, end)?))?;
        let raw_prefix = java_trim(sub(sig, 0, start)?).to_string();
        let prefix = self.remove_bad_spaces(&raw_prefix);
        let name_start = last_index_of(&prefix, " ").max(0);
        let name = java_trim(sub_from(&prefix, name_start)?).to_string();
        let return_type = (name_start > 0).then(|| prefix[..name_start as usize].to_string());
        Ok(Some(SignatureParts { return_type, name, raw_prefix, params }))
    }

    /// `getLambdaName(...).getFullText()`.
    fn lambda_name(&self, name: &str) -> R<Option<String>> {
        if !name.starts_with('{') {
            return Ok(None);
        }
        let r = Replaced::lambda(name);
        Ok(pats().lambda.captures(&r.modified).map(|c| r.restore(&c[1])))
    }

    /// `removeBadSpaces`: `CondensedString.getCondensedText`.
    fn remove_bad_spaces(&self, text: &str) -> String {
        // fixupUnnamedTypes
        let mut fixed = text.to_string();
        for m in pats().unnamed_type.find_iter(text) {
            let t = m.as_str();
            fixed = fixed.replace(t, &t.replacen(' ', "_", 1));
        }
        // convertTemplateAndParameterSpaces
        let bytes = fixed.as_bytes();
        let mut out = String::new();
        let mut depth = 0;
        let mut last = 0u8;
        for (i, &ch) in bytes.iter().enumerate() {
            if ch == b'<' || ch == b'(' {
                depth += 1;
            } else if (ch == b'>' || ch == b')') && depth != 0 {
                depth -= 1;
            }
            if depth > 0 && ch == b' ' {
                let next = bytes.get(i + 1).copied().unwrap_or(0);
                if last != 0 && next != 0 && is_letter_or_digit(last) && is_letter_or_digit(next) {
                    out.push('_');
                }
            } else {
                out.push(ch as char);
            }
            last = ch;
        }
        java_trim(&out).to_string()
    }

    /// `parseParameters`.
    fn parse_parameters(&self, s: &str) -> R<Vec<DataType>> {
        tokenize_parameters(s)?.iter().map(|p| self.parse_parameter(p)).collect()
    }

    /// `parseParameter`.
    fn parse_parameter(&self, p: &str) -> R<DataType> {
        let pt = pats();
        if pt.cast_full.is_match(p) {
            return DataType::new(p);
        }
        if let Some(c) = pt.varargs_in_parens.captures(p) {
            let mut dt = self.parse_data_type(&c[1])?;
            dt.varargs = true;
            return Ok(dt);
        }
        if java_trim(p).is_empty() {
            return DataType::new("missing_argument");
        }
        self.parse_data_type(p)
    }

    /// `parseDataType`.
    fn parse_data_type(&self, full: &str) -> R<DataType> {
        let mut dt = self.type_in_namespace(full)?;
        let datatype = dt.demangled.clone();
        if is_member_pointer_or_reference(full, &datatype) {
            return self.member_pointer(full);
        }
        if pats().literal.is_match(full) {
            return DataType::new(if full.ends_with('l') { "long" } else { "int" });
        }
        let dlen = datatype.len() as i64;
        let mut finished = false;
        let mut i = 0i64;
        while i < dlen {
            let ch = char_at(&datatype, i)?;
            if ch == b'&' && i == 0 {
                i += 1;
                continue;
            }
            if !finished && is_data_type_name_char(ch) {
                i += 1;
                continue;
            }
            if !finished {
                finished = true;
                if datatype == "..." {
                    dt.varargs = true;
                } else {
                    dt.set_name(java_trim(sub(&datatype, 0, i)?))?;
                }
            }
            match ch {
                b' ' => {
                    i += 1;
                    continue;
                }
                b'<' => {
                    let template_end = find_balanced_end(&datatype, i, b'<', b'>')?;
                    if template_end == -1 || template_end > dlen {
                        return jerr("DemanglerParseException", "Did not find ending to template");
                    }
                    let content = sub(&datatype, i + 1, template_end)?;
                    dt.template = Some(self.parse_template(content)?);
                    i = template_end;
                }
                b'(' => {
                    let lambda = self.lambda_name(&datatype)?;
                    if let Some(new_dt) = self.array_pointer_or_reference(&dt, &datatype, None)? {
                        dt = new_dt;
                        i = dlen;
                    } else if let Some(full_text) = lambda {
                        if let Some(new_dt) = self.array_pointer_or_reference(&dt, &datatype, Some(&full_text))? {
                            dt = new_dt;
                            i = dlen;
                        } else {
                            dt.set_name(&full_text)?;
                            let offset = index_of_char(&full_text, b'(', 0);
                            i = i + (full_text.len() as i64 - offset) - 1;
                        }
                    } else if has_consecutive_sets_of_parens(sub_from(&datatype, i)?)? {
                        let ns = dt.namespace.take();
                        let mut dfp = self.parse_function_pointer(&datatype)?;
                        let end = last_index_of(&datatype, ")");
                        if end == -1 {
                            return jerr("DemanglerParseException", "Did not find ending to closure");
                        }
                        dfp.func.as_mut().expect("a function pointer").ret.namespace = ns;
                        dt = dfp;
                        i = end + 1;
                    } else {
                        let ns = dt.namespace.take();
                        let mut dfp = self.parse_function(&datatype, i)?;
                        let end = index_of_char(&datatype, b')', i + 1);
                        if end == -1 {
                            return jerr("DemanglerParseException", "Did not find ending to closure");
                        }
                        dfp.func.as_mut().expect("a function pointer").ret.namespace = ns;
                        dt = dfp;
                        i = end + 1;
                    }
                }
                b'*' => {
                    dt.pointer_levels += 1;
                    i += 1;
                    continue;
                }
                b'&' => {
                    if !dt.is_reference() {
                        dt.set_lref();
                    } else {
                        dt.rref = true;
                        dt.lref = false;
                    }
                    i += 1;
                    continue;
                }
                b'[' => {
                    dt.array_dims += 1;
                    i = index_of_char(&datatype, b']', i + 1);
                    if i == -1 {
                        return Err(Error("not ported: an unclosed '[' (Java loops forever)".into()));
                    }
                    i += 1;
                    continue;
                }
                _ => {}
            }
            let substr = sub_from(&datatype, i)?;
            if substr.starts_with("const") {
                dt.is_const = true;
                i += 4;
            } else if substr.starts_with("struct") {
                dt.is_struct = true;
                i += 5;
            } else if substr.starts_with("class") {
                dt.is_class = true;
                i += 4;
            } else if substr.starts_with("enum") {
                dt.is_enum = true;
                i += 3;
            } else if dt.name == "long" {
                if substr.starts_with("long") {
                    dt.set_name("long long")?;
                    i += 3;
                } else if substr.starts_with("double") {
                    dt.set_name("long double")?;
                    i += 5;
                }
            } else if dt.name == "unsigned" {
                dt.is_unsigned = true;
                if substr.starts_with("long") {
                    dt.set_name("long")?;
                    i += 3;
                } else if substr.starts_with("int") {
                    dt.set_name("int")?;
                    i += 2;
                } else if substr.starts_with("short") {
                    dt.set_name("short")?;
                    i += 4;
                } else if substr.starts_with("char") {
                    dt.set_name("char")?;
                    i += 3;
                }
            }
            i += 1;
        }
        Ok(dt)
    }

    /// `tryToParseArrayPointerOrReference` (`lambda` None) and
    /// `tryToParseLambdaArrayPointerOrReference` (`lambda` the lambda's full text).
    fn array_pointer_or_reference(&self, dt: &DataType, datatype: &str, lambda: Option<&str>) -> R<Option<DataType>> {
        let r = match lambda {
            Some(text) => Replaced::custom(datatype, text),
            None => Replaced::templated(datatype),
        };
        let Some(c) = pats().array_ptr_ref.captures(&r.modified) else { return Ok(None) };
        let start = c.get(0).expect("group 0").start();
        let name = remove_trailing_dereference(&r.modified[..start]);
        // parseArrayPointerOrReference
        let mut new_dt = DataType::new(&r.restore(name))?;
        let ty = c.get(1).expect("group 1");
        if ty.as_str() == "*" {
            new_dt.pointer_levels += 1;
        } else {
            new_dt.set_lref();
        }
        let mid_start = index_of(&r.modified, name) + name.len() as i64;
        let mid = sub(&r.modified, mid_start, ty.start() as i64 - 1)?;
        if mid.contains(" const") {
            new_dt.is_const = true;
        }
        new_dt.pointer_levels += mid.matches('*').count() as u32;
        new_dt.array_dims = c[2].matches('[').count() as i64;
        new_dt.namespace = dt.namespace.clone();
        Ok(Some(new_dt))
    }

    /// `parseFunctionPointer`: `unsigned long (*)(long const &)`.
    fn parse_function_pointer(&self, s: &str) -> R<DataType> {
        let paren_start = index_of_char(s, b'(', 0);
        let paren_end = find_balanced_end(s, paren_start, b'(', b')')?;
        let return_type = java_trim(sub(s, 0, paren_start)?);
        let param_start = index_of_char(s, b'(', paren_end + 1);
        let param_end = last_index_of(s, ")");
        let params = sub(s, param_start + 1, param_end)?;
        self.function_pointer(params, return_type, true)
    }

    /// `parseFunction`: `unsigned long (long const &)`, a function pointer shown as a function.
    fn parse_function(&self, s: &str, offset: i64) -> R<DataType> {
        let paren_start = index_of_char(s, b'(', offset);
        let paren_end = find_balanced_end(s, paren_start, b'(', b')')?;
        let return_type = java_trim(sub(s, 0, paren_start)?);
        let params = sub(s, paren_start + 1, paren_end)?;
        self.function_pointer(params, return_type, false)
    }

    /// `createFunctionPointer`.
    fn function_pointer(&self, params: &str, return_type: &str, display: bool) -> R<DataType> {
        let params = self.parse_parameters(params)?;
        let ret = self.parse_data_type(return_type)?;
        Ok(DataType {
            name: "FuncDef".into(),
            demangled: "FuncDef".into(),
            pointer_levels: 1,
            func: Some(Box::new(FuncPtr { ret, params, display })),
            ..DataType::default()
        })
    }

    /// `createMemberPointer`: `Type NS1::Type1 NS1::ParenType::*`.
    fn member_pointer(&self, datatype: &str) -> R<DataType> {
        let ns_end = last_index_of(datatype, "::");
        let without = sub(datatype, 0, ns_end)?;
        let mut dt = match without.find(' ') {
            Some(space) => {
                let mut dt = self.type_in_namespace(&without[..space])?;
                dt.namespace = Some(Box::new(self.type_in_namespace(&without[space + 1..])?));
                dt
            }
            None => self.type_in_namespace(without)?,
        };
        dt.pointer_levels += 1;
        Ok(dt)
    }

    /// `parseTemplate`.
    fn parse_template(&self, s: &str) -> R<Vec<DataType>> {
        let contents = if s.starts_with('<') && s.ends_with('>') { sub(s, 1, s.len() as i64 - 1)? } else { s };
        self.parse_parameters(contents)
    }

    /// `createTypeInNamespace`.
    fn type_in_namespace(&self, name: &str) -> R<DataType> {
        let names = symbol_path(name)?;
        let (last, parents) = names.split_last().expect("a path");
        let mut dt = DataType::new(last)?;
        dt.namespace = self.to_namespaces(parents)?;
        Ok(dt)
    }

    /// `setNameAndNamespace`.
    fn set_name_and_namespace(&self, o: &mut Object, name: &str) -> R<()> {
        let names = symbol_path(name)?;
        let (last, parents) = names.split_last().expect("a path");
        let ns = self.to_namespaces(parents)?;
        o.set_name(Some(last))?;
        o.namespace = ns.map(Ns::Type);
        Ok(())
    }

    /// `convertToNamespaces`: the innermost namespace of `names` (outermost first).
    fn to_namespaces(&self, names: &[String]) -> R<Option<Box<DataType>>> {
        let mut ns: Option<Box<DataType>> = None;
        for n in names {
            let mut t = DataType::new(&self.remove_bad_spaces(n))?;
            t.namespace = ns;
            ns = Some(Box::new(t));
        }
        Ok(ns)
    }
}

/// `ParameterLocator`: the parentheses of the parameter list.
fn locate_parameters(text: &str) -> R<Option<(i64, i64)>> {
    let end = last_index_of(text, ")");
    if end < 0 {
        return Ok(None);
    }
    if end < text.len() as i64 - 1 && char_at(text, end + 1)? == b':' {
        return Ok(None);
    }
    // findParameterStart
    let b = text.as_bytes();
    let mut start = -1;
    let mut depth = 0;
    for i in (0..end as usize).rev() {
        match b[i] {
            b'(' if depth == 0 => {
                start = i as i64;
                break;
            }
            b'>' | b')' => depth += 1,
            b'<' | b'(' => depth -= 1,
            _ => {}
        }
    }
    let template_end = find_balanced_end(text, 0, b'<', b'>')?;
    let mut template_start = -1;
    if template_end != -1 {
        template_start = find_balanced_start(text, template_end, b'<', b'>')?;
    }
    if start > template_start && start < template_end {
        return Ok(None);
    }
    Ok((start != -1).then_some((start, end)))
}

/// `tokenizeParameters`.
fn tokenize_parameters(s: &str) -> R<Vec<String>> {
    let mut params = Vec::new();
    if s.is_empty() {
        return Ok(params);
    }
    let p = pats();
    let s = match p.unnecessary_parens.captures(s) {
        Some(c) => c.get(1).expect("group 1").as_str(),
        None => s,
    };
    if is_blank(s) {
        return Ok(params);
    }
    let len = s.len() as i64;
    let mut depth = 0;
    let mut start = 0i64;
    let mut i = 0i64;
    while i < len {
        let ch = s.as_bytes()[i as usize];
        if ch == b',' && depth == 0 {
            params.push(java_trim(sub(s, start, i)?).to_string());
            start = i + 1;
        } else if ch == b'<' {
            depth += 1;
        } else if ch == b'>' {
            depth -= 1;
        } else if ch == b'(' {
            let rest = &s[i as usize..];
            if let Some(m) = p.array_ptr_ref_piece.find(rest).filter(|m| m.start() == 0) {
                i += m.end() as i64;
                continue;
            }
            if let Some(m) = p.cast.find(rest).filter(|m| m.start() == 0) {
                i += m.end() as i64;
                continue;
            }
            let end = find_balanced_end(s, i, b'(', b')')?;
            i = if end == -1 { len } else { end };
        }
        i += 1;
    }
    if start < len {
        params.push(java_trim(sub_from(s, start)?).to_string());
    }
    Ok(params)
}

/// `findBalancedEnd`.
fn find_balanced_end(s: &str, start: i64, open: u8, close: u8) -> R<i64> {
    let (mut found, mut depth) = (false, 0);
    let mut i = start;
    while i < s.len() as i64 {
        let c = char_at(s, i)?;
        if c == open {
            depth += 1;
            found = true;
        } else if c == close {
            depth -= 1;
        }
        if found && depth == 0 {
            return Ok(i);
        }
        i += 1;
    }
    Ok(-1)
}

/// `findBalancedStart`.
fn find_balanced_start(s: &str, start: i64, open: u8, close: u8) -> R<i64> {
    let (mut found, mut depth) = (false, 0);
    let mut i = start;
    while i >= 0 {
        let c = char_at(s, i)?;
        if c == open {
            depth -= 1;
        } else if c == close {
            depth += 1;
            found = true;
        }
        if found && depth == 0 {
            return Ok(i);
        }
        i -= 1;
    }
    Ok(-1)
}

/// `findNamespaceStart`.
fn find_namespace_start(text: &str, start: i64, stop: i64) -> R<i64> {
    if !text.contains("::") {
        return Ok(-1);
    }
    let (mut colons, mut paren, mut template, mut brace) = (0, 0, 0, 0);
    let mut nested = false;
    let mut i = start;
    while i >= stop {
        match char_at(text, i)? {
            b':' => {
                colons += 1;
                if colons == 2 {
                    if !nested {
                        return Ok(i + 2);
                    }
                    colons = 0;
                }
            }
            b' ' if !nested => return Ok(-1),
            b'(' => {
                paren -= 1;
                nested = paren > 0 || template > 0 || brace > 0;
            }
            b')' => {
                paren += 1;
                nested = paren > 0 || template > 0 || brace > 0;
            }
            b'<' => {
                template -= 1;
                nested = paren > 0 || template > 0 || brace > 0;
            }
            b'>' => {
                template += 1;
                nested = paren > 0 || template > 0 || brace > 0;
            }
            b'{' => {
                brace -= 1;
                nested = paren > 0 || template > 0 || brace > 0;
            }
            b'}' => {
                brace += 1;
                nested = paren > 0 || template > 0 || brace > 0;
            }
            _ => {}
        }
        i -= 1;
    }
    Ok(-1)
}

/// `nextCharIs`.
fn next_char_is(text: &str, mut index: i64, c: u8) -> R<bool> {
    let mut next = char_at(text, index)?;
    while next == b' ' {
        index += 1;
        next = char_at(text, index)?;
    }
    Ok(next == c)
}

/// `hasConsecutiveSetsOfParens`.
fn has_consecutive_sets_of_parens(text: &str) -> R<bool> {
    let end = find_balanced_end(text, 0, b'(', b')')?;
    Ok(java_trim(sub_from(text, end + 1)?).starts_with('('))
}

/// `isMemberPointerOrReference`.
fn is_member_pointer_or_reference(full: &str, datatype: &str) -> bool {
    pats().member_strip.replace_all(datatype, "").is_empty() && full.ends_with(&format!("::{datatype}"))
}

/// `isDataTypeNameCharacter`.
fn is_data_type_name_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b':' | b'_' | b'{' | b'$')
}

/// `removeTrailingDereferenceCharacters`.
fn remove_trailing_dereference(s: &str) -> &str {
    s.trim_end_matches(['*', '&'])
}

/// `stripOffTemplates`.
fn strip_off_templates(s: &str) -> String {
    let mut out = String::new();
    let mut depth = 0;
    for c in s.chars() {
        match c {
            '<' => depth += 1,
            '>' => depth -= 1,
            _ if depth == 0 => out.push(c),
            _ => {}
        }
    }
    out
}

/// `SymbolPathParser.parse(name, false)`.
fn symbol_path(name: &str) -> R<Vec<String>> {
    if is_blank(name) {
        return jerr("IllegalArgumentException", "Pathname cannot be empty!");
    }
    if !name.contains("::") {
        return Ok(vec![name.to_string()]);
    }
    let b = name.as_bytes();
    let is_delimiter = |i: usize| i != b.len() - 1 && b[i] == b':' && b[i + 1] == b':';
    // naiveParseWithTemplates
    let mut list = Vec::new();
    let (mut template, mut paren, mut start) = (0, 0, 0);
    let mut i = 0;
    while i < b.len() {
        if is_delimiter(i) {
            if template == 0 && paren == 0 && i > start {
                list.push(name[start..i].to_string());
                start = i + 2;
            }
            i += 1;
        } else {
            match b[i] {
                b'<' => template += 1,
                b'>' => template -= 1,
                b'(' => paren += 1,
                b')' => paren -= 1,
                _ => {}
            }
        }
        i += 1;
    }
    let segment = &name[start.min(b.len())..];
    let angle_operator = matches!(
        segment,
        "operator<"
            | "operator>"
            | "operator<="
            | "operator>="
            | "operator<<"
            | "operator>>"
            | "operator<<="
            | "operator>>="
            | "operator<=>"
            | "operator->"
            | "operator->*"
    );
    if (template == 0 && paren == 0) || angle_operator {
        list.push(segment.to_string());
        return Ok(list);
    }
    // naiveParseIgnoringTemplates
    let mut list = Vec::new();
    let mut start = 0;
    let mut i = 0;
    while i < b.len() {
        if is_delimiter(i) {
            if i > start {
                list.push(name[start..i].to_string());
                start = i + 2;
            }
            i += 1;
        }
        i += 1;
    }
    list.push(name[start.min(b.len())..].to_string());
    Ok(list)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Expectations from GnuDemanglerParserTest.java.

    #[test]
    fn templated_shift_operator() {
        let d = parse(
            "fakemangled",
            "std::basic_istream<char, std::char_traits<char> >& std::operator>><char, std::char_traits<char> >\
             (std::basic_istream<char, std::char_traits<char> >&, char&)",
        )
        .unwrap();
        assert_eq!(d.name.as_deref(), Some("operator>>"));
        assert_eq!(
            d.signature.as_deref(),
            Some("std::istream & std::operator>><char,std::char_traits<char>>(std::istream &,char &)")
        );
    }

    #[test]
    fn shift_operator_with_function_pointer() {
        let d = parse(
            "_ZNSolsEPFRSoS_E",
            "std::basic_ostream<char, std::char_traits<char> >::operator<<(std::basic_ostream<char, \
             std::char_traits<char> >&(*)(std::basic_ostream<char, std::char_traits<char> >&))",
        )
        .unwrap();
        assert_eq!(d.qualified_name().as_deref(), Some("std::ostream::operator<<"));
        assert_eq!(
            d.signature.as_deref(),
            Some("undefined std::ostream::operator<<(std::ostream & (*)(std::ostream &))")
        );
    }

    #[test]
    fn conversion_operators() {
        let d = parse(
            "_ZNKSt17integral_constantIbLb0EEcvbEv",
            "std::integral_constant<bool, false>::operator bool() const",
        )
        .unwrap();
        assert_eq!(d.signature.as_deref(), Some("bool std::integral_constant::operator.cast.to.bool(void)"));
        let d = parse(
            "_ZNK17GCC_IndicationPDUcvRK31GCC_ApplicationInvokeIndicationEv",
            "GCC_IndicationPDU::operator GCC_ApplicationInvokeIndication const&() const",
        )
        .unwrap();
        assert_eq!(
            d.qualified_name().as_deref(),
            Some("GCC_IndicationPDU::operator.cast.to.GCC_ApplicationInvokeIndication&")
        );
        assert_eq!(
            d.signature.as_deref(),
            Some(
                "GCC_ApplicationInvokeIndication const & \
                 GCC_IndicationPDU::operator.cast.to.GCC_ApplicationInvokeIndication&(void)"
            )
        );
    }
}
