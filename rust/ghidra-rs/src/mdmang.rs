//! Ghidra's Microsoft demangler (`Ghidra/Features/MicrosoftDmang`, package `mdemangler`): the
//! parser `MDMang` and its object model, and the output of `MDParsableItem.toString()` (the
//! "original demangled" string `MicrosoftDemangler` keeps and the Demangler analyzer writes as a
//! plate comment).
//!
//! The Java builds a tree of `MDParsableItem`s while it parses and prints it by inserting pieces
//! at the front of a `StringBuilder`. This port keeps the tree (enums and structs, one per Java
//! class or family of classes; each names the class it ports) and the same insert/append steps,
//! so the spacing quirks come out as Java's. Two Java behaviours are kept on purpose:
//! - back references (`MDContext`) share one data type object between its uses (`Rc`), and
//!   `MDFunctionType.setFromModifier`, which printing calls, sticks (`Cell`);
//! - a Java runtime exception (a `null` type name, an empty context stack, a negative string
//!   length) is not an `MDException`: it ends the whole demangle. It is recorded as a fault and
//!   the demangle fails with it.
//!
//! Only the `MDMang` variant is ported (`MDMangGhidra` is `MDMang` with
//! `demangleOnlyKnownPatterns`, here [`Config::only_known_patterns`]); the VS2013/VS2015,
//! parse-info and genericize variants are not.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

/// `MDCharacterIterator.DONE`.
const DONE: char = '\u{FFFF}';

/// An `MDException` (or a Java runtime exception, see the module doc).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

impl Error {
    /// A case this port does not convert (as opposed to Java's own failure).
    pub fn is_not_ported(&self) -> bool {
        self.0.starts_with("not ported")
    }
}

type R<T> = Result<T, Error>;

fn err<T>(msg: impl Into<String>) -> R<T> {
    Err(Error(msg.into()))
}

/// `MDOutputOptions`.
#[derive(Clone, Copy, Debug)]
pub struct OutputOptions {
    pub use_encoded_anonymous_namespace: bool,
    pub apply_udt_argument_type_tag: bool,
}

impl Default for OutputOptions {
    /// `MDOutputOptions.DEFAULT_USE_ANON_NS` (false), `DEFAULT_APPLY_UDT_TAG` (true).
    fn default() -> Self {
        OutputOptions { use_encoded_anonymous_namespace: false, apply_udt_argument_type_tag: true }
    }
}

/// The settings `MicrosoftDemangler.demangle` gives `MDMangGhidra`.
#[derive(Clone, Copy, Debug)]
pub struct Config {
    /// `setArchitectureSize` (`MicrosoftMangledContext.getArchitectureSize`: the default
    /// address space's size, 0 without a program)
    pub arch: u32,
    /// `setIsFunction` (`FUNCTION_IF_EXISTS`: a function exists at the symbol's address)
    pub is_function: bool,
    /// `setErrorOnRemainingChars` (true in `MicrosoftDemanglerOptions`)
    pub error_on_remaining: bool,
    /// `MDMangGhidra.setDemangleOnlyKnownPatterns`
    pub only_known_patterns: bool,
}

impl Default for Config {
    /// `MDMang`'s own defaults: 32 bits, not a function, remaining characters allowed.
    fn default() -> Self {
        Config { arch: 32, is_function: false, error_on_remaining: false, only_known_patterns: false }
    }
}

// ---------------------------------------------------------------------------------------------
// MDMang's builder helpers (insertSpacedString, insertString, appendString, cleanOutput)

fn ins_spaced(b: &mut String, s: &str) {
    if !b.is_empty() && !s.is_empty() {
        if b.starts_with(' ') {
            if s.ends_with(' ') {
                b.remove(0);
            }
        } else if !s.ends_with(' ') {
            b.insert(0, ' ');
        }
    }
    b.insert_str(0, s);
}

fn ins(b: &mut String, s: &str) {
    if !b.is_empty() && !s.is_empty() && b.starts_with(' ') && s.ends_with(' ') {
        b.remove(0);
    }
    b.insert_str(0, s);
}

fn app(b: &mut String, s: &str) {
    if !b.is_empty() && !s.is_empty() && b.ends_with(' ') && s.starts_with(' ') {
        b.pop();
    }
    b.push_str(s);
}

fn clean(b: &mut String) {
    if let Some(p) = b.find('\0') {
        b.truncate(p);
    }
}

/// Java's `String.trim()`: strips characters up to U+0020.
pub(crate) fn java_trim(s: &str) -> &str {
    s.trim_matches(|c: char| c <= ' ')
}

/// Java's `Character.isLetter` / `isDigit` (exact for ASCII).
fn is_letter(c: char) -> bool {
    c != DONE && c.is_alphabetic()
}

fn is_digit(c: char) -> bool {
    c.is_ascii_digit() || (!c.is_ascii() && c != DONE && c.is_numeric())
}

/// What printing needs: the output options, the architecture (`MDVCall`) and the fault slot.
struct Out<'a> {
    opts: OutputOptions,
    arch: u32,
    fault: &'a RefCell<Option<String>>,
}

impl Out<'_> {
    fn fault(&self, msg: &str) {
        self.fault.borrow_mut().get_or_insert_with(|| msg.to_string());
    }
}

/// `MDMangUtils.createStandardAnonymousNamespaceNode`.
fn standard_anon(o: &Out, anon: &str) -> String {
    let s = if let Some(s) = anon.strip_prefix("A0x") {
        s
    } else if let Some(s) = anon.strip_prefix('`') {
        s
    } else {
        return anon.to_string();
    };
    // Long.valueOf(str, 16): a sign is allowed, anything else not hex throws
    let (neg, digits) = match s.strip_prefix('-') {
        Some(d) => (true, d),
        None => (false, s.strip_prefix('+').unwrap_or(s)),
    };
    match u64::from_str_radix(digits, 16).ok().filter(|v| *v <= i64::MAX as u64 + neg as u64) {
        Some(v) if !digits.is_empty() => {
            let v = if neg { (v as i64).wrapping_neg() } else { v as i64 };
            format!("_anon_{v:08X}")
        }
        _ => {
            o.fault(&format!("NumberFormatException: For input string: \"{s}\""));
            anon.to_string()
        }
    }
}

// ---------------------------------------------------------------------------------------------
// MDEncodedNumber, MDSignedEncodedNumber

/// `MDEncodedNumber`: its value as Java's `BigInteger.toString()` and its low 64 bits.
#[derive(Clone, Debug, Default)]
struct EncNum {
    dec: String,
    low: u64,
}

impl EncNum {
    fn int_value(&self) -> i32 {
        self.low as u32 as i32
    }
}

/// Decimal digits of a number given by hex nibbles (most significant first).
fn hex_to_dec(nibbles: &[u8]) -> String {
    const BASE: u64 = 1_000_000_000;
    let mut limbs: Vec<u64> = vec![0];
    for &n in nibbles {
        let mut carry = u64::from(n);
        for l in limbs.iter_mut() {
            let x = *l * 16 + carry;
            *l = x % BASE;
            carry = x / BASE;
        }
        if carry > 0 {
            limbs.push(carry);
        }
    }
    let mut s = limbs.last().map_or_else(String::new, |l| l.to_string());
    for l in limbs.iter().rev().skip(1) {
        s += &format!("{l:09}");
    }
    s
}

/// `MDSignedEncodedNumber`.
#[derive(Clone, Debug, Default)]
struct SignedNum {
    neg: bool,
    num: EncNum,
}

impl std::fmt::Display for EncNum {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.dec)
    }
}

impl std::fmt::Display for SignedNum {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut b = String::new();
        ins_spaced(&mut b, &self.num.dec);
        if self.neg {
            ins(&mut b, "-");
        }
        f.write_str(&b)
    }
}

// ---------------------------------------------------------------------------------------------
// The object model

type Dt = Rc<DataType>;

/// `MDDataType`'s `Signage`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
enum Sign {
    #[default]
    Signed,
    Specified,
    Unsigned,
}

/// `MDDataType` and its subclasses.
#[derive(Debug)]
struct DataType {
    sign: Sign,
    kind: DtKind,
}

#[derive(Debug)]
enum DtKind {
    /// a type whose name is fixed: the basic types and the `MDExtendedType`s
    Basic {
        name: &'static str,
        extended: bool,
    },
    /// `MDDataType` with `setTypeName` (template parameters and constants)
    Named(String),
    /// `MDDataType` with `setName` only (`__` object types): its type name is `null`
    NullName,
    /// `MDVoidDataType`
    Void {
        printable: bool,
    },
    /// `MDVarArgsType`
    VarArgs,
    /// `MDCustomType`, `MDNamedUnspecifiedType`: the type name is the qualified name
    QualNamed(QualifiedName),
    /// `MDEmptyParameterType`, `MDEndParameterType`
    EmptyParam,
    EndParam,
    /// `MDW64Type`
    W64(Dt),
    /// `MDComplexType` and subclasses (`MDEnumType`: the tag is its enum type name)
    Complex {
        tag: &'static str,
        qn: QualifiedName,
    },
    /// `MDArrayReferencedType`
    ArrayRef {
        array: String,
        r: Dt,
    },
    /// `MDModifierType` and subclasses
    Modifier(Box<Modifier>),
}

impl DataType {
    fn new(kind: DtKind) -> Self {
        DataType { sign: Sign::Signed, kind }
    }
    /// `instanceof MDModifierType || MDExtendedType || MDComplexType` (back reference kept)
    fn is_backref_kind(&self) -> bool {
        matches!(
            self.kind,
            DtKind::Modifier(_)
                | DtKind::Complex { .. }
                | DtKind::Basic { extended: true, .. }
                | DtKind::QualNamed(_)
                | DtKind::EmptyParam
                | DtKind::EndParam
                | DtKind::W64(_)
        )
    }
}

/// `MDModifierType`: which subclass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ModKind {
    Pointer,
    Reference,
    RightRef,
    DataRef,
    FuncIndirect,
    PointerRef,
    Question,
    ArrayBasic,
}

/// `MDModifierType`.
#[derive(Debug)]
struct Modifier {
    kind: ModKind,
    is_const: bool,
    is_volatile: bool,
    cv: CvMod,
    r: TypeRef,
}

/// An `MDType` a modifier refers to: a function type or a data type.
#[derive(Debug, Clone)]
enum TypeRef {
    Func(Rc<FunctionType>),
    Data(Dt),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CvPrefix {
    Ptr64,
    Unaligned,
    Restrict,
}

/// `MDCVMod`'s `CvModifierType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum ModType {
    #[default]
    Plain,
    Pointer,
    Reference,
    RightReference,
    Array,
    Question,
    Other,
}

/// `MDCVMod`.
#[derive(Debug, Default)]
struct CvMod {
    unaligned_restrict_ptr64: Vec<CvPrefix>,
    is_this_pointer_mod: bool,
    is_lref: bool,
    is_rref: bool,
    is_const: bool,
    is_volatile: bool,
    is_function: bool,
    is_based: bool,
    is_member: bool,
    found_managed_property: bool,
    is_gc: bool,
    is_pin_pointer: bool,
    is_cli_property: bool,
    is_cli_array: bool,
    array_rank: i32,
    no_properties: bool,
    no_cv: bool,
    mod_type: ModType,
    qual: Option<QualifiedName>,
    this_cv: Option<Rc<CvMod>>,
    based: Option<Based>,
}

/// `MDBasedAttribute` (parsed: `Some`).
#[derive(Debug, Clone, Default)]
struct Based {
    name: Option<String>,
    ptr_based: bool,
}

/// `MDFunctionType`.
#[derive(Debug, Default)]
struct FunctionType {
    convention: String,
    ret: Option<Dt>,
    args: Option<Vec<Dt>>,
    this_cv: Option<Rc<CvMod>>,
    throw: Option<Throw>,
    has_return: bool,
    has_args: bool,
    is_type_cast: bool,
    from_modifier: Cell<bool>,
    based: Option<Based>,
}

/// `MDThrowAttribute`.
#[derive(Debug, Default)]
struct Throw {
    no_except: bool,
    has_throw: bool,
    args: Vec<Dt>,
}

/// `MDTypeInfo`'s access specifier and storage class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Access {
    #[default]
    None,
    Private,
    Protected,
    Public,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Storage {
    #[default]
    None,
    Static,
    Virtual,
}

/// `MDTypeInfo` and subclasses.
#[derive(Debug, Default)]
struct TypeInfo {
    access: Access,
    storage: Storage,
    thunk: bool,
    extern_c: bool,
    /// `setNonMember` (`Y`, `Z`)
    non_member: bool,
    /// `setSpecialHandlingCode` (`$$` codes)
    special: Option<char>,
    kind: TiKind,
}

#[derive(Debug, Default)]
enum TiKind {
    /// `MDTypeInfo` itself and the RTTI 0-3 meta classes: no type
    #[default]
    Plain,
    /// `MDVariableInfo`
    Variable { cv: CvMod, dt: Dt },
    /// `MDGuard`
    Guard(EncNum),
    /// `MDVxTable` (`MDVFTable`, `MDVBTable`, `MDRTTI4`)
    VxTable { cv: CvMod, quals: Vec<Qualification>, good_termination: bool },
    /// `MDFunctionInfo` and subclasses, with the name modifier of the thunk ones
    Function { ft: Rc<FunctionType>, extra: FnExtra },
}

#[derive(Debug)]
enum FnExtra {
    None,
    /// `MDVFAdjustor`
    Adjustor(EncNum),
    /// `MDVtordisp`
    Vtordisp(EncNum, EncNum),
    /// `MDVtordispex`
    Vtordispex([EncNum; 4]),
    /// `MDVCall`: index, this far, call far, vfptr (None: based)
    VCall {
        index: EncNum,
        this_far: bool,
        call_far: bool,
        vfptr_far: Option<bool>,
        based: Option<Based>,
    },
}

/// `MDObjectCPP` (and the `MDHashedObject` inner class).
#[derive(Debug)]
struct ObjectCpp {
    body: CppBody,
}

#[derive(Debug)]
enum CppBody {
    Hashed(String),
    Normal { qn: Box<QualifiedBasicName>, ti: Option<Box<TypeInfo>> },
}

/// `MDQualifiedBasicName`.
#[derive(Debug)]
struct QualifiedBasicName {
    basic: BasicName,
    qual: Qualification,
}

/// `MDBasicName`.
#[derive(Debug)]
enum BasicName {
    Special(SpecialName),
    Template(Box<TemplateNa>),
    Reusable(ReusableName),
    /// an embedded object (the qualification after it is parsed, not kept: it is not printed)
    Embedded(Box<ObjectCpp>),
}

/// `MDSpecialName`.
#[derive(Debug, Default)]
struct SpecialName {
    name: String,
    is_ctor: bool,
    is_dtor: bool,
    is_type_cast: bool,
    rtti: i32,
    is_string: bool,
    cast_type_string: Option<String>,
    xtor_qual: Option<Rc<Qualifier>>,
}

/// `MDReusableName`.
#[derive(Debug, Default)]
struct ReusableName {
    fragment: Option<String>,
    template: Option<Box<TemplateNa>>,
    special: Option<String>,
}

/// `MDQualifiedName`.
#[derive(Debug, Default)]
struct QualifiedName {
    name: ReusableName,
    qual: Qualification,
}

/// `MDQualification`.
#[derive(Debug, Default)]
struct Qualification {
    quals: Vec<Rc<Qualifier>>,
}

/// `MDQualifier`.
#[derive(Debug)]
enum Qualifier {
    Name(ReusableName),
    Template(ReusableName),
    Anon(ReusableName),
    Interface(ReusableName),
    /// `MDNestedName`
    Nested(Box<ObjectCpp>),
    /// `MDNumberedNamespace`
    Numbered(EncNum),
    Q(Qualification),
}

/// `MDTemplateNameAndArguments` with its `MDTemplateArgumentsList`.
#[derive(Debug)]
struct TemplateNa {
    name: BasicName,
    args: Vec<Dt>,
    comma: Vec<bool>,
}

/// `MDObjectC`.
#[derive(Debug)]
struct ObjectC {
    name: String,
    convention: Option<usize>,
    param_bytes: i32,
}

const C_CONVENTIONS: [&str; 4] = ["__cdecl", "__stdcall", "__fastcall", "__vectorcall"];

/// `MDObjectReserved` subclasses.
#[derive(Debug)]
enum Reserved {
    ThrowInfo(String, Dt),
    CatchableTypeArray(String, Dt),
    CatchableType(String, Vec<ObjectCpp>),
    Catch(String, ObjectCpp),
    CatchSym(String, ObjectCpp),
    UnwindFunclet(String, ObjectCpp),
    TryBlockTable(ObjectCpp),
    UnwindTable(ObjectCpp),
    EhHandler(ObjectCpp),
    /// `MDObjectBracket`: the upper-cased fragment and the object
    Bracket(String, ObjectCpp),
    Unknown(String),
}

/// The item `MDMang.demangle` returns.
#[derive(Debug)]
enum Item {
    DataType(Dt),
    Cpp(ObjectCpp),
    /// `MDObjectCodeView`
    CodeView(ObjectCpp),
    Template(TemplateNa),
    C(ObjectC),
    Reserved(Reserved),
}

// ---------------------------------------------------------------------------------------------
// The parser (MDMang with MDCharacterIterator and MDContext)

type Shared<T> = Rc<RefCell<Vec<T>>>;

/// `MDContext`.
#[derive(Clone, Default)]
struct Ctx {
    names: Shared<String>,
    params: Shared<Dt>,
    tparams: Shared<Dt>,
}

struct Parser {
    s: Vec<char>,
    i: usize,
    ctx: Vec<Ctx>,
    llvm: bool,
    arch: u32,
    is_function: bool,
    fault: RefCell<Option<String>>,
    /// how many data types and C++ objects are being parsed inside each other ([`MAX_DEPTH`])
    depth: usize,
}

/// How deep data types and C++ objects may nest. Java recurses until the JVM stack overflows
/// (a `StackOverflowError`, which `AbstractDemanglerAnalyzer` catches as a failed demangle; the
/// depth depends on the JVM stack size); this port fails the demangle at this depth instead of
/// aborting the process, well inside a 2 MiB thread stack.
const MAX_DEPTH: usize = 200;

impl Parser {
    /// `f` one nesting level deeper; past [`MAX_DEPTH`] a failed demangle.
    fn nest<T>(&mut self, f: impl FnOnce(&mut Self) -> R<T>) -> R<T> {
        if self.depth >= MAX_DEPTH {
            return err(format!("MDMang: nested deeper than {MAX_DEPTH} (Java: StackOverflowError)"));
        }
        self.depth += 1;
        let r = f(self);
        self.depth -= 1;
        r
    }

    fn out(&self) -> Out<'_> {
        Out { opts: OutputOptions::default(), arch: self.arch, fault: &self.fault }
    }

    // MDCharacterIterator
    fn peek(&self) -> char {
        self.peek_at(0)
    }
    fn peek_at(&self, k: usize) -> char {
        self.s.get(self.i + k).copied().unwrap_or(DONE)
    }
    fn next(&mut self) -> char {
        self.i += 1;
        match self.s.get(self.i) {
            Some(&c) => c,
            None => {
                self.i = self.s.len();
                DONE
            }
        }
    }
    fn get_inc(&mut self) -> char {
        let c = self.s.get(self.i).copied();
        self.i += 1;
        c.unwrap_or_else(|| {
            self.i = self.s.len();
            DONE
        })
    }
    fn inc(&mut self) {
        self.i += 1;
    }
    fn inc_by(&mut self, n: usize) {
        self.i += n;
    }
    fn remaining(&self) -> usize {
        self.s.len().saturating_sub(self.i)
    }
    fn at(&self, p: &str) -> bool {
        let p: Vec<char> = p.chars().collect();
        self.s.get(self.i..self.i + p.len()) == Some(&p[..])
    }
    fn reset(&mut self) {
        self.ctx.clear();
        self.i = 0;
    }

    // MDContext stack
    fn top(&self) -> R<&Ctx> {
        match self.ctx.last() {
            Some(c) => Ok(c),
            None => {
                let msg = "IndexOutOfBoundsException: empty MDContext stack";
                self.out().fault(msg);
                err(msg)
            }
        }
    }
    fn push_context(&mut self) {
        self.ctx.push(Ctx::default());
    }
    fn push_shared_context(&mut self) -> R<()> {
        let c = self.top()?.clone();
        self.ctx.push(c);
        Ok(())
    }
    fn push_template_context(&mut self) -> R<()> {
        let c = Ctx { tparams: self.top()?.tparams.clone(), ..Ctx::default() };
        self.ctx.push(c);
        Ok(())
    }
    fn pop_context(&mut self) {
        self.ctx.pop();
    }
    fn add_name(&self, n: String) -> R<()> {
        self.top()?.names.borrow_mut().push(n);
        Ok(())
    }
    fn backref_name(&self, i: usize) -> R<String> {
        let names = self.top()?.names.borrow();
        names.get(i).cloned().map_or_else(|| err("Backref Names stack violation"), Ok)
    }
    fn add_param(&self, dt: &Dt) -> R<()> {
        self.top()?.params.borrow_mut().push(dt.clone());
        Ok(())
    }
    fn backref_param(&self, i: usize) -> R<Dt> {
        let p = self.top()?.params.borrow();
        p.get(i).cloned().map_or_else(|| err("Parameter stack violation"), Ok)
    }
    fn add_tparam(&self, dt: &Dt) -> R<()> {
        self.top()?.tparams.borrow_mut().push(dt.clone());
        Ok(())
    }
    fn backref_tparam(&self, i: usize) -> R<Dt> {
        let p = self.top()?.tparams.borrow();
        p.get(i).cloned().map_or_else(|| err("Template parameter stack violation"), Ok)
    }

    // ---- MDMangObjectParser

    /// `MDMangObjectParser.determineItemAndParse`: the standard pass, then the LLVM one.
    fn determine_item(&mut self) -> R<Item> {
        self.llvm = false;
        match self.item() {
            Ok(it) => Ok(it),
            Err(e1) => {
                self.reset();
                self.llvm = true;
                self.item().map_err(|e2| Error(format!("Reason1: {}; Reason2: {}", e1.0.trim(), e2.0.trim())))
            }
        }
    }

    /// `MDMangObjectParser.parse`.
    fn item(&mut self) -> R<Item> {
        if self.peek() == '.' && !self.s[1..].contains(&'.') {
            self.inc();
            let c = self.dt_header(false)?;
            self.push_context();
            let dt = self.dt_body(c)?;
            self.pop_context();
            return Ok(Item::DataType(dt));
        }
        if self.peek() == '?' {
            if self.peek_at(1) == '@' {
                self.push_context();
                let o = self.code_view()?;
                self.pop_context();
                return Ok(Item::CodeView(o));
            }
            if self.peek_at(1) == '$' {
                self.push_context();
                if let Ok(t) = self.template_na() {
                    self.pop_context();
                    if self.remaining() == 0 {
                        return Ok(Item::Template(t));
                    }
                }
                self.reset();
            }
            self.push_context();
            let o = self.object_cpp()?;
            self.pop_context();
            return Ok(Item::Cpp(o));
        }
        if self.peek() == '_' && (self.peek_at(1) == '_' || self.peek_at(1).is_ascii_uppercase()) {
            let r = self.reserved_header();
            self.push_context();
            let r = self.reserved_body(r)?;
            self.pop_context();
            return Ok(Item::Reserved(r));
        }
        self.push_context();
        let c = self.object_c()?;
        self.pop_context();
        Ok(Item::C(c))
    }

    /// `MDMangObjectParser.parseObjectReserved`: which object (the prefix consumed).
    fn reserved_header(&mut self) -> u8 {
        const PREFIXES: [(&str, u8, bool); 16] = [
            ("__TI", 0, true),
            ("_TI", 0, true),
            ("__CTA", 1, true),
            ("__CT", 2, true),
            ("_CTA", 1, true),
            ("_CT", 2, true),
            ("__catch$", 3, true),
            ("__catchsym$", 4, true),
            ("__unwindfunclet$", 5, true),
            ("__tryblocktable$", 6, true),
            ("__unwindtable$", 7, true),
            ("__ehhandler$", 8, true),
            ("__m2mep@", 9, false),
            ("__mep@", 9, false),
            ("__t2m@", 9, false),
            ("__unep@", 9, false),
        ];
        for (p, k, skip) in PREFIXES {
            if self.at(p) {
                if skip {
                    self.inc_by(p.chars().count());
                }
                return k;
            }
        }
        10
    }

    fn reserved_body(&mut self, k: u8) -> R<Reserved> {
        Ok(match k {
            0 => {
                let d = self.digits();
                Reserved::ThrowInfo(d, self.data_type(false)?)
            }
            1 => {
                let d = self.digits();
                Reserved::CatchableTypeArray(d, self.data_type(false)?)
            }
            2 => {
                let mut objs = Vec::new();
                let mut d;
                loop {
                    objs.push(self.object_cpp()?);
                    d = self.digits();
                    if !(self.peek() != DONE && d.is_empty()) {
                        break;
                    }
                }
                Reserved::CatchableType(d, objs)
            }
            3..=5 => {
                let o = self.object_cpp()?;
                self.inc();
                let d = self.digits();
                match k {
                    3 => Reserved::Catch(d, o),
                    4 => Reserved::CatchSym(d, o),
                    _ => Reserved::UnwindFunclet(d, o),
                }
            }
            6 => Reserved::TryBlockTable(self.object_cpp()?),
            7 => Reserved::UnwindTable(self.object_cpp()?),
            8 => Reserved::EhHandler(self.object_cpp()?),
            9 => {
                if self.peek() != '_' || self.peek_at(1) != '_' {
                    return err("Missing prefix in MDObjectBracket parsing");
                }
                self.inc_by(2);
                let frag = self.fragment(true);
                let mut b = String::new();
                self.render_fragment(&self.out(), &mut b, &frag);
                Reserved::Bracket(b.to_uppercase(), self.object_cpp()?)
            }
            _ => {
                let rest: String = self.s.get(self.i..).map_or_else(String::new, |r| r.iter().collect());
                self.i = self.s.len();
                Reserved::Unknown(rest)
            }
        })
    }

    /// `MDObjectReserved.parseDigits`.
    fn digits(&mut self) -> String {
        let mut d = String::new();
        while self.peek().is_ascii_digit() {
            d.push(self.get_inc());
        }
        d
    }

    /// `MDObjectC.parseInternal`.
    fn object_c(&mut self) -> R<ObjectC> {
        if !self.is_function {
            let name = self.fragment(true);
            return Ok(ObjectC { name, convention: None, param_bytes: 0 });
        }
        let index = self.i;
        let mut conv = match self.peek() {
            '@' => {
                self.next();
                2
            }
            '_' => {
                self.next();
                0
            }
            _ => 3,
        };
        let mut name = self.fragment(true);
        if self.peek() == '@' {
            if conv != 3 {
                return err("Error parsing C Object calling convention");
            }
            self.next();
        } else if conv == 0 && self.s.get(self.i.wrapping_sub(1)) == Some(&'@') {
            conv = 1;
        }
        if self.arch != 32 && conv != 3 {
            self.i = index;
            name = self.fragment(true);
            return Ok(ObjectC { name, convention: None, param_bytes: 0 });
        }
        let mut param_bytes = 0;
        if conv != 0 {
            let rest: String = self.s.get(self.i..).map_or_else(String::new, |r| r.iter().collect());
            self.i += self.remaining();
            param_bytes = rest.parse::<i32>().or_else(|_| err("Error parsing C Object calling convention"))?;
        }
        Ok(ObjectC { name, convention: Some(conv), param_bytes })
    }

    /// `MDObjectCodeView.parseInternal`.
    fn code_view(&mut self) -> R<ObjectCpp> {
        if self.peek() != '?' || self.peek_at(1) != '@' {
            return err("Missing prefix in MDObjectCodeView parsing");
        }
        self.inc_by(2);
        if self.peek() == '?' && self.peek_at(1) == '@' {
            return err("Cannot nest a MDObjectCodeView");
        }
        self.object_cpp()
    }

    /// `MDObjectCPP.parseInternal`.
    fn object_cpp(&mut self) -> R<ObjectCpp> {
        if self.peek() != '?' {
            return err("Invalid ObjectCPP");
        }
        self.inc();
        self.nest(Self::object_cpp_body)
    }

    fn object_cpp_body(&mut self) -> R<ObjectCpp> {
        if self.peek() == '?' && self.peek_at(1) == '@' {
            return Ok(ObjectCpp { body: CppBody::Hashed(self.hashed()?) });
        }
        let mut qn = self.qualified_basic_name()?;
        if qn.basic.is_string() || self.peek() == DONE {
            return Ok(ObjectCpp { body: CppBody::Normal { qn: Box::new(qn), ti: None } });
        }
        let cast = qn.basic.is_type_cast();
        let ti = self.type_info(qn.basic.rtti(), cast)?;
        if cast {
            // applyFunctionReturnTypeToTypeCastOperatorName
            if let TiKind::Function { ft, .. } = &ti.kind {
                if let (true, Some(r)) = (ft.has_return, &ft.ret) {
                    let s = dt_to_string(&self.out(), r);
                    qn.basic.set_cast_type_string(s);
                }
            }
        }
        Ok(ObjectCpp { body: CppBody::Normal { qn: Box::new(qn), ti: Some(Box::new(ti)) } })
    }

    /// `MDHashedObject.parseInternal`.
    fn hashed(&mut self) -> R<String> {
        self.inc_by(2);
        let start = self.i;
        let mut h = String::new();
        let mut ch = self.peek();
        while ch != DONE && ch != '@' && (is_letter(ch) || is_digit(ch)) {
            h.push(ch);
            self.inc();
            ch = self.peek();
        }
        if self.i - start != 32 || ch != '@' {
            return err("Invalid HashedObject");
        }
        self.inc();
        Ok(h)
    }

    // ---- naming

    /// `MDQualifiedBasicName.parseInternal`.
    fn qualified_basic_name(&mut self) -> R<QualifiedBasicName> {
        let mut basic = self.basic_name()?;
        let qual = self.qualification()?;
        let head = qual.quals.first().cloned();
        if basic.is_ctor() || basic.is_dtor() {
            let mut b = String::new();
            if let Some(h) = &head {
                self.render_qualifier(&self.out(), &mut b, h);
            }
            if basic.is_dtor() {
                ins(&mut b, "~");
            }
            basic.set_name(b);
            basic.set_xtor_qual(head);
        }
        Ok(QualifiedBasicName { basic, qual })
    }

    /// `MDBasicName.parseInternal`.
    fn basic_name(&mut self) -> R<BasicName> {
        if self.peek() != '?' {
            return Ok(BasicName::Reusable(self.reusable_name()?));
        }
        match self.peek_at(1) {
            '$' => Ok(BasicName::Template(Box::new(self.template_na()?))),
            '?' => {
                let o = self.object_cpp()?;
                self.qualification()?;
                Ok(BasicName::Embedded(Box::new(o)))
            }
            _ => {
                self.inc();
                Ok(BasicName::Special(self.special_name()?))
            }
        }
    }

    /// `MDFragmentName.parseInternal` (`parseFragmentName_Md`).
    fn fragment(&mut self, strip_terminator: bool) -> String {
        let mut f = String::new();
        loop {
            let ch = self.peek();
            if ch == DONE || !(is_letter(ch) || is_digit(ch) || "_$<>-.".contains(ch)) {
                break;
            }
            f.push(ch);
            self.next();
        }
        if self.peek() == '@' && strip_terminator {
            self.inc();
        }
        f
    }

    /// `MDReusableName.parseInternal`.
    fn reusable_name(&mut self) -> R<ReusableName> {
        let code = self.peek();
        let mut r = ReusableName::default();
        match code {
            '?' => {
                let t = self.template_na()?;
                let s = self.template_to_string(&t);
                self.add_name(s)?;
                r.template = Some(Box::new(t));
            }
            '0'..='9' => {
                self.inc();
                r.fragment = Some(self.backref_name(code as usize - '0' as usize)?);
            }
            _ => {
                let loc = self.i;
                let f = self.fragment(true);
                if loc == 1 {
                    r.special = special_reusable(&f)?;
                }
                self.add_name(f.clone())?;
                r.fragment = Some(f);
            }
        }
        Ok(r)
    }

    fn template_to_string(&self, t: &TemplateNa) -> String {
        let o = self.out();
        let mut b = String::new();
        render_template(&o, &mut b, t);
        clean(&mut b);
        b
    }

    /// `MDQualification.parseInternal`.
    fn qualification(&mut self) -> R<Qualification> {
        let mut q = Qualification::default();
        while self.peek() != DONE && self.peek() != '@' {
            let loc = self.i;
            let qual = self.qualifier()?;
            if self.i == loc {
                break;
            }
            q.quals.push(Rc::new(qual));
        }
        if self.peek() == '@' {
            self.inc();
        }
        Ok(q)
    }

    /// `MDQualifier.parseInternal`.
    fn qualifier(&mut self) -> R<Qualifier> {
        if self.peek() != '?' {
            return Ok(Qualifier::Name(self.reusable_name()?));
        }
        Ok(match self.peek_at(1) {
            '?' => self.nested_name()?,
            '$' => Qualifier::Template(self.reusable_name()?),
            'A' => {
                self.inc();
                Qualifier::Anon(self.reusable_name()?)
            }
            'I' => {
                self.inc_by(2);
                Qualifier::Interface(self.reusable_name()?)
            }
            // processQualCAsSpecialFragment is false: 'C' is a numbered namespace
            '0'..='9' | 'B'..='H' | 'J'..='P' => {
                self.inc();
                Qualifier::Numbered(self.enc_num()?)
            }
            'Q' => {
                self.inc_by(2);
                Qualifier::Q(self.qualification()?)
            }
            _ => {
                if !self.llvm {
                    return err("SpecialName not expected in qualification list");
                }
                self.nested_name()?
            }
        })
    }

    /// `MDNestedName.parseInternal`.
    fn nested_name(&mut self) -> R<Qualifier> {
        if self.peek() != '?' {
            return err("Missing '?' in MDNestedName parsing");
        }
        if self.peek_at(1) == '?' && !self.llvm {
            self.inc();
        }
        Ok(Qualifier::Nested(Box::new(self.object_cpp()?)))
    }

    /// `MDQualifiedName.parseInternal`.
    fn qualified_name(&mut self) -> R<QualifiedName> {
        let name = self.reusable_name()?;
        let qual = self.qualification()?;
        Ok(QualifiedName { name, qual })
    }

    /// `MDSpecialName.parseInternal` (the leading `?` consumed).
    fn special_name(&mut self) -> R<SpecialName> {
        let mut sn = SpecialName { rtti: -1, ..SpecialName::default() };
        let c = self.get_inc();
        let simple: Option<&str> = match c {
            '0' => {
                sn.is_ctor = true;
                Some("")
            }
            '1' => {
                sn.is_dtor = true;
                Some("")
            }
            'B' => {
                sn.is_type_cast = true;
                Some("operator")
            }
            '_' => None,
            _ => Some(operator_name(c)),
        };
        sn.name = match simple {
            Some(n) => n.to_string(),
            None => self.special_name_underscore(&mut sn)?,
        };
        Ok(sn)
    }

    /// `MDSpecialName.parseInternal`, the `?_` codes.
    fn special_name_underscore(&mut self, sn: &mut SpecialName) -> R<String> {
        let c = self.get_inc();
        Ok(match c {
            'C' => {
                sn.is_string = true;
                self.md_string()?
            }
            'P' => {
                let nested = self.special_name()?;
                let mut b = String::new();
                render_special(&self.out(), &mut b, &nested);
                ins(&mut b, "`udt returning'");
                b
            }
            'R' => self.rtti_name(sn)?,
            '_' => self.special_name_double_underscore()?,
            _ => underscore_name(c).to_string(),
        })
    }

    /// `MDSpecialName.parseInternal`, `?_R`: the RTTI names.
    fn rtti_name(&mut self, sn: &mut SpecialName) -> R<String> {
        let c = self.get_inc();
        Ok(match c {
            '0' => {
                sn.rtti = 0;
                let dt = self.data_type(false)?;
                let mut b = String::new();
                render_dt(&self.out(), &mut b, &dt);
                app(&mut b, " `RTTI Type Descriptor'");
                b
            }
            '1' => {
                sn.rtti = 1;
                let a = self.signed_num()?;
                let b = self.signed_num()?;
                let c = self.signed_num()?;
                let d = self.enc_num()?;
                format!("`RTTI Base Class Descriptor at ({a},{b},{c},{d})'")
            }
            '2' => {
                sn.rtti = 2;
                "`RTTI Base Class Array'".into()
            }
            '3' => {
                sn.rtti = 3;
                "`RTTI Class Hierarchy Descriptor'".into()
            }
            '4' => {
                sn.rtti = 4;
                "`RTTI Complete Object Locator'".into()
            }
            // Java leaves the name null; printing it would throw
            _ => {
                self.out().fault("NullPointerException: MDSpecialName ?_R name");
                String::new()
            }
        })
    }

    /// `MDSpecialName.parseInternal`, `?__`.
    fn special_name_double_underscore(&mut self) -> R<String> {
        let c = self.get_inc();
        Ok(match c {
            'E' | 'F' => {
                let mut b = String::new();
                if self.peek() == '?' {
                    let o = self.object_cpp()?;
                    render_cpp(&self.out(), &mut b, &o);
                    if self.peek() == '@' {
                        self.inc();
                    }
                } else {
                    let n = self.basic_name()?;
                    render_basic(&self.out(), &mut b, &n, None);
                }
                app(&mut b, "''");
                let what = if c == 'E' { "`dynamic initializer for '" } else { "`dynamic atexit destructor for '" };
                ins(&mut b, what);
                b
            }
            'K' => {
                let f = self.fragment(true);
                let mut b = String::new();
                self.render_fragment(&self.out(), &mut b, &f);
                ins(&mut b, "operator \"\" ");
                b
            }
            _ => double_underscore_name(c).to_string(),
        })
    }

    /// `MDString.parseInternal`, with the string as `getString(UTF8, UTF16)` gives it.
    fn md_string(&mut self) -> R<String> {
        if self.get_inc() != '@' {
            return err("MDString parse error: missing @");
        }
        if self.get_inc() != '_' {
            return err("MDString parse error: missing _");
        }
        let char_type = self.get_inc();
        let len = self.enc_num()?.int_value();
        let _crc = self.enc_num()?;
        let type_size = if char_type == '1' { 2 } else { 1 };
        if len < 0 {
            self.out().fault("NegativeArraySizeException: MDString length");
            return err("MDString: negative length");
        }
        let mut bytes = Vec::new();
        while self.peek() != '@' && bytes.len() < len as usize {
            bytes.push(self.string_byte()?);
        }
        self.inc();
        if self.peek() != DONE {
            let _addr = self.enc_num()?;
        }
        // the array is `len` bytes, zero after the parsed ones: two zeros suffice to end it
        let pad = (len as usize - bytes.len()).min(2);
        bytes.extend(std::iter::repeat_n(0, pad));
        let s = if type_size == 2 { decode_utf16_java(&bytes) } else { String::from_utf8_lossy(&bytes).into_owned() };
        let mut out = String::new();
        let s = s.split('\0').next().unwrap_or("").to_string();
        ins(&mut out, &s);
        Ok(out)
    }

    /// `MDString.parseByte`.
    fn string_byte(&mut self) -> R<u8> {
        let c = self.get_inc();
        if is_letter(c) || is_digit(c) || c == '_' || c == '$' {
            return Ok(c as u32 as u8);
        }
        if c != '?' {
            return err(format!("MDString parse error: invalid code1:{c}"));
        }
        if self.peek() == DONE {
            return err("MDString parse error: not enough data");
        }
        let c = self.get_inc();
        Ok(match c {
            'a'..='z' => (c as u8 - b'a').wrapping_add(0xe1),
            'A'..='Z' => (c as u8 - b'A').wrapping_add(0xc1),
            '0' => b',',
            '1' => b'/',
            '2' => b'\\',
            '3' => b':',
            '4' => b'.',
            '5' => b' ',
            '6' => b'\n',
            '7' => b'\t',
            '8' => b'\'',
            '9' => b'-',
            '$' => {
                let hi = self.hex_code()?;
                let lo = self.hex_code()?;
                (hi << 4) | lo
            }
            _ => return err(format!("MDString parse error: invalid code2: {c}")),
        })
    }

    fn hex_code(&mut self) -> R<u8> {
        if self.peek() == DONE {
            return err("MDString parse error: not enough data");
        }
        let c = self.get_inc();
        if !('A'..='P').contains(&c) {
            return err(format!("MDString parse error: invalid hex code:{c}"));
        }
        Ok(c as u8 - b'A')
    }

    // ---- numbers

    /// `MDEncodedNumber.parseInternal`.
    fn enc_num(&mut self) -> R<EncNum> {
        let c = self.peek();
        if c.is_ascii_digit() {
            self.inc();
            let v = c as u64 - '0' as u64 + 1;
            return Ok(EncNum { dec: v.to_string(), low: v });
        }
        if !(('A'..='P').contains(&c) || c == '@') {
            return err(format!("Illegal character at index {} in MDEncodedNumber: {c}", self.i));
        }
        let mut nibbles = Vec::new();
        let mut low = 0u64;
        while ('A'..='P').contains(&self.peek()) {
            let n = self.get_inc() as u8 - b'A';
            nibbles.push(n);
            low = (low << 4) | u64::from(n);
        }
        if self.peek() == '@' {
            self.inc();
        }
        Ok(EncNum { dec: hex_to_dec(&nibbles), low })
    }

    /// `MDSignedEncodedNumber.parseInternal`.
    fn signed_num(&mut self) -> R<SignedNum> {
        let neg = self.peek() == '?';
        if neg {
            self.inc();
        }
        Ok(SignedNum { neg, num: self.enc_num()? })
    }

    // ---- templates

    /// `MDTemplateNameAndArguments.parseInternal`.
    fn template_na(&mut self) -> R<TemplateNa> {
        if self.peek() != '?' || self.peek_at(1) != '$' {
            return err("Invalid TemplateNameandArguments");
        }
        self.inc_by(2);
        self.push_template_context()?;
        let name = self.basic_name()?;
        let (args, comma) = self.template_args()?;
        self.pop_context();
        Ok(TemplateNa { name, args, comma })
    }

    /// `MDTemplateArgumentsList.parseInternal`.
    fn template_args(&mut self) -> R<(Vec<Dt>, Vec<bool>)> {
        let mut args: Vec<Dt> = Vec::new();
        let mut comma = Vec::new();
        let mut needs_comma = false;
        loop {
            let code = self.peek();
            let dt = match code {
                '@' => {
                    self.inc();
                    break;
                }
                DONE => break,
                'X' => {
                    self.inc();
                    Rc::new(DataType::new(DtKind::Void { printable: true }))
                }
                'Z' => return err("Varargs not allowed as template parameter"),
                '?' => {
                    self.inc();
                    let x = self.enc_num()?;
                    let dt = Rc::new(DataType::new(DtKind::Named(format!("`template-parameter-{x}'"))));
                    self.add_tparam(&dt)?;
                    dt
                }
                '$' if self.peek_at(1) == '$' && self.peek_at(2) == '$' && self.peek_at(3) == 'V' => {
                    self.inc_by(4);
                    continue;
                }
                '$' if self.peek_at(1) == '$' && self.peek_at(2) == 'V' => {
                    self.inc_by(3);
                    continue;
                }
                '$' if self.peek_at(1) == '$' => {
                    let dt = self.primary_data_type(true)?;
                    // Java's `break` here leaves the switch, not the loop
                    if matches!(dt.kind, DtKind::EmptyParam | DtKind::EndParam) {
                        continue;
                    }
                    if dt.is_backref_kind() {
                        self.add_tparam(&dt)?;
                    }
                    dt
                }
                '$' => {
                    let name = self.template_constant()?;
                    if name.is_empty() {
                        continue;
                    }
                    let dt = Rc::new(DataType::new(DtKind::Named(name)));
                    self.add_tparam(&dt)?;
                    dt
                }
                '0'..='9' => {
                    self.inc();
                    let dt = self.backref_tparam(code as usize - '0' as usize)?;
                    // templateBackrefComma is true
                    comma.push(true);
                    needs_comma = true;
                    args.push(dt);
                    continue;
                }
                _ => {
                    let dt = self.primary_data_type(true)?;
                    if dt.is_backref_kind() {
                        self.add_tparam(&dt)?;
                    }
                    dt
                }
            };
            comma.push(needs_comma);
            needs_comma = true;
            args.push(dt);
        }
        Ok((args, comma))
    }

    /// `MDTemplateConstant.parseInternal`: its printed name.
    fn template_constant(&mut self) -> R<String> {
        let code = self.get_inc();
        if code != '$' {
            return err(format!("Template Parameter needs work: {code} code"));
        }
        let code = self.get_inc();
        let out = |p: &Self, o: &ObjectCpp| {
            let mut b = String::new();
            render_cpp(&p.out(), &mut b, o);
            b
        };
        Ok(match code {
            '0' => self.signed_num()?.to_string(),
            '1' => {
                self.push_shared_context()?;
                let o = self.object_cpp()?;
                self.pop_context();
                let mut b = out(self, &o);
                ins(&mut b, "&");
                b
            }
            '2' => {
                let at = self.i;
                match self.floating_point_constant() {
                    Ok(s) => s,
                    Err(_) => {
                        self.i = at;
                        self.initialized_template_constant()?
                    }
                }
            }
            'D' => format!("`template-parameter{}'", self.signed_num()?),
            'E' => {
                let o = self.object_cpp()?;
                out(self, &o)
            }
            'F' => {
                let a = self.signed_num()?;
                let b = self.signed_num()?;
                format!("{{{a},{b}}}")
            }
            'G' => {
                let a = self.signed_num()?;
                let b = self.signed_num()?;
                let c = self.signed_num()?;
                format!("{{{a},{b},{c}}}")
            }
            'H' | 'I' | 'J' => {
                let o = self.object_cpp()?;
                let mut b = out(self, &o);
                let n = match code {
                    'H' => 1,
                    'I' => 2,
                    _ => 3,
                };
                let mut nums = Vec::new();
                for _ in 0..n {
                    nums.push(self.signed_num()?);
                }
                ins(&mut b, "{");
                for x in nums {
                    app(&mut b, ",");
                    app(&mut b, &x.to_string());
                }
                app(&mut b, "}");
                b
            }
            'Q' => format!("`non-type-template-parameter{}'", self.signed_num()?),
            'R' => {
                let f = self.fragment(true);
                let _address = self.signed_num()?;
                let mut b = String::new();
                self.render_fragment(&self.out(), &mut b, &f);
                b
            }
            'S' => String::new(),
            _ => return err(format!("Unknown Template Constant: ${code} code")),
        })
    }

    /// `MDTemplateConstant.parseFloatingPointConstant`.
    fn floating_point_constant(&mut self) -> R<String> {
        let a = self.signed_num()?.to_string();
        let b = self.signed_num()?;
        let (mut s, a) = match a.strip_prefix('-') {
            Some(r) => ("-".to_string(), r.to_string()),
            None => (String::new(), a),
        };
        let mut chars = a.chars();
        let first = chars.next().ok_or_else(|| Error("StringIndexOutOfBounds".into()))?;
        s.push(first);
        s.push('.');
        s += chars.as_str();
        Ok(format!("{s}e{b}"))
    }

    /// `MDTemplateConstant.parseInitializedTemplateConstant`. Java's loop re-tests the first
    /// character only, so anything but `@` there loops until a type info fails to parse.
    fn initialized_template_constant(&mut self) -> R<String> {
        let t = self.data_type(true)?;
        let mut s = dt_to_string(&self.out(), &t) + "{";
        if self.peek() != '@' {
            loop {
                let ti = self.type_info(-1, false)?;
                s += &ti_to_string(&self.out(), &ti);
            }
        }
        self.next();
        s.push('}');
        Ok(s)
    }

    // ---- type info

    /// `MDTypeInfoParser.parse` and then the type info's `parse()`.
    fn type_info(&mut self, rtti: i32, type_cast: bool) -> R<TypeInfo> {
        let (mut ti, pend, based) = self.ti_header(rtti)?;
        self.ti_body(&mut ti, pend, type_cast, based)?;
        Ok(ti)
    }

    /// `MDTypeInfoParser.parse`: the type info made, with a based attribute of a function.
    fn ti_header(&mut self, rtti: i32) -> R<(TypeInfo, Pend, Option<Based>)> {
        let is_based = self.peek() == '_';
        if is_based {
            self.inc();
        }
        let code = self.peek();
        let mut ti = TypeInfo::default();
        let mut based = None;
        let (access, storage, pend) = match code {
            '$' => {
                self.inc();
                let (t, p, b) = self.ti_special(rtti)?;
                ti = t;
                based = b;
                (ti.access, ti.storage, p)
            }
            '0' => (Access::Private, Storage::Static, Pend::Variable),
            '1' => (Access::Protected, Storage::Static, Pend::Variable),
            '2' => (Access::Public, Storage::Static, Pend::Variable),
            '3' | '4' => (Access::None, Storage::None, Pend::Variable),
            '5' => (Access::None, Storage::None, Pend::Guard),
            '6' | '7' => (Access::None, Storage::None, Pend::VxTable),
            '8' | '9' => (Access::None, Storage::None, Pend::Plain),
            'A' | 'B' | 'I' | 'J' | 'Q' | 'R' => (member_access(code), Storage::None, Pend::Fn { member: true }),
            'C' | 'D' | 'K' | 'L' | 'S' | 'T' => (member_access(code), Storage::Static, Pend::Fn { member: true }),
            'E' | 'F' | 'M' | 'N' | 'U' | 'V' => (member_access(code), Storage::Virtual, Pend::Fn { member: true }),
            'G' | 'H' | 'O' | 'P' | 'W' | 'X' => (member_access(code), Storage::Virtual, Pend::Adjustor),
            'Y' | 'Z' => (Access::None, Storage::None, Pend::Fn { member: false }),
            _ => return err(format!("Invalid MDTypeInfo, unknown case: {code}")),
        };
        if code != '$' {
            self.inc();
        }
        ti.access = access;
        ti.non_member |= matches!(pend, Pend::Fn { member: false });
        ti.storage = storage;
        if matches!(pend, Pend::Adjustor) {
            ti.thunk = true;
        }
        if is_based && pend.is_function() {
            based = Some(self.based()?);
        }
        Ok((ti, pend, based))
    }

    /// `MDTypeInfoParser.parseSpecialHandlingFunction`.
    fn ti_special(&mut self, rtti: i32) -> R<(TypeInfo, Pend, Option<Based>)> {
        let ch = self.get_inc();
        let vt = |access| {
            (TypeInfo { access, storage: Storage::Virtual, thunk: true, ..TypeInfo::default() }, Pend::Vtordisp, None)
        };
        Ok(match ch {
            '0' | '1' => vt(Access::Private),
            '2' | '3' => vt(Access::Protected),
            '4' | '5' => vt(Access::Public),
            '$' => {
                let ch2 = self.get_inc();
                let r = match ch2 {
                    'J' | 'N' | 'O' => {
                        let c = self.get_inc();
                        if !c.is_ascii_digit() {
                            return err(format!("Access Level 'extern \"C\"' count is wrong: {c}"));
                        }
                        for _ in 0..(c as u32 - '0' as u32) {
                            self.get_inc();
                        }
                        let (mut t, p, b) = self.ti_header(rtti)?;
                        t.extern_c = true;
                        (t, p, b)
                    }
                    'F' | 'H' | 'L' | 'M' | 'Q' => self.ti_header(rtti)?,
                    _ => return err(format!("Access Level $$, unknown case: {ch2}")),
                };
                let (mut t, p, b) = r;
                t.special = Some(ch2);
                (t, p, b)
            }
            'B' => (TypeInfo { thunk: true, ..TypeInfo::default() }, Pend::VCall, None),
            'R' => {
                let ch3 = self.get_inc();
                let access = match ch3 {
                    '0' | '1' => Access::Private,
                    '2' | '3' => Access::Protected,
                    '4' | '5' => Access::Public,
                    _ => return err(format!("Access Level $R, unknown case: {ch3}")),
                };
                (
                    TypeInfo { access, storage: Storage::Virtual, thunk: true, ..TypeInfo::default() },
                    Pend::Vtordispex,
                    None,
                )
            }
            _ => return err(format!("Access Level $, unknown case: {ch}")),
        })
    }

    /// The type info's `parseInternal`.
    fn ti_body(&mut self, ti: &mut TypeInfo, pend: Pend, type_cast: bool, based: Option<Based>) -> R<()> {
        let member_cv = ti.storage != Storage::Static;
        let func = |p: &mut Self, args: bool, cv: bool, based: Option<Based>| -> R<Rc<FunctionType>> {
            Ok(Rc::new(p.function_type(args, args, cv, type_cast, None, based)?))
        };
        ti.kind = match pend {
            Pend::Plain => TiKind::Plain,
            Pend::Variable => {
                let dt = self.data_type(false)?;
                let cv = self.cv_mod(CvMod::default())?;
                TiKind::Variable { cv, dt }
            }
            Pend::Guard => TiKind::Guard(self.enc_num()?),
            Pend::VxTable => {
                let cv = self.cv_mod(CvMod::default())?;
                let mut quals = Vec::new();
                while self.peek() != '@' && self.peek() != DONE {
                    quals.push(self.qualification()?);
                }
                let good_termination = self.peek() == '@';
                if good_termination {
                    self.inc();
                }
                TiKind::VxTable { cv, quals, good_termination }
            }
            Pend::Fn { member } => {
                TiKind::Function { ft: func(self, true, member && member_cv, based)?, extra: FnExtra::None }
            }
            Pend::Adjustor => {
                let a = self.enc_num()?;
                TiKind::Function { ft: func(self, true, member_cv, based)?, extra: FnExtra::Adjustor(a) }
            }
            Pend::Vtordisp => {
                let a = self.enc_num()?;
                let b = self.enc_num()?;
                TiKind::Function { ft: func(self, true, member_cv, based)?, extra: FnExtra::Vtordisp(a, b) }
            }
            Pend::Vtordispex => {
                let n = [self.enc_num()?, self.enc_num()?, self.enc_num()?, self.enc_num()?];
                TiKind::Function { ft: func(self, true, member_cv, based)?, extra: FnExtra::Vtordispex(n) }
            }
            Pend::VCall => self.vcall(based, type_cast)?,
        };
        Ok(())
    }

    /// `MDVCall.parseInternal`.
    fn vcall(&mut self, based: Option<Based>, type_cast: bool) -> R<TiKind> {
        let index = self.enc_num()?;
        let t = self.get_inc();
        let (this_far, call_far, vfptr_far) = match t {
            'A' => (false, false, Some(false)),
            'B' => (false, true, Some(false)),
            'C' => (true, false, Some(false)),
            'D' => (true, true, Some(false)),
            'E' => (false, false, Some(true)),
            'F' => (false, true, Some(true)),
            'G' => (true, false, Some(true)),
            'H' => (true, true, Some(true)),
            'I' => (false, false, None),
            'J' => (false, true, None),
            'K' => (true, false, None),
            'L' => (true, true, None),
            _ => return err(format!("VCall ($B), unexpected thunkType: {t}")),
        };
        let vbased = if vfptr_far.is_none() { Some(self.based()?) } else { None };
        let ft = Rc::new(self.function_type(false, false, false, type_cast, None, based)?);
        Ok(TiKind::Function { ft, extra: FnExtra::VCall { index, this_far, call_far, vfptr_far, based: vbased } })
    }

    // ---- function types

    /// `MDFunctionType.parseInternal`.
    fn function_type(
        &mut self,
        has_args: bool,
        has_return: bool,
        has_cv: bool,
        type_cast: bool,
        this_cv: Option<Rc<CvMod>>,
        based: Option<Based>,
    ) -> R<FunctionType> {
        self.push_shared_context()?;
        let this_cv = if has_cv {
            Some(Rc::new(self.cv_mod(CvMod { is_this_pointer_mod: true, ..CvMod::default() })?))
        } else {
            this_cv
        };
        let convention = self.calling_convention()?;
        let ret = if has_return { Some(self.data_type(type_cast)?) } else { None };
        let (args, throw) = if has_args {
            let a = self.args_list()?;
            let t = self.throw_attr()?;
            (Some(a), Some(t))
        } else {
            (None, None)
        };
        self.pop_context();
        Ok(FunctionType {
            convention,
            ret,
            args,
            this_cv,
            throw,
            has_return,
            has_args,
            is_type_cast: type_cast,
            from_modifier: Cell::new(false),
            based,
        })
    }

    /// `MDCallingConvention.parseInternal`.
    fn calling_convention(&mut self) -> R<String> {
        let ch = self.get_inc();
        Ok(match ch {
            'A' | 'B' => "__cdecl",
            'C' | 'D' => "__pascal",
            'E' | 'F' => "__thiscall",
            'G' | 'H' => "__stdcall",
            'I' | 'J' => "__fastcall",
            'K' | 'L' | 'Y' | 'Z' => "",
            'M' | 'N' => "__clrcall",
            'O' | 'P' => "__eabi",
            'Q' | 'R' => "__vectorcall",
            'S' | 'T' => "__swift_1",
            'U' | 'V' => "__swift_2",
            'W' | 'X' => "__swiftasynccall",
            _ => return err(format!("Unknown calling convention {ch}\n")),
        }
        .to_string())
    }

    /// `MDArgumentsList.parseInternal`.
    fn args_list(&mut self) -> R<Vec<Dt>> {
        let mut args = Vec::new();
        loop {
            let code = self.peek();
            match code {
                '@' => {
                    self.inc();
                    break;
                }
                'X' => {
                    self.inc();
                    let first = args.is_empty();
                    args.push(Rc::new(DataType::new(DtKind::Void { printable: true })));
                    if self.peek() == '@' {
                        return err("Void list has '@' terminator");
                    }
                    if first {
                        break;
                    }
                }
                'Z' => {
                    self.inc();
                    args.push(Rc::new(DataType::new(DtKind::VarArgs)));
                    break;
                }
                '0'..='9' => {
                    self.inc();
                    args.push(self.backref_param(code as usize - '0' as usize)?);
                }
                DONE => return err("String Terminated"),
                _ => {
                    let dt = self.primary_data_type(true)?;
                    if dt.is_backref_kind() {
                        self.add_param(&dt)?;
                    }
                    args.push(dt);
                }
            }
        }
        Ok(args)
    }

    /// `MDThrowAttribute.parseInternal`.
    fn throw_attr(&mut self) -> R<Throw> {
        if self.peek() == '_' && self.peek_at(1) == 'E' {
            self.inc_by(2);
            return Ok(Throw { no_except: true, has_throw: false, args: Vec::new() });
        }
        if self.peek() == 'Z' {
            self.inc();
            return Ok(Throw { no_except: false, has_throw: false, args: Vec::new() });
        }
        Ok(Throw { no_except: false, has_throw: true, args: self.args_list()? })
    }

    // ---- data types

    /// `MDDataTypeParser.parseDataType` and the type's `parse()`.
    fn data_type(&mut self, hi: bool) -> R<Dt> {
        let c = self.dt_header(hi)?;
        self.dt_body(c)
    }

    /// `MDDataTypeParser.parsePrimaryDataType` and the type's `parse()`.
    fn primary_data_type(&mut self, hi: bool) -> R<Dt> {
        let c = self.primary_header(hi)?;
        self.dt_body(c)
    }

    /// `MDDataTypeParser.parseBasicDataType` and the type's `parse()`.
    fn basic_data_type(&mut self, hi: bool) -> R<Dt> {
        let c = self.basic_header(hi)?;
        self.dt_body(c)
    }

    /// `MDDataTypeParser.parseDataType`: which type (its code consumed).
    fn dt_header(&mut self, hi: bool) -> R<Ctor> {
        match self.peek() {
            '?' => {
                self.inc();
                Ok(Ctor::Mod(ModKind::Question, false, false))
            }
            'X' => {
                self.inc();
                Ok(Ctor::Done(DtKind::Void { printable: true }, Sign::Signed))
            }
            DONE => err(format!("Type code not expected: {DONE}")),
            _ => self.primary_header(hi),
        }
    }

    /// `MDDataTypeParser.parsePrimaryDataType`.
    fn primary_header(&mut self, hi: bool) -> R<Ctor> {
        match self.peek() {
            'A' => {
                self.inc();
                Ok(Ctor::Mod(ModKind::Reference, false, false))
            }
            'B' => {
                self.inc();
                Ok(Ctor::Mod(ModKind::Reference, false, hi))
            }
            DONE => err("PrimaryDataType: no data for type code"),
            _ => self.basic_header(hi),
        }
    }

    /// `MDDataTypeParser.parseBasicDataType`.
    fn basic_header(&mut self, hi: bool) -> R<Ctor> {
        let code = self.get_inc();
        let basic = |name, sign| Ok(Ctor::Done(DtKind::Basic { name, extended: false }, sign));
        let complex = |tag| Ok(Ctor::Complex(tag));
        match code {
            '?' => Ok(Ctor::QualNamed),
            '$' => self.special_extended_header(hi),
            'C' => basic("char", Sign::Specified),
            'D' => basic("char", Sign::Signed),
            'E' => basic("char", Sign::Unsigned),
            'F' => basic("short", Sign::Signed),
            'G' => basic("short", Sign::Unsigned),
            'H' => basic("int", Sign::Signed),
            'I' => basic("int", Sign::Unsigned),
            'J' => basic("long", Sign::Signed),
            'K' => basic("long", Sign::Unsigned),
            'L' => complex(""),
            'M' => basic("float", Sign::Signed),
            'N' => basic("double", Sign::Signed),
            'O' => basic("long double", Sign::Signed),
            'P' => Ok(Ctor::Mod(ModKind::Pointer, false, false)),
            'Q' => Ok(Ctor::Mod(ModKind::Pointer, hi, false)),
            'R' => Ok(Ctor::Mod(ModKind::Pointer, false, hi)),
            'S' => Ok(Ctor::Mod(ModKind::Pointer, hi, hi)),
            'T' => complex("union"),
            'U' => complex("struct"),
            'V' => complex("class"),
            'W' => Ok(Ctor::Enum),
            'X' => Ok(Ctor::Done(DtKind::Void { printable: true }, Sign::Signed)),
            'Y' => complex("cointerface"),
            'Z' => Ok(Ctor::Done(DtKind::VarArgs, Sign::Signed)),
            '_' => self.extended_header(),
            '@' => Ok(Ctor::Done(DtKind::Void { printable: false }, Sign::Signed)),
            DONE => err("BasicDataType: no data for type code"),
            _ => err(format!("BasicDataType: unrecognized code: {code}")),
        }
    }

    /// `MDDataTypeParser.parseBasicDataType`, the `_` codes.
    fn extended_header(&mut self) -> R<Ctor> {
        let code = self.get_inc();
        let ext = |name, sign| Ok(Ctor::Done(DtKind::Basic { name, extended: true }, sign));
        match code {
            '$' => Ok(Ctor::W64),
            'D' => ext("__int8", Sign::Signed),
            'E' => ext("__int8", Sign::Unsigned),
            'F' => ext("__int16", Sign::Signed),
            'G' => ext("__int16", Sign::Unsigned),
            'H' => ext("__int32", Sign::Signed),
            'I' => ext("__int32", Sign::Unsigned),
            'J' => ext("__int64", Sign::Signed),
            'K' => ext("__int64", Sign::Unsigned),
            'L' => ext("__int128", Sign::Signed),
            'M' => ext("__int128", Sign::Unsigned),
            'N' => ext("bool", Sign::Signed),
            'O' => Ok(Ctor::Mod(ModKind::ArrayBasic, false, false)),
            'P' => ext("auto", Sign::Signed),
            'Q' => ext("char8_t", Sign::Signed),
            'R' => ext("<unknown>", Sign::Signed),
            'S' => ext("char16_t", Sign::Signed),
            'T' => ext("decltype(auto)", Sign::Signed),
            'U' => ext("char32_t", Sign::Signed),
            'V' => ext("UNKNOWN", Sign::Signed),
            'W' => ext("wchar_t", Sign::Signed),
            'X' => Ok(Ctor::Complex("coclass")),
            'Y' => Ok(Ctor::Complex("cointerface")),
            '_' => {
                // an MDDataType given setName, not setTypeName: printing it throws
                let _ = self.object_cpp()?;
                Ok(Ctor::Done(DtKind::NullName, Sign::Signed))
            }
            DONE => err("Extended BasicDataType: no data for type code"),
            _ => err(format!("Extended BasicDataType: unrecognized code: {code}")),
        }
    }

    /// `MDDataTypeParser.parseSpecialExtendedType`.
    fn special_extended_header(&mut self, hi: bool) -> R<Ctor> {
        let code = self.get_inc();
        if code != '$' {
            return err(format!("ExtendedType invalid character: {code}"));
        }
        let code = self.get_inc();
        match code {
            'A' => Ok(Ctor::Mod(ModKind::FuncIndirect, false, false)),
            'B' => Ok(Ctor::Mod(ModKind::PointerRef, false, false)),
            'C' => Ok(Ctor::Mod(ModKind::DataRef, false, false)),
            'Q' => Ok(Ctor::Mod(ModKind::RightRef, false, false)),
            'R' => Ok(Ctor::Mod(ModKind::RightRef, false, hi)),
            'T' => Ok(Ctor::Done(DtKind::Basic { name: "std::nullptr_t", extended: true }, Sign::Signed)),
            'Y' => Ok(Ctor::QualNamed),
            'V' => Ok(Ctor::Done(DtKind::EmptyParam, Sign::Signed)),
            'Z' => Ok(Ctor::Done(DtKind::EndParam, Sign::Signed)),
            _ => err(format!("SpecialDataType: unrecognized code: {code}")),
        }
    }

    /// The data type's `parseInternal`.
    fn dt_body(&mut self, c: Ctor) -> R<Dt> {
        self.nest(|p| p.dt_body_nested(c))
    }

    fn dt_body_nested(&mut self, c: Ctor) -> R<Dt> {
        let (kind, sign) = match c {
            Ctor::Done(k, s) => (k, s),
            Ctor::QualNamed => (DtKind::QualNamed(self.qualified_name()?), Sign::Signed),
            Ctor::Complex(tag) => (DtKind::Complex { tag, qn: self.qualified_name()? }, Sign::Signed),
            Ctor::Enum => {
                let code = self.get_inc();
                let tag = match code {
                    '0' => "enum char",
                    '1' => "enum unsigned char",
                    '2' => "enum short",
                    '3' => "enum unsigned short",
                    '4' => "enum",
                    '5' => "enum unsigned int",
                    '6' => "enum long",
                    '7' => "enum unsigned long",
                    _ => return err(format!("Enum code not expected: {code}")),
                };
                (DtKind::Complex { tag, qn: self.qualified_name()? }, Sign::Signed)
            }
            Ctor::W64 => (DtKind::W64(self.basic_data_type(false)?), Sign::Signed),
            Ctor::Mod(kind, c, v) => (DtKind::Modifier(Box::new(self.modifier(kind, c, v)?)), Sign::Signed),
        };
        Ok(Rc::new(DataType { sign, kind }))
    }

    /// `MDModifierType.parseInternal` with the subclasses' constructors and overrides.
    fn modifier(&mut self, kind: ModKind, is_const: bool, is_volatile: bool) -> R<Modifier> {
        let mut cv = CvMod { mod_type: ModType::Question, ..CvMod::default() };
        match kind {
            ModKind::Pointer => cv.mod_type = ModType::Pointer,
            ModKind::Reference => cv.mod_type = ModType::Reference,
            ModKind::RightRef => cv.mod_type = ModType::RightReference,
            ModKind::DataRef => cv.mod_type = ModType::Other,
            ModKind::FuncIndirect => {
                cv.mod_type = ModType::Other;
                cv.no_properties = true;
                cv.is_function = true;
            }
            ModKind::PointerRef => {
                cv.mod_type = ModType::Other;
                cv.no_properties = true;
                cv.no_cv = true;
            }
            ModKind::Question => {}
            ModKind::ArrayBasic => cv.mod_type = ModType::Array,
        }
        let cv = self.cv_mod(cv)?;
        let r = if cv.is_function {
            let this_cv = cv.this_cv.clone();
            TypeRef::Func(Rc::new(self.function_type(true, true, false, false, this_cv, None)?))
        } else if self.peek() == 'Y' {
            TypeRef::Data(self.array_referenced()?)
        } else if kind == ModKind::Question {
            TypeRef::Data(self.primary_data_type(false)?)
        } else {
            TypeRef::Data(self.basic_data_type(false)?)
        };
        if kind == ModKind::Question {
            self.question_suffix();
        }
        Ok(Modifier { kind, is_const, is_volatile, cv, r })
    }

    /// `MDQuestionModifierType.parseSuffix` (parsed, not printed).
    fn question_suffix(&mut self) {
        if self.peek() != '`' {
            return;
        }
        let base = self.i;
        self.get_inc();
        for _ in 0..8 {
            if self.peek() == DONE || !self.get_inc().is_ascii_hexdigit() {
                self.i = base;
                return;
            }
        }
    }

    /// `MDArrayReferencedType.parseInternal`.
    fn array_referenced(&mut self) -> R<Dt> {
        self.inc();
        let n = self.enc_num()?.int_value();
        let mut array = String::new();
        for _ in 0..n.max(0) {
            array += &format!("[{}]", self.enc_num()?);
        }
        let r = self.primary_data_type(false)?;
        Ok(Rc::new(DataType::new(DtKind::ArrayRef { array, r })))
    }

    /// `MDCVMod.parseInternal`.
    fn cv_mod(&mut self, mut cv: CvMod) -> R<CvMod> {
        if !cv.no_properties {
            self.cv_efghi(&mut cv)?;
            while self.managed_property(&mut cv)? && self.cv_efghi(&mut cv)? {}
        }
        if !cv.no_cv {
            self.cv_code(&mut cv)?;
        }
        if cv.is_function && (cv.found_managed_property || !cv.unaligned_restrict_ptr64.is_empty()) {
            return err("EFI and Managed Properies not permitted for function pointer/reference");
        }
        if cv.is_function && cv.mod_type == ModType::Question {
            return err("Function refType only permitted on pointer or reference");
        }
        Ok(cv)
    }

    /// `MDCVMod.parseEFGHI` (`allowCVModLRefRRef` is true).
    fn cv_efghi(&mut self, cv: &mut CvMod) -> R<bool> {
        let mut found = false;
        loop {
            match self.peek() {
                'E' => cv.unaligned_restrict_ptr64.push(CvPrefix::Ptr64),
                'F' => cv.unaligned_restrict_ptr64.push(CvPrefix::Unaligned),
                'I' => cv.unaligned_restrict_ptr64.push(CvPrefix::Restrict),
                'G' => {
                    if !cv.is_this_pointer_mod {
                        return err("LRef only permitted on 'this' pointer");
                    }
                    cv.is_lref = true;
                }
                'H' => {
                    if !cv.is_this_pointer_mod {
                        return err("RRef only permitted on 'this' pointer");
                    }
                    cv.is_rref = true;
                }
                _ => return Ok(found),
            }
            self.inc();
            found = true;
        }
    }

    /// `MDCVMod.parseManagedProperty`.
    fn managed_property(&mut self, cv: &mut CvMod) -> R<bool> {
        if self.peek() != '$' {
            return Ok(false);
        }
        self.inc();
        let code = self.peek();
        match code {
            'A' => {
                self.inc();
                cv.is_gc = true;
            }
            'B' => {
                self.inc();
                if cv.mod_type != ModType::Plain && cv.mod_type != ModType::Other {
                    cv.is_pin_pointer = true;
                }
            }
            'C' => {
                self.inc();
                cv.is_cli_property = true;
                if cv.mod_type == ModType::Plain {
                    cv.mod_type = ModType::Pointer;
                }
            }
            '0'..='9' => {
                cv.is_cli_array = true;
                self.inc();
                let rank = code as i32 - '0' as i32;
                let c = self.get_inc();
                cv.array_rank = rank * 16 + c as i32 - '0' as i32;
            }
            _ => return err(format!("unknown managed property: {code}")),
        }
        cv.found_managed_property = true;
        Ok(true)
    }

    /// `MDCVMod.parseCV`.
    fn cv_code(&mut self, cv: &mut CvMod) -> R<()> {
        let code = self.get_inc();
        // (const, volatile, based, member, function)
        let (c, v, b, m, f) = match code {
            'A' => (false, false, false, false, false),
            'B' | 'J' => (true, false, false, false, false),
            'C' | 'G' | 'K' => (false, true, false, false, false),
            'D' | 'H' | 'L' => (true, true, false, false, false),
            'M' => (false, false, true, false, false),
            'N' => (true, false, true, false, false),
            'O' => (false, true, true, false, false),
            'P' => (true, true, true, false, false),
            'Q' | 'U' | 'Y' => (false, false, false, true, false),
            'R' | 'V' | 'Z' => (true, false, false, true, false),
            'S' | 'W' | '0' => (false, true, false, true, false),
            'T' | 'X' | '1' => (true, true, false, true, false),
            '2' => (false, false, true, true, false),
            '3' => (true, false, true, true, false),
            '4' => (false, true, true, true, false),
            '5' => (true, true, true, true, false),
            '6' | '7' => (false, false, false, false, true),
            '8' | '9' => (false, false, false, true, true),
            '_' => {
                let c1 = self.get_inc();
                match c1 {
                    'A' | 'B' => (false, false, true, false, true),
                    'C' | 'D' => (false, false, true, true, true),
                    _ => return err(format!("CV code not expected: _{c1}")),
                }
            }
            DONE => (false, false, false, false, false),
            _ => return err(format!("CV code not expected: {code}")),
        };
        cv.is_const |= c;
        cv.is_volatile |= v;
        cv.is_based |= b;
        cv.is_member |= m;
        cv.is_function |= f;
        if cv.is_member {
            cv.qual = Some(self.qualified_name()?);
            if cv.is_function {
                let t = self.cv_mod(CvMod { is_this_pointer_mod: true, ..CvMod::default() })?;
                cv.this_cv = Some(Rc::new(t));
            }
        }
        if cv.is_based {
            cv.based = Some(self.based()?);
        }
        Ok(())
    }

    /// `MDBasedAttribute.parseInternal`.
    fn based(&mut self) -> R<Based> {
        let c = self.get_inc();
        let name: Option<String> = if self.arch != 16 {
            match c {
                '0' => Some("void".into()),
                '2' => {
                    let qn = self.qualified_name()?;
                    let mut b = String::new();
                    render_qualified_name(&self.out(), &mut b, &qn);
                    Some(b)
                }
                '5' => return Ok(Based { name: None, ptr_based: true }),
                DONE => return err("Missing based value."),
                _ => Some(String::new()),
            }
        } else {
            match c {
                '0' => Some("void".into()),
                '1' => Some("__self".into()),
                '2' => Some("NYI:__near*".into()),
                '3' => Some("NYI:__far*".into()),
                '4' => Some("NYI:__huge*".into()),
                '5' => return Ok(Based { name: None, ptr_based: true }),
                '6' => Some("NYI:__segment".into()),
                '7' => {
                    let bn = self.basic_name()?;
                    let mut b = String::new();
                    render_basic(&self.out(), &mut b, &bn, None);
                    app(&mut b, "\")");
                    ins(&mut b, "__segmname(\"");
                    Some(b)
                }
                '8' => Some("NYI:<segment-address-of-variable>".into()),
                DONE => return err("Missing based value."),
                _ => Some(String::new()),
            }
        };
        Ok(Based { name, ptr_based: false })
    }

    fn render_fragment(&self, o: &Out, b: &mut String, name: &str) {
        render_fragment(o, b, name);
    }

    fn render_qualifier(&self, o: &Out, b: &mut String, q: &Qualifier) {
        render_qualifier(o, b, q);
    }
}

/// What `MDDataTypeParser` makes before the type's `parse()`.
enum Ctor {
    Done(DtKind, Sign),
    QualNamed,
    Complex(&'static str),
    Enum,
    W64,
    Mod(ModKind, bool, bool),
}

/// The type info `MDTypeInfoParser` made, before its `parse()`.
#[derive(Clone, Copy)]
enum Pend {
    Plain,
    Variable,
    Guard,
    VxTable,
    Fn { member: bool },
    Adjustor,
    Vtordisp,
    Vtordispex,
    VCall,
}

impl Pend {
    /// `instanceof MDFunctionInfo`
    fn is_function(self) -> bool {
        !matches!(self, Pend::Plain | Pend::Variable | Pend::Guard | Pend::VxTable)
    }
}

/// The access of a member function's code (`MDTypeInfoParser.parse`).
fn member_access(code: char) -> Access {
    match code {
        'A'..='H' => Access::Private,
        'I'..='P' => Access::Protected,
        _ => Access::Public,
    }
}

/// `MDReusableName.processSpecialName`.
fn special_reusable(name: &str) -> R<Option<String>> {
    let number = |s: &str| {
        if s.bytes().all(|b| b.is_ascii_digit()) {
            Ok(s.to_string())
        } else {
            err(format!("Illegal character in Number: {s}"))
        }
    };
    if let Some(n) = name.strip_prefix("$TSS") {
        return Ok(Some(format!("`thread safe static guard{{{}}}'", number(n)?)));
    }
    if name == "$S1" {
        return Ok(Some("`nonvisible static guard{1}'".into()));
    }
    if let Some(n) = name.strip_prefix("$RT") {
        return Ok(Some(format!("`reference temporary{{{}}}'", number(n)?)));
    }
    Ok(None)
}

/// `MDSpecialName.parseInternal`: the one-character operator codes.
fn operator_name(c: char) -> &'static str {
    match c {
        '2' => "operator new",
        '3' => "operator delete",
        '4' => "operator=",
        '5' => "operator>>",
        '6' => "operator<<",
        '7' => "operator!",
        '8' => "operator==",
        '9' => "operator!=",
        'A' => "operator[]",
        'C' => "operator->",
        'D' => "operator*",
        'E' => "operator++",
        'F' => "operator--",
        'G' => "operator-",
        'H' => "operator+",
        'I' => "operator&",
        'J' => "operator->*",
        'K' => "operator/",
        'L' => "operator%",
        'M' => "operator<",
        'N' => "operator<=",
        'O' => "operator>",
        'P' => "operator>=",
        'Q' => "operator,",
        'R' => "operator()",
        'S' => "operator~",
        'T' => "operator^",
        'U' => "operator|",
        'V' => "operator&&",
        'W' => "operator||",
        'X' => "operator*=",
        'Y' => "operator+=",
        'Z' => "operator-=",
        _ => "ERROR UNKNOWN OPERATOR TYPE",
    }
}

/// `MDSpecialName.parseInternal`: the `?_` codes with a fixed name.
fn underscore_name(c: char) -> &'static str {
    match c {
        '0' => "operator/=",
        '1' => "operator%=",
        '2' => "operator>>=",
        '3' => "operator<<=",
        '4' => "operator&=",
        '5' => "operator|=",
        '6' => "operator^=",
        '7' => "`vftable'",
        '8' => "`vbtable'",
        '9' => "`vcall'",
        'A' => "`typeof'",
        'B' => "`local static guard'",
        'D' => "`vbase destructor'",
        'E' => "`vector deleting destructor'",
        'F' => "`default constructor closure'",
        'G' => "`scalar deleting destructor'",
        'H' => "`vector constructor iterator'",
        'I' => "`vector destructor iterator'",
        'J' => "`vector vbase constructor iterator'",
        'K' => "`virtual displacement map'",
        'L' => "`eh vector constructor iterator'",
        'M' => "`eh vector destructor iterator'",
        'N' => "`eh vector vbase constructor iterator'",
        'O' => "`copy constructor closure'",
        'Q' => "",
        'S' => "`local vftable'",
        'T' => "`local vftable constructor closure'",
        'U' => "operator new[]",
        'V' => "operator delete[]",
        'W' => "`omni callsig'",
        'X' => "`placement delete closure'",
        'Y' => "`placement delete[] closure'",
        _ => "ERROR UNKNOWN OPERATOR TYPE",
    }
}

/// `MDSpecialName.parseInternal`: the `?__` codes with a fixed name.
fn double_underscore_name(c: char) -> &'static str {
    match c {
        'A' => "`managed vector constructor iterator'",
        'B' => "`managed vector destructor iterator'",
        'C' => "`eh vector copy constructor iterator'",
        'D' => "`eh vector vbase copy constructor iterator'",
        'G' => "`vector copy constructor iterator'",
        'H' => "`vector vbase copy constructor iterator'",
        'I' => "`managed vector copy constructor iterator'",
        'J' => "`local static thread guard'",
        _ => "ERROR UNKNOWN OPERATOR TYPE",
    }
}

/// Java's `new String(bytes, UTF_16)`: big-endian unless a byte order mark says otherwise.
fn decode_utf16_java(bytes: &[u8]) -> String {
    let (le, body) = match bytes {
        [0xfe, 0xff, rest @ ..] => (false, rest),
        [0xff, 0xfe, rest @ ..] => (true, rest),
        _ => (false, bytes),
    };
    let units = body.chunks(2).map(|c| match c {
        [a, b] if le => u16::from_le_bytes([*a, *b]),
        [a, b] => u16::from_be_bytes([*a, *b]),
        _ => 0xfffd,
    });
    char::decode_utf16(units).map(|c| c.unwrap_or('\u{FFFD}')).collect()
}

// ---------------------------------------------------------------------------------------------
// Printing: the insert/append methods

impl BasicName {
    fn is_ctor(&self) -> bool {
        match self {
            BasicName::Special(s) => s.is_ctor,
            BasicName::Template(t) => t.name.is_ctor(),
            _ => false,
        }
    }
    fn is_dtor(&self) -> bool {
        match self {
            BasicName::Special(s) => s.is_dtor,
            BasicName::Template(t) => t.name.is_dtor(),
            _ => false,
        }
    }
    fn is_type_cast(&self) -> bool {
        match self {
            BasicName::Special(s) => s.is_type_cast,
            BasicName::Template(t) => t.name.is_type_cast(),
            _ => false,
        }
    }
    fn rtti(&self) -> i32 {
        match self {
            BasicName::Special(s) => s.rtti,
            _ => -1,
        }
    }
    fn is_string(&self) -> bool {
        matches!(self, BasicName::Special(s) if s.is_string)
    }
    fn set_name(&mut self, n: String) {
        match self {
            BasicName::Special(s) => s.name = n,
            BasicName::Template(t) => t.name.set_name(n),
            _ => {}
        }
    }
    fn set_xtor_qual(&mut self, q: Option<Rc<Qualifier>>) {
        match self {
            BasicName::Special(s) => s.xtor_qual = q,
            BasicName::Template(t) => t.name.set_xtor_qual(q),
            _ => {}
        }
    }
    fn set_cast_type_string(&mut self, c: String) {
        match self {
            BasicName::Special(s) => s.cast_type_string = Some(c),
            BasicName::Template(t) => t.name.set_cast_type_string(c),
            _ => {}
        }
    }
    /// `MDBasicName.getName`.
    fn name(&self) -> String {
        match self {
            BasicName::Special(s) => s.name.clone(),
            BasicName::Template(t) => t.name.name(),
            BasicName::Reusable(r) => r.name(),
            BasicName::Embedded(_) => String::new(),
        }
    }
}

impl ReusableName {
    /// `MDReusableName.getName`.
    fn name(&self) -> String {
        if let Some(s) = &self.special {
            return s.clone();
        }
        if let Some(f) = &self.fragment {
            return f.clone();
        }
        self.template.as_ref().map_or_else(String::new, |t| t.name.name())
    }
}

fn render_fragment(o: &Out, b: &mut String, name: &str) {
    if o.opts.use_encoded_anonymous_namespace {
        ins(b, &standard_anon(o, name));
    } else {
        ins(b, name);
    }
}

fn render_reusable(o: &Out, b: &mut String, r: &ReusableName) {
    if let Some(s) = &r.special {
        ins(b, s);
    } else if let Some(f) = &r.fragment {
        render_fragment(o, b, f);
    } else if let Some(t) = &r.template {
        render_template(o, b, t);
    }
}

fn render_template(o: &Out, b: &mut String, t: &TemplateNa) {
    let mut ab = String::new();
    for (arg, &comma) in t.args.iter().zip(&t.comma) {
        if comma {
            app(&mut ab, ",");
        }
        let mut x = String::new();
        render_dt_as_arg(o, &mut x, arg);
        app(&mut ab, &x);
    }
    ins(b, ">");
    if ab.ends_with('>') {
        ins(b, " ");
    }
    ins(b, &ab);
    ins(b, "<");
    render_basic(o, b, &t.name, None);
}

fn render_qualification(o: &Out, b: &mut String, q: &Qualification) {
    let mut interface = false;
    let last = q.quals.len().saturating_sub(1);
    for (i, qual) in q.quals.iter().enumerate() {
        if interface {
            ins(b, "[");
        }
        interface = matches!(**qual, Qualifier::Interface(_));
        if interface {
            ins(b, "]");
        }
        render_qualifier(o, b, qual);
        if i != last {
            ins(b, "::");
        }
    }
    if interface {
        ins(b, "[");
    }
}

fn render_qualifier(o: &Out, b: &mut String, q: &Qualifier) {
    match q {
        Qualifier::Name(r) | Qualifier::Template(r) | Qualifier::Interface(r) => render_reusable(o, b, r),
        Qualifier::Anon(r) => {
            if o.opts.use_encoded_anonymous_namespace {
                ins(b, &standard_anon(o, &r.name()));
            } else {
                ins(b, "`anonymous namespace'");
            }
        }
        Qualifier::Nested(obj) => {
            ins(b, "'");
            ins(b, &cpp_to_string(o, obj));
            ins(b, "`");
        }
        Qualifier::Numbered(n) => ins(b, &format!("`{n}'")),
        Qualifier::Q(q) => {
            let mut x = String::new();
            render_qualification(o, &mut x, q);
            ins(&mut x, "[");
            app(&mut x, "]");
            ins(b, &x);
        }
    }
}

fn render_qualified_name(o: &Out, b: &mut String, qn: &QualifiedName) {
    render_reusable(o, b, &qn.name);
    if !qn.qual.quals.is_empty() {
        ins(b, "::");
        render_qualification(o, b, &qn.qual);
    }
}

fn qualified_name_to_string(o: &Out, qn: &QualifiedName) -> String {
    let mut b = String::new();
    render_qualified_name(o, &mut b, qn);
    clean(&mut b);
    b
}

fn render_special(o: &Out, b: &mut String, s: &SpecialName) {
    if s.is_ctor || s.is_dtor {
        match &s.xtor_qual {
            Some(q) => render_qualifier(o, b, q),
            None => ins(b, if s.is_ctor { "ctor" } else { "dtor" }),
        }
        if s.is_dtor {
            ins(b, "~");
        }
    } else {
        ins(b, &s.name);
    }
    if let (true, Some(c)) = (s.is_type_cast, &s.cast_type_string) {
        app(b, " ");
        app(b, c);
    }
}

/// `MDBasicName.insert`, with the name modifier of the object's type info.
fn render_basic(o: &Out, b: &mut String, n: &BasicName, modifier: Option<&TypeInfo>) {
    match n {
        BasicName::Reusable(r) => render_reusable(o, b, r),
        BasicName::Special(s) => render_special(o, b, s),
        BasicName::Embedded(obj) => render_cpp(o, b, obj),
        BasicName::Template(t) => render_template(o, b, t),
    }
    if let Some(ti) = modifier {
        b.push_str(&ti_modifier(o, ti));
    }
}

fn render_cpp(o: &Out, b: &mut String, obj: &ObjectCpp) {
    match &obj.body {
        CppBody::Hashed(h) => b.push_str(&format!("`{h}'")),
        CppBody::Normal { qn, ti } => {
            render_basic(o, b, &qn.basic, ti.as_deref());
            if !qn.qual.quals.is_empty() {
                ins(b, "::");
                render_qualification(o, b, &qn.qual);
            }
            if let Some(ti) = ti {
                render_ti(o, b, ti);
            }
        }
    }
}

fn cpp_to_string(o: &Out, obj: &ObjectCpp) -> String {
    let mut b = String::new();
    render_cpp(o, &mut b, obj);
    clean(&mut b);
    b
}

/// `MDTypeInfo.getModifier` and the overrides.
fn ti_modifier(o: &Out, ti: &TypeInfo) -> String {
    match &ti.kind {
        TiKind::Guard(n) => format!("{{{n}}}'"),
        TiKind::VxTable { quals, good_termination, .. } => {
            if !good_termination {
                return "{for ??}".into();
            }
            if quals.is_empty() {
                return String::new();
            }
            let mut m = String::new();
            app(&mut m, "{for `");
            for (i, q) in quals.iter().enumerate() {
                let mut x = String::new();
                render_qualification(o, &mut x, q);
                if i > 0 {
                    app(&mut m, "'s `");
                }
                app(&mut m, &x);
            }
            app(&mut m, "'}");
            m
        }
        TiKind::Function { extra, .. } => match extra {
            FnExtra::None => String::new(),
            FnExtra::Adjustor(a) => format!("`adjustor{{{a}}}' "),
            FnExtra::Vtordisp(a, b) => format!("`vtordisp{{{a},{b}}}' "),
            FnExtra::Vtordispex([a, b, c, d]) => format!("`vtordispex{{{a},{b},{c},{d}}}' "),
            FnExtra::VCall { index, this_far, call_far, vfptr_far, based } => {
                vcall_modifier(o, index, *this_far, *call_far, *vfptr_far, based.as_ref())
            }
        },
        TiKind::Plain | TiKind::Variable { .. } => String::new(),
    }
}

/// `MDVCall.getModifier`.
fn vcall_modifier(
    o: &Out,
    index: &EncNum,
    this_far: bool,
    call_far: bool,
    vfptr: Option<bool>,
    based: Option<&Based>,
) -> String {
    let model = |far: bool| if far { "__far " } else { "__near " };
    if o.arch != 16 {
        return if !this_far && !call_far && vfptr == Some(false) {
            format!("{{{index},{{flat}}}}' }}'")
        } else {
            String::new()
        };
    }
    let mut m = format!("{{{index},{{{}this, {}call, ", model(this_far), model(call_far));
    match vfptr {
        Some(far) => m += model(far),
        None => {
            let s = based.map_or_else(String::new, based_to_string);
            if !s.is_empty() {
                m += &s;
                m.push(' ');
            }
        }
    }
    m += "vfptr}}' }'";
    m
}

/// `MDTypeInfo.insert` and the overrides.
fn render_ti(o: &Out, b: &mut String, ti: &TypeInfo) {
    match &ti.kind {
        TiKind::VxTable { cv, .. } => {
            render_cv(o, b, cv);
            return;
        }
        TiKind::Variable { cv, dt } => {
            ins_spaced(b, " ");
            render_cv(o, b, cv);
            render_dt(o, b, dt);
        }
        TiKind::Function { ft, .. } => render_ft(o, b, ft),
        TiKind::Plain | TiKind::Guard(_) => {}
    }
    let mut m = String::new();
    match ti.storage {
        Storage::None => {}
        Storage::Static => ins(&mut m, "static "),
        Storage::Virtual => ins(&mut m, "virtual "),
    }
    match ti.access {
        Access::None => {}
        Access::Private => ins(&mut m, "private: "),
        Access::Protected => ins(&mut m, "protected: "),
        Access::Public => ins(&mut m, "public: "),
    }
    if ti.thunk {
        ins(&mut m, "[thunk]:");
    }
    if ti.extern_c {
        ins(&mut m, "extern \"C\" ");
    }
    ins_spaced(b, &m);
}

fn ti_to_string(o: &Out, ti: &TypeInfo) -> String {
    let mut b = String::new();
    render_ti(o, &mut b, ti);
    clean(&mut b);
    b
}

/// `MDBasedAttribute.insert`.
fn render_based(b: &mut String, based: &Based) {
    if based.ptr_based {
        b.clear();
        b.push('\0');
        return;
    }
    ins_spaced(b, ")");
    ins(b, based.name.as_deref().unwrap_or(""));
    ins(b, "__based(");
}

/// `MDBasedAttribute.append`.
fn append_based(b: &mut String, based: &Based) {
    if based.ptr_based {
        b.clear();
        b.push('\0');
        return;
    }
    app(b, " ");
    app(b, "__based(");
    app(b, based.name.as_deref().unwrap_or(""));
    app(b, ")");
}

fn based_to_string(based: &Based) -> String {
    let mut b = String::new();
    render_based(&mut b, based);
    clean(&mut b);
    b
}

/// `MDFunctionType.insert`.
fn render_ft(o: &Out, b: &mut String, ft: &FunctionType) {
    if b.chars().next().is_some_and(|c| !"*&( ".contains(c)) {
        ins(b, " ");
    }
    let mut cb = String::new();
    ins(&mut cb, &ft.convention);
    if let Some(based) = &ft.based {
        append_based(&mut cb, based);
    }
    clean(&mut cb);
    ins(b, &cb);
    if ft.from_modifier.get() {
        ins(b, "(");
        app(b, ")");
    }
    if let (true, Some(args)) = (ft.has_args, &ft.args) {
        app(b, "(");
        render_args(o, b, args);
        app(b, ")");
    }
    if let Some(cv) = &ft.this_cv {
        let mut x = String::new();
        render_cv(o, &mut x, cv);
        app(b, &x);
    }
    if let (true, Some(r), false) = (ft.has_return, &ft.ret, ft.is_type_cast) {
        render_dt(o, b, r);
    }
    if let Some(t) = &ft.throw {
        let mut x = String::new();
        if t.no_except {
            app(&mut x, "noexcept");
        } else if t.has_throw {
            app(&mut x, "throw(");
            render_args(o, &mut x, &t.args);
            app(&mut x, ")");
        }
        clean(&mut x);
        if !x.is_empty() {
            app(b, &format!(" {x}"));
        }
    }
}

/// `MDArgumentsList.insert`.
fn render_args(o: &Out, b: &mut String, args: &[Dt]) {
    for (i, arg) in args.iter().enumerate() {
        if i > 0 {
            app(b, ",");
        }
        let mut x = String::new();
        render_dt_as_arg(o, &mut x, arg);
        app(b, java_trim(&x));
    }
}

/// `MDCVMod.insert`.
fn render_cv(o: &Out, b: &mut String, cv: &CvMod) {
    if cv.is_cli_array {
        return;
    }
    let mut m = String::new();
    if cv.is_rref {
        ins(&mut m, "&& ");
    }
    if cv.is_lref {
        ins(&mut m, "& ");
    }
    // insertPrefixEI
    let mut ei = String::new();
    for p in cv.unaligned_restrict_ptr64.iter().rev() {
        match p {
            CvPrefix::Ptr64 => ins_spaced(&mut ei, " __ptr64"),
            CvPrefix::Restrict => ins_spaced(&mut ei, " __restrict"),
            CvPrefix::Unaligned => {}
        }
    }
    ins(&mut m, &ei);
    ins_spaced(&mut m, cv_annotation(cv));
    for p in &cv.unaligned_restrict_ptr64 {
        if *p == CvPrefix::Unaligned {
            ins_spaced(&mut m, "__unaligned ");
        }
    }
    render_cv_cv(o, &mut m, cv);
    ins_spaced(b, &m);
}

/// `MDCVMod.insertCV`.
fn render_cv_cv(o: &Out, b: &mut String, cv: &CvMod) {
    if let (true, Some(q)) = (cv.is_member, &cv.qual) {
        if cv.mod_type != ModType::Plain {
            let mut x = String::new();
            render_qualified_name(o, &mut x, q);
            if !x.is_empty() {
                x.push_str("::");
                ins(b, &x);
            }
        }
    }
    if cv.is_based {
        if let Some(based) = &cv.based {
            render_based(b, based);
            if based.ptr_based {
                return;
            }
        }
    }
    if cv.is_volatile {
        ins_spaced(b, "volatile ");
    }
    if cv.is_const {
        ins_spaced(b, "const ");
    }
}

/// `MDCVMod.getModTypeAnnotation`.
fn cv_annotation(cv: &CvMod) -> &'static str {
    match cv.mod_type {
        ModType::Pointer if cv.is_cli_property => "%",
        ModType::Pointer if cv.is_gc => "^",
        ModType::Pointer => "*",
        ModType::Reference | ModType::RightReference if cv.is_cli_property || cv.is_gc => "%",
        ModType::Reference => "&",
        ModType::RightReference => "&&",
        ModType::Array => "",
        _ if cv.is_cli_property => "%",
        _ => "",
    }
}

/// `MDCVMod.insertManagedPropertiesPrefix` / `Suffix`.
fn managed_prefix(b: &mut String, cv: &CvMod) {
    if cv.is_cli_array {
        ins(b, "cli::array<");
    } else if cv.is_pin_pointer {
        ins(b, "cli::pin_ptr<");
    }
}

fn managed_suffix(b: &mut String, cv: &CvMod) {
    if cv.is_cli_array {
        app(b, " ");
        if cv.array_rank > 1 {
            app(b, ",");
            app(b, &(cv.array_rank as u32).to_string());
        }
        app(b, ">^");
    } else if cv.is_pin_pointer {
        app(b, ">");
    }
}

fn render_ref(o: &Out, b: &mut String, r: &TypeRef, as_arg: bool) {
    match r {
        TypeRef::Func(ft) => render_ft(o, b, ft),
        TypeRef::Data(dt) if as_arg => render_dt_as_arg(o, b, dt),
        TypeRef::Data(dt) => render_dt(o, b, dt),
    }
}

/// `MDModifierType.insertInternal`.
fn render_modifier(o: &Out, b: &mut String, m: &Modifier, as_arg: bool) {
    let cv = &m.cv;
    if !cv.is_cli_array {
        if m.is_volatile {
            ins_spaced(b, "volatile");
        }
        if m.is_const {
            ins_spaced(b, "const");
        }
    }
    if let TypeRef::Func(ft) = &m.r {
        if matches!(cv.mod_type, ModType::Pointer | ModType::Reference | ModType::Array) || !b.is_empty() {
            ft.from_modifier.set(true);
        }
    }
    // insertCVMod
    match m.kind {
        ModKind::ArrayBasic => {}
        ModKind::Pointer | ModKind::Reference | ModKind::RightRef if cv.is_function => {
            let mut x = String::new();
            render_cv(o, &mut x, cv);
            ins(b, &x);
            clean(b);
        }
        _ => {
            render_cv(o, b, cv);
            clean(b);
        }
    }
    let is_array_ref = matches!(&m.r, TypeRef::Data(d) if matches!(d.kind, DtKind::ArrayRef { .. }));
    if is_array_ref {
        render_referred(o, b, m, as_arg);
    } else if cv.is_pin_pointer {
        let mut x = String::new();
        render_referred(o, &mut x, m, as_arg);
        app(&mut x, " ");
        let void = matches!(&m.r, TypeRef::Data(d) if matches!(d.kind, DtKind::Void { .. }));
        if !(cv.mod_type == ModType::Question || (cv.mod_type == ModType::Pointer && void)) {
            managed_prefix(&mut x, cv);
            managed_suffix(&mut x, cv);
        }
        ins(b, &x);
    } else if cv.is_cli_array {
        let mut x = String::new();
        render_referred(o, &mut x, m, as_arg);
        if !matches!(&m.r, TypeRef::Data(d) if matches!(d.kind, DtKind::Void { .. })) {
            managed_prefix(&mut x, cv);
        }
        managed_suffix(&mut x, cv);
        ins_spaced(b, &x);
    } else {
        render_referred(o, b, m, as_arg);
    }
}

/// `insertReferredType`, with `MDArrayBasicType`'s override.
fn render_referred(o: &Out, b: &mut String, m: &Modifier, as_arg: bool) {
    if m.kind != ModKind::ArrayBasic {
        render_ref(o, b, &m.r, as_arg);
        return;
    }
    let mut array = String::from("[]");
    let mut dt = m.r.clone();
    while let TypeRef::Data(d) = &dt {
        match &d.kind {
            DtKind::ArrayRef { array: s, r } => {
                array += s;
                dt = TypeRef::Data(r.clone());
            }
            DtKind::Modifier(pm)
                if pm.kind == ModKind::Pointer && !(pm.cv.is_function && pm.cv.mod_type == ModType::Pointer) =>
            {
                dt = pm.r.clone();
            }
            _ => break,
        }
    }
    if let (TypeRef::Func(ft), false) = (&m.r, b.is_empty()) {
        ft.from_modifier.set(true);
    }
    render_ref(o, b, &dt, false);
    clean(b);
    app(b, &array);
}

/// `MDDataType.insert` and the overrides.
fn render_dt(o: &Out, b: &mut String, dt: &DataType) {
    match &dt.kind {
        DtKind::Modifier(m) => render_modifier(o, b, m, false),
        DtKind::Complex { tag, qn } => {
            if b.chars().next().is_some_and(|c| c != ' ') {
                ins(b, " ");
            }
            render_qualified_name(o, b, qn);
            render_named(b, tag, dt.sign);
        }
        DtKind::W64(inner) => {
            render_dt(o, b, inner);
            render_named(b, "__w64", dt.sign);
        }
        DtKind::ArrayRef { array, r } => {
            if !b.is_empty() {
                ins(b, "(");
                app(b, ")");
            }
            app(b, array);
            render_dt(o, b, r);
        }
        DtKind::NullName => o.fault("NullPointerException: MDDataType type name is null"),
        DtKind::Basic { name, .. } => render_named(b, name, dt.sign),
        DtKind::Named(n) => render_named(b, n, dt.sign),
        DtKind::Void { printable } => render_named(b, if *printable { "void" } else { "" }, dt.sign),
        DtKind::VarArgs => render_named(b, "...", dt.sign),
        DtKind::QualNamed(qn) => render_named(b, &qualified_name_to_string(o, qn), dt.sign),
        DtKind::EmptyParam => render_named(b, "_EMPTY_PARAMETER_TYPE_", dt.sign),
        DtKind::EndParam => render_named(b, "_END_PARAMETER_TYPE_", dt.sign),
    }
}

/// `MDDataType.insert` for a type name.
fn render_named(b: &mut String, name: &str, sign: Sign) {
    if !name.is_empty() {
        if !b.is_empty() {
            ins(b, " ");
        }
        ins(b, name);
    }
    match sign {
        Sign::Specified => ins_spaced(b, "signed "),
        Sign::Unsigned => ins_spaced(b, "unsigned "),
        Sign::Signed => {}
    }
}

/// `MDDataType.insertAsArg` and the overrides.
fn render_dt_as_arg(o: &Out, b: &mut String, dt: &DataType) {
    match &dt.kind {
        DtKind::Modifier(m) => render_modifier(o, b, m, true),
        DtKind::Complex { tag, qn } => {
            if b.chars().next().is_some_and(|c| c != ' ') {
                ins(b, " ");
            }
            render_qualified_name(o, b, qn);
            if o.opts.apply_udt_argument_type_tag {
                render_named(b, tag, dt.sign);
            }
        }
        _ => render_dt(o, b, dt),
    }
}

fn dt_to_string(o: &Out, dt: &DataType) -> String {
    let mut b = String::new();
    render_dt(o, &mut b, dt);
    clean(&mut b);
    b
}

fn render_reserved(o: &Out, b: &mut String, r: &Reserved) {
    let s = |x: &ObjectCpp| cpp_to_string(o, x);
    match r {
        Reserved::ThrowInfo(d, dt) => app(b, &format!("[ThrowInfo,{d}]{{{}}}", dt_to_string(o, dt))),
        Reserved::CatchableTypeArray(d, dt) => app(b, &format!("[CatchableTypeArray,{d}]{{{}}}", dt_to_string(o, dt))),
        Reserved::CatchableType(d, objs) => {
            app(b, &format!("[CatchableType,{d}]"));
            for x in objs {
                app(b, &format!("{{{}}}", s(x)));
            }
        }
        Reserved::Catch(d, x) => app(b, &format!("[Catch,{d}]{{{}}}", s(x))),
        Reserved::CatchSym(d, x) => app(b, &format!("[CatchSym,{d}]{{{}}}", s(x))),
        Reserved::UnwindFunclet(d, x) => app(b, &format!("[UnwindFunclet,{d}]{{{}}}", s(x))),
        Reserved::TryBlockTable(x) => app(b, &format!("[TryblockTable]{{{}}}", s(x))),
        Reserved::UnwindTable(x) => app(b, &format!("[UnwindTable]{{{}}}", s(x))),
        Reserved::EhHandler(x) => app(b, &format!("[EHHandler]{{{}}}", s(x))),
        Reserved::Bracket(frag, x) => {
            render_cpp(o, b, x);
            let mut p = String::new();
            ins(&mut p, "]");
            render_fragment(o, &mut p, frag);
            ins(&mut p, "[");
            ins_spaced(b, &p);
        }
        Reserved::Unknown(rest) => b.push_str(rest),
    }
}

fn render_item(o: &Out, b: &mut String, item: &Item) {
    match item {
        Item::DataType(dt) => render_dt(o, b, dt),
        Item::Cpp(x) => render_cpp(o, b, x),
        Item::CodeView(x) => {
            render_cpp(o, b, x);
            ins_spaced(b, "CV:");
        }
        Item::Template(t) => render_template(o, b, t),
        Item::C(c) => {
            let conv = c.convention.filter(|i| (1..=3).contains(i));
            if let Some(i) = conv {
                b.push_str(C_CONVENTIONS[i]);
                b.push(' ');
            }
            let mut n = String::new();
            render_fragment(o, &mut n, &c.name);
            b.push_str(&n);
            if conv.is_some() {
                b.push(',');
                b.push_str(&c.param_bytes.to_string());
            }
        }
        Item::Reserved(r) => render_reserved(o, b, r),
    }
}

// ---------------------------------------------------------------------------------------------
// The API

/// A demangled symbol: `MDMang.demangle()`'s item.
#[derive(Debug)]
pub struct Demangled {
    item: Item,
    arch: u32,
    fault: RefCell<Option<String>>,
}

impl Demangled {
    /// `MDParsableItem.toString()` with the given output options; fails where Java would throw
    /// a runtime exception while printing.
    pub fn to_string_with(&self, opts: OutputOptions) -> Result<String, Error> {
        let o = Out { opts, arch: self.arch, fault: &self.fault };
        let mut b = String::new();
        render_item(&o, &mut b, &self.item);
        clean(&mut b);
        match self.fault.borrow().as_ref() {
            Some(f) => Err(Error(f.clone())),
            None => Ok(b),
        }
    }

    /// `MicrosoftDemangler`'s `originalDemangled`: `item.toString()` with `MDMang`'s default
    /// output options.
    pub fn original(&self) -> Result<String, Error> {
        self.to_string_with(OutputOptions::default())
    }

    /// The item is an `MDDataType`.
    pub fn is_data_type(&self) -> bool {
        matches!(self.item, Item::DataType(_))
    }

    /// `MDObjectC.getCallingConvention` of a C symbol (`None` for any other item).
    pub fn c_calling_convention(&self) -> Option<&'static str> {
        match &self.item {
            Item::C(c) => c.convention.map(|i| C_CONVENTIONS[i]),
            _ => None,
        }
    }

    /// The item is an `MDObjectC` (a C name, possibly with a calling convention).
    pub fn is_c(&self) -> bool {
        matches!(self.item, Item::C(_))
    }
}

/// `MDMang.demangle()` (with `MDMangGhidra`'s known-pattern test when asked).
pub fn demangle(mangled: &str, cfg: Config) -> Result<Option<Demangled>, Error> {
    if mangled.trim().is_empty() {
        return err("MDMang: Mangled string is null or blank.");
    }
    if cfg.only_known_patterns {
        let c = mangled.chars().next().unwrap_or(' ');
        let known = mangled.starts_with(['?', '.', '_']) || c < 'a' || c.is_ascii_lowercase() || c.is_ascii_uppercase();
        if !known {
            return Ok(None);
        }
    }
    // Java iterates UTF-16 units (a character past U+FFFF is two), this port `char`s
    if mangled.chars().any(|c| c > '\u{FFFF}') {
        return err("not ported: a mangled name with a character past U+FFFF (Java reads UTF-16 units)");
    }
    let mut p = Parser {
        s: mangled.chars().collect(),
        i: 0,
        ctx: Vec::new(),
        llvm: false,
        arch: cfg.arch,
        is_function: cfg.is_function,
        fault: RefCell::new(None),
        depth: 0,
    };
    let item = p.determine_item();
    if let Some(f) = p.fault.borrow().as_ref() {
        return Err(Error(f.clone()));
    }
    let item = item?;
    let n = p.remaining();
    if cfg.error_on_remaining && n > 0 {
        return err(format!("MDMang: characters remain after demangling: {n}."));
    }
    Ok(Some(Demangled { item, arch: cfg.arch, fault: p.fault }))
}

// ---------------------------------------------------------------------------------------------
// The Ghidra side: MicrosoftDemangler and the name parts of MicrosoftDemanglerUtil

/// `MicrosoftDemanglerOptions`' output options for the conversion
/// (`DEFAULT_MSD_USE_ANON_NS`, `DEFAULT_MSD_APPLY_UDT_TAG`).
pub const GHIDRA_OUTPUT: OutputOptions =
    OutputOptions { use_encoded_anonymous_namespace: true, apply_udt_argument_type_tag: false };

/// Which `DemangledObject` subclass `MicrosoftDemanglerUtil.processItem` makes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Function,
    Variable,
    Unknown,
    String,
}

/// A namespace node (`DemangledNamespaceNode` / `DemangledType`): its safe name and its
/// demangled name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NsNode {
    pub name: String,
    pub demangled: String,
}

/// The parts of a `DemangledObject` ported: names, namespace and calling convention. The data
/// types, parameters and the rest of the signature are not.
#[derive(Debug, Clone)]
pub struct GhidraDemangled {
    pub kind: Kind,
    /// `getOriginalDemangled()`: the plate comment the Demangler analyzer writes
    pub original: String,
    /// `getName()`: the safe name (`None`: Java's `null`, a `DemangledUnknown` of `$$F`)
    pub name: Option<String>,
    /// `getDemangledName()`
    pub demangled_name: Option<String>,
    /// `getNamespace()`, innermost first
    pub namespace: Vec<NsNode>,
    /// `DemangledFunction.getCallingConvention()`
    pub calling_convention: Option<String>,
}

impl GhidraDemangled {
    /// `Demangled.getNamespaceString()` of the namespace (outermost first, demangled names).
    pub fn namespace_string(&self) -> Option<String> {
        let ns: Vec<&str> = self.namespace.iter().rev().map(|n| n.demangled.as_str()).collect();
        (!ns.is_empty()).then(|| ns.join("::"))
    }

    /// The symbol's `getName(true)` once the Demangler analyzer applied it: the namespaces' safe
    /// names (`createNamespace`) and the safe name.
    pub fn qualified_name(&self) -> Option<String> {
        let mut parts: Vec<&str> = self.namespace.iter().rev().map(|n| n.name.as_str()).collect();
        parts.push(self.name.as_deref()?);
        Some(parts.join("::"))
    }
}

/// `DemanglerUtil.stripSuperfluousSignatureSpaces`.
pub(crate) fn strip_superfluous_spaces(s: &str) -> String {
    let mut a = String::new();
    let cs: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < cs.len() {
        if cs[i] == ' ' && cs.get(i + 1).is_some_and(|c| "*&)".contains(*c)) {
            i += 1;
            continue;
        }
        a.push(cs[i]);
        i += 1;
    }
    let mut b = String::new();
    let mut it = a.chars().peekable();
    while let Some(c) = it.next() {
        b.push(c);
        if (c == '(' || c == ',') && it.peek() == Some(&' ') {
            it.next();
        }
    }
    b
}

/// `DemangledObject.setName`'s safe name.
pub(crate) fn safe_name(name: &str) -> String {
    java_trim(&strip_superfluous_spaces(name)).replace(' ', "_")
}

/// The context `MicrosoftDemangler` reads from its `MicrosoftMangledContext`.
#[derive(Clone, Copy, Debug)]
pub struct Context {
    /// the default address space's size; 0 without a program (`DemanglerUtil.demangle(program,
    /// name)`, which Function ID uses)
    pub arch: u32,
    /// `MsCInterpretation.FUNCTION_IF_EXISTS`: a function is at the symbol's address
    pub is_function: bool,
}

/// `MicrosoftDemangler.demangle` with `MicrosoftDemanglerOptions`' defaults (error on remaining
/// characters, only known patterns): `Ok(None)` where Java returns `null` or throws a
/// `DemangledException`; `Err` for an `MDException` or a Java runtime exception, and for a case
/// this port does not convert.
pub fn microsoft_demangle(mangled: &str, ctx: Context) -> Result<Option<GhidraDemangled>, Error> {
    let cfg =
        Config { arch: ctx.arch, is_function: ctx.is_function, error_on_remaining: true, only_known_patterns: true };
    let Some(d) = demangle(mangled, cfg)? else { return Ok(None) };
    let original = d.original()?;
    let o = Out { opts: GHIDRA_OUTPUT, arch: d.arch, fault: &d.fault };
    let r = convert_item(&o, &d.item, original)?;
    if let Some(f) = d.fault.borrow().as_ref() {
        return Err(Error(f.clone()));
    }
    Ok(r)
}

/// `MicrosoftDemanglerUtil.processItem`.
fn convert_item(o: &Out, item: &Item, original: String) -> R<Option<GhidraDemangled>> {
    let unknown = |name: Option<String>| GhidraDemangled {
        kind: Kind::Unknown,
        demangled_name: name.clone(),
        name: name.as_deref().map(safe_name),
        original: original.clone(),
        namespace: Vec::new(),
        calling_convention: None,
    };
    Ok(match item {
        Item::Reserved(Reserved::Unknown(_)) => None,
        Item::Reserved(Reserved::Bracket(_, obj)) | Item::CodeView(obj) => match convert_cpp(o, obj, &original)? {
            Some(r) => Some(r),
            None => return err("NullPointerException: setSpecialPrefix on a null object"),
        },
        Item::Reserved(r) => {
            let mut b = String::new();
            render_reserved(o, &mut b, r);
            clean(&mut b);
            Some(unknown(Some(b)))
        }
        Item::Cpp(obj) => convert_cpp(o, obj, &original)?,
        Item::C(c) => c.convention.map(|i| {
            let name = c.name.clone();
            GhidraDemangled {
                kind: Kind::Function,
                original: original.clone(),
                name: Some(safe_name(&name)),
                demangled_name: Some(name),
                namespace: Vec::new(),
                calling_convention: Some(C_CONVENTIONS[i].to_string()),
            }
        }),
        // a DemangledException: a data type, not an object
        Item::DataType(_) => None,
        Item::Template(t) => {
            let mut b = String::new();
            render_template(o, &mut b, t);
            clean(&mut b);
            Some(GhidraDemangled {
                kind: Kind::Variable,
                original: original.clone(),
                name: Some(safe_name(&b)),
                demangled_name: Some(b),
                namespace: Vec::new(),
                calling_convention: None,
            })
        }
    })
}

/// `MicrosoftDemanglerUtil.processNamespace` / `getDemangled`: the qualifiers, innermost first.
fn convert_namespace(o: &Out, q: &Qualification) -> Vec<NsNode> {
    q.quals
        .iter()
        .map(|qual| {
            let mut b = String::new();
            render_qualifier(o, &mut b, qual);
            clean(&mut b);
            let demangled = match &**qual {
                Qualifier::Numbered(n) => format!("__l{n}"),
                _ => b,
            };
            NsNode { name: strip_superfluous_spaces(&demangled).replace(' ', "_"), demangled }
        })
        .collect()
}

/// `MicrosoftDemanglerUtil.processObjectCPP` (names, namespace, calling convention).
fn convert_cpp(o: &Out, obj: &ObjectCpp, original: &str) -> R<Option<GhidraDemangled>> {
    let (name, ns, ti) = match &obj.body {
        CppBody::Hashed(h) => (format!("`{h}'"), Vec::new(), None),
        CppBody::Normal { qn, ti } => {
            let mut b = String::new();
            render_basic(o, &mut b, &qn.basic, ti.as_deref());
            clean(&mut b);
            (b, convert_namespace(o, &qn.qual), ti.as_deref())
        }
    };
    let string = matches!(&obj.body, CppBody::Normal { qn, .. } if qn.basic.is_string());
    let mut r = GhidraDemangled {
        kind: Kind::Variable,
        original: original.to_string(),
        name: Some(safe_name(&name)),
        demangled_name: Some(name.clone()),
        namespace: ns,
        calling_convention: None,
    };
    let Some(ti) = ti else {
        if string {
            // DemangledString: MDString.getName()
            r.kind = Kind::String;
            r.name = Some("`string'".into());
            r.demangled_name = Some("`string'".into());
            r.namespace.clear();
            return Ok(Some(r));
        }
        return Ok((!name.is_empty()).then_some(r));
    };
    match &ti.kind {
        TiKind::Variable { dt, .. } => {
            if is_nullptr(dt) {
                r.name = Some(String::new());
                r.demangled_name = Some(String::new());
                r.namespace.clear();
            } else if matches!(dt.kind, DtKind::Modifier(_)) && refers_to_nullptr(dt) {
                return err("not ported: MicrosoftDemanglerUtil.processDataType of a modifier of std::nullptr_t");
            }
        }
        TiKind::Function { ft, .. } => {
            if ti_special_code_f(ti) {
                return Ok(Some(GhidraDemangled {
                    kind: Kind::Unknown,
                    name: None,
                    demangled_name: None,
                    namespace: Vec::new(),
                    ..r
                }));
            }
            r.kind = Kind::Function;
            let member = !ti.non_member;
            let conv = if ft.convention == "__cdecl" && member && ti.storage != Storage::Static {
                "__thiscall".to_string()
            } else {
                ft.convention.clone()
            };
            r.calling_convention = Some(conv);
        }
        _ => {}
    }
    Ok(Some(r))
}

/// `getSpecialHandlingCode() == 'F'`.
fn ti_special_code_f(ti: &TypeInfo) -> bool {
    ti.special == Some('F')
}

fn is_nullptr(dt: &DataType) -> bool {
    matches!(dt.kind, DtKind::Basic { name: "std::nullptr_t", .. })
}

fn refers_to_nullptr(dt: &DataType) -> bool {
    match &dt.kind {
        DtKind::Modifier(m) => matches!(&m.r, TypeRef::Data(d) if refers_to_nullptr(d)),
        _ => is_nullptr(dt),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn md(s: &str) -> String {
        let cfg = Config { error_on_remaining: true, ..Config::default() };
        demangle(s, cfg).ok().flatten().and_then(|d| d.original().ok()).unwrap_or_default()
    }

    #[test]
    fn a_few_names() {
        assert_eq!(md("?Swap@GMatrix2D@@QAEXPAV1@@Z"), "public: void __thiscall GMatrix2D::Swap(class GMatrix2D *)");
        assert_eq!(md("??_7name0@name1@@6B@"), "const name1::name0::`vftable'");
        assert_eq!(md("?var@@YMXXZ"), "void __clrcall var(void)");
        assert_eq!(hex_to_dec(&[0xf; 20]), "1208925819614629174706175");
    }

    /// Java overflows its stack on this (a caught `StackOverflowError`); the port fails the demangle.
    #[test]
    fn deep_nesting_fails() {
        let deep = format!("?x@@3PAP{}HA", "AP".repeat(20000));
        let ctx = Context { arch: 32, is_function: false };
        let e = microsoft_demangle(&deep, ctx).err();
        assert!(e.is_some_and(|e| !e.is_not_ported() && e.0.contains("nested deeper")));
        // just inside the limit (the object, the pointers, char): parsed and printed without overflowing a test thread's stack
        let ok = md(&format!("?x@@3{}DA", "PA".repeat(MAX_DEPTH - 2)));
        assert_eq!(ok, format!("char {}x", "* ".repeat(MAX_DEPTH - 2)));
        assert_eq!(md(&format!("?x@@3{}DA", "PA".repeat(MAX_DEPTH - 1))), "");
    }

    #[test]
    fn non_bmp_not_ported() {
        let e = demangle("?x\u{1F600}@@3HA", Config::default()).err();
        assert!(e.is_some_and(|e| e.is_not_ported()));
    }
}
