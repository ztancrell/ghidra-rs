//! Ghidra's GNU demangler, native half: libiberty's Itanium C++ ABI demangler (`cp-demangle.c`)
//! as Ghidra ships it, built into `demangler_gnu_v2_41` (`GPL/DemanglerGnu/src/demangler_gnu_v2_41`,
//! binutils 2.41), driven the way that program's `cxxfilt.c` drives it: one line in, one line
//! out, `cplus_demangle` with `DMGL_PARAMS | DMGL_ANSI | DMGL_VERBOSE` in the auto style (the
//! options Ghidra's `GnuDemanglerNativeProcess` starts it with: none).
//!
//! The parse builds components in a fixed array (`2 * strlen` of them, `strlen` substitutions),
//! mutated in place as the C does; the printer keeps the C's modifier and template lists as
//! indices into vectors, so a node is never freed while a list may name it. The output equals
//! the C's byte for byte: the 256-byte flush buffer of `d_print_info` only matters to the
//! `", "` that an empty argument list takes back, and that case is the same with one buffer.
//! `di->expansion` (only an allocation estimate) is not kept. Java (`DMGL_JAVA`), the return
//! postfix options and `DMGL_TYPES` are never set by `cxxfilt` without options, so they are not
//! ported. A Rust symbol (tried before C++ in the auto style, `rust-demangle.c`) fails as "not
//! ported". Where the C would read through a null pointer (a component array exhausted under a
//! builtin type) the demangle fails.

use crate::mdmang::Error;

/// `DEMANGLE_RECURSION_LIMIT`.
const RECURSION_LIMIT: u32 = 2048;
/// `MAX_RECURSION_COUNT` of the printer.
const MAX_RECURSION_COUNT: i32 = 1024;
/// The stand-in for Java's 3 s timeout on the native demangler (GnuDemanglerOptions.java:51,
/// GnuDemanglerNativeProcess.java:152-162): a name whose text passes this many bytes fails as
/// "not demangled: limit" (a wall-clock bound would make the output depend on the machine).
const OUT_LIMIT: usize = 1 << 20;
/// The stack of the thread `native_demangle` and `gnu_demangle` run on: the parse and the
/// printer recurse as deep as the C (see rust/README.md, "The GNU demangler").
const STACK: usize = 256 << 20;

type Id = usize;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum T {
    Name,
    QualName,
    LocalName,
    TypedName,
    Template,
    TemplateParam,
    FunctionParam,
    Ctor,
    Dtor,
    Vtable,
    Vtt,
    ConstructionVtable,
    Typeinfo,
    TypeinfoName,
    TypeinfoFn,
    Thunk,
    VirtualThunk,
    CovariantThunk,
    JavaClass,
    Guard,
    TlsInit,
    TlsWrapper,
    Reftemp,
    HiddenAlias,
    SubStd,
    Restrict,
    Volatile,
    Const,
    RestrictThis,
    VolatileThis,
    ConstThis,
    ReferenceThis,
    RvalueReferenceThis,
    VendorTypeQual,
    Pointer,
    Reference,
    RvalueReference,
    Complex,
    Imaginary,
    BuiltinType,
    VendorType,
    FunctionType,
    ArrayType,
    PtrmemType,
    VectorType,
    Arglist,
    TemplateArglist,
    TparmObj,
    InitializerList,
    Operator,
    ExtendedOperator,
    Cast,
    Conversion,
    Nullary,
    Unary,
    Binary,
    BinaryArgs,
    Trinary,
    TrinaryArg1,
    TrinaryArg2,
    Literal,
    LiteralNeg,
    VendorExpr,
    JavaResource,
    CompoundName,
    Character,
    Number,
    Decltype,
    GlobalConstructors,
    GlobalDestructors,
    Lambda,
    DefaultArg,
    UnnamedType,
    TransactionClone,
    NontransactionClone,
    PackExpansion,
    TaggedName,
    TransactionSafe,
    Clone,
    Noexcept,
    ThrowSpec,
    StructuredBinding,
    ModuleName,
    ModulePartition,
    ModuleEntity,
    ModuleInit,
    TemplateHead,
    TemplateTypeParm,
    TemplateNonTypeParm,
    TemplateTemplateParm,
    TemplatePackParm,
    ExtendedBuiltinType,
}

/// `FNQUAL_COMPONENT_CASE`.
fn is_fnqual(t: T) -> bool {
    matches!(
        t,
        T::RestrictThis
            | T::VolatileThis
            | T::ConstThis
            | T::ReferenceThis
            | T::RvalueReferenceThis
            | T::TransactionSafe
            | T::Noexcept
            | T::ThrowSpec
    )
}

/// `demangle_operator_info`.
struct Op {
    code: &'static str,
    name: &'static str,
    args: i64,
}

const fn op(code: &'static str, name: &'static str, args: i64) -> Op {
    Op { code, name, args }
}

/// `cplus_demangle_operators` (sorted by code, binary-searched).
static OPERATORS: [Op; 74] = [
    op("aN", "&=", 2),
    op("aS", "=", 2),
    op("aa", "&&", 2),
    op("ad", "&", 1),
    op("an", "&", 2),
    op("at", "alignof ", 1),
    op("aw", "co_await ", 1),
    op("az", "alignof ", 1),
    op("cc", "const_cast", 2),
    op("cl", "()", 2),
    op("cm", ",", 2),
    op("co", "~", 1),
    op("dV", "/=", 2),
    op("dX", "[...]=", 3),
    op("da", "delete[] ", 1),
    op("dc", "dynamic_cast", 2),
    op("de", "*", 1),
    op("di", "=", 2),
    op("dl", "delete ", 1),
    op("ds", ".*", 2),
    op("dt", ".", 2),
    op("dv", "/", 2),
    op("dx", "]=", 2),
    op("eO", "^=", 2),
    op("eo", "^", 2),
    op("eq", "==", 2),
    op("fL", "...", 3),
    op("fR", "...", 3),
    op("fl", "...", 2),
    op("fr", "...", 2),
    op("ge", ">=", 2),
    op("gs", "::", 1),
    op("gt", ">", 2),
    op("ix", "[]", 2),
    op("lS", "<<=", 2),
    op("le", "<=", 2),
    op("li", "operator\"\" ", 1),
    op("ls", "<<", 2),
    op("lt", "<", 2),
    op("mI", "-=", 2),
    op("mL", "*=", 2),
    op("mi", "-", 2),
    op("ml", "*", 2),
    op("mm", "--", 1),
    op("na", "new[]", 3),
    op("ne", "!=", 2),
    op("ng", "-", 1),
    op("nt", "!", 1),
    op("nw", "new", 3),
    op("nx", "noexcept", 1),
    op("oR", "|=", 2),
    op("oo", "||", 2),
    op("or", "|", 2),
    op("pL", "+=", 2),
    op("pl", "+", 2),
    op("pm", "->*", 2),
    op("pp", "++", 1),
    op("ps", "+", 1),
    op("pt", "->", 2),
    op("qu", "?", 3),
    op("rM", "%=", 2),
    op("rS", ">>=", 2),
    op("rc", "reinterpret_cast", 2),
    op("rm", "%", 2),
    op("rs", ">>", 2),
    op("sP", "sizeof...", 1),
    op("sZ", "sizeof...", 1),
    op("sc", "static_cast", 2),
    op("ss", "<=>", 2),
    op("st", "sizeof ", 1),
    op("sz", "sizeof ", 1),
    op("tr", "throw", 0),
    op("tw", "throw ", 1),
    // the sentinel `{ NULL, NULL, 0, 0 }` is the binary search's `high`, never compared
    op("", "", 0),
];

/// `d_builtin_type_print`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Pr {
    Default,
    Int,
    Unsigned,
    Long,
    UnsignedLong,
    LongLong,
    UnsignedLongLong,
    Bool,
    Float,
    Void,
}

struct Builtin {
    name: &'static str,
    print: Pr,
}

const fn bt(name: &'static str, print: Pr) -> Builtin {
    Builtin { name, print }
}

/// `cplus_demangle_builtin_types` (the empty names are the C's `NULL` entries, never reached).
static BUILTINS: [Builtin; 36] = [
    bt("signed char", Pr::Default),
    bt("bool", Pr::Bool),
    bt("char", Pr::Default),
    bt("double", Pr::Float),
    bt("long double", Pr::Float),
    bt("float", Pr::Float),
    bt("__float128", Pr::Float),
    bt("unsigned char", Pr::Default),
    bt("int", Pr::Int),
    bt("unsigned int", Pr::Unsigned),
    bt("", Pr::Default),
    bt("long", Pr::Long),
    bt("unsigned long", Pr::UnsignedLong),
    bt("__int128", Pr::Default),
    bt("unsigned __int128", Pr::Default),
    bt("", Pr::Default),
    bt("", Pr::Default),
    bt("", Pr::Default),
    bt("short", Pr::Default),
    bt("unsigned short", Pr::Default),
    bt("", Pr::Default),
    bt("void", Pr::Void),
    bt("wchar_t", Pr::Default),
    bt("long long", Pr::LongLong),
    bt("unsigned long long", Pr::UnsignedLongLong),
    bt("...", Pr::Default),
    bt("decimal32", Pr::Default),
    bt("decimal64", Pr::Default),
    bt("decimal128", Pr::Default),
    bt("half", Pr::Float),
    bt("char8_t", Pr::Default),
    bt("char16_t", Pr::Default),
    bt("char32_t", Pr::Default),
    bt("decltype(nullptr)", Pr::Default),
    bt("_Float", Pr::Float),
    bt("std::bfloat16_t", Pr::Float),
];

/// `standard_subs`: code, full expansion (`DMGL_VERBOSE`), the name it sets as the last name.
static STANDARD_SUBS: [(u8, &str, Option<&str>); 7] = [
    (b't', "std", None),
    (b'a', "std::allocator", Some("allocator")),
    (b'b', "std::basic_string", Some("basic_string")),
    (b's', "std::basic_string<char, std::char_traits<char>, std::allocator<char> >", Some("basic_string")),
    (b'i', "std::basic_istream<char, std::char_traits<char> >", Some("basic_istream")),
    (b'o', "std::basic_ostream<char, std::char_traits<char> >", Some("basic_ostream")),
    (b'd', "std::basic_iostream<char, std::char_traits<char> >", Some("basic_iostream")),
];

/// A `demangle_component`. The union's pointer members share `left` / `right` where the C's
/// share them: `s_unary_num.sub` (a lambda, a default argument) is `left`; `s_ctor.name`,
/// `s_dtor.name` and `s_extended_operator.name` are `right`.
#[derive(Clone, Copy)]
struct Comp<'a> {
    t: T,
    left: Option<Id>,
    right: Option<Id>,
    /// `s_name` / `s_string`
    s: &'a [u8],
    /// `s_number`, `s_unary_num.num`, a ctor/dtor kind, `s_extended_operator.args`,
    /// `s_character`, `s_extended_builtin.arg`
    num: i64,
    op: Option<&'static Op>,
    bt: Option<&'static Builtin>,
    suffix: u8,
}

impl<'a> Comp<'a> {
    fn new(t: T) -> Self {
        Comp { t, left: None, right: None, s: b"", num: 0, op: None, bt: None, suffix: 0 }
    }
}

/// `d_info`.
struct D<'a> {
    s: &'a [u8],
    n: usize,
    comps: Vec<Comp<'a>>,
    next_comp: usize,
    num_comps: usize,
    subs: Vec<Id>,
    next_sub: usize,
    num_subs: usize,
    last_name: Option<Id>,
    is_expression: bool,
    is_conversion: bool,
    unresolved_name_state: i32,
    recursion_level: u32,
}

impl<'a> D<'a> {
    /// `cplus_demangle_init_info` (the unresolved-name state is kept by the caller).
    fn new(s: &'a [u8], unresolved_name_state: i32) -> Self {
        D {
            s,
            n: 0,
            comps: Vec::new(),
            next_comp: 0,
            num_comps: 2 * s.len(),
            subs: Vec::new(),
            next_sub: 0,
            num_subs: s.len(),
            last_name: None,
            is_expression: false,
            is_conversion: false,
            unresolved_name_state,
            recursion_level: 0,
        }
    }

    fn peek(&self) -> u8 {
        self.s.get(self.n).copied().unwrap_or(0)
    }
    fn peek_next(&self) -> u8 {
        self.s.get(self.n + 1).copied().unwrap_or(0)
    }
    fn at(&self, i: usize) -> u8 {
        self.s.get(i).copied().unwrap_or(0)
    }
    fn advance(&mut self, i: usize) {
        self.n += i;
    }
    fn check(&mut self, c: u8) -> bool {
        if self.peek() == c {
            self.n += 1;
            true
        } else {
            false
        }
    }
    fn next_char(&mut self) -> u8 {
        let c = self.peek();
        if c != 0 {
            self.n += 1;
        }
        c
    }
    fn t(&self, id: Id) -> T {
        self.comps[id].t
    }
    fn left(&self, id: Id) -> Option<Id> {
        self.comps[id].left
    }
    fn right(&self, id: Id) -> Option<Id> {
        self.comps[id].right
    }
    fn set_left(&mut self, id: Id, v: Option<Id>) {
        self.comps[id].left = v;
    }
    fn set_right(&mut self, id: Id, v: Option<Id>) {
        self.comps[id].right = v;
    }
    fn is_module(&self, id: Id) -> bool {
        matches!(self.t(id), T::ModuleName | T::ModulePartition)
    }

    /// `d_make_empty`: the next slot of the fixed array (a slot given back by `d_backtrack` is
    /// written again, as in the C).
    fn make_empty(&mut self, c: Comp<'a>) -> Option<Id> {
        if self.next_comp >= self.num_comps {
            return None;
        }
        let id = self.next_comp;
        if id < self.comps.len() {
            self.comps[id] = c;
        } else {
            self.comps.push(c);
        }
        self.next_comp += 1;
        Some(id)
    }

    /// `d_make_comp`.
    fn make_comp(&mut self, t: T, left: Option<Id>, right: Option<Id>) -> Option<Id> {
        use T::*;
        match t {
            QualName | LocalName | TypedName | TaggedName | Template | ConstructionVtable | VendorTypeQual
            | PtrmemType | Unary | Binary | BinaryArgs | Trinary | TrinaryArg1 | Literal | LiteralNeg | VendorExpr
            | CompoundName | VectorType | Clone | ModuleEntity => {
                if left.is_none() || right.is_none() {
                    return None;
                }
            }
            Vtable | Vtt | Typeinfo | TypeinfoName | TypeinfoFn | Thunk | VirtualThunk | CovariantThunk | JavaClass
            | Guard | TlsInit | TlsWrapper | Reftemp | HiddenAlias | TransactionClone | NontransactionClone
            | Pointer | Reference | RvalueReference | Complex | Imaginary | VendorType | Cast | Conversion
            | JavaResource | Decltype | PackExpansion | GlobalConstructors | GlobalDestructors | Nullary
            | TrinaryArg2 | TparmObj | StructuredBinding | ModuleInit | TemplateHead | TemplateNonTypeParm
            | TemplateTemplateParm | TemplatePackParm => {
                left?;
            }
            ArrayType | InitializerList | ModuleName | ModulePartition => {
                right?;
            }
            FunctionType | Restrict | Volatile | Const | Arglist | TemplateArglist | TemplateTypeParm => {}
            t if is_fnqual(t) => {}
            _ => return None,
        }
        let mut c = Comp::new(t);
        c.left = left;
        c.right = right;
        self.make_empty(c)
    }

    /// `d_make_name`: the slot is taken even where the name is refused.
    fn make_name(&mut self, s: &'a [u8]) -> Option<Id> {
        let mut c = Comp::new(T::Name);
        c.s = s;
        let p = self.make_empty(c)?;
        (!s.is_empty()).then_some(p)
    }

    fn make_builtin(&mut self, i: usize) -> Option<Id> {
        let mut c = Comp::new(T::BuiltinType);
        c.bt = Some(&BUILTINS[i]);
        self.make_empty(c)
    }

    fn make_with_num(&mut self, t: T, num: i64) -> Option<Id> {
        let mut c = Comp::new(t);
        c.num = num;
        self.make_empty(c)
    }

    /// `d_make_ctor` / `d_make_dtor` / `d_make_extended_operator`: the name in `right`; the slot
    /// is taken even where the fill is refused.
    fn make_named(&mut self, t: T, num: i64, name: Option<Id>) -> Option<Id> {
        let mut c = Comp::new(t);
        c.num = num;
        c.right = name;
        let p = self.make_empty(c)?;
        if name.is_none() || (t == T::ExtendedOperator && num < 0) {
            return None;
        }
        Some(p)
    }

    fn make_sub(&mut self, s: &'static str) -> Option<Id> {
        let mut c = Comp::new(T::SubStd);
        c.s = s.as_bytes();
        self.make_empty(c)
    }

    fn op_code(&self, id: Option<Id>) -> &'static str {
        id.and_then(|i| self.comps[i].op).map_or("", |o| o.code)
    }

    /// `d_make_demangle_mangled_name`.
    fn make_demangle_mangled_name(&mut self) -> Option<Id> {
        if self.peek() != b'_' || self.peek_next() != b'Z' {
            let rest = &self.s[self.n.min(self.s.len())..];
            return self.make_name(rest);
        }
        self.advance(2);
        self.encoding(false)
    }

    /// `cplus_demangle_mangled_name`.
    fn mangled_name(&mut self, top_level: bool) -> Option<Id> {
        if !self.check(b'_') && top_level {
            return None;
        }
        if !self.check(b'Z') {
            return None;
        }
        let mut p = self.encoding(top_level);
        if top_level {
            while self.peek() == b'.'
                && (self.peek_next().is_ascii_lowercase()
                    || self.peek_next() == b'_'
                    || self.peek_next().is_ascii_digit())
            {
                p = self.clone_suffix(p);
            }
        }
        p
    }

    fn has_return_type(&self, dc: Option<Id>) -> bool {
        let Some(dc) = dc else { return false };
        match self.t(dc) {
            T::LocalName => self.has_return_type(self.right(dc)),
            T::Template => !self.is_ctor_dtor_or_conversion(self.left(dc)),
            t if is_fnqual(t) => self.has_return_type(self.left(dc)),
            _ => false,
        }
    }

    fn is_ctor_dtor_or_conversion(&self, dc: Option<Id>) -> bool {
        let Some(dc) = dc else { return false };
        match self.t(dc) {
            T::QualName | T::LocalName => self.is_ctor_dtor_or_conversion(self.right(dc)),
            T::Ctor | T::Dtor | T::Conversion => true,
            _ => false,
        }
    }

    /// `d_encoding` (with `DMGL_PARAMS`).
    fn encoding(&mut self, top_level: bool) -> Option<Id> {
        let peek = self.peek();
        if peek == b'G' || peek == b'T' {
            return self.special_name();
        }
        let mut dc = self.name(false)?;
        let peek = self.peek();
        if peek != 0 && peek != b'E' {
            let hrt = self.has_return_type(Some(dc));
            let ftype = self.bare_function_type(hrt)?;
            if !top_level && self.t(dc) == T::LocalName && self.t(ftype) == T::FunctionType {
                self.set_left(ftype, None);
            }
            dc = self.make_comp(T::TypedName, Some(dc), Some(ftype))?;
        }
        Some(dc)
    }

    /// `d_abi_tags`.
    fn abi_tags(&mut self, mut dc: Option<Id>) -> Option<Id> {
        let hold = self.last_name;
        while self.peek() == b'B' {
            self.advance(1);
            let tag = self.source_name();
            dc = self.make_comp(T::TaggedName, dc, tag);
        }
        self.last_name = hold;
        dc
    }

    /// `d_name`.
    fn name(&mut self, substable: bool) -> Option<Id> {
        let peek = self.peek();
        let mut dc = None;
        let mut subst = false;
        match peek {
            b'N' => dc = self.nested_name(),
            b'Z' => dc = self.local_name(),
            b'U' => dc = self.unqualified_name(None, None),
            _ => {
                let mut module = None;
                if peek == b'S' {
                    if self.peek_next() == b't' {
                        self.advance(2);
                        dc = self.make_name(b"std");
                    }
                    if self.peek() == b'S' {
                        let m = self.substitution(false)?;
                        if !self.is_module(m) {
                            if dc.is_some() {
                                return None;
                            }
                            subst = true;
                            dc = Some(m);
                        } else {
                            module = Some(m);
                        }
                    }
                }
                if !subst {
                    dc = self.unqualified_name(dc, module);
                }
                if self.peek() == b'I' {
                    if !subst && !self.add_substitution(dc) {
                        return None;
                    }
                    let args = self.template_args();
                    dc = self.make_comp(T::Template, dc, args);
                    subst = false;
                }
            }
        }
        if substable && !subst && !self.add_substitution(dc) {
            return None;
        }
        dc
    }

    /// Stores `v` in the slot `d_cv_qualifiers` returned: the chain's head, or the last
    /// qualifier's `left`.
    fn fill_slot(&mut self, head: &mut Option<Id>, last: Option<Id>, v: Option<Id>) {
        match last {
            None => *head = v,
            Some(l) => self.set_left(l, v),
        }
    }

    /// `d_nested_name`.
    fn nested_name(&mut self) -> Option<Id> {
        if !self.check(b'N') {
            return None;
        }
        let (mut ret, last) = self.cv_qualifiers(true)?;
        let rqual = self.ref_qualifier(None);
        let p = self.prefix(true);
        self.fill_slot(&mut ret, last, p);
        p?;
        if let Some(r) = rqual {
            self.set_left(r, ret);
            ret = Some(r);
        }
        if !self.check(b'E') {
            return None;
        }
        ret
    }

    /// `d_prefix`.
    fn prefix(&mut self, substable: bool) -> Option<Id> {
        let mut ret: Option<Id> = None;
        loop {
            let peek = self.peek();
            if peek == b'D' && (self.peek_next() == b'T' || self.peek_next() == b't') {
                if ret.is_some() {
                    return None;
                }
                ret = self.type_();
            } else if peek == b'I' {
                ret?;
                let dc = self.template_args()?;
                ret = self.make_comp(T::Template, ret, Some(dc));
            } else if peek == b'T' {
                if ret.is_some() {
                    return None;
                }
                ret = self.template_param();
            } else if peek == b'M' {
                self.advance(1);
                continue;
            } else {
                let mut module = None;
                if peek == b'S' {
                    let m = self.substitution(true)?;
                    if !self.is_module(m) {
                        if ret.is_some() {
                            return None;
                        }
                        ret = Some(m);
                        continue;
                    }
                    module = Some(m);
                }
                ret = self.unqualified_name(ret, module);
            }
            if ret.is_none() || self.peek() == b'E' {
                break;
            }
            if substable && !self.add_substitution(ret) {
                return None;
            }
        }
        ret
    }

    /// `d_maybe_module_name`.
    fn maybe_module_name(&mut self, name: &mut Option<Id>) -> bool {
        while self.peek() == b'W' {
            self.advance(1);
            let mut code = T::ModuleName;
            if self.peek() == b'P' {
                code = T::ModulePartition;
                self.advance(1);
            }
            let sn = self.source_name();
            *name = self.make_comp(code, *name, sn);
            if name.is_none() || !self.add_substitution(*name) {
                return false;
            }
        }
        true
    }

    /// `d_unqualified_name`.
    fn unqualified_name(&mut self, scope: Option<Id>, mut module: Option<Id>) -> Option<Id> {
        if !self.maybe_module_name(&mut module) {
            return None;
        }
        let peek = self.peek();
        let mut ret;
        if peek.is_ascii_digit() {
            ret = self.source_name();
        } else if peek.is_ascii_lowercase() {
            let was_expr = self.is_expression;
            if peek == b'o' && self.peek_next() == b'n' {
                self.advance(2);
                self.is_expression = false;
            }
            ret = self.operator_name();
            self.is_expression = was_expr;
            if let Some(r) = ret {
                if self.t(r) == T::Operator && self.op_code(Some(r)) == "li" {
                    let sn = self.source_name();
                    ret = self.make_comp(T::Unary, ret, sn);
                }
            }
        } else if peek == b'D' && self.peek_next() == b'C' {
            self.advance(2);
            let mut prev: Option<Id> = None;
            ret = None;
            loop {
                let sn = self.source_name();
                let next = self.make_comp(T::StructuredBinding, sn, None);
                match prev {
                    Some(p) => self.set_right(p, next),
                    None => ret = next,
                }
                prev = next;
                if !(prev.is_some() && self.peek() != b'E') {
                    break;
                }
            }
            if prev.is_some() {
                self.advance(1);
            } else {
                ret = None;
            }
        } else if peek == b'C' || peek == b'D' {
            ret = self.ctor_dtor_name();
        } else if peek == b'L' {
            self.advance(1);
            ret = self.source_name();
            ret?;
            if !self.discriminator() {
                return None;
            }
        } else if peek == b'U' {
            match self.peek_next() {
                b'l' => ret = self.lambda(),
                b't' => ret = self.unnamed_type(),
                _ => return None,
            }
        } else {
            return None;
        }
        if module.is_some() {
            ret = self.make_comp(T::ModuleEntity, ret, module);
        }
        if self.peek() == b'B' {
            ret = self.abi_tags(ret);
        }
        if scope.is_some() {
            ret = self.make_comp(T::QualName, scope, ret);
        }
        ret
    }

    /// `d_source_name`.
    fn source_name(&mut self) -> Option<Id> {
        let len = self.number();
        if len <= 0 {
            return None;
        }
        let ret = self.identifier(len as usize);
        self.last_name = ret;
        ret
    }

    /// `d_number`.
    fn number(&mut self) -> i32 {
        let mut negative = false;
        let mut peek = self.peek();
        if peek == b'n' {
            negative = true;
            self.advance(1);
            peek = self.peek();
        }
        let mut ret: i32 = 0;
        loop {
            if !peek.is_ascii_digit() {
                return if negative { -ret } else { ret };
            }
            let d = (peek - b'0') as i32;
            if ret > (i32::MAX - d) / 10 {
                return -1;
            }
            ret = ret * 10 + d;
            self.advance(1);
            peek = self.peek();
        }
    }

    /// `d_number_component`.
    fn number_component(&mut self) -> Option<Id> {
        let id = self.make_with_num(T::Number, 0)?;
        self.comps[id].num = self.number() as i64;
        Some(id)
    }

    /// `d_identifier`.
    fn identifier(&mut self, len: usize) -> Option<Id> {
        let start = self.n;
        if self.s.len().saturating_sub(start) < len {
            return None;
        }
        self.advance(len);
        let name = &self.s[start..start + len];
        if len >= 8 + 2 && name.starts_with(b"_GLOBAL_") && matches!(name[8], b'.' | b'_' | b'$') && name[9] == b'N' {
            return self.make_name(b"(anonymous namespace)");
        }
        self.make_name(name)
    }

    /// `d_operator_name`.
    fn operator_name(&mut self) -> Option<Id> {
        let c1 = self.next_char();
        let c2 = self.next_char();
        if c1 == b'v' && c2.is_ascii_digit() {
            let sn = self.source_name();
            self.make_named(T::ExtendedOperator, (c2 - b'0') as i64, sn)
        } else if c1 == b'c' && c2 == b'v' {
            let was = self.is_conversion;
            self.is_conversion = !self.is_expression;
            let ty = self.type_();
            let res = if self.is_conversion {
                self.make_comp(T::Conversion, ty, None)
            } else {
                self.make_comp(T::Cast, ty, None)
            };
            self.is_conversion = was;
            res
        } else {
            let (mut low, mut high) = (0usize, OPERATORS.len() - 1);
            loop {
                let i = low + (high - low) / 2;
                let p = &OPERATORS[i];
                let code = p.code.as_bytes();
                if c1 == code[0] && c2 == code[1] {
                    let mut c = Comp::new(T::Operator);
                    c.op = Some(p);
                    return self.make_empty(c);
                }
                if c1 < code[0] || (c1 == code[0] && c2 < code[1]) {
                    high = i;
                } else {
                    low = i + 1;
                }
                if low == high {
                    return None;
                }
            }
        }
    }

    /// `d_make_character`.
    fn make_character(&mut self, c: u8) -> Option<Id> {
        self.make_with_num(T::Character, c as i64)
    }

    /// `d_java_resource`.
    fn java_resource(&mut self) -> Option<Id> {
        let mut p: Option<Id> = None;
        let mut len = self.number();
        if len <= 1 {
            return None;
        }
        if self.next_char() != b'_' {
            return None;
        }
        len -= 1;
        let mut str_ = self.n;
        let mut i = 0usize;
        while len > 0 {
            let c = self.at(str_ + i);
            if c == 0 {
                return None;
            }
            let next = if c == b'$' {
                i += 1;
                let e = self.at(str_ + i);
                i += 1;
                let c = match e {
                    b'S' => b'/',
                    b'_' => b'.',
                    b'$' => b'$',
                    _ => return None,
                };
                self.make_character(c)
            } else {
                while (i as i32) < len && self.at(str_ + i) != 0 && self.at(str_ + i) != b'$' {
                    i += 1;
                }
                let s = &self.s[str_..str_ + i];
                self.make_name(s)
            };
            self.advance(i);
            str_ = self.n;
            len -= i as i32;
            i = 0;
            next?;
            p = match p {
                None => next,
                Some(_) => Some(self.make_comp(T::CompoundName, p, next)?),
            };
        }
        self.make_comp(T::JavaResource, p, None)
    }

    /// `d_special_name`.
    fn special_name(&mut self) -> Option<Id> {
        if self.check(b'T') {
            match self.next_char() {
                b'V' => {
                    let t = self.type_();
                    self.make_comp(T::Vtable, t, None)
                }
                b'T' => {
                    let t = self.type_();
                    self.make_comp(T::Vtt, t, None)
                }
                b'I' => {
                    let t = self.type_();
                    self.make_comp(T::Typeinfo, t, None)
                }
                b'S' => {
                    let t = self.type_();
                    self.make_comp(T::TypeinfoName, t, None)
                }
                b'h' => {
                    if !self.call_offset(b'h') {
                        return None;
                    }
                    let e = self.encoding(false);
                    self.make_comp(T::Thunk, e, None)
                }
                b'v' => {
                    if !self.call_offset(b'v') {
                        return None;
                    }
                    let e = self.encoding(false);
                    self.make_comp(T::VirtualThunk, e, None)
                }
                b'c' => {
                    if !self.call_offset(0) || !self.call_offset(0) {
                        return None;
                    }
                    let e = self.encoding(false);
                    self.make_comp(T::CovariantThunk, e, None)
                }
                b'C' => {
                    let derived = self.type_();
                    if self.number() < 0 || !self.check(b'_') {
                        return None;
                    }
                    let base = self.type_();
                    self.make_comp(T::ConstructionVtable, base, derived)
                }
                b'F' => {
                    let t = self.type_();
                    self.make_comp(T::TypeinfoFn, t, None)
                }
                b'J' => {
                    let t = self.type_();
                    self.make_comp(T::JavaClass, t, None)
                }
                b'H' => {
                    let n = self.name(false);
                    self.make_comp(T::TlsInit, n, None)
                }
                b'W' => {
                    let n = self.name(false);
                    self.make_comp(T::TlsWrapper, n, None)
                }
                b'A' => {
                    let a = self.template_arg();
                    self.make_comp(T::TparmObj, a, None)
                }
                _ => None,
            }
        } else if self.check(b'G') {
            match self.next_char() {
                b'V' => {
                    let n = self.name(false);
                    self.make_comp(T::Guard, n, None)
                }
                b'R' => {
                    let n = self.name(false);
                    let num = self.number_component();
                    self.make_comp(T::Reftemp, n, num)
                }
                b'A' => {
                    let e = self.encoding(false);
                    self.make_comp(T::HiddenAlias, e, None)
                }
                b'I' => {
                    let mut module = None;
                    if !self.maybe_module_name(&mut module) || module.is_none() {
                        return None;
                    }
                    self.make_comp(T::ModuleInit, module, None)
                }
                b'T' => {
                    let t = if self.next_char() == b'n' { T::NontransactionClone } else { T::TransactionClone };
                    let e = self.encoding(false);
                    self.make_comp(t, e, None)
                }
                b'r' => self.java_resource(),
                _ => None,
            }
        } else {
            None
        }
    }

    /// `d_call_offset`.
    fn call_offset(&mut self, c: u8) -> bool {
        let c = if c == 0 { self.next_char() } else { c };
        if c == b'h' {
            self.number();
        } else if c == b'v' {
            self.number();
            if !self.check(b'_') {
                return false;
            }
            self.number();
        } else {
            return false;
        }
        self.check(b'_')
    }

    /// `d_ctor_dtor_name`.
    fn ctor_dtor_name(&mut self) -> Option<Id> {
        match self.peek() {
            b'C' => {
                let mut inheriting = false;
                if self.peek_next() == b'I' {
                    inheriting = true;
                    self.advance(1);
                }
                let kind = match self.peek_next() {
                    b'1' => 1,
                    b'2' => 2,
                    b'3' => 3,
                    b'4' => 4,
                    b'5' => 5,
                    _ => return None,
                };
                self.advance(2);
                if inheriting {
                    self.type_();
                }
                self.make_named(T::Ctor, kind, self.last_name)
            }
            b'D' => {
                let kind = match self.peek_next() {
                    b'0' => 1,
                    b'1' => 2,
                    b'2' => 3,
                    b'4' => 4,
                    b'5' => 5,
                    _ => return None,
                };
                self.advance(2);
                self.make_named(T::Dtor, kind, self.last_name)
            }
            _ => None,
        }
    }

    fn next_is_type_qual(&self) -> bool {
        let peek = self.peek();
        if peek == b'r' || peek == b'V' || peek == b'K' {
            return true;
        }
        peek == b'D' && matches!(self.peek_next(), b'x' | b'o' | b'O' | b'w')
    }

    /// `cplus_demangle_type`.
    fn type_(&mut self) -> Option<Id> {
        if self.next_is_type_qual() {
            let (mut ret, last) = self.cv_qualifiers(false)?;
            let p = if self.peek() == b'F' { self.function_type() } else { self.type_() };
            self.fill_slot(&mut ret, last, p);
            let p = p?;
            if matches!(self.t(p), T::RvalueReferenceThis | T::ReferenceThis) {
                let f = self.left(p);
                self.set_left(p, ret);
                ret = Some(p);
                // the slot is a qualifier's `left`: one was parsed (`next_is_type_qual`)
                self.fill_slot(&mut ret, last, f);
            }
            if !self.add_substitution(ret) {
                return None;
            }
            return ret;
        }
        let mut can_subst = true;
        let peek = self.peek();
        let ret;
        match peek {
            b'a'..=b'j' | b'l' | b'm' | b'n' | b'o' | b's' | b't' | b'v'..=b'z' => {
                ret = Some(self.make_builtin((peek - b'a') as usize)?);
                can_subst = false;
                self.advance(1);
            }
            b'u' => {
                self.advance(1);
                let sn = self.source_name();
                ret = self.make_comp(T::VendorType, sn, None);
            }
            b'F' => ret = self.function_type(),
            b'A' => ret = self.array_type(),
            b'M' => ret = self.pointer_to_member_type(),
            b'T' => {
                let mut r = self.template_param();
                if self.peek() == b'I' {
                    if !self.is_conversion {
                        if !self.add_substitution(r) {
                            return None;
                        }
                        let a = self.template_args();
                        r = self.make_comp(T::Template, r, a);
                    } else {
                        let cp = (self.n, self.next_comp, self.next_sub);
                        let args = self.template_args();
                        if self.peek() == b'I' {
                            if !self.add_substitution(r) {
                                return None;
                            }
                            r = self.make_comp(T::Template, r, args);
                        } else {
                            (self.n, self.next_comp, self.next_sub) = cp;
                        }
                    }
                }
                ret = r;
            }
            b'O' | b'P' | b'R' | b'C' | b'G' => {
                self.advance(1);
                let t = match peek {
                    b'O' => T::RvalueReference,
                    b'P' => T::Pointer,
                    b'R' => T::Reference,
                    b'C' => T::Complex,
                    _ => T::Imaginary,
                };
                let sub = self.type_();
                ret = self.make_comp(t, sub, None);
            }
            b'U' => {
                self.advance(1);
                let mut r = self.source_name();
                if self.peek() == b'I' {
                    let a = self.template_args();
                    r = self.make_comp(T::Template, r, a);
                }
                let sub = self.type_();
                ret = self.make_comp(T::VendorTypeQual, sub, r);
            }
            b'D' => {
                can_subst = false;
                self.advance(1);
                match self.next_char() {
                    b'T' | b't' => {
                        let e = self.expression();
                        let mut r = self.make_comp(T::Decltype, e, None);
                        if r.is_some() && self.next_char() != b'E' {
                            r = None;
                        }
                        ret = r;
                        can_subst = true;
                    }
                    b'p' => {
                        let sub = self.type_();
                        ret = self.make_comp(T::PackExpansion, sub, None);
                        can_subst = true;
                    }
                    b'a' => ret = self.make_name(b"auto"),
                    b'c' => ret = self.make_name(b"decltype(auto)"),
                    b'f' => ret = Some(self.make_builtin(26)?),
                    b'd' => ret = Some(self.make_builtin(27)?),
                    b'e' => ret = Some(self.make_builtin(28)?),
                    b'h' => ret = Some(self.make_builtin(29)?),
                    b'u' => ret = Some(self.make_builtin(30)?),
                    b's' => ret = Some(self.make_builtin(31)?),
                    b'i' => ret = Some(self.make_builtin(32)?),
                    b'F' => {
                        let arg = self.number();
                        if self.peek() == b'b' {
                            if arg != 16 {
                                return None;
                            }
                            self.advance(1);
                            ret = Some(self.make_builtin(35)?);
                        } else {
                            let suffix = if self.peek() == b'x' { b'x' } else { 0 };
                            if suffix == 0 && self.peek() != b'_' {
                                return None;
                            }
                            let mut c = Comp::new(T::ExtendedBuiltinType);
                            c.bt = Some(&BUILTINS[34]);
                            c.num = arg as i16 as i64;
                            c.suffix = suffix;
                            ret = Some(self.make_empty(c)?);
                            self.advance(1);
                        }
                    }
                    b'v' => {
                        ret = self.vector_type();
                        can_subst = true;
                    }
                    b'n' => ret = Some(self.make_builtin(33)?),
                    _ => return None,
                }
            }
            _ => return self.name(true),
        }
        if can_subst && !self.add_substitution(ret) {
            return None;
        }
        ret
    }

    /// `d_cv_qualifiers`: the chain's head and its last qualifier (whose `left` is the slot
    /// returned; `None`: the slot is the head itself).
    #[allow(clippy::type_complexity)]
    fn cv_qualifiers(&mut self, member_fn: bool) -> Option<(Option<Id>, Option<Id>)> {
        let mut head: Option<Id> = None;
        let mut last: Option<Id> = None;
        let mut peek = self.peek();
        while self.next_is_type_qual() {
            let mut right = None;
            self.advance(1);
            let t = match peek {
                b'r' => {
                    if member_fn {
                        T::RestrictThis
                    } else {
                        T::Restrict
                    }
                }
                b'V' => {
                    if member_fn {
                        T::VolatileThis
                    } else {
                        T::Volatile
                    }
                }
                b'K' => {
                    if member_fn {
                        T::ConstThis
                    } else {
                        T::Const
                    }
                }
                _ => {
                    peek = self.next_char();
                    match peek {
                        b'x' => T::TransactionSafe,
                        b'o' | b'O' => {
                            if peek == b'O' {
                                right = Some(self.expression()?);
                                if !self.check(b'E') {
                                    return None;
                                }
                            }
                            T::Noexcept
                        }
                        b'w' => {
                            right = Some(self.parmlist()?);
                            if !self.check(b'E') {
                                return None;
                            }
                            T::ThrowSpec
                        }
                        _ => return None,
                    }
                }
            };
            let p = self.make_comp(t, None, right)?;
            self.fill_slot(&mut head, last, Some(p));
            last = Some(p);
            peek = self.peek();
        }
        if !member_fn && peek == b'F' {
            let mut c = head;
            while let Some(id) = c {
                let nt = match self.t(id) {
                    T::Restrict => T::RestrictThis,
                    T::Volatile => T::VolatileThis,
                    T::Const => T::ConstThis,
                    t => t,
                };
                self.comps[id].t = nt;
                c = self.left(id);
            }
        }
        Some((head, last))
    }

    /// `d_ref_qualifier`.
    fn ref_qualifier(&mut self, sub: Option<Id>) -> Option<Id> {
        let t = match self.peek() {
            b'R' => T::ReferenceThis,
            b'O' => T::RvalueReferenceThis,
            _ => return sub,
        };
        self.advance(1);
        self.make_comp(t, sub, None)
    }

    /// `d_function_type`.
    fn function_type(&mut self) -> Option<Id> {
        if self.recursion_level > RECURSION_LIMIT {
            return None;
        }
        self.recursion_level += 1;
        let mut ret = None;
        if self.check(b'F') {
            if self.peek() == b'Y' {
                self.advance(1);
            }
            ret = self.bare_function_type(true);
            ret = self.ref_qualifier(ret);
            if !self.check(b'E') {
                ret = None;
            }
        }
        self.recursion_level -= 1;
        ret
    }

    /// `d_parmlist`.
    fn parmlist(&mut self) -> Option<Id> {
        let mut tl: Option<Id> = None;
        let mut last: Option<Id> = None;
        loop {
            let peek = self.peek();
            if peek == 0 || peek == b'E' || peek == b'.' {
                break;
            }
            if (peek == b'R' || peek == b'O') && self.peek_next() == b'E' {
                break;
            }
            let ty = self.type_()?;
            let p = self.make_comp(T::Arglist, Some(ty), None)?;
            match last {
                None => tl = Some(p),
                Some(l) => self.set_right(l, Some(p)),
            }
            last = Some(p);
        }
        let tl = tl?;
        if self.right(tl).is_none() {
            if let Some(l) = self.left(tl) {
                if self.t(l) == T::BuiltinType && self.comps[l].bt.is_some_and(|b| b.print == Pr::Void) {
                    self.set_left(tl, None);
                }
            }
        }
        Some(tl)
    }

    /// `d_bare_function_type`.
    fn bare_function_type(&mut self, mut has_return_type: bool) -> Option<Id> {
        if self.peek() == b'J' {
            self.advance(1);
            has_return_type = true;
        }
        let rt = if has_return_type { Some(self.type_()?) } else { None };
        let tl = self.parmlist()?;
        self.make_comp(T::FunctionType, rt, Some(tl))
    }

    /// `d_array_type`.
    fn array_type(&mut self) -> Option<Id> {
        if !self.check(b'A') {
            return None;
        }
        let peek = self.peek();
        let dim = if peek == b'_' {
            None
        } else if peek.is_ascii_digit() {
            let s = self.n;
            while {
                self.advance(1);
                self.peek().is_ascii_digit()
            } {}
            let slice = &self.s[s..self.n];
            Some(self.make_name(slice)?)
        } else {
            Some(self.expression()?)
        };
        if !self.check(b'_') {
            return None;
        }
        let t = self.type_();
        self.make_comp(T::ArrayType, dim, t)
    }

    /// `d_vector_type`.
    fn vector_type(&mut self) -> Option<Id> {
        let dim = if self.peek() == b'_' {
            self.advance(1);
            self.expression()
        } else {
            self.number_component()
        };
        dim?;
        if !self.check(b'_') {
            return None;
        }
        let t = self.type_();
        self.make_comp(T::VectorType, dim, t)
    }

    /// `d_pointer_to_member_type`.
    fn pointer_to_member_type(&mut self) -> Option<Id> {
        if !self.check(b'M') {
            return None;
        }
        let cl = self.type_()?;
        let mem = self.type_()?;
        self.make_comp(T::PtrmemType, Some(cl), Some(mem))
    }

    /// `d_compact_number`.
    fn compact_number(&mut self) -> i32 {
        let num = if self.peek() == b'_' {
            0
        } else if self.peek() == b'n' {
            return -1;
        } else {
            self.number().wrapping_add(1)
        };
        if num < 0 || !self.check(b'_') {
            return -1;
        }
        num
    }

    /// `d_template_param`.
    fn template_param(&mut self) -> Option<Id> {
        if !self.check(b'T') {
            return None;
        }
        let param = self.compact_number();
        if param < 0 {
            return None;
        }
        self.make_with_num(T::TemplateParam, param as i64)
    }

    /// `d_template_args`.
    fn template_args(&mut self) -> Option<Id> {
        if self.peek() != b'I' && self.peek() != b'J' {
            return None;
        }
        self.advance(1);
        self.template_args_1()
    }

    /// `d_template_args_1`.
    fn template_args_1(&mut self) -> Option<Id> {
        let hold = self.last_name;
        if self.peek() == b'E' {
            self.advance(1);
            return self.make_comp(T::TemplateArglist, None, None);
        }
        let mut al: Option<Id> = None;
        let mut last: Option<Id> = None;
        loop {
            let a = self.template_arg()?;
            let p = self.make_comp(T::TemplateArglist, Some(a), None)?;
            match last {
                None => al = Some(p),
                Some(l) => self.set_right(l, Some(p)),
            }
            last = Some(p);
            if self.peek() == b'E' {
                self.advance(1);
                break;
            }
        }
        self.last_name = hold;
        al
    }

    /// `d_template_arg`.
    fn template_arg(&mut self) -> Option<Id> {
        match self.peek() {
            b'X' => {
                self.advance(1);
                let ret = self.expression();
                if !self.check(b'E') {
                    return None;
                }
                ret
            }
            b'L' => self.expr_primary(),
            b'I' | b'J' => self.template_args(),
            _ => self.type_(),
        }
    }

    /// `d_exprlist`.
    fn exprlist(&mut self, terminator: u8) -> Option<Id> {
        if self.peek() == terminator {
            self.advance(1);
            return self.make_comp(T::Arglist, None, None);
        }
        let mut list: Option<Id> = None;
        let mut last: Option<Id> = None;
        loop {
            let arg = self.expression()?;
            let p = self.make_comp(T::Arglist, Some(arg), None)?;
            match last {
                None => list = Some(p),
                Some(l) => self.set_right(l, Some(p)),
            }
            last = Some(p);
            if self.peek() == terminator {
                self.advance(1);
                break;
            }
        }
        list
    }

    /// `d_unresolved_name`.
    fn unresolved_name(&mut self) -> Option<Id> {
        self.advance(2);
        let peek = self.peek();
        let ty = if self.unresolved_name_state != 0
            && (peek.is_ascii_digit() || peek.is_ascii_lowercase() || matches!(peek, b'C' | b'U' | b'L'))
        {
            self.unresolved_name_state = -1;
            let t = self.prefix(false);
            if self.peek() == b'E' {
                self.advance(1);
            }
            t
        } else {
            self.type_()
        };
        let mut name = self.unqualified_name(ty, None);
        if self.peek() == b'I' {
            let a = self.template_args();
            name = self.make_comp(T::Template, name, a);
        }
        name
    }

    /// `d_expression_1`.
    fn expression_1(&mut self) -> Option<Id> {
        let peek = self.peek();
        if peek == b'L' {
            return self.expr_primary();
        } else if peek == b'T' {
            return self.template_param();
        } else if peek == b's' && self.peek_next() == b'r' {
            return self.unresolved_name();
        } else if peek == b's' && self.peek_next() == b'p' {
            self.advance(2);
            let e = self.expression_1();
            return self.make_comp(T::PackExpansion, e, None);
        } else if peek == b'f' && self.peek_next() == b'p' {
            self.advance(2);
            let index = if self.peek() == b'T' {
                self.advance(1);
                0
            } else {
                let i = self.compact_number();
                if i == i32::MAX || i == -1 {
                    return None;
                }
                i + 1
            };
            return self.make_with_num(T::FunctionParam, index as i64);
        } else if peek.is_ascii_digit() || (peek == b'o' && self.peek_next() == b'n') {
            if peek == b'o' {
                self.advance(2);
            }
            let name = self.unqualified_name(None, None)?;
            if self.peek() == b'I' {
                let a = self.template_args();
                return self.make_comp(T::Template, Some(name), a);
            }
            return Some(name);
        } else if (peek == b'i' || peek == b't') && self.peek_next() == b'l' {
            self.advance(2);
            let ty = if peek == b't' { self.type_() } else { None };
            if self.peek() == 0 || self.peek_next() == 0 {
                return None;
            }
            let l = self.exprlist(b'E');
            return self.make_comp(T::InitializerList, ty, l);
        } else if peek == b'u' {
            self.advance(1);
            let name = self.source_name();
            let args = self.template_args_1();
            return self.make_comp(T::VendorExpr, name, args);
        }
        let op = self.operator_name()?;
        let mut code = None;
        if self.t(op) == T::Operator {
            let c = self.op_code(Some(op));
            code = Some(c);
            if c == "st" {
                let t = self.type_();
                return self.make_comp(T::Unary, Some(op), t);
            }
        }
        let args = match self.t(op) {
            T::Operator => self.comps[op].op.map_or(0, |o| o.args),
            T::ExtendedOperator => self.comps[op].num,
            T::Cast => 1,
            _ => return None,
        };
        let cb = |i: usize| code.map_or(0, |c: &str| c.as_bytes()[i]);
        match args {
            0 => self.make_comp(T::Nullary, Some(op), None),
            1 => {
                let mut suffix = false;
                if code.is_some() && (cb(0) == b'p' || cb(0) == b'm') && cb(1) == cb(0) {
                    suffix = !self.check(b'_');
                }
                let mut operand = if self.t(op) == T::Cast && self.check(b'_') {
                    self.exprlist(b'E')
                } else if code == Some("sP") {
                    self.template_args_1()
                } else {
                    self.expression_1()
                };
                if suffix {
                    operand = self.make_comp(T::BinaryArgs, operand, operand);
                }
                self.make_comp(T::Unary, Some(op), operand)
            }
            2 => {
                let c = code?;
                let left = if c.as_bytes()[1] == b'c' && matches!(c.as_bytes()[0], b's' | b'd' | b'c' | b'r') {
                    self.type_()
                } else if c.as_bytes()[0] == b'f' {
                    self.operator_name()
                } else if c == "di" {
                    self.unqualified_name(None, None)
                } else {
                    self.expression_1()
                };
                let right = if c == "cl" {
                    self.exprlist(b'E')
                } else if c == "dt" || c == "pt" {
                    let peek = self.peek();
                    if (peek == b'g' && self.peek_next() == b's') || (peek == b's' && self.peek_next() == b'r') {
                        self.expression_1()
                    } else {
                        let mut r = self.unqualified_name(None, None);
                        if self.peek() == b'I' {
                            let a = self.template_args();
                            r = self.make_comp(T::Template, r, a);
                        }
                        r
                    }
                } else {
                    self.expression_1()
                };
                let ba = self.make_comp(T::BinaryArgs, left, right);
                self.make_comp(T::Binary, Some(op), ba)
            }
            3 => {
                let c = code?;
                let (first, second, third);
                if c == "qu" || c == "dX" {
                    first = self.expression_1();
                    second = self.expression_1();
                    third = Some(self.expression_1()?);
                } else if c.as_bytes()[0] == b'f' {
                    first = self.operator_name();
                    second = self.expression_1();
                    third = Some(self.expression_1()?);
                } else if c.as_bytes()[0] == b'n' {
                    if c.as_bytes()[1] != b'w' && c.as_bytes()[1] != b'a' {
                        return None;
                    }
                    first = self.exprlist(b'_');
                    second = self.type_();
                    if self.peek() == b'E' {
                        self.advance(1);
                        third = None;
                    } else if self.peek() == b'p' && self.peek_next() == b'i' {
                        self.advance(2);
                        third = self.exprlist(b'E');
                    } else if self.peek() == b'i' && self.peek_next() == b'l' {
                        third = self.expression_1();
                    } else {
                        return None;
                    }
                } else {
                    return None;
                }
                let a2 = self.make_comp(T::TrinaryArg2, second, third);
                let a1 = self.make_comp(T::TrinaryArg1, first, a2);
                self.make_comp(T::Trinary, Some(op), a1)
            }
            _ => None,
        }
    }

    /// `d_expression`.
    fn expression(&mut self) -> Option<Id> {
        let was = self.is_expression;
        self.is_expression = true;
        let ret = self.expression_1();
        self.is_expression = was;
        ret
    }

    /// `d_expr_primary`.
    fn expr_primary(&mut self) -> Option<Id> {
        if !self.check(b'L') {
            return None;
        }
        let ret = if self.peek() == b'_' || self.peek() == b'Z' {
            self.mangled_name(false)
        } else {
            let ty = self.type_()?;
            if self.t(ty) == T::BuiltinType
                && self.comps[ty].bt.is_some_and(|b| b.name == BUILTINS[33].name)
                && self.peek() == b'E'
            {
                self.advance(1);
                return Some(ty);
            }
            let mut t = T::Literal;
            if self.peek() == b'n' {
                t = T::LiteralNeg;
                self.advance(1);
            }
            let s = self.n;
            while self.peek() != b'E' {
                if self.peek() == 0 {
                    return None;
                }
                self.advance(1);
            }
            let slice = &self.s[s..self.n];
            let name = self.make_name(slice);
            self.make_comp(t, Some(ty), name)
        };
        if !self.check(b'E') {
            return None;
        }
        ret
    }

    /// `d_local_name`.
    fn local_name(&mut self) -> Option<Id> {
        if !self.check(b'Z') {
            return None;
        }
        let function = self.encoding(false)?;
        if !self.check(b'E') {
            return None;
        }
        let name = if self.peek() == b's' {
            self.advance(1);
            if !self.discriminator() {
                return None;
            }
            self.make_name(b"string literal")
        } else {
            let mut num = -1;
            if self.peek() == b'd' {
                self.advance(1);
                num = self.compact_number();
                if num < 0 {
                    return None;
                }
            }
            let mut n = self.name(false);
            if let Some(ni) = n {
                if !matches!(self.t(ni), T::Lambda | T::UnnamedType) && !self.discriminator() {
                    return None;
                }
            }
            if num >= 0 {
                let mut c = Comp::new(T::DefaultArg);
                c.num = num as i64;
                c.left = n;
                n = self.make_empty(c);
            }
            n
        };
        if self.t(function) == T::TypedName {
            if let Some(r) = self.right(function) {
                if self.t(r) == T::FunctionType {
                    self.set_left(r, None);
                }
            }
        }
        self.make_comp(T::LocalName, Some(function), name)
    }

    /// `d_discriminator`.
    fn discriminator(&mut self) -> bool {
        if self.peek() != b'_' {
            return true;
        }
        self.advance(1);
        let mut num_underscores = 1;
        if self.peek() == b'_' {
            num_underscores += 1;
            self.advance(1);
        }
        let discrim = self.number();
        if discrim < 0 {
            return false;
        }
        if num_underscores > 1 && discrim >= 10 {
            if self.peek() == b'_' {
                self.advance(1);
            } else {
                return false;
            }
        }
        true
    }

    /// `d_template_parm`.
    fn template_parm(&mut self, bad: &mut bool) -> Option<Id> {
        if self.peek() != b'T' {
            return None;
        }
        let (kind, op) = match self.peek_next() {
            b'p' => {
                self.advance(2);
                let op = self.template_parm(bad);
                if op.is_none() {
                    *bad = true;
                    return None;
                }
                (T::TemplatePackParm, op)
            }
            b'y' => {
                self.advance(2);
                (T::TemplateTypeParm, None)
            }
            b'n' => {
                self.advance(2);
                let op = self.type_();
                if op.is_none() {
                    *bad = true;
                    return None;
                }
                (T::TemplateNonTypeParm, op)
            }
            b't' => {
                self.advance(2);
                let op = self.template_head(bad);
                if op.is_none() || !self.check(b'E') {
                    *bad = true;
                    return None;
                }
                (T::TemplateTemplateParm, op)
            }
            _ => return None,
        };
        self.make_comp(kind, op, None)
    }

    /// `d_template_head`.
    fn template_head(&mut self, bad: &mut bool) -> Option<Id> {
        let mut res: Option<Id> = None;
        let mut last: Option<Id> = None;
        while let Some(op) = self.template_parm(bad) {
            match last {
                None => res = Some(op),
                Some(l) => self.set_right(l, Some(op)),
            }
            last = Some(op);
        }
        if res.is_some() {
            res = self.make_comp(T::TemplateHead, res, None);
        }
        res
    }

    /// `d_lambda`.
    fn lambda(&mut self) -> Option<Id> {
        if !self.check(b'U') || !self.check(b'l') {
            return None;
        }
        let mut bad = false;
        let head = self.template_head(&mut bad);
        if bad {
            return None;
        }
        let mut tl = self.parmlist()?;
        if let Some(h) = head {
            self.set_right(h, Some(tl));
            tl = h;
        }
        if !self.check(b'E') {
            return None;
        }
        let num = self.compact_number();
        if num < 0 {
            return None;
        }
        let mut c = Comp::new(T::Lambda);
        c.left = Some(tl);
        c.num = num as i64;
        self.make_empty(c)
    }

    /// `d_unnamed_type`.
    fn unnamed_type(&mut self) -> Option<Id> {
        if !self.check(b'U') || !self.check(b't') {
            return None;
        }
        let num = self.compact_number();
        if num < 0 {
            return None;
        }
        let ret = self.make_with_num(T::UnnamedType, num as i64);
        if !self.add_substitution(ret) {
            return None;
        }
        ret
    }

    /// `d_clone_suffix`.
    fn clone_suffix(&mut self, encoding: Option<Id>) -> Option<Id> {
        let suffix = self.n;
        let mut pend = suffix;
        let lower_digit_us = |c: u8| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_';
        if self.at(pend) == b'.' && lower_digit_us(self.at(pend + 1)) {
            pend += 2;
            while lower_digit_us(self.at(pend)) {
                pend += 1;
            }
        }
        while self.at(pend) == b'.' && self.at(pend + 1).is_ascii_digit() {
            pend += 2;
            while self.at(pend).is_ascii_digit() {
                pend += 1;
            }
        }
        self.advance(pend - suffix);
        let slice = &self.s[suffix..pend];
        let n = self.make_name(slice);
        self.make_comp(T::Clone, encoding, n)
    }

    /// `d_add_substitution`.
    fn add_substitution(&mut self, dc: Option<Id>) -> bool {
        let Some(dc) = dc else { return false };
        if self.next_sub >= self.num_subs {
            return false;
        }
        if self.next_sub < self.subs.len() {
            self.subs[self.next_sub] = dc;
        } else {
            self.subs.push(dc);
        }
        self.next_sub += 1;
        true
    }

    /// `d_substitution` (with `DMGL_VERBOSE`: the full expansions).
    fn substitution(&mut self, _prefix: bool) -> Option<Id> {
        if !self.check(b'S') {
            return None;
        }
        let mut c = self.next_char();
        if c == b'_' || c.is_ascii_digit() || c.is_ascii_uppercase() {
            let mut id: u32 = 0;
            if c != b'_' {
                loop {
                    let new_id = if c.is_ascii_digit() {
                        id.wrapping_mul(36).wrapping_add((c - b'0') as u32)
                    } else if c.is_ascii_uppercase() {
                        id.wrapping_mul(36).wrapping_add((c - b'A') as u32 + 10)
                    } else {
                        return None;
                    };
                    if new_id < id {
                        return None;
                    }
                    id = new_id;
                    c = self.next_char();
                    if c == b'_' {
                        break;
                    }
                }
                id = id.wrapping_add(1);
            }
            if id as usize >= self.next_sub {
                return None;
            }
            return Some(self.subs[id as usize]);
        }
        let &(_, full, set_last) = STANDARD_SUBS.iter().find(|s| s.0 == c)?;
        if let Some(l) = set_last {
            self.last_name = self.make_sub(l);
        }
        let mut dc = self.make_sub(full);
        if self.peek() == b'B' {
            dc = self.abi_tags(dc);
            if !self.add_substitution(dc) {
                return None;
            }
        }
        dc
    }
}

/// `d_print_template`.
#[derive(Clone, Copy)]
struct Tpl {
    next: Option<usize>,
    decl: Option<Id>,
}

/// `d_print_mod`.
#[derive(Clone, Copy)]
struct Mod {
    next: Option<usize>,
    m: Id,
    printed: bool,
    templates: Option<usize>,
}

const NO_MOD: Mod = Mod { next: None, m: 0, printed: false, templates: None };

/// `d_print_info`.
struct P<'c, 'a> {
    c: &'c [Comp<'a>],
    out: Vec<u8>,
    last: u8,
    printing: Vec<u8>,
    counting: Vec<u8>,
    templates: Option<usize>,
    tpl: Vec<Tpl>,
    modifiers: Option<usize>,
    mods: Vec<Mod>,
    failure: bool,
    /// the text passed OUT_LIMIT
    limited: bool,
    recursion: i32,
    lambda_tpl_parms: i32,
    pack_index: i32,
    /// `component_stack`, innermost last
    stack: Vec<Id>,
    saved_scopes: Vec<(Id, Option<usize>)>,
    num_saved_scopes: i32,
    next_copy_template: i32,
    num_copy_templates: i32,
    current_template: Option<Id>,
}

impl<'c, 'a> P<'c, 'a> {
    fn t(&self, id: Id) -> T {
        self.c[id].t
    }
    fn tt(&self, id: Option<Id>) -> Option<T> {
        id.map(|i| self.c[i].t)
    }
    fn left(&self, id: Id) -> Option<Id> {
        self.c[id].left
    }
    fn right(&self, id: Id) -> Option<Id> {
        self.c[id].right
    }
    fn code(&self, id: Option<Id>) -> &'static [u8] {
        id.and_then(|i| self.c[i].op).map_or(b"\0\0", |o| o.code.as_bytes())
    }
    fn fail(&mut self) {
        self.failure = true;
    }
    fn ch(&mut self, c: u8) {
        if self.out.len() >= OUT_LIMIT {
            self.limited = true;
            return;
        }
        self.out.push(c);
        self.last = c;
    }
    fn s(&mut self, s: &[u8]) {
        for &c in s {
            self.ch(c);
        }
    }
    fn num(&mut self, n: i32) {
        self.s(n.to_string().as_bytes());
    }
    fn push_mod(&mut self, m: Mod) -> usize {
        self.mods.push(m);
        self.mods.len() - 1
    }
    fn push_tpl(&mut self, decl: Option<Id>) -> usize {
        self.tpl.push(Tpl { next: self.templates, decl });
        self.tpl.len() - 1
    }

    /// `d_count_templates_scopes`.
    fn count_templates_scopes(&mut self, dc: Option<Id>) {
        let Some(dc) = dc else { return };
        if self.counting[dc] > 1 || self.recursion > MAX_RECURSION_COUNT {
            return;
        }
        self.counting[dc] += 1;
        use T::*;
        let recurse = match self.t(dc) {
            Template => {
                self.num_copy_templates += 1;
                true
            }
            Reference | RvalueReference => {
                if self.tt(self.left(dc)) == Some(TemplateParam) {
                    self.num_saved_scopes += 1;
                }
                true
            }
            QualName | LocalName | TypedName | Vtable | Vtt | ConstructionVtable | Typeinfo | TypeinfoName
            | TypeinfoFn | Thunk | VirtualThunk | CovariantThunk | JavaClass | Guard | TlsInit | TlsWrapper
            | Reftemp | HiddenAlias | Restrict | Volatile | Const | RestrictThis | VolatileThis | ConstThis
            | ReferenceThis | RvalueReferenceThis | TransactionSafe | Noexcept | ThrowSpec | VendorTypeQual
            | Pointer | Complex | Imaginary | VendorType | FunctionType | ArrayType | PtrmemType | VectorType
            | Arglist | TemplateArglist | TparmObj | InitializerList | Cast | Conversion | Nullary | Unary | Binary
            | BinaryArgs | Trinary | TrinaryArg1 | TrinaryArg2 | Literal | LiteralNeg | VendorExpr | JavaResource
            | CompoundName | Decltype | TransactionClone | NontransactionClone | PackExpansion | TaggedName | Clone => {
                true
            }
            Ctor | Dtor | ExtendedOperator => {
                self.count_templates_scopes(self.right(dc));
                false
            }
            GlobalConstructors | GlobalDestructors | ModuleEntity | Lambda | DefaultArg => {
                self.count_templates_scopes(self.left(dc));
                false
            }
            _ => false,
        };
        if recurse {
            if self.recursion > RECURSION_LIMIT as i32 {
                return;
            }
            self.recursion += 1;
            self.count_templates_scopes(self.left(dc));
            self.count_templates_scopes(self.right(dc));
            self.recursion -= 1;
        }
    }

    /// `d_index_template_argument`.
    fn index_template_argument(&self, args: Option<Id>, mut i: i32) -> Option<Id> {
        if i < 0 {
            return args;
        }
        let mut a = args;
        while let Some(x) = a {
            if self.t(x) != T::TemplateArglist {
                return None;
            }
            if i <= 0 {
                break;
            }
            i -= 1;
            a = self.right(x);
        }
        if i != 0 {
            return None;
        }
        self.left(a?)
    }

    /// `d_lookup_template_argument`.
    fn lookup_template_argument(&mut self, dc: Id) -> Option<Id> {
        let Some(t) = self.templates else {
            self.fail();
            return None;
        };
        let decl = self.tpl[t].decl?;
        self.index_template_argument(self.right(decl), self.c[dc].num as i32)
    }

    /// `d_find_pack`.
    fn find_pack(&mut self, dc: Option<Id>) -> Option<Id> {
        let dc = dc?;
        use T::*;
        match self.t(dc) {
            TemplateParam => {
                let a = self.lookup_template_argument(dc)?;
                (self.t(a) == TemplateArglist).then_some(a)
            }
            PackExpansion | Lambda | Name | TaggedName | Operator | BuiltinType | ExtendedBuiltinType | SubStd
            | Character | FunctionParam | UnnamedType | DefaultArg | Number => None,
            ExtendedOperator | Ctor | Dtor => self.find_pack(self.right(dc)),
            _ => {
                let a = self.find_pack(self.left(dc));
                if a.is_some() {
                    return a;
                }
                self.find_pack(self.right(dc))
            }
        }
    }

    /// `d_pack_length`.
    fn pack_length(&self, mut dc: Option<Id>) -> i32 {
        let mut count = 0;
        while let Some(d) = dc {
            if self.t(d) != T::TemplateArglist || self.left(d).is_none() {
                break;
            }
            count += 1;
            dc = self.right(d);
        }
        count
    }

    /// `d_args_length`.
    fn args_length(&mut self, mut dc: Option<Id>) -> i32 {
        let mut count = 0;
        while let Some(d) = dc {
            if self.t(d) != T::TemplateArglist {
                break;
            }
            let Some(elt) = self.left(d) else { break };
            if self.t(elt) == T::PackExpansion {
                let a = self.find_pack(self.left(elt));
                count += self.pack_length(a);
            } else {
                count += 1;
            }
            dc = self.right(d);
        }
        count
    }

    /// `d_print_subexpr`.
    fn subexpr(&mut self, dc: Option<Id>) {
        let simple = matches!(self.tt(dc), Some(T::Name | T::QualName | T::InitializerList | T::FunctionParam));
        if !simple {
            self.ch(b'(');
        }
        self.comp(dc);
        if !simple {
            self.ch(b')');
        }
    }

    /// `d_save_scope`.
    fn save_scope(&mut self, container: Id) {
        if self.saved_scopes.len() as i32 >= self.num_saved_scopes {
            self.fail();
            return;
        }
        let mut decls = Vec::new();
        let mut src = self.templates;
        while let Some(s) = src {
            decls.push(self.tpl[s].decl);
            src = self.tpl[s].next;
        }
        let mut head = None;
        let mut copies = Vec::new();
        for d in decls {
            if self.next_copy_template >= self.num_copy_templates {
                self.saved_scopes.push((container, None));
                self.fail();
                return;
            }
            self.next_copy_template += 1;
            copies.push(d);
        }
        for d in copies.into_iter().rev() {
            self.tpl.push(Tpl { next: head, decl: d });
            head = Some(self.tpl.len() - 1);
        }
        self.saved_scopes.push((container, head));
    }

    /// `d_maybe_print_fold_expression`.
    fn maybe_fold(&mut self, dc: Id) -> bool {
        let fold_code = self.code(self.left(dc));
        if fold_code[0] != b'f' {
            return false;
        }
        let Some(ops) = self.right(dc) else { return false };
        let operator = self.left(ops);
        let mut op1 = self.right(ops);
        let mut op2 = None;
        if let Some(o) = op1 {
            if self.t(o) == T::TrinaryArg2 {
                op2 = self.right(o);
                op1 = self.left(o);
            }
        }
        let save = self.pack_index;
        self.pack_index = -1;
        match fold_code[1] {
            b'l' => {
                self.s(b"(...");
                self.expr_op(operator);
                self.subexpr(op1);
                self.ch(b')');
            }
            b'r' => {
                self.ch(b'(');
                self.subexpr(op1);
                self.expr_op(operator);
                self.s(b"...)");
            }
            b'L' | b'R' => {
                self.ch(b'(');
                self.subexpr(op1);
                self.expr_op(operator);
                self.s(b"...");
                self.expr_op(operator);
                self.subexpr(op2);
                self.ch(b')');
            }
            _ => {}
        }
        self.pack_index = save;
        true
    }

    fn is_designated_init(&self, dc: Option<Id>) -> bool {
        let Some(dc) = dc else { return false };
        if !matches!(self.t(dc), T::Binary | T::Trinary) {
            return false;
        }
        let code = self.code(self.left(dc));
        code[0] == b'd' && matches!(code[1], b'i' | b'x' | b'X')
    }

    /// `d_maybe_print_designated_init`.
    fn maybe_designated_init(&mut self, dc: Id) -> bool {
        if !self.is_designated_init(Some(dc)) {
            return false;
        }
        let code = self.code(self.left(dc));
        let Some(operands) = self.right(dc) else { return false };
        let op1 = self.left(operands);
        let mut op2 = self.right(operands);
        self.ch(if code[1] == b'i' { b'.' } else { b'[' });
        self.comp(op1);
        if code[1] == b'X' {
            self.s(b" ... ");
            self.comp(op2.and_then(|o| self.left(o)));
            op2 = op2.and_then(|o| self.right(o));
        }
        if code[1] != b'i' {
            self.ch(b']');
        }
        if self.is_designated_init(op2) {
            self.comp(op2);
        } else {
            self.ch(b'=');
            self.subexpr(op2);
        }
        true
    }

    /// `d_print_lambda_parm_name`.
    fn lambda_parm_name(&mut self, t: T, index: i32) {
        let s: &[u8] = match t {
            T::TemplateTypeParm => b"$T",
            T::TemplateNonTypeParm => b"$N",
            T::TemplateTemplateParm => b"$TT",
            _ => {
                self.fail();
                b""
            }
        };
        self.s(s);
        self.num(index);
    }

    /// `d_print_comp`.
    fn comp(&mut self, dc: Option<Id>) {
        if self.limited {
            return;
        }
        let Some(id) = dc else {
            self.fail();
            return;
        };
        if self.printing[id] > 1 || self.recursion > MAX_RECURSION_COUNT {
            self.fail();
            return;
        }
        self.printing[id] += 1;
        self.recursion += 1;
        self.stack.push(id);
        self.comp_inner(id);
        self.stack.pop();
        self.printing[id] -= 1;
        self.recursion -= 1;
    }

    /// The `modifier:` label of `d_print_comp_inner`.
    fn modifier(&mut self, dc: Id, mod_inner: Option<Id>, restore: Option<Option<usize>>) {
        let m = self.push_mod(Mod { next: self.modifiers, m: dc, printed: false, templates: self.templates });
        self.modifiers = Some(m);
        let inner = mod_inner.or(self.left(dc));
        self.comp(inner);
        if !self.mods[m].printed {
            self.print_mod(dc);
        }
        self.modifiers = self.mods[m].next;
        if let Some(saved) = restore {
            self.templates = saved;
        }
    }

    /// `d_print_comp_inner` (`options` fixed: neither `DMGL_JAVA` nor the return postfix).
    fn comp_inner(&mut self, dc: Id) {
        if self.failure {
            return;
        }
        let c = self.c[dc];
        use T::*;
        match c.t {
            Name => self.s(c.s),
            TaggedName => {
                self.comp(c.left);
                self.s(b"[abi:");
                self.comp(c.right);
                self.ch(b']');
            }
            StructuredBinding => {
                self.ch(b'[');
                let mut d = dc;
                loop {
                    self.comp(self.left(d));
                    match self.right(d) {
                        Some(r) => d = r,
                        None => break,
                    }
                    self.s(b", ");
                }
                self.ch(b']');
            }
            ModuleEntity => {
                self.comp(c.left);
                self.ch(b'@');
                self.comp(c.right);
            }
            ModuleName | ModulePartition => {
                if c.left.is_some() {
                    self.comp(c.left);
                }
                if c.t == ModulePartition {
                    self.ch(b':');
                } else if c.left.is_some() {
                    self.ch(b'.');
                }
                self.comp(c.right);
            }
            QualName | LocalName => {
                self.comp(c.left);
                self.s(b"::");
                let mut local = c.right;
                if let Some(l) = local {
                    if self.t(l) == DefaultArg {
                        self.s(b"{default arg#");
                        self.num(self.c[l].num as i32 + 1);
                        self.s(b"}::");
                        local = self.left(l);
                    }
                }
                self.comp(local);
            }
            TypedName => self.typed_name(dc),
            Template => {
                let hold_cur = self.current_template;
                self.current_template = Some(dc);
                let hold = self.modifiers;
                self.modifiers = None;
                self.comp(c.left);
                if self.last == b'<' {
                    self.ch(b' ');
                }
                self.ch(b'<');
                self.comp(c.right);
                if self.last == b'>' {
                    self.ch(b' ');
                }
                self.ch(b'>');
                self.modifiers = hold;
                self.current_template = hold_cur;
            }
            TemplateParam => {
                if self.lambda_tpl_parms as i64 > c.num + 1 {
                    let decl = self.templates.and_then(|t| self.tpl[t].decl);
                    let mut a = decl.and_then(|d| self.left(d));
                    let mut n = c.num as u32;
                    while let Some(x) = a {
                        if n == 0 {
                            break;
                        }
                        a = self.right(x);
                        n -= 1;
                    }
                    if let Some(x) = a {
                        if self.t(x) == TemplatePackParm {
                            a = self.left(x);
                        }
                    }
                    match a {
                        None => self.fail(),
                        Some(x) => self.lambda_parm_name(self.t(x), c.num as i32),
                    }
                } else if self.lambda_tpl_parms != 0 {
                    self.s(b"auto:");
                    self.num(c.num as i32 + 1);
                } else {
                    let mut a = self.lookup_template_argument(dc);
                    if let Some(x) = a {
                        if self.t(x) == TemplateArglist {
                            a = self.index_template_argument(Some(x), self.pack_index);
                        }
                    }
                    let Some(a) = a else {
                        self.fail();
                        return;
                    };
                    let hold = self.templates;
                    self.templates = hold.and_then(|t| self.tpl[t].next);
                    self.comp(Some(a));
                    self.templates = hold;
                }
            }
            TparmObj => self.prefixed(b"template parameter object for ", c.left),
            Ctor => self.comp(c.right),
            Dtor => {
                self.ch(b'~');
                self.comp(c.right);
            }
            ModuleInit => self.prefixed(b"initializer for module ", c.left),
            Vtable => self.prefixed(b"vtable for ", c.left),
            Vtt => self.prefixed(b"VTT for ", c.left),
            ConstructionVtable => {
                self.prefixed(b"construction vtable for ", c.left);
                self.s(b"-in-");
                self.comp(c.right);
            }
            Typeinfo => self.prefixed(b"typeinfo for ", c.left),
            TypeinfoName => self.prefixed(b"typeinfo name for ", c.left),
            TypeinfoFn => self.prefixed(b"typeinfo fn for ", c.left),
            Thunk => self.prefixed(b"non-virtual thunk to ", c.left),
            VirtualThunk => self.prefixed(b"virtual thunk to ", c.left),
            CovariantThunk => self.prefixed(b"covariant return thunk to ", c.left),
            JavaClass => self.prefixed(b"java Class for ", c.left),
            Guard => self.prefixed(b"guard variable for ", c.left),
            TlsInit => self.prefixed(b"TLS init function for ", c.left),
            TlsWrapper => self.prefixed(b"TLS wrapper function for ", c.left),
            Reftemp => {
                self.prefixed(b"reference temporary #", c.right);
                self.s(b" for ");
                self.comp(c.left);
            }
            HiddenAlias => self.prefixed(b"hidden alias for ", c.left),
            TransactionClone => self.prefixed(b"transaction clone for ", c.left),
            NontransactionClone => self.prefixed(b"non-transaction clone for ", c.left),
            SubStd => self.s(c.s),
            Restrict | Volatile | Const => {
                let mut p = self.modifiers;
                while let Some(pi) = p {
                    let pm = self.mods[pi];
                    if !pm.printed {
                        let mt = self.t(pm.m);
                        if !matches!(mt, Restrict | Volatile | Const) {
                            break;
                        }
                        if mt == c.t {
                            self.comp(c.left);
                            return;
                        }
                    }
                    p = pm.next;
                }
                self.modifier(dc, None, None);
            }
            Reference | RvalueReference => self.reference(dc),
            VendorTypeQual | Pointer | Complex | Imaginary => self.modifier(dc, None, None),
            t if is_fnqual(t) => self.modifier(dc, None, None),
            BuiltinType => self.s(c.bt.map_or("", |b| b.name).as_bytes()),
            ExtendedBuiltinType => {
                self.s(c.bt.map_or("", |b| b.name).as_bytes());
                self.num(c.num as i32);
                if c.suffix != 0 {
                    self.ch(c.suffix);
                }
            }
            VendorType => self.comp(c.left),
            FunctionType => {
                if c.left.is_some() {
                    let m =
                        self.push_mod(Mod { next: self.modifiers, m: dc, printed: false, templates: self.templates });
                    self.modifiers = Some(m);
                    self.comp(c.left);
                    self.modifiers = self.mods[m].next;
                    if self.mods[m].printed {
                        return;
                    }
                    self.ch(b' ');
                }
                self.function_type(dc, self.modifiers);
            }
            ArrayType => self.array(dc),
            PtrmemType | VectorType => {
                let m = self.push_mod(Mod { next: self.modifiers, m: dc, printed: false, templates: self.templates });
                self.modifiers = Some(m);
                self.comp(c.right);
                if !self.mods[m].printed {
                    self.print_mod(dc);
                }
                self.modifiers = self.mods[m].next;
            }
            Arglist | TemplateArglist => {
                if c.left.is_some() {
                    self.comp(c.left);
                }
                if c.right.is_some() {
                    self.s(b", ");
                    let len = self.out.len();
                    self.comp(c.right);
                    if self.out.len() == len {
                        self.out.truncate(len - 2);
                    }
                }
            }
            InitializerList => {
                if c.left.is_some() {
                    self.comp(c.left);
                }
                self.ch(b'{');
                self.comp(c.right);
                self.ch(b'}');
            }
            Operator => {
                let name = c.op.map_or("", |o| o.name).as_bytes();
                self.s(b"operator");
                if name.first().is_some_and(u8::is_ascii_lowercase) {
                    self.ch(b' ');
                }
                let len = if name.last() == Some(&b' ') { name.len() - 1 } else { name.len() };
                self.s(&name[..len]);
            }
            ExtendedOperator => self.prefixed(b"operator ", c.right),
            Conversion => {
                self.s(b"operator ");
                self.conversion(dc);
            }
            Nullary => self.expr_op(c.left),
            Unary => self.unary(dc),
            Binary => self.binary(dc),
            BinaryArgs | TrinaryArg1 | TrinaryArg2 => self.fail(),
            Trinary => self.trinary(dc),
            Literal | LiteralNeg => self.literal(dc),
            VendorExpr => {
                self.comp(c.left);
                self.ch(b'(');
                self.comp(c.right);
                self.ch(b')');
            }
            Number => self.num(c.num as i32),
            JavaResource => self.prefixed(b"java resource ", c.left),
            CompoundName => {
                self.comp(c.left);
                self.comp(c.right);
            }
            Character => self.ch(c.num as u8),
            Decltype => {
                self.prefixed(b"decltype (", c.left);
                self.ch(b')');
            }
            PackExpansion => {
                let a = if self.lambda_tpl_parms == 0 { self.find_pack(c.left) } else { None };
                match a {
                    None => {
                        self.subexpr(c.left);
                        self.s(b"...");
                    }
                    Some(a) => {
                        let len = self.pack_length(Some(a));
                        for i in 0..len {
                            if i != 0 {
                                self.s(b", ");
                            }
                            self.pack_index = i;
                            self.comp(c.left);
                        }
                    }
                }
            }
            FunctionParam => {
                if c.num == 0 {
                    self.s(b"this");
                } else {
                    self.s(b"{parm#");
                    self.num(c.num as i32);
                    self.ch(b'}');
                }
            }
            GlobalConstructors => self.prefixed(b"global constructors keyed to ", c.left),
            GlobalDestructors => self.prefixed(b"global destructors keyed to ", c.left),
            Lambda => self.lambda(dc),
            UnnamedType => {
                self.s(b"{unnamed type#");
                self.num(c.num as i32 + 1);
                self.ch(b'}');
            }
            Clone => {
                self.comp(c.left);
                self.s(b" [clone ");
                self.comp(c.right);
                self.ch(b']');
            }
            TemplateHead => {
                self.ch(b'<');
                let mut parm = c.left;
                let mut count = 0;
                while let Some(p) = parm {
                    if count != 0 {
                        self.s(b", ");
                    }
                    count += 1;
                    self.comp(Some(p));
                    parm = self.right(p);
                }
                self.ch(b'>');
            }
            TemplateTypeParm => self.s(b"typename"),
            TemplateNonTypeParm => self.comp(c.left),
            TemplateTemplateParm => {
                self.prefixed(b"template", c.left);
                self.s(b" class");
            }
            TemplatePackParm => {
                self.comp(c.left);
                self.s(b"...");
            }
            _ => self.fail(),
        }
    }

    fn prefixed(&mut self, s: &[u8], dc: Option<Id>) {
        self.s(s);
        self.comp(dc);
    }

    /// `DEMANGLE_COMPONENT_TYPED_NAME` of `d_print_comp_inner`.
    fn typed_name(&mut self, dc: Id) {
        let hold_modifiers = self.modifiers;
        self.modifiers = None;
        let base = self.mods.len();
        self.mods.extend([NO_MOD; 4]);
        let mut i = 0usize;
        let mut typed_name = self.left(dc);
        while let Some(tn) = typed_name {
            if i >= 4 {
                self.fail();
                return;
            }
            self.mods[base + i] = Mod { next: self.modifiers, m: tn, printed: false, templates: self.templates };
            self.modifiers = Some(base + i);
            i += 1;
            if !is_fnqual(self.t(tn)) {
                break;
            }
            typed_name = self.left(tn);
        }
        let Some(mut tn) = typed_name else {
            self.fail();
            return;
        };
        if self.t(tn) == T::LocalName {
            let mut x = self.right(tn);
            if let Some(xi) = x {
                if self.t(xi) == T::DefaultArg {
                    x = self.left(xi);
                }
            }
            while let Some(xi) = x {
                if !is_fnqual(self.t(xi)) {
                    break;
                }
                if i >= 4 {
                    self.fail();
                    return;
                }
                self.mods[base + i] = self.mods[base + i - 1];
                self.mods[base + i].next = Some(base + i - 1);
                self.modifiers = Some(base + i);
                self.mods[base + i - 1].m = xi;
                self.mods[base + i - 1].printed = false;
                self.mods[base + i - 1].templates = self.templates;
                i += 1;
                x = self.left(xi);
            }
            let Some(xi) = x else {
                self.fail();
                return;
            };
            tn = xi;
        }
        let saved = self.templates;
        let is_template = self.t(tn) == T::Template;
        if is_template {
            let d = self.push_tpl(Some(tn));
            self.templates = Some(d);
        }
        self.comp(self.right(dc));
        if is_template {
            self.templates = saved;
        }
        while i > 0 {
            i -= 1;
            if !self.mods[base + i].printed {
                self.ch(b' ');
                self.print_mod(self.mods[base + i].m);
            }
        }
        self.modifiers = hold_modifiers;
    }

    /// `DEMANGLE_COMPONENT_REFERENCE` / `RVALUE_REFERENCE` of `d_print_comp_inner`.
    fn reference(&mut self, dc0: Id) {
        let mut dc = dc0;
        let mut mod_inner = None;
        let mut restore = None;
        let Some(mut sub) = self.left(dc) else {
            self.modifier(dc, None, None);
            return;
        };
        if self.lambda_tpl_parms == 0 && self.t(sub) == T::TemplateParam {
            let scope = self.saved_scopes.iter().find(|s| s.0 == sub).map(|s| s.1);
            match scope {
                None => {
                    self.save_scope(sub);
                    if self.failure {
                        return;
                    }
                }
                Some(templates) => {
                    let n = self.stack.len();
                    let found = self.stack.iter().enumerate().any(|(k, &e)| e == sub || (e == dc && k + 1 != n));
                    if !found {
                        restore = Some(self.templates);
                        self.templates = templates;
                    }
                }
            }
            let mut a = self.lookup_template_argument(sub);
            if let Some(x) = a {
                if self.t(x) == T::TemplateArglist {
                    a = self.index_template_argument(Some(x), self.pack_index);
                }
            }
            let Some(a) = a else {
                if let Some(saved) = restore {
                    self.templates = saved;
                }
                self.fail();
                return;
            };
            sub = a;
        }
        let st = self.t(sub);
        if st == T::Reference || st == self.t(dc) {
            dc = sub;
        } else if st == T::RvalueReference {
            mod_inner = self.left(sub);
        }
        self.modifier(dc, mod_inner, restore);
    }

    /// `DEMANGLE_COMPONENT_ARRAY_TYPE` of `d_print_comp_inner`.
    fn array(&mut self, dc: Id) {
        let hold = self.modifiers;
        let base = self.mods.len();
        self.mods.extend([NO_MOD; 4]);
        self.mods[base] = Mod { next: hold, m: dc, printed: false, templates: self.templates };
        self.modifiers = Some(base);
        let mut i = 1usize;
        let mut pd = hold;
        while let Some(pi) = pd {
            if !matches!(self.t(self.mods[pi].m), T::Restrict | T::Volatile | T::Const) {
                break;
            }
            if !self.mods[pi].printed {
                if i >= 4 {
                    self.fail();
                    return;
                }
                self.mods[base + i] = self.mods[pi];
                self.mods[base + i].next = self.modifiers;
                self.modifiers = Some(base + i);
                self.mods[pi].printed = true;
                i += 1;
            }
            pd = self.mods[pi].next;
        }
        self.comp(self.right(dc));
        self.modifiers = hold;
        if self.mods[base].printed {
            return;
        }
        while i > 1 {
            i -= 1;
            self.print_mod(self.mods[base + i].m);
        }
        self.array_type(dc, self.modifiers);
    }

    /// `DEMANGLE_COMPONENT_UNARY` of `d_print_comp_inner`.
    fn unary(&mut self, dc: Id) {
        let op = self.left(dc);
        let mut operand = self.right(dc);
        let mut code: Option<&[u8]> = None;
        if self.tt(op) == Some(T::Operator) {
            let c = self.code(op);
            code = Some(c);
            if c == b"ad" {
                if let Some(o) = operand {
                    if self.t(o) == T::TypedName
                        && self.tt(self.left(o)) == Some(T::QualName)
                        && self.tt(self.right(o)) == Some(T::FunctionType)
                    {
                        operand = self.left(o);
                    }
                }
            }
            if self.tt(operand) == Some(T::BinaryArgs) {
                operand = operand.and_then(|o| self.left(o));
                self.subexpr(operand);
                self.expr_op(op);
                return;
            }
        }
        if code == Some(b"sZ") {
            let a = self.find_pack(operand);
            let len = self.pack_length(a);
            self.num(len);
            return;
        } else if code == Some(b"sP") {
            let len = self.args_length(operand);
            self.num(len);
            return;
        }
        if self.tt(op) != Some(T::Cast) {
            self.expr_op(op);
        } else {
            self.ch(b'(');
            self.comp(op.and_then(|o| self.left(o)));
            self.ch(b')');
        }
        if code == Some(b"gs") {
            self.comp(operand);
        } else if code == Some(b"st") || code == Some(b"nx") {
            self.ch(b'(');
            self.comp(operand);
            self.ch(b')');
        } else {
            self.subexpr(operand);
        }
    }

    fn op_is_new_cast(&self, op: Option<Id>) -> bool {
        let code = self.code(op);
        code[1] == b'c' && matches!(code[0], b's' | b'd' | b'c' | b'r')
    }

    /// `DEMANGLE_COMPONENT_BINARY` of `d_print_comp_inner`.
    fn binary(&mut self, dc: Id) {
        let Some(args) = self.right(dc).filter(|&r| self.t(r) == T::BinaryArgs) else {
            self.fail();
            return;
        };
        let op = self.left(dc);
        if self.op_is_new_cast(op) {
            self.expr_op(op);
            self.ch(b'<');
            self.comp(self.left(args));
            self.s(b">(");
            self.comp(self.right(args));
            self.ch(b')');
            return;
        }
        if self.maybe_fold(dc) || self.maybe_designated_init(dc) {
            return;
        }
        let gt = op.and_then(|o| self.c[o].op).is_some_and(|o| o.name == ">") && self.tt(op) == Some(T::Operator);
        if gt {
            self.ch(b'(');
        }
        let code = self.code(op);
        if code == b"cl" && self.tt(self.left(args)) == Some(T::TypedName) {
            let func = self.left(args).unwrap_or_default();
            if self.tt(self.right(func)) != Some(T::FunctionType) {
                self.fail();
            }
            self.subexpr(self.left(func));
        } else {
            self.subexpr(self.left(args));
        }
        if code == b"ix" {
            self.ch(b'[');
            self.comp(self.right(args));
            self.ch(b']');
        } else {
            if code != b"cl" {
                self.expr_op(op);
            }
            self.subexpr(self.right(args));
        }
        if gt {
            self.ch(b')');
        }
    }

    /// `DEMANGLE_COMPONENT_TRINARY` of `d_print_comp_inner`.
    fn trinary(&mut self, dc: Id) {
        let a1 = self.right(dc).filter(|&r| self.t(r) == T::TrinaryArg1);
        let Some((a1, a2)) = a1.and_then(|a| self.right(a).filter(|&r| self.t(r) == T::TrinaryArg2).map(|b| (a, b)))
        else {
            self.fail();
            return;
        };
        if self.maybe_fold(dc) || self.maybe_designated_init(dc) {
            return;
        }
        let op = self.left(dc);
        let (first, second, third) = (self.left(a1), self.left(a2), self.right(a2));
        if self.code(op) == b"qu" {
            self.subexpr(first);
            self.expr_op(op);
            self.subexpr(second);
            self.s(b" : ");
            self.subexpr(third);
        } else {
            self.s(b"new ");
            if first.and_then(|f| self.left(f)).is_some() {
                self.subexpr(first);
                self.ch(b' ');
            }
            self.comp(second);
            if third.is_some() {
                self.subexpr(third);
            }
        }
    }

    /// `DEMANGLE_COMPONENT_LITERAL` / `LITERAL_NEG` of `d_print_comp_inner`.
    fn literal(&mut self, dc: Id) {
        let c = self.c[dc];
        let mut tp = Pr::Default;
        let right = c.right.map(|r| self.c[r]);
        if let Some(b) = c.left.filter(|&l| self.t(l) == T::BuiltinType).and_then(|l| self.c[l].bt) {
            tp = b.print;
            match tp {
                Pr::Int | Pr::Unsigned | Pr::Long | Pr::UnsignedLong | Pr::LongLong | Pr::UnsignedLongLong => {
                    if right.is_some_and(|r| r.t == T::Name) {
                        if c.t == T::LiteralNeg {
                            self.ch(b'-');
                        }
                        self.comp(c.right);
                        let suffix: &[u8] = match tp {
                            Pr::Unsigned => b"u",
                            Pr::Long => b"l",
                            Pr::UnsignedLong => b"ul",
                            Pr::LongLong => b"ll",
                            Pr::UnsignedLongLong => b"ull",
                            _ => b"",
                        };
                        self.s(suffix);
                        return;
                    }
                }
                Pr::Bool => {
                    if let Some(r) = right.filter(|r| r.t == T::Name && r.s.len() == 1 && c.t == T::Literal) {
                        match r.s[0] {
                            b'0' => return self.s(b"false"),
                            b'1' => return self.s(b"true"),
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }
        self.ch(b'(');
        self.comp(c.left);
        self.ch(b')');
        if c.t == T::LiteralNeg {
            self.ch(b'-');
        }
        if tp == Pr::Float {
            self.ch(b'[');
        }
        self.comp(c.right);
        if tp == Pr::Float {
            self.ch(b']');
        }
    }

    /// `DEMANGLE_COMPONENT_LAMBDA` of `d_print_comp_inner`.
    fn lambda(&mut self, dc: Id) {
        self.s(b"{lambda");
        let mut parms = self.left(dc);
        let saved_tpl_parms = self.lambda_tpl_parms;
        self.lambda_tpl_parms = 0;
        let saved_templates = self.templates;
        let dpt = self.push_tpl(None);
        self.templates = Some(dpt);
        if let Some(head) = parms.filter(|&p| self.t(p) == T::TemplateHead) {
            self.tpl[dpt].decl = Some(head);
            self.ch(b'<');
            let mut parm = self.left(head);
            while let Some(p) = parm {
                if self.lambda_tpl_parms != 0 {
                    self.s(b", ");
                }
                self.lambda_tpl_parms += 1;
                self.comp(Some(p));
                self.ch(b' ');
                let mut q = Some(p);
                if self.t(p) == T::TemplatePackParm {
                    q = self.left(p);
                }
                match q {
                    Some(q) => self.lambda_parm_name(self.t(q), self.lambda_tpl_parms - 1),
                    None => self.fail(),
                }
                parm = q.and_then(|q| self.right(q));
            }
            self.ch(b'>');
            parms = self.right(head);
        }
        self.lambda_tpl_parms += 1;
        self.ch(b'(');
        self.comp(parms);
        self.lambda_tpl_parms = saved_tpl_parms;
        self.templates = saved_templates;
        self.s(b")#");
        self.num(self.c[dc].num as i32 + 1);
        self.ch(b'}');
    }

    /// `d_print_mod_list`.
    fn print_mod_list(&mut self, mods: Option<usize>, suffix: bool) {
        let Some(mi) = mods else { return };
        if self.failure {
            return;
        }
        let m = self.mods[mi];
        let mt = self.t(m.m);
        if m.printed || (!suffix && is_fnqual(mt)) {
            self.print_mod_list(m.next, suffix);
            return;
        }
        self.mods[mi].printed = true;
        let hold = self.templates;
        self.templates = m.templates;
        match mt {
            T::FunctionType => {
                self.function_type(m.m, m.next);
                self.templates = hold;
                return;
            }
            T::ArrayType => {
                self.array_type(m.m, m.next);
                self.templates = hold;
                return;
            }
            T::LocalName => {
                let hm = self.modifiers;
                self.modifiers = None;
                self.comp(self.left(m.m));
                self.modifiers = hm;
                self.s(b"::");
                let mut d = self.right(m.m);
                if let Some(di) = d.filter(|&x| self.t(x) == T::DefaultArg) {
                    self.s(b"{default arg#");
                    self.num(self.c[di].num as i32 + 1);
                    self.s(b"}::");
                    d = self.left(di);
                }
                while let Some(di) = d.filter(|&x| is_fnqual(self.t(x))) {
                    d = self.left(di);
                }
                self.comp(d);
                self.templates = hold;
                return;
            }
            _ => {}
        }
        self.print_mod(m.m);
        self.templates = hold;
        self.print_mod_list(m.next, suffix);
    }

    /// `d_print_mod`.
    fn print_mod(&mut self, m: Id) {
        use T::*;
        match self.t(m) {
            Restrict | RestrictThis => self.s(b" restrict"),
            Volatile | VolatileThis => self.s(b" volatile"),
            Const | ConstThis => self.s(b" const"),
            TransactionSafe => self.s(b" transaction_safe"),
            Noexcept | ThrowSpec => {
                self.s(if self.t(m) == Noexcept { b" noexcept" } else { b" throw" });
                if self.right(m).is_some() {
                    self.ch(b'(');
                    self.comp(self.right(m));
                    self.ch(b')');
                }
            }
            VendorTypeQual => {
                self.ch(b' ');
                self.comp(self.right(m));
            }
            Pointer => self.ch(b'*'),
            ReferenceThis => self.s(b" &"),
            Reference => self.ch(b'&'),
            RvalueReferenceThis => self.s(b" &&"),
            RvalueReference => self.s(b"&&"),
            Complex => self.s(b" _Complex"),
            Imaginary => self.s(b" _Imaginary"),
            PtrmemType => {
                if self.last != b'(' {
                    self.ch(b' ');
                }
                self.comp(self.left(m));
                self.s(b"::*");
            }
            TypedName => self.comp(self.left(m)),
            VectorType => {
                self.s(b" __vector(");
                self.comp(self.left(m));
                self.ch(b')');
            }
            _ => self.comp(Some(m)),
        }
    }

    /// `d_print_function_type`.
    fn function_type(&mut self, dc: Id, mods: Option<usize>) {
        use T::*;
        let (mut need_paren, mut need_space) = (false, false);
        let mut p = mods;
        while let Some(pi) = p {
            if self.mods[pi].printed {
                break;
            }
            match self.t(self.mods[pi].m) {
                Pointer | Reference | RvalueReference => need_paren = true,
                Restrict | Volatile | Const | VendorTypeQual | Complex | Imaginary | PtrmemType => {
                    need_space = true;
                    need_paren = true;
                }
                _ => {}
            }
            if need_paren {
                break;
            }
            p = self.mods[pi].next;
        }
        if need_paren {
            if !need_space && self.last != b'(' && self.last != b'*' {
                need_space = true;
            }
            if need_space && self.last != b' ' {
                self.ch(b' ');
            }
            self.ch(b'(');
        }
        let hold = self.modifiers;
        self.modifiers = None;
        self.print_mod_list(mods, false);
        if need_paren {
            self.ch(b')');
        }
        self.ch(b'(');
        if self.right(dc).is_some() {
            self.comp(self.right(dc));
        }
        self.ch(b')');
        self.print_mod_list(mods, true);
        self.modifiers = hold;
    }

    /// `d_print_array_type`.
    fn array_type(&mut self, dc: Id, mods: Option<usize>) {
        let mut need_space = true;
        if mods.is_some() {
            let mut need_paren = false;
            let mut p = mods;
            while let Some(pi) = p {
                if !self.mods[pi].printed {
                    if self.t(self.mods[pi].m) == T::ArrayType {
                        need_space = false;
                    } else {
                        need_paren = true;
                        need_space = true;
                    }
                    break;
                }
                p = self.mods[pi].next;
            }
            if need_paren {
                self.s(b" (");
            }
            self.print_mod_list(mods, false);
            if need_paren {
                self.ch(b')');
            }
        }
        if need_space {
            self.ch(b' ');
        }
        self.ch(b'[');
        if self.left(dc).is_some() {
            self.comp(self.left(dc));
        }
        self.ch(b']');
    }

    /// `d_print_expr_op`.
    fn expr_op(&mut self, dc: Option<Id>) {
        match dc.filter(|&d| self.t(d) == T::Operator) {
            Some(d) => self.s(self.c[d].op.map_or("", |o| o.name).as_bytes()),
            None => self.comp(dc),
        }
    }

    /// `d_print_conversion`.
    fn conversion(&mut self, dc: Id) {
        let saved = self.templates;
        if self.current_template.is_some() {
            let t = self.push_tpl(self.current_template);
            self.templates = Some(t);
        }
        self.comp(self.left(dc));
        if self.current_template.is_some() {
            self.templates = saved;
        }
    }
}

/// `cplus_demangle_print_callback`: `None` where the printer saw an error.
fn print(comps: &[Comp], dc: Id) -> Result<Option<Vec<u8>>, Error> {
    let mut p = P {
        c: comps,
        out: Vec::new(),
        last: 0,
        printing: vec![0; comps.len()],
        counting: vec![0; comps.len()],
        templates: None,
        tpl: Vec::new(),
        modifiers: None,
        mods: Vec::new(),
        failure: false,
        limited: false,
        recursion: 0,
        lambda_tpl_parms: 0,
        pack_index: 0,
        stack: Vec::new(),
        saved_scopes: Vec::new(),
        num_saved_scopes: 0,
        next_copy_template: 0,
        num_copy_templates: 0,
        current_template: None,
    };
    p.count_templates_scopes(Some(dc));
    if p.recursion < RECURSION_LIMIT as i32 {
        p.recursion = 0;
    }
    p.num_copy_templates *= p.num_saved_scopes;
    p.comp(Some(dc));
    if p.limited {
        return Err(Error(format!("not demangled: limit (the text passes {OUT_LIMIT} bytes)")));
    }
    Ok((!p.failure).then_some(p.out))
}

/// `d_demangle_callback` with `DMGL_PARAMS | DMGL_ANSI | DMGL_VERBOSE`.
fn d_demangle(mangled: &[u8]) -> Result<Option<Vec<u8>>, Error> {
    let at = |i: usize| mangled.get(i).copied().unwrap_or(0);
    let global = if mangled.starts_with(b"_Z") {
        None
    } else if mangled.starts_with(b"_GLOBAL_")
        && matches!(at(8), b'.' | b'_' | b'$')
        && matches!(at(9), b'D' | b'I')
        && at(10) == b'_'
    {
        Some(if at(9) == b'I' { T::GlobalConstructors } else { T::GlobalDestructors })
    } else {
        // DMGL_TYPES is not set
        return Ok(None);
    };
    let mut state = 1;
    loop {
        if 2 * mangled.len() > RECURSION_LIMIT as usize {
            return Ok(None);
        }
        let mut d = D::new(mangled, state);
        let mut dc = match global {
            None => d.mangled_name(true),
            Some(t) => {
                d.advance(11);
                let inner = d.make_demangle_mangled_name();
                let dc = d.make_comp(t, inner, None);
                d.n = mangled.len();
                dc
            }
        };
        if d.peek() != 0 {
            dc = None;
        }
        if dc.is_none() && d.unresolved_name_state == -1 {
            state = 0;
            continue;
        }
        return dc.map_or(Ok(None), |dc| print(&d.comps, dc));
    }
}

/// `rust_demangle_callback`'s checks before it parses: whether the auto style would take the
/// symbol as Rust (v0, or legacy with its `17h<hash>E` tail). Its parse is not ported.
fn looks_rust(m: &[u8]) -> bool {
    let (sym, legacy) = if m.starts_with(b"_R") {
        (&m[2..], false)
    } else if m.starts_with(b"_ZN") {
        (&m[3..], true)
    } else {
        return false;
    };
    if !legacy && !sym.first().is_some_and(u8::is_ascii_uppercase) {
        return false;
    }
    let mut len = 0;
    for &c in sym {
        if !legacy && c == b'.' {
            break;
        }
        len += 1;
        if c == b'_' || c.is_ascii_alphanumeric() || (legacy && b"$.:@".contains(&c)) {
            continue;
        }
        return false;
    }
    if !legacy {
        return true;
    }
    let mut dot_suffix = true;
    while len > 0 && !(dot_suffix && sym[len - 1] == b'E') {
        dot_suffix = sym[len - 1] == b'.';
        len -= 1;
    }
    if !(len > 0 && sym[len - 1] == b'E') {
        return false;
    }
    len -= 1;
    if !(len > 19 && &sym[len - 19..len - 16] == b"17h") {
        return false;
    }
    // the first pass of `parse_ident` over the segments, then `is_legacy_prefixed_hash`
    let (mut next, mut last) = (0usize, (0usize, 0usize));
    while next < len {
        let c = sym[next];
        next += 1;
        if !c.is_ascii_digit() {
            return false;
        }
        let mut l = (c - b'0') as usize;
        if c != b'0' {
            while next < len && sym[next].is_ascii_digit() {
                let Some(v) = l.checked_mul(10).and_then(|v| v.checked_add((sym[next] - b'0') as usize)) else {
                    return false;
                };
                l = v;
                next += 1;
            }
        }
        let start = next;
        next = match start.checked_add(l) {
            Some(n) if n <= len && l > 0 => n,
            _ => return false,
        };
        last = (start, l);
    }
    let (start, l) = last;
    if l != 17 || sym[start] != b'h' {
        return false;
    }
    let mut seen = 0u16;
    for &c in &sym[start + 1..start + 17] {
        let nibble = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => return false,
        };
        seen |= 1 << nibble;
    }
    seen.count_ones() >= 5
}

/// `cplus_demangle(mangled, DMGL_PARAMS | DMGL_ANSI | DMGL_VERBOSE)` in the auto style: Rust
/// first (not ported: an error where the symbol could be Rust), then the V3 ABI. `Ok(None)` where
/// it returns `NULL`.
pub fn cplus_demangle(mangled: &[u8]) -> Result<Option<Vec<u8>>, Error> {
    on_big_stack(|| cplus_demangle_here(mangled))
}

fn cplus_demangle_here(mangled: &[u8]) -> Result<Option<Vec<u8>>, Error> {
    if looks_rust(mangled) {
        return Err(Error("not ported: a Rust symbol (rust-demangle.c)".into()));
    }
    d_demangle(mangled)
}

/// Runs `f` on a thread of its own with a `STACK`-byte stack, so the recursion of a hostile
/// name cannot overflow the caller's (a default thread has 2 MiB, the main one 8 MiB).
fn on_big_stack<T: Send>(f: impl FnOnce() -> Result<T, Error> + Send) -> Result<T, Error> {
    std::thread::scope(|s| {
        let job = std::thread::Builder::new()
            .stack_size(STACK)
            .spawn_scoped(s, f)
            .map_err(|e| Error(format!("the demangler thread: {e}")))?;
        job.join().unwrap_or_else(|p| std::panic::resume_unwind(p))
    })
}

/// The line `demangler_gnu_v2_41` (its `cxxfilt.c` main loop and `demangle_it`, no options) prints
/// for one input line, as `GnuDemanglerNativeProcess.demangle` reads it back: each run of
/// `[A-Za-z0-9_$.]` (at most 32,766 characters) demangled, or echoed where it does not demangle,
/// and every other character echoed. The output bytes are read as UTF-8 (lossy), as Java reads
/// them on a UTF-8 platform.
pub fn native_demangle(line: &str) -> Result<String, Error> {
    on_big_stack(|| native_demangle_here(line))
}

fn native_demangle_here(line: &str) -> Result<String, Error> {
    let b = line.as_bytes();
    let valid = |c: u8| c.is_ascii_alphanumeric() || b"_$.".contains(&c);
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let start = i;
        while i < b.len() && valid(b[i]) && i - start < 32766 {
            i += 1;
        }
        let tok = &b[start..i];
        if !tok.is_empty() {
            let skip = usize::from(tok[0] == b'.' || tok[0] == b'$');
            match cplus_demangle_here(&tok[skip..])? {
                None => out.extend_from_slice(tok),
                Some(r) => {
                    if tok[0] == b'.' {
                        out.push(b'.');
                    }
                    out.extend_from_slice(&r);
                }
            }
        }
        if i < b.len() {
            out.push(b[i]);
            i += 1;
        }
    }
    Ok(String::from_utf8_lossy(&out).into_owned())
}

/// `GnuDemangler.demangle` with the Demangler analyzer's options: this native half under the
/// parser of `gnuparse` (the entry an ELF program's symbols go through; Ghidra's
/// `GnuDemangler.canDemangle` takes ELF and Mach-O programs, `MicrosoftDemangler` the Windows PE
/// ones).
pub fn gnu_demangle(mangled: &str) -> Result<Option<crate::gnuparse::GnuDemangled>, Error> {
    on_big_stack(|| crate::gnuparse::demangle(mangled, |s| native_demangle_here(s).map(Some)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dm(s: &str) -> String {
        cplus_demangle(s.as_bytes()).unwrap().map(|v| String::from_utf8(v).unwrap()).unwrap_or_default()
    }

    /// Expectations are the native `demangler_gnu_v2_41`'s output.
    #[test]
    fn substitutions_and_templates() {
        // S_ / S0_ back references, the verbose std::string expansion
        assert_eq!(
            dm("_ZN9__gnu_cxx13new_allocatorIcE8allocateEmPKv"),
            "__gnu_cxx::new_allocator<char>::allocate(unsigned long, void const*)"
        );
        assert_eq!(
            dm("_ZNSs4_Rep10_M_disposeERKSaIcE"),
            "std::basic_string<char, std::char_traits<char>, std::allocator<char> >::_Rep::_M_dispose(std::allocator<char> const&)"
        );
        // a template parameter standing for a function's return type, `> >` spacing
        assert_eq!(dm("_Z1fIiEvT_"), "void f<int>(int)");
        assert_eq!(dm("_Z1fI1AIS0_EEvv"), "void f<A<A> >()");
    }

    #[test]
    fn ctors_dtors_operators() {
        assert_eq!(dm("_ZN1AC2Ev"), "A::A()");
        assert_eq!(dm("_ZN1AD0Ev"), "A::~A()");
        assert_eq!(dm("_ZN1AplERKS_"), "A::operator+(A const&)");
        assert_eq!(dm("_ZN1AcviEv"), "A::operator int()");
        assert_eq!(dm("_ZThn8_N1A1fEv"), "non-virtual thunk to A::f()");
        assert_eq!(dm("_ZTV1A"), "vtable for A");
    }

    #[test]
    fn function_pointers_and_qualifiers() {
        assert_eq!(dm("_Z1fPFivE"), "f(int (*)())");
        assert_eq!(dm("_Z1fRA10_i"), "f(int (&) [10])");
        assert_eq!(dm("_ZNK1A1fEv"), "A::f() const");
        assert_eq!(dm("_Z1fM1AKFvvE"), "f(void (A::*)() const)");
    }

    /// GCC 4.4 has no lambdas (they came with 4.5); this is a later GCC's mangling.
    #[test]
    fn lambdas_and_local_names() {
        assert_eq!(dm("_ZZ4mainENKUlvE_clEv"), "main::{lambda()#1}::operator()() const");
        assert_eq!(dm("_ZZ1fvE1x"), "f()::x");
    }

    #[test]
    fn failures() {
        assert_eq!(dm("_Z"), "");
        assert_eq!(dm("foo"), "");
        // longer than 1,024 characters: binutils 2.41 refuses it
        assert_eq!(dm(&format!("_Z{}{}v", 1100, "a".repeat(1100))), "");
        assert!(cplus_demangle(b"_ZN3foo17h0123456789abcdefE").is_err());
        assert_eq!(native_demangle("_ZN1AC2Ev x").unwrap(), "A::A() x");
    }

    #[test]
    fn through_the_parser() {
        let d = gnu_demangle("_ZNK1A1B1fEi").unwrap().unwrap();
        assert_eq!(d.qualified_name().as_deref(), Some("A::B::f"));
        assert_eq!(d.namespace_string().as_deref(), Some("A::B"));
        assert!(d.is_const);
        assert!(gnu_demangle("_ZN1x@@GLIBC").unwrap().is_none());
    }
}
