//! `print C`, layer three: port of the parts of `PrintC` (printc.cc) the checks reach: the
//! header comments, the declaration, the local variable declarations, every structured block
//! (lists, if/else with the `else if` merge, while, for, do-while, infinite loops, `&&`/`||`
//! conditions, switch with its case labels, gotos, labels, break and continue), and statements
//! of assignments, loads, stores, direct calls, returns and branches over the arithmetic, logic
//! and comparison operators, casts (`opTypeCast`), extensions and SUBPIECE (cast, hidden,
//! `ZEXT14(x)` style or a field extraction: `sym.field`, `x.field`; slice 4), the operators in
//! functional syntax (`CARRY4`, `SCARRY4`, `SBORROW4`, `CONCAT44`, `POPCOUNT`, `LZCOUNT`) and
//! CALLOTHER of a SLEIGH user-op under its name (slice 4), direct and indirect calls
//! (`(*fn)(args)`), the float operators and
//! conversions, constants (float constants as `printDecimal` prints them, character constants)
//! and variables, array and field access (`PTRADD`, `PTRSUB`, LOAD and STORE through them, parts
//! of symbols; slice 3A), the names of anonymous data-types (`genericTypeName`), and the body
//! comments (the warnings at an address, placed by `CommentSorter`, comment.rs; slice 3B).
//! Slice 5: the label of a spliced block (`BlockBasic::getEntryAddr` over the merged cover),
//! a global variable that is a whole function or external reference symbol (its name), string
//! constants (`pushPtrCharConstant`, the string read as `StringManagerUnicode` reads it) and
//! function pointer constants (`pushPtrCodeConstant`, the function's name).
//!
//! Every construct the C++ would print that is not ported fails with an error naming it, so a
//! function prints identically or not at all. Not ported yet: the long suffix of a constant, a
//! cast to a pointer to an array (`checkAddressOfCast`), the label of a block of several ranges
//! without ops, a variable that is part of an external reference or larger than the function or
//! external reference at its address (`pushPartialSymbol` of a code pointer,
//! `pushMismatchSymbol`), a function that writes read-only memory (the warning of
//! `fillinReadOnly` is not ported), unions, `TypePointerRel`, CALLOTHER of a built-in user-op, the
//! bit-field operators (`INSERT`, `ZPULL`, `SPULL`), `SEGMENTOP`, `CPOOLREF` and `NEW`.
//! (Superseded: "labels of spliced blocks, strings", before slice 5; "and the remaining
//! operators", before slice 4. Slice 1 had no casts or structured
//! blocks, slice 2 no field and array access, characters, comments, floats, indirect calls or
//! anonymous types; superseded.)

use super::finalstructure::{
    case_label_list, switch_leaf, switch_table, CaseOrder, F_BREAK_GOTO, F_CONTINUE_GOTO, F_GOTO_GOTO, F_LABEL_BUMPUP,
    F_UNSTRUCTURED_TARG,
};
use super::namevars::SymRef;
use super::op::{Halt, OpFlags, OpId};
use super::opcode::Opcode;
use super::prettyprint::BraceStyle;
use super::printlanguage::{modifier, most_natural_base, Atom, OpToken, PrintC, TokenType, MAX_DEPTH};
use super::returnsplit::{front_leaf, goto_prints};
use super::scope::{SymbolId, LOCAL};
use super::structure::{Kind, SId, F_WHILEDO_OVERFLOW};
use super::types::{Kind as TKind, Meta, TypeId};
use super::varnode::{Space, VarnodeId, VnFlags};
use super::{err, Arch, Funcdata, LowlevelError, Result};

macro_rules! token {
    ($name:ident, $p1:expr, $p2:expr, $stage:expr, $prec:expr, $assoc:expr, $ty:ident, $sp:expr, $bump:expr) => {
        pub(crate) static $name: OpToken = OpToken {
            print1: $p1,
            print2: $p2,
            stage: $stage,
            precedence: $prec,
            associative: $assoc,
            ty: TokenType::$ty,
            spacing: $sp,
            bump: $bump,
        };
    };
}

// The `PrintC` tokens (printc.cc) the slice uses.
token!(FUNCTION_CALL, "(", ")", 2, 66, false, Postsurround, 0, 10);
token!(BITWISE_NOT, "~", "", 1, 62, false, UnaryPrefix, 0, 0);
token!(BOOLEAN_NOT, "!", "", 1, 62, false, UnaryPrefix, 0, 0);
token!(UNARY_MINUS, "-", "", 1, 62, false, UnaryPrefix, 0, 0);
token!(DEREFERENCE, "*", "", 1, 62, false, UnaryPrefix, 0, 0);
token!(HIDDEN, "", "", 1, 70, false, HiddenFunction, 0, 0);
token!(TYPECAST, "(", ")", 2, 62, false, Presurround, 0, 0);
token!(MULTIPLY, "*", "", 2, 54, true, Binary, 1, 0);
token!(DIVIDE, "/", "", 2, 54, false, Binary, 1, 0);
token!(MODULO, "%", "", 2, 54, false, Binary, 1, 0);
token!(BINARY_PLUS, "+", "", 2, 50, true, Binary, 1, 0);
token!(BINARY_MINUS, "-", "", 2, 50, false, Binary, 1, 0);
token!(SHIFT_LEFT, "<<", "", 2, 46, false, Binary, 1, 0);
token!(SHIFT_RIGHT, ">>", "", 2, 46, false, Binary, 1, 0);
token!(SHIFT_SRIGHT, ">>", "", 2, 46, false, Binary, 1, 0);
token!(LESS_THAN, "<", "", 2, 42, false, Binary, 1, 0);
token!(LESS_EQUAL, "<=", "", 2, 42, false, Binary, 1, 0);
token!(GREATER_THAN, ">", "", 2, 42, false, Binary, 1, 0);
token!(GREATER_EQUAL, ">=", "", 2, 42, false, Binary, 1, 0);
token!(EQUAL, "==", "", 2, 38, false, Binary, 1, 0);
token!(NOT_EQUAL, "!=", "", 2, 38, false, Binary, 1, 0);
token!(BITWISE_AND, "&", "", 2, 34, true, Binary, 1, 0);
token!(BITWISE_XOR, "^", "", 2, 30, true, Binary, 1, 0);
token!(BITWISE_OR, "|", "", 2, 26, true, Binary, 1, 0);
token!(BOOLEAN_AND, "&&", "", 2, 22, false, Binary, 1, 0);
token!(BOOLEAN_XOR, "^^", "", 2, 20, false, Binary, 1, 0);
token!(BOOLEAN_OR, "||", "", 2, 18, false, Binary, 1, 0);
token!(ASSIGNMENT, "=", "", 2, 14, false, Binary, 1, 5);
token!(COMMA, ",", "", 2, 2, true, Binary, 0, 0);
token!(TYPE_EXPR_SPACE, "", "", 2, 10, false, Space, 1, 0);
token!(TYPE_EXPR_NOSPACE, "", "", 2, 10, false, Space, 0, 0);
token!(PTR_EXPR, "*", "", 1, 62, false, UnaryPrefix, 0, 0);
token!(ARRAY_EXPR, "[", "]", 2, 66, false, Postsurround, 1, 0);
token!(OBJECT_MEMBER, ".", "", 2, 66, true, Binary, 0, 0);
token!(POINTER_MEMBER, "->", "", 2, 66, true, Binary, 0, 0);
token!(SUBSCRIPT, "[", "]", 2, 66, false, Postsurround, 0, 0);
token!(ADDRESSOF, "&", "", 1, 62, false, UnaryPrefix, 0, 0);

/// `OpToken::negate` (set in the `PrintC` constructor): the flipped comparison.
pub(crate) fn negate(tok: &'static OpToken) -> Option<&'static OpToken> {
    let pairs: [(&'static OpToken, &'static OpToken); 6] = [
        (&LESS_THAN, &GREATER_EQUAL),
        (&LESS_EQUAL, &GREATER_THAN),
        (&GREATER_THAN, &LESS_EQUAL),
        (&GREATER_EQUAL, &LESS_THAN),
        (&EQUAL, &NOT_EQUAL),
        (&NOT_EQUAL, &EQUAL),
    ];
    pairs.iter().find(|(t, _)| std::ptr::eq(*t, tok)).map(|&(_, n)| n)
}

/// `print C` (`IfcPrintCStruct`, `PrintC::docFunction`): the function `name` as C.
pub fn print_c(fd: &mut Funcdata, arch: &Arch, name: &str) -> Result<String> {
    fd.fill_comment_cache();
    if fd.structure.is_empty() {
        return err("Function not fully decompiled. No structure present.");
    }
    if fd.readonly_write || super::action::readonly_written(fd, arch) {
        return err("print C: the warning for a written read-only address (fillinReadOnly) is not ported");
    }
    let mut p = PrintC::new(fd, arch);
    p.doc_function(name)?;
    p.emit.flush().map_err(LowlevelError)
}

/// `AddrSpace::printRaw` for an address size `size`, wordsize 1.
fn raw_offset(size: u32, off: u64) -> String {
    let sz = match size {
        s if s > 4 && off >> 32 == 0 => 4,
        s if s > 4 && off >> 48 == 0 => 6,
        s => s,
    };
    format!("0x{off:0w$x}", w = 2 * sz as usize)
}

/// `calc_mask`
fn calc_mask(size: u32) -> u64 {
    if size >= 8 {
        u64::MAX
    } else {
        (1u64 << (8 * size)) - 1
    }
}

/// Port of `PrintC::genericTypeName`: the name printed for a data-type without one.
fn generic_type_name(meta: Meta, size: u32) -> String {
    let base = match meta {
        Meta::Int => "unkint",
        Meta::Uint => "unkuint",
        Meta::Unknown => "unkbyte",
        Meta::Float => "unkfloat",
        Meta::Spacebase => return "BADSPACEBASE".into(),
        _ => return "BADTYPE".into(),
    };
    format!("{base}{size}")
}

/// The token of `PrintC::push_float`: `INFINITY`, `NAN` (signed), or the shortest decimal
/// that reads back as the value, with `.0` when it would look like an integer. The x86
/// translator has float formats for sizes 4 and 8 only (`getFloatFormat`); any other size is
/// `FLOAT_UNKNOWN`. (`force_scinote` is never set.)
fn float_token(val: u64, size: u32) -> String {
    let (host, neg) = match size {
        4 => {
            let f = f32::from_bits(val as u32);
            (f64::from(f), f.is_sign_negative())
        }
        8 => {
            let f = f64::from_bits(val);
            (f, f.is_sign_negative())
        }
        _ => return "FLOAT_UNKNOWN".into(),
    };
    let sign = if neg { "-" } else { "" };
    if host.is_infinite() {
        return format!("{sign}INFINITY");
    }
    if host.is_nan() {
        return format!("{sign}NAN");
    }
    let mut t = print_decimal(host, size);
    if !t.contains(['.', 'e']) {
        t.push_str(".0");
    }
    t
}

/// Port of `FloatFormat::printDecimal` (not in scientific notation): `ostream << double` at
/// rising precision, from `decimalMinPrecision` until the text reads back as the value (as a
/// float for size 4), at most `decimalMaxPrecision`.
fn print_decimal(host: f64, size: u32) -> String {
    // floor(frac_size * 0.30103) and ceil((frac_size + 1) * 0.30103) + 1, frac_size 23 or 52
    let (min, max) = if size <= 4 { (6, 9) } else { (15, 17) };
    let mut res = String::new();
    for prec in min..=max {
        let s = format_g(host, prec);
        if prec == max {
            return s;
        }
        // `istream >> float` leaves 0.0 when it cannot read the text and the largest finite value
        // on overflow (libstdc++'s `__convert_to_v`)
        let back = if size <= 4 {
            s.parse::<f32>().map(|f| f64::from(if f.is_infinite() { f32::MAX.copysign(f) } else { f }))
        } else {
            s.parse::<f64>().map(|f| if f.is_infinite() { f64::MAX.copysign(f) } else { f })
        };
        let same = back.unwrap_or(0.0) == host;
        res = s;
        if same {
            break;
        }
    }
    res
}

/// `printf("%.*g", prec, v)`, as `ostream << double` prints in the default float field:
/// `prec` significant digits, scientific when the exponent is below -4 or at least `prec`,
/// trailing zeros removed.
fn format_g(v: f64, prec: usize) -> String {
    let p = prec.max(1);
    if v == 0.0 {
        return if v.is_sign_negative() { "-0" } else { "0" }.into();
    }
    let sci = format!("{:.*e}", p - 1, v);
    let Some((mant, exp)) = sci.split_once('e') else { return sci };
    let exp: i32 = exp.parse().unwrap_or(0);
    let strip = |s: &str| -> String {
        if s.contains('.') {
            s.trim_end_matches('0').trim_end_matches('.').to_string()
        } else {
            s.to_string()
        }
    };
    if exp < -4 || exp >= p as i32 {
        format!("{}e{}{:02}", strip(mant), if exp < 0 { '-' } else { '+' }, exp.unsigned_abs())
    } else {
        strip(&format!("{:.*}", (p as i32 - 1 - exp) as usize, v))
    }
}

impl PrintC<'_> {
    /// Port of `PrintC::docFunction`.
    fn doc_function(&mut self, name: &str) -> Result<()> {
        self.commsorter = super::comment::CommentSorter::setup_function_list(self.fd)?;
        if self.fd.proto.locked.is_some() {
            return err("print C: the declaration of a locked prototype is not ported");
        }
        self.emit.open_group(); // beginFunction
        self.emit_comment_func_header();
        self.emit.tag_line();
        self.emit_function_declaration(name)?;
        self.emit.open_brace_indent("{", BraceStyle::SkipLine);
        self.emit_local_var_decls()?;
        // emitBlockGraph on the structure's root
        for i in 0..self.fd.structure.size() {
            let b = self.fd.structure.get(i);
            self.emit_block(b)?;
        }
        self.emit.close_brace_indent("}");
        self.emit.tag_line();
        self.emit.close_group(); // endFunction
        Ok(())
    }

    /// Port of `PrintC::emitCommentFuncHeader`: the header warnings (`Funcdata::warningHeader`,
    /// stored once each with their prefix, the partial function's included).
    fn emit_comment_func_header(&mut self) {
        let warnings = self.fd.warnings.clone();
        for w in &warnings {
            self.emit_line_comment(0, w);
        }
        if !warnings.is_empty() {
            self.emit.tag_line();
        }
    }

    /// Port of `PrintLanguage::emitLineComment` with the C delimiters.
    fn emit_line_comment(&mut self, indent: i32, text: &str) {
        self.emit.tag_line_indent(indent);
        self.emit.start_comment();
        self.emit.print_str("/* ");
        let b = text.as_bytes();
        let mut pos = 0;
        while pos < b.len() {
            let c = b[pos];
            pos += 1;
            match c {
                b' ' | b'\t' => {
                    let mut count = 1;
                    while pos < b.len() && (b[pos] == b' ' || b[pos] == b'\t') {
                        count += 1;
                        pos += 1;
                    }
                    self.emit.spaces(count, 0);
                }
                b'\n' => self.emit.tag_line(),
                b'\r' => {}
                b'{' if b.get(pos) == Some(&b'@') => {
                    let start = pos - 1;
                    while pos < b.len() {
                        pos += 1;
                        if b[pos - 1] == b'}' {
                            break;
                        }
                    }
                    self.emit.print_str(&text[start..pos]);
                }
                _ => {
                    let start = pos - 1;
                    while pos < b.len() && !b[pos].is_ascii_whitespace() && b[pos] != 0x0b {
                        pos += 1;
                    }
                    self.emit.print_str(&text[start..pos]);
                }
            }
        }
        self.emit.print_str(" */");
        self.emit.stop_comment();
    }

    /// Port of `PrintC::emitFunctionDeclaration`.
    fn emit_function_declaration(&mut self, name: &str) -> Result<()> {
        self.emit.open_group(); // beginFuncProto
        self.emit_prototype_output()?;
        self.emit.spaces(1, 0);
        // option_convention: a model other than the default is printed (`printInDecl`)
        let models = &self.arch.spec.models;
        let model = self.fd.proto.model.ok_or_else(|| LowlevelError("print C: a prototype without a model".into()))?;
        if model != models.default {
            self.emit.print_str(&models.get(model).name);
            self.emit.spaces(1, 0);
        }
        self.emit.open_group();
        // emitSymbolScope: a function in the global scope needs no scope prefix
        self.emit.print_str(name);
        self.emit.spaces(FUNCTION_CALL.spacing, FUNCTION_CALL.bump);
        self.emit.open_paren("(");
        self.emit.spaces(0, FUNCTION_CALL.bump);
        self.emit_prototype_inputs()?;
        self.emit.close_paren(")");
        self.emit.close_group();
        self.emit.close_group(); // endFuncProto
        Ok(())
    }

    /// Port of `PrintC::emitPrototypeOutput`.
    fn emit_prototype_output(&mut self) -> Result<()> {
        let ty = match self.fd.proto.out_param {
            Some((_, _, t)) => t,
            None => self.fd.types.find_by_name("void").ok_or_else(|| LowlevelError("print C: no void type".into()))?,
        };
        self.emit.open_group(); // beginReturnType
        self.push_type(ty)?;
        self.recurse()?;
        self.emit.close_group();
        Ok(())
    }

    /// Port of `PrintC::emitPrototypeInputs`: the parameters are the symbols of category 0.
    fn emit_prototype_inputs(&mut self) -> Result<()> {
        let params = self.fd.symtab.category(LOCAL, 0);
        if params.is_empty() {
            self.emit.print_str("void");
        }
        for (i, &sym) in params.iter().enumerate() {
            if i > 0 {
                self.emit.print_str(",");
            }
            self.emit_var_decl(sym)?;
        }
        Ok(())
    }

    /// Port of `PrintC::emitLocalVarDecls` and `emitScopeVarDecls` on the local scope (it has
    /// no child scopes and no dynamic symbols here).
    fn emit_local_var_decls(&mut self) -> Result<()> {
        let mut notempty = false;
        for (sym, e) in self.fd.symtab.map_records(LOCAL) {
            let s = self.fd.symtab.symbol(sym);
            if s.entries[e].piece.is_some() || s.category.is_some() || s.name.is_empty() {
                continue;
            }
            // no symbol has several whole entries (`mergeMultiEntry` fails on one), so each is
            // declared at its entry (`getFirstWholeMap`)
            notempty = true;
            self.emit.tag_line();
            self.emit_var_decl(sym)?;
            self.emit.print_str(";");
        }
        if notempty {
            self.emit.tag_line();
        }
        Ok(())
    }

    /// Port of `PrintC::emitVarDecl`.
    fn emit_var_decl(&mut self, sym: SymbolId) -> Result<()> {
        let s = self.fd.symtab.symbol(sym);
        let ty = s.ty.ok_or_else(|| LowlevelError(format!("print C: symbol {} has no data-type", s.name)))?;
        let name = s.name.clone();
        self.emit.open_group(); // beginVarDecl
        self.push_type_start(ty, false)?;
        self.push_atom(Atom::Text(name))?; // pushSymbol
        self.push_type_end(ty)?;
        self.recurse()?;
        self.emit.close_group();
        Ok(())
    }

    /// Port of `PrintC::buildTypeStack`: the type, then what it points to or holds, down to
    /// the first named type.
    fn type_stack(&self, mut ty: TypeId) -> Result<Vec<TypeId>> {
        let mut stack = Vec::new();
        loop {
            stack.push(ty);
            if self.fd.types.name(ty).is_some_and(|n| !n.is_empty()) {
                break;
            }
            match self.fd.types.get(ty).kind {
                TKind::Pointer { to, .. } => ty = to,
                TKind::Array { elem, .. } => ty = elem,
                _ if self.fd.types.meta(ty) == Meta::Code => {
                    return err("print C: a function data-type in a declaration is not ported");
                }
                _ => break,
            }
        }
        Ok(stack)
    }

    /// Port of `PrintC::pushTypeStart`.
    fn push_type_start(&mut self, ty: TypeId, noident: bool) -> Result<()> {
        let stack = self.type_stack(ty)?;
        let base = *stack.last().ok_or_else(|| LowlevelError("print C: empty type stack".into()))?;
        let tok = if noident && stack.len() == 1 { &TYPE_EXPR_NOSPACE } else { &TYPE_EXPR_SPACE };
        let name = match self.fd.types.name(base).filter(|n| !n.is_empty()) {
            Some(n) => n.to_string(),
            None => generic_type_name(self.fd.types.meta(base), self.fd.types.size(base)),
        };
        self.push_op(tok)?;
        self.push_atom(Atom::Text(name))?;
        for &t in stack[..stack.len() - 1].iter().rev() {
            match self.fd.types.get(t).kind {
                TKind::Pointer { .. } => self.push_op(&PTR_EXPR)?,
                TKind::Array { .. } => self.push_op(&ARRAY_EXPR)?,
                _ => return err("Bad type expression"),
            }
        }
        Ok(())
    }

    /// Port of `PrintC::pushTypeEnd`: the array sizes, in decimal.
    fn push_type_end(&mut self, mut ty: TypeId) -> Result<()> {
        self.push_mod();
        self.set_mod(modifier::FORCE_DEC);
        loop {
            if self.fd.types.name(ty).is_some_and(|n| !n.is_empty()) {
                break;
            }
            match self.fd.types.get(ty).kind {
                TKind::Pointer { to, .. } => ty = to,
                TKind::Array { elem, count } => {
                    self.push_integer(u64::from(count), 4, false, None)?;
                    ty = elem;
                }
                _ => break,
            }
        }
        self.pop_mod();
        Ok(())
    }

    /// Port of `PrintC::pushType`: a type as a cast shows it.
    fn push_type(&mut self, ty: TypeId) -> Result<()> {
        self.push_type_start(ty, true)?;
        self.push_atom(Atom::Blank)?;
        self.push_type_end(ty)
    }

    /// `FlowBlock::emit`: the `emitBlock*` method of the block's kind. The C++ recursion is
    /// kept (the printer's order is the recursion's); a nesting deeper than [`MAX_DEPTH`]
    /// fails instead of overflowing the stack.
    fn emit_block(&mut self, b: SId) -> Result<()> {
        if self.depth >= MAX_DEPTH {
            return err(format!("print C: blocks nested deeper than {MAX_DEPTH} are not supported"));
        }
        self.depth += 1;
        let res = self.emit_block_kind(b);
        self.depth -= 1;
        res
    }

    /// The dispatch of [`Self::emit_block`].
    fn emit_block_kind(&mut self, b: SId) -> Result<()> {
        match self.fd.structure.b(b).kind.clone() {
            Kind::Graph => self.emit_block_graph(b),
            Kind::Copy(bb) => {
                // emitBlockCopy
                self.emit_any_label_statement(b)?;
                self.emit_block_basic(bb)
            }
            Kind::Goto(target) => self.emit_block_goto(b, target),
            // BlockMultiGoto::emit
            Kind::MultiGoto { .. } => self.emit_block(self.component(b, 0)?),
            Kind::List => self.emit_block_ls(b),
            Kind::Condition(opc) => self.emit_block_condition(b, opc),
            Kind::If | Kind::IfElse | Kind::IfNoExit | Kind::IfGoto(_) => self.emit_block_if(b),
            Kind::WhileDo => self.emit_block_while_do(b),
            Kind::DoWhile => self.emit_block_do_while(b),
            Kind::InfLoop => self.emit_block_inf_loop(b),
            Kind::Switch => self.emit_block_switch(b),
        }
    }

    /// Component `i` of a structured block (`getBlock(i)`).
    fn component(&self, b: SId, i: usize) -> Result<SId> {
        self.fd.structure.b(b).list.get(i).copied().ok_or_else(|| LowlevelError("print C: missing component".into()))
    }

    /// Port of `PrintC::emitBlockGraph`.
    fn emit_block_graph(&mut self, b: SId) -> Result<()> {
        for sub in self.fd.structure.b(b).list.clone() {
            self.emit_block(sub)?;
        }
        Ok(())
    }

    /// Port of `PrintC::emitBlockGoto`.
    fn emit_block_goto(&mut self, b: SId, target: SId) -> Result<()> {
        self.push_mod();
        self.set_mod(modifier::NO_BRANCH);
        self.emit_block(self.component(b, 0)?)?;
        self.pop_mod();
        // no goto when the target is the next block printed
        if goto_prints(&self.fd.structure, b, target) {
            self.emit.tag_line();
            self.emit_goto_statement(Some(target), self.fd.structure.b(b).goto_type)?;
        }
        Ok(())
    }

    /// Port of `PrintC::emitBlockLs` (structured printing): every block but the last prints
    /// without its branch (`nofallthru`, which only flat printing reads, is left out).
    fn emit_block_ls(&mut self, b: SId) -> Result<()> {
        let list = self.fd.structure.b(b).list.clone();
        if self.is_set(modifier::ONLY_BRANCH) {
            let Some(&last) = list.last() else { return err("print C: empty list block") };
            return self.emit_block(last);
        }
        let Some((&last, rest)) = list.split_last() else { return Ok(()) };
        self.push_mod();
        self.set_mod(modifier::NO_BRANCH);
        for &sub in rest {
            self.emit_block(sub)?;
        }
        self.pop_mod();
        self.emit_block(last)
    }

    /// Port of `PrintC::emitBlockCondition`: `&&` or `||` between the two conditions (an
    /// `INT_AND`/`INT_OR` condition never negated prints `||`, as the C++ tests only for
    /// BOOL_AND).
    fn emit_block_condition(&mut self, b: SId, opc: Opcode) -> Result<()> {
        if self.is_set(modifier::NO_BRANCH) {
            return self.emit_block(self.component(b, 0)?);
        }
        if self.is_set(modifier::ONLY_BRANCH) || self.is_set(modifier::COMMA_SEPARATE) {
            self.emit.open_paren("(");
            self.emit_block(self.component(b, 0)?)?;
            self.push_mod();
            self.unset_mod(modifier::ONLY_BRANCH);
            // comma_separate only on the second block
            self.set_mod(modifier::COMMA_SEPARATE);
            let tok = if opc == Opcode::BoolAnd { &BOOLEAN_AND } else { &BOOLEAN_OR };
            self.emit_op(tok, 1);
            self.emit.open_paren("(");
            self.emit_block(self.component(b, 1)?)?;
            self.emit.close_paren(")");
            self.pop_mod();
            self.emit.close_paren(")");
        }
        Ok(())
    }

    /// Port of `PrintC::emitBlockIf` (also `BlockIfElse`, `BlockIfNoExit`, `BlockIfGoto`): an
    /// `else` whose block is another if prints `else if`, the brace of the inner if waiting
    /// (`PendingBrace`) for a statement of its condition block.
    fn emit_block_if(&mut self, b: SId) -> Result<()> {
        let kind = self.fd.structure.b(b).kind.clone();
        let pending = self.is_set(modifier::PENDING_BRACE).then(|| self.emit.set_pending_brace());
        // an if block never prints its final branch
        self.push_mod();
        self.unset_mod(modifier::NO_BRANCH | modifier::ONLY_BRANCH | modifier::PENDING_BRACE);
        self.push_mod();
        self.set_mod(modifier::NO_BRANCH);
        let cond = self.component(b, 0)?;
        self.emit_block(cond)?;
        self.pop_mod();
        self.emit_comment_block_tree(cond)?;
        match pending {
            Some(id) if self.emit.has_pending_brace(id) => {
                // the brace was not printed: "else if"
                self.emit.cancel_pending();
                self.emit.spaces(1, 0);
            }
            _ => self.emit.tag_line(),
        }
        self.emit.print_str("if");
        self.emit.spaces(1, 0);
        self.push_mod();
        self.set_mod(modifier::ONLY_BRANCH);
        self.emit_block(cond)?;
        self.pop_mod();
        if let Kind::IfGoto(target) = kind {
            self.emit.spaces(1, 0);
            self.emit_goto_statement(Some(target), self.fd.structure.b(b).goto_type)?;
        } else {
            self.set_mod(modifier::NO_BRANCH);
            self.emit.open_brace_indent("{", BraceStyle::SameLine);
            self.emit_block(self.component(b, 1)?)?;
            self.emit.close_brace_indent("}");
            if kind == Kind::IfElse {
                self.emit.tag_line();
                self.emit.print_str("else");
                let else_block = self.component(b, 2)?;
                if matches!(self.fd.structure.b(else_block).kind, Kind::If | Kind::IfElse | Kind::IfGoto(_)) {
                    // merge "else" and "if"
                    self.set_mod(modifier::PENDING_BRACE);
                    self.emit_block(else_block)?;
                } else {
                    self.emit.open_brace_indent("{", BraceStyle::SameLine);
                    self.emit_block(else_block)?;
                    self.emit.close_brace_indent("}");
                }
            } else if kind == Kind::IfNoExit {
                // the body does not exit: the alternate path needs no else
                self.emit_block(self.component(b, 2)?)?;
            }
        }
        self.pop_mod();
        if pending.is_some_and(|id| self.emit.brace_opened(id)) {
            self.emit.close_brace_indent("}");
        }
        Ok(())
    }

    /// Port of `PrintC::emitForLoop`.
    fn emit_for_loop(&mut self, b: SId, iterate: OpId) -> Result<()> {
        self.push_mod();
        self.unset_mod(modifier::NO_BRANCH | modifier::ONLY_BRANCH);
        self.emit_any_label_statement(b)?;
        let cond = self.component(b, 0)?;
        self.emit_comment_block_tree(cond)?;
        self.emit.tag_line();
        self.emit.print_str("for");
        self.emit.spaces(1, 0);
        self.emit.open_paren("(");
        self.push_mod();
        self.set_mod(modifier::COMMA_SEPARATE);
        if let Some(init) = self.fd.structure.b(b).for_loop.initialize {
            self.emit.open_group(); // beginStatement
            self.emit_expression(init)?;
            self.emit.close_group();
        }
        self.emit.print_str(";");
        self.emit.spaces(1, 0);
        self.emit_block(cond)?;
        self.emit.print_str(";");
        self.emit.spaces(1, 0);
        self.emit.open_group(); // beginStatement
        self.emit_expression(iterate)?;
        self.emit.close_group();
        self.pop_mod();
        self.emit.close_paren(")");
        self.emit.open_brace_indent("{", BraceStyle::SameLine);
        self.set_mod(modifier::NO_BRANCH);
        self.emit_block(self.component(b, 1)?)?;
        self.emit.close_brace_indent("}");
        self.pop_mod();
        Ok(())
    }

    /// Port of `PrintC::emitBlockWhileDo`: a `for` loop when `finalTransform` found the
    /// iterate op; `while( true )` with an `if (..) break;` when the condition block has
    /// statements that cannot go in the condition (`f_whiledo_overflow`).
    fn emit_block_while_do(&mut self, b: SId) -> Result<()> {
        let bl = self.fd.structure.b(b);
        if let Some(iterate) = bl.for_loop.iterate {
            return self.emit_for_loop(b, iterate);
        }
        let overflow = bl.flags & F_WHILEDO_OVERFLOW != 0;
        // a while-do block never prints its final branch
        self.push_mod();
        self.unset_mod(modifier::NO_BRANCH | modifier::ONLY_BRANCH);
        self.emit_any_label_statement(b)?;
        let cond = self.component(b, 0)?;
        if overflow {
            self.emit.tag_line();
            self.emit.print_str("while");
            self.emit.open_paren("(");
            self.emit.spaces(1, 0);
            self.emit.print_str("true");
            self.emit.spaces(1, 0);
            self.emit.close_paren(")");
            self.emit.open_brace_indent("{", BraceStyle::SameLine);
            self.push_mod();
            self.set_mod(modifier::NO_BRANCH);
            self.emit_block(cond)?;
            self.pop_mod();
            self.emit_comment_block_tree(cond)?;
            self.emit.tag_line();
            self.emit.print_str("if");
            self.emit.spaces(1, 0);
            self.push_mod();
            self.set_mod(modifier::ONLY_BRANCH);
            self.emit_block(cond)?;
            self.pop_mod();
            self.emit.spaces(1, 0);
            self.emit_goto_statement(None, F_BREAK_GOTO)?;
        } else {
            self.emit_comment_block_tree(cond)?;
            self.emit.tag_line();
            self.emit.print_str("while");
            self.emit.spaces(1, 0);
            self.emit.open_paren("(");
            self.push_mod();
            self.set_mod(modifier::COMMA_SEPARATE);
            self.emit_block(cond)?;
            self.pop_mod();
            self.emit.close_paren(")");
            self.emit.open_brace_indent("{", BraceStyle::SameLine);
        }
        self.set_mod(modifier::NO_BRANCH); // no goto at the bottom of the body
        self.emit_block(self.component(b, 1)?)?;
        self.emit.close_brace_indent("}");
        self.pop_mod();
        Ok(())
    }

    /// Port of `PrintC::emitBlockDoWhile`.
    fn emit_block_do_while(&mut self, b: SId) -> Result<()> {
        // a do-while block never prints its final branch
        self.push_mod();
        self.unset_mod(modifier::NO_BRANCH | modifier::ONLY_BRANCH);
        self.emit_any_label_statement(b)?;
        self.emit.tag_line();
        self.emit.print_str("do");
        self.emit.open_brace_indent("{", BraceStyle::SameLine);
        self.push_mod();
        self.set_mod(modifier::NO_BRANCH);
        let body = self.component(b, 0)?;
        self.emit_block(body)?;
        self.pop_mod();
        self.emit.close_brace_indent("}");
        self.emit.spaces(1, 0);
        self.emit.print_str("while");
        self.emit.spaces(1, 0);
        self.set_mod(modifier::ONLY_BRANCH);
        self.emit_block(body)?;
        self.emit.print_str(";");
        self.pop_mod();
        Ok(())
    }

    /// Port of `PrintC::emitBlockInfLoop`.
    fn emit_block_inf_loop(&mut self, b: SId) -> Result<()> {
        self.push_mod();
        self.unset_mod(modifier::NO_BRANCH | modifier::ONLY_BRANCH);
        self.emit_any_label_statement(b)?;
        self.emit.tag_line();
        self.emit.print_str("do");
        self.emit.open_brace_indent("{", BraceStyle::SameLine);
        self.emit_block(self.component(b, 0)?)?;
        self.emit.close_brace_indent("}");
        self.emit.spaces(1, 0);
        self.emit.print_str("while");
        self.emit.open_paren("(");
        self.emit.spaces(1, 0);
        self.emit.print_str("true");
        self.emit.spaces(1, 0);
        self.emit.close_paren(")");
        self.emit.print_str(";");
        self.pop_mod();
        Ok(())
    }

    /// Port of `PrintC::emitBlockSwitch`: the switch block's statements, `switch(..)`, then
    /// each case's labels and body in the order `finalizePrinting` sorted them.
    fn emit_block_switch(&mut self, b: SId) -> Result<()> {
        let switch_block = self.component(b, 0)?;
        self.push_mod();
        self.unset_mod(modifier::NO_BRANCH | modifier::ONLY_BRANCH);
        self.push_mod();
        self.set_mod(modifier::NO_BRANCH);
        self.emit_block(switch_block)?;
        self.pop_mod();
        self.emit.tag_line();
        self.push_mod();
        self.set_mod(modifier::ONLY_BRANCH | modifier::COMMA_SEPARATE);
        self.emit_block(switch_block)?;
        self.pop_mod();
        self.emit.open_brace("{", BraceStyle::SameLine);
        let cases = self.fd.structure.b(b).cases.clone();
        for (i, case) in cases.iter().enumerate() {
            self.emit_switch_case(b, case)?;
            self.emit.start_indent();
            if case.gototype != 0 {
                self.emit.tag_line();
                self.emit_goto_statement(Some(case.block), case.gototype)?;
            } else {
                self.emit_block(case.block)?;
                if case.isexit && i != cases.len() - 1 {
                    // a case that formally exits the switch needs an explicit break
                    self.emit.tag_line();
                    self.emit_goto_statement(None, F_BREAK_GOTO)?;
                }
            }
            self.emit.stop_indent();
        }
        self.emit.tag_line();
        self.emit.print_str("}");
        self.pop_mod();
        Ok(())
    }

    /// Port of `PrintC::emitSwitchCase`: `default:`, or a `case` line for each label of the
    /// case's first basic block, in the switch variable's type.
    fn emit_switch_case(&mut self, b: SId, case: &CaseOrder) -> Result<()> {
        if case.isdefault {
            self.emit.tag_line();
            self.emit.print_str("default");
            self.emit.print_str(":");
            return Ok(());
        }
        let switchbl = switch_leaf(&self.fd.structure, b)?;
        let jt = switch_table(self.fd, switchbl)?;
        let indirect = jt.op;
        let labels = case_label_list(self.fd, jt, case, usize::MAX)?;
        // getSwitchType: the BRANCHIND input's high type, read facing; the jump table's display
        // format is 0 (none is ported), as is the type's
        let selector = self.fd.input(indirect, 0)?;
        let ct = super::cast::print_facing(self.fd, selector)?;
        for val in labels {
            self.emit.tag_line();
            self.emit.print_str("case");
            self.emit.spaces(1, 0);
            self.push_constant(val, ct, None)?;
            self.recurse()?;
            self.emit.print_str(":");
        }
        Ok(())
    }

    /// Port of `PrintC::emitGotoStatement`: `break`, `continue` or `goto` and the target's
    /// label (`exp_bl`).
    fn emit_goto_statement(&mut self, exp_bl: Option<SId>, ty: u32) -> Result<()> {
        self.emit.open_group(); // beginStatement
        match ty {
            F_BREAK_GOTO => self.emit.print_str("break"),
            F_CONTINUE_GOTO => self.emit.print_str("continue"),
            F_GOTO_GOTO => {
                self.emit.print_str("goto");
                self.emit.spaces(1, 0);
                let target = exp_bl.ok_or_else(|| LowlevelError("print C: a goto without a target".into()))?;
                self.emit_label(target)?;
            }
            _ => {}
        }
        self.emit.print_str(";");
        self.emit.close_group();
        Ok(())
    }

    /// Port of `PrintC::emitLabel`: the label of a block's first basic block, `code_`,
    /// `joined_` or `dup_` and the entry address (`getEntryAddr`; no code label symbol, `queryCodeLabel`, is
    /// ported: the checks declare none).
    fn emit_label(&mut self, b: SId) -> Result<()> {
        let Some(leaf) = front_leaf(&self.fd.structure, b) else { return Ok(()) };
        let Kind::Copy(bb) = self.fd.structure.b(leaf).kind else {
            return err("print C: the front leaf of a label is not a block copy");
        };
        let block = self.fd.blocks.block(bb);
        // `queryCodeLabel`: the listing's label at the block's entry (the facts of stage S10),
        // unless the block has a special label (joined or duplicated)
        if let (Some(facts), false) = (&self.arch.facts, block.joined || block.duplicated) {
            let first_op = block.ops.first().map(|&op| self.fd.op(op).seq.addr);
            let label = block.entry_addr(first_op).map(|a| facts.label(a, self.fd.entry)).transpose()?;
            if let Some(label) = label.flatten() {
                self.emit.print_str(label);
                return Ok(());
            }
        }
        let prefix = if block.joined {
            "joined_"
        } else if block.duplicated {
            "dup_"
        } else {
            "code_"
        };
        let first_op = block.ops.first().map(|&op| self.fd.op(op).seq.addr);
        let Some(start) = block.entry_addr(first_op) else {
            return err("print C: the label of a block of several ranges without ops (an invalid entry address)");
        };
        let code = self.arch.sleigh.code_space();
        let sp =
            self.arch.sleigh.spaces.get(code as usize).ok_or_else(|| LowlevelError("print C: bad space".into()))?;
        let text = format!("{prefix}{}{}", super::print::shortcut(&sp.name), self.raw_addr(code, start)?);
        self.emit.print_str(&text);
        Ok(())
    }

    /// Port of `PrintC::emitLabelStatement` (structured printing): the label of a block copy
    /// that is the target of an unstructured goto, at indent 0.
    fn emit_label_statement(&mut self, b: SId) -> Result<()> {
        if self.is_set(modifier::ONLY_BRANCH) {
            return Ok(());
        }
        let bl = self.fd.structure.b(b);
        if bl.flags & F_UNSTRUCTURED_TARG == 0 || !matches!(bl.kind, Kind::Copy(_)) {
            return Ok(());
        }
        self.emit.tag_line_indent(0);
        self.emit_label(b)?;
        self.emit.print_str(":");
        Ok(())
    }

    /// Port of `PrintC::emitAnyLabelStatement`: the label of a block's first leaf, unless a
    /// block higher up prints it.
    fn emit_any_label_statement(&mut self, b: SId) -> Result<()> {
        if self.fd.structure.b(b).flags & F_LABEL_BUMPUP != 0 {
            return Ok(());
        }
        match front_leaf(&self.fd.structure, b) {
            Some(leaf) => self.emit_label_statement(leaf),
            None => Ok(()),
        }
    }

    /// Port of `PrintC::emitCommentGroup`: the comments the sorter holds up to the statement
    /// rooted at `inst` (none: the rest of the block), each at the comment indent
    /// (`line_commentindent`, 20). Every body comment is a warning, a type
    /// `instr_comment_type` shows.
    fn emit_comment_group(&mut self, inst: Option<OpId>) -> Result<()> {
        let key = match inst {
            Some(op) => {
                let o = self.fd.op(op);
                let bb = o.parent.ok_or_else(|| LowlevelError("print C: a statement outside a block".into()))?;
                Some((self.fd.blocks.block(bb).index, o.order))
            }
            None => None,
        };
        self.commsorter.setup_op_list(key);
        while let Some(c) = self.commsorter.next() {
            if self.commsorter.is_emitted(c) {
                continue;
            }
            let text = self.fd.comments[c].1.clone();
            self.emit_line_comment(20, &text);
            self.commsorter.set_emitted(c);
        }
        Ok(())
    }

    /// Port of `PrintC::emitCommentBlockTree`: the comments of every basic block under `b`,
    /// before a line that prints statements of several blocks.
    fn emit_comment_block_tree(&mut self, b: SId) -> Result<()> {
        if let Kind::Copy(bb) = self.fd.structure.b(b).kind {
            let index = self.fd.blocks.block(bb).index;
            self.commsorter.setup_block_list(index);
            return self.emit_comment_group(None);
        }
        for sub in self.fd.structure.b(b).list.clone() {
            self.emit_comment_block_tree(sub)?;
        }
        Ok(())
    }

    /// Port of `PrintC::emitBlockBasic` (structured printing): with `only_branch` just the
    /// branch, else the statements, comma separated inside a condition, each after its
    /// comments. (`emitLabelStatement` of the basic block itself prints nothing: it is not a
    /// copy.)
    fn emit_block_basic(&mut self, bb: super::block::BlockId) -> Result<()> {
        let ops = self.fd.blocks.block(bb).ops.clone();
        self.commsorter.setup_block_list(self.fd.blocks.block(bb).index);
        if self.is_set(modifier::ONLY_BRANCH) {
            if let Some(&last) = ops.last() {
                if self.fd.op(last).is_branch() {
                    self.emit_expression(last)?;
                }
            }
            return Ok(());
        }
        let mut separator = false;
        for op in ops {
            let o = self.fd.op(op);
            // PcodeOp::notPrinted
            if o.is_marker() || o.flags.has(OpFlags::NONPRINTING) || o.halt == Some(Halt::NoReturn) {
                continue;
            }
            if o.is_branch() && (self.is_set(modifier::NO_BRANCH) || o.opc == Opcode::Branch) {
                continue;
            }
            if o.out.is_some_and(|v| self.fd.vn(v).has(VnFlags::IMPLIED)) {
                continue;
            }
            if self.is_set(modifier::COMMA_SEPARATE) {
                if separator {
                    self.emit.print_str(",");
                    self.emit.spaces(1, 0);
                }
            } else {
                self.emit_comment_group(Some(op))?;
                self.emit.tag_line();
            }
            self.emit_statement(op)?;
            separator = true;
        }
        self.emit_comment_group(None) // any remaining comments
    }

    /// Port of `PrintC::emitStatement`.
    fn emit_statement(&mut self, op: OpId) -> Result<()> {
        self.emit.open_group(); // beginStatement
        self.emit_expression(op)?;
        self.emit.close_group();
        if !self.is_set(modifier::COMMA_SEPARATE) {
            self.emit.print_str(";");
        }
        Ok(())
    }

    /// Port of `PrintC::emitExpression` (`option_inplace_ops` is off).
    fn emit_expression(&mut self, op: OpId) -> Result<()> {
        let o = self.fd.op(op);
        if o.flags.has(OpFlags::SPECIAL_PRINT) {
            match o.opc {
                Opcode::Subpiece => {}
                opc if o.is_call() || matches!(opc, Opcode::Store | Opcode::Insert) => {
                    return err(format!("print C: special printing of {opc:?} is not ported"));
                }
                _ => return err("Unsupported special printing"),
            }
        }
        if let Some(out) = o.out {
            self.push_op(&ASSIGNMENT)?;
            self.push_symbol_detail(out, false)?;
        }
        self.push_opcode(op, None)?;
        self.recurse()
    }

    /// `TypeOp::push`: the expression of `op`, read by `read_op` (none for a statement).
    pub(crate) fn push_opcode(&mut self, op: OpId, read_op: Option<OpId>) -> Result<()> {
        use Opcode::*;
        let opc = self.fd.op(op).opc;
        let tok: &'static OpToken = match opc {
            Copy => {
                self.push_vn(self.fd.op(op).ins[0], op, self.mods);
                return Ok(());
            }
            Cast => return self.op_type_cast(op),
            IntZext => return self.op_int_ext(op, read_op, false),
            IntSext => return self.op_int_ext(op, read_op, true),
            Subpiece => return self.op_subpiece(op),
            Branch => return Ok(()), // opBranch prints only in flat mode
            Cbranch => return self.op_cbranch(op),
            Branchind => return self.op_branchind(op),
            Load => return self.op_load(op),
            Store => return self.op_store(op),
            Ptradd => return self.op_ptradd(op),
            Ptrsub => return self.op_ptrsub(op),
            Call => return self.op_call(op),
            Callind => return self.op_callind(op),
            Callother => return self.op_callother(op),
            IntCarry => return self.op_func_sized(op, "CARRY", 1),
            IntScarry => return self.op_func_sized(op, "SCARRY", 1),
            IntSborrow => return self.op_func_sized(op, "SBORROW", 1),
            Piece => return self.op_func_sized(op, "CONCAT", 2),
            Popcount => return self.op_func_named(op, "POPCOUNT"),
            Lzcount => return self.op_func_named(op, "LZCOUNT"),
            FloatNan => return self.op_func_named(op, "NAN"),
            FloatAbs => return self.op_func_named(op, "ABS"),
            FloatSqrt => return self.op_func_named(op, "SQRT"),
            FloatCeil => return self.op_func_named(op, "CEIL"),
            FloatFloor => return self.op_func_named(op, "FLOOR"),
            FloatRound => return self.op_func_named(op, "ROUND"),
            FloatInt2float => return self.op_float_int2float(op),
            FloatFloat2float | FloatTrunc => return self.op_type_cast(op),
            Return => return self.op_return(op),
            BoolNegate => return self.op_bool_negate(op),
            Int2comp | FloatNeg => return self.op_unary(&UNARY_MINUS, op),
            IntNegate => return self.op_unary(&BITWISE_NOT, op),
            Multiequal | Indirect => return Ok(()),
            IntEqual | FloatEqual => &EQUAL,
            IntNotequal | FloatNotequal => &NOT_EQUAL,
            IntSless | IntLess | FloatLess => &LESS_THAN,
            IntSlessequal | IntLessequal | FloatLessequal => &LESS_EQUAL,
            IntAdd | FloatAdd => &BINARY_PLUS,
            IntSub | FloatSub => &BINARY_MINUS,
            IntXor => &BITWISE_XOR,
            IntAnd => &BITWISE_AND,
            IntOr => &BITWISE_OR,
            IntLeft => &SHIFT_LEFT,
            IntRight => &SHIFT_RIGHT,
            IntSright => &SHIFT_SRIGHT,
            IntMult | FloatMult => &MULTIPLY,
            IntDiv | IntSdiv | FloatDiv => &DIVIDE,
            IntRem | IntSrem => &MODULO,
            BoolXor => &BOOLEAN_XOR,
            BoolAnd => &BOOLEAN_AND,
            BoolOr => &BOOLEAN_OR,
            _ => return err(format!("print C: printing {opc:?} is not ported")),
        };
        self.op_binary(tok, op)
    }

    /// Port of `PrintC::opLoad`: `*p`, or the value of an array or field expression.
    fn op_load(&mut self, op: OpId) -> Result<()> {
        let ptr = self.fd.input(op, 1)?;
        let mut m = self.mods;
        if self.check_array_deref(ptr) && !self.is_set(modifier::FORCE_POINTER) {
            m |= modifier::PRINT_LOAD_VALUE;
        } else {
            self.push_op(&DEREFERENCE)?;
        }
        self.push_vn(ptr, op, m);
        Ok(())
    }

    /// Port of `PrintC::opStore`.
    fn op_store(&mut self, op: OpId) -> Result<()> {
        let (ptr, val) = (self.fd.input(op, 1)?, self.fd.input(op, 2)?);
        let mut m = self.mods;
        self.push_op(&ASSIGNMENT)?;
        if self.check_array_deref(ptr) && !self.is_set(modifier::FORCE_POINTER) {
            m |= modifier::PRINT_STORE_VALUE;
        } else {
            self.push_op(&DEREFERENCE)?;
        }
        self.push_vn(val, op, self.mods);
        self.push_vn(ptr, op, m);
        Ok(())
    }

    /// Port of `PrintC::opCall`: a direct call, by the callee's name.
    fn op_call(&mut self, op: OpId) -> Result<()> {
        self.push_op(&FUNCTION_CALL)?;
        let ins = self.fd.op(op).ins.clone();
        let callpoint = self.fd.vn(ins[0]);
        if callpoint.space != Space::Fspec {
            return err("Missing function callspec");
        }
        let call = self
            .fd
            .calls
            .get(callpoint.offset as usize)
            .ok_or_else(|| LowlevelError("Missing function callspec".into()))?;
        // fc->getName(), else genericFunctionName; pushSymbolScope: depth 0 in the global scope
        let name = match call.callee().and_then(|e| self.arch.functions.get(&e)) {
            Some(f) if !f.name.is_empty() => f.name.clone(),
            _ => {
                let entry =
                    call.entry.ok_or_else(|| LowlevelError("print C: a call without a target address".into()))?;
                format!("func_{}", self.raw_addr(self.arch.sleigh.code_space(), entry)?)
            }
        };
        self.check_scope_depth(&name)?;
        self.push_atom(Atom::Text(name))?;
        if ins.len() > 1 {
            for _ in 0..ins.len() - 2 {
                self.push_op(&COMMA)?;
            }
            for &vn in ins[1..].iter().rev() {
                self.push_vn(vn, op, self.mods);
            }
        } else {
            self.push_atom(Atom::Blank)?;
        }
        Ok(())
    }

    /// Port of `PrintC::opCallind`: `(*fn)(args)`, the function pointer under a dereference
    /// (`getHiddenThisSlot` is -1: `hide_thisparam` is set only by the Java printer).
    fn op_callind(&mut self, op: OpId) -> Result<()> {
        self.push_op(&FUNCTION_CALL)?;
        self.push_op(&DEREFERENCE)?;
        if self.fd.call_of(op).is_none() {
            return err("Missing indirect function callspec");
        }
        let ins = self.fd.op(op).ins.clone();
        let m = self.mods;
        match ins.len() {
            0 => return err("print C: a CALLIND without inputs"),
            1 => {
                self.push_vn(ins[0], op, m);
                self.push_atom(Atom::Blank)?;
            }
            2 => {
                self.push_vn(ins[1], op, m);
                self.push_vn(ins[0], op, m);
            }
            n => {
                self.push_vn(ins[0], op, m);
                for _ in 0..n - 2 {
                    self.push_op(&COMMA)?;
                }
                for &vn in ins[1..].iter().rev() {
                    self.push_vn(vn, op, m);
                }
            }
        }
        Ok(())
    }

    /// Port of `PrintC::opFloatInt2Float`: a cast of the input, or of the input of the
    /// implied INT_ZEXT the conversion absorbs (`TypeOpFloatInt2Float::absorbZext`).
    fn op_float_int2float(&mut self, op: OpId) -> Result<()> {
        let in0 = self.fd.input(op, 0)?;
        let v = self.fd.vn(in0);
        let zext = v.def.filter(|&d| v.has(VnFlags::IMPLIED) && self.fd.op(d).opc == Opcode::IntZext);
        let vn0 = match zext {
            Some(z) => self.fd.input(z, 0)?,
            None => in0,
        };
        let out = self.fd.op(op).out.ok_or_else(|| LowlevelError("print C: an INT2FLOAT without output".into()))?;
        let dt = super::cast::print_facing(self.fd, out)?;
        self.push_op(&TYPECAST)?;
        self.push_type(dt)?;
        self.push_vn(vn0, op, self.mods);
        Ok(())
    }

    /// Port of `PrintC::opReturn`.
    fn op_return(&mut self, op: OpId) -> Result<()> {
        let o = self.fd.op(op);
        let nm = match o.halt {
            None => {
                let ins = o.ins.clone();
                self.emit.print_str("return");
                if let Some(&v) = ins.get(1) {
                    self.emit.spaces(1, 0);
                    self.push_vn(v, op, self.mods);
                }
                return Ok(());
            }
            Some(Halt::BadInstruction) => "halt_baddata",
            Some(Halt::Unimplemented) => "halt_unimplemented",
            Some(Halt::NoReturn) => "halt",
        };
        self.push_op(&FUNCTION_CALL)?;
        self.push_atom(Atom::Text(nm.into()))?;
        self.push_atom(Atom::Blank)
    }

    /// Port of `PrintC::opBoolNegate`: a negated comparison prints as its complement.
    fn op_bool_negate(&mut self, op: OpId) -> Result<()> {
        let input = self.fd.op(op).ins[0];
        if self.is_set(modifier::NEGATETOKEN) {
            self.mods &= !modifier::NEGATETOKEN;
            self.push_vn(input, op, self.mods);
        } else if self.check_print_negation(input) {
            self.push_vn(input, op, self.mods | modifier::NEGATETOKEN);
        } else {
            self.push_op(&BOOLEAN_NOT)?;
            self.push_vn(input, op, self.mods);
        }
        Ok(())
    }

    /// Port of `PrintC::checkPrintNegation`: `vn` is an implied comparison that prints negated
    /// as its complement.
    fn check_print_negation(&self, vn: VarnodeId) -> bool {
        let v = self.fd.vn(vn);
        v.has(VnFlags::IMPLIED)
            && v.def.is_some_and(|d| super::rules::boolean::boolean_flip(self.fd.op(d).opc).is_some())
    }

    /// Port of `PrintC::opCbranch` (structured printing): the condition, in parentheses
    /// unless inside a comma-separated condition, negated when the branch is flipped.
    fn op_cbranch(&mut self, op: OpId) -> Result<()> {
        let yesparen = !self.is_set(modifier::COMMA_SEPARATE);
        let mut booleanflip = self.fd.op(op).flags.has(OpFlags::BOOLEAN_FLIP);
        let mut m = self.mods;
        if yesparen {
            self.emit.open_paren("(");
        } else {
            self.emit.open_group();
        }
        let cond = self.fd.input(op, 1)?;
        if booleanflip && self.check_print_negation(cond) {
            m |= modifier::NEGATETOKEN;
            booleanflip = false;
        }
        if booleanflip {
            self.push_op(&BOOLEAN_NOT)?;
        }
        self.push_vn(cond, op, m);
        self.recurse()?; // the stack is empty before more is emitted
        if yesparen {
            self.emit.close_paren(")");
        } else {
            self.emit.close_group();
        }
        Ok(())
    }

    /// Port of `PrintC::opBranchind`: the header of a switch.
    fn op_branchind(&mut self, op: OpId) -> Result<()> {
        self.emit.print_str("switch");
        self.emit.open_paren("(");
        self.push_vn(self.fd.input(op, 0)?, op, self.mods);
        self.recurse()?;
        self.emit.close_paren(")");
        Ok(())
    }

    /// Port of `PrintC::opTypeCast`: `(type)` and the input. A cast to a pointer to an array
    /// (`checkAddressOfCast`, which may print `&`) fails loudly.
    fn op_type_cast(&mut self, op: OpId) -> Result<()> {
        let out = self.fd.op(op).out.ok_or_else(|| LowlevelError("print C: a CAST without output".into()))?;
        let dt = super::cast::print_facing(self.fd, out)?;
        if self.fd.types.ptr_to(dt).is_some_and(|to| self.fd.types.meta(to) == Meta::Array) {
            return err("print C: a cast to a pointer to an array (checkAddressOfCast) is not ported");
        }
        // option_nocasts is off
        self.push_op(&TYPECAST)?;
        self.push_type(dt)?;
        self.push_vn(self.fd.input(op, 0)?, op, self.mods);
        Ok(())
    }

    /// Port of `PrintC::opIntZext` and `opIntSext`: a cast when the input's signedness
    /// matches the extension, hidden when C promotes the integer on its own
    /// (`option_hide_exts` is on), else `ZEXT14(x)` / `SEXT14(x)`.
    fn op_int_ext(&mut self, op: OpId, read_op: Option<OpId>, signed: bool) -> Result<()> {
        let out = self.fd.op(op).out.ok_or_else(|| LowlevelError("print C: an extension without output".into()))?;
        let input = self.fd.input(op, 0)?;
        let outtype = super::cast::print_facing(self.fd, out)?;
        let intype = super::cast::print_facing(self.fd, input)?;
        let is_cast = if signed {
            super::cast::is_sext_cast(&self.fd.types, outtype, intype)
        } else {
            super::cast::is_zext_cast(&self.fd.types, outtype, intype)
        };
        if !is_cast {
            return self.op_func(op, if signed { "SEXT" } else { "ZEXT" });
        }
        if super::cast::is_extension_cast_implied(self.fd, op, read_op)? {
            // opHiddenFunc
            self.push_op(&HIDDEN)?;
            self.push_vn(input, op, self.mods);
            return Ok(());
        }
        self.op_type_cast(op)
    }

    /// Port of `PrintC::opSubpiece`: a field extraction (special printing of a structured input:
    /// `sym.field` for an explicit variable with a symbol, else `x.field` for a formal structure
    /// field), a cast of the low bytes, else `SUB41(x,0)`. A union input fails loudly (its
    /// data-type needs resolution).
    fn op_subpiece(&mut self, op: OpId) -> Result<()> {
        let out = self.fd.op(op).out.ok_or_else(|| LowlevelError("print C: a SUBPIECE without output".into()))?;
        let (input, off) = (self.fd.input(op, 0)?, self.fd.input(op, 1)?);
        let intype = super::cast::print_facing(self.fd, input)?;
        // isPieceStructured (the partial struct and union metatypes are not ported)
        if self.fd.op(op).flags.has(OpFlags::SPECIAL_PRINT)
            && matches!(self.fd.types.meta(intype), Meta::Array | Meta::Struct | Meta::Union)
        {
            // TypeOpSubpiece::computeByteOffsetForComposite, little-endian
            let mut byte_off = i64::from(self.fd.vn(off).offset as i32);
            let sz = self.fd.vn(out).size;
            let h = super::variable::high(self.fd, input)?;
            if let (Some((sym, _, _)), true) =
                (super::namevars::high_symbol(self.fd, h), self.fd.vn(input).has(VnFlags::EXPLICIT))
            {
                let suboff = super::namevars::symbol_offset(self.fd, self.arch, h)?;
                if suboff > 0 {
                    byte_off += i64::from(suboff);
                }
                return self.push_partial_symbol(sym, byte_off, sz, Some(out));
            }
            // TypeStruct::findTruncation(byteOff, sz) giving offset 0: a formal structure field
            if let Some((name, foff, fty)) = self.find_field(intype, byte_off) {
                if foff == byte_off && sz <= self.fd.types.size(fty) {
                    self.push_op(&OBJECT_MEMBER)?;
                    self.push_vn(input, op, self.mods);
                    return self.push_atom(Atom::Text(name));
                }
            }
        }
        let outtype = super::cast::print_facing(self.fd, out)?;
        let offset = u64::from(self.fd.vn(off).offset as u32);
        if super::cast::is_subpiece_cast(&self.fd.types, outtype, intype, offset) {
            self.op_type_cast(op)
        } else {
            self.op_func(op, "SUB")
        }
    }

    /// Port of `PrintC::opCallother` for a SLEIGH user-op (display 0: functional syntax under
    /// the op's name, the inputs after the index). Any other user-op (the built-in ones: volatile
    /// read and write, string data, with the other displays) fails loudly.
    fn op_callother(&mut self, op: OpId) -> Result<()> {
        let index = self.fd.vn(self.fd.input(op, 0)?).offset;
        let Some(name) = self.arch.sleigh.userop_name(index) else {
            return err("print C: a CALLOTHER of a user-op that is not a SLEIGH one (built-in) is not ported");
        };
        self.op_func_from(op, name, 1)
    }

    /// `getOperatorName` of the operators named after their input sizes: `SBORROW4`, `CONCAT44`.
    fn op_func_sized(&mut self, op: OpId, name: &str, inputs: usize) -> Result<()> {
        let mut name = name.to_string();
        for i in 0..inputs {
            name += &self.fd.vn(self.fd.input(op, i)?).size.to_string();
        }
        self.op_func_named(op, &name)
    }

    /// Port of `PrintC::opFunc`: functional syntax, the operator's name
    /// (`getOperatorName`: `name`, the input and the output size) and the inputs.
    fn op_func(&mut self, op: OpId, name: &str) -> Result<()> {
        let o = self.fd.op(op);
        let outsize = o.out.map_or(0, |v| self.fd.vn(v).size);
        let insize = o.ins.first().map_or(0, |&v| self.fd.vn(v).size);
        self.op_func_named(op, &format!("{name}{insize}{outsize}"))
    }

    /// Port of `PrintC::opFunc` for an operator whose name has no sizes (`TypeOp::getOperatorName`:
    /// `NAN`, `ABS`, `SQRT`, `CEIL`, `FLOOR`, `ROUND`, `POPCOUNT`, `LZCOUNT`).
    fn op_func_named(&mut self, op: OpId, name: &str) -> Result<()> {
        self.op_func_from(op, name, 0)
    }

    /// `opFunc` over the inputs from `first` on (`opCallother`: 1, after the user-op index).
    fn op_func_from(&mut self, op: OpId, name: &str, first: usize) -> Result<()> {
        self.push_op(&FUNCTION_CALL)?;
        let ins: Vec<VarnodeId> = self.fd.op(op).ins.iter().skip(first).copied().collect();
        self.push_atom(Atom::Text(name.to_string()))?;
        if ins.is_empty() {
            return self.push_atom(Atom::Blank);
        }
        for _ in 0..ins.len() - 1 {
            self.push_op(&COMMA)?;
        }
        for &vn in ins.iter().rev() {
            self.push_vn(vn, op, self.mods);
        }
        Ok(())
    }

    /// Port of `PrintLanguage::pushSymbolDetail`: a whole symbol, a part of one (`is_read`: the
    /// varnode is read, not written) or the unnamed location.
    pub(crate) fn push_symbol_detail(&mut self, vn: VarnodeId, is_read: bool) -> Result<()> {
        let h = super::variable::high(self.fd, vn)?;
        let Some((sym, _, _)) = super::namevars::high_symbol(self.fd, h) else {
            let rep = super::namevars::name_representative(self.fd, h)?;
            let r = self.fd.vn(rep);
            if r.has(VnFlags::PERSIST) {
                let (off, size) = (r.offset, r.size);
                // the type-locked symbol holding the whole varnode, linked when the varnode is
                // made (`setSymbolProperties`): a function or an external reference
                if let Some(e) = super::infertypes::query_global(self.arch, off, size) {
                    let whole = if e.externref { self.arch.externref_size() } else { 1 };
                    if e.addr != off || size != whole {
                        return err("print C: part of an external reference (pushPartialSymbol of a code pointer) is not ported");
                    }
                    let name = if e.externref { self.externref_name(off)? } else { self.function_name(off)? };
                    self.check_scope_depth(&name)?;
                    return self.push_atom(Atom::Text(name));
                }
                // `linkSymbol` asks for the symbol at the first byte only
                if super::infertypes::query_global(self.arch, off, 1).is_some() {
                    return err("print C: a variable larger than the function or external reference at its address (pushMismatchSymbol) is not ported");
                }
            }
            let size = self.fd.vn(vn).size;
            return self.push_unnamed_location(rep, size);
        };
        let off = super::namevars::symbol_offset(self.fd, self.arch, h)?;
        let sty = self.fd.symtab.symbol(sym).ty;
        if sty.is_some_and(|t| self.fd.types.needs_resolution(t)) {
            return err("print C: a symbol whose data-type needs resolution (union, one-element array or one-field structure) is not ported");
        }
        if off == -1 {
            return self.push_symbol(sym);
        }
        let size = self.fd.vn(vn).size;
        let Some(sty) = sty else {
            return err("print C: part of a symbol without a data-type is not ported");
        };
        if i64::from(off) + i64::from(size) > i64::from(self.fd.types.size(sty)) {
            // PrintC::pushMismatchSymbol: at the symbol's address but larger than it, the name
            // with an underscore before it; else the location. Ported for the data symbols of
            // the facts (stage S10), where the check against Java Ghidra covers it; the checks
            // against decomp_dbg have not run it, so without facts it still fails
            if self.arch.facts.is_none() {
                return err("print C: a variable past the end of its symbol (pushMismatchSymbol) is not ported");
            }
            if off == 0 {
                let name = &self.fd.symtab.symbol(sym).name;
                // '_' + getDisplayName(): the name without its namespaces, which the port's
                // symbol keeps as one string
                if name.contains("::") {
                    return err(
                        "print C: a variable larger than its symbol in a namespace (pushMismatchSymbol) is not ported",
                    );
                }
                let name = format!("_{name}");
                return self.push_atom(Atom::Text(name));
            }
            return self.push_unnamed_location(vn, size);
        }
        self.push_partial_symbol(sym, i64::from(off), size, is_read.then_some(vn))
    }

    /// Port of `PrintC::pushSymbol` (no merge problems: `mergeMultiEntry` is not ported) with
    /// `pushSymbolScope`.
    fn push_symbol(&mut self, sym: SymbolId) -> Result<()> {
        let s = self.fd.symtab.symbol(sym);
        let (name, global) = (s.name.clone(), s.scope == super::scope::GLOBAL);
        if global {
            self.check_scope_depth(&name)?;
        }
        self.push_atom(Atom::Text(name))
    }

    /// Port of `AddrSpace::printRaw` (wordsize 1, as every x86 space): `0x` and the offset in hex,
    /// padded to the address size (a wide space's small offset to 4 or 6 bytes).
    fn raw_addr(&self, space: u32, off: u64) -> Result<String> {
        let sp =
            self.arch.sleigh.spaces.get(space as usize).ok_or_else(|| LowlevelError("print C: bad space".into()))?;
        Ok(raw_offset(sp.size, off))
    }

    /// `Symbol::getResolutionDepth` of a global name used in the local scope: 0 unless the
    /// local scope holds the same name (`isNameUsed`), which would print a `::` prefix (not
    /// ported).
    fn check_scope_depth(&self, name: &str) -> Result<()> {
        if self.fd.symtab.find_first_by_name(LOCAL, name).is_some() {
            return err(format!(
                "print C: the global {name} is hidden by a local name (a scope prefix) and is not ported"
            ));
        }
        Ok(())
    }

    /// Port of `PrintC::pushUnnamedLocation`: the space name and the register name, or the
    /// raw address.
    fn push_unnamed_location(&mut self, rep: VarnodeId, size: u32) -> Result<()> {
        let v = self.fd.vn(rep);
        self.push_unnamed_addr(v.space, v.offset, size)
    }

    /// `pushUnnamedLocation` of an address: a SLEIGH space (`register_ESP`, `ram0x00401000`) or
    /// the stack (`stack0xfffffff0`, the stack has no registers).
    fn push_unnamed_addr(&mut self, space: Space, off: u64, size: u32) -> Result<()> {
        let i = match space {
            Space::Sleigh(i) => i,
            Space::Stack => self.arch.spec.stack_container,
            _ => return err("print C: an unnamed variable outside a SLEIGH space is not ported"),
        };
        let sp = self.arch.sleigh.spaces.get(i as usize).ok_or_else(|| LowlevelError("print C: bad space".into()))?;
        let name = if space == Space::Stack { "stack" } else { sp.name.as_str() };
        let text = match self.arch.register_name(i, off, size).filter(|_| space != Space::Stack) {
            Some((reg, base, regsize)) if base == off && regsize == size => format!("{name}_{reg}"),
            _ => format!("{name}{}", self.raw_addr(i, off)?),
        };
        self.push_atom(Atom::Text(text))
    }

    /// Port of `PrintC::pushConstant` with the constant's high type
    /// (`getHighTypeReadFacing`).
    pub(crate) fn push_constant_vn(&mut self, vn: VarnodeId) -> Result<()> {
        let h = super::variable::high(self.fd, vn)?;
        let (ty, _) = super::variable::h_type(self.fd, h);
        self.push_constant(self.fd.vn(vn).offset, ty, Some(vn))
    }

    /// Port of `PrintC::pushConstant` of `val` in type `ty` (`vn`, the constant varnode, is
    /// none for a case label).
    fn push_constant(&mut self, val: u64, ty: TypeId, vn: Option<VarnodeId>) -> Result<()> {
        if self.fd.types.needs_resolution(ty) {
            return err("print C: a constant whose data-type needs resolution (getHighTypeReadFacing) is not ported");
        }
        let size = self.fd.types.size(ty);
        let meta = self.fd.types.meta(ty);
        match meta {
            Meta::Uint | Meta::Int => {
                if self.fd.types.is_char_print(ty) {
                    return self.push_char_constant(val, ty, meta == Meta::Int, vn);
                }
                if matches!(self.fd.types.get(ty).kind, TKind::Enum(_)) {
                    return err("print C: enum constants are not ported");
                }
                return self.push_integer(val, size, meta == Meta::Int, vn);
            }
            Meta::Unknown => return self.push_integer(val, size, false, vn),
            Meta::Bool => return self.push_atom(Atom::Text(if val != 0 { "true" } else { "false" }.into())),
            Meta::Void => return err("Cannot have a constant of type void"),
            Meta::Float => return self.push_atom(Atom::Text(float_token(val, size))),
            Meta::Ptr => {
                if let Some(to) = self.fd.types.ptr_to(ty) {
                    if self.fd.types.is_char_print(to) {
                        if let Some(text) = self.ptr_char_constant(val, self.fd.types.size(to))? {
                            return self.push_atom(Atom::Text(text));
                        }
                    } else if self.fd.types.meta(to) == Meta::Code && self.arch.functions.contains_key(&val) {
                        // pushPtrCodeConstant: the function at the address (`queryFunction`; the
                        // code space has word size 1)
                        let name = self.function_name(val)?;
                        return self.push_atom(Atom::Text(name));
                    }
                }
            }
            _ => {}
        }
        // the default: a cast to the type, the value in hex
        self.push_op(&TYPECAST)?;
        self.push_type(ty)?;
        self.push_mod();
        if !self.is_set(modifier::FORCE_DEC) {
            self.set_mod(modifier::FORCE_HEX);
        }
        self.push_integer(val, size, false, vn)?;
        self.pop_mod();
        Ok(())
    }

    /// Port of `PrintC::push_integer` with display format 0: a ported data-type has no display
    /// format (`getDisplayFormat`; neither `parse line` nor the core types set one), and a
    /// constant with a symbol, which could set one, fails.
    fn push_integer(&mut self, mut val: u64, size: u32, sign: bool, vn: Option<VarnodeId>) -> Result<()> {
        if let Some(vn) = vn.filter(|&v| !self.fd.vn(v).is_annotation()) {
            let h = super::variable::high(self.fd, vn)?;
            if super::namevars::high_symbol(self.fd, h).is_some() {
                return err("print C: a constant with a symbol (equate) is not ported");
            }
        }
        // isUnsignedPrint and isLongPrint, set by setcasts (markExplicitUnsigned, markExplicitLongSize)
        let flags = vn.filter(|&v| !self.fd.vn(v).is_annotation()).map(|v| self.fd.vn(v));
        let mut force_unsigned = flags.is_some_and(|v| v.has(VnFlags::UNSIGNED_PRINT));
        if flags.is_some_and(|v| v.has(VnFlags::LONG_PRINT)) {
            // sizeSuffix comes from the data organization's long size, not ported
            return err("print C: the long suffix of a constant (isLongPrint, sizeSuffix) is not ported");
        }
        let mut negsign = false;
        if sign {
            let mask = calc_mask(size);
            let flip = val ^ mask;
            negsign = flip < val;
            force_unsigned = false;
            if negsign {
                val = flip.wrapping_add(1);
            }
        }
        let hex = if self.is_set(modifier::FORCE_HEX) {
            true
        } else if val <= 10 || self.is_set(modifier::FORCE_DEC) {
            false
        } else {
            most_natural_base(val) == 16
        };
        let mut t = String::new();
        if negsign {
            t.push('-');
        }
        t += &if hex { format!("0x{val:x}") } else { format!("{val}") };
        if force_unsigned {
            t.push('U');
        }
        self.push_atom(Atom::Text(t))
    }
}

/// What the offset of a space-base PTRSUB refers to: a symbol and the offset into it, or a
/// function by its name.
enum SbRef {
    Sym(SymbolId, i64),
    Func(String),
}

/// Slice 3A: array and field access (`PTRADD`, `PTRSUB`, LOAD and STORE through them, parts of
/// symbols) and character constants.
impl PrintC<'_> {
    /// Port of `PrintC::checkArrayDeref`: whether the pointer `vn` of a LOAD or STORE prints
    /// in array or field syntax rather than with `*`.
    fn check_array_deref(&self, mut vn: VarnodeId) -> bool {
        let implied_def = |p: &Self, v: VarnodeId| {
            let x = p.fd.vn(v);
            x.def.filter(|_| x.has(VnFlags::IMPLIED))
        };
        let Some(mut def) = implied_def(self, vn) else { return false };
        if self.fd.op(def).opc == Opcode::Segmentop {
            let Some(&v) = self.fd.op(def).ins.get(2) else { return false };
            vn = v;
            let Some(d) = implied_def(self, vn) else { return false };
            def = d;
        }
        matches!(self.fd.op(def).opc, Opcode::Ptrsub | Opcode::Ptradd)
    }

    /// `isValueFlexible` (printc.cc): `vn` is an implied PTRSUB or PTRADD, maybe through an
    /// implied COPY, so it can take over a dereference.
    fn is_value_flexible(&self, vn: VarnodeId) -> Result<bool> {
        let v = self.fd.vn(vn);
        let Some(def) = v.def.filter(|_| v.has(VnFlags::IMPLIED)) else { return Ok(false) };
        let mut opc = self.fd.op(def).opc;
        if opc == Opcode::Copy {
            let inv = self.fd.vn(self.fd.input(def, 0)?);
            let Some(d) = inv.def.filter(|_| inv.has(VnFlags::IMPLIED)) else { return Ok(false) };
            opc = self.fd.op(d).opc;
        }
        Ok(matches!(opc, Opcode::Ptrsub | Opcode::Ptradd))
    }

    /// Port of `PrintC::opPtradd`: `p[i]` when the value is printed, else `p + i`.
    fn op_ptradd(&mut self, op: OpId) -> Result<()> {
        let value = modifier::PRINT_LOAD_VALUE | modifier::PRINT_STORE_VALUE;
        let printval = self.is_set(value);
        let m = self.mods & !value;
        self.push_op(if printval { &SUBSCRIPT } else { &BINARY_PLUS })?;
        self.push_vn(self.fd.input(op, 1)?, op, m);
        self.push_vn(self.fd.input(op, 0)?, op, m);
        Ok(())
    }

    /// Port of `PrintC::opPtrsub` (no `TypePointerRel` is ported, so the relative-pointer parts
    /// never apply): a field of a structure (`&p->x`, `p->x`, `&(..).x`, `(..).x`, `[0]` for an
    /// array field), a symbol of a space (`&name`, `name`, `name[0]`, the unnamed location) or
    /// the first element of an array (`*p`, `p[0]`).
    fn op_ptrsub(&mut self, op: OpId) -> Result<()> {
        let in0 = self.fd.input(op, 0)?;
        let in1const = self.fd.vn(self.fd.input(op, 1)?).offset;
        let ptype = super::cast::print_facing(self.fd, in0)?;
        let ct = match self.fd.types.ptr_to(ptype) {
            Some(to) if self.fd.types.meta(ptype) == Meta::Ptr => to,
            _ => return err("PTRSUB off of non-pointer type"),
        };
        let value = modifier::PRINT_LOAD_VALUE | modifier::PRINT_STORE_VALUE;
        let m = self.mods & !value;
        let mut valueon = self.is_set(value);
        let flex = self.is_value_flexible(in0)?;
        match self.fd.types.meta(ct) {
            Meta::Union => err("print C: a PTRSUB into a union (getUnionField) is not ported"),
            Meta::Struct => {
                let suboff = i64::from(in1const as i32);
                let (fieldname, fieldtype) = match self.find_field(ct, suboff) {
                    Some((name, _, ty)) => (name, Some(ty)),
                    None if i64::from(self.fd.types.size(ct)) <= suboff || suboff < 0 => {
                        return err("PTRSUB out of bounds into struct");
                    }
                    None => (format!("field_0x{suboff:x}"), None),
                };
                let mut arrayvalue = false;
                // the '&' is dropped if the field is an array
                if fieldtype.is_some_and(|t| self.fd.types.meta(t) == Meta::Array) {
                    arrayvalue = valueon;
                    valueon = true;
                }
                if !valueon {
                    self.push_op(&ADDRESSOF)?;
                } else if arrayvalue {
                    self.push_op(&SUBSCRIPT)?;
                }
                if flex {
                    // ( ).name
                    self.push_op(&OBJECT_MEMBER)?;
                    self.push_vn(in0, op, m | modifier::PRINT_LOAD_VALUE);
                } else {
                    // ( )->name
                    self.push_op(&POINTER_MEMBER)?;
                    self.push_vn(in0, op, m);
                }
                self.push_atom(Atom::Text(fieldname))?;
                if arrayvalue {
                    self.push_integer(0, 4, false, None)?;
                }
                Ok(())
            }
            Meta::Spacebase => {
                let r = self.spacebase_ref(op)?;
                let mut arrayvalue = false;
                if let Some(SbRef::Func(_)) = r {
                    valueon = true; // a function symbol has a code data-type
                } else if let Some(SbRef::Sym(sym, _)) = r {
                    let sct =
                        self.fd.symtab.symbol(sym).ty.ok_or_else(|| {
                            LowlevelError("print C: a symbol without a data-type under a PTRSUB".into())
                        })?;
                    match self.fd.types.meta(sct) {
                        Meta::Array => {
                            arrayvalue = valueon;
                            valueon = true;
                        }
                        Meta::Code => valueon = true,
                        _ => {}
                    }
                }
                if !valueon {
                    self.push_op(&ADDRESSOF)?;
                } else if arrayvalue {
                    self.push_op(&SUBSCRIPT)?;
                }
                match r {
                    None => {
                        let (space, addr) = self.spacebase_addr(op, ct)?;
                        self.push_unnamed_addr(space, addr, 1)?;
                    }
                    Some(SbRef::Func(name)) => {
                        self.check_scope_depth(&name)?;
                        self.push_atom(Atom::Text(name))?;
                    }
                    Some(SbRef::Sym(sym, 0)) => self.push_symbol(sym)?,
                    Some(SbRef::Sym(sym, off)) => self.push_partial_symbol(sym, off, 0, None)?,
                }
                if arrayvalue {
                    self.push_integer(0, 4, false, None)?;
                }
                Ok(())
            }
            Meta::Array => {
                if in1const != 0 {
                    return err("PTRSUB with non-zero offset into array type");
                }
                // the array as a structure: PTRSUB(*,0) turns it into a pointer to its element
                if valueon {
                    // ( )[0] or (* )[0]
                    self.push_op(&SUBSCRIPT)?;
                }
                if flex {
                    self.push_vn(in0, op, m | modifier::PRINT_LOAD_VALUE);
                } else {
                    self.push_op(&DEREFERENCE)?;
                    self.push_vn(in0, op, m);
                }
                if valueon {
                    self.push_integer(0, 4, false, None)?;
                }
                Ok(())
            }
            _ => err("PTRSUB off of non structured pointer type"),
        }
    }

    /// `TypeStruct::getFieldIter` and the field `findTruncation(off, 0)` returns: the field
    /// holding byte `off`: its name, offset and type.
    fn find_field(&self, ct: TypeId, off: i64) -> Option<(String, i64, TypeId)> {
        let TKind::Fields(fields) = &self.fd.types.get(ct).kind else { return None };
        let (mut min, mut max) = (0i64, fields.len() as i64 - 1);
        while min <= max {
            let mid = (min + max) / 2;
            let (name, foff, fty) = &fields[mid as usize];
            let foff = i64::from(*foff);
            if foff > off {
                max = mid - 1;
            } else if foff + i64::from(self.fd.types.size(*fty)) > off {
                return Some((name.clone(), foff, *fty));
            } else {
                min = mid + 1;
            }
        }
        None
    }

    /// `TypeSpacebase::getAddress` of the offset of the PTRSUB `op` off the space-base type
    /// `sb` (`resolveConstant`: no segmented space, so the offset wrapped to the space).
    fn spacebase_addr(&self, op: OpId, sb: TypeId) -> Result<(Space, u64)> {
        let TKind::Spacebase { space, .. } = self.fd.types.get(sb).kind else {
            return err("print C: a space-base PTRSUB without a space-base type");
        };
        let off = self.fd.vn(self.fd.input(op, 1)?).offset;
        Ok((space, off & super::heritage::space_mask(self.arch, space)))
    }

    /// What the offset of the PTRSUB `op` refers to: the link `namevars` made
    /// (`linkSymbolReference`, `Funcdata::symref`; none prints the unnamed location). A function
    /// is its name (the `FunctionSymbol`: `fc->getName()`, else `genericFunctionName`); an
    /// external reference fails loudly.
    fn spacebase_ref(&self, op: OpId) -> Result<Option<SbRef>> {
        Ok(match self.fd.symref.get(&self.fd.input(op, 1)?).copied() {
            None => None,
            Some(SymRef::Sym(sym, off)) => Some(SbRef::Sym(sym, off)),
            Some(SymRef::ExternRef) => return err("print C: a PTRSUB into an external reference is not ported"),
            Some(SymRef::Function(addr)) => Some(SbRef::Func(self.function_name(addr)?)),
        })
    }

    /// The name of the function at `addr` (`FunctionSymbol`), `func_` and the address without one.
    fn function_name(&self, addr: u64) -> Result<String> {
        Ok(match self.arch.functions.get(&addr) {
            Some(f) if !f.name.is_empty() => f.name.clone(),
            _ => format!("func_{}", self.raw_addr(self.arch.sleigh.code_space(), addr)?),
        })
    }

    /// The name of the external reference at `slot` (`ExternRefSymbol::buildNameType`): the one
    /// `map externalref` gave, else the address it refers to and `_exref`.
    fn externref_name(&self, slot: u64) -> Result<String> {
        if let Some(name) = self.arch.externref_name(slot) {
            return Ok(name.to_string());
        }
        let target =
            self.arch.externref_target(slot).ok_or_else(|| LowlevelError("print C: no external reference".into()))?;
        let code = self.arch.sleigh.code_space();
        let sp =
            self.arch.sleigh.spaces.get(code as usize).ok_or_else(|| LowlevelError("print C: bad space".into()))?;
        Ok(format!("{}{}_exref", super::print::shortcut(&sp.name), self.raw_addr(code, target)?))
    }

    /// Port of `PrintC::pushPartialSymbol`: the part of `sym` at `off` of `sz` bytes (0: to the
    /// end) as `sym.field`, `sym[i]` or `sym._off_size_`; `vn` is the varnode read (none for a
    /// write or a PTRSUB), whose type may print as a cast of the part (`isSubpieceCastEndian`).
    fn push_partial_symbol(&mut self, sym: SymbolId, mut off: i64, mut sz: u32, vn: Option<VarnodeId>) -> Result<()> {
        enum Part {
            Field(&'static OpToken, String),
            Index(i64),
            Unnamed(i64, i64),
        }
        let mut stack = Vec::new();
        let mut finalcast = None;
        let mut ct = self.fd.symtab.symbol(sym).ty;
        while let Some(t) = ct {
            let tsize = self.fd.types.size(t);
            let tmeta = self.fd.types.meta(t);
            if off == 0 && (sz == 0 || (sz == tsize && (!self.fd.types.needs_resolution(t) || tmeta == Meta::Ptr))) {
                break;
            }
            let mut succeeded = false;
            match tmeta {
                Meta::Struct => {
                    if self.fd.types.needs_resolution(t) && tsize == sz {
                        return err("print C: part of a symbol through a structure that needs resolution (findResolve) is not ported");
                    }
                    // findTruncation(off, sz)
                    if let Some((name, foff, fty)) = self.find_field(t, off) {
                        let noff = off - foff;
                        if noff + i64::from(sz) <= i64::from(self.fd.types.size(fty)) {
                            off = noff;
                            stack.push(Part::Field(&OBJECT_MEMBER, name));
                            ct = Some(fty);
                            succeeded = true;
                        }
                    }
                }
                Meta::Array => {
                    // TypeArray::getSubEntry
                    let TKind::Array { elem, .. } = self.fd.types.get(t).kind else {
                        return err("print C: an array data-type without an element");
                    };
                    let a = i64::from(self.fd.types.align_size(elem));
                    if a == 0 {
                        return err("print C: an array of zero-size elements");
                    }
                    let (noff, el) = (off % a, off / a);
                    if noff + i64::from(sz) <= a {
                        off = noff;
                        stack.push(Part::Index(el));
                        ct = Some(elem);
                        succeeded = true;
                    }
                }
                Meta::Union => return err("print C: part of a symbol through a union is not ported"),
                _ => {
                    if let Some(vn) = vn {
                        // isSubpieceCastEndian, little-endian
                        let h = super::variable::high(self.fd, vn)?;
                        let outtype = super::variable::h_type(self.fd, h).0;
                        if off >= 0 && super::cast::is_subpiece_cast(&self.fd.types, outtype, t, off as u64) {
                            finalcast = Some(outtype);
                            ct = None;
                            succeeded = true;
                        }
                    }
                }
            }
            if !succeeded {
                if sz == 0 {
                    sz = (i64::from(tsize) - off) as u32;
                }
                stack.push(Part::Unnamed(off, i64::from(sz as i32)));
                ct = None;
            }
        }
        if let Some(t) = finalcast {
            self.push_op(&TYPECAST)?;
            self.push_type(t)?;
        }
        for p in stack.iter().rev() {
            self.push_op(match p {
                Part::Field(tok, _) => tok,
                Part::Index(_) => &SUBSCRIPT,
                Part::Unnamed(..) => &OBJECT_MEMBER,
            })?;
        }
        self.push_symbol(sym)?;
        for p in stack {
            match p {
                Part::Field(_, name) => self.push_atom(Atom::Text(name))?,
                Part::Index(el) => self.push_integer(el as u64, 0, el < 0, None)?,
                Part::Unnamed(o, s) if s <= 0 => self.push_integer(o as u64, s as u32, o < 0, None)?,
                Part::Unnamed(o, s) => self.push_atom(Atom::Text(format!("_{o}_{s}_")))?,
            }
        }
        Ok(())
    }

    /// Port of `PrintC::pushPtrCharConstant` with `printCharacterConstant`: the quoted string a
    /// constant pointer to characters of `charsize` bytes points at, none when it is null, not
    /// in read-only memory or not a terminated string of valid characters. `resolveConstant`
    /// is the address itself (no segment resolver for the checks' flat space) and no ported
    /// data-type is an opaque string. The string read at an address is kept (`stringMap`): a
    /// later constant there prints the same characters even with another character size. The
    /// C++ keeps it for the whole session, this for one `print C`.
    fn ptr_char_constant(&mut self, val: u64, charsize: u32) -> Result<Option<String>> {
        if val == 0 || !self.arch.is_readonly(val, 1) {
            return Ok(None);
        }
        let arch = self.arch;
        let data = self.strings.entry(val).or_insert_with(|| string_data(arch, val, charsize as usize));
        let data = data.clone();
        java_reads_the_same(arch, val, charsize, data.as_ref())?;
        let Some((chars, trunc)) = data else { return Ok(None) };
        let mut t = String::from(if charsize > 1 { "L\"" } else { "\"" });
        for cp in chars {
            print_unicode(&mut t, cp)?;
        }
        t += if trunc { "...\" /* TRUNCATED STRING LITERAL */" } else { "\"" };
        Ok(Some(t))
    }

    /// Port of `PrintC::pushCharConstant` with display format 0 (no ported data-type or
    /// symbol has one): a byte of 0x80 or more as an integer, else the quoted character.
    fn push_char_constant(&mut self, val: u64, ty: TypeId, signed: bool, vn: Option<VarnodeId>) -> Result<()> {
        if let Some(v) = vn.filter(|&v| !self.fd.vn(v).is_annotation()) {
            let h = super::variable::high(self.fd, v)?;
            if super::namevars::high_symbol(self.fd, h).is_some() {
                return err("print C: a character constant with a symbol (equate) is not ported");
            }
        }
        let size = self.fd.types.size(ty);
        if size == 1 && val >= 0x80 {
            return self.push_integer(val, 1, signed, vn);
        }
        self.push_atom(Atom::Text(char_constant(val, size)?))
    }
}

/// The text `pushCharConstant` prints for the code point `val` in a character of `size` bytes:
/// `L` for a wide character, the character in single quotes, escaped by `printUnicode`.
fn char_constant(val: u64, size: u32) -> Result<String> {
    let mut t = String::new();
    if size > 1 {
        t.push('L');
    }
    t.push('\'');
    print_unicode(&mut t, val as i32)?;
    t.push('\'');
    Ok(t)
}

/// Port of `PrintC::printUnicode`: the code point escaped, or as UTF-8.
fn print_unicode(t: &mut String, cp: i32) -> Result<()> {
    if unicode_needs_escape(cp) {
        let special = match cp {
            0 => "\\0",
            7 => "\\a",
            8 => "\\b",
            9 => "\\t",
            10 => "\\n",
            11 => "\\v",
            12 => "\\f",
            13 => "\\r",
            92 => "\\\\",
            34 => "\\\"",
            39 => "\\'",
            _ => "",
        };
        if special.is_empty() {
            *t += &char_hex_escape(cp);
        } else {
            *t += special;
        }
    } else {
        // StringManager::writeUtf8: every code point left is a valid character
        let c = char::from_u32(cp as u32).ok_or_else(|| LowlevelError("Illegal unicode codepoint".into()))?;
        t.push(c);
    }
    Ok(())
}

/// `StringManagerUnicode::maximumChars` (sleigh_arch.cc: 2048).
const MAXIMUM_CHARS: usize = 2048;

/// With facts (stage S10) Java reads a string (`DecompileCallback.getStringData`): the listing's
/// defined string data holding the address, with its length, character set and translation,
/// else a terminated string of the bytes. [`string_data`] reads the bytes up to a terminator.
/// The two are taken to agree on a whole string of plain one-byte ASCII that either lies
/// outside defined string data, or in a string the export found plain and that ends where the
/// raw read does (`Facts::string_at`); and on no string where the listing defines none. Any
/// other case fails.
// ponytail: outside defined string data, bytes without a terminator within `MAXIMUM_CHARS`
// are no string here and are taken as none in Java (its limit may differ by one character)
fn java_reads_the_same(arch: &Arch, addr: u64, charsize: u32, data: Option<&(Vec<i32>, bool)>) -> Result<()> {
    let Some(facts) = &arch.facts else { return Ok(()) };
    let defined = facts.string_at(addr);
    let plain = |&c: &i32| matches!(c, 0x20..=0x7e | 9 | 10 | 13);
    let same = match data {
        None => defined.is_none(),
        Some((chars, trunc)) => {
            let whole = charsize == 1 && !trunc && chars.len() + 2 < MAXIMUM_CHARS && chars.iter().all(plain);
            whole && defined.is_none_or(|(at, n)| n.is_some_and(|n| n.saturating_sub(at) == chars.len() as u64))
        }
    };
    if !same {
        return err("print C: a string Java Ghidra reads (getStringData) from defined string data of another length or form, or that is not plain ASCII, is not ported");
    }
    Ok(())
}

/// Port of `StringManager::isString`: whether a string of characters of `charsize` bytes
/// (not an empty one) is at `addr`.
pub(crate) fn is_string(arch: &Arch, addr: u64, charsize: u32) -> Result<bool> {
    let data = string_data(arch, addr, charsize as usize);
    java_reads_the_same(arch, addr, charsize, data.as_ref())?;
    Ok(data.is_some_and(|(chars, _)| !chars.is_empty()))
}

/// Port of `StringManagerUnicode::getStringData` (with `checkCharacters` and
/// `assignStringData`), read as `escapeCharacterData` reads the UTF-8 it stores: the code
/// points of the string at `addr` up to its terminator and whether it was truncated. None:
/// the bytes are not loaded, no terminator within `MAXIMUM_CHARS` bytes, or an invalid
/// encoding. The bytes are read 32 at a time, a terminator looked for at each character
/// position of the new bytes.
fn string_data(arch: &Arch, addr: u64, charsize: usize) -> Option<(Vec<i32>, bool)> {
    let mut buf: Vec<u8> = Vec::new();
    loop {
        let amount = 32.min(MAXIMUM_CHARS - buf.len());
        if amount == 0 {
            return None;
        }
        let cur = buf.len();
        buf.resize(cur + amount, 0);
        arch.fill_bytes(addr + cur as u64, &mut buf[cur..])?;
        // hasCharTerminator
        if (cur..buf.len()).step_by(charsize).any(|i| buf[i..].iter().take(charsize).all(|&b| b == 0)) {
            break;
        }
    }
    let mut chars = Vec::new();
    let mut i = 0;
    while i < buf.len() {
        let (cp, skip) = get_codepoint(&buf[i..], charsize, arch.sleigh.big_endian)?;
        if cp == 0 {
            break;
        }
        chars.push(cp);
        i += skip;
    }
    // assignStringData: one-byte characters under the limit are kept as they are; else
    // writeUnicode stops at the limit
    let trunc = chars.len() >= MAXIMUM_CHARS;
    chars.truncate(MAXIMUM_CHARS);
    Some((chars, trunc))
}

/// Port of `StringManager::getCodepoint`: the code point at the start of `buf` and the bytes
/// it takes, none for an invalid encoding.
fn get_codepoint(buf: &[u8], charsize: usize, bigend: bool) -> Option<(i32, usize)> {
    let b = |i: usize| buf.get(i).map(|&x| i32::from(x));
    let utf16 = |i: usize| Some(if bigend { (b(i)? << 8) + b(i + 1)? } else { (b(i + 1)? << 8) + b(i)? });
    let cont = |i: usize| b(i).filter(|v| v & 0xc0 == 0x80).map(|v| v & 0x3f);
    let (cp, skip) = match charsize {
        2 => {
            let cp = utf16(0)?;
            match cp {
                0xd800..=0xdbff => {
                    let trail = utf16(2).filter(|t| (0xdc00..=0xdfff).contains(t))?;
                    ((cp << 10) + trail + (0x10000 - (0xd800 << 10) - 0xdc00), 4)
                }
                0xdc00..=0xdfff => return None,
                _ => (cp, 2),
            }
        }
        1 => {
            let val = b(0)?;
            if val & 0x80 == 0 {
                (val, 1)
            } else if val & 0xe0 == 0xc0 {
                (((val & 0x1f) << 6) | cont(1)?, 2)
            } else if val & 0xf0 == 0xe0 {
                (((val & 0xf) << 12) | (cont(1)? << 6) | cont(2)?, 3)
            } else if val & 0xf8 == 0xf0 {
                (((val & 7) << 18) | (cont(1)? << 12) | (cont(2)? << 6) | cont(3)?, 4)
            } else {
                return None;
            }
        }
        4 => {
            let w = [b(0)?, b(1)?, b(2)?, b(3)?];
            let cp = if bigend {
                (w[0] << 24).wrapping_add(w[1] << 16) + (w[2] << 8) + w[3]
            } else {
                (w[3] << 24).wrapping_add(w[2] << 16) + (w[1] << 8) + w[0]
            };
            (cp, 4)
        }
        _ => return None,
    };
    // a negative UTF-32 value is invalid to every caller (`checkCharacters`)
    if cp < 0 || (cp >= 0xd800 && (cp > 0x10ffff || cp <= 0xdfff)) {
        return None;
    }
    Some((cp, skip))
}

/// Port of `PrintC::printCharHexEscape`: `\x` and 2, 4 or 8 hex digits (a negative value
/// prints as its unsigned 32 bits, as the C++ stream does).
fn char_hex_escape(val: i32) -> String {
    let u = val as u32;
    if val < 256 {
        format!("\\x{u:02x}")
    } else if val < 65536 {
        format!("\\x{u:04x}")
    } else {
        format!("\\x{u:08x}")
    }
}

/// Port of `PrintLanguage::unicodeNeedsEscape`.
fn unicode_needs_escape(cp: i32) -> bool {
    match cp {
        _ if cp < 0x20 => true,
        _ if cp < 0x7f => matches!(cp, 92 | 34 | 39),
        _ if cp < 0x100 => cp <= 0xa0,
        _ if cp >= 0x2fa20 => true,
        _ if cp < 0x2000 => (0x180b..=0x180e).contains(&cp) || cp == 0x61c || cp == 0x1680,
        _ if cp < 0x3000 => {
            cp < 0x2010
                || (0x2028..=0x202f).contains(&cp)
                || cp == 0x205f
                || cp == 0x2060
                || (0x2066..=0x206f).contains(&cp)
        }
        _ if cp < 0xe000 => cp == 0x3000 || cp >= 0xd7fc,
        _ if cp < 0xf900 => true,
        _ => {
            (0xfe00..=0xfe0f).contains(&cp)
                || cp == 0xfeff
                || ((0xfff0..=0xffff).contains(&cp) && cp != 0xfffc && cp != 0xfffd)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `getCodepoint`: UTF-16 surrogate pairs, a lone trail, UTF-8 continuation bytes.
    #[test]
    fn codepoints() {
        assert_eq!(get_codepoint(&[0x3d, 0xd8, 0x00, 0xde], 2, false), Some((0x1f600, 4)));
        assert_eq!(get_codepoint(&[0x00, 0xde, 0x41, 0x00], 2, false), None);
        assert_eq!(get_codepoint(&[0xc3, 0xa9], 1, false), Some((0xe9, 2)));
        assert_eq!(get_codepoint(&[0xc3, 0x41], 1, false), None);
        assert_eq!(get_codepoint(&[0xe2, 0x82], 1, false), None);
        assert_eq!(get_codepoint(&[0, 0, 0, 0x80], 4, false), None);
    }

    #[test]
    fn negation_pairs() {
        assert!(std::ptr::eq(negate(&LESS_THAN).unwrap(), &GREATER_EQUAL));
        assert!(std::ptr::eq(negate(&NOT_EQUAL).unwrap(), &EQUAL));
        assert!(negate(&BINARY_PLUS).is_none());
        // two tokens with the same text are still different tokens
        assert!(!std::ptr::eq(&SHIFT_RIGHT, &SHIFT_SRIGHT));
    }

    #[test]
    fn raw_offsets() {
        assert_eq!(raw_offset(4, 0x17200), "0x00017200");
        assert_eq!(raw_offset(8, 0x401000), "0x00401000");
        assert_eq!(raw_offset(8, 0x1_0000_0000), "0x000100000000");
        assert_eq!(raw_offset(8, 0x1_0000_0000_0000), "0x0001000000000000");
    }

    /// The tokens of the C++ `printDecimal` (libstdc++ `ostream << double`), printed by a
    /// small C++ program for these encodings.
    #[test]
    fn float_tokens_match_the_cpp() {
        let cases: &[(u32, u64, &str)] = &[
            (4, 0x3f80_0000, "1.0"),
            (4, 0x3dcc_cccd, "0.1"),
            (4, 0xbf00_0000, "-0.5"),
            (4, 0, "0.0"),
            (4, 0x8000_0000, "-0.0"),
            (4, 0x4b18_9680, "1e+07"),
            (4, 0x3e99_999a, "0.3"),
            (4, 0x461c_4000, "10000.0"),
            (4, 1, "1.4013e-45"),
            (4, 0x7f7f_ffff, "3.4028235e+38"),
            (4, 0x3a83_126f, "0.001"),
            (4, 0x4974_2400, "1e+06"),
            (4, 0x4cbe_bc20, "1e+08"),
            (8, 0x3ff0_0000_0000_0000, "1.0"),
            (8, 0x3fb9_9999_9999_999a, "0.1"),
            (8, 0x4009_21fb_5444_2d18, "3.141592653589793"),
            (8, 1, "4.94065645841247e-324"),
            (8, 0x7fef_ffff_ffff_ffff, "1.79769313486232e+308"),
            (8, 0x3f50_624d_d2f1_a9fc, "0.001"),
            (8, 0x412e_8480_0000_0000, "1000000.0"),
            (8, 0x4415_af1d_78b5_8c40, "1e+20"),
            (8, 0xc08f_4000_0000_0000, "-1000.0"),
            (8, 0x3fe0_0000_0000_0000, "0.5"),
            (8, 0x3eb0_c6f7_a0b5_ed8d, "1e-06"),
            (8, 0x4202_a05f_2000_0000, "10000000000.0"),
        ];
        for &(size, enc, want) in cases {
            assert_eq!(float_token(enc, size), want, "size {size} encoding {enc:#x}");
        }
        assert_eq!(float_token(0x7f80_0000, 4), "INFINITY");
        assert_eq!(float_token(0xfff0_0000_0000_0000, 8), "-INFINITY");
        assert_eq!(float_token(0x7fc0_0000, 4), "NAN");
        assert_eq!(float_token(0xffc0_0000, 4), "-NAN");
        assert_eq!(float_token(0, 10), "FLOAT_UNKNOWN");
    }

    #[test]
    fn format_g_rounds_as_printf() {
        assert_eq!(format_g(2.5, 1), "2"); // ties to even, as glibc
        assert_eq!(format_g(0.000123456, 3), "0.000123");
        assert_eq!(format_g(123456.0, 3), "1.23e+05");
        assert_eq!(format_g(9.9999996, 6), "10");
        assert_eq!(format_g(-1e-300, 2), "-1e-300");
    }

    #[test]
    fn generic_type_names() {
        assert_eq!(generic_type_name(Meta::Unknown, 3), "unkbyte3");
        assert_eq!(generic_type_name(Meta::Int, 16), "unkint16");
        assert_eq!(generic_type_name(Meta::Float, 2), "unkfloat2");
        assert_eq!(generic_type_name(Meta::Spacebase, 4), "BADSPACEBASE");
        assert_eq!(generic_type_name(Meta::Struct, 8), "BADTYPE");
    }

    #[test]
    fn character_constants() {
        let c = |v, s| char_constant(v, s).unwrap();
        assert_eq!(c(0x41, 1), "'A'");
        assert_eq!(c(0, 1), "'\\0'");
        assert_eq!(c(10, 1), "'\\n'");
        assert_eq!(c(0x27, 1), "'\\''");
        assert_eq!(c(0x22, 1), "'\\\"'");
        assert_eq!(c(0x5c, 1), "'\\\\'");
        assert_eq!(c(0x1b, 1), "'\\x1b'");
        assert_eq!(c(0x7f, 2), "L'\\x7f'");
        assert_eq!(c(0xe9, 2), "L'\u{e9}'");
        assert_eq!(c(0x2000, 2), "L'\\x2000'");
        assert_eq!(c(0x4e2d, 2), "L'\u{4e2d}'");
        assert_eq!(c(0xd800, 2), "L'\\xd800'");
        assert_eq!(c(0x30000, 4), "L'\\x00030000'");
        assert_eq!(c(0xffff_ffff, 4), "L'\\xffffffff'");
        assert!(!unicode_needs_escape(0xa1) && unicode_needs_escape(0xa0) && !unicode_needs_escape(0xfffd));
    }

    #[test]
    fn masks() {
        assert_eq!(calc_mask(1), 0xff);
        assert_eq!(calc_mask(4), 0xffff_ffff);
        assert_eq!(calc_mask(8), u64::MAX);
    }
}
