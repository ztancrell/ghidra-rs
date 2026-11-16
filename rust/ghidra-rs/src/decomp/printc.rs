//! `print C`, layer three: port of the parts of `PrintC` (printc.cc) the checks reach: the
//! header comments, the declaration, the local variable declarations, every structured block
//! (lists, if/else with the `else if` merge, while, for, do-while, infinite loops, `&&`/`||`
//! conditions, switch with its case labels, gotos, labels, break and continue), and statements
//! of assignments, loads, stores, direct calls, returns and branches over the arithmetic, logic
//! and comparison operators, casts (`opTypeCast`), extensions and SUBPIECE (cast, hidden or
//! `ZEXT14(x)` style), constants and variables.
//!
//! Every construct the C++ would print that is not ported fails with an error naming it, so a
//! function prints identically or not at all. Not ported yet: comments inside the body, the
//! long suffix of a constant, a cast to a pointer to an array (`checkAddressOfCast`), labels of
//! spliced blocks, strings and characters, floats, field and array access, anonymous types and
//! the remaining operators. (Slice 1 had no casts or structured blocks; superseded.)

use super::finalstructure::{
    case_label_list, switch_leaf, switch_table, CaseOrder, F_BREAK_GOTO, F_CONTINUE_GOTO, F_GOTO_GOTO, F_LABEL_BUMPUP,
    F_UNSTRUCTURED_TARG,
};
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
    if fd.structure.is_empty() {
        return err("Function not fully decompiled. No structure present.");
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

impl PrintC<'_> {
    /// Port of `PrintC::docFunction`.
    fn doc_function(&mut self, name: &str) -> Result<()> {
        if !self.fd.comments.is_empty() {
            return err("print C: comments inside the body (warnings at an address) are not ported");
        }
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
        let Some(name) = self.fd.types.name(base).filter(|n| !n.is_empty()).map(str::to_string) else {
            return err("print C: an anonymous data-type (genericTypeName) is not ported");
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
        // emitCommentBlockTree: no comment reaches the body (docFunction fails on one)
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
    /// `joined_` or `dup_` and the entry address (no code label symbol, `queryCodeLabel`, is
    /// ported: the checks declare none).
    fn emit_label(&mut self, b: SId) -> Result<()> {
        let Some(leaf) = front_leaf(&self.fd.structure, b) else { return Ok(()) };
        let Kind::Copy(bb) = self.fd.structure.b(leaf).kind else {
            return err("print C: the front leaf of a label is not a block copy");
        };
        let block = self.fd.blocks.block(bb);
        if block.spliced {
            return err(
                "print C: the label of a spliced block (getEntryAddr of a cover with several ranges) is not ported",
            );
        }
        let prefix = if block.joined {
            "joined_"
        } else if block.duplicated {
            "dup_"
        } else {
            "code_"
        };
        let start = block.start;
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

    /// Port of `PrintC::emitBlockBasic` (structured printing, no comments): with
    /// `only_branch` just the branch, else the statements, comma separated inside a condition.
    /// (`emitLabelStatement` of the basic block itself prints nothing: it is not a copy.)
    fn emit_block_basic(&mut self, bb: super::block::BlockId) -> Result<()> {
        let ops = self.fd.blocks.block(bb).ops.clone();
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
            if o.is_marker() || o.flags.has(OpFlags::NONPRINTING) {
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
                self.emit.tag_line();
            }
            self.emit_statement(op)?;
            separator = true;
        }
        Ok(())
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
            self.push_symbol_detail(out)?;
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
            Call => return self.op_call(op),
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

    /// Port of `PrintC::checkArrayDeref`; true would print array syntax, not ported.
    fn check_array_deref(&self, vn: VarnodeId) -> Result<()> {
        let v = self.fd.vn(vn);
        let Some(def) = v.def.filter(|_| v.has(VnFlags::IMPLIED)) else { return Ok(()) };
        match self.fd.op(def).opc {
            Opcode::Ptrsub | Opcode::Ptradd | Opcode::Segmentop => {
                err("print C: array or field access through a pointer is not ported")
            }
            _ => Ok(()),
        }
    }

    /// Port of `PrintC::opLoad`.
    fn op_load(&mut self, op: OpId) -> Result<()> {
        let ptr = self.fd.op(op).ins[1];
        self.check_array_deref(ptr)?;
        self.push_op(&DEREFERENCE)?;
        self.push_vn(ptr, op, self.mods);
        Ok(())
    }

    /// Port of `PrintC::opStore`.
    fn op_store(&mut self, op: OpId) -> Result<()> {
        let (ptr, val) = (self.fd.op(op).ins[1], self.fd.op(op).ins[2]);
        self.push_op(&ASSIGNMENT)?;
        self.check_array_deref(ptr)?;
        self.push_op(&DEREFERENCE)?;
        self.push_vn(val, op, self.mods);
        self.push_vn(ptr, op, self.mods);
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

    /// Port of `PrintC::opSubpiece`: a cast of the low bytes, else `SUB41(x,0)`; special
    /// printing (a field extraction) fails loudly.
    fn op_subpiece(&mut self, op: OpId) -> Result<()> {
        if self.fd.op(op).flags.has(OpFlags::SPECIAL_PRINT) {
            return err("print C: a SUBPIECE printed as a field extraction (doesSpecialPrinting) is not ported");
        }
        let out = self.fd.op(op).out.ok_or_else(|| LowlevelError("print C: a SUBPIECE without output".into()))?;
        let (input, off) = (self.fd.input(op, 0)?, self.fd.input(op, 1)?);
        let outtype = super::cast::print_facing(self.fd, out)?;
        let intype = super::cast::print_facing(self.fd, input)?;
        let offset = u64::from(self.fd.vn(off).offset as u32);
        if super::cast::is_subpiece_cast(&self.fd.types, outtype, intype, offset) {
            self.op_type_cast(op)
        } else {
            self.op_func(op, "SUB")
        }
    }

    /// Port of `PrintC::opFunc`: functional syntax, the operator's name
    /// (`getOperatorName`: `name`, the input and the output size) and the inputs.
    fn op_func(&mut self, op: OpId, name: &str) -> Result<()> {
        self.push_op(&FUNCTION_CALL)?;
        let o = self.fd.op(op);
        let ins = o.ins.clone();
        let outsize = o.out.map_or(0, |v| self.fd.vn(v).size);
        let insize = ins.first().map_or(0, |&v| self.fd.vn(v).size);
        self.push_atom(Atom::Text(format!("{name}{insize}{outsize}")))?;
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

    /// Port of `PrintLanguage::pushSymbolDetail` for a varnode that is a whole symbol or has
    /// none.
    pub(crate) fn push_symbol_detail(&mut self, vn: VarnodeId) -> Result<()> {
        let h = super::variable::high(self.fd, vn)?;
        let Some((sym, _, _)) = super::namevars::high_symbol(self.fd, h) else {
            let rep = super::namevars::name_representative(self.fd, h)?;
            let r = self.fd.vn(rep);
            if r.has(VnFlags::PERSIST) && super::infertypes::query_global(self.arch, r.offset, 1).is_some() {
                return err("print C: a variable linked to a function or an external reference is not ported");
            }
            let size = self.fd.vn(vn).size;
            return self.push_unnamed_location(rep, size);
        };
        if super::namevars::symbol_offset(self.fd, self.arch, h)? != -1 {
            return err("print C: part of a symbol (pushPartialSymbol) is not ported");
        }
        let s = self.fd.symtab.symbol(sym);
        if s.ty.is_some_and(|t| self.fd.types.needs_resolution(t)) {
            return err("print C: a symbol whose data-type needs resolution (union, one-element array or one-field structure) is not ported");
        }
        // pushSymbol: no merge problems (mergeMultiEntry is not ported)
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
        let Space::Sleigh(i) = v.space else {
            return err("print C: an unnamed variable outside a SLEIGH space is not ported");
        };
        let sp = self.arch.sleigh.spaces.get(i as usize).ok_or_else(|| LowlevelError("print C: bad space".into()))?;
        let text = match self.arch.register_name(i, v.offset, size) {
            Some((reg, base, regsize)) if base == v.offset && regsize == size => format!("{}_{reg}", sp.name),
            _ => format!("{}{}", sp.name, self.raw_addr(i, v.offset)?),
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
                    return err("print C: character constants are not ported");
                }
                if matches!(self.fd.types.get(ty).kind, TKind::Enum(_)) {
                    return err("print C: enum constants are not ported");
                }
                return self.push_integer(val, size, meta == Meta::Int, vn);
            }
            Meta::Unknown => return self.push_integer(val, size, false, vn),
            Meta::Bool => return self.push_atom(Atom::Text(if val != 0 { "true" } else { "false" }.into())),
            Meta::Void => return err("Cannot have a constant of type void"),
            Meta::Float => return err("print C: float constants are not ported"),
            Meta::Ptr => {
                if let Some(to) = self.fd.types.ptr_to(ty) {
                    if self.fd.types.is_char_print(to) {
                        return err("print C: string constants are not ported");
                    }
                    if self.fd.types.meta(to) == Meta::Code {
                        return err("print C: function pointer constants are not ported");
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

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn masks() {
        assert_eq!(calc_mask(1), 0xff);
        assert_eq!(calc_mask(4), 0xffff_ffff);
        assert_eq!(calc_mask(8), u64::MAX);
    }
}
