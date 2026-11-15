//! `print C`, layer three: port of the parts of `PrintC` (printc.cc) a straight-line function
//! needs: the header comments, the declaration, the local variable declarations, the basic
//! blocks of a list, and statements of assignments, loads, stores, direct calls and returns
//! over the arithmetic, logic and comparison operators, constants and variables.
//!
//! Every construct the C++ would print that is not ported fails with an error naming it, so a
//! function prints identically or not at all. Not ported yet: casts (`setcasts` is not ported,
//! the checks skip it on both engines), structured control flow (if, loops, switch, gotos and
//! labels), comments inside the body, strings and characters, floats, field and array access,
//! and the remaining operators.

use super::op::{Halt, OpFlags, OpId};
use super::opcode::Opcode;
use super::printlanguage::{modifier, most_natural_base, Atom, OpToken, PrintC, TokenType};
use super::scope::{SymbolId, LOCAL};
use super::structure::{Kind, SId};
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
        self.emit.open_brace_indent("{");
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

    /// Port of `PrintC::emitCommentFuncHeader`: the header warnings
    /// (`Funcdata::warningHeader`, each stored once).
    fn emit_comment_func_header(&mut self) {
        let mut seen: Vec<&String> = Vec::new();
        let warnings = self.fd.warnings.clone();
        for w in &warnings {
            if seen.contains(&w) {
                continue;
            }
            seen.push(w);
            self.emit_line_comment(0, &format!("WARNING: {w}"));
        }
        if !seen.is_empty() {
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
            // a multi-entry symbol is declared at its first whole entry (`getFirstWholeMap`)
            if s.entries.len() > 1 && s.entries.iter().position(|x| x.piece.is_none()) != Some(e) {
                continue;
            }
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

    /// `FlowBlock::emit` of a structured block: a list and the copies of basic blocks are
    /// ported, every other kind fails.
    fn emit_block(&mut self, b: SId) -> Result<()> {
        let bl = self.fd.structure.b(b);
        match bl.kind.clone() {
            Kind::Copy(bb) => {
                // emitAnyLabelStatement: the target of a goto has a label
                if bl.flags & 0x20 != 0 {
                    return err("print C: labels (the target of a goto) are not ported");
                }
                self.emit_block_basic(bb)
            }
            Kind::List => self.emit_block_ls(b),
            Kind::Graph => {
                for sub in self.fd.structure.b(b).list.clone() {
                    self.emit_block(sub)?;
                }
                Ok(())
            }
            k => err(format!("print C: {} blocks are not ported", block_name(&k))),
        }
    }

    /// Port of `PrintC::emitBlockLs` (structured printing): every block but the last prints
    /// without its branch.
    fn emit_block_ls(&mut self, b: SId) -> Result<()> {
        let list = self.fd.structure.b(b).list.clone();
        let Some((&last, rest)) = list.split_last() else { return Ok(()) };
        self.push_mod();
        self.set_mod(modifier::NO_BRANCH);
        for &sub in rest {
            self.emit_block(sub)?;
        }
        self.pop_mod();
        self.emit_block(last)
    }

    /// Port of `PrintC::emitBlockBasic` (structured printing, no comments).
    fn emit_block_basic(&mut self, bb: super::block::BlockId) -> Result<()> {
        let ops = self.fd.blocks.block(bb).ops.clone();
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
            self.emit.tag_line();
            self.emit_statement(op)?;
        }
        Ok(())
    }

    /// Port of `PrintC::emitStatement`.
    fn emit_statement(&mut self, op: OpId) -> Result<()> {
        self.emit.open_group(); // beginStatement
        self.emit_expression(op)?;
        self.emit.close_group();
        self.emit.print_str(";");
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
            self.push_symbol_detail(out, op, false)?;
        }
        self.push_opcode(op, None)?;
        self.recurse()
    }

    /// `TypeOp::push`: the expression of `op` (read by `read`, unused by the ported ops).
    pub(crate) fn push_opcode(&mut self, op: OpId, _read: Option<OpId>) -> Result<()> {
        use Opcode::*;
        let opc = self.fd.op(op).opc;
        let tok: &'static OpToken = match opc {
            Copy => {
                self.push_vn(self.fd.op(op).ins[0], op, self.mods);
                return Ok(());
            }
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
            _ => format!("func_0x{:08x}", call.entry.unwrap_or_default()),
        };
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
            return Ok(());
        }
        // checkPrintNegation
        let v = self.fd.vn(input);
        let flips = v.has(VnFlags::IMPLIED)
            && v.def.is_some_and(|d| super::rules::boolean::boolean_flip(self.fd.op(d).opc).is_some());
        if flips {
            self.push_vn(input, op, self.mods | modifier::NEGATETOKEN);
        } else {
            self.push_op(&BOOLEAN_NOT)?;
            self.push_vn(input, op, self.mods);
        }
        Ok(())
    }

    /// Port of `PrintLanguage::pushSymbolDetail` for a varnode that is a whole symbol or has
    /// none.
    pub(crate) fn push_symbol_detail(&mut self, vn: VarnodeId, _op: OpId, _is_read: bool) -> Result<()> {
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
        if s.ty.is_some_and(|t| self.fd.types.meta(t) == Meta::Union) {
            return err("print C: a union symbol (needsResolution) is not ported");
        }
        // pushSymbol: no merge problems (mergeMultiEntry is not ported), no scope prefix
        let name = s.name.clone();
        self.push_atom(Atom::Text(name))
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
            _ => format!("{}0x{:0w$x}", sp.name, v.offset, w = 2 * sp.size as usize),
        };
        self.push_atom(Atom::Text(text))
    }

    /// Port of `PrintC::pushConstant` with the constant's high type
    /// (`getHighTypeReadFacing`).
    pub(crate) fn push_constant_vn(&mut self, vn: VarnodeId, _op: OpId) -> Result<()> {
        let h = super::variable::high(self.fd, vn)?;
        let (ty, _) = super::variable::h_type(self.fd, h);
        let (val, size) = (self.fd.vn(vn).offset, self.fd.types.size(ty));
        let meta = self.fd.types.meta(ty);
        match meta {
            Meta::Uint | Meta::Int => {
                if self.fd.types.is_char_print(ty) {
                    return err("print C: character constants are not ported");
                }
                if matches!(self.fd.types.get(ty).kind, TKind::Enum(_)) {
                    return err("print C: enum constants are not ported");
                }
                return self.push_integer(val, size, meta == Meta::Int, Some(vn));
            }
            Meta::Unknown => return self.push_integer(val, size, false, Some(vn)),
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
        self.push_integer(val, size, false, Some(vn))?;
        self.pop_mod();
        Ok(())
    }

    /// Port of `PrintC::push_integer` (display format 0: no ported type or symbol forces one).
    fn push_integer(&mut self, mut val: u64, size: u32, sign: bool, vn: Option<VarnodeId>) -> Result<()> {
        if let Some(vn) = vn.filter(|&v| !self.fd.vn(v).is_annotation()) {
            let h = super::variable::high(self.fd, vn)?;
            if super::namevars::high_symbol(self.fd, h).is_some() {
                return err("print C: a constant with a symbol (equate) is not ported");
            }
        }
        let mut negsign = false;
        if sign {
            let mask = calc_mask(size);
            let flip = val ^ mask;
            negsign = flip < val;
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
        self.push_atom(Atom::Text(t))
    }
}

/// The C++ class name of a structured block kind, for the errors.
fn block_name(k: &Kind) -> &'static str {
    match k {
        Kind::Graph => "BlockGraph",
        Kind::Copy(_) => "BlockCopy",
        Kind::Goto(_) => "BlockGoto",
        Kind::MultiGoto { .. } => "BlockMultiGoto",
        Kind::List => "BlockList",
        Kind::Condition(_) => "BlockCondition",
        Kind::If | Kind::IfElse | Kind::IfNoExit => "BlockIf",
        Kind::IfGoto(_) => "BlockIfGoto",
        Kind::WhileDo => "BlockWhileDo",
        Kind::DoWhile => "BlockDoWhile",
        Kind::InfLoop => "BlockInfLoop",
        Kind::Switch => "BlockSwitch",
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
    fn masks() {
        assert_eq!(calc_mask(1), 0xff);
        assert_eq!(calc_mask(4), 0xffff_ffff);
        assert_eq!(calc_mask(8), u64::MAX);
    }
}
