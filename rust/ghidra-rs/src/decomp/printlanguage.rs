//! `print C`, layer two: port of the expression machinery of `PrintLanguage`
//! (printlanguage.cc): the reverse-Polish stack of operator tokens, the pending varnodes, the
//! parenthesis rule and the number-base choice. The C-specific parts are in `printc.rs`.

use super::op::OpId;
use super::prettyprint::EmitPrettyPrint;
use super::varnode::{VarnodeId, VnFlags};
use super::{err, Arch, Funcdata, Result};

/// `OpToken::tokentype`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TokenType {
    Binary,
    UnaryPrefix,
    Postsurround,
    Presurround,
    Space,
    HiddenFunction,
}

/// Port of `OpToken`: an operator's text, precedence and spacing. Tokens are `static`s
/// compared by address, as the C++ compares the pointers.
#[derive(Debug)]
pub(crate) struct OpToken {
    pub(crate) print1: &'static str,
    pub(crate) print2: &'static str,
    pub(crate) stage: u32,
    pub(crate) precedence: i32,
    pub(crate) associative: bool,
    pub(crate) ty: TokenType,
    pub(crate) spacing: i32,
    pub(crate) bump: i32,
}

/// `PrintLanguage::modifiers` (the ones ported).
pub(crate) mod modifier {
    pub(crate) const NO_BRANCH: u32 = 0x80;
    pub(crate) const ONLY_BRANCH: u32 = 0x100;
    pub(crate) const COMMA_SEPARATE: u32 = 0x200;
    pub(crate) const PENDING_BRACE: u32 = 0x8000;
    pub(crate) const FORCE_HEX: u32 = 1;
    pub(crate) const FORCE_DEC: u32 = 2;
    pub(crate) const FORCE_POINTER: u32 = 0x10;
    pub(crate) const PRINT_LOAD_VALUE: u32 = 0x20;
    pub(crate) const PRINT_STORE_VALUE: u32 = 0x40;
    pub(crate) const NEGATETOKEN: u32 = 0x2000;
}

/// Port of `PrintLanguage::ReversePolish`.
#[derive(Debug, Clone, Copy)]
struct ReversePolish {
    tok: &'static OpToken,
    visited: u32,
    paren: bool,
}

/// Port of `PrintLanguage::NodePending`.
#[derive(Debug, Clone, Copy)]
struct NodePending {
    vn: VarnodeId,
    /// the op reading `vn`
    op: OpId,
    mods: u32,
}

/// A leaf token (`PrintLanguage::Atom`): its text, or nothing (`blanktoken`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Atom {
    /// an operator, keyword or constant token: printed as it is
    Text(String),
    /// a function, variable, type, field or label name that is not a constant: Java's
    /// `PrettyPrinter` (`DecompileResults.getDecompiledFunction`) prints it through
    /// `IllegalCharCppTransformer` ([`clean_name`])
    Name(String),
    Blank,
}

/// The deepest block nesting the printer recurses into.
pub(crate) const MAX_DEPTH: u32 = 1000;

/// The printer: `PrintC` with its `PrintLanguage` state, printing one function.
pub(crate) struct PrintC<'a> {
    pub(crate) fd: &'a mut Funcdata,
    pub(crate) arch: &'a Arch,
    pub(crate) emit: EmitPrettyPrint,
    revpol: Vec<ReversePolish>,
    nodepend: Vec<NodePending>,
    pending: usize,
    pub(crate) mods: u32,
    modstack: Vec<u32>,
    /// the block nesting being printed
    pub(crate) depth: u32,
    /// the body comments (`commsorter`)
    pub(crate) commsorter: super::comment::CommentSorter,
    /// the `ns` text of the namespace of the function being printed (`a::b::`), once its
    /// declaration is printed (`pushScope` of its local scope); empty in the global one
    pub(crate) scope: String,
    /// `StringManager::stringMap`: the string read at an address (its code points and whether
    /// it was truncated; none: no string), kept for the next constant at that address, whatever
    /// its character type
    pub(crate) strings: std::collections::HashMap<u64, Option<(Vec<i32>, bool)>>,
}

impl<'a> PrintC<'a> {
    pub(crate) fn new(fd: &'a mut Funcdata, arch: &'a Arch) -> PrintC<'a> {
        let mut emit = EmitPrettyPrint::new(100);
        emit.set_comment_fill("   "); // setCStyleComments: "/* " ... " */", filled with spaces
        PrintC {
            fd,
            arch,
            emit,
            revpol: Vec::new(),
            nodepend: Vec::new(),
            pending: 0,
            mods: 0,
            modstack: Vec::new(),
            depth: 0,
            commsorter: Default::default(),
            scope: String::new(),
            strings: Default::default(),
        }
    }

    pub(crate) fn is_set(&self, m: u32) -> bool {
        self.mods & m != 0
    }
    pub(crate) fn push_mod(&mut self) {
        self.modstack.push(self.mods);
    }
    pub(crate) fn pop_mod(&mut self) {
        if let Some(m) = self.modstack.pop() {
            self.mods = m;
        }
    }
    pub(crate) fn set_mod(&mut self, m: u32) {
        self.mods |= m;
    }
    pub(crate) fn unset_mod(&mut self, m: u32) {
        self.mods &= !m;
    }

    /// Port of `PrintLanguage::pushOp`.
    pub(crate) fn push_op(&mut self, tok: &'static OpToken) -> Result<()> {
        if self.pending < self.nodepend.len() {
            self.recurse()?;
        }
        let paren = if self.revpol.is_empty() {
            self.emit.open_group();
            false
        } else {
            self.emit_op_top();
            let paren = self.parentheses(tok);
            if paren {
                self.emit.open_paren("(");
            } else {
                self.emit.open_group();
            }
            paren
        };
        self.revpol.push(ReversePolish { tok, visited: 0, paren });
        Ok(())
    }

    /// Port of `PrintLanguage::pushAtom`.
    pub(crate) fn push_atom(&mut self, atom: Atom) -> Result<()> {
        if self.pending < self.nodepend.len() {
            self.recurse()?;
        }
        if self.revpol.is_empty() {
            self.emit_atom(&atom)?;
            return Ok(());
        }
        self.emit_op_top();
        self.emit_atom(&atom)?;
        while let Some(top) = self.revpol.last_mut() {
            top.visited += 1;
            if top.visited != top.tok.stage {
                break;
            }
            self.emit_op_top();
            match self.revpol.pop().map(|t| t.paren) {
                Some(true) => self.emit.close_paren(")"),
                _ => self.emit.close_group(),
            }
        }
        Ok(())
    }

    /// Port of `PrintLanguage::pushVn`: the expression of `vn`, read by `op`, is pushed later by
    /// `recurse`; inputs are pushed last first.
    pub(crate) fn push_vn(&mut self, vn: VarnodeId, op: OpId, mods: u32) {
        self.nodepend.push(NodePending { vn, op, mods });
    }

    /// Port of `PrintLanguage::recurse`: push every pending varnode's expression.
    pub(crate) fn recurse(&mut self) -> Result<()> {
        let modsave = self.mods;
        let last = self.pending;
        self.pending = self.nodepend.len();
        while last < self.pending {
            let Some(n) = self.nodepend.pop() else { break };
            self.pending -= 1;
            self.mods = n.mods;
            if self.fd.vn(n.vn).has(VnFlags::IMPLIED) {
                let Some(def) = self.fd.vn(n.vn).def else {
                    return err("print C: an implied varnode without a defining op");
                };
                self.push_opcode(def, Some(n.op))?;
            } else {
                self.push_vn_explicit(n.vn)?;
            }
            self.pending = self.nodepend.len();
        }
        self.mods = modsave;
        Ok(())
    }

    /// Port of `PrintLanguage::opBinary`.
    pub(crate) fn op_binary(&mut self, tok: &'static OpToken, op: OpId) -> Result<()> {
        let tok = if self.is_set(modifier::NEGATETOKEN) {
            self.mods &= !modifier::NEGATETOKEN;
            super::printc::negate(tok).ok_or_else(|| super::LowlevelError("Could not find fliptoken".into()))?
        } else {
            tok
        };
        self.push_op(tok)?;
        let ins = &self.fd.op(op).ins;
        let (a, b) = (ins[0], ins[1]);
        self.push_vn(b, op, self.mods);
        self.push_vn(a, op, self.mods);
        Ok(())
    }

    /// Port of `PrintLanguage::opUnary`.
    pub(crate) fn op_unary(&mut self, tok: &'static OpToken, op: OpId) -> Result<()> {
        self.push_op(tok)?;
        self.push_vn(self.fd.op(op).ins[0], op, self.mods);
        Ok(())
    }

    /// Port of `PrintLanguage::parentheses`: whether `op2`, an input of the token on top of
    /// the stack, needs parentheses.
    fn parentheses(&self, op2: &'static OpToken) -> bool {
        let Some(top) = self.revpol.last() else { return false };
        let t = top.tok;
        let stage = top.visited;
        let prec = || t.precedence.cmp(&op2.precedence);
        use std::cmp::Ordering::{Greater, Less};
        match t.ty {
            TokenType::Space | TokenType::Binary => match prec() {
                Greater => true,
                Less => false,
                _ if t.associative && std::ptr::eq(t, op2) => false,
                _ => !(op2.ty == TokenType::Postsurround && stage == 0),
            },
            TokenType::UnaryPrefix => match prec() {
                Greater => true,
                Less => false,
                _ => !matches!(op2.ty, TokenType::UnaryPrefix | TokenType::Presurround),
            },
            TokenType::HiddenFunction => {
                if stage == 0 && self.revpol.len() > 1 {
                    // the new token prints next to the token before the hidden one
                    let prev = self.revpol[self.revpol.len() - 2].tok;
                    if !matches!(prev.ty, TokenType::Binary | TokenType::UnaryPrefix) {
                        return false;
                    }
                    if prev.precedence < op2.precedence {
                        return false;
                    }
                }
                true
            }
            TokenType::Postsurround => match prec() {
                _ if stage == 1 => false,
                Greater => true,
                Less => false,
                _ => !matches!(op2.ty, TokenType::Postsurround | TokenType::Binary),
            },
            TokenType::Presurround => match prec() {
                _ if stage == 0 => false,
                Greater => true,
                Less => false,
                _ => !matches!(op2.ty, TokenType::UnaryPrefix | TokenType::Presurround),
            },
        }
    }

    /// Port of `PrintLanguage::emitOp` on the top of the stack.
    fn emit_op_top(&mut self) {
        if let Some(&ReversePolish { tok, visited, .. }) = self.revpol.last() {
            self.emit_op(tok, visited);
        }
    }

    /// Port of `PrintLanguage::emitOp` of a token at stage `visited`.
    pub(crate) fn emit_op(&mut self, tok: &OpToken, visited: u32) {
        match tok.ty {
            TokenType::Binary => {
                if visited != 1 {
                    return;
                }
                self.emit.spaces(tok.spacing, tok.bump);
                self.emit.print_str(tok.print1);
                self.emit.spaces(tok.spacing, tok.bump);
            }
            TokenType::UnaryPrefix => {
                if visited != 0 {
                    return;
                }
                self.emit.print_str(tok.print1);
                self.emit.spaces(tok.spacing, tok.bump);
            }
            TokenType::Postsurround => {
                if visited == 0 {
                    return;
                }
                if visited == 1 {
                    self.emit.spaces(tok.spacing, tok.bump);
                    self.emit.open_paren(tok.print1);
                    self.emit.spaces(0, tok.bump);
                } else {
                    self.emit.close_paren(tok.print2);
                }
            }
            TokenType::Presurround => {
                if visited == 2 {
                    return;
                }
                if visited == 0 {
                    self.emit.open_paren(tok.print1);
                } else {
                    self.emit.close_paren(tok.print2);
                    self.emit.spaces(tok.spacing, tok.bump);
                }
            }
            TokenType::Space => {
                if visited == 1 {
                    self.emit.spaces(tok.spacing, tok.bump);
                }
            }
            TokenType::HiddenFunction => {}
        }
    }

    /// The text of a name token: with Java's facts loaded ghidra-rs prints what Java's
    /// `DecompileResults.getDecompiledFunction` prints, the name cleaned by its
    /// `PrettyPrinter` ([`clean_name`]); without them, what the C++ console prints (the name).
    pub(crate) fn name_text(&self, name: &str) -> Result<String> {
        if let Some(facts) = self.arch.facts.as_ref() {
            // emitSymbolScope: the scopes printed from the function's own namespace
            match self.scope.is_empty() {
                true => clean_name(name),
                false => clean_name(&facts.scoped_name(&self.scope, name)?.0),
            }
        } else {
            Ok(name.to_string())
        }
    }

    /// Port of `PrintLanguage::emitAtom` (plain text: every kind but blank prints its name; a
    /// name as Java's `PrettyPrinter` cleans it).
    fn emit_atom(&mut self, atom: &Atom) -> Result<()> {
        match atom {
            Atom::Text(s) => self.emit.print_str(s),
            Atom::Name(s) => {
                let text = self.name_text(s)?;
                self.emit.print_str(&text)
            }
            Atom::Blank => {}
        }
        Ok(())
    }

    /// Port of `PrintLanguage::pushVnExplicit`.
    fn push_vn_explicit(&mut self, vn: VarnodeId) -> Result<()> {
        let v = self.fd.vn(vn);
        if v.is_annotation() {
            return err("print C: an annotation varnode (pushAnnotation) is not ported");
        }
        if v.is_constant() {
            return self.push_constant_vn(vn);
        }
        self.push_symbol_detail(vn, true)
    }
}

/// Port of `PrintLanguage::mostNaturalBase`: 10 or 16, by the runs of 0/9 and 0/f digits.
pub(crate) fn most_natural_base(val: u64) -> u32 {
    if val == 0 {
        return 10;
    }
    let mut countdec = 0;
    let mut tmp = val;
    let setdig = tmp % 10;
    if setdig == 0 || setdig == 9 {
        countdec += 1;
        tmp /= 10;
        while tmp != 0 && tmp % 10 == setdig {
            countdec += 1;
            tmp /= 10;
        }
    }
    let hex = match countdec {
        0 => true,
        1 => tmp > 1 || setdig == 9,
        2 => tmp > 10,
        3 | 4 => tmp > 100,
        _ => tmp > 1000,
    };
    if hex {
        return 16;
    }
    let mut counthex = 0;
    let mut tmp = val;
    let setdig = tmp & 0xf;
    if setdig == 0 || setdig == 0xf {
        counthex += 1;
        tmp >>= 4;
        while tmp != 0 && tmp & 0xf == setdig {
            counthex += 1;
            tmp >>= 4;
        }
    }
    if countdec > counthex {
        10
    } else {
        16
    }
}

/// Where the namespace path glued before a name ends: the last `::` outside template brackets.
pub(crate) fn scope_cut(name: &str) -> Option<usize> {
    let mut depth = 0u32;
    let mut cut = None;
    for (i, c) in name.char_indices() {
        match c {
            '<' => depth += 1,
            '>' => depth = depth.saturating_sub(1),
            ':' if depth == 0 && name[i + 1..].starts_with(':') => cut = Some(i),
            _ => {}
        }
    }
    cut
}

/// A name as Java's `PrettyPrinter` prints it: the facts glue a symbol's namespace path to its
/// name (`ns::name`), which the C++ prints as separate syntax tokens (`emitSymbolScope`, not
/// cleaned) before the name token (cleaned, [`illegal_char_cpp`]). The prefix is the text up to
/// the last `::` outside template brackets.
pub(crate) fn clean_name(name: &str) -> Result<String> {
    match scope_cut(name) {
        Some(i) => Ok(format!("{}::{}", &name[..i], illegal_char_cpp(&name[i + 2..])?)),
        None => illegal_char_cpp(name),
    }
}

/// Port of `IllegalCharCppTransformer.simplify` (Java, Decompiler): each character not legal in a
/// C++ identifier at its position becomes `_`. Letters are always legal; `_` and digits after the
/// first character (`_` and `~` also first); `*:()[],&~` inside template brackets; operator
/// characters right after a leading `operator`. Positions count UTF-16 units, as Java's `String`
/// does: a character outside the BMP is two illegal units, so two `_`. A non-ASCII alphabetic
/// character is an error: `Character.isLetter` (general categories L*) is not ported, and Rust's
/// `is_alphabetic` is a wider set.
pub(crate) fn illegal_char_cpp(input: &str) -> Result<String> {
    const AFTER_FIRST: u8 = 1;
    const TEMPLATE: u8 = 2;
    const OPERATOR: u8 = 4;
    const FIRST: u8 = 8;
    fn legal(c: char) -> u8 {
        match c {
            '_' => AFTER_FIRST | TEMPLATE | OPERATOR | FIRST,
            '0'..='9' => AFTER_FIRST | TEMPLATE | OPERATOR,
            '*' | '(' | ')' | '[' | ']' | '&' => TEMPLATE | OPERATOR,
            ':' | ',' => TEMPLATE,
            '+' | '-' | '|' | '=' | '!' | '/' | '%' | '^' => OPERATOR,
            '~' => TEMPLATE | OPERATOR | FIRST,
            _ => 0,
        }
    }
    let operator = input.starts_with("operator");
    let mut depth = 0u32;
    let mut out = String::with_capacity(input.len());
    let mut i = 0usize; // the UTF-16 index of `c`
    for c in input.chars() {
        let units = c.len_utf16();
        let ok = if c.is_ascii_alphabetic() {
            true
        } else if c.is_alphabetic() {
            return err(format!("print C: the name {input:?} has a non-ASCII letter (Character.isLetter) not ported"));
        } else if c == '<' {
            depth += 1;
            true
        } else if c == '>' {
            depth = depth.saturating_sub(1);
            true
        } else {
            let val = legal(c);
            (val & AFTER_FIRST != 0 && i > 0)
                || (val & FIRST != 0 && i == 0)
                || (val & TEMPLATE != 0 && depth > 0)
                || (val & OPERATOR != 0 && (8..=10).contains(&i) && operator)
        };
        if ok {
            out.push(c);
        } else {
            out.extend(std::iter::repeat_n('_', units));
        }
        i += units;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn illegal_char_cpp_as_java() {
        let s = |t: &str| illegal_char_cpp(t).ok();
        assert_eq!(s("_BinkPause@8").as_deref(), Some("_BinkPause_8"));
        assert_eq!(s("8a~b").as_deref(), Some("_a_b"));
        assert_eq!(s("~A").as_deref(), Some("~A"));
        assert_eq!(s("vec<int*,a::b> x").as_deref(), Some("vec<int*,a::b>_x"));
        assert_eq!(s("a::b").as_deref(), Some("a__b"));
        assert_eq!(s("operator==").as_deref(), Some("operator=="));
        assert_eq!(s("x\u{1F600}").as_deref(), Some("x__"));
        assert!(s("\u{e9}").is_none());
        assert_eq!(clean_name("hkpEntityListener::vftable").ok().as_deref(), Some("hkpEntityListener::vftable"));
        assert_eq!(clean_name("a@b::f@4").ok().as_deref(), Some("a@b::f_4"));
    }

    #[test]
    fn natural_base() {
        assert_eq!(most_natural_base(0), 10);
        assert_eq!(most_natural_base(100), 10);
        assert_eq!(most_natural_base(1000), 10);
        assert_eq!(most_natural_base(0x1a1), 16);
        assert_eq!(most_natural_base(999), 10);
        assert_eq!(most_natural_base(0x100), 16);
        assert_eq!(most_natural_base(0xffffffff), 16);
        assert_eq!(most_natural_base(20), 16); // one trailing 0 before a digit above 1
        assert_eq!(most_natural_base(19), 16);
    }
}
