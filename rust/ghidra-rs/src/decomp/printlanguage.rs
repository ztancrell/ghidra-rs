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
    Text(String),
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
            self.emit_atom(&atom);
            return Ok(());
        }
        self.emit_op_top();
        self.emit_atom(&atom);
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

    /// Port of `PrintLanguage::emitAtom` (plain text: every kind but blank prints its name).
    fn emit_atom(&mut self, atom: &Atom) {
        if let Atom::Text(s) = atom {
            self.emit.print_str(s);
        }
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
        self.push_symbol_detail(vn)
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

#[cfg(test)]
mod tests {
    use super::*;

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
