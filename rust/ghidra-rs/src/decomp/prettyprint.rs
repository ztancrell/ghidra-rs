//! `print C`, layer one: port of `EmitPrettyPrint` (prettyprint.cc) over `EmitNoMarkup`, the
//! token stream that breaks lines to the width and indents.
//!
//! Tokens wait in a queue until the breaker knows whether the group they belong to fits on the
//! line (Oppen's algorithm, as the C++ does it). The C++ queues are circular buffers that grow
//! when full, so a `VecDeque` with absolute positions behaves the same. Only the plain-text
//! output (`EmitNoMarkup`) is ported: markup tokens (blocks, statements, declarations) only
//! group, and highlighting is dropped.

use std::collections::VecDeque;

/// `TokenSplit::printclass`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    Begin,
    End,
    String,
    Break,
    BeginIndent,
    EndIndent,
    BeginComment,
    EndComment,
}

/// Port of `TokenSplit` (the fields plain text needs).
#[derive(Debug, Clone)]
struct Token {
    class: Class,
    text: String,
    /// `tagLine(indent)` (`line_t`): an absolute indent rather than a relative one
    line: bool,
    indentbump: i32,
    numspaces: i32,
    size: i32,
}

impl Token {
    fn new(class: Class) -> Token {
        Token { class, text: String::new(), line: false, indentbump: 0, numspaces: 0, size: 0 }
    }
}

/// Port of `EmitPrettyPrint` with an `EmitNoMarkup` low-level emitter writing to a string.
#[derive(Debug)]
pub(crate) struct EmitPrettyPrint {
    out: String,
    tokqueue: VecDeque<Token>,
    /// the absolute position of `tokqueue[0]`
    base: usize,
    /// absolute positions in `tokqueue`
    scanqueue: VecDeque<usize>,
    indentstack: Vec<i32>,
    spaceremain: i32,
    maxlinesize: i32,
    indentincrement: i32,
    leftotal: i32,
    rightotal: i32,
    needbreak: bool,
    commentmode: bool,
    commentfill: String,
    /// the first error (`LowlevelError` in the C++), reported by [`EmitPrettyPrint::flush`]
    error: Option<String>,
}

impl EmitPrettyPrint {
    /// `EmitPrettyPrint` with `setMaxLineSize(width)` (100 by default) and an indent
    /// increment of 2.
    pub(crate) fn new(width: i32) -> EmitPrettyPrint {
        EmitPrettyPrint {
            out: String::new(),
            tokqueue: VecDeque::new(),
            base: 0,
            scanqueue: VecDeque::new(),
            indentstack: Vec::new(),
            spaceremain: width,
            maxlinesize: width,
            indentincrement: 2,
            leftotal: 1,
            rightotal: 1,
            needbreak: false,
            commentmode: false,
            commentfill: String::new(),
            error: None,
        }
    }

    /// `setCommentFill`
    pub(crate) fn set_comment_fill(&mut self, fill: &str) {
        self.commentfill = fill.to_string();
    }

    fn fail(&mut self, msg: &str) {
        self.error.get_or_insert_with(|| msg.to_string());
    }

    /// The class of the queued token at absolute position `pos` (one the scan queue refers to,
    /// so still queued: its size is unknown).
    fn class_at(&self, pos: usize) -> Option<Class> {
        self.tokqueue.get(pos.wrapping_sub(self.base)).map(|t| t.class)
    }

    /// Set the size of the queued token at `pos` (`f` of its size).
    fn set_size(&mut self, pos: usize, f: impl FnOnce(i32) -> i32) {
        match self.tokqueue.get_mut(pos.wrapping_sub(self.base)) {
            Some(t) => t.size = f(t.size),
            None => self.fail("prettyprint scan queue lost a token"),
        }
    }

    fn indent_top(&mut self) -> i32 {
        match self.indentstack.last() {
            Some(&v) => v,
            None => {
                self.fail("indent error");
                self.maxlinesize
            }
        }
    }

    // EmitNoMarkup
    fn low_tag_line(&mut self, indent: i32) {
        self.out.push('\n');
        self.out.extend(std::iter::repeat_n(' ', indent.max(0) as usize));
    }
    fn low_spaces(&mut self, n: i32) {
        self.out.extend(std::iter::repeat_n(' ', n.max(0) as usize));
    }

    /// Port of `EmitPrettyPrint::overflow`.
    fn overflow(&mut self) {
        let half = self.maxlinesize / 2;
        for v in self.indentstack.iter_mut().rev() {
            if *v < half {
                *v = half;
            } else {
                break;
            }
        }
        let newspaceremain = self.indentstack.last().copied().unwrap_or(self.maxlinesize);
        if newspaceremain == self.spaceremain {
            return;
        }
        if self.commentmode && newspaceremain == self.spaceremain + self.commentfill.len() as i32 {
            return;
        }
        self.spaceremain = newspaceremain;
        self.low_tag_line(self.maxlinesize - self.spaceremain);
        self.print_fill();
    }

    fn print_fill(&mut self) {
        if self.commentmode && !self.commentfill.is_empty() {
            let fill = self.commentfill.clone();
            self.out.push_str(&fill);
            self.spaceremain -= fill.len() as i32;
        }
    }

    /// Port of `EmitPrettyPrint::print(const TokenSplit &)`.
    fn print(&mut self, tok: &Token) {
        match tok.class {
            Class::BeginIndent => {
                let v = self.indent_top() - tok.indentbump;
                self.indentstack.push(v);
            }
            Class::BeginComment | Class::Begin => {
                if tok.class == Class::BeginComment {
                    self.commentmode = true;
                }
                self.indentstack.push(self.spaceremain);
            }
            Class::EndIndent => {
                if self.indentstack.pop().is_none() {
                    self.fail("indent error");
                }
            }
            Class::EndComment | Class::End => {
                if tok.class == Class::EndComment {
                    self.commentmode = false;
                }
                if self.indentstack.pop().is_none() {
                    self.fail("indent error");
                }
            }
            Class::String => {
                if tok.size > self.spaceremain {
                    self.overflow();
                }
                self.out.push_str(&tok.text);
                self.spaceremain -= tok.size;
            }
            Class::Break => {
                if tok.size > self.spaceremain {
                    if tok.line {
                        self.spaceremain = self.maxlinesize - tok.indentbump;
                    } else {
                        let val = self.indent_top() - tok.indentbump;
                        // a line break that saves little is not taken
                        if tok.numspaces <= self.spaceremain && val - self.spaceremain < 10 {
                            self.low_spaces(tok.numspaces);
                            self.spaceremain -= tok.numspaces;
                            return;
                        }
                        if let Some(top) = self.indentstack.last_mut() {
                            *top = val;
                        }
                        self.spaceremain = val;
                    }
                    self.low_tag_line(self.maxlinesize - self.spaceremain);
                    self.print_fill();
                } else {
                    self.low_spaces(tok.numspaces);
                    self.spaceremain -= tok.numspaces;
                }
            }
        }
    }

    /// Port of `EmitPrettyPrint::advanceleft`: print the tokens whose size is known.
    fn advanceleft(&mut self) {
        while let Some(tok) = self.tokqueue.front() {
            let l = tok.size;
            if l < 0 {
                break;
            }
            let tok = tok.clone();
            self.print(&tok);
            match tok.class {
                Class::Break => self.leftotal += tok.numspaces,
                Class::String => self.leftotal += l,
                _ => {}
            }
            self.tokqueue.pop_front();
            self.base += 1;
        }
    }

    /// Port of `EmitPrettyPrint::scan`, run on each token as it is queued.
    fn push(&mut self, mut tok: Token) {
        let top = self.base + self.tokqueue.len();
        match tok.class {
            Class::BeginComment | Class::Begin => {
                if self.scanqueue.is_empty() {
                    self.leftotal = 1;
                    self.rightotal = 1;
                }
                tok.size = -self.rightotal;
                self.tokqueue.push_back(tok);
                self.scanqueue.push_back(top);
            }
            Class::EndComment | Class::End => {
                tok.size = 0;
                self.tokqueue.push_back(tok);
                if let Some(r) = self.scanqueue.pop_back() {
                    let rt = self.rightotal;
                    self.set_size(r, |s| s + rt);
                    if self.class_at(r) == Some(Class::Break) {
                        if let Some(r2) = self.scanqueue.pop_back() {
                            self.set_size(r2, |s| s + rt);
                        }
                    }
                    if self.scanqueue.is_empty() {
                        self.advanceleft();
                    }
                }
            }
            Class::Break => {
                if self.scanqueue.is_empty() {
                    self.leftotal = 1;
                    self.rightotal = 1;
                } else if let Some(&r) = self.scanqueue.back() {
                    let rt = self.rightotal;
                    if self.class_at(r) == Some(Class::Break) {
                        self.scanqueue.pop_back();
                        self.set_size(r, |s| s + rt);
                    }
                }
                tok.size = -self.rightotal;
                self.rightotal += tok.numspaces;
                self.tokqueue.push_back(tok);
                self.scanqueue.push_back(top);
            }
            Class::BeginIndent | Class::EndIndent => {
                tok.size = 0;
                self.tokqueue.push_back(tok);
            }
            Class::String => {
                let size = tok.size;
                self.tokqueue.push_back(tok);
                if !self.scanqueue.is_empty() {
                    self.rightotal += size;
                    while self.rightotal - self.leftotal > self.spaceremain {
                        let Some(r) = self.scanqueue.pop_front() else { break };
                        self.set_size(r, |_| 999999);
                        self.advanceleft();
                        if self.scanqueue.is_empty() {
                            break;
                        }
                    }
                }
            }
        }
    }

    fn push_string(&mut self, text: &str) {
        let mut t = Token::new(Class::String);
        t.text = text.to_string();
        t.size = text.len() as i32;
        self.push(t);
    }

    fn push_spaces(&mut self, num: i32, bump: i32) {
        let mut t = Token::new(Class::Break);
        t.numspaces = num;
        t.indentbump = bump;
        self.push(t);
    }

    /// `checkstart`
    fn checkstart(&mut self) {
        if self.needbreak {
            self.push_spaces(0, 0);
        }
        self.needbreak = false;
    }
    /// `checkstring`
    fn checkstring(&mut self) {
        if self.needbreak {
            self.push_spaces(0, 0);
        }
        self.needbreak = true;
    }
    /// `checkend`
    fn checkend(&mut self) {
        if !self.needbreak {
            self.push_string("");
        }
        self.needbreak = true;
    }
    /// `checkbreak`
    fn checkbreak(&mut self) {
        if !self.needbreak {
            self.push_string("");
        }
        self.needbreak = false;
    }

    /// `openGroup`, and every markup begin (`beginFunction`, `beginStatement`,
    /// `beginVarDecl`, `beginReturnType`, `beginFuncProto`)
    pub(crate) fn open_group(&mut self) {
        self.checkstart();
        self.push(Token::new(Class::Begin));
    }
    /// `closeGroup`, and the markup ends
    pub(crate) fn close_group(&mut self) {
        self.checkend();
        self.push(Token::new(Class::End));
    }

    /// `print` and every `tag*` call of a name, operator, type or comment word
    pub(crate) fn print_str(&mut self, text: &str) {
        self.checkstring();
        self.push_string(text);
    }

    /// `openParen`
    pub(crate) fn open_paren(&mut self, paren: &str) {
        self.open_group();
        let mut t = Token::new(Class::String);
        t.text = paren.to_string();
        t.size = 1;
        self.push(t);
        self.needbreak = true;
    }
    /// `closeParen`
    pub(crate) fn close_paren(&mut self, paren: &str) {
        self.checkstring();
        let mut t = Token::new(Class::String);
        t.text = paren.to_string();
        t.size = 1;
        self.push(t);
        self.close_group();
    }

    /// `spaces(num, bump)`
    pub(crate) fn spaces(&mut self, num: i32, bump: i32) {
        self.checkbreak();
        self.push_spaces(num, bump);
    }

    /// `tagLine()`: a line break at the current indent
    pub(crate) fn tag_line(&mut self) {
        self.checkbreak();
        let mut t = Token::new(Class::Break);
        t.numspaces = 999999;
        self.push(t);
    }
    /// `tagLine(indent)`: a line break to an absolute indent
    pub(crate) fn tag_line_indent(&mut self, indent: i32) {
        self.checkbreak();
        let mut t = Token::new(Class::Break);
        t.numspaces = 999999;
        t.indentbump = indent;
        t.line = true;
        self.push(t);
    }

    /// `startIndent`
    pub(crate) fn start_indent(&mut self) {
        let mut t = Token::new(Class::BeginIndent);
        t.indentbump = self.indentincrement;
        self.push(t);
    }
    /// `stopIndent`
    pub(crate) fn stop_indent(&mut self) {
        self.push(Token::new(Class::EndIndent));
    }

    /// `startComment`
    pub(crate) fn start_comment(&mut self) {
        self.checkstart();
        self.push(Token::new(Class::BeginComment));
    }
    /// `stopComment`
    pub(crate) fn stop_comment(&mut self) {
        self.checkend();
        self.push(Token::new(Class::EndComment));
    }

    /// `Emit::openBraceIndent` with `skip_line`, the style of a function body
    /// (`option_brace_func`); the other styles come with the if and loop blocks.
    pub(crate) fn open_brace_indent(&mut self, brace: &str) {
        self.tag_line();
        self.tag_line();
        self.start_indent();
        self.print_str(brace);
    }
    /// `Emit::closeBraceIndent`
    pub(crate) fn close_brace_indent(&mut self, brace: &str) {
        self.stop_indent();
        self.tag_line();
        self.print_str(brace);
    }

    /// Port of `EmitPrettyPrint::flush`: print what is queued and hand back the text.
    pub(crate) fn flush(&mut self) -> Result<String, String> {
        while let Some(tok) = self.tokqueue.pop_front() {
            self.base += 1;
            if tok.size < 0 {
                return Err("Cannot flush pretty printer. Missing group end".into());
            }
            self.print(&tok);
        }
        self.needbreak = false;
        self.scanqueue.clear();
        if let Some(e) = self.error.take() {
            return Err(e);
        }
        Ok(std::mem::take(&mut self.out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `a = b + c;` as PrintC emits it: group, operands, operator spacing.
    fn statement(e: &mut EmitPrettyPrint, lhs: &str, terms: &[&str]) {
        e.tag_line();
        e.open_group(); // beginStatement
        e.open_group(); // the assignment
        e.print_str(lhs);
        e.spaces(1, 0);
        e.print_str("=");
        e.spaces(1, 0);
        e.open_group();
        for (i, t) in terms.iter().enumerate() {
            if i > 0 {
                e.spaces(1, 0);
                e.print_str("+");
                e.spaces(1, 0);
            }
            e.print_str(t);
        }
        e.close_group();
        e.close_group();
        e.close_group();
        e.print_str(";");
    }

    fn body(width: i32, f: impl Fn(&mut EmitPrettyPrint)) -> String {
        let mut e = EmitPrettyPrint::new(width);
        e.open_group(); // beginFunction
        e.print_str("f");
        e.open_brace_indent("{");
        f(&mut e);
        e.close_brace_indent("}");
        e.tag_line();
        e.close_group();
        e.flush().unwrap()
    }

    #[test]
    fn short_lines_stay_whole_and_indent() {
        let s = body(100, |e| statement(e, "x", &["a", "b"]));
        assert_eq!(s, "f\n\n{\n  x = a + b;\n}\n");
    }

    #[test]
    fn long_expression_breaks_at_a_space_with_bump() {
        let terms = ["aaaaaaaaaa", "bbbbbbbbbb", "cccccccccc", "dddddddddd"];
        let s = body(30, |e| statement(e, "x", &terms));
        // every line fits the width; the first break comes where the line overflows, at the
        // innermost open group, the second at the next space that does not fit
        for line in s.lines() {
            assert!(line.len() <= 30, "{line:?} is too long in {s:?}");
        }
        assert_eq!(s, "f\n\n{\n  x = aaaaaaaaaa + bbbbbbbbbb\n      + cccccccccc +\n      dddddddddd;\n}\n");
    }

    #[test]
    fn absolute_indent_and_comment_fill() {
        let mut e = EmitPrettyPrint::new(20);
        e.set_comment_fill("   ");
        e.open_group();
        e.tag_line_indent(0);
        e.start_comment();
        e.print_str("/* ");
        for (i, w) in ["one", "two", "three", "four", "five"].iter().enumerate() {
            if i > 0 {
                e.spaces(1, 0);
            }
            e.print_str(w);
        }
        e.print_str(" */");
        e.stop_comment();
        e.tag_line();
        e.close_group();
        let s = e.flush().unwrap();
        assert_eq!(s, "\n/* one two three\n   four five */\n");
    }

    #[test]
    fn missing_group_end_fails() {
        let mut e = EmitPrettyPrint::new(100);
        e.open_group();
        e.print_str("x");
        assert!(e.flush().is_err());
    }
}
