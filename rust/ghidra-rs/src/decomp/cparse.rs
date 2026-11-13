//! The C declaration parser of the console's `parse line` (stage S6), replacing the bison
//! grammar `grammar.y`/`grammar.cc`: `struct`/`union`/`enum` definitions, `typedef`s and
//! `extern` function declarations, with pointers, arrays and function declarators. Types are
//! resolved against a [`TypeFactory`]; an unknown type name is an error, as in `parse_C`.

use super::types::{TypeFactory, TypeId};
use super::{LowlevelError, Result};

/// One parsed declaration.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Decl {
    /// a `struct`, `union`, `enum` or `typedef`: the type it defines
    Type(TypeId),
    /// an `extern` function: name, model (`__stdcall`, ...), output, inputs, and `...`
    Function { name: String, model: Option<String>, output: TypeId, inputs: Vec<(String, TypeId)>, dotdotdot: bool },
}

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Ident(String),
    Num(u64),
    Punct(char),
    Ellipsis,
}

fn lex(s: &str) -> Result<Vec<Tok>> {
    let b = s.as_bytes();
    let (mut i, mut out) = (0, Vec::new());
    while i < b.len() {
        let c = b[i] as char;
        if c.is_ascii_whitespace() {
            i += 1;
        } else if c.is_ascii_alphabetic() || c == '_' {
            let st = i;
            while i < b.len()
                && (b[i].is_ascii_alphanumeric() || b[i] == b'_' || (b[i] == b':' && b.get(i + 1) == Some(&b':')))
            {
                // a namespace path (`a::b::name`) is one name
                i += if b[i] == b':' { 2 } else { 1 };
            }
            out.push(Tok::Ident(s[st..i].to_string()));
        } else if c.is_ascii_digit() {
            let st = i;
            while i < b.len() && b[i].is_ascii_alphanumeric() {
                i += 1;
            }
            let t = &s[st..i];
            let v = match t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
                Some(h) => u64::from_str_radix(h, 16),
                None => t.parse(),
            };
            out.push(Tok::Num(v.map_err(|_| perr(&format!("bad number {t}")))?));
        } else if s[i..].starts_with("...") {
            out.push(Tok::Ellipsis);
            i += 3;
        } else if "{}()[];,*=-:".contains(c) {
            out.push(Tok::Punct(c));
            i += 1;
        } else {
            return Err(perr(&format!("unexpected character '{c}'")));
        }
    }
    Ok(out)
}

fn perr(msg: &str) -> LowlevelError {
    LowlevelError(format!("Error parsing C declaration: {msg}"))
}

/// What a declarator adds around its base type, innermost first.
enum Suffix {
    Pointer,
    Array(u32),
    Function(Vec<(String, TypeId)>, bool),
}

struct Parser<'a> {
    toks: Vec<Tok>,
    pos: usize,
    types: &'a mut TypeFactory,
    ptr_size: u32,
}

impl Parser<'_> {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }
    fn next(&mut self) -> Result<Tok> {
        let t = self.toks.get(self.pos).cloned().ok_or_else(|| perr("unexpected end of declaration"))?;
        self.pos += 1;
        Ok(t)
    }
    fn eat(&mut self, c: char) -> bool {
        if self.peek() == Some(&Tok::Punct(c)) {
            self.pos += 1;
            return true;
        }
        false
    }
    fn expect(&mut self, c: char) -> Result<()> {
        if self.eat(c) {
            Ok(())
        } else {
            Err(perr(&format!("expected '{c}'")))
        }
    }
    fn ident(&mut self) -> Result<String> {
        match self.next()? {
            Tok::Ident(s) => Ok(s),
            t => Err(perr(&format!("expected a name, found {t:?}"))),
        }
    }
    fn peek_ident(&self, word: &str) -> bool {
        matches!(self.peek(), Some(Tok::Ident(s)) if s == word)
    }

    /// A type specifier: a type name, or a `struct`/`union`/`enum` reference or definition;
    /// `const` and `volatile` are dropped.
    fn specifier(&mut self) -> Result<TypeId> {
        while self.peek_ident("const") || self.peek_ident("volatile") {
            self.pos += 1;
        }
        let word = self.ident()?;
        let ty = match word.as_str() {
            "struct" | "union" => {
                let name = self.ident()?;
                if self.eat('{') {
                    let mut members = Vec::new();
                    while !self.eat('}') {
                        let base = self.specifier()?;
                        loop {
                            let (n, t) = self.declarator(base)?;
                            if self.eat(':') {
                                return Err(perr("bit-fields are not implemented in ghidra-rs yet"));
                            }
                            members.push((n.unwrap_or_default(), t));
                            if !self.eat(',') {
                                break;
                            }
                        }
                        self.expect(';')?;
                    }
                    self.types.aggregate(&name, word == "union", members)
                } else {
                    self.types.find_by_name(&name).ok_or_else(|| perr(&format!("undefined {word} {name}")))?
                }
            }
            "enum" => {
                let name = self.ident()?;
                if self.eat('{') {
                    let (mut values, mut next) = (Vec::new(), 0u64);
                    while !self.eat('}') {
                        let n = self.ident()?;
                        if self.eat('=') {
                            let neg = self.eat('-');
                            let Tok::Num(v) = self.next()? else { return Err(perr("expected an enum value")) };
                            next = if neg { v.wrapping_neg() } else { v };
                        }
                        values.push((n, next));
                        next = next.wrapping_add(1);
                        if !self.eat(',') {
                            self.expect('}')?;
                            break;
                        }
                    }
                    self.types.enumeration(&name, values)
                } else {
                    self.types.find_by_name(&name).ok_or_else(|| perr(&format!("undefined enum {name}")))?
                }
            }
            _ => self.types.find_by_name(&word).ok_or_else(|| perr(&format!("unknown type {word}")))?,
        };
        while self.peek_ident("const") || self.peek_ident("volatile") {
            self.pos += 1;
        }
        Ok(ty)
    }

    /// A declarator around `base`: pointers, a name (or a parenthesized declarator), then array
    /// and function suffixes, applied as C does (suffixes bind tighter than `*`).
    fn declarator(&mut self, base: TypeId) -> Result<(Option<String>, TypeId)> {
        let mut suffixes = Vec::new();
        let name = self.declarator_into(&mut suffixes)?;
        let mut ty = base;
        for s in suffixes.into_iter().rev() {
            ty = match s {
                Suffix::Pointer => self.types.pointer(self.ptr_size, ty, 1),
                Suffix::Array(n) => self.types.array_of(ty, n),
                // ponytail: a function type keeps no prototype yet (TypeCode with a FuncProto)
                Suffix::Function(..) => self.types.code(),
            };
        }
        Ok((name, ty))
    }

    /// Collects the declarator's suffixes, outermost first, and returns its name.
    fn declarator_into(&mut self, out: &mut Vec<Suffix>) -> Result<Option<String>> {
        let mut ptrs = 0;
        loop {
            if self.eat('*') {
                ptrs += 1;
            } else if self.peek_ident("const") || self.peek_ident("volatile") {
                self.pos += 1;
            } else {
                break;
            }
        }
        let mut inner = Vec::new();
        let name = match self.peek().cloned() {
            Some(Tok::Ident(s)) => {
                self.pos += 1;
                Some(s)
            }
            Some(Tok::Punct('(')) if matches!(self.toks.get(self.pos + 1), Some(Tok::Punct('*'))) => {
                self.pos += 1;
                let n = self.declarator_into(&mut inner)?;
                self.expect(')')?;
                n
            }
            _ => None,
        };
        let mut post = Vec::new();
        loop {
            if self.eat('[') {
                let Tok::Num(n) = self.next()? else { return Err(perr("expected an array size")) };
                self.expect(']')?;
                post.push(Suffix::Array(u32::try_from(n).map_err(|_| perr("array too large"))?));
            } else if self.eat('(') {
                let (params, dots) = self.params()?;
                post.push(Suffix::Function(params, dots));
            } else {
                break;
            }
        }
        // outermost first: the parenthesized part, then the suffixes, then the pointers
        out.extend(inner);
        out.extend(post);
        out.extend((0..ptrs).map(|_| Suffix::Pointer));
        Ok(name)
    }

    /// A parameter list after its `(`, through the `)`.
    fn params(&mut self) -> Result<(Vec<(String, TypeId)>, bool)> {
        let (mut params, mut dots) = (Vec::new(), false);
        if self.peek_ident("void") && self.toks.get(self.pos + 1) == Some(&Tok::Punct(')')) {
            self.pos += 2;
            return Ok((params, dots));
        }
        while !self.eat(')') {
            if self.peek() == Some(&Tok::Ellipsis) {
                self.pos += 1;
                dots = true;
            } else {
                let base = self.specifier()?;
                let (n, t) = self.declarator(base)?;
                params.push((n.unwrap_or_default(), t));
            }
            if !self.eat(',') {
                self.expect(')')?;
                break;
            }
        }
        Ok((params, dots))
    }
}

/// Port of `parse_C`: one declaration, ending in `;`. `ptr_size` is the size of a pointer.
pub(crate) fn parse_line(types: &mut TypeFactory, text: &str, ptr_size: u32) -> Result<Decl> {
    let mut p = Parser { toks: lex(text)?, pos: 0, types, ptr_size };
    let decl = if p.peek_ident("typedef") {
        p.pos += 1;
        let base = p.specifier()?;
        let (name, ty) = p.declarator(base)?;
        let name = name.ok_or_else(|| perr("typedef without a name"))?;
        Decl::Type(p.types.typedef(ty, &name))
    } else if p.peek_ident("extern") {
        p.pos += 1;
        let model = match p.peek() {
            Some(Tok::Ident(s)) if s.starts_with("__") => Some(p.ident()?),
            _ => None,
        };
        let output = p.specifier()?;
        let mut suffixes = Vec::new();
        let name = p.declarator_into(&mut suffixes)?.ok_or_else(|| perr("function without a name"))?;
        // the outermost suffix must be the function's parameter list; the rest shape its output
        let mut rest = suffixes.into_iter();
        let Some(Suffix::Function(inputs, dotdotdot)) = rest.next() else {
            return Err(perr(&format!("{name} is not a function")));
        };
        let mut out = output;
        for s in rest.rev() {
            out = match s {
                Suffix::Pointer => p.types.pointer(ptr_size, out, 1),
                Suffix::Array(n) => p.types.array_of(out, n),
                Suffix::Function(..) => p.types.code(),
            };
        }
        Decl::Function { name, model, output: out, inputs, dotdotdot }
    } else {
        let ty = p.specifier()?;
        Decl::Type(ty)
    };
    p.eat(';');
    if p.pos != p.toks.len() {
        return Err(perr("extra text after the declaration"));
    }
    Ok(decl)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn declarations() {
        let mut t = TypeFactory::new();
        let Decl::Type(s) = parse_line(&mut t, "struct twostruct { int4 field1; char c; int4 array[5]; };", 4).unwrap()
        else {
            panic!()
        };
        assert_eq!((t.size(s), t.print_raw(s)), (28, "twostruct".to_string()));
        let Decl::Function { name, output, inputs, dotdotdot, .. } =
            parse_line(&mut t, "extern twostruct *f(int4 **ptr,char *,...);", 4).unwrap()
        else {
            panic!()
        };
        assert_eq!(
            (name.as_str(), t.print_raw(output), inputs.len(), dotdotdot),
            ("f", "twostruct *".to_string(), 2, true)
        );
        assert_eq!(t.print_raw(inputs[0].1), "int4 * *");
        assert!(parse_line(&mut t, "extern nosuch g(void);", 4).is_err());
    }

    /// Every `parse line` of the upstream datatests (the D corpus) parses, in file order.
    #[test]
    fn d_corpus_parse_lines() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../Ghidra/Features/Decompiler/src/decompile/datatests");
        let Ok(rd) = std::fs::read_dir(dir) else { return };
        let mut files: Vec<_> = rd.filter_map(|e| e.ok().map(|e| e.path())).collect();
        files.sort();
        let (mut n, mut failed) = (0, Vec::new());
        for f in files {
            // not parse-line gaps: bit-fields are stage R5, and pointersub.xml names a relative
            // pointer type made by `pointer setting`
            if f.file_name().is_some_and(|n| n.to_string_lossy().starts_with("bitfields") || n == "pointersub.xml") {
                continue;
            }
            let text = std::fs::read_to_string(&f).unwrap_or_default();
            let mut t = TypeFactory::new();
            // a command may span lines inside its <com> element
            for com in text.split("<com>").skip(1) {
                let Some(rest) = com.split("</com>").next().and_then(|c| c.trim_start().strip_prefix("parse line "))
                else {
                    continue;
                };
                let decl = rest.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&");
                n += 1;
                if let Err(e) = parse_line(&mut t, &decl, 4) {
                    failed.push(format!("{}: {decl}: {e}", f.display()));
                }
            }
        }
        assert!(n > 200, "{n} parse lines");
        assert!(failed.is_empty(), "{} of {n} failed:\n{}", failed.len(), failed.join("\n"));
    }
}
