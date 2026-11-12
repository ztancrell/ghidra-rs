//! P-code injection: the `.cspec` `<callfixup>` snippets (port of `pcodeinject.cc`,
//! `inject_sleigh.cc` and the snippet part of `pcodecompile.cc`/`pcodeparse.y`).
//!
//! A snippet is p-code source (`ESP = ESP + 4 - EAX;`). The C++ compiles it with the SLEIGH
//! semantic grammar; this is a small parser for the subset snippets use: assignments to
//! registers and new temporaries (`name = e;`, `name:4 = e;`, `local name = e;`), stores
//! (`*[space]:size e = e;`), and expressions of registers, integers, loads, parentheses and the
//! integer and boolean operators. Anything else (user ops, branches, float and signed operators)
//! is an error at load time.
//!
//! What reaches the output is kept exact: every operator and every named temporary takes the
//! next 16-byte slot of the unique space (`PcodeSnippet::allocateTemp`), counting on from one
//! snippet to the next as `PcodeInjectLibrarySleigh::parseInject` does, so injected temporaries
//! print as `u0x00309190` like the reference's.

use super::cspec::SleighNames;
use super::opcode::Opcode;
use super::{err, LowlevelError, Result};
use crate::sleigh::{PcodeOp, Sleigh, Varnode};
use std::collections::HashMap;

/// `Translate::INJECT`: where injection temporaries start, above the `.sla`'s unique base.
const INJECT_UNIQUE_START: u64 = 0x200;
/// `PcodeSnippet::allocateTemp`'s step.
const TEMP_STEP: u64 = 16;
/// Size of the space-id constant of a LOAD/STORE template (`ConstTpl(ConstTpl::real,8)`).
const SPACE_ID_SIZE: u32 = 8;

/// Index of a payload in [`InjectLibrary::payloads`] (the C++ inject id).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct InjectId(pub(crate) u32);

/// Port of `InjectPayloadSleigh` for a call fixup: the compiled ops, emitted at the call's
/// address in place of the call.
#[derive(Debug)]
pub(crate) struct InjectPayload {
    pub(crate) name: String,
    pub(crate) ops: Vec<PcodeOp>,
}

/// Port of `PcodeInjectLibrarySleigh`, the call fixups only.
#[derive(Debug, Default)]
pub(crate) struct InjectLibrary {
    payloads: Vec<InjectPayload>,
    /// the next free temporary (`PcodeInjectLibrarySleigh::tempbase`)
    tempbase: u64,
}

impl InjectLibrary {
    pub(crate) fn new(sleigh: &Sleigh) -> InjectLibrary {
        InjectLibrary { payloads: Vec::new(), tempbase: sleigh.uniq_base() + INJECT_UNIQUE_START }
    }

    /// Port of `PcodeInjectLibrary::decodeInject` + `parseInject` for a `<callfixup>`.
    pub(crate) fn add_callfixup(&mut self, names: &SleighNames, name: &str, body: &str) -> Result<()> {
        let mut c = Compiler::new(names, self.tempbase);
        let ops = c.compile(body).map_err(|e| LowlevelError(format!("callfixup {name}: {}", e.0)))?;
        self.tempbase = c.tempbase;
        self.payloads.push(InjectPayload { name: name.to_string(), ops });
        Ok(())
    }

    /// Port of `PcodeInjectLibrary::getPayloadId(CALLFIXUP_TYPE, name)`.
    pub(crate) fn callfixup_id(&self, name: &str) -> Option<InjectId> {
        self.payloads.iter().position(|p| p.name == name).map(|i| InjectId(i as u32))
    }

    pub(crate) fn payload(&self, id: InjectId) -> &InjectPayload {
        &self.payloads[id.0 as usize]
    }
}

// ---------------------------------------------------------------- lexer

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Ident(String),
    Int(u64),
    /// an operator or punctuation
    P(&'static str),
}

/// Operators and punctuation, longest first so `<<` wins over `<`.
const PUNCT: &[&str] = &[
    "<<", ">>", "<=", ">=", "==", "!=", "&&", "||", "^^", "=", ";", ":", "(", ")", "[", "]", "+", "-", "*", "/", "%",
    "&", "|", "^", "~", "!", "<", ">",
];

fn lex(src: &str) -> Result<Vec<Tok>> {
    let mut toks = Vec::new();
    let mut s = src;
    loop {
        s = s.trim_start();
        let Some(c) = s.chars().next() else { return Ok(toks) };
        if c.is_ascii_alphabetic() || c == '_' {
            let n = s.find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '.')).unwrap_or(s.len());
            toks.push(Tok::Ident(s[..n].to_string()));
            s = &s[n..];
        } else if c.is_ascii_digit() {
            let n = s.find(|c: char| !c.is_ascii_alphanumeric()).unwrap_or(s.len());
            let text = &s[..n];
            let v = match (text.strip_prefix("0x"), text.strip_prefix("0b")) {
                (Some(h), _) => u64::from_str_radix(h, 16),
                (_, Some(b)) => u64::from_str_radix(b, 2),
                _ => text.parse(),
            };
            toks.push(Tok::Int(v.map_err(|_| LowlevelError(format!("bad integer {text}")))?));
            s = &s[n..];
        } else if let Some(p) = PUNCT.iter().find(|p| s.starts_with(**p)) {
            toks.push(Tok::P(p));
            s = &s[p.len()..];
        } else {
            return err(format!("unexpected character {c:?}"));
        }
    }
}

// ---------------------------------------------------------------- templates

/// Port of `VarnodeTpl` with every field resolved but the size (0 = not known yet).
#[derive(Debug, Clone, Copy)]
struct Vn {
    space: u32,
    offset: u64,
    size: u32,
    /// a temporary made for an operator's result (`VarnodeTpl::isUnnamed`)
    unnamed: bool,
}

/// Port of `OpTpl`.
#[derive(Debug)]
struct Op {
    opc: Opcode,
    out: Option<Vn>,
    ins: Vec<Vn>,
}

/// Port of `ExprTree`: the ops computing an expression and the varnode holding its value.
struct Expr {
    ops: Vec<Op>,
    out: Vn,
}

/// A slot of an op: its output (`None`) or input `i`.
type Slot = (usize, Option<usize>);

/// Port of `PcodeSnippet` (`PcodeCompile`): one snippet's parse.
struct Compiler<'a> {
    /// the registers and spaces
    names: &'a SleighNames<'a>,
    /// the snippet's own temporaries, by name
    temps: HashMap<String, Vn>,
    tempbase: u64,
    toks: Vec<Tok>,
    pos: usize,
}

impl<'a> Compiler<'a> {
    fn new(names: &'a SleighNames<'a>, tempbase: u64) -> Compiler<'a> {
        Compiler { names, temps: HashMap::new(), tempbase, toks: Vec::new(), pos: 0 }
    }

    /// A name in the snippet: one of its temporaries, else a register.
    fn symbol(&self, name: &str) -> Option<Vn> {
        self.temps.get(name).copied().or_else(|| {
            let (space, offset, size) = self.names.register(name).ok()?;
            Some(Vn { space, offset, size, unnamed: false })
        })
    }

    /// Port of `PcodeSnippet::parseStream` and `PcodeCompile::propagateSize`.
    fn compile(&mut self, body: &str) -> Result<Vec<PcodeOp>> {
        self.toks = lex(body)?;
        let mut ops = Vec::new();
        while self.pos < self.toks.len() {
            self.statement(&mut ops)?;
        }
        if !propagate_size(&mut ops, self.names.uniq_space())? {
            return err("could not resolve the size of every varnode");
        }
        Ok(ops
            .into_iter()
            .map(|o| {
                let vn = |v: Vn| Varnode { space: v.space, offset: v.offset, size: v.size };
                PcodeOp { opc: o.opc as u8, out: o.out.map(vn), ins: o.ins.into_iter().map(vn).collect() }
            })
            .collect())
    }

    // -------------------------------------------------------- tokens

    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }

    fn peek_p(&self, p: &str) -> bool {
        matches!(self.peek(), Some(Tok::P(q)) if *q == p)
    }

    fn eat(&mut self, p: &str) -> bool {
        let found = self.peek_p(p);
        if found {
            self.pos += 1;
        }
        found
    }

    fn expect(&mut self, p: &str) -> Result<()> {
        if self.eat(p) {
            return Ok(());
        }
        err(format!("expected '{p}', found {:?}", self.peek()))
    }

    fn int(&mut self) -> Result<u64> {
        match self.peek() {
            Some(&Tok::Int(v)) => {
                self.pos += 1;
                Ok(v)
            }
            t => err(format!("expected an integer, found {t:?}")),
        }
    }

    fn size(&mut self) -> Result<u32> {
        let v = self.int()?;
        u32::try_from(v).map_err(|_| LowlevelError(format!("bad size {v}")))
    }

    fn ident(&mut self) -> Result<String> {
        match self.peek() {
            Some(Tok::Ident(n)) => {
                let n = n.clone();
                self.pos += 1;
                Ok(n)
            }
            t => err(format!("expected a name, found {t:?}")),
        }
    }

    // -------------------------------------------------------- statements

    /// One `statement` of `pcodeparse.y`, its ops appended to `ops`.
    fn statement(&mut self, ops: &mut Vec<Op>) -> Result<()> {
        if self.peek_p("*") {
            // sizedstar expr '=' expr ';'
            let (space, size) = self.sized_star()?;
            let ptr = self.expr(0)?;
            self.expect("=")?;
            let val = self.expr(0)?;
            self.expect(";")?;
            return self.create_store(ops, space, size, ptr, val);
        }
        let local = matches!(self.peek(), Some(Tok::Ident(n)) if n == "local");
        if local {
            self.pos += 1;
        }
        let name = self.ident()?;
        let size = if self.eat(":") { self.size()? } else { 0 };
        self.expect("=")?;
        let rhs = self.expr(0)?;
        self.expect(";")?;
        match self.symbol(&name) {
            Some(_) if local || size != 0 => err(format!("redefinition of symbol {name}")),
            // lhsvarnode '=' expr ';'
            Some(lhs) => {
                ops.extend(set_output(rhs, lhs));
                Ok(())
            }
            None => {
                ops.extend(self.new_output(rhs, name, size));
                Ok(())
            }
        }
    }

    /// Port of `PcodeCompile::newOutput`: a new temporary named `name` takes the value.
    fn new_output(&mut self, rhs: Expr, name: String, size: u32) -> Vec<Op> {
        let mut tmp = self.build_temporary();
        tmp.size = if size != 0 { size } else { rhs.out.size };
        let ops = set_output(rhs, tmp);
        self.temps.insert(name, Vn { unnamed: false, ..tmp });
        ops
    }

    /// Port of `PcodeCompile::buildTemporary` (`PcodeSnippet::allocateTemp`).
    fn build_temporary(&mut self) -> Vn {
        let offset = self.tempbase;
        self.tempbase += TEMP_STEP;
        Vn { space: self.names.uniq_space(), offset, size: 0, unnamed: true }
    }

    /// Port of `PcodeCompile::createStore`.
    fn create_store(&mut self, ops: &mut Vec<Op>, space: u32, size: u32, ptr: Expr, val: Expr) -> Result<()> {
        let first = ops.len();
        ops.extend(ptr.ops);
        ops.extend(val.ops);
        ops.push(Op { opc: Opcode::Store, out: None, ins: vec![space_id(space), ptr.out, val.out] });
        let at = ops.len() - 1;
        force_size(&mut ops[first..], self.names.uniq_space(), (at - first, Some(2)), size)
    }

    // -------------------------------------------------------- expressions

    /// `'*' ['[' space ']'] [':' size]`: the space (default: the code space) and size (0: unknown).
    fn sized_star(&mut self) -> Result<(u32, u32)> {
        self.expect("*")?;
        let mut space = self.names.code_space();
        if self.eat("[") {
            let name = self.ident()?;
            space = self.names.space(&name)?;
            self.expect("]")?;
        }
        let size = if self.eat(":") { self.size()? } else { 0 };
        Ok((space, size))
    }

    /// An expression whose binary operators bind at least as tightly as `min` (precedence
    /// climbing over the `%left` levels of `pcodeparse.y`).
    fn expr(&mut self, min: u8) -> Result<Expr> {
        let mut lhs = self.unary()?;
        while let Some(&Tok::P(p)) = self.peek() {
            let Some((prec, opc, swap)) = binary(p) else { break };
            if prec < min {
                break;
            }
            self.pos += 1;
            // every level is left-associative but the comparisons (`%nonassoc`: `a < b < c` is an error)
            let rhs = self.expr(prec + 1)?;
            if prec == COMPARE && matches!(self.peek(), Some(Tok::P(p)) if binary(p).is_some_and(|b| b.0 == COMPARE)) {
                return err("comparisons do not chain");
            }
            let (a, b) = if swap { (rhs, lhs) } else { (lhs, rhs) };
            lhs = self.create_op2(opc, a, b);
        }
        Ok(lhs)
    }

    fn unary(&mut self) -> Result<Expr> {
        if self.peek_p("*") {
            let (space, size) = self.sized_star()?;
            let ptr = self.unary()?;
            return self.create_load(space, size, ptr);
        }
        for (p, opc) in [("-", Opcode::Int2comp), ("~", Opcode::IntNegate), ("!", Opcode::BoolNegate)] {
            if self.eat(p) {
                let e = self.unary()?;
                return Ok(self.create_op1(opc, e));
            }
        }
        if self.eat("(") {
            let e = self.expr(0)?;
            self.expect(")")?;
            return Ok(e);
        }
        let out = match self.peek() {
            Some(Tok::Int(_)) => {
                let v = self.int()?;
                let size = if self.eat(":") { self.size()? } else { 0 };
                Vn { space: 0, offset: v, size, unnamed: false }
            }
            _ => {
                let name = self.ident()?;
                if self.peek_p("(") {
                    return err(format!("{name}(...): user ops are not supported in snippets"));
                }
                self.symbol(&name).ok_or_else(|| LowlevelError(format!("Unknown varnode parameter: {name}")))?
            }
        };
        Ok(Expr { ops: Vec::new(), out })
    }

    /// Port of `PcodeCompile::createOp` (unary).
    fn create_op1(&mut self, opc: Opcode, mut e: Expr) -> Expr {
        let out = self.build_temporary();
        e.ops.push(Op { opc, out: Some(out), ins: vec![e.out] });
        e.out = out;
        e
    }

    /// Port of `PcodeCompile::createOp` (binary).
    fn create_op2(&mut self, opc: Opcode, mut a: Expr, b: Expr) -> Expr {
        let out = self.build_temporary();
        a.ops.extend(b.ops);
        a.ops.push(Op { opc, out: Some(out), ins: vec![a.out, b.out] });
        a.out = out;
        a
    }

    /// Port of `PcodeCompile::createLoad`.
    fn create_load(&mut self, space: u32, size: u32, mut ptr: Expr) -> Result<Expr> {
        let out = self.build_temporary();
        ptr.ops.push(Op { opc: Opcode::Load, out: Some(out), ins: vec![space_id(space), ptr.out] });
        let at = ptr.ops.len() - 1;
        if size > 0 {
            force_size(&mut ptr.ops, self.names.uniq_space(), (at, None), size)?;
        }
        ptr.out = ptr.ops[at].out.unwrap_or(out);
        Ok(ptr)
    }
}

/// The precedence level of the comparisons (`%nonassoc` in `pcodeparse.y`).
const COMPARE: u8 = 7;

/// The binary operator `p`: its precedence level, opcode and whether the operands swap
/// (`a > b` is `b < a`).
fn binary(p: &str) -> Option<(u8, Opcode, bool)> {
    use Opcode::*;
    Some(match p {
        "||" => (1, BoolOr, false),
        "&&" => (2, BoolAnd, false),
        "^^" => (2, BoolXor, false),
        "|" => (3, IntOr, false),
        "^" => (4, IntXor, false),
        "&" => (5, IntAnd, false),
        "==" => (6, IntEqual, false),
        "!=" => (6, IntNotequal, false),
        "<" => (COMPARE, IntLess, false),
        ">" => (COMPARE, IntLess, true),
        "<=" => (COMPARE, IntLessequal, false),
        ">=" => (COMPARE, IntLessequal, true),
        "<<" => (8, IntLeft, false),
        ">>" => (8, IntRight, false),
        "+" => (9, IntAdd, false),
        "-" => (9, IntSub, false),
        "*" => (10, IntMult, false),
        "/" => (10, IntDiv, false),
        "%" => (10, IntRem, false),
        _ => return None,
    })
}

/// The constant naming a LOAD/STORE space.
fn space_id(space: u32) -> Vn {
    Vn { space: 0, offset: u64::from(space), size: SPACE_ID_SIZE, unnamed: false }
}

/// Port of `ExprTree::setOutput`: the expression's value goes to `out`, by renaming the last
/// op's output when that is an operator temporary, else by a COPY.
fn set_output(mut e: Expr, out: Vn) -> Vec<Op> {
    match e.ops.last_mut() {
        Some(last) if e.out.unnamed => last.out = Some(out),
        _ => e.ops.push(Op { opc: Opcode::Copy, out: Some(out), ins: vec![e.out] }),
    }
    e.ops
}

fn slot(ops: &mut [Op], (op, i): Slot) -> Option<&mut Vn> {
    let o = ops.get_mut(op)?;
    match i {
        None => o.out.as_mut(),
        Some(i) => o.ins.get_mut(i),
    }
}

/// Port of `PcodeCompile::force_size`: give a size to a varnode of unknown size; a temporary
/// (`isLocalTemp`: in the unique space `uniq`) gets it at every occurrence.
fn force_size(ops: &mut [Op], uniq: u32, at: Slot, size: u32) -> Result<()> {
    let Some(vt) = slot(ops, at).filter(|v| v.size == 0) else { return Ok(()) };
    vt.size = size;
    let offset = vt.offset;
    if vt.space != uniq {
        return Ok(());
    }
    for o in ops.iter_mut() {
        for v in o.out.iter_mut().chain(o.ins.iter_mut()).filter(|v| v.space == uniq && v.offset == offset) {
            if v.size != 0 && v.size != size {
                return err("Localtemp size mismatch");
            }
            v.size = size;
        }
    }
    Ok(())
}

/// Port of `PcodeCompile::matchSize`: fill slot `j` from the op's first known size.
fn match_size(ops: &mut [Op], uniq: u32, i: usize, j: Option<usize>, inputonly: bool) -> Result<()> {
    let o = &ops[i];
    let out = o.out.filter(|v| !inputonly && v.size != 0);
    let found = out.or_else(|| o.ins.iter().copied().find(|v| v.size != 0));
    match found {
        Some(m) => force_size(ops, uniq, (i, j), m.size),
        None => Ok(()),
    }
}

fn zero_size(o: &Op) -> bool {
    o.out.is_some_and(|v| v.size == 0) || o.ins.iter().any(|v| v.size == 0)
}

/// Port of `PcodeCompile::fillinZero` for the opcodes the snippet parser makes.
fn fillin_zero(ops: &mut [Op], uniq: u32, i: usize) -> Result<()> {
    use Opcode::*;
    let n = ops[i].ins.len();
    match ops[i].opc {
        Copy | IntAdd | IntSub | Int2comp | IntNegate | IntXor | IntAnd | IntOr | IntMult | IntDiv | IntRem => {
            if ops[i].out.is_some_and(|v| v.size == 0) {
                match_size(ops, uniq, i, None, false)?;
            }
            for j in 0..n {
                if ops[i].ins[j].size == 0 {
                    match_size(ops, uniq, i, Some(j), false)?;
                }
            }
        }
        IntEqual | IntNotequal | IntLess | IntLessequal | BoolNegate | BoolXor | BoolAnd | BoolOr => {
            if ops[i].out.is_some_and(|v| v.size == 0) {
                force_size(ops, uniq, (i, None), 1)?;
            }
            for j in 0..n {
                if ops[i].ins[j].size == 0 {
                    match_size(ops, uniq, i, Some(j), true)?;
                }
            }
        }
        IntLeft | IntRight => {
            let (out, in0) = (ops[i].out.map_or(0, |v| v.size), ops[i].ins[0].size);
            if out == 0 {
                if in0 != 0 {
                    force_size(ops, uniq, (i, None), in0)?;
                }
            } else if in0 == 0 {
                force_size(ops, uniq, (i, Some(0)), out)?;
            }
            if ops[i].ins[1].size == 0 {
                force_size(ops, uniq, (i, Some(1)), 4)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Port of `PcodeCompile::propagateSize`: `false` when some size stays unknown.
fn propagate_size(ops: &mut [Op], uniq: u32) -> Result<bool> {
    let mut zero = Vec::new();
    for i in 0..ops.len() {
        if zero_size(&ops[i]) {
            fillin_zero(ops, uniq, i)?;
            if zero_size(&ops[i]) {
                zero.push(i);
            }
        }
    }
    let mut last = zero.len() + 1;
    while zero.len() < last {
        last = zero.len();
        let mut again = Vec::new();
        for &i in &zero {
            fillin_zero(ops, uniq, i)?;
            if zero_size(&ops[i]) {
                again.push(i);
            }
        }
        zero = again;
    }
    Ok(last == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sleigh() -> Sleigh {
        let path = Sleigh::sla_path("x86");
        assert!(path.exists(), "{} is missing: run rust/build-sla.sh first", path.display());
        Sleigh::load(&path).unwrap()
    }

    fn reg(sl: &Sleigh, name: &str) -> Varnode {
        let (_, space, offset, size) = sl.varnode_syms().into_iter().find(|s| s.0 == name).unwrap();
        Varnode { space, offset, size }
    }

    /// The ops as (opcode, output, inputs) for comparing.
    fn shape(ops: &[PcodeOp]) -> Vec<(u8, Option<Varnode>, Vec<Varnode>)> {
        ops.iter().map(|o| (o.opc, o.out, o.ins.clone())).collect()
    }

    #[test]
    fn operators_take_temporaries_assignments_rename_them() {
        let sl = sleigh();
        let mut lib = InjectLibrary::new(&sl);
        let base = lib.tempbase;
        lib.add_callfixup(&SleighNames::new(&sl), "alloca_probe", "ESP = ESP + 4 - EAX;").unwrap();
        // `ESP + 4` takes the first slot, `... - EAX` the second, renamed to ESP
        assert_eq!(lib.tempbase, base + 2 * TEMP_STEP);
        let (esp, eax) = (reg(&sl, "ESP"), reg(&sl, "EAX"));
        let t = Varnode { space: sl.uniq_space(), offset: base, size: 4 };
        let four = Varnode { space: 0, offset: 4, size: 4 };
        let p = lib.payload(lib.callfixup_id("alloca_probe").unwrap());
        assert_eq!(
            shape(&p.ops),
            vec![(Opcode::IntAdd as u8, Some(t), vec![esp, four]), (Opcode::IntSub as u8, Some(esp), vec![t, eax])]
        );
    }

    #[test]
    fn named_temporaries_loads_and_stores() {
        let sl = sleigh();
        let mut lib = InjectLibrary::new(&sl);
        let base = lib.tempbase;
        lib.add_callfixup(
            &SleighNames::new(&sl),
            "f",
            "frame = ESP + 8; size:4 = * frame; *(ESP + 4) = EDI; zero:4 = 0;",
        )
        .unwrap();
        let u = |slot: u64| Varnode { space: sl.uniq_space(), offset: base + slot * TEMP_STEP, size: 4 };
        let (esp, edi) = (reg(&sl, "ESP"), reg(&sl, "EDI"));
        let ram = Varnode { space: 0, offset: u64::from(sl.code_space()), size: SPACE_ID_SIZE };
        let c = |v: u64| Varnode { space: 0, offset: v, size: 4 };
        let p = lib.payload(InjectId(0));
        // slot 0: `ESP + 8` (renamed), 1: frame, 2: the load (renamed), 3: size, 4: `ESP + 4`, 5: zero
        assert_eq!(
            shape(&p.ops),
            vec![
                (Opcode::IntAdd as u8, Some(u(1)), vec![esp, c(8)]),
                (Opcode::Load as u8, Some(u(3)), vec![ram, u(1)]),
                (Opcode::IntAdd as u8, Some(u(4)), vec![esp, c(4)]),
                (Opcode::Store as u8, None, vec![ram, u(4), edi]),
                (Opcode::Copy as u8, Some(u(5)), vec![c(0)]),
            ]
        );
        // temporaries keep counting in the next snippet
        lib.add_callfixup(&SleighNames::new(&sl), "g", "EAX = 0;").unwrap();
        assert_eq!(lib.tempbase, base + 6 * TEMP_STEP);
    }

    #[test]
    fn unary_minus_and_sized_store() {
        let sl = sleigh();
        let mut lib = InjectLibrary::new(&sl);
        let base = lib.tempbase;
        lib.add_callfixup(&SleighNames::new(&sl), "f", "*:4 ESP = -1;").unwrap();
        let t = Varnode { space: sl.uniq_space(), offset: base, size: 4 };
        let ops = &lib.payload(InjectId(0)).ops;
        assert_eq!(ops[0].opc, Opcode::Int2comp as u8);
        assert_eq!((ops[0].out, ops[0].ins[0].size), (Some(t), 4));
        assert_eq!(ops[1].ins[2], t);
    }

    #[test]
    fn errors() {
        let sl = sleigh();
        let mut lib = InjectLibrary::new(&sl);
        for bad in ["EAX = nosuch;", "EAX = 1", "foo(EAX);", "t = 5;", "EAX = 1 @ 2;", "EAX:4 = 1;", "EAX = 1 < 2 < 3;"]
        {
            assert!(lib.add_callfixup(&SleighNames::new(&sl), "bad", bad).is_err(), "{bad} should not compile");
        }
    }
}
