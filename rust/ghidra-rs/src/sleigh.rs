//! SLEIGH decode engine: a port of the runtime half of Ghidra's C++ sleigh
//! (sleigh.cc, slghsymbol.cc, slghpattern.cc, slghpatexpress.cc, context.cc, semantics.cc).
//! Logic follows upstream; the class hierarchy is flattened into enums and index arenas.
//!
//! Not ported (not needed for x86-64 linear disassembly): delay slots, crossbuild,
//! inst_next2, flowref/flowdest, and context *commits* (globalset). Each instruction is
//! decoded from the default context, so context that flows between instructions is lost.

use crate::sla::{self, a, e, Elem, Result};
use std::collections::HashMap;
use std::path::Path;

const NONE: u32 = u32::MAX;
const MAX_OPERAND: usize = 20; // ParserContext::MAX_OPERAND
const MAX_DEPTH: usize = 32; // ParserContext::MAX_DEPTH
const MAX_INSTRUCTION_LEN: u32 = 16;
const CONST_SPACE: u32 = 0;

// p-code opcodes that mean something else inside templates (semantics.hh)
const OP_BUILD: u8 = 60;
const OP_DELAY_SLOT: u8 = 61;
const OP_LABELBUILD: u8 = 65;
const OP_CROSSBUILD: u8 = 66;
const OP_LOAD: u8 = 2;
const OP_STORE: u8 = 3;
const OP_INT_ADD: u8 = 19;
const RUNTIME_BITRANGE_EA: u64 = 0x100; // Translate::RUNTIME_BITRANGE_EA

pub const OPCODE_NAMES: [&str; 75] = [
    "BLANK", "COPY", "LOAD", "STORE", "BRANCH", "CBRANCH", "BRANCHIND", "CALL", "CALLIND",
    "CALLOTHER", "RETURN", "INT_EQUAL", "INT_NOTEQUAL", "INT_SLESS", "INT_SLESSEQUAL", "INT_LESS",
    "INT_LESSEQUAL", "INT_ZEXT", "INT_SEXT", "INT_ADD", "INT_SUB", "INT_CARRY", "INT_SCARRY",
    "INT_SBORROW", "INT_2COMP", "INT_NEGATE", "INT_XOR", "INT_AND", "INT_OR", "INT_LEFT",
    "INT_RIGHT", "INT_SRIGHT", "INT_MULT", "INT_DIV", "INT_SDIV", "INT_REM", "INT_SREM",
    "BOOL_NEGATE", "BOOL_XOR", "BOOL_AND", "BOOL_OR", "FLOAT_EQUAL", "FLOAT_NOTEQUAL",
    "FLOAT_LESS", "FLOAT_LESSEQUAL", "UNUSED1", "FLOAT_NAN", "FLOAT_ADD", "FLOAT_DIV",
    "FLOAT_MULT", "FLOAT_SUB", "FLOAT_NEG", "FLOAT_ABS", "FLOAT_SQRT", "INT2FLOAT",
    "FLOAT2FLOAT", "TRUNC", "CEIL", "FLOOR", "ROUND", "MULTIEQUAL", "INDIRECT", "PIECE",
    "SUBPIECE", "CAST", "PTRADD", "PTRSUB", "SEGMENTOP", "CPOOLREF", "NEW", "INSERT", "ZPULL",
    "POPCOUNT", "LZCOUNT", "SPULL",
];

// x86-64.pspec <context_set>: the defaults for 64-bit code.
const X86_64_CONTEXT: [(&str, u32); 4] =
    [("addrsize", 2), ("opsize", 1), ("rexprefix", 0), ("longMode", 1)];

// ---------------------------------------------------------------- model

#[derive(Debug)]
enum Expr {
    Token { be: bool, sign: bool, bitstart: i32, bitend: i32, bytestart: i32, byteend: i32, shift: i32 },
    Ctx { sign: bool, startbit: i32, endbit: i32, startbyte: i32, endbyte: i32, shift: i32 },
    Const(i64),
    Operand { index: usize, table: usize, ct: usize },
    Start,
    End,
    Next2,
    Bin(u32, Box<Expr>, Box<Expr>), // element id of the operator
    Neg(Box<Expr>),
    Not(Box<Expr>),
}

#[derive(Debug)]
struct Operand {
    index: usize,
    reloff: i32,
    offbase: i32,
    minlen: u32,
    triple: Option<usize>,
    defexp: Option<Expr>,
}

#[derive(Debug)]
enum Kind {
    None,
    UserOp,
    Epsilon,
    Value(Expr),
    ValueMap(Expr, Vec<i64>),
    Name(Expr, Vec<String>),
    Varnode { space: u32, off: u64, size: u32 },
    Context { exp: Expr, low: u32, high: u32 },
    VarList(Expr, Vec<Option<usize>>),
    Operand(Operand),
    Start,
    End,
    Next2,
    Subtable { ctors: Vec<usize>, tree: Option<Decision> },
}

#[derive(Debug)]
struct Sym {
    name: String,
    kind: Kind,
}

#[derive(Debug)]
enum Piece {
    Lit(String),
    Op(usize),
}

#[derive(Debug)]
enum CtxChange {
    Op { num: usize, shift: u32, mask: u32, exp: Expr },
    Commit, // globalset: not applied (see module docs)
}

#[derive(Debug)]
struct Ctor {
    operands: Vec<usize>,
    pieces: Vec<Piece>,
    firstws: i32,
    minlen: u32,
    flowthru: Option<usize>,
    ctx: Vec<CtxChange>,
    templ: Option<Tpl>,
    named: Vec<Option<Tpl>>,
}

#[derive(Debug, Clone, Copy)]
enum C {
    Real(u64),
    Handle { idx: usize, sel: u8, plus: u64 },
    Start,
    Next,
    Next2,
    CurSpace,
    CurSpaceSize,
    SpaceId(u32),
    Relative(u64),
    Flow, // flowref/flowdest and their sizes: unsupported
}

#[derive(Debug)]
struct VnTpl {
    space: C,
    off: C,
    size: C,
}

#[derive(Debug)]
struct HandleTpl {
    space: C,
    size: C,
    ptrspace: C,
    ptroffset: C,
    ptrsize: C,
    temp_space: C,
    temp_offset: C,
}

#[derive(Debug)]
struct OpTpl {
    opc: u8,
    out: Option<VnTpl>,
    ins: Vec<VnTpl>,
}

#[derive(Debug)]
struct Tpl {
    labels: u32,
    result: Option<HandleTpl>,
    ops: Vec<OpTpl>,
}

#[derive(Debug)]
struct Block {
    off: u32,
    nonzero: i32,
    words: Vec<(u32, u32)>, // (mask, value)
}

#[derive(Debug)]
enum Pat {
    Instr(Block),
    Ctx(Block),
    Both(Block, Block), // (context, instruction)
}

#[derive(Debug)]
struct Decision {
    ctx: bool,
    start: i32,
    size: i32,
    list: Vec<(Pat, usize)>,
    kids: Vec<Decision>,
}

#[derive(Debug)]
pub struct Space {
    pub name: String,
    pub size: u32,
}

pub struct Sleigh {
    pub spaces: Vec<Space>,
    syms: Vec<Sym>,
    ctors: Vec<Ctor>,
    root: usize,
    code_space: u32,
    uniq_space: u32,
    uniq_base: u64,
    uniq_mask: u64,
    ctx_default: Vec<u32>,
    regnames: HashMap<(u32, u64, u32), usize>,
}

// ---------------------------------------------------------------- parse state

#[derive(Debug, Clone, Copy)]
struct Handle {
    space: u32,
    size: u32,
    offset_space: u32, // NONE: not dynamic
    offset_offset: u64,
    offset_size: u32,
    temp_space: u32,
    temp_offset: u64,
}

impl Default for Handle {
    fn default() -> Self {
        Handle { space: CONST_SPACE, size: 0, offset_space: NONE, offset_offset: 0, offset_size: 0, temp_space: 0, temp_offset: 0 }
    }
}

fn const_handle(v: u64) -> Handle {
    Handle { offset_offset: v, ..Handle::default() }
}

#[derive(Clone)]
struct State {
    ct: usize,
    parent: u32,
    resolve: [u32; MAX_OPERAND],
    offset: u32,
    length: u32,
    hand: Handle,
}

impl State {
    fn new(parent: u32) -> Self {
        State { ct: 0, parent, resolve: [NONE; MAX_OPERAND], offset: 0, length: 0, hand: Handle::default() }
    }
}

/// Reusable per-instruction parse state (Ghidra's ParserContext).
pub struct Parse {
    buf: [u8; 48],
    pub addr: u64,
    pub naddr: u64,
    pub len: usize,
    ctx: Vec<u32>,
    states: Vec<State>,
}

impl Parse {
    fn ins_bytes(&self, pos: u32, n: u32) -> Result<u32> {
        if pos >= MAX_INSTRUCTION_LEN {
            return Err(format!("{:#x}: instruction is using more than 16 bytes", self.addr));
        }
        let mut r = 0u32;
        for i in 0..n {
            r = (r << 8) | self.buf[(pos + i) as usize] as u32;
        }
        Ok(r)
    }
    fn ins_bits(&self, off: u32, startbit: i32, size: i32) -> Result<u32> {
        let pos = off + (startbit / 8) as u32;
        if pos >= MAX_INSTRUCTION_LEN {
            return Err(format!("{:#x}: instruction is using more than 16 bytes", self.addr));
        }
        let w = u64::from_be_bytes(self.buf[pos as usize..pos as usize + 8].try_into().unwrap());
        Ok(((w << (startbit % 8)) >> (64 - size)) as u32)
    }
    fn ctx_word(&self, i: usize) -> u64 {
        self.ctx.get(i).copied().unwrap_or(0) as u64
    }
    fn ctx_bits(&self, startbit: i32, size: i32) -> u32 {
        let i = (startbit / 32) as usize;
        let w = (self.ctx_word(i) << 32) | self.ctx_word(i + 1);
        ((w << (startbit % 32)) >> (64 - size)) as u32
    }
    fn ctx_bytes(&self, bytestart: i32, size: i32) -> u32 {
        let mut r = 0u32;
        for b in bytestart..bytestart + size {
            let w = self.ctx_word((b / 4) as usize) as u32;
            r = (r << 8) | ((w >> (24 - 8 * (b % 4))) & 0xff);
        }
        r
    }
}

// ---------------------------------------------------------------- p-code output

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Varnode {
    pub space: u32,
    pub offset: u64,
    pub size: u32,
}

#[derive(Debug, Clone)]
pub struct PcodeOp {
    pub opc: u8,
    pub out: Option<Varnode>,
    pub ins: Vec<Varnode>,
}

#[derive(Debug, Clone)]
pub struct Insn {
    pub addr: u64,
    pub len: usize,
    pub mnemonic: String,
    pub body: String,
}

fn calc_mask(size: u32) -> u64 {
    if size >= 8 { u64::MAX } else { (1u64 << (8 * size)) - 1 }
}

fn sign_extend(v: i64, bit: i32) -> i64 {
    let sa = 63 - bit;
    (v << sa) >> sa
}

fn zero_extend(v: i64, bit: i32) -> i64 {
    let sa = 63 - bit;
    (((v as u64) << sa) >> sa) as i64
}

fn hex(out: &mut String, v: i64) {
    use std::fmt::Write;
    let _ = if v >= 0 { write!(out, "0x{:x}", v) } else { write!(out, "-0x{:x}", v.unsigned_abs()) };
}

// ---------------------------------------------------------------- loading

fn expr(el: &Elem) -> Result<Expr> {
    let i = |id| el.int(id).map(|v| v as i32);
    let kid = |n: usize| -> Result<Box<Expr>> { Ok(Box::new(expr(el.kids.get(n).ok_or("missing operand")?)?)) };
    Ok(match el.id {
        e::TOKENFIELD => Expr::Token {
            be: el.boolean(a::BIGENDIAN)?,
            sign: el.boolean(a::SIGNBIT)?,
            bitstart: i(a::STARTBIT)?,
            bitend: i(a::ENDBIT)?,
            bytestart: i(a::STARTBYTE)?,
            byteend: i(a::ENDBYTE)?,
            shift: i(a::SHIFT)?,
        },
        e::CONTEXTFIELD => Expr::Ctx {
            sign: el.boolean(a::SIGNBIT)?,
            startbit: i(a::STARTBIT)?,
            endbit: i(a::ENDBIT)?,
            startbyte: i(a::STARTBYTE)?,
            endbyte: i(a::ENDBYTE)?,
            shift: i(a::SHIFT)?,
        },
        e::INTB => Expr::Const(el.int(a::VAL)?),
        e::OPERAND_EXP => Expr::Operand {
            index: el.int(a::INDEX)? as usize,
            table: el.uint(a::TABLE)? as usize,
            ct: el.uint(a::CT)? as usize,
        },
        e::START_EXP => Expr::Start,
        e::END_EXP => Expr::End,
        e::NEXT2_EXP => Expr::Next2,
        e::MINUS_EXP => Expr::Neg(kid(0)?),
        e::NOT_EXP => Expr::Not(kid(0)?),
        e::AND_EXP | e::DIV_EXP | e::LSHIFT_EXP | e::MULT_EXP | e::OR_EXP | e::PLUS_EXP
        | e::RSHIFT_EXP | e::SUB_EXP | e::XOR_EXP => Expr::Bin(el.id, kid(0)?, kid(1)?),
        id => return Err(format!("bad pattern expression element {id}")),
    })
}

fn const_tpl(el: &Elem) -> Result<C> {
    Ok(match el.id {
        e::CONST_REAL => C::Real(el.uint(a::VAL)?),
        e::CONST_HANDLE => C::Handle {
            idx: el.int(a::VAL)? as usize,
            sel: el.int(a::S)? as u8,
            plus: if el.has(a::PLUS) { el.uint(a::PLUS)? } else { 0 },
        },
        e::CONST_START => C::Start,
        e::CONST_NEXT => C::Next,
        e::CONST_NEXT2 => C::Next2,
        e::CONST_CURSPACE => C::CurSpace,
        e::CONST_CURSPACE_SIZE => C::CurSpaceSize,
        e::CONST_SPACEID => C::SpaceId(el.int(a::SPACE)? as u32),
        e::CONST_RELATIVE => C::Relative(el.uint(a::VAL)?),
        e::CONST_FLOWREF | e::CONST_FLOWREF_SIZE | e::CONST_FLOWDEST | e::CONST_FLOWDEST_SIZE => C::Flow,
        id => return Err(format!("bad constant template element {id}")),
    })
}

fn vn_tpl(el: &Elem) -> Result<VnTpl> {
    if el.kids.len() != 3 {
        return Err("bad varnode_tpl".into());
    }
    Ok(VnTpl { space: const_tpl(&el.kids[0])?, off: const_tpl(&el.kids[1])?, size: const_tpl(&el.kids[2])? })
}

/// Returns the template and its section id (-1 for the main section).
fn tpl(el: &Elem) -> Result<(Tpl, i64)> {
    let section = if el.has(a::SECTION) { el.int(a::SECTION)? } else { -1 };
    let labels = if el.has(a::LABELS) { el.int(a::LABELS)? as u32 } else { 0 };
    let mut kids = el.kids.iter();
    let result = match kids.next() {
        Some(h) if h.id == e::HANDLE_TPL => {
            let c: Vec<C> = h.kids.iter().map(const_tpl).collect::<Result<_>>()?;
            if c.len() != 7 {
                return Err("bad handle_tpl".into());
            }
            Some(HandleTpl { space: c[0], size: c[1], ptrspace: c[2], ptroffset: c[3], ptrsize: c[4], temp_space: c[5], temp_offset: c[6] })
        }
        _ => None,
    };
    let mut ops = Vec::new();
    for o in kids {
        let mut it = o.kids.iter();
        let out = match it.next() {
            Some(v) if v.id == e::VARNODE_TPL => Some(vn_tpl(v)?),
            _ => None,
        };
        let ins = it.map(vn_tpl).collect::<Result<_>>()?;
        ops.push(OpTpl { opc: o.int(a::CODE)? as u8, out, ins });
    }
    Ok((Tpl { labels, result, ops }, section))
}

fn block(el: &Elem) -> Result<Block> {
    let b = el.kids.first().ok_or("missing pat_block")?;
    let words = b.kids.iter().map(|w| Ok((w.uint(a::MASK)? as u32, w.uint(a::VAL)? as u32))).collect::<Result<_>>()?;
    Ok(Block { off: b.int(a::OFF)? as u32, nonzero: b.int(a::NONZERO)? as i32, words })
}

fn pattern(el: &Elem) -> Result<Pat> {
    Ok(match el.id {
        e::INSTRUCT_PAT => Pat::Instr(block(el)?),
        e::CONTEXT_PAT => Pat::Ctx(block(el)?),
        e::COMBINE_PAT => {
            if el.kids.len() != 2 {
                return Err("bad combine_pat".into());
            }
            Pat::Both(block(&el.kids[0])?, block(&el.kids[1])?)
        }
        id => return Err(format!("bad pattern element {id}")),
    })
}

fn decision(el: &Elem, ctors: &[usize]) -> Result<Decision> {
    let mut d = Decision {
        ctx: el.boolean(a::CONTEXT)?,
        start: el.int(a::STARTBIT)? as i32,
        size: el.int(a::SIZE)? as i32,
        list: Vec::new(),
        kids: Vec::new(),
    };
    for k in &el.kids {
        if k.id == e::PAIR {
            let ct = *ctors.get(k.int(a::ID)? as usize).ok_or("invalid constructor id")?;
            d.list.push((pattern(k.kids.first().ok_or("missing pattern")?)?, ct));
        } else if k.id == e::DECISION {
            d.kids.push(decision(k, ctors)?);
        }
    }
    Ok(d)
}

fn ctor(el: &Elem) -> Result<Ctor> {
    let mut c = Ctor {
        operands: Vec::new(),
        pieces: Vec::new(),
        firstws: el.int(a::FIRST)? as i32,
        minlen: el.int(a::LENGTH)? as u32,
        flowthru: None,
        ctx: Vec::new(),
        templ: None,
        named: Vec::new(),
    };
    for k in &el.kids {
        match k.id {
            e::OPER => c.operands.push(k.uint(a::ID)? as usize),
            e::PRINT => c.pieces.push(Piece::Lit(k.string(a::PIECE)?.to_string())),
            e::OPPRINT => c.pieces.push(Piece::Op(k.int(a::ID)? as usize)),
            e::CONTEXT_OP => c.ctx.push(CtxChange::Op {
                num: k.int(a::I)? as usize,
                shift: k.int(a::SHIFT)? as u32,
                mask: k.uint(a::MASK)? as u32,
                exp: expr(k.kids.first().ok_or("context_op without expression")?)?,
            }),
            e::COMMIT => c.ctx.push(CtxChange::Commit),
            _ => {
                let (t, sec) = tpl(k)?;
                if sec < 0 {
                    c.templ = Some(t);
                } else {
                    let sec = sec as usize;
                    c.named.resize_with(c.named.len().max(sec + 1), || None);
                    c.named[sec] = Some(t);
                }
            }
        }
    }
    if let [Piece::Op(i)] = c.pieces[..] {
        c.flowthru = Some(i);
    }
    Ok(c)
}

impl Sleigh {
    /// Default location of the x86-64 .sla built by `rust/build-sla.sh`.
    pub fn default_sla_path() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Ghidra/Processors/x86/data/languages/x86-64.sla")
    }

    pub fn load(path: &Path) -> Result<Sleigh> {
        let root = sla::read_file(path)?;
        if root.id != e::SLEIGH || root.int(a::VERSION)? != 4 {
            return Err(format!("{}: unexpected .sla root/version", path.display()));
        }
        let kid = |id| root.kids.iter().find(|k| k.id == id).ok_or(format!("missing element {id}"));
        let sp = kid(e::SPACES)?;
        let mut spaces = vec![Space { name: "const".into(), size: 8 }];
        let mut uniq_space = NONE;
        for s in &sp.kids {
            let idx = s.int(a::INDEX)? as usize;
            let name = match s.id {
                e::SPACE_UNIQUE => "unique".to_string(),
                e::SPACE_OTHER => "OTHER".to_string(),
                _ => s.string(a::NAME)?.to_string(),
            };
            let size = if s.has(a::SIZE) { s.int(a::SIZE)? as u32 } else { 8 };
            if s.id == e::SPACE_UNIQUE {
                uniq_space = idx as u32;
            }
            spaces.resize_with(spaces.len().max(idx + 1), || Space { name: String::new(), size: 8 });
            spaces[idx] = Space { name, size };
        }
        let defname = sp.string(a::DEFAULTSPACE)?;
        let code_space = spaces.iter().position(|s| s.name == defname).ok_or("bad defaultspace")? as u32;

        let st = kid(e::SYMBOL_TABLE)?;
        let n = st.int(a::SYMBOLSIZE)? as usize;
        let mut syms: Vec<Sym> = (0..n).map(|_| Sym { name: String::new(), kind: Kind::None }).collect();
        let mut ctors = Vec::new();
        for k in &st.kids {
            if k.has(a::NAME) && k.has(a::SCOPE) {
                let id = k.uint(a::ID)? as usize;
                syms.get_mut(id).ok_or("bad symbol id")?.name = k.string(a::NAME)?.to_string();
            }
        }
        for k in &st.kids {
            let first = || k.kids.first().ok_or_else(|| format!("symbol element {} without expression", k.id));
            let kind = match k.id {
                e::USEROP => Kind::UserOp,
                e::EPSILON_SYM => Kind::Epsilon,
                e::VALUE_SYM => Kind::Value(expr(first()?)?),
                e::VALUEMAP_SYM => Kind::ValueMap(
                    expr(first()?)?,
                    k.kids[1..].iter().map(|v| v.int(a::VAL)).collect::<Result<_>>()?,
                ),
                e::NAME_SYM => Kind::Name(
                    expr(first()?)?,
                    k.kids[1..].iter().map(|v| v.string(a::NAME).unwrap_or("\t").to_string()).collect(),
                ),
                e::VARNODE_SYM => Kind::Varnode {
                    space: k.int(a::SPACE)? as u32,
                    off: k.uint(a::OFF)?,
                    size: k.int(a::SIZE)? as u32,
                },
                e::CONTEXT_SYM => Kind::Context {
                    exp: expr(first()?)?,
                    low: k.int(a::LOW)? as u32,
                    high: k.int(a::HIGH)? as u32,
                },
                e::VARLIST_SYM => Kind::VarList(
                    expr(first()?)?,
                    k.kids[1..]
                        .iter()
                        .map(|v| if v.id == e::VAR { v.uint(a::ID).map(|x| Some(x as usize)) } else { Ok(None) })
                        .collect::<Result<_>>()?,
                ),
                e::OPERAND_SYM => Kind::Operand(Operand {
                    index: k.int(a::INDEX).unwrap_or(0) as usize,
                    reloff: k.int(a::OFF).unwrap_or(0) as i32,
                    offbase: k.int(a::BASE).unwrap_or(-1) as i32,
                    minlen: k.int(a::MINLEN).unwrap_or(0) as u32,
                    triple: if k.has(a::SUBSYM) { Some(k.uint(a::SUBSYM)? as usize) } else { None },
                    defexp: match k.kids.get(1) {
                        Some(x) => Some(expr(x)?),
                        None => None,
                    },
                }),
                e::START_SYM => Kind::Start,
                e::END_SYM => Kind::End,
                e::NEXT2_SYM => Kind::Next2,
                e::SUBTABLE_SYM => {
                    let mut list = Vec::new();
                    let mut tree = None;
                    for c in &k.kids {
                        if c.id == e::CONSTRUCTOR {
                            list.push(ctors.len());
                            ctors.push(ctor(c)?);
                        } else if c.id == e::DECISION {
                            tree = Some(decision(c, &list)?);
                        }
                    }
                    Kind::Subtable { ctors: list, tree }
                }
                _ => continue, // scopes and symbol headers
            };
            let id = k.uint(a::ID)? as usize;
            syms.get_mut(id).ok_or("bad symbol id")?.kind = kind;
        }
        let root_sym = syms
            .iter()
            .position(|s| s.name == "instruction" && matches!(s.kind, Kind::Subtable { .. }))
            .ok_or("no instruction table")?;

        // Context: one 32-bit word per 32 bits of context register, set to the pspec defaults.
        let mut words = 1;
        for s in &syms {
            if let Kind::Context { high, .. } = s.kind {
                words = words.max(high as usize / 32 + 1);
            }
        }
        let mut ctx_default = vec![0u32; words];
        for (name, val) in X86_64_CONTEXT {
            if let Some(Sym { kind: Kind::Context { low, high, .. }, .. }) = syms.iter().find(|s| s.name == name) {
                let num = (*low / 32) as usize;
                let shift = 31 - high % 32;
                let mask = ((u32::MAX >> (low % 32 + shift)) << shift) as u32;
                ctx_default[num] = (ctx_default[num] & !mask) | ((val << shift) & mask);
            }
        }
        let mut regnames = HashMap::new();
        for (i, s) in syms.iter().enumerate() {
            if let Kind::Varnode { space, off, size } = s.kind {
                regnames.entry((space, off, size)).or_insert(i);
            }
        }
        Ok(Sleigh {
            spaces,
            syms,
            ctors,
            root: root_sym,
            code_space,
            uniq_space,
            uniq_base: root.uint(a::UNIQBASE).unwrap_or(0),
            uniq_mask: root.uint(a::UNIQMASK).unwrap_or(0),
            ctx_default,
            regnames,
        })
    }

    pub fn new_parse(&self) -> Parse {
        Parse { buf: [0; 48], addr: 0, naddr: 0, len: 0, ctx: self.ctx_default.clone(), states: Vec::with_capacity(64) }
    }

    fn operand(&self, sym: usize) -> &Operand {
        match &self.syms[sym].kind {
            Kind::Operand(o) => o,
            _ => panic!("symbol {} is not an operand", self.syms[sym].name),
        }
    }

    fn is_subtable(&self, sym: usize) -> bool {
        matches!(self.syms[sym].kind, Kind::Subtable { .. })
    }

    fn wrap(&self, space: u32, off: u64) -> u64 {
        match self.spaces.get(space as usize) {
            Some(s) if space != CONST_SPACE => off & calc_mask(s.size),
            _ => off,
        }
    }

    // ------------------------------------------------------------ expressions

    fn eval(&self, x: &Expr, p: &Parse, point: u32, off: u32) -> Result<i64> {
        Ok(match x {
            Expr::Token { be, sign, bitstart, bitend, bytestart, byteend, shift } => {
                let size = byteend - bytestart + 1;
                let mut res: u64 = 0;
                let mut pos = *bytestart;
                let mut left = size;
                while left > 0 {
                    let n = left.min(4);
                    res = (res << (8 * n)) | p.ins_bytes(off + pos as u32, n as u32)? as u64;
                    pos += n;
                    left -= n;
                }
                if !be {
                    res = res.swap_bytes() >> (64 - 8 * size);
                }
                let v = (res as i64) >> shift;
                if *sign { sign_extend(v, bitend - bitstart) } else { zero_extend(v, bitend - bitstart) }
            }
            Expr::Ctx { sign, startbit, endbit, startbyte, endbyte, shift } => {
                let mut res: u64 = 0;
                let mut b = *startbyte;
                while b <= *endbyte {
                    let n = (endbyte - b + 1).min(4);
                    res = (res << (8 * n)) | p.ctx_bytes(b, n) as u64;
                    b += n;
                }
                let v = (res as i64) >> shift;
                if *sign { sign_extend(v, endbit - startbit) } else { zero_extend(v, endbit - startbit) }
            }
            Expr::Const(v) => *v,
            Expr::Operand { index, table, ct } => self.eval_operand(*index, *table, *ct, p, point)?,
            Expr::Start => p.addr as i64,
            Expr::End => p.naddr as i64,
            Expr::Next2 => return Err("inst_next2 is not supported".into()),
            Expr::Neg(u) => self.eval(u, p, point, off)?.wrapping_neg(),
            Expr::Not(u) => !self.eval(u, p, point, off)?,
            Expr::Bin(op, l, r) => {
                let l = self.eval(l, p, point, off)?;
                let r = self.eval(r, p, point, off)?;
                match *op {
                    e::PLUS_EXP => l.wrapping_add(r),
                    e::SUB_EXP => l.wrapping_sub(r),
                    e::MULT_EXP => l.wrapping_mul(r),
                    e::LSHIFT_EXP => l.wrapping_shl(r as u32),
                    e::RSHIFT_EXP => l.wrapping_shr(r as u32),
                    e::AND_EXP => l & r,
                    e::OR_EXP => l | r,
                    e::XOR_EXP => l ^ r,
                    _ => {
                        if r == 0 {
                            return Err("division by zero in pattern expression".into());
                        }
                        l.wrapping_div(r)
                    }
                }
            }
        })
    }

    /// OperandValue::getValue: evaluate another operand of constructor `ct` at its offset.
    fn eval_operand(&self, index: usize, table: usize, ctid: usize, p: &Parse, point: u32) -> Result<i64> {
        let ct = match &self.syms[table].kind {
            Kind::Subtable { ctors, .. } => *ctors.get(ctid).ok_or("invalid constructor id")?,
            _ => return Err("operand_exp table is not a subtable".into()),
        };
        let op = self.operand(self.ctors[ct].operands[index]);
        let mut pt = point;
        while pt != NONE && p.states[pt as usize].ct != ct {
            pt = p.states[pt as usize].parent;
        }
        if pt == NONE {
            return Ok(0);
        }
        let st = &p.states[pt as usize];
        let off = if op.offbase < 0 {
            (st.offset as i32 + op.reloff) as u32
        } else {
            match st.resolve[index] {
                NONE => 0,
                r => p.states[r as usize].offset,
            }
        };
        match (&op.defexp, op.triple) {
            (Some(x), _) => self.eval(x, p, pt, off),
            (None, Some(t)) => self.sym_value(t, p, pt, off),
            _ => Ok(0),
        }
    }

    /// Value of a symbol's pattern expression (TripleSymbol::getPatternExpression()->getValue).
    fn sym_value(&self, sym: usize, p: &Parse, point: u32, off: u32) -> Result<i64> {
        match &self.syms[sym].kind {
            Kind::Value(x) | Kind::ValueMap(x, _) | Kind::Name(x, _) | Kind::VarList(x, _) | Kind::Context { exp: x, .. } => {
                self.eval(x, p, point, off)
            }
            Kind::Epsilon | Kind::Varnode { .. } => Ok(0),
            Kind::Start => Ok(p.addr as i64),
            Kind::End => Ok(p.naddr as i64),
            _ => Err(format!("symbol {} has no pattern value", self.syms[sym].name)),
        }
    }

    // ------------------------------------------------------------ resolve (Sleigh::resolve)

    fn pat_block(&self, b: &Block, p: &Parse, point: u32, ctx: bool) -> Result<bool> {
        if b.nonzero <= 0 {
            return Ok(b.nonzero == 0);
        }
        let base = p.states[point as usize].offset;
        let mut off = b.off;
        for &(mask, val) in &b.words {
            let data = if ctx { p.ctx_bytes(off as i32, 4) } else { p.ins_bytes(base + off, 4)? };
            if mask & data != val {
                return Ok(false);
            }
            off += 4;
        }
        Ok(true)
    }

    fn pat_match(&self, pat: &Pat, p: &Parse, point: u32) -> Result<bool> {
        Ok(match pat {
            Pat::Instr(b) => self.pat_block(b, p, point, false)?,
            Pat::Ctx(b) => self.pat_block(b, p, point, true)?,
            Pat::Both(c, i) => self.pat_block(i, p, point, false)? && self.pat_block(c, p, point, true)?,
        })
    }

    fn resolve_decision(&self, mut d: &Decision, p: &Parse, point: u32) -> Result<usize> {
        loop {
            if d.size == 0 {
                for (pat, ct) in &d.list {
                    if self.pat_match(pat, p, point)? {
                        return Ok(*ct);
                    }
                }
                return Err(format!("{:#x}: no matching constructor", p.addr));
            }
            let v = if d.ctx {
                p.ctx_bits(d.start, d.size)
            } else {
                p.ins_bits(p.states[point as usize].offset, d.start, d.size)?
            };
            d = d.kids.get(v as usize).ok_or("decision tree out of range")?;
        }
    }

    fn table_index(&self, x: &Expr, len: usize, p: &Parse, point: u32) -> Result<usize> {
        let v = self.eval(x, p, point, p.states[point as usize].offset)?;
        if v < 0 || v as usize >= len {
            return Err(format!("{:#x}: no corresponding table entry", p.addr));
        }
        Ok(v as usize)
    }

    /// TripleSymbol::resolve: a constructor for subtables, validation for tables.
    fn resolve_sym(&self, sym: usize, p: &Parse, point: u32) -> Result<Option<usize>> {
        match &self.syms[sym].kind {
            Kind::Subtable { tree: Some(d), .. } => Ok(Some(self.resolve_decision(d, p, point)?)),
            Kind::Subtable { tree: None, .. } => Err(format!("table {} has no decision tree", self.syms[sym].name)),
            Kind::ValueMap(x, t) => self.table_index(x, t.len(), p, point).map(|_| None),
            Kind::Name(x, t) => {
                let i = self.table_index(x, t.len(), p, point)?;
                if t[i] == "\t" || t[i] == "_" {
                    return Err(format!("{:#x}: no corresponding entry in nametable", p.addr));
                }
                Ok(None)
            }
            Kind::VarList(x, t) => {
                let i = self.table_index(x, t.len(), p, point)?;
                if t[i].is_none() {
                    return Err(format!("{:#x}: no corresponding entry in varnode list", p.addr));
                }
                Ok(None)
            }
            _ => Ok(None),
        }
    }

    fn apply_ctx(&self, ct: usize, p: &mut Parse, point: u32) -> Result<()> {
        for c in &self.ctors[ct].ctx {
            if let CtxChange::Op { num, shift, mask, exp } = c {
                let v = (self.eval(exp, p, point, p.states[point as usize].offset)? as u32).wrapping_shl(*shift);
                if let Some(w) = p.ctx.get_mut(*num) {
                    *w = (*w & !mask) | (mask & v);
                }
            }
        }
        Ok(())
    }

    /// Decode one instruction at `addr` from `bytes` into `p`; returns its length.
    pub fn decode(&self, p: &mut Parse, addr: u64, bytes: &[u8]) -> Result<usize> {
        p.buf = [0; 48];
        let n = bytes.len().min(MAX_INSTRUCTION_LEN as usize);
        p.buf[..n].copy_from_slice(&bytes[..n]);
        p.addr = addr;
        p.naddr = addr;
        p.ctx.clear();
        p.ctx.extend_from_slice(&self.ctx_default);
        p.states.clear();
        p.states.push(State::new(NONE));

        let mut point: u32 = 0;
        let mut depth: usize = 0;
        let mut bc = [0u32; MAX_DEPTH];
        let ct = self.resolve_sym(self.root, p, 0)?.ok_or("root table did not resolve")?;
        p.states[0].ct = ct;
        self.apply_ctx(ct, p, 0)?;
        while point != NONE {
            let ct = p.states[point as usize].ct;
            let mut oper = bc[depth] as usize;
            let numoper = self.ctors[ct].operands.len();
            while oper < numoper {
                let op = self.operand(self.ctors[ct].operands[oper]);
                let st = &p.states[point as usize];
                let base = if op.offbase < 0 {
                    st.offset
                } else {
                    let r = &p.states[st.resolve[op.offbase as usize] as usize];
                    r.offset + r.length
                };
                let off = (base as i32 + op.reloff) as u32;
                // ParserContext::allocateOperand
                let ns = p.states.len() as u32;
                p.states.push(State::new(point));
                p.states[point as usize].resolve[oper] = ns;
                if depth > MAX_DEPTH - 2 {
                    return Err("SLEIGH exceeded maximum parse depth".into());
                }
                bc[depth] += 1;
                depth += 1;
                point = ns;
                bc[depth] = 0;
                p.states[point as usize].offset = off;
                if let Some(t) = op.triple {
                    if let Some(sub) = self.resolve_sym(t, p, point)? {
                        p.states[point as usize].ct = sub;
                        self.apply_ctx(sub, p, point)?;
                        break;
                    }
                }
                p.states[point as usize].length = op.minlen;
                point = p.states[point as usize].parent;
                depth -= 1;
                oper += 1;
            }
            if oper >= numoper {
                // ParserWalkerChange::calcCurrentLength
                let st = &p.states[point as usize];
                let mut length = self.ctors[ct].minlen + st.offset;
                for &r in &st.resolve[..numoper] {
                    let s = &p.states[r as usize];
                    length = length.max(s.length + s.offset);
                }
                let st = &mut p.states[point as usize];
                st.length = length - st.offset;
                point = st.parent;
                depth = depth.wrapping_sub(1);
            }
        }
        p.len = p.states[0].length as usize;
        p.naddr = addr + p.len as u64;
        self.resolve_handles(p)?;
        Ok(p.len)
    }

    // ------------------------------------------------------------ handles (Sleigh::resolveHandles)

    fn sym_handle(&self, sym: usize, p: &Parse, point: u32) -> Result<Handle> {
        let off = p.states[point as usize].offset;
        Ok(match &self.syms[sym].kind {
            Kind::Value(x) | Kind::Name(x, _) | Kind::Context { exp: x, .. } => const_handle(self.eval(x, p, point, off)? as u64),
            Kind::ValueMap(x, t) => const_handle(t[self.table_index(x, t.len(), p, point)?] as u64),
            Kind::Varnode { space, off, size } => Handle { space: *space, size: *size, offset_offset: *off, ..Handle::default() },
            Kind::VarList(x, t) => match t[self.table_index(x, t.len(), p, point)?].map(|v| &self.syms[v].kind) {
                Some(Kind::Varnode { space, off, size }) => {
                    Handle { space: *space, size: *size, offset_offset: *off, ..Handle::default() }
                }
                _ => return Err("bad varnode list entry".into()),
            },
            Kind::Epsilon => const_handle(0),
            Kind::Start | Kind::End => Handle {
                space: self.code_space,
                size: self.spaces[self.code_space as usize].size,
                offset_offset: if matches!(self.syms[sym].kind, Kind::Start) { p.addr } else { p.naddr },
                ..Handle::default()
            },
            Kind::Operand(o) => self.handle(p, point, o.index),
            _ => return Err(format!("symbol {} cannot be an operand", self.syms[sym].name)),
        })
    }

    fn handle(&self, p: &Parse, point: u32, idx: usize) -> Handle {
        match p.states[point as usize].resolve.get(idx) {
            Some(&r) if r != NONE => p.states[r as usize].hand,
            _ => Handle::default(),
        }
    }

    fn fix(&self, c: &C, p: &Parse, point: u32) -> Result<u64> {
        Ok(match *c {
            C::Real(v) | C::Relative(v) => v,
            C::Start => p.addr,
            C::Next => p.naddr,
            C::CurSpace => self.code_space as u64,
            C::CurSpaceSize => self.spaces[self.code_space as usize].size as u64,
            C::SpaceId(s) => s as u64,
            C::Handle { idx, sel, plus } => {
                let h = self.handle(p, point, idx);
                let dynamic = h.offset_space != NONE;
                match sel {
                    0 => (if dynamic { h.temp_space } else { h.space }) as u64,
                    1 => if dynamic { h.temp_offset } else { h.offset_offset },
                    2 => h.size as u64,
                    _ => {
                        let v = if dynamic { h.temp_offset } else { h.offset_offset };
                        if h.space != CONST_SPACE {
                            v.wrapping_add(plus & 0xffff)
                        } else {
                            v.checked_shr(8 * (plus >> 16) as u32).unwrap_or(0)
                        }
                    }
                }
            }
            C::Next2 => return Err("inst_next2 is not supported".into()),
            C::Flow => return Err("flowref/flowdest are not supported".into()),
        })
    }

    fn fix_space(&self, c: &C, p: &Parse, point: u32) -> Result<u32> {
        match *c {
            C::CurSpace => Ok(self.code_space),
            C::SpaceId(s) => Ok(s),
            C::Handle { idx, sel: 0, .. } => {
                let h = self.handle(p, point, idx);
                Ok(if h.offset_space == NONE { h.space } else { h.temp_space })
            }
            _ => Err("constant template is not a space".into()),
        }
    }

    /// HandleTpl::fix
    fn fix_handle(&self, t: &HandleTpl, p: &Parse, point: u32) -> Result<Handle> {
        let mut h = Handle::default();
        if let C::Real(_) = t.ptrspace {
            h.space = match t.space {
                C::Handle { idx, sel: 0, .. } => self.handle(p, point, idx).space,
                ref c => self.fix_space(c, p, point)?,
            };
            h.size = self.fix(&t.size, p, point)? as u32;
            if let C::Handle { idx, .. } = t.ptroffset {
                let o = self.handle(p, point, idx);
                h.offset_space = o.offset_space;
                h.offset_offset = o.offset_offset;
                h.offset_size = o.offset_size;
                h.temp_space = o.temp_space;
                h.temp_offset = o.temp_offset;
            } else {
                h.offset_offset = self.wrap(h.space, self.fix(&t.ptroffset, p, point)?);
            }
        } else {
            h.space = self.fix_space(&t.space, p, point)?;
            h.size = self.fix(&t.size, p, point)? as u32;
            h.offset_offset = self.fix(&t.ptroffset, p, point)?;
            h.offset_space = self.fix_space(&t.ptrspace, p, point)?;
            if h.offset_space == CONST_SPACE {
                h.offset_space = NONE;
                h.offset_offset = self.wrap(h.space, h.offset_offset);
            } else {
                h.offset_size = self.fix(&t.ptrsize, p, point)? as u32;
                h.temp_space = self.fix_space(&t.temp_space, p, point)?;
                h.temp_offset = self.fix(&t.temp_offset, p, point)?;
            }
        }
        Ok(h)
    }

    fn resolve_handles(&self, p: &mut Parse) -> Result<()> {
        let mut point: u32 = 0;
        let mut depth: usize = 0;
        let mut bc = [0u32; MAX_DEPTH];
        while point != NONE {
            let ct = p.states[point as usize].ct;
            let mut oper = bc[depth] as usize;
            let numoper = self.ctors[ct].operands.len();
            while oper < numoper {
                let op = self.operand(self.ctors[ct].operands[oper]);
                // pushOperand
                bc[depth] = oper as u32 + 1;
                depth += 1;
                point = p.states[point as usize].resolve[oper];
                bc[depth] = 0;
                let hand = match (op.triple, &op.defexp) {
                    (Some(t), _) if self.is_subtable(t) => break,
                    (Some(t), _) => self.sym_handle(t, p, point)?,
                    (None, Some(x)) => const_handle(self.eval(x, p, point, p.states[point as usize].offset)? as u64),
                    (None, None) => return Err("operand is undefined".into()),
                };
                p.states[point as usize].hand = hand;
                point = p.states[point as usize].parent;
                depth -= 1;
                oper += 1;
            }
            if oper >= numoper {
                if let Some(r) = self.ctors[ct].templ.as_ref().and_then(|t| t.result.as_ref()) {
                    let h = self.fix_handle(r, p, point)?;
                    p.states[point as usize].hand = h;
                }
                point = p.states[point as usize].parent;
                depth = depth.wrapping_sub(1);
            }
        }
        Ok(())
    }

    // ------------------------------------------------------------ printing

    fn print_pieces(&self, ct: usize, range: std::ops::Range<usize>, p: &Parse, point: u32, out: &mut String) -> Result<()> {
        for piece in &self.ctors[ct].pieces[range] {
            match piece {
                Piece::Lit(s) => out.push_str(s),
                Piece::Op(i) => self.print_operand(ct, *i, p, point, out)?,
            }
        }
        Ok(())
    }

    fn print_operand(&self, ct: usize, i: usize, p: &Parse, point: u32, out: &mut String) -> Result<()> {
        let op = self.operand(self.ctors[ct].operands[i]);
        let child = p.states[point as usize].resolve[op.index];
        let off = p.states[child as usize].offset;
        match (op.triple, &op.defexp) {
            (Some(t), _) if self.is_subtable(t) => {
                let cct = p.states[child as usize].ct;
                self.print_pieces(cct, 0..self.ctors[cct].pieces.len(), p, child, out)?
            }
            (Some(t), _) => self.print_sym(t, p, child, out)?,
            (None, Some(x)) => hex(out, self.eval(x, p, child, off)?),
            (None, None) => {}
        }
        Ok(())
    }

    fn print_sym(&self, sym: usize, p: &Parse, point: u32, out: &mut String) -> Result<()> {
        let off = p.states[point as usize].offset;
        match &self.syms[sym].kind {
            Kind::Value(x) | Kind::Context { exp: x, .. } => hex(out, self.eval(x, p, point, off)?),
            Kind::ValueMap(x, t) => hex(out, t[self.table_index(x, t.len(), p, point)?]),
            Kind::Name(x, t) => out.push_str(&t[self.table_index(x, t.len(), p, point)?]),
            Kind::VarList(x, t) => {
                let v = t[self.table_index(x, t.len(), p, point)?].ok_or("bad varnode list entry")?;
                out.push_str(&self.syms[v].name)
            }
            Kind::Varnode { .. } => out.push_str(&self.syms[sym].name),
            Kind::Epsilon => out.push('0'),
            Kind::Start => hex(out, p.addr as i64),
            Kind::End => hex(out, p.naddr as i64),
            Kind::Operand(o) => {
                let child = p.states[point as usize].resolve[o.index];
                if let Some(t) = o.triple {
                    self.print_sym(t, p, child, out)?
                }
            }
            _ => return Err(format!("cannot print symbol {}", self.syms[sym].name)),
        }
        Ok(())
    }

    /// Constructor::printMnemonic / printBody, following flow-through constructors.
    fn print_part(&self, mut ct: usize, p: &Parse, mut point: u32, body: bool, out: &mut String) -> Result<()> {
        while let Some(i) = self.ctors[ct].flowthru {
            let op = self.operand(self.ctors[ct].operands[i]);
            match op.triple {
                Some(t) if self.is_subtable(t) => {
                    point = p.states[point as usize].resolve[op.index];
                    ct = p.states[point as usize].ct;
                }
                _ => break,
            }
        }
        let c = &self.ctors[ct];
        let n = c.pieces.len();
        let range = match (body, c.firstws) {
            (false, -1) => 0..n,
            (false, w) => 0..(w as usize).min(n),
            (true, -1) => return Ok(()),
            (true, w) => (w as usize + 1).min(n)..n,
        };
        self.print_pieces(ct, range, p, point, out)
    }

    /// Decode and render one instruction.
    pub fn disasm(&self, p: &mut Parse, addr: u64, bytes: &[u8]) -> Result<Insn> {
        let len = self.decode(p, addr, bytes)?;
        let mut mnemonic = String::new();
        let mut body = String::new();
        let ct = p.states[0].ct;
        self.print_part(ct, p, 0, false, &mut mnemonic)?;
        self.print_part(ct, p, 0, true, &mut body)?;
        Ok(Insn { addr, len, mnemonic, body })
    }

    // ------------------------------------------------------------ p-code (SleighBuilder)

    /// P-code for the instruction last decoded into `p`.
    pub fn pcode(&self, p: &Parse) -> Result<Vec<PcodeOp>> {
        let mut b = Builder {
            s: self,
            p,
            ops: Vec::new(),
            labelbase: 0,
            labelcount: 0,
            labels: Vec::new(),
            label_refs: Vec::new(),
            uniqoff: (p.addr & self.uniq_mask) << 8,
        };
        let t = self.ctors[p.states[0].ct].templ.as_ref().ok_or("instruction not implemented in p-code")?;
        b.build(t, -1, 0)?;
        for &i in &b.label_refs {
            let vn = &mut b.ops[i].ins[0];
            let target = *b.labels.get(vn.offset as usize).filter(|&&l| l != NONE).ok_or("reference to missing sleigh label")?;
            vn.offset = (target as u64).wrapping_sub(i as u64) & calc_mask(vn.size);
        }
        Ok(b.ops)
    }

    pub fn fmt_varnode(&self, v: &Varnode) -> String {
        if v.space == CONST_SPACE {
            return format!("{:#x}:{}", v.offset, v.size);
        }
        if let Some(&i) = self.regnames.get(&(v.space, v.offset, v.size)) {
            return self.syms[i].name.clone();
        }
        let name = self.spaces.get(v.space as usize).map_or("?", |s| s.name.as_str());
        format!("{}[{:#x}]:{}", name, v.offset, v.size)
    }

    pub fn fmt_op(&self, op: &PcodeOp) -> String {
        let mut s = String::new();
        if let Some(o) = &op.out {
            s += &self.fmt_varnode(o);
            s += " = ";
        }
        s += OPCODE_NAMES.get(op.opc as usize).unwrap_or(&"?");
        for (i, v) in op.ins.iter().enumerate() {
            s += if i == 0 { " " } else { ", " };
            if i == 0 && (op.opc == OP_LOAD || op.opc == OP_STORE) {
                s += self.spaces.get(v.offset as usize).map_or("?", |x| x.name.as_str());
            } else {
                s += &self.fmt_varnode(v);
            }
        }
        s
    }
}

struct Builder<'a> {
    s: &'a Sleigh,
    p: &'a Parse,
    ops: Vec<PcodeOp>,
    labelbase: u32,
    labelcount: u32,
    labels: Vec<u32>,
    label_refs: Vec<usize>,
    uniqoff: u64,
}

impl Builder<'_> {
    fn build(&mut self, t: &Tpl, secnum: i64, point: u32) -> Result<()> {
        let old = self.labelbase;
        self.labelbase = self.labelcount;
        self.labelcount += t.labels;
        for op in &t.ops {
            match op.opc {
                OP_BUILD => self.append_build(op, secnum, point)?,
                OP_LABELBUILD => {
                    let id = (self.s.fix(&op.ins[0].off, self.p, point)? as u32 + self.labelbase) as usize;
                    self.labels.resize(self.labels.len().max(id + 1), NONE);
                    self.labels[id] = self.ops.len() as u32;
                }
                OP_DELAY_SLOT | OP_CROSSBUILD => return Err("delay slots / crossbuild are not supported".into()),
                _ => self.dump(op, point)?,
            }
        }
        self.labelbase = old;
        Ok(())
    }

    fn build_sub(&mut self, point: u32, secnum: i64) -> Result<()> {
        let ct = &self.s.ctors[self.p.states[point as usize].ct];
        if secnum >= 0 {
            match ct.named.get(secnum as usize).and_then(|t| t.as_ref()) {
                Some(t) => self.build(t, secnum, point),
                None => self.build_empty(point, secnum),
            }
        } else {
            let t = ct.templ.as_ref().ok_or("instruction not implemented in p-code")?;
            self.build(t, -1, point)
        }
    }

    fn append_build(&mut self, op: &OpTpl, secnum: i64, point: u32) -> Result<()> {
        let index = self.s.fix(&op.ins[0].off, self.p, point)? as usize;
        let ct = self.p.states[point as usize].ct;
        let o = self.s.operand(self.s.ctors[ct].operands[index]);
        match o.triple {
            Some(t) if self.s.is_subtable(t) => self.build_sub(self.p.states[point as usize].resolve[index], secnum),
            _ => Ok(()),
        }
    }

    fn build_empty(&mut self, point: u32, secnum: i64) -> Result<()> {
        let ct = self.p.states[point as usize].ct;
        for (i, &osym) in self.s.ctors[ct].operands.iter().enumerate() {
            if let Some(t) = self.s.operand(osym).triple {
                if self.s.is_subtable(t) {
                    self.build_sub(self.p.states[point as usize].resolve[i], secnum)?;
                }
            }
        }
        Ok(())
    }

    fn loc(&self, vt: &VnTpl, point: u32) -> Result<Varnode> {
        let space = self.s.fix_space(&vt.space, self.p, point)?;
        let size = self.s.fix(&vt.size, self.p, point)? as u32;
        let off = self.s.fix(&vt.off, self.p, point)?;
        let offset = if space == CONST_SPACE {
            off & calc_mask(size)
        } else if space == self.s.uniq_space {
            off | self.uniqoff
        } else {
            self.s.wrap(space, off)
        };
        Ok(Varnode { space, offset, size })
    }

    fn dynamic(&self, vt: &VnTpl, point: u32) -> Option<Handle> {
        match vt.off {
            C::Handle { idx, .. } => Some(self.s.handle(self.p, point, idx)).filter(|h| h.offset_space != NONE),
            _ => None,
        }
    }

    /// The pointer of a dynamic operand, plus an INT_ADD for a truncation offset if any.
    fn pointer(&mut self, vt: &VnTpl, h: Handle) -> Varnode {
        let s = self.s;
        let offset = if h.offset_space == s.uniq_space {
            h.offset_offset | self.uniqoff
        } else {
            s.wrap(h.offset_space, h.offset_offset)
        };
        let ptr = Varnode { space: h.offset_space, offset, size: h.offset_size };
        match vt.off {
            C::Handle { sel: 3, plus, .. } if plus & 0xffff != 0 => {
                let tmp = Varnode { space: s.uniq_space, offset: s.uniq_base + RUNTIME_BITRANGE_EA, size: ptr.size };
                let k = Varnode { space: CONST_SPACE, offset: plus & 0xffff, size: ptr.size };
                self.ops.push(PcodeOp { opc: OP_INT_ADD, out: Some(tmp), ins: vec![ptr, k] });
                tmp
            }
            _ => ptr,
        }
    }

    fn dump(&mut self, op: &OpTpl, point: u32) -> Result<()> {
        let mut ins = Vec::with_capacity(op.ins.len());
        for vt in &op.ins {
            let vn = self.loc(vt, point)?;
            if let Some(h) = self.dynamic(vt, point) {
                let spc = Varnode { space: CONST_SPACE, offset: h.space as u64, size: 8 };
                let ptr = self.pointer(vt, h);
                self.ops.push(PcodeOp { opc: OP_LOAD, out: Some(vn), ins: vec![spc, ptr] });
            }
            ins.push(vn);
        }
        if let Some(C::Relative(_)) = op.ins.first().map(|v| v.off) {
            ins[0].offset += self.labelbase as u64;
            self.label_refs.push(self.ops.len());
        }
        let mut store = None;
        let out = match &op.out {
            None => None,
            Some(vt) => {
                let vn = self.loc(vt, point)?;
                store = self.dynamic(vt, point).map(|h| (vt, h, vn));
                Some(vn)
            }
        };
        self.ops.push(PcodeOp { opc: op.opc, out, ins });
        if let Some((vt, h, vn)) = store {
            let spc = Varnode { space: CONST_SPACE, offset: h.space as u64, size: 8 };
            let ptr = self.pointer(vt, h);
            self.ops.push(PcodeOp { opc: OP_STORE, out: None, ins: vec![spc, ptr, vn] });
        }
        Ok(())
    }
}
