//! SLEIGH decode engine: a port of the runtime half of Ghidra's C++ sleigh
//! (sleigh.cc, slghsymbol.cc, slghpattern.cc, slghpatexpress.cc, context.cc, semantics.cc).
//! Logic follows upstream; the class hierarchy is flattened into enums and index arenas.
//!
//! Not ported (x86 does not use them): delay slots, crossbuild, inst_next2 and
//! flowref/flowdest. Context starts from the `.pspec` defaults; context commits
//! (globalset) are recorded in the `Parse` and apply to later decodes at their address.

use crate::sla::{self, a, e, Elem, Result};
use std::collections::{BTreeMap, HashMap};
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
    "BLANK",
    "COPY",
    "LOAD",
    "STORE",
    "BRANCH",
    "CBRANCH",
    "BRANCHIND",
    "CALL",
    "CALLIND",
    "CALLOTHER",
    "RETURN",
    "INT_EQUAL",
    "INT_NOTEQUAL",
    "INT_SLESS",
    "INT_SLESSEQUAL",
    "INT_LESS",
    "INT_LESSEQUAL",
    "INT_ZEXT",
    "INT_SEXT",
    "INT_ADD",
    "INT_SUB",
    "INT_CARRY",
    "INT_SCARRY",
    "INT_SBORROW",
    "INT_2COMP",
    "INT_NEGATE",
    "INT_XOR",
    "INT_AND",
    "INT_OR",
    "INT_LEFT",
    "INT_RIGHT",
    "INT_SRIGHT",
    "INT_MULT",
    "INT_DIV",
    "INT_SDIV",
    "INT_REM",
    "INT_SREM",
    "BOOL_NEGATE",
    "BOOL_XOR",
    "BOOL_AND",
    "BOOL_OR",
    "FLOAT_EQUAL",
    "FLOAT_NOTEQUAL",
    "FLOAT_LESS",
    "FLOAT_LESSEQUAL",
    "UNUSED1",
    "FLOAT_NAN",
    "FLOAT_ADD",
    "FLOAT_DIV",
    "FLOAT_MULT",
    "FLOAT_SUB",
    "FLOAT_NEG",
    "FLOAT_ABS",
    "FLOAT_SQRT",
    "INT2FLOAT",
    "FLOAT2FLOAT",
    "TRUNC",
    "CEIL",
    "FLOOR",
    "ROUND",
    "MULTIEQUAL",
    "INDIRECT",
    "PIECE",
    "SUBPIECE",
    "CAST",
    "PTRADD",
    "PTRSUB",
    "SEGMENTOP",
    "CPOOLREF",
    "NEW",
    "INSERT",
    "ZPULL",
    "POPCOUNT",
    "LZCOUNT",
    "SPULL",
];

/// `<set name=".." val=".."/>` entries of a .pspec `<context_set>`: the context defaults.
fn pspec_context(text: &str) -> Vec<(String, u32)> {
    pspec_sets(text, "context_set")
}

/// `<set name=".." val=".."/>` entries of the .pspec element `tag` (`context_set`, `tracked_set`).
fn pspec_sets(text: &str, tag: &str) -> Vec<(String, u32)> {
    let Some(start) = text.find(&format!("<{tag}")) else { return Vec::new() };
    let end = text[start..].find(&format!("</{tag}>")).map_or(text.len(), |e| start + e);
    let attr = |tag: &str, name: &str| {
        let i = tag.find(&format!("{name}=\""))? + name.len() + 2;
        Some(tag[i..i + tag[i..].find('"')?].to_string())
    };
    text[start..end]
        .split("<set ")
        .skip(1)
        .filter_map(|tag| {
            let v = attr(tag, "val")?;
            let v = match v.strip_prefix("0x") {
                Some(h) => u32::from_str_radix(h, 16).ok()?,
                None => v.parse().ok()?,
            };
            Some((attr(tag, "name")?, v))
        })
        .collect()
}

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
    UserOp(u32),
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
    Commit { sym: usize, num: usize, mask: u32, flow: bool }, // globalset
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
    /// the .pspec `<tracked_set>`: registers with a known value at every address (x86: DF = 0)
    pub tracked: Vec<(String, u32)>,
    /// user-defined op names by index
    userops: Vec<Option<String>>,
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
        Handle {
            space: CONST_SPACE,
            size: 0,
            offset_space: NONE,
            offset_offset: 0,
            offset_size: 0,
            temp_space: 0,
            temp_offset: 0,
        }
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
    pending: Vec<(usize, u32, usize, u32, u32, bool)>, // (sym, point, num, mask, value, flow)
    /// Context changes committed by `globalset`, by address: (word, mask, value, flows).
    pub changes: BTreeMap<u64, Vec<(usize, u32, u32, bool)>>,
    /// Record the instruction bits the decode matched on, for `fid_parts` (Function ID).
    pub fid: bool,
    pats: std::cell::RefCell<Vec<(u32, u32, u32)>>, // (state, byte offset, mask word)
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

/// Why an instruction has no p-code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PcodeError {
    /// a constructor of the instruction has no p-code body (C++ `UnimplError`)
    Unimplemented,
    /// anything else (a malformed template, an unsupported directive)
    Invalid(String),
}

impl std::fmt::Display for PcodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PcodeError::Unimplemented => f.write_str("instruction not implemented in p-code"),
            PcodeError::Invalid(e) => f.write_str(e),
        }
    }
}

impl From<String> for PcodeError {
    fn from(e: String) -> Self {
        PcodeError::Invalid(e)
    }
}

pub type PcodeResult<T> = std::result::Result<T, PcodeError>;

#[derive(Debug, Clone)]
pub struct Insn {
    pub addr: u64,
    pub len: usize,
    pub mnemonic: String,
    pub body: String,
}

/// An operand object as Function ID sees it (`Instruction.getOpObjects`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FidObj {
    Reg(u64), // offset in the register space
    Scalar(i64),
    Addr,
}

/// One display operand: its value bits, objects, and whether its handle is a constant
/// (`OperandType.SCALAR` before references are added).
#[derive(Debug, Clone)]
pub struct FidOperand {
    pub mask: Vec<u8>,
    pub objs: Vec<FidObj>,
    pub scalar: bool,
}

/// The instruction mask (operand bits cleared) and operands of an instruction, as
/// Ghidra's SleighDebugLogger (MASKS_ONLY) and SleighInstructionPrototype compute them.
#[derive(Debug, Clone)]
pub struct FidParts {
    pub mask: Vec<u8>,
    pub ops: Vec<FidOperand>,
}

fn calc_mask(size: u32) -> u64 {
    if size >= 8 {
        u64::MAX
    } else {
        (1u64 << (8 * size)) - 1
    }
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
        e::AND_EXP
        | e::DIV_EXP
        | e::LSHIFT_EXP
        | e::MULT_EXP
        | e::OR_EXP
        | e::PLUS_EXP
        | e::RSHIFT_EXP
        | e::SUB_EXP
        | e::XOR_EXP => Expr::Bin(el.id, kid(0)?, kid(1)?),
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
            Some(HandleTpl {
                space: c[0],
                size: c[1],
                ptrspace: c[2],
                ptroffset: c[3],
                ptrsize: c[4],
                temp_space: c[5],
                temp_offset: c[6],
            })
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
            e::COMMIT => c.ctx.push(CtxChange::Commit {
                sym: k.uint(a::ID)? as usize,
                num: k.int(a::NUMBER)? as usize,
                mask: k.uint(a::MASK)? as u32,
                flow: k.boolean(a::FLOW)?,
            }),
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
        Self::sla_path("x86-64")
    }

    /// Path of `<name>.sla` in Ghidra's x86 language directory (built by `rust/build-sla.sh`).
    pub fn sla_path(name: &str) -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("../../Ghidra/Processors/x86/data/languages/{name}.sla"))
    }

    /// Load a `.sla`; context defaults come from the `.pspec` of the same name next to it, if any.
    pub fn load(path: &Path) -> Result<Sleigh> {
        let pspec = std::fs::read_to_string(path.with_extension("pspec")).unwrap_or_default();
        let mut sl = Self::load_with_context(path, &pspec_context(&pspec))?;
        sl.tracked = pspec_sets(&pspec, "tracked_set");
        Ok(sl)
    }

    pub fn load_with_context(path: &Path, context: &[(String, u32)]) -> Result<Sleigh> {
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
                e::USEROP => Kind::UserOp(k.int(a::INDEX)? as u32),
                e::EPSILON_SYM => Kind::Epsilon,
                e::VALUE_SYM => Kind::Value(expr(first()?)?),
                e::VALUEMAP_SYM => {
                    Kind::ValueMap(expr(first()?)?, k.kids[1..].iter().map(|v| v.int(a::VAL)).collect::<Result<_>>()?)
                }
                e::NAME_SYM => Kind::Name(
                    expr(first()?)?,
                    k.kids[1..].iter().map(|v| v.string(a::NAME).unwrap_or("\t").to_string()).collect(),
                ),
                e::VARNODE_SYM => {
                    Kind::Varnode { space: k.int(a::SPACE)? as u32, off: k.uint(a::OFF)?, size: k.int(a::SIZE)? as u32 }
                }
                e::CONTEXT_SYM => {
                    Kind::Context { exp: expr(first()?)?, low: k.int(a::LOW)? as u32, high: k.int(a::HIGH)? as u32 }
                }
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
        for (name, val) in context {
            let val = *val;
            if let Some(Sym { kind: Kind::Context { low, high, .. }, .. }) = syms.iter().find(|s| s.name == *name) {
                let num = (*low / 32) as usize;
                let shift = 31 - high % 32;
                let mask = (u32::MAX >> (low % 32 + shift)) << shift;
                ctx_default[num] = (ctx_default[num] & !mask) | ((val << shift) & mask);
            }
        }
        let mut userops: Vec<Option<String>> = Vec::new();
        for s in &syms {
            if let Kind::UserOp(i) = s.kind {
                let i = i as usize;
                userops.resize(userops.len().max(i + 1), None);
                userops[i] = Some(s.name.clone());
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
            tracked: Vec::new(),
            userops,
        })
    }

    /// Index of the default code space (`ram` on x86), as used in `Varnode::space`.
    pub fn code_space(&self) -> u32 {
        self.code_space
    }

    /// Index of the `unique` (temporary) space.
    pub fn uniq_space(&self) -> u32 {
        self.uniq_space
    }

    pub fn new_parse(&self) -> Parse {
        Parse {
            buf: [0; 48],
            addr: 0,
            naddr: 0,
            len: 0,
            ctx: self.ctx_default.clone(),
            states: Vec::with_capacity(64),
            pending: Vec::new(),
            changes: BTreeMap::new(),
            fid: false,
            pats: Default::default(),
        }
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
                if *sign {
                    sign_extend(v, bitend - bitstart)
                } else {
                    zero_extend(v, bitend - bitstart)
                }
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
                if *sign {
                    sign_extend(v, endbit - startbit)
                } else {
                    zero_extend(v, endbit - startbit)
                }
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
            Kind::Value(x)
            | Kind::ValueMap(x, _)
            | Kind::Name(x, _)
            | Kind::VarList(x, _)
            | Kind::Context { exp: x, .. } => self.eval(x, p, point, off),
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
        // SleighDebugLogger: a matched instruction pattern joins the instruction mask
        if p.fid && !ctx {
            let mut pats = p.pats.borrow_mut();
            pats.extend(b.words.iter().enumerate().map(|(i, w)| (point, base + b.off + 4 * i as u32, w.0)));
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
                if p.fid {
                    // DecisionNode.debugInstructionBitsDecision
                    let m = u32::MAX.wrapping_shl(32 - d.size as u32).wrapping_shr(d.start as u32);
                    p.pats.borrow_mut().push((point, p.states[point as usize].offset, m));
                }
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
            match *c {
                CtxChange::Op { num, shift, mask, ref exp } => {
                    let v = (self.eval(exp, p, point, p.states[point as usize].offset)? as u32).wrapping_shl(shift);
                    if let Some(w) = p.ctx.get_mut(num) {
                        *w = (*w & !mask) | (mask & v);
                    }
                }
                // ParserContext::addCommit: the value is taken now, the address after the parse.
                CtxChange::Commit { sym, num, mask, flow } => {
                    let value = p.ctx.get(num).copied().unwrap_or(0) & mask;
                    p.pending.push((sym, point, num, mask, value, flow));
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
        // ponytail: replays every earlier change point, O(changes); fine while specs commit rarely
        for (&at, list) in p.changes.range(..=addr) {
            for &(num, mask, value, flow) in list {
                if flow || at == addr {
                    if let Some(w) = p.ctx.get_mut(num) {
                        *w = (*w & !mask) | value;
                    }
                }
            }
        }
        p.pending.clear();
        p.pats.borrow_mut().clear();
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
        // ParserContext::applyCommits
        for i in 0..p.pending.len() {
            let (sym, point, num, mask, value, flow) = p.pending[i];
            let at = self.sym_handle(sym, p, point)?.offset_offset;
            p.changes.entry(at).or_default().push((num, mask, value, flow));
        }
        Ok(p.len)
    }

    // ------------------------------------------------------------ handles (Sleigh::resolveHandles)

    fn sym_handle(&self, sym: usize, p: &Parse, point: u32) -> Result<Handle> {
        let off = p.states[point as usize].offset;
        Ok(match &self.syms[sym].kind {
            Kind::Value(x) | Kind::Name(x, _) | Kind::Context { exp: x, .. } => {
                const_handle(self.eval(x, p, point, off)? as u64)
            }
            Kind::ValueMap(x, t) => const_handle(t[self.table_index(x, t.len(), p, point)?] as u64),
            Kind::Varnode { space, off, size } => {
                Handle { space: *space, size: *size, offset_offset: *off, ..Handle::default() }
            }
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
                    1 => {
                        if dynamic {
                            h.temp_offset
                        } else {
                            h.offset_offset
                        }
                    }
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

    fn print_pieces(
        &self,
        ct: usize,
        range: std::ops::Range<usize>,
        p: &Parse,
        point: u32,
        out: &mut String,
    ) -> Result<()> {
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

    // ------------------------------------------------------------ Function ID masks

    /// Masks and operand objects of the instruction last decoded into `p`, which must have
    /// been decoded with `p.fid` set (SleighDebugLogger.buildMasks, getOpObjects, getOpType).
    pub fn fid_parts(&self, p: &Parse) -> FidParts {
        let len = p.len;
        let pats = p.pats.borrow();
        let under = |mut s: u32, top: u32| {
            while s != NONE && s != top {
                s = p.states[s as usize].parent;
            }
            s == top
        };
        let pat_mask = |top: u32| {
            let mut m = vec![0u8; len];
            for &(pt, off, w) in pats.iter().filter(|x| under(x.0, top)) {
                let _ = pt;
                for n in 0..4 {
                    if let Some(b) = m.get_mut(off as usize + n) {
                        *b |= (w >> (24 - 8 * n)) as u8;
                    }
                }
            }
            m
        };
        let mut mask = pat_mask(0);
        // mnemonic state (cacheMnemonicState)
        let (mut ct, mut point) = (p.states[0].ct, 0u32);
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
        let order: Vec<usize> = match c.firstws {
            -1 => vec![],
            w => c
                .pieces
                .iter()
                .skip(w as usize + 1)
                .filter_map(|x| if let Piece::Op(i) = x { Some(*i) } else { None })
                .collect(),
        };
        let root = &self.ctors[p.states[0].ct];
        let mut ops = Vec::new();
        for i in order {
            let sym = c.operands[i];
            let mut m = vec![0u8; len];
            self.fid_op_mask(p, point, sym, &mut m);
            if m.iter().all(|&b| b == 0) {
                // steal the bits of the top-level pattern group of the same name
                if let Some(&s) = root.operands.iter().find(|&&s| self.syms[s].name == self.syms[sym].name) {
                    let sub = p.states[0].resolve[self.operand(s).index];
                    if sub != NONE {
                        m = pat_mask(sub);
                    }
                }
            }
            for (a, b) in mask.iter_mut().zip(&m) {
                *a &= !b;
            }
            let mut list = Vec::new();
            self.fid_op_list(p, point, sym, &mut list);
            let objs = list.into_iter().flatten().filter_map(|h| self.fid_obj(&h)).collect();
            let child = p.states[point as usize].resolve[self.operand(sym).index];
            let h = if child == NONE { Handle::default() } else { p.states[child as usize].hand };
            ops.push(FidOperand { mask: m, objs, scalar: h.offset_space == NONE && h.space == CONST_SPACE });
        }
        FidParts { mask, ops }
    }

    /// SleighDebugLogger.combineOperandMask
    fn fid_op_mask(&self, p: &Parse, point: u32, sym: usize, m: &mut [u8]) {
        let op = self.operand(sym);
        let sub = p.states[point as usize].resolve[op.index];
        let x = match op.triple {
            Some(t) if self.is_subtable(t) => {
                if sub != NONE {
                    let c = &self.ctors[p.states[sub as usize].ct];
                    for piece in &c.pieces {
                        if let Piece::Op(j) = piece {
                            self.fid_op_mask(p, sub, c.operands[*j], m);
                        }
                    }
                }
                None
            }
            Some(t) => match &self.syms[t].kind {
                Kind::Value(x)
                | Kind::ValueMap(x, _)
                | Kind::Name(x, _)
                | Kind::VarList(x, _)
                | Kind::Context { exp: x, .. } => Some(x),
                _ => None,
            },
            None => op.defexp.as_ref(),
        };
        let Some(x) = x else { return };
        if op.offbase < 0 {
            self.fid_pat_mask(p, point, x, (p.states[point as usize].offset as i32 + op.reloff) as u32, m);
        } else if sub != NONE {
            self.fid_pat_mask(p, sub, x, p.states[sub as usize].offset, m);
        }
    }

    /// SleighDebugLogger.combinePatternMask (little-endian memory)
    fn fid_pat_mask(&self, p: &Parse, point: u32, x: &Expr, off: u32, m: &mut [u8]) {
        match x {
            Expr::Bin(_, l, r) => {
                self.fid_pat_mask(p, point, l, off, m);
                self.fid_pat_mask(p, point, r, off, m);
            }
            Expr::Neg(u) | Expr::Not(u) => self.fid_pat_mask(p, point, u, off, m),
            Expr::Operand { index, table, ct } => {
                if let Kind::Subtable { ctors, .. } = &self.syms[*table].kind {
                    if let Some(&c) = ctors.get(*ct) {
                        self.fid_op_mask(p, point, self.ctors[c].operands[*index], m);
                    }
                }
            }
            Expr::Token { bitstart, bitend, bytestart, byteend, .. } => {
                for i in *bytestart..=*byteend {
                    let (mut first, mut last) = (0i32, 7i32);
                    if i == *byteend {
                        last = bitend % 8;
                    }
                    if i == *bytestart {
                        first = bitstart % 8;
                    }
                    let b = (0xffi32.wrapping_shr((7 - last + first) as u32) << first) as u8;
                    if let Some(x) = m.get_mut((i + off as i32) as usize) {
                        *x |= b;
                    }
                }
            }
            _ => {}
        }
    }

    /// OperandSymbol.printList: handles in print order (None for printed characters).
    fn fid_op_list(&self, p: &Parse, point: u32, sym: usize, out: &mut Vec<Option<Handle>>) {
        let op = self.operand(sym);
        let child = p.states[point as usize].resolve[op.index];
        if child == NONE {
            return;
        }
        let st = &p.states[child as usize];
        match op.triple {
            Some(t) if self.is_subtable(t) => self.fid_ctor_list(p, child, out),
            Some(t) => match &self.syms[t].kind {
                Kind::Name(x, names) => {
                    if let Ok(i) = self.table_index(x, names.len(), p, child) {
                        out.extend(names[i].chars().map(|_| None));
                    }
                }
                Kind::Operand(_) | Kind::Subtable { .. } | Kind::None | Kind::UserOp(_) => {}
                _ => out.push(Some(st.hand)),
            },
            None => {
                let mut h = st.hand;
                if h.offset_size == 0 {
                    h.offset_size = st.length;
                }
                out.push(Some(h));
            }
        }
    }

    /// Constructor.printList, with its fix of a constant exported as an address.
    fn fid_ctor_list(&self, p: &Parse, point: u32, out: &mut Vec<Option<Handle>>) {
        let ct = p.states[point as usize].ct;
        let c = &self.ctors[ct];
        let (mut count, mut last) = (0, None);
        for piece in &c.pieces {
            match piece {
                Piece::Lit(s) => out.extend(s.chars().map(|_| None)),
                Piece::Op(i) => {
                    let prev = out.len();
                    self.fid_op_list(p, point, c.operands[*i], out);
                    if out.len() != prev {
                        count += 1;
                        if count == 1 {
                            for (n, slot) in out.iter().enumerate().skip(prev) {
                                if slot.is_some() {
                                    if last.is_some() {
                                        last = None;
                                        break;
                                    }
                                    last = Some((n, *i));
                                }
                            }
                        }
                    }
                }
            }
        }
        let (Some((n, i)), 1) = (last, count) else { return };
        let Some(res) = c.templ.as_ref().and_then(|t| t.result.as_ref()) else { return };
        let Some(mut h) = out[n] else { return };
        if h.space != CONST_SPACE || matches!(res.space, C::SpaceId(s) if s == self.uniq_space) {
            return;
        }
        if let C::Handle { idx, .. } = res.ptroffset {
            if idx == i {
                if let (Ok(space), Ok(size)) = (self.fix_space(&res.space, p, point), self.fix(&res.size, p, point)) {
                    h.space = space;
                    h.size = size as u32;
                    out[n] = Some(h);
                }
            }
        }
    }

    /// SleighInstructionPrototype.addHandleObject
    fn fid_obj(&self, h: &Handle) -> Option<FidObj> {
        let name = self.spaces.get(h.space as usize).map(|s| s.name.as_str());
        if h.space == CONST_SPACE {
            let size = [h.size, h.offset_size, self.spaces[self.code_space as usize].size]
                .into_iter()
                .find(|&s| s != 0)
                .unwrap();
            let v = h.offset_offset as i64;
            return Some(FidObj::Scalar(if size >= 8 { v } else { sign_extend(v, 8 * size as i32 - 1) }));
        }
        match name {
            Some("register") => {
                self.regnames.get(&(h.space, h.offset_offset, h.size)).map(|_| FidObj::Reg(h.offset_offset))
            }
            Some(_) if h.space == self.code_space => {
                if h.offset_space == NONE {
                    Some(FidObj::Addr)
                } else if self.spaces.get(h.offset_space as usize).map(|s| s.name.as_str()) == Some("register") {
                    Some(FidObj::Reg(h.offset_offset))
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    // ------------------------------------------------------------ p-code (SleighBuilder)

    /// P-code for the instruction last decoded into `p`.
    pub fn pcode(&self, p: &Parse) -> PcodeResult<Vec<PcodeOp>> {
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
        let t = self.ctors[p.states[0].ct].templ.as_ref().ok_or(PcodeError::Unimplemented)?;
        b.build(t, -1, 0)?;
        for &i in &b.label_refs {
            let vn = &mut b.ops[i].ins[0];
            let target = *b
                .labels
                .get(vn.offset as usize)
                .filter(|&&l| l != NONE)
                .ok_or_else(|| PcodeError::Invalid("reference to missing sleigh label".into()))?;
            vn.offset = (target as u64).wrapping_sub(i as u64) & calc_mask(vn.size);
        }
        Ok(b.ops)
    }

    /// The register table: (name, offset, size) of every varnode symbol in the `register`
    /// space, and that space's index (as in `Varnode::space`).
    pub fn registers(&self) -> (u32, Vec<(&str, u64, u32)>) {
        let reg = self.spaces.iter().position(|s| s.name == "register").map_or(NONE, |i| i as u32);
        let list = self
            .syms
            .iter()
            .filter_map(|s| match s.kind {
                Kind::Varnode { space, off, size } if space == reg => Some((s.name.as_str(), off, size)),
                _ => None,
            })
            .collect();
        (reg, list)
    }

    /// Every varnode symbol (registers): (name, space, offset, size).
    pub fn varnode_syms(&self) -> Vec<(&str, u32, u64, u32)> {
        self.syms
            .iter()
            .filter_map(|s| match s.kind {
                Kind::Varnode { space, off, size } => Some((s.name.as_str(), space, off, size)),
                _ => None,
            })
            .collect()
    }

    /// The name of user-defined p-code op `index` (CALLOTHER's first input).
    pub fn userop_name(&self, index: u64) -> Option<&str> {
        self.userops.get(usize::try_from(index).ok()?).and_then(|n| n.as_deref())
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
    fn build(&mut self, t: &Tpl, secnum: i64, point: u32) -> PcodeResult<()> {
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
                OP_DELAY_SLOT | OP_CROSSBUILD => {
                    return Err(PcodeError::Invalid("delay slots / crossbuild are not supported".into()))
                }
                _ => self.dump(op, point)?,
            }
        }
        self.labelbase = old;
        Ok(())
    }

    fn build_sub(&mut self, point: u32, secnum: i64) -> PcodeResult<()> {
        let ct = &self.s.ctors[self.p.states[point as usize].ct];
        if secnum >= 0 {
            match ct.named.get(secnum as usize).and_then(|t| t.as_ref()) {
                Some(t) => self.build(t, secnum, point),
                None => self.build_empty(point, secnum),
            }
        } else {
            let t = ct.templ.as_ref().ok_or(PcodeError::Unimplemented)?;
            self.build(t, -1, point)
        }
    }

    fn append_build(&mut self, op: &OpTpl, secnum: i64, point: u32) -> PcodeResult<()> {
        let index = self.s.fix(&op.ins[0].off, self.p, point)? as usize;
        let ct = self.p.states[point as usize].ct;
        let o = self.s.operand(self.s.ctors[ct].operands[index]);
        match o.triple {
            Some(t) if self.s.is_subtable(t) => self.build_sub(self.p.states[point as usize].resolve[index], secnum),
            _ => Ok(()),
        }
    }

    fn build_empty(&mut self, point: u32, secnum: i64) -> PcodeResult<()> {
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

    fn dump(&mut self, op: &OpTpl, point: u32) -> PcodeResult<()> {
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
