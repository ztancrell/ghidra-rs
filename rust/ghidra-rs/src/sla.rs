//! Reader for Ghidra's compiled `.sla` files (format version 4).
//!
//! Layout (see slaformat.cc / marshal.cc `PackedDecode` upstream): the 4-byte header
//! `"sla" 0x04`, then a zlib stream. The inflated bytes are a "packed" element tree:
//! element-start / attribute / element-end records, each a header byte with a 5-bit id
//! (extended by a second byte when bit 0x20 is set). Attribute values carry a type byte
//! (type code in the high nibble, length in the low nibble) followed by 7-bit big-endian
//! integer bytes. We inflate and parse the whole tree up front; it is a few MB for x86-64.

use std::io::Read;

pub type Result<T> = std::result::Result<T, String>;

#[derive(Debug, Clone)]
pub enum Val {
    Bool(bool),
    Int(i64),
    UInt(u64),
    Space(u64),
    Special(u32),
    Str(String),
}

#[derive(Debug, Clone)]
pub struct Elem {
    pub id: u32,
    pub attrs: Vec<(u32, Val)>,
    pub kids: Vec<Elem>,
}

impl Elem {
    fn get(&self, id: u32) -> Option<&Val> {
        self.attrs.iter().find(|a| a.0 == id).map(|a| &a.1)
    }
    pub fn has(&self, id: u32) -> bool {
        self.get(id).is_some()
    }
    /// Any integer-like attribute as i64 (signed, unsigned and space indices).
    pub fn int(&self, id: u32) -> Result<i64> {
        match self.get(id) {
            Some(Val::Int(v)) => Ok(*v),
            Some(Val::UInt(v)) | Some(Val::Space(v)) => Ok(*v as i64),
            Some(Val::Bool(b)) => Ok(*b as i64),
            _ => Err(format!("element {}: missing integer attribute {}", self.id, id)),
        }
    }
    pub fn uint(&self, id: u32) -> Result<u64> {
        self.int(id).map(|v| v as u64)
    }
    pub fn boolean(&self, id: u32) -> Result<bool> {
        match self.get(id) {
            Some(Val::Bool(b)) => Ok(*b),
            _ => Err(format!("element {}: missing bool attribute {}", self.id, id)),
        }
    }
    pub fn string(&self, id: u32) -> Result<&str> {
        match self.get(id) {
            Some(Val::Str(s)) => Ok(s),
            _ => Err(format!("element {}: missing string attribute {}", self.id, id)),
        }
    }
}

pub fn read_file(path: &std::path::Path) -> Result<Elem> {
    let raw = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if raw.len() < 4 || &raw[..3] != b"sla" {
        return Err(format!("{}: not a .sla file", path.display()));
    }
    if raw[3] != 4 {
        return Err(format!("{}: .sla format version {} (expected 4)", path.display(), raw[3]));
    }
    let mut data = Vec::new();
    flate2::read::ZlibDecoder::new(&raw[4..])
        .read_to_end(&mut data)
        .map_err(|e| format!("{}: inflate: {e}", path.display()))?;
    let mut r = Packed { d: &data, pos: 0 };
    r.elem()
}

struct Packed<'a> {
    d: &'a [u8],
    pos: usize,
}

impl Packed<'_> {
    fn byte(&mut self) -> Result<u8> {
        let b = *self.d.get(self.pos).ok_or("truncated .sla stream")?;
        self.pos += 1;
        Ok(b)
    }
    fn peek(&self) -> u8 {
        self.d.get(self.pos).copied().unwrap_or(0)
    }
    fn id(&mut self) -> Result<u32> {
        let h = self.byte()?;
        let mut id = (h & 0x1f) as u32;
        if h & 0x20 != 0 {
            id = (id << 7) | (self.byte()? & 0x7f) as u32;
        }
        Ok(id)
    }
    fn integer(&mut self, len: u8) -> Result<u64> {
        let mut v = 0u64;
        for _ in 0..len {
            v = (v << 7) | (self.byte()? & 0x7f) as u64;
        }
        Ok(v)
    }
    fn elem(&mut self) -> Result<Elem> {
        if self.peek() & 0xc0 != 0x40 {
            return Err("expected element start".into());
        }
        let id = self.id()?;
        let mut attrs = Vec::new();
        while self.peek() & 0xc0 == 0xc0 {
            let aid = self.id()?;
            let t = self.byte()?;
            let len = t & 0xf;
            let v = match t >> 4 {
                1 => Val::Bool(len != 0),
                2 => Val::Int(self.integer(len)? as i64),
                3 => Val::Int(-(self.integer(len)? as i64)),
                4 => Val::UInt(self.integer(len)?),
                5 => Val::Space(self.integer(len)?),
                6 => Val::Special(len as u32),
                7 => {
                    let n = self.integer(len)? as usize;
                    let s = self.d.get(self.pos..self.pos + n).ok_or("truncated string")?;
                    self.pos += n;
                    Val::Str(String::from_utf8_lossy(s).into_owned())
                }
                c => return Err(format!("bad attribute type code {c}")),
            };
            attrs.push((aid, v));
        }
        let mut kids = Vec::new();
        while self.peek() & 0xc0 == 0x40 {
            kids.push(self.elem()?);
        }
        if self.peek() & 0xc0 != 0x80 || self.id()? != id {
            return Err(format!("element {id}: bad close"));
        }
        Ok(Elem { id, attrs, kids })
    }
}

// Attribute ids (slaformat.cc).
pub mod a {
    pub const VAL: u32 = 2;
    pub const ID: u32 = 3;
    pub const SPACE: u32 = 4;
    pub const S: u32 = 5;
    pub const OFF: u32 = 6;
    pub const CODE: u32 = 7;
    pub const MASK: u32 = 8;
    pub const INDEX: u32 = 9;
    pub const NONZERO: u32 = 10;
    pub const PIECE: u32 = 11;
    pub const NAME: u32 = 12;
    pub const STARTBIT: u32 = 14;
    pub const SIZE: u32 = 15;
    pub const TABLE: u32 = 16;
    pub const CT: u32 = 17;
    pub const MINLEN: u32 = 18;
    pub const BASE: u32 = 19;
    pub const NUMBER: u32 = 20;
    pub const CONTEXT: u32 = 21;
    pub const SUBSYM: u32 = 23;
    pub const LENGTH: u32 = 26;
    pub const FIRST: u32 = 27;
    pub const PLUS: u32 = 28;
    pub const SHIFT: u32 = 29;
    pub const ENDBIT: u32 = 30;
    pub const SIGNBIT: u32 = 31;
    pub const ENDBYTE: u32 = 32;
    pub const STARTBYTE: u32 = 33;
    pub const VERSION: u32 = 34;
    pub const BIGENDIAN: u32 = 35;
    pub const UNIQBASE: u32 = 37;
    pub const UNIQMASK: u32 = 39;
    pub const DEFAULTSPACE: u32 = 41;
    pub const DELAY: u32 = 42;
    pub const LOW: u32 = 48;
    pub const HIGH: u32 = 49;
    pub const FLOW: u32 = 50;
    pub const I: u32 = 52;
    pub const SCOPE: u32 = 13;
    pub const SYMBOLSIZE: u32 = 46;
    pub const SECTION: u32 = 54;
    pub const LABELS: u32 = 55;
}

// Element ids (slaformat.cc).
pub mod e {
    pub const CONST_REAL: u32 = 1;
    pub const VARNODE_TPL: u32 = 2;
    pub const CONST_SPACEID: u32 = 3;
    pub const CONST_HANDLE: u32 = 4;
    pub const OP_TPL: u32 = 5;
    pub const PAT_BLOCK: u32 = 7;
    pub const PRINT: u32 = 8;
    pub const PAIR: u32 = 9;
    pub const CONTEXT_PAT: u32 = 10;
    pub const NULL: u32 = 11;
    pub const OPERAND_EXP: u32 = 12;
    pub const OPERAND_SYM: u32 = 13;
    pub const OPERAND_SYM_HEAD: u32 = 14;
    pub const OPER: u32 = 15;
    pub const DECISION: u32 = 16;
    pub const OPPRINT: u32 = 17;
    pub const INSTRUCT_PAT: u32 = 18;
    pub const COMBINE_PAT: u32 = 19;
    pub const CONSTRUCTOR: u32 = 20;
    pub const CONSTRUCT_TPL: u32 = 21;
    pub const VARNODE_SYM: u32 = 23;
    pub const VARNODE_SYM_HEAD: u32 = 24;
    pub const USEROP: u32 = 25;
    pub const USEROP_HEAD: u32 = 26;
    pub const TOKENFIELD: u32 = 27;
    pub const VAR: u32 = 28;
    pub const CONTEXTFIELD: u32 = 29;
    pub const HANDLE_TPL: u32 = 30;
    pub const CONST_RELATIVE: u32 = 31;
    pub const CONTEXT_OP: u32 = 32;
    pub const SLEIGH: u32 = 33;
    pub const SPACES: u32 = 34;
    pub const SPACE: u32 = 37;
    pub const SYMBOL_TABLE: u32 = 38;
    pub const VALUE_SYM: u32 = 39;
    pub const VALUE_SYM_HEAD: u32 = 40;
    pub const CONTEXT_SYM: u32 = 41;
    pub const CONTEXT_SYM_HEAD: u32 = 42;
    pub const END_SYM: u32 = 43;
    pub const END_SYM_HEAD: u32 = 44;
    pub const SPACE_OTHER: u32 = 45;
    pub const SPACE_UNIQUE: u32 = 46;
    pub const AND_EXP: u32 = 47;
    pub const DIV_EXP: u32 = 48;
    pub const LSHIFT_EXP: u32 = 49;
    pub const MINUS_EXP: u32 = 50;
    pub const MULT_EXP: u32 = 51;
    pub const NOT_EXP: u32 = 52;
    pub const OR_EXP: u32 = 53;
    pub const PLUS_EXP: u32 = 54;
    pub const RSHIFT_EXP: u32 = 55;
    pub const SUB_EXP: u32 = 56;
    pub const XOR_EXP: u32 = 57;
    pub const INTB: u32 = 58;
    pub const END_EXP: u32 = 59;
    pub const NEXT2_EXP: u32 = 60;
    pub const START_EXP: u32 = 61;
    pub const EPSILON_SYM: u32 = 62;
    pub const EPSILON_SYM_HEAD: u32 = 63;
    pub const NAME_SYM: u32 = 64;
    pub const NAME_SYM_HEAD: u32 = 65;
    pub const NEXT2_SYM: u32 = 67;
    pub const NEXT2_SYM_HEAD: u32 = 68;
    pub const START_SYM: u32 = 69;
    pub const START_SYM_HEAD: u32 = 70;
    pub const SUBTABLE_SYM: u32 = 71;
    pub const SUBTABLE_SYM_HEAD: u32 = 72;
    pub const VALUEMAP_SYM: u32 = 73;
    pub const VALUEMAP_SYM_HEAD: u32 = 74;
    pub const VARLIST_SYM: u32 = 76;
    pub const VARLIST_SYM_HEAD: u32 = 77;
    pub const COMMIT: u32 = 79;
    pub const CONST_START: u32 = 80;
    pub const CONST_NEXT: u32 = 81;
    pub const CONST_NEXT2: u32 = 82;
    pub const CONST_CURSPACE: u32 = 83;
    pub const CONST_CURSPACE_SIZE: u32 = 84;
    pub const CONST_FLOWREF: u32 = 85;
    pub const CONST_FLOWREF_SIZE: u32 = 86;
    pub const CONST_FLOWDEST: u32 = 87;
    pub const CONST_FLOWDEST_SIZE: u32 = 88;
}
