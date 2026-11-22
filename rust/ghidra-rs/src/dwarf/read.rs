//! The raw DWARF reader: unit headers (`DWARFUnitHeader`, `DWARFCompilationUnit`), abbreviations
//! (`DWARFAbbreviation`), the DIE index (`DIEContainer.indexDIEs`: offsets, parents, siblings, the
//! heads of `DW_AT_abstract_origin` / `DW_AT_specification` chains), attribute values by form
//! (`DWARFForm.readValue`: numeric, boolean, string, blob), the file table of a line program
//! header (`DWARFLine.readV4`), `.debug_ranges` (`DWARFRangeList.readV4`) and the small part of
//! `DWARFExpressionEvaluator` that member offsets and sizes use. DIE attributes are decoded on
//! demand from the section bytes, as Java re-reads DIEs it does not hold.
use super::Error;
use std::collections::HashMap;

type Result<T> = std::result::Result<T, Error>;

pub const DW_TAG_ARRAY: u16 = 0x01;
pub const DW_TAG_CLASS: u16 = 0x02;
pub const DW_TAG_ENUMERATION: u16 = 0x04;
pub const DW_TAG_FORMAL_PARAMETER: u16 = 0x05;
pub const DW_TAG_LABEL: u16 = 0x0a;
pub const DW_TAG_LEXICAL_BLOCK: u16 = 0x0b;
pub const DW_TAG_MEMBER: u16 = 0x0d;
pub const DW_TAG_POINTER: u16 = 0x0f;
pub const DW_TAG_REFERENCE: u16 = 0x10;
pub const DW_TAG_COMPILE_UNIT: u16 = 0x11;
pub const DW_TAG_STRUCTURE: u16 = 0x13;
pub const DW_TAG_SUBROUTINE_TYPE: u16 = 0x15;
pub const DW_TAG_TYPEDEF: u16 = 0x16;
pub const DW_TAG_UNION: u16 = 0x17;
pub const DW_TAG_UNSPECIFIED_PARAMETERS: u16 = 0x18;
pub const DW_TAG_INHERITANCE: u16 = 0x1c;
pub const DW_TAG_INLINED_SUBROUTINE: u16 = 0x1d;
pub const DW_TAG_PTR_TO_MEMBER: u16 = 0x1f;
pub const DW_TAG_SUBRANGE: u16 = 0x21;
pub const DW_TAG_BASE_TYPE: u16 = 0x24;
pub const DW_TAG_CONST: u16 = 0x26;
pub const DW_TAG_ENUMERATOR: u16 = 0x28;
pub const DW_TAG_INTERFACE: u16 = 0x38;
pub const DW_TAG_NAMESPACE: u16 = 0x39;
pub const DW_TAG_SUBPROGRAM: u16 = 0x2e;
pub const DW_TAG_VARIABLE: u16 = 0x34;
pub const DW_TAG_VOLATILE: u16 = 0x35;
pub const DW_TAG_RESTRICT: u16 = 0x37;
pub const DW_TAG_UNSPECIFIED_TYPE: u16 = 0x3b;
pub const DW_TAG_SHARED: u16 = 0x40;
pub const DW_TAG_RVALUE_REFERENCE: u16 = 0x42;
pub const DW_TAG_ATOMIC: u16 = 0x47;
pub const DW_TAG_CALL_SITE: u16 = 0x48;
pub const DW_TAG_GNU_CALL_SITE: u16 = 0x4109;
pub const DW_TAG_APPLE_PTRAUTH: u16 = 0x4300;

pub const DW_AT_NAME: u16 = 0x03;
pub const DW_AT_BYTE_SIZE: u16 = 0x0b;
pub const DW_AT_STMT_LIST: u16 = 0x10;
pub const DW_AT_LOW_PC: u16 = 0x11;
pub const DW_AT_HIGH_PC: u16 = 0x12;
pub const DW_AT_LANGUAGE: u16 = 0x13;
pub const DW_AT_BIT_OFFSET: u16 = 0x0c;
pub const DW_AT_BIT_SIZE: u16 = 0x0d;
pub const DW_AT_CONST_VALUE: u16 = 0x1c;
pub const DW_AT_UPPER_BOUND: u16 = 0x2f;
pub const DW_AT_ABSTRACT_ORIGIN: u16 = 0x31;
pub const DW_AT_COUNT: u16 = 0x37;
pub const DW_AT_DATA_MEMBER_LOCATION: u16 = 0x38;
pub const DW_AT_DECL_FILE: u16 = 0x3a;
pub const DW_AT_DECL_LINE: u16 = 0x3b;
pub const DW_AT_DECLARATION: u16 = 0x3c;
pub const DW_AT_ENCODING: u16 = 0x3e;
pub const DW_AT_EXTERNAL: u16 = 0x3f;
pub const DW_AT_SPECIFICATION: u16 = 0x47;
pub const DW_AT_TYPE: u16 = 0x49;
pub const DW_AT_RANGES: u16 = 0x55;
pub const DW_AT_CONTAINING_TYPE: u16 = 0x1d;
pub const DW_AT_ARTIFICIAL: u16 = 0x34;
pub const DW_AT_OBJECT_POINTER: u16 = 0x64;
pub const DW_AT_DATA_BIT_OFFSET: u16 = 0x6b;
pub const DW_AT_LINKAGE_NAME: u16 = 0x6e;
pub const DW_AT_NORETURN: u16 = 0x87;
pub const DW_AT_MIPS_LINKAGE_NAME: u16 = 0x2007;

/// An attribute value, by `DWARFAttributeValue` class.
#[derive(Debug, Clone, Copy)]
pub enum Val<'a> {
    /// `DWARFNumericAttribute`: a `Scalar` of `bits` bits, its signedness, and whether that
    /// signedness is a guess (`DW_FORM_data<n>`)
    Num {
        raw: u64,
        bits: u8,
        signed: bool,
        ambiguous: bool,
    },
    Bool(bool),
    Str(&'a [u8]),
    Blob(&'a [u8]),
}

impl Val<'_> {
    fn mask(raw: u64, bits: u8) -> u64 {
        if bits >= 64 {
            raw
        } else {
            raw & ((1u64 << bits) - 1)
        }
    }
    /// `Scalar.getValue(signed)`
    fn scalar(raw: u64, bits: u8, signed: bool) -> i64 {
        let u = Self::mask(raw, bits);
        if signed && bits < 64 && bits > 0 && (u >> (bits - 1)) & 1 == 1 {
            (u | !((1u64 << bits) - 1)) as i64
        } else {
            u as i64
        }
    }
    /// `DWARFNumericAttribute.getValue()`
    pub fn value(&self) -> Option<i64> {
        match *self {
            Val::Num { raw, bits, signed, .. } => Some(Self::scalar(raw, bits, signed)),
            _ => None,
        }
    }
    /// `getUnsignedValue()`
    pub fn unsigned(&self) -> Option<u64> {
        match *self {
            Val::Num { raw, bits, .. } => Some(Self::mask(raw, bits)),
            _ => None,
        }
    }
    /// `getValueWithSignednessHint`
    pub fn with_hint(&self, hint: bool) -> Option<i64> {
        match *self {
            Val::Num { raw, bits, signed, ambiguous } => {
                Some(Self::scalar(raw, bits, if ambiguous { hint } else { signed }))
            }
            _ => None,
        }
    }
}

/// One attribute of one DIE: its form, value and the DIE it was read from.
#[derive(Debug, Clone, Copy)]
pub struct Attr<'a> {
    pub form: u16,
    pub val: Val<'a>,
    pub die: u32,
}

#[derive(Debug)]
pub struct Abbrev {
    pub tag: u16,
    pub children: bool,
    /// (attribute, form, implicit const)
    pub attrs: Vec<(u16, u16, i64)>,
}

/// A compilation unit (`DWARFCompilationUnit`): its header and the attributes of its first DIE.
#[derive(Debug)]
pub struct Cu {
    pub start: u64,
    pub end: u64,
    pub first_die: u64,
    pub version: u16,
    pub addr_size: u8,
    pub int_size: u8,
    abbrevs: usize,
    pub language: i64,
    pub low_pc: u64,
    /// the file names of the line program header (`DWARFLine.getFile`), `None` without one
    pub files: Option<Vec<String>>,
    pub files_v5: bool,
}

/// The `.debug_*` sections and the DIE index of `DIEContainer`.
pub struct Dwarf<'a> {
    info: &'a [u8],
    strs: &'a [u8],
    line: &'a [u8],
    ranges: &'a [u8],
    abbrev_tables: Vec<HashMap<u64, Abbrev>>,
    pub cus: Vec<Cu>,
    /// per DIE, by index: offset, parent index (-1 at a unit's root), next sibling index, tag
    pub offsets: Vec<u64>,
    pub parents: Vec<i32>,
    pub siblings: Vec<u32>,
    pub tags: Vec<u16>,
    /// index of the last DIE of each unit, ascending (`compUnitDieIndex`)
    cu_last: Vec<u32>,
    /// DIEs that are the target of an `abstract_origin` / `specification` (`indexHasRef`)
    pub has_ref: Vec<bool>,
}

pub struct Cursor<'a> {
    pub d: &'a [u8],
    pub p: usize,
}

impl<'a> Cursor<'a> {
    pub fn new(d: &'a [u8], p: usize) -> Self {
        Cursor { d, p }
    }
    fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .p
            .checked_add(n)
            .filter(|&e| e <= self.d.len())
            .ok_or(Error::Dwarf("read past the end of a section".into()))?;
        let s = &self.d[self.p..end];
        self.p = end;
        Ok(s)
    }
    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.bytes(1)?[0])
    }
    pub fn uint(&mut self, n: usize) -> Result<u64> {
        let b = self.bytes(n)?;
        Ok(b.iter().rev().fold(0u64, |a, &x| (a << 8) | x as u64))
    }
    pub fn uleb(&mut self) -> Result<u64> {
        let (mut v, mut s) = (0u64, 0u32);
        loop {
            let b = self.u8()?;
            if s < 64 {
                v |= ((b & 0x7f) as u64) << s;
            }
            s += 7;
            if b & 0x80 == 0 {
                return Ok(v);
            }
        }
    }
    pub fn sleb(&mut self) -> Result<i64> {
        let (mut v, mut s) = (0i64, 0u32);
        loop {
            let b = self.u8()?;
            if s < 64 {
                v |= ((b & 0x7f) as i64) << s;
            }
            s += 7;
            if b & 0x80 == 0 {
                if s < 64 && b & 0x40 != 0 {
                    v |= -1i64 << s;
                }
                return Ok(v);
            }
        }
    }
    pub fn cstr(&mut self) -> Result<&'a [u8]> {
        let n = self.d[self.p.min(self.d.len())..]
            .iter()
            .position(|&b| b == 0)
            .ok_or(Error::Dwarf("unterminated string".into()))?;
        let s = self.bytes(n)?;
        self.p += 1;
        Ok(s)
    }
}

fn cstr_at(d: &[u8], off: u64) -> Result<&[u8]> {
    let mut c = Cursor::new(d, usize::try_from(off).unwrap_or(usize::MAX));
    if c.p >= d.len() {
        return Err(Error::Dwarf(format!("string offset 0x{off:x} past the end")));
    }
    c.cstr()
}

impl<'a> Dwarf<'a> {
    /// `DIEContainer.init` + `indexData`: units, then every DIE of every unit.
    pub fn new(info: &'a [u8], abbrev: &'a [u8], strs: &'a [u8], line: &'a [u8], ranges: &'a [u8]) -> Result<Self> {
        let mut dw = Dwarf {
            info,
            strs,
            line,
            ranges,
            abbrev_tables: Vec::new(),
            cus: Vec::new(),
            offsets: Vec::new(),
            parents: Vec::new(),
            siblings: Vec::new(),
            tags: Vec::new(),
            cu_last: Vec::new(),
            has_ref: Vec::new(),
        };
        let mut abbrev_at: HashMap<u64, usize> = HashMap::new();
        let mut c = Cursor::new(info, 0);
        while c.p < info.len() {
            let start = c.p as u64;
            let mut len = c.uint(4)?;
            let mut int_size = 4u8;
            if len == 0xffff_ffff {
                len = c.uint(8)?;
                int_size = 8;
            }
            if len == 0 {
                break;
            }
            let end = c.p as u64 + len;
            let version = c.uint(2)? as u16;
            let (unit_type, addr_size, abbrev_off) = if version >= 5 {
                let ut = c.u8()?;
                let asz = c.u8()?;
                (ut, asz, c.uint(int_size as usize)?)
            } else if (2..5).contains(&version) {
                let ao = c.uint(int_size as usize)?;
                (1, c.u8()?, ao)
            } else {
                return Err(Error::Dwarf(format!("unsupported DWARF version {version} at 0x{start:x}")));
            };
            if version >= 5 && (unit_type == 5 || unit_type == 4) {
                c.uint(8)?; // dwo id
            }
            let first_die = c.p as u64;
            c.p = end as usize;
            if !(unit_type == 1 || unit_type == 3 || unit_type == 4 || unit_type == 5) {
                continue; // type units: DWARFUnitHeader that is not a compilation unit
            }
            let ab = match abbrev_at.get(&abbrev_off) {
                Some(&i) => i,
                None => {
                    let t = read_abbrevs(abbrev, abbrev_off)?;
                    dw.abbrev_tables.push(t);
                    abbrev_at.insert(abbrev_off, dw.abbrev_tables.len() - 1);
                    dw.abbrev_tables.len() - 1
                }
            };
            dw.cus.push(Cu {
                start,
                end,
                first_die,
                version,
                addr_size,
                int_size,
                abbrevs: ab,
                language: -1,
                low_pc: 0,
                files: None,
                files_v5: false,
            });
        }
        let mut targets = Vec::new();
        for cu in 0..dw.cus.len() {
            dw.index_cu(cu, &mut targets)?;
            dw.cu_last.push(dw.offsets.len() as u32 - 1);
        }
        dw.has_ref = vec![false; dw.offsets.len()];
        for t in targets {
            let i = dw.index_of(t).ok_or(Error::Dwarf(format!("reference to 0x{t:x}, not a DIE")))?;
            dw.has_ref[i as usize] = true;
        }
        for cu in 0..dw.cus.len() {
            dw.init_cu(cu);
        }
        Ok(dw)
    }

    fn index_cu(&mut self, cu: usize, targets: &mut Vec<u64>) -> Result<()> {
        let (end, first) = (self.cus[cu].end, self.cus[cu].first_die);
        let mut c = Cursor::new(self.info, first as usize);
        let mut parent: i32 = -1;
        let mut count = 0;
        while (c.p as u64) < end {
            let start = c.p as u64;
            let code = c.uleb()?;
            if code == 0 {
                if parent != -1 {
                    parent = self.parents[parent as usize];
                }
                continue;
            }
            if parent == -1 && count != 0 {
                return Err(Error::Dwarf(format!("Unexpected root level DIE at 0x{start:x}")));
            }
            let ab = self.abbrev_tables[self.cus[cu].abbrevs]
                .get(&code)
                .ok_or(Error::Dwarf(format!("unknown abbreviation {code} at 0x{start:x}")))?;
            let index = self.offsets.len() as u32;
            self.offsets.push(start);
            self.parents.push(parent);
            self.siblings.push(index + 1);
            self.tags.push(ab.tag);
            count += 1;
            let mut p = index as i32;
            while p != -1 {
                self.siblings[p as usize] = index + 1;
                p = self.parents[p as usize];
            }
            let children = ab.children;
            let cuh = &self.cus[cu];
            let attrs: Vec<(u16, u16, i64)> = ab.attrs.clone();
            for (at, form, ic) in attrs {
                let (form, val) = read_form(&mut c, form, ic, cuh, self.strs)?;
                if at == DW_AT_ABSTRACT_ORIGIN || at == DW_AT_SPECIFICATION {
                    if let Val::Num { .. } = val {
                        targets.push(local_ref(form, val.unsigned().unwrap_or(0), cuh.start)?);
                    }
                }
            }
            if children {
                parent = index as i32;
            }
        }
        Ok(())
    }

    /// `DWARFCompilationUnit.init` from the unit's first DIE, and its line header's files.
    fn init_cu(&mut self, cu: usize) {
        let Some(root) = self.index_of(self.cus[cu].first_die) else { return };
        let lang = self.attr(root, 0x13).and_then(|a| a.val.value()).unwrap_or(-1);
        let low = self.attr(root, DW_AT_LOW_PC).and_then(|a| a.val.unsigned()).unwrap_or(0);
        let stmt = self.attr(root, DW_AT_STMT_LIST).and_then(|a| a.val.unsigned());
        self.cus[cu].language = lang;
        self.cus[cu].low_pc = low;
        if let Some(off) = stmt {
            if let Ok((files, v5)) = read_line_files(self.line, off, self.cus[cu].int_size) {
                self.cus[cu].files = Some(files);
                self.cus[cu].files_v5 = v5;
            }
        }
    }

    /// `getDIEIndex`: the index of the DIE at a `.debug_info` offset.
    pub fn index_of(&self, off: u64) -> Option<u32> {
        self.offsets.binary_search(&off).ok().map(|i| i as u32)
    }

    /// The unit a DIE index belongs to (`getCompilationUnitForDIE`).
    pub fn cu_of(&self, die: u32) -> usize {
        self.cu_last.partition_point(|&last| last < die)
    }

    /// The attribute `at` of one DIE, if it has it (`DebugInfoEntry.findAttribute`).
    pub fn attr(&self, die: u32, at: u16) -> Option<Attr<'a>> {
        let cu = &self.cus[self.cu_of(die)];
        let mut c = Cursor::new(self.info, self.offsets[die as usize] as usize);
        let code = c.uleb().ok()?;
        let ab = self.abbrev_tables[cu.abbrevs].get(&code)?;
        for &(a, form, ic) in &ab.attrs {
            let (form, val) = read_form(&mut c, form, ic, cu, self.strs).ok()?;
            if a == at {
                return Some(Attr { form, val, die });
            }
        }
        None
    }

    /// The DIE an attribute value refers to (`DIEContainer.getDIE`).
    pub fn ref_target(&self, a: &Attr) -> Option<u32> {
        let cu = &self.cus[self.cu_of(a.die)];
        let off = local_ref(a.form, a.val.unsigned()?, cu.start).ok()?;
        self.index_of(off)
    }

    /// A string attribute's text (`DWARFStringAttribute.getValue`), UTF-8 with replacement.
    pub fn string(&self, a: &Attr) -> Option<String> {
        match a.val {
            Val::Str(s) => Some(String::from_utf8_lossy(s).into_owned()),
            _ => None,
        }
    }

    /// The children of a DIE, in order (`getChildrenOf`).
    pub fn children(&self, die: u32) -> impl Iterator<Item = u32> + '_ {
        let end = self.siblings[die as usize];
        let mut i = die + 1;
        std::iter::from_fn(move || {
            if i < end {
                let r = i;
                i = self.siblings[i as usize];
                Some(r)
            } else {
                None
            }
        })
    }

    pub fn parent(&self, die: u32) -> Option<u32> {
        let p = self.parents[die as usize];
        (p >= 0).then_some(p as u32)
    }

    /// `DWARFRangeList.readV4`: the ranges at a `.debug_ranges` offset, from the unit's base.
    pub fn ranges_v4(&self, off: u64, cu: usize) -> Result<Vec<(u64, u64)>> {
        let cuh = &self.cus[cu];
        let asz = cuh.addr_size as usize;
        let mut c = Cursor::new(self.ranges, usize::try_from(off).unwrap_or(usize::MAX));
        let mut base = cuh.low_pc;
        let max = if asz == 8 { u64::MAX } else { (1u64 << (asz * 8)) - 1 };
        let mut out = Vec::new();
        loop {
            let (a, b) = (c.uint(asz)?, c.uint(asz)?);
            if a == 0 && b == 0 {
                return Ok(out);
            }
            if a == max {
                base = b;
                continue;
            }
            out.push((base.wrapping_add(a), base.wrapping_add(b)));
        }
    }
}

fn read_abbrevs(d: &[u8], off: u64) -> Result<HashMap<u64, Abbrev>> {
    let mut c = Cursor::new(d, off as usize);
    let mut out = HashMap::new();
    loop {
        let code = c.uleb()?;
        if code == 0 {
            return Ok(out);
        }
        let tag = c.uleb()? as u16;
        let children = c.u8()? != 0;
        let mut attrs = Vec::new();
        loop {
            let at = c.uleb()? as u16;
            let form = c.uleb()? as u16;
            if at == 0 && form == 0 {
                break;
            }
            let ic = if form == 0x21 { c.sleb()? } else { 0 };
            attrs.push((at, form, ic));
        }
        out.insert(code, Abbrev { tag, children, attrs });
    }
}

/// `DIEContainer.getLocalDIEOffset`
fn local_ref(form: u16, raw: u64, cu_start: u64) -> Result<u64> {
    match form {
        0x11..=0x15 => Ok(raw + cu_start),
        0x1f20 => Err(Error::Dwarf("Unsupported DIE reference form: DW_FORM_gnu_ref_alt".into())),
        _ => Ok(raw),
    }
}

/// `DWARFForm.readValue`: one attribute value at the cursor.
fn read_form<'a>(c: &mut Cursor<'a>, form: u16, ic: i64, cu: &Cu, strs: &'a [u8]) -> Result<(u16, Val<'a>)> {
    let num = |raw: u64, bits: u8, signed: bool| Val::Num { raw, bits, signed, ambiguous: false };
    let is = cu.int_size as usize;
    let v = match form {
        0x01 => num(c.uint(cu.addr_size as usize)?, cu.addr_size * 8, false),
        0x03 => {
            let n = c.uint(2)? as usize;
            Val::Blob(c.bytes(n)?)
        }
        0x04 => {
            let n = c.uint(4)? as usize;
            Val::Blob(c.bytes(n)?)
        }
        0x09 | 0x18 => {
            let n = c.uleb()? as usize;
            Val::Blob(c.bytes(n)?)
        }
        0x0a => {
            let n = c.u8()? as usize;
            Val::Blob(c.bytes(n)?)
        }
        0x0b | 0x05 | 0x06 | 0x07 => {
            let n = match form {
                0x0b => 1,
                0x05 => 2,
                0x06 => 4,
                _ => 8,
            };
            Val::Num { raw: c.uint(n)?, bits: (n * 8) as u8, signed: true, ambiguous: true }
        }
        0x08 => Val::Str(c.cstr()?),
        0x0c => Val::Bool(c.u8()? != 0),
        0x0d => num(c.sleb()? as u64, 64, true),
        0x0e | 0x1f | 0x1d => {
            let off = c.uint(is)?;
            // strp_sup and line_strp read their table elsewhere; only .debug_str is ported
            Val::Str(if form == 0x0e { cstr_at(strs, off)? } else { &[] })
        }
        0x0f => num(c.uleb()?, 64, false),
        0x10 | 0x17 => num(c.uint(is)?, (is * 8) as u8, false),
        0x11 => num(c.uint(1)?, 8, false),
        0x12 => num(c.uint(2)?, 16, false),
        0x13 | 0x1c => num(c.uint(4)?, 32, false),
        0x14 | 0x20 | 0x24 => num(c.uint(8)?, 64, false),
        0x15 | 0x1a | 0x1b | 0x22 | 0x23 => num(c.uleb()?, 64, false),
        0x16 => {
            let f = c.uleb()? as u16;
            return read_form(c, f, ic, cu, strs);
        }
        0x19 => Val::Bool(true),
        0x1e => Val::Blob(c.bytes(16)?),
        0x21 => num(ic as u64, 64, true),
        0x25 | 0x29 => num(c.uint(1)?, 8, false),
        0x26 | 0x2a => num(c.uint(2)?, 16, false),
        0x27 | 0x2b => num(c.uint(3)?, 24, false),
        0x28 | 0x2c => num(c.uint(4)?, 32, false),
        _ => return Err(Error::Dwarf(format!("unsupported form 0x{form:x}"))),
    };
    Ok((form, v))
}

/// `DWARFLine.read` up to the file table: the file names (v2-v4: `readV4`). Version 5 headers
/// (entry formats) are not ported: no files, so no source info.
fn read_line_files(d: &[u8], off: u64, _int: u8) -> Result<(Vec<String>, bool)> {
    let mut c = Cursor::new(d, usize::try_from(off).unwrap_or(usize::MAX));
    let mut len = c.uint(4)?;
    let mut is = 4;
    if len == 0xffff_ffff {
        len = c.uint(8)?;
        is = 8;
    }
    let _ = len;
    let version = c.uint(2)?;
    if version >= 5 {
        return Err(Error::Dwarf("DWARF 5 line header not ported".into()));
    }
    c.uint(is)?; // header_length
    c.u8()?; // minimum_instruction_length
    if version >= 4 {
        c.u8()?;
    }
    c.u8()?; // default_is_stmt
    c.u8()?; // line_base
    c.u8()?; // line_range
    let opcode_base = c.u8()?;
    for _ in 1..opcode_base {
        c.u8()?;
    }
    while !c.cstr()?.is_empty() {}
    let mut files = Vec::new();
    loop {
        let name = c.cstr()?;
        if name.is_empty() {
            return Ok((files, false));
        }
        c.uleb()?;
        c.uleb()?;
        c.uleb()?;
        files.push(String::from_utf8_lossy(name).into_owned());
    }
}

/// `DWARFExpressionEvaluator.evaluate(bytes, 0)` then `popLong`, for the constant operations a
/// member offset, a size or a bound uses; any other operation is an error, as Java's
/// unsupported-operation exceptions make the attribute unreadable.
pub fn eval_const(expr: &[u8], addr_size: u8) -> Result<i64> {
    let mut st: Vec<i64> = vec![0];
    let mut c = Cursor::new(expr, 0);
    while c.p < expr.len() {
        let op = c.u8()?;
        let v = match op {
            0x03 => c.uint(addr_size as usize)? as i64,
            0x08 => c.uint(1)? as i64,
            0x09 => c.uint(1)? as i8 as i64,
            0x0a => c.uint(2)? as i64,
            0x0b => c.uint(2)? as i16 as i64,
            0x0c => c.uint(4)? as i64,
            0x0d => c.uint(4)? as i32 as i64,
            0x0e | 0x0f => c.uint(8)? as i64,
            0x10 => c.uleb()? as i64,
            0x11 => c.sleb()?,
            0x30..=0x4f => (op - 0x30) as i64,
            0x23 => {
                let n = c.uleb()? as i64;
                let t = st.pop().ok_or(Error::Dwarf("empty expression stack".into()))?;
                t.wrapping_add(n)
            }
            _ => return Err(Error::Dwarf(format!("unsupported DWARF expression op 0x{op:x}"))),
        };
        st.push(v);
    }
    st.pop().ok_or(Error::Dwarf("empty expression stack".into()))
}
