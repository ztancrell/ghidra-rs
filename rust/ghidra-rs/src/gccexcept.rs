//! Ghidra's GCC Exception Handlers analyzer (`GccExceptionAnalyzer`, Java 12.3,
//! `Ghidra/Features/Base/src/main/java/ghidra/app/plugin/exceptionhandlers/gcc`), as far as the
//! facts need it: the call-site records of the LSDAs `.eh_frame`'s FDEs point to, and the `try {`,
//! `} // end try` and `catch(...)` comments the analyzer writes for each record with a landing pad.
//!
//! Not ported (no facts record of a function body depends on them here): the data, labels
//! (`cie_`, `fde_`, `lsda_exception_table_`), plate and EOL comments and references in
//! `.eh_frame`, `.eh_frame_hdr` and `.gcc_except_table`; `.debug_frame` (its regions are never
//! used for call sites, GccExceptionAnalyzer.java:144); the disassembly the analyzer starts at
//! each PcBegin, call site and landing pad (FrameDescriptionEntry.java:474-477,
//! GccExceptionAnalyzer.java:226, 232); the image base adjustment of an `absptr` value is taken
//! without Java's check for a relocation at the value (AbstractDwarfEHDecoder.java:234-236).

use crate::analysis::Image;
use std::collections::{BTreeMap, HashMap};

/// A call-site record with a landing pad, in the order the analyzer processes them.
#[derive(Clone, Debug, PartialEq)]
pub struct CallSite {
    /// the call site's first and last address (LSDACallSiteRecord.java:89-94)
    pub first: u64,
    pub last: u64,
    pub landing_pad: u64,
    /// the catch types: the action's type filter and its type-info address (None:
    /// Address.NO_ADDRESS), GccExceptionAnalyzer.getTypeInfos (241-266)
    pub types: Vec<(i32, Option<u64>)>,
}

/// What stops the Java code: a MemoryAccessException or ExceptionHandlerFrameException (`Mem`,
/// `Frame`), or a runtime exception, which ends the analyzer (`Fatal`).
#[derive(Debug)]
enum Fault {
    Mem(String),
    Frame(String),
    Fatal(String),
}

impl Fault {
    fn text(self) -> String {
        match self {
            Fault::Mem(s) | Fault::Frame(s) | Fault::Fatal(s) => s,
        }
    }
}

type R<T> = Result<T, Fault>;

struct Mem<'a> {
    img: &'a Image,
}

impl Mem<'_> {
    fn byte(&self, a: u64) -> R<u8> {
        let a32 = u32::try_from(a).map_err(|_| Fault::Mem(format!("{a:x}: past 32 bits")))?;
        let s = self.img.block_of(a32).ok_or_else(|| Fault::Mem(format!("{a:x}: not in memory")))?;
        Ok(s.data[(a32 - s.addr) as usize])
    }
    fn contains(&self, a: u64) -> bool {
        self.byte(a).is_ok()
    }
    fn le(&self, a: u64, n: u64) -> R<u64> {
        let mut v = 0u64;
        for i in (0..n).rev() {
            v = v << 8 | u64::from(self.byte(a + i)?);
        }
        Ok(v)
    }
    /// Memory.getInt, sign-extended as Java's `long` gets it
    fn int(&self, a: u64) -> R<i64> {
        Ok(i64::from(self.le(a, 4)? as u32 as i32))
    }
    fn short(&self, a: u64) -> R<i64> {
        Ok(i64::from(self.le(a, 2)? as u16 as i16))
    }
    fn long(&self, a: u64) -> R<i64> {
        Ok(self.le(a, 8)? as i64)
    }
    /// Memory.getBytes: the bytes up to the first one not in memory (none: an exception)
    fn bytes(&self, a: u64, n: u64) -> R<Vec<u8>> {
        let mut v = vec![self.byte(a)?];
        for i in 1..n {
            match self.byte(a + i) {
                Ok(b) => v.push(b),
                Err(_) => break,
            }
        }
        Ok(v)
    }
    /// GccAnalysisUtils.readLEB128Info (LEB128Info.readValue: at most 10 bytes): (value, length)
    fn leb(&self, a: u64, signed: bool) -> R<(i64, u64)> {
        let (mut v, mut shift, mut n) = (0u64, 0u32, 0u64);
        loop {
            let b = self.byte(a + n)?;
            n += 1;
            if n > 10 {
                return Err(Fault::Mem(format!("LEB128 value at {a:x}: more than 10 bytes")));
            }
            if shift < 64 {
                v |= u64::from(b & 0x7f) << shift;
            }
            shift += 7;
            if b & 0x80 == 0 {
                if signed && shift < 64 && b & 0x40 != 0 {
                    v |= !0u64 << shift;
                }
                return Ok((v as i64, n));
            }
        }
    }
}

/// DwarfDecoderFactory.getDecoder (44-69): an encoding byte as an `int` (a Java `byte` read is
/// sign-extended; the masks make it the same).
#[derive(Clone, Copy)]
struct Decoder {
    format: i32,
    app: i32,
    indirect: bool,
    omit: bool,
}

/// A DwarfDecodeContext's bases: the `.eh_frame` block's start (datarel) and the function entry
/// (funcrel).
#[derive(Clone, Copy, Default)]
struct Ctx {
    eh_block: Option<u64>,
    func: Option<u64>,
}

fn decoder(mode: i32) -> Decoder {
    Decoder { format: mode & 0x0f, app: mode & 0x70, indirect: mode & 0x80 == 0x80, omit: mode & 0xff == 0xff }
}

impl Decoder {
    fn is_omit(&self) -> bool {
        // the omit decoder, or DwarfEHDataDecodeFormat DW_EH_PE_omit (0x0f) of createDecoder
        self.omit || self.format == 0x0f
    }
    /// getDecodeSize: absptr 8 on x86-64 (DwarfDecoderFactory.java:136-151), LEB128 and
    /// `signed` -1, omit 0
    fn size(&self) -> R<i64> {
        if self.is_omit() {
            return Ok(0);
        }
        Ok(match self.format {
            0x00 => 8,
            0x01 | 0x08 | 0x09 => -1,
            0x02 | 0x0a => 2,
            0x03 | 0x0b => 4,
            0x04 | 0x0c => 8,
            f => return Err(Fault::Fatal(format!("DWARF EH data format {f:#x} (no decoder)"))),
        })
    }
    /// doDecode then resolveRelativeOffset (AbstractDwarfEHDecoder.java:256-316): (value, length)
    fn decode(&self, m: &Mem, img: &Image, at: u64, ctx: Ctx) -> R<(i64, u64)> {
        if self.is_omit() {
            return Ok((0, 0));
        }
        let (mut val, len) = match self.format {
            0x00 => (m.long(at)?, 8),
            0x01 => {
                let (v, n) = m.leb(at, false)?;
                (v, n)
            }
            0x09 => m.leb(at, true)?,
            0x02 | 0x0a => (m.short(at)?, 2),
            0x03 | 0x0b => (m.int(at)?, 4),
            0x04 | 0x0c => (m.long(at)?, 8),
            0x08 => return Err(Fault::Mem("Don't know now to decode DW_EH_PE_signed-encoded values".into())),
            f => return Err(Fault::Fatal(format!("DWARF EH data format {f:#x} (no decoder)"))),
        };
        if (val == 0 || val as u64 == at) && self.indirect {
            return Ok((val, len));
        }
        match self.app {
            0x10 => val = (at as i64).wrapping_add(val),
            0x20 => {
                let t = img.section(".text").ok_or_else(|| Fault::Fatal("texrel without a .text block".into()))?;
                val = i64::from(t.addr).wrapping_add(val);
            }
            0x30 => {
                let b = ctx.eh_block.ok_or_else(|| Fault::Fatal("datarel without an eh block".into()))?;
                val = (b as i64).wrapping_add(val);
            }
            0x40 => {
                let f = ctx.func.ok_or_else(|| Fault::Fatal("funcrel without a function".into()))?;
                val = (f as i64).wrapping_add(val);
            }
            _ => {}
        }
        if self.indirect {
            // ptrval of an 8-byte address reads 4 bytes (AbstractDwarfEHDecoder.java:75-81)
            val = m.int(val as u64)?;
        }
        Ok((val, len))
    }
    /// decodeAddress (226-240): an absptr value gets the image base adjustment
    fn address(&self, m: &Mem, img: &Image, at: u64, ctx: Ctx) -> R<(u64, u64)> {
        let (mut v, len) = self.decode(m, img, at, ctx)?;
        if self.app == 0 && !self.omit {
            v = v.wrapping_add(i64::from(img.elf_adjust));
        }
        Ok((v as u64, len))
    }
}

/// The parts of a CIE the FDEs read (Cie.java:461-524, 559-612).
#[derive(Clone)]
struct Cie {
    end_of_frame: bool,
    next: Option<u64>,
    augmentation: String,
    fde_encoding: i32,
    lsda_encoding: i32,
}

fn cie(m: &Mem, img: &Image, at: u64) -> R<Cie> {
    let mut c = Cie { end_of_frame: false, next: None, augmentation: String::new(), fde_encoding: 0, lsda_encoding: 0 };
    if m.int(at)? == 0 {
        c.end_of_frame = true;
        return Ok(c);
    }
    let int_length = m.int(at)?;
    let mut a = at + 4;
    let ext = int_length == -1;
    if ext {
        a += 8;
    }
    // processCieId sets curSize to 4 (`curSize = +DWORD_LEN`), which makes the instruction
    // count come out right: the length does not count itself
    let mut cur_size: i64 = 4;
    a += 4;
    let version = m.byte(a)? as i8;
    cur_size += 1;
    a += 1;
    let mut s = Vec::new();
    while let Ok(b) = m.byte(a + s.len() as u64) {
        if b == 0 {
            break;
        }
        s.push(b);
    }
    c.augmentation = String::from_utf8_lossy(&s).into_owned();
    cur_size += s.len() as i64 + 1;
    a += s.len() as u64 + 1;
    if version >= 4 {
        a += 2;
        cur_size += 2;
    }
    for signed in [false, true] {
        let (_, n) = m.leb(a, signed)?;
        cur_size += n as i64;
        a += n;
    }
    if version == 1 {
        m.byte(a)?;
        cur_size += 1;
        a += 1;
    } else {
        let (_, n) = m.leb(a, false)?;
        cur_size += n as i64;
        a += n;
    }
    if c.augmentation.starts_with('z') {
        let (len, n) = m.leb(a, false)?;
        cur_size += n as i64;
        a += n;
        let data_at = a;
        let data = if len > 0 { m.bytes(a, len as u64)? } else { Vec::new() };
        cur_size += data.len() as i64;
        a += data.len() as u64;
        let mut i = 0usize;
        for ch in c.augmentation.chars().skip(1) {
            if i >= data.len() {
                break;
            }
            let d = i32::from(data[i]);
            match ch {
                'L' => {
                    c.lsda_encoding = d;
                    i += 1;
                }
                'R' => {
                    c.fde_encoding = d;
                    i += 1;
                }
                'P' => {
                    i += 1;
                    let (_, n) = decoder(d).address(m, img, data_at + i as u64, Ctx::default())?;
                    i += n as usize;
                }
                _ => {}
            }
        }
    }
    if ext {
        return Err(Fault::Frame("ExtLength is not completely implemented.".into()));
    }
    if cur_size < int_length {
        let n = m.bytes(a, (int_length - cur_size) as u64)?.len() as u64;
        a += n;
    }
    c.next = Some(a);
    Ok(c)
}

/// An LSDA call-site record with its landing pad offset and action offset.
struct Record {
    first: u64,
    last: u64,
    lp_offset: i64,
    landing_pad: u64,
    action: i32,
}

/// An action record (LSDAActionRecord.java:68-127): its type filter, address, the address of
/// the next action, its size.
#[derive(Clone)]
struct Action {
    filter: i32,
    at: u64,
    next: Option<u64>,
    size: i64,
}

/// What LSDATable.create (81-131) leaves in the region: the call-site records read before any
/// exception, and the action and type tables when it got that far.
#[derive(Default)]
struct Lsda {
    records: Vec<Record>,
    /// the action table's address and its records
    actions: Option<(u64, Vec<Action>)>,
    types: Option<Vec<u64>>,
}

/// LSDATable.create, filling `out` as it goes (Java keeps what was made before an exception).
fn lsda(m: &Mem, img: &Image, at: u64, range_start: u64, out: &mut Lsda) -> R<()> {
    // LSDAHeader.create (193-249); readByte is a signed byte
    let mut a = at;
    let lp_enc = i32::from(m.byte(a)? as i8);
    let mut cur_size: i64 = 1;
    a += 1;
    let d = decoder(lp_enc);
    let lp_start = if d.is_omit() {
        range_start
    } else {
        let (raw, n) = d.decode(m, img, a, Ctx { eh_block: None, func: Some(range_start) })?;
        cur_size += n as i64;
        a += n;
        // LSDAHeader.java:114-116, as Java has it
        (raw | 0xf) as u64
    };
    let ttype_enc = i32::from(m.byte(a)? as i8);
    cur_size += 1;
    a += 1;
    let ttype_offset = if decoder(ttype_enc).is_omit() {
        0
    } else {
        let (v, n) = m.leb(a, false)?;
        a += n;
        // LSDAHeader.java:154: one less than the type table's base, as Java has it
        v + cur_size + n as i64 - 1
    };
    let cs_enc = i32::from(m.byte(a)? as i8);
    a += 1;
    let (cs_len, n) = m.leb(a, false)?;
    let cs_len = cs_len as i32;
    a += n;
    // OMITTED_ENCODING_TYPE is 0xFF and the encoding a signed byte: never equal
    let ttype_addr = (ttype_enc != 0xff).then(|| (at as i64 + ttype_offset) as u64);
    // LSDACallSiteTable.create (62-108)
    if cs_len > 0 {
        let base = a;
        let limit = base as i64 + i64::from(cs_len) - 1;
        let d = decoder(cs_enc);
        loop {
            // LSDACallSiteRecord.create (72-115)
            let (pos, n) = d.decode(m, img, a, Ctx::default())?;
            a += n;
            let (len, n) = d.decode(m, img, a, Ctx::default())?;
            a += n;
            let (lp, n) = d.decode(m, img, a, Ctx::default())?;
            a += n;
            let (action, n) = m.leb(a, false)?;
            a += n;
            let first = (lp_start as i64).wrapping_add(pos) as u64;
            let last = (first as i64).wrapping_add(len - 1) as u64;
            if last < first {
                return Err(Fault::Fatal(format!("call site {first:x} of length {len}")));
            }
            let landing_pad = (lp_start as i64).wrapping_add(lp) as u64;
            out.records.push(Record { first, last, lp_offset: lp, landing_pad, action: action as i32 });
            if limit - a as i64 <= 0 {
                break;
            }
        }
    }
    // the action table, from the largest action offset (LSDATable.java:97-114)
    let max = out.records.iter().map(|r| r.action).max().unwrap_or(0).max(0);
    if out.records.iter().any(|r| r.action != 0) {
        let table = a;
        let mut recs = Vec::new();
        out.actions = Some((table, Vec::new()));
        while a <= table + max as u64 {
            // LSDAActionRecord.create (68-90)
            let (filter, n1) = m.leb(a, true)?;
            let (disp, n2) = m.leb(a + n1, true)?;
            let next = (disp != 0).then(|| (a as i64 + n1 as i64 + disp) as u64);
            recs.push(Action { filter: filter as i32, at: a, next, size: (n1 + n2) as i64 });
            a += n1 + n2;
            out.actions = Some((table, recs.clone()));
        }
    }
    // the type table (LSDATypeTable.create, 66-117), read down from its base
    if ttype_enc != 0xff {
        if let Some(bottom) = ttype_addr {
            let d = decoder(ttype_enc);
            let stride = d.size()?;
            let top = match a & 3 {
                0 => a,
                r => a + 4 - r,
            } as i64;
            let mut types = Vec::new();
            let mut p = bottom as i64 - (stride - 1);
            // an omitted encoding (stride 0) reads nothing; a LEB128 one (-1) would not end in Java
            if p >= top && stride <= 0 {
                return Err(Fault::Fatal(format!("type table encoding {ttype_enc:#x}: stride {stride}")));
            }
            while p >= top {
                if let Ok((t, _)) = d.address(m, img, p as u64, Ctx::default()) {
                    types.push(t);
                }
                p -= stride;
            }
            out.types = Some(types);
        }
    }
    Ok(())
}

/// A region (RegionDescriptor) with its LSDA.
struct Region {
    lsda: Option<Lsda>,
}

enum Fde {
    End,
    Region(Region, Option<u64>),
}

/// FrameDescriptionEntry.create (441-515).
fn fde(m: &Mem, img: &Image, at: u64, eh: u64, cies: &mut HashMap<u64, Cie>) -> R<Fde> {
    if m.int(at)? == 0 {
        return Ok(Fde::End);
    }
    let int_length = m.int(at)?;
    let mut a = at + 4;
    let mut cur_size: i64 = 0;
    let ext = int_length == -1;
    if ext {
        a += 8;
        cur_size += 8;
    }
    // createCiePointer (194-236)
    let ptr = m.int(a)?;
    if ptr == 0 {
        return Err(Fault::Frame(format!("Invalid CIE Reference Pointer (0x{ptr:x})")));
    }
    let cie_at = (a as i64 - ptr) as u64;
    let c = match cies.get(&cie_at) {
        Some(c) => c.clone(),
        None => {
            let c = cie(m, img, cie_at)?;
            cies.insert(cie_at, c.clone());
            c
        }
    };
    cur_size += 4;
    a += 4;
    // createPcBegin (252-277)
    let (pc_begin, n) = decoder(c.fde_encoding).address(m, img, a, Ctx { eh_block: Some(eh), func: None })?;
    cur_size += n as i64;
    a += n;
    // createPcRange (288-339): 8 bytes, or 4 where the upper half is not 0
    // getBytes leaves the bytes past memory 0
    let mut range = m.bytes(a, 8)?;
    range.resize(8, 0);
    let mut pc_range = u64::from_le_bytes(range.try_into().unwrap()) as u32 as i32;
    if pc_range < 0 {
        // pcEndAddr stays NO_ADDRESS: the AddressRangeImpl of create throws
        return Err(Fault::Fatal(format!("FDE {at:x}: PcRange {pc_range}")));
    }
    if pc_range == 0 {
        pc_range = 1;
    }
    let _pc_end = pc_begin + pc_range as u64 - 1;
    let dt = if m.int(a + 4)? != 0 { 4 } else { 8 };
    cur_size += dt;
    a += dt as u64;
    let mut next = Some(a);
    let mut aug_data_at = None;
    let mut aug_len = 0i64;
    if cur_size < int_length {
        // createAugmentationFields (540-556)
        if c.augmentation.starts_with('z') {
            let (len, n) = m.leb(a, false)?;
            aug_len = len;
            cur_size += n as i64;
            a += n;
            aug_data_at = Some(a);
            if len > 0 {
                m.bytes(a, len as u64)?;
            }
            cur_size += len;
            a += len as u64;
        }
        if ext {
            return Err(Fault::Frame("ExtLength is not completely implemented.".into()));
        }
        if cur_size < int_length {
            // createCallFrameInstructions (396-429)
            let count = int_length - cur_size;
            m.bytes(a, count as u64)?;
            a += count as u64;
        }
        next = Some(a);
    }
    // createAugmentationInfo (576-622)
    let mut region = Region { lsda: None };
    if let Some(data_at) = aug_data_at.filter(|_| aug_len != 0) {
        if c.augmentation.find('L').is_some_and(|i| i > 1) {
            // createLsda (624-672)
            let (lsda_at, _) =
                decoder(c.lsda_encoding).address(m, img, data_at, Ctx { eh_block: Some(eh), func: None })?;
            if lsda_at != data_at && m.contains(lsda_at) {
                let mut l = Lsda::default();
                // an exception here is logged (FrameDescriptionEntry.java:665-671)
                let _ = lsda(m, img, lsda_at, pc_begin, &mut l);
                region.lsda = Some(l);
            }
        } else {
            // the decode can throw; its result is data only
            decoder(c.lsda_encoding).address(m, img, data_at, Ctx { eh_block: Some(eh), func: None })?;
        }
    }
    Ok(Fde::Region(region, next))
}

/// EhFrameSection.analyze (65-143): the regions of `.eh_frame`, or the exception that ends it
/// (GccExceptionAnalyzer.handleStandardSections then writes nothing, 193-196).
fn regions(img: &Image) -> R<Vec<Region>> {
    let m = Mem { img };
    let Some(block) = img.section(".eh_frame") else { return Ok(Vec::new()) };
    let (start, end) = (u64::from(block.addr), u64::from(block.addr) + block.data.len() as u64 - 1);
    let mut cies: HashMap<u64, Cie> = HashMap::new();
    let mut regions = Vec::new();
    let mut cur = Some(start);
    while let Some(at) = cur.filter(|&a| a < end) {
        let c = match cies.get(&at) {
            Some(c) => c.clone(),
            None => {
                let c = cie(&m, img, at)?;
                cies.insert(at, c.clone());
                c
            }
        };
        if c.end_of_frame {
            break;
        }
        cur = c.next;
        while let Some(at) = cur.filter(|&a| a < end) {
            match fde(&m, img, at, start, &mut cies) {
                Ok(Fde::End) => break,
                Ok(Fde::Region(r, next)) => {
                    regions.push(r);
                    cur = next;
                }
                // "May have run into another CIE."
                Err(Fault::Frame(_)) => break,
                Err(e) => return Err(e),
            }
        }
    }
    Ok(regions)
}

/// The call-site records with a landing pad of every region, in GccExceptionAnalyzer's order
/// (handleStandardSections, processCallSiteRecord: 160-239). `Err`: the analyzer stops before
/// it writes a comment. A runtime exception in getTypeInfos (getNextAction, 170-185) ends the
/// list there.
pub fn call_sites(img: &Image) -> Result<Vec<CallSite>, String> {
    // canAnalyze (102-125): the gcc compiler spec of x86-64 ELF, with an .eh_frame_hdr,
    // .eh_frame or .debug_frame block; only .eh_frame gives call sites
    let regions = regions(img).map_err(Fault::text)?;
    let mut out = Vec::new();
    for r in &regions {
        let Some(l) = &r.lsda else { continue };
        for cs in &l.records {
            if cs.lp_offset == 0 {
                continue;
            }
            let mut types = Vec::new();
            if let (Some((table, recs)), Some(tt)) = (&l.actions, &l.types) {
                // getActionRecordAtOffset (LSDAActionTable.java:142-154)
                let mut off = 0i64;
                let mut action = None;
                for (i, rec) in recs.iter().enumerate() {
                    if i64::from(cs.action) >= off && i64::from(cs.action) < off + rec.size {
                        action = Some(i);
                        break;
                    }
                    off += rec.size;
                }
                let mut steps = 0;
                while let Some(i) = action {
                    let Action { filter, next, .. } = recs[i];
                    let t = (filter > 0 && filter as usize <= tt.len()).then(|| tt[filter as usize - 1]);
                    types.push((filter, t));
                    action = match next {
                        None => None,
                        Some(n) if n == *table => None,
                        Some(n) => match recs.iter().position(|r| r.at == n) {
                            Some(j) => Some(j),
                            // IllegalArgumentException: the analyzer ends
                            None => return Ok(out),
                        },
                    };
                    steps += 1;
                    if steps > recs.len() {
                        return Err(format!("action records of the call site at {:x} loop", cs.first));
                    }
                }
            }
            out.push(CallSite { first: cs.first, last: cs.last, landing_pad: cs.landing_pad, types });
        }
    }
    Ok(out)
}

/// StringUtilities.mergeStrings (827-855) after the analyzer's `contains` check.
fn merge(map: &mut BTreeMap<u64, String>, at: u64, text: String) {
    match map.get_mut(&at) {
        None => {
            map.insert(at, text);
        }
        Some(old) if old.contains(&text) => {}
        Some(old) if old.is_empty() || text.contains(old.as_str()) => *old = text,
        Some(old) => {
            old.push('\n');
            old.push_str(&text);
        }
    }
}

/// The PRE and POST comments the analyzer writes (markStartOfTry, markEndOfTry,
/// markStartOfCatch: 292-345), by address. `unit` is the first address of the code unit that
/// holds an address (Listing.getCodeUnitContaining).
pub fn comments(sites: &[CallSite], unit: impl Fn(u64) -> u64) -> (BTreeMap<u64, String>, BTreeMap<u64, String>) {
    let (mut pre, mut post) = (BTreeMap::new(), BTreeMap::new());
    for cs in sites {
        let (a, b, lp) = (cs.first, cs.last, cs.landing_pad);
        merge(&mut pre, a, format!("try {{ // try from {a:08x} to {b:08x} has its CatchHandler @ {lp:08x}"));
        merge(&mut post, unit(b), format!("}} // end try from {a:08x} to {b:08x}"));
        let types: Vec<String> = cs
            .types
            .iter()
            .map(|&(filter, t)| match t {
                Some(t) if filter != 0 => format!("type#{filter} @ {t:08x}"),
                _ => String::new(),
            })
            .collect();
        merge(
            &mut pre,
            lp,
            format!("catch({}) {{ ... }} // from try @ {a:08x} with catch @ {lp:08x}", types.join(", ")),
        );
    }
    (pre, post)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::Section;

    /// One CIE `zPLR` and one FDE with an LSDA of one call site, laid out as clang writes them.
    #[test]
    fn one_call_site() {
        let eh = 0x1000u32;
        let mut d = Vec::new();
        // CIE: length, id 0, version 1, "zPLR", code 1, data -8, RA 16, aug len 7:
        // P = 0x9b + 4 bytes, L = 0x1b, R = 0x1b, then instructions
        let mut cie = vec![0, 0, 0, 0, 1, b'z', b'P', b'L', b'R', 0, 1, 0x78, 0x10, 7, 0x9b, 0, 0, 0, 0, 0x1b, 0x1b];
        cie.extend([0x0c, 7, 8, 0x90, 1, 0, 0]);
        d.extend((cie.len() as u32).to_le_bytes());
        d.extend(&cie);
        // FDE: length, CIE pointer, PcBegin (pcrel sdata4) -> 0x2000, PcRange 0x40, aug len 4,
        // LSDA (pcrel sdata4) -> 0x3000, instructions
        let fde_at = eh + d.len() as u32;
        let mut fde = Vec::new();
        fde.extend((fde_at + 4 - eh).to_le_bytes());
        let pc_at = fde_at + 8;
        fde.extend((0x2000i32 - pc_at as i32).to_le_bytes());
        fde.extend(0x40u32.to_le_bytes());
        fde.push(4);
        let lsda_ptr = fde_at + 4 + fde.len() as u32;
        fde.extend((0x3000i32 - lsda_ptr as i32).to_le_bytes());
        fde.extend([0, 0, 0]);
        d.extend((fde.len() as u32).to_le_bytes());
        d.extend(&fde);
        d.extend([0, 0, 0, 0]);
        // LSDA: lpstart omit, ttype omit, call sites uleb128, length 4: one record
        // (start 0x10, length 5, landing pad 0x30, no action)
        let lsda = vec![0xff, 0xff, 0x01, 4, 0x10, 5, 0x30, 0];
        let img = Image {
            elf64: true,
            sections: vec![
                Section { name: ".eh_frame".into(), exec: false, readonly: true, zero_tail: 0, addr: eh, data: d },
                Section {
                    name: ".gcc_except_table".into(),
                    exec: false,
                    readonly: true,
                    zero_tail: 0,
                    addr: 0x3000,
                    data: lsda,
                },
            ],
            ..Default::default()
        };
        let sites = call_sites(&img).unwrap();
        assert_eq!(sites, vec![CallSite { first: 0x2010, last: 0x2014, landing_pad: 0x2030, types: vec![] }]);
        let (pre, post) = comments(&sites, |a| a - 4);
        assert_eq!(pre[&0x2010], "try { // try from 00002010 to 00002014 has its CatchHandler @ 00002030");
        assert_eq!(post[&0x2010], "} // end try from 00002010 to 00002014");
        assert_eq!(pre[&0x2030], "catch() { ... } // from try @ 00002010 with catch @ 00002030");
    }
}
