//! Function discovery, bodies and references for 32-bit x86 PE images, modelled on what
//! Ghidra's auto-analysis produces for the scripts in `main.rs` (ExportFunctions, ExportGaps).
//! Every executable section is disassembled; results are reported for `.text`. See rust/README.md "Analysis" for what is and isn't covered.

use crate::sleigh::Sleigh;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

pub struct Section {
    pub name: String,
    pub exec: bool,
    pub addr: u32,
    pub data: Vec<u8>, // virtual size, zero filled past the raw data
}

#[derive(Default)]
pub struct Image {
    pub sections: Vec<Section>, // first entry: the "Headers" block, as Ghidra names it
    pub entry: Option<u32>,
    pub exports: Vec<(u32, String)>,
    pub imports: HashMap<u32, (String, String)>, // IAT slot -> (library, function)
}

impl Image {
    pub fn from_pe(bytes: &[u8]) -> Result<Image, String> {
        use object::pe::ImageNtHeaders32;
        use object::read::pe::{ImageNtHeaders, ImageOptionalHeader, ImageThunkData, Import, PeFile32};
        use object::{LittleEndian as LE, Object};
        let pe = PeFile32::parse(bytes).map_err(|e| e.to_string())?;
        let opt = pe.nt_headers().optional_header();
        let base = opt.image_base() as u32;
        let hdr = opt.size_of_headers() as usize;
        let mut img = Image::default();
        img.sections.push(Section { name: "Headers".into(), exec: false, addr: base, data: bytes[..hdr.min(bytes.len())].to_vec() });
        for s in pe.section_table().iter() {
            let name = String::from_utf8_lossy(s.raw_name()).trim_end_matches('\0').to_string();
            let mut data = s.pe_data(bytes).map_err(|e| e.to_string())?.to_vec();
            data.resize(s.virtual_size.get(LE) as usize, 0);
            let exec = s.characteristics.get(LE) & (object::pe::IMAGE_SCN_CNT_CODE | object::pe::IMAGE_SCN_MEM_EXECUTE) != 0;
            img.sections.push(Section { name, exec, addr: base + s.virtual_address.get(LE), data });
        }
        let entry = opt.address_of_entry_point();
        img.entry = (entry != 0).then_some(base + entry);
        for x in pe.exports().map_err(|e| e.to_string())? {
            img.exports.push((x.address() as u32, String::from_utf8_lossy(x.name()).into_owned()));
        }
        if let Some(t) = pe.import_table().map_err(|e| e.to_string())? {
            let mut descs = t.descriptors().map_err(|e| e.to_string())?;
            while let Ok(Some(d)) = descs.next() {
                let lib = String::from_utf8_lossy(t.name(d.name.get(LE)).unwrap_or(b"")).to_uppercase();
                let first = d.first_thunk.get(LE);
                let orig = d.original_first_thunk.get(LE);
                let Ok(mut thunks) = t.thunks(if orig != 0 { orig } else { first }) else { continue };
                let mut i = 0;
                while let Ok(Some(th)) = thunks.next::<ImageNtHeaders32>() {
                    let name = match t.import::<ImageNtHeaders32>(th) {
                        Ok(Import::Name(_, n)) => String::from_utf8_lossy(n).into_owned(),
                        _ => format!("Ordinal_{}", th.raw() & 0xffff),
                    };
                    img.imports.insert(base + first + 4 * i, (lib.clone(), name));
                    i += 1;
                }
            }
        }
        Ok(img)
    }

    pub fn section(&self, name: &str) -> Option<&Section> {
        self.sections.iter().find(|s| s.name == name)
    }

    pub fn block_of(&self, a: u32) -> Option<&Section> {
        self.sections.iter().find(|s| a >= s.addr && ((a - s.addr) as usize) < s.data.len())
    }

    pub fn read_u32(&self, a: u32) -> Option<u32> {
        let s = self.block_of(a)?;
        let o = (a - s.addr) as usize;
        Some(u32::from_le_bytes(s.data.get(o..o + 4)?.try_into().ok()?))
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Flow {
    Fall,
    Jump,     // unconditional, direct
    CondJump, // conditional, direct
    JumpInd,
    Call,
    CallInd,
    Return,
}

#[derive(Clone, Debug)]
pub struct Ins {
    pub len: u8,
    pub flow: Flow,
    pub target: Option<u32>, // direct flow target
    pub slot: Option<u32>,   // memory operand of an indirect call/jump through a constant address
    pub refs: Vec<u32>,      // data references: constant addresses inside the image
}

impl Ins {
    pub fn falls_through(&self) -> bool {
        !matches!(self.flow, Flow::Jump | Flow::JumpInd | Flow::Return)
    }
}

pub struct Analysis {
    pub text_start: u32,
    pub text_end: u32,
    code_lo: u32, // span of the executable sections, which `owner` covers
    code_hi: u32,
    pub insns: BTreeMap<u32, Ins>,
    pub tables: HashMap<u32, Vec<u32>>, // switch jump -> case targets
    pub funcs: BTreeSet<u32>,
    pub noreturn: HashSet<u32>,          // functions and IAT slots that do not return
    pub bodies: BTreeMap<u32, Vec<u32>>, // function -> sorted instruction addresses
}

const KNOWN_NORETURN: [&str; 9] =
    ["ExitProcess", "ExitThread", "exit", "_exit", "abort", "_amsg_exit", "RaiseException", "_CxxThrowException", "FatalAppExitA"];

// x86win_patterns.xml, the two <patternpairs> whose matches are definite function starts.
// Pattern bytes are (value, mask); prepatterns end right before the candidate.
type Pat = &'static [(u8, u8)];
const PRE_FILL: [Pat; 6] = [
    &[(0xcc, 0xff)],
    &[(0xcc, 0xff), (0xcc, 0xff)],
    &[(0x90, 0xff)],
    &[(0xc3, 0xff)],
    &[(0xc9, 0xff), (0xc3, 0xff)],
    &[(0xc2, 0xff), (0, 0x03), (0, 0xff)],
];
const PRE_JMP: [Pat; 2] = [&[(0xe9, 0xff), (0, 0), (0, 0), (0, 0), (0, 0)], &[(0xeb, 0xff), (0, 0)]];
const POST_ALL: [Pat; 18] = [
    &[(0x55, 0xff), (0x8b, 0xff), (0xec, 0xff)],
    &[(0x55, 0xff), (0x89, 0xff), (0xe5, 0xff)],
    &[(0x83, 0xff), (0xec, 0xff), (0x00, 0x83)],
    &[(0x6a, 0xff), (0xff, 0xff), (0x68, 0xff), (0, 0), (0, 0), (0, 0), (0, 0), (0x64, 0xff), (0xa1, 0xff), (0, 0xff), (0, 0xff), (0, 0xff), (0, 0xff)],
    &[(0x56, 0xff), (0x8b, 0xff), (0xf1, 0xff)],
    &[(0xb8, 0xff), (0, 0), (0, 0), (0, 0), (0, 0), (0xe8, 0xff)],
    &[(0x8b, 0xff), (0xff, 0xff), (0x55, 0xff), (0x8b, 0xff), (0xec, 0xff)],
    &[(0x53, 0xff), (0x8b, 0xff), (0xd8, 0xfc)],
    &[(0x53, 0xff), (0x56, 0xff), (0x57, 0xff)],
    &[(0x53, 0xff), (0x55, 0xff), (0x56, 0xff)],
    &[(0x53, 0xff), (0x56, 0xff), (0x51, 0xff)],
    &[(0x53, 0xff), (0x56, 0xff), (0x8b, 0xff), (0xf2, 0xff)],
    &[(0x53, 0xff), (0x56, 0xff), (0x8b, 0xff), (0xd8, 0xff)],
    &[(0x53, 0xff), (0x56, 0xff), (0x8b, 0xff), (0xf1, 0xff)],
    &[(0x53, 0xff), (0x56, 0xff), (0x8b, 0xff), (0xda, 0xff)],
    &[(0x53, 0xff), (0x56, 0xff), (0x8b, 0xff), (0xf0, 0xff)],
    &[(0x56, 0xff), (0x57, 0xff), (0x8b, 0xff), (0xf9, 0xff)],
    &[(0x56, 0xff), (0x57, 0xff), (0x8b, 0xff), (0xf1, 0xff)],
];
const POST_AFTER_JMP: [usize; 4] = [0, 4, 5, 6]; // indexes into POST_ALL
const POST_EXTRA: Pat = &[(0x55, 0xff), (0x57, 0xff), (0x56, 0xff), (0x53, 0xff)];

fn matches(bytes: &[u8], pat: Pat) -> bool {
    bytes.len() >= pat.len() && pat.iter().zip(bytes).all(|(&(v, m), &b)| b & m == v & m)
}

impl Analysis {
    pub fn is_text(&self, a: u32) -> bool {
        a >= self.text_start && a < self.text_end
    }

    fn is_code(&self, img: &Image, a: u32) -> bool {
        a >= self.code_lo && a < self.code_hi && img.block_of(a).is_some_and(|s| s.exec)
    }

    /// Discover code and functions from exports, the entry point, RTTI vftables, call targets,
    /// prologue patterns and far jumps, then compute function bodies. `extra` entries are
    /// disassembled and made functions too; with `exact`, they are the whole function set.
    pub fn run(img: &Image, sl: &Sleigh, extra: &[u32], exact: bool) -> Result<Analysis, String> {
        let text = img.section(".text").ok_or("no .text section")?;
        let exec = || img.sections.iter().filter(|s| s.exec);
        let mut an = Analysis {
            text_start: text.addr,
            text_end: text.addr + text.data.len() as u32,
            code_lo: exec().map(|s| s.addr).min().unwrap_or(0),
            code_hi: exec().map(|s| s.addr + s.data.len() as u32).max().unwrap_or(0),
            insns: BTreeMap::new(),
            tables: HashMap::new(),
            funcs: BTreeSet::new(),
            noreturn: HashSet::new(),
            bodies: BTreeMap::new(),
        };
        for (slot, (_, name)) in &img.imports {
            if KNOWN_NORETURN.contains(&name.as_str()) {
                an.noreturn.insert(*slot);
            }
        }
        let mut seeds: Vec<u32> = img.exports.iter().map(|e| e.0).chain(img.entry).chain(extra.iter().copied()).collect();
        // RTTI vftable slots (the RTTI analyzer makes a function of each)
        let tables = crate::scripts::vftables(img);
        for &v in tables.keys() {
            for i in 0..4096 {
                match img.read_u32(v + 4 * i) {
                    Some(t) if an.is_code(img, t) && (i == 0 || !tables.contains_key(&(v + 4 * i))) => seeds.push(t),
                    _ => break,
                }
            }
        }
        seeds.retain(|&a| an.is_code(img, a));
        let mut p = sl.new_parse();
        // 1: instruction start, 2: inside an instruction, 3: switch table
        let mut owner = vec![0u8; (an.code_hi - an.code_lo) as usize];
        let mut queue: Vec<u32> = Vec::new();
        let mut tables_queue: Vec<u32> = Vec::new();
        // Create Address Tables: runs of 2+ code pointers in data are disassembled after
        // everything else, without making functions. (Making functions of lone pointers or of
        // referenced tables matched Ghidra worse: more extra functions than found ones.)
        for sec in img.sections.iter().filter(|s| !s.exec && s.name != "Headers") {
            let mut run = Vec::new();
            for o in (0..sec.data.len().saturating_sub(3) + 4).step_by(4) {
                let t = sec.data.get(o..o + 4).map_or(0, |b| u32::from_le_bytes(b.try_into().unwrap()));
                if an.is_code(img, t) {
                    run.push(t);
                    continue;
                }
                if run.len() >= 2 {
                    tables_queue.extend(&run);
                }
                run.clear();
            }
        }
        for &s in &seeds {
            an.funcs.insert(s);
            queue.push(s);
        }
        loop {
            an.descend(img, sl, &mut p, &mut owner, &mut queue);
            // Function Start Search: prologue patterns in bytes no code covers yet.
            let before = an.funcs.len();
            for sec in exec() {
                let d = &sec.data;
                for o in 1..d.len() {
                    let a = sec.addr + o as u32;
                    if owner[(a - an.code_lo) as usize] != 0 {
                        continue;
                    }
                    let at = &d[o..];
                    let pre = |list: &[Pat]| list.iter().any(|p| o >= p.len() && matches(&d[o - p.len()..o], p));
                    let hit = (pre(&PRE_FILL) && (POST_ALL.iter().any(|p| matches(at, p)) || matches(at, POST_EXTRA)))
                        || (pre(&PRE_JMP) && POST_AFTER_JMP.iter().any(|&i| matches(at, POST_ALL[i])));
                    if hit {
                        an.funcs.insert(a);
                        queue.push(a);
                        an.descend(img, sl, &mut p, &mut owner, &mut queue);
                    }
                }
            }
            if an.funcs.len() == before {
                if tables_queue.is_empty() {
                    break;
                }
                // after everything the seeds reach, so stray pointers cannot claim their bytes
                queue.append(&mut tables_queue);
                an.descend(img, sl, &mut p, &mut owner, &mut queue);
            }
        }
        an.funcs.retain(|a| an.insns.contains_key(a));
        an.shared_returns();
        if exact {
            an.funcs = extra.iter().copied().filter(|a| an.insns.contains_key(a)).collect();
        }
        an.compute_bodies();
        // Non-returning functions: no RETURN anywhere in the body; then redo the bodies.
        for _ in 0..4 {
            let n = an.noreturn.len();
            let found: Vec<u32> = an
                .bodies
                .iter()
                .filter(|(_, b)| {
                    !b.iter().any(|a| {
                        let i = &an.insns[a];
                        i.flow == Flow::Return || i.flow == Flow::JumpInd && !an.tables.contains_key(a)
                            || i.flow == Flow::Jump && i.target.is_some_and(|t| an.funcs.contains(&t) && !an.noreturn.contains(&t))
                    })
                })
                .map(|(&f, _)| f)
                .collect();
            an.noreturn.extend(found);
            if an.noreturn.len() == n {
                break;
            }
            an.compute_bodies();
        }
        Ok(an)
    }

    fn decode(&self, img: &Image, sl: &Sleigh, p: &mut crate::sleigh::Parse, a: u32) -> Option<Ins> {
        let sec = img.block_of(a)?;
        let o = (a - sec.addr) as usize;
        let len = sl.decode(p, a as u64, &sec.data[o..]).ok()?;
        if len == 0 || o + len > sec.data.len() {
            return None;
        }
        let ops = sl.pcode(p).ok()?;
        let code = sl.code_space();
        let next = a as u64 + len as u64;
        let (mut flow, mut target, mut slot) = (Flow::Fall, None, None);
        let mut refs = Vec::new();
        for op in &ops {
            match op.opc {
                // REP-prefixed string ops branch to their own start or end: no flow change
                4 | 5 if op.ins[0].space == code && (op.ins[0].offset == a as u64 || op.ins[0].offset == next) => {}
                4 | 5 | 7 if op.ins[0].space == code => {
                    target = Some(op.ins[0].offset as u32);
                    flow = match op.opc {
                        4 => Flow::Jump,
                        5 => Flow::CondJump,
                        _ => Flow::Call,
                    };
                }
                6 | 8 => {
                    flow = if op.opc == 6 { Flow::JumpInd } else { Flow::CallInd };
                    // through a direct memory operand: `CALL dword ptr [slot]`
                    slot = (op.ins[0].space == code).then_some(op.ins[0].offset as u32);
                }
                10 => flow = Flow::Return,
                _ => {}
            }
            // data references: direct memory operands (ram varnodes), not flow targets
            let skip = usize::from(matches!(op.opc, 4 | 5 | 7));
            for v in op.ins.iter().skip(skip).chain(op.out.as_ref()) {
                let is_ref = match v.space {
                    0 => v.size == 4 && img.block_of(v.offset as u32).is_some_and(|s| !s.exec), // immediate pointing at data
                    s => s == code && img.block_of(v.offset as u32).is_some(),
                };
                if is_ref && !refs.contains(&(v.offset as u32)) {
                    refs.push(v.offset as u32);
                }
            }
        }
        Some(Ins { len: len as u8, flow, target, slot, refs })
    }

    /// Recursive descent from every queued address. Call targets in .text become functions.
    fn descend(&mut self, img: &Image, sl: &Sleigh, p: &mut crate::sleigh::Parse, owner: &mut [u8], queue: &mut Vec<u32>) {
        while let Some(start) = queue.pop() {
            let mut a = start;
            let mut recent: Vec<u32> = Vec::new(); // straight-line history, for switch bounds
            while self.is_code(img, a) && owner[(a - self.code_lo) as usize] == 0 {
                let Some(ins) = self.decode(img, sl, p, a) else { break };
                let o = (a - self.code_lo) as usize;
                if owner[o..o + ins.len as usize].iter().any(|&b| b != 0) {
                    break; // would overlap code already there
                }
                owner[o] = 1;
                owner[o + 1..o + ins.len as usize].fill(2);
                if let Some(t) = ins.target.filter(|&t| self.is_code(img, t)) {
                    if ins.flow == Flow::Call {
                        self.funcs.insert(t);
                    }
                    queue.push(t);
                }
                if ins.flow == Flow::JumpInd {
                    if let Some((table, cases)) = self.switch_table(img, a, &recent) {
                        queue.extend(&cases);
                        // the table is data: keep the pattern search out of it
                        if self.is_code(img, table) {
                            let t = (table - self.code_lo) as usize;
                            let e = (t + 4 * cases.len()).min(owner.len());
                            owner[t..e].iter_mut().filter(|b| **b == 0).for_each(|b| *b = 3);
                        }
                        self.tables.insert(a, cases);
                    }
                }
                let stop = !ins.falls_through()
                    || ins.flow == Flow::Call && ins.target.is_some_and(|t| self.noreturn.contains(&t))
                    || ins.flow == Flow::CallInd && ins.slot.is_some_and(|s| self.noreturn.contains(&s));
                recent.push(a);
                let len = ins.len as u32;
                self.insns.insert(a, ins);
                if stop {
                    break;
                }
                a += len;
            }
        }
    }

    // `JMP dword ptr [reg*4 + table]`, bounded by a preceding `CMP reg,imm` when there is one,
    // possibly through a byte index table (`MOVZX reg,byte ptr [idx + bytetable]`). Cases must
    // lie in the jump's own section.
    fn switch_table(&self, img: &Image, at: u32, recent: &[u32]) -> Option<(u32, Vec<u32>)> {
        let bytes = |a: u32| img.block_of(a).map(|s| &s.data[(a - s.addr) as usize..]);
        let b = bytes(at)?.get(..7)?;
        if b[0] != 0xff || b[1] != 0x24 || b[2] & 0xc7 != 0x85 {
            return None;
        }
        let mut reg = (b[2] >> 3) & 7; // the register the CMP bounds
        let table = u32::from_le_bytes(b[3..7].try_into().unwrap());
        let mut count = None;
        let mut index_table = None; // two-level switch: `MOVZX reg,byte ptr [r + bytetable]`
        for &r in recent.iter().rev().take(8) {
            let Some(c) = bytes(r) else { continue };
            if let [0x0f, 0xb6, m, d0, d1, d2, d3, ..] = c {
                if index_table.is_none() && m & 0xc0 == 0x80 && m & 7 != 4 && (m >> 3) & 7 == reg {
                    index_table = Some(u32::from_le_bytes([*d0, *d1, *d2, *d3]));
                    reg = m & 7;
                    continue;
                }
            }
            let imm = match c {
                [0x83, m, i, ..] if *m == 0xf8 | reg => Some(*i as u32),
                [0x81, m, i0, i1, i2, i3, ..] if *m == 0xf8 | reg => Some(u32::from_le_bytes([*i0, *i1, *i2, *i3])),
                [0x3d, i0, i1, i2, i3, ..] if reg == 0 => Some(u32::from_le_bytes([*i0, *i1, *i2, *i3])),
                _ => None,
            };
            if let Some(n) = imm {
                count = Some(n as usize + 1);
                break;
            }
        }
        // The CMP bounds the byte table; the jump table has max(byte table) + 1 entries.
        if let (Some(bt), Some(n)) = (index_table, count) {
            let b = img.block_of(bt).map(|s| &s.data[(bt - s.addr) as usize..])?;
            count = Some(*b.get(..n.min(b.len()))?.iter().max()? as usize + 1);
        }
        let own = img.block_of(at)?.addr;
        let mut cases = Vec::new();
        for i in 0..count.unwrap_or(1024).min(1024) {
            match img.read_u32(table + 4 * i as u32) {
                Some(t) if self.is_code(img, t) && img.block_of(t).is_some_and(|s| s.addr == own) => cases.push(t),
                _ => break,
            }
        }
        (!cases.is_empty()).then_some((table, cases))
    }

    /// SharedReturnAnalysisCmd with "assume contiguous functions": an unconditional jump past
    /// the next function entry (or before the previous one) is a tail call, so its target
    /// becomes a function, unless a conditional jump or a fallthrough also reaches it.
    fn shared_returns(&mut self) {
        let mut cond = HashSet::new();
        let mut fall = HashSet::new();
        for (&a, i) in &self.insns {
            if i.flow == Flow::CondJump {
                cond.extend(i.target);
            }
            if i.falls_through() && !matches!(i.flow, Flow::Call | Flow::CallInd) {
                fall.insert(a + i.len as u32);
            }
        }
        loop {
            let mut new = Vec::new();
            for (&src, i) in &self.insns {
                let Some(t) = i.target.filter(|t| i.flow == Flow::Jump && self.insns.contains_key(t)) else { continue };
                if self.funcs.contains(&t) || cond.contains(&t) || fall.contains(&t) {
                    continue;
                }
                let far = if t > src {
                    self.funcs.range(src + 1..).next().is_some_and(|&next| t >= next)
                } else {
                    self.funcs.range(..src).next_back().is_some_and(|&prev| t < prev)
                };
                if far {
                    new.push(t);
                }
            }
            if new.is_empty() {
                break;
            }
            self.funcs.extend(new);
        }
    }

    fn compute_bodies(&mut self) {
        let mut bodies = BTreeMap::new();
        for &f in &self.funcs {
            let mut seen = BTreeSet::new();
            let mut work = vec![f];
            while let Some(a) = work.pop() {
                if (a != f && self.funcs.contains(&a)) || !seen.insert(a) {
                    continue;
                }
                let Some(i) = self.insns.get(&a) else {
                    seen.remove(&a);
                    continue;
                };
                let noret = match i.flow {
                    Flow::Call => i.target.is_some_and(|t| self.noreturn.contains(&t)),
                    Flow::CallInd => i.slot.is_some_and(|s| self.noreturn.contains(&s)),
                    _ => false,
                };
                if i.falls_through() && !noret {
                    work.push(a + i.len as u32);
                }
                if matches!(i.flow, Flow::Jump | Flow::CondJump) {
                    work.extend(i.target);
                }
                if let Some(cases) = self.tables.get(&a) {
                    work.extend(cases);
                }
            }
            bodies.insert(f, seen.into_iter().collect());
        }
        self.bodies = bodies;
    }

    /// Is this instruction a call reference to `t` (a CALL, or a JMP to a function entry,
    /// which Ghidra's Shared Return Calls analyzer turns into a call)?
    pub fn call_target(&self, i: &Ins) -> Option<u32> {
        match i.flow {
            Flow::Call => i.target,
            Flow::Jump => i.target.filter(|t| self.funcs.contains(t)),
            _ => None,
        }
    }

    pub fn body_size(&self, f: u32) -> u64 {
        self.bodies[&f].iter().map(|a| self.insns[a].len as u64).sum()
    }
}
