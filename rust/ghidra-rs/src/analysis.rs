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
    pub export_dir: (u32, u32), // export directory (address, size): its tables hold RVAs, not addresses
    pub eat: Vec<(u32, u32)>,   // export address table: (slot, function it names)
}

impl Image {
    pub fn from_pe(bytes: &[u8]) -> Result<Image, String> {
        use object::read::pe::{ImageNtHeaders, ImageOptionalHeader, PeFile32};
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
        // The loader types the export address table as image-base offsets (ibo32): each slot
        // references base + RVA.
        if let Some(d) = pe.data_directory(object::pe::IMAGE_DIRECTORY_ENTRY_EXPORT) {
            let at = base + d.virtual_address.get(LE);
            img.export_dir = (at, d.size.get(LE));
            let (n, funcs) = (img.read_u32(at + 0x14).unwrap_or(0), img.read_u32(at + 0x1c).unwrap_or(0));
            for i in 0..n.min(0x10000) {
                if let Some(rva) = img.read_u32(base + funcs + 4 * i).filter(|&r| r != 0) {
                    img.eat.push((base + funcs + 4 * i, base + rva));
                }
            }
        }
        // Import descriptors, read through the loaded image: names and thunks may lie in other
        // sections than the directory (the mercs2 image keeps its IAT in .rdata and the
        // directory in .securom), which object's section-bound ImportTable cannot read.
        let dir = pe.data_directory(object::pe::IMAGE_DIRECTORY_ENTRY_IMPORT).map_or(0, |d| d.virtual_address.get(LE));
        let mut d = base + dir;
        while dir != 0 {
            let f = |i: u32| img.read_u32(d + 4 * i).unwrap_or(0);
            let (orig, name, first) = (f(0), f(3), f(4));
            if name == 0 || first == 0 {
                break;
            }
            let lib = img.c_string(base + name).to_uppercase();
            let mut i = 0;
            loop {
                let Some(th) = img.read_u32(base + if orig != 0 { orig } else { first } + 4 * i).filter(|&t| t != 0) else { break };
                let name =
                    if th & 0x8000_0000 != 0 { format!("Ordinal_{}", th & 0xffff) } else { img.c_string(base + th + 2) };
                img.imports.insert(base + first + 4 * i, (lib.clone(), name));
                i += 1;
            }
            d += 20;
        }
        Ok(img)
    }

    pub fn c_string(&self, a: u32) -> String {
        let Some(s) = self.block_of(a) else { return String::new() };
        let b = &s.data[(a - s.addr) as usize..];
        String::from_utf8_lossy(&b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())]).into_owned()
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
    pub computed: Option<u32>, // code target of another indirect call/jump, from the local fold
    pub refs: Vec<u32>,      // data references: constant addresses inside the image
    pub code_imms: Vec<u32>, // immediates that point into an executable section
}

/// A value of the local fold: a constant, or what a 4-byte register held where the fold
/// began (or before the last call that clobbered it) plus an offset, as Ghidra's
/// SymbolicPropogator keeps unknown registers as symbols.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Val {
    C(u32),
    S(u64, u32),
}

/// State of the local fold: (space, offset, size, value or unknown, computed rather than a
/// plain immediate) of registers and temporaries, and memory written through a folded
/// address (address, value or unknown, computed).
#[derive(Clone, Default)]
pub struct Fold {
    regs: Vec<(u32, u64, u32, Option<Val>, bool)>,
    mem: Vec<(Val, Option<Val>, bool)>,
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
    pub table_slots: BTreeMap<u32, u32>, // Create Address Tables (`disassemble` with constants): slot -> pointer
    fpu_ip: Option<(u32, u64)>,          // FPUInstructionPointer, which x87 constructors set to inst_start
    reg_space: u32,
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
            table_slots: BTreeMap::new(),
            fpu_ip: None,
            reg_space: 0,
        };
        let (rs, list) = sl.registers();
        an.fpu_ip = list.iter().find(|r| r.0 == "FPUInstructionPointer").map(|r| (rs, r.1));
        an.reg_space = rs;
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
            an.descend(img, sl, &mut p, &mut owner, &mut queue, &mut Vec::new());
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
                        an.descend(img, sl, &mut p, &mut owner, &mut queue, &mut Vec::new());
                    }
                }
            }
            if an.funcs.len() == before {
                if tables_queue.is_empty() {
                    break;
                }
                // after everything the seeds reach, so stray pointers cannot claim their bytes
                queue.append(&mut tables_queue);
                an.descend(img, sl, &mut p, &mut owner, &mut queue, &mut Vec::new());
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
                        // a JMP [slot] thunk to a non-returning import does not return either
                        i.flow == Flow::Return
                            || i.flow == Flow::JumpInd && !an.tables.contains_key(a) && !i.slot.is_some_and(|s| an.noreturn.contains(&s))
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

    fn decode(&self, img: &Image, sl: &Sleigh, p: &mut crate::sleigh::Parse, a: u32, fold: &mut Fold) -> Option<Ins> {
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
        let (mut refs, mut code_imms) = (Vec::new(), Vec::new());
        // Local constant fold (a stand-in for Ghidra's constant propagation): 4-byte register
        // and temporary values from immediates, initialised memory, ADD/SUB/XOR/AND/OR. A
        // computed value (not a plain immediate) stored to memory that is code is a code
        // constant, e.g. SecuROM's `MOV EDI,[a]; XOR EDI,[b]; XCHG [ESP],EDI`.
        //
        // Unknown 4-byte registers are symbols (`Val::S`), and values stored through a folded
        // address are kept, as Ghidra's SymbolicPropogator does: `MOV [ESI],vtable; MOV
        // ECX,ESI; MOV EAX,[ECX]; MOV EDX,[EAX+0x14]; CALL EDX` gives a READ reference to the
        // slot vtable+0x14 and the call's target (Ghidra's COMPUTED_CALL reference). The fold
        // follows jumps (`descend` hands it to the target) and a call clobbers EAX/ECX/EDX/ESP.
        let (uniq, rs) = (sl.uniq_space(), self.reg_space);
        fold.regs.retain(|f| f.0 != uniq);
        let val = |v: &crate::sleigh::Varnode, fold: &Fold| -> Option<(Val, bool)> {
            let mem = |x: u32| match fold.mem.iter().find(|m| m.0 == Val::C(x)) {
                Some(m) => m.1.map(|v| (v, m.2)),
                None => img.read_u32(x).map(|x| (Val::C(x), true)),
            };
            match v.space {
                0 => Some((Val::C(v.offset as u32), false)),
                s if s == code => (v.size == 4).then(|| mem(v.offset as u32)).flatten(),
                s => match fold.regs.iter().find(|f| f.0 == s && f.1 < v.offset + v.size as u64 && v.offset < f.1 + f.2 as u64) {
                    Some(f) if f.1 == v.offset && f.2 == v.size => f.3.map(|x| (x, f.4)),
                    None if s == rs && v.size == 4 => Some((Val::S(v.offset, 0), false)),
                    _ => None,
                },
            }
        };
        let load = |p: Val, fold: &Fold| -> Option<(Val, bool)> {
            match p {
                Val::C(x) => val(&crate::sleigh::Varnode { space: code, offset: x as u64, size: 4 }, fold),
                s => fold.mem.iter().find(|m| m.0 == s).and_then(|m| m.1.map(|v| (v, m.2))),
            }
        };
        let in_image = |x: u32| img.block_of(x).is_some();
        // ponytail: at most 16 stack stores (ESP-relative) and 64 others, the newest; Ghidra
        // keeps all. A map would lift the cap but costs more to copy at every jump.
        let stack = fold.mem.iter().filter(|m| matches!(m.0, Val::S(0x10, _))).count();
        if stack > 16 {
            let old = fold.mem.iter().position(|m| matches!(m.0, Val::S(0x10, _))).unwrap();
            fold.mem.remove(old);
        }
        if fold.mem.len() - stack.min(16) > 64 {
            let old = fold.mem.iter().position(|m| !matches!(m.0, Val::S(0x10, _))).unwrap();
            fold.mem.remove(old);
        }
        let mut computed = None;
        for op in &ops {
            if op.opc == 3 {
                let v = op.ins.get(2).and_then(|v| val(v, fold));
                if let Some((Val::C(x), true)) = v {
                    if self.is_code(img, x) && !code_imms.contains(&x) {
                        code_imms.push(x);
                    }
                }
                if let Some((p, _)) = op.ins.get(1).and_then(|v| val(v, fold)) {
                    if let Val::C(x) = p {
                        if in_image(x) && !refs.contains(&x) {
                            refs.push(x); // WRITE reference through a folded address
                        }
                    }
                    fold.mem.retain(|m| m.0 != p);
                    let size4 = op.ins.get(2).is_some_and(|v| v.size == 4);
                    fold.mem.push((p, v.filter(|_| size4).map(|v| v.0), v.is_some_and(|v| v.1)));
                }
            }
            if let Some(o) = op.out.as_ref() {
                let r = match (op.opc, op.ins.as_slice()) {
                    (1, [x]) if o.size == 4 => val(x, fold),
                    (2, [_, x]) if o.size == 4 => val(x, fold).and_then(|(p, _)| {
                        if let Val::C(x) = p {
                            if in_image(x) && !refs.contains(&x) {
                                refs.push(x); // READ reference through a folded address
                            }
                        }
                        load(p, fold).map(|(v, _)| (v, true))
                    }),
                    (19 | 20 | 26 | 27 | 28, [x, y]) if o.size == 4 => val(x, fold).zip(val(y, fold)).and_then(|((x, _), (y, _))| {
                        let r = match (op.opc, x, y) {
                            (_, Val::C(x), Val::C(y)) => Val::C(match op.opc {
                                19 => x.wrapping_add(y),
                                20 => x.wrapping_sub(y),
                                26 => x ^ y,
                                27 => x & y,
                                _ => x | y,
                            }),
                            (19, Val::S(b, d), Val::C(c)) | (19, Val::C(c), Val::S(b, d)) => Val::S(b, d.wrapping_add(c)),
                            (20, Val::S(b, d), Val::C(c)) => Val::S(b, d.wrapping_sub(c)),
                            _ => return None,
                        };
                        Some((r, true))
                    }),
                    _ => None,
                };
                if o.space == code {
                    // a direct store, `MOV [g],reg`
                    let p = Val::C(o.offset as u32);
                    fold.mem.retain(|m| m.0 != p);
                    fold.mem.push((p, r.map(|r| r.0), r.is_some_and(|r| r.1)));
                } else {
                    let end = o.offset + o.size as u64;
                    fold.regs.retain(|f| f.0 != o.space || f.1 >= end || f.1 + f.2 as u64 <= o.offset);
                    fold.regs.push((o.space, o.offset, o.size, r.map(|r| r.0), r.is_some_and(|r| r.1)));
                }
            }
            if matches!(op.opc, 6 | 8) && op.ins[0].space != code {
                if let Some((Val::C(t), _)) = val(&op.ins[0], fold) {
                    computed = Some(t).filter(|&t| self.is_code(img, t));
                }
            }
            if matches!(op.opc, 7 | 8) {
                // EAX, ECX, EDX and ESP (offsets 0, 4, 8, 0x10) are the callee's, flags too: each
                // becomes a new symbol of this call, which aliases nothing stored before it
                // (ponytail: ESP loses its stack offset; Ghidra adds the callee's purge)
                fold.regs.retain(|f| f.0 != rs || (f.1 >= 0xc && f.1 < 0x10) || (f.1 >= 0x14 && f.1 < 0x200));
                for r in [0u64, 4, 8, 0x10] {
                    fold.regs.push((rs, r, 4, Some(Val::S(1 << 40 | (a as u64) << 8 | r, 0)), false));
                }
            }
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
                    // (CALL copies the slot to a temporary first, since it pushes the return)
                    let mut v = &op.ins[0];
                    if let Some(c) = ops.iter().rev().find(|c| c.opc == 1 && c.out.as_ref().is_some_and(|o| o == v)) {
                        v = &c.ins[0];
                    }
                    slot = (v.space == code).then_some(v.offset as u32);
                }
                10 => flow = Flow::Return,
                _ => {}
            }
            // data references: direct memory operands (ram varnodes), not flow targets
            let skip = usize::from(matches!(op.opc, 4 | 5 | 7));
            // x87 constructors copy inst_start into FPUInstructionPointer: not a reference
            let fpu_ip = op.out.as_ref().is_some_and(|o| Some((o.space, o.offset)) == self.fpu_ip);
            for v in op.ins.iter().skip(skip).chain(op.out.as_ref()) {
                // e.g. PUSH offset callback (not CALL's pushed return address)
                let imm = v.offset as u32;
                if v.space == 0 && v.size == 4 && v.offset != next && !fpu_ip && self.is_code(img, imm) && !code_imms.contains(&imm) {
                    code_imms.push(imm);
                }
                let is_ref = match v.space {
                    0 => v.size == 4 && img.block_of(v.offset as u32).is_some_and(|s| !s.exec), // immediate pointing at data
                    s => s == code && img.block_of(v.offset as u32).is_some(),
                };
                if is_ref && !refs.contains(&(v.offset as u32)) {
                    refs.push(v.offset as u32);
                }
            }
        }
        let computed = computed.filter(|_| slot.is_none());
        Some(Ins { len: len as u8, flow, target, slot, computed, refs, code_imms })
    }

    /// Ghidra's `disassemble(addr)` after analysis: recursive descent from `addrs` into bytes no
    /// code covers yet, without making functions. With `constants`, also the code Ghidra's
    /// analysis decodes beyond the function bodies, which reference checks see: code reached
    /// through code constants (`PUSH offset callback`, `MOV [g],offset fn`, SecuROM's
    /// `PUSH next; PUSH callee; RET`, values the local fold computes) where `valid_subroutine`
    /// accepts them, and the entries of address tables of code (`address_tables`), repeated
    /// over what that reaches. Bodies stay as they are.
    pub fn disassemble(&mut self, img: &Image, sl: &Sleigh, addrs: &[u32], constants: bool) {
        let mut owner = vec![0u8; (self.code_hi - self.code_lo) as usize];
        for (&a, i) in &self.insns {
            let o = (a - self.code_lo) as usize;
            owner[o] = 1;
            owner[o + 1..o + i.len as usize].fill(2);
        }
        let funcs = self.funcs.clone();
        let mut queue: Vec<u32> = addrs.iter().copied().filter(|&a| self.is_code(img, a)).collect();
        let mut p = sl.new_parse();
        let mut log: Vec<u32> = if constants { self.insns.keys().copied().collect() } else { Vec::new() };
        self.descend(img, sl, &mut p, &mut owner, &mut queue, &mut log);
        let mut checked = HashSet::new(); // targets asked once, as Ghidra's checkedTargets
        while constants && !log.is_empty() {
            let mut queue: Vec<u32> = Vec::new();
            for t in log.iter().flat_map(|a| self.insns[a].code_imms.iter().copied()).collect::<Vec<_>>() {
                if owner[(t - self.code_lo) as usize] == 0 && checked.insert(t) && self.valid_subroutine(img, sl, &mut p, &owner, t) {
                    queue.push(t);
                }
            }
            log.clear();
            self.descend(img, sl, &mut p, &mut owner, &mut queue, &mut log);
            if log.is_empty() {
                // Create Address Tables over what is still undefined; tables of code are
                // disassembled, and what that reaches is checked for code constants again.
                let mut queue = self.address_tables(img, &owner);
                queue.retain(|&t| owner[(t - self.code_lo) as usize] == 0);
                self.descend(img, sl, &mut p, &mut owner, &mut queue, &mut log);
            }
        }
        self.funcs = funcs;
    }

    /// PseudoDisassembler.isValidSubroutine(entry, false), which Ghidra asks before it
    /// disassembles at a code constant ("Found code from operand reference"): the flow from
    /// `entry` (not into calls, nor jumps to functions) decodes without a bad instruction, runs
    /// into no existing code, jumps only to instruction starts, never branches conditionally
    /// to its own fallthrough, and returns, jumps through a register or reaches a function;
    /// a single instruction must reach a function. Not modelled: references into the body.
    fn valid_subroutine(&self, img: &Image, sl: &Sleigh, p: &mut crate::sleigh::Parse, owner: &[u8], entry: u32) -> bool {
        if img.read_u32(entry) == Some(0) && img.read_u32(entry + 4) == Some(0) {
            return false;
        }
        let (mut body, mut targets) = (BTreeMap::new(), Vec::new());
        let (mut terminated, mut called) = (false, false);
        let mut work = vec![entry];
        let mut fold = Fold::default();
        while let Some(mut a) = work.pop() {
            while body.len() < 4000 && !body.contains_key(&a) {
                if !self.is_code(img, a) {
                    return false;
                }
                let Some(i) = self.decode(img, sl, p, a, &mut fold) else { return false };
                let o = (a - self.code_lo) as usize;
                if owner.get(o..o + i.len as usize).is_none_or(|b| b.iter().any(|&b| b != 0)) {
                    return false;
                }
                body.insert(a, i.len);
                let next = a + i.len as u32;
                match (i.flow, i.target) {
                    (Flow::Return, _) | (Flow::JumpInd, _) => terminated = true,
                    (Flow::Call, Some(t)) => {
                        called |= self.funcs.contains(&t);
                        if self.noreturn.contains(&t) {
                            break;
                        }
                    }
                    (Flow::CondJump, Some(t)) if t == next => return false,
                    (Flow::Jump | Flow::CondJump, Some(t)) if self.funcs.contains(&t) => called = true,
                    (Flow::Jump | Flow::CondJump, Some(t)) => {
                        targets.push(t);
                        work.push(t);
                    }
                    _ => {}
                }
                if !i.falls_through() {
                    break;
                }
                a = next;
            }
        }
        let start_of = |t: u32| body.range(..=t).next_back().map(|(&s, &l)| (s, t < s + l as u32));
        if targets.iter().any(|&t| matches!(start_of(t), Some((s, true)) if s != t)) {
            return false; // a jump into the middle of an instruction of the body
        }
        (terminated || called) && (called || body.len() > 1)
    }

    /// Ghidra's Create Address Tables analyzer (AddressTableAnalyzer, AddressTable.getEntry and
    /// checkTable) over the bytes no instruction covers, in every section: runs of at least
    /// `getThresholdRunOfValidPointers` (one in a billion by chance) 4-aligned words that are
    /// addresses (not 0, not below 1024), cut by a reference into the run (after its second
    /// word, or before its end), the next instruction, a pointer into the middle of an
    /// instruction or to an instruction something falls into, a UTF-16 string, or a jump of
    /// more than 0xffffff between neighbours (which drops that entry). Adds the slots to
    /// `table_slots` and returns the entries of tables whose entries are all code.
    /// Not modelled: Ghidra's defined data (strings, structures) and its order of analysis.
    pub fn address_tables(&mut self, img: &Image, owner: &[u8]) -> Vec<u32> {
        let undefined = |a: u32| !self.is_code(img, a) || owner[(a - self.code_lo) as usize] == 0;
        let bytes: f64 = img.sections.iter().map(|s| s.data.len() as f64).sum();
        let min = ((1e-9f64).ln() / (bytes / 2f64.powi(32)).ln()).ceil().max(2.0) as usize;
        // Reference destinations in undefined bytes (anything else is past the next instruction).
        let mut refs: BTreeSet<u32> = BTreeSet::new();
        for i in self.insns.values() {
            refs.extend(i.refs.iter().chain(&i.code_imms).chain(&i.target).copied().filter(|&t| undefined(t)));
        }
        for c in self.tables.values() {
            refs.extend(c.iter().copied().filter(|&t| undefined(t)));
        }
        let collides = |t: u32| {
            self.is_code(img, t)
                && match owner[(t - self.code_lo) as usize] {
                    2 => true, // into the middle of an instruction
                    1 => self.insns.range(..t).next_back().is_some_and(|(&a, i)| {
                        a + i.len as u32 == t
                            && i.falls_through()
                            && !(i.flow == Flow::Call && i.target.is_some_and(|t| self.noreturn.contains(&t)))
                    }),
                    _ => false,
                }
        };
        let (mut code, mut slots) = (Vec::new(), Vec::new());
        for s in &img.sections {
            let end = s.addr + s.data.len() as u32;
            let word = |a: u32| u32::from_le_bytes(s.data[(a - s.addr) as usize..][..4].try_into().unwrap());
            let mut top = s.addr;
            while top + 4 <= end {
                if !undefined(top) {
                    top += 4;
                    continue;
                }
                // getEntry
                let mut elems: Vec<u32> = Vec::new();
                let mut cur = top;
                while cur + 4 <= end {
                    let v = word(cur);
                    if v < 1024 || img.block_of(v).is_none() || (elems.len() > 1 && refs.contains(&cur)) || collides(v) {
                        break;
                    }
                    elems.push(v);
                    cur += 4;
                }
                let mut count = elems.len();
                if count >= min {
                    let stop = refs.range(top + 1..top + 4 * count as u32).next().copied();
                    let stop = stop.into_iter().chain((top..top + 4 * count as u32).find(|&a| !undefined(a)));
                    if let Some(at) = stop.min() {
                        count = count.min(((at - top) / 4) as usize);
                    }
                }
                if count < min {
                    top += 4;
                    continue;
                }
                elems.truncate(count);
                // processAddressTable: checkTable, make the table, carry on one entry past it
                let mut first = 0;
                while first < count {
                    let at = |i: usize| top + 4 * i as u32;
                    let strings = utf16_strings(s, at(first), at(count));
                    let mut len = 0;
                    for i in first..count {
                        let offcut = self.is_code(img, elems[i]) && owner[(elems[i] - self.code_lo) as usize] == 2;
                        let far = i > first && elems[i - 1].abs_diff(elems[i]) > 0xff_ffff;
                        if strings.iter().any(|r| r.contains(&at(i)) || r.contains(&(at(i) + 3))) || far || offcut {
                            break;
                        }
                        len += 1;
                    }
                    if len >= min {
                        let t = &elems[first..first + len];
                        for (i, &v) in t.iter().enumerate() {
                            slots.push((at(first + i), v));
                            if undefined(v) {
                                refs.insert(v);
                            }
                        }
                        // ponytail: "valid code" is "in an executable section"; Ghidra pseudo-disassembles
                        if t.iter().all(|&v| self.is_code(img, v)) {
                            code.extend(t);
                        }
                    }
                    first += len + 1;
                }
                top += 4 * count as u32;
            }
        }
        self.table_slots.extend(slots);
        code
    }

    /// Recursive descent from every queued address. Call targets in .text become functions.
    fn descend(&mut self, img: &Image, sl: &Sleigh, p: &mut crate::sleigh::Parse, owner: &mut [u8], queue: &mut Vec<u32>, log: &mut Vec<u32>) {
        let mut pending: HashMap<u32, Fold> = HashMap::new();
        while let Some(start) = queue.pop() {
            let mut a = start;
            let mut recent: Vec<u32> = Vec::new(); // straight-line history, for switch bounds
            // the fold of the first jump that reached `start` (Ghidra: first flow wins)
            let mut fold = pending.remove(&start).unwrap_or_default();
            while self.is_code(img, a) && owner[(a - self.code_lo) as usize] == 0 {
                let Some(ins) = self.decode(img, sl, p, a, &mut fold) else { break };
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
                    if ins.flow != Flow::Call {
                        if owner[(t - self.code_lo) as usize] == 0 {
                            pending.entry(t).or_insert_with(|| fold.clone());
                        }
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
                log.push(a);
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

    /// The function a call references, as Ghidra's `getCalledFunctions` counts it: a direct
    /// CALL; a JMP to a function entry (Shared Return Calls makes it a call; counting these
    /// matches Ghidra better than not, though Ghidra leaves some as jumps, e.g. 0x72cc00);
    /// `CALL [slot]` through an import slot (the slot stands for the external function);
    /// `CALL [global]` whose initial value is a function entry.
    pub fn call_target(&self, img: &Image, i: &Ins) -> Option<u32> {
        match (i.flow, i.slot) {
            (Flow::Call | Flow::Jump, _) => i.target.filter(|t| self.funcs.contains(t)),
            (Flow::CallInd, Some(s)) if img.imports.contains_key(&s) => Some(s),
            (Flow::CallInd, Some(s)) => img.read_u32(s).filter(|t| self.funcs.contains(t)),
            _ => None,
        }
    }

    pub fn body_size(&self, f: u32) -> u64 {
        self.bodies[&f].iter().map(|a| self.insns[a].len as u64).sum()
    }
}

/// AddressTableAnalyzer.findPossibleStrings over `[from, to)`: the ranges of UTF-16 strings
/// longer than 4 characters (tab, CR, LF and 0x20..0x7e, up to a 0 or half the range).
fn utf16_strings(s: &Section, from: u32, to: u32) -> Vec<std::ops::RangeInclusive<u32>> {
    let max = (to - from) / 2;
    let short = |a: u32| s.data.get((a - s.addr) as usize..(a - s.addr) as usize + 2).map(|b| u16::from_le_bytes([b[0], b[1]]));
    let mut out = Vec::new();
    let mut a = from;
    while a < to {
        let mut n = 0;
        while n < max {
            match short(a + 2 * n) {
                Some(0) => {
                    n += 1;
                    break;
                }
                Some(9 | 10 | 13 | 0x20..=0x7e) => n += 1,
                _ => break,
            }
        }
        if n > 4 {
            out.push(a..=a + 2 * n);
            a += 2 * n;
        } else {
            a += 1;
        }
    }
    out
}
