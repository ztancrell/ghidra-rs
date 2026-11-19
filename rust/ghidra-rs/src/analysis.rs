//! Function discovery, bodies                 Task::SharedReturns => an.shared_returns(&set),nd references for 32-bit x86 PE images, modelled on what
//! Ghidra's auto-analysis produces for the scripts in `main.rs` (ExportFunctions, ExportGaps).
//! Every executable section is disassembled; results are reported for `.text`. See rust/README.md "Analysis" for what is and isn't covered.

use crate::queue::{priority, Analyzer, Kind, Manager};
use crate::sleigh::Sleigh;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

pub struct Section {
    pub name: String,
    pub exec: bool,
    /// not writable (no `IMAGE_SCN_MEM_WRITE`): bfd's `SEC_READONLY`, which the decompiler reads as constant
    pub readonly: bool,
    /// how many bytes at the end of `data` lie past the section as bfd loads it (its `size`: the
    /// raw size when that is smaller than the virtual size, else the virtual size), which the
    /// decompiler treats as unmapped (`LoadImageBfd`)
    pub zero_tail: u32,
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
        img.sections.push(Section {
            name: "Headers".into(),
            exec: false,
            readonly: false, // not a section of the file, so not in bfd's list
            zero_tail: 0,
            addr: base,
            data: bytes[..hdr.min(bytes.len())].to_vec(),
        });
        for s in pe.section_table().iter() {
            let name = String::from_utf8_lossy(s.raw_name()).trim_end_matches('\0').to_string();
            let mut data = s.pe_data(bytes).map_err(|e| e.to_string())?.to_vec();
            data.resize(s.virtual_size.get(LE) as usize, 0);
            let exec =
                s.characteristics.get(LE) & (object::pe::IMAGE_SCN_CNT_CODE | object::pe::IMAGE_SCN_MEM_EXECUTE) != 0;
            let flags = s.characteristics.get(LE);
            let readonly = flags & object::pe::IMAGE_SCN_MEM_WRITE == 0;
            // bfd (_bfd_XXi_swap_scnhdr_in) takes the virtual size when the raw size is larger, or
            // for uninitialized data without raw bytes; else the raw size
            let (raw, virt) = (s.size_of_raw_data.get(LE), s.virtual_size.get(LE));
            let uninit = flags & object::pe::IMAGE_SCN_CNT_UNINITIALIZED_DATA != 0;
            let bfd_size = if raw > virt || uninit && raw == 0 { virt } else { raw };
            let zero_tail = virt.saturating_sub(bfd_size);
            let addr = base + s.virtual_address.get(LE);
            img.sections.push(Section { name, exec, readonly, zero_tail, addr, data });
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
        // A zero directory means no imports; otherwise the table ends at an all-zero descriptor.
        let mut d = base + dir;
        while dir != 0 && d < base + dir + 20 * 0x10000 {
            let f = |i: u32| img.read_u32(d + 4 * i).unwrap_or(0);
            let (orig, name, first) = (f(0), f(3), f(4));
            if name == 0 || first == 0 {
                break;
            }
            let lib = img.c_string(base + name).to_uppercase();
            let mut i = 0;
            let names = if orig != 0 { orig } else { first };
            while let Some(th) = img.read_u32(base + names + 4 * i).filter(|&t| t != 0) {
                let name = if th & 0x8000_0000 != 0 {
                    format!("Ordinal_{}", th & 0xffff)
                } else {
                    img.c_string(base + th + 2)
                };
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
    pub target: Option<u32>,   // direct flow target
    pub slot: Option<u32>,     // memory operand of an indirect call/jump through a constant address
    pub computed: Option<u32>, // code target of another indirect call/jump, from the local fold
    pub refs: Vec<u32>,        // data references: constant addresses inside the image
    pub code_imms: Vec<u32>,   // immediates that point into an executable section
}

/// The references `Analysis::disassemble` goes by: every destination, and the destinations in
/// executable blocks that a memory operand reads or writes (Ghidra's READ and WRITE references).
#[derive(Default)]
struct Refs {
    dests: BTreeSet<u32>,
    reads: HashSet<u32>,
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
    whole: bool, // a whole-function walk (`propagate`): keeps more memory
    /// the stack slots the last instruction read or wrote through a folded address: (offset
    /// from ESP at the entry, bytes, written)
    pub stack: Vec<(u32, u32, bool)>,
    /// bytes of the last LOAD or STORE of the last instruction, 0 without one
    pub mem_size: u32,
    /// the memory the last instruction read or wrote through an address the fold knows (a
    /// constant a register holds): (address, bytes, written)
    pub data: Vec<(u32, u32, bool)>,
    /// `AND ESP,mask` keeps a stack address (the mask applies to its offset), as Ghidra's
    /// stack analysis has it; off for the walks of `propagate`
    stack_and: bool,
}

impl Fold {
    /// The offset from ESP at the entry that the 4-byte register at `reg` of the register
    /// space `rs` holds, where it holds a stack address.
    pub fn stack_offset(&self, rs: u32, reg: u64) -> Option<u32> {
        match self.regs.iter().find(|f| f.0 == rs && f.1 < reg + 4 && reg < f.1 + f.2 as u64) {
            Some(&(_, at, 4, Some(Val::S(0x10, d)), _)) if at == reg => Some(d),
            Some(_) => None,
            None => (reg == 0x10).then_some(0),
        }
    }
}

impl Ins {
    pub fn falls_through(&self) -> bool {
        !matches!(self.flow, Flow::Jump | Flow::JumpInd | Flow::Return)
    }
}

#[derive(Clone)]
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
    purge: HashMap<u32, u32>,            // function -> bytes its RETs pop (RET n), where they agree
    /// The purge X86 Function Callee Purge set, by function (`callee_purge`); none is unknown.
    pub callee_purges: HashMap<u32, u32>,
    reg_space: u32,
    /// Flow overrides of the project store (`store.rs`), by instruction: CALL_RETURN (true) or
    /// none (false) in place of what `call_return` derives. Empty without a store.
    pub overrides: HashMap<u32, bool>,
    /// Bodies the store sets (inclusive address ranges) in place of the flow from the entry.
    pub fixed_bodies: BTreeMap<u32, Vec<(u32, u32)>>,
    /// Thunk marks of the store: the thunked function, or `None` for "not a thunk".
    pub thunks: HashMap<u32, Option<u32>>,
    /// The thunks CreateFunctionCmd made (`resolve_thunk`): thunk -> thunked function.
    pub thunk_of: BTreeMap<u32, u32>,
    /// During `run`: the function whose body holds each instruction (Ghidra's bodies do not
    /// overlap); emptied when `run` ends.
    body_owner: HashMap<u32, u32>,
    /// What `run` met that is not ported, one line each, for the caller to print.
    pub warnings: Vec<String>,
}

const MAX_STACK: [usize; 2] = [16, 1024]; // local fold, whole-function walk
const MAX_MEM: [usize; 2] = [64, 1024];

const KNOWN_NORETURN: [&str; 9] = [
    "ExitProcess",
    "ExitThread",
    "exit",
    "_exit",
    "abort",
    "_amsg_exit",
    "RaiseException",
    "_CxxThrowException",
    "FatalAppExitA",
];

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
const POST_FILL: [Pat; 19] = [
    &[(0x55, 0xff), (0x8b, 0xff), (0xec, 0xff)],
    &[(0x55, 0xff), (0x89, 0xff), (0xe5, 0xff)],
    &[(0x83, 0xff), (0xec, 0xff), (0x00, 0x83)],
    &[
        (0x6a, 0xff),
        (0xff, 0xff),
        (0x68, 0xff),
        (0, 0),
        (0, 0),
        (0, 0),
        (0, 0),
        (0x64, 0xff),
        (0xa1, 0xff),
        (0, 0xff),
        (0, 0xff),
        (0, 0xff),
        (0, 0xff),
    ],
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
    &[(0x55, 0xff), (0x57, 0xff), (0x56, 0xff), (0x53, 0xff)],
];
const POST_JMP: [Pat; 4] = [POST_FILL[0], POST_FILL[4], POST_FILL[5], POST_FILL[6]];

fn matches(bytes: &[u8], pat: Pat) -> bool {
    bytes.len() >= pat.len() && pat.iter().zip(bytes).all(|(&(v, m), &b)| b & m == v & m)
}

/// PatternPairSet.createFinalPatterns: a prepattern/postpattern pair of `<patternpairs
/// totalbits="32" postbits="16">` is a pattern only when the postpattern has 16 fixed bits and
/// both together 32 (`getNumFixedBits`); e.g. `CC` + `SUB ESP,small` (8 + 19 bits) is none.
/// True when such a pair matches with the postpattern at `d[o]`.
fn pair_hit(d: &[u8], o: usize, pres: &[Pat], posts: &[Pat]) -> bool {
    let bits = |p: Pat| p.iter().map(|&(_, m)| m.count_ones()).sum::<u32>();
    pres.iter().filter(|p| o >= p.len() && matches(&d[o - p.len()..o], p)).any(|&pre| {
        posts.iter().any(|&post| bits(post) >= 16 && bits(pre) + bits(post) >= 32 && matches(&d[o..], post))
    })
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
            purge: HashMap::new(),
            callee_purges: HashMap::new(),
            reg_space: 0,
            overrides: HashMap::new(),
            fixed_bodies: BTreeMap::new(),
            thunks: HashMap::new(),
            thunk_of: BTreeMap::new(),
            body_owner: HashMap::new(),
            warnings: Vec::new(),
        };
        let (rs, list) = sl.registers();
        an.fpu_ip = list.iter().find(|r| r.0 == "FPUInstructionPointer").map(|r| (rs, r.1));
        an.reg_space = rs;
        for (slot, (_, name)) in &img.imports {
            if KNOWN_NORETURN.contains(&name.as_str()) {
                an.noreturn.insert(*slot);
            }
        }
        let mut seeds: Vec<u32> =
            img.exports.iter().map(|e| e.0).chain(img.entry).chain(extra.iter().copied()).collect();
        seeds.retain(|&a| an.is_code(img, a));
        // RTTI vftable slots: the RTTI analyzer (599) makes a function of each
        // (`EHDataTypeUtilities.createFunctionIfNeeded`)
        let mut rtti = Vec::new();
        let tables = crate::scripts::vftables(img);
        for &v in tables.keys() {
            for i in 0..4096 {
                match img.read_u32(v + 4 * i) {
                    Some(t) if an.is_code(img, t) && (i == 0 || !tables.contains_key(&(v + 4 * i))) => rtti.push(t),
                    _ => break,
                }
            }
        }
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
        // Discovery's analyzers, run by Ghidra's task queue at Ghidra's priorities. Disassembly
        // and Subroutine References (a function at each call target) are `descend`, inside the
        // analyzer that brings the code.
        #[derive(Clone, Copy)]
        enum Task {
            EntryPoints,
            StartSearch,
            Rtti,
            AddressTables,
            StartSearchAfterData,
            SharedReturns,
            Purge,
        }
        let analyzer = |name, kind, priority, id| Analyzer { name, kind, priority, id };
        let mut mgr = Manager::new(vec![
            // Not Java's analyzers, the old discovery at their priorities (to port):
            // - Disassemble Entry Points: EntryPointAnalyzer's do-later set (suspect entries,
            //   REFERENCE_ANALYSIS.before()) is not modelled; all seeds go in at 200.
            // - Function Start Search (402): one search, disassembly inline, skipping covered
            //   bytes and repeating until nothing is new; Java searches once and queues
            //   DisassembleCommand and CreateFunctionCmd at priority - 2 and - 1.
            // - Function Start Search After Data (898): the same full sweep, ignoring its set;
            //   Java's FunctionStartDataPostAnalyzer searches only the added data for the
            //   after="data" patterns, and its notify set here is the table targets, not new data.
            // with External Entry References: the seeds
            analyzer("Disassemble Entry Points", Kind::Byte, priority::BLOCK_ANALYSIS, Task::EntryPoints),
            analyzer("Function Start Search", Kind::Byte, priority::CODE_ANALYSIS + 2, Task::StartSearch),
            analyzer("RTTI Analyzer", Kind::Byte, priority::REFERENCE_ANALYSIS - 1, Task::Rtti),
            analyzer("Create Address Tables", Kind::Byte, priority::DATA_TYPE_PROPOGATION - 1, Task::AddressTables),
            analyzer(
                "Function Start Search After Data",
                Kind::Data,
                priority::DATA_TYPE_PROPOGATION - 2,
                Task::StartSearchAfterData,
            ),
            // CODE_ANALYSIS.before().before(): on each batch of functions added or with a changed body
            analyzer("Shared Return Calls", Kind::Function, priority::CODE_ANALYSIS - 2, Task::SharedReturns),
            analyzer("X86 Function Callee Purge", Kind::Function, priority::FUNCTION_ANALYSIS, Task::Purge),
        ]);
        mgr.notify(Kind::Byte, &exec().map(|s| s.addr).collect());
        // with `exact`, only the given functions are made (CreateFunctionCmd)
        let allowed: Option<HashSet<u32>> = exact.then(|| extra.iter().copied().collect());
        // the non-returning functions the bodies go by (FindNoReturnFunctionsAnalyzer's side);
        // discovery's disassembly goes by `an.noreturn`, the imports'
        let mut body_noreturn = an.noreturn.clone();
        while let Some((task, set)) = mgr.next_task() {
            let mut data = BTreeSet::new();
            match task {
                Task::EntryPoints => {
                    for &s in &seeds {
                        an.funcs.insert(s);
                        queue.push(s);
                    }
                    an.descend(img, sl, &mut p, &mut owner, &mut queue, &mut Vec::new());
                }
                Task::Rtti => {
                    for &s in &rtti {
                        an.funcs.insert(s);
                        queue.push(s);
                    }
                    an.descend(img, sl, &mut p, &mut owner, &mut queue, &mut Vec::new());
                }
                // the tables come after everything the seeds reach, so stray pointers cannot
                // claim their bytes
                Task::AddressTables => {
                    data.extend(&tables_queue);
                    queue.append(&mut tables_queue);
                    an.descend(img, sl, &mut p, &mut owner, &mut queue, &mut Vec::new());
                }
                Task::StartSearch | Task::StartSearchAfterData => {
                    an.start_search(img, sl, &mut p, &mut owner, &mut queue)
                }
                Task::SharedReturns => an.shared_returns(&set),
                Task::Purge => an.callee_purge(img, &set, &body_noreturn),
            }
            mgr.notify(Kind::Data, &data);
            // CreateFunctionCmd on the functions the task found, in address order, then the
            // no-return repairs. AutoAnalysisManager sends FUNCTION_ADDED and
            // FUNCTION_BODY_CHANGED alike to functionDefined: the function analyzers get the
            // functions made and the ones whose body was set (the purge sets none)
            if !matches!(task, Task::Purge) {
                let known = std::mem::replace(&mut an.noreturn, std::mem::take(&mut body_noreturn));
                let mut defined = BTreeSet::new();
                let new: Vec<u32> = an.funcs.iter().copied().filter(|f| !an.bodies.contains_key(f)).collect();
                for f in new {
                    an.create_function(f, allowed.as_ref(), &mut Vec::new(), &mut defined);
                }
                an.find_noreturn(&mut defined);
                body_noreturn = std::mem::replace(&mut an.noreturn, known);
                mgr.notify(Kind::Function, &defined);
            }
        }
        if exact {
            an.funcs = extra.iter().copied().filter(|a| an.insns.contains_key(a)).collect();
            an.bodies.retain(|f, _| an.funcs.contains(f));
        }
        an.noreturn = body_noreturn;
        an.body_owner = HashMap::new();
        // a thunk's purge is its thunked function's (FunctionDB.getStackPurgeSize)
        let thunked: Vec<(u32, u32)> = an.thunk_of.keys().map(|&f| (f, an.thunked_end(f))).collect();
        for (f, t) in thunked {
            if let Some(&n) = an.callee_purges.get(&t) {
                an.callee_purges.insert(f, n);
            }
        }
        // two thunk definitions: the purges go by `thunk_of`, the facts' names and
        // `Project::thunked` by a body of one direct jump to a function
        let (only_made, only_one_jump) = an.bodies.iter().fold((0, 0), |(m, o), (&f, b)| {
            let one_jump = b.len() == 1
                && an.insns[&f].flow == Flow::Jump
                && an.insns[&f].target.is_some_and(|t| t != f && an.funcs.contains(&t));
            match (an.thunk_of.contains_key(&f), one_jump) {
                (true, false) => (m + 1, o),
                (false, true) => (m, o + 1),
                _ => (m, o),
            }
        });
        if only_made + only_one_jump > 0 {
            an.warnings.push(format!(
                "thunks disagree: {only_made} made by CreateFunctionCmd (thunk_of, the purges) are no one-jump body (the facts' names), {only_one_jump} one-jump bodies were not made thunks"
            ));
        }
        // getThunkedAddr steps over an entry instruction without p-code (`NOP; JMP x` is a thunk
        // of x); resolve_thunk does not. Counted for the one-byte NOP only
        let nop_thunks = an
            .bodies
            .keys()
            .filter(|&&f| {
                img.block_of(f).is_some_and(|s| s.data.get((f - s.addr) as usize) == Some(&0x90))
                    && an.insns.get(&(f + 1)).is_some_and(|i| i.flow == Flow::Jump)
            })
            .count();
        if nop_thunks > 0 {
            an.warnings.push(format!(
                "not ported: getThunkedAddr past a no-p-code entry instruction: {nop_thunks} functions start `NOP; JMP` and are no thunks here"
            ));
        }
        an.stack_purges(img);
        Ok(an)
    }

    /// X86 Function Callee Purge (`FunctionPurgeAnalysisCmd`) on the functions added or with a
    /// changed body since its last turn, in address order (`analyzeFunction`). Only a purge
    /// that is unknown (or past 128) is looked for; a thunk's purge is its thunked function's,
    /// read and set (`FunctionDB.getStackPurgeSize`). The purge instruction is searched in the
    /// body, else in the flow from the entry (`locatePurgeInstruction`); its value is the RET's
    /// operand, or for a CALL_RETURN flow the purge the function it reaches has at this moment
    /// (none for a non-returning one). `body_noreturn`: the non-returning functions the
    /// bodies go by.
    // ponytail: the non-returning functions are this analysis's rule on the bodies (Java's
    // analyzer runs at 302 with its own rule)
    fn callee_purge(&mut self, img: &Image, set: &BTreeSet<u32>, body_noreturn: &HashSet<u32>) {
        let known = std::mem::replace(&mut self.noreturn, body_noreturn.clone());
        for &f in set.iter().filter(|f| self.bodies.contains_key(f)) {
            let at = self.thunked_end(f);
            if self.callee_purges.get(&at).is_some_and(|&n| n <= 128) {
                continue;
            }
            let found = self.purge_insn(img, &self.bodies[&f]).or_else(|| {
                let flow = self.walk(f, |a| self.bodies.contains_key(&a));
                self.purge_insn(img, &flow)
            });
            if let Some(n) = found.and_then(|(a, n)| n.or_else(|| self.call_purge(a))) {
                self.callee_purges.insert(at, n);
            }
        }
        self.noreturn = known;
    }

    /// findPurgeInstruction: the first RET or RETF of `body` by address, among its first 2048
    /// instructions, with its operand; else the last CALL_RETURN flow (CALL_TERMINATOR or
    /// COMPUTED_CALL_TERMINATOR), without a value.
    fn purge_insn(&self, img: &Image, body: &[u32]) -> Option<(u32, Option<u32>)> {
        let mut backup = None;
        for &a in body.iter().take(2048) {
            let i = &self.insns[&a];
            if i.flow == Flow::Return {
                let sec = img.block_of(a)?;
                let b = &sec.data[(a - sec.addr) as usize..];
                let b = &b[b.iter().take_while(|&&x| matches!(x, 0xf2 | 0xf3 | 0x66)).count()..];
                // an IRET is no "ret" or "retf": the search goes on
                match b {
                    [0xc2 | 0xca, lo, hi, ..] => return Some((a, Some(u16::from_le_bytes([*lo, *hi]) as u32))),
                    [0xc3 | 0xcb, ..] => return Some((a, Some(0))),
                    _ => continue,
                }
            }
            if matches!(i.flow, Flow::Jump | Flow::Call | Flow::CallInd | Flow::JumpInd) && self.call_return(a, i) {
                backup = Some((a, None));
            }
        }
        backup
    }

    /// getPurgeValue of a CALL_RETURN flow: the purge of the function at its target, unless
    /// that function does not return.
    fn call_purge(&self, a: u32) -> Option<u32> {
        let t = self.insns[&a].target.filter(|t| self.bodies.contains_key(t) && !self.noreturn.contains(t))?;
        self.callee_purges.get(&self.thunked_end(t)).copied()
    }

    /// The function a chain of thunks made by `resolve_thunk` ends at (`f` itself if none).
    fn thunked_end(&self, mut f: u32) -> u32 {
        for _ in 0..16 {
            match self.thunk_of.get(&f) {
                Some(&t) => f = t,
                None => break,
            }
        }
        f
    }

    /// CreateFunctionCmd at `f`, a function with an instruction and no body yet: the flow from
    /// the entry up to the entries of the functions made so far (getFunctionBody), less what
    /// other bodies hold (subtractBodyFromExisting, which also cuts those bodies), made a thunk
    /// where the entry is a jump (resolveThunk); once more when the thunk's target, made
    /// meanwhile, overlaps the body (OverlappingFunctionException). `referring`: the thunks
    /// whose target this is (referringThunkAddresses); a body that holds one is no function.
    /// Bodies made or cut go to `changed`. With `allowed`, only those functions are made.
    fn create_function(
        &mut self,
        f: u32,
        allowed: Option<&HashSet<u32>>,
        referring: &mut Vec<u32>,
        changed: &mut BTreeSet<u32>,
    ) -> bool {
        if self.bodies.contains_key(&f) || !self.insns.contains_key(&f) || allowed.is_some_and(|s| !s.contains(&f)) {
            return false;
        }
        for _ in 0..2 {
            let body = self.walk(f, |a| self.bodies.contains_key(&a));
            let body = self.subtract_existing(f, body, changed);
            if let Some(b) = self.resolve_thunk(f, &body, allowed, referring, changed) {
                self.set_body(f, b, changed);
                return true;
            }
            if referring.iter().any(|r| body.binary_search(r).is_ok()) {
                return false;
            }
            if !body.iter().any(|a| self.body_owner.contains_key(a)) {
                self.set_body(f, body, changed);
                return true;
            }
        }
        false
    }

    /// subtractBodyFromExisting: each function whose body overlaps `body` loses the part from
    /// `f` to the end of `body` (it lies before `f`) or up to its own entry (it lies after);
    /// `body` loses what the function keeps.
    fn subtract_existing(&mut self, f: u32, mut body: Vec<u32>, changed: &mut BTreeSet<u32>) -> Vec<u32> {
        let over: BTreeSet<u32> =
            body.iter().filter_map(|a| self.body_owner.get(a).copied()).filter(|&g| g != f).collect();
        for g in over {
            let Some(&max) = body.last() else { break };
            let end = if g < f { max } else { g - 1 };
            if let Some(gb) = self.bodies.get_mut(&g) {
                let n = gb.len();
                gb.retain(|&a| {
                    let cut = (f..=end).contains(&a);
                    if cut {
                        self.body_owner.remove(&a);
                    }
                    !cut
                });
                if gb.len() != n {
                    changed.insert(g);
                }
            }
            body.retain(|a| self.body_owner.get(a) != Some(&g));
        }
        body
    }

    /// CreateFunctionCmd.resolveThunk with CreateThunkFunctionCmd: a function whose first
    /// instruction is a direct JMP (getSimpleFlow) is a thunk of the function at the target,
    /// made first where there is none (getReferencedFunction), but not where the target lies in
    /// another function's body, has no instruction, or is a thunk on the way. The thunk's body
    /// is `body` less the target's body; where `body` held the target, that must leave one
    /// range from the entry, else it must not overlap the target. Returns the thunk's body.
    fn resolve_thunk(
        &mut self,
        f: u32,
        body: &[u32],
        allowed: Option<&HashSet<u32>>,
        referring: &mut Vec<u32>,
        changed: &mut BTreeSet<u32>,
    ) -> Option<Vec<u32>> {
        let t = self.insns.get(&f).filter(|i| i.flow == Flow::Jump)?.target.filter(|&t| t != f)?;
        if referring.contains(&f) {
            return None;
        }
        if !self.bodies.contains_key(&t) {
            if self.body_owner.contains_key(&t) || !self.insns.contains_key(&t) || referring.contains(&t) {
                return None;
            }
            referring.push(f);
            let made = self.create_function(t, allowed, referring, changed);
            referring.pop();
            // getFunctionContaining(entry): the target's body may hold the entry now
            if !made || self.body_owner.contains_key(&f) {
                return None;
            }
        }
        let thunk: Vec<u32> = body.iter().copied().filter(|a| self.body_owner.get(a) != Some(&t)).collect();
        // createThunkFunction throws OverlappingFunctionException where the body holds a third
        // function's code (made with the target); CreateFunctionCmd tries again
        if thunk.iter().any(|a| self.body_owner.get(a).is_some_and(|&g| g != f)) {
            return None;
        }
        let one_range =
            thunk.first() == Some(&f) && thunk.windows(2).all(|w| w[0] + self.insns[&w[0]].len as u32 == w[1]);
        let held = body.binary_search(&t).is_ok();
        if held && !one_range || !held && thunk.len() != body.len() {
            return None;
        }
        self.thunk_of.insert(f, t);
        Some(thunk)
    }

    /// Function.setBody (FUNCTION_BODY_CHANGED; a new function's body with FUNCTION_ADDED).
    fn set_body(&mut self, f: u32, body: Vec<u32>, changed: &mut BTreeSet<u32>) {
        for a in self.bodies.get(&f).into_iter().flatten() {
            if self.body_owner.get(a) == Some(&f) {
                self.body_owner.remove(a);
            }
        }
        for &a in &body {
            self.body_owner.insert(a, f);
        }
        self.bodies.insert(f, body);
        self.funcs.insert(f);
        changed.insert(f);
    }

    /// CreateFunctionCmd.fixupFunctionBody: the flow from the entry, as at creation; a
    /// function that is no thunk and whose entry jumps to a function becomes its thunk
    /// (resolveThunk); a body that overlaps others cuts them as at creation.
    // ponytail: the thunk case takes a target that is a function already and a body that
    // overlaps none; Java's would make the target and set the thunk even where the body then
    // fails (CreateThunkFunctionCmd.applyTo on an existing function)
    fn fixup_body(&mut self, f: u32, changed: &mut BTreeSet<u32>) {
        let new = self.walk(f, |a| self.bodies.contains_key(&a));
        let overlaps = new.iter().any(|a| self.body_owner.get(a).is_some_and(|&g| g != f));
        if !self.thunk_of.contains_key(&f) && !overlaps {
            let i = &self.insns[&f];
            if let Some(t) = i.target.filter(|t| i.flow == Flow::Jump && *t != f && self.bodies.contains_key(t)) {
                self.thunk_of.insert(f, t);
                if self.bodies.get(&f) != Some(&new) {
                    self.set_body(f, new, changed);
                }
                return;
            }
        }
        if new.is_empty() || self.bodies.get(&f) == Some(&new) {
            return;
        }
        let new = if overlaps { self.subtract_existing(f, new, changed) } else { new };
        self.set_body(f, new, changed);
    }

    /// Non-returning functions, this analysis's rule (FindNoReturnFunctionsAnalyzer's place):
    /// no way out of the body: no RETURN, no jump (conditional or not) or fallthrough out of
    /// it, unless to a non-returning function. An approximation: Java's analyzer decides from
    /// the call sites (`FindNoReturnFunctionsAnalyzer`, its evidence threshold), never from a
    /// body without a RET; a mark here is kept once made, so a wrong one stays. The functions that call a new one get their bodies
    /// fixed up (`fixCallingFunctionBody`), and the rule runs again. Bodies set go to `changed`.
    fn find_noreturn(&mut self, changed: &mut BTreeSet<u32>) {
        for _ in 0..4 {
            let found: HashSet<u32> = self
                .bodies
                .iter()
                .filter(|(f, b)| {
                    !self.noreturn.contains(f)
                        && !b.iter().any(|a| {
                            let i = &self.insns[a];
                            // a JMP [slot] thunk to a non-returning import does not return either
                            i.flow == Flow::Return
                                || i.flow == Flow::JumpInd
                                    && !self.tables.contains_key(a)
                                    && !i.slot.is_some_and(|s| self.noreturn.contains(&s))
                                // a jump out of the body (to a function, made or not, or
                                // to code the body does not hold) unless to a non-returning one
                                || matches!(i.flow, Flow::Jump | Flow::CondJump)
                                    && i.target.is_some_and(|t| {
                                        !self.noreturn.contains(&t)
                                            && b.binary_search(&t).is_err()
                                    })
                                // a fallthrough out of the body (into another function's)
                                || i.falls_through()
                                    && !(matches!(i.flow, Flow::Call | Flow::CallInd) && self.call_return(*a, i))
                                    && b.binary_search(&(a + i.len as u32)).is_err()
                        })
                })
                .map(|(&f, _)| f)
                .collect();
            if found.is_empty() {
                break;
            }
            self.noreturn.extend(&found);
            let callers: BTreeSet<u32> = self
                .insns
                .iter()
                .filter(|(_, i)| i.flow == Flow::Call && i.target.is_some_and(|t| found.contains(&t)))
                .filter_map(|(a, _)| self.body_owner.get(a).copied())
                .collect();
            for g in callers {
                self.fixup_body(g, changed);
            }
        }
    }

    /// Function Start Search: functions at prologue patterns in bytes no code covers yet, each
    /// disassembled when found; again while a sweep finds one.
    fn start_search(
        &mut self,
        img: &Image,
        sl: &Sleigh,
        p: &mut crate::sleigh::Parse,
        owner: &mut [u8],
        queue: &mut Vec<u32>,
    ) {
        loop {
            let before = self.funcs.len();
            for sec in img.sections.iter().filter(|s| s.exec) {
                let d = &sec.data;
                for o in 1..d.len() {
                    let a = sec.addr + o as u32;
                    if owner[(a - self.code_lo) as usize] != 0 {
                        continue;
                    }
                    if pair_hit(d, o, &PRE_FILL, &POST_FILL) || pair_hit(d, o, &PRE_JMP, &POST_JMP) {
                        self.funcs.insert(a);
                        queue.push(a);
                        self.descend(img, sl, p, owner, queue, &mut Vec::new());
                    }
                }
            }
            if self.funcs.len() == before {
                return;
            }
        }
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
        fold.stack.clear();
        fold.mem_size = 0;
        fold.data.clear();
        let val = |v: &crate::sleigh::Varnode, fold: &Fold| -> Option<(Val, bool)> {
            let mem = |x: u32| match fold.mem.iter().find(|m| m.0 == Val::C(x)) {
                Some(m) => m.1.map(|v| (v, m.2)),
                None => img.read_u32(x).map(|x| (Val::C(x), true)),
            };
            match v.space {
                0 => Some((Val::C(v.offset as u32), false)),
                s if s == code => (v.size == 4).then(|| mem(v.offset as u32)).flatten(),
                s => match fold
                    .regs
                    .iter()
                    .find(|f| f.0 == s && f.1 < v.offset + v.size as u64 && v.offset < f.1 + f.2 as u64)
                {
                    Some(f) if f.1 == v.offset && f.2 == v.size => f.3.map(|x| (x, f.4)),
                    // a constant's low bytes, `ROL EDX,CL` after `MOV ECX,[a]`
                    Some(f) if f.1 <= v.offset && v.offset + v.size as u64 <= f.1 + f.2 as u64 => match f.3 {
                        Some(Val::C(c)) => Some((Val::C(mask(c >> (8 * (v.offset - f.1)), v.size)), f.4)),
                        _ => None,
                    },
                    None if s == rs && v.size == 4 => Some((Val::S(v.offset, 0), false)),
                    _ => None,
                },
            }
        };
        let load = |p: Val, fold: &Fold| -> Option<(Val, bool)> {
            match p {
                Val::C(x) => val(&crate::sleigh::Varnode { space: code, offset: x as u64, size: 4 }, fold),
                // memory nothing was stored to holds a symbol of its own (its first value), as
                // Ghidra keeps an unknown location: `MOV EBP,[ESP+0xc]` is the third argument
                Val::S(b, d) => match fold.mem.iter().find(|m| m.0 == p) {
                    Some(m) => m.1.map(|v| (v, m.2)),
                    None => Some((Val::S(1 << 63 | (b.wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ d as u64) >> 1, 0), false)),
                },
            }
        };
        let in_image = |x: u32| img.block_of(x).is_some();
        // ponytail: at most MAX_STACK stack stores (ESP-relative) and MAX_MEM others, the newest;
        // Ghidra keeps all. Lookups are linear: a map if a body ever stores far more. (16 and 64,
        // the caps of the local fold, lose 7 gate lines on mercs2 now that walks span functions.)
        let stack = fold.mem.iter().filter(|m| matches!(m.0, Val::S(0x10, _))).count();
        let (max_stack, max_mem) = (MAX_STACK[fold.whole as usize], MAX_MEM[fold.whole as usize]);
        if stack > max_stack {
            let old = fold.mem.iter().position(|m| matches!(m.0, Val::S(0x10, _))).unwrap();
            fold.mem.remove(old);
        }
        if fold.mem.len() - stack.min(max_stack) > max_mem {
            let old = fold.mem.iter().position(|m| !matches!(m.0, Val::S(0x10, _))).unwrap();
            fold.mem.remove(old);
        }
        let mut computed = None;
        for op in &ops {
            if matches!(op.opc, 2 | 3) {
                // for the stack variables of `stack_uses`; nothing here reads these
                let size = if op.opc == 2 { op.out.as_ref().map_or(0, |o| o.size) } else { op.ins[2].size };
                fold.mem_size = size;
                match op.ins.get(1).and_then(|v| val(v, fold)) {
                    Some((Val::S(0x10, d), _)) => fold.stack.push((d, size, op.opc == 3)),
                    Some((Val::C(x), _)) => fold.data.push((x, size, op.opc == 3)),
                    _ => {}
                }
            }
            if op.opc == 3 {
                let v = op.ins.get(2).and_then(|v| val(v, fold));
                // a constant stored through a register, `MOV ECX,fn; MOV [EAX*8+t],ECX`: Ghidra's
                // addStoredReferences (a plain immediate is an operand reference already)
                if let (Some((Val::C(x), _)), true) = (v, op.ins.get(2).is_some_and(|v| v.space != 0)) {
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
                    // smaller constants, for the carry of `STC; ADC EBP,[a]` (SecuROM)
                    (1, [x]) if o.size < 4 => val(x, fold).filter(|v| matches!(v.0, Val::C(_))),
                    (17 | 18, [x]) if o.size == 4 && x.size < 4 => match val(x, fold) {
                        Some((Val::C(c), _)) => {
                            let sh = 32 - 8 * x.size;
                            Some((Val::C(if op.opc == 17 { c } else { ((c << sh) as i32 >> sh) as u32 }), true))
                        }
                        _ => None,
                    },
                    (2, [_, x]) if o.size == 4 => val(x, fold).and_then(|(p, _)| {
                        if let Val::C(x) = p {
                            if in_image(x) && !refs.contains(&x) {
                                refs.push(x); // READ reference through a folded address
                            }
                        }
                        load(p, fold).map(|(v, _)| (v, true))
                    }),
                    (24 | 25, [x]) if o.size == 4 => match val(x, fold) {
                        Some((Val::C(x), _)) => Some((Val::C(if op.opc == 24 { x.wrapping_neg() } else { !x }), true)),
                        _ => None,
                    },
                    (19 | 20 | 26 | 27 | 28 | 29 | 30 | 31 | 32, [x, y])
                        if o.size <= 4 && y.size <= 4 && (o.size == 4 || op.opc != 31) =>
                    {
                        val(x, fold).zip(val(y, fold)).and_then(|((x, _), (y, _))| {
                            let r = match (op.opc, x, y) {
                                (_, Val::C(x), Val::C(y)) => Val::C(mask(
                                    match op.opc {
                                        19 => x.wrapping_add(y),
                                        20 => x.wrapping_sub(y),
                                        26 => x ^ y,
                                        27 => x & y,
                                        28 => x | y,
                                        29 => x.checked_shl(y).unwrap_or(0),
                                        30 => x.checked_shr(y).unwrap_or(0),
                                        31 => (x as i32).checked_shr(y).unwrap_or(if (x as i32) < 0 { -1 } else { 0 })
                                            as u32,
                                        _ => x.wrapping_mul(y),
                                    },
                                    o.size,
                                )),
                                _ if o.size < 4 => return None,
                                (19, Val::S(b, d), Val::C(c)) | (19, Val::C(c), Val::S(b, d)) => {
                                    Val::S(b, d.wrapping_add(c))
                                }
                                (20, Val::S(b, d), Val::C(c)) => Val::S(b, d.wrapping_sub(c)),
                                (27, Val::S(0x10, d), Val::C(m)) if fold.stack_and => Val::S(0x10, d & m),
                                (20 | 26, x, y) if x == y => Val::C(0), // `XOR EDI,EDI`
                                (20, Val::S(b, d), Val::S(b2, d2)) if b == b2 => Val::C(d.wrapping_sub(d2)),
                                _ => return None,
                            };
                            Some((r, true))
                        })
                    }
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
                // EAX, ECX, EDX (offsets 0, 4, 8) and flags are the callee's: each becomes a new
                // symbol of this call, which aliases nothing stored before it. ESP (0x10) pops the
                // return address and the callee's purge (`RET n`), as Ghidra's
                // handleFunctionSideEffects does for __stdcall's unknown extrapop; where the purge
                // is unknown (no body, RETs that disagree, imports) ESP is a new symbol too.
                // a call through a slot with a known purge (an import, where the purges are Ghidra's)
                let through = || {
                    let v = &op.ins[0];
                    let c = ops.iter().rev().find(|c| c.opc == 1 && c.out.as_ref().is_some_and(|o| o == v));
                    let v = c.map_or(v, |c| &c.ins[0]);
                    (v.space == code).then_some(v.offset as u32).filter(|s| self.purge.contains_key(s))
                };
                let callee = if op.opc == 7 { Some(op.ins[0].offset as u32) } else { through().or(computed) };
                let esp = crate::sleigh::Varnode { space: rs, offset: 0x10, size: 4 };
                let after = callee.and_then(|t| self.purge.get(&t)).zip(val(&esp, fold)).map(|(&n, (v, _))| match v {
                    Val::C(x) => Val::C(x.wrapping_add(4 + n)),
                    Val::S(b, d) => Val::S(b, d.wrapping_add(4 + n)),
                });
                fold.regs.retain(|f| f.0 != rs || (f.1 >= 0xc && f.1 < 0x10) || (f.1 >= 0x14 && f.1 < 0x200));
                for r in [0u64, 4, 8, 0x10] {
                    let new = Val::S(1 << 40 | (a as u64) << 8 | r, 0);
                    fold.regs.push((rs, r, 4, Some(if r == 0x10 { after.unwrap_or(new) } else { new }), false));
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
                if v.space == 0
                    && v.size == 4
                    && v.offset != next
                    && !fpu_ip
                    && self.is_code(img, imm)
                    && !code_imms.contains(&imm)
                {
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
    /// `PUSH next; PUSH callee; RET`, values the local fold computes) where
    /// OperandReferenceAnalyzer would disassemble (no table of addresses there, nothing reads or
    /// writes the target, the instruction is no jump or call and does not compute with the
    /// value, `valid_subroutine` accepts it), and the entries of address tables of code
    /// (`address_tables`), repeated over what that reaches. An address table an instruction
    /// refers to becomes pointers (`table_slots`). Bodies stay as they are. Returns the
    /// instructions decoded by the descent from `addrs`.
    // ponytail: the references a check sees are all of the instructions decoded so far, where
    // Ghidra has those of the code it had disassembled when it asked (its analysis works in
    // small steps from the entry points); a faithful order needs its task queue ported
    pub fn disassemble(&mut self, img: &Image, sl: &Sleigh, addrs: &[u32], constants: bool) -> Vec<u32> {
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
        let known = log.len();
        self.descend(img, sl, &mut p, &mut owner, &mut queue, &mut log);
        let new = log[known..].to_vec();
        if constants {
            self.propagate(img, sl);
        }
        let mut checked = HashSet::new(); // targets asked once, as Ghidra's checkedTargets
        let mut asked = HashSet::new(); // pointer targets asked once
        let min_table = Self::min_table(img);
        // every reference destination so far, and those in executable blocks that a memory
        // operand reads or writes (Ghidra's READ and WRITE references)
        let mut refs = Refs::default();
        refs.dests.extend(self.table_slots.values());
        while constants && !log.is_empty() {
            for a in &log {
                let i = &self.insns[a];
                refs.dests.extend(i.refs.iter().chain(&i.code_imms).chain(&i.target));
                refs.dests.extend(self.tables.get(a).into_iter().flatten());
                refs.reads.extend(i.refs.iter().filter(|&&t| self.is_code(img, t)));
            }
            let mut queue: Vec<u32> = Vec::new();
            let targets = |i: &Ins| i.refs.iter().chain(&i.code_imms).copied().collect::<Vec<_>>();
            for (a, t) in
                log.iter().flat_map(|&a| targets(&self.insns[&a]).into_iter().map(move |t| (a, t))).collect::<Vec<_>>()
            {
                let defined = self.is_code(img, t) && owner[(t - self.code_lo) as usize] != 0;
                if defined || !checked.insert(t) {
                    continue;
                }
                // OperandReferenceAnalyzer.getAddressTable, createFlowTable: an address table
                // an instruction refers to becomes pointers, and nothing is disassembled there
                let flows = !matches!(self.insns[&a].flow, Flow::Fall | Flow::Return);
                if let Some(elems) = self.table_entry(img, &owner, &refs.dests, t, 3).filter(|e| e.len() >= min_table) {
                    if !flows {
                        self.make_table(img, &mut owner, &mut refs, t, &elems);
                    }
                    continue;
                }
                // "Subroutine References": not where something reads or writes the target, not
                // from a jump or call, not a value the instruction computes with
                if self.is_code(img, t)
                    && !refs.reads.contains(&t)
                    && !flows
                    && !self.used_for_calculation(img, sl, &mut p, a, t)
                    && self.valid_subroutine(img, sl, &mut p, &owner, &refs.dests, t, false, true)
                {
                    queue.push(t);
                }
            }
            log.clear();
            self.descend(img, sl, &mut p, &mut owner, &mut queue, &mut log);
            if log.is_empty() {
                // Pointers in referenced data first (the operand analyzer runs before
                // Create Address Tables), then address tables over what is still undefined;
                // code either reaches is checked for code constants again.
                let mut queue = self.pointer_targets(img, sl, &mut p, &owner, &refs, &mut asked);
                if queue.is_empty() {
                    queue = self.address_tables(img, sl, &mut p, &mut owner, &mut refs);
                    queue.extend(self.pointer_targets(img, sl, &mut p, &owner, &refs, &mut asked));
                }
                queue.retain(|&t| owner[(t - self.code_lo) as usize] == 0);
                self.descend(img, sl, &mut p, &mut owner, &mut queue, &mut log);
            }
        }
        self.funcs = funcs;
        new
    }

    /// PseudoDisassembler.isValidSubroutine(entry, false), which Ghidra asks before it
    /// disassembles at a code constant ("Found code from operand reference"): the flow from
    /// `entry` (not into calls, nor jumps to functions) decodes without a bad instruction, runs
    /// into no existing code, jumps only to instruction starts, never branches conditionally
    /// to its own fallthrough, and returns, jumps through a register or reaches a function;
    /// a single instruction must reach a function. With `existing` (isValidSubroutine(entry,
    /// true), asked for pointers in data), the flow may run through existing instructions and a
    /// single instruction is enough. `checkPseudoBody`: no defined data in the body, no
    /// reference (`dests`) into the middle of an instruction of the body, and without
    /// `existing` no reference to the body but to its entry. Without `must_terminate` this is
    /// PseudoDisassembler.isValidCode, which Create Address Tables asks.
    #[allow(clippy::too_many_arguments)]
    fn valid_subroutine(
        &self,
        img: &Image,
        sl: &Sleigh,
        p: &mut crate::sleigh::Parse,
        owner: &[u8],
        dests: &BTreeSet<u32>,
        entry: u32,
        existing: bool,
        must_terminate: bool,
    ) -> bool {
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
                let taken = |b: u8| b >= 3 || b != 0 && !existing; // 3, 4: defined data (a switch table, a pointer)
                if owner.get(o..o + i.len as usize).is_none_or(|b| b.iter().any(|&b| taken(b))) {
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
        if must_terminate && !(terminated || called) {
            return false;
        }
        // checkPseudoBody
        if body.iter().any(|(&s, &l)| dests.range(s + 1..s + l as u32).next().is_some()) {
            return false; // an offcut reference
        }
        existing
            || (called || body.len() > 1)
                && !body.iter().any(|(&s, &l)| dests.range(s..s + l as u32).any(|&t| t != entry))
    }

    /// OperandReferenceAnalyzer.isUsedForCalculation: the instruction at `a` computes with the
    /// constant `t` (any operation but COPY, LOAD and STORE on it or on a copy of it), or
    /// loads or stores through a copy of it.
    fn used_for_calculation(&self, img: &Image, sl: &Sleigh, p: &mut crate::sleigh::Parse, a: u32, t: u32) -> bool {
        let Some(sec) = img.block_of(a) else { return false };
        if sl.decode(p, a as u64, &sec.data[(a - sec.addr) as usize..]).is_err() {
            return false;
        }
        let Ok(ops) = sl.pcode(p) else { return false };
        let mut target: Option<crate::sleigh::Varnode> = None;
        for op in &ops {
            let through = matches!(op.opc, 2 | 3);
            if through && target.is_some() && op.ins.get(1) == target.as_ref() {
                return true;
            }
            for v in &op.ins {
                if target.as_ref() == Some(v) || v.space == 0 && v.offset == t as u64 {
                    if through {
                        continue;
                    }
                    if op.opc != 1 {
                        return true;
                    }
                    if let Some(o) = &op.out {
                        target = Some(*o);
                    }
                }
            }
        }
        false
    }

    /// AddressTable.getThresholdRunOfValidPointers(BILLION_CASES): the run of pointers that
    /// happens by chance once in a billion, at least 2.
    fn min_table(img: &Image) -> usize {
        let bytes: f64 = img.sections.iter().map(|s| s.data.len() as f64).sum();
        ((1e-9f64).ln() / (bytes / 2f64.powi(32)).ln()).ceil().max(2.0) as usize
    }

    /// Bytes at `a` that hold no instruction and no data but pointers (which a table may take
    /// over, as AddressTable.getEntry and makeTable allow).
    fn undefined(&self, img: &Image, owner: &[u8], a: u32) -> bool {
        !self.is_code(img, a) || matches!(owner[(a - self.code_lo) as usize], 0 | 4)
    }

    /// AddressTable.getEntry(top, checkExisting, `min`, alignment 1, MINIMUM_SAFE_ADDRESS): the
    /// run of words from `top` that are addresses of the image (not below 1024), cut by a
    /// reference to a word after the second, by a word that points into the middle of an
    /// instruction or to one something falls into (checkForCollisionAtTarget), by the next
    /// reference destination and by the next instruction or data that is no pointer.
    fn table_entry(&self, img: &Image, owner: &[u8], dests: &BTreeSet<u32>, top: u32, min: usize) -> Option<Vec<u32>> {
        let s = img.block_of(top)?;
        let end = s.addr + s.data.len() as u32;
        if !self.undefined(img, owner, top) {
            return None;
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
        let mut elems: Vec<u32> = Vec::new();
        let mut cur = top;
        while cur + 4 <= end {
            let v = u32::from_le_bytes(s.data[(cur - s.addr) as usize..][..4].try_into().unwrap());
            if v < 1024 || img.block_of(v).is_none() || (elems.len() > 1 && dests.contains(&cur)) || collides(v) {
                break;
            }
            elems.push(v);
            cur += 4;
        }
        let mut count = elems.len();
        if count >= min {
            let stop = dests.range(top + 1..top + 4 * count as u32).next().copied();
            let stop = stop.into_iter().chain((top..top + 4 * count as u32).find(|&a| !self.undefined(img, owner, a)));
            if let Some(at) = stop.min() {
                count = count.min(((at - top) / 4) as usize);
            }
        }
        elems.truncate(count);
        (count >= min).then_some(elems)
    }

    /// AddressTable.makeTable: the words from `top` become pointers, each a reference to its
    /// value.
    fn make_table(&mut self, img: &Image, owner: &mut [u8], refs: &mut Refs, top: u32, elems: &[u32]) {
        for (i, &v) in elems.iter().enumerate() {
            let slot = top + 4 * i as u32;
            self.table_slots.insert(slot, v);
            refs.dests.insert(v);
            if self.is_code(img, slot) {
                let o = (slot - self.code_lo) as usize;
                owner[o..].iter_mut().take(4).filter(|b| **b == 0).for_each(|b| *b = 4);
            }
        }
    }

    /// OperandReferenceAnalyzer (`added`, `checkForPointer`): a data word an instruction
    /// references, holding an address no other reference points into, becomes a pointer; the
    /// pointer's reference into undecoded code is disassembled where isValidSubroutine(target,
    /// true) accepts it. This is how Ghidra reaches functions only a vtable names (deleting
    /// destructors). The pointers of address tables (`table_slots`) go the same way
    /// (DataOperandReferenceAnalyzer), so a table that mixes code and data pointers still
    /// reaches its code. Returns those targets; `asked` holds the ones already asked.
    /// ponytail: no string check at the slot (checkForAscii/Unicode) and no pointer chains.
    fn pointer_targets(
        &self,
        img: &Image,
        sl: &Sleigh,
        p: &mut crate::sleigh::Parse,
        owner: &[u8],
        refs: &Refs,
        asked: &mut HashSet<u32>,
    ) -> Vec<u32> {
        let dests = &refs.dests;
        // checkForPointer: a value of 4096 up, and no reference into the rest of the slot
        let pointers = dests.iter().filter(|&&t| !self.is_code(img, t)).filter_map(|&t| {
            img.read_u32(t).filter(|&v| v >= 4096 && dests.range(t + 1..t.saturating_add(4)).next().is_none())
        });
        let mut out = Vec::new();
        for v in pointers.chain(self.table_slots.values().copied()) {
            // hasDataAccessReferences: not where something reads or writes the target
            if self.is_code(img, v)
                && owner[(v - self.code_lo) as usize] == 0
                && asked.insert(v)
                && !refs.reads.contains(&v)
                && self.valid_subroutine(img, sl, p, owner, &refs.dests, v, true, true)
            {
                out.push(v);
            }
        }
        out
    }

    /// Ghidra's Create Address Tables analyzer (AddressTableAnalyzer, AddressTable.getEntry and
    /// checkTable) over the bytes no instruction covers, in every section: runs of at least
    /// `getThresholdRunOfValidPointers` (one in a billion by chance) 4-aligned words that are
    /// addresses (`table_entry`), cut by a pointer into the middle of an instruction, a UTF-16
    /// string, or a jump of more than 0xffffff between neighbours (which drops that entry).
    /// Adds the slots to `table_slots` and returns the entries to disassemble
    /// (`getFunctionEntries`): those of a table whose every entry lies in an executable block
    /// and is the start of an instruction or, where nothing is defined, valid code
    /// (PseudoDisassembler.isValidCode). An entry at defined data (a pointer of this or another
    /// table) is not, so a table of pointers to pointers stays data.
    /// Not modelled: Ghidra's other defined data (strings, structures); the analyzer's
    /// disassembly between one table and the next (here after the whole pass).
    fn address_tables(
        &mut self,
        img: &Image,
        sl: &Sleigh,
        p: &mut crate::sleigh::Parse,
        owner: &mut [u8],
        refs: &mut Refs,
    ) -> Vec<u32> {
        let min = Self::min_table(img);
        let mut code = Vec::new();
        for s in &img.sections {
            let end = s.addr + s.data.len() as u32;
            let mut top = s.addr;
            while top + 4 <= end {
                let Some(elems) = self.table_entry(img, owner, &refs.dests, top, min) else {
                    top += 4;
                    continue;
                };
                let count = elems.len();
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
                        self.make_table(img, owner, refs, at(first), &elems[first..first + len]);
                        // getFunctionEntries, over the whole table that is left
                        let rest = &elems[first..];
                        let valid: Vec<u32> = rest
                            .iter()
                            .copied()
                            .filter(|&v| {
                                self.is_code(img, v)
                                    && match owner[(v - self.code_lo) as usize] {
                                        0 => self.valid_subroutine(img, sl, p, owner, &refs.dests, v, true, false),
                                        b => b == 1,
                                    }
                            })
                            .collect();
                        if valid.len() >= rest.len() {
                            code.extend(valid);
                        }
                    }
                    first += len + 1;
                }
                top += 4 * count as u32;
            }
        }
        code
    }

    /// Recursive descent from every queued address. Call targets in .text become functions.
    fn descend(
        &mut self,
        img: &Image,
        sl: &Sleigh,
        p: &mut crate::sleigh::Parse,
        owner: &mut [u8],
        queue: &mut Vec<u32>,
        log: &mut Vec<u32>,
    ) {
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
                    if ins.flow != Flow::Call && owner[(t - self.code_lo) as usize] == 0 {
                        pending.entry(t).or_insert_with(|| fold.clone());
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

    /// SharedReturnAnalysisCmd with "assume contiguous functions" (x86's default) and without
    /// conditional branches, on `set`: the entries of the functions added or with a body set
    /// since its last turn (a FUNCTION_ANALYZER at 398). The jump
    /// scan set is built per function of `set` as `checkAboveFunction` /
    /// `checkBelowFunction` build it (from the previous function's entry to the next one's,
    /// a single-range body taken out again), and the jump sources in it are walked in address
    /// order with Java's cached "function after / before the source", whose staleness decides
    /// some targets. A target becomes a function when an unconditional jump (a jump's first
    /// flow reference) passes the next function entry or goes before the previous one, no
    /// conditional flow reaches it, no instruction falls into it and it is not a lone return
    /// (`checkIfCouldHaveFallThruTo`). The functions are the ones with a body (the function
    /// manager's); the targets go to `funcs` and are made by CreateFunctionCmd after the task
    /// (Java queues them with `AutoAnalysisManager.createFunction` at 397, before the next
    /// task). The jumps to a function in `set` are not given CALL_RETURN here
    /// (`processFunctionJumpReferences`): ghidra-rs derives that override (`call_return`).
    fn shared_returns(&mut self, set: &BTreeSet<u32>) {
        let mut cond = HashSet::new();
        for i in self.insns.values() {
            if i.flow == Flow::CondJump {
                cond.extend(i.target);
            }
        }
        let funcs = &self.bodies;
        let mut scan = RangeSet::default();
        for &f in set.iter().filter(|f| funcs.contains_key(f)) {
            // checkAboveFunction
            let prev = funcs.range(..f).next_back().map_or(0, |(&p, _)| p);
            scan.add(prev, f);
            // checkBelowFunction
            let body = self.body_ranges(f);
            if body.len() > 1 {
                body.iter().for_each(|&(lo, hi)| scan.add(lo, hi));
            }
            let next = funcs.range(f + 1..).next().map_or(u32::MAX, |(&n, _)| n - 1);
            scan.add(f, next);
            if body.len() <= 1 {
                body.iter().for_each(|&(lo, hi)| scan.remove(lo, hi));
            }
        }
        let mut created = BTreeSet::new();
        // Java's cache: None is null, Some(None) is Address.NO_ADDRESS
        let (mut after, mut before): (Option<Option<u32>>, Option<Option<u32>>) = (None, None);
        let after_of = |a: u32| funcs.range(a + 1..).next().map(|(&n, _)| n);
        let before_of = |a: u32| funcs.range(..a).next_back().map(|(&p, _)| p);
        for (&src, i) in scan.ranges().flat_map(|(lo, hi)| self.insns.range(lo..=hi)) {
            // the first flow reference: the jump's target, or a computed jump's lowest case
            let dest = match i.flow {
                Flow::Jump => i.target,
                Flow::JumpInd => self.tables.get(&src).and_then(|c| c.iter().min().copied()),
                _ => None,
            };
            let Some(dest) = dest else { continue };
            if cond.contains(&dest) {
                continue;
            }
            if src < dest {
                if after == Some(None) {
                    continue;
                }
                if after.is_none_or(|a| a.is_some_and(|a| a <= src)) {
                    after = Some(after_of(src));
                    if after == Some(None) {
                        continue;
                    }
                }
                if after.flatten().is_some_and(|a| dest >= a) {
                    self.shared_target(dest, &mut created);
                }
            } else {
                if after.is_none() {
                    after = Some(after_of(src));
                }
                if before == Some(None) {
                    let Some(a) = after.flatten() else { continue };
                    if src < a {
                        continue;
                    }
                    before = None;
                    after = Some(after_of(src));
                }
                let keep = before.is_some() && after.is_some_and(|a| a.is_none_or(|a| src < a));
                if !keep {
                    before = Some(before_of(src));
                    if before == Some(None) {
                        continue;
                    }
                }
                if before.flatten().is_some_and(|b| dest < b) {
                    self.shared_target(dest, &mut created);
                }
            }
        }
        self.funcs.extend(created);
    }

    /// SharedReturnAnalysisCmd.createFunction: nothing for an existing function (its jump
    /// overrides are derived, see `call_return`), else a function unless something could fall
    /// into the target (`checkIfCouldHaveFallThruTo`): no instruction there, an instruction
    /// whose fallthrough is the target, or a lone terminator (a return).
    fn shared_target(&self, dest: u32, created: &mut BTreeSet<u32>) {
        if self.bodies.contains_key(&dest) {
            return;
        }
        let Some(i) = self.insns.get(&dest) else { return };
        if i.flow == Flow::Return {
            return;
        }
        let falls_in = self.insns.range(..dest).next_back().is_some_and(|(&a, p)| {
            a + p.len as u32 == dest
                && p.falls_through()
                && !(matches!(p.flow, Flow::Call | Flow::CallInd) && self.call_return(a, p))
        });
        if !falls_in {
            created.insert(dest);
        }
    }

    /// The address ranges of a function's body (Ghidra's body AddressSet): its instructions'
    /// bytes, adjacent ones merged.
    fn body_ranges(&self, f: u32) -> Vec<(u32, u32)> {
        let mut out: Vec<(u32, u32)> = Vec::new();
        // the body set (func.getBody)
        for &a in self.bodies.get(&f).into_iter().flatten() {
            let hi = a + self.insns[&a].len as u32 - 1;
            match out.last_mut() {
                Some(last) if last.1.checked_add(1) == Some(a) => last.1 = hi,
                _ => out.push((a, hi)),
            }
        }
        out
    }

    /// Ghidra's CALL_RETURN flow override at an instruction, which ghidra-rs derives: a call of
    /// a non-returning function (the no-return analyzer) and a jump to a function (Shared
    /// Return Calls). An override of the project store wins.
    pub fn call_return(&self, a: u32, i: &Ins) -> bool {
        if let Some(&o) = self.overrides.get(&a) {
            return o;
        }
        match i.flow {
            Flow::Call => i.target.is_some_and(|t| self.noreturn.contains(&t)),
            Flow::CallInd => i.slot.is_some_and(|s| self.noreturn.contains(&s)),
            Flow::Jump => i.target.is_some_and(|t| self.funcs.contains(&t) && self.insns.contains_key(&t)),
            _ => false,
        }
    }

    /// The body of function `f`: the instructions of the ranges the store set for it, else the
    /// flow from its entry up to other function entries.
    pub fn body_of(&self, f: u32) -> Vec<u32> {
        if let Some(ranges) = self.fixed_bodies.get(&f) {
            return ranges.iter().flat_map(|&(lo, hi)| self.insns.range(lo..=hi).map(|(&a, _)| a)).collect();
        }
        self.walk(f, |a| self.funcs.contains(&a))
    }

    /// The flow from `f` (getFunctionBody without other functions): fallthroughs (not past a
    /// CALL_RETURN call), jumps and switch cases, up to the entries `is_entry` names.
    fn walk(&self, f: u32, is_entry: impl Fn(u32) -> bool) -> Vec<u32> {
        let mut seen = BTreeSet::new();
        let mut work = vec![f];
        while let Some(a) = work.pop() {
            if (a != f && is_entry(a)) || !seen.insert(a) {
                continue;
            }
            let Some(i) = self.insns.get(&a) else {
                seen.remove(&a);
                continue;
            };
            let calls = matches!(i.flow, Flow::Call | Flow::CallInd);
            // the override of a jump matters only where the store set one: a derived one
            // targets a function entry, where the walk stops anyway
            let tail = self.overrides.get(&a) == Some(&true);
            if i.falls_through() && !(calls && self.call_return(a, i)) {
                work.push(a + i.len as u32);
            }
            if matches!(i.flow, Flow::Jump | Flow::CondJump) && !tail {
                work.extend(i.target);
            }
            if let Some(cases) = self.tables.get(&a) {
                work.extend(cases);
            }
        }
        seen.into_iter().collect()
    }

    /// Each function's stack purge, as Ghidra sets it from the function's returns: the `n` of
    /// `RET n` (0 for `RET`), where every return of the body agrees.
    pub fn stack_purges(&mut self, img: &Image) {
        self.purge.clear();
        for (&f, body) in &self.bodies {
            let mut pops = body.iter().filter(|a| self.insns[a].flow == Flow::Return).map(|&a| {
                let s = img.block_of(a).unwrap();
                match s.data[(a - s.addr) as usize..].strip_prefix(&[0xf3]).unwrap_or(&s.data[(a - s.addr) as usize..])
                {
                    [0xc3, ..] => Some(0),
                    [0xc2, lo, hi, ..] => Some(u16::from_le_bytes([*lo, *hi]) as u32),
                    _ => None,
                }
            });
            if let Some(Some(n)) = pops.next() {
                if pops.all(|p| p == Some(n)) {
                    self.purge.insert(f, n);
                }
            }
        }
    }

    /// Ghidra's ConstantPropagationAnalyzer: `SymbolicPropogator.flowConstants` from every
    /// function entry over its body, with the registers of the entry as symbols. Each path
    /// keeps its own state: a conditional branch goes on with the fallthrough and saves a
    /// copy for its target (taken later, last saved first), and a flow into code already
    /// visited runs on for at most 16 instructions or up to a call, as Ghidra's
    /// MAX_EXTRA_INSTRUCTION_FLOW (Ghidra does not merge the states where flows join; the
    /// first flow to reach code decides its values). A jump to another function is a tail
    /// call and ends the path. The references, code constants and computed targets of the
    /// instructions of a body are then the ones these walks find (all of them, where several
    /// walks or functions visit an instruction), in place of the local fold's.
    pub fn propagate(&mut self, img: &Image, sl: &Sleigh) {
        let funcs: Vec<u32> = self.funcs.iter().copied().filter(|f| self.bodies.contains_key(f)).collect();
        let n = std::env::var("GHIDRA_RS_THREADS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or_else(|| std::thread::available_parallelism().map_or(1, |n| n.get()))
            .max(1);
        let this = &*self;
        let found: Vec<Vec<Vec<(u32, Ins)>>> = std::thread::scope(|s| {
            let hs: Vec<_> = (0..n)
                .map(|t| {
                    let funcs = &funcs;
                    s.spawn(move || {
                        let mut p = sl.new_parse();
                        funcs
                            .iter()
                            .skip(t)
                            .step_by(n)
                            .map(|&f| this.flow_constants(img, sl, &mut p, f))
                            .collect::<Vec<_>>()
                    })
                })
                .collect();
            hs.into_iter().map(|h| h.join().unwrap()).collect()
        });
        // merged in function order, so the result does not depend on the thread count
        let mut merged: HashMap<u32, Ins> = HashMap::new();
        for i in 0..funcs.len() {
            for (a, d) in &found[i % n][i / n] {
                let m = merged.entry(*a).or_insert_with(|| Ins {
                    refs: Vec::new(),
                    code_imms: Vec::new(),
                    computed: None,
                    ..d.clone()
                });
                for &r in &d.refs {
                    if !m.refs.contains(&r) {
                        m.refs.push(r);
                    }
                }
                for &c in &d.code_imms {
                    if !m.code_imms.contains(&c) {
                        m.code_imms.push(c);
                    }
                }
                m.computed = m.computed.or(d.computed);
            }
        }
        for (a, d) in merged {
            let i = self.insns.get_mut(&a).unwrap();
            (i.refs, i.code_imms, i.computed) = (d.refs, d.code_imms, d.computed);
        }
    }

    /// One function's walk for `propagate`: every decode of an instruction of the body, with
    /// the state the walk brought there.
    fn flow_constants(&self, img: &Image, sl: &Sleigh, p: &mut crate::sleigh::Parse, f: u32) -> Vec<(u32, Ins)> {
        self.flow_walk(img, sl, p, f, false, &mut |_, _| {})
    }

    /// The walk of `flow_constants`; `visit` sees each instruction's address and the state
    /// after it. With `stack_and`, `AND ESP,mask` keeps ESP a stack address.
    pub fn flow_walk(
        &self,
        img: &Image,
        sl: &Sleigh,
        p: &mut crate::sleigh::Parse,
        f: u32,
        stack_and: bool,
        visit: &mut dyn FnMut(u32, &Fold),
    ) -> Vec<(u32, Ins)> {
        const MAX_EXTRA_INSTRUCTION_FLOW: u32 = 16;
        let body = &self.bodies[&f];
        let (mut out, mut visited, mut edges) = (Vec::new(), HashSet::new(), HashSet::new());
        // (destination, source, state, instructions run since hitting visited code)
        let mut stack = vec![(f, f, Fold { whole: true, stack_and, ..Fold::default() }, None::<u32>)];
        while let Some((mut a, src, mut fold, mut extra)) = stack.pop() {
            if !edges.insert((a, src)) {
                continue; // already flowed here from there
            }
            if visited.contains(&a) {
                extra = extra.or(Some(0));
            }
            let mut popped = true;
            while body.binary_search(&a).is_ok() {
                let Some(ins) = self.insns.get(&a) else { break };
                if !visited.contains(&a) {
                    extra = None;
                }
                let Some(d) = self.decode(img, sl, p, a, &mut fold) else { break };
                visit(a, &fold);
                let computed = d.computed;
                out.push((a, d));
                let call = matches!(ins.flow, Flow::Call | Flow::CallInd);
                if !popped && !visited.insert(a) {
                    let e = extra.map_or(0, |e| e + 1);
                    extra = Some(e);
                    if e >= MAX_EXTRA_INSTRUCTION_FLOW || call {
                        break;
                    }
                }
                visited.insert(a);
                popped = false;
                match ins.flow {
                    Flow::CondJump => stack.extend(ins.target.map(|t| (t, a, fold.clone(), extra))),
                    Flow::Jump => {
                        stack.extend(
                            ins.target.filter(|t| !self.funcs.contains(t)).map(|t| (t, a, fold.clone(), extra)),
                        );
                        break;
                    }
                    Flow::JumpInd => {
                        let cases = self.tables.get(&a).cloned().unwrap_or_default();
                        stack.extend(cases.into_iter().chain(computed).map(|t| (t, a, fold.clone(), extra)));
                        break;
                    }
                    Flow::Return => break,
                    Flow::Call if ins.target.is_some_and(|t| self.noreturn.contains(&t)) => break,
                    Flow::CallInd if ins.slot.is_some_and(|s| self.noreturn.contains(&s)) => break,
                    _ => {}
                }
                a += ins.len as u32;
            }
        }
        out
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

    /// The bytes the RETs of `f` pop (`RET n`), where they agree.
    /// Replace the purges a call's stack effect goes by (function entry or import slot ->
    /// bytes popped besides the return address); returns the ones replaced.
    pub fn swap_call_purges(&mut self, purges: HashMap<u32, u32>) -> HashMap<u32, u32> {
        std::mem::replace(&mut self.purge, purges)
    }

    pub fn purge(&self, f: u32) -> Option<u32> {
        self.purge.get(&f).copied()
    }

    pub fn body_size(&self, f: u32) -> u64 {
        self.bodies[&f].iter().map(|a| self.insns[a].len as u64).sum()
    }
}

/// AddressTableAnalyzer.findPossibleStrings over `[from, to)`: the ranges of UTF-16 strings
/// longer than 4 characters (tab, CR, LF and 0x20..0x7e, up to a 0 or half the range).
fn mask(x: u32, size: u32) -> u32 {
    if size >= 4 {
        x
    } else {
        x & ((1 << (8 * size)) - 1)
    }
}

fn utf16_strings(s: &Section, from: u32, to: u32) -> Vec<std::ops::RangeInclusive<u32>> {
    let max = (to - from) / 2;
    let short =
        |a: u32| s.data.get((a - s.addr) as usize..(a - s.addr) as usize + 2).map(|b| u16::from_le_bytes([b[0], b[1]]));
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

/// Disjoint inclusive address ranges (Ghidra's AddressSet, for one space), first -> last.
#[derive(Default)]
struct RangeSet(BTreeMap<u32, u32>);

impl RangeSet {
    fn add(&mut self, mut lo: u32, mut hi: u32) {
        // merge every range that overlaps or touches [lo, hi]
        let touching: Vec<(u32, u32)> = self
            .0
            .range(..=hi.saturating_add(1))
            .rev()
            .take_while(|&(_, &h)| h.saturating_add(1) >= lo)
            .map(|(&l, &h)| (l, h))
            .collect();
        for (l, h) in touching {
            self.0.remove(&l);
            lo = lo.min(l);
            hi = hi.max(h);
        }
        self.0.insert(lo, hi);
    }

    fn remove(&mut self, lo: u32, hi: u32) {
        let hit: Vec<(u32, u32)> =
            self.0.range(..=hi).rev().take_while(|&(_, &h)| h >= lo).map(|(&l, &h)| (l, h)).collect();
        for (l, h) in hit {
            self.0.remove(&l);
            if l < lo {
                self.0.insert(l, lo - 1);
            }
            if h > hi {
                self.0.insert(hi + 1, h);
            }
        }
    }

    fn ranges(&self) -> impl Iterator<Item = (u32, u32)> + '_ {
        self.0.iter().map(|(&l, &h)| (l, h))
    }
}

#[cfg(test)]
mod tests {
    use super::{pair_hit, Analysis, Flow, Ins, RangeSet, POST_FILL, PRE_FILL};
    use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

    #[test]
    fn pattern_pairs_need_their_bits() {
        // `CC` + `SUB ESP,8`: 8 + 19 fixed bits, below totalbits 32; `CC CC` + it: 35
        let d = [0x90, 0xcc, 0x83, 0xec, 0x08, 0xcc, 0xcc, 0x83, 0xec, 0x08];
        assert!(!pair_hit(&d, 2, &PRE_FILL, &POST_FILL));
        assert!(pair_hit(&d, 7, &PRE_FILL, &POST_FILL));
    }

    #[test]
    fn range_set_add_remove() {
        let mut s = RangeSet::default();
        s.add(10, 20);
        s.add(30, 40);
        s.add(21, 29); // touches both
        assert_eq!(s.ranges().collect::<Vec<_>>(), [(10, 40)]);
        s.remove(15, 35);
        assert_eq!(s.ranges().collect::<Vec<_>>(), [(10, 14), (36, 40)]);
        s.add(0, u32::MAX);
        s.remove(0, 5);
        assert_eq!(s.ranges().collect::<Vec<_>>(), [(6, u32::MAX)]);
    }

    /// An analysis of `insns` alone (no image), with a function at each of `funcs` made in
    /// order as CreateFunctionCmd makes it.
    fn bare(insns: &[(u32, Flow, Option<u32>)], funcs: &[u32]) -> (Analysis, BTreeSet<u32>) {
        let ins = |&(a, flow, target): &(u32, Flow, Option<u32>)| {
            let i = Ins { len: 1, flow, target, slot: None, computed: None, refs: vec![], code_imms: vec![] };
            (a, i)
        };
        let mut an = Analysis {
            text_start: 0,
            text_end: 0,
            code_lo: 0,
            code_hi: 0,
            insns: insns.iter().map(ins).collect(),
            tables: HashMap::new(),
            funcs: BTreeSet::new(),
            noreturn: HashSet::new(),
            bodies: BTreeMap::new(),
            table_slots: BTreeMap::new(),
            fpu_ip: None,
            purge: HashMap::new(),
            callee_purges: HashMap::new(),
            reg_space: 0,
            overrides: HashMap::new(),
            fixed_bodies: BTreeMap::new(),
            thunks: HashMap::new(),
            thunk_of: BTreeMap::new(),
            body_owner: HashMap::new(),
            warnings: Vec::new(),
        };
        let mut changed = BTreeSet::new();
        for &f in funcs {
            an.create_function(f, None, &mut Vec::new(), &mut changed);
        }
        (an, changed)
    }

    #[test]
    fn noreturn_counts_a_fallthrough_into_another_body_as_returning() {
        // 0x10 falls into 0x11, made first; 0x20 only loops
        let (mut an, mut changed) = bare(
            &[(0x10, Flow::Fall, None), (0x11, Flow::Return, None), (0x20, Flow::Jump, Some(0x20))],
            &[0x11, 0x10, 0x20],
        );
        assert_eq!(an.bodies[&0x10], [0x10]);
        an.find_noreturn(&mut changed);
        assert!(!an.noreturn.contains(&0x10));
        assert!(an.noreturn.contains(&0x20));
    }

    #[test]
    fn thunk_body_never_takes_a_third_functions_code() {
        // 0x10 JMP 0x12; 0x12 JMP 0x11 makes 0x11 first: 0x10's first body less 0x12's would
        // hold 0x11, so the thunk is tried again on the flow up to the entries made
        let (an, _) = bare(
            &[(0x10, Flow::Jump, Some(0x12)), (0x11, Flow::Return, None), (0x12, Flow::Jump, Some(0x11))],
            &[0x10],
        );
        assert_eq!(an.bodies[&0x10], [0x10]);
        assert_eq!(an.bodies[&0x11], [0x11]);
        assert_eq!(an.thunk_of.get(&0x10), Some(&0x12));
        assert_eq!(an.thunk_of.get(&0x12), Some(&0x11));
    }
}
