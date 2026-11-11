//! Port of the mercs2 Ghidra script tools/ghidra/CheckAbiCallers.java: proves the clobbers and
//! outputs of `register_abi.csv` against every static reference to each contract, and the
//! inputs against the original's own reads. Register liveness is tracked per byte of each base
//! register ("EDX#0", "ZMM1#4", "CF#0"); an instruction's register reads and writes come from
//! its p-code the way Ghidra's `getInputObjects`/`getResultObjects` compute them.
//! The method names and comments follow the Java script, so the two can be read side by side.

use crate::analysis::{Analysis, Flow, Image};
use crate::sleigh::{Parse, Sleigh, Varnode};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::io::Write;
use std::rc::Rc;

type Live = BTreeSet<String>;

// Instructions per walk; call depth into callees; levels up through callers of a caller that
// returns with a clobbered value still live.
const MAX_STEPS: usize = 6000;
const MAX_DEPTH: usize = 10;
const MAX_UP: usize = 2;

const FLAGS: [&str; 6] = ["CF", "PF", "AF", "ZF", "SF", "OF"];
const X87_CC: [&str; 4] = ["C0", "C1", "C2", "C3"];
const X87_PUSH: [&str; 10] = ["FLD", "FILD", "FLD1", "FLDZ", "FLDPI", "FLDLN2", "FLDLG2", "FLDL2E", "FLDL2T", "FBLD"];
const X87_STORE_POP: [&str; 4] = ["FSTP", "FISTP", "FISTTP", "FBSTP"];
const X87_READ_POP: [&str; 14] = [
    "FADDP", "FMULP", "FSUBP", "FSUBRP", "FDIVP", "FDIVRP", "FCOMP", "FICOMP", "FUCOMP", "FCOMIP", "FUCOMIP", "FYL2X", "FYL2XP1",
    "FPATAN",
];
const X87_CONTROL: [&str; 14] = [
    "FNSTCW", "FSTCW", "FLDCW", "FNSTSW", "FSTSW", "FNCLEX", "FCLEX", "FWAIT", "FNOP", "FNSTENV", "FLDENV", "FXSAVE", "FXRSTOR",
    "FRSTOR",
];
const SAVED: [&str; 4] = ["EBX", "ESI", "EDI", "EBP"];
const FLAG_USERS: [&str; 9] = ["ADC", "SBB", "RCL", "RCR", "LAHF", "CMC", "PUSHFD", "FNSTSW", "FSTSW"];

fn base(key: &str) -> &str {
    &key[..key.find('#').unwrap_or(key.len())]
}

fn flaglike(b: &str) -> bool {
    FLAGS.contains(&b) || X87_CC.contains(&b)
}

fn hex(a: u32) -> String {
    format!("{a:08x}")
}

fn join(s: &Live) -> String {
    s.iter().cloned().collect::<Vec<_>>().join(";")
}

fn word(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// `E\w\w`
fn ereg(s: &str) -> bool {
    s.len() == 3 && s.starts_with('E') && word(s)
}

fn parse_hex(s: &str) -> Option<u64> {
    u64::from_str_radix(s.strip_prefix("0x")?, 16).ok()
}

/// Ghidra's register table: per register, its bytes as keys of its base register (the
/// largest register containing it), and the `(offset, size) -> register` map of
/// `RegisterManager.getRegister(Address, int)`.
pub struct Regs {
    space: u32,
    names: Vec<String>,
    offs: Vec<u64>,
    bases: Vec<String>,
    keys: Vec<Vec<String>>,
    by_name: HashMap<String, usize>,
    size_map: HashMap<(u64, u32), usize>,
}

impl Regs {
    pub fn new(sl: &Sleigh) -> Regs {
        let (space, list) = sl.registers();
        let mut r = Regs {
            space,
            names: Vec::new(),
            offs: Vec::new(),
            bases: Vec::new(),
            keys: Vec::new(),
            by_name: HashMap::new(),
            size_map: HashMap::new(),
        };
        for (i, &(name, off, size)) in list.iter().enumerate() {
            let &(bname, boff, _) = list
                .iter()
                .filter(|&&(_, o, s)| o <= off && off + size as u64 <= o + s as u64)
                .max_by_key(|&&(_, _, s)| s)
                .unwrap();
            r.names.push(name.to_string());
            r.offs.push(off);
            r.bases.push(bname.to_string());
            r.keys.push((0..size as u64).map(|k| format!("{bname}#{}", off - boff + k)).collect());
            r.by_name.insert(name.to_string(), i);
        }
        // largest to smallest, so the smallest register of at least that size wins
        let mut order: Vec<usize> = (0..list.len()).collect();
        order.sort_by_key(|&i| std::cmp::Reverse(list[i].2));
        for i in order {
            for s in 1..=list[i].2 {
                r.size_map.insert((list[i].1, s), i);
            }
        }
        r
    }

    pub fn lookup(&self, v: &Varnode) -> Option<usize> {
        if v.space != self.space {
            return None;
        }
        self.size_map.get(&(v.offset, v.size)).copied()
    }

    pub fn get(&self, name: &str) -> usize {
        *self.by_name.get(name).unwrap_or_else(|| panic!("no register {name}"))
    }

    pub fn bytes_of(&self, name: &str) -> &[String] {
        &self.keys[self.get(name)]
    }

    pub fn keys(&self, r: usize) -> &[String] {
        &self.keys[r]
    }

    pub fn base(&self, r: usize) -> &str {
        &self.bases[r]
    }

    pub fn name(&self, r: usize) -> &str {
        &self.names[r]
    }
}

/// Registers an instruction reads and writes, as Ghidra's `SleighInstructionPrototype`
/// `getInputObjects` and `getResultObjects` compute them from the p-code: a register read
/// after the instruction wrote it is no input; varnodes that are no whole register are ignored.
/// Inputs come in Java `HashSet` iteration order (`Register.hashCode` is its offset), since the
/// script reports the first live one.
pub fn reads_writes(regs: &Regs, ops: &[crate::sleigh::PcodeOp]) -> (Vec<usize>, Vec<usize>) {
    let mut inputs: Vec<usize> = Vec::new();
    let mut others: HashSet<(u32, u64, u32)> = HashSet::new(); // other input objects, for the set's capacity
    let mut written: Vec<usize> = Vec::new();
    for op in ops {
        let skip = match op.opc {
            4 | 7 => None,                                     // BRANCH, CALL: flow only
            5 | 3 => Some(1),                                  // CBRANCH: target; STORE: space id
            2 if op.ins.get(1).is_some_and(|v| v.space == 0) => None, // LOAD from a constant address
            2 => Some(1),
            _ => Some(0),
        };
        if let Some(skip) = skip {
            for v in op.ins.iter().skip(skip) {
                match regs.lookup(v) {
                    Some(r) if !written.contains(&r) && !inputs.contains(&r) => inputs.push(r),
                    Some(_) => {}
                    None => {
                        others.insert((v.space, v.offset, v.size));
                    }
                }
            }
        }
        if op.opc != 3 {
            if let Some(r) = op.out.as_ref().and_then(|v| regs.lookup(v)) {
                if !written.contains(&r) {
                    written.push(r);
                }
            }
        }
    }
    let n = inputs.len() + others.len();
    let mut cap = 16usize;
    while n as f64 > cap as f64 * 0.75 {
        cap *= 2;
    }
    inputs.sort_by_key(|&r| {
        let h = regs.offs[r] as u32;
        ((h ^ (h >> 16)) as usize) & (cap - 1)
    });
    (inputs, written)
}

struct Info {
    mnem: String,
    text: String, // Ghidra's Instruction.toString()
    inputs: Vec<usize>,
    results: Vec<usize>,
    scalar0: Option<u64>, // getScalar(0): a plain immediate operand
    reg0: Option<usize>,  // getRegister(0): a plain register operand
}

#[derive(Default)]
struct Fl {
    call: bool,
    jump: bool,
    computed: bool,
    conditional: bool,
    terminal: bool,
    fallthrough: bool, // FlowType.isFallthrough(): plain FALL_THROUGH
    flows: Vec<u32>,
    fall: Option<u32>,
}

#[derive(Clone, Copy, PartialEq)]
enum RefKind {
    UncondCall,
    UncondJump,
    CondJump,
    ComputedCall,
    ComputedJump,
    Data,
    Read,
}

impl RefKind {
    fn name(self) -> &'static str {
        match self {
            RefKind::UncondCall => "UNCONDITIONAL_CALL",
            RefKind::UncondJump => "UNCONDITIONAL_JUMP",
            RefKind::CondJump => "CONDITIONAL_JUMP",
            RefKind::ComputedCall => "COMPUTED_CALL",
            RefKind::ComputedJump => "COMPUTED_JUMP",
            RefKind::Data => "DATA",
            RefKind::Read => "READ",
        }
    }
    fn is_call(self) -> bool {
        matches!(self, RefKind::UncondCall | RefKind::ComputedCall)
    }
    fn is_jump(self) -> bool {
        matches!(self, RefKind::UncondJump | RefKind::CondJump | RefKind::ComputedJump)
    }
    fn is_computed(self) -> bool {
        matches!(self, RefKind::ComputedCall | RefKind::ComputedJump)
    }
    fn is_data(self) -> bool {
        matches!(self, RefKind::Data | RefKind::Read)
    }
}

#[derive(Clone, Default)]
struct Outcome {
    status: String,
    reg: String,
    where_: String,
    at_return: Live,
}

fn ok() -> Outcome {
    Outcome { status: "ok".into(), ..Default::default() }
}

fn fail(status: &str, reg: &str, where_: &str) -> Outcome {
    Outcome { status: status.into(), reg: reg.into(), where_: where_.replace(',', " "), at_return: Live::new() }
}

/// The script's state over one program.
pub struct Checker<'a> {
    img: &'a Image,
    an: &'a Analysis,
    sl: &'a Sleigh,
    regs: Regs,
    parse: Parse,
    info: HashMap<u32, Rc<Info>>,
    func_of: HashMap<u32, u32>,
    refs_to: HashMap<u32, Vec<(u32, RefKind)>>,
    relocated: HashSet<u32>,
    contracts: HashMap<u32, Vec<String>>,
    output_check: bool,
    output_walk: bool,
    input_walk: bool,
    callee_memo: HashMap<(bool, bool, u32, Live), Outcome>,
    never_returned_memo: HashMap<u32, Live>,
    pushes_float_memo: HashMap<u32, bool>,
    input_hits: Vec<(String, [String; 3])>,
    input_memo: HashMap<(u32, Live), Outcome>,
}

impl<'a> Checker<'a> {
    /// `relocated`: function bodies the wrapper relocated (securom_functions.csv targets).
    pub fn new(img: &'a Image, an: &'a Analysis, sl: &'a Sleigh, relocated: HashSet<u32>) -> Checker<'a> {
        let mut func_of = HashMap::new();
        for (&f, body) in &an.bodies {
            for &a in body {
                // shared code belongs to the nearest entry at or before it
                let e = func_of.entry(a).or_insert(f);
                if f <= a && (*e > a || f > *e) {
                    *e = f;
                }
            }
        }
        Checker {
            img,
            an,
            sl,
            regs: Regs::new(sl),
            parse: sl.new_parse(),
            info: HashMap::new(),
            func_of,
            refs_to: HashMap::new(),
            relocated,
            contracts: HashMap::new(),
            output_check: false,
            output_walk: false,
            input_walk: false,
            callee_memo: HashMap::new(),
            never_returned_memo: HashMap::new(),
            pushes_float_memo: HashMap::new(),
            input_hits: Vec::new(),
            input_memo: HashMap::new(),
        }
    }

    /// References to function entries and contract addresses, as Ghidra records them: flows,
    /// switch cases, calls/jumps through an initialised pointer, memory operands (READ),
    /// immediates (DATA) and aligned pointers in data sections (DATA). Sorted by source.
    fn index_refs(&mut self) {
        let an = self.an;
        let wanted = |t: u32| an.funcs.contains(&t) || self.contracts.contains_key(&t);
        let mut refs: HashMap<u32, Vec<(u32, RefKind)>> = HashMap::new();
        let mut add = |t: u32, from: u32, k: RefKind| {
            if wanted(t) {
                let v = refs.entry(t).or_default();
                if !v.iter().any(|&(f, _)| f == from) {
                    v.push((from, k));
                }
            }
        };
        for (&a, i) in &an.insns {
            match (i.flow, i.target) {
                (Flow::Call, Some(t)) => add(t, a, RefKind::UncondCall),
                (Flow::Jump, Some(t)) if an.funcs.contains(&t) => add(t, a, RefKind::UncondCall),
                (Flow::Jump, Some(t)) => add(t, a, RefKind::UncondJump),
                (Flow::CondJump, Some(t)) => add(t, a, RefKind::CondJump),
                _ => {}
            }
            for &t in an.tables.get(&a).into_iter().flatten() {
                add(t, a, RefKind::ComputedJump);
            }
            if let Some(s) = i.slot.filter(|s| !self.img.imports.contains_key(s)) {
                if let Some(t) = self.img.read_u32(s) {
                    add(t, a, if i.flow == Flow::CallInd { RefKind::ComputedCall } else { RefKind::ComputedJump });
                }
            }
            for &t in &i.refs {
                add(t, a, RefKind::Read);
            }
            for &t in &i.code_imms {
                add(t, a, RefKind::Data);
            }
        }
        // Pointers in data: every aligned word equal to an entry. (Only runs of 2+ code pointers,
        // like Create Address Tables, matched Ghidra on fewer rows.)
        let is_code = |v: u32| self.img.block_of(v).is_some_and(|s| s.exec);
        for s in self.img.sections.iter().filter(|s| !s.exec && s.name != "Headers") {
            for (o, c) in s.data.chunks_exact(4).enumerate() {
                add(u32::from_le_bytes(c.try_into().unwrap()), s.addr + 4 * o as u32, RefKind::Data);
            }
        }
        // Code references first (made while disassembling), then pointers in data.
        for v in refs.values_mut() {
            v.sort_by_key(|r| (!is_code(r.0), r.0));
        }
        self.refs_to = refs;
    }

    fn refs(&self, t: u32) -> Vec<(u32, RefKind)> {
        self.refs_to.get(&t).cloned().unwrap_or_default()
    }

    fn ins(&mut self, a: u32) -> Option<Rc<Info>> {
        if let Some(i) = self.info.get(&a) {
            return Some(i.clone());
        }
        let ins = self.an.insns.get(&a)?;
        let sec = self.img.block_of(a)?;
        let bytes = &sec.data[(a - sec.addr) as usize..];
        let d = self.sl.disasm(&mut self.parse, a as u64, bytes).ok()?;
        let ops = self.sl.pcode(&self.parse).unwrap_or_default();
        let (inputs, results) = reads_writes(&self.regs, &ops);
        let branch = matches!(ins.flow, Flow::Call | Flow::Jump | Flow::CondJump);
        let body = ghidra_operands(&d.body, branch);
        let text = if body.is_empty() { d.mnemonic.clone() } else { format!("{} {}", d.mnemonic, body) };
        let scalar0 = if d.body.starts_with("-0x") {
            parse_hex(&d.body[1..]).map(|v| (v as u32).wrapping_neg() as u64)
        } else {
            parse_hex(&d.body)
        };
        let reg0 = self.regs.by_name.get(d.body.as_str()).copied();
        let info = Rc::new(Info { mnem: d.mnemonic, text, inputs, results, scalar0, reg0 });
        self.info.insert(a, info.clone());
        Some(info)
    }

    fn flow(&self, a: u32) -> Fl {
        let an = self.an;
        let i = &an.insns[&a];
        let mut f = Fl { fall: Some(a + i.len as u32), ..Fl::default() };
        let noret_slot = i.slot.is_some_and(|s| an.noreturn.contains(&s));
        // CALL/JMP [ptr] through an initialised pointer to code: Ghidra flows to its value
        let via_ptr: Vec<u32> = i
            .slot
            .filter(|s| !self.img.imports.contains_key(s))
            .and_then(|s| self.img.read_u32(s))
            .filter(|&t| self.img.block_of(t).is_some_and(|s| s.exec))
            .into_iter()
            .collect();
        match i.flow {
            Flow::Fall => f.fallthrough = true,
            Flow::Call => {
                f.call = true;
                f.flows.extend(i.target);
                if i.target.is_some_and(|t| an.noreturn.contains(&t)) {
                    (f.terminal, f.fall) = (true, None);
                }
            }
            Flow::CallInd => {
                (f.call, f.computed, f.flows) = (true, true, via_ptr);
                if noret_slot {
                    (f.terminal, f.fall) = (true, None);
                }
            }
            // a JMP to a function: Shared Return Calls' CALL_RETURN override
            Flow::Jump if i.target.is_some_and(|t| an.funcs.contains(&t)) => {
                (f.call, f.terminal, f.fall) = (true, true, None);
                f.flows.extend(i.target);
            }
            Flow::Jump => {
                (f.jump, f.fall) = (true, None);
                f.flows.extend(i.target);
            }
            Flow::CondJump => {
                (f.jump, f.conditional) = (true, true);
                f.flows.extend(i.target);
            }
            Flow::JumpInd => {
                (f.jump, f.computed, f.fall) = (true, true, None);
                f.flows = an.tables.get(&a).cloned().unwrap_or(via_ptr);
            }
            Flow::Return => (f.terminal, f.fall) = (true, None),
        }
        f
    }

    fn next(&self, a: u32) -> Option<u32> {
        self.an.insns.range(a + 1..).next().map(|(&n, _)| n)
    }

    fn prev(&self, a: u32) -> Option<u32> {
        self.an.insns.range(..a).next_back().map(|(&n, _)| n)
    }

    fn keys_of(&self, name: &str) -> Vec<String> {
        self.regs.bytes_of(name).to_vec()
    }

    fn watched(&self, clobbers: &str, output: &str) -> Live {
        let mut out = Live::new();
        for c in clobbers.split(';') {
            let c = c.replace('?', ""); // `edx?`: clobbered for callers all the same
            if c.is_empty() {
                continue;
            }
            let names: Vec<String> = match c.as_str() {
                "flags" => FLAGS.iter().map(|s| s.to_string()).collect(),
                "st" => X87_CC.iter().map(|s| s.to_string()).collect(),
                _ => vec![c.to_uppercase()],
            };
            for n in names {
                out.extend(self.keys_of(&n));
            }
        }
        let written: &[&str] = match output {
            "eax" => &["EAX"],
            "al" => &["AL"],
            "edx:eax" => &["EAX", "EDX"],
            "xmm0" => &["XMM0_Da"],
            "st0" => &X87_CC,
            _ => &[],
        };
        for n in written {
            for k in self.regs.bytes_of(n) {
                out.remove(k);
            }
        }
        out
    }

    // Base registers the original writes anywhere in its body. Any flag write clobbers all
    // flags; any x87 condition write all four.
    fn written_by_original(&mut self, entry: u32) -> HashSet<String> {
        let mut out = HashSet::new();
        for a in self.body_of(entry) {
            let Some(i) = self.ins(a) else { continue };
            for &r in &i.results {
                let b = self.regs.base(r);
                if FLAGS.contains(&b) {
                    out.extend(FLAGS.iter().map(|s| s.to_string()));
                } else if X87_CC.contains(&b) {
                    out.extend(X87_CC.iter().map(|s| s.to_string()));
                } else {
                    out.insert(b.to_string());
                }
            }
        }
        out
    }

    fn body_of(&mut self, entry: u32) -> Vec<u32> {
        if self.an.funcs.contains(&entry) {
            if let Some(b) = self.an.bodies.get(&entry) {
                return b.clone();
            }
        }
        // Not in the inventory: the straight-line run from the entry.
        let mut run = Vec::new();
        let mut i = self.an.insns.contains_key(&entry).then_some(entry);
        while let Some(a) = i.filter(|_| run.len() < 64) {
            run.push(a);
            let t = self.flow(a);
            if t.terminal || (t.jump && !t.conditional) {
                break;
            }
            i = self.next(a);
        }
        if run.is_empty() {
            eprintln!("warning: no function or code at {}", hex(entry));
        }
        run
    }

    // Instructions whose result does not depend on the register they name.
    fn pure_write(text: &str) -> bool {
        let Some((m, ops)) = text.split_once(' ') else { return false };
        if ["XOR", "SUB", "PXOR", "XORPS", "XORPD"].contains(&m) {
            if let Some((a, b)) = ops.split_once(',') {
                return word(a) && a == b;
            }
        }
        (m == "OR" && ops.strip_suffix(",0xffffffff").is_some_and(ereg)) || (m == "AND" && ops.strip_suffix(",0x0").is_some_and(ereg))
    }

    // Alignment padding such as LEA ECX,[ECX] or MOV EDI,EDI.
    fn nop_move(text: &str) -> bool {
        let Some((m, ops)) = text.split_once(' ') else { return false };
        let Some((a, b)) = ops.split_once(',') else { return false };
        match m {
            "LEA" => ereg(a) && b.strip_prefix('[').and_then(|b| b.strip_suffix(']')) == Some(a),
            "MOV" | "XCHG" => ereg(a) && a == b,
            _ => false,
        }
    }

    /// `(AND|TEST) (E\w\w),0x([0-9a-f]+)`
    fn and_imm(text: &str) -> Option<(&str, u64)> {
        let (m, ops) = text.split_once(' ')?;
        if m != "AND" && m != "TEST" {
            return None;
        }
        let (r, imm) = ops.split_once(',')?;
        let h = imm.strip_prefix("0x")?;
        if !ereg(r) || h.is_empty() || !h.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
            return None;
        }
        Some((r, u64::from_str_radix(h, 16).ok()?))
    }

    fn reads_watched(&self, i: &Info, live: &Live) -> Option<String> {
        if Self::pure_write(&i.text) {
            return None;
        }
        if let Some(r) = i.text.strip_prefix("SBB ").and_then(|o| o.split_once(',')).filter(|(a, b)| ereg(a) && a == b) {
            let _ = r; // depends only on CF
            return live.contains("CF#0").then(|| "CF#0".to_string());
        }
        if let Some((r, mask)) = Self::and_imm(&i.text) {
            // AND r,imm reads only the bytes the mask keeps
            for b in 0..4 {
                let k = format!("{r}#{b}");
                if (mask >> (8 * b)) & 0xff != 0 && live.contains(&k) {
                    return Some(k);
                }
            }
            return None;
        }
        for &r in &i.inputs {
            for k in self.regs.keys(r) {
                if live.contains(k) {
                    return Some(k.clone());
                }
            }
        }
        None
    }

    fn kill(&self, i: &Info, live: &mut Live) {
        for &r in &i.results {
            for k in self.regs.keys(r) {
                live.remove(k);
            }
            // Output walk: code that writes AL treats EAX as a new value.
            if self.output_walk && self.regs.base(r) == "EAX" {
                live.retain(|k| base(k) != "EAX");
            }
        }
    }

    // Calls never see a watched x87 value. Removes the keys from `live` and returns them as
    // they stand after the call.
    fn x87_across_call(&mut self, target: Option<u32>, computed: bool, live: &mut Live) -> Live {
        let mut out = Live::new();
        let keys: Vec<String> = live.iter().filter(|k| base(k) == "X87").cloned().collect();
        for k in keys {
            live.remove(&k);
            if self.output_walk {
                continue;
            }
            let d: i64 = k[4..].parse().unwrap();
            let pushes = !computed && target.is_some_and(|t| self.pushes_float(t));
            out.insert(format!("X87#{}", d + pushes as i64));
        }
        out
    }

    // The watched x87 value is the key "X87#d": it sits at ST(d). Returns the key an
    // instruction reads, or moves the keys as the stack moves.
    fn x87_step(&self, i: &Info, live: &mut Live) -> Option<String> {
        let m = i.mnem.as_str();
        if m == "EMMS" || m == "FNINIT" || m == "FNSAVE" {
            live.retain(|k| base(k) != "X87");
            return None;
        }
        if !m.starts_with('F') || X87_CONTROL.contains(&m) || !live.iter().any(|k| base(k) == "X87") {
            return None;
        }
        let text = &i.text;
        let mut slots: Vec<i64> = Vec::new();
        let tb = text.as_bytes();
        let isw = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
        for (p, _) in text.match_indices("ST") {
            let before = p == 0 || !isw(tb[p - 1]);
            let digit = tb.get(p + 2).is_some_and(|b| b.is_ascii_digit());
            let after = tb.get(p + 3).is_none_or(|&b| !isw(b));
            if before && digit && after {
                slots.push((tb[p + 2] - b'0') as i64);
            }
        }
        let mut reads: BTreeSet<i64> = BTreeSet::new();
        let (mut overwritten, mut delta) = (-1i64, 0i64);
        if X87_PUSH.contains(&m) {
            reads.extend(&slots);
            delta = 1;
        } else if m == "FFREE" {
            overwritten = slots[0];
        } else if m == "FST" || X87_STORE_POP.contains(&m) {
            delta = if m == "FST" { 0 } else { -1 };
            if let Some(&s) = slots.first() {
                overwritten = s;
            }
            if !(m == "FSTP" && overwritten == 0) {
                reads.insert(0);
            }
        } else if m == "FCOMPP" || m == "FUCOMPP" {
            reads.extend([0, 1]);
            delta = -2;
        } else {
            reads.insert(0);
            reads.extend(&slots);
            if X87_READ_POP.contains(&m) {
                delta = -1;
                if slots.is_empty() && !text.contains("ptr") {
                    reads.insert(1);
                }
            } else if m == "FXCH" && slots.is_empty() {
                reads.insert(1);
            } else if ["FXTRACT", "FPTAN", "FSINCOS"].contains(&m) {
                delta = 1;
            }
        }
        let mut moved = Live::new();
        let keys: Vec<String> = live.iter().filter(|k| base(k) == "X87").cloned().collect();
        for k in keys {
            let d: i64 = k[4..].parse().unwrap();
            if reads.contains(&d) {
                return Some(k);
            }
            live.remove(&k);
            if d != overwritten {
                moved.insert(format!("X87#{}", d + delta));
            }
        }
        live.extend(moved);
        None
    }

    // MSVC's PUSH reg stack-reserve idiom: the pushed value is overwritten at [ESP] before
    // anything reads [ESP] or moves ESP.
    fn reserve_slot(&mut self, push: u32) -> bool {
        let mut i = self.next(push);
        for _ in 0..8 {
            let Some(a) = i else { return false };
            let Some(info) = self.ins(a) else { return false };
            if info.text.contains("[ESP]") {
                let Some((m, rest)) = info.text.split_once(' ') else { return false };
                let rest = rest.strip_prefix("dword ptr [ESP]").or_else(|| rest.strip_prefix("float ptr [ESP]"));
                return ["FSTP", "FST", "FISTP", "MOV", "MOVSS"].contains(&m)
                    && rest.is_some_and(|r| r.is_empty() || r.starts_with(','));
            }
            if !self.flow(a).fallthrough {
                return false;
            }
            if info.results.iter().any(|&r| self.regs.name(r) == "ESP") {
                return false;
            }
            i = self.next(a);
        }
        false
    }

    // Library of a call or jump through the import table, or None.
    fn import_library(&mut self, a: u32) -> Option<String> {
        if let Some(s) = self.an.insns[&a].slot {
            return self.img.imports.get(&s).map(|(lib, _)| lib.clone());
        }
        // `CALL ESI` after `MOV ESI,dword ptr [slot]`, which Ghidra resolves by constant
        // propagation. ponytail: the nearest write of the register before the call, by address
        // within the function, must be that MOV; full constant propagation would follow flow.
        let r = self.ins(a)?.reg0?;
        let f = *self.func_of.get(&a)?;
        let body = self.an.bodies.get(&f)?;
        let before: Vec<u32> = body[..body.partition_point(|&b| b < a)].iter().rev().copied().collect();
        for b in before {
            let i = self.ins(b)?;
            if i.results.iter().any(|&w| self.regs.base(w) == self.regs.base(r)) {
                let slot = self.an.insns[&b].refs.iter().find(|s| self.img.imports.contains_key(s));
                return slot.filter(|_| i.mnem == "MOV").map(|s| self.img.imports[s].0.clone());
            }
        }
        None
    }

    fn standard_entry(&self, f: u32) -> bool {
        // Address taken (data reference) or called indirectly; a direct JMP does not count.
        self.refs(f).iter().any(|&(_, t)| t.is_data() || (t.is_call() && t.is_computed()))
    }

    fn in_text(&self, a: u32) -> bool {
        self.img.block_of(a).is_some_and(|s| s.name == ".text")
    }

    // Walks from `start` while any watched value is live. Values still live at a return are
    // collected in at_return (flags excluded at depth 0).
    fn walk(&mut self, start: Option<u32>, live0: &Live, depth: usize) -> Outcome {
        let mut o = ok();
        let Some(start) = start else { return o }; // call that does not return
        let mut work: Vec<(u32, Live)> = vec![(start, live0.clone())];
        let mut seen: HashSet<(u32, Live)> = HashSet::new();
        let mut steps = 0;
        while let Some((at0, live1)) = work.pop() {
            let mut at = Some(at0);
            let mut live = live1;
            while let Some(a) = at.filter(|_| !live.is_empty()) {
                if !seen.insert((a, live.clone())) {
                    break;
                }
                steps += 1;
                if steps > MAX_STEPS {
                    return fail("unknown", &join(&live), &format!("{} step limit", hex(a)));
                }
                // The output check reads on through what the wrapper decoded; the input walk
                // reads relocated function bodies, not the wrapper's own code.
                let has_ins = self.an.insns.contains_key(&a);
                if !self.in_text(a) && !(self.output_check && has_ins) && !(self.input_walk && self.relocated_body(a)) {
                    return fail("unknown", &join(&live), &format!("{} enters wrapper code", hex(a)));
                }
                let Some(ins) = self.ins(a) else { return fail("unknown", "", &format!("{} no instruction", hex(a))) };
                let flow = self.flow(a);
                // A call wants the x87 stack empty: what is there after it is the callee's.
                if self.input_walk && (flow.call || self.mutated_return(a).is_some()) {
                    live.retain(|k| base(k) != "X87");
                }
                if Self::nop_move(&ins.text) {
                    at = flow.fall;
                    continue;
                }
                if self.output_check && ins.mnem == "PUSHAD" {
                    return fail("unknown", &join(&live), &format!("{} wrapper saves every register", hex(a)));
                }
                let resume = if self.output_check || self.input_walk { self.mutated_return(a) } else { None };
                if let Some(resume) = resume {
                    // PUSH next; JMP next is an opaque jump.
                    let to = self.mutated_target(a);
                    if to == Some(resume) {
                        return fail("unknown", &join(&live), &format!("{} opaque jump", hex(a)));
                    }
                    let x87 = self.x87_across_call(to, false, &mut live);
                    if !live.is_empty() {
                        let inner = match to {
                            Some(t) => self.callee(t, &live, depth + 1),
                            None => ok(),
                        };
                        if inner.status != "ok" {
                            return inner;
                        }
                        live = inner.at_return;
                    }
                    live.extend(x87);
                    at = Some(resume);
                    continue;
                }
                if flow.call || flow.jump {
                    let library = if flow.computed { self.import_library(a) } else { None };
                    if let Some(library) = library {
                        // Imports use standard conventions; only C++ runtime imports
                        // (thiscall) take an argument in ECX.
                        if live.iter().any(|k| base(k) == "ECX") && library.to_uppercase().starts_with("MSVCP") {
                            return fail("unknown", "ECX", &format!("{} live at {} import {}", hex(a), library, ins.text));
                        }
                        live.retain(|k| {
                            let b = base(k);
                            !(["EAX", "ECX", "EDX"].contains(&b) || b.starts_with("XMM") || b.starts_with("YMM") || flaglike(b))
                        });
                        let x87 = self.x87_across_call(None, true, &mut live);
                        live.extend(x87);
                        if flow.call {
                            at = flow.fall;
                            continue;
                        }
                        o.at_return.extend(live.iter().cloned());
                        break;
                    }
                }
                if flow.call && ins.mnem == "JMP" && flow.flows.len() == 1 {
                    // A jump Ghidra marks as a call (tail call): its returns are ours.
                    work.push((flow.flows[0], live.clone()));
                    break;
                }
                if flow.call {
                    live.retain(|k| !flaglike(base(k))); // flags are never call arguments
                    let target = if flow.flows.len() == 1 { Some(flow.flows[0]) } else { None };
                    let x87 = self.x87_across_call(target, flow.computed, &mut live);
                    if live.is_empty() && x87.is_empty() {
                        break;
                    }
                    if flow.computed {
                        if live.iter().any(|k| ["ECX", "EDX"].contains(&base(k))) {
                            return fail("unknown", &join(&live), &format!("{} live at indirect call {}", hex(a), ins.text));
                        }
                        live.retain(|k| !volatile_reg(k));
                        live.extend(x87);
                        at = flow.fall;
                        continue;
                    }
                    if live.is_empty() {
                        live.extend(x87);
                        at = flow.fall;
                        continue;
                    }
                    let known = if self.input_walk { target.and_then(|t| self.contracts.get(&t).cloned()) } else { None };
                    if let Some(known) = known {
                        // A callee with a contract: its inputs are reads, its writes kill.
                        for k in self.contract_inputs(&known) {
                            if live.contains(&k) {
                                self.input_hit(&k, &format!("{} {} passes it to {}", hex(a), ins.text, known[1]), &mut live);
                            }
                        }
                        for k in self.watched(&known[6], "") {
                            live.remove(&k);
                        }
                        for k in self.declared_regs(&known[5]) {
                            live.remove(&k);
                        }
                        live.extend(x87);
                        at = flow.fall;
                        continue;
                    }
                    if flow.flows.len() != 1 || depth >= MAX_DEPTH {
                        return fail("unknown", &join(&live), &format!("{} live at call {}", hex(a), ins.text));
                    }
                    let inner = self.callee(flow.flows[0], &live, depth + 1);
                    if inner.status != "ok" {
                        return inner;
                    }
                    live = inner.at_return;
                    live.extend(x87);
                    at = flow.fall;
                    continue;
                }
                let mut read = if ins.mnem == "PUSH" && self.reserve_slot(a) {
                    None
                } else if self.input_walk {
                    if self.saves(&ins, &mut live) {
                        None
                    } else {
                        self.input_read_whole(&ins, &live)
                    }
                } else {
                    self.reads_watched(&ins, &live)
                };
                if read.is_none() {
                    read = self.x87_step(&ins, &mut live);
                }
                // The input walk records a read and goes on without that register.
                while let Some(k) = read.clone().filter(|_| self.input_walk) {
                    self.input_hit(&k, &format!("{} {}", hex(a), ins.text), &mut live);
                    read = if self.saves(&ins, &mut Live::new()) { None } else { self.input_read_whole(&ins, &live) };
                    if read.is_none() {
                        read = self.x87_step(&ins, &mut live);
                    }
                }
                if let Some(k) = read {
                    return fail("violation", &k, &format!("{} {}", hex(a), ins.text));
                }
                self.kill(&ins, &mut live);
                if self.input_walk {
                    self.restores(&ins, &mut live);
                }
                if flow.terminal {
                    if depth == 0 {
                        live.retain(|k| !flaglike(base(k)));
                    }
                    o.at_return.extend(live.iter().cloned());
                    break;
                }
                if flow.jump {
                    if flow.flows.is_empty() {
                        return fail("unknown", &join(&live), &format!("{} computed jump {}", hex(a), ins.text));
                    }
                    // Jumps out of a function body are followed: the code reached returns to
                    // the same caller.
                    for &t in &flow.flows {
                        work.push((t, live.clone()));
                    }
                    if !flow.conditional {
                        break;
                    }
                }
                at = flow.fall;
            }
        }
        o
    }

    fn callee(&mut self, target: u32, live: &Live, depth: usize) -> Outcome {
        if self.input_walk {
            // A callee pops what it pushes: the caller's push histories pass through it.
            let (held, rest): (Live, Live) = live.iter().cloned().partition(|k| k.starts_with('H'));
            let key = (target, rest.clone());
            let o = match self.input_memo.get(&key) {
                Some(o) => o.clone(),
                None => {
                    let o = self.walk(Some(target), &rest, depth);
                    if o.status != "unknown" {
                        self.input_memo.insert(key, o.clone());
                    }
                    o
                }
            };
            if o.status != "ok" {
                return o;
            }
            let mut r = ok();
            r.at_return = o.at_return.into_iter().filter(|k| !k.starts_with('H')).collect();
            r.at_return.extend(held);
            return r;
        }
        if !self.output_check {
            return self.walk(Some(target), live, depth);
        }
        let key = (self.output_walk, self.input_walk, target, live.clone());
        if let Some(m) = self.callee_memo.get(&key) {
            return m.clone();
        }
        let o = self.walk(Some(target), live, depth);
        if o.status != "unknown" {
            self.callee_memo.insert(key, o.clone());
        }
        o
    }

    // Walks from a call's return address; a value still live when the caller returns is
    // followed into each of the caller's own call sites, up to MAX_UP levels.
    fn from_site(&mut self, ret: Option<u32>, live: &Live, up: usize) -> Outcome {
        let Some(r) = ret else { return ok() };
        let o = self.walk(Some(r), live, 0);
        if o.status != "ok" || o.at_return.is_empty() {
            return o;
        }
        let f = self.func_of.get(&r).copied();
        self.live_at_return(f, r, &o.at_return, up)
    }

    // `f`, reached at `at`, returns with `live` still unwritten.
    fn live_at_return(&mut self, f: Option<u32>, at: u32, live: &Live, up: usize) -> Outcome {
        let mut at_return = live.clone();
        if let (true, Some(f)) = (self.output_walk, f) {
            for k in self.never_returned(f) {
                at_return.remove(&k);
            }
            if let Some(contract) = self.contracts.get(&f).cloned() {
                // Its contract answers for what its callers read.
                for k in self.declared_output(&contract[5]) {
                    if at_return.contains(&k) {
                        return fail(
                            "violation",
                            &k,
                            &format!("{} returned by {} as its output {}", hex(at), contract[1], contract[5]),
                        );
                    }
                }
                return ok();
            }
            if at_return.is_empty() {
                return ok();
            }
        }
        if f.is_some_and(|f| self.standard_entry(f)) {
            // Standard convention: only EAX/EDX (or ST0) can carry a value back.
            at_return.retain(|k| !(volatile_reg(k) && !["EAX", "EDX", "X87"].contains(&base(k))));
            if at_return.is_empty() {
                return ok();
            }
        }
        let regs_live = join(&at_return);
        let Some(f) = f.filter(|_| up < MAX_UP) else {
            let of = f.map_or(String::new(), |f| format!(" of {}", hex(f)));
            return fail("unknown", &regs_live, &format!("{} live at return{of}", hex(at)));
        };
        let refs = self.refs(f);
        for &(from, kind) in &refs {
            let ci = self.ins(from);
            if let (true, Some(ci)) = (self.output_walk, &ci) {
                if !kind.is_computed() {
                    // Mutated calls and direct jumps, which site walks of the output also follow.
                    let inner = if let Some(resume) = self.mutated_return(from) {
                        Some(self.from_site(Some(resume), &at_return, up + 1))
                    } else if kind.is_jump() || ci.mnem == "JMP" {
                        let g = self.func_of.get(&from).copied();
                        Some(self.live_at_return(g, from, &at_return, up + 1))
                    } else {
                        None
                    };
                    if let Some(inner) = inner {
                        if inner.status != "ok" {
                            return inner;
                        }
                        continue;
                    }
                }
            }
            let fall = ci.as_ref().and_then(|_| self.flow(from).fall);
            if ci.is_none() || !kind.is_call() || kind.is_computed() || ci.as_ref().unwrap().mnem == "JMP" || fall.is_none() {
                return fail(
                    "unknown",
                    &regs_live,
                    &format!("{} live at return; {} reference from {}", hex(f), kind.name(), hex(from)),
                );
            }
            let inner = self.from_site(fall, &at_return, up + 1);
            if inner.status != "ok" {
                return inner;
            }
        }
        if refs.is_empty() {
            fail("unknown", &regs_live, &format!("{} live at return; no references", hex(f)))
        } else {
            ok()
        }
    }

    fn eax_bytes(&self) -> Live {
        self.keys_of("EAX").into_iter().collect()
    }

    fn declared_output(&self, output: &str) -> Live {
        let mut out = Live::new();
        if output == "eax" || output == "edx:eax" {
            out.extend(self.eax_bytes());
        }
        if output == "al" {
            out.extend(self.keys_of("AL"));
        }
        if output == "st0" {
            out.insert("X87#0".into());
        }
        out
    }

    // What the original cannot be returning: a path reaching RET with a byte of EAX still
    // unwritten, or with no net x87 push.
    fn never_returned(&mut self, entry: u32) -> Live {
        if let Some(m) = self.never_returned_memo.get(&entry) {
            return m.clone();
        }
        let was = self.output_walk;
        self.output_walk = false; // byte-exact here
        let mut out = Live::new();
        let eax = self.callee(entry, &self.eax_bytes(), 1);
        if eax.status == "ok" {
            let all = self.eax_bytes();
            out.extend(eax.at_return.into_iter().filter(|k| all.contains(k)));
        }
        let x87 = self.callee(entry, &Live::from(["X87#0".to_string()]), 1);
        if x87.status == "ok" && x87.at_return.contains("X87#0") {
            out.insert("X87#0".into());
        }
        self.output_walk = was;
        self.never_returned_memo.insert(entry, out.clone());
        out
    }

    // Does the function leave a value on the x87 stack at every return?
    fn pushes_float(&mut self, entry: u32) -> bool {
        if let Some(&m) = self.pushes_float_memo.get(&entry) {
            return m;
        }
        if let Some(c) = self.contracts.get(&entry) {
            return c[5] == "st0";
        }
        self.pushes_float_memo.insert(entry, false); // recursion
        let (was, was_input) = (self.output_walk, self.input_walk);
        (self.output_walk, self.input_walk) = (false, false);
        let o = self.walk(Some(entry), &Live::from(["X87#0".to_string()]), 1);
        (self.output_walk, self.input_walk) = (was, was_input);
        let pushes = o.status == "ok" && !o.at_return.is_empty() && !o.at_return.contains("X87#0");
        self.pushes_float_memo.insert(entry, pushes);
        pushes
    }

    // Is there sign the original returns the value? A plain load into the value that reaches
    // RET unread on every path is a return value. Returns the write, or None.
    fn return_sign(&mut self, entry: u32, bytes: &Live) -> Option<String> {
        let was = self.output_walk;
        self.output_walk = false;
        let mut found = None;
        for a in self.body_of(entry) {
            let Some(i) = self.ins(a) else { continue };
            if !["MOV", "MOVZX", "MOVSX", "LEA"].contains(&i.mnem.as_str()) && !Self::pure_write(&i.text) {
                continue;
            }
            let wrote: Live = i.results.iter().flat_map(|&r| self.regs.keys(r).iter().cloned()).filter(|k| bytes.contains(k)).collect();
            let fall = self.flow(a).fall;
            let Some(fall) = fall.filter(|_| !wrote.is_empty()) else { continue };
            let o = self.callee(fall, &wrote, 1);
            if o.status == "ok" && !o.at_return.is_empty() {
                found = Some(format!("{} {}", hex(a), i.text));
                break;
            }
        }
        self.output_walk = was;
        found
    }

    fn leaves_value(&mut self, entry: u32, lost: &Live) -> Option<String> {
        if lost.contains("X87#0") && self.pushes_float(entry) {
            return Some("pushes ST0 on every path".into());
        }
        let all = self.eax_bytes();
        let eax: Live = lost.iter().filter(|k| all.contains(*k)).cloned().collect();
        if eax.is_empty() {
            None
        } else {
            self.return_sign(entry, &eax)
        }
    }

    // SecuROM's mutated call: PUSH next; JMP callee, or PUSH next; PUSH callee; RET. Called at
    // the JMP or at the second PUSH.
    fn mutated_return(&mut self, a: u32) -> Option<u32> {
        let i = self.ins(a)?;
        let jump = i.mnem == "JMP" && self.flow(a).flows.len() == 1;
        let push_ret = i.mnem == "PUSH"
            && i.scalar0.is_some()
            && self.next(a).and_then(|n| self.ins(n)).is_some_and(|n| n.mnem == "RET");
        if !jump && !push_ret {
            return None;
        }
        let push = self.prev(a).and_then(|p| self.ins(p))?;
        if push.mnem != "PUSH" {
            return None;
        }
        let r = push.scalar0?;
        let at = a as u64;
        (at < r && r < at + 0x200).then_some(r as u32)
    }

    fn mutated_target(&mut self, a: u32) -> Option<u32> {
        let i = self.ins(a)?;
        if i.mnem == "JMP" {
            self.flow(a).flows.first().copied()
        } else {
            i.scalar0.map(|v| v as u32)
        }
    }

    fn lost_output(&mut self, row: &[String], target: u32) -> Live {
        let mut lost = Live::new();
        let clobbers: Vec<String> = row[6].split(';').map(|c| c.replace('?', "")).collect();
        if clobbers.iter().any(|c| c == "eax") || row[5] == "al" {
            lost.extend(self.eax_bytes());
        }
        if clobbers.iter().any(|c| c == "st") {
            lost.insert("X87#0".into());
        }
        for k in self.declared_output(&row[5]) {
            lost.remove(&k);
        }
        for k in self.never_returned(target) {
            lost.remove(&k);
        }
        lost
    }

    fn output_at_site(&mut self, from: u32, kind: RefKind, lost: &Live) -> Outcome {
        let ins = self.ins(from);
        let direct = ins.is_some() && !kind.is_computed();
        let resume = if ins.is_some() { self.mutated_return(from) } else { None };
        if resume.is_some() {
            return self.from_site(resume, lost, 0);
        }
        if let Some(i) = &ins {
            // A computed call Ghidra resolved to this function is a call site like any other.
            if kind.is_call() && i.mnem != "JMP" {
                let fall = self.flow(from).fall;
                return self.from_site(fall, lost, 0);
            }
        }
        // A direct jump leaves the value to the jumper's callers.
        if direct && (kind.is_call() || kind.is_jump()) {
            let f = self.func_of.get(&from).copied();
            return self.live_at_return(f, from, lost, 0);
        }
        fail("unknown", &join(lost), &format!("{} reference", kind.name()))
    }

    fn contract_inputs(&self, row: &[String]) -> Live {
        let mut out = Live::new();
        for i in row[3].split(';') {
            let r = i.split(':').next().unwrap_or("");
            if !r.is_empty() && r != "stack" {
                out.extend(self.keys_of(&r.to_uppercase()));
            }
        }
        out
    }

    fn declared_regs(&self, output: &str) -> Live {
        let mut out = Live::new();
        for r in output.split(':') {
            if !r.is_empty() && r != "st0" {
                out.extend(self.keys_of(&r.to_uppercase()));
            }
        }
        out
    }

    fn input_watch(&self, row: &[String]) -> Live {
        let mut live = Live::new();
        for r in ["EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP"].iter().chain(&FLAGS).chain(&X87_CC) {
            live.extend(self.keys_of(r));
        }
        // XMM: the low float only.
        for i in 0..8 {
            live.extend(self.keys_of(&format!("XMM{i}_Da")));
            live.insert(format!("X87#{i}"));
        }
        for k in self.contract_inputs(row) {
            live.remove(&k);
        }
        live
    }

    fn relocated_body(&self, a: u32) -> bool {
        self.an.insns.contains_key(&a) && self.func_of.get(&a).is_some_and(|f| self.relocated.contains(f))
    }

    // Pushing a register is no use of it: a save (EBX/ESI/EDI/EBP, popped back) or MSVC's
    // PUSH ECX stack reserve. The key "H<reg>/<bits>#" keeps one bit per push still on the
    // stack, 1 when the value pushed was undefined, so the POP makes it undefined again.
    fn saves(&self, ins: &Info, live: &mut Live) -> bool {
        let m = ins.mnem.as_str();
        if m == "PUSHAD" || m == "PUSHFD" {
            return true;
        }
        // A spill of a saved register into the frame (__SEH_prolog4's mov [esp+10h],ebp).
        if let Some(rest) = ins.text.strip_prefix("MOV dword ptr [ESP") {
            if let Some((mid, reg)) = rest.split_once("],") {
                let disp_ok = mid.is_empty()
                    || mid.strip_prefix(" + 0x").is_some_and(|h| !h.is_empty() && h.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
                if disp_ok && SAVED.contains(&reg) {
                    return true;
                }
            }
        }
        let Some(r) = ins.reg0.filter(|_| m == "PUSH") else { return false };
        let b = self.regs.base(r).to_string();
        if b == "ESP" {
            return false;
        }
        if SAVED.contains(&b.as_str()) {
            let undefined = live.contains(&format!("{b}#0"));
            let h = history(&b, live);
            if let Some(h) = &h {
                live.remove(h);
            }
            let mut bits = h.map_or(String::new(), |h| h[b.len() + 2..h.len() - 1].to_string());
            bits.push(if undefined { '1' } else { '0' });
            // ponytail: 8 pushes deep, as in the script.
            if bits.len() > 8 {
                bits = bits[bits.len() - 8..].to_string();
            }
            live.insert(format!("H{b}/{bits}#"));
        }
        true
    }

    fn restores(&self, ins: &Info, live: &mut Live) {
        let r = match ins.mnem.as_str() {
            "LEAVE" => Some(self.regs.get("EBP")),
            "POP" => ins.reg0,
            _ => None,
        };
        let Some(r) = r else { return };
        let b = self.regs.base(r).to_string();
        let Some(h) = history(&b, live) else { return };
        live.remove(&h);
        let bits = &h[b.len() + 2..h.len() - 1];
        if bits.ends_with('1') {
            live.extend(self.keys_of(&b));
        }
        if bits.len() > 1 {
            live.insert(format!("H{b}/{}#", &bits[..bits.len() - 1]));
        }
    }

    // Shifts, moves and the like list the flags among their inputs; only these and
    // conditional instructions use them.
    fn input_read(&self, ins: &Info, live: &Live) -> Option<String> {
        let m = ins.mnem.as_str();
        if FLAG_USERS.contains(&m) || m.starts_with('J') || m.starts_with("SET") || m.starts_with("CMOV") || m.starts_with("FCMOV") {
            return self.reads_watched(ins, live);
        }
        let no_flags: Live = live.iter().filter(|k| !flaglike(base(k))).cloned().collect();
        self.reads_watched(ins, &no_flags)
    }

    // The upper bytes of a register whose low byte the function wrote carry nothing.
    fn input_read_whole(&self, ins: &Info, live: &Live) -> Option<String> {
        let upper = |k: &str| {
            let b = k.as_bytes();
            b.len() == 5
                && b[0] == b'E'
                && b[3] == b'#'
                && (b'1'..=b'3').contains(&b[4])
                && ((b[1].is_ascii_uppercase() && b[2] == b'X') || (b"SDB".contains(&b[1]) && b"IP".contains(&b[2])))
        };
        let whole: Live = live.iter().filter(|k| !(upper(k) && !live.contains(&format!("{}#0", base(k))))).cloned().collect();
        self.input_read(ins, &whole)
    }

    // The first read of each register is the finding; the walk forgets it on this path.
    fn input_hit(&mut self, key: &str, where_: &str, live: &mut Live) {
        let b = reg_of(key).to_string();
        if !self.input_hits.iter().any(|(k, _)| *k == b) {
            self.input_hits.push((b.clone(), ["violation".into(), key.into(), where_.replace(',', " ")]));
        }
        live.retain(|k| reg_of(k) != b);
    }

    fn input_findings(&mut self, row: &[String]) -> Vec<[String; 3]> {
        let mut live = self.input_watch(row);
        self.input_hits.clear();
        self.input_memo.clear();
        self.input_walk = true;
        let entry = parse_hex(&row[0]).unwrap_or(0) as u32;
        // A walk that stops leaves what is still live unconcluded; the rest is walked again.
        for _ in 0..8 {
            if live.is_empty() {
                break;
            }
            let o = self.walk(Some(entry), &live, 0);
            if o.status == "ok" {
                break;
            }
            let mut regs: BTreeSet<String> =
                o.reg.split(';').filter(|k| k.contains('#')).map(|k| reg_of(k).to_string()).collect();
            regs.retain(|r| !self.input_hits.iter().any(|(k, _)| k == r));
            if regs.is_empty() {
                break;
            }
            let joined = regs.iter().cloned().collect::<Vec<_>>().join(";");
            let v = ["unconcluded".to_string(), joined.clone(), o.where_.clone()];
            match self.input_hits.iter_mut().find(|(k, _)| *k == joined) {
                Some(e) => e.1 = v,
                None => self.input_hits.push((joined, v)),
            }
            live.retain(|k| !regs.contains(reg_of(k)));
            self.input_memo.clear();
        }
        self.input_walk = false;
        self.input_hits.iter().map(|(_, v)| v.clone()).collect()
    }

    /// Runs the check of `register_abi.csv` (its text) and writes `abi_callers.csv` rows.
    /// Returns (references checked, output findings, input findings).
    pub fn run(&mut self, abi_csv: &str, out: &mut dyn Write) -> Result<(usize, usize, usize), String> {
        // A project without ClearFalseNoReturn stops every walk at 458 calls.
        if self.an.noreturn.contains(&0x0040_1740) && self.an.funcs.contains(&0x0040_1740) {
            return Err("SquareRootFloatX87 is flagged no-return; run ClearFalseNoReturn.java first".into());
        }
        let lines: Vec<&str> = abi_csv.lines().collect();
        if lines.first() != Some(&"address,name,kind,inputs,cleanup,output,clobbers") {
            return Err("unexpected register_abi.csv header".into());
        }
        let rows: Vec<Vec<String>> =
            lines[1..].iter().filter(|l| !l.trim().is_empty()).map(|l| l.split(',').map(String::from).collect()).collect();
        for f in &rows {
            if f.len() < 7 {
                return Err(format!("register_abi.csv: short row {}", f.join(",")));
            }
            let a = parse_hex(&f[0]).ok_or(format!("register_abi.csv: bad address {}", f[0]))? as u32;
            self.contracts.insert(a, f.clone());
        }
        self.index_refs();
        let io = |e: std::io::Error| e.to_string();
        let (mut total, mut output_findings, mut input_count) = (0, 0, 0);
        writeln!(out, "address,contract,site,status,register,instruction").map_err(io)?;
        for f in &rows {
            if f[2] == "extern" {
                continue; // not replaced: callers need no proof
            }
            let target = parse_hex(&f[0]).unwrap() as u32;
            let contract = format!("{}|{}", f[5], f[6]);
            let mut watch = self.watched(&f[6], &f[5]);
            let written = self.written_by_original(target);
            watch.retain(|k| !written.contains(base(k)));
            let refs = self.refs(target);
            for &(from, kind) in &refs {
                let ins = self.ins(from);
                let o = if watch.is_empty() {
                    fail("trivial", "", "every clobber is written by the original")
                } else if ins.is_none() || !kind.is_call() || kind.is_computed() {
                    fail("unknown", "", &format!("{} reference", kind.name()))
                } else if ins.as_ref().unwrap().mnem == "JMP" {
                    // A JMP Ghidra types as a call is a tail call.
                    fail("unknown", "", "tail jump reference")
                } else {
                    let fall = self.flow(from).fall;
                    self.from_site(fall, &watch, 0)
                };
                writeln!(out, "{},{contract},{},{},{},{}", f[0], hex(from), o.status, o.reg, o.where_).map_err(io)?;
                total += 1;
            }
            if refs.is_empty() {
                let st = if watch.is_empty() { "trivial" } else { "unknown" };
                writeln!(out, "{},{contract},,{st},,no references", f[0]).map_err(io)?;
            }
            // Output results: a row per finding, and one saying the check ran.
            self.output_check = true;
            let lost = self.lost_output(f, target);
            self.output_walk = true;
            if !lost.is_empty() {
                for &(from, kind) in &refs {
                    let mut o = self.output_at_site(from, kind, &lost);
                    if o.status == "ok" {
                        continue;
                    }
                    // A stopped walk blocks the build only when the original shows it returns the value.
                    if o.status == "unknown" {
                        match self.leaves_value(target, &lost) {
                            None => o.status = "unconcluded".into(),
                            Some(sign) => o = fail("unknown", &o.reg, &format!("{}; original returns it: {sign}", o.where_)),
                        }
                    }
                    writeln!(out, "{},{contract},output:{},{},{},{}", f[0], hex(from), o.status, o.reg, o.where_).map_err(io)?;
                    output_findings += 1;
                }
            }
            (self.output_walk, self.output_check) = (false, false);
            writeln!(out, "{},{contract},output,ok,{},output check ran", f[0], join(&lost)).map_err(io)?;
            for r in self.input_findings(f) {
                let site = r[2].split(' ').next().unwrap_or("");
                writeln!(out, "{},{contract},input:{site},{},{},{}", f[0], r[0], r[1], r[2]).map_err(io)?;
                input_count += 1;
            }
            writeln!(out, "{},{contract},input,ok,,input check ran", f[0]).map_err(io)?;
        }
        Ok((total, output_findings, input_count))
    }
}

// Indirect calls and functions reached through data use MSVC's standard conventions:
// EAX/ECX/EDX/XMM/flags are clobbered.
fn volatile_reg(key: &str) -> bool {
    let b = base(key);
    ["EAX", "ECX", "EDX"].contains(&b) || b.starts_with("XMM") || b.starts_with("YMM") || b.starts_with("ZMM") || flaglike(b)
}

fn history(b: &str, live: &Live) -> Option<String> {
    let p = format!("H{b}/");
    live.iter().find(|k| k.starts_with(&p)).cloned()
}

fn reg_of(key: &str) -> &str {
    if key.starts_with('H') {
        &key[1..key.find('/').unwrap_or(key.len())]
    } else {
        base(key)
    }
}

/// Operands as Ghidra's Java `Instruction.toString` prints them: memory addresses (a direct
/// branch target, `[0x...]`) as 8-digit `0x%08x`; scalars as they are; `, ` between operands as `,`.
fn ghidra_operands(body: &str, branch: bool) -> String {
    let body = body.replace(", ", ","); // Java joins operands with a bare comma
    let body = body.as_str();
    if branch {
        if let Some(v) = parse_hex(body) {
            return format!("0x{v:08x}");
        }
    }
    let mut out = String::new();
    let mut rest = body;
    while let Some(p) = rest.find("[0x") {
        let after = &rest[p + 3..];
        let end = after.find(']');
        let digits = end.map(|e| &after[..e]).filter(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_hexdigit()));
        let seg = p > 0 && rest.as_bytes()[p - 1] == b':';
        match (digits, seg) {
            (Some(d), false) => {
                out.push_str(&rest[..p]);
                out.push_str(&format!("[0x{:08x}]", u64::from_str_radix(d, 16).unwrap()));
                rest = &after[d.len() + 1..];
            }
            _ => {
                out.push_str(&rest[..p + 3]);
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}
