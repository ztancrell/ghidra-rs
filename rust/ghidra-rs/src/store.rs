//! The project store: the edits a project keeps on top of ghidra-rs's analysis, as one plain
//! text file that diffs in git (DESIGN.md, Decided 2026-11-15). Every run analyses from scratch;
//! `Store::apply` then lays the edits over the result. A `Project` is an analysis with its
//! store: each edit through it changes both, and `Project::finish` proves that the store alone
//! gives the same program again. See rust/README.md "Project store".
//!
//! One record per line, fields separated by one space, addresses as `0x%08x`, written in the
//! order they are applied and sorted by address within a kind:
//!
//! ```text
//! ghidra-rs-store 1
//! clear <first>-<last>               instructions overlapping the range are removed
//! noreturn <addr> on|off             the no-return flag of a function (or import slot)
//! switch <jump> <target>...          the targets of a computed jump
//! code <addr>                        disassemble from here (flow is followed)
//! function <entry> create|remove     a function analysis lacks, or one it has
//! body <entry> <first>-<last>...     a fixed body in place of the flow from the entry
//! override <addr> call_return|none   the flow override of an instruction
//! thunk <entry> off|<target>         the function is (not) a thunk
//! ```

use crate::analysis::{Analysis, Flow, Image, Ins};
use crate::sleigh::Sleigh;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Write as _;

const HEADER: &str = "ghidra-rs-store 1";

#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub struct Store {
    pub clear: BTreeSet<(u32, u32)>,
    pub noreturn: BTreeMap<u32, bool>,
    pub switches: BTreeMap<u32, Vec<u32>>,
    pub code: BTreeSet<u32>,
    /// true: create, false: remove
    pub functions: BTreeMap<u32, bool>,
    pub bodies: BTreeMap<u32, Vec<(u32, u32)>>,
    /// true: CALL_RETURN, false: none
    pub overrides: BTreeMap<u32, bool>,
    pub thunks: BTreeMap<u32, Option<u32>>,
}

impl std::fmt::Display for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ranges = |r: &[(u32, u32)]| r.iter().fold(String::new(), |s, (a, b)| s + &format!(" 0x{a:08x}-0x{b:08x}"));
        writeln!(f, "{HEADER}")?;
        for &r in &self.clear {
            writeln!(f, "clear{}", ranges(&[r]))?;
        }
        for (a, on) in &self.noreturn {
            writeln!(f, "noreturn 0x{a:08x} {}", if *on { "on" } else { "off" })?;
        }
        for (a, targets) in &self.switches {
            let t = targets.iter().fold(String::new(), |s, t| s + &format!(" 0x{t:08x}"));
            writeln!(f, "switch 0x{a:08x}{t}")?;
        }
        for a in &self.code {
            writeln!(f, "code 0x{a:08x}")?;
        }
        for (a, create) in &self.functions {
            writeln!(f, "function 0x{a:08x} {}", if *create { "create" } else { "remove" })?;
        }
        for (a, r) in &self.bodies {
            writeln!(f, "body 0x{a:08x}{}", ranges(r))?;
        }
        for (a, on) in &self.overrides {
            writeln!(f, "override 0x{a:08x} {}", if *on { "call_return" } else { "none" })?;
        }
        for (a, t) in &self.thunks {
            writeln!(f, "thunk 0x{a:08x} {}", t.map_or("off".into(), |t| format!("0x{t:08x}")))?;
        }
        Ok(())
    }
}

impl Store {
    /// Reads the text of a store. Anything it does not know is an error, never skipped.
    pub fn parse(text: &str) -> Result<Store, String> {
        let mut lines = text.lines().enumerate();
        if lines.next().map(|l| l.1) != Some(HEADER) {
            return Err(format!("not a project store this version reads: the first line must be `{HEADER}`"));
        }
        let mut s = Store::default();
        for (n, line) in lines {
            let err = |why: &str| format!("line {}: {why}: {line}", n + 1);
            let addr = |t: &str| {
                let hex = t.strip_prefix("0x").filter(|h| h.len() == 8);
                hex.and_then(|h| u32::from_str_radix(h, 16).ok()).ok_or_else(|| err("bad address"))
            };
            let range = |t: &str| -> Result<(u32, u32), String> {
                let (a, b) = t.split_once('-').ok_or_else(|| err("bad range"))?;
                let r = (addr(a)?, addr(b)?);
                if r.0 > r.1 {
                    return Err(err("bad range"));
                }
                Ok(r)
            };
            let fields: Vec<&str> = line.split(' ').collect();
            let fresh = match fields.as_slice() {
                ["clear", r] => s.clear.insert(range(r)?),
                ["noreturn", a, v @ ("on" | "off")] => s.noreturn.insert(addr(a)?, *v == "on").is_none(),
                ["switch", a, t @ ..] if !t.is_empty() => {
                    let targets = t.iter().map(|t| addr(t)).collect::<Result<_, _>>()?;
                    s.switches.insert(addr(a)?, targets).is_none()
                }
                ["code", a] => s.code.insert(addr(a)?),
                ["function", a, v @ ("create" | "remove")] => s.functions.insert(addr(a)?, *v == "create").is_none(),
                ["body", a, r @ ..] if !r.is_empty() => {
                    let body = r.iter().map(|r| range(r)).collect::<Result<_, _>>()?;
                    s.bodies.insert(addr(a)?, body).is_none()
                }
                ["override", a, v @ ("call_return" | "none")] => {
                    s.overrides.insert(addr(a)?, *v == "call_return").is_none()
                }
                ["thunk", a, "off"] => s.thunks.insert(addr(a)?, None).is_none(),
                ["thunk", a, t] => s.thunks.insert(addr(a)?, Some(addr(t)?)).is_none(),
                _ => return Err(err("unknown record")),
            };
            if !fresh {
                return Err(err("a second record of this kind for the address"));
            }
        }
        Ok(s)
    }

    pub fn load(path: &str) -> Result<Store, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
        Store::parse(&text).map_err(|e| format!("{path}: {e}"))
    }

    /// Lays the edits over a fresh analysis, in the order of the file, and computes the bodies
    /// again. A record that cannot hold (no instruction decodes at a `code` or `function`
    /// address, a `body` or `thunk` of no function) is an error.
    pub fn apply(&self, an: &mut Analysis, img: &Image, sl: &Sleigh) -> Result<(), String> {
        for &(lo, hi) in &self.clear {
            clear_insns(an, lo, hi);
        }
        for (&a, &on) in &self.noreturn {
            if on {
                an.noreturn.insert(a);
            } else {
                an.noreturn.remove(&a);
            }
        }
        let code: Vec<u32> = self.code.iter().copied().collect();
        an.disassemble(img, sl, &code, false);
        let need_insn = |an: &Analysis, kind: &str, a: u32| match an.insns.contains_key(&a) {
            true => Ok(()),
            false => Err(format!("store: {kind} 0x{a:08x}: no instruction there")),
        };
        for &a in &self.code {
            need_insn(an, "code", a)?;
        }
        for (&a, targets) in &self.switches {
            need_insn(an, "switch", a)?;
            an.tables.insert(a, targets.clone());
        }
        for (&f, &create) in &self.functions {
            if create {
                need_insn(an, "function", f)?;
                an.funcs.insert(f);
            } else {
                an.funcs.remove(&f);
            }
        }
        for &a in self.overrides.keys() {
            need_insn(an, "override", a)?;
        }
        for (kind, f) in self.bodies.keys().map(|f| ("body", f)).chain(self.thunks.keys().map(|f| ("thunk", f))) {
            if !an.funcs.contains(f) {
                return Err(format!("store: {kind} 0x{f:08x}: no function there"));
            }
        }
        an.overrides = self.overrides.iter().map(|(&a, &o)| (a, o)).collect();
        an.fixed_bodies = self.bodies.clone();
        an.thunks = self.thunks.iter().map(|(&f, &t)| (f, t)).collect();
        an.compute_bodies();
        an.stack_purges(img);
        Ok(())
    }
}

/// Ghidra's `clearListing(lo, hi)` for instructions: every one overlapping the range goes.
fn clear_insns(an: &mut Analysis, lo: u32, hi: u32) -> Vec<u32> {
    let before = an.insns.range(..lo).next_back().filter(|(&a, i)| a + i.len as u32 > lo);
    let from = before.map_or(lo, |(&a, _)| a);
    let gone: Vec<u32> = an.insns.range(from..=hi).map(|(&a, _)| a).collect();
    for a in &gone {
        an.insns.remove(a);
        an.tables.remove(a);
    }
    gone
}

/// The kind of a reference, named as Ghidra's `RefType` prints it.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Ref {
    UnconditionalJump,
    ConditionalJump,
    ComputedJump,
    UnconditionalCall,
    ComputedCall,
    Data,
}

impl Ref {
    pub fn is_jump(self) -> bool {
        matches!(self, Ref::UnconditionalJump | Ref::ConditionalJump | Ref::ComputedJump)
    }

    pub fn is_flow(self) -> bool {
        self != Ref::Data
    }

    pub fn name(self) -> &'static str {
        match self {
            Ref::UnconditionalJump => "UNCONDITIONAL_JUMP",
            Ref::ConditionalJump => "CONDITIONAL_JUMP",
            Ref::ComputedJump => "COMPUTED_JUMP",
            Ref::UnconditionalCall => "UNCONDITIONAL_CALL",
            Ref::ComputedCall => "COMPUTED_CALL",
            Ref::Data => "DATA",
        }
    }
}

/// The references of the instruction at `a`: (to, kind).
fn refs_from(an: &Analysis, a: u32, i: &Ins) -> Vec<(u32, Ref)> {
    let mut out: Vec<(u32, Ref)> = Vec::new();
    match i.flow {
        Flow::Jump => out.extend(i.target.map(|t| (t, Ref::UnconditionalJump))),
        Flow::CondJump => out.extend(i.target.map(|t| (t, Ref::ConditionalJump))),
        Flow::Call => out.extend(i.target.map(|t| (t, Ref::UnconditionalCall))),
        Flow::JumpInd => match an.tables.get(&a) {
            Some(cases) => out.extend(cases.iter().map(|&t| (t, Ref::ComputedJump))),
            None => out.extend(i.computed.map(|t| (t, Ref::ComputedJump))),
        },
        Flow::CallInd => out.extend(i.computed.map(|t| (t, Ref::ComputedCall))),
        Flow::Fall | Flow::Return => {}
    }
    out.extend(i.refs.iter().chain(&i.code_imms).map(|&t| (t, Ref::Data)));
    out
}

/// An analysis with its store, edited together through Ghidra's script primitives.
pub struct Project<'a> {
    pub img: &'a Image,
    pub sl: &'a Sleigh,
    pub an: Analysis,
    pub store: Store,
    // ponytail: a Vec per instruction (about 100 MB on mercs2); a map of the shared ones only
    // if memory ever matters
    /// the functions whose body holds each instruction
    owners: HashMap<u32, Vec<u32>>,
    /// the references to each address, sorted: (from, kind)
    refs: HashMap<u32, Vec<(u32, Ref)>>,
}

impl<'a> Project<'a> {
    /// `an`: the analysis with `store` applied.
    pub fn new(img: &'a Image, sl: &'a Sleigh, an: Analysis, store: Store) -> Project<'a> {
        let mut p = Project { img, sl, an, store, owners: HashMap::new(), refs: HashMap::new() };
        for (&f, body) in &p.an.bodies {
            for &a in body {
                p.owners.entry(a).or_default().push(f);
            }
        }
        let all: Vec<u32> = p.an.insns.keys().copied().collect();
        p.index_refs(&all, true);
        for (&slot, &t) in &p.an.table_slots {
            p.refs.entry(t).or_default().push((slot, Ref::Data));
        }
        p.refs.values_mut().for_each(|v| v.sort_unstable());
        p
    }

    fn index_refs(&mut self, insns: &[u32], add: bool) {
        for &a in insns {
            for (to, kind) in refs_from(&self.an, a, &self.an.insns[&a]) {
                let v = self.refs.entry(to).or_default();
                match (v.binary_search(&(a, kind)), add) {
                    (Err(at), true) => v.insert(at, (a, kind)),
                    (Ok(at), false) => drop(v.remove(at)),
                    _ => {}
                }
            }
        }
    }

    /// `getReferencesTo(a)`, by source address. Fall-through is not a reference.
    pub fn refs_to(&self, a: u32) -> Vec<(u32, Ref)> {
        self.refs.get(&a).cloned().unwrap_or_default()
    }

    /// `getInstructionContaining(a)`: its address.
    pub fn insn_containing(&self, a: u32) -> Option<u32> {
        self.an.insns.range(..=a).next_back().filter(|(&s, i)| a < s + i.len as u32).map(|(&s, _)| s)
    }

    /// `getFunctionContaining(a)`. Bodies can share instructions here: the function starting
    /// at the instruction, else the lowest entry.
    pub fn function_containing(&self, a: u32) -> Option<u32> {
        let s = self.insn_containing(a)?;
        if self.an.funcs.contains(&s) {
            return Some(s);
        }
        self.owners.get(&s)?.iter().min().copied()
    }

    /// The functions whose bodies hold the instruction at `a`.
    pub fn owners_at(&self, a: u32) -> &[u32] {
        self.owners.get(&a).map_or(&[], |v| v)
    }

    /// The instruction has a CALL_RETURN flow override.
    pub fn call_return(&self, a: u32) -> bool {
        self.an.insns.get(&a).is_some_and(|i| self.an.call_return(a, i))
    }

    /// `getFlowType().isCall()`: a call, or a jump overridden to a call that returns.
    pub fn is_call(&self, a: u32) -> bool {
        let i = &self.an.insns[&a];
        matches!(i.flow, Flow::Call | Flow::CallInd) || i.flow == Flow::Jump && self.call_return(a)
    }

    /// `getFlowType().isJump()`.
    pub fn is_jump(&self, a: u32) -> bool {
        matches!(self.an.insns[&a].flow, Flow::Jump | Flow::CondJump | Flow::JumpInd) && !self.call_return(a)
    }

    /// `getFlows()`: the targets of the instruction's flow references.
    pub fn flows(&self, a: u32) -> Vec<u32> {
        let refs = refs_from(&self.an, a, &self.an.insns[&a]);
        refs.into_iter().filter(|r| r.1.is_flow()).map(|r| r.0).collect()
    }

    /// `getFallThrough()`.
    pub fn fallthrough(&self, a: u32) -> Option<u32> {
        let i = &self.an.insns[&a];
        let calls = matches!(i.flow, Flow::Call | Flow::CallInd);
        (i.falls_through() && !(calls && self.call_return(a))).then_some(a + i.len as u32)
    }

    /// `Function.getThunkedFunction`: the mark of the store, else derived: a body of one jump
    /// to a function or through an import slot.
    pub fn thunked(&self, f: u32) -> Option<u32> {
        if let Some(&t) = self.an.thunks.get(&f) {
            return t;
        }
        let [a] = self.an.bodies.get(&f)?.as_slice() else { return None };
        let i = &self.an.insns[a];
        match i.flow {
            Flow::Jump => i.target.filter(|t| *t != f && self.an.funcs.contains(t)),
            Flow::JumpInd => i.slot.filter(|s| self.img.imports.contains_key(s)),
            _ => None,
        }
    }

    /// The bytes of a function's body (`getBody().getNumAddresses()`).
    pub fn body_bytes(&self, f: u32) -> u64 {
        self.an.bodies.get(&f).map_or(0, |b| b.iter().map(|a| self.an.insns[a].len as u64).sum())
    }

    /// Computes the bodies of `funcs` again and keeps `owners` in step.
    fn rebody(&mut self, funcs: impl IntoIterator<Item = u32>) {
        for f in funcs.into_iter().collect::<BTreeSet<u32>>() {
            for a in self.an.bodies.remove(&f).unwrap_or_default() {
                if let Some(v) = self.owners.get_mut(&a) {
                    v.retain(|g| *g != f);
                }
            }
            if self.an.funcs.contains(&f) {
                let body = self.an.body_of(f);
                for &a in &body {
                    self.owners.entry(a).or_default().push(f);
                }
                self.an.bodies.insert(f, body);
            }
        }
    }

    fn owners_of(&self, insns: impl IntoIterator<Item = u32>) -> Vec<u32> {
        insns.into_iter().flat_map(|a| self.owners.get(&a).cloned().unwrap_or_default()).collect()
    }

    /// The functions whose flow enters `a`: through a jump, or by falling into it.
    fn flowing_into(&self, a: u32) -> Vec<u32> {
        let jumps = self.refs_to(a).into_iter().filter(|r| r.1.is_jump()).map(|r| r.0);
        let before = self.an.insns.range(..a).next_back().filter(|(&s, i)| s + i.len as u32 == a).map(|(&s, _)| s);
        self.owners_of(jumps.chain(before))
    }

    /// `disassemble(a)`: true when an instruction starts at `a` afterwards.
    pub fn disassemble(&mut self, a: u32) -> bool {
        if self.an.insns.contains_key(&a) {
            return true;
        }
        let new = self.an.disassemble(self.img, self.sl, &[a], false);
        if !self.an.insns.contains_key(&a) {
            return false;
        }
        self.store.code.insert(a);
        self.index_refs(&new, true);
        let reached: Vec<u32> = new.iter().flat_map(|&n| self.flowing_into(n)).collect();
        self.rebody(reached);
        true
    }

    /// `clearListing(lo, hi)`.
    pub fn clear(&mut self, lo: u32, hi: u32) {
        let gone: Vec<u32> = match self.insn_containing(lo) {
            Some(first) => self.an.insns.range(first..=hi).map(|(&a, _)| a).collect(),
            None => self.an.insns.range(lo..=hi).map(|(&a, _)| a).collect(),
        };
        self.index_refs(&gone, false);
        let owners = self.owners_of(gone.iter().copied());
        if gone.is_empty() {
            return;
        }
        clear_insns(&mut self.an, lo, hi);
        self.store.clear.insert((lo, hi));
        for a in &gone {
            self.store.code.remove(a);
            self.store.switches.remove(a);
            self.store.overrides.remove(a);
            self.an.overrides.remove(a);
        }
        self.rebody(owners);
    }

    /// `createFunction(a, null)`. False without an instruction at `a`: Java Ghidra makes a
    /// function of one undefined byte there, which this analysis cannot hold.
    pub fn create_function(&mut self, a: u32) -> bool {
        if !self.an.insns.contains_key(&a) {
            return false;
        }
        if self.an.funcs.insert(a) {
            // a `remove` record means analysis has the function: dropping the record brings it back
            if self.store.functions.remove(&a) != Some(false) {
                self.store.functions.insert(a, true);
            }
            let split = self.owners_of([a]);
            self.rebody(split.into_iter().chain([a]));
        }
        true
    }

    /// `removeFunction(f)`: its marks in the store go with it.
    pub fn remove_function(&mut self, f: u32) {
        if !self.an.funcs.remove(&f) {
            return;
        }
        if self.store.functions.remove(&f) != Some(true) {
            self.store.functions.insert(f, false);
        }
        self.store.bodies.remove(&f);
        self.store.thunks.remove(&f);
        self.an.fixed_bodies.remove(&f);
        self.an.thunks.remove(&f);
        // jumps to it are no tail calls now: their owners flow on
        let into = self.flowing_into(f);
        self.rebody(into.into_iter().chain([f]));
    }

    /// `Function.setNoReturn`.
    pub fn set_noreturn(&mut self, f: u32, on: bool) {
        if on {
            self.an.noreturn.insert(f);
        } else {
            self.an.noreturn.remove(&f);
        }
        self.store.noreturn.insert(f, on);
        let callers = self.owners_of(self.refs_to(f).into_iter().map(|r| r.0));
        self.rebody(callers);
    }

    /// `Instruction.setFlowOverride`: CALL_RETURN or NONE.
    pub fn set_override(&mut self, a: u32, call_return: bool) {
        self.an.overrides.insert(a, call_return);
        self.store.overrides.insert(a, call_return);
        self.rebody(self.owners_of([a]));
    }

    /// `Function.setThunkedFunction`.
    pub fn set_thunk(&mut self, f: u32, target: Option<u32>) {
        self.an.thunks.insert(f, target);
        self.store.thunks.insert(f, target);
    }

    /// `Function.setBody`: the body is these instructions, whatever the flow says.
    pub fn set_body(&mut self, f: u32, insns: &BTreeSet<u32>) {
        let mut ranges: Vec<(u32, u32)> = Vec::new();
        for &a in insns {
            let last = a + self.an.insns[&a].len as u32 - 1;
            match ranges.last_mut() {
                Some(r) if r.1 + 1 == a => r.1 = last,
                _ => ranges.push((a, last)),
            }
        }
        self.an.fixed_bodies.insert(f, ranges.clone());
        self.store.bodies.insert(f, ranges);
        self.rebody([f]);
    }

    /// `CreateFunctionCmd.fixupFunctionBody`: the body is the flow from the entry again.
    pub fn reflow(&mut self, f: u32) {
        self.an.fixed_bodies.remove(&f);
        self.store.bodies.remove(&f);
        self.rebody([f]);
    }

    /// COMPUTED_JUMP references from the jump at `a` to `targets`.
    pub fn set_switch(&mut self, a: u32, targets: Vec<u32>) {
        self.index_refs(&[a], false);
        self.an.tables.insert(a, targets.clone());
        self.store.switches.insert(a, targets);
        self.index_refs(&[a], true);
        self.rebody(self.owners_of([a]));
    }

    /// Ends the edits: the store, once it is shown to give this program again when applied to
    /// `base` (the analysis before any store). A difference is an error, so a store is never
    /// written that does not hold what the commands did.
    pub fn finish(self, mut base: Analysis) -> Result<Store, String> {
        self.store.apply(&mut base, self.img, self.sl)?;
        let live = &self.an;
        let first = |a: Vec<u32>, b: Vec<u32>| {
            let (a, b): (BTreeSet<u32>, BTreeSet<u32>) = (a.into_iter().collect(), b.into_iter().collect());
            a.symmetric_difference(&b).next().copied()
        };
        let keys = |an: &Analysis| an.insns.keys().copied().collect::<Vec<u32>>();
        let differs = [
            ("instructions", first(keys(live), keys(&base))),
            ("functions", first(live.funcs.iter().copied().collect(), base.funcs.iter().copied().collect())),
            (
                "no-return flags",
                first(live.noreturn.iter().copied().collect(), base.noreturn.iter().copied().collect()),
            ),
            ("switch targets", first(live.tables.keys().copied().collect(), base.tables.keys().copied().collect())),
            ("switch targets", live.tables.iter().find(|(a, t)| base.tables.get(a) != Some(t)).map(|(&a, _)| a)),
            ("bodies", first(live.bodies.keys().copied().collect(), base.bodies.keys().copied().collect())),
            ("bodies", live.bodies.iter().find(|(f, b)| base.bodies.get(f) != Some(b)).map(|(&f, _)| f)),
        ];
        let mut why = String::new();
        for (what, at) in differs {
            if let Some(a) = at {
                let _ = write!(why, " {what} differ, first at 0x{a:08x};");
            }
        }
        if !why.is_empty() {
            return Err(format!("the store does not reproduce the edits (nothing written):{why}"));
        }
        Ok(self.store)
    }
}
