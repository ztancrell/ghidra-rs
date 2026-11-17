//! mercs2's five project-editing Ghidra scripts (mercs2-decomp `tools/ghidra/*.java`), ported
//! statement by statement onto `store::Project`, so their edits land in the project store.
//! Each function names its script; comments mark what this analysis has no state for. See
//! rust/README.md "Project store" for how the results compare with Java's.

use crate::analysis::Flow;
use crate::store::Project;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::io::Write;

type Res<T> = Result<T, String>;

/// `Long.decode` of an address.
fn decode(s: &str) -> Res<u32> {
    let n = match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(hex) => u32::from_str_radix(hex, 16),
        None => s.parse(),
    };
    n.map_err(|e| format!("address `{s}`: {e}"))
}

fn io(e: std::io::Error) -> String {
    format!("report: {e}")
}

/// `getInt(a)`, which throws where no memory is.
fn pointer(p: &Project, a: u32) -> Res<u32> {
    p.img.read_u32(a).ok_or(format!("no memory at 0x{a:08x}"))
}

/// The mnemonic and operands of the instruction that decodes at `a`, and its length.
fn text_at(p: &Project, a: u32) -> Option<(String, String, u32)> {
    let sec = p.img.block_of(a)?;
    let ins = p.sl.disasm(&mut p.sl.new_parse(), a as u64, &sec.data[(a - sec.addr) as usize..]).ok()?;
    Some((ins.mnemonic, ins.body, ins.len as u32))
}

fn mnemonic(p: &Project, a: u32) -> String {
    text_at(p, a).map_or(String::new(), |t| t.0)
}

/// AddRelocatedEntries.java: a function at each entry of `config/securom_functions.csv` (its
/// text) that lies in none.
pub fn add_relocated_entries(p: &mut Project, csv: &str) -> Res<()> {
    let mut added = 0;
    for line in csv.lines().filter(|l| l.starts_with("0x")) {
        let a = decode(line.split(',').next().unwrap_or(""))?;
        if p.function_containing(a).is_some() {
            continue;
        }
        if !p.an.insns.contains_key(&a) {
            p.clear(a, a + 5);
            p.disassemble(a);
        }
        if p.create_function(a) {
            added += 1;
        } else {
            eprintln!("AddRelocatedEntries: 0x{a:08x} not created: no instruction decodes there (Java makes a one-byte function)");
        }
    }
    println!("AddRelocatedEntries: {added} functions added");
    Ok(())
}

/// DefineTableFunctions.java: a function at every `.text` pointer of the data ranges
/// `start end [start end]...` that lies in none.
pub fn define_table_functions(p: &mut Project, args: &[String]) -> Res<()> {
    let mut created = 0;
    for [start, end] in args.as_chunks::<2>().0 {
        let (start, end) = (decode(start)?, decode(end)?);
        for at in (start..end.saturating_sub(3)).step_by(4) {
            let target = pointer(p, at)?;
            if !p.an.is_text(target) || p.function_containing(target).is_some() {
                continue;
            }
            p.disassemble(target);
            if !p.create_function(target) {
                eprintln!("DefineTableFunctions: {target:08x} not created: no instruction decodes there (Java makes a one-byte function)");
                continue;
            }
            println!("defined {target:08x} (pointer at {at:08x})");
            created += 1;
        }
    }
    println!("defined {created} functions");
    Ok(())
}

/// RecoverFunctions.java: functions from pointer runs in `.rdata`/`.data` and from direct
/// calls, with the audit CSV. Defined data is only known for address-table slots here.
pub fn recover_functions(p: &mut Project, out: &mut dyn Write) -> Res<()> {
    fn recover(p: &mut Project, target: u32) -> Res<&'static str> {
        let text_end = p.an.text_end;
        if p.an.funcs.contains(&target) {
            return Ok("existing");
        }
        if p.function_containing(target).is_some() {
            return Ok("inside_function");
        }
        if p.an.table_slots.range(..=target).next_back().is_some_and(|(&s, _)| target < s + 4) {
            return Ok("defined_data");
        }
        if p.insn_containing(target).is_some_and(|s| s != target) {
            return Ok("inside_instruction");
        }
        // Leave wrapper-entry stubs to the separate slot investigation.
        let bytes = p.img.block_of(target).map(|s| &s.data[(target - s.addr) as usize..]);
        if target as u64 + 6 <= text_end as u64 && bytes.is_some_and(|b| b.starts_with(&[0xff, 0x25])) {
            let slot = pointer(p, target + 2)?;
            if p.img.block_of(slot).is_some_and(|s| s.name == ".securom") {
                return Ok("wrapper_entry");
            }
        }
        if !p.disassemble(target) {
            // Java tells "disassembly_failed" from "no_entry_instruction" by what disassemble()
            // returned, which is true even when a conflict stopped it; one answer here
            return Ok("no_entry_instruction");
        }
        if !p.create_function(target) {
            return Ok("creation_failed");
        }
        Ok("created")
    }
    writeln!(out, "pass,address,evidence,result").map_err(io)?;
    // the results by address; a pass returns how many functions it created and the total examined
    let mut attempted: BTreeMap<u32, &str> = BTreeMap::new();
    let mut process = |p: &mut Project, candidates: &BTreeMap<u32, String>, pass: u32| -> Res<(usize, usize)> {
        let mut created = 0;
        for (&target, evidence) in candidates {
            if attempted.contains_key(&target) {
                continue;
            }
            let result = recover(p, target)?;
            attempted.insert(target, result);
            created += (result == "created") as usize;
            writeln!(out, "{pass},0x{target:08x},{evidence},{result}").map_err(io)?;
        }
        Ok((created, attempted.len()))
    };
    let mut candidates: BTreeMap<u32, String> = BTreeMap::new();
    for name in [".rdata", ".data"] {
        let Some(block) = p.img.section(name) else { continue };
        let last = block.addr as u64 + block.data.len() as u64 - 1; // getEnd()
        let mut at = (block.addr as u64 + 3) & !3;
        while at + 3 <= last {
            let mut run = Vec::new();
            let mut anchored = false;
            let mut end = at;
            while end + 3 <= last {
                let target = pointer(p, end as u32)?;
                if !p.an.is_text(target) {
                    break;
                }
                run.push(target);
                anchored |= p.an.funcs.contains(&target);
                end += 4;
            }
            // Pointer arrays are candidates, not proof of class ownership.
            if run.len() >= 4 && anchored {
                for &target in &run {
                    candidates.entry(target).or_insert_with(|| format!("pointer_run@0x{at:08x}"));
                }
            }
            if !run.is_empty() {
                at = end - 4;
            }
            at += 4;
        }
    }
    let (mut made, mut examined) = process(p, &candidates, 0)?;
    let mut passes = 0;
    for pass in 1..=4 {
        candidates.clear();
        let sites: Vec<u32> = p.an.insns.range(p.an.text_start..p.an.text_end).map(|(&a, _)| a).collect();
        for a in sites {
            // isCall() and not isComputed(): a direct call, or a jump overridden to one
            if p.an.insns[&a].flow == Flow::CallInd || !p.is_call(a) {
                continue;
            }
            for target in p.flows(a).into_iter().filter(|&t| p.an.is_text(t)) {
                candidates.entry(target).or_insert_with(|| format!("direct_call@0x{a:08x}"));
            }
        }
        let (created, total) = process(p, &candidates, pass)?;
        (made, examined, passes) = (made + created, total, pass);
        if created == 0 {
            break;
        }
    }
    out.flush().map_err(io)?;
    println!("recovered {made} functions; examined {examined} candidates; direct-call passes {passes}");
    Ok(())
}

/// ClearFalseNoReturn.java: clears the no-return flag of every function whose flow reaches a
/// RET without a call, decodes what follows its calls and regrows the callers, to a fixpoint.
/// There are no fall-through overrides and no defined data to clear here.
pub fn clear_false_noreturn(p: &mut Project, out: &mut dyn Write) -> Res<()> {
    // A RET reached through jumps and fall-through alone, no call on the way.
    fn reaches_ret(p: &mut Project, entry: u32) -> bool {
        let mut work = VecDeque::from([entry]);
        let mut seen = HashSet::new();
        while let Some(at) = work.pop_front() {
            if !seen.insert(at) || seen.len() > 20000 {
                continue;
            }
            if !p.disassemble(at) {
                continue;
            }
            if mnemonic(p, at) == "RET" {
                return true;
            }
            if p.is_call(at) {
                continue;
            }
            if let Some(next) = p.fallthrough(at) {
                work.push_front(next);
            }
            if p.is_jump(at) {
                work.extend(p.flows(at));
            }
        }
        false
    }
    // Clears what the instruction at `at` would overlap. A function that starts mid-instruction
    // here goes with it; one that merely holds the item is left alone.
    fn clear_for(p: &mut Project, at: u32, out: &mut dyn Write) -> Res<()> {
        let Some((_, _, len)) = text_at(p, at) else { return Ok(()) };
        let mut blocking: Vec<u32> = p.insn_containing(at).filter(|&b| b != at).into_iter().collect();
        blocking.extend(p.an.insns.range(at..at + len).map(|(&a, _)| a));
        for &u in &blocking {
            if p.function_containing(u).is_some_and(|holder| holder != u) {
                return Ok(());
            }
            let game = |from: u32| p.img.block_of(from).is_none_or(|s| s.name == ".text");
            if p.refs_to(u).iter().any(|&(from, kind)| kind.is_flow() && game(from)) {
                return Ok(());
            }
        }
        for u in blocking {
            let (m, body, ulen) = text_at(p, u).ok_or(format!("0x{u:08x}: an instruction that does not decode"))?;
            let unit = format!("{m} {body}").replace(',', " ");
            writeln!(out, "{at:08x},,cleared_in_flow,{u:08x} {unit}").map_err(io)?;
            p.remove_function(u);
            p.clear(u, u + ulen - 1);
        }
        p.disassemble(at);
        Ok(())
    }
    // Flow from a call's return address is code: decode through it, clearing what is in the way.
    fn decode_through(p: &mut Project, start: u32, out: &mut dyn Write) -> Res<()> {
        let mut work = VecDeque::from([start]);
        let mut seen = HashSet::new();
        while let Some(at) = work.pop_front() {
            if !seen.insert(at) || seen.len() > 20000 {
                continue;
            }
            if !p.disassemble(at) {
                clear_for(p, at, out)?;
            }
            if !p.an.insns.contains_key(&at) {
                writeln!(out, "{at:08x},,decode_failed,").map_err(io)?;
                continue;
            }
            if let Some(next) = p.fallthrough(at) {
                work.push_front(next);
            }
            if p.is_jump(at) {
                work.extend(p.flows(at));
            }
        }
        Ok(())
    }
    let name = |p: &Project, f: u32| {
        let export = p.img.exports.iter().find(|e| e.0 == f).map(|e| e.1.clone());
        export.unwrap_or(format!("FUN_{f:08x}"))
    };
    let code_bytes = |p: &Project| p.an.insns.values().map(|i| i.len as u64).sum::<u64>();
    let before = code_bytes(p);
    let (mut cleared, mut sites) = (0, 0);
    writeln!(out, "address,name,action,detail").map_err(io)?;
    let mut again = true;
    while again {
        again = false;
        let mut next = p.an.funcs.first().copied();
        while let Some(f) = next {
            next = p.an.funcs.range(f + 1..).next().copied();
            if !p.an.noreturn.contains(&f) || p.thunked(f).is_some() || !reaches_ret(p, f) {
                continue;
            }
            p.set_noreturn(f, false);
            again = true;
            cleared += 1;
            let mut callers = BTreeSet::new();
            let refs = p.refs_to(f);
            for &(from, _) in &refs {
                if !p.an.insns.contains_key(&from) || mnemonic(p, from) != "CALL" {
                    continue;
                }
                if p.call_return(from) {
                    p.set_override(from, false);
                }
                let after = from + p.an.insns[&from].len as u32;
                decode_through(p, after, out)?;
                callers.extend(p.function_containing(from));
                sites += 1;
            }
            for c in callers {
                p.reflow(c);
            }
            writeln!(out, "{f:08x},{},cleared,{} references", name(p, f), refs.len()).map_err(io)?;
        }
    }
    // Whatever stays flagged, for review: no RET on any path the listing shows.
    for &f in p.an.funcs.iter().filter(|f| p.an.noreturn.contains(f)) {
        writeln!(out, "{f:08x},{},kept,", name(p, f)).map_err(io)?;
    }
    out.flush().map_err(io)?;
    let added = code_bytes(p) as i64 - before as i64;
    println!("ClearFalseNoReturn: {cleared} cleared, {sites} call sites, {added} code bytes added");
    Ok(())
}

/// FoldSlotFragments.java: folds wrapper-exit fragments back into their owners. `original`:
/// the text of the original functions CSV; `rewrites`: the rewritten sites CSV (site,exit).
/// `setBody` cannot fail on an overlap here (bodies may share instructions in this analysis).
pub fn fold_slot_fragments(p: &mut Project, original: &str, rewrites: &str, out: &mut dyn Write) -> Res<()> {
    const WALK_LIMIT: usize = 20000;
    fn rows(csv: &str) -> Res<Vec<(u32, u32)>> {
        let row = |l: &str| {
            let mut f = l.split(',');
            Ok((decode(f.next().unwrap_or(""))?, f.next().map_or(Ok(0), decode)?))
        };
        csv.lines().skip(1).map(row).collect()
    }
    struct Fold<'p, 'a> {
        p: &'p mut Project<'a>,
        original: HashSet<u32>,
        owners: BTreeSet<u32>,
        out: &'p mut dyn Write,
        removed: usize,
    }
    impl Fold<'_, '_> {
        fn unthunk(&mut self, g: u32) {
            if self.p.thunked(g).is_some() {
                self.p.set_thunk(g, None);
                self.owners.insert(g);
            }
        }

        fn clear_override(&mut self, a: u32) {
            if self.p.call_return(a) {
                self.p.set_override(a, false);
            }
        }

        // Remove the invented function at `entry` if only jumps reach it.
        fn fold(&mut self, entry: u32) -> Res<()> {
            if !self.p.an.funcs.contains(&entry) || self.original.contains(&entry) {
                return Ok(());
            }
            for (from, _) in self.p.refs_to(entry) {
                self.clear_override(from);
            }
            let mut from = Vec::new();
            for (source, kind) in self.p.refs_to(entry) {
                if !kind.is_jump() {
                    writeln!(self.out, "0x{entry:08x},kept {} from 0x{source:08x}", kind.name()).map_err(io)?;
                    return Ok(());
                }
                from.extend(self.p.function_containing(source).filter(|&g| g != entry));
            }
            for g in from {
                if self.p.thunked(g) == Some(entry) {
                    self.unthunk(g);
                }
                self.owners.insert(g);
            }
            self.p.remove_function(entry);
            writeln!(self.out, "0x{entry:08x},removed").map_err(io)?;
            self.removed += 1;
            Ok(())
        }

        // Follow jumps and fall-through from a fragment, folding invented functions on the way.
        fn walk(&mut self, start: u32, owner: u32) -> Res<BTreeSet<u32>> {
            let mut body = BTreeSet::new();
            let mut visited = HashSet::new();
            let mut work = VecDeque::from([start]);
            let mut steps = 0;
            while steps < WALK_LIMIT {
                let Some(at) = work.pop_front() else { break };
                steps += 1;
                if !visited.insert(at) || at != start && self.original.contains(&at) {
                    continue;
                }
                if !self.p.an.insns.contains_key(&at) {
                    continue;
                }
                self.fold(at)?;
                if self.p.function_containing(at).is_some_and(|other| other != owner) {
                    continue; // a real neighbour: tail call or shared code
                }
                body.insert(at);
                self.clear_override(at);
                let flows = self.p.flows(at);
                if self.p.is_jump(at) {
                    for &t in &flows {
                        if !self.original.contains(&t) {
                            work.push_back(t);
                        } else {
                            writeln!(self.out, "0x{at:08x},tail to original 0x{t:08x}").map_err(io)?;
                        }
                    }
                }
                let computed = matches!(self.p.an.insns[&at].flow, Flow::JumpInd | Flow::CallInd);
                if computed && flows.is_empty() {
                    work.extend(self.switch_targets(at)?);
                }
                work.extend(self.p.fallthrough(at));
            }
            Ok(body)
        }

        // `jmp [reg*4 + table]` guarded by `cmp reg, N` within three instructions: N+1 .text entries.
        fn switch_targets(&mut self, at: u32) -> Res<Vec<u32>> {
            let bytes = |a: u32| self.p.img.block_of(a).map(|s| &s.data[(a - s.addr) as usize..]);
            if self.p.an.insns[&at].flow != Flow::JumpInd {
                return Ok(Vec::new()); // not a JMP
            }
            let (sib, table) = match *bytes(at).unwrap_or(&[]) {
                [0xff, 0x24, sib, d0, d1, d2, d3, ..] if sib >> 6 == 2 && sib & 7 == 5 => {
                    (sib, u32::from_le_bytes([d0, d1, d2, d3]))
                }
                // a prefix, or base + index*4 + table, where Java takes the last register of the
                // operand: rare enough not to guess at
                [0xff, 0x64 | 0xa4, sib, ..] if sib >> 6 == 2 => {
                    return Err(format!("not ported: the switch at 0x{at:08x} has a base register"));
                }
                [0xff, ..] => return Ok(Vec::new()), // no register, scale 4 and table in the operand
                _ => return Err(format!("not ported: the computed jump at 0x{at:08x} has a prefix")),
            };
            let reg = (sib >> 3) & 7;
            if reg == 4 {
                return Ok(Vec::new()); // no index register
            }
            let (mut prev, mut bound) = (at, None);
            for _ in 0..3 {
                let Some((&b, _)) = self.p.an.insns.range(..prev).next_back() else { break };
                prev = b;
                bound = match bytes(prev) {
                    Some(&[0x83, m, i, ..]) if m == 0xf8 | reg => Some(i as i8 as u32),
                    Some(&[0x81, m, i0, i1, i2, i3, ..]) if m == 0xf8 | reg => {
                        Some(u32::from_le_bytes([i0, i1, i2, i3]))
                    }
                    Some(&[0x3d, i0, i1, i2, i3, ..]) if reg == 0 => Some(u32::from_le_bytes([i0, i1, i2, i3])),
                    _ => None,
                };
                if bound.is_some() {
                    break;
                }
            }
            let Some(bound) = bound.filter(|&b| b <= 1024) else { return Ok(Vec::new()) };
            let mut targets = Vec::new();
            for k in 0..=bound {
                let t = pointer(self.p, table + 4 * k)?;
                if !self.p.an.is_text(t) {
                    return Ok(Vec::new());
                }
                targets.push(t);
            }
            self.p.set_switch(at, targets.clone());
            for &t in &targets {
                self.p.disassemble(t);
            }
            writeln!(self.out, "0x{at:08x},switch {} targets", targets.len()).map_err(io)?;
            Ok(targets)
        }
    }

    let sites = rows(rewrites)?;
    let original = rows(original)?.into_iter().map(|r| r.0).collect();
    let mut s = Fold { p, original, owners: BTreeSet::new(), out, removed: 0 };
    let mut refit = 0;
    writeln!(s.out, "entry,action").map_err(io)?;
    // Bodies truncated at one site hide later sites from their owner; repeat until stable.
    for round in 1..=8 {
        s.owners.clear();
        let mut flow: HashMap<u32, BTreeSet<u32>> = HashMap::new();
        let mut changed = 0;
        // Java's bodies stay as they are until setBody, so its "before" is the body at the start
        // of the round; here a body re-flows as soon as a fragment goes
        let sizes: HashMap<u32, u64> = s.p.an.funcs.iter().map(|&f| (f, s.p.body_bytes(f))).collect();
        for &(site, exit) in &sites {
            s.clear_override(site);
            let Some(owner) = s.p.function_containing(site) else { continue };
            if s.original.contains(&exit) {
                continue;
            }
            s.owners.insert(owner);
            s.unthunk(owner);
            let reached = s.walk(exit, owner)?;
            flow.entry(owner).or_default().extend(reached);
        }
        // A worklist, lowest entry first: walk() can fold a function and add its jump sources.
        let mut done = HashSet::new();
        while let Some(a) = s.owners.iter().copied().find(|c| done.insert(*c)) {
            if !s.p.an.funcs.contains(&a) {
                continue;
            }
            // Branches cut by earlier tail-call readings: re-walk the owner from its entry.
            if flow.contains_key(&a) && s.p.thunked(a).is_none() {
                let reached = s.walk(a, a)?;
                flow.entry(a).or_default().extend(reached);
            }
            if !s.p.an.funcs.contains(&a) {
                // the walk folded the owner itself: an invented function only jumps reach. Java
                // goes on with the deleted function (and fails); its jump sources are owners now
                continue;
            }
            if s.p.thunked(a).is_some_and(|target| !s.original.contains(&target)) {
                s.unthunk(a);
            }
            if s.p.thunked(a).is_some() {
                continue;
            }
            let before = sizes.get(&a).copied().unwrap_or_else(|| s.p.body_bytes(a));
            // Explicit body: fixupFunctionBody re-thunks an owner that is a lone jump.
            match flow.get(&a) {
                Some(reached) => {
                    let mut body: BTreeSet<u32> = s.p.an.bodies[&a].iter().copied().collect();
                    body.extend(reached);
                    s.p.set_body(a, &body);
                }
                None => s.p.reflow(a),
            }
            let after = s.p.body_bytes(a);
            if after == before {
                continue;
            }
            writeln!(s.out, "0x{a:08x},refit {before}->{after} round {round}").map_err(io)?;
            refit += 1;
            changed += 1;
        }
        println!("round {round}: {changed} bodies changed");
        if changed == 0 {
            break;
        }
    }
    s.out.flush().map_err(io)?;
    println!("removed {} fragment functions; refit {refit} owners", s.removed);
    Ok(())
}
