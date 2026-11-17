//! mercs2's eight remaining Ghidra scripts (mercs2-decomp `tools/ghidra/*.java`), ported
//! statement by statement onto `store::Project`: six that only read the program, and two with
//! an editing option (`ExportBindings --recover`, `AuditRecoveredFunctions --remove-empty`)
//! whose edits land in the project store. Each function names its script; what this analysis
//! has no state for is an error, not a guess. See rust/README.md "The read-only scripts".

use crate::analysis::{Flow, Section};
use crate::store::{Project, Ref};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::io::Write;

type Res<T> = Result<T, String>;

fn io(e: std::io::Error) -> String {
    format!("output: {e}")
}

/// `toAddr(String)`: hex, `0x` optional.
fn to_addr(s: &str) -> Res<u32> {
    let hex = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    u32::from_str_radix(hex, 16).map_err(|e| format!("address `{s}`: {e}"))
}

/// `Long.decode` of an address. Java reads a leading `0` as octal, which is an error here.
fn decode(s: &str) -> Res<u32> {
    let n = match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(hex) => u32::from_str_radix(hex, 16),
        None if s.len() > 1 && s.starts_with('0') => return Err(format!("address `{s}`: octal is not ported")),
        None => s.parse(),
    };
    n.map_err(|e| format!("address `{s}`: {e}"))
}

/// The end of the initialized block Ghidra makes of a section (the raw data; the rest of the
/// virtual size is an uninitialized block of the same name, which `getBlock(name)` never returns).
fn init_end(s: &Section) -> u32 {
    s.addr + s.data.len() as u32 - s.zero_tail.min(s.data.len() as u32)
}

/// `getMemory().getBlock(".text")`, as (first, end).
fn text_block(p: &Project) -> Res<(u32, u32)> {
    let s = p.img.section(".text").ok_or("no .text block")?;
    Ok((s.addr, init_end(s)))
}

/// `getFunctionContaining(a)`. Ghidra's bodies never overlap; an instruction that two bodies
/// share here has no one answer (unless a function starts at it), which is an error. With
/// `GHIDRA_RS_SHARED=lowest` it is the store's rule instead (`Project::function_containing`: the
/// lowest entry), and each such answer is a `shared` line on stderr. A function without an
/// instruction at its entry is Java's function of one undefined byte.
fn owner(p: &Project, a: u32) -> Res<Option<u32>> {
    let Some(s) = p.insn_containing(a) else { return Ok(p.an.funcs.contains(&a).then_some(a)) };
    match p.owners_at(s) {
        [] => Ok(None),
        [f] => Ok(Some(*f)),
        _ if p.an.funcs.contains(&s) => Ok(Some(s)),
        fs if std::env::var("GHIDRA_RS_SHARED").is_ok_and(|v| v == "lowest") => {
            eprintln!("shared 0x{a:08x} {}", fs.iter().map(|f| format!("{f:08x}")).collect::<Vec<_>>().join(" "));
            Ok(p.function_containing(a))
        }
        fs => Err(format!(
            "0x{a:08x} lies in the bodies of {} functions here (0x{:08x}, 0x{:08x}, ...); Ghidra's bodies do not overlap, so its function is not known (GHIDRA_RS_SHARED=lowest takes the lowest entry and lists each such address)",
            fs.len(),
            fs[0],
            fs[1]
        )),
    }
}

/// `getBody().getAddressRanges()`: the instructions of the body, joined. One byte where no
/// instruction is at the entry (Java's function of one undefined byte).
fn ranges(p: &Project, f: u32) -> Vec<(u32, u32)> {
    let mut out: Vec<(u32, u32)> = Vec::new();
    for &a in p.an.bodies.get(&f).map_or(&[][..], |b| b) {
        let last = a + p.an.insns[&a].len as u32 - 1;
        match out.last_mut() {
            Some(r) if a <= r.1 + 1 => r.1 = r.1.max(last),
            _ => out.push((a, last)),
        }
    }
    if out.is_empty() {
        out.push((f, f));
    }
    out
}

/// `getBody().getNumAddresses()`.
fn size(ranges: &[(u32, u32)]) -> u64 {
    ranges.iter().map(|r| (r.1 - r.0) as u64 + 1).sum()
}

fn in_body(p: &Project, f: u32, a: u32) -> bool {
    p.an.bodies.get(&f).is_some_and(|b| b.binary_search(&a).is_ok())
}

/// `Instruction.getPrevious()` and `getNext()`: the listing's order.
fn previous(p: &Project, a: u32) -> Option<u32> {
    p.an.insns.range(..a).next_back().map(|(&b, _)| b)
}

fn next(p: &Project, a: u32) -> Option<u32> {
    p.an.insns.range(a + 1..).next().map(|(&b, _)| b)
}

/// `Instruction.toString()`.
fn text(p: &Project, a: u32) -> Res<String> {
    let sec = p.img.block_of(a).ok_or(format!("no memory at 0x{a:08x}"))?;
    let d =
        p.sl.disasm(&mut p.sl.new_parse(), a as u64, &sec.data[(a - sec.addr) as usize..])
            .map_err(|e| format!("0x{a:08x}: {e}"))?;
    let branch = matches!(p.an.insns[&a].flow, Flow::Call | Flow::Jump | Flow::CondJump);
    // LEA's `[0x...]` is a scalar to Java (`LEA ECX,[0x25692ee]`), not an address of 8 digits
    let body = match d.mnemonic.as_str() {
        "LEA" => d.body.replace(", ", ","),
        _ => crate::abi::ghidra_operands(&d.body, branch),
    };
    Ok(if body.is_empty() { d.mnemonic } else { format!("{} {body}", d.mnemonic) })
}

fn hex(f: Option<u32>, none: &str) -> String {
    f.map_or(none.to_string(), |f| format!("{f:08x}"))
}

/// ExportModHookOwners.java: the function containing each address (first column) of `csv`.
pub fn mod_hook_owners(p: &Project, csv: &str, out: &mut dyn Write) -> Res<()> {
    writeln!(out, "address,function_address").map_err(io)?;
    for line in csv.lines().filter(|l| !l.starts_with("address,")) {
        let (address, _) = line.split_once(',').ok_or(format!("no comma in `{line}`"))?;
        let f = owner(p, to_addr(address)?)?;
        writeln!(out, "{address},{}", f.map_or(String::new(), |f| format!("0x{f:08x}"))).map_err(io)?;
    }
    Ok(())
}

/// ExportSlotOwners.java: the function containing each captured jump site of `slots.csv`.
pub fn slot_owners(p: &Project, csv: &str, out: &mut dyn Write) -> Res<()> {
    writeln!(out, "site,function").map_err(io)?;
    for line in csv.lines().filter(|l| *l != "site,slot,target" && !l.is_empty()) {
        let site = line.split(',').next().unwrap_or("");
        let f = owner(p, decode(site)?)?;
        writeln!(out, "{site},{}", f.map_or(String::new(), |f| format!("0x{f:08x}"))).map_err(io)?;
    }
    Ok(())
}

/// InspectBoundaries.java: the body ranges of the function containing each address and of the
/// function before it, and the instructions around the address with their owners and overrides.
pub fn inspect_boundaries(p: &Project, addresses: &[&str], out: &mut dyn Write) -> Res<()> {
    for arg in addresses {
        let address = to_addr(arg)?;
        let own = owner(p, address)?;
        let before = address.checked_sub(1).and_then(|b| p.an.funcs.range(..=b).next_back().copied());
        writeln!(out, "ADDRESS {address:08x}").map_err(io)?;
        for f in [own, before].into_iter().flatten() {
            let r = ranges(p, f);
            let (min, max) = (r[0].0, r[r.len() - 1].1);
            let noreturn = p.an.noreturn.contains(&f);
            writeln!(out, "FUNCTION {f:08x} count={} min={min:08x} max={max:08x} noreturn={noreturn}", size(&r))
                .map_err(io)?;
            for (lo, hi) in r {
                writeln!(out, "RANGE [{lo:08x}, {hi:08x}]").map_err(io)?;
            }
        }
        let at = p.insn_containing(address).or_else(|| next(p, address));
        let Some(mut a) = at else { continue };
        for _ in 0..8 {
            match previous(p, a) {
                Some(b) => a = b,
                None => break,
            }
        }
        let mut cur = Some(a);
        for _ in 0..28 {
            let Some(a) = cur else { break };
            // the store's override or the derived one (README "What ghidra-rs derives")
            let over = if p.call_return(a) { "CALL_RETURN" } else { "NONE" };
            writeln!(out, "{a:08x} {} owner={} override={over}", text(p, a)?, hex(owner(p, a)?, "none")).map_err(io)?;
            cur = next(p, a);
        }
    }
    Ok(())
}

/// `Reference.getReferenceType()` of a reference to code. A flow reference of an instruction
/// with a CALL_RETURN override is a call terminator. Data references: an immediate is DATA;
/// whether a memory operand reads, writes or calls through the address is not kept.
fn ref_type(p: &Project, from: u32, kind: Ref, to: u32) -> Res<&'static str> {
    let Some(i) = p.an.insns.get(&from) else { return Ok("DATA") }; // a pointer in data
    if kind == Ref::Data {
        if i.code_imms.contains(&to) && !i.refs.contains(&to) {
            return Ok("DATA");
        }
        return Err(format!(
            "the reference from 0x{from:08x} to 0x{to:08x} is a memory operand's or to data: its type (READ, WRITE, INDIRECTION, DATA) is not derived"
        ));
    }
    Ok(match (kind, p.call_return(from)) {
        (Ref::UnconditionalJump | Ref::UnconditionalCall, true) => "CALL_TERMINATOR",
        (Ref::ConditionalJump, true) => "CONDITIONAL_CALL_TERMINATOR",
        (Ref::ComputedJump | Ref::ComputedCall, true) => "COMPUTED_CALL_TERMINATOR",
        _ => kind.name(),
    })
}

/// ExportCallContexts.java: up to 6 instructions before and 22 from there on around every
/// reference to `target`, within the referring function. Returns the number of references.
pub fn call_contexts(p: &Project, target: &str, out: &mut dyn Write) -> Res<usize> {
    let target = to_addr(target)?;
    let refs = p.refs_to(target);
    for &(from, kind) in &refs {
        let own = owner(p, from)?;
        writeln!(out, "REFERENCE {from:08x} {} owner={}", ref_type(p, from, kind, target)?, hex(own, "none"))
            .map_err(io)?;
        if !p.an.insns.contains_key(&from) {
            continue;
        }
        let inside = |a: u32| own.is_none_or(|f| in_body(p, f, a));
        let mut a = from;
        for _ in 0..6 {
            match previous(p, a) {
                Some(b) if inside(b) => a = b,
                _ => break,
            }
        }
        let mut cur = Some(a);
        for _ in 0..22 {
            let Some(a) = cur.filter(|&a| inside(a)) else { break };
            writeln!(out, "{a:08x} {}", text(p, a)?).map_err(io)?;
            cur = next(p, a);
        }
        writeln!(out).map_err(io)?;
    }
    writeln!(out, "TOTAL_REFERENCES {}", refs.len()).map_err(io)?;
    Ok(refs.len())
}

/// AuditRecoveredFunctions.java: the body of every `created` row of RecoverFunctions' audit
/// CSV. With `remove_empty`, a function of one byte without an instruction is removed.
pub fn audit_recovered_functions(p: &mut Project, csv: &str, remove_empty: bool, out: &mut dyn Write) -> Res<()> {
    let (text_lo, text_hi) = text_block(p)?;
    writeln!(
        out,
        "address,size,instructions,instruction_bytes,non_instruction_bytes,outside_text,wrapper_flows,status"
    )
    .map_err(io)?;
    for line in csv.lines().filter(|l| l.ends_with(",created")) {
        let address = line.split(',').nth(1).ok_or(format!("no address in `{line}`"))?;
        let f = decode(address)?;
        if !p.an.funcs.contains(&f) {
            return Err(format!("missing recovered function {address}"));
        }
        let body = p.an.bodies.get(&f).cloned().unwrap_or_default();
        let (mut covered, mut wrapper_flows) = (0u64, 0u64);
        for &a in &body {
            let wrapper = |d: &u32| p.img.block_of(*d).is_some_and(|s| s.name == ".securom" || s.name.starts_with('S'));
            wrapper_flows += p.flows(a).iter().filter(|d| wrapper(d)).count() as u64;
            covered += p.an.insns[&a].len as u64; // every byte of a body's instruction is in the body
        }
        let r = ranges(p, f);
        let inside = |&(lo, hi): &(u32, u32)| (hi.min(text_hi - 1) as u64 + 1).saturating_sub(lo.max(text_lo) as u64);
        let size = size(&r);
        let outside = size - r.iter().map(inside).sum::<u64>();
        let mut status = "retained";
        if body.is_empty() && size == 1 && remove_empty {
            p.remove_function(f);
            status = "removed_empty";
        }
        writeln!(
            out,
            "{address},{size},{},{covered},{},{outside},{wrapper_flows},{status}",
            body.len(),
            size - covered
        )
        .map_err(io)?;
    }
    Ok(())
}

/// What the scripts read of a facts file (`analyze --facts`, or the Java project's from
/// `tools/ghidra/ExportFacts.java`): the function names and the defined strings.
#[derive(Default)]
pub struct Facts {
    /// `Function.getName()` by entry
    pub names: HashMap<u32, String>,
    /// defined string data: (address, length, its characters when a raw read gives the value)
    pub strings: Vec<(u32, u32, Option<u32>)>,
}

impl Facts {
    pub fn parse(text: &str) -> Res<Facts> {
        let mut lines = text.lines();
        if !lines.next().is_some_and(|l| l.starts_with("ghidra-rs-facts ")) {
            return Err("not a facts file (first line is not `ghidra-rs-facts <version>`)".into());
        }
        let mut facts = Facts::default();
        let addr = |s: &str| u32::from_str_radix(s, 16).map_err(|e| format!("facts: address `{s}`: {e}"));
        for line in lines {
            let mut cells = line.splitn(4, '\t');
            match (cells.next(), cells.next(), cells.next(), cells.next()) {
                (Some("func"), Some(entry), Some(xml), None) => {
                    let name = xml.split_once("<function ").and_then(|(_, r)| r.split_once(" name=\""));
                    let name =
                        name.and_then(|(_, r)| r.split_once('"')).ok_or(format!("facts: func {entry} has no name"))?;
                    let name = ["&lt;<", "&gt;>", "&quot;\"", "&apos;'", "&amp;&"]
                        .iter()
                        .fold(name.0.to_string(), |n, e| n.replace(&e[..e.len() - 1], &e[e.len() - 1..]));
                    facts.names.insert(addr(entry)?, name);
                }
                (Some("string"), Some(first), Some(len), Some(plain)) => {
                    let len = len.parse().map_err(|e| format!("facts: string {first}: {e}"))?;
                    let plain = match plain {
                        "-" => None,
                        n => Some(n.parse().map_err(|e| format!("facts: string {first}: {e}"))?),
                    };
                    facts.strings.push((addr(first)?, len, plain));
                }
                _ => {}
            }
        }
        facts.strings.sort_unstable();
        Ok(facts)
    }
}

fn quote(s: &str) -> String {
    format!("\"{}\"", s.replace('"', "\"\""))
}

/// ExportLibraryEvidence.java: the `.text` functions that refer to a defined string containing
/// a marker of `config/library_markers.csv`. Returns the number of rows.
pub fn library_evidence(p: &Project, markers: &str, facts: &Facts, out: &mut dyn Write) -> Res<usize> {
    let mut lines = markers.lines();
    if lines.next() != Some("marker,module,source") {
        return Err("marker header".into());
    }
    let mut rows: Vec<Vec<&str>> = Vec::new();
    for line in lines {
        let cells: Vec<&str> = line.split(',').collect();
        if cells.len() != 3 || line.contains('"') {
            return Err("marker fields must be unquoted and comma-free".into());
        }
        if !cells[0].is_ascii() {
            return Err(format!("marker `{}`: only ASCII markers are ported", cells[0]));
        }
        rows.push(cells);
    }
    let (text_lo, text_hi) = text_block(p)?;
    let holds = |hay: &[u8], m: &str| m.is_empty() || hay.windows(m.len()).any(|w| w == m.as_bytes());
    let mut count = 0;
    writeln!(out, "address,module,string_address,marker,source").map_err(io)?;
    for &(a, len, plain) in &facts.strings {
        // without a reference there is no row, whatever the string holds (so a string of a
        // block this image lacks, as Ghidra's `tdb`, passes while nothing refers to it)
        let refs = p.refs_to(a);
        if refs.is_empty() {
            continue;
        }
        // a string can run from one block into the next
        let byte = |b: u32| p.img.block_of(b).map(|s| s.data[(b - s.addr) as usize]);
        let bytes: Option<Vec<u8>> = (a..a + len).map(byte).collect();
        let bytes = &bytes.ok_or(format!("the string at 0x{a:08x} of the facts is not in the image"))?[..];
        for m in &rows {
            let hit = match plain {
                Some(n) => holds(&bytes[..(n as usize).min(bytes.len())], m[0]),
                // wide, translated or other characters: Java's value is not known here, so
                // such a string may hold a marker under no reading of its bytes
                None => {
                    let wide: Vec<u8> =
                        bytes.chunks(2).map(|c| if c.len() == 2 && c[1] == 0 { c[0] } else { 0xff }).collect();
                    if holds(bytes, m[0]) || holds(&wide, m[0]) {
                        return Err(format!(
                            "the string at 0x{a:08x} is not plain ASCII and may hold the marker `{}`: its value in Java is not known",
                            m[0]
                        ));
                    }
                    false
                }
            };
            if !hit {
                continue;
            }
            for &(from, _) in &refs {
                let Some(f) = owner(p, from)? else { continue };
                if f < text_lo || f >= text_hi {
                    continue;
                }
                writeln!(out, "0x{f:08x},{},0x{a:08x},{},{}", m[1], quote(m[0]), quote(m[2])).map_err(io)?;
                count += 1;
            }
        }
    }
    Ok(count)
}

/// ExportBindings.java: tables of four or more (ASCII name, `.text` pointer) pairs in `.rdata`
/// and `.data`. With `recover`, a function at each target that lies in none.
pub fn export_bindings(p: &mut Project, recover: bool, out: &mut dyn Write) -> Res<()> {
    let img = p.img;
    let (text_lo, text_hi) = text_block(p)?;
    let name = |at: u32| -> Option<String> {
        let block = img.block_of(at).filter(|s| at < init_end(s) && !s.exec)?;
        let mut value = String::new();
        for &ch in block.data[(at - block.addr) as usize..(init_end(block) - block.addr) as usize].iter().take(256) {
            if ch == 0 {
                return (!value.is_empty()).then_some(value);
            }
            if !(32..=126).contains(&ch) {
                return None;
            }
            value.push(ch as char);
        }
        None
    };
    let (mut tables, mut entries, mut recovered, mut unresolved) = (0, 0, 0, 0);
    let mut visited = HashSet::new();
    writeln!(out, "table,index,name,function,library").map_err(io)?;
    for section in [".rdata", ".data"] {
        let Some(block) = img.section(section).filter(|s| init_end(s) > s.addr) else { continue };
        let end = init_end(block) as u64 - 1;
        let word = |pos: u64| {
            let o = (pos - block.addr as u64) as usize;
            u32::from_le_bytes(block.data[o..o + 4].try_into().expect("four bytes"))
        };
        let mut start = (block.addr as u64 + 3) & !3;
        while start + 7 <= end {
            let (mut names, mut targets) = (Vec::new(), Vec::new());
            let mut pos = start;
            while pos + 7 <= end {
                let target = word(pos + 4);
                if target < text_lo || target >= text_hi {
                    break;
                }
                let Some(value) = name(word(pos)) else { break };
                names.push(value);
                targets.push(target);
                pos += 8;
            }
            if names.len() >= 4 {
                tables += 1;
                for (i, (name, &target)) in names.iter().zip(&targets).enumerate() {
                    if recover && visited.insert(target) && !p.an.funcs.contains(&target) {
                        // Never split an existing body or clear conflicting code/data. Defined
                        // data is only known for address-table slots here.
                        let data = p.an.table_slots.range(..=target).next_back().is_some_and(|(&s, _)| target < s + 4);
                        let free = p.function_containing(target).is_none()
                            && !data
                            && p.insn_containing(target).is_none_or(|s| s == target);
                        if free && p.disassemble(target) && p.create_function(target) {
                            recovered += 1;
                        } else {
                            if free {
                                eprintln!("ExportBindings: {target:08x} not created: no instruction decodes there (Java makes a one-byte function)");
                            }
                            unresolved += 1;
                            println!("unresolved binding target: {target:08x}");
                        }
                    }
                    writeln!(out, "0x{start:08x},{i},\"{}\",0x{target:08x},", name.replace('"', "\"\"")).map_err(io)?;
                    entries += 1;
                }
                start += names.len() as u64 * 8 - 4;
            }
            start += 4;
        }
    }
    println!("exported {entries} candidate bindings in {tables} tables");
    if recover {
        println!("recovered {recovered} functions; {unresolved} unresolved targets");
    }
    Ok(())
}

// ExportAbiCandidates.MAX_SIZE, MIN_REFS
const MAX_SIZE: u64 = 96;
const MIN_REFS: usize = 5;

/// The registers `in_`/`unaff_` variables name in decompiled C, sorted.
fn register_params(c: &str) -> BTreeSet<String> {
    let re = regex_lite::Regex::new(r"\b(?:in|unaff)_(E[A-Z]{2}|XMM\d|ST\d)\b").expect("pattern");
    re.captures_iter(c).map(|m| m[1].to_string()).collect()
}

/// ExportAbiCandidates.java: small leaf functions with five or more references whose
/// decompilation shows register parameters. The selection is ported; the C is Java's
/// decompiler output, which ghidra-rs does not give yet for every function (stage S10). So the
/// C of each selected function is read from `c_dir/0x<entry>` (`tools/ghidra-diff.sh`'s
/// naming), where the caller has put output verified identical to Java's, and a function
/// without a file there is an error. Names are the facts'. Returns the number of candidates.
pub fn abi_candidates(
    p: &Project,
    facts: Option<&Facts>,
    c_dir: Option<&str>,
    csv: &mut dyn Write,
    txt: &mut dyn Write,
) -> Res<usize> {
    let mut selected = Vec::new();
    for &f in &p.an.funcs {
        let size = size(&ranges(p, f));
        if size > MAX_SIZE || p.thunked(f).is_some() {
            continue;
        }
        let body = p.an.bodies.get(&f).map_or(&[][..], |b| b);
        // a call, or a computed jump
        if body.iter().any(|&a| p.is_call(a) || p.an.insns[&a].flow == Flow::JumpInd) {
            continue;
        }
        let refs = p.refs_to(f).len();
        if refs >= MIN_REFS {
            selected.push((f, size, refs));
        }
    }
    let read = |f: u32| {
        let dir = std::path::Path::new(c_dir?);
        let c = std::fs::read_to_string(dir.join(format!("0x{f:x}")));
        c.or_else(|_| std::fs::read_to_string(dir.join(format!("0x{f:08x}")))).ok()
    };
    let c: Vec<Option<String>> = selected.iter().map(|s| read(s.0)).collect();
    let missing: Vec<u32> = selected.iter().zip(&c).filter(|(_, c)| c.is_none()).map(|(s, _)| s.0).collect();
    let (Some(facts), true) = (facts, missing.is_empty()) else {
        missing.iter().for_each(|f| eprintln!("unverified 0x{f:08x}"));
        return Err(format!(
            "abi-candidates needs S10 Java-identical output: {} functions pass the size, thunk, leaf and reference tests, and {} of them have no verified C{} (their addresses are the `unverified` lines above: a corpus for tools/ghidra-diff.sh){}",
            selected.len(),
            missing.len(),
            c_dir.map_or(" (no directory of verified C was given)".to_string(), |d| format!(" in {d}")),
            if facts.is_none() { "; the names need --facts" } else { "" }
        ));
    };
    let mut rows = Vec::new();
    for (&(f, size, refs), c) in selected.iter().zip(c.iter().flatten()) {
        let found = register_params(c);
        if found.is_empty() {
            continue;
        }
        let name = facts.names.get(&f).ok_or(format!("the facts have no function at 0x{f:08x}"))?;
        rows.push((f, size, refs, found.into_iter().collect::<Vec<_>>().join(";"), name));
        writeln!(txt, "=== {f:08x} {name}").map_err(io)?;
        for &a in &p.an.bodies[&f] {
            writeln!(txt, "{a:08x}  {}", text(p, a)?).map_err(io)?;
        }
        // getC(): a blank line, the function, a blank line; then the script's own line end
        let lines: Vec<&str> = c.lines().collect();
        let first = lines.iter().position(|l| !l.trim().is_empty()).unwrap_or(0);
        let last = lines.iter().rposition(|l| !l.trim().is_empty()).map_or(0, |i| i + 1);
        writeln!(txt, "\n{}\n\n", lines[first..last].join("\n")).map_err(io)?;
    }
    rows.sort_by_key(|a| std::cmp::Reverse(a.2)); // stable, as List.sort
    writeln!(csv, "address,size,references,registers,name").map_err(io)?;
    for (f, size, refs, registers, name) in &rows {
        writeln!(csv, "0x{f:08x},{size},{refs},{registers},{name}").map_err(io)?;
    }
    Ok(rows.len())
}

/// Runs the command `command` of `ghidra-rs export` (or, with `edit`, one of the two editing
/// options) and prints the script's summary line. A file is written only when the command ran
/// to its end. False when the command is none of these.
pub fn run(p: &mut Project, command: &str, rest: &[&str], facts: Option<&str>, edit: bool) -> Res<bool> {
    let read = |f: &str| std::fs::read_to_string(f).map_err(|e| format!("{f}: {e}"));
    let create = |f: &str| -> Res<(String, Vec<u8>)> { Ok((f.to_string(), Vec::new())) };
    let facts = || facts.map(|f| Facts::parse(&read(f)?).map_err(|e| format!("{f}: {e}"))).transpose();
    let mut files: Vec<(String, Vec<u8>)> = Vec::new();
    match (edit, command, rest) {
        (true, "export-bindings", [out, "--recover"]) => {
            files.push(create(out)?);
            export_bindings(p, true, &mut files[0].1)?;
        }
        (true, "audit-recovered-functions", [csv, out, "--remove-empty"]) => {
            files.push(create(out)?);
            audit_recovered_functions(p, &read(csv)?, true, &mut files[0].1)?;
        }
        (true, _, _) => return Ok(false),
        (false, "mod-hook-owners", [csv, out]) => {
            files.push(create(out)?);
            mod_hook_owners(p, &read(csv)?, &mut files[0].1)?;
            println!("Companion hook owners exported: {out}");
        }
        (false, "slot-owners", [csv, out]) => {
            files.push(create(out)?);
            slot_owners(p, &read(csv)?, &mut files[0].1)?;
        }
        (false, "boundaries", [out, addresses @ ..]) => {
            files.push(create(out)?);
            inspect_boundaries(p, addresses, &mut files[0].1)?;
            println!("Boundary inspection complete: {out}");
        }
        (false, "call-contexts", [target, out]) => {
            files.push(create(out)?);
            let count = call_contexts(p, target, &mut files[0].1)?;
            println!("Exported {count} reference contexts to {out}");
        }
        (false, "audit-recovered-functions", [csv, out]) => {
            files.push(create(out)?);
            audit_recovered_functions(p, &read(csv)?, false, &mut files[0].1)?;
        }
        (false, "library-evidence", [markers, out]) => {
            let facts = facts()?.ok_or(
                "library-evidence needs the defined strings: --facts <file> (`analyze --facts`, or the Java project's)",
            )?;
            files.push(create(out)?);
            let count = library_evidence(p, &read(markers)?, &facts, &mut files[0].1)?;
            println!("exported {count} direct library-marker references");
        }
        (false, "bindings", [out]) => {
            files.push(create(out)?);
            export_bindings(p, false, &mut files[0].1)?;
        }
        (false, "abi-candidates", [csv, txt, c_dir @ ..]) if c_dir.len() <= 1 => {
            // nothing is written unless every selected function has its C
            let (mut c, mut t) = (Vec::new(), Vec::new());
            let count = abi_candidates(p, facts()?.as_ref(), c_dir.first().copied(), &mut c, &mut t)?;
            std::fs::write(csv, c).map_err(|e| format!("{csv}: {e}"))?;
            std::fs::write(txt, t).map_err(|e| format!("{txt}: {e}"))?;
            println!("Exported {count} candidates");
        }
        (false, _, _) => return Ok(false),
    }
    for (f, text) in files {
        std::fs::write(&f, text).map_err(|e| format!("{f}: {e}"))?;
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    #[test]
    fn register_params_as_the_java_pattern() {
        let c = "x = in_EAX + unaff_ESI; y = in_XMM0_Da; z = in_ST0; plain_EBX; in_XMM10; in_EAXX; in_FS_OFFSET";
        let found: Vec<String> = super::register_params(c).into_iter().collect();
        assert_eq!(found, ["EAX", "ESI", "ST0"]);
    }
}
