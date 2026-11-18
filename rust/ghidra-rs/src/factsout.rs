//! Stage S10: the facts of ghidra-rs's own analysis (`analyze --facts <out>`), in the format
//! of `tools/ghidra/ExportFacts.java`, so `load facts` (decomp/facts.rs) needs no Java Ghidra
//! project. Each record is written as Java's `DecompileCallback` would send it for a listing
//! that held what this analysis found: functions, bodies, imports, data symbols at the
//! references, labels, strings, read-only blocks, tracked registers, flow overrides.
//!
//! What this analysis does not derive is named by an `underived <address> <what>` record, and
//! the loader fails when a decompile reads it (see `Underived`). `tools/facts-diff.sh` compares
//! the file with a Java project's, record by record.

use crate::analysis::{Analysis, Flow, Image};
use crate::fid::Applied;
use crate::sleigh::{Parse, Sleigh};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt::Write as _;
use std::io::{self, Write};

/// `PcodeDataTypeManager.encodeCoreTypes` for x86:LE:32 with the Windows compiler spec: the
/// built-in data-types of Ghidra, which do not depend on the program (copied from an export).
const CORE_TYPES: &str = include_str!("facts_coretypes.xml");

/// `undefined`, the data-type of a byte without one: built into Ghidra, but no core type, so
/// Java sends it as a `type` record (its id and text).
const UNDEFINED: (&str, &str) =
    ("c000000000000000", "<type name=\"undefined\" id=\"0xc000000000000000\" metatype=\"unknown\" size=\"1\"/>");

/// Where Ghidra's "Windows x86 Thread Environment Block" analyzer puts the TEB of a 32-bit
/// program (a block of its own) and the value it gives `FS_OFFSET` everywhere.
const TEB: (u32, u32) = (0xffdf_f000, 0x1000);

/// `DecompileCallback.MAX_FUNCTION_OFFCUT`
const MAX_FUNCTION_OFFCUT: u32 = 8;

/// What an `underived` record names: a part of the facts Java Ghidra has and this analysis
/// does not derive. The loader fails when a decompile reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Underived {
    /// a function's name, namespace and prototype (a C++ name the small demangler leaves, an
    /// import without the archive's prototypes)
    Function,
    /// the plate and pre comments of the listing (Function ID's and the demangler's)
    Comments,
    /// the label of a switch case (`caseD_3` in a `switchD_...` namespace)
    Label,
}

impl Underived {
    pub fn word(self) -> &'static str {
        match self {
            Underived::Function => "function",
            Underived::Comments => "comments",
            Underived::Label => "label",
        }
    }
}

/// Function prototypes exported once from Ghidra's data-type archives
/// (`tools/ghidra/ExportArchiveProtos.java`): `proto <name> <xml>` with `@ADDR@` and `@SIZE@`
/// where the function's address and size go, and the `type` records they refer to.
#[derive(Default)]
pub struct Protos {
    by_name: HashMap<String, String>,
    types: HashMap<String, String>,
}

impl Protos {
    pub fn parse(text: &str) -> Result<Protos, String> {
        let mut lines = text.lines();
        if lines.next() != Some("ghidra-rs-protos 1") {
            return Err("not a prototype file of version 1 (tools/ghidra-protos.sh writes it)".into());
        }
        let mut p = Protos::default();
        for line in lines {
            let mut it = line.splitn(3, '\t');
            match (it.next(), it.next(), it.next()) {
                (Some("proto"), Some(name), Some(xml)) => p.by_name.insert(name.to_string(), xml.to_string()),
                (Some("type"), Some(id), Some(xml)) => p.types.insert(id.to_string(), xml.to_string()),
                _ => return Err(format!("bad prototype record: {}", line.chars().take(60).collect::<String>())),
            };
        }
        Ok(p)
    }
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&apos;")
}

/// A function as the records name it.
#[derive(Clone, Default)]
struct Func {
    name: String,
    /// a locked model (`__fastcall` of a `@name@4` symbol)
    model: Option<&'static str>,
    /// the import slot whose prototype a thunk takes
    import: Option<u32>,
    /// the function a thunk jumps to
    thunked: Option<u32>,
    underived: bool,
}

impl Func {
    /// Take the name of a symbol as Ghidra's demangler leaves it: `@name@4` is `name` with
    /// `__fastcall` locked, `_name` is `name` with `__cdecl` locked, `_name@12` and `__name`
    /// stay; a C++ name is not derived (Java has its namespace and the prototype of its
    /// mangling).
    fn named(&mut self, raw: &str) {
        let sized = |s: &str| s.rsplit_once('@').is_some_and(|(_, n)| n.bytes().all(|b| b.is_ascii_digit()));
        if raw.starts_with('?') || raw.contains("::") || raw.contains('`') || raw.contains('<') {
            self.underived = true;
        } else if let Some(n) = raw.strip_prefix('@').filter(|n| sized(n)) {
            (self.name, self.model) = (n.rsplit_once('@').map_or(n, |x| x.0).to_string(), Some("__fastcall"));
        } else if let Some(n) = raw.strip_prefix('_').filter(|n| !n.starts_with('_') && !n.contains('@')) {
            (self.name, self.model) = (n.to_string(), Some("__cdecl"));
        } else {
            self.name = raw.to_string();
        }
    }
}

/// One address something refers to.
#[derive(Clone, Copy, Default)]
struct Target {
    /// bytes of the last read or write with a size (constant propagation's `createData`)
    size: u32,
    /// a write among the first 100 references (`MappedEntry.getMutabilityOfAddress`)
    write: bool,
    refs: u32,
}

/// Data the Reference analyzer defines at a reference target.
#[derive(Clone)]
enum Def {
    /// a pointer and its value
    Ptr(u32),
    /// a string: its bytes with the terminator, UTF-16 or not, and `s_<text>` for its name
    Str { len: u32, wide: bool, label: String },
}

impl Def {
    fn len(&self) -> u32 {
        match self {
            Def::Ptr(_) => 4,
            Def::Str { len, .. } => *len,
        }
    }
}

/// `OperandReferenceAnalyzer.getStringLength` with its defaults: the characters before the
/// terminator, 5 or more of 0x20..0x7e, tab, CR and LF, within 1000 bytes.
fn ascii_len(bytes: &[u8]) -> Option<u32> {
    let window = &bytes[..bytes.len().min(1000)];
    let n = window.iter().position(|&b| !matches!(b, 0x20..=0x7e | 9 | 10 | 13))?;
    (window[n] == 0 && n >= 5).then_some(n as u32)
}

/// `StringDataInstance.makeStringLabel`: the displayable characters, a run of others as one
/// `_`, up to the 32 characters of the default label length.
fn string_label(prefix: &str, text: impl Iterator<Item = char>) -> String {
    let (mut label, mut gap) = (String::new(), false);
    for c in text {
        if label.len() >= 32 {
            break;
        }
        if ('!'..='~').contains(&c) {
            if std::mem::take(&mut gap) && !label.is_empty() {
                label.push('_');
            }
            label.push(c);
        } else {
            gap = true;
        }
    }
    format!("{prefix}{label}")
}

struct Exporter<'a> {
    img: &'a Image,
    an: &'a Analysis,
    sl: &'a Sleigh,
    protos: &'a Protos,
    funcs: BTreeMap<u32, Func>,
    /// body ranges of every function: first -> (last, entry)
    ranges: BTreeMap<u32, (u32, u32)>,
    /// the `<callfixup>` of the compiler spec by target name
    fixups: HashMap<String, String>,
    underived: BTreeSet<(u32, Underived)>,
    /// ids of the `type` records the written records refer to
    types: BTreeSet<String>,
    core: HashMap<String, String>,
}

/// `name="..." ... id="0x..."` of every type in the core types.
fn core_ids() -> HashMap<String, String> {
    let mut m = HashMap::from([("undefined".to_string(), format!("0x{}", UNDEFINED.0))]);
    for t in CORE_TYPES.split("<type ").skip(1) {
        let attr = |a: &str| t.split(&format!("{a}=\"")).nth(1).and_then(|x| x.split('"').next());
        if let (Some(n), Some(id)) = (attr("name"), attr("id")) {
            m.insert(n.to_string(), id.to_string());
        }
    }
    m
}

/// The call fixups of a compiler spec: target name -> fixup name.
pub fn callfixups(cspec: &str) -> HashMap<String, String> {
    let mut m = HashMap::new();
    for block in cspec.split("<callfixup name=\"").skip(1) {
        let Some((name, rest)) = block.split_once('"') else { continue };
        let rest = rest.split("</callfixup>").next().unwrap_or("");
        for t in rest.split("<target name=\"").skip(1) {
            if let Some(target) = t.split('"').next() {
                m.insert(target.to_string(), name.to_string());
            }
        }
    }
    m
}

impl Exporter<'_> {
    fn writable(&self, a: u32) -> bool {
        a >= TEB.0 || self.img.block_of(a).is_some_and(|s| !s.readonly && s.name != "Headers")
    }

    /// The body range holding `a`: (first, last, entry).
    fn range_at(&self, a: u32) -> Option<(u32, u32, u32)> {
        let (&first, &(last, entry)) = self.ranges.range(..=a).next_back()?;
        (a <= last).then_some((first, last, entry))
    }

    /// The instruction holding `a` and whether `a` is its first byte.
    fn insn_at(&self, a: u32) -> Option<(u32, bool)> {
        let (&start, i) = self.an.insns.range(..=a).next_back()?;
        (a < start + i.len as u32).then_some((start, a == start))
    }

    fn typeref(&self, name: &str) -> String {
        format!("<typeref name=\"{name}\" id=\"{}\"/>", self.core.get(name).map_or("0x0", |s| s.as_str()))
    }

    /// The function's symbol size: its first range from the entry on, at most 8 bytes.
    fn func_size(&self, f: u32) -> u32 {
        self.range_at(f).map_or(1, |(_, last, _)| (last - f + 1).clamp(1, MAX_FUNCTION_OFFCUT))
    }

    /// `<doc>` of a function at `addr` (its entry, or the import slot it hangs on).
    fn function_xml(
        &mut self,
        f: &Func,
        addr: u32,
        size: u32,
        purge: Option<u32>,
        noreturn: bool,
        locals: &str,
    ) -> String {
        if let Some(xml) = self.protos.by_name.get(&f.name).filter(|_| f.import.is_some()) {
            let mut xml = xml.clone();
            if noreturn && !xml.contains(" noreturn=\"true\"") {
                // the no-return analyzers mark the function after the archive's prototype
                xml = xml.replacen("size=\"@SIZE@\">", "size=\"@SIZE@\" noreturn=\"true\">", 1);
                if let Some(end) = xml.find("<prototype").and_then(|p| Some(p + xml[p..].find('>')?)) {
                    xml.insert_str(end, " noreturn=\"true\"");
                }
            }
            let xml = xml.replace("@ADDR@", &format!("0x{addr:x}")).replace("@SIZE@", &size.to_string());
            self.note_types(&xml);
            return xml;
        }
        let name = esc(&f.name);
        let nr = if noreturn { " noreturn=\"true\"" } else { "" };
        let extrapop = purge.map_or("unknown".to_string(), |p| (p + 4).to_string());
        let (model, lock) = f.model.map_or(("unknown", ""), |m| (m, " modellock=\"true\""));
        let symbols =
            if locals.is_empty() { "<symbollist/>".into() } else { format!("<symbollist>{locals}</symbollist>") };
        let inject = self.fixups.get(&f.name).map(|i| format!("<inject>{i}</inject>")).unwrap_or_default();
        format!(
            "<doc id=\"0x0\"><mapsym><function id=\"0x0\" name=\"{name}\" size=\"{size}\"{nr}>\
             <addr space=\"ram\" offset=\"0x{addr:x}\"/><localdb lock=\"false\" main=\"stack\">\
             <scope name=\"{name}\"><parent id=\"0x0\"/><rangelist/>{symbols}</scope></localdb>\
             <prototype extrapop=\"{extrapop}\" model=\"{model}\"{lock}{nr}><returnsym><addr/><void/></returnsym>\
             {inject}</prototype></function><addr space=\"ram\" offset=\"0x{addr:x}\" size=\"{size}\"/>\
             <rangelist/></mapsym></doc>"
        )
    }

    /// Keep the `type` records `xml` refers to, and those they refer to.
    fn note_types(&mut self, xml: &str) {
        let mut todo: Vec<String> = Vec::new();
        let scan = |x: &str, todo: &mut Vec<String>| {
            for t in x.split("<typeref ").skip(1) {
                if let Some(id) = t.split(" id=\"0x").nth(1).and_then(|r| r.split('"').next()) {
                    todo.push(id.to_string());
                }
            }
        };
        scan(xml, &mut todo);
        while let Some(id) = todo.pop() {
            if let Some(rec) = self.protos.types.get(&id) {
                if self.types.insert(id) {
                    scan(rec, &mut todo);
                }
            }
        }
    }

    /// `<doc>` of a data symbol.
    fn symbol_xml(&self, name: &str, addr: u32, size: u32, ty: &str) -> String {
        let ro = if self.writable(addr) { "" } else { " readonly=\"true\"" };
        format!(
            "<doc id=\"0x0\"><mapsym><symbol id=\"0x0\" name=\"{}\" typelock=\"true\" namelock=\"true\"{ro} \
             merge=\"false\" cat=\"-1\">{ty}</symbol><addr space=\"ram\" offset=\"0x{addr:x}\" size=\"{size}\"/>\
             <rangelist/></mapsym></doc>",
            esc(name)
        )
    }

    /// The constant addresses an instruction reads or writes, with the size of each access:
    /// what `SymbolicPropogator` hands `evaluateReference` for a LOAD or STORE.
    fn accesses(&self, p: &mut Parse, a: u32) -> Vec<(u32, u32, bool)> {
        let mut out = Vec::new();
        let Some(sec) = self.img.block_of(a) else { return out };
        if self.sl.decode(p, a as u64, &sec.data[(a - sec.addr) as usize..]).is_err() {
            return out;
        }
        let Ok(ops) = self.sl.pcode(p) else { return out };
        let (code, uniq) = (self.sl.code_space(), self.sl.uniq_space());
        let mut consts: HashMap<u64, u64> = HashMap::new();
        for op in &ops {
            let cv = |v: &crate::sleigh::Varnode, consts: &HashMap<u64, u64>| match v.space {
                0 => Some(v.offset),
                s if s == uniq => consts.get(&v.offset).copied(),
                _ => None,
            };
            // a COPY, INT_ZEXT or INT_SEXT from memory are the direct accesses the propagator
            // sizes (those cases of `SymbolicPropogator.applyPcode` make the reference with the
            // input varnode); a direct write only counts as a write
            if let Some(v) = op.ins.first().filter(|v| matches!(op.opc, 1 | 17 | 18) && v.space == code) {
                out.push((v.offset as u32, v.size, false));
            }
            if let Some(o) = op.out.as_ref().filter(|o| o.space == code) {
                out.push((o.offset as u32, 0, true));
            }
            match (op.opc, op.out.as_ref()) {
                (1, Some(o)) if o.space == uniq => {
                    if let Some(c) = cv(&op.ins[0], &consts) {
                        consts.insert(o.offset, c);
                    }
                }
                (19, Some(o)) if o.space == uniq => {
                    if let (Some(x), Some(y)) = (cv(&op.ins[0], &consts), cv(&op.ins[1], &consts)) {
                        consts.insert(o.offset, x.wrapping_add(y) & 0xffff_ffff);
                    }
                }
                (2, Some(o)) => out.extend(cv(&op.ins[1], &consts).map(|c| (c as u32, o.size, false))),
                (3, None) => out.extend(cv(&op.ins[1], &consts).map(|c| (c as u32, op.ins[2].size, true))),
                _ => {}
            }
        }
        out
    }

    /// Ghidra's Reference analyzer (`OperandReferenceAnalyzer`) over the reference targets
    /// that are not code: a string of 5 or more ASCII characters with its terminator
    /// (`checkForAscii`), a UTF-16 string of more than 3 (`checkForUnicode`), or a pointer
    /// (`checkForPointer`), whose target is looked at in turn. A reference into the bytes a
    /// string or pointer would take stops it. The slots of the address tables are pointers
    /// already. Pointer targets join `targets`.
    // ponytail: Ghidra looks at the references there are when a target comes up, and asks
    // its pseudo-disassembler whether a string in an executable block is code; here every
    // reference of the instructions counts from the start and no string is made in an
    // executable block
    fn reference_data(&self, targets: &mut BTreeMap<u32, Target>, code_refs: &BTreeSet<u32>) -> BTreeMap<u32, Def> {
        let (img, an) = (self.img, self.an);
        let mut defs: BTreeMap<u32, Def> = an.table_slots.iter().map(|(&s, &p)| (s, Def::Ptr(p))).collect();
        let mut refs: BTreeSet<u32> = targets.keys().chain(code_refs).copied().collect();
        let mut queue: std::collections::VecDeque<u32> = targets.keys().copied().collect();
        let mut checked = HashSet::new();
        // the defined data holding `a`: its first address
        let holding = |defs: &BTreeMap<u32, Def>, a: u32| {
            defs.range(..=a).next_back().filter(|(&s, d)| a < s + d.len()).map(|(&s, _)| s)
        };
        while let Some(t) = queue.pop_front() {
            let Some(sec) = img.block_of(t) else { continue };
            if !checked.insert(t) || img.imports.contains_key(&t) || self.insn_at(t).is_some() {
                continue;
            }
            if holding(&defs, t).is_some() {
                continue;
            }
            let bytes = &sec.data[(t - sec.addr) as usize..];
            let within = |refs: &BTreeSet<u32>, len: u32| refs.range(t + 1..t.saturating_add(len)).next().is_some();
            let free = |defs: &BTreeMap<u32, Def>, len: u32| {
                len as usize <= bytes.len()
                    && defs.range(t..t + len).next().is_none()
                    && an.insns.range(t..t + len).next().is_none()
            };
            if let Some(n) = ascii_len(bytes) {
                if !within(&refs, n + 1) && free(&defs, n + 1) {
                    let label = string_label("s_", bytes[..n as usize].iter().map(|&b| b as char));
                    defs.insert(t, Def::Str { len: n + 1, wide: false, label });
                }
                continue;
            }
            let wide = |a: u32| {
                (0..1000u32).find_map(|i| {
                    let o = (a.checked_sub(sec.addr)? + 2 * i) as usize;
                    match u16::from_le_bytes([*sec.data.get(o)?, *sec.data.get(o + 1)?]) {
                        0 => Some(Some(i)),
                        9 | 10 | 13 | 0x20..=0x7e => None,
                        _ => Some(None),
                    }
                })?
            };
            if let Some(n) = wide(t).filter(|&n| n > 3 && wide(t.wrapping_sub(8)).is_none_or(|m| m <= n + 2)) {
                if !within(&refs, n) {
                    if free(&defs, 2 * (n + 1)) {
                        let chars = bytes[..2 * n as usize].chunks(2).map(|c| c[0] as char);
                        defs.insert(t, Def::Str { len: 2 * (n + 1), wide: true, label: string_label("u_", chars) });
                    }
                    continue;
                }
            }
            let Some(v) = img.read_u32(t).filter(|&v| v >= 4096 && img.block_of(v).is_some()) else { continue };
            // the code unit at the value starts there; an instruction something falls into
            // must be a function's entry, any other must not lie inside another function
            let lands = match self.insn_at(v) {
                Some((_, false)) => false,
                Some(_)
                    if an
                        .insns
                        .range(v.saturating_sub(15)..v)
                        .any(|(&s, i)| s + i.len as u32 == v && i.falls_through()) =>
                {
                    an.funcs.contains(&v)
                }
                Some(_) => self.range_at(v).is_none_or(|(_, _, entry)| entry == v),
                None => holding(&defs, v).is_none_or(|s| s == v),
            };
            if lands && !within(&refs, 4) && free(&defs, 4) {
                defs.insert(t, Def::Ptr(v));
                targets.entry(v).or_default().refs += 1;
                refs.insert(v);
                queue.push_back(v);
            }
        }
        defs
    }

    /// Ghidra's ASCII Strings analyzer (`StringsAnalyzer` with its defaults, `crate::strings`)
    /// over the listing the reference analysis left: a string the search finds and the model
    /// accepts becomes data where its bytes are undefined (no instruction, pointer, string or
    /// import slot; `DataUtilities.isUndefinedRange`), or where only a string of its kind lies
    /// at its end ("Create Strings Containing Existing Strings"), which it takes over. Its
    /// length takes the zero bytes up to the next multiple of 4 ("String end alignment") when
    /// they are undefined.
    // ponytail: the listing is this analysis's (Ghidra's loader and RTTI structures are not
    // derived, so a string inside one is found here and not in Java); f64 `log10` is Rust's,
    // which can differ from Java's in the last bit of a score at its threshold
    fn ascii_strings(&self, defs: &mut BTreeMap<u32, Def>, model: &crate::strings::Model) {
        let (img, an) = (self.img, self.an);
        let slots: BTreeSet<u32> = img.imports.keys().copied().collect();
        // the first instruction or defined data that overlaps `first..=last`
        let defined = |defs: &BTreeMap<u32, Def>, first: u32, last: u32| -> Option<u32> {
            let ins = an.insns.range(..=last).next_back().filter(|(&a, i)| a + i.len as u32 > first).map(|(&a, _)| a);
            let def = defs.range(..=last).next_back().filter(|(&a, d)| a + d.len() > first).map(|(&a, _)| a);
            let slot = slots.range(..=last).next_back().filter(|&&a| a + 4 > first).copied();
            ins.or(def).or(slot)
        };
        // the ranges of initialized memory: sections that follow one another without a gap
        let mut runs: Vec<(u32, Vec<u8>)> = Vec::new();
        let mut sections: Vec<&crate::analysis::Section> = img.sections.iter().collect();
        sections.sort_by_key(|s| s.addr);
        let mut open = false;
        for s in sections {
            let init = &s.data[..s.data.len() - (s.zero_tail as usize).min(s.data.len())];
            match runs.last_mut() {
                Some((base, bytes)) if open && *base + bytes.len() as u32 == s.addr => bytes.extend(init),
                _ => runs.push((s.addr, init.to_vec())),
            }
            open = s.zero_tail == 0;
        }
        for (base, bytes) in &runs {
            let mut found = Vec::new();
            crate::strings::search(bytes, &mut |f| found.push(f));
            for f in found {
                let (start, wide) = (base + f.offset as u32, f.wide);
                let end = start + f.len as u32 - 1;
                let step = if wide { 2 } else { 1 };
                let chars: Vec<u8> = bytes[f.offset..f.offset + f.len - step].iter().step_by(step).copied().collect();
                if !model.accepts(&chars) || img.block_of(start).is_none_or(|s| end >= s.addr + s.data.len() as u32) {
                    continue;
                }
                if defined(defs, start, end).is_some() {
                    // only a string of the same kind holding the end, after the start
                    let Some((&at, Def::Str { wide: w, .. })) = defs.range(..=end).next_back() else { continue };
                    if *w != wide
                        || at <= start
                        || at + defs[&at].len() <= end
                        || defined(defs, start, at - 1).is_some()
                    {
                        continue;
                    }
                }
                let mut len = f.len as u32;
                let pad = (crate::strings::END_ALIGNMENT - (end + 1) % crate::strings::END_ALIGNMENT)
                    % crate::strings::END_ALIGNMENT;
                let zero = |a: u32| img.block_of(a).is_some_and(|s| s.data[(a - s.addr) as usize] == 0);
                if pad > 0 && (end + 1..=end + pad).all(zero) && defined(defs, end + 1, end + pad).is_none() {
                    len += pad;
                }
                let taken: Vec<u32> = defs.range(start..start + len).map(|(&a, _)| a).collect();
                taken.iter().for_each(|a| {
                    defs.remove(a);
                });
                let label = string_label(if wide { "u_" } else { "s_" }, chars.iter().map(|&c| c as char));
                defs.insert(start, Def::Str { len, wide, label });
            }
        }
    }

    /// Ghidra's stack analysis (`NewFunctionStackAnalysisCmd` with its defaults: local
    /// variables, no parameters) as the `<mapsym>` list of the function's scope. Constant
    /// propagation walks the function with ESP at the entry as the stack's origin; a read or
    /// write through a stack address that an operand names makes a variable of the bytes the
    /// instruction's last LOAD or STORE moves, an LEA of a stack address one of no size
    /// (`undefined`), and a variable that meets others becomes one over them all
    /// (`accumulateVariable`).
    // ponytail: "an operand names the address" is "not the slot a PUSH, POP or CALL uses
    // itself" (Ghidra adds up the operand's registers and scalars, `getStackOpIndex`). A call
    // whose purge is unknown ends the stack tracking of its path; the purges are the ones
    // `call_purges` gives the analysis for this walk, which have every function Ghidra's
    // auto-analysis made, not only those it had made when it analysed the caller
    fn locals(&self, p: &mut Parse, f: u32) -> String {
        const PREFIXES: [u8; 10] = [0x66, 0x67, 0xf2, 0xf3, 0x26, 0x2e, 0x36, 0x3e, 0x64, 0x65];
        let (rs, _) = self.sl.registers();
        // offset -> (bytes, of no data-type)
        let mut vars: BTreeMap<i32, (u32, bool)> = BTreeMap::new();
        let mut accumulate = |offset: i32, ref_size: u32| {
            // MAX_LOCAL_OFFSET, MAX_PARAM_OFFSET; from the return address up are parameters
            if !(-(64 * 1024)..4).contains(&offset) {
                return;
            }
            let size = ref_size.max(1) as i32;
            let hits: Vec<(i32, u32)> = vars
                .range(..offset + size)
                .filter(|(&o, &(len, _))| o + len as i32 > offset)
                .map(|(&o, &(len, _))| (o, len))
                .collect();
            match (hits.first(), hits.last()) {
                (Some(&(_, len)), _) if len == size as u32 => {} // "exact match": the length alone
                (Some(&(first, _)), Some(&(last, len))) => {
                    let (min, max) = (first.min(offset), (last + len as i32).max(offset + size));
                    hits.iter().for_each(|h| {
                        vars.remove(&h.0);
                    });
                    vars.insert(min, ((max - min) as u32, false));
                }
                _ => {
                    vars.insert(offset, (size as u32, ref_size == 0));
                }
            }
        };
        self.an.flow_walk(self.img, self.sl, p, f, true, &mut |a, fold| {
            let Some(sec) = self.img.block_of(a) else { return };
            let bytes = &sec.data[(a - sec.addr) as usize..];
            let op = &bytes[bytes.iter().take_while(|b| PREFIXES.contains(b)).count()..];
            let reg = |r: u64| fold.stack_offset(rs, r);
            let modrm = op.get(1).map_or(0, |m| (m >> 3) & 7);
            // the slot the instruction uses itself, which no operand names
            let (skip_all, own_store, own_load) = match (op.first().copied().unwrap_or(0), modrm, op.get(1)) {
                (0xc2 | 0xc3 | 0xca | 0xcb | 0xcf | 0xc8 | 0xc9 | 0x60 | 0x61 | 0x9c | 0x9d, ..) => (true, None, None),
                (0xe8 | 0x9a, ..) | (0xff, 2 | 3, _) => (false, Some(None), None), // CALL: any store
                (0x50..=0x57 | 0x68 | 0x6a | 0x06 | 0x0e | 0x16 | 0x1e, ..) | (0xff, 6, _) => {
                    (false, Some(reg(0x10)), None)
                }
                (0x0f, _, Some(0xa0 | 0xa8)) => (false, Some(reg(0x10)), None),
                (0x58..=0x5f | 0x07 | 0x17 | 0x1f, ..) | (0x8f, 0, _) | (0x0f, _, Some(0xa1 | 0xa9)) => {
                    (false, None, reg(0x10).map(|d| d.wrapping_sub(4)))
                }
                _ => (false, None, None),
            };
            if skip_all {
                return;
            }
            for &(d, _, store) in &fold.stack {
                let own = if store { own_store.is_some_and(|s| s.is_none_or(|s| s == d)) } else { own_load == Some(d) };
                if !own {
                    accumulate(d as i32, fold.mem_size);
                }
            }
            // LEA: the stack address its register holds afterwards
            if op.first() == Some(&0x8d) && !bytes[..bytes.len() - op.len()].contains(&0x66) {
                if let Some(d) = reg(4 * modrm as u64) {
                    accumulate(d as i32, fold.mem_size);
                }
            }
        });
        let mut xml = String::new();
        for (&offset, &(len, plain)) in &vars {
            let name = if offset < 0 { format!("local_{:x}", -offset) } else { format!("local_res{offset:x}") };
            let ty = match len {
                1 if plain => self.typeref("undefined"),
                1..=8 => self.typeref(&format!("undefined{len}")),
                _ => format!(
                    "<type name=\"\" metatype=\"array\" size=\"{len}\" arraysize=\"{len}\">{}</type>",
                    self.typeref("undefined1")
                ),
            };
            let _ = write!(
                xml,
                "<mapsym><symbol id=\"0x0\" name=\"{name}\" typelock=\"false\" namelock=\"true\" cat=\"-1\">{ty}</symbol>\
                 <addr space=\"stack\" offset=\"0x{:x}\" size=\"{len}\"/><rangelist/></mapsym>",
                offset as u32
            );
        }
        xml
    }

    /// `Analysis::ret_purge`: Ghidra's purge of the function.
    fn purge(&self, f: u32, depth: u32) -> Option<u32> {
        self.an.ret_purge(self.img, f, depth)
    }
}

/// The names of the functions: an export's, Function ID's, a thunk's, or `FUN_<address>`.
fn name_functions(img: &Image, an: &Analysis, fid: &BTreeMap<u32, Applied>, protos: &Protos) -> BTreeMap<u32, Func> {
    let exports: HashMap<u32, &str> = img.exports.iter().map(|(a, n)| (*a, n.as_str())).collect();
    let mut funcs: BTreeMap<u32, Func> = BTreeMap::new();
    for &f in &an.funcs {
        let mut func = Func { name: format!("FUN_{f:08x}"), ..Func::default() };
        let raw = exports.get(&f).copied().or_else(|| fid.get(&f).map(|a| a.name.as_str()));
        if let Some(raw) = raw {
            func.named(raw);
        } else if let Some(i) = an.bodies.get(&f).filter(|b| b.len() == 1).and_then(|_| an.insns.get(&f)) {
            // a thunk: one jump to a function or through an import slot
            match (i.flow, i.target, i.slot) {
                (Flow::Jump, Some(t), _) if t != f && an.funcs.contains(&t) => func.thunked = Some(t),
                (Flow::JumpInd, _, Some(s)) if img.imports.contains_key(&s) => func.import = Some(s),
                // through a pointer that holds a function's entry (SecuROM's slots)
                (Flow::JumpInd, _, Some(s)) => {
                    func.thunked = img.read_u32(s).filter(|t| *t != f && an.funcs.contains(t))
                }
                _ => {}
            }
        }
        funcs.insert(f, func);
    }
    // a thunk takes the name of the function at the end of its chain, `thunk_` before a
    // default one
    let entries: Vec<u32> = funcs.keys().copied().collect();
    for f in entries {
        let (mut t, mut hops) = (f, 0);
        while let Some(next) = funcs[&t].thunked.filter(|_| hops < 16) {
            (t, hops) = (next, hops + 1);
        }
        if t != f {
            let end = funcs[&t].clone();
            let me = funcs.get_mut(&f).unwrap();
            me.name = if end.import.is_none() && end.name.starts_with("FUN_") {
                format!("thunk_{}", end.name)
            } else {
                end.name.clone()
            };
            (me.model, me.import, me.underived) = (end.model, end.import, end.underived);
            me.thunked = Some(t);
        }
        if let Some(slot) = funcs[&f].import {
            let (me, raw) = (funcs.get_mut(&f).unwrap(), &img.imports[&slot].1);
            me.name = raw.clone();
            // a name the archive has stays as it is (`_cexit`); the demangler has the others
            if !protos.by_name.contains_key(raw) {
                me.named(raw);
            }
        }
    }
    funcs
}

/// What `export` takes besides the analysis.
pub struct Inputs<'a> {
    /// Function ID's names
    pub fid: &'a BTreeMap<u32, Applied>,
    /// the prototypes of Ghidra's data-type archives, for the imports
    pub protos: Option<&'a Protos>,
    /// the functions discovery finds without seeds, where seeds were given: Ghidra's
    /// auto-analysis worked on these, a seeded one stands for a function a script made later
    pub analyzed: Option<&'a BTreeSet<u32>>,
    /// the text of the compiler spec (its call fixups)
    pub cspec: &'a str,
    /// the trigram model of Ghidra's ASCII Strings analyzer; without it that analyzer does not run
    pub strings: Option<&'a crate::strings::Model>,
}

/// The bytes a call pops besides the return address, as Ghidra's stack analysis has them at a
/// call site (`SymbolicPropogator.getFunctionPurge`), by function entry and by import slot: 0
/// for a calling convention with a known extrapop (`__cdecl`), whatever the function's purge
/// is; the prototype's for an import of the archive; else the purge
/// `FunctionPurgeAnalysisCmd` gave the function, which only a function of auto-analysis has. A
/// thunk has its target's.
pub fn call_purges(img: &Image, an: &Analysis, inputs: &Inputs) -> HashMap<u32, u32> {
    let none = Protos::default();
    let protos = inputs.protos.unwrap_or(&none);
    let auto = |f: u32| inputs.analyzed.is_none_or(|s| s.contains(&f));
    // the prototype of the function itself comes after its symbols
    let proto_purge = |name: &str| {
        let xml = protos.by_name.get(name)?;
        let at = xml.find("</localdb><prototype extrapop=\"")? + "</localdb><prototype extrapop=\"".len();
        xml[at..].split('"').next()?.parse::<u32>().ok()?.checked_sub(4)
    };
    let mut out = HashMap::new();
    for (&slot, (_, name)) in &img.imports {
        if let Some(n) = proto_purge(name) {
            out.insert(slot, n);
        }
    }
    for (&f, func) in &name_functions(img, an, inputs.fid, protos) {
        let end = func.thunked.unwrap_or(f);
        let purge = match func.import {
            _ if func.model == Some("__cdecl") => Some(0),
            Some(slot) => out.get(&slot).copied(),
            None if auto(end) => an.ret_purge(img, end, 0),
            None => None,
        };
        if let Some(n) = purge {
            out.insert(f, n);
        }
    }
    out
}

/// Write the facts of `an` to `out`.
pub fn export(img: &Image, an: &Analysis, sl: &Sleigh, inputs: &Inputs, out: &mut dyn Write) -> io::Result<()> {
    let Inputs { fid, protos, analyzed, cspec, strings } = *inputs;
    let none = Protos::default();
    let mut ex = Exporter {
        img,
        an,
        sl,
        protos: protos.unwrap_or(&none),
        funcs: name_functions(img, an, fid, protos.unwrap_or(&none)),
        ranges: BTreeMap::new(),
        fixups: callfixups(cspec),
        underived: BTreeSet::new(),
        types: BTreeSet::new(),
        core: core_ids(),
    };
    // bodies as ranges; where bodies overlap the lowest entry keeps the bytes
    let mut body_ranges: BTreeMap<u32, Vec<(u32, u32)>> = BTreeMap::new();
    for (&f, body) in &an.bodies {
        let mut v: Vec<(u32, u32)> = Vec::new();
        for &a in body {
            let end = a + an.insns[&a].len as u32 - 1;
            match v.last_mut() {
                Some(r) if r.1 + 1 == a => r.1 = end,
                _ => v.push((a, end)),
            }
        }
        for &(first, last) in &v {
            ex.ranges.entry(first).or_insert((last, f));
        }
        body_ranges.insert(f, v);
    }

    writeln!(out, "ghidra-rs-facts 2")?;
    writeln!(out, "coretypes\t{}", CORE_TYPES.trim_end())?;

    // every address something refers to, in the order of the functions and their instructions
    let mut targets: BTreeMap<u32, Target> = BTreeMap::new();
    let mut code_refs: BTreeSet<u32> = BTreeSet::new();
    let mut p = sl.new_parse();
    // the functions Ghidra's analyzers worked on: every one, or the ones found without the seeds
    let auto = |f: u32| analyzed.is_none_or(|s| s.contains(&f));
    let mut owner: HashMap<u32, u32> = HashMap::new();
    for (&f, body) in &an.bodies {
        for &a in body {
            owner.entry(a).or_insert(f);
        }
    }
    for (&a, i) in &an.insns {
        // constant propagation sizes the data only in the functions it ran on
        let sized = match owner.get(&a) {
            Some(&f) if !i.refs.is_empty() && auto(f) => ex.accesses(&mut p, a),
            _ => Vec::new(),
        };
        for &r in &i.refs {
            let t = targets.entry(r).or_default();
            t.refs += 1;
            for &(_, size, write) in sized.iter().filter(|x| x.0 == r) {
                if (1..=8).contains(&size) {
                    t.size = size;
                }
                t.write |= write && t.refs <= 100;
            }
        }
        code_refs.extend(i.code_imms.iter().copied());
        if matches!(i.flow, Flow::Jump | Flow::CondJump | Flow::Call) {
            code_refs.extend(i.target);
        }
        code_refs.extend(i.computed);
    }
    // SymbolicPropogator's LOAD and STORE through an address a register holds: a reference to
    // the memory, of the bytes moved, where constant propagation ran
    for &f in an.bodies.keys().filter(|&&f| auto(f)) {
        an.flow_walk(img, sl, &mut p, f, false, &mut |_, fold| {
            for &(x, size, write) in fold.data.iter().filter(|d| img.block_of(d.0).is_some()) {
                let t = targets.entry(x).or_default();
                t.refs += 1;
                if (1..=8).contains(&size) {
                    t.size = size;
                }
                t.write |= write && t.refs <= 100;
            }
        });
    }
    let mut cases: HashSet<u32> = HashSet::new();
    for c in an.tables.values() {
        cases.extend(c.iter().copied());
    }
    for (&slot, &ptr) in &an.table_slots {
        targets.entry(ptr).or_default().refs += 1;
        targets.entry(slot).or_default();
    }

    // memory blocks, and the addresses of the read-only ones that are written
    for s in &img.sections {
        let last = s.addr + s.data.len() as u32 - 1;
        writeln!(out, "block\t{:x}\t{last:x}\t{}", s.addr, if ex.writable(s.addr) { "w" } else { "r" })?;
    }
    writeln!(out, "block\t{:x}\t{:x}\tw", TEB.0, TEB.0 + (TEB.1 - 1))?;
    for (&a, t) in &targets {
        if t.write && !ex.writable(a) && img.block_of(a).is_some() {
            writeln!(out, "wref\t{a:x}")?;
        }
    }

    // functions
    let (_, regs) = sl.registers();
    let mut sets: Vec<(u64, u32, u64)> = Vec::new();
    for (name, val) in sl.tracked.iter().map(|(n, v)| (n.as_str(), *v as u64)).chain([("FS_OFFSET", TEB.0 as u64)]) {
        if let Some(r) = regs.iter().find(|r| r.0 == name) {
            sets.push((r.1, r.2, val));
        }
    }
    sets.sort();
    let entries: Vec<u32> = an.funcs.iter().copied().filter(|f| an.bodies.contains_key(f)).collect();
    for (n, &f) in entries.iter().enumerate() {
        let func = ex.funcs[&f].clone();
        let end = func.thunked.unwrap_or(f);
        let noreturn = an.noreturn.contains(&f) || func.import.is_some_and(|s| an.noreturn.contains(&s));
        let size = ex.func_size(f);
        let purge = match func.import {
            // an import: `__cdecl` pops nothing, any other is the prototype's business
            Some(_) => (func.model == Some("__cdecl")).then_some(0),
            None if auto(end) => ex.purge(end, 0),
            None => None,
        };
        let thunk = func.thunked.is_some() || func.import.is_some();
        let locals = if auto(f) && !thunk { ex.locals(&mut p, f) } else { String::new() };
        let xml = ex.function_xml(&func, f, size, purge, noreturn, &locals);
        writeln!(out, "func\t{f:x}\t{xml}")?;
        write!(out, "body\t{f:x}")?;
        for (first, last) in &body_ranges[&f] {
            write!(out, "\t{first:x}-{last:x}")?;
        }
        writeln!(out)?;
        if n == 0 {
            let mut x = format!("<tracked_pointset space=\"ram\" offset=\"0x{f:x}\">");
            for (off, size, val) in &sets {
                let _ = write!(x, "<set space=\"register\" offset=\"0x{off:x}\" size=\"{size}\" val=\"0x{val:x}\"/>");
            }
            writeln!(out, "tracked\t{f:x}\t{x}</tracked_pointset>")?;
        }
        let cdecl = func.model == Some("__cdecl");
        if func.underived || (func.import.is_some() && !cdecl && !ex.protos.by_name.contains_key(&func.name)) {
            ex.underived.insert((f, Underived::Function));
        }
        // Function ID's plate comment; the demangler's comment of a C++ name is not derived
        match fid.get(&f).map(|a| &a.comment) {
            Some(Some(text)) if !func.underived => writeln!(
                out,
                "comments\t{f:x}\t<commentdb><comment type=\"header\"><addr space=\"ram\" offset=\"0x{f:x}\"/>\
                 <addr space=\"ram\" offset=\"0x{f:x}\"/><text>{}</text></comment></commentdb>",
                esc(text).replace('\n', "&#10;")
            )?,
            Some(_) => {
                ex.underived.insert((f, Underived::Comments));
            }
            None if func.underived => {
                ex.underived.insert((f, Underived::Comments));
            }
            None => {}
        }
    }

    // imports: the pointer and the function Java hangs on it
    let mut slots: Vec<(&u32, &(String, String))> = img.imports.iter().collect();
    slots.sort();
    for (&slot, (_, raw)) in slots {
        let mut func = Func { name: raw.clone(), import: Some(slot), ..Func::default() };
        if !ex.protos.by_name.contains_key(raw) {
            func.named(raw);
        }
        let name = &func.name;
        let sym = format!(
            "<doc id=\"0x0\"><mapsym><externrefsymbol name=\"{}_exref\"><addr space=\"ram\" offset=\"0x{slot:x}\"/>\
             </externrefsymbol><addr space=\"ram\" offset=\"0x{slot:x}\" size=\"1\"/><rangelist/></mapsym></doc>",
            esc(name)
        );
        writeln!(out, "data\t{slot:x}\t4\t{sym}")?;
        // a `__cdecl` function pops nothing: its extrapop is known without a prototype
        let cdecl = func.model == Some("__cdecl");
        let xml = ex.function_xml(&func, slot, 2, cdecl.then_some(0), an.noreturn.contains(&slot), "");
        writeln!(out, "extref\t{slot:x}\t{xml}")?;
        if func.underived || !(cdecl || ex.protos.by_name.contains_key(name)) {
            ex.underived.insert((slot, Underived::Function));
        }
        targets.remove(&slot);
    }

    let mut defs = ex.reference_data(&mut targets, &code_refs);
    if let Some(model) = strings {
        ex.ascii_strings(&mut defs, model);
    }

    // labels at instructions: a function's name, `LAB_` where something refers to one
    for (&a, i) in &an.insns {
        let _ = i;
        if let Some(f) = ex.funcs.get(&a).filter(|_| an.bodies.contains_key(&a)) {
            writeln!(out, "label\t{a:x}\t{}", f.name)?;
        } else if cases.contains(&a) {
            ex.underived.insert((a, Underived::Label));
        } else if code_refs.contains(&a) || targets.contains_key(&a) {
            writeln!(out, "label\t{a:x}\tLAB_{a:08x}")?;
            if ex.range_at(a).is_none() {
                // code outside every function: a label without data
                let ro = if ex.writable(a) { "" } else { " readonly=\"true\"" };
                writeln!(
                    out,
                    "data\t{a:x}\t1\t<doc id=\"0x0\"><mapsym><labelsym id=\"0x0\" name=\"LAB_{a:08x}\" typelock=\"true\" \
                     namelock=\"true\"{ro} merge=\"false\" cat=\"-1\"/><addr space=\"ram\" offset=\"0x{a:x}\" size=\"1\"/>\
                     <rangelist/></mapsym></doc>"
                )?;
            }
        }
    }

    // data symbols: what the references define, and a plain symbol at every other reference
    let undefined = ex.typeref("undefined");
    let pointer = format!("<type name=\"\" metatype=\"ptr\" size=\"4\">{undefined}</type>");
    let mut covered = 0u32; // the end of the data symbol before
    let mut defined: Vec<(u32, u32)> = Vec::new(); // instructions and data with a data-type
    let addrs: BTreeSet<u32> = targets.keys().chain(defs.keys()).copied().collect();
    for &a in &addrs {
        let skip = a < covered || img.block_of(a).is_none() || img.imports.contains_key(&a);
        if skip || ex.range_at(a).is_some() || ex.insn_at(a).is_some() {
            continue; // code: its label is written above
        }
        // room up to the next reference or defined data
        let next = addrs.range(a + 1..).next().copied().unwrap_or(u32::MAX);
        let sized = targets.get(&a).map_or(0, |t| t.size);
        let (name, size, ty) = match defs.get(&a) {
            Some(Def::Ptr(to)) => (format!("PTR_{}_{a:08x}", pointee_name(&ex, &defs, *to)), 4, pointer.clone()),
            Some(Def::Str { len, wide, label }) => {
                let (elem, n) = if *wide { ("wchar_t", len / 2) } else { ("char", *len) };
                let ty = format!(
                    "<type name=\"\" metatype=\"array\" size=\"{len}\" arraysize=\"{n}\">{}</type>",
                    ex.typeref(elem)
                );
                // the characters before the terminator (zero bytes may follow it)
                let chars = img.block_of(a).map_or(0, |s| {
                    s.data[(a - s.addr) as usize..].iter().take(*len as usize).take_while(|&&b| b != 0).count()
                });
                let plain = if *wide { "-".to_string() } else { chars.to_string() };
                writeln!(out, "string\t{a:x}\t{len}\t{plain}")?;
                (format!("{label}_{a:08x}"), *len, ty)
            }
            None if sized >= 1 && a + sized <= next => {
                (format!("DAT_{a:08x}"), sized, ex.typeref(&format!("undefined{sized}")))
            }
            None => (format!("DAT_{a:08x}"), 1, undefined.clone()),
        };
        writeln!(out, "data\t{a:x}\t{size}\t{}", ex.symbol_xml(&name, a, size, &ty))?;
        covered = a + size;
        if ty != undefined {
            defined.push((a, a + size));
        }
    }

    // the undefined bytes of the blocks that are not writable: Java gives each one without a
    // symbol a read-only `UNK_` symbol of one byte
    defined.extend(an.insns.iter().map(|(&a, i)| (a, a + i.len as u32)));
    defined.extend(img.imports.keys().map(|&s| (s, s + 4)));
    defined.sort_unstable();
    for s in img.sections.iter().filter(|s| !ex.writable(s.addr)) {
        let end = s.addr + s.data.len() as u32;
        let mut at = s.addr;
        let lo = defined.partition_point(|d| d.1 <= s.addr);
        for &(first, last) in defined[lo..].iter().take_while(|d| d.0 < end).chain([&(end, end)]) {
            if first > at && !(at..first).all(|b| targets.contains_key(&b)) {
                writeln!(out, "undef\t{at:x}\t{:x}\tUNK_", first - 1)?;
            }
            at = at.max(last);
        }
    }

    // flow overrides: a jump to another function is a call followed by a return
    // (Ghidra's Shared Return Calls analyzer); a thunk's jump is not
    // and so is a call of a function that does not return (the no-return analyzers)
    for (&a, i) in &an.insns {
        let f = owner.get(&a).copied();
        if f.and_then(|f| ex.funcs.get(&f)).is_some_and(|x| x.thunked.is_some() || x.import.is_some()) {
            continue;
        }
        let call_return = match i.flow {
            Flow::Jump => i.target.is_some_and(|t| Some(t) != f && an.funcs.contains(&t)),
            Flow::Call => i.target.is_some_and(|t| an.noreturn.contains(&t)),
            Flow::CallInd => i.slot.is_some_and(|s| an.noreturn.contains(&s)),
            _ => false,
        };
        if call_return {
            writeln!(out, "override\t{a:x}\tCALL_RETURN")?;
        }
    }

    for (a, what) in &ex.underived {
        writeln!(out, "underived\t{a:x}\t{}", what.word())?;
    }
    for id in &ex.types {
        writeln!(out, "type\t{id}\t{}", ex.protos.types[id])?;
    }
    if !ex.types.contains(UNDEFINED.0) {
        writeln!(out, "type\t{}\t{}", UNDEFINED.0, UNDEFINED.1)?;
    }
    Ok(())
}

/// The part of a pointer's name that names what it points to: the label there without its
/// address (`SymbolUtilities.getDynamicName`: `PTR_FUN_`, `PTR_DAT_`, `PTR_LAB_`, `PTR_PTR_`).
fn pointee_name(ex: &Exporter, defs: &BTreeMap<u32, Def>, to: u32) -> String {
    if let Some(f) = ex.funcs.get(&to).filter(|_| ex.an.bodies.contains_key(&to)) {
        return if f.name.ends_with(&format!("_{to:08x}")) {
            f.name[..f.name.len() - 9].to_string()
        } else {
            f.name.clone()
        };
    }
    match defs.get(&to) {
        _ if ex.an.insns.contains_key(&to) => "LAB".into(),
        Some(Def::Ptr(_)) => "PTR".into(),
        Some(Def::Str { label, .. }) => label.clone(),
        None => "DAT".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strings_as_the_reference_analyzer_reads_them() {
        assert_eq!(ascii_len(b"hello\0"), Some(5));
        assert_eq!(ascii_len(b"four\0"), None); // fewer than 5 characters
        assert_eq!(ascii_len(b"hello"), None); // no terminator
        assert_eq!(ascii_len(b"hel\x01lo\0"), None);
        // a run of spaces is one `_`, and the label stops after 32 characters
        assert_eq!(string_label("s_", "a  b %d".chars()), "s_a_b_%d");
        assert_eq!(string_label("s_", " x".chars()), "s_x");
        assert_eq!(string_label("s_", "x".repeat(40).chars()).len(), 34);
    }

    #[test]
    fn call_fixups_and_prototypes() {
        let spec = "<callfixup name=\"EH_prolog\">\n<target name=\"__EH_prolog\"/><target name=\"_EH_prolog\"/>\n\
                    <pcode/></callfixup><callfixup name=\"x\"><target name=\"y\"/></callfixup>";
        let m = callfixups(spec);
        assert_eq!((m.len(), m["_EH_prolog"].as_str(), m["y"].as_str()), (3, "EH_prolog", "x"));
        let p = Protos::parse("ghidra-rs-protos 1\nproto\tSleep\t<doc/>\ntype\t5\t<type/>\n").unwrap();
        assert_eq!((p.by_name["Sleep"].as_str(), p.types["5"].as_str()), ("<doc/>", "<type/>"));
        assert!(Protos::parse("ghidra-rs-protos 0\n").is_err());
        assert!(Protos::parse("ghidra-rs-protos 1\nbad\n").is_err());
    }
}
