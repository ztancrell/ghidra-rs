//! Milestone 3, stage S0: the harness the decompiler stages are checked with (see
//! `docs/plans/m3-decompiler.md`). It has three parts:
//!
//! - [`prelude`]: the console commands both engines read before a function, generated from
//!   ghidra-rs's own analysis (functions, import slots, read-only `.rdata`);
//! - [`Console`]: the Rust side of Ghidra's console decompiler (`decomp_dbg`). It reads the same
//!   scripts and prints in the same format. `decompile` runs the ported actions up to a `break
//!   start` (see [`crate::decomp::action`]); every command the corpora do not need fails loudly;
//! - [`datatest`]: a port of `testfunction.cc`, which runs the upstream XML datatests (corpus D)
//!   on either engine and checks their `<stringmatch>` patterns.

use crate::analysis::{Analysis, Image};
use crate::decomp::action::{self, ActionTree, Outcome};
use crate::decomp::{Arch, Funcdata, LowlevelError};
use crate::sleigh::Sleigh;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::Write;

/// A name the console reads as one token: whitespace and anything outside the usual symbol
/// characters become `_`.
fn token(name: &str) -> String {
    name.chars().map(|c| if c.is_ascii_alphanumeric() || "_@?$.:<>~".contains(c) { c } else { '_' }).collect()
}

/// The shared prelude, for `source` before `load addr`:
/// - `option readonly on`: Ghidra's default ("respect read-only flags"); the console's is off;
/// - `readonly` over `.rdata`, so constants there (floats, tables) fold as in Ghidra;
/// - for each IAT slot, a function at the slot (`nocode`, named after the import) and an
///   external reference from the slot to it, so `CALL [slot]` becomes a call to the import
///   instead of a decode of the bound address the slot holds;
/// - `map function` for every function, with its FID name or export name when it has one;
/// - ELF only: after a function's `map function` (which makes it the current function, as in the
///   datatests), `override flow <address> callreturn` for each instruction of its body with a
///   CALL_RETURN override in the facts (`factsout::call_returns`: Shared Return Calls and calls
///   that do not return), so flow stops at a tail jump to another function, as in Ghidra. The
///   PE prelude has none: it and the checks built on it (bars.sh) stay as they are.
pub fn prelude(img: &Image, an: &Analysis, fid: &BTreeMap<u32, crate::fid::Applied>) -> String {
    let mut s = String::from("option readonly on\n");
    // a PIE linked at 0: bfd's sections move where ghidra-rs's image has them (IfcAdjustVma);
    // the read-only ranges bfd gave at load stay at the old addresses, so all are marked again
    if img.elf_adjust != 0 {
        let _ = writeln!(s, "adjust vma 0x{:x}", img.elf_adjust);
    }
    // ELF: bfd marks the sections without SHF_WRITE read-only itself (LoadImageBfd::getReadonly,
    // loadimage_bfd.cc:286-301); `.got` and `.got.plt` are read-only in ghidra-rs's image too
    let marked = |sec: &crate::analysis::Section| match img.elf64 {
        true => sec.name.starts_with(".got") || (img.elf_adjust != 0 && sec.readonly),
        false => sec.name == ".rdata",
    };
    for sec in img.sections.iter().filter(|s| marked(s)) {
        let _ = writeln!(s, "readonly 0x{:08x}:{}", sec.addr, sec.data.len());
    }
    let mut imports: Vec<_> = img.imports.iter().collect();
    imports.sort();
    for (slot, (_, name)) in imports {
        let name = token(name);
        let _ = writeln!(s, "map function 0x{slot:08x} {name} nocode");
        let _ = writeln!(s, "map externalref 0x{slot:08x} 0x{slot:08x} {name}");
    }
    let exports: BTreeMap<u32, &str> = img.exports.iter().map(|(a, n)| (*a, n.as_str())).collect();
    let overrides = if img.elf64 { crate::factsout::call_returns(img, an, fid) } else { Default::default() };
    for &f in &an.funcs {
        let name = fid.get(&f).map(|a| a.name.as_str()).or_else(|| exports.get(&f).copied());
        let _ = writeln!(s, "map function 0x{f:08x}{}", name.map(|n| format!(" {}", token(n))).unwrap_or_default());
        for a in an.bodies.get(&f).into_iter().flatten().filter(|a| overrides.contains(a)) {
            let _ = writeln!(s, "override flow 0x{a:x} callreturn");
        }
    }
    s
}

/// The Rust console. It echoes each command after the `init> ` prompt, as `decomp_dbg -i` does.
#[derive(Default)]
pub struct Console {
    /// the program from `load file`
    arch: Option<Arch>,
    function: Option<(u32, String)>,
    /// functions from `map function`, by name
    functions: std::collections::HashMap<String, u32>,
    /// functions mapped `nocode` (imports): `decompile` prints "No code for"
    nocode: std::collections::HashSet<u32>,
    /// the action `break start` stops before
    break_start: Option<String>,
    /// the function `decompile` worked on last
    fd: Option<Funcdata>,
    /// the action tree working on `fd`, kept for `continue`
    actions: Option<ActionTree>,
    /// groups switched off with `option currentaction decompile <group> off`
    disabled: std::collections::HashSet<String>,
    /// `load facts` was given
    facts: bool,
    /// `override flow <address> callreturn`, by function entry: the C++ keeps them in the
    /// function's `Override`, which `Funcdata::clear` leaves
    call_returns: std::collections::HashMap<u32, std::collections::BTreeSet<u64>>,
    /// functions `load function` or `load addr` selected: the C++ follows the flow there
    /// (`IfaceDecompData::followFlow`), so a flow override given later does not reach it
    flowed: std::collections::HashSet<u32>,
}

/// The language `load file` gives a program, as `BfdArchitecture::resolveArchitecture`
/// (bfd_arch.cc:88-110) picks it from the bfd target: a 32-bit PE is x86:LE:32:default:windows,
/// an ELF64 x86:LE:64:default:gcc. Returns the `.sla` (`GHIDRA_RS_SLA`, else the one built by
/// `build-sla.sh`; for x86-64, `x86-64.sla` next to it, whose `.pspec` `Sleigh::load` reads), the
/// text of the compiler spec next to it and the language description of x86.ldefs.
fn language(elf64: bool) -> Result<(Sleigh, String, &'static str), String> {
    let path =
        std::env::var_os("GHIDRA_RS_SLA").map(std::path::PathBuf::from).unwrap_or_else(|| Sleigh::sla_path("x86"));
    let (path, cspec, desc) = if elf64 {
        (path.with_file_name("x86-64.sla"), "x86-64-gcc.cspec", "Intel/AMD 64-bit x86")
    } else {
        (path, "x86win.cspec", "Intel/AMD 32-bit x86")
    };
    let cspec_path = path.with_file_name(cspec);
    let cspec = std::fs::read_to_string(&cspec_path).map_err(|e| format!("{}: {e}", cspec_path.display()))?;
    Sleigh::refuse_truncated(&path)?;
    Ok((Sleigh::load(&path)?, cspec, desc))
}

impl Console {
    /// Run (or resume) the actions on the current function and print where they stopped, as
    /// `IfcDecompile`/`IfcContinue` do. `set` is the outcome of setting the breakpoint. An error
    /// is reported and drops the function, and the script goes on (`abortFunction`).
    fn run_actions(&mut self, set: Result<(), LowlevelError>, out: &mut dyn Write) -> Result<(), String> {
        let io = |e: std::io::Error| e.to_string();
        let (Some(arch), Some(fd)) = (&self.arch, &mut self.fd) else { return Err("no function decompiled".into()) };
        let name = self.function.as_ref().map_or("", |f| f.1.as_str());
        let res = set.and_then(|()| match &mut self.actions {
            Some(t) => t.perform(fd, arch),
            None => Err(LowlevelError("no actions".into())),
        });
        match res {
            Ok(Outcome::Break(path)) => writeln!(out, "Break at {path}").map_err(io)?,
            Ok(Outcome::Complete) => writeln!(out, "Decompilation complete").map_err(io)?,
            Err(e) => {
                writeln!(out, "Low-level ERROR: {e}\nUnable to proceed with function: {name}").map_err(io)?;
                self.fd = None;
                self.actions = None;
                return Ok(());
            }
        }
        // the function's prototype lives on in the scope, as the C++ Funcdata's does
        let entry = fd.entry;
        let proto = fd.proto.clone();
        if let Some(f) = self.arch.as_mut().and_then(|a| a.functions.get_mut(&entry)) {
            f.proto = proto;
        }
        Ok(())
    }

    /// Run the commands of a script file; `Err` stops the script (an unported command, or
    /// `decompile`, which is not implemented yet).
    pub fn run_file(&mut self, path: &str, out: &mut dyn Write) -> Result<bool, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
        for line in text.lines() {
            if !self.command(line, out)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Run one command; `Ok(false)` after `quit`.
    pub fn command(&mut self, line: &str, out: &mut dyn Write) -> Result<bool, String> {
        let io = |e: std::io::Error| e.to_string();
        let words: Vec<&str> = line.split_whitespace().collect();
        if words.is_empty() || words[0].starts_with('#') {
            return Ok(true);
        }
        writeln!(out, "init> {line}").map_err(io)?;
        let addr = |w: Option<&&str>| -> Result<u32, String> {
            let w = w.ok_or(format!("{line}: missing address"))?;
            let a = w.split(':').next().unwrap_or("");
            u32::from_str_radix(a.trim_start_matches("0x"), 16).map_err(|e| format!("{line}: {e}"))
        };
        match words.as_slice() {
            ["quit"] => return Ok(false),
            ["source", file] => return self.run_file(file, out),
            ["load", "file", path] => {
                let data = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
                let image = if data.starts_with(b"\x7fELF") { Image::from_elf(&data) } else { Image::from_pe(&data) };
                let image = image.map_err(|e| format!("{path}: {e}"))?;
                let (sleigh, cspec, desc) = language(image.elf64)?;
                self.arch = Some(Arch::new(sleigh, image, &cspec).map_err(|e| e.to_string())?);
                writeln!(out, "{path} successfully loaded: {desc}").map_err(io)?;
            }
            // `load facts <file>` (stage S10, no console command of Ghidra's): the facts of a
            // Ghidra program replace the prelude; from here on names, data-types, prototypes
            // and memory properties are Java Ghidra's
            ["load", "facts", path] => {
                let arch = self.arch.as_mut().ok_or("load facts: no program loaded")?;
                let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
                arch.load_facts(text).map_err(|e| e.to_string())?;
                self.facts = true;
                writeln!(out, "{path} successfully loaded: facts").map_err(io)?;
            }
            ["load", "addr", rest @ ..] if self.arch.is_some() => {
                let a = addr(rest.first())?;
                // with facts, the function has the name the listing gives it
                let listed =
                    self.arch.as_ref().filter(|_| self.facts).and_then(|arch| arch.function_name(u64::from(a)));
                let name = rest
                    .get(1)
                    .map(|n| n.to_string())
                    .or(listed.map(String::from))
                    .unwrap_or_else(|| format!("func_0x{a:08x}"));
                writeln!(out, "Function {name}: 0x{a:08x}").map_err(io)?;
                // `IfcAddrrangeLoad`: the function joins the global scope (`addFunction`), where
                // constants and variables at its address find it. One already mapped there stays
                // (the C++ warns of the overlap and adds a second symbol; not ported)
                if let Some(arch) = self.arch.as_mut().filter(|arch| !arch.functions.contains_key(&u64::from(a))) {
                    arch.add_function(u64::from(a), name.clone());
                }
                self.flowed.insert(a);
                self.function = Some((a, name));
            }
            // `map function <addr> [<name>] [nocode]`: remembered for `load function`
            ["map", "function", a, rest @ ..] => {
                let arch = self.arch.as_mut().ok_or("map function: no program loaded")?;
                let a = addr(Some(a))?;
                let name = rest
                    .first()
                    .filter(|n| **n != "nocode")
                    .map_or_else(|| format!("func_0x{a:08x}"), |n| n.to_string());
                arch.add_function(u64::from(a), name.clone());
                // a name mapped twice finds the first (`findFirstByName`: the lowest dedup number)
                self.functions.entry(name.clone()).or_insert(a);
                if rest.contains(&"nocode") {
                    self.nocode.insert(a);
                }
                // `IfcMapfunction` makes it the current function (`dcp->fd`), not loaded yet
                self.function = Some((a, name));
            }
            ["load", "function", name] if self.arch.is_some() => {
                let a = *self.functions.get(*name).ok_or(format!("Unknown function name: {name}"))?;
                writeln!(out, "Function {name}: 0x{a:08x}").map_err(io)?;
                self.flowed.insert(a);
                self.function = Some((a, name.to_string()));
            }
            ["break", "start", action] if self.arch.is_some() => self.break_start = Some(action.to_string()),
            // `map externalref <slot> <refaddr> [<name>]`: the slot's symbol (read-only lookups skip it)
            ["map", "externalref", slot, refaddr, name @ ..] => {
                let arch = self.arch.as_mut().ok_or("map externalref: no program loaded")?;
                let slot = u64::from(addr(Some(slot))?);
                arch.add_externref(slot, u64::from(addr(Some(refaddr))?));
                if let Some(name) = name.first() {
                    arch.name_externref(slot, name.to_string());
                }
            }
            // `adjust vma <n>`: ghidra-rs's ELF image is already where Ghidra loads it
            ["adjust", "vma", n] => {
                let arch = self.arch.as_ref().ok_or("No load image present")?;
                let n = u64::from_str_radix(n.trim_start_matches("0x"), 16).map_err(|e| format!("{line}: {e}"))?;
                if n != u64::from(arch.image.elf_adjust) {
                    return Err(format!("{line}: not ported: an adjustment other than the image's own"));
                }
            }
            ["option", "readonly", on @ ("on" | "off")] => {
                let arch = self.arch.as_mut().ok_or("option: no program loaded")?;
                arch.readonly_propagate = *on == "on";
                let msg = if arch.readonly_propagate { "now propagate as constants" } else { "now do not propagate" };
                writeln!(out, "Read-only memory locations {msg}").map_err(io)?;
            }
            // `option currentaction decompile <group> on|off`: the groups of the root action
            ["option", "currentaction", "decompile", group, on @ ("on" | "off")] if self.arch.is_some() => {
                if *on == "off" {
                    self.disabled.insert(group.to_string());
                } else {
                    self.disabled.remove(*group);
                }
                writeln!(out, "Toggled {group} in action decompile").map_err(io)?;
            }
            // `option togglerule <rule> on|off` (its message precedes `load function`, which the
            // checks compare from, so none is printed)
            ["option", "togglerule", rule, on @ ("on" | "off")] if self.arch.is_some() => {
                let key = format!("rule:{rule}");
                if *on == "off" {
                    self.disabled.insert(key);
                } else {
                    self.disabled.remove(&key);
                }
            }
            // `option nanignore none|compare|all` (`OptionNanIgnore::apply`): `none` disables
            // rule `ignorenan`, the others enable it; `all` also sets `nan_ignore_all`
            ["option", "nanignore", mode @ ("none" | "compare" | "all")] => {
                let arch = self.arch.as_mut().ok_or("option: no program loaded")?;
                let old = (arch.nan_ignore_all, !self.disabled.contains("rule:ignorenan"));
                arch.nan_ignore_all = *mode == "all";
                if *mode == "none" {
                    self.disabled.insert("rule:ignorenan".to_string());
                } else {
                    self.disabled.remove("rule:ignorenan");
                }
                if old == (arch.nan_ignore_all, *mode != "none") {
                    writeln!(out, "NaN ignore configuration unchanged").map_err(io)?;
                } else {
                    writeln!(out, "Nan ignore configuration set to: {mode}").map_err(io)?;
                }
            }
            // options that only change the printed C, which ghidra-rs does not print yet: read
            // and ignored
            ["option", "nullprinting" | "inplaceops" | "conventionprinting" | "nocastprinting" | "maxlinewidth"
            | "indentincrement" | "commentindent" | "commentstyle" | "commentheader" | "commentinstruction"
            | "integerformat" | "braceformat" | "namespacestrategy" | "forloops", ..]
                if self.arch.is_some() => {}
            // every other option can change the ported analysis: not ported, so an error rather
            // than a silent difference
            ["option", ..] if self.arch.is_some() => return Err(format!("{line}: option not ported")),
            // `readonly <addr>:<size>`
            ["readonly", range] => {
                let arch = self.arch.as_mut().ok_or("readonly: no program loaded")?;
                let size =
                    range.split_once(':').and_then(|(_, s)| s.parse().ok()).ok_or(format!("{line}: bad size"))?;
                arch.add_readonly(u64::from(addr(Some(range))?), size);
                writeln!(out, "Successfully marked range as readonly").map_err(io)?;
            }
            // `IfcFlowOverride`: `override flow <address> branch|call|callreturn|return` on the
            // current function, the one `map function` made last (the datatests' order). Only
            // `callreturn` is ported, and only before the function is loaded: the C++ follows the
            // flow at `load function`, and an override given after it waits for a second `decompile`
            ["override", "flow", a, kind] => {
                let (f, _) = self.function.as_ref().ok_or("No function selected")?;
                if *kind != "callreturn" {
                    return Err(format!("{line}: not ported: a flow override other than callreturn"));
                }
                if self.flowed.contains(f) {
                    return Err(format!("{line}: not ported: a flow override on a function already loaded"));
                }
                self.call_returns.entry(*f).or_default().insert(u64::from(addr(Some(a))?));
                writeln!(out, "Successfully added flow override").map_err(io)?;
            }
            ["fixup", "apply", fixup, func] => {
                let arch = self.arch.as_mut().ok_or("fixup apply: no program loaded")?;
                let a = *self.functions.get(*func).ok_or(format!("Unknown function name: {func}"))?;
                arch.apply_fixup(fixup, u64::from(a)).map_err(|e| e.to_string())?;
                writeln!(out, "Successfully applied callfixup").map_err(io)?;
            }
            ["decompile"] => {
                self.arch.as_ref().ok_or("decompile: no program loaded")?;
                let (a, name) = self.function.as_ref().ok_or("decompile: no function selected")?;
                // `IfcDecompile`: a function mapped without code (an import) is not decompiled
                if self.nocode.contains(a) {
                    writeln!(out, "No code for {name}").map_err(io)?;
                    self.fd = None;
                    self.actions = None;
                    return Ok(true);
                }
                writeln!(out, "Decompiling {name}").map_err(io)?;
                // `DECOMP_SKIP_ACTIONS` (comma list): a check-only switch the reference patch reads
                // too; those actions do nothing on both sides. It is read on every decompile, so a
                // name that is not a single action of the tree (with every group on) is an error:
                // the C++ would skip a group of that name and the engines would disagree.
                let mut disabled = self.disabled.clone();
                if let Ok(skip) = std::env::var("DECOMP_SKIP_ACTIONS") {
                    let all = action::universal(&Default::default());
                    for s in skip.split(',').filter(|s| !s.is_empty()) {
                        all.has_leaf(s)
                            .then_some(())
                            .ok_or(format!("DECOMP_SKIP_ACTIONS: {s} is not an action of the decompile tree"))?;
                        disabled.insert(format!("action:{s}"));
                    }
                }
                let mut actions = action::universal(&disabled);
                let set = match &self.break_start {
                    Some(b) => actions.set_break_start(b),
                    None => Ok(()),
                };
                self.fd = Some(Funcdata::new(u64::from(*a)));
                if let (Some(fd), Some(arch)) = (&mut self.fd, &self.arch) {
                    fd.types = arch.types.clone();
                    fd.call_returns = self.call_returns.get(a).cloned().unwrap_or_default();
                    // the function symbol's prototype (`Funcdata::funcp`), locked by `parse line`
                    if let Some(p) = arch.function_proto(u64::from(*a)) {
                        fd.proto = p;
                    }
                }
                // with facts, the function starts from its record
                let set = match (&mut self.fd, &mut self.arch) {
                    (Some(fd), Some(arch)) => set.and_then(|()| arch.start_function(fd)),
                    _ => set,
                };
                self.actions = set.is_ok().then_some(actions);
                self.run_actions(set, out)?;
            }
            // `IfcContinue`: resume the actions after a breakpoint
            ["continue"] => {
                if self.fd.is_none() || self.actions.is_none() {
                    return Err("continue: no function being decompiled".into());
                }
                self.run_actions(Ok(()), out)?;
            }
            ["print", "raw"] => {
                let (Some(arch), Some(fd)) = (&self.arch, &mut self.fd) else {
                    return Err("print raw: no function decompiled".into());
                };
                // the C++ types a ram varnode from its global symbol when it is made; ghidra-rs before
                // a pass reads types, and none has run at a break with `typerecovery` off
                crate::decomp::symbol_types(fd, arch);
                write!(out, "{}", crate::decomp::print_raw(fd, arch).map_err(|e| e.to_string())?).map_err(io)?;
            }
            // `IfcParseLine`: a C declaration (types, or a locked function prototype)
            ["parse", "line", ..] => {
                let Some(arch) = &mut self.arch else { return Err("parse line: no architecture loaded".into()) };
                let text = line
                    .trim_start()
                    .strip_prefix("parse")
                    .map(str::trim_start)
                    .and_then(|s| s.strip_prefix("line"))
                    .unwrap_or("");
                let functions = &self.functions;
                crate::decomp::parse_line(arch, text, &|n| functions.get(n).map(|&a| u64::from(a)))
                    .map_err(|e| e.to_string())?;
            }
            // `IfcPrintMap` without a name: the local scope of the current function
            ["print", "map"] => {
                let (Some(arch), Some(fd)) = (&self.arch, &self.fd) else {
                    return Err("print map: no function selected".into());
                };
                write!(
                    out,
                    "{}",
                    crate::decomp::print_map(fd, arch, self.function.as_ref().map_or("", |f| f.1.as_str()))
                        .map_err(|e| e.to_string())?
                )
                .map_err(io)?;
            }
            // read by the corpora but needing later stages
            ["print", "tree", "block"] => {
                let Some(fd) = &self.fd else { return Err("No function selected".into()) };
                write!(out, "{}", crate::decomp::print_block_tree(fd).map_err(|e| e.to_string())?).map_err(io)?;
            }
            // `IfcPrintCStruct`: the first slice of the C printer (decomp/printc.rs)
            ["print", "C"] => {
                let (Some(arch), Some(fd)) = (&self.arch, &mut self.fd) else {
                    return Err("No function selected".into());
                };
                let name = self.function.as_ref().map_or("", |f| f.1.as_str());
                write!(out, "{}", crate::decomp::print_c(fd, arch, name).map_err(|e| e.to_string())?).map_err(io)?;
            }
            _ => return Err(format!("not implemented in ghidra-rs: {line}")),
        }
        Ok(true)
    }
}

pub mod datatest {
    //! Port of `testfunction.cc`: an upstream XML datatest is a `<binaryimage>`, a `<script>` of
    //! console commands and `<stringmatch>` checks, each a regular expression (one per line for
    //! a multi-line match) that must match between `min` and `max` times in the bulk output.

    use std::path::Path;

    pub struct Test {
        pub commands: Vec<String>,
        pub checks: Vec<Check>,
    }

    pub struct Check {
        pub name: String,
        pub min: usize,
        pub max: usize,
        pub patterns: Vec<regex_lite::Regex>,
    }

    /// std::regex (ECMAScript) reads `\<` and `\>` as the characters; regex-lite reads them as
    /// word boundaries.
    pub fn ecmascript(pat: &str) -> String {
        let mut s = String::new();
        let mut it = pat.chars();
        while let Some(c) = it.next() {
            match (c, it.clone().next()) {
                ('\\', Some(n @ ('<' | '>'))) => s.push(n),
                ('\\', Some(n)) => s.extend(['\\', n]),
                _ => {
                    s.push(c);
                    continue;
                }
            }
            it.next();
        }
        s
    }

    pub fn load(path: &Path) -> Result<Test, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let root = crate::xml::parse(&text).map_err(|e| format!("{}: {e}", path.display()))?;
        let script = root.find("script").ok_or("Did not see <script> tag in <decompilertest>")?;
        // stripNewlines: CR removed, LF made a space
        let commands = script.kids_named("com").map(|c| c.text.replace('\r', "").replace('\n', " ")).collect();
        let mut checks = Vec::new();
        for tag in root.kids_named("stringmatch") {
            let num = |n| tag.attr(n).and_then(|v| v.trim().parse().ok()).ok_or(format!("stringmatch: bad {n}"));
            let mut patterns = Vec::new();
            // one regex per line, leading blanks removed (FunctionTestProperty::restoreXml)
            for line in tag.text.split('\n') {
                let line = line.trim_start_matches([' ', '\t']);
                if !line.is_empty() {
                    patterns.push(regex_lite::Regex::new(&ecmascript(line)).map_err(|e| format!("{line}: {e}"))?);
                }
            }
            checks.push(Check {
                name: tag.attr("name").unwrap_or_default().to_string(),
                min: num("min")?,
                max: num("max")?,
                patterns,
            });
        }
        if checks.is_empty() {
            return Err("Did not see any <stringmatch> tags in <decompilertest>".into());
        }
        Ok(Test { commands, checks })
    }

    impl Check {
        /// FunctionTestProperty::processLine over every line, then endTest.
        pub fn passes(&self, output: &str) -> bool {
            let (mut count, mut patnum) = (0, 0);
            for line in output.split_terminator('\n') {
                if self.patterns[patnum].is_match(line) {
                    patnum += 1;
                    if patnum == self.patterns.len() {
                        count += 1;
                        patnum = 0;
                    }
                } else if patnum > 0 {
                    patnum = usize::from(self.patterns[0].is_match(line));
                }
            }
            self.min <= count && count <= self.max
        }
    }

    /// The bulk output of the test's script on the reference: `decomp_dbg` (by absolute path)
    /// loads the test file, sends bulk output to a file and runs the commands. `Err` when the
    /// console reports an error, as the C++ runner stops a test on one.
    pub fn run_reference(decomp_dbg: &Path, xml: &Path, test: &Test, work: &Path) -> Result<String, String> {
        let stem = xml.file_stem().unwrap_or_default().to_string_lossy();
        let (script, bulk) = (work.join(format!("{stem}.txt")), work.join(format!("{stem}.out")));
        let abs = std::fs::canonicalize(xml).map_err(|e| format!("{}: {e}", xml.display()))?;
        let mut s = format!("load test file {}\nopenfile write {}\n", abs.display(), bulk.display());
        // the C++ runner's script just ends; a `quit` here would skip `closefile`
        test.commands.iter().filter(|c| c.trim() != "quit").for_each(|c| s += &format!("{c}\n"));
        s += "closefile\nquit\n";
        std::fs::write(&script, s).map_err(|e| e.to_string())?;
        let out = std::process::Command::new(decomp_dbg)
            .arg("-i")
            .arg(&script)
            .stdin(std::process::Stdio::null())
            .output()
            .map_err(|e| format!("{}: {e}", decomp_dbg.display()))?;
        let stdout = String::from_utf8_lossy(&out.stdout);
        if let Some(e) =
            stdout.lines().find(|l| l.starts_with("Execution error") || l.starts_with("Command parsing error"))
        {
            return Err(e.to_string());
        }
        // no bulk output: decomp_dbg died early (e.g. "Could not discover root of Ghidra
        // installation" without SLEIGHHOME); show what it said
        std::fs::read_to_string(&bulk).map_err(|e| {
            match stdout.lines().find(|l| !l.is_empty() && !l.starts_with("init>")) {
                Some(l) => format!("decomp_dbg: {l}"),
                None => format!("{}: {e}", bulk.display()),
            }
        })
    }

    /// The bulk output on the Rust console. It cannot load a test's `<binaryimage>` yet.
    pub fn run_rust(_test: &Test) -> Result<String, String> {
        Err("not implemented in ghidra-rs: load test file".into())
    }
}
