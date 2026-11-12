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
/// - `map function` for every function, with its FID name or export name when it has one.
pub fn prelude(img: &Image, an: &Analysis, fid: &BTreeMap<u32, crate::fid::Applied>) -> String {
    let mut s = String::from("option readonly on\n");
    for sec in img.sections.iter().filter(|s| s.name == ".rdata") {
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
    for &f in &an.funcs {
        let name = fid.get(&f).map(|a| a.name.as_str()).or_else(|| exports.get(&f).copied());
        let _ = writeln!(s, "map function 0x{f:08x}{}", name.map(|n| format!(" {}", token(n))).unwrap_or_default());
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
}

/// The `.sla` for a 32-bit PE (`GHIDRA_RS_SLA`, else x86.sla built by `build-sla.sh`) and the
/// text of the Windows compiler spec `x86win.cspec` next to it, as the console's
/// `x86:LE:32:default:windows` language reads them.
fn x86_windows() -> Result<(Sleigh, String), String> {
    let path =
        std::env::var_os("GHIDRA_RS_SLA").map(std::path::PathBuf::from).unwrap_or_else(|| Sleigh::sla_path("x86"));
    let cspec_path = path.with_file_name("x86win.cspec");
    let cspec = std::fs::read_to_string(&cspec_path).map_err(|e| format!("{}: {e}", cspec_path.display()))?;
    Ok((Sleigh::load(&path)?, cspec))
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
                let image = Image::from_pe(&data).map_err(|e| format!("{path}: {e}"))?;
                let (sleigh, cspec) = x86_windows()?;
                self.arch = Some(Arch::new(sleigh, image, &cspec).map_err(|e| e.to_string())?);
                writeln!(out, "{path} successfully loaded: Intel/AMD 32-bit x86").map_err(io)?;
            }
            ["load", "addr", rest @ ..] if self.arch.is_some() => {
                let a = addr(rest.first())?;
                let name = rest.get(1).map_or_else(|| format!("func_0x{a:08x}"), |n| n.to_string());
                writeln!(out, "Function {name}: 0x{a:08x}").map_err(io)?;
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
                self.functions.entry(name).or_insert(a);
                if rest.contains(&"nocode") {
                    self.nocode.insert(a);
                }
            }
            ["load", "function", name] if self.arch.is_some() => {
                let a = *self.functions.get(*name).ok_or(format!("Unknown function name: {name}"))?;
                writeln!(out, "Function {name}: 0x{a:08x}").map_err(io)?;
                self.function = Some((a, name.to_string()));
            }
            ["break", "start", action] if self.arch.is_some() => self.break_start = Some(action.to_string()),
            // `map externalref <slot> <refaddr> [<name>]`: the slot's symbol (read-only lookups skip it)
            ["map", "externalref", slot, refaddr, ..] => {
                let arch = self.arch.as_mut().ok_or("map externalref: no program loaded")?;
                arch.add_externref(u64::from(addr(Some(slot))?), u64::from(addr(Some(refaddr))?));
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
            // the other options (`togglerule`: no rule is ported) are read and ignored
            ["option", ..] if self.arch.is_some() => {}
            // `readonly <addr>:<size>`
            ["readonly", range] => {
                let arch = self.arch.as_mut().ok_or("readonly: no program loaded")?;
                let size =
                    range.split_once(':').and_then(|(_, s)| s.parse().ok()).ok_or(format!("{line}: bad size"))?;
                arch.add_readonly(u64::from(addr(Some(range))?), size);
                writeln!(out, "Successfully marked range as readonly").map_err(io)?;
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
                let mut actions = action::universal(&self.disabled);
                let set = match &self.break_start {
                    Some(b) => actions.set_break_start(b),
                    None => Ok(()),
                };
                self.fd = Some(Funcdata::new(u64::from(*a)));
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
                let (Some(arch), Some(fd)) = (&self.arch, &self.fd) else {
                    return Err("print raw: no function decompiled".into());
                };
                write!(out, "{}", crate::decomp::print_raw(fd, arch).map_err(|e| e.to_string())?).map_err(io)?;
            }
            // read by the corpora but needing later stages (`parse line`: the types of S6)
            ["print", "C"] | ["print", "tree", "block"] | ["parse", "line", ..] => {
                return Err(format!("{line}: not implemented in ghidra-rs yet (milestone 3, later stages)"));
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
