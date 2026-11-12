//! Milestone 3, stage S0: the harness the decompiler stages are checked with (see
//! `docs/plans/m3-decompiler.md`). It has three parts:
//!
//! - [`prelude`]: the console commands both engines read before a function, generated from
//!   ghidra-rs's own analysis (functions, import slots, read-only `.rdata`);
//! - [`Console`]: the Rust side of Ghidra's console decompiler (`decomp_dbg`). It reads the same
//!   scripts and prints in the same format. There is no decompiler yet, so `decompile` fails
//!   loudly; every command the corpora do not need fails loudly too;
//! - [`datatest`]: a port of `testfunction.cc`, which runs the upstream XML datatests (corpus D)
//!   on either engine and checks their `<stringmatch>` patterns.

use crate::analysis::{Analysis, Image};
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
    loaded: bool,
    function: Option<(u32, String)>,
    /// functions from `map function`, by name
    functions: std::collections::HashMap<String, u32>,
}

impl Console {
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
                Image::from_pe(&data).map_err(|e| format!("{path}: {e}"))?;
                self.loaded = true;
                writeln!(out, "{path} successfully loaded: Intel/AMD 32-bit x86").map_err(io)?;
            }
            ["load", "addr", rest @ ..] if self.loaded => {
                let a = addr(rest.first())?;
                let name = rest.get(1).map_or_else(|| format!("func_0x{a:08x}"), |n| n.to_string());
                writeln!(out, "Function {name}: 0x{a:08x}").map_err(io)?;
                self.function = Some((a, name));
            }
            // `map function <addr> [<name>] [nocode]`: remembered for `load function`
            ["map", "function", a, rest @ ..] if self.loaded => {
                let a = addr(Some(a))?;
                let name = rest
                    .first()
                    .filter(|n| **n != "nocode")
                    .map_or_else(|| format!("func_0x{a:08x}"), |n| n.to_string());
                self.functions.insert(name, a);
            }
            ["load", "function", name] if self.loaded => {
                let a = *self.functions.get(*name).ok_or(format!("Unknown function name: {name}"))?;
                writeln!(out, "Function {name}: 0x{a:08x}").map_err(io)?;
                self.function = Some((a, name.to_string()));
            }
            // symbols and options only matter to the decompiler, which is not ported yet
            ["map", "externalref", ..] | ["option", ..] | ["break", "start", _] if self.loaded => {}
            ["readonly", rest @ ..] if self.loaded => {
                addr(rest.first())?;
                writeln!(out, "Successfully marked range as readonly").map_err(io)?;
            }
            ["decompile"] => {
                let (_, name) = self.function.as_ref().ok_or("decompile: no function selected")?;
                writeln!(out, "Decompiling {name}").map_err(io)?;
                return Err("decompile: not implemented in ghidra-rs yet (milestone 3, stage S1a)".into());
            }
            // read by the corpora but needing the decompiler (or, for `parse line`, the types of S6)
            ["continue"] | ["print", "raw" | "C"] | ["print", "tree", "block"] | ["parse", "line", ..] => {
                return Err(format!("{line}: not implemented in ghidra-rs yet (milestone 3, stage S1a and later)"));
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

    /// XML character data: entities and character references (`&#xc2;` is one byte, as in
    /// Ghidra's XML reader) decoded, `<![CDATA[...]]>` sections taken as they are.
    fn unescape(s: &str) -> String {
        let mut out = Vec::new();
        let mut rest = s;
        while let Some(i) = rest.find(['&', '<']) {
            out.extend_from_slice(&rest.as_bytes()[..i]);
            rest = &rest[i..];
            if let Some(cdata) = rest.strip_prefix("<![CDATA[") {
                let end = cdata.find("]]>").unwrap_or(cdata.len());
                out.extend_from_slice(&cdata.as_bytes()[..end]);
                rest = cdata.get(end + 3..).unwrap_or("");
                continue;
            }
            let ent = rest.find(';').map(|e| &rest[1..e]);
            let byte = match ent {
                Some("lt") => Some(b'<'),
                Some("gt") => Some(b'>'),
                Some("amp") => Some(b'&'),
                Some("quot") => Some(b'"'),
                Some("apos") => Some(b'\''),
                Some(e) if e.starts_with("#x") => u8::from_str_radix(&e[2..], 16).ok(),
                Some(e) if e.starts_with('#') => e[1..].parse().ok(),
                _ => None,
            };
            match (byte, ent) {
                (Some(b), Some(e)) => {
                    out.push(b);
                    rest = &rest[e.len() + 2..];
                }
                _ => {
                    out.push(rest.as_bytes()[0]);
                    rest = &rest[1..];
                }
            }
        }
        out.extend_from_slice(rest.as_bytes());
        String::from_utf8_lossy(&out).into_owned()
    }

    fn attr(tag: &str, name: &str) -> Option<String> {
        let i = tag.find(&format!(" {name}=\""))? + name.len() + 3;
        Some(unescape(&tag[i..i + tag[i..].find('"')?]))
    }

    /// The elements `<name ...>content</name>` in `xml`: (start tag, content).
    fn elements<'a>(xml: &'a str, name: &str) -> Vec<(&'a str, &'a str)> {
        let (open, close) = (format!("<{name}"), format!("</{name}>"));
        let mut v = Vec::new();
        let mut rest = xml;
        while let Some(i) = rest.find(&open) {
            rest = &rest[i..];
            let Some(gt) = rest.find('>') else { break };
            let Some(end) = rest.find(&close) else { break };
            v.push((&rest[..gt], &rest[gt + 1..end]));
            rest = &rest[end + close.len()..];
        }
        v
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
        let xml = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let script =
            elements(&xml, "script").into_iter().next().ok_or("Did not see <script> tag in <decompilertest>")?.1;
        // stripNewlines: CR removed, LF made a space
        let commands =
            elements(script, "com").iter().map(|(_, c)| unescape(c).replace('\r', "").replace('\n', " ")).collect();
        let mut checks = Vec::new();
        for (tag, content) in elements(&xml, "stringmatch") {
            let num = |n| attr(tag, n).and_then(|v| v.trim().parse().ok()).ok_or(format!("stringmatch: bad {n}"));
            let mut patterns = Vec::new();
            // one regex per line, leading blanks removed (FunctionTestProperty::restoreXml)
            for line in unescape(content).split('\n') {
                let line = line.trim_start_matches([' ', '\t']);
                if !line.is_empty() {
                    patterns.push(regex_lite::Regex::new(&ecmascript(line)).map_err(|e| format!("{line}: {e}"))?);
                }
            }
            checks.push(Check {
                name: attr(tag, "name").unwrap_or_default(),
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
