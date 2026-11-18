use ghidra_rs::sleigh::Sleigh;
use object::{Architecture, Object, ObjectSection, ObjectSymbol};
use std::io::Write;
use std::path::PathBuf;

const USAGE: &str = "usage: ghidra-rs disasm <binary> [--func <symbol>|--addr <hex>] [--count N] [--pcode] [--sla <file>]
       ghidra-rs analyze <pe32> [--functions <csv>] [--gaps <csv>] [--abi-callers <register_abi.csv> <out.csv> [--data-pointers]]
                         [--decomp-prelude <out>] [--facts <out> [--protos <file>]] [--seeds <csv> | --functions-from <csv>]... [--store <file>] [--sla <file>]
       ghidra-rs edit <pe32> --store <file> [--new-store] [--seeds <csv> | --functions-from <csv>]... [--sla <file>] <command>
           commands: add-relocated-entries <securom_functions.csv>
                     define-table-functions <start> <end> [<start> <end>]...
                     recover-functions <audit.csv>
                     clear-false-noreturn <report.csv>
                     fold-slot-fragments <functions-original.csv> <slot-rewrites.csv> <report.csv>
                     create-function <addr> | remove-function <addr> | reflow <addr>
                     export-bindings <out.csv> --recover
                     audit-recovered-functions <recovery.csv> <audit.csv> --remove-empty
       ghidra-rs export <pe32> [--store <file>] [--facts <file>] [--seeds <csv> | --functions-from <csv>]... [--sla <file>] <command>
           commands: mod-hook-owners <sites.csv> <out.csv>
                     slot-owners <slots.csv> <out.csv>
                     boundaries <out.txt> <addr>...
                     call-contexts <target> <out.txt>
                     audit-recovered-functions <recovery.csv> <audit.csv>
                     library-evidence <markers.csv> <out.csv>      (needs --facts)
                     bindings <out.csv>
                     abi-candidates <out.csv> <out.txt> [<verified-c-dir>]   (needs --facts)
       ghidra-rs decompile -i <script>
       ghidra-rs datatest [--ref <decomp_dbg>] <test.xml|dir>...";

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() >= 2 && args[0] == "analyze" {
        return analyze(&args[1], &args[2..]);
    }
    if args.len() >= 2 && (args[0] == "edit" || args[0] == "export") {
        return edit(&args[1], &args[2..], args[0] == "edit");
    }
    if args.len() == 3 && args[0] == "decompile" && args[1] == "-i" {
        let stdout = std::io::stdout();
        let mut out = std::io::BufWriter::new(stdout.lock());
        let r = ghidra_rs::console::Console::default().run_file(&args[2], &mut out);
        out.flush().map_err(|e| e.to_string())?;
        return r.map(|_| ());
    }
    if args.len() >= 2 && args[0] == "datatest" {
        return datatest(&args[1..]);
    }
    if args.len() < 2 || args[0] != "disasm" {
        return Err(USAGE.into());
    }
    let path = &args[1];
    let (mut func, mut addr, mut count, mut pcode) = (None, None, None, false);
    let mut sla = std::env::var_os("GHIDRA_RS_SLA").map(PathBuf::from).unwrap_or_else(Sleigh::default_sla_path);
    let mut it = args[2..].iter();
    while let Some(flag) = it.next() {
        let mut val = || it.next().cloned().ok_or(format!("{flag} needs a value"));
        match flag.as_str() {
            "--func" => func = Some(val()?),
            "--addr" => {
                let v = val()?;
                addr =
                    Some(u64::from_str_radix(v.trim_start_matches("0x"), 16).map_err(|e| format!("--addr {v}: {e}"))?)
            }
            "--count" => count = Some(val()?.parse::<usize>().map_err(|e| format!("--count: {e}"))?),
            "--pcode" => pcode = true,
            "--sla" => sla = PathBuf::from(val()?),
            _ => return Err(USAGE.into()),
        }
    }

    let data = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
    let file = object::File::parse(&*data).map_err(|e| format!("{path}: {e}"))?;
    match file.architecture() {
        Architecture::X86_64 => {}
        Architecture::I386 if std::env::var_os("GHIDRA_RS_SLA").is_none() && !args.iter().any(|a| a == "--sla") => {
            sla = Sleigh::sla_path("x86")
        }
        Architecture::I386 => {}
        a => return Err(format!("{path}: only x86 and x86-64 are supported (found {a:?})")),
    }
    let (start, sym_end) = match (&func, addr) {
        (Some(name), _) => {
            let matches = |n: &[u8]| n == name.as_bytes() || n.strip_prefix(b"_") == Some(name.as_bytes());
            let sym = file
                .symbols()
                .chain(file.dynamic_symbols())
                .find(|s| s.address() != 0 && s.name_bytes().is_ok_and(matches))
                .map(|s| (s.address(), (s.size() > 0).then(|| s.address() + s.size())));
            // PE exports are not in the symbol tables
            let export = || file.exports().ok()?.into_iter().find(|x| matches(x.name())).map(|x| (x.address(), None));
            sym.or_else(export).ok_or(format!("{path}: symbol {name} not found"))?
        }
        (None, Some(a)) => (a, None),
        (None, None) => (file.entry(), None),
    };
    let count = count.unwrap_or(if sym_end.is_some() { usize::MAX } else { 20 });
    let sec = file
        .sections()
        .find(|s| s.address() <= start && start < s.address() + s.size())
        .ok_or(format!("{start:#x} is not in any section"))?;
    let bytes = sec.data().map_err(|e| e.to_string())?;
    let base = sec.address();
    let sec_end = base + bytes.len() as u64;
    let end = sym_end.unwrap_or(sec_end).min(sec_end);

    let sl = Sleigh::load(&sla)?;
    let mut p = sl.new_parse();
    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());
    let (mut a, mut n) = (start, 0);
    let mut line = String::new();
    while a < end && n < count {
        use std::fmt::Write as _;
        let rest = &bytes[(a - base) as usize..];
        line.clear();
        let _ = write!(line, "{a:016x}  ");
        match sl.disasm(&mut p, a, rest) {
            Ok(ins) if ins.len > 0 && a + ins.len as u64 <= sec_end => {
                for (i, b) in rest[..ins.len].iter().enumerate() {
                    let _ = write!(line, "{}{b:02x}", if i > 0 { " " } else { "" });
                }
                let pad = (3 * ins.len).max(31) - 3 * ins.len + 1;
                let _ = writeln!(line, "{:pad$}{} {}", "", ins.mnemonic, ins.body);
                if pcode {
                    match sl.pcode(&p) {
                        Ok(ops) => ops.iter().for_each(|op| {
                            let _ = writeln!(line, "    {}", sl.fmt_op(op));
                        }),
                        Err(e) => {
                            let _ = writeln!(line, "    <no p-code: {e}>");
                        }
                    }
                }
                a += ins.len as u64;
            }
            r => {
                let why = r.err().unwrap_or_else(|| "truncated".into());
                let _ = writeln!(line, "{:<30} (bad: {why})", format!("{:02x}", rest[0]));
                a += 1;
            }
        }
        if out.write_all(line.as_bytes()).is_err() {
            return Ok(()); // closed pipe
        }
        n += 1;
    }
    Ok(())
}

/// `datatest`: run upstream decompiler datatests (`console::datatest`) on the Rust console, or
/// with `--ref <decomp_dbg>` on the reference, and print `decomp_test_dbg`'s summary.
fn datatest(args: &[String]) -> Result<(), String> {
    use ghidra_rs::console::datatest;
    let (reference, paths) = match args {
        [flag, exe, rest @ ..] if flag == "--ref" => (Some(PathBuf::from(exe)), rest),
        _ => (None, args),
    };
    let mut files = Vec::new();
    for p in paths.iter().map(PathBuf::from) {
        if p.is_dir() {
            let mut v: Vec<_> = std::fs::read_dir(&p)
                .map_err(|e| format!("{}: {e}", p.display()))?
                .flatten()
                .map(|e| e.path())
                .collect();
            v.retain(|f| f.extension().is_some_and(|x| x == "xml"));
            v.sort();
            files.extend(v);
        } else {
            files.push(p);
        }
    }
    let work = std::env::temp_dir().join(format!("ghidra-rs-datatest-{}", std::process::id()));
    if reference.is_some() {
        std::fs::create_dir_all(&work).map_err(|e| format!("{}: {e}", work.display()))?;
    }
    let (mut applied, mut passed, mut failures) = (0, 0, Vec::new());
    for f in &files {
        let test = match datatest::load(f) {
            Ok(t) => t,
            Err(e) => {
                let msg = format!("Error parsing {}: {e}", f.display());
                println!("{msg}");
                failures.push(msg);
                continue;
            }
        };
        let out = match &reference {
            Some(exe) => datatest::run_reference(exe, f, &test, &work),
            None => datatest::run_rust(&test),
        };
        let out = match out {
            Ok(o) => o,
            Err(e) => {
                println!("Error: Did not apply tests in {}: {e}", f.display());
                failures.push(format!("Execution failed for {}", f.display()));
                continue;
            }
        };
        for c in &test.checks {
            applied += 1;
            if c.passes(&out) {
                passed += 1;
                println!("Success -- {}", c.name);
            } else {
                println!("FAIL -- {}", c.name);
                failures.push(c.name.clone());
            }
        }
    }
    let _ = std::fs::remove_dir_all(&work);
    println!("\nTotal tests applied = {applied}\nTotal passing tests = {passed}\n");
    if !failures.is_empty() {
        println!("Failures: ");
        failures.iter().take(10).for_each(|f| println!("  {f}"));
    }
    if passed < applied || !failures.is_empty() {
        return Err(format!("{} of {applied} checks failed, {} failures in all", applied - passed, failures.len()));
    }
    Ok(())
}

/// Function entries of a CSV: the first column of each 0x-prefixed line.
fn read_seeds(path: &str) -> Result<Vec<u32>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    let lines = text.lines().filter(|l| l.starts_with("0x"));
    let entry = |l: &str| {
        let a = l.split(',').next().unwrap_or("");
        u32::from_str_radix(&a[2..], 16).map_err(|e| format!("{path}: {a}: {e}"))
    };
    lines.map(entry).collect()
}

/// `edit`: runs one editing command on the analysis of a 32-bit PE with the project store laid
/// over it, and writes the store back. The five mercs2 editing scripts are `edits.rs`, the
/// editing options of two more are `exports.rs`.
/// `export` (`write` false): one of mercs2's read-only scripts (`exports.rs`) on the same
/// program, with the references of the code beyond the function bodies, as `--abi-callers`
/// reads them. The store is optional and is not written; when given, it must exist and have
/// been made on the same binary and seed set.
fn edit(path: &str, args: &[String], write: bool) -> Result<(), String> {
    use ghidra_rs::{analysis, edits, exports, store};
    let (mut file, mut seeds, mut exact, mut facts, mut new_store) = (None, Vec::new(), false, None, false);
    let mut sla = std::env::var_os("GHIDRA_RS_SLA").map(PathBuf::from).unwrap_or_else(|| Sleigh::sla_path("x86"));
    let mut it = args.iter();
    let mut command = None;
    while let Some(flag) = it.next() {
        if !flag.starts_with("--") {
            command = Some(flag.as_str());
            break;
        }
        if flag == "--new-store" {
            new_store = true;
            continue;
        }
        let val = it.next().cloned().ok_or(format!("{flag} needs a value"))?;
        match flag.as_str() {
            "--store" => file = Some(val),
            "--facts" if !write => facts = Some(val),
            "--sla" => sla = PathBuf::from(val),
            "--seeds" | "--functions-from" => {
                exact |= flag == "--functions-from";
                seeds.extend(read_seeds(&val)?);
            }
            _ => return Err(USAGE.into()),
        }
    }
    let rest: Vec<&str> = it.map(String::as_str).collect();
    let Some(command) = command else { return Err(USAGE.into()) };
    if write && file.is_none() {
        return Err(USAGE.into());
    }
    let data = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
    let img = analysis::Image::from_pe(&data).map_err(|e| format!("{path}: {e}"))?;
    let sl = Sleigh::load(&sla)?;
    let basis = store::Basis::new(&data, &seeds, exact);
    let exists = file.as_deref().is_some_and(|f| std::path::Path::new(f).exists());
    let before = match (file.as_deref(), exists, new_store) {
        (None, _, false) => store::Store::new(basis),
        (Some(f), true, false) => store::Store::load(f)?,
        (Some(_), false, true) if write => store::Store::new(basis),
        (Some(f), true, true) => return Err(format!("{f}: exists; --new-store makes a store only where none is")),
        (Some(f), false, false) => return Err(format!("{f}: no such store (--new-store makes one)")),
        _ => return Err(USAGE.into()),
    };
    before.check(basis).map_err(|e| format!("{}: {e}", file.as_deref().unwrap_or(path)))?;
    let mut base = analysis::Analysis::run(&img, &sl, &seeds, exact)?;
    // the scripts run after auto-analysis, its constants pass included, as `analyze --store`
    base.disassemble(&img, &sl, &[], true);
    let mut an = base.clone();
    before.apply(&mut an, &img, &sl)?;
    if !write {
        an.disassemble(&img, &sl, &[], true);
    }
    let mut p = store::Project::new(&img, &sl, an, before);
    let read = |f: &str| std::fs::read_to_string(f).map_err(|e| format!("{f}: {e}"));
    let report = |f: &str| std::fs::File::create(f).map(std::io::BufWriter::new).map_err(|e| format!("{f}: {e}"));
    let addr = |p: &store::Project, a: &str| {
        u32::from_str_radix(a.trim_start_matches("0x"), 16).map_err(|e| format!("{a}: {e}")).and_then(|a| {
            match p.an.funcs.contains(&a) || command == "create-function" {
                true => Ok(a),
                false => Err(format!("no function at 0x{a:08x}")),
            }
        })
    };
    // the commands of `exports.rs`: the read-only ones end here
    let exported = exports::run(&mut p, command, &rest, facts.as_deref(), write)?;
    if exported && !write {
        return Ok(());
    }
    match (command, rest.as_slice()) {
        _ if exported => {}
        _ if !write => return Err(format!("unknown export command or wrong arguments: {command}\n{USAGE}")),
        ("add-relocated-entries", [csv]) => edits::add_relocated_entries(&mut p, &read(csv)?)?,
        ("define-table-functions", ranges) if !ranges.is_empty() && ranges.len() % 2 == 0 => {
            let ranges: Vec<String> = ranges.iter().map(|r| r.to_string()).collect();
            edits::define_table_functions(&mut p, &ranges)?
        }
        ("recover-functions", [audit]) => edits::recover_functions(&mut p, &mut report(audit)?)?,
        ("clear-false-noreturn", [out]) => edits::clear_false_noreturn(&mut p, &mut report(out)?)?,
        ("fold-slot-fragments", [original, rewrites, out]) => {
            edits::fold_slot_fragments(&mut p, &read(original)?, &read(rewrites)?, &mut report(out)?)?
        }
        ("create-function", [a]) => {
            let a = addr(&p, a)?;
            if !(p.disassemble(a) && p.create_function(a)) {
                return Err(format!("no instruction decodes at 0x{a:08x}"));
            }
        }
        ("remove-function", [a]) => {
            let a = addr(&p, a)?;
            p.remove_function(a)
        }
        ("reflow", [a]) => {
            let a = addr(&p, a)?;
            p.reflow(a)
        }
        _ => return Err(format!("unknown edit command or wrong arguments: {command}\n{USAGE}")),
    }
    let Some(file) = file else { return Err(USAGE.into()) };
    let (funcs, text) = (p.an.funcs.len(), p.finish(base)?.to_string());
    // a whole new file in place of the old, never half of one
    let part = format!("{file}.part");
    std::fs::write(&part, &text).map_err(|e| format!("{part}: {e}"))?;
    std::fs::rename(&part, &file).map_err(|e| format!("{part} -> {file}: {e}"))?;
    println!("{file}: {} records, {funcs} functions", text.lines().count() - 1);
    Ok(())
}

/// `analyze`: Ghidra-style function discovery on a 32-bit PE, writing the files of the mercs2
/// scripts ExportFunctions.java (`--functions`) and ExportGaps.java (`--gaps`).
fn analyze(path: &str, args: &[String]) -> Result<(), String> {
    use ghidra_rs::{analysis, scripts};
    let (mut functions, mut gaps, mut seeds, mut exact, mut data_pointers) = (None, None, Vec::new(), false, false);
    let mut store = None;
    let mut abi: Option<(String, String)> = None;
    let mut prelude = None;
    let (mut facts, mut protos) = (None, None);
    let mut sla = std::env::var_os("GHIDRA_RS_SLA").map(PathBuf::from).unwrap_or_else(|| Sleigh::sla_path("x86"));
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        if flag == "--data-pointers" {
            data_pointers = true;
            continue;
        }
        let val = it.next().cloned().ok_or(format!("{flag} needs a value"))?;
        match flag.as_str() {
            "--functions" => functions = Some(val),
            "--gaps" => gaps = Some(val),
            "--decomp-prelude" => prelude = Some(val),
            "--facts" => facts = Some(val),
            "--protos" => protos = Some(val),
            "--store" => store = Some(val),
            "--sla" => sla = PathBuf::from(val),
            "--abi-callers" => {
                let out = it.next().cloned().ok_or("--abi-callers needs <register_abi.csv> <out.csv>")?;
                abi = Some((val, out));
            }
            // function entries: the first column of each 0x-prefixed line. --seeds adds them
            // to what discovery finds; --functions-from makes them the whole function set.
            "--seeds" | "--functions-from" => {
                exact |= flag == "--functions-from";
                seeds.extend(read_seeds(&val)?);
            }
            _ => return Err(USAGE.into()),
        }
    }
    // CheckAbiCallers reads config/securom_functions.csv next to register_abi.csv: the targets
    // (second column) are the function bodies the wrapper relocated, which the pipeline's
    // AddRelocatedEntries.java makes functions.
    let mut relocated = std::collections::HashSet::new();
    if let Some((csv, _)) = &abi {
        let p = std::path::Path::new(csv).with_file_name("securom_functions.csv");
        let text = std::fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()))?;
        for t in text.lines().skip(1).filter_map(|l| l.split(',').nth(1)) {
            let a = u32::from_str_radix(t.trim_start_matches("0x"), 16)
                .map_err(|e| format!("{}: {t}: {e}", p.display()))?;
            relocated.insert(a);
            seeds.push(a);
        }
    }
    let data = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
    let img = analysis::Image::from_pe(&data).map_err(|e| format!("{path}: {e}"))?;
    let sl = Sleigh::load(&sla)?;
    let t = std::time::Instant::now();
    // --facts: the functions discovery finds without the seeds are the ones Ghidra's
    // auto-analysis worked on; a seeded one stands for a function a script made afterwards
    let plain = match &facts {
        Some(_) if !seeds.is_empty() => {
            let a = analysis::Analysis::run(&img, &sl, &[], false)?;
            Some((a.funcs, a.callee_purges))
        }
        _ => None,
    };
    // a store made on another binary or seed set fails before any analysis
    let store = match store {
        Some(p) => {
            let s = ghidra_rs::store::Store::load(&p)?;
            s.check(ghidra_rs::store::Basis::new(&data, &seeds, exact)).map_err(|e| format!("{p}: {e}"))?;
            Some(s)
        }
        None => None,
    };
    let mut an = analysis::Analysis::run(&img, &sl, &seeds, exact)?;
    // the project's edits, before anything reads the analysis. Java's order: auto-analysis,
    // the constants pass included, then the scripts' edits; `edit` proves the store on the
    // same base
    if let Some(s) = &store {
        an.disassemble(&img, &sl, &[], true);
        s.apply(&mut an, &img, &sl)?;
    }
    if let Some((csv, _)) = &abi {
        // The script disassembles a contract entry analysis never reached (a vtable-only function).
        // Its references also come from code Ghidra decoded outside the function bodies: code
        // reached through code constants. Neither changes --functions or --gaps.
        let text = std::fs::read_to_string(csv).map_err(|e| format!("{csv}: {e}"))?;
        let entries: Vec<u32> = text
            .lines()
            .filter(|l| l.split(',').nth(2) != Some("extern"))
            .filter_map(|l| u32::from_str_radix(l.split(',').next()?.strip_prefix("0x")?, 16).ok())
            .filter(|a| !an.insns.contains_key(a))
            .collect();
        an.disassemble(&img, &sl, &entries, true);
    } else if facts.is_some() {
        // as above, with Create Address Tables: the pointers in data are facts too
        an.disassemble(&img, &sl, &[], true);
    } else if functions.is_some() {
        // Ghidra's ConstantPropagationAnalyzer, which `disassemble` above runs too: its
        // references and computed calls count in `callees`, `callers` and `data_refs`. It
        // leaves the bodies, so --gaps does not need it.
        an.propagate(&img, &sl);
    }
    eprintln!(
        "analyzed {} instructions, {} functions ({} imports) in {:.1}s",
        an.insns.len(),
        an.funcs.len(),
        img.imports.len(),
        t.elapsed().as_secs_f64()
    );
    let create = |p: &str| std::fs::File::create(p).map(std::io::BufWriter::new).map_err(|e| format!("{p}: {e}"));
    if functions.is_some() || prelude.is_some() || facts.is_some() {
        let t = std::time::Instant::now();
        let files = ghidra_rs::fid::default_files();
        let dbs = files.iter().map(|f| ghidra_rs::fid::FidDb::open(f)).collect::<Result<Vec<_>, _>>()?;
        let fid = ghidra_rs::fid::apply(&img, &an, &sl, &dbs, &scripts::demangle);
        eprintln!(
            "function id: {} functions named from {} databases in {:.1}s",
            fid.len(),
            dbs.len(),
            t.elapsed().as_secs_f64()
        );
        if let Some(p) = functions {
            let n = scripts::export_functions(&img, &an, &fid, &mut create(&p)?).map_err(|e| e.to_string())?;
            println!("exported {n} functions");
        }
        if let Some(p) = prelude {
            std::fs::write(&p, ghidra_rs::console::prelude(&img, &an, &fid)).map_err(|e| format!("{p}: {e}"))?;
            println!("wrote decompiler prelude {p}");
        }
        if let Some(p) = facts {
            let t = std::time::Instant::now();
            let protos = match &protos {
                Some(f) => {
                    let text = std::fs::read_to_string(f).map_err(|e| format!("{f}: {e}"))?;
                    Some(ghidra_rs::factsout::Protos::parse(&text).map_err(|e| format!("{f}: {e}"))?)
                }
                None => None,
            };
            let cspec_path = sla.with_file_name("x86win.cspec");
            let cspec = std::fs::read_to_string(&cspec_path).map_err(|e| format!("{}: {e}", cspec_path.display()))?;
            // the model of the ASCII Strings analyzer, in the Ghidra tree the .sla file is in
            let model_path =
                sla.ancestors().nth(5).map(|g| g.join("Features/Base/data/stringngrams/StringModel.sng")).ok_or_else(
                    || format!("{}: not in a Ghidra tree (the strings model is found from it)", sla.display()),
                )?;
            let model = std::fs::read_to_string(&model_path).map_err(|e| format!("{}: {e}", model_path.display()))?;
            let strings =
                ghidra_rs::strings::Model::parse(&model).map_err(|e| format!("{}: {e}", model_path.display()))?;
            // the purges of auto-analysis: of the run without seeds, where seeds were given
            let callee_purges = plain.as_ref().map_or_else(|| an.callee_purges.clone(), |p| p.1.clone());
            let mut w = create(&p)?;
            let inputs = ghidra_rs::factsout::Inputs {
                fid: &fid,
                protos: protos.as_ref(),
                analyzed: plain.as_ref().map(|p| &p.0),
                purges: &callee_purges,
                cspec: &cspec,
                strings: Some(&strings),
            };
            // the stack analysis goes by the purges Ghidra has at a call site
            let purges = ghidra_rs::factsout::call_purges(&img, &an, &inputs);
            let own = an.swap_call_purges(purges);
            let done = ghidra_rs::factsout::export(&img, &an, &sl, &inputs, &mut w).and_then(|()| w.flush());
            an.swap_call_purges(own);
            done.map_err(|e| format!("{p}: {e}"))?;
            println!("wrote facts {p}");
            eprintln!("facts in {:.1}s", t.elapsed().as_secs_f64());
        }
    }
    if let Some(p) = gaps {
        let (covered, total) = scripts::export_gaps(&img, &an, &mut create(&p)?).map_err(|e| e.to_string())?;
        println!("function coverage: {covered} / {total} .text bytes");
    }
    if let Some((csv, out)) = abi {
        let t = std::time::Instant::now();
        let text = std::fs::read_to_string(&csv).map_err(|e| format!("{csv}: {e}"))?;
        let mut ck = ghidra_rs::abi::Checker::new(&img, &an, &sl, relocated);
        ck.data_pointers = data_pointers;
        let mut w = create(&out)?;
        let threads = std::env::var("GHIDRA_RS_THREADS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or_else(|| std::thread::available_parallelism().map_or(1, |n| n.get()));
        let (total, outputs, inputs) = ck.run(&text, &mut w, threads)?;
        w.flush().map_err(|e| format!("{out}: {e}"))?;
        println!("Checked {total} references into {out}; {outputs} output findings; {inputs} input findings");
        eprintln!("abi check in {:.1}s", t.elapsed().as_secs_f64());
    }
    Ok(())
}
