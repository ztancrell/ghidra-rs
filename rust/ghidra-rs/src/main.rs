use ghidra_rs::sleigh::Sleigh;
use object::{Architecture, Object, ObjectSection, ObjectSymbol};
use std::io::Write;
use std::path::PathBuf;

const USAGE: &str = "usage: ghidra-rs disasm <binary|psp-prx> [--func <symbol>|--addr <hex>] [--count N] [--pcode] [--sla <file>]
       ghidra-rs analyze <pe32|elf64|psp-prx> [--functions <csv>] [--gaps <csv>] [--purges <txt>] [--abi-callers <register_abi.csv> <out.csv> [--data-pointers]]
                         [--decomp-prelude <out>] [--facts <out> [--protos <file> | --gdt <archive>]] [--seeds <csv> | --functions-from <csv>]... [--store <file>] [--sla <file>]
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
       ghidra-rs prx-elf <psp-prx> <out.elf>        (the PRX as `analyze` loads it, relocated, as a plain ELF: the input of tools/mips-ref.sh)
       ghidra-rs gdt-protos <archive.gdt> <out>     (the prototype file of tools/ghidra-protos.sh, from the archive)
       ghidra-rs dwarf <elf> <out>                  (the DWARF import's data types and signatures, as tools/ghidra/DumpDwarf.java)
       ghidra-rs decompile -i <script>
       ghidra-rs datatest [--ref <decomp_dbg>] <test.xml|dir>...
       ghidra-rs gnu-demangle <names.txt>   (one name per line; the line demangler_gnu_v2_41 prints for each)
       ghidra-rs gnu-parse <tsv>     (mangled<TAB>native demangler text per line; the line format of tools/ghidra/GnuParseDump.java)";

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
    if args.len() == 3 && args[0] == "prx-elf" {
        let data = std::fs::read(&args[1]).map_err(|e| format!("{}: {e}", args[1]))?;
        let elf = prx_elf(&data).map_err(|e| format!("{}: {e}", args[1]))?;
        return std::fs::write(&args[2], elf).map_err(|e| format!("{}: {e}", args[2]));
    }
    if args.len() == 3 && args[0] == "gdt-protos" {
        let ar = ghidra_rs::gdt::Archive::open(std::path::Path::new(&args[1]))?;
        let text = ghidra_rs::gdt::protos::export(&ar)?;
        return std::fs::write(&args[2], text).map_err(|e| format!("{}: {e}", args[2]));
    }
    if args.len() == 3 && args[0] == "dwarf" {
        let data = std::fs::read(&args[1]).map_err(|e| format!("{}: {e}", args[1]))?;
        let t = std::time::Instant::now();
        let imp = ghidra_rs::dwarf::import(&data).map_err(|e| e.to_string())?;
        for w in imp.warnings.iter().take(20) {
            eprintln!("warning: {w}");
        }
        let text = ghidra_rs::dwarf::dump(&imp);
        let types = text.lines().filter(|l| l.starts_with("T ")).count();
        eprintln!(
            "{} units, {} DIEs, {} types, {} functions, {} warnings, {:.1} s",
            imp.units,
            imp.dies,
            types,
            imp.funcs.len(),
            imp.warnings.len(),
            t.elapsed().as_secs_f64()
        );
        return std::fs::write(&args[2], text).map_err(|e| format!("{}: {e}", args[2]));
    }
    if args.len() == 3 && args[0] == "decompile" && args[1] == "-i" {
        let stdout = std::io::stdout();
        let mut out = std::io::BufWriter::new(stdout.lock());
        let r = ghidra_rs::console::Console::default().run_file(&args[2], &mut out);
        out.flush().map_err(|e| e.to_string())?;
        return r.map(|_| ());
    }
    if args.len() == 2 && args[0] == "gnu-demangle" {
        return gnu_demangle(&args[1]);
    }
    if args.len() >= 2 && args[0] == "datatest" {
        return datatest(&args[1..]);
    }
    if args.len() == 2 && args[0] == "gnu-parse" {
        return gnu_parse(&args[1]);
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
    let own_sla = std::env::var_os("GHIDRA_RS_SLA").is_some() || args.iter().any(|a| a == "--sla");
    let mips = file.architecture() == Architecture::Mips;
    match file.architecture() {
        Architecture::X86_64 => {}
        Architecture::I386 if !own_sla => sla = Sleigh::sla_path("x86"),
        Architecture::I386 => {}
        // a PSP PRX is Allegrex code; any other MIPS file gets Ghidra's stock MIPS32
        Architecture::Mips if file.is_little_endian() && !own_sla && ghidra_rs::psp::is_prx(&data) => {
            sla = Sleigh::allegrex_sla_path()
        }
        Architecture::Mips if file.is_little_endian() && !own_sla => sla = Sleigh::mips32le_sla_path(),
        Architecture::Mips if file.is_little_endian() => {}
        a => return Err(format!("{path}: only x86, x86-64 and little-endian MIPS32 are supported (found {a:?})")),
    }
    // a PSP PRX is loaded at `psp::DEFAULT_BASE` with its relocations applied
    let prx = match ghidra_rs::psp::is_prx(&data) {
        true => Some(ghidra_rs::psp::load(&data, ghidra_rs::psp::DEFAULT_BASE).map_err(|e| format!("{path}: {e}"))?),
        false => None,
    };
    if let Some(prx) = &prx {
        eprintln!("PRX loaded at {:#010x}: {}", prx.base, prx.relocs.summary());
        match &prx.module {
            Ok(m) => {
                eprintln!("{}", m.summary());
                m.notes.iter().for_each(|n| eprintln!("  note: {n}"));
            }
            Err(e) => eprintln!("module info not read: {e}"),
        }
        if func.is_some() {
            return Err(format!(
                "{path}: --func is not supported on a PRX (its symbols are not relocated); use --addr"
            ));
        }
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
        (None, None) => (prx.as_ref().map_or(file.entry(), |p| p.entry as u64), None),
    };
    let count = count.unwrap_or(if sym_end.is_some() { usize::MAX } else { 20 });
    let no_section = || format!("{start:#x} is not in any section");
    let (bytes, base) = match &prx {
        Some(prx) => {
            let inside = |s: &&ghidra_rs::psp::Section| (s.addr as u64..s.addr as u64 + s.size as u64).contains(&start);
            let s = prx.sections.iter().find(inside).ok_or_else(no_section)?;
            let at = (s.addr - prx.base) as usize;
            (&prx.mem[at..at + s.size as usize], s.addr as u64)
        }
        None => {
            let sec = file
                .sections()
                .find(|s| s.address() <= start && start < s.address() + s.size())
                .ok_or_else(no_section)?;
            (sec.data().map_err(|e| e.to_string())?, sec.address())
        }
    };
    let sec_end = base + bytes.len() as u64;
    let end = sym_end.unwrap_or(sec_end).min(sec_end);

    // the MIPS32 language's processor spec is not named after its .sla (mips.ldefs); Allegrex's
    // is (`allegrex.pspec`)
    let sl = match mips && !sla.with_extension("pspec").exists() {
        true => Sleigh::load_with_pspec(&sla, Some(&sla.with_file_name("mips32.pspec")))?,
        false => Sleigh::load(&sla)?,
    };
    // a word that does not decode is skipped whole on MIPS32 and Allegrex (fixed 4-byte instructions)
    let bad_step = if mips { 4 } else { 1 };
    // the names of a PRX's import stubs and exported functions: a `<name>:` line at the address
    // and `  ; <name>` after a `j` or `jal` to it (no other file gets names in `disasm`)
    let names = prx.as_ref().and_then(|p| p.module.as_ref().ok()).map(|m| m.names()).unwrap_or_default();
    let mut p = sl.new_parse();
    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());
    let (mut a, mut n) = (start, 0);
    let mut line = String::new();
    while a < end && n < count {
        use std::fmt::Write as _;
        let rest = &bytes[(a - base) as usize..];
        line.clear();
        if let Some(name) = names.get(&(a as u32)) {
            let _ = writeln!(line, "{name}:");
        }
        let _ = write!(line, "{a:016x}  ");
        match sl.disasm(&mut p, a, rest) {
            Ok(ins) if ins.len > 0 && a + ins.len as u64 <= sec_end => {
                for (i, b) in rest[..ins.len].iter().enumerate() {
                    let _ = write!(line, "{}{b:02x}", if i > 0 { " " } else { "" });
                }
                let pad = (3 * ins.len).max(31) - 3 * ins.len + 1;
                let _ = write!(line, "{:pad$}{} {}", "", ins.mnemonic, ins.body);
                // lean: the target is read from the word (`j` and `jal`, opcodes 2 and 3), not
                // from p-code, so a call through a register gets no name
                let word = rest.get(..4).map_or(0, |w| u32::from_le_bytes(w.try_into().unwrap()));
                let target = (a as u32).wrapping_add(4) & 0xf000_0000 | (word & 0x03ff_ffff) << 2;
                match names.get(&target) {
                    Some(name) if word >> 27 == 1 => {
                        let _ = writeln!(line, "  ; {name}");
                    }
                    _ => line.push('\n'),
                }
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
                let skipped: Vec<String> = rest.iter().take(bad_step).map(|b| format!("{b:02x}")).collect();
                let _ = writeln!(line, "{:<30} (bad: {why})", skipped.join(" "));
                a += bad_step as u64;
            }
        }
        if out.write_all(line.as_bytes()).is_err() {
            return Ok(()); // closed pipe
        }
        n += 1;
    }
    Ok(())
}

/// `prx-elf`: a PSP PRX as `psp::load` lays it out at `psp::DEFAULT_BASE`, relocations applied,
/// written as an ELF32 executable (`ET_EXEC`) Java Ghidra's ELF loaders take: the
/// `PT_LOAD` segments and the loaded sections at their loaded addresses, with the file's names,
/// flags and `e_flags`, and the loaded entry point. Java cannot relocate a PRX
/// (`MIPS_ElfExtension.java`), so the reference of `analyze` on a PRX is Java on this file.
fn prx_elf(data: &[u8]) -> Result<Vec<u8>, String> {
    use object::read::elf::{FileHeader, ProgramHeader, SectionHeader};
    let prx = ghidra_rs::psp::load(data, ghidra_rs::psp::DEFAULT_BASE)?;
    let le = object::Endianness::Little;
    let head = object::elf::FileHeader32::<object::Endianness>::parse(data).map_err(|e| e.to_string())?;
    let sections = head.sections(le, data).map_err(|e| e.to_string())?;
    const DATA: u32 = 0x1000; // file offset of the image's first byte
    let loads: Vec<_> = head
        .program_headers(le, data)
        .map_err(|e| e.to_string())?
        .iter()
        .filter(|p| p.p_type(le) == object::elf::PT_LOAD)
        .collect();
    let file_end = loads.iter().map(|p| p.p_vaddr(le) + p.p_filesz(le)).max().unwrap_or(0);
    let mut out = vec![0u8; DATA as usize];
    out.extend(&prx.mem[..file_end as usize]);
    // section headers: the null one, the loaded sections, `.shstrtab`
    let mut names = vec![0u8];
    let mut heads: Vec<[u32; 10]> = vec![[0; 10]];
    for s in sections.iter().filter(|s| s.sh_flags(le) & object::elf::SHF_ALLOC != 0 && s.sh_size(le) > 0) {
        let name = sections.section_name(le, s).map_err(|e| e.to_string())?;
        let nobits = s.sh_type(le) == object::elf::SHT_NOBITS;
        let kind = if nobits { object::elf::SHT_NOBITS } else { object::elf::SHT_PROGBITS };
        let (addr, size) = (s.sh_addr(le), s.sh_size(le));
        if !nobits && addr + size > file_end {
            return Err(format!("section {} lies past the segments' file bytes", String::from_utf8_lossy(name)));
        }
        heads.push([names.len() as u32, kind, s.sh_flags(le), prx.base + addr, DATA + addr, size, 0, 0, 4, 0]);
        names.extend(name);
        names.push(0);
    }
    heads.push([names.len() as u32, object::elf::SHT_STRTAB, 0, 0, out.len() as u32, 0, 0, 0, 1, 0]);
    names.extend(b".shstrtab\0");
    heads.last_mut().unwrap()[5] = names.len() as u32;
    out.extend(&names);
    out.resize(out.len().next_multiple_of(4), 0);
    let shoff = out.len() as u32;
    out.extend(heads.iter().flatten().flat_map(|w| w.to_le_bytes()));
    let mut h = Vec::new();
    h.extend(b"\x7fELF\x01\x01\x01");
    h.resize(16, 0);
    for v in [object::elf::ET_EXEC, object::elf::EM_MIPS] {
        h.extend(v.to_le_bytes());
    }
    for v in [1, prx.entry, 52, shoff, head.e_flags(le)] {
        h.extend(v.to_le_bytes());
    }
    for v in [52u16, 32, loads.len() as u16, 40, heads.len() as u16, heads.len() as u16 - 1] {
        h.extend(v.to_le_bytes());
    }
    for p in &loads {
        let (addr, filesz) = (prx.base + p.p_vaddr(le), p.p_filesz(le));
        for v in [object::elf::PT_LOAD, DATA + p.p_vaddr(le), addr, addr, filesz, p.p_memsz(le), p.p_flags(le), 0x10] {
            h.extend(v.to_le_bytes());
        }
    }
    if h.len() > DATA as usize {
        return Err("too many program headers".into());
    }
    out[..h.len()].copy_from_slice(&h);
    Ok(out)
}

/// `gnu-demangle`: each line of the file through the GNU demangler's native half
/// (`gnudemangle::native_demangle`, what Ghidra's `demangler_gnu_v2_41` prints for it), one line
/// out per line in; a case not ported prints `ERR <reason>`. Runs on a thread with a large stack
/// (the demangler recurses as deep as the C does).
fn gnu_demangle(path: &str) -> Result<(), String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    let job = std::thread::Builder::new().stack_size(1 << 30).spawn(move || {
        let mut out = String::new();
        for line in text.lines() {
            match ghidra_rs::gnudemangle::native_demangle(line) {
                Ok(s) => out.push_str(&s),
                Err(e) => out.push_str(&format!("ERR {e}")),
            }
            out.push('\n');
        }
        out
    });
    let out = job.map_err(|e| e.to_string())?.join().map_err(|_| "the demangler thread panicked".to_string())?;
    std::io::stdout().write_all(out.as_bytes()).map_err(|e| e.to_string())
}

/// `gnu-parse`: [`ghidra_rs::gnuparse::dump_line`] of each `mangled<TAB>text` line.
fn gnu_parse(path: &str) -> Result<(), String> {
    let tsv = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());
    for line in tsv.lines() {
        let (mangled, text) = line.split_once('\t').unwrap_or((line, ""));
        writeln!(out, "{}", ghidra_rs::gnuparse::dump_line(mangled, text)).map_err(|e| e.to_string())?;
    }
    out.flush().map_err(|e| e.to_string())
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
    base.warnings.iter().for_each(|w| eprintln!("warning: {w}"));
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

/// `analyze`: Ghidra-style function discovery on a 32-bit PE or an ELF x86-64, writing the files of the mercs2
/// scripts ExportFunctions.java (`--functions`) and ExportGaps.java (`--gaps`).
fn analyze(path: &str, args: &[String]) -> Result<(), String> {
    use ghidra_rs::{analysis, scripts};
    let (mut functions, mut gaps, mut seeds, mut exact, mut data_pointers) = (None, None, Vec::new(), false, false);
    let mut store = None;
    let mut abi: Option<(String, String)> = None;
    let mut prelude = None;
    let mut purges = None;
    let (mut facts, mut protos, mut gdt) = (None, None, None);
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
            "--purges" => purges = Some(val),
            "--decomp-prelude" => prelude = Some(val),
            "--facts" => facts = Some(val),
            "--protos" => protos = Some(val),
            "--gdt" => gdt = Some(val),
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
    let img = if ghidra_rs::psp::is_prx(&data) {
        // Allegrex:LE:32:default, as `disasm` takes a PRX; `--sla` is taken as given
        if !args.iter().any(|a| a == "--sla") && std::env::var_os("GHIDRA_RS_SLA").is_none() {
            sla = Sleigh::allegrex_sla_path();
        }
        if abi.is_some() || store.is_some() || facts.is_some() || prelude.is_some() {
            return Err(format!(
                "{path}: --abi-callers, --store, --facts and --decomp-prelude do not take a PSP PRX (MIPS-4)"
            ));
        }
        analysis::Image::from_prx(&data).map_err(|e| format!("{path}: {e}"))?
    } else if data.starts_with(b"\x7fELF") {
        let img = analysis::Image::from_elf(&data).map_err(|e| format!("{path}: {e}"))?;
        // x86:LE:64:default, the gcc compiler spec: `x86-64.sla`, next to a `GHIDRA_RS_SLA` that
        // names x86's (as the console's `load file` takes it); `--sla` is taken as given
        if !args.iter().any(|a| a == "--sla") {
            sla = match std::env::var_os("GHIDRA_RS_SLA") {
                Some(p) => PathBuf::from(p).with_file_name("x86-64.sla"),
                None => Sleigh::sla_path("x86-64"),
            };
        }
        if abi.is_some() || store.is_some() {
            return Err(format!("{path}: --abi-callers and --store take a 32-bit PE only"));
        }
        img
    } else {
        analysis::Image::from_pe(&data).map_err(|e| format!("{path}: {e}"))?
    };
    // ELF with --facts: the call sites of the GCC exception tables (GccExceptionAnalyzer)
    let eh_sites = match facts.is_some() && img.elf64 {
        true => ghidra_rs::gccexcept::call_sites(&img),
        false => Ok(Vec::new()),
    };
    if let Err(e) = &eh_sites {
        eprintln!("warning: GCC exception tables: {e}; every function's comments are not derived");
    }
    // ELF with --facts: the functions the DWARF importer gives a signature (Java's DWARF
    // analyzer; DWARFAnalyzer.canAnalyze: a program with DWARF sections), at the image base
    // Ghidra gives a PIE linked at 0. Imported before the analysis, so its memory is freed
    // first: on Hatred both at once did not fit in the desktop's memory.
    let has_dwarf = facts.is_some() && img.elf64 && {
        use object::Object;
        object::File::parse(&*data).is_ok_and(|f| f.section_by_name(".debug_info").is_some())
    };
    type DwarfFacts = (
        std::collections::BTreeMap<u32, ghidra_rs::factsout::DwarfFunc>,
        std::collections::HashMap<String, Result<String, String>>,
        Vec<(u64, Option<String>)>,
    );
    let (dwarf, dwarf_types, dwarf_pre): DwarfFacts = if has_dwarf {
        let imp = ghidra_rs::dwarf::import(&data).map_err(|e| format!("{path}: DWARF: {e}"))?;
        // the prototypes and data types as Java's decompiler gets them, before the import is freed
        let (mut protos, types) = ghidra_rs::dwarf::pcode::facts(&imp, &ghidra_rs::factsout::core_ids64());
        let funcs = imp
            .funcs
            .into_iter()
            .filter_map(|f| {
                // the import adds the image base adjustment itself (programBaseAddressFixup)
                let a = u32::try_from(f.addr).ok()?;
                let facts = protos.remove(&f.addr)?;
                Some((
                    a,
                    ghidra_rs::factsout::DwarfFunc { name: f.name, plate: f.plate, facts, locals: f.locals_underived },
                ))
            })
            .collect();
        (funcs, types, imp.unresolved)
    } else {
        Default::default()
    };
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
    an.warnings.iter().for_each(|w| eprintln!("warning: {w}"));
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
        // the databases are x86:LE:32's; Function ID on x86-64 is not ported (warned)
        let no_fid = img.elf64 || img.mips;
        let files = if no_fid { Vec::new() } else { ghidra_rs::fid::default_files() };
        let dbs = files.iter().map(|f| ghidra_rs::fid::FidDb::open(f)).collect::<Result<Vec<_>, _>>()?;
        let fid = if no_fid { Default::default() } else { ghidra_rs::fid::apply(&img, &an, &sl, &dbs)? };
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
            let text = match (&protos, &gdt) {
                (Some(_), Some(_)) => return Err("--protos and --gdt: give one".into()),
                (Some(f), None) => Some((f, std::fs::read_to_string(f).map_err(|e| format!("{f}: {e}"))?)),
                // the archive read in place gives the same prototype file
                (None, Some(f)) => {
                    Some((f, ghidra_rs::gdt::protos::export(&ghidra_rs::gdt::Archive::open(f.as_ref())?)?))
                }
                (None, None) => None,
            };
            let protos = match text {
                Some((f, text)) => Some(ghidra_rs::factsout::Protos::parse(&text).map_err(|e| format!("{f}: {e}"))?),
                None => None,
            };
            let cspec_path = sla.with_file_name(if img.elf64 { "x86-64-gcc.cspec" } else { "x86win.cspec" });
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
            // ELF: the function names of the archive Java's Apply Data Archives analyzer applies
            // (DataTypeArchiveUtility.getArchiveList: `generic_clib_64`), from the Ghidra tree
            let archive = if img.elf64 {
                let path = sla
                    .ancestors()
                    .nth(5)
                    .map(|g| g.join("Features/Base/data/typeinfo/generic/generic_clib_64.gdt"))
                    .ok_or_else(|| {
                        format!("{}: not in a Ghidra tree (the data-type archive is found from it)", sla.display())
                    })?;
                let ar = ghidra_rs::gdt::Archive::open(&path).map_err(|e| format!("{}: {e}", path.display()))?;
                let names: Result<std::collections::HashSet<String>, _> =
                    ar.function_defs.iter().map(|&f| ar.get(f).map(|t| t.name.clone())).collect();
                // and the prototypes of its definitions, as applied to an x86-64 gcc program
                let text = ghidra_rs::gdt::protos::export_elf64(&ar).map_err(|e| format!("{}: {e}", path.display()))?;
                let applied =
                    ghidra_rs::factsout::Protos::parse(&text).map_err(|e| format!("{}: {e}", path.display()))?;
                Some((names.map_err(|e| format!("{}: {e}", path.display()))?, applied))
            } else {
                None
            };
            let inputs = ghidra_rs::factsout::Inputs {
                fid: &fid,
                protos: archive.as_ref().map(|a| &a.1).or(protos.as_ref()),
                analyzed: plain.as_ref().map(|p| &p.0),
                purges: &callee_purges,
                cspec: &cspec,
                strings: Some(&strings),
                dwarf: &dwarf,
                dwarf_types: &dwarf_types,
                archive: archive.as_ref().map(|a| &a.0),
                eh_sites: eh_sites.as_ref().ok().map(|v| &v[..]),
                dwarf_pre: &dwarf_pre,
            };
            // the stack analysis goes by the purges Ghidra has at a call site
            let purges = ghidra_rs::factsout::call_purges(&img, &an, &inputs);
            // and runs the call fixups the Call-Fixup Installer set
            let fixups = ghidra_rs::factsout::call_fixups(&img, &an, &sl, &inputs).map_err(|e| format!("{p}: {e}"))?;
            let own = an.swap_call_purges(purges);
            let own_fixups = an.swap_call_fixups(fixups);
            let done = ghidra_rs::factsout::export(&img, &an, &sl, &inputs, &mut w).and_then(|()| w.flush());
            an.swap_call_fixups(own_fixups);
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
    if let Some(p) = purges {
        let mut w = create(&p)?;
        let n = scripts::dump_purges(&img, &an, &mut w)
            .and_then(|n| w.flush().map(|()| n))
            .map_err(|e| format!("{p}: {e}"))?;
        println!("dumped {n} functions");
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
