use ghidra_rs::sleigh::Sleigh;
use object::{Architecture, Object, ObjectSection, ObjectSymbol};
use std::io::Write;
use std::path::PathBuf;

const USAGE: &str = "usage: ghidra-rs disasm <binary> [--func <symbol>|--addr <hex>] [--count N] [--pcode] [--sla <file>]
       ghidra-rs analyze <pe32> [--functions <csv>] [--gaps <csv>] [--seeds <csv> | --functions-from <csv>]... [--sla <file>]";

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
                addr = Some(u64::from_str_radix(v.trim_start_matches("0x"), 16).map_err(|e| format!("--addr {v}: {e}"))?)
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

/// `analyze`: Ghidra-style function discovery on a 32-bit PE, writing the files of the mercs2
/// scripts ExportFunctions.java (`--functions`) and ExportGaps.java (`--gaps`).
fn analyze(path: &str, args: &[String]) -> Result<(), String> {
    use ghidra_rs::{analysis, scripts};
    let (mut functions, mut gaps, mut seeds, mut exact) = (None, None, Vec::new(), false);
    let mut sla = std::env::var_os("GHIDRA_RS_SLA").map(PathBuf::from).unwrap_or_else(|| Sleigh::sla_path("x86"));
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let val = it.next().cloned().ok_or(format!("{flag} needs a value"))?;
        match flag.as_str() {
            "--functions" => functions = Some(val),
            "--gaps" => gaps = Some(val),
            "--sla" => sla = PathBuf::from(val),
            // function entries: the first column of each 0x-prefixed line. --seeds adds them
            // to what discovery finds; --functions-from makes them the whole function set.
            "--seeds" | "--functions-from" => {
                exact |= flag == "--functions-from";
                let text = std::fs::read_to_string(&val).map_err(|e| format!("{val}: {e}"))?;
                for line in text.lines().filter(|l| l.starts_with("0x")) {
                    let a = line.split(',').next().unwrap_or("");
                    seeds.push(u32::from_str_radix(&a[2..], 16).map_err(|e| format!("{val}: {a}: {e}"))?);
                }
            }
            _ => return Err(USAGE.into()),
        }
    }
    let data = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
    let img = analysis::Image::from_pe(&data).map_err(|e| format!("{path}: {e}"))?;
    let sl = Sleigh::load(&sla)?;
    let t = std::time::Instant::now();
    let an = analysis::Analysis::run(&img, &sl, &seeds, exact)?;
    eprintln!(
        "analyzed {} instructions, {} functions ({} imports) in {:.1}s",
        an.insns.len(),
        an.funcs.len(),
        img.imports.len(),
        t.elapsed().as_secs_f64()
    );
    let create = |p: &str| std::fs::File::create(p).map(std::io::BufWriter::new).map_err(|e| format!("{p}: {e}"));
    if let Some(p) = functions {
        let n = scripts::export_functions(&img, &an, &mut create(&p)?).map_err(|e| e.to_string())?;
        println!("exported {n} functions");
    }
    if let Some(p) = gaps {
        let (covered, total) = scripts::export_gaps(&img, &an, &mut create(&p)?).map_err(|e| e.to_string())?;
        println!("function coverage: {covered} / {total} .text bytes");
    }
    Ok(())
}
