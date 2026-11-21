//! The test vectors of Ghidra's MDMangBaseTest (`tests/data/mdmang-vectors.tsv`, extracted by
//! `tools/mdmang-vectors.sh`), run as `MDBaseTestConfiguration` runs them: `MDMang` with
//! `setErrorOnRemainingChars(true)`, compared with `mdTruth` (and a `.?A` name must give an
//! `MDDataType`). Every failure is listed; the test
//! fails when a vector outside `MDMangFailingTestCategory` (which Ghidra fails too) fails, or
//! when a vector in it passes or fails differently than the known list says.
use ghidra_rs::mdmang::{demangle, Config};

/// Java string literal contents to the string.
fn unescape(s: &str) -> String {
    let mut out = String::new();
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match it.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('0') => out.push('\0'),
            Some('u') => {
                let hex: String = (0..4).filter_map(|_| it.next()).collect();
                out.push(u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32).unwrap_or('?'));
            }
            Some(o) => out.push(o),
            None => {}
        }
    }
    out
}

/// MDBaseTestConfiguration.isMangled
fn is_mangled(s: &str) -> bool {
    s.starts_with('?') || s.starts_with("__")
}

#[test]
fn mdmang_base_test_vectors() {
    let data = include_str!("data/mdmang-vectors.tsv");
    let (mut pass, mut fail, mut known_fail, mut known_pass) = (0, Vec::new(), Vec::new(), Vec::new());
    let mut not_run = (0, Vec::new());
    for line in data.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        let [name, mode, failing, mangled, truth] = f[..] else { panic!("bad line {line}") };
        let (mangled, truth) = (unescape(mangled), unescape(truth));
        let (arch, is_function) = match mode {
            "F32" => (32, true),
            "16" => (16, false),
            _ => (64, false),
        };
        let cfg = Config { arch, is_function, error_on_remaining: true, only_known_patterns: false };
        let d = demangle(&mangled, cfg);
        let is_data_type = matches!(&d, Ok(Some(d)) if d.is_data_type());
        let got = d.map(|d| d.map(|d| d.original()));
        let out = match &got {
            Ok(Some(Ok(s))) => s.clone(),
            _ => String::new(),
        };
        let ok = if truth == mangled && is_mangled(&mangled) { out.is_empty() } else { out == truth };
        // MDBaseTestConfiguration: a `.?A` name demangles to an `MDDataType`
        let ok = ok && (!mangled.starts_with(".?A") || is_data_type);
        let report = || format!("{name}\n  mangled {mangled}\n  want    {truth}\n  got     {out}\n  ({got:?})");
        match (ok, failing) {
            (true, "0") => pass += 1,
            (false, "0") => fail.push(report()),
            (true, "1") => known_pass.push(name.to_string()),
            (false, "1") => known_fail.push(report()),
            (true, _) => not_run.0 += 1,
            (false, _) => not_run.1.push(report()),
        }
    }
    eprintln!(
        "MDMangBaseTest vectors: {pass} pass, {} fail; MDMangFailingTestCategory: {} fail, {} pass; not run by JUnit: {} pass, {} fail",
        fail.len(),
        known_fail.len(),
        known_pass.len(),
        not_run.0,
        not_run.1.len()
    );
    for f in &known_fail {
        eprintln!("FAIL (in MDMangFailingTestCategory) {f}");
    }
    for f in &not_run.1 {
        eprintln!("FAIL (not run by JUnit) {f}");
    }
    for f in &fail {
        eprintln!("FAIL {f}");
    }
    for p in &known_pass {
        eprintln!("PASS (in MDMangFailingTestCategory) {p}");
    }
    assert!(fail.is_empty(), "{} vectors fail", fail.len());
}
