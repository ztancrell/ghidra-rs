//! Writers that reproduce the output files of the mercs2 Ghidra scripts
//! (tools/ghidra/ExportFunctions.java and ExportGaps.java) from an `Analysis`.

use crate::analysis::{Analysis, Image};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Write;

// ExportFunctions.LUA_MARKERS
const LUA_MARKERS: [&str; 5] =
    ["attempt to %s a %s value", "attempt to compare two %s values", "attempt to compare %s with %s", "C stack overflow", "%s expected, got %s"];

fn quote(s: &str) -> String {
    format!("\"{}\"", s.replace('"', "\"\""))
}

/// MSVC qualified name `a@b@c@@` -> `c::b::a`, with simple template arguments.
/// Returns the name and the rest of the input.
fn qualified(s: &str) -> Option<(String, &str)> {
    let mut parts = Vec::new();
    let mut rest = s;
    while !rest.starts_with('@') {
        let (part, r) = component(rest)?;
        parts.push(part);
        rest = r;
    }
    parts.reverse();
    Some((parts.join("::"), &rest[1..]))
}

fn component(s: &str) -> Option<(String, &str)> {
    if let Some(t) = s.strip_prefix("?$") {
        let i = t.find('@')?;
        let mut args = Vec::new();
        let mut rest = &t[i + 1..];
        while !rest.starts_with('@') {
            let (arg, r) = template_arg(rest)?;
            args.push(arg);
            rest = r;
        }
        return Some((format!("{}<{}>", &t[..i], args.join(",")), &rest[1..]));
    }
    let i = s.find('@')?;
    Some((s[..i].to_string(), &s[i + 1..]))
}

fn template_arg(s: &str) -> Option<(String, &str)> {
    let simple = [("H", "int"), ("I", "unsigned_int"), ("M", "float"), ("N", "double"), ("_N", "bool"), ("D", "char"), ("E", "unsigned_char")];
    if let Some(r) = s.strip_prefix('V').or_else(|| s.strip_prefix('U')) {
        return qualified(r);
    }
    if let Some(r) = s.strip_prefix("$0") {
        // encoded integer: digit 0-9 means 1-10, else hex letters A-P ending in '@'
        let c = r.chars().next()?;
        if let Some(d) = c.to_digit(10) {
            return Some(((d + 1).to_string(), &r[1..]));
        }
        let end = r.find('@')?;
        let v = r[..end].bytes().fold(0u64, |v, b| v * 16 + (b - b'A') as u64);
        return Some((v.to_string(), &r[end + 1..]));
    }
    simple.iter().find(|(k, _)| s.starts_with(k)).map(|(k, v)| (v.to_string(), &s[k.len()..]))
}

/// Ghidra's qualified display name for an exported MSVC symbol (no parameters).
pub fn demangle(sym: &str) -> String {
    let Some(r) = sym.strip_prefix('?') else { return sym.to_string() };
    let special = |code: &str, r: &str| {
        let (cls, _) = qualified(r)?;
        let last = cls.rsplit("::").next().unwrap_or(&cls).to_string();
        let base = last.split('<').next().unwrap_or(&last).to_string();
        let name = match code {
            "0" => base,
            "1" => format!("~{base}"),
            "_F" => "`default_constructor_closure'".to_string(),
            _ => return None,
        };
        Some(format!("{cls}::{name}"))
    };
    let out = if let Some(x) = r.strip_prefix("?_F") {
        special("_F", x)
    } else if let Some(x) = r.strip_prefix("?0") {
        special("0", x)
    } else if let Some(x) = r.strip_prefix("?1") {
        special("1", x)
    } else {
        qualified(r).map(|(n, _)| n)
    };
    out.unwrap_or_else(|| sym.to_string())
}

/// RTTI: vftable address -> owning class, from MSVC CompleteObjectLocators.
pub fn vftables(img: &Image) -> BTreeMap<u32, String> {
    let mut out = BTreeMap::new();
    let Some(rdata) = img.section(".rdata") else { return out };
    for o in (0..rdata.data.len().saturating_sub(4)).step_by(4) {
        let slot = rdata.addr + o as u32;
        let Some(col) = img.read_u32(slot) else { continue };
        if img.block_of(col).map(|s| s.name.as_str()) != Some(".rdata") || img.read_u32(col) != Some(0) {
            continue;
        }
        let Some(td) = img.read_u32(col + 12) else { continue };
        let Some(sec) = img.block_of(td + 8) else { continue };
        let start = (td + 8 - sec.addr) as usize;
        let name: Vec<u8> = sec.data[start..].iter().take_while(|&&b| b != 0).take(512).copied().collect();
        let Ok(name) = std::str::from_utf8(&name) else { continue };
        let Some(mangled) = name.strip_prefix(".?AV").or_else(|| name.strip_prefix(".?AU")) else { continue };
        if let Some((cls, _)) = qualified(mangled) {
            out.insert(slot + 4, cls);
        }
    }
    out
}

/// The function whose body holds each instruction (lowest entry wins where bodies overlap).
fn containing(an: &Analysis) -> HashMap<u32, u32> {
    let mut m = HashMap::new();
    for (&f, body) in &an.bodies {
        for &a in body {
            m.entry(a).or_insert(f);
        }
    }
    m
}

/// tools/ghidra/ExportFunctions.java: one CSV row per function in .text.
pub fn export_functions(img: &Image, an: &Analysis, out: &mut dyn Write) -> std::io::Result<usize> {
    let owner = containing(an);
    // vftable slots -> class; a walk stops at the next labelled or referenced slot
    let tables = vftables(img);
    let mut labelled: HashSet<u32> = an.insns.values().flat_map(|i| i.refs.iter().copied()).collect();
    labelled.extend(tables.keys().flat_map(|&v| [v, v - 4]));
    let mut vclass: HashMap<u32, &str> = HashMap::new();
    for (&v, cls) in &tables {
        for i in 0..4096u32 {
            let slot = v + 4 * i;
            if i > 0 && labelled.contains(&slot) {
                break;
            }
            match img.read_u32(slot) {
                Some(t) if an.is_text(t) => {
                    vclass.entry(t).or_insert(cls);
                }
                _ => break,
            }
        }
    }
    // functions that reference a Lua runtime message (by the string's start address)
    let mut lua_strings = HashSet::new();
    for s in img.sections.iter().filter(|s| s.name != ".text") {
        for m in LUA_MARKERS {
            let hits = s.data.windows(m.len()).enumerate().filter(|(_, w)| *w == m.as_bytes());
            for (i, _) in hits {
                let start = s.data[..i].iter().rposition(|&b| b == 0).map_or(0, |z| z + 1);
                lua_strings.insert(s.addr + start as u32);
            }
        }
    }
    let mut lua = HashSet::new();
    let mut callers: HashMap<u32, HashSet<u32>> = HashMap::new();
    for (&a, i) in &an.insns {
        let Some(&f) = owner.get(&a) else { continue };
        if i.refs.iter().any(|r| lua_strings.contains(r)) {
            lua.insert(f);
        }
        if let Some(t) = an.call_target(i).filter(|t| an.funcs.contains(t)) {
            callers.entry(t).or_default().insert(f);
        }
    }
    let exports: HashMap<u32, &str> = img.exports.iter().map(|(a, n)| (*a, n.as_str())).collect();
    writeln!(out, "address,size,name,exported,fid,vtable_class,lua,callees,callers,data_refs")?;
    let mut n = 0;
    for (&f, body) in &an.bodies {
        if !an.is_text(f) {
            continue;
        }
        let callees: HashSet<u32> =
            body.iter().filter_map(|a| an.call_target(&an.insns[a])).filter(|t| an.funcs.contains(t)).collect();
        let data_refs: usize = body.iter().map(|a| an.insns[a].refs.len()).sum();
        let name = exports.get(&f).map(|s| demangle(s)).unwrap_or_default();
        writeln!(
            out,
            "0x{f:08x},{},{},{},0,{},{},{},{},{}",
            an.body_size(f),
            quote(&name),
            exports.contains_key(&f) as u8,
            quote(vclass.get(&f).copied().unwrap_or("")),
            lua.contains(&f) as u8,
            callees.len(),
            callers.get(&f).map_or(0, |c| c.len()),
            data_refs
        )?;
        n += 1;
    }
    Ok(n)
}

/// tools/ghidra/ExportGaps.java: .text ranges outside every function body.
/// Returns (covered, total) .text bytes.
pub fn export_gaps(img: &Image, an: &Analysis, out: &mut dyn Write) -> std::io::Result<(u64, u64)> {
    let total = (an.text_end - an.text_start) as usize;
    let mut covered = vec![false; total];
    for body in an.bodies.values() {
        for &a in body.iter().filter(|&&a| an.is_text(a)) {
            let o = (a - an.text_start) as usize;
            covered[o..o + an.insns[&a].len as usize].fill(true);
        }
    }
    let text = img.section(".text").expect(".text");
    writeln!(out, "address,size,class")?;
    let mut o = 0;
    while o < total {
        if covered[o] {
            o += 1;
            continue;
        }
        let start = o;
        while o < total && !covered[o] {
            o += 1;
        }
        let bytes = &text.data[start..o];
        let addr = an.text_start + start as u32;
        let class = if bytes.iter().all(|&b| b == 0 || b == 0x90 || b == 0xcc) {
            "padding"
        } else if addr % 4 == 0
            && bytes.len() % 4 == 0
            && bytes.chunks(4).all(|c| img.block_of(u32::from_le_bytes(c.try_into().unwrap())).is_some())
        {
            "table"
        } else {
            "unexamined"
        };
        writeln!(out, "0x{addr:08x},{},{class}", o - start)?;
    }
    let n = covered.iter().filter(|&&c| c).count() as u64;
    Ok((n, total as u64))
}
