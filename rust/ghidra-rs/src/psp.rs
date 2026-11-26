//! PSP PRX loading: an ELF32 little-endian MIPS file of type `ET_MIPS_PSP_PRX` (0xffa0), its
//! `PT_LOAD` segments laid out at their link addresses and the PSP relocation sections
//! (`SHT_MIPS_PSPREL`, 0x700000a0) applied for a load base.
//!
//! Ghidra itself names these constants but does not apply the relocations
//! (`MIPS_ElfExtension.java`: "PSP relocation table ... relocations not supported"), so there is
//! no Ghidra code to port. The entry format and the rules per type follow PPSSPP's
//! `ElfReader::LoadRelocations` (Core/ELF/ElfReader.cpp), read 2026-11-26: an `Elf32_Rel` whose
//! `r_info` holds the type (bits 0-7), the program header the offset is relative to (bits 8-15)
//! and the program header whose load address is added (bits 16-23). The words in the file are
//! relative to that second segment's start (checked on SOCOM FTB's BOOT.BIN: every one lies
//! inside its segment).
//!
//! The module's own tables are read from the relocated image ([`parse_module`]): `sceModuleInfo`,
//! the import stub table it points at (`.lib.stub`) and the export table (`.lib.ent`). The
//! layouts follow PPSSPP's `PspModuleInfo` (Core/HLE/sceKernelModule.h), `PspLibStubEntry` and
//! `PspLibEntEntry` and the loops that walk them in `KernelImportModuleFuncs` and
//! `__KernelLoadELFFromPtr` (Core/HLE/sceKernelModule.cpp, commit c771d85441, read 2026-11-26),
//! and pspsdk's `_sceModuleInfo` (src/user/pspmoduleinfo.h). An import or export is identified
//! by a 32-bit NID; [`nid_name`] names the ones pspsdk's import files list, and one found by
//! SHA-1 search.
use std::collections::BTreeMap;

/// Where a PRX is loaded when nothing else says so: the usual address of a game's main module
/// (the ghidra-allegrex loader's README recommends it "to match the usual address where games
/// are loaded"; PPSSPP allocates from user memory, which starts at 0x08800000).
pub const DEFAULT_BASE: u32 = 0x0880_4000;

const ET_MIPS_PSP_PRX: u16 = 0xffa0;
const EM_MIPS: u16 = 8;
const PT_LOAD: u32 = 1;
const PT_MIPS_PSPREL2: u32 = 0x7000_00a1;
const SHT_REL: u32 = 9;
const SHT_RELA: u32 = 4;
const SHT_MIPS_PSPREL: u32 = 0x7000_00a0;
const SHF_ALLOC: u32 = 2;
const SHF_EXECINSTR: u32 = 4;

const R_MIPS_NONE: u8 = 0;
const R_MIPS_32: u8 = 2;
const R_MIPS_26: u8 = 4;
const R_MIPS_HI16: u8 = 5;
const R_MIPS_LO16: u8 = 6;

/// The name of a relocation type `Relocs` counts.
pub fn reloc_name(t: u8) -> String {
    let names = [
        "R_MIPS_NONE",
        "R_MIPS_16",
        "R_MIPS_32",
        "R_MIPS_REL32",
        "R_MIPS_26",
        "R_MIPS_HI16",
        "R_MIPS_LO16",
        "R_MIPS_GPREL16",
    ];
    names.get(t as usize).map_or_else(|| format!("type {t}"), |n| n.to_string())
}

/// What `relocate` did, by relocation type. Nothing is skipped silently: an entry is in
/// `applied` or in one of the other counts.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Relocs {
    pub applied: BTreeMap<u8, u32>,
    /// types with no rule here (left as they are in the file). `R_MIPS_16` and
    /// `R_MIPS_GPREL16`, which PPSSPP handles, are among them: no file to check them on yet.
    pub unknown: BTreeMap<u8, u32>,
    /// `R_MIPS_HI16` with no `R_MIPS_LO16` after it in its section (left as it is)
    pub unpaired_hi16: u32,
    /// entries naming a segment that is no `PT_LOAD`, or an address outside the image
    pub out_of_image: u32,
    /// entries of standard `SHT_REL`/`SHT_RELA` sections on loaded sections: not applied
    /// (they need symbols; PPSSPP does not apply them either)
    pub standard: u32,
}

impl Relocs {
    pub fn summary(&self) -> String {
        // "107760 (R_MIPS_32 12661, ...)", or "0"
        let list = |m: &BTreeMap<u8, u32>| {
            let by_type: Vec<String> = m.iter().map(|(&t, n)| format!("{} {n}", reloc_name(t))).collect();
            let total = m.values().sum::<u32>();
            if by_type.is_empty() {
                total.to_string()
            } else {
                format!("{total} ({})", by_type.join(", "))
            }
        };
        format!(
            "relocations applied: {}; of unknown type: {}; HI16 without LO16: {}; outside the image: {}; standard REL/RELA entries not applied: {}",
            list(&self.applied),
            list(&self.unknown),
            self.unpaired_hi16,
            self.out_of_image,
            self.standard
        )
    }
}

#[derive(Debug)]
pub struct Section {
    pub name: String,
    /// loaded address (link address + base)
    pub addr: u32,
    pub size: u32,
    pub exec: bool,
}

/// A loaded PRX. `mem[i]` is the byte at address `base + i`.
#[derive(Debug)]
pub struct Prx {
    pub base: u32,
    pub mem: Vec<u8>,
    /// loaded entry point
    pub entry: u32,
    /// the loaded (`SHF_ALLOC`) sections
    pub sections: Vec<Section>,
    pub relocs: Relocs,
    /// the module's own tables, or why they could not be read (the image still loads)
    pub module: Result<Module, String>,
}

/// An imported or exported function or variable.
#[derive(Debug, PartialEq, Eq)]
pub struct Symbol {
    pub library: String,
    pub nid: u32,
    /// an imported function: its stub (8 bytes the firmware fills in); an imported variable: its
    /// list of references; an export: the function or variable itself
    pub addr: u32,
    pub var: bool,
    /// the name of [`nid_name`], or `<library>_0x<NID>`
    pub name: String,
    /// whether `name` came from a NID table
    pub resolved: bool,
}

/// `sceModuleInfo` and the tables it points at, from the relocated image.
#[derive(Debug, PartialEq, Eq)]
pub struct Module {
    pub info_addr: u32,
    pub name: String,
    pub attributes: u16,
    pub version: u16,
    pub gp: u32,
    /// the export table, `[start, end)`
    pub ent: (u32, u32),
    /// the import stub table, `[start, end)`
    pub stub: (u32, u32),
    /// the library of each import stub table entry, in table order
    pub libraries: Vec<String>,
    pub imports: Vec<Symbol>,
    pub exports: Vec<Symbol>,
    /// every entry that was not read as the format says, and every difference from the section
    /// headers: nothing is skipped silently
    pub notes: Vec<String>,
}

impl Module {
    /// The names of the functions: each import stub and each exported function, by address
    /// (for a listing; `analyze` does not use it yet).
    pub fn names(&self) -> BTreeMap<u32, &str> {
        let funcs = self.imports.iter().chain(&self.exports).filter(|s| !s.var);
        funcs.map(|s| (s.addr, s.name.as_str())).collect()
    }

    pub fn summary(&self) -> String {
        let count = |v: &[Symbol], var: bool| v.iter().filter(|s| s.var == var).count();
        let named = self.imports.iter().filter(|s| s.resolved).count();
        format!(
            "module {}: attributes {:#06x}, version {:#06x}, gp {:#010x}; {} import libraries, {} imported functions, {} imported variables ({} named by NID table, {} by NID only); {} exported functions, {} exported variables; {} notes",
            self.name,
            self.attributes,
            self.version,
            self.gp,
            self.libraries.len(),
            count(&self.imports, false),
            count(&self.imports, true),
            named,
            self.imports.len() - named,
            count(&self.exports, false),
            count(&self.exports, true),
            self.notes.len()
        )
    }
}

fn u16_at(d: &[u8], o: usize) -> Result<u16, String> {
    let b = d.get(o..).and_then(|s| s.get(..2)).ok_or(format!("truncated at {o:#x}"))?;
    Ok(u16::from_le_bytes(b.try_into().unwrap()))
}

fn u32_at(d: &[u8], o: usize) -> Result<u32, String> {
    let b = d.get(o..).and_then(|s| s.get(..4)).ok_or(format!("truncated at {o:#x}"))?;
    Ok(u32::from_le_bytes(b.try_into().unwrap()))
}

/// The bytes `[off, off + size)` of the file.
fn slice(d: &[u8], off: u32, size: u32) -> Result<&[u8], String> {
    d.get(off as usize..).and_then(|s| s.get(..size as usize)).ok_or(format!("{off:#x}+{size:#x} is outside the file"))
}

/// NID to name, per library: `<library> 0x<NID> <name>` lines extracted from pspsdk's import
/// files (BSD licence; `rust/psp-nids/NOTICE`).
const NIDS: &str = include_str!("../../psp-nids/pspsdk-nids.txt");

/// The exports every module may have under its own name. The NID is the first four bytes of the
/// name's SHA-1, little-endian (PPSSPP's comment on `PspLibStubEntry`; each pair below was
/// checked that way, and PPSSPP's `NID_MODULE_*` constants hold the same values).
const MODULE_NIDS: [(u32, &str); 10] = [
    (0xd632_acdb, "module_start"),
    (0xcee8_593c, "module_stop"),
    (0x2f06_4fa6, "module_reboot_before"),
    (0xadf1_2745, "module_reboot_phase"),
    (0xd374_4be0, "module_bootstart"),
    (0xf01d_73a7, "module_info"),
    (0x0f7c_276c, "module_start_thread_parameter"),
    (0xcf0c_c697, "module_stop_thread_parameter"),
    (0xf4f4_299d, "module_reboot_before_thread_parameter"),
    (0x11b9_7506, "module_sdk_version"),
];

/// Library, NID and name for NIDs pspsdk does not list, found by hashing candidate names: the
/// NID is the first four bytes of the name's SHA-1, little-endian, as for [`MODULE_NIDS`].
/// `sceMpegAvcDecodeFlush` (2026-11-26) was the one match among 39,449,440 names of the form
/// `sceMpeg` + 1 to 4 parts from a fixed word list; chance matches expected for that many
/// tries: 39,449,440 / 2^32, about 0.009. Not copied from any source.
const SEARCHED_NIDS: [(&str, u32, &str); 1] = [("sceMpeg", 0x4571_cc64, "sceMpegAvcDecodeFlush")];

/// The name pspsdk gives function `nid` of `library`, if it lists one, else a name of
/// [`SEARCHED_NIDS`].
pub fn nid_name(library: &str, nid: u32) -> Option<&'static str> {
    // lean: a scan of the 3,159 lines per lookup (a module imports a few hundred functions); a
    // map built once if a caller ever looks up many more
    let key = format!("{library} 0x{nid:08X} ");
    let searched = || SEARCHED_NIDS.iter().find(|n| n.0 == library && n.1 == nid).map(|n| n.2);
    NIDS.lines().find_map(|l| l.strip_prefix(key.as_str())).or_else(searched)
}

/// lean: a module with more imports or exports than this is cut off, with a note (a hostile
/// file can make the tables overlap and repeat without end); raise it if a real module has more
const MAX_SYMBOLS: usize = 1 << 16;

/// Read `sceModuleInfo` at address `info` of the relocated image `mem` (loaded at `base`), then
/// the import stub table and the export table it points at. Only an unreadable `sceModuleInfo`
/// is an error; a bad table entry is a note.
pub fn parse_module(mem: &[u8], base: u32, info: u32) -> Result<Module, String> {
    let bytes = |a: u32, n: usize| {
        let s = a.checked_sub(base).and_then(|o| mem.get(o as usize..)).and_then(|s| s.get(..n));
        s.ok_or(format!("{a:#010x} is outside the image"))
    };
    let word = |a: u32| bytes(a, 4).map(|b| u32::from_le_bytes(b.try_into().unwrap()));
    // a name from the file: what is not printable ASCII becomes `_`, and it ends at 255 bytes
    let text = |b: &[u8]| -> String {
        let s = b.split(|&c| c == 0).next().unwrap_or(&[]);
        s.iter().take(255).map(|&c| if c.is_ascii_graphic() { c as char } else { '_' }).collect()
    };
    let string = |a: u32| a.checked_sub(base).and_then(|o| mem.get(o as usize..)).map(text);
    let symbol = |library: &str, nid: u32, addr: u32, var: bool, known: Option<&str>| Symbol {
        library: library.to_string(),
        nid,
        addr,
        var,
        name: known.map_or_else(|| format!("{library}_0x{nid:08X}"), str::to_string),
        resolved: known.is_some(),
    };

    let head = word(info)?;
    let mut m = Module {
        info_addr: info,
        name: text(bytes(info.wrapping_add(4), 28)?),
        attributes: head as u16,
        version: (head >> 16) as u16,
        gp: word(info.wrapping_add(32))?,
        ent: (word(info.wrapping_add(36))?, word(info.wrapping_add(40))?),
        stub: (word(info.wrapping_add(44))?, word(info.wrapping_add(48))?),
        libraries: Vec::new(),
        imports: Vec::new(),
        exports: Vec::new(),
        notes: Vec::new(),
    };

    // the import stub table: entries of `size` words (5, 6 or 7), one per library
    let mut pos = m.stub.0;
    while pos < m.stub.1 && m.imports.len() < MAX_SYMBOLS {
        let fields = (|| {
            Ok::<_, String>([
                word(pos)?,
                word(pos.wrapping_add(8))?,
                word(pos.wrapping_add(12))?,
                word(pos.wrapping_add(16))?,
            ])
        })();
        let [name, counts, nids, stubs] = match fields {
            Ok(f) => f,
            Err(e) => {
                m.notes.push(format!("import entry at {pos:#010x}: {e}"));
                break;
            }
        };
        let (size, vars, funcs) = (counts & 0xff, counts >> 8 & 0xff, counts >> 16);
        if size < 5 {
            m.notes.push(format!("import entry at {pos:#010x}: size {size} words; the table is cut off here"));
            break;
        }
        let library = string(name).unwrap_or_else(|| {
            m.notes.push(format!("import entry at {pos:#010x}: name at {name:#010x} is outside the image"));
            "(invalidname)".into()
        });
        for i in 0..funcs {
            match word(nids.wrapping_add(4 * i)) {
                _ if m.imports.len() >= MAX_SYMBOLS => break,
                Ok(nid) => {
                    let known = nid_name(&library, nid);
                    m.imports.push(symbol(&library, nid, stubs.wrapping_add(8 * i), false, known))
                }
                Err(e) => {
                    m.notes.push(format!("{library}: function {i} of {funcs}: NID at {e}"));
                    break;
                }
            }
        }
        // the variables: (address of the list of references, NID) pairs; the field is there
        // from 6 words on
        let var_data = if size >= 6 && vars > 0 { word(pos.wrapping_add(20)).unwrap_or(0) } else { 0 };
        for i in (0..vars).take_while(|_| var_data != 0) {
            let at = var_data.wrapping_add(8 * i);
            match (word(at), word(at.wrapping_add(4))) {
                _ if m.imports.len() >= MAX_SYMBOLS => break,
                (Ok(refs), Ok(nid)) => m.imports.push(symbol(&library, nid, refs, true, None)),
                (Err(e), _) | (_, Err(e)) => {
                    m.notes.push(format!("{library}: variable {i} of {vars}: {e}"));
                    break;
                }
            }
        }
        if vars > 0 && var_data == 0 {
            m.notes.push(format!("{library}: {vars} variables with no table (entry of {size} words)"));
        }
        m.libraries.push(library);
        pos = pos.saturating_add(4 * size);
    }

    // the export table: entries of `size` words (4 or 5); each has its NIDs, then as many
    // addresses, functions first
    let mut pos = m.ent.0;
    while pos < m.ent.1 && m.exports.len() < MAX_SYMBOLS {
        let fields = (|| Ok::<_, String>([word(pos)?, word(pos.wrapping_add(8))?, word(pos.wrapping_add(12))?]))();
        let [name, counts, table] = match fields {
            Ok(f) => f,
            Err(e) => {
                m.notes.push(format!("export entry at {pos:#010x}: {e}"));
                break;
            }
        };
        let (size, mut vars, funcs) = (counts & 0xff, counts >> 8 & 0xff, counts >> 16);
        if size < 4 {
            m.notes.push(format!("export entry at {pos:#010x}: size {size} words; the table is cut off here"));
            break;
        }
        if size > 4 {
            // a second, wider variable count (PPSSPP's `vcountNew`)
            vars = vars.max(word(pos.wrapping_add(16)).unwrap_or(0) & 0xffff);
        }
        // an entry with no name holds the module's own exports, under the module's name
        let library = match name {
            0 => m.name.clone(),
            _ => string(name).unwrap_or_else(|| "(invalidname)".into()),
        };
        let total = funcs + vars;
        for j in 0..total {
            let pair = (word(table.wrapping_add(4 * j)), word(table.wrapping_add(4 * (total + j))));
            match pair {
                _ if m.exports.len() >= MAX_SYMBOLS => break,
                (Ok(nid), Ok(addr)) => {
                    let own = MODULE_NIDS.iter().find(|n| name == 0 && n.0 == nid).map(|n| n.1);
                    let known = own.or_else(|| nid_name(&library, nid).filter(|_| j < funcs));
                    m.exports.push(symbol(&library, nid, addr, j >= funcs, known))
                }
                (Err(e), _) | (_, Err(e)) => {
                    m.notes.push(format!("export entry at {pos:#010x}: symbol {j} of {total}: {e}"));
                    break;
                }
            }
        }
        pos = pos.saturating_add(4 * size);
    }
    if m.imports.len() >= MAX_SYMBOLS || m.exports.len() >= MAX_SYMBOLS {
        m.notes.push(format!("more than {MAX_SYMBOLS} imports or exports: the rest is not read"));
    }
    Ok(m)
}

/// An ELF32 little-endian MIPS file of type `ET_MIPS_PSP_PRX`.
pub fn is_prx(data: &[u8]) -> bool {
    data.starts_with(b"\x7fELF\x01\x01") && u16_at(data, 16) == Ok(ET_MIPS_PSP_PRX) && u16_at(data, 18) == Ok(EM_MIPS)
}

/// Apply the entries `rels` of one PSP relocation section to `mem` (the image at its link
/// addresses, from 0) for load base `base`. `segs[i]` is the link address of program header
/// `i`, `None` when it is no `PT_LOAD`.
pub fn relocate(mem: &mut [u8], segs: &[Option<u32>], base: u32, rels: &[u8], stats: &mut Relocs) {
    let seg = |i: u32| segs.get((i & 0xff) as usize).copied().flatten();
    let word = |mem: &[u8], a: Option<u32>| a.and_then(|a| u32_at(mem, a as usize).ok());
    // (type, address, segment added, the word before any relocation), as PPSSPP's first pass
    let entries: Vec<(u8, Option<u32>, Option<u32>, Option<u32>)> = rels
        .chunks_exact(8)
        .map(|e| {
            let (off, info) = (u32_at(e, 0).unwrap(), u32_at(e, 4).unwrap());
            let addr = seg(info >> 8).and_then(|v| v.checked_add(off));
            (info as u8, addr, seg(info >> 16), word(mem, addr))
        })
        .collect();
    for (i, &(t, addr, to, op)) in entries.iter().enumerate() {
        if !matches!(t, R_MIPS_NONE | R_MIPS_32 | R_MIPS_26 | R_MIPS_HI16 | R_MIPS_LO16) {
            *stats.unknown.entry(t).or_default() += 1;
            continue;
        }
        let (Some(addr), Some(to), Some(op)) = (addr, to, op) else {
            stats.out_of_image += 1;
            continue;
        };
        let to = to.wrapping_add(base);
        let new = match t {
            R_MIPS_32 => op.wrapping_add(to),
            R_MIPS_26 => (op & 0xfc00_0000) | ((op & 0x03ff_ffff).wrapping_add(to >> 2) & 0x03ff_ffff),
            R_MIPS_LO16 => (op & 0xffff_0000) | (op.wrapping_add(to) & 0xffff),
            R_MIPS_HI16 => {
                // the address is this word's high half plus the signed low half of the next LO16
                let lo = entries[i + 1..].iter().find(|e| e.0 == R_MIPS_LO16).and_then(|e| e.3);
                let Some(lo) = lo else {
                    stats.unpaired_hi16 += 1;
                    continue;
                };
                let full = (op << 16).wrapping_add(lo as u16 as i16 as u32).wrapping_add(to);
                (op & 0xffff_0000) | (full.wrapping_sub(full as u16 as i16 as u32) >> 16)
            }
            _ => op, // R_MIPS_NONE
        };
        mem[addr as usize..addr as usize + 4].copy_from_slice(&new.to_le_bytes());
        *stats.applied.entry(t).or_default() += 1;
    }
}

/// Load a PRX at `base`: the `PT_LOAD` segments at their link addresses (the rest zero, as
/// `.bss`), then every PSP relocation section on a loaded section.
pub fn load(data: &[u8], base: u32) -> Result<Prx, String> {
    if !is_prx(data) {
        return Err("not a PSP PRX (ELF32 little-endian MIPS of type 0xffa0)".into());
    }
    let (phoff, phentsize, phnum) = (u32_at(data, 28)? as usize, u16_at(data, 42)? as usize, u16_at(data, 44)?);
    let (shoff, shentsize, shnum) = (u32_at(data, 32)? as usize, u16_at(data, 46)? as usize, u16_at(data, 48)?);
    let shstrndx = u16_at(data, 50)? as usize;
    if (phnum > 0 && phentsize < 32) || (shnum > 0 && shentsize < 40) {
        return Err("bad program or section header size".into());
    }
    let mut mem: Vec<u8> = Vec::new();
    let mut segs = Vec::new();
    // `sceModuleInfo`: the physical address field of the first program header is its file offset
    // (PPSSPP's rule when no section names it)
    let mut info = None;
    for i in 0..phnum as usize {
        let ph = phoff + i * phentsize;
        let (kind, off, vaddr) = (u32_at(data, ph)?, u32_at(data, ph + 4)?, u32_at(data, ph + 8)?);
        if i == 0 {
            info = Some(vaddr.wrapping_add(u32_at(data, ph + 12)? & 0x7fff_ffff).wrapping_sub(off));
        }
        let (filesz, memsz) = (u32_at(data, ph + 16)?, u32_at(data, ph + 20)?);
        if kind == PT_MIPS_PSPREL2 {
            return Err("PSP type B relocations (program header 0x700000a1) are not implemented".into());
        }
        segs.push((kind == PT_LOAD).then_some(vaddr));
        if kind != PT_LOAD {
            continue;
        }
        let end = vaddr.checked_add(memsz.max(filesz)).ok_or("a segment wraps the address space")?;
        // lean: the image is one block from address 0 (a PRX links at 0); a file linked high
        // would need a sparse image
        if end > 0x1000_0000 {
            return Err(format!("segment end {end:#x}: more than 256 MiB from address 0"));
        }
        mem.resize(mem.len().max(end as usize), 0);
        mem[vaddr as usize..(vaddr + filesz) as usize].copy_from_slice(slice(data, off, filesz)?);
    }
    if base.checked_add(mem.len() as u32).is_none() {
        return Err(format!("base {base:#x} puts the image past 4 GiB"));
    }
    // section header fields: (name, type, flags, addr, offset, size, info)
    let sh = |i: usize| -> Result<[u32; 7], String> {
        let s = shoff + i * shentsize;
        let f = |k: usize| u32_at(data, s + 4 * k);
        Ok([f(0)?, f(1)?, f(2)?, f(3)?, f(4)?, f(5)?, f(7)?])
    };
    let strtab = if shstrndx < shnum as usize { sh(shstrndx)? } else { [0; 7] };
    let names = slice(data, strtab[4], strtab[5])?;
    let mut sections: Vec<Section> = Vec::new();
    let mut relocs = Relocs::default();
    for i in 0..shnum as usize {
        let [name, kind, flags, addr, off, size, info] = sh(i)?;
        if flags & SHF_ALLOC != 0 && size > 0 {
            if (addr as usize).checked_add(size as usize).is_none_or(|e| e > mem.len()) {
                return Err(format!("section {i} is outside the loaded segments"));
            }
            let text = names.get(name as usize..).unwrap_or(&[]);
            let name = String::from_utf8_lossy(text.split(|&b| b == 0).next().unwrap_or(&[])).into_owned();
            sections.push(Section { name, addr: base + addr, size, exec: flags & SHF_EXECINSTR != 0 });
        }
        let on_loaded = (info as usize) < shnum as usize && sh(info as usize)?[2] & SHF_ALLOC != 0;
        match kind {
            // as PPSSPP: only the relocation sections of loaded sections
            SHT_MIPS_PSPREL if on_loaded => relocate(&mut mem, &segs, base, slice(data, off, size)?, &mut relocs),
            SHT_REL if on_loaded => relocs.standard += size / 8,
            SHT_RELA if on_loaded => relocs.standard += size / 12,
            _ => {}
        }
    }
    let module = info.ok_or("no program header".to_string()).and_then(|info| {
        let mut m = parse_module(&mem, base, base.wrapping_add(info))?;
        // the section headers are a cross-check only
        let checks = [
            (".rodata.sceModuleInfo", (m.info_addr, m.info_addr.wrapping_add(52))),
            (".lib.ent", m.ent),
            (".lib.stub", m.stub),
        ];
        for (name, (start, end)) in checks {
            for s in sections.iter().filter(|s| s.name == name && (s.addr, s.addr + s.size) != (start, end)) {
                let (a, e) = (s.addr, s.addr + s.size);
                m.notes.push(format!(
                    "section {name} is {a:#010x}-{e:#010x}; sceModuleInfo gives {start:#010x}-{end:#010x}"
                ));
            }
        }
        Ok(m)
    });
    Ok(Prx { base, entry: base.wrapping_add(u32_at(data, 24)?), mem, sections, relocs, module })
}
