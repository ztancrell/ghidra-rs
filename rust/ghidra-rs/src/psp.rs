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
    for i in 0..phnum as usize {
        let ph = phoff + i * phentsize;
        let (kind, off, vaddr) = (u32_at(data, ph)?, u32_at(data, ph + 4)?, u32_at(data, ph + 8)?);
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
    let mut sections = Vec::new();
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
    Ok(Prx { base, entry: base.wrapping_add(u32_at(data, 24)?), mem, sections, relocs })
}
