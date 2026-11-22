//! Function discovery, bodies and references for 32-bit x86 PE images (and ELF x86-64 ones,
//! `Image::from_elf`), modelled on what
//! Ghidra's auto-analysis produces for the scripts in `main.rs` (ExportFunctions, ExportGaps).
//! Every executable section is disassembled; results are reported for `.text`. See rust/README.md "Analysis" for what is and isn't covered.

use crate::queue::{priority, Analyzer, Kind, Manager};

mod repair;
use crate::sleigh::Sleigh;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

pub struct Section {
    pub name: String,
    pub exec: bool,
    /// not writable (no `IMAGE_SCN_MEM_WRITE`): bfd's `SEC_READONLY`, which the decompiler reads as constant
    pub readonly: bool,
    /// how many bytes at the end of `data` lie past the section as bfd loads it (its `size`: the
    /// raw size when that is smaller than the virtual size, else the virtual size), which the
    /// decompiler treats as unmapped (`LoadImageBfd`)
    pub zero_tail: u32,
    pub addr: u32,
    pub data: Vec<u8>, // virtual size, zero filled past the raw data
}

#[derive(Default)]
pub struct Image {
    pub sections: Vec<Section>, // first entry: the "Headers" block, as Ghidra names it
    pub entry: Option<u32>,
    pub exports: Vec<(u32, String)>,
    pub imports: HashMap<u32, (String, String)>, // IAT slot -> (library, function)
    pub export_dir: (u32, u32), // export directory (address, size): its tables hold RVAs, not addresses
    pub eat: Vec<(u32, u32)>,   // export address table: (slot, function it names)
    /// An ELF x86-64 image (`from_elf`): pointers are 8 bytes, the language x86:LE:64:default
    pub elf64: bool,
    /// ELF: the functions the loader makes, in its order (ElfProgramBuilder: the symbol-table
    /// STT_FUNC symbols, then the entry point and the dynamic entries); the exports hold the
    /// global and weak ones and the entries
    pub elf_funcs: Vec<(u32, String)>,
    /// ELF: dynamic relocations `from_elf` does not apply (Ghidra applies them)
    pub unapplied_relocs: usize,
    /// ELF: what the image base was moved by (ElfHeader.findImageBase: 0x100000 for a PIE linked
    /// at 0); bfd loads the file where it is linked, so the prelude moves it (`adjust vma`)
    pub elf_adjust: u32,
    /// ELF: the non-loaded sections bfd marks read-only, (address, size): the console's
    /// read-only ranges have them, as the reference's (not Java's, which does not load them)
    pub bfd_readonly: Vec<(u64, u64)>,
    /// ELF: Java's EXTERNAL block, first and last address (ElfProgramBuilder.createExternalBlock,
    /// ElfProgramBuilder.java:1546-1568: uninitialized, writable). Not a section here: only the
    /// facts writer reads it, the analysis and the decompiler see no block there
    pub external_block: Option<(u32, u32)>,
    /// ELF: the entries of the EXTERNAL block, in allocation order
    pub externals: Vec<External>,
    /// ELF: GOT slots a GLOB_DAT or JUMP_SLOT relocation binds to an EXTERNAL entry, and the
    /// value Java writes there (X86_64_ElfRelocationHandler.java:168-171: the entry plus the
    /// addend); the slot itself holds 0 here
    pub got_external: HashMap<u32, u32>,
    /// ELF: the addresses of the named symbols the symbol tables define (Java's labels there)
    pub elf_named: HashSet<u32>,
}

/// An entry of Java's EXTERNAL block (ElfProgramBuilder.allocateExternalSymbol).
pub struct External {
    pub addr: u32,
    pub name: String,
    /// an STT_FUNC symbol: Java makes a one-byte thunk to the external function there
    /// (evaluateElfSymbol, ElfProgramBuilder.java:2140-2152)
    pub func: bool,
    /// the versioned names (`puts@GLIBC_2.2.5`) that make its PRE comment
    /// (processVersionedExternal, ElfProgramBuilder.java:2031-2041)
    pub versions: Vec<String>,
}

impl Image {
    pub fn from_pe(bytes: &[u8]) -> Result<Image, String> {
        use object::read::pe::{ImageNtHeaders, ImageOptionalHeader, PeFile32};
        use object::{LittleEndian as LE, Object};
        let pe = PeFile32::parse(bytes).map_err(|e| e.to_string())?;
        let opt = pe.nt_headers().optional_header();
        let base = opt.image_base() as u32;
        let hdr = opt.size_of_headers() as usize;
        let mut img = Image::default();
        img.sections.push(Section {
            name: "Headers".into(),
            exec: false,
            readonly: false, // not a section of the file, so not in bfd's list
            zero_tail: 0,
            addr: base,
            data: bytes[..hdr.min(bytes.len())].to_vec(),
        });
        for s in pe.section_table().iter() {
            let name = String::from_utf8_lossy(s.raw_name()).trim_end_matches('\0').to_string();
            let mut data = s.pe_data(bytes).map_err(|e| e.to_string())?.to_vec();
            data.resize(s.virtual_size.get(LE) as usize, 0);
            let exec =
                s.characteristics.get(LE) & (object::pe::IMAGE_SCN_CNT_CODE | object::pe::IMAGE_SCN_MEM_EXECUTE) != 0;
            let flags = s.characteristics.get(LE);
            let readonly = flags & object::pe::IMAGE_SCN_MEM_WRITE == 0;
            // bfd (_bfd_XXi_swap_scnhdr_in) takes the virtual size when the raw size is larger, or
            // for uninitialized data without raw bytes; else the raw size
            let (raw, virt) = (s.size_of_raw_data.get(LE), s.virtual_size.get(LE));
            let uninit = flags & object::pe::IMAGE_SCN_CNT_UNINITIALIZED_DATA != 0;
            let bfd_size = if raw > virt || uninit && raw == 0 { virt } else { raw };
            let zero_tail = virt.saturating_sub(bfd_size);
            let addr = base + s.virtual_address.get(LE);
            img.sections.push(Section { name, exec, readonly, zero_tail, addr, data });
        }
        let entry = opt.address_of_entry_point();
        img.entry = (entry != 0).then_some(base + entry);
        for x in pe.exports().map_err(|e| e.to_string())? {
            img.exports.push((x.address() as u32, String::from_utf8_lossy(x.name()).into_owned()));
        }
        // The loader types the export address table as image-base offsets (ibo32): each slot
        // references base + RVA.
        if let Some(d) = pe.data_directory(object::pe::IMAGE_DIRECTORY_ENTRY_EXPORT) {
            let at = base + d.virtual_address.get(LE);
            img.export_dir = (at, d.size.get(LE));
            let (n, funcs) = (img.read_u32(at + 0x14).unwrap_or(0), img.read_u32(at + 0x1c).unwrap_or(0));
            for i in 0..n.min(0x10000) {
                if let Some(rva) = img.read_u32(base + funcs + 4 * i).filter(|&r| r != 0) {
                    img.eat.push((base + funcs + 4 * i, base + rva));
                }
            }
        }
        // Import descriptors, read through the loaded image: names and thunks may lie in other
        // sections than the directory (the mercs2 image keeps its IAT in .rdata and the
        // directory in .securom), which object's section-bound ImportTable cannot read.
        let dir = pe.data_directory(object::pe::IMAGE_DIRECTORY_ENTRY_IMPORT).map_or(0, |d| d.virtual_address.get(LE));
        // A zero directory means no imports; otherwise the table ends at an all-zero descriptor.
        let mut d = base + dir;
        while dir != 0 && d < base + dir + 20 * 0x10000 {
            let f = |i: u32| img.read_u32(d + 4 * i).unwrap_or(0);
            let (orig, name, first) = (f(0), f(3), f(4));
            if name == 0 || first == 0 {
                break;
            }
            let lib = img.c_string(base + name).to_uppercase();
            let mut i = 0;
            let names = if orig != 0 { orig } else { first };
            while let Some(th) = img.read_u32(base + names + 4 * i).filter(|&t| t != 0) {
                let name = if th & 0x8000_0000 != 0 {
                    format!("Ordinal_{}", th & 0xffff)
                } else {
                    img.c_string(base + th + 2)
                };
                img.imports.insert(base + first + 4 * i, (lib.clone(), name));
                i += 1;
            }
            d += 20;
        }
        Ok(img)
    }

    /// An ELF x86-64 file as Ghidra's ElfLoader loads it, what analysis reads of it
    /// (ElfProgramBuilder.load): a memory block per allocated section (processSectionHeaders;
    /// `.tbss` left out, it overlaps the next section), the `.got` blocks read-only
    /// (processGOTSections), the image base 0x100000 for a shared object linked at 0
    /// (ElfLoaderOptionsFactory.IMAGE64_BASE_DEFAULT), a one-byte function at each STT_FUNC
    /// symbol of the symbol tables (evaluateElfSymbol; `.cold` parts are none), at the entry
    /// point and at DT_INIT, DT_FINI and the entries of the init, preinit and fini arrays
    /// (processEntryPoints). GOT slots the dynamic relocations bind to an undefined symbol are
    /// imports of `<EXTERNAL>` (Library.UNKNOWN), as the IAT slots of a PE: Ghidra points them
    /// at its EXTERNAL block, which only the facts writer has (`external_block`, `externals`,
    /// `got_external`): the slots hold 0 here. Addresses must fit in 32 bits.
    pub fn from_elf(bytes: &[u8]) -> Result<Image, String> {
        use object::elf;
        use object::read::elf::{Dyn, ElfFile64, FileHeader, ProgramHeader, Rela, SectionHeader, Sym};
        use object::LittleEndian as LE;
        let file = ElfFile64::<LE>::parse(bytes).map_err(|e| e.to_string())?;
        let (hdr, e) = (file.elf_header(), LE);
        if hdr.e_machine(e) != elf::EM_X86_64 {
            return Err(format!("ELF machine {} is not x86-64", hdr.e_machine(e)));
        }
        let kind = hdr.e_type(e);
        if kind == elf::ET_REL {
            // ElfProgramBuilder.java:3490-3500 packs an object's sections (all at 0) one after another
            return Err("ELF relocatable object (ET_REL) is not ported: Java packs its sections".into());
        }
        let segs = hdr.program_headers(e, bytes).map_err(|e| e.to_string())?;
        // ElfHeader.findImageBase (ElfHeader.java:1515-1539): the lowest PT_LOAD of the first 20
        let min_load =
            segs.iter().take(20).filter(|p| p.p_type(e) == elf::PT_LOAD).map(|p| p.p_vaddr(e)).min().unwrap_or(0);
        let adj = if min_load == 0 && kind == elf::ET_DYN { 0x10_0000 } else { 0 };
        let addr32 = |a: u64| {
            a.checked_add(adj)
                .and_then(|a| u32::try_from(a).ok())
                .ok_or(format!("address {a:#x} + {adj:#x} is past 32 bits"))
        };
        let mut img = Image { elf64: true, elf_adjust: adj as u32, ..Image::default() };
        let sections = hdr.sections(e, bytes).map_err(|e| e.to_string())?;
        for s in sections.iter() {
            let flags = s.sh_flags(e);
            let name = String::from_utf8_lossy(sections.section_name(e, s).unwrap_or_default()).into_owned();
            // bfd makes the non-loaded sections with contents (`.comment`, `.debug_*`) sections too,
            // at their address (0) and read-only without SHF_WRITE, and the reference's
            // LoadImageBfd::getReadonly (loadimage_bfd.cc:286-301) marks them; Java does not map them
            if flags & u64::from(elf::SHF_ALLOC) == 0
                && flags & u64::from(elf::SHF_WRITE) == 0
                && matches!(s.sh_type(e), elf::SHT_PROGBITS | elf::SHT_NOTE)
                && s.sh_size(e) != 0
            {
                img.bfd_readonly.push((s.sh_addr(e), s.sh_size(e)));
            }
            if flags & u64::from(elf::SHF_ALLOC) == 0 || s.sh_size(e) == 0 || name == ".tbss" {
                continue;
            }
            let nobits = s.sh_type(e) == elf::SHT_NOBITS;
            // the whole section must lie below 4 GiB (`Analysis` keeps u32 addresses), checked
            // before a `.bss` is allocated
            let addr = addr32(s.sh_addr(e))?;
            if u64::from(addr) + s.sh_size(e) > 1 << 32 {
                return Err(format!("section {name} at {addr:#x}, {:#x} bytes, ends past 32 bits", s.sh_size(e)));
            }
            let size = s.sh_size(e) as usize;
            let data = if nobits { vec![0; size] } else { s.data(e, bytes).map_err(|e| e.to_string())?.to_vec() };
            img.sections.push(Section {
                exec: flags & u64::from(elf::SHF_EXECINSTR) != 0,
                readonly: flags & u64::from(elf::SHF_WRITE) == 0 || name.starts_with(".got"),
                zero_tail: if nobits { size as u32 } else { 0 },
                addr,
                data,
                name,
            });
        }
        let exec_at = |img: &Image, a: u32| img.block_of(a).is_some_and(|s| s.exec);
        // the symbol tables, .symtab first as the section order has it
        let mut undefined = HashMap::new(); // (table, index) -> name, for the relocations
        let mut defined = HashMap::new(); // (table, index) -> address
        let mut made = HashSet::new(); // the entries of `elf_funcs`

        // Java's EXTERNAL block (ElfProgramBuilder.getNextExternalBlockEntryAddress,
        // ElfProgramBuilder.java:1511-1540): allocateLinkageBlock (1401-1498) with alignment
        // 0x1000 (ElfLoadAdapter.getLinkageBlockAlignment) takes the last free range of at least
        // 0x20000 bytes (getPreferredExternalBlockSize), the one past the highest block
        let ext_base = img.sections.iter().map(|s| u64::from(s.addr) + s.data.len() as u64).max().unwrap_or(0);
        let mut next_ext = ext_base.next_multiple_of(0x1000);
        let mut ext_of = HashMap::new(); // (table, index) -> EXTERNAL entry, for the relocations
        let mut ext_by_name: HashMap<String, usize> = HashMap::new();
        for (ti, table) in sections.iter().enumerate() {
            if !matches!(table.sh_type(e), elf::SHT_SYMTAB | elf::SHT_DYNSYM) {
                continue;
            }
            let Some(syms) = table.symbols(e, bytes, &sections, object::SectionIndex(ti)).map_err(|e| e.to_string())?
            else {
                continue;
            };
            for (i, s) in syms.iter().enumerate() {
                let name = String::from_utf8_lossy(s.name(e, syms.strings()).unwrap_or_default()).into_owned();
                if s.st_shndx(e) == elf::SHN_UNDEF {
                    // ElfProgramBuilder.processSymbols (1685-1713) with calculateSymbolAddress
                    // (1731-1900): NO_ADDRESS for an undefined symbol but the first, a TLS or
                    // a file one; not the GOT symbol nor a blank name
                    let external = i != 0
                        && !matches!(s.st_type(), elf::STT_TLS | elf::STT_FILE)
                        && !name.trim().is_empty()
                        && name != "_GLOBAL_OFFSET_TABLE_"
                        && (s.st_bind() != elf::STB_LOCAL || s.st_value(e) == 0 || s.st_value(e) == 1);
                    if external {
                        // a versioned name of an entry made before is its comment (processVersionedExternal);
                        // a name made before is that entry (processDuplicateExternal)
                        let real = name.find("@@").filter(|&i| i > 0).or(name.find('@')).map(|i| &name[..i]);
                        if let Some(&x) = real.and_then(|r| ext_by_name.get(r)) {
                            img.externals[x].versions.push(name.clone());
                            ext_of.insert((ti, i), x);
                        } else if let Some(&x) = ext_by_name.get(&name) {
                            ext_of.insert((ti, i), x);
                        } else {
                            // allocateExternalSymbol (1945-1960): a sized object its size aligned
                            // to 8 (getDefaultAlignment of a 64-bit file), anything else 8 bytes
                            let size = s.st_size(e);
                            let size = if s.st_type() == elf::STT_OBJECT && size > 0 && size < i32::MAX as u64 {
                                size.next_multiple_of(8)
                            } else {
                                8
                            };
                            let addr = u32::try_from(next_ext)
                                .ok()
                                .filter(|a| u64::from(*a) + size <= 1 << 32)
                                .ok_or(format!("EXTERNAL block entry {name} at {next_ext:#x} is past 32 bits"))?;
                            next_ext += size;
                            ext_by_name.insert(name.clone(), img.externals.len());
                            ext_of.insert((ti, i), img.externals.len());
                            img.externals.push(External {
                                addr,
                                name: name.clone(),
                                func: s.st_type() == elf::STT_FUNC,
                                versions: Vec::new(),
                            });
                        }
                    }
                    undefined.insert((ti, i), name);
                    continue;
                }
                if s.st_shndx(e) < elf::SHN_LORESERVE {
                    defined.insert((ti, i), s.st_value(e) + adj);
                    if !name.is_empty() && !matches!(s.st_type(), elf::STT_SECTION | elf::STT_FILE) {
                        if let Ok(a) = addr32(s.st_value(e)) {
                            img.elf_named.insert(a);
                        }
                    }
                }
                if s.st_type() != elf::STT_FUNC
                    || name.is_empty()
                    || is_cold(&name)
                    || s.st_shndx(e) >= elf::SHN_LORESERVE
                {
                    continue;
                }
                let a = addr32(s.st_value(e))?;
                if made.insert(a) {
                    img.elf_funcs.push((a, name.clone()));
                }
                if matches!(s.st_bind(), elf::STB_GLOBAL | elf::STB_WEAK) {
                    img.exports.push((a, name));
                }
            }
        }
        if let (Some(first), Some(last)) = (img.externals.first(), u32::try_from(next_ext - 1).ok()) {
            img.external_block = Some((first.addr, last));
        }
        img.entry = (hdr.e_entry(e) != 0).then(|| addr32(hdr.e_entry(e))).transpose()?;
        // the dynamic relocations (X86_64_ElfRelocationHandler): GOT slots bound to undefined
        // symbols by JUMP_SLOT and GLOB_DAT are imports, and hold Java's EXTERNAL-block address
        // there (X86_64_ElfRelocationHandler.java:168-170; 0 here, which is no block); to a
        // defined symbol they and R_X86_64_64 write its address plus the addend; RELATIVE,
        // RELATIVE64 and IRELATIVE write the image base adjustment plus the addend, a prelinked
        // RELATIVE plus the word in place (X86_64_ElfRelocationHandler.java:76-93; RELR, the
        // packed form, the word in place). Others are counted, not applied (COPY, which Java
        // does not apply either, among them), and so are those at no 8 bytes of a section.
        // ElfHeader.isPreLinked (ElfHeader.java:1582-1626): "PRE" at the file's end, or DT_GNU_PRELINKED
        let prelinked = bytes.len() >= 8 && String::from_utf8_lossy(&bytes[bytes.len() - 4..]).trim() == "PRE"
            || sections.iter().filter(|s| s.sh_type(e) == elf::SHT_DYNAMIC).any(|d| {
                d.data_as_array::<elf::Dyn64<LE>, _>(e, bytes)
                    .is_ok_and(|ds| ds.iter().any(|x| x.d_tag(e) == u64::from(elf::DT_GNU_PRELINKED)))
            });
        let mut other = 0;
        let put = |img: &mut Image, at: u32, f: &dyn Fn(u64) -> u64| {
            let sec = img.sections.iter_mut().find(|s| at >= s.addr && (at - s.addr) as usize + 8 <= s.data.len());
            sec.map(|sec| {
                let o = (at - sec.addr) as usize;
                let old = u64::from_le_bytes(sec.data[o..o + 8].try_into().unwrap());
                sec.data[o..o + 8].copy_from_slice(&f(old).to_le_bytes());
            })
            .is_some()
        };
        for s in sections.iter() {
            if s.sh_flags(e) & u64::from(elf::SHF_ALLOC) == 0 {
                continue;
            }
            if s.sh_type(e) == elf::SHT_RELR {
                let words: &[object::U64<LE>] = s.data_as_array(e, bytes).map_err(|e| e.to_string())?;
                let mut next = 0u64;
                for w in words.iter().map(|w| w.get(e)) {
                    let at = if w & 1 == 0 {
                        vec![w]
                    } else {
                        (1..64).filter(|b| w >> b & 1 != 0).map(|b| next + 8 * (b - 1)).collect()
                    };
                    for &a in &at {
                        if !put(&mut img, addr32(a)?, &|v| v.wrapping_add(adj)) {
                            other += 1;
                        }
                    }
                    next = if w & 1 == 0 { w + 8 } else { next + 63 * 8 };
                }
                continue;
            }
            if s.sh_type(e) != elf::SHT_RELA {
                continue;
            }
            let link = s.sh_link(e) as usize;
            let relas: &[elf::Rela64<LE>] = s.data_as_array(e, bytes).map_err(|e| e.to_string())?;
            for r in relas {
                let (at, sym) = (addr32(r.r_offset(e))?, r.r_sym(e, false) as usize);
                let addend = r.r_addend(e);
                let applied = match r.r_type(e, false) {
                    elf::R_X86_64_JUMP_SLOT | elf::R_X86_64_GLOB_DAT | elf::R_X86_64_64 => {
                        if let Some(&v) = defined.get(&(link, sym)) {
                            put(&mut img, at, &|_| v.wrapping_add(addend as u64))
                        } else if let Some(name) = undefined.get(&(link, sym)).filter(|n| !n.is_empty()) {
                            if r.r_type(e, false) == elf::R_X86_64_64 {
                                false
                            } else {
                                img.imports.insert(at, ("<EXTERNAL>".to_string(), name.clone()));
                                if let Some(x) = ext_of.get(&(link, sym)) {
                                    let v = u64::from(img.externals[*x].addr).wrapping_add(addend as u64);
                                    img.got_external.insert(
                                        at,
                                        u32::try_from(v)
                                            .map_err(|_| format!("GOT slot {at:#x}: {v:#x} is past 32 bits"))?,
                                    );
                                }
                                put(&mut img, at, &|_| 0)
                            }
                        } else {
                            false
                        }
                    }
                    elf::R_X86_64_RELATIVE | elf::R_X86_64_RELATIVE64 if prelinked => {
                        put(&mut img, at, &|v| v.wrapping_add(adj))
                    }
                    elf::R_X86_64_RELATIVE | elf::R_X86_64_RELATIVE64 | elf::R_X86_64_IRELATIVE => {
                        put(&mut img, at, &|_| (adj as i64).wrapping_add(addend) as u64)
                    }
                    _ => false,
                };
                if !applied {
                    other += 1;
                }
            }
        }
        img.unapplied_relocs = other;
        let mut entries = Vec::new();
        if hdr.e_entry(e) != 0 && matches!(kind, elf::ET_EXEC | elf::ET_DYN) {
            entries.push((addr32(hdr.e_entry(e))?, "entry".to_string()));
        }
        // the dynamic table: DT_INIT, DT_FINI and the arrays (createDynamicEntryPoints)
        let dynamic = sections.iter().find(|s| s.sh_type(e) == elf::SHT_DYNAMIC);
        if let Some(d) = dynamic {
            let dyns: &[elf::Dyn64<LE>] = d.data_as_array(e, bytes).map_err(|e| e.to_string())?;
            let val = |tag: u32| dyns.iter().find(|x| x.d_tag(e) == u64::from(tag)).map(|x| x.d_val(e));
            for (tag, name) in [(elf::DT_INIT, "_DT_INIT"), (elf::DT_FINI, "_DT_FINI")] {
                if let Some(v) = val(tag) {
                    entries.push((addr32(v)?, name.to_string()));
                }
            }
            for (at, size, base) in [
                (elf::DT_INIT_ARRAY, elf::DT_INIT_ARRAYSZ, "_INIT_"),
                (elf::DT_PREINIT_ARRAY, elf::DT_PREINIT_ARRAYSZ, "_PREINIT_"),
                (elf::DT_FINI_ARRAY, elf::DT_FINI_ARRAYSZ, "_FINI_"),
            ] {
                let (Some(at), Some(size)) = (val(at), val(size)) else { continue };
                for i in 0..size / 8 {
                    match img.read_ptr(addr32(at + 8 * i)?) {
                        Some(0) => {}
                        // relocated above where the array has RELATIVE relocations
                        Some(f) => entries.push((f, format!("{base}{i}"))),
                        None => break,
                    }
                }
            }
        }
        for (a, name) in entries {
            if !exec_at(&img, a) {
                continue;
            }
            if made.insert(a) {
                img.elf_funcs.push((a, name.clone()));
            }
            if img.exports.iter().all(|x| x.0 != a) {
                img.exports.push((a, name));
            }
        }
        Ok(img)
    }

    /// A pointer of the image: 4 bytes, or 8 for an ELF64 image (None past 32 bits).
    pub fn read_ptr(&self, a: u32) -> Option<u32> {
        if !self.elf64 {
            return self.read_u32(a);
        }
        let s = self.block_of(a)?;
        let o = (a - s.addr) as usize;
        ptr_value(s.data.get(o..o + 8)?)
    }

    /// The pointer size in bytes.
    pub fn ptr_size(&self) -> u32 {
        if self.elf64 {
            8
        } else {
            4
        }
    }

    pub fn c_string(&self, a: u32) -> String {
        let Some(s) = self.block_of(a) else { return String::new() };
        let b = &s.data[(a - s.addr) as usize..];
        String::from_utf8_lossy(&b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())]).into_owned()
    }

    pub fn section(&self, name: &str) -> Option<&Section> {
        self.sections.iter().find(|s| s.name == name)
    }

    pub fn block_of(&self, a: u32) -> Option<&Section> {
        self.sections.iter().find(|s| a >= s.addr && ((a - s.addr) as usize) < s.data.len())
    }

    pub fn read_u32(&self, a: u32) -> Option<u32> {
        let s = self.block_of(a)?;
        let o = (a - s.addr) as usize;
        Some(u32::from_le_bytes(s.data.get(o..o + 4)?.try_into().ok()?))
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Flow {
    Fall,
    Jump,     // unconditional, direct
    CondJump, // conditional, direct
    JumpInd,
    Call,
    CallInd,
    Return,
}

#[derive(Clone, Debug)]
pub struct Ins {
    pub len: u8,
    pub flow: Flow,
    pub target: Option<u32>,   // direct flow target
    pub slot: Option<u32>,     // memory operand of an indirect call/jump through a constant address
    pub computed: Option<u32>, // code target of another indirect call/jump, from the local fold
    pub refs: Vec<u32>,        // data references: constant addresses inside the image
    pub rw: Vec<u32>,          // the `refs` a memory operand makes (READ or WRITE; the others are DATA)
    pub code_imms: Vec<u32>,   // immediates that point into an executable section
    pub nop: bool,             // no p-code (ENDBR64), which getThunkedAddr steps over
}

/// The references `Analysis::disassemble` goes by: every destination, and the destinations in
/// executable blocks that a memory operand reads or writes (Ghidra's READ and WRITE references).
#[derive(Default)]
struct Refs {
    dests: BTreeSet<u32>,
    reads: HashSet<u32>,
}

/// A value of the local fold: a constant, or what a 4-byte register held where the fold
/// began (or before the last call that clobbered it) plus an offset, as Ghidra's
/// SymbolicPropogator keeps unknown registers as symbols.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Val {
    C(u64),
    S(u64, u32),
}

/// State of the local fold: (space, offset, size, value or unknown, computed rather than a
/// plain immediate) of registers and temporaries, and memory written through a folded
/// address (address, value or unknown, computed).
#[derive(Clone, Default)]
pub struct Fold {
    regs: Vec<(u32, u64, u32, Option<Val>, bool)>,
    mem: Vec<(Val, Option<Val>, bool)>,
    whole: bool, // a whole-function walk (`propagate`): keeps more memory
    /// the stack slots the last instruction read or wrote through a folded address: (offset
    /// from ESP at the entry, bytes, written)
    pub stack: Vec<(u32, u32, bool)>,
    /// bytes of the last LOAD or STORE of the last instruction, 0 without one
    pub mem_size: u32,
    /// the memory the last instruction read or wrote through an address the fold knows (a
    /// constant a register holds): (address, bytes, written)
    pub data: Vec<(u32, u32, bool)>,
    /// `AND ESP,mask` keeps a stack address (the mask applies to its offset), as Ghidra's
    /// stack analysis has it; off for the walks of `propagate`
    stack_and: bool,
}

impl Fold {
    /// The offset from ESP at the entry that the 4-byte register at `reg` of the register
    /// space `rs` holds, where it holds a stack address.
    pub fn stack_offset(&self, rs: u32, reg: u64) -> Option<u32> {
        match self.regs.iter().find(|f| f.0 == rs && f.1 < reg + 4 && reg < f.1 + f.2 as u64) {
            Some(&(_, at, 4, Some(Val::S(0x10, d)), _)) if at == reg => Some(d),
            Some(_) => None,
            None => (reg == 0x10).then_some(0),
        }
    }
}

impl Ins {
    pub fn falls_through(&self) -> bool {
        !matches!(self.flow, Flow::Jump | Flow::JumpInd | Flow::Return)
    }
}

#[derive(Clone)]
pub struct Analysis {
    pub text_start: u32,
    pub text_end: u32,
    code_lo: u32, // span of the executable sections, which `owner` covers
    code_hi: u32,
    pub insns: BTreeMap<u32, Ins>,
    pub tables: HashMap<u32, Vec<u32>>, // switch jump -> case targets
    pub funcs: BTreeSet<u32>,
    pub noreturn: HashSet<u32>, // functions and IAT slots that do not return
    /// Calls of a non-returning function that keep their fallthrough: Java's setNoFallThru
    /// overrides only the calls of the address the no-return analyzer found, so the calls made
    /// before the mark to another thunk of the same function, or to the thunked function, fall
    /// through still (the disassembler overrides the calls it makes later: isNoReturnCall).
    pub fallthru: HashSet<u32>,
    /// Jumps through a slot past a function's entry, which Java's Reference analyzer may make
    /// a thunk (CreateThunkFunctionCmd.isThunk on the holding function, not ported).
    slot_jumps_inside: HashSet<u32>,
    pub bodies: BTreeMap<u32, Vec<u32>>, // function -> sorted instruction addresses
    pub table_slots: BTreeMap<u32, u32>, // Create Address Tables (`disassemble` with constants): slot -> pointer
    fpu_ip: Option<(u32, u64)>,          // FPUInstructionPointer, which x87 constructors set to inst_start
    purge: HashMap<u32, u32>,            // function -> bytes its RETs pop (RET n), where they agree
    /// The purge X86 Function Callee Purge set, by function (`callee_purge`); none is unknown.
    pub callee_purges: HashMap<u32, u32>,
    reg_space: u32,
    /// the local fold: register and pointer width, the stack pointer's offset, and the
    /// registers a call kills besides it (the default prototype's `<killedbycall>`)
    width: u32,
    sp: u64,
    killed: Vec<u64>,
    /// the default prototype's stackshift where its extrapop is known (x86-64-gcc.cspec: 8); the
    /// PE's `__stdcall` has an unknown one
    stackshift: Option<u32>,
    /// Flow overrides of the project store (`store.rs`), by instruction: CALL_RETURN (true) or
    /// none (false) in place of what `call_return` derives. Empty without a store.
    pub overrides: HashMap<u32, bool>,
    /// Bodies the store sets (inclusive address ranges) in place of the flow from the entry.
    pub fixed_bodies: BTreeMap<u32, Vec<(u32, u32)>>,
    /// Thunk marks of the store: the thunked function, or `None` for "not a thunk".
    pub thunks: HashMap<u32, Option<u32>>,
    /// The thunks CreateFunctionCmd made (`resolve_thunk`): thunk -> thunked function.
    pub thunk_of: BTreeMap<u32, u32>,
    /// During `run`: the function whose body holds each instruction (Ghidra's bodies do not
    /// overlap); emptied when `run` ends.
    body_owner: HashMap<u32, u32>,
    /// What `run` met that is not ported, one line each, for the caller to print.
    pub warnings: Vec<String>,
    /// decodes of a direct flow whose target is past 32 bits (out of the image), for a warning
    wide_flows: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

const MAX_STACK: [usize; 2] = [16, 1024]; // local fold, whole-function walk
const MAX_MEM: [usize; 2] = [64, 1024];

/// Ghidra's list for ELF (noReturnFunctionConstraints.xml), read as data at build time
const ELF_NORETURN: &str = include_str!("../../../Ghidra/Features/Base/data/ElfFunctionsThatDoNotReturn");
/// The x86-64 System V compiler spec of x86:LE:64:default:gcc, read as data at build time
pub const X86_64_GCC_CSPEC: &str = include_str!("../../../Ghidra/Processors/x86/data/languages/x86-64-gcc.cspec");

const KNOWN_NORETURN: [&str; 9] = [
    "ExitProcess",
    "ExitThread",
    "exit",
    "_exit",
    "abort",
    "_amsg_exit",
    "RaiseException",
    "_CxxThrowException",
    "FatalAppExitA",
];

// x86win_patterns.xml, the two <patternpairs> whose matches are definite function starts.
// Pattern bytes are (value, mask); prepatterns end right before the candidate.
type Pat = &'static [(u8, u8)];
const PRE_FILL: [Pat; 6] = [
    &[(0xcc, 0xff)],
    &[(0xcc, 0xff), (0xcc, 0xff)],
    &[(0x90, 0xff)],
    &[(0xc3, 0xff)],
    &[(0xc9, 0xff), (0xc3, 0xff)],
    &[(0xc2, 0xff), (0, 0x03), (0, 0xff)],
];
const PRE_JMP: [Pat; 2] = [&[(0xe9, 0xff), (0, 0), (0, 0), (0, 0), (0, 0)], &[(0xeb, 0xff), (0, 0)]];
const POST_FILL: [Pat; 19] = [
    &[(0x55, 0xff), (0x8b, 0xff), (0xec, 0xff)],
    &[(0x55, 0xff), (0x89, 0xff), (0xe5, 0xff)],
    &[(0x83, 0xff), (0xec, 0xff), (0x00, 0x83)],
    &[
        (0x6a, 0xff),
        (0xff, 0xff),
        (0x68, 0xff),
        (0, 0),
        (0, 0),
        (0, 0),
        (0, 0),
        (0x64, 0xff),
        (0xa1, 0xff),
        (0, 0xff),
        (0, 0xff),
        (0, 0xff),
        (0, 0xff),
    ],
    &[(0x56, 0xff), (0x8b, 0xff), (0xf1, 0xff)],
    &[(0xb8, 0xff), (0, 0), (0, 0), (0, 0), (0, 0), (0xe8, 0xff)],
    &[(0x8b, 0xff), (0xff, 0xff), (0x55, 0xff), (0x8b, 0xff), (0xec, 0xff)],
    &[(0x53, 0xff), (0x8b, 0xff), (0xd8, 0xfc)],
    &[(0x53, 0xff), (0x56, 0xff), (0x57, 0xff)],
    &[(0x53, 0xff), (0x55, 0xff), (0x56, 0xff)],
    &[(0x53, 0xff), (0x56, 0xff), (0x51, 0xff)],
    &[(0x53, 0xff), (0x56, 0xff), (0x8b, 0xff), (0xf2, 0xff)],
    &[(0x53, 0xff), (0x56, 0xff), (0x8b, 0xff), (0xd8, 0xff)],
    &[(0x53, 0xff), (0x56, 0xff), (0x8b, 0xff), (0xf1, 0xff)],
    &[(0x53, 0xff), (0x56, 0xff), (0x8b, 0xff), (0xda, 0xff)],
    &[(0x53, 0xff), (0x56, 0xff), (0x8b, 0xff), (0xf0, 0xff)],
    &[(0x56, 0xff), (0x57, 0xff), (0x8b, 0xff), (0xf9, 0xff)],
    &[(0x56, 0xff), (0x57, 0xff), (0x8b, 0xff), (0xf1, 0xff)],
    &[(0x55, 0xff), (0x57, 0xff), (0x56, 0xff), (0x53, 0xff)],
];
const POST_JMP: [Pat; 4] = [POST_FILL[0], POST_FILL[4], POST_FILL[5], POST_FILL[6]];

fn matches(bytes: &[u8], pat: Pat) -> bool {
    bytes.len() >= pat.len() && pat.iter().zip(bytes).all(|(&(v, m), &b)| b & m == v & m)
}

/// PatternPairSet.createFinalPatterns: a prepattern/postpattern pair of `<patternpairs
/// totalbits="32" postbits="16">` is a pattern only when the postpattern has 16 fixed bits and
/// both together 32 (`getNumFixedBits`); e.g. `CC` + `SUB ESP,small` (8 + 19 bits) is none.
/// True when such a pair matches with the postpattern at `d[o]`.
fn pair_hit(d: &[u8], o: usize, pres: &[Pat], posts: &[Pat]) -> bool {
    let bits = |p: Pat| p.iter().map(|&(_, m)| m.count_ones()).sum::<u32>();
    pres.iter().filter(|p| o >= p.len() && matches(&d[o - p.len()..o], p)).any(|&pre| {
        posts.iter().any(|&post| bits(post) >= 16 && bits(pre) + bits(post) >= 32 && matches(&d[o..], post))
    })
}

impl Analysis {
    pub fn is_text(&self, a: u32) -> bool {
        a >= self.text_start && a < self.text_end
    }

    fn is_code(&self, img: &Image, a: u32) -> bool {
        a >= self.code_lo && a < self.code_hi && img.block_of(a).is_some_and(|s| s.exec)
    }

    /// Discover code and functions from exports, the entry point, RTTI vftables, call targets,
    /// prologue patterns and far jumps, then compute function bodies. `extra` entries are
    /// disassembled and made functions too; with `exact`, they are the whole function set.
    pub fn run(img: &Image, sl: &Sleigh, extra: &[u32], exact: bool) -> Result<Analysis, String> {
        let text = img.section(".text").ok_or("no .text section")?;
        let exec = || img.sections.iter().filter(|s| s.exec);
        let mut an = Analysis {
            text_start: text.addr,
            text_end: text.addr + text.data.len() as u32,
            code_lo: exec().map(|s| s.addr).min().unwrap_or(0),
            code_hi: exec().map(|s| s.addr + s.data.len() as u32).max().unwrap_or(0),
            insns: BTreeMap::new(),
            tables: HashMap::new(),
            funcs: BTreeSet::new(),
            noreturn: HashSet::new(),
            fallthru: HashSet::new(),
            slot_jumps_inside: HashSet::new(),
            bodies: BTreeMap::new(),
            table_slots: BTreeMap::new(),
            fpu_ip: None,
            purge: HashMap::new(),
            callee_purges: HashMap::new(),
            reg_space: 0,
            width: 4,
            sp: 0x10,
            killed: vec![0, 4, 8],
            stackshift: None,
            overrides: HashMap::new(),
            fixed_bodies: BTreeMap::new(),
            thunks: HashMap::new(),
            thunk_of: BTreeMap::new(),
            body_owner: HashMap::new(),
            warnings: Vec::new(),
            wide_flows: Default::default(),
        };
        let (rs, list) = sl.registers();
        an.fpu_ip = list.iter().find(|r| r.0 == "FPUInstructionPointer").map(|r| (rs, r.1));
        an.reg_space = rs;
        if img.elf64 {
            // the fold of x86-64: 8-byte registers, RSP, and the `<killedbycall>` registers of
            // x86-64-gcc.cspec's default prototype (x86win.cspec's EAX, ECX, EDX for the PE)
            let reg = |n: &str| list.iter().find(|r| r.0 == n).map(|r| r.1).ok_or(format!("no register {n}"));
            an.width = 8;
            an.sp = reg("RSP")?;
            let root = crate::xml::parse(X86_64_GCC_CSPEC).map_err(|e| format!("x86-64-gcc.cspec: {e}"))?;
            let proto = root
                .kid("default_proto")
                .and_then(|d| d.kid("prototype"))
                .ok_or("x86-64-gcc.cspec: no default prototype")?;
            let killed =
                proto.kid("killedbycall").map(|k| k.kids_named("register").collect::<Vec<_>>()).unwrap_or_default();
            an.stackshift = (proto.attr("extrapop") != Some("unknown"))
                .then(|| proto.attr("stackshift").and_then(|s| s.parse().ok()))
                .flatten();
            an.killed.clear();
            for r in killed {
                let (off, size) = list
                    .iter()
                    .find(|x| Some(x.0) == r.attr("name"))
                    .map(|x| (x.1, x.2))
                    .ok_or("x86-64-gcc.cspec: unknown killedbycall register")?;
                // the vector registers lie past the integer ones the fold keeps
                if size == 8 {
                    an.killed.push(off);
                }
            }
            // NoReturnFunctionAnalyzer with ElfFunctionsThatDoNotReturn: a symbol whose name,
            // leading '_'s stripped, is on the list (or starts with a name ending in '*')
            let names: Vec<&str> =
                ELF_NORETURN.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')).collect();
            let listed = |n: &str| {
                let n = n.trim_start_matches('_');
                names.iter().any(|&l| l == n || l.strip_suffix('*').is_some_and(|p| n.starts_with(p)))
            };
            let named = img.imports.iter().map(|(&s, (_, n))| (s, n)).chain(img.elf_funcs.iter().map(|(a, n)| (*a, n)));
            an.noreturn.extend(named.filter(|(_, n)| listed(n)).map(|(a, _)| a).collect::<Vec<_>>());
            an.warnings.push(
                "not ported for x86-64: Function Start Search (x86-64gcc_patterns.xml), Function ID, the PLT markup, the EXTERNAL block (in the facts only), DWARF; the X86 Function Callee Purge analyzer does not run on 64-bit (Java's canAnalyze)"
                    .into(),
            );
            if img.unapplied_relocs > 0 {
                an.warnings.push(format!("not ported: {} ELF dynamic relocations not applied", img.unapplied_relocs));
            }
        }
        for (slot, (_, name)) in img.imports.iter().filter(|_| !img.elf64) {
            if KNOWN_NORETURN.contains(&name.as_str()) {
                an.noreturn.insert(*slot);
            }
        }
        let mut seeds: Vec<u32> = img
            .elf_funcs
            .iter()
            .chain(&img.exports)
            .map(|e| e.0)
            .chain(img.entry)
            .chain(extra.iter().copied())
            .collect();
        seeds.retain(|&a| an.is_code(img, a));
        // RTTI vftable slots: the RTTI analyzer (599) makes a function of each
        // (`EHDataTypeUtilities.createFunctionIfNeeded`); MSVC's, so not on ELF
        let mut rtti = Vec::new();
        let tables = if img.elf64 { BTreeMap::new() } else { crate::scripts::vftables(img) };
        for &v in tables.keys() {
            for i in 0..4096 {
                match img.read_u32(v + 4 * i) {
                    Some(t) if an.is_code(img, t) && (i == 0 || !tables.contains_key(&(v + 4 * i))) => rtti.push(t),
                    _ => break,
                }
            }
        }
        let mut p = sl.new_parse();
        // 1: instruction start, 2: inside an instruction, 3: switch table
        let mut owner = vec![0u8; (an.code_hi - an.code_lo) as usize];
        let mut queue: Vec<u32> = Vec::new();
        let mut tables_queue: Vec<u32> = Vec::new();
        // Create Address Tables: runs of 2+ code pointers in data are disassembled after
        // everything else, without making functions. (Making functions of lone pointers or of
        // referenced tables matched Ghidra worse: more extra functions than found ones.)
        let w = img.ptr_size() as usize;
        for sec in img.sections.iter().filter(|s| !s.exec && s.name != "Headers") {
            let mut run = Vec::new();
            for o in (0..sec.data.len().saturating_sub(w - 1) + w).step_by(w) {
                let t = sec.data.get(o..o + w).and_then(ptr_value).unwrap_or(0);
                if an.is_code(img, t) {
                    run.push(t);
                    continue;
                }
                if run.len() >= 2 {
                    tables_queue.extend(&run);
                }
                run.clear();
            }
        }
        // Discovery's analyzers, run by Ghidra's task queue at Ghidra's priorities. Disassembly
        // and Subroutine References (a function at each call target) are `descend`, inside the
        // analyzer that brings the code.
        #[derive(Clone, Copy)]
        enum Task {
            EntryPoints,
            StartSearch,
            Rtti,
            AddressTables,
            StartSearchAfterData,
            SharedReturns,
            SlotJumps,
            Purge,
        }
        let analyzer = |name, kind, priority, id| Analyzer { name, kind, priority, id };
        let mut mgr = Manager::new(vec![
            // Not Java's analyzers, the old discovery at their priorities (to port):
            // - Disassemble Entry Points: EntryPointAnalyzer's do-later set (suspect entries,
            //   REFERENCE_ANALYSIS.before()) is not modelled; all seeds go in at 200.
            // - Function Start Search (402): one search, disassembly inline, skipping covered
            //   bytes and repeating until nothing is new; Java searches once and queues
            //   DisassembleCommand and CreateFunctionCmd at priority - 2 and - 1.
            // - Function Start Search After Data (898): the same full sweep, ignoring its set;
            //   Java's FunctionStartDataPostAnalyzer searches only the added data for the
            //   after="data" patterns, and its notify set here is the table targets, not new data.
            // with External Entry References: the seeds
            analyzer("Disassemble Entry Points", Kind::Byte, priority::BLOCK_ANALYSIS, Task::EntryPoints),
            analyzer("Function Start Search", Kind::Byte, priority::CODE_ANALYSIS + 2, Task::StartSearch),
            analyzer("RTTI Analyzer", Kind::Byte, priority::REFERENCE_ANALYSIS - 1, Task::Rtti),
            analyzer("Create Address Tables", Kind::Byte, priority::DATA_TYPE_PROPOGATION - 1, Task::AddressTables),
            analyzer(
                "Function Start Search After Data",
                Kind::Data,
                priority::DATA_TYPE_PROPOGATION - 2,
                Task::StartSearchAfterData,
            ),
            // CODE_ANALYSIS.before().before(): on each batch of functions added or with a changed body
            analyzer("Shared Return Calls", Kind::Function, priority::CODE_ANALYSIS - 2, Task::SharedReturns),
            analyzer("X86 Function Callee Purge", Kind::Function, priority::FUNCTION_ANALYSIS, Task::Purge),
            // ConstantPropagationAnalyzer (REFERENCE_ANALYSIS.before() x4) on each batch: only its
            // jumps through a pointer, with the thunks the Reference analyzer makes of them
            analyzer("Constant Reference Analyzer", Kind::Function, priority::REFERENCE_ANALYSIS - 4, Task::SlotJumps),
        ]);
        // ElfDefaultGotPltMarkup.processPLTSection at load: `.plt` past its first 16 bytes is
        // disassembled, following flows, from each byte no instruction covers yet; the first
        // address that decodes nothing ends it (processLinkageTable). No function is made.
        if let Some(plt) = img.section(".plt").filter(|s| img.elf64 && s.exec && s.data.len() > 16) {
            let (mut a, end) = (plt.addr + 16, plt.addr + plt.data.len() as u32);
            while a < end {
                queue.push(a);
                an.descend(img, sl, &mut p, &mut owner, &mut queue, &mut Vec::new());
                if owner[(a - an.code_lo) as usize] == 0 {
                    break;
                }
                while a < end && owner[(a - an.code_lo) as usize] != 0 {
                    a += 1;
                }
            }
        }
        mgr.notify(Kind::Byte, &exec().map(|s| s.addr).collect());
        // with `exact`, only the given functions are made (CreateFunctionCmd)
        let allowed: Option<HashSet<u32>> = exact.then(|| extra.iter().copied().collect());
        // the non-returning functions the bodies go by (FindNoReturnFunctionsAnalyzer's side);
        // discovery's disassembly goes by `an.noreturn`, the imports'
        let mut body_noreturn = an.noreturn.clone();
        // the instructions the no-return analyzer looked at, and INT3 (checkNonReturningIndicators)
        let mut noreturn_seen = HashSet::new();
        let int3 = |a: u32| img.block_of(a).is_some_and(|s| s.data[(a - s.addr) as usize] == 0xcc);
        let mut repair = repair::RepairCounts::default();
        while let Some((task, set)) = mgr.next_task() {
            let mut data = BTreeSet::new();
            // (thunk, target) of SlotJumps: the target is made with the task's new functions
            let mut slot_thunks = Vec::new();
            match task {
                Task::EntryPoints => {
                    for &s in &seeds {
                        an.funcs.insert(s);
                        queue.push(s);
                    }
                    an.descend(img, sl, &mut p, &mut owner, &mut queue, &mut Vec::new());
                }
                Task::Rtti => {
                    for &s in &rtti {
                        an.funcs.insert(s);
                        queue.push(s);
                    }
                    an.descend(img, sl, &mut p, &mut owner, &mut queue, &mut Vec::new());
                }
                // the tables come after everything the seeds reach, so stray pointers cannot
                // claim their bytes
                Task::AddressTables => {
                    data.extend(&tables_queue);
                    queue.append(&mut tables_queue);
                    an.descend(img, sl, &mut p, &mut owner, &mut queue, &mut Vec::new());
                }
                // x86win_patterns.xml is the PE's; x86-64gcc_patterns.xml is not ported (warned)
                Task::StartSearch | Task::StartSearchAfterData if img.elf64 => {}
                Task::StartSearch | Task::StartSearchAfterData => {
                    an.start_search(img, sl, &mut p, &mut owner, &mut queue)
                }
                Task::SharedReturns => an.shared_returns(&set),
                Task::SlotJumps => slot_thunks = an.slot_jumps(img, sl, &mut p, &mut owner, &set),
                // X86FunctionPurgeAnalyzer.canAnalyze: 32-bit only
                Task::Purge if img.elf64 => {}
                Task::Purge => an.callee_purge(img, &set, &body_noreturn),
            }
            mgr.notify(Kind::Data, &data);
            // CreateFunctionCmd on the functions the task found, in address order, then the
            // no-return repairs. AutoAnalysisManager sends FUNCTION_ADDED and
            // FUNCTION_BODY_CHANGED alike to functionDefined: the function analyzers get the
            // functions made and the ones whose body was set (the purge sets none)
            if !matches!(task, Task::Purge) {
                let known = std::mem::replace(&mut an.noreturn, std::mem::take(&mut body_noreturn));
                let mut defined = BTreeSet::new();
                let new: Vec<u32> = an.funcs.iter().copied().filter(|f| !an.bodies.contains_key(f)).collect();
                for f in new {
                    an.create_function(f, allowed.as_ref(), &mut Vec::new(), &mut defined);
                }
                // CreateFunctionCmd again on the function, now a thunk (functionDefined)
                for (f, t) in slot_thunks {
                    if an.bodies.contains_key(&t) && an.thunked_end(t) != f {
                        an.thunk_of.insert(f, t);
                        defined.insert(f);
                    }
                }
                let mut found = an.find_noreturn(&mut defined, &mut noreturn_seen, &int3);
                // Repair Flow Damage, then what its disassembly feeds: Subroutine References'
                // functions at the new calls, the no-return analyzer on the instructions
                // cleared, re-disassembled or handed to codeDefined
                let mut cx =
                    repair::Repair::new(img, sl, &mut p, &mut owner, allowed.as_ref(), &mut defined, &mut repair);
                while !found.is_empty() {
                    let before = an.funcs.clone();
                    let again = an.repair_flow_damage(&mut cx, &found)?;
                    if again.is_empty() {
                        break;
                    }
                    noreturn_seen.retain(|a| !again.contains(a));
                    let new: Vec<u32> =
                        an.funcs.difference(&before).copied().filter(|f| !an.bodies.contains_key(f)).collect();
                    for f in new {
                        an.create_function(f, allowed.as_ref(), &mut Vec::new(), cx.changed);
                    }
                    found = an.find_noreturn(cx.changed, &mut noreturn_seen, &int3);
                }
                body_noreturn = std::mem::replace(&mut an.noreturn, known);
                mgr.notify(Kind::Function, &defined);
            }
        }
        if exact {
            an.funcs = extra.iter().copied().filter(|a| an.insns.contains_key(a)).collect();
            an.bodies.retain(|f, _| an.funcs.contains(f));
        }
        an.noreturn = body_noreturn;
        if repair.runs > 0 {
            an.warnings.push(format!(
                "Repair Flow Damage (ClearFlowAndRepairCmd): {} runs, {} instructions cleared, {} functions removed, {} instructions disassembled again",
                repair.runs, repair.cleared, repair.removed, repair.redisassembled
            ));
        }
        if !repair.data.is_empty() {
            an.warnings.push(format!(
                "not ported: Repair Flow Damage clearing data (addDereferencedInstructionStarts): {} pointer data addresses (Create Address Tables, switch tables) only cleared code refers to, which Java clears",
                repair.data.len()
            ));
        }
        if !repair.data_refs.is_empty() {
            an.warnings.push(format!(
                "not modelled: Repair Flow Damage: {} addresses where a reference from a code pointer in data (outside Create Address Tables' runs; Java has it where it made pointer data) would change a prune, a dereferenced start or a block start",
                repair.data_refs.len()
            ));
        }
        if repair.unordered > 0 {
            an.warnings.push(format!(
                "not ported: Repair Flow Damage: {} subroutines whose new functions Java makes in a treeified HashSet bucket's order (address order here)",
                repair.unordered
            ));
        }
        if !repair.stale.is_empty() {
            an.warnings.push(format!(
                "Repair Flow Damage: {} function bodies keep the cleared bytes in Java (no repaired subroutine reaches them); here they lose them",
                repair.stale.len()
            ));
        }
        if repair.overlap > 0 {
            an.warnings.push(format!(
                "Repair Flow Damage: {} repaired bodies overlap another function and stay as they were (OverlappingFunctionException)",
                repair.overlap
            ));
        }
        if !an.slot_jumps_inside.is_empty() {
            an.warnings.push(format!(
                "not ported: CreateThunkFunctionCmd.isThunk for a jump through a slot past the entry: {} such jumps, no thunk made here",
                an.slot_jumps_inside.len()
            ));
        }
        an.body_owner = HashMap::new();
        // a thunk's purge is its thunked function's (FunctionDB.getStackPurgeSize)
        let thunked: Vec<(u32, u32)> = an.thunk_of.keys().map(|&f| (f, an.thunked_end(f))).collect();
        let long = thunked.iter().filter(|(_, t)| an.thunk_of.contains_key(t)).count();
        if long > 0 {
            an.warnings.push(format!("{long} thunk chains are longer than 16 thunks; their purge is cut short"));
        }
        for (f, t) in thunked {
            if let Some(&n) = an.callee_purges.get(&t) {
                an.callee_purges.insert(f, n);
            }
        }
        // two thunk definitions: the purges go by `thunk_of`, the facts' names and
        // `Project::thunked` by a body of one direct jump to a function
        let (only_made, only_one_jump) = an.bodies.iter().fold((0, 0), |(m, o), (&f, b)| {
            let i = &an.insns[&f];
            let target = match (i.flow, i.slot) {
                (Flow::Jump, _) => i.target,
                // through a pointer that holds a function's entry (the facts' SecuROM slots)
                (Flow::JumpInd, Some(s)) if !img.imports.contains_key(&s) => img.read_ptr(s),
                _ => None,
            };
            let one_jump = b.len() == 1 && target.is_some_and(|t| t != f && an.funcs.contains(&t));
            match (an.thunk_of.contains_key(&f), one_jump) {
                (true, false) => (m + 1, o),
                (false, true) => (m, o + 1),
                _ => (m, o),
            }
        });
        if only_made + only_one_jump > 0 {
            an.warnings.push(format!(
                "thunks disagree: {only_made} made by CreateFunctionCmd (thunk_of, the purges) are no one-jump body (the facts' names), {only_one_jump} one-jump bodies were not made thunks"
            ));
        }
        // getThunkedAddr steps over an entry instruction without p-code (`NOP; JMP x` is a thunk
        // of x); resolve_thunk does not. Counted for the one-byte NOP only
        let nop_thunks = an
            .bodies
            .keys()
            .filter(|&&f| {
                img.block_of(f).is_some_and(|s| s.data.get((f - s.addr) as usize) == Some(&0x90))
                    && an.insns.get(&(f + 1)).is_some_and(|i| i.flow == Flow::Jump)
            })
            .count();
        if nop_thunks > 0 {
            an.warnings.push(format!(
                "not ported: getThunkedAddr past a no-p-code entry instruction: {nop_thunks} functions start `NOP; JMP` and are no thunks here"
            ));
        }
        let wide = an.wide_flows.load(std::sync::atomic::Ordering::Relaxed);
        if wide > 0 {
            an.warnings
                .push(format!("{wide} decodes of a direct flow past 32 bits (out of the image): no target made"));
        }
        an.stack_purges(img);
        Ok(an)
    }

    /// X86 Function Callee Purge (`FunctionPurgeAnalysisCmd`) on the functions added or with a
    /// changed body since its last turn, in address order (`analyzeFunction`). Only a purge
    /// that is unknown (or past 128) is looked for; a thunk's purge is its thunked function's,
    /// read and set (`FunctionDB.getStackPurgeSize`). The purge instruction is searched in the
    /// body, else in the flow from the entry (`locatePurgeInstruction`); its value is the RET's
    /// operand, or for a CALL_RETURN flow the purge the function it reaches has at this moment
    /// (none for a non-returning one). `body_noreturn`: the non-returning functions the
    /// bodies go by.
    // ponytail: the non-returning functions are this analysis's rule on the bodies (Java's
    // analyzer runs at 302 with its own rule)
    fn callee_purge(&mut self, img: &Image, set: &BTreeSet<u32>, body_noreturn: &HashSet<u32>) {
        let known = std::mem::replace(&mut self.noreturn, body_noreturn.clone());
        for &f in set.iter().filter(|f| self.bodies.contains_key(f)) {
            let at = self.thunked_end(f);
            if self.callee_purges.get(&at).is_some_and(|&n| n <= 128) {
                continue;
            }
            let found = self.purge_insn(img, &self.bodies[&f]).or_else(|| {
                let flow = self.walk(f, |a| self.bodies.contains_key(&a));
                self.purge_insn(img, &flow)
            });
            if let Some(n) = found.and_then(|(a, n)| n.or_else(|| self.call_purge(a))) {
                self.callee_purges.insert(at, n);
            }
        }
        self.noreturn = known;
    }

    /// findPurgeInstruction: the first RET or RETF of `body` by address, among its first 2048
    /// instructions, with its operand; else the last CALL_RETURN flow (CALL_TERMINATOR or
    /// COMPUTED_CALL_TERMINATOR), without a value.
    fn purge_insn(&self, img: &Image, body: &[u32]) -> Option<(u32, Option<u32>)> {
        let mut backup = None;
        for &a in body.iter().take(2048) {
            let i = &self.insns[&a];
            if i.flow == Flow::Return {
                let sec = img.block_of(a)?;
                let b = &sec.data[(a - sec.addr) as usize..];
                let b = &b[b.iter().take_while(|&&x| matches!(x, 0xf2 | 0xf3 | 0x66)).count()..];
                // an IRET is no "ret" or "retf": the search goes on
                match b {
                    [0xc2 | 0xca, lo, hi, ..] => return Some((a, Some(u16::from_le_bytes([*lo, *hi]) as u32))),
                    [0xc3 | 0xcb, ..] => return Some((a, Some(0))),
                    _ => continue,
                }
            }
            if matches!(i.flow, Flow::Jump | Flow::Call | Flow::CallInd | Flow::JumpInd) && self.call_return(a, i) {
                backup = Some((a, None));
            }
        }
        backup
    }

    /// getPurgeValue of a CALL_RETURN flow: the purge of the function at its target, unless
    /// that function does not return.
    fn call_purge(&self, a: u32) -> Option<u32> {
        let t = self.insns[&a].target.filter(|t| self.bodies.contains_key(t) && !self.noreturn.contains(t))?;
        self.callee_purges.get(&self.thunked_end(t)).copied()
    }

    /// The function a chain of thunks made by `resolve_thunk` ends at (`f` itself if none).
    fn thunked_end(&self, mut f: u32) -> u32 {
        for _ in 0..16 {
            match self.thunk_of.get(&f) {
                Some(&t) => f = t,
                None => break,
            }
        }
        f
    }

    /// CreateFunctionCmd at `f`, a function with an instruction and no body yet: the flow from
    /// the entry up to the entries of the functions made so far (getFunctionBody), less what
    /// other bodies hold (subtractBodyFromExisting, which also cuts those bodies), made a thunk
    /// where the entry is a jump (resolveThunk); once more when the thunk's target, made
    /// meanwhile, overlaps the body (OverlappingFunctionException). `referring`: the thunks
    /// whose target this is (referringThunkAddresses); a body that holds one is no function.
    /// Bodies made or cut go to `changed`. With `allowed`, only those functions are made.
    fn create_function(
        &mut self,
        f: u32,
        allowed: Option<&HashSet<u32>>,
        referring: &mut Vec<u32>,
        changed: &mut BTreeSet<u32>,
    ) -> bool {
        if self.bodies.contains_key(&f) || !self.insns.contains_key(&f) || allowed.is_some_and(|s| !s.contains(&f)) {
            return false;
        }
        for _ in 0..2 {
            let body = self.walk(f, |a| self.bodies.contains_key(&a));
            let body = self.subtract_existing(f, body, changed);
            if let Some(b) = self.resolve_thunk(f, &body, allowed, referring, changed) {
                self.set_body(f, b, changed);
                return true;
            }
            if referring.iter().any(|r| body.binary_search(r).is_ok()) {
                return false;
            }
            if !body.iter().any(|a| self.body_owner.contains_key(a)) {
                self.set_body(f, body, changed);
                return true;
            }
        }
        false
    }

    /// subtractBodyFromExisting: each function whose body overlaps `body` loses the part from
    /// `f` to the end of `body` (it lies before `f`) or up to its own entry (it lies after);
    /// `body` loses what the function keeps.
    fn subtract_existing(&mut self, f: u32, mut body: Vec<u32>, changed: &mut BTreeSet<u32>) -> Vec<u32> {
        let over: BTreeSet<u32> =
            body.iter().filter_map(|a| self.body_owner.get(a).copied()).filter(|&g| g != f).collect();
        for g in over {
            let Some(&max) = body.last() else { break };
            let end = if g < f { max } else { g - 1 };
            if let Some(gb) = self.bodies.get_mut(&g) {
                let n = gb.len();
                gb.retain(|&a| {
                    let cut = (f..=end).contains(&a);
                    if cut {
                        self.body_owner.remove(&a);
                    }
                    !cut
                });
                if gb.len() != n {
                    changed.insert(g);
                }
            }
            body.retain(|a| self.body_owner.get(a) != Some(&g));
        }
        body
    }

    /// CreateFunctionCmd.resolveThunk with CreateThunkFunctionCmd: a function whose first
    /// instruction is a direct JMP (getSimpleFlow) is a thunk of the function at the target,
    /// made first where there is none (getReferencedFunction), but not where the target lies in
    /// another function's body, has no instruction, or is a thunk on the way. The thunk's body
    /// is `body` less the target's body; where `body` held the target, that must leave one
    /// range from the entry, else it must not overlap the target. Returns the thunk's body.
    fn resolve_thunk(
        &mut self,
        f: u32,
        body: &[u32],
        allowed: Option<&HashSet<u32>>,
        referring: &mut Vec<u32>,
        changed: &mut BTreeSet<u32>,
    ) -> Option<Vec<u32>> {
        let t = self.insns.get(&f).filter(|i| i.flow == Flow::Jump)?.target.filter(|&t| t != f)?;
        if referring.contains(&f) {
            return None;
        }
        if !self.bodies.contains_key(&t) {
            if self.body_owner.contains_key(&t) || !self.insns.contains_key(&t) || referring.contains(&t) {
                return None;
            }
            referring.push(f);
            let made = self.create_function(t, allowed, referring, changed);
            referring.pop();
            // getFunctionContaining(entry): the target's body may hold the entry now
            if !made || self.body_owner.contains_key(&f) {
                return None;
            }
        }
        let thunk: Vec<u32> = body.iter().copied().filter(|a| self.body_owner.get(a) != Some(&t)).collect();
        // createThunkFunction throws OverlappingFunctionException where the body holds a third
        // function's code (made with the target); CreateFunctionCmd tries again
        if thunk.iter().any(|a| self.body_owner.get(a).is_some_and(|&g| g != f)) {
            return None;
        }
        let one_range =
            thunk.first() == Some(&f) && thunk.windows(2).all(|w| w[0] + self.insns[&w[0]].len as u32 == w[1]);
        let held = body.binary_search(&t).is_ok();
        if held && !one_range || !held && thunk.len() != body.len() {
            return None;
        }
        self.thunk_of.insert(f, t);
        Some(thunk)
    }

    /// The target of a jump through a pointer (`JMP [slot]`, SecuROM's slots) as
    /// ConstantPropagationAnalyzer finds it: the slot's value (VarnodeContext reads writable
    /// memory, as the analyzer's "trust writable memory" default; an import slot is external),
    /// non-zero, in an executable block, not inside an instruction nor inside a function but at
    /// its entry (evaluatePureDataRef).
    fn slot_jump(&self, img: &Image, owner: &[u8], a: u32) -> Option<u32> {
        let i = self.insns.get(&a).filter(|i| i.flow == Flow::JumpInd)?;
        let s = i.slot.filter(|s| !img.imports.contains_key(s))?;
        let t = img.read_ptr(s).filter(|&t| t != 0 && self.is_code(img, t))?;
        let inside = owner[(t - self.code_lo) as usize] >= 2 || self.body_owner.get(&t).is_some_and(|&g| g != t);
        (!inside).then_some(t)
    }

    /// Constant propagation's computed jumps through a pointer on the functions of `set`: the
    /// COMPUTED_JUMP reference's target is disassembled (evaluateReference), and a function
    /// whose entry is such a jump becomes a thunk of it, its target made a function, as the
    /// Reference analyzer does (OperandReferenceAnalyzer: a computed jump of a function that
    /// is no thunk but CreateThunkFunctionCmd.isThunk, CreateFunctionCmd again). Returns
    /// (thunk, target); the targets are in `funcs`, for CreateFunctionCmd after the task.
    // ponytail: only jumps through a direct slot, with the slot's value as the image holds it
    // (Java's propagation would see a store to the slot earlier in the flow); and the thunk
    // step runs here, at 596, where Java's Reference analyzer (600) runs on code added.
    fn slot_jumps(
        &mut self,
        img: &Image,
        sl: &Sleigh,
        p: &mut crate::sleigh::Parse,
        owner: &mut [u8],
        set: &BTreeSet<u32>,
    ) -> Vec<(u32, u32)> {
        let jumps: Vec<(u32, u32)> = set
            .iter()
            .filter_map(|f| self.bodies.get(f))
            .flatten()
            .filter_map(|&a| self.slot_jump(img, owner, a).map(|t| (a, t)))
            .collect();
        let mut queue: Vec<u32> =
            jumps.iter().map(|&(_, t)| t).filter(|&t| owner[(t - self.code_lo) as usize] == 0).collect();
        self.descend(img, sl, p, owner, &mut queue, &mut Vec::new());
        let mut thunks = Vec::new();
        for (a, t) in jumps {
            // memRefs.length <= 2: the read of the slot and the COMPUTED_JUMP
            if self.insns[&a].refs.len() > 1 {
                continue;
            }
            // CreateThunkFunctionCmd.isThunk on the function holding a jump past its entry is
            // not ported (counted, `slot_jumps_inside`)
            if !set.contains(&a) {
                self.slot_jumps_inside.insert(a);
                continue;
            }
            if self.thunk_of.contains_key(&a) || t == a || !self.insns.contains_key(&t) {
                continue;
            }
            // getReferencedFunction: a function at the target, or none containing it
            if !self.bodies.contains_key(&t) {
                if self.body_owner.contains_key(&t) {
                    continue;
                }
                self.funcs.insert(t);
            }
            thunks.push((a, t));
        }
        thunks
    }

    /// Function.setBody (FUNCTION_BODY_CHANGED; a new function's body with FUNCTION_ADDED).
    fn set_body(&mut self, f: u32, body: Vec<u32>, changed: &mut BTreeSet<u32>) {
        for a in self.bodies.get(&f).into_iter().flatten() {
            if self.body_owner.get(a) == Some(&f) {
                self.body_owner.remove(a);
            }
        }
        for &a in &body {
            self.body_owner.insert(a, f);
        }
        self.bodies.insert(f, body);
        self.funcs.insert(f);
        changed.insert(f);
    }

    /// CreateFunctionCmd.fixupFunctionBody: the flow from the entry, as at creation; a
    /// function that is no thunk and whose entry jumps to a function becomes its thunk
    /// (resolveThunk); a body that overlaps others cuts them as at creation.
    // ponytail: the thunk case takes a target that is a function already and a body that
    // overlaps none; Java's would make the target and set the thunk even where the body then
    // fails (CreateThunkFunctionCmd.applyTo on an existing function)
    fn fixup_body(&mut self, f: u32, changed: &mut BTreeSet<u32>) {
        let new = self.walk(f, |a| self.bodies.contains_key(&a));
        let overlaps = new.iter().any(|a| self.body_owner.get(a).is_some_and(|&g| g != f));
        if !self.thunk_of.contains_key(&f) && !overlaps {
            let i = &self.insns[&f];
            if let Some(t) = i
                .target
                .filter(|t| i.flow == Flow::Jump && *t != f && self.bodies.contains_key(t) && self.thunked_end(*t) != f)
            {
                self.thunk_of.insert(f, t);
                if self.bodies.get(&f) != Some(&new) {
                    self.set_body(f, new, changed);
                }
                return;
            }
        }
        if new.is_empty() || self.bodies.get(&f) == Some(&new) {
            return;
        }
        let new = if overlaps { self.subtract_existing(f, new, changed) } else { new };
        self.set_body(f, new, changed);
    }

    /// FindNoReturnFunctionsAnalyzer.added: the call sites of `seen`'s complement (the
    /// instructions this analyzer has not looked at, its `set`) give evidence that a target does
    /// not return (`checkNonReturningIndicators`); a target with 3 callers that do (the evidence
    /// threshold) or that only calls non-returning functions (`targetOnlyCallsNoReturn`) is
    /// marked, again once more if some stayed suspicious. A mark on a thunk is its thunked
    /// function's (FunctionDB.setNoReturn), and so on every thunk of it. The calls of an address
    /// found lose their fallthrough (`setNoFallThru`) and the functions holding them get their
    /// bodies fixed up (`fixCallingFunctionBody`); the calls of the other addresses marked keep
    /// theirs (`fallthru`). Bodies set go to `changed`. `int3`: the instruction at an address is
    /// INT3.
    // ponytail: run after each batch of functions made, where Java's instruction analyzer runs
    // on instructions added (DISASSEMBLY + 2), so the functions it sees may differ;
    // "Repair Flow Damage" follows (`repair_flow_damage`, on the addresses returned); not
    // ported: a function made at a target that is none (setFunctionNonReturning), nor the
    // call-fixup exception
    fn find_noreturn(
        &mut self,
        changed: &mut BTreeSet<u32>,
        seen: &mut HashSet<u32>,
        int3: &dyn Fn(u32) -> bool,
    ) -> BTreeSet<u32> {
        // the references the analyzer reads: calls (with computed ones) and reads or writes
        let mut calls_to: HashMap<u32, Vec<u32>> = HashMap::new();
        let mut data_to: HashMap<u32, Vec<u32>> = HashMap::new();
        for (&a, i) in &self.insns {
            if let Some(t) = self.call_flows(i) {
                calls_to.entry(t).or_default().push(a);
            }
            for &t in i.refs.iter().filter(|&&t| self.insns.contains_key(&t)) {
                data_to.entry(t).or_default().push(a);
            }
        }
        let set: Vec<u32> = self.insns.keys().copied().filter(|a| !seen.contains(a)).collect();
        seen.extend(&set);
        let mut found = BTreeSet::new();
        for _ in 0..2 {
            if !self.detect_noreturn(&set, &calls_to, &data_to, &mut found, int3) {
                break;
            }
        }
        if found.is_empty() {
            return found;
        }
        let ends: HashSet<u32> = found.iter().map(|&t| self.thunked_end(t)).collect();
        let marked: Vec<u32> =
            self.bodies.keys().chain(&found).copied().filter(|&f| ends.contains(&self.thunked_end(f))).collect();
        // setNoFallThru on the calls of the addresses found; the calls of the other addresses
        // marked (FunctionDB's flag is the thunked function's) keep their fallthrough
        for m in marked.iter().filter(|m| !found.contains(m) && !self.noreturn.contains(m)) {
            self.fallthru.extend(calls_to.get(m).into_iter().flatten().filter(|c| self.insns[c].flow == Flow::Call));
        }
        for t in &found {
            for c in calls_to.get(t).into_iter().flatten() {
                self.fallthru.remove(c);
            }
        }
        self.noreturn.extend(&marked);
        // fixCallingFunctionBody: the functions holding a call of an address found
        let callers: BTreeSet<u32> = found
            .iter()
            .flat_map(|t| calls_to.get(t).into_iter().flatten())
            .filter_map(|a| self.body_owner.get(a).copied())
            .collect();
        for g in callers {
            self.fixup_body(g, changed);
        }
        found
    }

    /// The call targets of an instruction (Instruction.getFlows, getAllFlows): the direct one,
    /// or the computed one of an indirect call.
    fn call_flows(&self, i: &Ins) -> Option<u32> {
        match i.flow {
            Flow::Call => i.target,
            Flow::CallInd => i.computed,
            _ => None,
        }
    }

    /// A function that does not return: marked, or a thunk of one (Function.hasNoReturn).
    pub fn is_noreturn(&self, f: u32) -> bool {
        let t = self.thunked_end(f);
        self.noreturn.contains(&f) || self.noreturn.contains(&t) || self.width == 8 && self.import_thunk_noreturn(t)
    }

    /// A function of one `JMP [slot]` through a non-returning import's slot: Ghidra makes it a
    /// thunk of the external function (CreateThunkFunctionCmd.getThunkedExternalFunction),
    /// whose no-return flag it takes. ELF only (a PLT entry); the PE path keeps its rule.
    fn import_thunk_noreturn(&self, f: u32) -> bool {
        self.slot_thunk(f).is_some_and(|s| self.noreturn.contains(&s))
    }

    /// The slot of a function whose body is one `JMP [slot]`; on x86-64 also one after an
    /// entry instruction without p-code (`ENDBR64; BND JMP [slot]` of `.plt.sec`), which
    /// CreateThunkFunctionCmd.getThunkedAddr steps over (CreateThunkFunctionCmd.java:568-572).
    /// The PE path keeps the one-instruction body.
    pub fn slot_thunk(&self, f: u32) -> Option<u32> {
        let (body, first) = (self.bodies.get(&f)?, self.insns.get(&f)?);
        let (jmp, n) = match first.nop && self.width == 8 {
            true => (self.insns.get(&(f + first.len as u32))?, 2),
            false => (first, 1),
        };
        (body.len() == n && jmp.flow == Flow::JumpInd).then_some(jmp.slot).flatten()
    }

    /// detectNoReturn: one pass over the calls of `set`; true if a suspicious target stayed
    /// under the threshold.
    fn detect_noreturn(
        &self,
        set: &[u32],
        calls_to: &HashMap<u32, Vec<u32>>,
        data_to: &HashMap<u32, Vec<u32>>,
        found: &mut BTreeSet<u32>,
        int3: &dyn Fn(u32) -> bool,
    ) -> bool {
        const THRESHOLD: usize = 3;
        let mut checked = HashSet::new();
        let mut suspicious = false;
        for &a in set {
            if !checked.insert(a) {
                continue;
            }
            let i = &self.insns[&a];
            // a call with a fallthrough (a CALL_RETURN override has none)
            if !matches!(i.flow, Flow::Call | Flow::CallInd) || self.call_return(a, i) {
                continue;
            }
            if !self.noreturn_indicators(a, data_to, calls_to, int3) {
                continue;
            }
            let Some(t) = self.call_flows(i) else { continue };
            let mut count = 1;
            for &from in calls_to.get(&t).into_iter().flatten() {
                if !checked.insert(from) || found.contains(&t) {
                    continue;
                }
                if !self.noreturn_indicators(from, data_to, calls_to, int3) {
                    continue;
                }
                count += 1;
                if count >= THRESHOLD {
                    found.insert(t);
                    break;
                }
            }
            if count < THRESHOLD {
                if self.only_calls_noreturn(t, found) {
                    found.insert(t);
                    continue;
                }
                suspicious = true;
            }
        }
        suspicious
    }

    /// checkNonReturningIndicators: from the call's fallthrough on, while instructions fall
    /// through: a function starts there or inside the instruction, no instruction is there
    /// (data), a read or write from earlier in the calling function (or from anywhere, outside
    /// a function) or a call refers to it (hasInconsistentRefsTo), an address table is there,
    /// or it is an INT3.
    fn noreturn_indicators(
        &self,
        call: u32,
        data_to: &HashMap<u32, Vec<u32>>,
        calls_to: &HashMap<u32, Vec<u32>>,
        int3: &dyn Fn(u32) -> bool,
    ) -> bool {
        // getFallThrough is null under a CALL_RETURN override: nothing to check
        if self.call_return(call, &self.insns[&call]) {
            return false;
        }
        let caller = self.body_owner.get(&call).copied();
        let mut fall = call + self.insns[&call].len as u32;
        let next = self.bodies.range(fall..).next().map(|(&f, _)| f);
        loop {
            if next == Some(fall) {
                return true;
            }
            let Some(i) = self.insns.get(&fall) else { return true };
            if next.is_some_and(|n| n < fall + i.len as u32) {
                return true;
            }
            let data = data_to.get(&fall).into_iter().flatten().any(|&from| match caller {
                Some(g) => from < fall && self.body_owner.get(&from) == Some(&g),
                None => true,
            });
            if data || calls_to.contains_key(&fall) || self.table_slots.contains_key(&fall) || int3(fall) {
                return true;
            }
            if i.flow != Flow::Fall {
                return false;
            }
            fall += i.len as u32;
        }
    }

    /// targetOnlyCallsNoReturn: every path from `t` (SimpleBlockModel's blocks, calls not
    /// followed, computed jumps followed as their COMPUTED_JUMP destinations: switch cases and a
    /// computed target) ends in a call or jump to a non-returning function.
    fn only_calls_noreturn(&self, t: u32, found: &BTreeSet<u32>) -> bool {
        let nr = |d: u32| found.contains(&d) || self.is_noreturn(d);
        let mut todo = vec![t];
        let mut visited = HashSet::new();
        let mut hit = false;
        while let Some(mut a) = todo.pop() {
            if !visited.insert(a) {
                continue;
            }
            // the block from `a`: to its first instruction that is not a plain fallthrough
            let i = loop {
                let Some(i) = self.insns.get(&a) else { return false };
                if i.flow != Flow::Fall {
                    break i;
                }
                a += i.len as u32;
            };
            let ret = self.call_return(a, i);
            let fall = a + i.len as u32;
            match i.flow {
                Flow::Return => return false,
                Flow::Call | Flow::Jump => {
                    let Some(d) = i.target else { return false };
                    if nr(d) {
                        hit = true;
                    } else if ret {
                        // CALL_TERMINATOR: a call or a jump to a function that returns
                        return false;
                    } else if i.flow == Flow::Jump {
                        todo.push(d);
                    }
                    if i.flow == Flow::Call && !ret {
                        todo.push(fall);
                    }
                }
                Flow::CondJump => {
                    let d = i.target.unwrap_or(fall);
                    if nr(d) {
                        hit = true;
                    } else {
                        todo.push(d);
                    }
                    todo.push(fall);
                }
                Flow::CallInd | Flow::JumpInd => {
                    let slot = i.slot.is_some_and(|s| self.noreturn.contains(&s));
                    let cases = self.tables.get(&a).map_or(&[][..], Vec::as_slice);
                    let dests = slot || i.computed.is_some() || !cases.is_empty();
                    if !dests && (ret || i.flow == Flow::JumpInd) {
                        return false;
                    }
                    if slot || i.computed.is_some_and(nr) {
                        hit = true;
                    } else if ret {
                        return false;
                    }
                    if i.flow == Flow::CallInd {
                        if !ret {
                            todo.push(fall);
                        }
                    } else {
                        // COMPUTED_JUMP destinations (switch cases, a computed target) are
                        // followed: only an INDIRECTION one (isIndirect) is not
                        for &d in cases.iter().chain(i.computed.iter().filter(|&&d| !nr(d))) {
                            if nr(d) {
                                hit = true;
                            } else {
                                todo.push(d);
                            }
                        }
                    }
                }
                Flow::Fall => unreachable!(),
            }
        }
        hit
    }

    /// Function Start Search: functions at prologue patterns in bytes no code covers yet, each
    /// disassembled when found; again while a sweep finds one.
    fn start_search(
        &mut self,
        img: &Image,
        sl: &Sleigh,
        p: &mut crate::sleigh::Parse,
        owner: &mut [u8],
        queue: &mut Vec<u32>,
    ) {
        loop {
            let before = self.funcs.len();
            for sec in img.sections.iter().filter(|s| s.exec) {
                let d = &sec.data;
                for o in 1..d.len() {
                    let a = sec.addr + o as u32;
                    if owner[(a - self.code_lo) as usize] != 0 {
                        continue;
                    }
                    if pair_hit(d, o, &PRE_FILL, &POST_FILL) || pair_hit(d, o, &PRE_JMP, &POST_JMP) {
                        self.funcs.insert(a);
                        queue.push(a);
                        self.descend(img, sl, p, owner, queue, &mut Vec::new());
                    }
                }
            }
            if self.funcs.len() == before {
                return;
            }
        }
    }

    fn decode(&self, img: &Image, sl: &Sleigh, p: &mut crate::sleigh::Parse, a: u32, fold: &mut Fold) -> Option<Ins> {
        let sec = img.block_of(a)?;
        let o = (a - sec.addr) as usize;
        let len = sl.decode(p, a as u64, &sec.data[o..]).ok()?;
        if len == 0 || o + len > sec.data.len() {
            return None;
        }
        let ops = sl.pcode(p).ok()?;
        let code = sl.code_space();
        let next = a as u64 + len as u64;
        let (mut flow, mut target, mut slot) = (Flow::Fall, None, None);
        let (mut refs, mut code_imms, mut rw) = (Vec::new(), Vec::new(), Vec::new());
        // Local constant fold (a stand-in for Ghidra's constant propagation): 4-byte register
        // and temporary values from immediates, initialised memory, ADD/SUB/XOR/AND/OR. A
        // computed value (not a plain immediate) stored to memory that is code is a code
        // constant, e.g. SecuROM's `MOV EDI,[a]; XOR EDI,[b]; XCHG [ESP],EDI`.
        //
        // Unknown 4-byte registers are symbols (`Val::S`), and values stored through a folded
        // address are kept, as Ghidra's SymbolicPropogator does: `MOV [ESI],vtable; MOV
        // ECX,ESI; MOV EAX,[ECX]; MOV EDX,[EAX+0x14]; CALL EDX` gives a READ reference to the
        // slot vtable+0x14 and the call's target (Ghidra's COMPUTED_CALL reference). The fold
        // follows jumps (`descend` hands it to the target) and a call clobbers EAX/ECX/EDX/ESP.
        let (uniq, rs, w, sp) = (sl.uniq_space(), self.reg_space, self.width, self.sp);
        fold.regs.retain(|f| f.0 != uniq);
        fold.stack.clear();
        fold.mem_size = 0;
        fold.data.clear();
        let val = |v: &crate::sleigh::Varnode, fold: &Fold| -> Option<(Val, bool)> {
            // an address past 32 bits is in no block: memory there is unknown
            let mem = |x: u64| match fold.mem.iter().find(|m| m.0 == Val::C(x)) {
                Some(m) => m.1.map(|v| (v, m.2)),
                None => u32::try_from(x).ok().and_then(|x| img.read_ptr(x)).map(|x| (Val::C(x.into()), true)),
            };
            match v.space {
                0 => Some((Val::C(mask(v.offset, v.size)), false)),
                s if s == code => (v.size == w).then(|| mem(v.offset)).flatten(),
                s => match fold
                    .regs
                    .iter()
                    .find(|f| f.0 == s && f.1 < v.offset + v.size as u64 && v.offset < f.1 + f.2 as u64)
                {
                    Some(f) if f.1 == v.offset && f.2 == v.size => f.3.map(|x| (x, f.4)),
                    // a constant's low bytes, `ROL EDX,CL` after `MOV ECX,[a]`
                    Some(f) if f.1 <= v.offset && v.offset + v.size as u64 <= f.1 + f.2 as u64 => match f.3 {
                        Some(Val::C(c)) if v.offset - f.1 < 4 => {
                            Some((Val::C(mask(c >> (8 * (v.offset - f.1)), v.size)), f.4))
                        }
                        _ => None,
                    },
                    None if s == rs && v.size == w => Some((Val::S(v.offset, 0), false)),
                    _ => None,
                },
            }
        };
        let load = |p: Val, fold: &Fold| -> Option<(Val, bool)> {
            match p {
                Val::C(x) => val(&crate::sleigh::Varnode { space: code, offset: x, size: w }, fold),
                // memory nothing was stored to holds a symbol of its own (its first value), as
                // Ghidra keeps an unknown location: `MOV EBP,[ESP+0xc]` is the third argument
                Val::S(b, d) => match fold.mem.iter().find(|m| m.0 == p) {
                    Some(m) => m.1.map(|v| (v, m.2)),
                    None => Some((Val::S(1 << 63 | (b.wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ d as u64) >> 1, 0), false)),
                },
            }
        };
        // a folded value as an address: one past 32 bits is in no block (`from_elf` loads below 4 GiB)
        let addr = |x: u64| u32::try_from(x).ok().filter(|&x| img.block_of(x).is_some());
        let code_at = |x: u64| u32::try_from(x).ok().filter(|&x| self.is_code(img, x));
        // ponytail: at most MAX_STACK stack stores (ESP-relative) and MAX_MEM others, the newest;
        // Ghidra keeps all. Lookups are linear: a map if a body ever stores far more. (16 and 64,
        // the caps of the local fold, lose 7 gate lines on mercs2 now that walks span functions.)
        let stack = fold.mem.iter().filter(|m| matches!(m.0, Val::S(b, _) if b == sp)).count();
        let (max_stack, max_mem) = (MAX_STACK[fold.whole as usize], MAX_MEM[fold.whole as usize]);
        if stack > max_stack {
            let old = fold.mem.iter().position(|m| matches!(m.0, Val::S(b, _) if b == sp)).unwrap();
            fold.mem.remove(old);
        }
        if fold.mem.len() - stack.min(max_stack) > max_mem {
            let old = fold.mem.iter().position(|m| !matches!(m.0, Val::S(b, _) if b == sp)).unwrap();
            fold.mem.remove(old);
        }
        let mut computed = None;
        for op in &ops {
            if matches!(op.opc, 2 | 3) {
                // for the stack variables of `stack_uses`; nothing here reads these
                let size = if op.opc == 2 { op.out.as_ref().map_or(0, |o| o.size) } else { op.ins[2].size };
                fold.mem_size = size;
                match op.ins.get(1).and_then(|v| val(v, fold)) {
                    Some((Val::S(b, d), _)) if b == sp => fold.stack.push((d, size, op.opc == 3)),
                    Some((Val::C(x), _)) if x <= u64::from(u32::MAX) => fold.data.push((x as u32, size, op.opc == 3)),
                    _ => {}
                }
            }
            if op.opc == 3 {
                let v = op.ins.get(2).and_then(|v| val(v, fold));
                // a constant stored through a register, `MOV ECX,fn; MOV [EAX*8+t],ECX`: Ghidra's
                // addStoredReferences (a plain immediate is an operand reference already)
                if let (Some((Val::C(x), _)), true) = (v, op.ins.get(2).is_some_and(|v| v.space != 0)) {
                    if let Some(x) = code_at(x).filter(|x| !code_imms.contains(x)) {
                        code_imms.push(x);
                    }
                }
                if let Some((p, _)) = op.ins.get(1).and_then(|v| val(v, fold)) {
                    if let Val::C(x) = p {
                        if let Some(x) = addr(x) {
                            if !refs.contains(&x) {
                                refs.push(x); // WRITE reference through a folded address
                            }
                            if !rw.contains(&x) {
                                rw.push(x);
                            }
                        }
                    }
                    fold.mem.retain(|m| m.0 != p);
                    let size4 = op.ins.get(2).is_some_and(|v| v.size == w);
                    fold.mem.push((p, v.filter(|_| size4).map(|v| v.0), v.is_some_and(|v| v.1)));
                }
            }
            if let Some(o) = op.out.as_ref() {
                let r = match (op.opc, op.ins.as_slice()) {
                    (1, [x]) if o.size == w => val(x, fold),
                    // smaller constants, for the carry of `STC; ADC EBP,[a]` (SecuROM)
                    (1, [x]) if o.size < w => val(x, fold).filter(|v| matches!(v.0, Val::C(_))),
                    (17 | 18, [x]) if o.size == w && x.size < w => match val(x, fold) {
                        Some((Val::C(c), _)) => {
                            let sh = 64 - 8 * x.size;
                            let c = if op.opc == 17 { c } else { ((c << sh) as i64 >> sh) as u64 };
                            Some((Val::C(mask(c, o.size)), true))
                        }
                        _ => None,
                    },
                    (2, [_, x]) if o.size == w => val(x, fold).and_then(|(p, _)| {
                        if let Val::C(x) = p {
                            if let Some(x) = addr(x) {
                                if !refs.contains(&x) {
                                    refs.push(x); // READ reference through a folded address
                                }
                                if !rw.contains(&x) {
                                    rw.push(x);
                                }
                            }
                        }
                        load(p, fold).map(|(v, _)| (v, true))
                    }),
                    (24 | 25, [x]) if o.size == w => match val(x, fold) {
                        Some((Val::C(x), _)) => {
                            Some((Val::C(mask(if op.opc == 24 { x.wrapping_neg() } else { !x }, o.size)), true))
                        }
                        _ => None,
                    },
                    (19 | 20 | 26 | 27 | 28 | 29 | 30 | 31 | 32, [x, y])
                        if o.size <= w
                            && y.size <= w
                            && (o.size == w || op.opc != 31)
                            && (o.size <= 4 || !matches!(op.opc, 30 | 31)) =>
                    {
                        val(x, fold).zip(val(y, fold)).and_then(|((x, _), (y, _))| {
                            let r = match (op.opc, x, y) {
                                (_, Val::C(x), Val::C(y)) => Val::C(mask(
                                    match op.opc {
                                        19 => x.wrapping_add(y),
                                        20 => x.wrapping_sub(y),
                                        26 => x ^ y,
                                        27 => x & y,
                                        28 => x | y,
                                        29 => u32::try_from(y).ok().and_then(|y| x.checked_shl(y)).unwrap_or(0),
                                        30 => u32::try_from(y).ok().and_then(|y| x.checked_shr(y)).unwrap_or(0),
                                        31 => {
                                            let sh = 64 - 8 * o.size;
                                            let x = (x << sh) as i64 >> sh;
                                            u32::try_from(y).ok().and_then(|y| x.checked_shr(y)).unwrap_or(x >> 63)
                                                as u64
                                        }
                                        _ => x.wrapping_mul(y),
                                    },
                                    o.size,
                                )),
                                _ if o.size < w => return None,
                                // offsets from a symbol stay 32-bit, modulo 2^32
                                (19, Val::S(b, d), Val::C(c)) | (19, Val::C(c), Val::S(b, d)) => {
                                    Val::S(b, d.wrapping_add(c as u32))
                                }
                                (20, Val::S(b, d), Val::C(c)) => Val::S(b, d.wrapping_sub(c as u32)),
                                (27, Val::S(b, d), Val::C(m)) if b == sp && fold.stack_and => Val::S(sp, d & m as u32),
                                (20 | 26, x, y) if x == y => Val::C(0), // `XOR EDI,EDI`
                                (20, Val::S(b, d), Val::S(b2, d2)) if b == b2 => {
                                    Val::C(mask(d.wrapping_sub(d2) as i32 as u64, w))
                                }
                                _ => return None,
                            };
                            Some((r, true))
                        })
                    }
                    _ => None,
                };
                if o.space == code {
                    // a direct store, `MOV [g],reg`
                    let p = Val::C(o.offset);
                    fold.mem.retain(|m| m.0 != p);
                    fold.mem.push((p, r.map(|r| r.0), r.is_some_and(|r| r.1)));
                } else {
                    let end = o.offset + o.size as u64;
                    fold.regs.retain(|f| f.0 != o.space || f.1 >= end || f.1 + f.2 as u64 <= o.offset);
                    fold.regs.push((o.space, o.offset, o.size, r.map(|r| r.0), r.is_some_and(|r| r.1)));
                }
            }
            if matches!(op.opc, 6 | 8) && op.ins[0].space != code {
                if let Some((Val::C(t), _)) = val(&op.ins[0], fold) {
                    computed = code_at(t);
                }
            }
            if matches!(op.opc, 7 | 8) {
                // EAX, ECX, EDX (offsets 0, 4, 8) and flags are the callee's: each becomes a new
                // symbol of this call, which aliases nothing stored before it. ESP (0x10) pops the
                // return address and the callee's purge (`RET n`), as Ghidra's
                // handleFunctionSideEffects does for __stdcall's unknown extrapop; where the purge
                // is unknown (no body, RETs that disagree, imports) ESP is a new symbol too.
                // a call through a slot with a known purge (an import, where the purges are Ghidra's)
                let through = || {
                    let v = &op.ins[0];
                    let c = ops.iter().rev().find(|c| c.opc == 1 && c.out.as_ref().is_some_and(|o| o == v));
                    let v = c.map_or(v, |c| &c.ins[0]);
                    u32::try_from(v.offset).ok().filter(|s| v.space == code && self.purge.contains_key(s))
                };
                let callee = if op.opc == 7 { u32::try_from(op.ins[0].offset).ok() } else { through().or(computed) };
                let esp = crate::sleigh::Varnode { space: rs, offset: sp, size: w };
                // a default prototype with a known extrapop: every call moves the stack pointer by its
                // stackshift (SymbolicPropogator.getDefaultStackDepthChange), past the pushed return
                let purge = self.stackshift.map(|s| s - w).or_else(|| callee.and_then(|t| self.purge.get(&t).copied()));
                let after = purge.zip(val(&esp, fold)).map(|(n, (v, _))| match v {
                    Val::C(x) => Val::C(mask(x.wrapping_add(u64::from(w + n)), w)),
                    Val::S(b, d) => Val::S(b, d.wrapping_add(w + n)),
                });
                let gone = |r: u64| self.killed.iter().chain([&sp]).any(|&k| (k..k + w as u64).contains(&r));
                fold.regs.retain(|f| f.0 != rs || f.1 < 0x200 && !gone(f.1));
                for r in self.killed.iter().copied().chain([sp]) {
                    let new = Val::S(1 << 40 | (a as u64) << 8 | r, 0);
                    fold.regs.push((rs, r, w, Some(if r == sp { after.unwrap_or(new) } else { new }), false));
                }
            }
            match op.opc {
                // REP-prefixed string ops branch to their own start or end: no flow change
                4 | 5 if op.ins[0].space == code && (op.ins[0].offset == a as u64 || op.ins[0].offset == next) => {}
                4 | 5 | 7 if op.ins[0].space == code => {
                    // a flow past 32 bits leaves the image: no target, counted in a warning
                    target = u32::try_from(op.ins[0].offset).ok();
                    if target.is_none() {
                        self.wide_flows.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    flow = match op.opc {
                        4 => Flow::Jump,
                        5 => Flow::CondJump,
                        _ => Flow::Call,
                    };
                }
                6 | 8 => {
                    flow = if op.opc == 6 { Flow::JumpInd } else { Flow::CallInd };
                    // through a direct memory operand: `CALL dword ptr [slot]`
                    // (CALL copies the slot to a temporary first, since it pushes the return)
                    let mut v = &op.ins[0];
                    if let Some(c) = ops.iter().rev().find(|c| c.opc == 1 && c.out.as_ref().is_some_and(|o| o == v)) {
                        v = &c.ins[0];
                    }
                    slot = u32::try_from(v.offset).ok().filter(|_| v.space == code);
                }
                10 => flow = Flow::Return,
                _ => {}
            }
            // data references: direct memory operands (ram varnodes), not flow targets
            let skip = usize::from(matches!(op.opc, 4 | 5 | 7));
            // x87 constructors copy inst_start into FPUInstructionPointer: not a reference
            let fpu_ip = op.out.as_ref().is_some_and(|o| Some((o.space, o.offset)) == self.fpu_ip);
            for v in op.ins.iter().skip(skip).chain(op.out.as_ref()) {
                // a value past 32 bits is no address of the image: no reference, as Java makes
                // none outside memory
                let Ok(imm) = u32::try_from(v.offset) else { continue };
                // e.g. PUSH offset callback (not CALL's pushed return address)
                if v.space == 0
                    && (v.size == 4 || v.size == w)
                    && v.offset != next
                    && !fpu_ip
                    && self.is_code(img, imm)
                    && !code_imms.contains(&imm)
                {
                    code_imms.push(imm);
                }
                let is_ref = match v.space {
                    0 => (v.size == 4 || v.size == w) && img.block_of(imm).is_some_and(|s| !s.exec), // immediate pointing at data
                    s => s == code && img.block_of(imm).is_some(),
                };
                if is_ref && !refs.contains(&imm) {
                    refs.push(imm);
                }
                // a memory operand (not an immediate): READ or WRITE
                if is_ref && v.space != 0 && !rw.contains(&imm) {
                    rw.push(imm);
                }
            }
        }
        let computed = computed.filter(|_| slot.is_none());
        Some(Ins { len: len as u8, flow, target, slot, computed, refs, rw, code_imms, nop: ops.is_empty() })
    }

    /// Ghidra's `disassemble(addr)` after analysis: recursive descent from `addrs` into bytes no
    /// code covers yet, without making functions. With `constants`, also the code Ghidra's
    /// analysis decodes beyond the function bodies, which reference checks see: code reached
    /// through code constants (`PUSH offset callback`, `MOV [g],offset fn`, SecuROM's
    /// `PUSH next; PUSH callee; RET`, values the local fold computes) where
    /// OperandReferenceAnalyzer would disassemble (no table of addresses there, nothing reads or
    /// writes the target, the instruction is no jump or call and does not compute with the
    /// value, `valid_subroutine` accepts it), and the entries of address tables of code
    /// (`address_tables`), repeated over what that reaches. An address table an instruction
    /// refers to becomes pointers (`table_slots`). Bodies stay as they are. Returns the
    /// instructions decoded by the descent from `addrs`.
    // ponytail: the references a check sees are all of the instructions decoded so far, where
    // Ghidra has those of the code it had disassembled when it asked (its analysis works in
    // small steps from the entry points); a faithful order needs its task queue ported
    pub fn disassemble(&mut self, img: &Image, sl: &Sleigh, addrs: &[u32], constants: bool) -> Vec<u32> {
        let mut owner = vec![0u8; (self.code_hi - self.code_lo) as usize];
        for (&a, i) in &self.insns {
            let o = (a - self.code_lo) as usize;
            owner[o] = 1;
            owner[o + 1..o + i.len as usize].fill(2);
        }
        let funcs = self.funcs.clone();
        let mut queue: Vec<u32> = addrs.iter().copied().filter(|&a| self.is_code(img, a)).collect();
        let mut p = sl.new_parse();
        let mut log: Vec<u32> = if constants { self.insns.keys().copied().collect() } else { Vec::new() };
        let known = log.len();
        self.descend(img, sl, &mut p, &mut owner, &mut queue, &mut log);
        let new = log[known..].to_vec();
        if constants {
            self.propagate(img, sl);
        }
        let mut checked = HashSet::new(); // targets asked once, as Ghidra's checkedTargets
        let mut asked = HashSet::new(); // pointer targets asked once
        let min_table = Self::min_table(img);
        // every reference destination so far, and those in executable blocks that a memory
        // operand reads or writes (Ghidra's READ and WRITE references)
        let mut refs = Refs::default();
        refs.dests.extend(self.table_slots.values());
        while constants && !log.is_empty() {
            for a in &log {
                let i = &self.insns[a];
                refs.dests.extend(i.refs.iter().chain(&i.code_imms).chain(&i.target));
                refs.dests.extend(self.tables.get(a).into_iter().flatten());
                refs.reads.extend(i.refs.iter().filter(|&&t| self.is_code(img, t)));
            }
            let mut queue: Vec<u32> = Vec::new();
            let targets = |i: &Ins| i.refs.iter().chain(&i.code_imms).copied().collect::<Vec<_>>();
            for (a, t) in
                log.iter().flat_map(|&a| targets(&self.insns[&a]).into_iter().map(move |t| (a, t))).collect::<Vec<_>>()
            {
                let defined = self.is_code(img, t) && owner[(t - self.code_lo) as usize] != 0;
                if defined || !checked.insert(t) {
                    continue;
                }
                // OperandReferenceAnalyzer.getAddressTable, createFlowTable: an address table
                // an instruction refers to becomes pointers, and nothing is disassembled there
                let flows = !matches!(self.insns[&a].flow, Flow::Fall | Flow::Return);
                if let Some(elems) = self.table_entry(img, &owner, &refs.dests, t, 3).filter(|e| e.len() >= min_table) {
                    if !flows {
                        self.make_table(img, &mut owner, &mut refs, t, &elems);
                    }
                    continue;
                }
                // "Subroutine References": not where something reads or writes the target, not
                // from a jump or call, not a value the instruction computes with
                if self.is_code(img, t)
                    && !refs.reads.contains(&t)
                    && !flows
                    && !self.used_for_calculation(img, sl, &mut p, a, t)
                    && self.valid_subroutine(img, sl, &mut p, &owner, &refs.dests, t, false, true)
                {
                    queue.push(t);
                }
            }
            log.clear();
            self.descend(img, sl, &mut p, &mut owner, &mut queue, &mut log);
            if log.is_empty() {
                // Pointers in referenced data first (the operand analyzer runs before
                // Create Address Tables), then address tables over what is still undefined;
                // code either reaches is checked for code constants again.
                let mut queue = self.pointer_targets(img, sl, &mut p, &owner, &refs, &mut asked);
                if queue.is_empty() {
                    queue = self.address_tables(img, sl, &mut p, &mut owner, &mut refs);
                    queue.extend(self.pointer_targets(img, sl, &mut p, &owner, &refs, &mut asked));
                }
                queue.retain(|&t| owner[(t - self.code_lo) as usize] == 0);
                self.descend(img, sl, &mut p, &mut owner, &mut queue, &mut log);
            }
        }
        self.funcs = funcs;
        new
    }

    /// PseudoDisassembler.isValidSubroutine(entry, false), which Ghidra asks before it
    /// disassembles at a code constant ("Found code from operand reference"): the flow from
    /// `entry` (not into calls, nor jumps to functions) decodes without a bad instruction, runs
    /// into no existing code, jumps only to instruction starts, never branches conditionally
    /// to its own fallthrough, and returns, jumps through a register or reaches a function;
    /// a single instruction must reach a function. With `existing` (isValidSubroutine(entry,
    /// true), asked for pointers in data), the flow may run through existing instructions and a
    /// single instruction is enough. `checkPseudoBody`: no defined data in the body, no
    /// reference (`dests`) into the middle of an instruction of the body, and without
    /// `existing` no reference to the body but to its entry. Without `must_terminate` this is
    /// PseudoDisassembler.isValidCode, which Create Address Tables asks.
    #[allow(clippy::too_many_arguments)]
    fn valid_subroutine(
        &self,
        img: &Image,
        sl: &Sleigh,
        p: &mut crate::sleigh::Parse,
        owner: &[u8],
        dests: &BTreeSet<u32>,
        entry: u32,
        existing: bool,
        must_terminate: bool,
    ) -> bool {
        if img.read_u32(entry) == Some(0) && img.read_u32(entry + 4) == Some(0) {
            return false;
        }
        let (mut body, mut targets) = (BTreeMap::new(), Vec::new());
        let (mut terminated, mut called) = (false, false);
        let mut work = vec![entry];
        let mut fold = Fold::default();
        while let Some(mut a) = work.pop() {
            while body.len() < 4000 && !body.contains_key(&a) {
                if !self.is_code(img, a) {
                    return false;
                }
                let Some(i) = self.decode(img, sl, p, a, &mut fold) else { return false };
                let o = (a - self.code_lo) as usize;
                let taken = |b: u8| b >= 3 || b != 0 && !existing; // 3, 4: defined data (a switch table, a pointer)
                if owner.get(o..o + i.len as usize).is_none_or(|b| b.iter().any(|&b| taken(b))) {
                    return false;
                }
                body.insert(a, i.len);
                let next = a + i.len as u32;
                match (i.flow, i.target) {
                    (Flow::Return, _) | (Flow::JumpInd, _) => terminated = true,
                    (Flow::Call, Some(t)) => {
                        called |= self.funcs.contains(&t);
                        if self.noreturn.contains(&t) {
                            break;
                        }
                    }
                    (Flow::CondJump, Some(t)) if t == next => return false,
                    (Flow::Jump | Flow::CondJump, Some(t)) if self.funcs.contains(&t) => called = true,
                    (Flow::Jump | Flow::CondJump, Some(t)) => {
                        targets.push(t);
                        work.push(t);
                    }
                    _ => {}
                }
                if !i.falls_through() {
                    break;
                }
                a = next;
            }
        }
        let start_of = |t: u32| body.range(..=t).next_back().map(|(&s, &l)| (s, t < s + l as u32));
        if targets.iter().any(|&t| matches!(start_of(t), Some((s, true)) if s != t)) {
            return false; // a jump into the middle of an instruction of the body
        }
        if must_terminate && !(terminated || called) {
            return false;
        }
        // checkPseudoBody
        if body.iter().any(|(&s, &l)| dests.range(s + 1..s + l as u32).next().is_some()) {
            return false; // an offcut reference
        }
        existing
            || (called || body.len() > 1)
                && !body.iter().any(|(&s, &l)| dests.range(s..s + l as u32).any(|&t| t != entry))
    }

    /// OperandReferenceAnalyzer.isUsedForCalculation: the instruction at `a` computes with the
    /// constant `t` (any operation but COPY, LOAD and STORE on it or on a copy of it), or
    /// loads or stores through a copy of it.
    fn used_for_calculation(&self, img: &Image, sl: &Sleigh, p: &mut crate::sleigh::Parse, a: u32, t: u32) -> bool {
        let Some(sec) = img.block_of(a) else { return false };
        if sl.decode(p, a as u64, &sec.data[(a - sec.addr) as usize..]).is_err() {
            return false;
        }
        let Ok(ops) = sl.pcode(p) else { return false };
        let mut target: Option<crate::sleigh::Varnode> = None;
        for op in &ops {
            let through = matches!(op.opc, 2 | 3);
            if through && target.is_some() && op.ins.get(1) == target.as_ref() {
                return true;
            }
            for v in &op.ins {
                if target.as_ref() == Some(v) || v.space == 0 && v.offset == t as u64 {
                    if through {
                        continue;
                    }
                    if op.opc != 1 {
                        return true;
                    }
                    if let Some(o) = &op.out {
                        target = Some(*o);
                    }
                }
            }
        }
        false
    }

    /// AddressTable.getThresholdRunOfValidPointers(BILLION_CASES): the run of pointers that
    /// happens by chance once in a billion, at least 2.
    fn min_table(img: &Image) -> usize {
        let bytes: f64 = img.sections.iter().map(|s| s.data.len() as f64).sum();
        ((1e-9f64).ln() / (bytes / 2f64.powi(32)).ln()).ceil().max(2.0) as usize
    }

    /// Bytes at `a` that hold no instruction and no data but pointers (which a table may take
    /// over, as AddressTable.getEntry and makeTable allow).
    fn undefined(&self, img: &Image, owner: &[u8], a: u32) -> bool {
        !self.is_code(img, a) || matches!(owner[(a - self.code_lo) as usize], 0 | 4)
    }

    /// AddressTable.getEntry(top, checkExisting, `min`, alignment 1, MINIMUM_SAFE_ADDRESS): the
    /// run of words from `top` that are addresses of the image (not below 1024), cut by a
    /// reference to a word after the second, by a word that points into the middle of an
    /// instruction or to one something falls into (checkForCollisionAtTarget), by the next
    /// reference destination and by the next instruction or data that is no pointer.
    fn table_entry(&self, img: &Image, owner: &[u8], dests: &BTreeSet<u32>, top: u32, min: usize) -> Option<Vec<u32>> {
        let s = img.block_of(top)?;
        let end = s.addr + s.data.len() as u32;
        if !self.undefined(img, owner, top) {
            return None;
        }
        let collides = |t: u32| {
            self.is_code(img, t)
                && match owner[(t - self.code_lo) as usize] {
                    2 => true, // into the middle of an instruction
                    1 => self.insns.range(..t).next_back().is_some_and(|(&a, i)| {
                        a + i.len as u32 == t
                            && i.falls_through()
                            && !(i.flow == Flow::Call && i.target.is_some_and(|t| self.noreturn.contains(&t)))
                    }),
                    _ => false,
                }
        };
        // program.getDefaultPointerSize() words (AddressTable.java:1074-1100); an 8-byte value
        // past 32 bits is in no block
        let w = img.ptr_size();
        let mut elems: Vec<u32> = Vec::new();
        let mut cur = top;
        while u64::from(cur) + u64::from(w) <= u64::from(end) {
            let v = ptr_value(&s.data[(cur - s.addr) as usize..][..w as usize]).unwrap_or(0);
            if v < 1024 || img.block_of(v).is_none() || (elems.len() > 1 && dests.contains(&cur)) || collides(v) {
                break;
            }
            elems.push(v);
            cur += w;
        }
        let mut count = elems.len();
        if count >= min {
            let stop = dests.range(top + 1..top + w * count as u32).next().copied();
            let stop = stop.into_iter().chain((top..top + w * count as u32).find(|&a| !self.undefined(img, owner, a)));
            if let Some(at) = stop.min() {
                count = count.min(((at - top) / w) as usize);
            }
        }
        elems.truncate(count);
        (count >= min).then_some(elems)
    }

    /// AddressTable.makeTable: the words from `top` become pointers, each a reference to its
    /// value.
    fn make_table(&mut self, img: &Image, owner: &mut [u8], refs: &mut Refs, top: u32, elems: &[u32]) {
        let w = img.ptr_size();
        for (i, &v) in elems.iter().enumerate() {
            let slot = top + w * i as u32;
            self.table_slots.insert(slot, v);
            refs.dests.insert(v);
            if self.is_code(img, slot) {
                let o = (slot - self.code_lo) as usize;
                owner[o..].iter_mut().take(w as usize).filter(|b| **b == 0).for_each(|b| *b = 4);
            }
        }
    }

    /// OperandReferenceAnalyzer (`added`, `checkForPointer`): a data word an instruction
    /// references, holding an address no other reference points into, becomes a pointer; the
    /// pointer's reference into undecoded code is disassembled where isValidSubroutine(target,
    /// true) accepts it. This is how Ghidra reaches functions only a vtable names (deleting
    /// destructors). The pointers of address tables (`table_slots`) go the same way
    /// (DataOperandReferenceAnalyzer), so a table that mixes code and data pointers still
    /// reaches its code. Returns those targets; `asked` holds the ones already asked.
    /// ponytail: no string check at the slot (checkForAscii/Unicode) and no pointer chains.
    fn pointer_targets(
        &self,
        img: &Image,
        sl: &Sleigh,
        p: &mut crate::sleigh::Parse,
        owner: &[u8],
        refs: &Refs,
        asked: &mut HashSet<u32>,
    ) -> Vec<u32> {
        let dests = &refs.dests;
        // checkForPointer: a value of 4096 up, and no reference into the rest of the slot, of
        // getDefaultPointerSize bytes (OperandReferenceAnalyzer.java:961-972)
        let w = img.ptr_size();
        let pointers = dests.iter().filter(|&&t| !self.is_code(img, t)).filter_map(|&t| {
            img.read_ptr(t).filter(|&v| v >= 4096 && dests.range(t + 1..t.saturating_add(w)).next().is_none())
        });
        let mut out = Vec::new();
        for v in pointers.chain(self.table_slots.values().copied()) {
            // hasDataAccessReferences: not where something reads or writes the target
            if self.is_code(img, v)
                && owner[(v - self.code_lo) as usize] == 0
                && asked.insert(v)
                && !refs.reads.contains(&v)
                && self.valid_subroutine(img, sl, p, owner, &refs.dests, v, true, true)
            {
                out.push(v);
            }
        }
        out
    }

    /// Ghidra's Create Address Tables analyzer (AddressTableAnalyzer, AddressTable.getEntry and
    /// checkTable) over the bytes no instruction covers, in every section: runs of at least
    /// `getThresholdRunOfValidPointers` (one in a billion by chance) 4-aligned words that are
    /// addresses (`table_entry`), cut by a pointer into the middle of an instruction, a UTF-16
    /// string, or a jump of more than 0xffffff between neighbours (which drops that entry).
    /// Adds the slots to `table_slots` and returns the entries to disassemble
    /// (`getFunctionEntries`): those of a table whose every entry lies in an executable block
    /// and is the start of an instruction or, where nothing is defined, valid code
    /// (PseudoDisassembler.isValidCode). An entry at defined data (a pointer of this or another
    /// table) is not, so a table of pointers to pointers stays data.
    /// Not modelled: Ghidra's other defined data (strings, structures); the analyzer's
    /// disassembly between one table and the next (here after the whole pass).
    fn address_tables(
        &mut self,
        img: &Image,
        sl: &Sleigh,
        p: &mut crate::sleigh::Parse,
        owner: &mut [u8],
        refs: &mut Refs,
    ) -> Vec<u32> {
        let min = Self::min_table(img);
        let mut code = Vec::new();
        for s in &img.sections {
            let end = s.addr + s.data.len() as u32;
            let mut top = s.addr;
            while top + 4 <= end {
                let Some(elems) = self.table_entry(img, owner, &refs.dests, top, min) else {
                    top += 4;
                    continue;
                };
                let count = elems.len();
                // processAddressTable: checkTable, make the table, carry on one entry past it
                let w = img.ptr_size();
                let mut first = 0;
                while first < count {
                    let at = |i: usize| top + w * i as u32;
                    let strings = utf16_strings(s, at(first), at(count));
                    // checkTable tests `start + 4 * i` and its byte 3 whatever the pointer size
                    // (AddressTableAnalyzer.java:401-407)
                    let chk = |i: usize| at(first) + 4 * (i - first) as u32;
                    let mut len = 0;
                    for i in first..count {
                        let offcut = self.is_code(img, elems[i]) && owner[(elems[i] - self.code_lo) as usize] == 2;
                        let far = i > first && elems[i - 1].abs_diff(elems[i]) > 0xff_ffff;
                        if strings.iter().any(|r| r.contains(&chk(i)) || r.contains(&(chk(i) + 3))) || far || offcut {
                            break;
                        }
                        len += 1;
                    }
                    if len >= min {
                        self.make_table(img, owner, refs, at(first), &elems[first..first + len]);
                        // getFunctionEntries, over the whole table that is left
                        let rest = &elems[first..];
                        let valid: Vec<u32> = rest
                            .iter()
                            .copied()
                            .filter(|&v| {
                                self.is_code(img, v)
                                    && match owner[(v - self.code_lo) as usize] {
                                        0 => self.valid_subroutine(img, sl, p, owner, &refs.dests, v, true, false),
                                        b => b == 1,
                                    }
                            })
                            .collect();
                        if valid.len() >= rest.len() {
                            code.extend(valid);
                        }
                    }
                    first += len + 1;
                }
                // past the table's bytes (AddressTableAnalyzer.java:187-191); the next top is
                // 4-aligned (tableAlignment, 4 whatever the pointer size)
                top += w * count as u32;
            }
        }
        code
    }

    /// Recursive descent from every queued address. Call targets in .text become functions.
    fn descend(
        &mut self,
        img: &Image,
        sl: &Sleigh,
        p: &mut crate::sleigh::Parse,
        owner: &mut [u8],
        queue: &mut Vec<u32>,
        log: &mut Vec<u32>,
    ) {
        let mut pending: HashMap<u32, Fold> = HashMap::new();
        while let Some(start) = queue.pop() {
            let mut a = start;
            let mut recent: Vec<u32> = Vec::new(); // straight-line history, for switch bounds
                                                   // the fold of the first jump that reached `start` (Ghidra: first flow wins)
            let mut fold = pending.remove(&start).unwrap_or_default();
            while self.is_code(img, a) && owner[(a - self.code_lo) as usize] == 0 {
                let Some(ins) = self.decode(img, sl, p, a, &mut fold) else { break };
                let o = (a - self.code_lo) as usize;
                if owner[o..o + ins.len as usize].iter().any(|&b| b != 0) {
                    break; // would overlap code already there
                }
                owner[o] = 1;
                owner[o + 1..o + ins.len as usize].fill(2);
                if let Some(t) = ins.target.filter(|&t| self.is_code(img, t)) {
                    if ins.flow == Flow::Call {
                        self.funcs.insert(t);
                    }
                    if ins.flow != Flow::Call && owner[(t - self.code_lo) as usize] == 0 {
                        pending.entry(t).or_insert_with(|| fold.clone());
                    }
                    queue.push(t);
                }
                if ins.flow == Flow::JumpInd {
                    if let Some((table, cases)) = self.switch_table(img, a, &recent) {
                        queue.extend(&cases);
                        // the table is data: keep the pattern search out of it
                        if self.is_code(img, table) {
                            let t = (table - self.code_lo) as usize;
                            let e = (t + img.ptr_size() as usize * cases.len()).min(owner.len());
                            owner[t..e].iter_mut().filter(|b| **b == 0).for_each(|b| *b = 3);
                        }
                        self.tables.insert(a, cases);
                    }
                }
                let stop = !ins.falls_through()
                    || ins.flow == Flow::Call && ins.target.is_some_and(|t| self.noreturn.contains(&t))
                    // ELF: Java's flow goes on past `CALL [GOT slot]` of a non-returning import (the slot
                    // points into its EXTERNAL block; measured on libtcl, not traced)
                    || ins.flow == Flow::CallInd && !img.elf64 && ins.slot.is_some_and(|s| self.noreturn.contains(&s));
                recent.push(a);
                let len = ins.len as u32;
                log.push(a);
                self.insns.insert(a, ins);
                if stop {
                    break;
                }
                a += len;
            }
        }
    }

    // `JMP dword ptr [reg*4 + table]`, bounded by a preceding `CMP reg,imm` when there is one,
    // possibly through a byte index table (`MOVZX reg,byte ptr [idx + bytetable]`). Cases must
    // lie in the jump's own section.
    fn switch_table(&self, img: &Image, at: u32, recent: &[u32]) -> Option<(u32, Vec<u32>)> {
        let bytes = |a: u32| img.block_of(a).map(|s| &s.data[(a - s.addr) as usize..]);
        // x86-64: `JMP qword ptr [reg*8 + table]`; a REX prefix may come before it and before
        // the CMP or MOVZX (REX.X, REX.R and REX.B extend their registers)
        let w = img.ptr_size();
        fn split_rex(elf64: bool, c: &[u8]) -> (u8, &[u8]) {
            match c.first() {
                Some(&x) if elf64 && (0x40..0x50).contains(&x) => (x, &c[1..]),
                _ => (0, c),
            }
        }
        let rex = |c| split_rex(img.elf64, c);
        let (px, b) = rex(bytes(at)?);
        let b = b.get(..7)?;
        if b[0] != 0xff || b[1] != 0x24 || b[2] & 0xc7 != if img.elf64 { 0xc5 } else { 0x85 } {
            return None;
        }
        let mut reg = (b[2] >> 3) & 7 | (px & 2) << 2; // the register the CMP bounds
        let table = u32::from_le_bytes(b[3..7].try_into().unwrap());
        // x86-64 sign-extends the disp32: a negative one is past 32 bits, out of the image
        if img.elf64 && (table as i32) < 0 {
            return None;
        }
        let mut count = None;
        let mut index_table = None; // two-level switch: `MOVZX reg,byte ptr [r + bytetable]`
        for &r in recent.iter().rev().take(8) {
            let Some(c) = bytes(r) else { continue };
            let (cx, c) = rex(c);
            if let [0x0f, 0xb6, m, d0, d1, d2, d3, ..] = c {
                if index_table.is_none()
                    && m & 0xc0 == 0x80
                    && m & 7 != 4
                    && ((m >> 3) & 7 | (cx & 4) << 1) == reg
                    && !(img.elf64 && *d3 >= 0x80)
                {
                    index_table = Some(u32::from_le_bytes([*d0, *d1, *d2, *d3]));
                    reg = m & 7 | (cx & 1) << 3;
                    continue;
                }
            }
            // the CMP's ModRM names the low three bits, REX.B the fourth
            let (low, high) = (reg & 7, reg >> 3 == cx & 1);
            let imm = match c {
                [0x83, m, i, ..] if *m == 0xf8 | low && high => Some(*i as u32),
                [0x81, m, i0, i1, i2, i3, ..] if *m == 0xf8 | low && high => {
                    Some(u32::from_le_bytes([*i0, *i1, *i2, *i3]))
                }
                [0x3d, i0, i1, i2, i3, ..] if reg == 0 => Some(u32::from_le_bytes([*i0, *i1, *i2, *i3])),
                _ => None,
            };
            if let Some(n) = imm {
                count = Some(n as usize + 1);
                break;
            }
        }
        // The CMP bounds the byte table; the jump table has max(byte table) + 1 entries.
        if let (Some(bt), Some(n)) = (index_table, count) {
            let b = img.block_of(bt).map(|s| &s.data[(bt - s.addr) as usize..])?;
            count = Some(*b.get(..n.min(b.len()))?.iter().max()? as usize + 1);
        }
        let own = img.block_of(at)?.addr;
        let mut cases = Vec::new();
        for i in 0..count.unwrap_or(1024).min(1024) {
            match img.read_ptr(table + w * i as u32) {
                Some(t) if self.is_code(img, t) && img.block_of(t).is_some_and(|s| s.addr == own) => cases.push(t),
                _ => break,
            }
        }
        (!cases.is_empty()).then_some((table, cases))
    }

    /// SharedReturnAnalysisCmd with "assume contiguous functions" (x86's default) and without
    /// conditional branches, on `set`: the entries of the functions added or with a body set
    /// since its last turn (a FUNCTION_ANALYZER at 398). The jump
    /// scan set is built per function of `set` as `checkAboveFunction` /
    /// `checkBelowFunction` build it (from the previous function's entry to the next one's,
    /// a single-range body taken out again), and the jump sources in it are walked in address
    /// order with Java's cached "function after / before the source", whose staleness decides
    /// some targets. A target becomes a function when an unconditional jump (a jump's first
    /// flow reference) passes the next function entry or goes before the previous one, no
    /// conditional flow reaches it, no instruction falls into it and it is not a lone return
    /// (`checkIfCouldHaveFallThruTo`). The functions are the ones with a body (the function
    /// manager's); the targets go to `funcs` and are made by CreateFunctionCmd after the task
    /// (Java queues them with `AutoAnalysisManager.createFunction` at 397, before the next
    /// task). The jumps to a function in `set` are not given CALL_RETURN here
    /// (`processFunctionJumpReferences`): ghidra-rs derives that override (`call_return`).
    fn shared_returns(&mut self, set: &BTreeSet<u32>) {
        let mut cond = HashSet::new();
        for i in self.insns.values() {
            if i.flow == Flow::CondJump {
                cond.extend(i.target);
            }
        }
        let funcs = &self.bodies;
        let mut scan = RangeSet::default();
        for &f in set.iter().filter(|f| funcs.contains_key(f)) {
            // checkAboveFunction
            let prev = funcs.range(..f).next_back().map_or(0, |(&p, _)| p);
            scan.add(prev, f);
            // checkBelowFunction
            let body = self.body_ranges(f);
            if body.len() > 1 {
                body.iter().for_each(|&(lo, hi)| scan.add(lo, hi));
            }
            let next = funcs.range(f + 1..).next().map_or(u32::MAX, |(&n, _)| n - 1);
            scan.add(f, next);
            if body.len() <= 1 {
                body.iter().for_each(|&(lo, hi)| scan.remove(lo, hi));
            }
        }
        let mut created = BTreeSet::new();
        // Java's cache: None is null, Some(None) is Address.NO_ADDRESS
        let (mut after, mut before): (Option<Option<u32>>, Option<Option<u32>>) = (None, None);
        let after_of = |a: u32| funcs.range(a + 1..).next().map(|(&n, _)| n);
        let before_of = |a: u32| funcs.range(..a).next_back().map(|(&p, _)| p);
        for (&src, i) in scan.ranges().flat_map(|(lo, hi)| self.insns.range(lo..=hi)) {
            // the first flow reference: the jump's target, or a computed jump's lowest case
            let dest = match i.flow {
                Flow::Jump => i.target,
                Flow::JumpInd => self.tables.get(&src).and_then(|c| c.iter().min().copied()),
                _ => None,
            };
            let Some(dest) = dest else { continue };
            if cond.contains(&dest) {
                continue;
            }
            if src < dest {
                if after == Some(None) {
                    continue;
                }
                if after.is_none_or(|a| a.is_some_and(|a| a <= src)) {
                    after = Some(after_of(src));
                    if after == Some(None) {
                        continue;
                    }
                }
                if after.flatten().is_some_and(|a| dest >= a) {
                    self.shared_target(dest, &mut created);
                }
            } else {
                if after.is_none() {
                    after = Some(after_of(src));
                }
                if before == Some(None) {
                    let Some(a) = after.flatten() else { continue };
                    if src < a {
                        continue;
                    }
                    before = None;
                    after = Some(after_of(src));
                }
                let keep = before.is_some() && after.is_some_and(|a| a.is_none_or(|a| src < a));
                if !keep {
                    before = Some(before_of(src));
                    if before == Some(None) {
                        continue;
                    }
                }
                if before.flatten().is_some_and(|b| dest < b) {
                    self.shared_target(dest, &mut created);
                }
            }
        }
        self.funcs.extend(created);
    }

    /// SharedReturnAnalysisCmd.createFunction: nothing for an existing function (its jump
    /// overrides are derived, see `call_return`), else a function unless something could fall
    /// into the target (`checkIfCouldHaveFallThruTo`): no instruction there, an instruction
    /// whose fallthrough is the target, or a lone terminator (a return).
    fn shared_target(&self, dest: u32, created: &mut BTreeSet<u32>) {
        if self.bodies.contains_key(&dest) {
            return;
        }
        let Some(i) = self.insns.get(&dest) else { return };
        if i.flow == Flow::Return {
            return;
        }
        let falls_in = self.insns.range(..dest).next_back().is_some_and(|(&a, p)| {
            a + p.len as u32 == dest
                && p.falls_through()
                && !(matches!(p.flow, Flow::Call | Flow::CallInd) && self.call_return(a, p))
        });
        if !falls_in {
            created.insert(dest);
        }
    }

    /// The address ranges of a function's body (Ghidra's body AddressSet): its instructions'
    /// bytes, adjacent ones merged.
    fn body_ranges(&self, f: u32) -> Vec<(u32, u32)> {
        let mut out: Vec<(u32, u32)> = Vec::new();
        // the body set (func.getBody)
        for &a in self.bodies.get(&f).into_iter().flatten() {
            let hi = a + self.insns[&a].len as u32 - 1;
            match out.last_mut() {
                Some(last) if last.1.checked_add(1) == Some(a) => last.1 = hi,
                _ => out.push((a, hi)),
            }
        }
        out
    }

    /// Ghidra's CALL_RETURN flow override at an instruction, which ghidra-rs derives: a call of
    /// a non-returning function (the no-return analyzer) and a jump to a function (Shared
    /// Return Calls). An override of the project store wins.
    pub fn call_return(&self, a: u32, i: &Ins) -> bool {
        if let Some(&o) = self.overrides.get(&a) {
            return o;
        }
        match i.flow {
            Flow::Call => i.target.is_some_and(|t| self.noreturn.contains(&t)) && !self.fallthru.contains(&a),
            // not on ELF (x86-64): see `descend`
            Flow::CallInd => self.width != 8 && i.slot.is_some_and(|s| self.noreturn.contains(&s)),
            Flow::Jump => i.target.is_some_and(|t| self.funcs.contains(&t) && self.insns.contains_key(&t)),
            _ => false,
        }
    }

    /// The body of function `f`: the instructions of the ranges the store set for it, else the
    /// flow from its entry up to other function entries.
    pub fn body_of(&self, f: u32) -> Vec<u32> {
        if let Some(ranges) = self.fixed_bodies.get(&f) {
            return ranges.iter().flat_map(|&(lo, hi)| self.insns.range(lo..=hi).map(|(&a, _)| a)).collect();
        }
        self.walk(f, |a| self.funcs.contains(&a))
    }

    /// The flow from `f` (getFunctionBody without other functions): fallthroughs (not past a
    /// CALL_RETURN call), jumps and switch cases, up to the entries `is_entry` names.
    fn walk(&self, f: u32, is_entry: impl Fn(u32) -> bool) -> Vec<u32> {
        let mut seen = BTreeSet::new();
        let mut work = vec![f];
        while let Some(a) = work.pop() {
            if (a != f && is_entry(a)) || !seen.insert(a) {
                continue;
            }
            let Some(i) = self.insns.get(&a) else {
                seen.remove(&a);
                continue;
            };
            let calls = matches!(i.flow, Flow::Call | Flow::CallInd);
            // the override of a jump matters only where the store set one: a derived one
            // targets a function entry, where the walk stops anyway
            let tail = self.overrides.get(&a) == Some(&true);
            if i.falls_through() && !(calls && self.call_return(a, i)) {
                work.push(a + i.len as u32);
            }
            if matches!(i.flow, Flow::Jump | Flow::CondJump) && !tail {
                work.extend(i.target);
            }
            if let Some(cases) = self.tables.get(&a) {
                work.extend(cases);
            }
        }
        seen.into_iter().collect()
    }

    /// Each function's stack purge, as Ghidra sets it from the function's returns: the `n` of
    /// `RET n` (0 for `RET`), where every return of the body agrees.
    pub fn stack_purges(&mut self, img: &Image) {
        self.purge.clear();
        for (&f, body) in &self.bodies {
            let mut pops = body.iter().filter(|a| self.insns[a].flow == Flow::Return).map(|&a| {
                let s = img.block_of(a).unwrap();
                match s.data[(a - s.addr) as usize..].strip_prefix(&[0xf3]).unwrap_or(&s.data[(a - s.addr) as usize..])
                {
                    [0xc3, ..] => Some(0),
                    [0xc2, lo, hi, ..] => Some(u16::from_le_bytes([*lo, *hi]) as u32),
                    _ => None,
                }
            });
            if let Some(Some(n)) = pops.next() {
                if pops.all(|p| p == Some(n)) {
                    self.purge.insert(f, n);
                }
            }
        }
    }

    /// Ghidra's ConstantPropagationAnalyzer: `SymbolicPropogator.flowConstants` from every
    /// function entry over its body, with the registers of the entry as symbols. Each path
    /// keeps its own state: a conditional branch goes on with the fallthrough and saves a
    /// copy for its target (taken later, last saved first), and a flow into code already
    /// visited runs on for at most 16 instructions or up to a call, as Ghidra's
    /// MAX_EXTRA_INSTRUCTION_FLOW (Ghidra does not merge the states where flows join; the
    /// first flow to reach code decides its values). A jump to another function is a tail
    /// call and ends the path. The references, code constants and computed targets of the
    /// instructions of a body are then the ones these walks find (all of them, where several
    /// walks or functions visit an instruction), in place of the local fold's.
    pub fn propagate(&mut self, img: &Image, sl: &Sleigh) {
        let funcs: Vec<u32> = self.funcs.iter().copied().filter(|f| self.bodies.contains_key(f)).collect();
        let n = std::env::var("GHIDRA_RS_THREADS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or_else(|| std::thread::available_parallelism().map_or(1, |n| n.get()))
            .max(1);
        let this = &*self;
        // merged in function order, so the result does not depend on the thread count. The
        // walks run a chunk of functions at a time and each chunk is merged before the next, so
        // the decodes of all functions are never held at once (on Hatred they were about 6 GB)
        let mut merged: HashMap<u32, Ins> = HashMap::new();
        for funcs in funcs.chunks(1 << 14) {
            let found: Vec<Vec<Vec<(u32, Ins)>>> = std::thread::scope(|s| {
                let hs: Vec<_> = (0..n)
                    .map(|t| {
                        s.spawn(move || {
                            let mut p = sl.new_parse();
                            funcs
                                .iter()
                                .skip(t)
                                .step_by(n)
                                .map(|&f| this.flow_constants(img, sl, &mut p, f))
                                .collect::<Vec<_>>()
                        })
                    })
                    .collect();
                hs.into_iter().map(|h| h.join().unwrap()).collect()
            });
            for i in 0..funcs.len() {
                for (a, d) in &found[i % n][i / n] {
                    let m = merged.entry(*a).or_insert_with(|| Ins {
                        refs: Vec::new(),
                        rw: Vec::new(),
                        code_imms: Vec::new(),
                        computed: None,
                        ..d.clone()
                    });
                    for &r in &d.refs {
                        if !m.refs.contains(&r) {
                            m.refs.push(r);
                        }
                    }
                    for &r in &d.rw {
                        if !m.rw.contains(&r) {
                            m.rw.push(r);
                        }
                    }
                    for &c in &d.code_imms {
                        if !m.code_imms.contains(&c) {
                            m.code_imms.push(c);
                        }
                    }
                    m.computed = m.computed.or(d.computed);
                }
            }
        }
        for (a, d) in merged {
            let i = self.insns.get_mut(&a).unwrap();
            (i.refs, i.rw, i.code_imms, i.computed) = (d.refs, d.rw, d.code_imms, d.computed);
        }
    }

    /// One function's walk for `propagate`: every decode of an instruction of the body, with
    /// the state the walk brought there.
    fn flow_constants(&self, img: &Image, sl: &Sleigh, p: &mut crate::sleigh::Parse, f: u32) -> Vec<(u32, Ins)> {
        self.flow_walk(img, sl, p, f, false, &mut |_, _| {})
    }

    /// The walk of `flow_constants`; `visit` sees each instruction's address and the state
    /// after it. With `stack_and`, `AND ESP,mask` keeps ESP a stack address.
    pub fn flow_walk(
        &self,
        img: &Image,
        sl: &Sleigh,
        p: &mut crate::sleigh::Parse,
        f: u32,
        stack_and: bool,
        visit: &mut dyn FnMut(u32, &Fold),
    ) -> Vec<(u32, Ins)> {
        const MAX_EXTRA_INSTRUCTION_FLOW: u32 = 16;
        let body = &self.bodies[&f];
        let (mut out, mut visited, mut edges) = (Vec::new(), HashSet::new(), HashSet::new());
        // (destination, source, state, instructions run since hitting visited code)
        let mut stack = vec![(f, f, Fold { whole: true, stack_and, ..Fold::default() }, None::<u32>)];
        while let Some((mut a, src, mut fold, mut extra)) = stack.pop() {
            if !edges.insert((a, src)) {
                continue; // already flowed here from there
            }
            if visited.contains(&a) {
                extra = extra.or(Some(0));
            }
            let mut popped = true;
            while body.binary_search(&a).is_ok() {
                let Some(ins) = self.insns.get(&a) else { break };
                if !visited.contains(&a) {
                    extra = None;
                }
                let Some(d) = self.decode(img, sl, p, a, &mut fold) else { break };
                visit(a, &fold);
                let computed = d.computed;
                out.push((a, d));
                let call = matches!(ins.flow, Flow::Call | Flow::CallInd);
                if !popped && !visited.insert(a) {
                    let e = extra.map_or(0, |e| e + 1);
                    extra = Some(e);
                    if e >= MAX_EXTRA_INSTRUCTION_FLOW || call {
                        break;
                    }
                }
                visited.insert(a);
                popped = false;
                match ins.flow {
                    Flow::CondJump => stack.extend(ins.target.map(|t| (t, a, fold.clone(), extra))),
                    Flow::Jump => {
                        stack.extend(
                            ins.target.filter(|t| !self.funcs.contains(t)).map(|t| (t, a, fold.clone(), extra)),
                        );
                        break;
                    }
                    Flow::JumpInd => {
                        let cases = self.tables.get(&a).cloned().unwrap_or_default();
                        stack.extend(cases.into_iter().chain(computed).map(|t| (t, a, fold.clone(), extra)));
                        break;
                    }
                    Flow::Return => break,
                    Flow::Call if ins.target.is_some_and(|t| self.noreturn.contains(&t)) => break,
                    Flow::CallInd if ins.slot.is_some_and(|s| self.noreturn.contains(&s)) => break,
                    _ => {}
                }
                a += ins.len as u32;
            }
        }
        out
    }

    /// The function a call references, as Ghidra's `getCalledFunctions` counts it: a direct
    /// CALL; a JMP to a function entry (Shared Return Calls makes it a call; counting these
    /// matches Ghidra better than not, though Ghidra leaves some as jumps, e.g. 0x72cc00);
    /// `CALL [slot]` through an import slot (the slot stands for the external function);
    /// `CALL [global]` whose initial value is a function entry.
    pub fn call_target(&self, img: &Image, i: &Ins) -> Option<u32> {
        match (i.flow, i.slot) {
            (Flow::Call | Flow::Jump, _) => i.target.filter(|t| self.funcs.contains(t)),
            (Flow::CallInd, Some(s)) if img.imports.contains_key(&s) => Some(s),
            (Flow::CallInd, Some(s)) => img.read_ptr(s).filter(|t| self.funcs.contains(t)),
            _ => None,
        }
    }

    /// The bytes the RETs of `f` pop (`RET n`), where they agree.
    /// Replace the purges a call's stack effect goes by (function entry or import slot ->
    /// bytes popped besides the return address); returns the ones replaced.
    pub fn swap_call_purges(&mut self, purges: HashMap<u32, u32>) -> HashMap<u32, u32> {
        std::mem::replace(&mut self.purge, purges)
    }

    pub fn purge(&self, f: u32) -> Option<u32> {
        self.purge.get(&f).copied()
    }

    pub fn body_size(&self, f: u32) -> u64 {
        self.bodies[&f].iter().map(|a| self.insns[a].len as u64).sum()
    }
}

/// A little-endian pointer of 4 or 8 bytes; None past 32 bits.
/// ElfSymbol.isColdSymbol's pattern `.+\.cold((\.[0-9]+)?)` (ElfSymbol.java:96-98), a whole match.
fn is_cold(name: &str) -> bool {
    let tail = |t: &str| {
        t.is_empty() || t.strip_prefix('.').is_some_and(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()))
    };
    name.match_indices(".cold").any(|(i, _)| i > 0 && tail(&name[i + 5..]))
}

fn ptr_value(b: &[u8]) -> Option<u32> {
    match b.len() {
        4 => Some(u32::from_le_bytes(b.try_into().ok()?)),
        _ => u32::try_from(u64::from_le_bytes(b.try_into().ok()?)).ok(),
    }
}

/// AddressTableAnalyzer.findPossibleStrings over `[from, to)`: the ranges of UTF-16 strings
/// longer than 4 characters (tab, CR, LF and 0x20..0x7e, up to a 0 or half the range).
fn mask(x: u64, size: u32) -> u64 {
    if size >= 8 {
        x
    } else {
        x & ((1 << (8 * size)) - 1)
    }
}

fn utf16_strings(s: &Section, from: u32, to: u32) -> Vec<std::ops::RangeInclusive<u32>> {
    let max = (to - from) / 2;
    let short =
        |a: u32| s.data.get((a - s.addr) as usize..(a - s.addr) as usize + 2).map(|b| u16::from_le_bytes([b[0], b[1]]));
    let mut out = Vec::new();
    let mut a = from;
    while a < to {
        let mut n = 0;
        while n < max {
            match short(a + 2 * n) {
                Some(0) => {
                    n += 1;
                    break;
                }
                Some(9 | 10 | 13 | 0x20..=0x7e) => n += 1,
                _ => break,
            }
        }
        if n > 4 {
            out.push(a..=a + 2 * n);
            a += 2 * n;
        } else {
            a += 1;
        }
    }
    out
}

/// Disjoint inclusive address ranges (Ghidra's AddressSet, for one space), first -> last.
#[derive(Default)]
struct RangeSet(BTreeMap<u32, u32>);

impl RangeSet {
    fn add(&mut self, mut lo: u32, mut hi: u32) {
        // merge every range that overlaps or touches [lo, hi]
        let touching: Vec<(u32, u32)> = self
            .0
            .range(..=hi.saturating_add(1))
            .rev()
            .take_while(|&(_, &h)| h.saturating_add(1) >= lo)
            .map(|(&l, &h)| (l, h))
            .collect();
        for (l, h) in touching {
            self.0.remove(&l);
            lo = lo.min(l);
            hi = hi.max(h);
        }
        self.0.insert(lo, hi);
    }

    fn remove(&mut self, lo: u32, hi: u32) {
        let hit: Vec<(u32, u32)> =
            self.0.range(..=hi).rev().take_while(|&(_, &h)| h >= lo).map(|(&l, &h)| (l, h)).collect();
        for (l, h) in hit {
            self.0.remove(&l);
            if l < lo {
                self.0.insert(l, lo - 1);
            }
            if h > hi {
                self.0.insert(hi + 1, h);
            }
        }
    }

    fn ranges(&self) -> impl Iterator<Item = (u32, u32)> + '_ {
        self.0.iter().map(|(&l, &h)| (l, h))
    }

    fn contains(&self, a: u32) -> bool {
        self.0.range(..=a).next_back().is_some_and(|(_, &h)| h >= a)
    }
}

#[cfg(test)]
mod tests {
    use super::{pair_hit, repair, Analysis, Flow, Image, Ins, RangeSet, Section, POST_FILL, PRE_FILL};
    use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

    #[test]
    fn pattern_pairs_need_their_bits() {
        // `CC` + `SUB ESP,8`: 8 + 19 fixed bits, below totalbits 32; `CC CC` + it: 35
        let d = [0x90, 0xcc, 0x83, 0xec, 0x08, 0xcc, 0xcc, 0x83, 0xec, 0x08];
        assert!(!pair_hit(&d, 2, &PRE_FILL, &POST_FILL));
        assert!(pair_hit(&d, 7, &PRE_FILL, &POST_FILL));
    }

    #[test]
    fn range_set_add_remove() {
        let mut s = RangeSet::default();
        s.add(10, 20);
        s.add(30, 40);
        s.add(21, 29); // touches both
        assert_eq!(s.ranges().collect::<Vec<_>>(), [(10, 40)]);
        s.remove(15, 35);
        assert_eq!(s.ranges().collect::<Vec<_>>(), [(10, 14), (36, 40)]);
        s.add(0, u32::MAX);
        s.remove(0, 5);
        assert_eq!(s.ranges().collect::<Vec<_>>(), [(6, u32::MAX)]);
    }

    /// An analysis of `insns` alone (no image), with a function at each of `funcs` made in
    /// order as CreateFunctionCmd makes it.
    pub(super) fn bare(insns: &[(u32, Flow, Option<u32>)], funcs: &[u32]) -> (Analysis, BTreeSet<u32>) {
        let ins = |&(a, flow, target): &(u32, Flow, Option<u32>)| {
            let i = Ins {
                len: 1,
                flow,
                target,
                slot: None,
                computed: None,
                refs: vec![],
                rw: vec![],
                code_imms: vec![],
                nop: false,
            };
            (a, i)
        };
        let mut an = Analysis {
            text_start: 0,
            text_end: 0,
            code_lo: 0,
            code_hi: 0,
            insns: insns.iter().map(ins).collect(),
            tables: HashMap::new(),
            funcs: BTreeSet::new(),
            noreturn: HashSet::new(),
            fallthru: HashSet::new(),
            slot_jumps_inside: HashSet::new(),
            bodies: BTreeMap::new(),
            table_slots: BTreeMap::new(),
            fpu_ip: None,
            purge: HashMap::new(),
            callee_purges: HashMap::new(),
            reg_space: 0,
            width: 4,
            sp: 0x10,
            killed: vec![0, 4, 8],
            stackshift: None,
            overrides: HashMap::new(),
            fixed_bodies: BTreeMap::new(),
            thunks: HashMap::new(),
            thunk_of: BTreeMap::new(),
            body_owner: HashMap::new(),
            warnings: Vec::new(),
            wide_flows: Default::default(),
        };
        let mut changed = BTreeSet::new();
        for &f in funcs {
            an.create_function(f, None, &mut Vec::new(), &mut changed);
        }
        (an, changed)
    }

    #[test]
    fn noreturn_takes_three_call_sites_of_evidence() {
        // calls of 0x40 followed by a function (0x11, 0x21) and by no instruction (0x31);
        // 0x50 is a thunk of 0x40
        let calls = |n: u32| {
            // 0x60 calls the thunk 0x50 before the mark: it keeps its fallthrough (setNoFallThru
            // overrides only the calls of 0x40)
            let mut v = vec![
                (0x40, Flow::Return, None),
                (0x50, Flow::Jump, Some(0x40)),
                (0x60, Flow::Call, Some(0x50)),
                (0x61, Flow::Return, None),
            ];
            for k in 1..=n {
                v.push((0x10 * k, Flow::Call, Some(0x40)));
                if k < 3 {
                    v.push((0x10 * k + 1, Flow::Return, None));
                }
            }
            v
        };
        for (n, nr) in [(2, false), (3, true)] {
            let (mut an, mut changed) = bare(&calls(n), &[0x40, 0x50, 0x10, 0x11, 0x20, 0x21, 0x30]);
            an.find_noreturn(&mut changed, &mut HashSet::new(), &|_| false);
            assert_eq!(an.noreturn.contains(&0x40), nr);
            assert_eq!(an.noreturn.contains(&0x50), nr);
            assert!(!an.call_return(0x60, &an.insns[&0x60]));
            assert_eq!(an.call_return(0x10, &an.insns[&0x10]), nr);
        }
    }

    #[test]
    fn only_calls_noreturn_follows_switch_cases() {
        // 0x60: a switch whose case 0x62 returns and case 0x63 calls 0x40, which does not return
        let (mut an, _) = bare(
            &[
                (0x40, Flow::Return, None),
                (0x60, Flow::JumpInd, None),
                (0x62, Flow::Return, None),
                (0x63, Flow::Call, Some(0x40)),
            ],
            &[0x40, 0x60],
        );
        an.noreturn.insert(0x40);
        an.tables.insert(0x60, vec![0x63]);
        assert!(an.only_calls_noreturn(0x60, &BTreeSet::new()));
        an.tables.insert(0x60, vec![0x62, 0x63]);
        assert!(!an.only_calls_noreturn(0x60, &BTreeSet::new()));
    }
    #[test]
    fn thunk_body_never_takes_a_third_functions_code() {
        // 0x10 JMP 0x12; 0x12 JMP 0x11 makes 0x11 first: 0x10's first body less 0x12's would
        // hold 0x11, so the thunk is tried again on the flow up to the entries made
        let (an, _) = bare(
            &[(0x10, Flow::Jump, Some(0x12)), (0x11, Flow::Return, None), (0x12, Flow::Jump, Some(0x11))],
            &[0x10],
        );
        assert_eq!(an.bodies[&0x10], [0x10]);
        assert_eq!(an.bodies[&0x11], [0x11]);
        assert_eq!(an.thunk_of.get(&0x10), Some(&0x12));
        assert_eq!(an.thunk_of.get(&0x12), Some(&0x11));
    }

    #[test]
    fn repair_flow_damage_clears_only_unreferenced_fallthroughs() {
        // 0x10 and 0x20 call the non-returning 0x40; 0x30 jumps to 0x21, so only 0x11..0x12
        // (and the call 0x60 makes from there) is damage
        let (mut an, mut changed) = bare(
            &[
                (0x10, Flow::Call, Some(0x40)),
                (0x11, Flow::Call, Some(0x60)),
                (0x12, Flow::Return, None),
                (0x20, Flow::Call, Some(0x40)),
                (0x21, Flow::Fall, None),
                (0x22, Flow::Return, None),
                (0x30, Flow::Jump, Some(0x21)),
                (0x40, Flow::Jump, Some(0x40)),
                (0x60, Flow::Return, None),
            ],
            &[0x10, 0x20, 0x30, 0x40, 0x60],
        );
        an.noreturn.insert(0x40);
        for f in [0x10, 0x20] {
            an.fixup_body(f, &mut changed);
        }
        an.code_hi = 0x80;
        let mut owner = vec![0u8; 0x80];
        for &a in an.insns.keys() {
            owner[a as usize] = 1;
        }
        let text =
            Section { name: ".text".into(), exec: true, readonly: true, zero_tail: 0, addr: 0, data: vec![0x90; 0x80] };
        let img = Image { sections: vec![text], ..Image::default() };
        let sl = crate::sleigh::Sleigh::load(&crate::sleigh::Sleigh::sla_path("x86")).unwrap();
        let mut counts = repair::RepairCounts::default();
        let found = BTreeSet::from([0x40]);
        let mut p = sl.new_parse();
        let mut cx = repair::Repair::new(&img, &sl, &mut p, &mut owner, None, &mut changed, &mut counts);
        let again = an.repair_flow_damage(&mut cx, &found).unwrap();
        assert_eq!(again, BTreeSet::from([0x11, 0x12, 0x60]));
        assert!(an.insns.contains_key(&0x21) && !an.insns.contains_key(&0x11));
        // 0x60 was called from the cleared code only: its function goes (ClearCmd)
        assert!(!an.bodies.contains_key(&0x60) && an.bodies.contains_key(&0x40));
        assert_eq!(owner[0x11..0x13], [0, 0]);
    }
}
