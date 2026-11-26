// PSP relocation entries on a hand-made image: each rule's result worked out by hand, and
// every entry that is not applied counted.
use ghidra_rs::psp::{relocate, Relocs};

#[test]
fn psp_relocations() {
    let words: [u32; 7] = [
        0x0000_0010, // a pointer 0x10 into segment 1
        0x0c00_0010, // jal 0x40
        0x3c03_0001, // lui v1, 0x1
        0x2466_9000, // addiu a2, v1, -0x7000: the pair is 0x9000
        0x8f82_0020, // lw v0, 0x20(gp)
        0x0000_0044,
        0x3c04_0002, // lui a0, 0x2, with no LO16 after it
    ];
    let mut mem: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    // r_info: type, the segment of the offset << 8, the segment whose address is added << 16
    let entries: [(u32, u32); 7] = [
        (0, 2 | 1 << 16), // R_MIPS_32 against segment 1
        (4, 4),           // R_MIPS_26
        (8, 5),           // R_MIPS_HI16
        (12, 6),          // R_MIPS_LO16
        (16, 7),          // R_MIPS_GPREL16: no rule
        (20, 2 | 5 << 8), // segment 5 does not exist
        (24, 5),
    ];
    let rels: Vec<u8> = entries.iter().flat_map(|&(o, i)| [o.to_le_bytes(), i.to_le_bytes()].concat()).collect();
    let mut stats = Relocs::default();
    relocate(&mut mem, &[Some(0), Some(0x100)], 0x0880_4000, &rels, &mut stats);
    let got: Vec<u32> = mem.chunks(4).map(|w| u32::from_le_bytes(w.try_into().unwrap())).collect();
    let want = [
        0x0880_4110, // 0x10 + 0x100 + base
        0x0e20_1010, // jal 0x8804040
        0x3c03_0881, // 0x9000 + base = 0x0880d000 = (0x0881 << 16) - 0x3000
        0x2466_d000,
        0x8f82_0020,
        0x0000_0044,
        0x3c04_0002,
    ];
    assert_eq!(got, want, "{got:#010x?}");
    let want = Relocs {
        applied: [(2, 1), (4, 1), (5, 1), (6, 1)].into(),
        unknown: [(7, 1)].into(),
        unpaired_hi16: 1,
        out_of_image: 1,
        standard: 0,
    };
    assert_eq!(stats, want);
}

// A hand-made module at 0x1000: sceModuleInfo, one import library (two functions, one variable),
// the module's own export entry (module_start and module_info) and a second import entry of a
// size the format does not have.
#[test]
fn psp_module_tables() {
    use ghidra_rs::psp::parse_module;
    let base = 0x1000;
    let mut mem = vec![0u8; 0x100];
    let mut put = |at: usize, words: &[u32]| {
        for (i, w) in words.iter().enumerate() {
            mem[at + 4 * i..at + 4 * i + 4].copy_from_slice(&w.to_le_bytes());
        }
    };
    // sceModuleInfo at 0x1000: attributes and version, the name, gp, ent, stub
    put(0x00, &[0x0102_0000, u32::from_le_bytes(*b"mod\0")]);
    put(0x20, &[0x9000, 0x1040, 0x1050, 0x1050, 0x107c]);
    // the export entry: no name, 4 words, 1 variable, 1 function, the table at 0x1080
    put(0x40, &[0, 0x8000_0000, 0x0001_0104, 0x1080]);
    // the import entry: name, version and flags, 6 words, 1 variable, 2 functions, NIDs, stubs,
    // variables; then an entry of 3 words
    put(0x50, &[0x10a0, 0x4001_0011, 0x0002_0106, 0x1090, 0x10c0, 0x1098, 0, 0, 3]);
    put(0x80, &[0xd632_acdb, 0xf01d_73a7, 0x10d0, 0x1000]);
    put(0x90, &[0x289d_82fe, 0x1234_5678, 0x10e0, 0x9abc_def0]);
    mem[0xa0..0xab].copy_from_slice(b"sceDisplay\0");
    let m = parse_module(&mem, base, 0x1000).unwrap();
    assert_eq!((m.name.as_str(), m.attributes, m.version, m.gp), ("mod", 0, 0x0102, 0x9000));
    assert_eq!((m.ent, m.stub, &m.libraries), ((0x1040, 0x1050), (0x1050, 0x107c), &vec!["sceDisplay".to_string()]));
    let list = |v: &[ghidra_rs::psp::Symbol]| -> Vec<(String, u32, bool, bool)> {
        v.iter().map(|s| (s.name.clone(), s.addr, s.var, s.resolved)).collect()
    };
    let want = [
        ("sceDisplaySetFrameBuf", 0x10c0, false, true), // in the pspsdk table
        ("sceDisplay_0x12345678", 0x10c8, false, false),
        ("sceDisplay_0x9ABCDEF0", 0x10e0, true, false),
    ];
    assert_eq!(list(&m.imports), want.map(|(n, a, v, r)| (n.to_string(), a, v, r)));
    let want = [("module_start", 0x10d0, false, true), ("module_info", 0x1000, true, true)];
    assert_eq!(list(&m.exports), want.map(|(n, a, v, r)| (n.to_string(), a, v, r)));
    assert_eq!(
        m.names().into_iter().collect::<Vec<_>>(),
        [(0x10c0, "sceDisplaySetFrameBuf"), (0x10c8, "sceDisplay_0x12345678"), (0x10d0, "module_start")]
    );
    assert_eq!(m.notes, ["import entry at 0x00001068: size 3 words; the table is cut off here"]);
    // sceModuleInfo itself outside the image is the one error
    assert!(parse_module(&mem, base, 0x10f0).is_err());
    // a NID pspsdk lacks, named by the SHA-1 search table; the same NID in another library is not
    use ghidra_rs::psp::nid_name;
    assert_eq!(nid_name("sceMpeg", 0x4571_cc64), Some("sceMpegAvcDecodeFlush"));
    assert_eq!(nid_name("sceDisplay", 0x4571_cc64), None);
}
