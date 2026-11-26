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
