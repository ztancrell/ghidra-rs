// The pipeline passes of milestone 2c (docs/plans/m2c-pipeline.md).
use ghidra_rs::pipeline::slot_rewrites;

#[test]
fn slot_rewrites_finds_rewritten_jumps_only() {
    let mut orig = vec![0x90u8; 32];
    let mut patched = orig.clone();
    // site at offset 2: jmp [0x00d01000] became jmp +0x100; nop
    orig[2..8].copy_from_slice(&[0xFF, 0x25, 0x00, 0x10, 0xD0, 0x00]);
    patched[2..8].copy_from_slice(&[0xE9, 0x00, 0x01, 0x00, 0x00, 0x90]);
    // site at offset 12: a slot jump left alone in both images
    orig[12..18].copy_from_slice(&[0xFF, 0x25, 0x04, 0x10, 0xD0, 0x00]);
    patched[12..18].copy_from_slice(&[0xFF, 0x25, 0x04, 0x10, 0xD0, 0x00]);
    // site at offset 20: rewritten to a backward jump (rel32 = -0x20)
    orig[20..26].copy_from_slice(&[0xFF, 0x25, 0x08, 0x10, 0xD0, 0x00]);
    patched[20..26].copy_from_slice(&[0xE9, 0xE0, 0xFF, 0xFF, 0xFF, 0x90]);
    assert_eq!(
        slot_rewrites(&orig, &patched, 0x0040_1000),
        vec![(0x0040_1002, 0x0040_1107), (0x0040_1014, 0x0040_0FF9)]
    );
    // a site cut off by the end of the section is not reported, and nothing panics
    assert_eq!(slot_rewrites(&orig[..5], &patched[..5], 0x0040_1000), vec![]);
}
