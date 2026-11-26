// Decodes the start of /usr/bin/ls's _start (bytes copied in) and checks the text and p-code
// against what Ghidra's C++ SLEIGH engine prints for the same bytes (rust/tools/sleigh_ref.cc).
use ghidra_rs::sleigh::Sleigh;

#[test]
fn decode_x86_64_sequence() {
    let path = Sleigh::default_sla_path();
    assert!(path.exists(), "{} is missing: run rust/build-sla.sh first", path.display());
    let sl = Sleigh::load(&path).unwrap();
    let code: &[u8] = &[
        0xf3, 0x0f, 0x1e, 0xfa, 0x31, 0xed, 0x49, 0x89, 0xd1, 0x5e, 0x48, 0x89, 0xe2, 0x48, 0x83, 0xe4, 0xf0, 0x50,
        0x54, 0x45, 0x31, 0xc0, 0x31, 0xc9, 0x48, 0x8d, 0x3d, 0x41, 0xdf, 0xff, 0xff, 0xff, 0x15, 0x5b, 0x26, 0x02,
        0x00,
    ];
    let expected = [
        (0x5620, "ENDBR64 "),
        (0x5624, "XOR EBP,EBP"),
        (0x5626, "MOV R9,RDX"),
        (0x5629, "POP RSI"),
        (0x562a, "MOV RDX,RSP"),
        (0x562d, "AND RSP,-0x10"),
        (0x5631, "PUSH RAX"),
        (0x5632, "PUSH RSP"),
        (0x5633, "XOR R8D,R8D"),
        (0x5636, "XOR ECX,ECX"),
        (0x5638, "LEA RDI,[0x3580]"),
        (0x563f, "CALL qword ptr [0x27ca0]"),
    ];
    let mut p = sl.new_parse();
    let mut addr = 0x5620u64;
    for (want_addr, want_text) in expected {
        assert_eq!(addr, want_addr);
        let ins = sl.disasm(&mut p, addr, &code[(addr - 0x5620) as usize..]).unwrap();
        assert_eq!(format!("{} {}", ins.mnemonic, ins.body), want_text);
        if ins.mnemonic == "PUSH" && ins.body == "RAX" {
            let ops: Vec<String> = sl.pcode(&p).unwrap().iter().map(|o| sl.fmt_op(o)).collect();
            assert_eq!(
                ops,
                ["unique[0x4f900]:8 = COPY RAX", "RSP = INT_SUB RSP, 0x8:8", "STORE ram, RSP, unique[0x4f900]:8"]
            );
        }
        addr += ins.len as u64;
    }
    assert_eq!(addr, 0x5620 + code.len() as u64);
}

// A MIPS32 `jal` and its delay slot, as relocated in SOCOM FTB's BOOT.BIN (bytes copied in):
// the delay slot's p-code sits before the CALL, and `ra` is the address after the slot. Text
// and p-code are what sleigh_ref prints for the same bytes with mips32le.sla.
#[test]
fn decode_mips32le_delay_slot() {
    let path = Sleigh::mips32le_sla_path();
    assert!(path.exists(), "{} is missing: run rust/build-sla.sh first", path.display());
    let sl = Sleigh::load_with_pspec(&path, Some(&path.with_file_name("mips32.pspec"))).unwrap();
    let code: &[u8] = &[0xfc, 0x04, 0x23, 0x0e, 0x98, 0x98, 0x84, 0x24];
    let mut p = sl.new_parse();
    let ins = sl.disasm(&mut p, 0x880400c, code).unwrap();
    assert_eq!((ins.len, p.fall), (4, 8));
    assert_eq!(format!("{} {}", ins.mnemonic, ins.body), "jal 0x88c13f0");
    let ops: Vec<String> = sl.pcode(&p).unwrap().iter().map(|o| sl.fmt_op(o)).collect();
    assert_eq!(ops, ["ra = COPY 0x8804014:4", "a0 = INT_ADD a0, 0xffff9898:4", "CALL ram[0x88c13f0]:4"]);
    let ins = sl.disasm(&mut p, 0x8804010, &code[4..]).unwrap();
    assert_eq!((ins.len, p.fall), (4, 4));
    assert_eq!(format!("{} {}", ins.mnemonic, ins.body), "addiu a0, a0, -0x6768");
}
