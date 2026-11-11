// Decodes the start of /usr/bin/ls's _start (bytes copied in) and checks the text and p-code
// against what Ghidra's C++ SLEIGH engine prints for the same bytes (rust/tools/sleigh_ref.cc).
use ghidra_rs::sleigh::Sleigh;

#[test]
fn decode_x86_64_sequence() {
    let path = Sleigh::default_sla_path();
    assert!(path.exists(), "{} is missing: run rust/build-sla.sh first", path.display());
    let sl = Sleigh::load(&path).unwrap();
    let code: &[u8] = &[
        0xf3, 0x0f, 0x1e, 0xfa, 0x31, 0xed, 0x49, 0x89, 0xd1, 0x5e, 0x48, 0x89, 0xe2, 0x48, 0x83, 0xe4,
        0xf0, 0x50, 0x54, 0x45, 0x31, 0xc0, 0x31, 0xc9, 0x48, 0x8d, 0x3d, 0x41, 0xdf, 0xff, 0xff, 0xff,
        0x15, 0x5b, 0x26, 0x02, 0x00,
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
