// Register reads and writes from p-code, as CheckAbiCallers sees them (Ghidra's
// getInputObjects/getResultObjects): sub-registers map to bytes of their base register.
use ghidra_rs::abi::{reads_writes, Checker, Regs};
use ghidra_rs::analysis::{Analysis, Image, Section};
use ghidra_rs::sleigh::Sleigh;

#[test]
fn register_reads_writes_x86_32() {
    let path = Sleigh::sla_path("x86");
    assert!(path.exists(), "{} is missing: run rust/build-sla.sh first", path.display());
    let sl = Sleigh::load(&path).unwrap();
    let regs = Regs::new(&sl);
    let mut p = sl.new_parse();
    let keys = |rs: &[usize]| {
        let mut k: Vec<String> = rs.iter().flat_map(|&r| regs.keys(r).iter().map(|k| k.to_string())).collect();
        k.sort();
        k.join(" ")
    };
    // (bytes, text, read keys, written keys)
    let cases: [(&[u8], &str, &str, &str); 4] = [
        (&[0x00, 0xe2], "ADD DL,AH", "EAX#1 EDX#0", "CF#0 EDX#0 OF#0 PF#0 SF#0 ZF#0"),
        (&[0x8a, 0x01], "MOV AL,byte ptr [ECX]", "ECX#0 ECX#1 ECX#2 ECX#3", "EAX#0"),
        // ECX is written before it is read again: one input, as in Ghidra
        (
            &[0x87, 0xca],
            "XCHG EDX,ECX",
            "ECX#0 ECX#1 ECX#2 ECX#3 EDX#0 EDX#1 EDX#2 EDX#3",
            "ECX#0 ECX#1 ECX#2 ECX#3 EDX#0 EDX#1 EDX#2 EDX#3",
        ),
        (&[0xf3, 0x0f, 0x10, 0xc1], "MOVSS XMM0, XMM1", "ZMM1#0 ZMM1#1 ZMM1#2 ZMM1#3", "ZMM0#0 ZMM0#1 ZMM0#2 ZMM0#3"),
    ];
    for (bytes, text, reads, writes) in cases {
        let d = sl.disasm(&mut p, 0x401000, bytes).unwrap();
        assert_eq!(format!("{} {}", d.mnemonic, d.body), text);
        let (r, w) = reads_writes(&regs, &sl.pcode(&p).unwrap());
        assert_eq!((keys(&r).as_str(), keys(&w).as_str()), (reads, writes), "{text}");
    }
}

// The output check on a hand-made .text. G1 (output al) writes only AL, so EAX#1-3 pass
// through it: C1 reads its own EAX#1-3 back after the call, which the rewrite clobbers. A
// byte the original never writes is returned unchanged, not "never returned". G2 writes all
// of EAX; F reads EAX (an input) before calling it, and C2 reads EAX#1-3 after calling F.
#[test]
fn output_check_pass_through_and_input_eax() {
    let sl = Sleigh::load(&Sleigh::sla_path("x86")).unwrap();
    let mut text = vec![0x89, 0xc8, 0xe8, 0x19, 0, 0, 0, 0x89, 0x01, 0xc3]; // 401000 C1: MOV EAX,ECX; CALL G1; MOV [ECX],EAX; RET
    text.resize(0x10, 0xcc);
    text.extend([0x89, 0xc8, 0xe8, 0x19, 0, 0, 0, 0x89, 0x01, 0xc3]); // 401010 C2: the same, calling F
    text.resize(0x20, 0xcc);
    text.extend([0xb0, 0x01, 0xc3]); // 401020 G1: MOV AL,1; RET
    text.resize(0x30, 0xcc);
    text.extend([0x85, 0xc0, 0xe8, 0x09, 0, 0, 0, 0xc3]); // 401030 F: TEST EAX,EAX; CALL G2; RET
    text.resize(0x40, 0xcc);
    text.extend([0xb8, 0x01, 0, 0, 0, 0xc3]); // 401040 G2: MOV EAX,1; RET
    text.resize(0x50, 0xcc);
    let img = Image {
        sections: vec![Section {
            name: ".text".into(),
            exec: true,
            readonly: true,
            zero_tail: 0,
            addr: 0x401000,
            data: text,
        }],
        ..Image::default()
    };
    let an = Analysis::run(&img, &sl, &[0x401000, 0x401010, 0x401020, 0x401030, 0x401040], true).unwrap();
    let mut ck = Checker::new(&img, &an, &sl, Default::default());
    let csv = "address,name,kind,inputs,cleanup,output,clobbers\n\
               0x00401020,G1,cpp,,callee,al,eax\n\
               0x00401040,G2,cpp,,callee,al,eax\n";
    let mut out = Vec::new();
    ck.run(csv, &mut out, 1).unwrap();
    let out = String::from_utf8(out).unwrap();
    for want in
        ["0x00401020,al|eax,output:00401002,violation,EAX#1", "0x00401040,al|eax,output:00401032,violation,EAX#1"]
    {
        assert!(out.contains(want), "{want} missing from:\n{out}");
    }
}
