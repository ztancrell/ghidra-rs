// Function discovery, bodies, call xrefs and the ExportFunctions/ExportGaps writers on a
// hand-made 32-bit .text: an exported function calling a second one, and a third that only
// the prologue pattern search finds.
use ghidra_rs::analysis::{Analysis, Image, Section};
use ghidra_rs::scripts::{export_functions, export_gaps};
use ghidra_rs::sleigh::Sleigh;

#[test]
fn discover_functions_x86_32() {
    let path = Sleigh::sla_path("x86");
    assert!(path.exists(), "{} is missing: run rust/build-sla.sh first", path.display());
    let sl = Sleigh::load(&path).unwrap();
    let mut text = vec![
        0x55, 0x8b, 0xec, // 401000 PUSH EBP; MOV EBP,ESP
        0xe8, 0x08, 0x00, 0x00, 0x00, // 401003 CALL 0x401010
        0x5d, 0xc3, // 401008 POP EBP; RET
        0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // padding
        0x31, 0xc0, // 401010 XOR EAX,EAX
        0x74, 0x01, // 401012 JZ 0x401015
        0x40, // 401014 INC EAX
        0xc3, // 401015 RET
    ];
    text.resize(0x20, 0xcc);
    text.extend([0x55, 0x8b, 0xec, 0x5d, 0xc3]); // 401020: reached by nothing
    text.resize(0x30, 0xcc);
    let img = Image {
        sections: vec![Section {
            name: ".text".into(),
            exec: true,
            readonly: true,
            zero_tail: 0,
            addr: 0x401000,
            data: text,
        }],
        exports: vec![(0x401000, "?Swap@GMatrix2D@@QAEXPAV1@@Z".into())],
        ..Image::default()
    };
    let an = Analysis::run(&img, &sl, &[], false).unwrap();
    assert_eq!(an.funcs.iter().copied().collect::<Vec<_>>(), [0x401000, 0x401010, 0x401020]);
    assert_eq!([an.body_size(0x401000), an.body_size(0x401010), an.body_size(0x401020)], [10, 6, 5]);

    let mut out = Vec::new();
    export_functions(&img, &an, &Default::default(), &mut out).unwrap();
    assert_eq!(
        String::from_utf8(out).unwrap(),
        "address,size,name,exported,fid,vtable_class,lua,callees,callers,data_refs\n\
         0x00401000,10,\"GMatrix2D::Swap\",1,0,\"\",0,1,0,0\n\
         0x00401010,6,\"\",0,0,\"\",0,0,1,0\n\
         0x00401020,5,\"\",0,0,\"\",0,0,0,0\n"
    );
    let mut out = Vec::new();
    assert_eq!(export_gaps(&img, &an, &mut out).unwrap(), (21, 0x30));
    assert_eq!(
        String::from_utf8(out).unwrap(),
        "address,size,class\n0x0040100a,6,padding\n0x00401016,10,padding\n0x00401025,11,padding\n"
    );
}

// An x87 instruction's p-code copies its own address into FPUInstructionPointer: that is no
// code constant. SecuROM's disguised call `PUSH next; PUSH callee; RET` is reached through its
// code constants, without changing the function bodies.
#[test]
fn code_constants_x86_32() {
    let sl = Sleigh::load(&Sleigh::sla_path("x86")).unwrap();
    let mut text = vec![
        0xd9, 0x01, // 401000 FLD float ptr [ECX]
        0x68, 0x10, 0x10, 0x40, 0x00, // 401002 PUSH 0x401010 (return address)
        0x68, 0x20, 0x10, 0x40, 0x00, // 401007 PUSH 0x401020 (callee)
        0xc3, // 40100c RET
    ];
    // (a lone RET would be no valid subroutine to Ghidra, so each target is two instructions)
    text.resize(0x10, 0xcc);
    text.extend([0x33, 0xc0, 0xc3]); // 401010 XOR EAX,EAX; RET
    text.resize(0x20, 0xcc);
    text.extend([0x33, 0xc0, 0xc3]); // 401020 XOR EAX,EAX; RET
    text.resize(0x30, 0xcc);
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
    let mut an = Analysis::run(&img, &sl, &[0x401000], true).unwrap();
    assert!(an.insns[&0x401000].code_imms.is_empty());
    assert!(!an.insns.contains_key(&0x401010) && !an.insns.contains_key(&0x401020));
    an.disassemble(&img, &sl, &[], true);
    assert!(an.insns.contains_key(&0x401010) && an.insns.contains_key(&0x401020));
    assert_eq!(an.bodies[&0x401000].len(), 4);
}

// SecuROM hides a code address as two dwords XORed together (`MOV EDI,[a]; XOR EDI,[b];
// PUSH EDI`): the local constant fold makes the stored value a code constant at the PUSH,
// and the code there is disassembled (it decodes, returns, and is more than one instruction).
#[test]
fn xor_folded_code_pointer_x86_32() {
    let sl = Sleigh::load(&Sleigh::sla_path("x86")).unwrap();
    let mut text = vec![
        0x8b, 0x3d, 0x00, 0x20, 0x40, 0x00, // 401000 MOV EDI,[0x402000]
        0x33, 0x3d, 0x04, 0x20, 0x40, 0x00, // 401006 XOR EDI,[0x402004]
        0x57, // 40100c PUSH EDI
        0xc3, // 40100d RET
    ];
    text.resize(0x20, 0xcc);
    text.extend([0x33, 0xc0, 0xc3]); // 401020 XOR EAX,EAX; RET
    text.resize(0x30, 0xcc);
    let mut data = 0x1234_5678u32.to_le_bytes().to_vec();
    data.extend((0x1234_5678u32 ^ 0x401020).to_le_bytes());
    let img = Image {
        sections: vec![
            Section { name: ".text".into(), exec: true, readonly: true, zero_tail: 0, addr: 0x401000, data: text },
            Section { name: ".data".into(), exec: false, readonly: false, zero_tail: 0, addr: 0x402000, data },
        ],
        ..Image::default()
    };
    let mut an = Analysis::run(&img, &sl, &[0x401000], true).unwrap();
    assert_eq!(an.insns[&0x40100c].code_imms, [0x401020]);
    assert!(!an.insns.contains_key(&0x401020));
    an.disassemble(&img, &sl, &[], true);
    assert!(an.insns.contains_key(&0x401020) && an.insns.contains_key(&0x401022));
}

// A call through an object's vtable (`MOV [ESI],vtable; MOV ECX,ESI; JMP; MOV EAX,[ECX];
// MOV EDX,[EAX+4]; CALL EDX`): the fold keeps ESI as a symbol, remembers what was stored
// through it across the jump, and gives the slot a READ reference and the call its target
// (Ghidra's COMPUTED_CALL reference).
#[test]
fn vtable_call_through_symbolic_store_x86_32() {
    let sl = Sleigh::load(&Sleigh::sla_path("x86")).unwrap();
    let mut text = vec![
        0xc7, 0x06, 0x00, 0x20, 0x40, 0x00, // 401000 MOV dword ptr [ESI],0x402000
        0x8b, 0xce, // 401006 MOV ECX,ESI
        0xeb, 0x00, // 401008 JMP 0x40100a
        0x8b, 0x01, // 40100a MOV EAX,[ECX]
        0x8b, 0x50, 0x04, // 40100c MOV EDX,[EAX + 0x4]
        0xff, 0xd2, // 40100f CALL EDX
        0xc3, // 401011 RET
    ];
    text.resize(0x20, 0xcc);
    text.extend([0x33, 0xc0, 0xc3]); // 401020 XOR EAX,EAX; RET
    text.resize(0x30, 0xcc);
    let mut data = 0x401030u32.to_le_bytes().to_vec();
    data.extend(0x401020u32.to_le_bytes());
    let img = Image {
        sections: vec![
            Section { name: ".text".into(), exec: true, readonly: true, zero_tail: 0, addr: 0x401000, data: text },
            Section { name: ".rdata".into(), exec: false, readonly: true, zero_tail: 0, addr: 0x402000, data },
        ],
        ..Image::default()
    };
    let an = Analysis::run(&img, &sl, &[0x401000], true).unwrap();
    assert!(an.insns[&0x40100c].refs.contains(&0x402004));
    assert_eq!(an.insns[&0x40100f].computed, Some(0x401020));

    // With 0x401020 a function, ExportFunctions counts the computed call (callees, callers).
    let mut an = Analysis::run(&img, &sl, &[0x401000, 0x401020], true).unwrap();
    an.propagate(&img, &sl);
    let mut out = Vec::new();
    export_functions(&img, &an, &Default::default(), &mut out).unwrap();
    let rows = String::from_utf8(out).unwrap();
    assert!(rows.contains("0x00401000,18,\"\",0,0,\"\",0,1,0,"), "{rows}");
    assert!(rows.contains("0x00401020,3,\"\",0,0,\"\",0,0,1,0"), "{rows}");
}

// Whole-function constant propagation: a vtable stored to the stack must survive a call to a
// `RET 4` function (the callee's purge) and a join, so `CALL [EAX+4]` gets its target. The
// local fold of discovery, which knows no purges yet, loses ESP at the call.
#[test]
fn propagation_survives_call_purge_and_join_x86_32() {
    let sl = Sleigh::load(&Sleigh::sla_path("x86")).unwrap();
    let mut text = vec![
        0x83, 0xec, 0x08, // 401000 SUB ESP,0x8
        0xc7, 0x04, 0x24, 0x00, 0x20, 0x40, 0x00, // 401003 MOV dword ptr [ESP],0x402000
        0x6a, 0x01, // 40100a PUSH 0x1
        0xe8, 0x1f, 0x00, 0x00, 0x00, // 40100c CALL 0x401030 (RET 0x4)
        0x85, 0xc0, // 401011 TEST EAX,EAX
        0x74, 0x01, // 401013 JZ 0x401016
        0x90, // 401015 NOP
        0x8b, 0x04, 0x24, // 401016 MOV EAX,dword ptr [ESP]
        0xff, 0x50, 0x04, // 401019 CALL dword ptr [EAX + 0x4]
        0x83, 0xc4, 0x08, // 40101c ADD ESP,0x8
        0xc3, // 40101f RET
    ];
    text.resize(0x30, 0xcc);
    text.extend([0xc2, 0x04, 0x00]); // 401030 RET 0x4
    text.resize(0x40, 0xcc);
    text.extend([0x33, 0xc0, 0xc3]); // 401040 XOR EAX,EAX; RET
    text.resize(0x50, 0xcc);
    let mut data = 0x401050u32.to_le_bytes().to_vec();
    data.extend(0x401040u32.to_le_bytes());
    let img = Image {
        sections: vec![
            Section { name: ".text".into(), exec: true, readonly: true, zero_tail: 0, addr: 0x401000, data: text },
            Section { name: ".rdata".into(), exec: false, readonly: true, zero_tail: 0, addr: 0x402000, data },
        ],
        ..Image::default()
    };
    let mut an = Analysis::run(&img, &sl, &[0x401000, 0x401030, 0x401040], true).unwrap();
    assert_eq!(an.insns[&0x401019].computed, None);
    an.disassemble(&img, &sl, &[], true);
    assert_eq!(an.insns[&0x401019].computed, Some(0x401040));
    assert!(an.insns[&0x401019].refs.contains(&0x402004));
}
