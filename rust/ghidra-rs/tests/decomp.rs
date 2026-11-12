// Milestone 3, stage S1a: `print raw` at `break start funclink` for mercs2's 0x40a110, rebuilt
// from its bytes, against the reference decompiler's output (decomp_dbg, committed under
// tests/data). It covers flow across a jump, a conditional branch (blocks in reverse post-order),
// an import thunk jump turned into a call and a halt, the INDIRECT that ActionExtraPopSetup puts
// before the call, the tracked DF of ActionConstbase and the RETURN of ActionPrototypeTypes.
use ghidra_rs::analysis::{Image, Section};
use ghidra_rs::decomp::{action, print_raw, Arch, Funcdata};
use ghidra_rs::sleigh::Sleigh;

#[test]
fn print_raw_at_funclink() {
    let path = Sleigh::sla_path("x86");
    assert!(path.exists(), "{} is missing: run rust/build-sla.sh first", path.display());
    let section = |addr: u32, data: Vec<u8>| Section { name: ".text".into(), exec: true, addr, data };
    let img = Image {
        sections: vec![
            section(0x40a110, vec![0xe9, 0x4b, 0xe5, 0x09, 0x00]), // JMP 0x4a8660
            section(
                0x4a8660,
                vec![
                    0x8a, 0x88, 0x9c, 0xc8, 0x05, 0x00, // MOV CL,byte ptr [EAX + 0x5c89c]
                    0x84, 0xc9, // TEST CL,CL
                    0x75, 0x2a, // JNZ 0x4a8694
                    0xc7, 0x80, 0x64, 0xc8, 0x05, 0x00, 0xff, 0xff, 0xff, 0xff, // MOV [EAX + 0x5c864],-1
                    0xc7, 0x80, 0x98, 0xc8, 0x05, 0x00, 0xfe, 0xff, 0xff, 0xff, // MOV [EAX + 0x5c898],-2
                    0x03, 0x05, 0xcc, 0xde, 0x4d, 0x02, // ADD EAX,dword ptr [0x24ddecc]
                    0x50, // PUSH EAX
                    0x68, 0x94, 0x86, 0x4a, 0x00, // PUSH 0x4a8694
                    0xff, 0x25, 0x2c, 0x51, 0xb0, 0x00, // JMP dword ptr [0xb0512c] (LeaveCriticalSection)
                    0x13, 0xd6, 0xec, 0x9b, // never reached
                    0xc3, // 4a8694 RET
                ],
            ),
        ],
        ..Image::default()
    };
    let arch = Arch::new(Sleigh::load(&path).unwrap(), img).unwrap();
    let mut fd = Funcdata::new(0x40a110);
    action::perform(&mut fd, &arch, Some("funclink")).unwrap();
    let want = include_str!("data/raw-funclink-40a110.txt");
    assert_eq!(print_raw(&fd, &arch).unwrap(), want);
}
