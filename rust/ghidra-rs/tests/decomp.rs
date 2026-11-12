// Milestone 3, stages S1a and S1b: `print raw` at `break start funclink` and `heritage` for
// mercs2's 0x40a110, rebuilt from its bytes, against the reference decompiler's output
// (decomp_dbg, committed under tests/data). It covers flow across a jump, a conditional branch
// (blocks in reverse post-order), an import thunk jump turned into a call and a halt, the
// INDIRECT that ActionExtraPopSetup puts before the call, the tracked DF of ActionConstbase, the
// RETURN of ActionPrototypeTypes and the call's stack-pointer placeholder (ActionFuncLink).
use ghidra_rs::analysis::{Image, Section};
use ghidra_rs::decomp::{action, print_raw, Arch, Funcdata};
use ghidra_rs::sleigh::Sleigh;

#[test]
fn print_raw_at_funclink() {
    assert_eq!(raw_at(img_40a110(), 0x40a110, "funclink"), include_str!("data/raw-funclink-40a110.txt"));
}

/// At `heritage` the call has its stack-pointer placeholder: the default `__stdcall` model
/// passes parameters on the stack.
#[test]
fn print_raw_at_heritage() {
    assert_eq!(raw_at(img_40a110(), 0x40a110, "heritage"), include_str!("data/raw-heritage-40a110.txt"));
}

fn img_40a110() -> Image {
    let section = |addr: u32, data: Vec<u8>| Section {
        name: ".text".into(),
        exec: true,
        readonly: true,
        zero_tail: 0,
        addr,
        data,
    };
    Image {
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
    }
}

/// INTO branches inside its own p-code to the end of the instruction (a relative branch to the
/// fall-through), which needs the instruction recorded as visited before its ops are walked.
/// Expected output: decomp_dbg on a `load test file` image holding `INTO; RET` at 0x401000.
#[test]
fn print_raw_relative_branch_to_own_end() {
    let text = Section {
        name: ".text".into(),
        exec: true,
        readonly: true,
        zero_tail: 0,
        addr: 0x401000,
        data: vec![0xce, 0xc3],
    };
    let img = Image { sections: vec![text], ..Image::default() };
    assert_eq!(raw_at(img, 0x401000, "funclink"), include_str!("data/raw-funclink-into.txt"));
}

/// `print raw` after running the universal action up to `stop`.
fn raw_at(img: Image, entry: u64, stop: &str) -> String {
    let path = Sleigh::sla_path("x86");
    assert!(path.exists(), "{} is missing: run rust/build-sla.sh first", path.display());
    let cspec = std::fs::read_to_string(path.with_file_name("x86win.cspec")).unwrap();
    let arch = Arch::new(Sleigh::load(&path).unwrap(), img, &cspec).unwrap();
    let mut fd = Funcdata::new(entry);
    action::perform(&mut fd, &arch, Some(stop)).unwrap();
    print_raw(&fd, &arch).unwrap()
}
