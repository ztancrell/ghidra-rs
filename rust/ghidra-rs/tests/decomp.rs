// Milestone 3, stages S1a, S1b and S2: `print raw` at `break start funclink` and `heritage` for
// mercs2's 0x40a110 (and at `paramdouble` for 0x40ad80, below), rebuilt from its bytes, against
// the reference decompiler's output
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
    let mut actions = action::universal();
    actions.set_break_start(stop).unwrap();
    let brk = actions.perform(&mut fd, &arch).unwrap();
    assert!(matches!(brk, action::Outcome::Break(p) if p.ends_with(&format!("{stop} start"))));
    print_raw(&fd, &arch).unwrap()
}

/// Stage S2: `print raw` at `break start paramdouble`, after the first heritage pass, for
/// mercs2's 0x40ad80 (a loop of byte XORs with an indirect call after it), rebuilt from its
/// bytes, against decomp_dbg's output for the corpus script. It covers MULTIEQUAL placement
/// at the loop head for registers and unique temporaries, renaming across the back edge,
/// inputs, reads and writes widened to their whole range (SUBPIECE/CONCAT), the INDIRECTs and
/// INDIRECT creations at the call, and the return-value inputs of the RETURN.
#[test]
fn print_raw_at_paramdouble_with_a_loop() {
    let section = |addr: u32, data: Vec<u8>| Section {
        name: ".text".into(),
        exec: true,
        readonly: true,
        zero_tail: 0,
        addr,
        data,
    };
    let img = Image {
        sections: vec![
            // MOV ECX,dword ptr [0x24db07c]; JMP 0x730ce0
            section(0x40ad80, vec![0x8b, 0x0d, 0x7c, 0xb0, 0x4d, 0x02, 0xe9, 0x55, 0x5f, 0x32, 0x00]),
            section(
                0x730ce0,
                vec![
                    0x0f, 0xb6, 0x14, 0x0c, 0x30, 0x14, 0x04, 0x8a, 0x14, 0x04, 0x30, 0x14, 0x0c, 0x8a, 0x14, 0x0c,
                    0x30, 0x14, 0x04, 0x83, 0xc0, 0x01, 0x83, 0xe9, 0x01, 0x3b, 0xc1, 0x72, 0xe3, 0x8b, 0x0f, 0x8b,
                    0x01, 0x8b, 0x40, 0x14, 0x6a, 0x02, 0x8d, 0x54, 0x24, 0x04, 0x52, 0xff, 0xd0, 0x8b, 0xc7, 0x59,
                    0xc3,
                ],
            ),
        ],
        ..Image::default()
    };
    assert_eq!(raw_at(img, 0x40ad80, "paramdouble"), include_str!("data/raw-paramdouble-40ad80.txt"));
}

/// Stage S3: `print raw` at `break start paramdouble` for mercs2's 0x5f8f30, a two-level
/// switch (`ADD EDX,-0x21; CMP EDX,0x9d; JA`, a byte table at 0x5f8fac, the jump table at
/// 0x5f8f90), rebuilt from its bytes, against decomp_dbg's output for the corpus script. The
/// jump table comes from the partial function's guard (`!(CF || ZF)` on the normalized
/// variable) and the emulation of the byte and word table loads for each of the 158 values.
#[test]
fn print_raw_at_paramdouble_with_a_switch() {
    let hex = include_str!("data/switch-5f8f30.hex").trim();
    let data = (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect();
    let img = Image {
        sections: vec![Section {
            name: ".text".into(),
            exec: true,
            readonly: true,
            zero_tail: 0,
            addr: 0x5f8f30,
            data,
        }],
        ..Image::default()
    };
    assert_eq!(raw_at(img, 0x5f8f30, "paramdouble"), include_str!("data/raw-paramdouble-5f8f30.txt"));
}
