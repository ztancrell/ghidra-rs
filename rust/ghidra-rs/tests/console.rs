// Milestone 3 harness (S0): the console reads the corpora's commands and fails loudly on what is
// not ported; the datatest reader parses an upstream XML file and matches like testfunction.cc.
use ghidra_rs::console::{datatest, Console};
use std::path::Path;

#[test]
fn console_unported_commands_fail() {
    let mut c = Console::default();
    let mut out = Vec::new();
    assert!(c.command("option readonly on", &mut out).is_err(), "nothing loaded yet");
    assert_eq!(c.command("print C", &mut out).unwrap_err(), "No function selected");
    assert!(c.command("print raw", &mut out).is_err(), "nothing decompiled yet");
    assert!(c.command("frobnicate", &mut out).unwrap_err().contains("not implemented"));
    assert!(!c.command("quit", &mut out).unwrap());
}

#[test]
fn datatest_parse_and_match() {
    let xml = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../Ghidra/Features/Decompiler/src/decompile/datatests/zerotop.xml");
    let t = datatest::load(&xml).unwrap();
    assert!(!t.commands.is_empty() && !t.checks.is_empty());
    assert_eq!(datatest::ecmascript(r"a\<b\>\.c"), r"a<b>\.c");
    let c = &t.checks[0];
    assert!(c.passes("") == (c.min == 0), "an empty output matches 0 times");
}

/// MIPS-4: a hand-made Allegrex function, loaded from the `<binaryimage>` file both engines
/// read, prints the C of decomp_dbg (tests/data/mips-delay-c.txt, with allegrex.cspec less its
/// `<callotherfixup>` elements: tools/mips-decomp.sh). It covers what MIPS adds to the flow:
/// the store in the `jal`'s delay slot comes once, before the call (the instruction's length
/// includes its delay slot); a `lui`/`addiu` pair folds to one address; the fifth argument is
/// `t0`, as allegrex.cspec passes it; `ra` is the return address.
///   addiu sp,sp,-0x10; sw ra,0(sp); lui a1,0x880; addiu a1,a1,0x4100; li a2,3; li a3,4;
///   li t0,5; jal 0x8804040; sw a0,0(a1); lw ra,0(sp); jr ra; addiu sp,sp,0x10
#[test]
fn mips_delay_slot_print_c() {
    let sla = ghidra_rs::sleigh::Sleigh::allegrex_sla_path();
    assert!(sla.exists(), "{} is missing: run rust/build-sla.sh first", sla.display());
    let xml = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/mips-delay.xml");
    let mut c = Console::default();
    let mut out = Vec::new();
    for line in [&format!("load file {}", xml.display()), "load addr 0x08804000", "decompile"] {
        assert!(c.command(line, &mut out).unwrap());
    }
    out.clear();
    assert!(c.command("print C", &mut out).unwrap());
    assert_eq!(String::from_utf8(out).unwrap(), include_str!("data/mips-delay-c.txt"));
}
