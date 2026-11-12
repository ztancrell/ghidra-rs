// Milestone 3 harness (S0): the console reads the corpora's commands and fails loudly on what is
// not ported; the datatest reader parses an upstream XML file and matches like testfunction.cc.
use ghidra_rs::console::{datatest, Console};
use std::path::Path;

#[test]
fn console_unported_commands_fail() {
    let mut c = Console::default();
    let mut out = Vec::new();
    assert!(c.command("option readonly on", &mut out).is_err(), "nothing loaded yet");
    assert!(c.command("print raw", &mut out).unwrap_err().contains("not implemented"));
    assert!(c.command("frobnicate", &mut out).unwrap_err().contains("not implemented"));
    assert!(!c.command("quit", &mut out).unwrap());
}

#[test]
fn datatest_parse_and_match() {
    let xml = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Ghidra/Features/Decompiler/src/decompile/datatests/zerotop.xml");
    let t = datatest::load(&xml).unwrap();
    assert!(!t.commands.is_empty() && !t.checks.is_empty());
    assert_eq!(datatest::ecmascript(r"a\<b\>\.c"), r"a<b>\.c");
    let c = &t.checks[0];
    assert!(c.passes("") == (c.min == 0), "an empty output matches 0 times");
}
