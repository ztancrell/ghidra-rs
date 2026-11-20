// The project store on a hand-made 32-bit .text: edits through `Project` change the analysis and
// the store together, the store's text reads back, and applying it to a fresh analysis gives the
// same program (`Project::finish`).
use ghidra_rs::analysis::{Analysis, Image, Section};
use ghidra_rs::sleigh::Sleigh;
use ghidra_rs::store::{Basis, Project, Store};
use std::collections::BTreeSet;

fn image() -> Image {
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
    text.resize(0x30, 0xcc);
    text.extend([0x90, 0x90, 0xc3]); // 401030 NOP; NOP; RET: reached by nothing
    text.resize(0x40, 0xcc);
    let text = Section { name: ".text".into(), exec: true, readonly: true, zero_tail: 0, addr: 0x401000, data: text };
    Image { sections: vec![text], exports: vec![(0x401000, "main".into())], ..Image::default() }
}

#[test]
fn edits_round_trip_through_the_store() {
    let path = Sleigh::sla_path("x86");
    assert!(path.exists(), "{} is missing: run rust/build-sla.sh first", path.display());
    let (sl, img) = (Sleigh::load(&path).unwrap(), image());
    let base = Analysis::run(&img, &sl, &[], false).unwrap();
    assert_eq!(base.funcs.iter().copied().collect::<Vec<_>>(), [0x401000, 0x401010]);
    let mut p = Project::new(&img, &sl, base.clone(), Store::default());

    // a function where nothing was decoded: not before the code is there
    assert!(!p.create_function(0x401030));
    assert!(p.disassemble(0x401030) && p.create_function(0x401030));
    assert_eq!(p.body_bytes(0x401030), 3);
    // a function inside another splits it; removing it re-flows the owner
    assert_eq!(p.function_containing(0x401014), Some(0x401010));
    assert!(p.create_function(0x401014));
    assert_eq!((p.body_bytes(0x401010), p.body_bytes(0x401014)), (5, 2));
    p.remove_function(0x401014);
    assert_eq!((p.body_bytes(0x401010), p.function_containing(0x401014)), (6, Some(0x401010)));
    assert!(!p.store.functions.contains_key(&0x401014), "created and removed: no record left");
    // a no-return callee cuts its caller; an override of the call brings the rest back
    p.set_noreturn(0x401010, true);
    assert!(p.call_return(0x401003));
    assert_eq!(p.body_bytes(0x401000), 8);
    p.set_override(0x401003, false);
    assert_eq!(p.body_bytes(0x401000), 10);
    // a fixed body holds until the function is re-flowed
    p.set_body(0x401010, &BTreeSet::from([0x401010, 0x401012])).unwrap();
    assert_eq!(p.body_bytes(0x401010), 4);
    p.reflow(0x401010);
    assert_eq!(p.body_bytes(0x401010), 6);
    p.set_body(0x401030, &BTreeSet::from([0x401030, 0x401031])).unwrap();
    // removing a function analysis found is a record
    p.remove_function(0x401000);

    let live_bodies = p.an.bodies.clone();
    let store = p.finish(base.clone()).unwrap();
    let text = store.to_string();
    assert_eq!(
        text,
        "ghidra-rs-store 2 binary 0x0000000000000000 seeds 0x0000000000000000\n\
         code 0x00401030\n\
         noreturn 0x00401010 on\n\
         override 0x00401003 none\n\
         function 0x00401000 remove\n\
         function 0x00401030 create\n\
         body 0x00401030 0x00401030-0x00401031\n"
    );
    assert_eq!(Store::parse(&text).unwrap(), store);
    let mut again = base.clone();
    store.apply(&mut again, &img, &sl).unwrap();
    assert_eq!(again.bodies, live_bodies);
    assert_eq!(again.funcs.iter().copied().collect::<Vec<_>>(), [0x401010, 0x401030]);
}

#[test]
fn records_replay_in_edit_order() {
    let path = Sleigh::sla_path("x86");
    let (sl, img) = (Sleigh::load(&path).unwrap(), image());
    let base = Analysis::run(&img, &sl, &[], false).unwrap();
    let mut p = Project::new(&img, &sl, base.clone(), Store::default());
    // code, then a clear inside what it decoded: applied clear-first, the code would come back
    assert!(p.disassemble(0x401030));
    p.clear(0x401031, 0x401031);
    assert!(p.an.insns.contains_key(&0x401032) && !p.an.insns.contains_key(&0x401031));
    // a body that would take another function's instruction is Java's overlap error
    let err = p.set_body(0x401000, &BTreeSet::from([0x401000, 0x401010])).unwrap_err();
    assert!(err.contains("overlap with range [00401010,00401011]"), "{err}");
    let store = p.finish(base).unwrap();
    assert!(store.to_string().ends_with("code 0x00401030\nclear 0x00401031-0x00401031\n"));
}

#[test]
fn removing_a_function_re_flows_what_falls_into_it() {
    let path = Sleigh::sla_path("x86");
    let (sl, img) = (Sleigh::load(&path).unwrap(), image());
    // a base where 0x401014 is a function: 0x401010's body (the JZ and its target) falls into it
    let mut base = Analysis::run(&img, &sl, &[], false).unwrap();
    let made = Store::parse(&format!("{}function 0x00401014 create\n", Store::default())).unwrap();
    made.apply(&mut base, &img, &sl).unwrap();
    let mut p = Project::new(&img, &sl, base.clone(), Store::default());
    assert_eq!(p.body_bytes(0x401010), 5);
    p.remove_function(0x401014);
    assert_eq!(p.body_bytes(0x401010), 6);
    // the store alone gives the same body (Store::apply re-flows 0x401010 too)
    p.finish(base).unwrap();
}

#[test]
fn a_store_names_its_binary_and_seeds() {
    let basis = Basis::new(b"MZ", &[0x401010, 0x401000, 0x401010], false);
    assert_eq!(basis, Basis::new(b"MZ", &[0x401000, 0x401010], false));
    let store = Store::new(basis);
    assert!(store.check(basis).is_ok());
    assert!(store.check(Basis::new(b"MZ", &[0x401000, 0x401010], true)).unwrap_err().contains("seed set"));
    assert!(store.check(Basis::new(b"MZ!", &[0x401000, 0x401010], false)).unwrap_err().contains("binary"));
    assert_eq!(Store::parse(&store.to_string()).unwrap(), store);
}

#[test]
fn a_store_it_cannot_hold_fails() {
    const H: &str = "ghidra-rs-store 2 binary 0x0000000000000000 seeds 0x0000000000000000\n";
    let path = Sleigh::sla_path("x86");
    let (sl, img) = (Sleigh::load(&path).unwrap(), image());
    let base = Analysis::run(&img, &sl, &[], false).unwrap();
    for (text, why) in [
        ("ghidra-rs-store 1\n".to_string(), "first line"),
        (format!("{H}rename 0x00401000 main\n"), "unknown record"),
        (format!("{H}function 0x401000 create\n"), "bad address"),
        (format!("{H}function 0x00401030 create\nfunction 0x00401030 remove\n"), "second record"),
        (format!("{H}function 0x00401030 create\ncode 0x00401030\n"), "ordered record after"),
    ] {
        assert!(Store::parse(&text).unwrap_err().contains(why), "{text}");
    }
    for (text, why) in [
        (format!("{H}function 0x00401031 create\n"), "function 0x00401031: no instruction"),
        (format!("{H}code 0x00401004\n"), "code 0x00401004: no instruction"),
        (format!("{H}thunk 0x00401030 off\n"), "thunk 0x00401030: no function"),
        (
            format!("{H}code 0x00401030\nclear 0x00401030-0x00401030\noverride 0x00401030 none\n"),
            "override 0x00401030: no instruction",
        ),
    ] {
        let err = Store::parse(&text).unwrap().apply(&mut base.clone(), &img, &sl).unwrap_err();
        assert!(err.contains(why), "{err}");
    }
}
