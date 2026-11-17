// The project store on a hand-made 32-bit .text: edits through `Project` change the analysis and
// the store together, the store's text reads back, and applying it to a fresh analysis gives the
// same program (`Project::finish`).
use ghidra_rs::analysis::{Analysis, Image, Section};
use ghidra_rs::sleigh::Sleigh;
use ghidra_rs::store::{Project, Store};
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
    p.set_body(0x401010, &BTreeSet::from([0x401010, 0x401012]));
    assert_eq!(p.body_bytes(0x401010), 4);
    p.reflow(0x401010);
    assert_eq!(p.body_bytes(0x401010), 6);
    p.set_body(0x401030, &BTreeSet::from([0x401030, 0x401031]));
    // removing a function analysis found is a record
    p.remove_function(0x401000);

    let live_bodies = p.an.bodies.clone();
    let store = p.finish(base.clone()).unwrap();
    let text = store.to_string();
    assert_eq!(
        text,
        "ghidra-rs-store 1\n\
         noreturn 0x00401010 on\n\
         code 0x00401030\n\
         function 0x00401000 remove\n\
         function 0x00401030 create\n\
         body 0x00401030 0x00401030-0x00401031\n\
         override 0x00401003 none\n"
    );
    assert_eq!(Store::parse(&text).unwrap(), store);
    let mut again = base.clone();
    store.apply(&mut again, &img, &sl).unwrap();
    assert_eq!(again.bodies, live_bodies);
    assert_eq!(again.funcs.iter().copied().collect::<Vec<_>>(), [0x401010, 0x401030]);
}

#[test]
fn a_store_it_cannot_hold_fails() {
    let path = Sleigh::sla_path("x86");
    let (sl, img) = (Sleigh::load(&path).unwrap(), image());
    let base = Analysis::run(&img, &sl, &[], false).unwrap();
    for (text, why) in [
        ("ghidra-rs-store 2\n", "first line"),
        ("ghidra-rs-store 1\nrename 0x00401000 main\n", "unknown record"),
        ("ghidra-rs-store 1\nfunction 0x401000 create\n", "bad address"),
        ("ghidra-rs-store 1\ncode 0x00401030\ncode 0x00401030\n", "second record"),
    ] {
        assert!(Store::parse(text).unwrap_err().contains(why), "{text}");
    }
    for (text, why) in [
        ("ghidra-rs-store 1\nfunction 0x00401031 create\n", "function 0x00401031: no instruction"),
        ("ghidra-rs-store 1\ncode 0x00401004\n", "code 0x00401004: no instruction"),
        ("ghidra-rs-store 1\nthunk 0x00401030 off\n", "thunk 0x00401030: no function"),
    ] {
        let err = Store::parse(text).unwrap().apply(&mut base.clone(), &img, &sl).unwrap_err();
        assert!(err.contains(why), "{err}");
    }
}
