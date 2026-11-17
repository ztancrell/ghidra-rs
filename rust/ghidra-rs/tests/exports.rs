// mercs2's read-only scripts (`exports.rs`) on a hand-made 32-bit image: a `.text` of three
// pieces of code and a `.rdata` with one registration table of four (name, pointer) pairs.
use ghidra_rs::analysis::{Analysis, Image, Section};
use ghidra_rs::exports;
use ghidra_rs::sleigh::Sleigh;
use ghidra_rs::store::{Project, Store};

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
    text.resize(0x20, 0xcc);
    text.extend([0x68, 0x06, 0x20, 0x40, 0x00, 0xc3]); // 401020 PUSH 0x402006 ("beta"); RET: a function when seeded
    text.resize(0x30, 0xcc);
    text.extend([0x90, 0x90, 0xc3]); // 401030 NOP; NOP; RET: reached by nothing
    text.resize(0x40, 0xcc);
    let mut rdata = b"alpha\0beta\0gamma\0delta\0\0".to_vec(); // 402000, 402006, 40200b, 402011
    for word in [0x402000u32, 0x401000, 0x402006, 0x401010, 0x40200b, 0x401030, 0x402011, 0x401015, 0, 0] {
        rdata.extend(word.to_le_bytes()); // the table: 402018
    }
    let section =
        |name: &str, exec, addr, data| Section { name: name.into(), exec, readonly: true, zero_tail: 0, addr, data };
    Image {
        sections: vec![section(".text", true, 0x401000, text), section(".rdata", false, 0x402000, rdata)],
        exports: vec![(0x401000, "main".into())],
        ..Image::default()
    }
}

fn text(run: impl FnOnce(&mut Vec<u8>) -> Result<(), String>) -> String {
    let mut out = Vec::new();
    run(&mut out).unwrap();
    String::from_utf8(out).unwrap()
}

#[test]
fn scripts_on_a_small_image() {
    let path = Sleigh::sla_path("x86");
    assert!(path.exists(), "{} is missing: run rust/build-sla.sh first", path.display());
    let (sl, img) = (Sleigh::load(&path).unwrap(), image());
    let base = Analysis::run(&img, &sl, &[], false).unwrap();
    let mut p = Project::new(&img, &sl, base.clone(), Store::default());

    assert_eq!(
        text(|o| exports::mod_hook_owners(&p, "address,span\n0x00401014,1\n0x0040103c,1\n", o)),
        "address,function_address\n0x00401014,0x00401010\n0x0040103c,\n"
    );
    assert_eq!(
        text(|o| exports::slot_owners(&p, "site,slot,target\n0x401009,1,2\n\n", o)),
        "site,function\n0x401009,0x00401000\n"
    );
    assert_eq!(
        text(|o| exports::call_contexts(&p, "0x401010", o).map(|n| assert_eq!(n, 1))),
        "REFERENCE 00401003 UNCONDITIONAL_CALL owner=00401000\n00401000 PUSH EBP\n00401001 MOV EBP,ESP\n\
         00401003 CALL 0x00401010\n00401008 POP EBP\n00401009 RET\n\nTOTAL_REFERENCES 1\n"
    );
    let around = text(|o| exports::inspect_boundaries(&p, &["0x401014"], o));
    assert!(
        around.starts_with(
            "ADDRESS 00401014\nFUNCTION 00401010 count=6 min=00401010 max=00401015 noreturn=false\n\
             RANGE [00401010, 00401015]\nFUNCTION 00401010 count=6"
        ),
        "{around}"
    );
    assert!(around.contains("\n00401012 JZ 0x00401015 owner=00401010 override=NONE\n"), "{around}");
    assert_eq!(
        text(|o| exports::audit_recovered_functions(&mut p, "0,0x00401010,call,created\n0,0x1,x,existing\n", true, o)),
        "address,size,instructions,instruction_bytes,non_instruction_bytes,outside_text,wrapper_flows,status\n\
         0x00401010,6,4,6,0,0,0,retained\n"
    );
    assert!(exports::audit_recovered_functions(&mut p, "0,0x00401030,call,created\n", false, &mut Vec::new()).is_err());

    // the table, and with `recover` a function at the one target that lies in none
    let table = "table,index,name,function,library\n0x00402018,0,\"alpha\",0x00401000,\n\
                 0x00402018,1,\"beta\",0x00401010,\n0x00402018,2,\"gamma\",0x00401030,\n\
                 0x00402018,3,\"delta\",0x00401015,\n";
    assert_eq!(text(|o| exports::export_bindings(&mut p, false, o)), table);
    assert!(!p.an.funcs.contains(&0x401030));
    assert_eq!(text(|o| exports::export_bindings(&mut p, true, o)), table);
    assert!(p.an.funcs.contains(&0x401030) && !p.an.funcs.contains(&0x401015));
    assert!(p.finish(base).is_ok());
}

#[test]
fn library_evidence_reads_the_strings_of_the_facts() {
    let (sl, img) = (Sleigh::load(&Sleigh::sla_path("x86")).unwrap(), image());
    let an = Analysis::run(&img, &sl, &[0x401020], false).unwrap();
    let p = Project::new(&img, &sl, an, Store::default());
    let facts = exports::Facts::parse(
        "ghidra-rs-facts 2\nstring\t402006\t5\t4\nfunc\t401000\t<function id=\"1\" name=\"a&lt;b\">\n",
    )
    .unwrap();
    assert_eq!(facts.names[&0x401000], "a<b");
    assert_eq!(
        text(|o| exports::library_evidence(&p, "marker,module,source\net,lib,src\n", &facts, o)
            .map(|n| assert_eq!(n, 1))),
        "address,module,string_address,marker,source\n0x00401020,lib,0x00402006,\"et\",\"src\"\n"
    );
    assert!(exports::library_evidence(&p, "marker,module\n", &facts, &mut Vec::new()).is_err());
    // a string that is not plain and may hold the marker is an error
    let wide = exports::Facts::parse("ghidra-rs-facts 2\nstring\t402006\t5\t-\n").unwrap();
    assert!(exports::library_evidence(&p, "marker,module,source\net,lib,src\n", &wide, &mut Vec::new()).is_err());
}
