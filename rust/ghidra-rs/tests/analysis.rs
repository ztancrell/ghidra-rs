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
        sections: vec![Section { name: ".text".into(), exec: true, addr: 0x401000, data: text }],
        exports: vec![(0x401000, "?Swap@GMatrix2D@@QAEXPAV1@@Z".into())],
        ..Image::default()
    };
    let an = Analysis::run(&img, &sl, &[], false).unwrap();
    assert_eq!(an.funcs.iter().copied().collect::<Vec<_>>(), [0x401000, 0x401010, 0x401020]);
    assert_eq!([an.body_size(0x401000), an.body_size(0x401010), an.body_size(0x401020)], [10, 6, 5]);

    let mut out = Vec::new();
    export_functions(&img, &an, &mut out).unwrap();
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
