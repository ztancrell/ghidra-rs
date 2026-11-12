// Function ID: the hash of a known MSVC CRT function, and its record in Ghidra's databases.
use ghidra_rs::fid::{default_files, hash, FidDb, HashInsn, Quad};
use ghidra_rs::sleigh::Sleigh;

// @__security_check_cookie@4 as linked into mercs2 at 0x9eec5e:
// CMP ECX,[0xcde2b0]; JNZ +2; REP RET; JMP ___report_gsfailure (a call: Shared Return Calls)
const COOKIE: [(u32, &[u8], bool); 4] = [
    (0x9eec5e, &[0x3b, 0x0d, 0xb0, 0xe2, 0xcd, 0x00], false),
    (0x9eec64, &[0x75, 0x02], false),
    (0x9eec66, &[0xf3, 0xc3], false),
    (0x9eec68, &[0xe9, 0x6f, 0x05, 0x00, 0x00], true),
];
const QUAD: Quad = Quad {
    code_units: 3,
    full: 0x8e1abbebf48dd414_u64 as i64,
    specific_count: 0,
    specific: 0xe1fd1886d3360c04_u64 as i64,
};

#[test]
fn fid_hash() {
    let sl = Sleigh::load(&Sleigh::sla_path("x86")).unwrap();
    let insns: Vec<HashInsn> =
        COOKIE.iter().map(|&(addr, bytes, call)| HashInsn { addr, bytes, call, addresses: [&[], &[]] }).collect();
    assert_eq!(hash(&sl, &insns), Some(QUAD));
    assert_eq!(hash(&sl, &insns[..3]), None, "under 4 code units");
}

#[test]
fn fid_db_record() {
    let files = default_files();
    if files.is_empty() {
        eprintln!("no Ghidra Function ID databases (set GHIDRA_RS_FID): skipped");
        return;
    }
    let found = files.iter().any(|f| {
        let db = FidDb::open(f).unwrap();
        let hit = db.by_full_hash(QUAD.full).any(|r| {
            db.strings[&r.name] == "@__security_check_cookie@4" && r.specific == QUAD.specific && r.code_units == 3
        });
        hit
    });
    assert!(found, "@__security_check_cookie@4 not found by its full hash");
}
