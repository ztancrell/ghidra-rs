//! Checks over the archives of the Ghidra tree, `windows_vs12_32.gdt` and `generic_clib_64.gdt`
//! (a test fails without them, as the decoder tests do without the .sla files).
use super::*;

fn archive() -> Archive {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../Ghidra/Features/Base/data/typeinfo/win32/windows_vs12_32.gdt");
    assert!(p.exists(), "{} is missing", p.display());
    Archive::open(&p).unwrap()
}

#[test]
fn reads_every_table() {
    let ar = archive();
    let count = |k: i64| ar.types.keys().filter(|&&id| kind(id) == k).count();
    // the record counts of the archive's tables
    assert_eq!(ar.function_defs.len(), 22825);
    assert_eq!(count(COMPOSITE), 6065);
    assert_eq!(count(TYPEDEF), 9441);
    assert_eq!(count(POINTER), 18114);
    assert_eq!(count(ARRAY), 379);
    assert_eq!(count(ENUM), 32504);
    assert_eq!(count(BUILT_IN), 16);
}

/// A checked slice of Java 12.3's export (`ExportArchiveProtos.java`): the first prototype
/// with parameters, one by name, and the first type records.
#[test]
fn protos_match_java_slice() {
    let ar = archive();
    let text = protos::export(&ar).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 1 + 22825 + 17957);
    assert_eq!(lines[0], "ghidra-rs-protos 1");
    assert!(lines[3].starts_with(concat!(
        "proto\t_invoke_watson\t<doc id=\"0x0\"><mapsym><function id=\"0x4\" name=\"_invoke_watson\" ",
        "size=\"@SIZE@\" noreturn=\"true\"><addr space=\"ram\" offset=\"@ADDR@\"/><localdb lock=\"false\" ",
        "main=\"stack\"><scope name=\"_invoke_watson\"><parent id=\"0x0\"/><rangelist/><symbollist><mapsym>",
        "<symbol id=\"0x5\" name=\"param_1\" typelock=\"true\" namelock=\"false\" merge=\"false\" cat=\"0\" ",
        "index=\"0x0\"><type name=\"\" metatype=\"ptr\" size=\"4\"><typeref name=\"wchar_t\" ",
        "id=\"0xc0000000000000d7\"/></type></symbol><addr space=\"stack\" offset=\"0x4\" size=\"4\"/>"
    )));
    let create = lines.iter().find(|l| l.starts_with("proto\tCreateFileA\t")).unwrap();
    // symbols in java.util.HashMap order, stdcall purge, a typedef return in EAX
    assert!(create.contains("<function id=\"0x12ea\""));
    assert!(create.contains("<symbollist><mapsym><symbol id=\"0x12f0\" name=\"dwFlagsAndAttributes\""));
    assert!(create.contains(concat!(
        "<prototype extrapop=\"32\" model=\"__stdcall\" modellock=\"true\"><returnsym typelock=\"true\">",
        "<addr space=\"register\" offset=\"0x0\" size=\"4\"/><typeref name=\"HANDLE\" id=\"0x500000000000052\"/>"
    )));
    assert_eq!(lines[22826], "type\tc0000000000000d7\t<type name=\"wchar_t\" id=\"0xc0000000000000d7\" metatype=\"int\" size=\"2\" utf=\"true\"/>");
    assert_eq!(
        lines[22827],
        "type\t500000000000000\t<def name=\"uintptr_t\" id=\"0x500000000000000\"><type name=\"uint\" id=\"0xc0000000000000cd\" metatype=\"uint\" size=\"4\"/></def>"
    );
}

/// `export_elf64` of `generic_clib_64.gdt` against Java 12.3's facts of an ELF x86-64 program
/// (`puts` and `exit` of tools/corpus/elf64/t1.c, the ids aside): a parameter in RDI from the
/// address before the entry, the return in EAX, no model. The archive does not mark `exit`
/// as not returning: the no-return analyzers do.
#[test]
fn elf64_protos_match_java_slice() {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../Ghidra/Features/Base/data/typeinfo/generic/generic_clib_64.gdt");
    assert!(p.exists(), "{} is missing", p.display());
    let text = protos::export_elf64(&Archive::open(&p).unwrap()).unwrap();
    let proto = |name: &str| text.lines().find(|l| l.starts_with(&format!("proto\t{name}\t"))).unwrap();
    assert!(proto("puts").ends_with(concat!(
        " name=\"__s\" typelock=\"true\" namelock=\"true\" merge=\"false\" cat=\"0\" index=\"0x0\">",
        "<type name=\"\" metatype=\"ptr\" size=\"8\"><type name=\"char\" id=\"0xc00000000000007b\" metatype=\"int\" ",
        "size=\"1\" char=\"true\"/></type></symbol><addr space=\"register\" offset=\"0x38\" size=\"8\"/><rangelist>",
        "<range space=\"ram\" first=\"@PC@\" last=\"@PC@\"/></rangelist></mapsym></symbollist></scope></localdb>",
        "<prototype extrapop=\"8\" model=\"unknown\"><returnsym typelock=\"true\"><addr space=\"register\" ",
        "offset=\"0x0\" size=\"4\"/><type name=\"int\" id=\"0xc000000000000099\" metatype=\"int\" size=\"4\"/>",
        "</returnsym></prototype></function><addr space=\"ram\" offset=\"@ADDR@\" size=\"@SIZE@\"/><rangelist/>",
        "</mapsym></doc>"
    )));
    assert!(proto("exit").contains(concat!(
        "<addr space=\"register\" offset=\"0x38\" size=\"4\"/><rangelist><range space=\"ram\" first=\"@PC@\" ",
        "last=\"@PC@\"/></rangelist></mapsym></symbollist></scope></localdb><prototype extrapop=\"8\" ",
        "model=\"unknown\"><returnsym typelock=\"true\"><addr/><void/></returnsym></prototype>"
    )));
    // every type a prototype names has its record
    let ids: std::collections::HashSet<&str> =
        text.lines().filter_map(|l| l.strip_prefix("type\t")?.split('\t').next()).collect();
    for l in text.lines().filter(|l| l.starts_with("proto\t")) {
        for r in l.split("<typeref ").skip(1) {
            let id = r.split(" id=\"0x").nth(1).and_then(|x| x.split('"').next()).unwrap();
            assert!(ids.contains(id), "{id} of {}", &l[..40]);
        }
    }
}
