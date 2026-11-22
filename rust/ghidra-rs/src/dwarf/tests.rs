use super::*;

#[test]
fn mangled_nestings() {
    assert_eq!(parse_mangled_nestings("_ZN3geo6Circle4areaEv"), ["geo", "Circle", "area"]);
    assert_eq!(parse_mangled_nestings("N3Foo3barE"), ["Foo", "bar"]);
    assert!(parse_mangled_nestings("_Z3fooi").is_empty());
}

#[test]
fn java_names() {
    assert_eq!(java_hash("abc"), 96354);
    assert_eq!(explicit_size_from_name(Some("u32")), 32);
    assert_eq!(explicit_size_from_name(Some("__int128")), 128);
    assert_eq!(explicit_size_from_name(Some("int")), -1);
    assert_eq!(dtm::strip_conflict("foo.conflict12"), "foo");
}

#[test]
fn gcc_bitfield_packing() {
    // struct { unsigned a:1, b:3; int c:5; unsigned :0; unsigned d:7; char e; } is 8 bytes
    let mut d = Dtm::new();
    let (u, i, c) = (d.builtin(dtm::UINT), d.builtin(dtm::INT), d.builtin(dtm::CHAR));
    let bf = |ty, n| dtm::Comp {
        offset: 0,
        len: 1,
        name: None,
        comment: None,
        ty,
        bf: Some(dtm::Bitfield { base: ty, bit_size: n, bit_offset: 0 }),
    };
    let plain = dtm::Comp { offset: 0, len: 1, name: None, comment: None, ty: c, bf: None };
    let comps = vec![bf(u, 1), bf(u, 3), bf(i, 5), bf(u, 0), bf(u, 7), plain];
    let s = d.new_pre(
        "s".into(),
        0,
        Kind::Composite(Composite { union: false, len: 0, packed: false, align: 1, comps, description: String::new() }),
    );
    d.pack(s);
    let Kind::Composite(p) = &d.dt(s).kind else { panic!() };
    let got: Vec<(i32, i32)> = p.comps.iter().map(|x| (x.offset, x.len)).collect();
    assert_eq!(got, [(0, 1), (0, 1), (0, 2), (4, 0), (4, 1), (5, 1)]);
    assert_eq!((p.len, p.align), (8, 4));
}

// ---- malformed input: no panic, no hang; what Java skips is skipped with a warning

/// an abbreviation: code, tag, children, [(attribute, form)]
type Abb<'a> = (u64, u16, bool, &'a [(u16, u16)]);

fn uleb(mut v: u64, out: &mut Vec<u8>) {
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        out.push(if v == 0 { b } else { b | 0x80 });
        if v == 0 {
            return;
        }
    }
}

/// `.debug_abbrev`: (code, tag, children, [(attribute, form)])
fn abbrevs(list: &[Abb]) -> Vec<u8> {
    let mut o = Vec::new();
    for (code, tag, ch, attrs) in list {
        uleb(*code, &mut o);
        uleb(*tag as u64, &mut o);
        o.push(*ch as u8);
        for (a, f) in attrs.iter() {
            uleb(*a as u64, &mut o);
            uleb(*f as u64, &mut o);
        }
        o.extend([0, 0]);
    }
    o.push(0);
    o
}

/// A DWARF 4 unit, 32-bit format, 8-byte addresses, abbreviations at 0; DIEs start at 11.
fn unit(body: &[u8]) -> Vec<u8> {
    let mut o = ((7 + body.len()) as u32).to_le_bytes().to_vec();
    o.extend(4u16.to_le_bytes());
    o.extend(0u32.to_le_bytes());
    o.push(8);
    o.extend(body);
    o
}

fn run_on(info: &[u8], abbrev: &[u8]) -> Import {
    run(Dwarf::new(info, abbrev, &[], &[], &[]).expect("indexes"), 0, Vec::new())
}

const CU: Abb = (1, DW_TAG_COMPILE_UNIT, true, &[]);

#[test]
fn nameless_typedef_cycles_fail_their_types() {
    // H1: a nameless typedef of itself (12), and two of each other (17, 22)
    let ab = abbrevs(&[CU, (2, DW_TAG_TYPEDEF, false, &[(DW_AT_TYPE, 0x13)])]);
    let mut body = vec![1];
    for r in [12u32, 22, 17] {
        body.push(2);
        body.extend(r.to_le_bytes());
    }
    body.push(0);
    let imp = run_on(&unit(&body), &ab);
    assert_eq!(imp.warnings.len(), 3, "{:?}", imp.warnings);
    assert!(imp.warnings.iter().all(|w| w.contains("recursion too deep")), "{:?}", imp.warnings);
}

#[test]
fn member_without_parent_fails_its_type() {
    // H2: an anonymous structure (12) whose only member is the root DIE of another unit
    let ab = abbrevs(&[
        CU,
        (3, DW_TAG_STRUCTURE, false, &[(DW_AT_BYTE_SIZE, 0x0b)]),
        (4, DW_TAG_MEMBER, false, &[(DW_AT_NAME, 0x08), (DW_AT_TYPE, 0x10)]),
    ]);
    let mut info = unit(&[1, 3, 4, 0]);
    let mut b = vec![4, b'm', 0];
    b.extend(12u32.to_le_bytes());
    info.extend(unit(&b));
    let imp = run_on(&info, &ab);
    assert!(imp.warnings.iter().any(|w| w.contains("has no parent")), "{:?}", imp.warnings);
}

#[test]
fn unit_lengths_past_the_section_end() {
    // H3: a 64-bit length that wraps the offset to 0 (Java: a negative end, an empty unit)
    let mut info = 0xffff_ffffu32.to_le_bytes().to_vec();
    info.extend((u64::MAX - 11).to_le_bytes());
    info.extend(4u16.to_le_bytes());
    info.extend(0u64.to_le_bytes());
    info.push(8);
    info.extend([1, 0]);
    let ab = abbrevs(&[CU]);
    let dw = Dwarf::new(&info, &ab, &[], &[], &[]).expect("indexes");
    assert_eq!((dw.cus.len(), dw.offsets.len()), (1, 0));
    // a 32-bit length past the end: DIEs read until one fails, the rest skipped with a warning
    let mut info = unit(&[1, 2]);
    info[..4].copy_from_slice(&1000u32.to_le_bytes());
    let imp = run_on(&info, &ab);
    assert_eq!((imp.units, imp.dies), (1, 1));
    assert!(imp.warnings[0].contains("skipping remainder of compilation unit"), "{:?}", imp.warnings);
}

#[test]
fn empty_first_unit() {
    // H4: a unit without DIEs, then one with: DIE 0 belongs to the second unit
    let ab = abbrevs(&[CU]);
    let mut info = unit(&[]);
    info.extend(unit(&[1, 0]));
    let dw = Dwarf::new(&info, &ab, &[], &[], &[]).expect("indexes");
    assert_eq!((dw.cus.len(), dw.cu_of(0)), (2, 1));
}

#[test]
fn int_overflows_wrap_or_fail_the_type() {
    // H5: a bitfield whose byte size times 8 overflows an int (wraps, as Java); an enum of 16
    // bytes (EnumDataType's IllegalArgumentException: that type fails)
    let ab = abbrevs(&[
        CU,
        (2, DW_TAG_STRUCTURE, true, &[(DW_AT_NAME, 0x08), (DW_AT_BYTE_SIZE, 0x0b)]),
        (
            3,
            DW_TAG_MEMBER,
            false,
            &[
                (DW_AT_NAME, 0x08),
                (DW_AT_TYPE, 0x13),
                (DW_AT_BYTE_SIZE, 0x06),
                (DW_AT_BIT_SIZE, 0x0b),
                (DW_AT_BIT_OFFSET, 0x0b),
                (DW_AT_DATA_MEMBER_LOCATION, 0x0b),
            ],
        ),
        (4, DW_TAG_BASE_TYPE, false, &[(DW_AT_NAME, 0x08), (DW_AT_BYTE_SIZE, 0x0b), (DW_AT_ENCODING, 0x0b)]),
        (5, DW_TAG_ENUMERATION, false, &[(DW_AT_NAME, 0x08), (DW_AT_BYTE_SIZE, 0x0b)]),
    ]);
    // 11: CU; 12: struct "s" (5 bytes); 17: member "b" (16 bytes); 33: 0; 34: int; 41: enum
    let mut body = vec![1, 2, b's', 0, 4, 3, b'b', 0];
    body.extend(34u32.to_le_bytes());
    body.extend(0x2000_0000u32.to_le_bytes());
    body.extend([3, 1, 0, 0, 4, b'i', b'n', b't', 0, 4, 5, 5, b'E', 0, 16, 0]);
    let imp = run_on(&unit(&body), &ab);
    assert_eq!(imp.warnings.len(), 1, "{:?}", imp.warnings);
    assert!(imp.warnings[0].contains("unsupported enum length: 16"), "{:?}", imp.warnings);
}

#[test]
fn long_indirect_form_chain() {
    // M6: DW_FORM_indirect 200,000 times, then DW_FORM_string
    let ab = abbrevs(&[(1, DW_TAG_COMPILE_UNIT, false, &[(DW_AT_NAME, 0x16)])]);
    let mut body = vec![1];
    body.extend(std::iter::repeat_n(0x16, 200_000));
    body.extend([0x08, b'x', 0]);
    let info = unit(&body);
    let dw = Dwarf::new(&info, &ab, &[], &[], &[]).expect("indexes");
    assert_eq!(dw.offsets.len(), 1);
}
