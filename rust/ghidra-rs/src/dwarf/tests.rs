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
