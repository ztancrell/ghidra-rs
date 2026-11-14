use super::*;

/// A register input of `size` bytes at `off`.
fn input(fd: &mut Funcdata, size: u32, off: u64) -> VarnodeId {
    let v = fd.new_varnode(size, Space::Sleigh(1), off);
    fd.vn_set(v, VnFlags::INPUT);
    v
}

/// A new op `opc` with inputs `ins` and a register output of `size` bytes at `off`.
fn op(fd: &mut Funcdata, opc: Opcode, ins: &[VarnodeId], size: u32, off: u64) -> (OpId, VarnodeId) {
    let o = fd.new_op(opc, 0x1000);
    let out = fd.new_varnode_out(size, Space::Sleigh(1), off, o);
    for (i, &v) in ins.iter().enumerate() {
        fd.op_set_input(o, v, i).unwrap();
    }
    (o, out)
}

/// `x * y` (8 bytes) split into its low and high 4-byte SUBPIECEs: (lo op, lo, hi op, hi).
fn split_mult(fd: &mut Funcdata, base: u64) -> (OpId, VarnodeId, OpId, VarnodeId) {
    let x = input(fd, 8, base);
    let y = input(fd, 8, base + 8);
    let (_, w) = op(fd, IntMult, &[x, y], 8, base + 0x10);
    let c0 = fd.new_constant(4, 0);
    let (lop, lo) = op(fd, Subpiece, &[w, c0], 4, base + 0x20);
    let c4 = fd.new_constant(4, 4);
    let (hop, hi) = op(fd, Subpiece, &[w, c4], 4, base + 0x24);
    (lop, lo, hop, hi)
}

#[test]
fn double_in_marks_the_halves_of_an_arithmetic_whole() {
    let mut fd = Funcdata::new(0x1000);
    let arch_free = |fd: &mut Funcdata, o, v| double_in_marking(fd, v, o).unwrap();
    let (lop, lo, hop, hi) = split_mult(&mut fd, 0);
    // the low SUBPIECE is not at the half: no marking from it
    assert_eq!(arch_free(&mut fd, lop, lo), 0);
    assert_eq!(arch_free(&mut fd, hop, hi), 1);
    assert!(fd.vn(lo).is_precis_lo() && fd.vn(hi).is_precis_hi());
    let w = fd.op(hop).ins[0];
    let list = whole_list(&fd, w).unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].pieces(), Some((lo, hi)));
    let mut sv = SplitVarnode::default();
    assert!(sv.in_hand_lo(&fd, lo).unwrap());
    assert_eq!((sv.hi, sv.whole, sv.wholesize), (Some(hi), Some(w), 8));
    let mut sv = SplitVarnode::default();
    assert!(sv.in_hand_hi(&fd, hi).unwrap());
    assert_eq!(sv.lo, Some(lo));
}

#[test]
fn double_in_skips_a_whole_not_made_by_arithmetic() {
    let mut fd = Funcdata::new(0x1000);
    let x = input(&mut fd, 8, 0);
    let (_, w) = op(&mut fd, IntAnd, &[x, x], 8, 0x10);
    let c0 = fd.new_constant(4, 0);
    op(&mut fd, Subpiece, &[w, c0], 4, 0x20);
    let c4 = fd.new_constant(4, 4);
    let (hop, hi) = op(&mut fd, Subpiece, &[w, c4], 4, 0x24);
    assert_eq!(double_in_marking(&mut fd, hi, hop).unwrap(), 0);
    assert!(!fd.vn(hi).is_precis());
}

#[test]
fn init_partial_folds_constant_pieces() {
    let mut fd = Funcdata::new(0x1000);
    let l = fd.new_constant(4, 0x89ab_cdef);
    let h = fd.new_constant(4, 0x0123_4567);
    let mut sv = SplitVarnode::default();
    sv.init_partial(&fd, 8, l, Some(h));
    assert!(sv.is_constant());
    assert_eq!(sv.val, 0x0123_4567_89ab_cdef);
    assert!(!sv.exceeds_const_precision());
    assert!(SplitVarnode::constant(16, 0).exceeds_const_precision());
}

#[test]
fn adjacent_offsets_of_pointers() {
    let mut fd = Funcdata::new(0x1000);
    let (a, b) = (fd.new_constant(4, 0x100), fd.new_constant(4, 0x104));
    assert!(adjacent_offsets(&fd, a, b, 4).unwrap());
    assert!(!adjacent_offsets(&fd, a, b, 8).unwrap());
    let p = input(&mut fd, 4, 0);
    let c4 = fd.new_constant(4, 4);
    let (_, p4) = op(&mut fd, IntAdd, &[p, c4], 4, 0x10);
    assert!(adjacent_offsets(&fd, p, p4, 4).unwrap());
    let c8 = fd.new_constant(4, 8);
    let (_, p8) = op(&mut fd, IntAdd, &[p, c8], 4, 0x14);
    assert!(adjacent_offsets(&fd, p4, p8, 4).unwrap());
    assert!(!adjacent_offsets(&fd, p4, p8, 8).unwrap());
}

#[test]
fn logical_form_finds_the_high_op_with_a_constant() {
    let mut fd = Funcdata::new(0x1000);
    let (_, lo, hop, hi) = split_mult(&mut fd, 0);
    double_in_marking(&mut fd, hi, hop).unwrap();
    let (cl, ch) = (fd.new_constant(4, 0xff), fd.new_constant(4, 0xf0));
    let (lop, _) = op(&mut fd, IntAnd, &[lo, cl], 4, 0x40);
    let (hiop, _) = op(&mut fd, IntAnd, &[hi, ch], 4, 0x44);
    let w = fd.op(hop).ins[0];
    let sv = whole_list(&fd, w).unwrap().remove(0);
    assert_eq!(LogicalForm::find_hi_match(&fd, &sv, lop, hi).unwrap(), Some(hiop));
    // a second constant AND of the high piece makes the match ambiguous
    let c2 = fd.new_constant(4, 1);
    op(&mut fd, IntAnd, &[hi, c2], 4, 0x48);
    assert_eq!(LogicalForm::find_hi_match(&fd, &sv, lop, hi).unwrap(), None);
}

#[test]
fn shift_amounts_must_add_up_to_the_piece() {
    let fd = {
        let mut fd = Funcdata::new(0x1000);
        let lo = input(&mut fd, 4, 0);
        fd.new_constant(4, 3);
        fd.new_constant(4, 29);
        fd.new_constant(4, 28);
        let _ = lo;
        fd
    };
    let (lo, c3, c29, c28) = (VarnodeId(0), VarnodeId(1), VarnodeId(2), VarnodeId(3));
    let f = |samid| ShiftForm::with_amounts(lo, c3, c3, samid);
    assert!(f(c29).verify_shift_amount(&fd));
    assert!(!f(c28).verify_shift_amount(&fd));
}
