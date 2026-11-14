//! Expression helpers the rules share: `functionalEqualityLevel` (expression.cc),
//! `BlockBasic::earliestUse`, `Funcdata::cseFindInBlock`, and `TermOrder` (expression.cc).

use super::*;

/// `functionalEqualityLevel0` (expression.cc).
pub(super) fn func_eq0(fd: &Funcdata, a: VarnodeId, b: VarnodeId) -> i32 {
    if a == b {
        return 0;
    }
    let (va, vb) = (fd.vn(a), fd.vn(b));
    if va.size != vb.size {
        return -1;
    }
    if va.is_constant() {
        return if vb.is_constant() && va.offset == vb.offset { 0 } else { -1 };
    }
    if va.is_free() || vb.is_free() {
        return -1;
    }
    1
}

/// Port of `functionalEqualityLevel`: 0 equal, 1 or 2 equal up to that many pairs of inputs
/// (returned), -1 different.
pub(crate) fn func_eq_level(
    fd: &Funcdata,
    a: VarnodeId,
    b: VarnodeId,
) -> (i32, [Option<VarnodeId>; 2], [Option<VarnodeId>; 2]) {
    let mut r1 = [None; 2];
    let mut r2 = [None; 2];
    let t = func_eq0(fd, a, b);
    if t != 1 {
        return (t, r1, r2);
    }
    let (Some(op1), Some(op2)) = (def(fd, a), def(fd, b)) else { return (-1, r1, r2) };
    let (o1, o2) = (fd.op(op1), fd.op(op2));
    let opc = o1.opc;
    if opc != o2.opc {
        return (-1, r1, r2);
    }
    let mut num = o1.ins.len();
    if num != o2.ins.len() || o1.is_marker() || o2.is_call() {
        return (-1, r1, r2);
    }
    if opc == Load && o1.seq.addr != o2.seq.addr {
        return (-1, r1, r2);
    }
    if num >= 3 {
        if opc != Ptradd || fd.vn(o1.ins[2]).offset != fd.vn(o2.ins[2]).offset {
            return (-1, r1, r2);
        }
        num = 2;
    }
    if num == 0 {
        return (-1, r1, r2);
    }
    for i in 0..num {
        r1[i] = Some(o1.ins[i]);
        r2[i] = Some(o2.ins[i]);
    }
    let t = func_eq0(fd, o1.ins[0], o2.ins[0]);
    if t == 0 {
        if num == 1 {
            return (0, r1, r2);
        }
        let t2 = func_eq0(fd, o1.ins[1], o2.ins[1]);
        if t2 == 0 {
            return (0, r1, r2);
        }
        if t2 < 0 {
            return (-1, r1, r2);
        }
        r1[0] = r1[1];
        r2[0] = r2[1];
        return (1, r1, r2);
    }
    if num == 1 {
        return (t, r1, r2);
    }
    let t2 = func_eq0(fd, o1.ins[1], o2.ins[1]);
    if t2 == 0 {
        return (t, r1, r2);
    }
    let unmatch = if t == 1 && t2 == 1 { 2 } else { -1 };
    if !opc.is_commutative() {
        return (unmatch, r1, r2);
    }
    let c1 = func_eq0(fd, o1.ins[0], o2.ins[1]);
    let c2 = func_eq0(fd, o1.ins[1], o2.ins[0]);
    if c1 == 0 && c2 == 0 {
        return (0, r1, r2);
    }
    if c1 < 0 || c2 < 0 {
        return (unmatch, r1, r2);
    }
    if c1 == 0 {
        r1[0] = r1[1];
        return (1, r1, r2);
    }
    if c2 == 0 {
        r2[0] = r2[1];
        return (1, r1, r2);
    }
    if unmatch == 2 {
        return (2, r1, r2);
    }
    r2.swap(0, 1);
    (2, r1, r2)
}

/// `functionalEquality`.
pub(crate) fn func_equal(fd: &Funcdata, a: VarnodeId, b: VarnodeId) -> bool {
    func_eq_level(fd, a, b).0 == 0
}

/// Port of `BlockBasic::earliestUse`.
pub(super) fn earliest_use(fd: &Funcdata, bl: BlockId, vn: VarnodeId) -> Option<OpId> {
    let mut res: Option<OpId> = None;
    for &op in fd.vn(vn).descend.iter() {
        if fd.op(op).parent != Some(bl) {
            continue;
        }
        if res.is_none_or(|r| fd.op(op).order < fd.op(r).order) {
            res = Some(op);
        }
    }
    res
}

/// Port of `Funcdata::cseFindInBlock`.
pub(super) fn cse_find_in_block(
    fd: &Funcdata,
    op: OpId,
    vn: VarnodeId,
    bl: BlockId,
    earliest: Option<OpId>,
) -> Option<OpId> {
    for &res in fd.vn(vn).descend.iter() {
        if res == op || fd.op(res).parent != Some(bl) {
            continue;
        }
        if let Some(e) = earliest {
            if fd.op(e).order < fd.op(res).order {
                continue;
            }
        }
        let (Some(o1), Some(o2)) = (fd.op(op).out, fd.op(res).out) else { continue };
        if func_eq_level(fd, o1, o2).0 == 0 {
            return Some(res);
        }
    }
    None
}

/// `Varnode::termOrder`: constants last, then by address (looking through a multiply by a
/// constant).
pub(super) fn term_cmp(fd: &Funcdata, a: VarnodeId, b: VarnodeId) -> i32 {
    match (is_const(fd, a), is_const(fd, b)) {
        (true, true) => 0,
        (true, false) => 1,
        (false, true) => -1,
        (false, false) => {
            let strip = |vn: VarnodeId| match def(fd, vn) {
                Some(d) if fd.op(d).opc == IntMult && fd.op(d).ins.get(1).is_some_and(|&c| is_const(fd, c)) => {
                    fd.op(d).ins[0]
                }
                _ => vn,
            };
            let (x, y) = (addr(fd, strip(a)), addr(fd, strip(b)));
            match x.cmp(&y) {
                std::cmp::Ordering::Less => -1,
                std::cmp::Ordering::Greater => 1,
                std::cmp::Ordering::Equal => 0,
            }
        }
    }
}

/// An `AdditiveEdge`: input `slot` of `op`, under the multiply `mult` if any.
#[derive(Debug, Clone, Copy)]
pub(super) struct Term {
    pub(super) op: OpId,
    pub(super) slot: usize,
    pub(super) mult: Option<OpId>,
}

/// Port of `TermOrder::collect` and `sortTerms` (`std::sort`).
pub(super) fn collect_additive(fd: &Funcdata, root: OpId) -> Vec<Term> {
    let mut terms = Vec::new();
    let mut stack = vec![(root, None)];
    while let Some((cur, mult)) = stack.pop() {
        for (i, &vn) in fd.op(cur).ins.iter().enumerate() {
            let term = Term { op: cur, slot: i, mult };
            let Some(sub) = def(fd, vn) else {
                terms.push(term);
                continue;
            };
            if lone_descend(fd, vn).is_none() {
                terms.push(term);
                continue;
            }
            let s = fd.op(sub);
            if s.opc != IntAdd {
                if s.opc == IntMult && s.ins.get(1).is_some_and(|&c| is_const(fd, c)) {
                    if let Some(add) = def(fd, s.ins[0]) {
                        if fd.op(add).opc == IntAdd && fd.op(add).out.is_some_and(|o| lone_descend(fd, o).is_some()) {
                            stack.push((add, Some(sub)));
                            continue;
                        }
                    }
                }
                terms.push(term);
                continue;
            }
            stack.push((sub, mult));
        }
    }
    let vn = |t: &Term| fd.op(t.op).ins[t.slot];
    stdsort::sort(&mut terms, |a, b| term_cmp(fd, vn(a), vn(b)) == -1);
    terms
}
