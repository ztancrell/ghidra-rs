//! Port of jump-table recovery (jumptable.cc): from the BRANCHIND of a partial function
//! (simplified by the `jumptable` root action), find the switch variable, its range of values
//! from the guards before the switch, and the target of each value by emulating the address
//! calculation. The models ported are `JumpBasic` and `JumpBasic2`, with `PathMeld`,
//! `GuardRecord`, `JumpValuesRange(Default)`, `EmulateFunction` ([`super::emulate`]),
//! `JumpTable::recoverAddresses` with its sanity checks, `earlyJumpTableFail` and the non-zero
//! masks of `ActionNonzeroMask` ([`calc_nz_mask`]). Ranges are [`super::rangeutil`].
//!
//! What differs from the C++, and why:
//!
//! - The partial function is simplified only as far as the actions are ported (heritage of
//!   registers and temporaries, read-only constants; `action::jumptable_partial`), not by the
//!   rule pool. Three stand-ins read the raw p-code as the rules would have left it, until the
//!   rule stages replace them: [`konst`] folds constants (copies, constant operations,
//!   `xor r,r`, loads from read-only memory); [`cond_range`] reads a guard's x86 flag logic
//!   (`!(CF || ZF)`, `OF != SF`, `x - c == 0`) as the one comparison the rules rewrite it into,
//!   counted as one pull-back; [`split_const`] puts a commutative op's constant in slot 1
//!   (`RuleTermOrder`). The stack is not heritaged, so a switch variable kept on the stack is
//!   matched through its two LOADs (`GuardRecord::valueMatch` code 2), as the C++ does for
//!   memory it cannot heritage.
//! - Not ported: `JumpAssisted` (x86 has no `jumpassist` user op), `JumpBasicOverride` and
//!   `JumpModelTrivial` (overrides; the console sets none), multistage tables, label recovery
//!   and guard folding (`recoverLabels`, `foldInGuards`: after `paramdouble`), unrolled
//!   guards (`checkUnrolledGuard`), LOAD collection (`record_jumploads` is off by default),
//!   `testForReturnAddress` (x86's return address is on the stack, not heritaged yet).

use super::block::BlockId;
use super::emulate::{eval_binary, eval_unary, EmuError, EmulateFunction};
use super::op::OpId;
use super::opcode::Opcode;
use super::rangeutil::{calc_mask, CircleRange};
use super::varnode::{Space, VarnodeId};
use super::{Arch, Funcdata};
use std::collections::HashSet;

/// `Architecture::max_jumptable_size`
pub(crate) const MAX_JUMPTABLE_SIZE: u64 = 1024;

/// The failure modes of `JumpTable::RecoveryMode` (`success` is `Ok`).
#[derive(Debug)]
pub(crate) enum Fail {
    /// `fail_normal`, with the warning the C++ records
    Normal(String),
    /// `fail_thunk`
    Thunk,
    /// `fail_callother`
    Callother,
}

/// `getNZMask`: from [`calc_nz_mask`], else (before it runs) a constant's value or every bit.
fn nz_mask(fd: &Funcdata, vn: VarnodeId) -> u64 {
    if let Some(&m) = fd.nzm.get(vn.0 as usize) {
        return m;
    }
    let v = fd.vn(vn);
    if v.is_constant() {
        v.offset
    } else {
        calc_mask(v.size)
    }
}

fn pcode_left(v: u64, sa: u64) -> u64 {
    if sa >= 64 {
        0
    } else {
        v << sa
    }
}

fn pcode_right(v: u64, sa: u64) -> u64 {
    if sa >= 64 {
        0
    } else {
        v >> sa
    }
}

/// `coveringmask`
fn covering_mask(v: u64) -> u64 {
    let mut r = v;
    let mut sz = 1;
    while sz < 64 {
        r |= r >> sz;
        sz <<= 1;
    }
    r
}

/// Port of `PcodeOp::getNZMaskLocal` (for outputs of at most 8 bytes, all x86 needs).
/// An input that folds to a constant ([`konst`]) counts as that constant, as it is in
/// the C++ partial function after its rules.
fn nz_mask_local(fd: &Funcdata, arch: &Arch, op: OpId, cliploop: bool) -> u64 {
    use Opcode::*;
    let o = fd.op(op);
    let size = fd.vn(o.out.unwrap()).size;
    let full = calc_mask(size);
    let konst = |i: usize| konst(fd, arch, o.ins[i]);
    let nz = |i: usize| konst(i).unwrap_or_else(|| nz_mask(fd, o.ins[i]));
    match o.opc {
        opc if is_bool_output(opc) => 1,
        Copy | IntZext => nz(0),
        IntSext => {
            let isz = fd.vn(o.ins[0]).size;
            let sh = 64 - 8 * isz.min(8);
            ((((nz(0) << sh) as i64) >> sh) as u64) & full
        }
        IntXor | IntOr => {
            let m = nz(0);
            if m != full {
                m | nz(1)
            } else {
                m
            }
        }
        IntAnd => {
            let m = nz(0);
            if m != 0 {
                m & nz(1)
            } else {
                m
            }
        }
        IntLeft => konst(1).map_or(full, |sa| pcode_left(nz(0), sa) & full),
        IntRight => konst(1).map_or(full, |sa| pcode_right(nz(0), sa)),
        IntSright => match konst(1) {
            Some(sa) if size <= 8 => {
                let m = nz(0);
                let r = pcode_right(m, sa);
                if m & (full ^ (full >> 1)) == 0 {
                    r
                } else {
                    r | (pcode_right(full, sa) ^ full)
                }
            }
            _ => full,
        },
        IntDiv => {
            let mut r = covering_mask(nz(0));
            if konst(1).is_some() {
                let sa = mostsigbit_set(nz(1));
                if sa != -1 {
                    r >>= sa;
                }
            }
            r
        }
        IntRem => covering_mask(nz(1).wrapping_sub(1)),
        Popcount => covering_mask(u64::from(nz(0).count_ones())) & full,
        Lzcount => covering_mask(u64::from(fd.vn(o.ins[0]).size * 8)) & full,
        Subpiece => {
            let sz1 = fd.vn(o.ins[1]).offset; // always a constant
            let m = match (fd.vn(o.ins[0]).size <= 8, sz1 < 8) {
                (true, true) => nz(0) >> (8 * sz1),
                (true, false) => 0,
                // extended precision: the bits above the 64 shift in as possibly non-zero
                (false, true) if sz1 > 0 => (nz(0) >> (8 * sz1)) | (u64::MAX << (8 * (8 - sz1))),
                (false, true) => nz(0),
                (false, false) => u64::MAX,
            };
            m & full
        }
        Piece => {
            let sa = fd.vn(o.ins[1]).size;
            (if sa < 8 { nz(0) << (8 * sa) } else { 0 }) | nz(1)
        }
        IntMult => {
            let (val, m) = (nz(0), nz(1));
            let (s1, s2) = (mostsigbit_set(val), mostsigbit_set(m));
            if s1 == -1 || s2 == -1 {
                return 0;
            }
            let (l1, l2) = (val.trailing_zeros() as i32, m.trailing_zeros() as i32);
            let sa = l1 + l2;
            if sa >= 8 * size as i32 {
                return 0;
            }
            let (s1, s2) = (s1 - l1 + 1, s2 - l2 + 1);
            let mut total = s1 + s2;
            if s1 == 1 || s2 == 1 {
                total -= 1;
            }
            let mut r = full;
            if total < 8 * size as i32 {
                r >>= 8 * size as i32 - total;
            }
            (r << sa) & full
        }
        IntAdd => {
            let mut r = nz(0);
            if r != full {
                let other = nz(1);
                if other & r == 0 {
                    r |= other;
                } else {
                    r |= other;
                    r |= r << 1;
                }
                r &= full;
            }
            r
        }
        Multiequal => {
            let bl = o.parent.unwrap();
            let mut r = 0;
            for i in 0..o.ins.len() {
                if cliploop && fd.blocks.is_loop_in(bl, i) {
                    continue;
                }
                r |= nz(i);
            }
            if o.ins.is_empty() {
                full
            } else {
                r
            }
        }
        _ => full,
    }
}

/// Port of `Funcdata::calcNZMask` (`ActionNonzeroMask`): each varnode's non-zero mask, first
/// along the data flow without loop edges, then to a fixed point through the MULTIEQUALs. The
/// stack pointer's input counts as aligned (`isSpacebase`), as `ActionSpacebase` marks it.
pub(crate) fn calc_nz_mask(fd: &mut Funcdata, arch: &Arch) {
    fd.folded = calc_folded(fd, arch);
    let n = fd.vns.len();
    let mut nzm: Vec<u64> = fd.vns.iter().map(|v| if v.is_constant() { v.offset } else { calc_mask(v.size) }).collect();
    let (sps, spo, spz) = arch.spec.stack_pointer;
    for (i, v) in fd.vns.iter().enumerate() {
        if v.is_input() && v.space == Space::Sleigh(sps) && v.offset == spo && v.size == spz {
            nzm[i] &= !0xff;
        }
    }
    fd.nzm = nzm;
    let alive: Vec<OpId> = fd.blocks.ops().collect();
    let mut mark = vec![false; fd.ops.len()];
    for &start in &alive {
        if mark[start.0 as usize] {
            continue;
        }
        mark[start.0 as usize] = true;
        let mut stack = vec![(start, 0usize)];
        while let Some(&(op, slot)) = stack.last() {
            let o = fd.op(op);
            if slot >= o.ins.len() {
                if let Some(out) = o.out {
                    let m = nz_mask_local(fd, arch, op, true);
                    fd.nzm[out.0 as usize] = m;
                }
                stack.pop();
                continue;
            }
            let old = slot;
            stack.last_mut().unwrap().1 += 1;
            if o.opc == Opcode::Multiequal && fd.blocks.is_loop_in(o.parent.unwrap(), old) {
                continue;
            }
            if let Some(d) = fd.vn(o.ins[old]).def {
                if !mark[d.0 as usize] {
                    mark[d.0 as usize] = true;
                    stack.push((d, 0));
                }
            }
        }
    }
    let mut work: Vec<OpId> = alive.iter().copied().filter(|&o| fd.op(o).opc == Opcode::Multiequal).collect();
    while let Some(op) = work.pop() {
        let Some(out) = fd.op(op).out else { continue };
        let m = nz_mask_local(fd, arch, op, false);
        if m != fd.nzm[out.0 as usize] {
            fd.nzm[out.0 as usize] = m;
            work.extend(fd.vn(out).descend.iter().copied());
        }
    }
    debug_assert_eq!(fd.nzm.len(), n);
}

/// The value `vn` has when it is a constant, or folds to one through ops whose inputs do: what
/// the C++ rules (`RulePropagateCopy`, `RuleCollapseConstants`, `xor r,r` to 0,
/// `RuleLoadVarnode` with read-only memory) leave as a constant in the partial function. From
/// [`calc_folded`] once it has run, else only literal constants.
fn konst(fd: &Funcdata, _arch: &Arch, vn: VarnodeId) -> Option<u64> {
    match fd.folded.get(vn.0 as usize) {
        Some(&v) => v,
        None => fd.vn(vn).is_constant().then(|| fd.vn(vn).offset),
    }
}

/// The folded value of `op`'s output from its inputs' folded values (`val`), see [`konst`].
fn fold(fd: &Funcdata, arch: &Arch, op: OpId, val: &[Option<u64>]) -> Option<u64> {
    let o = fd.op(op);
    let size = fd.vn(o.out?).size;
    let get = |i: usize| val[o.ins[i].0 as usize];
    match o.opc {
        Opcode::Load => {
            let addr = get(1)?;
            if !arch.readonly_propagate || !arch.is_readonly(addr, size) {
                return None;
            }
            let mut buf = [0u8; 8];
            arch.fill_bytes(addr, &mut buf)?;
            Some(u64::from_le_bytes(buf) & calc_mask(size))
        }
        Opcode::Multiequal | Opcode::Indirect | Opcode::Callother | Opcode::Call | Opcode::Callind => None,
        Opcode::IntXor | Opcode::IntSub if o.ins.len() == 2 && o.ins[0] == o.ins[1] => Some(0),
        opc if o.ins.len() == 1 => eval_unary(opc, size, fd.vn(o.ins[0]).size, get(0)?).ok(),
        opc if o.ins.len() == 2 => eval_binary(opc, size, fd.vn(o.ins[0]).size, get(0)?, get(1)?).ok(),
        _ => None,
    }
}

/// Folds every varnode of the partial function to a constant where it can ([`konst`]),
/// in one pass over the data flow (MULTIEQUAL and INDIRECT are not followed, so there are no
/// cycles).
fn calc_folded(fd: &Funcdata, arch: &Arch) -> Vec<Option<u64>> {
    let n = fd.vns.len();
    let mut val: Vec<Option<u64>> = vec![None; n];
    let mut done = vec![false; n];
    for start in 0..n {
        let mut stack = vec![(start, false)];
        while let Some((v, expanded)) = stack.pop() {
            if done[v] {
                continue;
            }
            let vn = &fd.vns[v];
            let Some(d) = vn.def.filter(|_| !vn.is_constant()) else {
                val[v] = vn.is_constant().then_some(vn.offset);
                done[v] = true;
                continue;
            };
            let o = fd.op(d);
            if !expanded {
                stack.push((v, true));
                if !matches!(o.opc, Opcode::Multiequal | Opcode::Indirect) {
                    stack.extend(o.ins.iter().filter(|i| !done[i.0 as usize]).map(|i| (i.0 as usize, false)));
                }
                continue;
            }
            val[v] = fold(fd, arch, d, &val);
            done[v] = true;
        }
    }
    val
}

/// `mostsigbit_set`: the index of the highest set bit, -1 for 0.
fn mostsigbit_set(v: u64) -> i32 {
    63 - v.leading_zeros() as i32
}

fn def(fd: &Funcdata, vn: VarnodeId) -> Option<OpId> {
    fd.vn(vn).def
}

/// `PcodeOp::isBoolOutput`
fn is_bool_output(opc: Opcode) -> bool {
    use Opcode::*;
    matches!(
        opc,
        IntEqual
            | IntNotequal
            | IntSless
            | IntSlessequal
            | IntLess
            | IntLessequal
            | IntCarry
            | IntScarry
            | IntSborrow
            | BoolNegate
            | BoolXor
            | BoolAnd
            | BoolOr
            | FloatEqual
            | FloatNotequal
            | FloatLess
            | FloatLessequal
            | FloatNan
    )
}

/// `CircleRange::pullBack` from `vn` through the op defining it: the input varnode and its
/// range of values for which `vn` lies in `rng`.
fn pull_back(
    fd: &Funcdata,
    arch: &Arch,
    vn: VarnodeId,
    mut rng: CircleRange,
    usenzmask: bool,
) -> Option<(VarnodeId, CircleRange)> {
    let op = fd.op(def(fd, vn)?);
    let outsize = fd.vn(vn).size;
    let res;
    if op.ins.len() == 1 {
        res = op.ins[0];
        if konst(fd, arch, res).is_some() || !rng.pull_back_unary(op.opc, fd.vn(res).size, outsize) {
            return None;
        }
    } else if op.ins.len() == 2 {
        let (mut slot, mut r, mut c) = (0, op.ins[0], op.ins[1]);
        if konst(fd, arch, r).is_some() {
            slot = 1;
            c = r;
            r = op.ins[1];
            if konst(fd, arch, r).is_some() {
                return None;
            }
        } else if konst(fd, arch, c).is_none() {
            return None;
        }
        res = r;
        let val = konst(fd, arch, c).unwrap();
        if !rng.pull_back_binary(op.opc, val, slot, fd.vn(res).size) {
            if usenzmask && op.opc == Opcode::Subpiece && val == 0 {
                let msb = (mostsigbit_set(nz_mask(fd, res)) + 8) / 8;
                if (outsize as i32) < msb {
                    return None;
                }
                rng.mask = calc_mask(fd.vn(res).size);
            } else {
                return None;
            }
        }
    } else {
        return None;
    }
    if usenzmask {
        let mut nz = CircleRange::default();
        if nz.set_nz_mask(nz_mask(fd, res), fd.vn(res).size) {
            rng.intersect(&nz);
        }
    }
    Some((res, rng))
}

/// The value a copy chain starts from: what `RulePropagateCopy` reads in place of `vn`.
fn copy_source(fd: &Funcdata, mut vn: VarnodeId) -> VarnodeId {
    while let Some(op) = def(fd, vn) {
        let o = fd.op(op);
        if o.opc != Opcode::Copy || fd.vn(o.ins[0]).is_constant() {
            break;
        }
        vn = o.ins[0];
    }
    vn
}

/// `x s< c` from x86's `OF != SF` after `CMP x,c`: `OF = SBORROW(x,c)`, `SF = (x - c) s< 0`.
fn signed_less(fd: &Funcdata, arch: &Arch, a: VarnodeId, b: VarnodeId) -> Option<(VarnodeId, u64)> {
    let side = |of: VarnodeId, sf: VarnodeId| -> Option<(VarnodeId, u64)> {
        let o = fd.op(def(fd, of)?);
        let s = fd.op(def(fd, sf)?);
        if o.opc != Opcode::IntSborrow || s.opc != Opcode::IntSless {
            return None;
        }
        let (x, c) = (o.ins[0], o.ins[1]);
        let c = konst(fd, arch, c)?;
        if konst(fd, arch, s.ins[1]) != Some(0) {
            return None;
        }
        let t = fd.op(def(fd, s.ins[0])?);
        (t.opc == Opcode::IntSub && t.ins[0] == x && konst(fd, arch, t.ins[1]) == Some(c)).then_some((x, c))
    };
    side(a, b).or_else(|| side(b, a))
}

/// The guard condition `vn == val` as a range of the variable it compares, the form the C++
/// rule pool rewrites x86 flag logic into (see the module notes): BOOL_NEGATE, BOOL_OR and
/// BOOL_AND of comparisons of one variable, `OF != SF` (signed less), `x - c == 0` (equality
/// with `c`), and plain comparisons with a constant.
fn cond_range(fd: &Funcdata, arch: &Arch, vn: VarnodeId, val: bool) -> Option<(VarnodeId, CircleRange)> {
    let op = fd.op(def(fd, vn)?);
    match op.opc {
        Opcode::BoolNegate => cond_range(fd, arch, op.ins[0], !val),
        Opcode::BoolOr | Opcode::BoolAnd => {
            let (x, mut r) = cond_range(fd, arch, op.ins[0], val)?;
            let (y, r2) = cond_range(fd, arch, op.ins[1], val)?;
            if x != y {
                return None;
            }
            let ok = if (op.opc == Opcode::BoolOr) == val { r.circle_union(&r2) } else { r.intersect(&r2) };
            (ok == 0).then_some((x, r))
        }
        Opcode::IntEqual | Opcode::IntNotequal
            if fd.vn(op.ins[0]).size == 1
                && konst(fd, arch, op.ins[0]).is_none()
                && konst(fd, arch, op.ins[1]).is_none() =>
        {
            let (x, c) = signed_less(fd, arch, op.ins[0], op.ins[1])?;
            let mut r = CircleRange::boolean((op.opc == Opcode::IntNotequal) == val);
            r.pull_back_binary(Opcode::IntSless, c, 0, fd.vn(x).size).then_some((copy_source(fd, x), r))
        }
        opc => {
            let (mut x, mut r) = pull_back(fd, arch, vn, CircleRange::boolean(val), true)?;
            if matches!(opc, Opcode::IntEqual | Opcode::IntNotequal) {
                if let Some(d) = def(fd, x).map(|d| fd.op(d).opc) {
                    if matches!(d, Opcode::IntAdd | Opcode::IntSub) {
                        (x, r) = pull_back(fd, arch, x, r, true)?;
                    }
                }
            }
            Some((copy_source(fd, x), r))
        }
    }
}

/// Port of `GuardRecord`: a range a CBRANCH before the switch puts on a varnode.
#[derive(Debug, Clone)]
struct GuardRecord {
    vn: VarnodeId,
    base_vn: VarnodeId,
    bits_preserved: i32,
    range: CircleRange,
}

impl GuardRecord {
    fn new(fd: &Funcdata, vn: VarnodeId, range: CircleRange) -> GuardRecord {
        let (base_vn, bits_preserved) = quasi_copy(fd, vn);
        GuardRecord { vn, base_vn, bits_preserved, range }
    }

    /// `valueMatch`: 0 (different), 1 (same value), 2 (same value but for aliased writes)
    fn value_match(&self, fd: &Funcdata, arch: &Arch, vn2: VarnodeId, base2: VarnodeId, bits2: i32) -> i32 {
        if self.vn == vn2 {
            return 1;
        }
        let (op1, op2);
        if self.bits_preserved == bits2 {
            if self.base_vn == base2 {
                return 1;
            }
            op1 = def(fd, self.base_vn);
            op2 = def(fd, base2);
        } else {
            op1 = def(fd, self.vn);
            op2 = def(fd, vn2);
        }
        let (Some(op1), Some(op2)) = (op1, op2) else { return 0 };
        if one_off_match(fd, arch, op1, op2) {
            return 1;
        }
        let (l1, l2) = (fd.op(op1), fd.op(op2));
        if l1.opc != Opcode::Load || l2.opc != Opcode::Load {
            return 0;
        }
        if fd.vn(l1.ins[0]).offset != fd.vn(l2.ins[0]).offset {
            return 0;
        }
        let (p1, p2) = (l1.ins[1], l2.ins[1]);
        if p1 == p2 {
            return 2;
        }
        let (Some(a1), Some(a2)) = (def(fd, p1), def(fd, p2)) else { return 0 };
        if fd.op(a1).opc != Opcode::IntAdd || fd.op(a2).opc != Opcode::IntAdd {
            return 0;
        }
        match (split_const(fd, arch, a1), split_const(fd, arch, a2)) {
            (Some((v1, c1)), Some((v2, c2))) if v1 == v2 && c1 == c2 => 2,
            _ => 0,
        }
    }
}

/// A binary op's variable input and constant, with the constant in slot 1 as `RuleTermOrder`
/// puts it for commutative ops (raw x86 p-code has `#0x14 + ESP`).
fn split_const(fd: &Funcdata, arch: &Arch, op: OpId) -> Option<(VarnodeId, u64)> {
    use Opcode::*;
    let o = fd.op(op);
    if o.ins.len() != 2 {
        return None;
    }
    if let Some(c) = konst(fd, arch, o.ins[1]) {
        return Some((o.ins[0], c));
    }
    let commutative = matches!(o.opc, IntAdd | IntAnd | IntOr | IntXor | IntMult);
    let c = konst(fd, arch, o.ins[0]).filter(|_| commutative)?;
    Some((o.ins[1], c))
}

/// `GuardRecord::oneOffMatch`
fn one_off_match(fd: &Funcdata, arch: &Arch, op1: OpId, op2: OpId) -> bool {
    use Opcode::*;
    let (a, b) = (fd.op(op1), fd.op(op2));
    if a.opc != b.opc {
        return false;
    }
    if !matches!(a.opc, IntAnd | IntAdd | IntXor | IntOr | IntLeft | IntRight | IntSright | IntMult | Subpiece) {
        return false;
    }
    matches!((split_const(fd, arch, op1), split_const(fd, arch, op2)), (Some(x), Some(y)) if x == y)
}

/// `GuardRecord::quasiCopy`: the earliest varnode whose low bits `vn` copies, and how many.
fn quasi_copy(fd: &Funcdata, mut vn: VarnodeId) -> (VarnodeId, i32) {
    let bits = mostsigbit_set(nz_mask(fd, vn)) + 1;
    if bits == 0 {
        return (vn, bits);
    }
    let mask = (2u64 << (bits - 1)).wrapping_sub(1);
    let mut op = def(fd, vn);
    while let Some(o) = op.map(|o| fd.op(o)) {
        let konst = |i: usize| fd.vn(o.ins[i]).is_constant().then(|| fd.vn(o.ins[i]).offset);
        let next = match o.opc {
            Opcode::Copy => Some(o.ins[0]),
            Opcode::IntAnd if konst(1) == Some(mask) => Some(o.ins[0]),
            Opcode::IntOr if konst(1).is_some_and(|c| (c | mask) == (c ^ mask)) => Some(o.ins[0]),
            Opcode::IntSext | Opcode::IntZext if fd.vn(o.ins[0]).size as i32 * 8 >= bits => Some(o.ins[0]),
            Opcode::Piece if fd.vn(o.ins[1]).size as i32 * 8 >= bits => Some(o.ins[1]),
            Opcode::Subpiece if konst(1) == Some(0) => Some(o.ins[0]),
            _ => None,
        };
        match next {
            Some(v) => {
                vn = v;
                op = def(fd, vn);
            }
            None => op = None,
        }
    }
    (vn, bits)
}

/// One edge of a data-flow path: the op and the input slot (`PcodeOpNode`).
type Node = (OpId, usize);

/// Port of `PathMeld`: the paths from possible switch variables to the BRANCHIND, as the
/// varnodes common to all of them and the ops of all of them in reverse execution order.
#[derive(Debug, Clone, Default)]
struct PathMeld {
    common: Vec<VarnodeId>,
    /// (op, index of the common varnode its path leaves from); `None`: split and not rejoined
    ops: Vec<(Option<OpId>, i32)>,
}

impl PathMeld {
    fn op(&self, i: usize) -> OpId {
        self.ops[i].0.unwrap()
    }

    /// `set(const vector<PcodeOpNode> &)`
    fn set_path(&mut self, fd: &Funcdata, path: &[Node]) {
        for (i, &(op, slot)) in path.iter().enumerate() {
            self.ops.push((Some(op), i as i32));
            self.common.push(fd.op(op).ins[slot]);
        }
    }

    /// `internalIntersect`
    fn internal_intersect(&mut self, marked: &mut HashSet<VarnodeId>) -> Vec<i32> {
        let mut parent = Vec::new();
        let mut newvn = Vec::new();
        for &vn in &self.common {
            if marked.remove(&vn) {
                parent.push(newvn.len() as i32);
                newvn.push(vn);
            } else {
                parent.push(-1);
            }
        }
        self.common = newvn;
        let mut last = -1;
        for p in parent.iter_mut().rev() {
            if *p == -1 {
                *p = last;
            } else {
                last = *p;
            }
        }
        parent
    }

    /// `meldOps`
    fn meld_ops(&mut self, fd: &Funcdata, path: &[Node], cut_off: i32, parent: &[i32]) -> i32 {
        for e in &mut self.ops {
            let pos = parent[e.1 as usize];
            if pos == -1 {
                e.0 = None;
            } else {
                e.1 = pos;
            }
        }
        let mut newmeld = Vec::new();
        let mut cur_root = -1;
        let mut meld_pos = 0;
        let mut last_block: Option<BlockId> = None;
        for &(op, _) in path.iter().take(cut_off.max(0) as usize) {
            let mut cur_op = None;
            while meld_pos < self.ops.len() {
                let Some(trial) = self.ops[meld_pos].0 else {
                    meld_pos += 1;
                    continue;
                };
                let (tp, op_p) = (fd.op(trial).parent, fd.op(op).parent);
                if tp != op_p {
                    if op_p == last_block {
                        cur_op = None;
                        break;
                    } else if tp != last_block {
                        let res = self.ops[meld_pos].1;
                        self.ops = newmeld;
                        return res;
                    }
                } else if fd.op(trial).order <= fd.op(op).order {
                    cur_op = Some(trial);
                    break;
                }
                last_block = tp;
                newmeld.push(self.ops[meld_pos]);
                cur_root = self.ops[meld_pos].1;
                meld_pos += 1;
            }
            if cur_op == Some(op) {
                newmeld.push(self.ops[meld_pos]);
                cur_root = self.ops[meld_pos].1;
                meld_pos += 1;
            } else {
                newmeld.push((Some(op), cur_root));
            }
            last_block = fd.op(op).parent;
        }
        self.ops = newmeld;
        -1
    }

    /// `truncatePaths`
    fn truncate_paths(&mut self, cut: i32) {
        while self.ops.len() > 1 {
            if self.ops.last().unwrap().1 < cut {
                break;
            }
            self.ops.pop();
        }
        self.common.truncate(cut as usize);
    }

    /// `meld`
    fn meld(&mut self, fd: &Funcdata, path: &mut Vec<Node>) {
        let mut marked: HashSet<VarnodeId> = path.iter().map(|&(op, s)| fd.op(op).ins[s]).collect();
        let parent = self.internal_intersect(&mut marked);
        let mut cut_off = -1;
        for (i, &(op, s)) in path.iter().enumerate() {
            let vn = fd.op(op).ins[s];
            if !marked.remove(&vn) {
                cut_off = i as i32 + 1;
            }
        }
        let newcut = self.meld_ops(fd, path, cut_off, &parent);
        if newcut >= 0 {
            self.truncate_paths(newcut);
        }
        path.truncate(cut_off.max(0) as usize);
    }

    /// `append`
    fn append(&mut self, o: &PathMeld) {
        let n = o.ops.len();
        self.common.splice(0..0, o.common.iter().copied());
        self.ops.splice(0..0, o.ops.iter().copied());
        for e in &mut self.ops[n..] {
            e.1 += o.common.len() as i32;
        }
    }

    /// `getEarliestOp`
    fn earliest_op(&self, pos: usize) -> Option<OpId> {
        self.ops.iter().rev().find(|e| e.1 == pos as i32).and_then(|e| e.0)
    }

    /// `isLoadInPath`
    fn is_load_in_path(&self, fd: &Funcdata, mut i: usize) -> bool {
        while i > 0 {
            i -= 1;
            if let Some(d) = def(fd, self.common[i]) {
                if fd.op(d).opc == Opcode::Load {
                    return true;
                }
            }
        }
        false
    }
}

/// Port of `JumpValuesRange` and `JumpValuesRangeDefault` (`extra`: the default value with
/// the varnode and op its emulation starts from).
#[derive(Debug, Clone)]
struct JumpValues {
    range: CircleRange,
    normqvn: VarnodeId,
    startop: OpId,
    extra: Option<(u64, VarnodeId, OpId)>,
}

impl JumpValues {
    fn size(&self) -> u64 {
        self.range.get_size() + u64::from(self.extra.is_some())
    }

    /// The values in order, each with the varnode and op the emulation starts from
    /// (`initializeForReading`, `next`, `getStartVarnode`, `getStartOp`).
    fn values(&self) -> Vec<(u64, VarnodeId, OpId)> {
        let mut v = Vec::new();
        if self.range.get_size() != 0 {
            let mut cur = self.range.left;
            loop {
                v.push((cur, self.normqvn, self.startop));
                if !self.range.get_next(&mut cur) {
                    break;
                }
            }
        }
        if let Some(e) = self.extra {
            v.push(e);
        }
        v
    }

    /// `JumpValuesRange::truncate`
    fn truncate(&mut self, nm: usize) {
        let r = &mut self.range;
        let right = r.left.wrapping_add(u64::from(r.step) * nm as u64) & r.mask;
        r.right = right;
        r.isempty = false;
    }
}

/// Port of `JumpBasic` (and `JumpBasic2`, which reuses it from the MULTIEQUAL where the first
/// model stopped).
struct JumpBasic<'a> {
    fd: &'a Funcdata,
    arch: &'a Arch,
    indop: OpId,
    path: PathMeld,
    guards: Vec<GuardRecord>,
    jrange: Option<JumpValues>,
    varnode_index: usize,
}

impl<'a> JumpBasic<'a> {
    fn new(fd: &'a Funcdata, arch: &'a Arch, indop: OpId) -> JumpBasic<'a> {
        JumpBasic { fd, arch, indop, path: PathMeld::default(), guards: Vec::new(), jrange: None, varnode_index: 0 }
    }

    /// `isprune`
    fn isprune(&self, vn: VarnodeId) -> bool {
        if konst(self.fd, self.arch, vn).is_some() {
            return true; // a constant once the C++ rules fold it
        }
        let Some(op) = def(self.fd, vn) else { return true };
        let o = self.fd.op(op);
        o.is_call() || o.is_marker() || o.ins.is_empty()
    }

    /// `ispoint`
    fn ispoint(&self, vn: VarnodeId) -> bool {
        let v = self.fd.vn(vn);
        konst(self.fd, self.arch, vn).is_none() && !v.is_annotation() && !self.is_readonly(vn)
    }

    fn is_readonly(&self, vn: VarnodeId) -> bool {
        let v = self.fd.vn(vn);
        v.space == Space::Sleigh(self.arch.sleigh.code_space()) && self.arch.is_readonly(v.offset, v.size)
    }

    /// `findDeterminingVarnodes`
    fn find_determining_varnodes(&mut self, op: OpId, slot: usize) {
        let fd = self.fd;
        let mut path: Vec<Node> = vec![(op, slot)];
        let mut firstpoint = false;
        loop {
            let (nop, nslot) = *path.last().unwrap();
            let curvn = fd.op(nop).ins[nslot];
            if self.isprune(curvn) {
                if self.ispoint(curvn) {
                    if !firstpoint {
                        self.path.set_path(fd, &path);
                        firstpoint = true;
                    } else {
                        self.path.meld(fd, &mut path);
                    }
                }
                path.last_mut().unwrap().1 += 1;
                while path.last().unwrap().1 >= fd.op(path.last().unwrap().0).ins.len() {
                    path.pop();
                    if path.is_empty() {
                        break;
                    }
                    path.last_mut().unwrap().1 += 1;
                }
            } else {
                path.push((def(fd, curvn).unwrap(), 0));
            }
            if path.len() <= 1 {
                break;
            }
        }
        if self.path.common.is_empty() {
            self.path.common.push(fd.op(op).ins[slot]);
            self.path.ops.push((Some(op), 0));
        }
    }

    /// `getStride`
    fn stride(&self, vn: VarnodeId) -> u32 {
        let mut mask = nz_mask(self.fd, vn);
        if mask & 0x3f == 0 {
            return 32;
        }
        let mut stride = 1;
        while mask & 1 == 0 {
            mask >>= 1;
            stride <<= 1;
        }
        stride
    }

    /// `getInitialRange`
    fn initial_range(&self, vn: VarnodeId) -> CircleRange {
        let fd = self.fd;
        let v = fd.vn(vn);
        if let Some(c) = konst(fd, self.arch, vn) {
            return CircleRange::single(c, v.size);
        }
        let Some(op) = def(fd, vn) else {
            return CircleRange::new(0, 0, v.size, self.stride(vn));
        };
        if is_bool_output(fd.op(op).opc) {
            return CircleRange::new(0, 2, 1, 1);
        }
        let step = self.stride(vn);
        let mut rng = CircleRange::new(0, nz_mask(fd, vn).wrapping_add(u64::from(step)), v.size, step);
        let o = fd.op(op);
        let c = o.ins.get(1).map(|&c| fd.vn(c)).filter(|c| c.is_constant());
        let tmp = match (o.opc, c) {
            (Opcode::IntAnd, Some(c)) => {
                Some(CircleRange::new(0, c.offset.wrapping_add(u64::from(step)), v.size, step))
            }
            (Opcode::IntRem, Some(c)) => Some(CircleRange::new(0, c.offset, v.size, step)),
            (Opcode::IntSrem, Some(c)) => {
                let mut val = c.offset;
                if (val >> (8 * c.size - 1)) & 1 != 0 {
                    val = val.wrapping_neg() & calc_mask(c.size);
                    val += 1;
                }
                Some(CircleRange::new(val.wrapping_neg().wrapping_add(u64::from(step)), val, v.size, step))
            }
            _ => None,
        };
        if let Some(t) = tmp.filter(|t| t.get_size() < rng.get_size()) {
            rng = t;
        }
        rng
    }

    /// `analyzeGuards`, the pull-backs of each guard through [`cond_range`] (see the module).
    fn analyze_guards(&mut self, mut bl: BlockId, mut pathout: i32) {
        let (fd, arch) = (self.fd, self.arch);
        let blocks = &fd.blocks;
        self.guards.clear();
        for i in 0..2 {
            let prevbl;
            let indpath;
            if pathout >= 0 && blocks.block(bl).outs.len() == 2 {
                prevbl = bl;
                indpath = pathout as usize;
                pathout = -1;
            } else {
                pathout = -1;
                loop {
                    if blocks.block(bl).ins.len() != 1 {
                        return; // `checkUnrolledGuard` for several ins is not ported
                    }
                    let p = blocks.block(bl).ins[0].point;
                    if blocks.block(p).outs.len() != 1 {
                        break;
                    }
                    bl = p;
                }
                prevbl = blocks.block(bl).ins[0].point;
                indpath = blocks.block(bl).ins[0].reverse;
            }
            let Some(&cbranch) = blocks.block(prevbl).ops.last() else { break };
            if fd.op(cbranch).opc != Opcode::Cbranch {
                break;
            }
            if i != 0 {
                let other = blocks.block(prevbl).outs[1 - indpath].point;
                if let Some(&oop) = blocks.block(other).ops.last() {
                    if fd.op(oop).opc == Opcode::Branchind && oop != self.indop {
                        break;
                    }
                }
            }
            let toswitchval = indpath == 1;
            bl = prevbl;
            let vn = fd.op(cbranch).ins[1];
            self.guards.push(GuardRecord::new(fd, vn, CircleRange::boolean(toswitchval)));
            let Some((x, r)) = cond_range(fd, arch, vn, toswitchval) else { continue };
            if r.is_empty() {
                continue;
            }
            self.guards.push(GuardRecord::new(fd, x, r));
            if let Some((y, r2)) = pull_back(fd, arch, x, r, true) {
                if !r2.is_empty() {
                    self.guards.push(GuardRecord::new(fd, y, r2));
                }
            }
        }
    }

    /// `calcRange`
    fn calc_range(&self, vn: VarnodeId) -> CircleRange {
        let mut rng = self.initial_range(vn);
        let (base, bits) = quasi_copy(self.fd, vn);
        for g in &self.guards {
            if g.value_match(self.fd, self.arch, vn, base, bits) == 0 {
                continue;
            }
            rng.intersect(&g.range);
        }
        if rng.get_size() > 0x10000 {
            let mut positive = CircleRange::new(0, (rng.mask >> 1) + 1, self.fd.vn(vn).size, rng.step);
            positive.intersect(&rng);
            if !positive.is_empty() {
                rng = positive;
            }
        }
        rng
    }

    fn set_range(&mut self, range: CircleRange, vn: VarnodeId, op: OpId) {
        let extra = self.jrange.as_ref().and_then(|j| j.extra);
        self.jrange = Some(JumpValues { range, normqvn: vn, startop: op, extra });
    }

    /// `isPreferredRange`
    fn is_preferred(&self, pos: usize, new: &CircleRange) -> bool {
        let old = &self.jrange.as_ref().unwrap().range;
        if old.step != new.step {
            return new.step < old.step;
        }
        if old.left != new.left {
            return new.left < old.left;
        }
        self.fd.vn(self.path.common[pos]).size < self.fd.vn(self.path.common[self.varnode_index]).size
    }

    /// `findSmallestNormal` (no previous model: multistage tables are not ported)
    fn find_smallest_normal(&mut self) {
        self.varnode_index = 0;
        let rng = self.calc_range(self.path.common[0]);
        self.set_range(rng, self.path.common[0], self.path.op(0));
        let mut maxsize = rng.get_size();
        for i in 1..self.path.common.len() {
            let rng = self.calc_range(self.path.common[i]);
            let sz = rng.get_size();
            if sz > maxsize || (sz == maxsize && !self.is_preferred(i, &rng)) {
                continue;
            }
            self.varnode_index = i;
            maxsize = sz;
            let op = self.path.earliest_op(i).unwrap();
            self.set_range(rng, self.path.common[i], op);
        }
        let vi = self.path.common[self.varnode_index];
        if maxsize == 256 && self.fd.vn(vi).size == 1 && !self.path.is_load_in_path(self.fd, self.varnode_index) {
            let v0 = self.path.common[0];
            self.set_range(CircleRange::full(self.fd.vn(v0).size), v0, self.path.op(0));
        }
    }

    /// `findNormalized`
    fn find_normalized(&mut self, rootbl: BlockId, pathout: i32) {
        self.analyze_guards(rootbl, pathout);
        self.find_smallest_normal();
        let sz = self.jrange.as_ref().unwrap().size();
        if sz > MAX_JUMPTABLE_SIZE && self.path.common.len() == 1 {
            let vn = self.path.common[0];
            if self.is_readonly(vn) {
                let v = self.fd.vn(vn);
                let mut buf = [0u8; 8];
                if self.arch.fill_bytes(v.offset, &mut buf).is_some() {
                    let val = u64::from_le_bytes(buf) & calc_mask(v.size);
                    self.varnode_index = 0;
                    self.set_range(CircleRange::single(val, v.size), vn, self.path.op(0));
                }
            }
        }
    }

    /// `JumpBasic::recoverModel`
    fn recover_model(&mut self) -> bool {
        self.find_determining_varnodes(self.indop, 0);
        let bl = self.fd.op(self.indop).parent.unwrap();
        self.find_normalized(bl, -1);
        self.jrange.as_ref().unwrap().size() <= MAX_JUMPTABLE_SIZE
    }

    /// `JumpBasic2::recoverModel`, from the paths `JumpBasic` found.
    fn recover_model2(&mut self, orig: PathMeld) -> bool {
        let fd = self.fd;
        let Some(&joinvn) = orig.common.last() else { return false };
        let Some(multiop) = def(fd, joinvn) else { return false };
        let m = fd.op(multiop);
        if m.opc != Opcode::Multiequal || m.ins.len() != 2 {
            return false;
        }
        let mut found = None;
        for path in 0..2 {
            let Some(c) = def(fd, m.ins[path]) else { continue };
            let c = fd.op(c);
            if c.opc == Opcode::Copy && fd.vn(c.ins[0]).is_constant() {
                found = Some((path, fd.vn(c.ins[0]).offset));
                break;
            }
        }
        let Some((path, extravalue)) = found else { return false };
        let mbl = m.parent.unwrap();
        let rootbl = fd.blocks.block(mbl).ins[1 - path].point;
        let pathout = fd.blocks.block(mbl).ins[1 - path].reverse as i32;
        let defop = orig.op(orig.ops.len() - 1);
        self.jrange = Some(JumpValues {
            range: CircleRange::default(),
            normqvn: joinvn,
            startop: defop,
            extra: Some((extravalue, joinvn, defop)),
        });
        self.find_determining_varnodes(multiop, 1 - path);
        self.find_normalized(rootbl, pathout);
        if self.jrange.as_ref().unwrap().size() > MAX_JUMPTABLE_SIZE {
            return false;
        }
        self.path.append(&orig);
        self.varnode_index += orig.common.len();
        true
    }

    /// `EmulateFunction::emulatePath`
    fn emulate_path(
        &self,
        emu: &mut EmulateFunction,
        val: u64,
        startop: OpId,
        mut startvn: VarnodeId,
    ) -> Result<u64, String> {
        let fd = self.fd;
        let p = &self.path;
        let mut i = p.ops.iter().position(|e| e.0 == Some(startop)).unwrap_or(p.ops.len());
        if fd.op(startop).opc == Opcode::Multiequal {
            let s = fd.op(startop);
            if !s.ins.contains(&startvn) || i == 0 {
                return Err("Cannot start jumptable emulation with unresolved MULTIEQUAL".into());
            }
            startvn = s.out.unwrap();
            i -= 1;
        }
        if i == p.ops.len() {
            return Err("Bad jumptable emulation".into());
        }
        if !fd.vn(startvn).is_constant() {
            emu.set(startvn, val);
        }
        while i > 0 {
            let cur = p.op(i);
            i -= 1;
            emu.execute(cur).map_err(|e| match e {
                EmuError::DataUnavail => {
                    format!("Could not emulate address calculation at 0x{:08x}", fd.op(cur).seq.addr)
                }
                EmuError::Other(m) => m,
            })?;
        }
        emu.get(fd.op(p.op(0)).ins[0]).map_err(|_| "Could not emulate address calculation".into())
    }

    /// `buildAddresses` (`funcptr_align` is 0 for x86: no mask)
    fn build_addresses(&self) -> Result<Vec<u64>, String> {
        let mut emu = EmulateFunction::new(self.fd, self.arch);
        let mut out = Vec::new();
        for (val, vn, op) in self.jrange.as_ref().unwrap().values() {
            out.push(self.emulate_path(&mut emu, val, op, vn)?);
        }
        Ok(out)
    }

    /// `JumpBasic::sanityCheck`: cut the table at the first unreasonable address.
    fn sanity_check(&mut self, table: &mut Vec<u64>) -> bool {
        if table.is_empty() {
            return true;
        }
        let first = table[0];
        let mut i = 0;
        if first != 0 {
            i = 1;
            while i < table.len() {
                if table[i] == 0 {
                    break;
                }
                if first.abs_diff(table[i]) > 0xffff && self.arch.fill_bytes(table[i], &mut [0u8; 4]).is_none() {
                    break;
                }
                i += 1;
            }
        }
        if i == 0 {
            return false;
        }
        if i != table.len() {
            table.truncate(i);
            self.jrange.as_mut().unwrap().truncate(i);
        }
        true
    }
}

/// `JumpTable::isReachable`: false when a guard before the switch has become a constant that
/// never leads to it.
fn is_reachable(fd: &Funcdata, op: OpId) -> bool {
    let mut parent = fd.op(op).parent.unwrap();
    for _ in 0..2 {
        let b = fd.blocks.block(parent);
        if b.ins.len() != 1 {
            return true;
        }
        let bl = b.ins[0].point;
        let blk = fd.blocks.block(bl);
        if blk.outs.len() != 2 {
            continue;
        }
        let Some(&cb) = blk.ops.last() else { continue };
        if fd.op(cb).opc != Opcode::Cbranch {
            continue;
        }
        let vn = fd.vn(fd.op(cb).ins[1]);
        if !vn.is_constant() {
            continue;
        }
        let trueslot = if vn.offset == 0 { 0 } else { 1 };
        if blk.outs[trueslot].point != parent {
            return false;
        }
        parent = bl;
    }
    true
}

/// `JumpTable::isThunk`
fn is_thunk(fd: &Funcdata, table: &[u64]) -> bool {
    if table.len() != 1 {
        return false;
    }
    table[0] == 0 || fd.blocks.ops().all(|o| matches!(fd.op(o).opc, Opcode::Branchind | Opcode::Branch))
}

/// Port of `JumpTable::recoverAddresses` (`recoverModel`, `buildAddresses`, `sanityCheck`) on
/// the partial function `fd`: the targets in table order and whether the table is partial
/// (its switch looks unreachable).
pub(crate) fn recover_addresses(fd: &Funcdata, arch: &Arch, indop: OpId) -> Result<(Vec<u64>, bool), Fail> {
    let addr = fd.op(indop).seq.addr;
    let mut basic = JumpBasic::new(fd, arch, indop);
    let ok = basic.recover_model();
    if std::env::var("GHIDRA_RS_JT_DEBUG").is_ok_and(|v| v == "2") {
        eprintln!(
            "common {:?}\nguards {:?}\njrange {:?} index {}",
            basic.path.common, basic.guards, basic.jrange, basic.varnode_index
        );
    }
    let mut model = if ok {
        basic
    } else {
        let orig = basic.path.clone();
        let mut b2 = JumpBasic::new(fd, arch, indop);
        if !b2.recover_model2(orig) {
            return Err(Fail::Normal(format!("Could not recover jumptable at 0x{addr:08x}. Too many branches")));
        }
        b2
    };
    if model.jrange.as_ref().unwrap().size() == 0 {
        return Err(Fail::Normal(format!("Jumptable with 0 entries at 0x{addr:08x}")));
    }
    let mut table = model.build_addresses().map_err(Fail::Normal)?;
    let partial = !is_reachable(fd, indop);
    if is_thunk(fd, &table) {
        return Err(Fail::Thunk);
    }
    if !model.sanity_check(&mut table) {
        return Err(Fail::Normal(format!("Jumptable at 0x{addr:08x} did not pass sanity check.")));
    }
    Ok((table, partial))
}

/// Port of `Funcdata::earlyJumpTableFail`: walking back from the BRANCHIND over at most 8 ops
/// of the dead list, an address formed by a CALLOTHER fails at once. (x86 declares no
/// injected, `jumpassist` or segment user ops.)
pub(crate) fn early_fail(fd: &Funcdata, op: OpId) -> Option<Fail> {
    let pos = fd.dead.iter().position(|&o| o == op)?;
    let mut vn = fd.op(op).ins[0];
    let mut count = 8;
    for &o in fd.dead[..pos].iter().rev() {
        if fd.vn(vn).size == 1 {
            return None;
        }
        count -= 1;
        if count < 0 {
            return None;
        }
        let p = fd.op(o);
        let outhit = p.out.is_some_and(|out| {
            let (a, b) = (fd.vn(vn), fd.vn(out));
            a.space == b.space
                && a.offset < b.offset.wrapping_add(u64::from(b.size))
                && b.offset < a.offset.wrapping_add(u64::from(a.size))
        });
        use Opcode::*;
        match p.opc {
            Callother if outhit => return Some(Fail::Callother),
            Callother => {}
            Call | Callind | Branch | Cbranch | Branchind | Store => return None,
            Return | Load | Multiequal | Indirect | Segmentop | Cpoolref | New | Insert | Zpull | Spull | Ptradd
            | Ptrsub => {
                if outhit {
                    return None;
                }
            }
            _ if p.ins.len() == 1 => {
                if outhit {
                    if fd.vn(p.ins[0]).size != fd.vn(vn).size {
                        return None;
                    }
                    vn = p.ins[0];
                }
            }
            opc => {
                if outhit {
                    if !matches!(opc, IntAdd | IntSub | IntXor) || !fd.vn(p.ins[1]).is_constant() {
                        return None;
                    }
                    if fd.vn(p.ins[0]).size != fd.vn(vn).size {
                        return None;
                    }
                    vn = p.ins[0];
                }
            }
        }
    }
    None
}
