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
//! - The partial function is simplified by the `jumptable` root action as far as it is ported
//!   (`action::jumptable_partial`: the main loop with dead code, heritage and the rule pool of
//!   stages R1 and R2), so the guards are read as the C++ reads them (`analyzeGuards`: the
//!   CBRANCH condition and two pull-backs). The partial function runs with the `stackvars`
//!   rules, as in the C++, so the stack is heritaged there (superseded: "The stack is not
//!   heritaged", "One stand-in is left"). When its stack heritage reaches a path not ported,
//!   flow.rs falls back to the partial function without those rules (`Flow::build_partial`);
//!   only there [`konst`] still folds what `RuleLoadVarnode` would (a load from read-only
//!   memory and the constant operations after it), and a switch variable kept on the stack is
//!   matched through its two LOADs (`GuardRecord::valueMatch` code 2). Superseded (stage R2):
//!   the stand-ins reading x86 flag logic as one comparison (`cond_range`) and a commutative
//!   op's constant in slot 0 are gone.
//! - The second half of the file is the action `switchnorm` on the function itself
//!   (`ActionSwitchNorm`: `JumpTable::matchModel`, `recoverLabels` with `findUnnormalized`,
//!   `buildLabels` and `backup2Switch`, `foldInNormalization`, `foldInGuards`, and
//!   `JumpModelTrivial` when no model matches). A table keeps the values of the model its
//!   addresses were recovered with ([`ValueRange`]) and its `switchOver` state on
//!   `funcdata::JumpTable`.
//! - `JumpAssisted` (the model of a switch a `<jumpassist>` user op makes; tried first when a
//!   CALLOTHER makes the address) with its scripts on `userop::JumpAssistOp`. Superseded: "not
//!   ported: `JumpAssisted` (x86 has no `jumpassist` user op)".
//! - Not ported: `JumpBasicOverride`
//!   (overrides; the console sets none), multistage tables (`matchModel` fails loudly on the
//!   restart), LOAD collection (`record_jumploads` is off by default), the reverse of
//!   a shift in `backup2Switch` (not reachable: `findUnnormalized` steps over ADD, SUB and
//!   extensions). Superseded: "`testForReturnAddress` fails loudly": flow.rs ports it
//!   (`Fail::Return`, the jump becomes a RETURN).

use super::block::BlockId;
use super::coreaction::{minimal_mask, structure_reset};
use super::emulate::{eval_binary, eval_unary, recover_input_binary, recover_input_unary, EmuError, EmulateFunction};
use super::funcdata::JumpTable;
use super::op::{OpFlags, OpId};
use super::opcode::{is_bool_output, Opcode};
use super::rangeutil::{self, calc_mask, mostsigbit_set, pcode_left, pcode_right, CircleRange};
use super::varnode::{Space, VarnodeId};
use super::{err, Arch, Funcdata, LowlevelError, Result};
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
    /// `fail_return`
    Return,
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

/// The value `vn` has when it is a constant, or (in the partial function, after
/// [`fold_constants`]) folds to one through ops whose inputs do: what the rules not ported yet
/// (`RuleLoadVarnode` with read-only memory, stage R5) would leave as a constant. In the function
/// itself only literal constants count, as in the C++.
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

/// Sets [`Funcdata::folded`] for the partial function of jump-table recovery ([`konst`]).
pub(crate) fn fold_constants(fd: &mut Funcdata, arch: &Arch) {
    fd.folded = calc_folded(fd, arch);
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

fn def(fd: &Funcdata, vn: VarnodeId) -> Option<OpId> {
    fd.vn(vn).def
}

/// [`rangeutil::pull_back`] with the partial function's folded constants ([`konst`]).
fn pull_back(
    fd: &Funcdata,
    arch: &Arch,
    vn: VarnodeId,
    rng: CircleRange,
    usenzmask: bool,
) -> Option<(VarnodeId, CircleRange)> {
    rangeutil::pull_back(fd, vn, rng, usenzmask, |v| konst(fd, arch, v), |v| nz_mask(fd, v))
}

/// Port of `GuardRecord`: a range a CBRANCH before the switch puts on a varnode.
#[derive(Debug, Clone)]
struct GuardRecord {
    /// the guard's CBRANCH; `None` once the guard is cleared (not part of the model, or folded)
    cbranch: Option<OpId>,
    /// the op reading `vn` on the way to the CBRANCH
    read_op: OpId,
    /// the CBRANCH's out edge to the switch, as of the block's flip state when recorded
    indpath: usize,
    /// the guard is duplicated across the blocks flowing into the switch block
    unrolled: bool,
    vn: VarnodeId,
    base_vn: VarnodeId,
    bits_preserved: i32,
    range: CircleRange,
}

impl GuardRecord {
    fn new(
        fd: &Funcdata,
        (cbranch, read_op, indpath): (OpId, OpId, usize),
        range: CircleRange,
        vn: VarnodeId,
        unrolled: bool,
    ) -> GuardRecord {
        let (base_vn, bits_preserved) = quasi_copy(fd, vn);
        GuardRecord { cbranch: Some(cbranch), read_op, indpath, unrolled, vn, base_vn, bits_preserved, range }
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

/// A binary op with a constant in slot 1: its variable input and the constant.
fn split_const(fd: &Funcdata, arch: &Arch, op: OpId) -> Option<(VarnodeId, u64)> {
    let o = fd.op(op);
    if o.ins.len() != 2 {
        return None;
    }
    konst(fd, arch, o.ins[1]).map(|c| (o.ins[0], c))
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

/// `CircleRange::operator==`: two empty ranges are equal whatever their fields.
fn range_eq(a: &CircleRange, b: &CircleRange) -> bool {
    a.isempty == b.isempty && (a.isempty || a == b)
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

    /// What `JumpBasic::clone` keeps of the model: the values.
    fn kept(&self) -> ValueRange {
        ValueRange { range: self.range, extra: self.extra.map(|e| e.0), assisted: None }
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
    /// the range of the model recovered earlier for the same switch (`previous`)
    expected: Option<CircleRange>,
    /// `JumpBasic2::extravn`: where the first model stopped
    extravn: Option<VarnodeId>,
    normalvn: Option<VarnodeId>,
    switchvn: Option<VarnodeId>,
}

impl<'a> JumpBasic<'a> {
    fn new(fd: &'a Funcdata, arch: &'a Arch, indop: OpId) -> JumpBasic<'a> {
        JumpBasic {
            fd,
            arch,
            indop,
            path: PathMeld::default(),
            guards: Vec::new(),
            jrange: None,
            varnode_index: 0,
            expected: None,
            extravn: None,
            normalvn: None,
            switchvn: None,
        }
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

    /// `analyzeGuards`: each guard's condition and up to two pull-backs of it.
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
                        if blocks.block(bl).ins.len() > 1 {
                            self.check_unrolled_guard(bl, 2, true);
                        }
                        return;
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
            let toswitchval = (indpath == 1) != fd.op(cbranch).flags.has(OpFlags::BOOLEAN_FLIP);
            bl = prevbl;
            let mut vn = fd.op(cbranch).ins[1];
            let mut rng = CircleRange::boolean(toswitchval);
            // the path as of an unflipped block (`getFlipPath`)
            let indpathstore = if blocks.block(prevbl).flip_path { 1 - indpath } else { indpath };
            self.guards.push(GuardRecord::new(fd, (cbranch, cbranch, indpathstore), rng, vn, false));
            for _ in 0..2 {
                let Some(read_op) = def(fd, vn) else { break };
                let Some((v, r)) = pull_back(fd, arch, vn, rng, true) else { break };
                if r.is_empty() {
                    break;
                }
                (vn, rng) = (v, r);
                self.guards.push(GuardRecord::new(fd, (cbranch, read_op, indpathstore), rng, vn, false));
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

    /// `findSmallestNormal`: with the range of an earlier model (`expected`), the search stops
    /// at the first variable whose range is that one (the test reads the range computed last,
    /// selected or not, as the C++ does).
    fn find_smallest_normal(&mut self) {
        let expected = self.expected.unwrap_or_default();
        self.varnode_index = 0;
        let mut rng = self.calc_range(self.path.common[0]);
        self.set_range(rng, self.path.common[0], self.path.op(0));
        let mut maxsize = rng.get_size();
        for i in 1..self.path.common.len() {
            if range_eq(&rng, &expected) {
                return;
            }
            rng = self.calc_range(self.path.common[i]);
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
        if self.jrange.as_ref().unwrap().size() > MAX_JUMPTABLE_SIZE {
            return false;
        }
        self.mark_foldable_guards();
        true
    }

    /// `markFoldableGuards`: a guard on another variable, or an unrolled one, is not folded.
    fn mark_foldable_guards(&mut self) {
        let vn = self.path.common[self.varnode_index];
        let (base, bits) = quasi_copy(self.fd, vn);
        for i in 0..self.guards.len() {
            if self.guards[i].value_match(self.fd, self.arch, vn, base, bits) == 0 || self.guards[i].unrolled {
                self.guards[i].cbranch = None;
            }
        }
    }

    /// `findCbranch`: the CBRANCH deciding the flow into `bl` through in edge `inslot` (through
    /// blocks with one in and one out edge), and its out edge.
    fn find_cbranch(&self, mut bl: BlockId, mut inslot: usize) -> Option<(OpId, usize)> {
        let (fd, blocks) = (self.fd, &self.fd.blocks);
        loop {
            let inb = blocks.block(bl).ins.get(inslot)?.point;
            if let Some(&c) = blocks.block(inb).ops.last().filter(|&&c| fd.op(c).opc == Opcode::Cbranch) {
                return Some((c, blocks.block(bl).ins[inslot].reverse));
            }
            if blocks.block(inb).outs.len() != 1 || blocks.block(inb).ins.len() != 1 {
                return None;
            }
            (bl, inslot) = (inb, 0);
        }
    }

    /// `checkCommonCbranch`: a CBRANCH per in edge of `bl`, all selecting `bl` the same way;
    /// the first one, their boolean inputs and the out edge.
    fn check_common_cbranch(&self, bl: BlockId) -> Option<(OpId, Vec<VarnodeId>, usize)> {
        let fd = self.fd;
        let (cbranch, path) = self.find_cbranch(bl, 0)?;
        let flip = fd.op(cbranch).flags.has(OpFlags::BOOLEAN_FLIP);
        let mut vars = vec![fd.op(cbranch).ins[1]];
        for i in 1..fd.blocks.block(bl).ins.len() {
            let (alt, altpath) = self.find_cbranch(bl, i)?;
            if fd.op(alt).flags.has(OpFlags::BOOLEAN_FLIP) != flip || path != altpath {
                return None;
            }
            vars.push(fd.op(alt).ins[1]);
        }
        Some((cbranch, vars, path))
    }

    /// `BlockBasic::findMultiequal`: the MULTIEQUAL of `bl` taking exactly `vars`.
    fn find_multiequal(&self, bl: BlockId, vars: &[VarnodeId]) -> Option<OpId> {
        let fd = self.fd;
        let mut readers = fd.vn(vars[0]).descend.iter().copied();
        let op = readers.find(|&o| fd.op(o).opc == Opcode::Multiequal && fd.op(o).parent == Some(bl))?;
        (fd.op(op).ins.as_slice() == vars).then_some(op)
    }

    /// `BlockBasic::liftVerifyUnroll`: every variable is made by the same op (with the same
    /// constant, if binary); each is replaced by that op's input `slot`.
    fn lift_verify_unroll(&self, vars: &mut [VarnodeId], slot: usize) -> bool {
        let fd = self.fd;
        let Some(op) = def(fd, vars[0]) else { return false };
        let o = fd.op(op);
        let cvn = if o.ins.len() == 2 {
            let c = fd.vn(o.ins[1 - slot]);
            if !c.is_constant() {
                return false;
            }
            Some((c.size, c.offset))
        } else {
            None
        };
        let opc = o.opc;
        vars[0] = o.ins[slot];
        for v in vars.iter_mut().skip(1) {
            let Some(op) = def(fd, *v) else { return false };
            let o = fd.op(op);
            if o.opc != opc {
                return false;
            }
            if let Some(c) = cvn {
                let Some(c2) = o.ins.get(1 - slot).map(|&c| fd.vn(c)) else { return false };
                if !c2.is_constant() || (c2.size, c2.offset) != c {
                    return false;
                }
            }
            let Some(&next) = o.ins.get(slot) else { return false };
            *v = next;
        }
        true
    }

    /// `checkUnrolledGuard`: a guard duplicated across the blocks flowing into `bl`, on the
    /// MULTIEQUAL of the duplicated switch variables.
    fn check_unrolled_guard(&mut self, bl: BlockId, maxpullback: usize, usenzmask: bool) {
        let (fd, arch) = (self.fd, self.arch);
        let Some((cbranch, mut vars, indpath)) = self.check_common_cbranch(bl) else { return };
        let toswitchval = (indpath == 1) != fd.op(cbranch).flags.has(OpFlags::BOOLEAN_FLIP);
        let mut rng = CircleRange::boolean(toswitchval);
        let flipped = fd.op(cbranch).parent.is_some_and(|p| fd.blocks.block(p).flip_path);
        let indpathstore = if flipped { 1 - indpath } else { indpath };
        let mut read_op = cbranch;
        for _ in 0..maxpullback {
            let guarded = if vars.iter().all(|&v| v == vars[0]) {
                Some(vars[0])
            } else {
                self.find_multiequal(bl, &vars).and_then(|m| fd.op(m).out)
            };
            if let Some(vn) = guarded {
                self.guards.push(GuardRecord::new(fd, (cbranch, read_op, indpathstore), rng, vn, true));
            }
            let Some(d) = def(fd, vars[0]) else { break };
            read_op = d;
            let Some((v, r)) = pull_back(fd, arch, vars[0], rng, usenzmask) else { break };
            rng = r;
            if rng.is_empty() {
                break;
            }
            let Some(slot) = fd.op(read_op).ins.iter().position(|&i| i == v) else { break };
            if !self.lift_verify_unroll(&mut vars, slot) {
                break;
            }
        }
    }

    /// `JumpBasic2::recoverModel`, from the paths `JumpBasic` found.
    fn recover_model2(&mut self, orig: PathMeld) -> bool {
        let fd = self.fd;
        let Some(&joinvn) = orig.common.last() else { return false };
        self.extravn = Some(joinvn);
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
    ) -> std::result::Result<u64, String> {
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
        // a load image read failing here is a `DataUnavailError` the loop does not catch, with
        // the load image's own message, which is not ported
        emu.get(fd.op(p.op(0)).ins[0]).map_err(|_| {
            "jump table: reading the table after emulation (DataUnavailError of the load image) is not ported".into()
        })
    }

    /// `buildAddresses` (`funcptr_align` is 0 for x86: no mask)
    fn build_addresses(&self) -> std::result::Result<Vec<u64>, String> {
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

/// The conditions of the CBRANCHs `analyzeGuards` reads for the jump `indop` (flow.rs checks
/// them in the partial function made without the stack rules).
pub(crate) fn guard_conditions(fd: &Funcdata, arch: &Arch, indop: OpId) -> Vec<VarnodeId> {
    let mut basic = JumpBasic::new(fd, arch, indop);
    basic.recover_model();
    let ops = basic.guards.iter().map(|g| g.read_op).filter(|&o| fd.op(o).opc == Opcode::Cbranch);
    ops.map(|o| fd.op(o).ins[1]).collect()
}

/// Port of `JumpTable::recoverAddresses` (`recoverModel`, `buildAddresses`, `sanityCheck`) on
/// the partial function `fd`: the targets in table order, whether the table is partial (its
/// switch looks unreachable), the values kept and whether the sanity check truncated the table
/// (the caller records the partial function's warning).
pub(crate) fn recover_addresses(
    fd: &Funcdata,
    arch: &Arch,
    indop: OpId,
) -> std::result::Result<(Vec<u64>, bool, ValueRange, bool), Fail> {
    let addr = fd.op(indop).seq.addr;
    // JumpTable::recoverModel: the assisted model first, when a CALLOTHER makes the address
    let low = |e: LowlevelError| Fail::Normal(e.0);
    if let Some(assisted) = JumpAssisted::recover_model(fd, arch, indop, None).map_err(low)? {
        // getTableSize is never 0 (the default is an entry); JumpAssisted::sanityCheck passes
        let table = assisted.build_addresses(fd, arch).map_err(low)?;
        let partial = !is_reachable(fd, indop);
        if is_thunk(fd, &table) {
            return Err(Fail::Thunk);
        }
        let kept = ValueRange { assisted: Some(assisted.size_indices), ..ValueRange::default() };
        return Ok((table, partial, kept, false));
    }
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
    let size = table.len();
    let partial = !is_reachable(fd, indop);
    if is_thunk(fd, &table) {
        return Err(Fail::Thunk);
    }
    if !model.sanity_check(&mut table) {
        return Err(Fail::Normal(format!("Jumptable at 0x{addr:08x} did not pass sanity check.")));
    }
    let kept = model.jrange.as_ref().map(JumpValues::kept).unwrap_or_default();
    let truncated = table.len() != size;
    Ok((table, partial, kept, truncated))
}

/// Port of `Funcdata::earlyJumpTableFail`: walking back from the BRANCHIND over at most 8 ops
/// of the dead list, an address formed by a CALLOTHER fails at once, unless the user op is a
/// `jumpassist` or a segment op, which end the walk. (No spec ghidra-rs reads declares an
/// injected user op, `<callotherfixup>`.)
pub(crate) fn early_fail(fd: &Funcdata, arch: &Arch, op: OpId) -> Option<Fail> {
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
        let userop = p.ins.first().map_or(0, |&v| fd.vn(v).offset);
        match p.opc {
            Callother if arch.userops.jump_assist(userop).is_some() || arch.userops.is_segment(userop) => return None,
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

// ---------------------------------------------------------------------------------------
// Labels: ActionSwitchNorm with JumpTable::matchModel, recoverLabels, foldInNormalization and
// foldInGuards, on the function itself

/// `JumpValues::NO_LABEL`: a table entry without a case label (the default, an exit).
pub(crate) const NO_LABEL: u64 = 0xBAD1_ABE1_BAD1_ABE1;

/// The values of a model as `JumpBasic::clone` keeps them (`JumpValuesRange`, and
/// `JumpValuesRangeDefault` with its extra value): what a table keeps of the model its
/// addresses were recovered with on the partial function.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ValueRange {
    range: CircleRange,
    extra: Option<u64>,
    /// the model was a `JumpAssisted`: its `sizeIndices` (`JumpAssisted::clone`)
    assisted: Option<u64>,
}

impl ValueRange {
    /// `getSize` (`JumpAssisted::getTableSize`: the indices and the default)
    fn size(&self) -> u64 {
        match self.assisted {
            Some(n) => n + 1,
            None => self.range.get_size() + u64::from(self.extra.is_some()),
        }
    }

    /// `contains`
    fn contains(&self, val: u64) -> bool {
        self.extra == Some(val) || self.range.contains(val)
    }

    /// The values in order, each with `isReversible` (false for the extra value).
    fn values(&self) -> Vec<(u64, bool)> {
        let mut v = Vec::new();
        if self.range.get_size() != 0 {
            let mut cur = self.range.left;
            loop {
                v.push((cur, true));
                if !self.range.get_next(&mut cur) {
                    break;
                }
            }
        }
        v.extend(self.extra.map(|e| (e, false)));
        v
    }
}

/// The model of a table on its function after `matchModel`, as far as `foldInGuards` reads it:
/// the guards still to fold (CBRANCH and stored path to the switch). `JumpModelTrivial` has no
/// guards.
#[derive(Debug, Clone)]
pub(crate) struct Model {
    /// `JumpBasic2`: its guard only makes the last block the default
    basic2: bool,
    guards: Vec<(Option<OpId>, usize)>,
    /// `JumpAssisted`: no guards, the last block is the default
    assisted: bool,
}

/// Port of `JumpAssisted`: the model of a switch whose address a `jumpassist` user op makes.
/// The op's inputs after the switch variable are constants; the scripts of the
/// [`JumpAssistOp`](super::userop::JumpAssistOp) give the table from them.
struct JumpAssisted<'a> {
    userop: &'a super::userop::JumpAssistOp,
    /// the `jumpassist` CALLOTHER
    assist_op: OpId,
    /// the switch variable (the op's first parameter)
    switchvn: VarnodeId,
    /// how many indices the table has, the default not counted
    size_indices: u64,
}

impl<'a> JumpAssisted<'a> {
    /// Port of `JumpAssisted::recoverModel`; `previous` is the table size of the model to
    /// match. `None`: the address of `indop` is not made by a `jumpassist` op, or its table
    /// does not fit.
    fn recover_model(
        fd: &Funcdata,
        arch: &'a Arch,
        indop: OpId,
        previous: Option<u64>,
    ) -> Result<Option<JumpAssisted<'a>>> {
        let Some(assist_op) = def(fd, fd.op(indop).ins[0]).filter(|&d| fd.op(d).opc == Opcode::Callother) else {
            return Ok(None);
        };
        let ins = &fd.op(assist_op).ins;
        if ins.len() < 3 {
            return Ok(None);
        }
        let Some(userop) = arch.userops.jump_assist(fd.vn(ins[0]).offset) else { return Ok(None) };
        if ins[2..].iter().any(|&v| !fd.vn(v).is_constant()) {
            return Ok(None); // all remaining parameters must be constant
        }
        let mut model = JumpAssisted { userop, assist_op, switchvn: ins[1], size_indices: 0 };
        model.size_indices = match &userop.calc_size {
            // without a size script the first parameter after the switch variable is the size
            None => fd.vn(ins[2]).offset,
            Some(script) => script.evaluate(arch, &model.inputs(fd, script, "size_pcode")?)?,
        };
        if previous.is_some_and(|p| p.wrapping_sub(1) != model.size_indices) || model.size_indices > MAX_JUMPTABLE_SIZE
        {
            return Ok(None);
        }
        Ok(Some(model))
    }

    /// The script inputs: the offsets of the op's parameters (the first is replaced by the index).
    fn inputs(&self, fd: &Funcdata, script: &super::inject::ExecutablePcode, tag: &str) -> Result<Vec<u64>> {
        let ins = &fd.op(self.assist_op).ins[1..];
        if script.inputs.len() != ins.len() {
            return err(format!("{}: <{tag}> has wrong number of parameters", self.userop.name));
        }
        Ok(ins.iter().map(|&v| fd.vn(v).offset).collect())
    }

    /// Port of `JumpAssisted::buildAddresses`: the target of each index, then the default.
    /// (`funcptr_align` is 0 for every spec ghidra-rs reads: no mask.)
    fn build_addresses(&self, fd: &Funcdata, arch: &Arch) -> Result<Vec<u64>> {
        let script = &self.userop.index2addr;
        let mut inputs = self.inputs(fd, script, "addr_pcode")?;
        let mut table = Vec::new();
        for index in 0..self.size_indices {
            inputs[0] = index;
            table.push(script.evaluate(arch, &inputs)?);
        }
        let script = &self.userop.default_addr;
        let mut inputs = self.inputs(fd, script, "default_pcode")?;
        inputs[0] = 0;
        table.push(script.evaluate(arch, &inputs)?);
        Ok(table)
    }

    /// Port of `JumpAssisted::buildLabels`: the label of each index, and none for the default.
    fn build_labels(&self, fd: &Funcdata, arch: &Arch) -> Result<Vec<u64>> {
        let mut labels: Vec<u64> = match &self.userop.index2case {
            None => (0..self.size_indices).collect(), // the index is the label
            Some(script) => {
                let mut inputs = self.inputs(fd, script, "case_pcode")?;
                let mut labels = Vec::new();
                for index in 0..self.size_indices {
                    inputs[0] = index;
                    labels.push(script.evaluate(arch, &inputs)?);
                }
                labels
            }
        };
        labels.push(NO_LABEL);
        Ok(labels)
    }
}

/// `std::lower_bound` / `std::upper_bound` over `block2addr` by position, as libstdc++ walks
/// them (the vector is not sorted once `addBlockToSwitch` appends to it).
fn bound(v: &[(usize, usize)], pos: usize, upper: bool) -> usize {
    let (mut first, mut len) = (0, v.len());
    while len > 0 {
        let half = len >> 1;
        let right = if upper { pos >= v[first + half].0 } else { v[first + half].0 < pos };
        if right {
            first += half + 1;
            len -= half + 1;
        } else {
            len = half;
        }
    }
    first
}

impl JumpTable {
    pub(crate) fn new(op: OpId, targets: Vec<u64>, orig: Option<ValueRange>) -> JumpTable {
        JumpTable {
            op,
            targets,
            labels: Vec::new(),
            block2addr: Vec::new(),
            default_block: None,
            last_block: 0,
            default_is_folded: false,
            switch_var_consume: u64::MAX,
            orig,
            model: None,
        }
    }

    /// Port of `JumpTable::switchOver`, given the out-edge position of the switch block each
    /// table entry goes to: the sorted map from positions to entries, and the default (the
    /// position most entries go to, if more than one does).
    pub(crate) fn switch_over(&mut self, positions: &[usize]) {
        self.block2addr = positions.iter().copied().zip(0..).collect();
        let Some(&(last, _)) = self.block2addr.last() else { return };
        self.last_block = last;
        self.block2addr.sort_unstable();
        self.default_block = None;
        let mut maxcount = 1;
        for group in self.block2addr.chunk_by(|a, b| a.0 == b.0) {
            if group.len() > maxcount {
                maxcount = group.len();
                self.default_block = Some(group[0].0);
            }
        }
    }

    /// `block2Position`: the out edge of the switch block that reaches `bl`.
    fn block2position(&self, fd: &Funcdata, bl: BlockId) -> Result<usize> {
        let parent = fd.op(self.op).parent;
        let edge = fd.blocks.block(bl).ins.iter().find(|e| Some(e.point) == parent);
        edge.map(|e| e.reverse).ok_or_else(|| LowlevelError("Requested block, not in jumptable".into()))
    }

    /// `numIndicesByBlock`: how many table entries go to `bl` (`std::equal_range`).
    pub(crate) fn num_indices_by_block(&self, fd: &Funcdata, bl: BlockId) -> Result<usize> {
        let pos = self.block2position(fd, bl)?;
        let v = &self.block2addr;
        let (mut first, mut len) = (0, v.len());
        while len > 0 {
            let half = len >> 1;
            let mid = first + half;
            if v[mid].0 < pos {
                first = mid + 1;
                len -= half + 1;
            } else if pos < v[mid].0 {
                len = half;
            } else {
                let left = first + bound(&v[first..mid], pos, false);
                let right = mid + 1 + bound(&v[mid + 1..first + len], pos, true);
                return Ok(right - left);
            }
        }
        Ok(0)
    }

    /// `getIndexByBlock`: the table index of the `i`-th entry going to `bl`.
    pub(crate) fn index_by_block(&self, fd: &Funcdata, bl: BlockId, i: usize) -> Result<usize> {
        let pos = self.block2position(fd, bl)?;
        let from = bound(&self.block2addr, pos, false);
        let mut hits = self.block2addr[from..].iter().filter(|e| e.0 == pos);
        hits.nth(i).map(|e| e.1).ok_or_else(|| LowlevelError("Could not get jumptable index for block".into()))
    }
}

impl JumpBasic<'_> {
    /// `markModel(true)`: the ops of the paths from the normalized variable to the BRANCHIND
    /// (`PathMeld::markPaths`) and the ops reading the guards' variables.
    fn model_ops(&self) -> HashSet<OpId> {
        let mut marks = HashSet::new();
        if let Some(start) = self.path.ops.iter().rposition(|e| e.1 == self.varnode_index as i32) {
            marks.extend(self.path.ops[..=start].iter().filter_map(|e| e.0));
        }
        marks.extend(self.guards.iter().filter(|g| g.cbranch.is_some()).map(|g| g.read_op));
        marks
    }

    /// Port of `JumpBasic::findUnnormalized` (`maxaddsub` and `maxext` are 1): from the
    /// normalized variable back through at most one addition or subtraction of a constant and
    /// one extension, as long as the variable only flows into the model.
    fn find_unnormalized(&mut self) {
        let fd = self.fd;
        let mut i = self.varnode_index;
        let normalvn = self.path.common[i];
        i += 1;
        let mut switchvn = normalvn;
        let marks = self.model_ops();
        let (mut countaddsub, mut countext) = (0, 0);
        let mut normop: Option<OpId> = None;
        while i < self.path.common.len() {
            // flowsOnlyToModel
            if !fd.vn(switchvn).descend.iter().all(|&op| Some(op) == normop || marks.contains(&op)) {
                break;
            }
            let testvn = self.path.common[i];
            let Some(d) = def(fd, switchvn) else { break };
            normop = Some(d);
            let o = fd.op(d);
            let Some(j) = o.ins.iter().position(|&v| v == testvn) else { break };
            match o.opc {
                Opcode::IntAdd | Opcode::IntSub => {
                    countaddsub += 1;
                    if countaddsub <= 1 && fd.vn(o.ins[1 - j]).is_constant() {
                        switchvn = testvn;
                    }
                }
                Opcode::IntZext | Opcode::IntSext => {
                    countext += 1;
                    if countext <= 1 {
                        switchvn = testvn;
                    }
                }
                _ => {}
            }
            if switchvn != testvn {
                break;
            }
            i += 1;
        }
        (self.normalvn, self.switchvn) = (Some(normalvn), Some(switchvn));
    }

    /// Port of `JumpBasic2::findUnnormalized`: the basic form when the normalized variable's
    /// block dominates the switch (`checkNormalDominance`); else the MULTIEQUAL where the first
    /// model stopped is both variables.
    fn find_unnormalized2(&mut self) -> Result<()> {
        let fd = self.fd;
        let normalvn = self.path.common[self.varnode_index];
        let dominates = match def(fd, normalvn) {
            None if fd.vn(normalvn).is_input() => true,
            None => return err("JumpBasic2: a normalized switch variable that is neither written nor an input"),
            Some(d) => {
                let defblock = fd.op(d).parent;
                let mut bl = fd.op(self.path.op(0)).parent;
                while bl.is_some() && bl != defblock {
                    bl = bl.and_then(|b| fd.blocks.block(b).idom);
                }
                bl.is_some()
            }
        };
        if dominates {
            self.find_unnormalized();
            return Ok(());
        }
        let extravn = self.extravn.ok_or_else(|| LowlevelError("JumpBasic2 without its join varnode".into()))?;
        if !def(fd, extravn).is_some_and(|m| fd.op(m).ins.iter().take(2).any(|&v| v == normalvn)) {
            return err("Backward normalization not implemented");
        }
        (self.normalvn, self.switchvn) = (Some(extravn), Some(extravn));
        Ok(())
    }

    /// Port of `JumpBasic::backup2Switch`: the value of `invn` for which `outvn` is `output`.
    /// `None` is the C++ `EvaluationError` (the value is outside what an extension gives).
    fn backup2switch(&self, mut output: u64, outvn: VarnodeId, invn: VarnodeId) -> Result<Option<u64>> {
        let fd = self.fd;
        let mut cur = outvn;
        while cur != invn {
            let op = def(fd, cur).ok_or_else(|| LowlevelError("Bad switch normalization op".into()))?;
            let o = fd.op(op);
            let sizeout = fd.vn(cur).size;
            let slot = o.ins.iter().position(|&v| !fd.vn(v).is_constant());
            let slot = slot.ok_or_else(|| LowlevelError("Bad switch normalization op".into()))?;
            let sizein = fd.vn(o.ins[slot]).size;
            match o.ins.len() {
                2 => {
                    let other = fd.vn(o.ins[1 - slot]);
                    if !other.is_constant() {
                        return err("backup2Switch: an operand read from memory is not ported");
                    }
                    output = recover_input_binary(o.opc, slot, sizeout, output, other.offset)?;
                }
                1 => match recover_input_unary(o.opc, sizeout, output, sizein)? {
                    Some(v) => output = v,
                    None => return Ok(None),
                },
                _ => return err("Bad switch normalization op"),
            }
            cur = o.ins[slot];
        }
        Ok(Some(output))
    }

    /// Port of `JumpBasic::buildLabels`: the label of each table entry, walking the values of
    /// the model the addresses were recovered with (`orig`); the warnings by table index.
    fn build_labels(&self, orig: &ValueRange, ntargets: usize) -> Result<(Vec<u64>, LabelWarnings)> {
        let own = self.jrange.as_ref().map(JumpValues::kept).unwrap_or_default();
        let no_vn = || LowlevelError("buildLabels before findUnnormalized".into());
        let (normalvn, switchvn) = (self.normalvn.ok_or_else(no_vn)?, self.switchvn.ok_or_else(no_vn)?);
        let (mut labels, mut warnings) = (Vec::new(), Vec::new());
        for (val, reversible) in orig.values() {
            let mut switchval = NO_LABEL; // not reversible: the default or an exit, hopefully
            if reversible {
                match self.backup2switch(val, normalvn, switchvn)? {
                    Some(v) => {
                        switchval = v;
                        if !own.contains(val) {
                            warnings.push(("This code block may not be properly labeled as switch case", labels.len()));
                        }
                    }
                    None => warnings.push(("Calculation of case label failed", labels.len())),
                }
            }
            labels.push(switchval);
            // the table may have been truncated by the sanity check
            if labels.len() >= ntargets {
                break;
            }
        }
        while labels.len() < ntargets {
            warnings.push(("Bad switch case", labels.len()));
            labels.push(NO_LABEL);
        }
        Ok((labels, warnings))
    }
}

/// The warnings of `buildLabels`, each with the index of the table entry it is about.
type LabelWarnings = Vec<(&'static str, usize)>;

/// What `matchModel` and `recoverLabels` find for one table.
struct Labelled {
    model: Model,
    labels: Vec<u64>,
    warnings: LabelWarnings,
    /// the unnormalized switch variable (none for the trivial model)
    switchvn: Option<VarnodeId>,
    /// the model's table size is not the address table's
    mismatch: bool,
    /// `JumpAssisted`: the `jumpassist` op `foldInNormalization` removes
    assist_op: Option<OpId>,
}

/// Port of `JumpTable::matchModel` (`recoverModel` on the function itself, against the range
/// recovered on the partial function) and `JumpTable::recoverLabels`. `None`: no model matches
/// (`JumpModelTrivial`).
fn match_model(fd: &Funcdata, arch: &Arch, jt: &JumpTable) -> Result<Option<Labelled>> {
    // JumpTable::recoverModel: the assisted model first, when a CALLOTHER makes the address
    if let Some(assisted) = JumpAssisted::recover_model(fd, arch, jt.op, jt.orig.map(|o| o.size()))? {
        let size = assisted.size_indices + 1;
        let mismatch = size != jt.targets.len() as u64;
        if mismatch && jt.targets.len() == 1 && size > 1 {
            return err("switchnorm: a multistage jump table (insertMultistageJump, restart) is not ported");
        }
        // JumpAssisted::buildLabels reads the saved model as a JumpAssisted
        if jt.orig.is_some_and(|o| o.size() != 0 && o.assisted != Some(assisted.size_indices)) {
            return err("JumpAssisted table size changed during recovery");
        }
        return Ok(Some(Labelled {
            model: Model { basic2: false, guards: Vec::new(), assisted: true },
            labels: assisted.build_labels(fd, arch)?,
            warnings: Vec::new(),
            switchvn: Some(assisted.switchvn),
            mismatch,
            assist_op: Some(assisted.assist_op),
        }));
    }
    if jt.orig.is_some_and(|o| o.assisted.is_some()) {
        // the C++ goes on to JumpBasic with the saved JumpAssisted as the model to match
        return err("switchnorm: a jumpassist table whose op no longer matches on the function is not ported");
    }
    let expected = jt.orig.map(|o| o.range);
    let mut basic = JumpBasic::new(fd, arch, jt.op);
    basic.expected = expected;
    let mut basic2 = false;
    if !basic.recover_model() {
        let path = std::mem::take(&mut basic.path);
        basic = JumpBasic::new(fd, arch, jt.op);
        basic.expected = expected;
        basic2 = true;
        if !basic.recover_model2(path) {
            return Ok(None);
        }
    }
    let size = basic.jrange.as_ref().map_or(0, JumpValues::size);
    let mismatch = size != jt.targets.len() as u64;
    if mismatch && jt.targets.len() == 1 && size > 1 {
        return err("switchnorm: a multistage jump table (insertMultistageJump, restart) is not ported");
    }
    if basic2 {
        basic.find_unnormalized2()?;
    } else {
        basic.find_unnormalized();
    }
    let own = basic.jrange.as_ref().map(JumpValues::kept).unwrap_or_default();
    let orig = jt.orig.filter(|o| o.size() != 0).unwrap_or(own);
    let (labels, warnings) = basic.build_labels(&orig, jt.targets.len())?;
    let guards = basic.guards.iter().map(|g| (g.cbranch, g.indpath)).collect();
    let model = Model { basic2, guards, assisted: false };
    Ok(Some(Labelled { model, labels, warnings, switchvn: basic.switchvn, mismatch, assist_op: None }))
}

/// `matchModel`, `recoverLabels` and `foldInNormalization` for table `i`.
fn recover_labels(fd: &mut Funcdata, arch: &Arch, i: usize) -> Result<()> {
    let indop = fd.jumptables[i].op;
    if fd.jumptables[i].targets.is_empty() {
        return err("Trying to recover jumptable labels without addresses");
    }
    let Some(parent) = fd.op(indop).parent else { return err("switchnorm: a jump table whose BRANCHIND is dead") };
    let Some(found) = match_model(fd, arch, &fd.jumptables[i])? else {
        // JumpModelTrivial: one entry per out edge of the switch block, labelled by its address
        let targets: Vec<u64> = fd.blocks.block(parent).outs.iter().map(|e| fd.blocks.block(e.point).start).collect();
        let jt = &mut fd.jumptables[i];
        jt.block2addr = (0..targets.len()).map(|p| (p, p)).collect();
        jt.last_block = targets.len().checked_sub(1).ok_or_else(|| LowlevelError("switch without out edges".into()))?;
        jt.default_block = None;
        jt.labels = targets.clone();
        jt.targets = targets;
        jt.model = Some(Model { basic2: false, guards: Vec::new(), assisted: false });
        jt.orig = None;
        return Ok(());
    };
    let addr = fd.op(indop).seq.addr;
    if found.mismatch {
        fd.warning("Could not find normalized switch variable to match jumptable", addr);
    }
    for (msg, index) in found.warnings {
        let target = fd.jumptables[i].targets[index];
        fd.warning(msg, target);
    }
    let jt = &mut fd.jumptables[i];
    jt.labels = found.labels;
    jt.model = Some(found.model);
    jt.orig = None; // clearSavedModel
    if let Some(switchvn) = found.switchvn {
        // JumpTable::foldInNormalization: the BRANCHIND reads the unnormalized variable, so the
        // address calculation dies; the variable's unused high bits may be truncated
        match found.assist_op {
            // JumpAssisted::foldInNormalization: every reader of the jumpassist op's output
            // (the BRANCHIND among them) reads the switch variable, and the op goes
            Some(assist) => {
                let readers = fd.op(assist).out.map_or_else(Vec::new, |o| fd.vn(o).descend.to_vec());
                for op in readers {
                    fd.op_set_input(op, switchvn, 0)?;
                }
                fd.op_destroy(assist);
            }
            None => fd.op_set_input(indop, switchvn, 0)?,
        }
        let v = fd.vn(switchvn);
        let mut consume = minimal_mask(fd.nzmask(switchvn));
        if consume >= calc_mask(v.size) {
            if let Some(d) = v.def.filter(|&d| fd.op(d).opc == Opcode::IntSext) {
                consume = calc_mask(fd.vn(fd.op(d).ins[0]).size);
            }
        }
        fd.jumptables[i].switch_var_consume = consume;
    }
    Ok(())
}

/// Port of `BlockBasic::noInterveningStatement`: nothing in the switch block but the switch
/// (a call, a store, or a value used outside the block or kept in memory is a statement).
fn no_intervening_statement(fd: &Funcdata, bl: BlockId) -> Result<bool> {
    for &op in &fd.blocks.block(bl).ops {
        let o = fd.op(op);
        if o.is_marker() || o.is_branch() {
            continue;
        }
        if o.is_call() || o.opc == Opcode::Store {
            return Ok(false);
        }
        if matches!(o.opc, Opcode::Copy | Opcode::Subpiece) {
            continue;
        }
        let out = fd.vn(o.out.ok_or_else(|| LowlevelError("noInterveningStatement: an op without output".into()))?);
        if out.has(super::varnode::VnFlags::ADDRTIED) || out.descend.iter().any(|&r| fd.op(r).parent != Some(bl)) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Port of `Funcdata::pushBranch`: the conditional branch of `bb` becomes a branch, and its
/// out edge `slot` leaves the switch block `bbnew` instead.
fn push_branch(fd: &mut Funcdata, bb: BlockId, slot: usize, bbnew: BlockId) -> Result<()> {
    let last = |fd: &Funcdata, b: BlockId| fd.blocks.block(b).ops.last().copied();
    let cbranch = last(fd, bb).filter(|&c| fd.op(c).opc == Opcode::Cbranch && fd.blocks.block(bb).outs.len() == 2);
    let Some(cbranch) = cbranch else { return err("Cannot push non-conditional edge") };
    if !last(fd, bbnew).is_some_and(|i| fd.op(i).opc == Opcode::Branchind) {
        return err("Can only push branch into indirect jump");
    }
    fd.op_remove_input(cbranch, 1);
    fd.op_set_opcode(cbranch, Opcode::Branch);
    fd.blocks.move_out_edge(bb, slot, bbnew);
    structure_reset(fd)
}

/// The table whose BRANCHIND is `jop`. Held as an op, not an index: `push_branch` resets the
/// structure, which drops dead tables and moves the others (the C++ keeps a `JumpTable *`).
fn table_of(fd: &Funcdata, jop: OpId) -> Result<usize> {
    fd.jumptables
        .iter()
        .position(|jt| jt.op == jop)
        .ok_or_else(|| LowlevelError("jump table lost while folding a guard".into()))
}

/// Port of `JumpBasic::foldInOneGuard`: the guard's other target becomes the switch's default,
/// as a new out edge of the switch block or, when the switch already goes there, by fixing the
/// CBRANCH's condition. `jop` is the table's BRANCHIND.
fn fold_in_one_guard(fd: &mut Funcdata, jop: OpId, cbranch: OpId, stored: usize) -> Result<bool> {
    let Some(cbl) = fd.op(cbranch).parent else { return Ok(false) };
    let cb = fd.blocks.block(cbl);
    if cb.outs.len() != 2 {
        return Ok(false); // the branch was converted since the recovery
    }
    let indpath = if cb.flip_path { 1 - stored } else { stored };
    let Some(switchbl) = fd.op(jop).parent else { return Ok(false) };
    if cb.outs[indpath].point != switchbl {
        return Ok(false); // the guard must go straight into the switch block
    }
    let guardtarget = cb.outs[1 - indpath].point;
    let outs = &fd.blocks.block(switchbl).outs;
    let nout = outs.len();
    let pos = outs.iter().position(|e| e.point == guardtarget).unwrap_or(nout);
    let jt = &fd.jumptables[table_of(fd, jop)?];
    if jt.default_is_folded && jt.default_block != Some(pos) {
        return Ok(false); // only one folded target
    }
    if !no_intervening_statement(fd, switchbl)? {
        return Ok(false);
    }
    if pos == nout {
        // addBlockToSwitch without a label, setLastAsDefault
        let start = fd.blocks.block(guardtarget).start;
        let i = table_of(fd, jop)?;
        let jt = &mut fd.jumptables[i];
        jt.targets.push(start);
        jt.last_block = nout;
        jt.block2addr.push((nout, jt.targets.len() - 1));
        jt.labels.push(NO_LABEL);
        jt.default_block = Some(nout);
        push_branch(fd, cbl, 1 - indpath, switchbl)?;
    } else {
        let val = u64::from((indpath == 0) == fd.op(cbranch).flags.has(OpFlags::BOOLEAN_FLIP));
        let size = fd.vn(fd.op(cbranch).ins[0]).size;
        let c = fd.new_constant(size, val);
        fd.op_set_input(cbranch, c, 1)?;
        let i = table_of(fd, jop)?;
        fd.jumptables[i].default_block = Some(pos);
    }
    let i = table_of(fd, jop)?;
    fd.jumptables[i].default_is_folded = true;
    Ok(true)
}

/// Port of `JumpBasic::foldInGuards` (with `JumpBasic2::foldInOneGuard`) and
/// `JumpAssisted::foldInGuards` for table `i`.
fn fold_in_guards(fd: &mut Funcdata, i: usize) -> Result<bool> {
    let jop = fd.jumptables[i].op;
    let Some(mut model) = fd.jumptables[i].model.take() else { return Ok(false) };
    if model.assisted {
        // the default case is always the last block (`setLastAsDefault`)
        let jt = &mut fd.jumptables[i];
        let orig = jt.default_block.replace(jt.last_block);
        jt.model = Some(model);
        return Ok(orig != jt.default_block);
    }
    let mut change = false;
    for g in &mut model.guards {
        let Some(cbranch) = g.0 else { continue };
        if fd.op(cbranch).is_dead() {
            g.0 = None;
            continue;
        }
        let folded = if model.basic2 {
            // the last block of the table is the value the guard's other path gives
            let i = table_of(fd, jop)?;
            let jt = &mut fd.jumptables[i];
            jt.default_block = Some(jt.last_block);
            true
        } else {
            fold_in_one_guard(fd, jop, cbranch, g.1)?
        };
        if folded {
            g.0 = None;
            change = true;
        }
    }
    let i = table_of(fd, jop)?;
    fd.jumptables[i].model = Some(model);
    Ok(change)
}

/// Port of `ActionSwitchNorm::apply`: each table gets its case labels once (the model matched
/// on the function, the labels, the BRANCHIND reading the unnormalized switch variable), and
/// its guards are folded into the switch as they become foldable. As in the C++, the count of
/// tables is read again each time round (folding a guard can drop a dead table).
pub(crate) fn switch_norm(fd: &mut Funcdata, arch: &Arch) -> Result<i32> {
    let mut count = 0;
    let mut i = 0;
    while i < fd.jumptables.len() {
        if fd.jumptables[i].labels.is_empty() {
            recover_labels(fd, arch, i)?;
            count += 1;
        }
        if fold_in_guards(fd, i)? {
            fd.structure.clear(); // the structure is redone
            count += 1;
        }
        i += 1;
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Table entries 0..5 go to out edges 2, 0, 2, 1, 2: the map sorts by edge then entry, the
    /// default is the edge most entries take, the last block is the last entry's.
    #[test]
    fn switch_over_sorts_and_picks_the_default() {
        let mut jt = JumpTable::new(OpId(0), vec![0x30, 0x10, 0x30, 0x20, 0x30], None);
        jt.switch_over(&[2, 0, 2, 1, 2]);
        assert_eq!(jt.block2addr, [(0, 1), (1, 3), (2, 0), (2, 2), (2, 4)]);
        assert_eq!((jt.default_block, jt.last_block), (Some(2), 2));
        assert_eq!((bound(&jt.block2addr, 2, false), bound(&jt.block2addr, 2, true)), (2, 5));
        assert_eq!((bound(&jt.block2addr, 3, false), bound(&jt.block2addr, 0, true)), (5, 1));
        // one entry per edge: no default
        jt.switch_over(&[1, 0]);
        assert_eq!((jt.default_block, jt.last_block), (None, 0));
    }

    /// The values of a range with an extra value: the extra one comes last and is not reversible.
    #[test]
    fn value_range_walks_range_then_extra() {
        let v = ValueRange { range: CircleRange::new(3, 6, 4, 1), extra: Some(9), assisted: None };
        assert_eq!(v.values(), [(3, true), (4, true), (5, true), (9, false)]);
        assert_eq!(v.size(), 4);
        assert!(v.contains(9) && v.contains(4) && !v.contains(6));
        let empty = ValueRange::default();
        assert_eq!((empty.size(), empty.values()), (0, vec![]));
        assert!(range_eq(&CircleRange::default(), &CircleRange { left: 5, ..CircleRange::default() }));
    }

    /// A hand-made `<jumpassist>` (no spec ghidra-rs can load declares one; the scripts follow
    /// the shape of JVM.pspec's `switchAssist`) on x86's user op `segment`:
    /// `BRANCHIND(segment(sw, #0x2000, #2))` over the pairs (7, +0x10), (9, +0x20) at 0x2000.
    /// The scripts give the size, the targets with the default last, and the labels. Not
    /// checked against decomp_dbg.
    #[test]
    fn jump_assisted_model_runs_the_scripts() {
        use crate::analysis::{Image, Section};
        use crate::sleigh::Sleigh;
        let params = r#"<input name="index" size="4"/><input name="tbl" size="4"/><input name="n" size="4"/>"#;
        let script = |tag: &str, out: &str, body: &str| {
            format!("<{tag}>{params}<output name=\"{out}\" size=\"4\"/><body><![CDATA[{body}]]></body></{tag}>")
        };
        let spec = format!(
            "<jumpassist name=\"segment\">{}{}{}{}</jumpassist>",
            script("case_pcode", "case", "case = *:4 (tbl + 8*index);"),
            script("addr_pcode", "addr", "_off:4 = tbl + 8*index + 4; addr = tbl + *:4 (_off);"),
            script("default_pcode", "addr", "addr = tbl - 4;"),
            script("size_pcode", "size", "size = n;"),
        );
        let path = Sleigh::sla_path("x86");
        assert!(path.exists(), "{} is missing: run rust/build-sla.sh first", path.display());
        let cspec = std::fs::read_to_string(path.with_file_name("x86win.cspec")).unwrap();
        let table = [7u32, 0x10, 9, 0x20].iter().flat_map(|v| v.to_le_bytes()).collect();
        let section =
            Section { name: ".rdata".into(), exec: false, readonly: true, zero_tail: 0, addr: 0x2000, data: table };
        let img = Image { sections: vec![section], ..Image::default() };
        let mut arch = Arch::new(Sleigh::load(&path).unwrap(), img, &cspec).unwrap();
        let el = crate::xml::parse(&spec).unwrap();
        arch.userops.decode(&el, &arch.sleigh, &super::super::cspec::SleighNames::new(&arch.sleigh)).unwrap();
        // the user op has one meaning only
        let again = arch.userops.decode(&el, &arch.sleigh, &super::super::cspec::SleighNames::new(&arch.sleigh));
        assert!(again.unwrap_err().0.contains("overloads userop"));

        let index = arch.sleigh.userop_index("segment").unwrap();
        let uniq = arch.sleigh.uniq_space();
        let mut fd = Funcdata::new(0x1000);
        let assist = fd.new_op(Opcode::Callother, 0x1000);
        let addr = fd.new_unique_out(4, uniq, assist);
        let sw = fd.new_varnode(4, super::super::varnode::Space::Sleigh(arch.spec.stack_pointer.0), 0);
        let ins = [fd.new_constant(4, index), sw, fd.new_constant(4, 0x2000), fd.new_constant(4, 2)];
        fd.op_set_all_input(assist, &ins).unwrap();
        let indop = fd.new_op(Opcode::Branchind, 0x1000);
        fd.op_set_all_input(indop, &[addr]).unwrap();

        let model = JumpAssisted::recover_model(&fd, &arch, indop, None).unwrap().unwrap();
        assert_eq!((model.size_indices, model.switchvn, model.assist_op), (2, sw, assist));
        assert_eq!(model.build_addresses(&fd, &arch).unwrap(), [0x2010, 0x2020, 0x1ffc]);
        assert_eq!(model.build_labels(&fd, &arch).unwrap(), [7, 9, NO_LABEL]);
        // the model to match has another size: no match
        assert!(JumpAssisted::recover_model(&fd, &arch, indop, Some(5)).unwrap().is_none());
        assert!(JumpAssisted::recover_model(&fd, &arch, indop, Some(3)).unwrap().is_some());
        // walking back from the BRANCHIND, a jumpassist op is not a failure
        fd.dead = vec![assist, indop];
        assert!(early_fail(&fd, &arch, indop).is_none());
    }

    /// Reverse evaluation as `OpBehavior::recoverInput*`: `x + 5 == 7`, `9 - x == 2`,
    /// `x - 9 == 2`; an extension's output outside its image is an evaluation error.
    #[test]
    fn reverse_evaluation() {
        assert_eq!(recover_input_binary(Opcode::IntAdd, 0, 4, 7, 5).unwrap(), 2);
        assert_eq!(recover_input_binary(Opcode::IntSub, 1, 4, 2, 9).unwrap(), 7);
        assert_eq!(recover_input_binary(Opcode::IntSub, 0, 4, 2, 9).unwrap(), 11);
        assert_eq!(recover_input_binary(Opcode::IntAdd, 0, 1, 1, 2).unwrap(), 0xff);
        assert!(recover_input_binary(Opcode::IntMult, 0, 4, 8, 2).is_err());
        assert_eq!(recover_input_unary(Opcode::IntZext, 4, 0x7f, 1).unwrap(), Some(0x7f));
        assert_eq!(recover_input_unary(Opcode::IntZext, 4, 0x100, 1).unwrap(), None);
        assert_eq!(recover_input_unary(Opcode::IntSext, 4, 0xffff_ff80, 1).unwrap(), Some(0x80));
        assert_eq!(recover_input_unary(Opcode::IntSext, 4, 0x80, 1).unwrap(), None);
        assert_eq!(recover_input_unary(Opcode::IntSext, 4, 0x17f, 1).unwrap(), None);
    }
}
