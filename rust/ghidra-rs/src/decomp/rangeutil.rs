//! Port of `CircleRange` (rangeutil.cc): a range of integers on a circle (wrapping modulo the
//! varnode size), with a step, as jump-table recovery uses it to bound a switch variable. The
//! value-set solver of rangeutil.cc (`ValueSetSolver`) is not ported: jump-table recovery does
//! not use it.

use super::opcode::Opcode;
use super::varnode::VarnodeId;
use super::Funcdata;

/// `calc_mask`: the mask of a `size`-byte value.
pub(crate) fn calc_mask(size: u32) -> u64 {
    if size >= 8 {
        u64::MAX
    } else {
        (1u64 << (8 * size)) - 1
    }
}

/// `sign_extend(val, sizein, sizeout)` (address.cc): both sizes are clamped to 8 bytes.
pub(crate) fn sign_extend(val: u64, sizein: u32, sizeout: u32) -> u64 {
    let (sizein, sizeout) = (sizein.clamp(1, 8), sizeout.min(8));
    let sh = 64 - 8 * sizein;
    let v = (((val << sh) as i64) >> sh) as u64;
    v & calc_mask(sizeout)
}

/// `bit_transitions` (address.cc)
pub(crate) fn bit_transitions(mut val: u64, sz: u32) -> u32 {
    let mut res = 0;
    let mut last = val & 1;
    for _ in 1..8 * sz {
        val >>= 1;
        let cur = val & 1;
        if cur != last {
            res += 1;
            last = cur;
        }
        if val == 0 {
            break;
        }
    }
    res
}

/// `CircleRange::arrange`
const ARRANGE: &[u8; 64] = b"gcgbegdagggggggeggggcgbggggggggcdfgggggggegdggggbgggfggggcgbegda";

/// `encodeRangeOverlaps`
fn overlaps(l1: u64, r1: u64, l2: u64, r2: u64) -> u8 {
    let mut v = if l1 <= r1 { 0x20 } else { 0 };
    v |= if l1 <= l2 { 0x10 } else { 0 };
    v |= if l1 <= r2 { 8 } else { 0 };
    v |= if r1 <= l2 { 4 } else { 0 };
    v |= if r1 <= r2 { 2 } else { 0 };
    v |= if l2 <= r2 { 1 } else { 0 };
    ARRANGE[v]
}

/// Port of `CircleRange`: the open range `[left, right)` stepping by `step`, modulo `mask + 1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CircleRange {
    pub(crate) left: u64,
    pub(crate) right: u64,
    pub(crate) mask: u64,
    pub(crate) isempty: bool,
    pub(crate) step: u32,
}

impl Default for CircleRange {
    /// The empty range
    fn default() -> CircleRange {
        CircleRange { left: 0, right: 0, mask: 0, isempty: true, step: 1 }
    }
}

impl CircleRange {
    /// `CircleRange(lft, rgt, size, stp)`
    pub(crate) fn new(lft: u64, rgt: u64, size: u32, step: u32) -> CircleRange {
        let mask = calc_mask(size);
        CircleRange { left: lft & mask, right: rgt & mask, mask, isempty: false, step }
    }
    /// `CircleRange(bool)`
    pub(crate) fn boolean(val: bool) -> CircleRange {
        CircleRange { left: val as u64, right: val as u64 + 1, mask: 0xff, isempty: false, step: 1 }
    }
    /// `CircleRange(val, size)`: one value
    pub(crate) fn single(val: u64, size: u32) -> CircleRange {
        let mask = calc_mask(size);
        CircleRange { left: val, right: (val + 1) & mask, mask, isempty: false, step: 1 }
    }
    /// `setFull`
    pub(crate) fn full(size: u32) -> CircleRange {
        CircleRange { left: 0, right: 0, mask: calc_mask(size), isempty: false, step: 1 }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.isempty
    }
    pub(crate) fn is_single(&self) -> bool {
        !self.isempty && self.right == (self.left.wrapping_add(u64::from(self.step)) & self.mask)
    }
    /// `complement`
    fn complement(&mut self) {
        if self.isempty {
            self.left = 0;
            self.right = 0;
            self.isempty = false;
            return;
        }
        if self.left == self.right {
            self.isempty = true;
            return;
        }
        std::mem::swap(&mut self.left, &mut self.right);
    }

    /// `convertToBoolean`: true when both 0 and 1 are in the range.
    fn convert_to_boolean(&mut self) -> bool {
        if self.isempty {
            return false;
        }
        let (z, o) = (self.contains(0), self.contains(1));
        self.mask = 0xff;
        self.step = 1;
        match (z, o) {
            (true, true) => {
                self.left = 0;
                self.right = 2;
                self.isempty = false;
                return true;
            }
            (true, false) => (self.left, self.right, self.isempty) = (0, 1, false),
            (false, true) => (self.left, self.right, self.isempty) = (1, 2, false),
            _ => self.isempty = true,
        }
        false
    }

    /// `newStride`: true when the result is empty
    fn new_stride(mask: u64, step: u32, old_step: u32, rem: u32, l: &mut u64, r: &mut u64) -> bool {
        let step64 = u64::from(step);
        if old_step != 1 && (*l % u64::from(old_step)) as u32 != rem % old_step {
            return true;
        }
        let orig = *l < *r;
        let lrem = (*l % step64) as u32;
        let rrem = (*r % step64) as u32;
        *l = l.wrapping_add(if lrem > rem { u64::from(rem + step - lrem) } else { u64::from(rem - lrem) });
        *r = r.wrapping_add(if rrem > rem { u64::from(rem + step - rrem) } else { u64::from(rem - rrem) });
        *l &= mask;
        *r &= mask;
        orig != (*l < *r)
    }

    /// `newDomain`: true when the result is empty
    fn new_domain(new_mask: u64, new_step: u32, l: &mut u64, r: &mut u64) -> bool {
        let rem = if new_step != 1 { *l % u64::from(new_step) } else { 0 };
        if *l > new_mask {
            if *r > new_mask {
                if *l < *r {
                    return true;
                }
                *l = rem;
                *r = rem;
                return false;
            }
            *l = rem;
        }
        if *r > new_mask {
            *r = rem;
        }
        if *l == *r {
            *l = rem;
            *r = rem;
        }
        false
    }

    /// `getSize`
    pub(crate) fn get_size(&self) -> u64 {
        if self.isempty {
            return 0;
        }
        let step = u64::from(self.step);
        if self.left < self.right {
            return (self.right - self.left) / step;
        }
        let mut val = self.mask.wrapping_sub(self.left - self.right).wrapping_add(step) / step;
        if val == 0 {
            val = self.mask;
            if step > 1 {
                val = val / step + 1;
            }
        }
        val
    }

    /// `getNext`
    pub(crate) fn get_next(&self, val: &mut u64) -> bool {
        *val = val.wrapping_add(u64::from(self.step)) & self.mask;
        *val != self.right
    }

    /// `contains(uintb)`
    pub(crate) fn contains(&self, val: u64) -> bool {
        if self.isempty {
            return false;
        }
        if self.step != 1 && self.left % u64::from(self.step) != val % u64::from(self.step) {
            return false;
        }
        if self.left < self.right {
            return val >= self.left && val < self.right;
        }
        if self.right < self.left {
            return val < self.right || val >= self.left;
        }
        true
    }

    /// `circleUnion`: 0 on success, 2 when the union is two pieces
    pub(crate) fn circle_union(&mut self, o: &CircleRange) -> i32 {
        if o.isempty {
            return 0;
        }
        if self.isempty {
            *self = *o;
            return 0;
        }
        if self.mask != o.mask {
            return 2;
        }
        let (mut ar, mut br) = (self.right, o.right);
        let mut ns = self.step;
        if self.step < o.step {
            if !self.is_single() {
                return 2;
            }
            ns = o.step;
            ar = self.left.wrapping_add(u64::from(ns)) & self.mask;
        } else if o.step < self.step {
            if !o.is_single() {
                return 2;
            }
            br = o.left.wrapping_add(u64::from(ns)) & self.mask;
        }
        let rem = if ns != 1 {
            let r = self.left % u64::from(ns);
            if r != o.left % u64::from(ns) {
                return 2;
            }
            r
        } else {
            0
        };
        if self.left == ar || o.left == br {
            (self.left, self.right, self.step) = (rem, rem, ns);
            return 0;
        }
        match overlaps(self.left, ar, o.left, br) {
            b'a' | b'f' => {
                if ar == o.left {
                    (self.right, self.step) = (br, ns);
                    return 0;
                }
                if self.left == br {
                    (self.left, self.right, self.step) = (o.left, ar, ns);
                    return 0;
                }
                2
            }
            b'b' => {
                (self.right, self.step) = (br, ns);
                0
            }
            b'c' => {
                (self.right, self.step) = (ar, ns);
                0
            }
            b'd' => {
                (self.left, self.right, self.step) = (o.left, br, ns);
                0
            }
            b'e' => {
                (self.left, self.right, self.step) = (o.left, ar, ns);
                0
            }
            _ => {
                (self.left, self.right, self.step) = (rem, rem, ns);
                0
            }
        }
    }

    /// Port of `CircleRange::translate2Op`: the range as one comparison with a constant: the
    /// opcode, the constant and its slot, with result 0; else 1 (everything), 2 (cannot be
    /// one comparison) or 3 (empty).
    pub(crate) fn translate_2_op(&self) -> (i32, Opcode, u64, usize) {
        let (left, right, mask) = (self.left, self.right, self.mask);
        let none = |res: i32| (res, Opcode::Copy, 0, 0);
        let half = (mask >> 1) + 1;
        if self.isempty {
            none(3)
        } else if self.step != 1 {
            none(2)
        } else if right == (left.wrapping_add(1) & mask) {
            (0, Opcode::IntEqual, left, 0)
        } else if left == (right.wrapping_add(1) & mask) {
            (0, Opcode::IntNotequal, right, 0)
        } else if left == right {
            none(1)
        } else if left == 0 {
            (0, Opcode::IntLess, right, 1)
        } else if right == 0 {
            (0, Opcode::IntLess, left.wrapping_sub(1) & mask, 0)
        } else if left == half {
            (0, Opcode::IntSless, right, 1)
        } else if right == half {
            (0, Opcode::IntSless, left.wrapping_sub(1) & mask, 0)
        } else {
            none(2)
        }
    }

    /// `intersect`: 0 on success, 2 when the result would be two pieces (`self` unchanged)
    pub(crate) fn intersect(&mut self, o: &CircleRange) -> i32 {
        if self.isempty {
            return 0;
        }
        if o.isempty {
            self.isempty = true;
            return 0;
        }
        let (mut ml, mut mr, mut ol, mut or) = (self.left, self.right, o.left, o.right);
        let new_step;
        if self.step < o.step {
            new_step = o.step;
            let rem = (ol % u64::from(new_step)) as u32;
            if Self::new_stride(self.mask, new_step, self.step, rem, &mut ml, &mut mr) {
                self.isempty = true;
                return 0;
            }
        } else if o.step < self.step {
            new_step = self.step;
            let rem = (ml % u64::from(new_step)) as u32;
            if Self::new_stride(o.mask, new_step, o.step, rem, &mut ol, &mut or) {
                self.isempty = true;
                return 0;
            }
        } else {
            new_step = self.step;
        }
        let new_mask = self.mask & o.mask;
        if self.mask != new_mask {
            if Self::new_domain(new_mask, new_step, &mut ml, &mut mr) {
                self.isempty = true;
                return 0;
            }
        } else if o.mask != new_mask && Self::new_domain(new_mask, new_step, &mut ol, &mut or) {
            self.isempty = true;
            return 0;
        }
        let set = |s: &mut CircleRange, l: u64, r: u64, maybe_empty: bool| {
            s.left = l;
            s.right = r;
            if maybe_empty && l == r {
                s.isempty = true;
            }
            0
        };
        let retval = if ml == mr {
            set(self, ol, or, false)
        } else if ol == or {
            set(self, ml, mr, false)
        } else {
            match overlaps(ml, mr, ol, or) {
                b'a' | b'f' => {
                    self.isempty = true;
                    0
                }
                b'b' => set(self, ol, mr, true),
                b'c' => set(self, ol, or, false),
                b'd' => set(self, ml, mr, false),
                b'e' => set(self, ml, or, true),
                b'g' if ml == or => set(self, ol, mr, true),
                b'g' if ol == mr => set(self, ml, or, true),
                _ => 2,
            }
        };
        if retval != 0 {
            return retval;
        }
        self.mask = new_mask;
        self.step = new_step;
        0
    }

    /// `setNZMask`: the range of values a non-zero mask allows, if it is one range.
    pub(crate) fn set_nz_mask(&mut self, nzmask: u64, size: u32) -> bool {
        let trans = bit_transitions(nzmask, size);
        if trans > 2 {
            return false;
        }
        let hasstep = nzmask & 1 == 0;
        if !hasstep && trans == 2 {
            return false;
        }
        self.isempty = false;
        self.mask = calc_mask(size);
        self.step = 1;
        self.left = 0;
        if trans == 0 {
            self.right = if hasstep { 1 } else { 0 };
            return true;
        }
        self.step = 1 << nzmask.trailing_zeros();
        self.right = nzmask.wrapping_add(u64::from(self.step)) & self.mask;
        true
    }

    /// `pullBackUnary`
    pub(crate) fn pull_back_unary(&mut self, opc: Opcode, in_size: u32, out_size: u32) -> bool {
        if self.isempty {
            return true;
        }
        let step = u64::from(self.step);
        match opc {
            Opcode::BoolNegate => {
                if !self.convert_to_boolean() {
                    self.left ^= 1;
                    self.right = self.left + 1;
                }
            }
            Opcode::Copy => {}
            Opcode::Int2comp => {
                let val = (!self.left).wrapping_add(1).wrapping_add(step) & self.mask;
                self.left = (!self.right).wrapping_add(1).wrapping_add(step) & self.mask;
                self.right = val;
            }
            Opcode::IntNegate => {
                let val = (!self.left).wrapping_add(step) & self.mask;
                self.left = (!self.right).wrapping_add(step) & self.mask;
                self.right = val;
            }
            Opcode::IntZext => {
                let val = calc_mask(in_size);
                let rem = self.left % step;
                let z = CircleRange {
                    left: rem,
                    right: val.wrapping_add(1).wrapping_add(rem),
                    mask: self.mask,
                    step: self.step,
                    isempty: false,
                };
                if self.intersect(&z) != 0 {
                    return false;
                }
                self.left &= val;
                self.right &= val;
                self.mask &= val;
            }
            Opcode::IntSext => {
                let val = calc_mask(in_size);
                let rem = self.left & step; // sic: `left & step` in the C++
                let l = (val ^ (val >> 1)).wrapping_add(rem);
                let mut s = CircleRange {
                    left: l,
                    right: sign_extend(l, in_size, out_size),
                    mask: self.mask,
                    step: self.step,
                    isempty: false,
                };
                if s.intersect(self) != 0 || !s.is_empty() {
                    return false;
                }
                self.left &= val;
                self.right &= val;
                self.mask &= val;
            }
            _ => return false,
        }
        true
    }

    /// The comparison part of `pullBackBinary`, after `convertToBoolean`.
    fn compare(&mut self, mask: u64, f: impl FnOnce(&mut CircleRange)) {
        let both = self.convert_to_boolean();
        self.mask = mask;
        if both {
            return;
        }
        let yescomplement = self.left == 0;
        f(self);
        if yescomplement {
            self.complement();
        }
    }

    /// `pullBackBinary`
    pub(crate) fn pull_back_binary(&mut self, opc: Opcode, val: u64, slot: usize, in_size: u32) -> bool {
        if self.isempty {
            return true;
        }
        let m = calc_mask(in_size);
        let half = (m >> 1) + 1; // -infinity
        match opc {
            Opcode::IntEqual => self.compare(m, |s| (s.left, s.right) = (val, val.wrapping_add(1) & m)),
            Opcode::IntNotequal => self.compare(m, |s| (s.left, s.right) = (val.wrapping_add(1) & m, val)),
            Opcode::IntLess => self.compare(m, |s| {
                if slot == 0 {
                    if val == 0 {
                        s.isempty = true;
                    } else {
                        (s.left, s.right) = (0, val);
                    }
                } else if val == m {
                    s.isempty = true;
                } else {
                    (s.left, s.right) = (val.wrapping_add(1) & m, 0);
                }
            }),
            Opcode::IntLessequal => self.compare(m, |s| {
                if slot == 0 {
                    (s.left, s.right) = (0, val.wrapping_add(1) & m);
                } else {
                    (s.left, s.right) = (val, 0);
                }
            }),
            Opcode::IntSless => self.compare(m, |s| {
                if slot == 0 {
                    if val == half {
                        s.isempty = true;
                    } else {
                        (s.left, s.right) = (half, val);
                    }
                } else if val == m >> 1 {
                    s.isempty = true;
                } else {
                    (s.left, s.right) = (val.wrapping_add(1) & m, half);
                }
            }),
            Opcode::IntSlessequal => self.compare(m, |s| {
                if slot == 0 {
                    (s.left, s.right) = (half, val.wrapping_add(1) & m);
                } else {
                    (s.left, s.right) = (val, half);
                }
            }),
            Opcode::IntCarry => self.compare(m, |s| {
                if val == 0 {
                    s.isempty = true;
                } else {
                    (s.left, s.right) = ((m - val).wrapping_add(1) & m, 0);
                }
            }),
            Opcode::IntAdd => {
                self.left = self.left.wrapping_sub(val) & self.mask;
                self.right = self.right.wrapping_sub(val) & self.mask;
            }
            Opcode::IntSub => {
                if slot == 0 {
                    self.left = self.left.wrapping_add(val) & self.mask;
                    self.right = self.right.wrapping_add(val) & self.mask;
                } else {
                    self.left = val.wrapping_sub(self.left) & self.mask;
                    self.right = val.wrapping_sub(self.right) & self.mask;
                }
            }
            Opcode::IntRight => {
                if self.step != 1 {
                    return false;
                }
                let rb = (m >> val).wrapping_add(1);
                let (l, r) = (self.left, self.right);
                if (l >= rb && r >= rb && l >= r) || (l == 0 && r >= rb) || l == r {
                    self.left = 0;
                    self.right = 0;
                } else {
                    if self.left > rb {
                        self.left = rb;
                    }
                    if self.right > rb {
                        self.right = 0;
                    }
                    self.left = (self.left << val) & self.mask;
                    self.right = (self.right << val) & self.mask;
                    if self.left == self.right {
                        self.isempty = true;
                    }
                }
            }
            Opcode::IntSright => {
                if self.step != 1 {
                    return false;
                }
                let mut rightb = m;
                let mut leftb = rightb >> (val + 1);
                rightb ^= leftb;
                leftb += 1;
                let (l, r) = (self.left, self.right);
                if (l >= leftb && l <= rightb && r >= leftb && r <= rightb && l >= r) || l == r {
                    self.left = 0;
                    self.right = 0;
                } else {
                    if self.left > leftb && self.left < rightb {
                        self.left = leftb;
                    }
                    if self.right > leftb && self.right < rightb {
                        self.right = rightb;
                    }
                    self.left = (self.left << val) & self.mask;
                    self.right = (self.right << val) & self.mask;
                    if self.left == self.right {
                        self.isempty = true;
                    }
                }
            }
            _ => return false,
        }
        true
    }
}

pub(crate) fn pcode_left(v: u64, sa: u64) -> u64 {
    if sa >= 64 {
        0
    } else {
        v << sa
    }
}

pub(crate) fn pcode_right(v: u64, sa: u64) -> u64 {
    if sa >= 64 {
        0
    } else {
        v >> sa
    }
}

/// `mostsigbit_set`: the index of the highest set bit, -1 for 0.
pub(crate) fn mostsigbit_set(v: u64) -> i32 {
    63 - v.leading_zeros() as i32
}

/// Port of `CircleRange::pullBack` from `vn` through the op defining it: the input varnode and
/// its range of values for which `vn` lies in `rng`. `konst` gives a varnode's constant value
/// and `nz` its non-zero mask (jump-table recovery passes what it folds in the partial function).
pub(crate) fn pull_back(
    fd: &Funcdata,
    vn: VarnodeId,
    mut rng: CircleRange,
    usenzmask: bool,
    konst: impl Fn(VarnodeId) -> Option<u64>,
    nz: impl Fn(VarnodeId) -> u64,
) -> Option<(VarnodeId, CircleRange)> {
    let op = fd.op(fd.vn(vn).def?);
    let outsize = fd.vn(vn).size;
    let res;
    if op.ins.len() == 1 {
        res = op.ins[0];
        if konst(res).is_some() || !rng.pull_back_unary(op.opc, fd.vn(res).size, outsize) {
            return None;
        }
    } else if op.ins.len() == 2 {
        let (mut slot, mut r, mut c) = (0, op.ins[0], op.ins[1]);
        if konst(r).is_some() {
            slot = 1;
            c = r;
            r = op.ins[1];
            if konst(r).is_some() {
                return None;
            }
        }
        res = r;
        let val = konst(c)?;
        if !rng.pull_back_binary(op.opc, val, slot, fd.vn(res).size) {
            if !(usenzmask && op.opc == Opcode::Subpiece && val == 0) {
                return None;
            }
            // everything truncated is known to be zero: keep the range on the bigger mask
            if (outsize as i32) < (mostsigbit_set(nz(res)) + 8) / 8 {
                return None;
            }
            rng.mask = calc_mask(fd.vn(res).size);
        }
    } else {
        return None;
    }
    if usenzmask {
        let mut nzr = CircleRange::default();
        if nzr.set_nz_mask(nz(res), fd.vn(res).size) {
            rng.intersect(&nzr);
        }
    }
    Some((res, rng))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn translate_2_op_table() {
        use Opcode::*;
        let r = |l: u64, rt: u64| CircleRange::new(l, rt, 1, 1);
        // range [left, right) on one byte: result, opcode, constant, slot of the constant
        for (rng, want) in [
            (r(5, 6), (0, IntEqual, 5, 0)),
            (r(6, 5), (0, IntNotequal, 5, 0)),
            (r(0, 10), (0, IntLess, 10, 1)),
            (r(10, 0), (0, IntLess, 9, 0)),
            (r(0x80, 3), (0, IntSless, 3, 1)),
            (r(3, 0x80), (0, IntSless, 2, 0)),
            (r(3, 9), (2, Copy, 0, 0)),
            (CircleRange::default(), (3, Copy, 0, 0)),
            (CircleRange::full(1), (1, Copy, 0, 0)),
        ] {
            assert_eq!(rng.translate_2_op(), want, "{rng:?}");
        }
        assert_eq!(CircleRange::new(0, 8, 1, 2).translate_2_op().0, 2, "a stride has no single comparison");
    }

    #[test]
    fn bit_helpers_table() {
        assert_eq!(
            (mostsigbit_set(0), mostsigbit_set(1), mostsigbit_set(0x90), mostsigbit_set(u64::MAX)),
            (-1, 0, 7, 63)
        );
        assert_eq!(
            (pcode_left(1, 63), pcode_left(1, 64), pcode_right(0x80, 7), pcode_right(0x80, 64)),
            (1 << 63, 0, 1, 0)
        );
    }

    #[test]
    fn guard_ranges() {
        // x > 0x1f is false on the switch path (`x <= 0x1f` is true): x in [0, 0x20)
        let mut r = CircleRange::boolean(false);
        assert!(r.pull_back_binary(Opcode::IntLessequal, 0x1f, 0, 4));
        assert_eq!((r.left, r.right, r.get_size()), (0x20, 0, 0xffff_ffe0));
        let mut r = CircleRange::boolean(true);
        assert!(r.pull_back_binary(Opcode::IntLessequal, 0x1f, 0, 4));
        assert_eq!((r.left, r.right, r.get_size()), (0, 0x20, 0x20));
        // x - 2 in [0, 0x20): x in [2, 0x22)
        assert!(r.pull_back_binary(Opcode::IntAdd, 0xffff_fffe, 0, 4));
        assert_eq!((r.left, r.right), (2, 0x22));
        let mut full = CircleRange::full(4);
        assert_eq!(full.intersect(&r), 0);
        assert_eq!(full.get_size(), 0x20);
        // x < 5 united with x == 5
        let mut a = CircleRange::new(0, 5, 4, 1);
        assert_eq!(a.circle_union(&CircleRange::single(5, 4)), 0);
        assert_eq!((a.left, a.right), (0, 6));
    }
}
