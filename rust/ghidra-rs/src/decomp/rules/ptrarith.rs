//! The pointer rules of group `typerecovery` (stage R5): `RulePtrArith` with `AddTreeState`,
//! `RuleStructOffset0`, `RulePushPtr` (pool `oppool2`), `RulePtraddUndo`, `RulePtrsubUndo`
//! (pool `oppool1`), ruleaction.cc, with the type queries they make (`isPtrsubMatching`,
//! `isOffsetValid`, `nearestArrayedComponent`, type.cc) and `Funcdata::opUndoPtradd`,
//! `collapseIntMultMult`, `newOpBefore`.
//!
//! Not ported, failing loudly: `TypePointerRel` (the type store never makes one, so
//! `isFormalPointerRel` is false and `initAlternateForm` has nothing to try), sub-types of
//! structs and the arrays inside them (`TypeStruct::getSubType`, `nearestArrayedComponent`),
//! unions (`needsResolution`), and the propagated types `RulePtrArith` assigns once type
//! recovery has given up (`isTypeRecoveryExceeded`).

use super::*;
use crate::decomp::infertypes::{sub_type, vn_type};
use crate::decomp::types::{Kind, Meta, TypeId};

/// `RulePtrsubUndo::MAX_TERMS`.
const MAX_TERMS: i32 = 64;
/// ponytail: recursion bound for walks the C++ leaves unbounded (add trees, local adds); a
/// deeper expression fails loudly instead of overflowing the stack.
const MAX_DEPTH: u32 = 1000;

/// `Varnode::getTypeReadFacing` (also `getTypeDefFacing`): the type, unless it needs a union
/// resolved, which is not ported.
fn facing(fd: &mut Funcdata, vn: VarnodeId) -> Result<TypeId> {
    let t = vn_type(fd, vn);
    no_union(fd, t)?;
    Ok(t)
}

/// Fails on `Datatype::needsResolution` (a union, or a pointer to one): `unionresolve` is not
/// ported.
fn no_union(fd: &Funcdata, t: TypeId) -> Result<()> {
    let to = fd.types.ptr_to(t).unwrap_or(t);
    if fd.types.meta(t) == Meta::Union || fd.types.meta(to) == Meta::Union {
        return err("pointer rules on a union (needsResolution): not implemented in ghidra-rs yet");
    }
    Ok(())
}

fn is_ptr(fd: &mut Funcdata, vn: VarnodeId) -> Result<bool> {
    let t = facing(fd, vn)?;
    Ok(fd.types.meta(t) == Meta::Ptr)
}

/// The C++ `sign_extend(v, size * 8 - 1)` as a signed value.
fn sext(v: u64, size: u32) -> i64 {
    sign_extend(v, size, 8) as i64
}

/// Port of `Funcdata::newOpBefore`: its output.
fn new_op_before(fd: &mut Funcdata, follow: OpId, opc: Opcode, ins: &[VarnodeId]) -> Result<VarnodeId> {
    let size = sz(fd, ins[0]);
    insert_new(fd, opc, op_addr(fd, follow), size, ins, follow)
}

fn def_op(fd: &Funcdata, vn: VarnodeId) -> Result<OpId> {
    def(fd, vn).ok_or_else(|| LowlevelError("pointer rule: varnode has no defining op".into()))
}

/// Port of `Datatype::nearestArrayedComponent` for the kinds that can reach it: a space-base
/// type's scopes hold only functions (`code`) and external references (pointers to `code`), so
/// no symbol has an arrayed component; a struct is not ported.
fn nearest_arrayed_component(fd: &Funcdata, t: TypeId) -> Result<bool> {
    match fd.types.meta(t) {
        Meta::Struct | Meta::Union => err("nearestArrayedComponent of a struct: not implemented in ghidra-rs yet"),
        _ => Ok(false),
    }
}

/// Port of `Datatype::testForArraySlack`.
fn test_for_array_slack(fd: &Funcdata, t: TypeId) -> Result<bool> {
    if fd.types.meta(t) == Meta::Array {
        return Ok(true);
    }
    nearest_arrayed_component(fd, t)
}

/// Port of `isOffsetValid` (`Datatype`, `TypeArray`, `TypeCode`, `TypeSpacebase`).
fn is_offset_valid(fd: &mut Funcdata, arch: &Arch, t: TypeId, off: i64, extra: i64, mult: i64) -> Result<bool> {
    match fd.types.meta(t) {
        Meta::Array => Ok(off == 0 && mult < i64::from(fd.types.align_size(t))),
        Meta::Code => Ok(extra >= 0),
        Meta::Struct => err("TypeStruct::isOffsetValid: not implemented in ghidra-rs yet"),
        Meta::Spacebase => {
            let Some((sub, newoff)) = sub_type(fd, arch, t, off)? else { return Ok(false) };
            if newoff != 0 {
                return Ok(false);
            }
            if fd.types.meta(sub) == Meta::Code {
                return Ok(extra >= 0);
            }
            if extra < 0 || extra >= i64::from(fd.types.size(sub)) {
                return test_for_array_slack(fd, sub);
            }
            Ok(true)
        }
        _ => Ok(false),
    }
}

/// Port of `Datatype::isPtrsubMatching` (`TypePointer`'s; the default is false).
fn is_ptrsub_matching(fd: &mut Funcdata, arch: &Arch, t: TypeId, off: i64, extra: i64, mult: i64) -> Result<bool> {
    match fd.types.ptr_to(t) {
        Some(to) => is_offset_valid(fd, arch, to, off, extra, mult),
        None => Ok(false),
    }
}

/// Port of `AddTreeState`: an INT_ADD tree on a pointer, split into multiples of the pointed-to
/// size (a PTRADD), an offset into it (a PTRSUB) and the rest.
struct AddTree {
    base_op: OpId,
    ptr: VarnodeId,
    ct: TypeId,
    base_type: TypeId,
    ptrsize: u32,
    ptrmask: u64,
    /// the pointed-to size (`int4`)
    size: i64,
    multiple: Vec<VarnodeId>,
    coeff: Vec<i64>,
    nonmult: Vec<VarnodeId>,
    distribute_op: Option<OpId>,
    multsum: u64,
    nonmultsum: u64,
    correct: u64,
    offset: u64,
    biggest_non_mult_coeff: u32,
    valid: bool,
    is_degenerate: bool,
    is_distribute_used: bool,
    is_subtype: bool,
    prevent_distribution: bool,
}

impl AddTree {
    /// The constructor `AddTreeState(Funcdata &, PcodeOp *, int4)` (no `TypePointerRel`).
    fn new(fd: &mut Funcdata, op: OpId, slot: usize) -> Result<AddTree> {
        let ptr = inp(fd, op, slot)?;
        let ct = facing(fd, ptr)?;
        let base_type = fd.types.ptr_to(ct).ok_or_else(|| LowlevelError("AddTreeState: not a pointer".into()))?;
        let align = i64::from(fd.types.align_size(base_type));
        let ptrsize = sz(fd, ptr);
        Ok(AddTree {
            base_op: op,
            ptr,
            ct,
            base_type,
            ptrsize,
            ptrmask: calc_mask(ptrsize),
            size: align,
            multiple: Vec::new(),
            coeff: Vec::new(),
            nonmult: Vec::new(),
            distribute_op: None,
            multsum: 0,
            nonmultsum: 0,
            correct: 0,
            offset: 0,
            biggest_non_mult_coeff: 0,
            valid: true,
            // the word size is 1 on x86
            is_degenerate: align <= 1 && align > 0,
            is_distribute_used: false,
            is_subtype: false,
            prevent_distribution: false,
        })
    }

    /// Port of `AddTreeState::clear`.
    fn clear(&mut self) {
        self.multsum = 0;
        self.nonmultsum = 0;
        self.biggest_non_mult_coeff = 0;
        self.multiple.clear();
        self.coeff.clear();
        self.nonmult.clear();
        self.correct = 0;
        self.offset = 0;
        self.valid = true;
        self.is_distribute_used = false;
        self.is_subtype = false;
        self.distribute_op = None;
    }

    /// `sval % size`, or `sval` for an open size.
    fn rem(&self, sval: i64) -> i64 {
        if self.size == 0 {
            sval
        } else {
            sval.wrapping_rem(self.size)
        }
    }

    fn note_coeff(&mut self, c: u64) {
        if c > u64::from(self.biggest_non_mult_coeff) {
            self.biggest_non_mult_coeff = c as u32;
        }
    }

    /// Port of `AddTreeState::checkMultTerm`.
    fn check_mult_term(&mut self, fd: &Funcdata, vn: VarnodeId, op: OpId, tree_coeff: u64, depth: u32) -> Result<bool> {
        let vnconst = inp(fd, op, 1)?;
        let vnterm = inp(fd, op, 0)?;
        if is_free(fd, vnterm) {
            self.valid = false;
            return Ok(false);
        }
        if is_const(fd, vnconst) {
            let val = off(fd, vnconst).wrapping_mul(tree_coeff) & self.ptrmask;
            let sval = sext(val, sz(fd, vn));
            if self.rem(sval) != 0 {
                if self.size != 0 && val >= self.size as u64 {
                    self.valid = false;
                    return Ok(false);
                }
                if !self.prevent_distribution {
                    if let Some(d) = def_with(fd, vnterm, IntAdd) {
                        if self.distribute_op.is_none() {
                            self.distribute_op = Some(op);
                        }
                        return self.span_add_tree(fd, d, val, depth + 1);
                    }
                }
                let vncoeff = sval.unsigned_abs() as u32;
                if vncoeff > self.biggest_non_mult_coeff {
                    self.biggest_non_mult_coeff = vncoeff;
                }
                return Ok(true);
            }
            if tree_coeff != 1 {
                self.is_distribute_used = true;
            }
            self.multiple.push(vnterm);
            self.coeff.push(sval);
            return Ok(false);
        }
        self.note_coeff(tree_coeff);
        Ok(true)
    }

    /// Port of `AddTreeState::checkTerm`.
    fn check_term(&mut self, fd: &Funcdata, vn: VarnodeId, tree_coeff: u64, depth: u32) -> Result<bool> {
        if vn == self.ptr {
            return Ok(false);
        }
        if is_const(fd, vn) {
            let val = off(fd, vn).wrapping_mul(tree_coeff);
            let sval = sext(val, sz(fd, vn));
            if self.rem(sval) != 0 {
                if tree_coeff != 1 && matches!(fd.types.meta(self.base_type), Meta::Array | Meta::Struct) {
                    self.is_distribute_used = true;
                }
                self.nonmultsum = self.nonmultsum.wrapping_add(val) & self.ptrmask;
                return Ok(true);
            }
            if tree_coeff != 1 {
                self.is_distribute_used = true;
            }
            self.multsum = self.multsum.wrapping_add(val) & self.ptrmask;
            return Ok(false);
        }
        if let Some(d) = def(fd, vn) {
            match code(fd, d) {
                IntAdd => return self.span_add_tree(fd, d, tree_coeff, depth + 1),
                Copy => {
                    self.valid = false;
                    return Ok(false);
                }
                IntMult => return self.check_mult_term(fd, vn, d, tree_coeff, depth),
                _ => {}
            }
        } else if is_free(fd, vn) {
            self.valid = false;
            return Ok(false);
        }
        self.note_coeff(tree_coeff);
        Ok(true)
    }

    /// Port of `AddTreeState::spanAddTree`.
    fn span_add_tree(&mut self, fd: &Funcdata, op: OpId, tree_coeff: u64, depth: u32) -> Result<bool> {
        if depth > MAX_DEPTH {
            return err("RulePtrArith: add tree too deep");
        }
        let (in0, in1) = (inp(fd, op, 0)?, inp(fd, op, 1)?);
        let one_is_non = self.check_term(fd, in0, tree_coeff, depth)?;
        if !self.valid {
            return Ok(false);
        }
        let two_is_non = self.check_term(fd, in1, tree_coeff, depth)?;
        if !self.valid {
            return Ok(false);
        }
        if one_is_non && two_is_non {
            return Ok(true);
        }
        if one_is_non {
            self.nonmult.push(in0);
        }
        if two_is_non {
            self.nonmult.push(in1);
        }
        Ok(false)
    }

    fn span_root(&mut self, fd: &Funcdata) -> Result<()> {
        self.span_add_tree(fd, self.base_op, 1, 0).map(|_| ())
    }

    /// Port of `AddTreeState::calcSubtype`.
    fn calc_subtype(&mut self, fd: &mut Funcdata, arch: &Arch) -> Result<()> {
        let tmpoff = self.multsum.wrapping_add(self.nonmultsum) & self.ptrmask;
        if self.size == 0 || tmpoff < self.size as u64 {
            self.offset = tmpoff;
        } else {
            let stmpoff = sext(tmpoff, self.ptrsize).wrapping_rem(self.size);
            self.offset = if stmpoff >= 0 {
                stmpoff as u64
            } else if fd.types.meta(self.base_type) == Meta::Struct
                && self.biggest_non_mult_coeff != 0
                && self.multsum == 0
            {
                tmpoff
            } else {
                stmpoff.wrapping_add(self.size) as u64
            };
        }
        self.correct = self.nonmultsum;
        self.multsum = tmpoff.wrapping_sub(self.offset) & self.ptrmask;
        if self.nonmult.is_empty() {
            if self.multsum == 0 && self.multiple.is_empty() {
                self.valid = false;
                return Ok(());
            }
            self.is_subtype = false;
            return Ok(());
        }
        match fd.types.meta(self.base_type) {
            Meta::Spacebase => {
                let offsetbytes = self.offset as i64;
                let mut found = None;
                if self.biggest_non_mult_coeff != 0 && nearest_arrayed_component(fd, self.base_type)? {
                    return err("nearestArrayedComponent hit: not implemented in ghidra-rs yet");
                }
                if let Some((_, extra)) = sub_type(fd, arch, self.base_type, offsetbytes)? {
                    found = Some(extra);
                }
                if found.is_none() && self.biggest_non_mult_coeff == 0 && nearest_arrayed_component(fd, self.base_type)?
                {
                    return err("nearestArrayedComponent hit: not implemented in ghidra-rs yet");
                }
                let Some(extra) = found else {
                    self.valid = false;
                    return Ok(());
                };
                self.offset = self.offset.wrapping_sub(extra as u64) & self.ptrmask;
                self.correct = self.correct.wrapping_sub(extra as u64) & self.ptrmask;
                self.is_subtype = true;
            }
            Meta::Struct => return err("RulePtrArith into a struct (calcSubtype): not implemented in ghidra-rs yet"),
            Meta::Array => {
                self.is_subtype = true;
                self.correct = self.correct.wrapping_sub(self.offset) & self.ptrmask;
                self.offset = 0;
            }
            _ => self.valid = false,
        }
        Ok(())
    }

    /// Port of `AddTreeState::buildMultiples`.
    fn build_multiples(&mut self, fd: &mut Funcdata) -> Result<Option<VarnodeId>> {
        let smultsum = sext(self.multsum, self.ptrsize);
        let div = |v: i64| if self.size == 0 { 0 } else { v.wrapping_div(self.size) as u64 & self.ptrmask };
        let const_coeff = div(smultsum);
        let mut res = (const_coeff != 0).then(|| fd.new_constant(self.ptrsize, const_coeff));
        for i in 0..self.multiple.len() {
            let final_coeff = div(self.coeff[i]);
            let mut vn = self.multiple[i];
            if final_coeff != 1 {
                let c = fd.new_constant(self.ptrsize, final_coeff);
                vn = new_op_before(fd, self.base_op, IntMult, &[vn, c])?;
            }
            res = Some(match res {
                None => vn,
                Some(r) => new_op_before(fd, self.base_op, IntAdd, &[vn, r])?,
            });
        }
        Ok(res)
    }

    /// Port of `AddTreeState::buildExtra`.
    fn build_extra(&mut self, fd: &mut Funcdata) -> Result<Option<VarnodeId>> {
        let mut res: Option<VarnodeId> = None;
        for i in 0..self.nonmult.len() {
            let vn = self.nonmult[i];
            if is_const(fd, vn) {
                self.correct = self.correct.wrapping_sub(off(fd, vn));
                continue;
            }
            res = Some(match res {
                None => vn,
                Some(r) => new_op_before(fd, self.base_op, IntAdd, &[vn, r])?,
            });
        }
        self.correct &= self.ptrmask;
        if self.correct != 0 {
            // uintb_negate(correct - 1, ptrsize)
            let vn = fd.new_constant(self.ptrsize, !self.correct.wrapping_sub(1) & self.ptrmask);
            res = Some(match res {
                None => vn,
                Some(r) => new_op_before(fd, self.base_op, IntAdd, &[vn, r])?,
            });
        }
        Ok(res)
    }

    /// Port of `AddTreeState::buildDegenerate`.
    fn build_degenerate(&self, fd: &mut Funcdata) -> Result<bool> {
        if fd.types.align_size(self.base_type) < 1 {
            return Ok(false);
        }
        let o = out(fd, self.base_op)?;
        let t = facing(fd, o)?;
        if fd.types.meta(t) != Meta::Ptr {
            return Ok(false);
        }
        let slot = fd.slot_of(self.base_op, self.ptr).unwrap_or(0);
        let other = inp(fd, self.base_op, 1 - slot)?;
        let one = fd.new_constant(fd.types.size(self.ct), 1);
        fd.op_set_all_input(self.base_op, &[self.ptr, other, one])?;
        fd.op_set_opcode(self.base_op, Ptradd);
        Ok(true)
    }

    /// Port of `AddTreeState::apply`.
    fn apply(&mut self, fd: &mut Funcdata, arch: &Arch) -> Result<bool> {
        if self.is_degenerate {
            return self.build_degenerate(fd);
        }
        self.span_root(fd)?;
        if !self.valid {
            return Ok(false);
        }
        self.respan_undistributed(fd)?;
        self.calc_subtype(fd, arch)?;
        if !self.valid {
            return Ok(false);
        }
        while self.valid {
            let Some(dop) = self.distribute_op else { break };
            if !fd.distribute_int_mult_add(dop)? {
                self.valid = false;
                break;
            }
            for slot in 0..2 {
                let v = inp(fd, dop, slot)?;
                collapse_int_mult_mult(fd, v)?;
            }
            self.clear();
            self.span_root(fd)?;
            self.respan_undistributed(fd)?;
            self.calc_subtype(fd, arch)?;
        }
        if !self.valid {
            let addr = op_addr(fd, self.base_op);
            fd.warning_header(format!("Problems distributing in pointer arithmetic at r0x{addr:08x}"));
            return Ok(true);
        }
        self.build_tree(fd)?;
        Ok(true)
    }

    /// The step of `apply` that walks the tree again without distributing when a distribution
    /// was found but no multiple needs it.
    fn respan_undistributed(&mut self, fd: &Funcdata) -> Result<()> {
        if self.distribute_op.is_some() && !self.is_distribute_used {
            self.clear();
            self.prevent_distribution = true;
            self.span_root(fd)?;
        }
        Ok(())
    }

    /// Port of `AddTreeState::buildTree`.
    fn build_tree(&mut self, fd: &mut Funcdata) -> Result<()> {
        let mult = self.build_multiples(fd)?;
        let extra = self.build_extra(fd)?;
        let mut newop = None;
        let mut mult_node = self.ptr;
        if let Some(m) = mult {
            let c = fd.new_constant(self.ptrsize, self.size as u64);
            let o = new_op_before(fd, self.base_op, Ptradd, &[self.ptr, m, c])?;
            let t = vn_type(fd, self.ptr);
            no_union(fd, t)?;
            exceeded(fd)?;
            newop = def(fd, o);
            mult_node = o;
        }
        if self.is_subtype {
            let c = fd.new_constant(self.ptrsize, self.offset);
            let o = new_op_before(fd, self.base_op, Ptrsub, &[mult_node, c])?;
            let t = vn_type(fd, mult_node);
            no_union(fd, t)?;
            exceeded(fd)?;
            let p = def_op(fd, o)?;
            if self.size != 0 {
                fd.op_mut(p).flags.set(OpFlags::STOP_TYPE_PROPAGATION);
            }
            newop = Some(p);
            mult_node = o;
        }
        if let Some(e) = extra {
            let o = new_op_before(fd, self.base_op, IntAdd, &[mult_node, e])?;
            newop = def(fd, o);
        }
        let Some(newop) = newop else { return err("ptrarith problems") };
        let o = out(fd, self.base_op)?;
        fd.op_set_output(newop, o)?;
        fd.op_destroy(self.base_op);
        Ok(())
    }
}

/// `if (data.isTypeRecoveryExceeded()) assignPropagatedType(newop)`: not ported (it reads the
/// propagation's temporary types outside a pass).
fn exceeded(fd: &Funcdata) -> Result<()> {
    if fd.typerecovery_exceeded {
        return err("AddTreeState::assignPropagatedType: not implemented in ghidra-rs yet");
    }
    Ok(())
}

/// Port of `Funcdata::collapseIntMultMult`.
fn collapse_int_mult_mult(fd: &mut Funcdata, vn: VarnodeId) -> Result<bool> {
    let Some(op) = def_with(fd, vn, IntMult) else { return Ok(false) };
    let c1 = inp(fd, op, 1)?;
    if !is_const(fd, c1) {
        return Ok(false);
    }
    let Some(other) = def_with(fd, inp(fd, op, 0)?, IntMult) else { return Ok(false) };
    let c2 = inp(fd, other, 1)?;
    if !is_const(fd, c2) {
        return Ok(false);
    }
    let invn = inp(fd, other, 0)?;
    if is_free(fd, invn) {
        return Ok(false);
    }
    let size = sz(fd, invn);
    let val = off(fd, c1).wrapping_mul(off(fd, c2)) & calc_mask(size);
    let newvn = fd.new_constant(size, val);
    fd.op_set_input(op, newvn, 1)?;
    fd.op_set_input(op, invn, 0)?;
    Ok(true)
}

/// Port of `Funcdata::opUndoPtradd(op, false)`.
fn op_undo_ptradd(fd: &mut Funcdata, op: OpId) -> Result<()> {
    let mult_vn = inp(fd, op, 2)?;
    let mult_size = i64::from(off(fd, mult_vn) as i32);
    fd.op_remove_input(op, 2);
    fd.op_set_opcode(op, IntAdd);
    if mult_size == 1 {
        return Ok(());
    }
    let off_vn = inp(fd, op, 1)?;
    let size = sz(fd, off_vn);
    if is_const(fd, off_vn) {
        let v = (mult_size as u64).wrapping_mul(off(fd, off_vn)) & calc_mask(size);
        let c = fd.new_constant(size, v);
        return fd.op_set_input(op, c, 1);
    }
    let mult_op = fd.new_op(IntMult, op_addr(fd, op));
    let add_vn = uniq_out(fd, size, mult_op)?;
    fd.op_set_input(mult_op, off_vn, 0)?;
    fd.op_set_input(mult_op, mult_vn, 1)?;
    fd.op_set_input(op, add_vn, 1)?;
    fd.op_insert_before(mult_op, op)
}

/// Port of `RulePtrArith::verifyPreferredPointer`.
fn verify_preferred_pointer(fd: &mut Funcdata, op: OpId, slot: usize) -> Result<bool> {
    let vn = inp(fd, op, slot)?;
    let Some(pre) = def_with(fd, vn, IntAdd) else { return Ok(true) };
    let mut preslot = 0;
    if !is_ptr(fd, inp(fd, pre, 0)?)? {
        preslot = 1;
        if !is_ptr(fd, inp(fd, pre, 1)?)? {
            return Ok(true);
        }
    }
    Ok(evaluate_pointer_expression(fd, pre, preslot)? != 1)
}

/// Port of `RulePtrArith::evaluatePointerExpression`: 0 no action, 1 push, 2 convert.
fn evaluate_pointer_expression(fd: &mut Funcdata, op: OpId, slot: usize) -> Result<i32> {
    let mut res = 1;
    let ptr_base = inp(fd, op, slot)?;
    if is_free(fd, ptr_base) && !is_const(fd, ptr_base) {
        return Ok(0);
    }
    let other = inp(fd, op, 1 - slot)?;
    if is_ptr(fd, other)? {
        res = 2;
    }
    let out_vn = out(fd, op)?;
    let readers = fd.vn(out_vn).descend.to_vec();
    for &dec in &readers {
        match code(fd, dec) {
            IntAdd => {
                let s = fd.slot_of(dec, out_vn).unwrap_or(0);
                let o = inp(fd, dec, 1 - s)?;
                if is_free(fd, o) && !is_const(fd, o) {
                    return Ok(0);
                }
                if is_ptr(fd, o)? {
                    res = 2;
                }
            }
            Load | Store if inp(fd, dec, 1)? == out_vn => {
                let b = fd.vn(ptr_base);
                if b.has(VnFlags::SPACEBASE) && (b.is_input() || b.is_constant()) && is_const(fd, other) {
                    return Ok(0);
                }
                res = 2;
            }
            _ => res = 2,
        }
    }
    if readers.is_empty() {
        return Ok(0);
    }
    if readers.len() > 1 && fd.vn(out_vn).has(VnFlags::SPACEBASE) {
        return Ok(0);
    }
    Ok(res)
}

/// The first input slot whose read type is a pointer.
fn pointer_slot(fd: &mut Funcdata, op: OpId) -> Result<Option<usize>> {
    for slot in 0..ins(fd, op).len() {
        if is_ptr(fd, inp(fd, op, slot)?)? {
            return Ok(Some(slot));
        }
    }
    Ok(None)
}

/// Port of `RulePtrArith`: INT_ADDs on a pointer become PTRADD and PTRSUB.
pub(super) fn ptr_arith(fd: &mut Funcdata, op: OpId, arch: &Arch) -> Result<i32> {
    if !fd.typerecovery_start {
        return Ok(0);
    }
    let Some(slot) = pointer_slot(fd, op)? else { return Ok(0) };
    if evaluate_pointer_expression(fd, op, slot)? != 2 || !verify_preferred_pointer(fd, op, slot)? {
        return Ok(0);
    }
    let mut state = AddTree::new(fd, op, slot)?;
    // initAlternateForm has a second form only for a TypePointerRel, never made here
    Ok(i32::from(state.apply(fd, arch)?))
}

/// Port of `RuleStructOffset0`: a LOAD or STORE of the first field through a pointer to a struct
/// or array reads through a PTRSUB of 0.
pub(super) fn struct_offset0(fd: &mut Funcdata, op: OpId, arch: &Arch) -> Result<i32> {
    if !fd.typerecovery_start {
        return Ok(0);
    }
    let movesize = match code(fd, op) {
        Load => sz(fd, out(fd, op)?),
        Store => sz(fd, inp(fd, op, 2)?),
        _ => return Ok(0),
    };
    let ptr_vn = inp(fd, op, 1)?;
    let ct = facing(fd, ptr_vn)?;
    let Some(base) = fd.types.ptr_to(ct) else { return Ok(0) };
    let base_size = fd.types.size(base);
    match fd.types.meta(base) {
        Meta::Struct => {
            if base_size < movesize {
                return Ok(0);
            }
            // TypeStruct::getSubType is not ported: this fails
            let Some((sub, _)) = sub_type(fd, arch, base, 0)? else { return Ok(0) };
            if fd.types.size(sub) < movesize {
                return Ok(0);
            }
        }
        Meta::Array => {
            if base_size < movesize {
                return Ok(0);
            }
            if base_size == movesize && !matches!(fd.types.get(base).kind, Kind::Array { count: 1, .. }) {
                return Ok(0);
            }
        }
        _ => return Ok(0),
    }
    let zero = fd.new_constant(sz(fd, ptr_vn), 0);
    let o = new_op_before(fd, op, Ptrsub, &[ptr_vn, zero])?;
    let t = vn_type(fd, ptr_vn);
    no_union(fd, t)?;
    let p = def_op(fd, o)?;
    fd.op_mut(p).flags.set(OpFlags::STOP_TYPE_PROPAGATION);
    fd.op_set_input(op, o, 1)?;
    Ok(1)
}

/// Port of `RulePushPtr::buildVarnodeOut`.
fn build_varnode_out(fd: &mut Funcdata, vn: VarnodeId, op: OpId) -> Result<VarnodeId> {
    let v = fd.vn(vn);
    let internal = matches!(v.space, Space::Sleigh(i) if Some(i) == fd.uniq);
    if v.has(VnFlags::ADDRTIED) || internal {
        return uniq_out(fd, v.size, op);
    }
    let (size, space, offset) = (v.size, v.space, v.offset);
    Ok(fd.new_varnode_out(size, space, offset, op))
}

/// Port of `RulePushPtr::collectDuplicateNeeds`.
fn collect_duplicate_needs(fd: &Funcdata, mut vn: VarnodeId) -> Result<Vec<OpId>> {
    let mut res = Vec::new();
    loop {
        let Some(op) = def(fd, vn) else { return Ok(res) };
        if fd.vn(vn).is_auto_live() || lone_descend(fd, vn).is_none() {
            return Ok(res);
        }
        match code(fd, op) {
            IntZext | IntSext | Int2comp => res.push(op),
            IntMult if is_const(fd, inp(fd, op, 1)?) => res.push(op),
            _ => return Ok(res),
        }
        vn = inp(fd, op, 0)?;
    }
}

/// Port of `RulePushPtr::duplicateNeed`.
fn duplicate_need(fd: &mut Funcdata, op: OpId) -> Result<()> {
    let out_vn = out(fd, op)?;
    let in_vn = inp(fd, op, 0)?;
    let second = ins(fd, op).get(1).copied();
    let opc = code(fd, op);
    let addr = op_addr(fd, op);
    while let Some(&dec) = fd.vn(out_vn).descend.first() {
        let slot = fd.slot_of(dec, out_vn).unwrap_or(0);
        let new_op = fd.new_op(opc, addr);
        let new_out = build_varnode_out(fd, out_vn, new_op)?;
        let t = vn_type(fd, out_vn);
        if !fd.vn(new_out).has(VnFlags::TYPELOCK) {
            fd.vn_mut(new_out).ty = Some(t);
        }
        fd.op_set_input(new_op, in_vn, 0)?;
        if let Some(s) = second {
            fd.op_set_input(new_op, s, 1)?;
        }
        fd.op_set_input(dec, new_out, slot)?;
        fd.op_insert_before(new_op, dec)?;
    }
    fd.op_destroy(op);
    Ok(())
}

/// Port of `RulePushPtr`: a pointer moves to the bottom of its additive expression.
pub(super) fn push_ptr(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    if !fd.typerecovery_start {
        return Ok(0);
    }
    let Some(slot) = pointer_slot(fd, op)? else { return Ok(0) };
    if evaluate_pointer_expression(fd, op, slot)? != 1 {
        return Ok(0);
    }
    let vni = inp(fd, op, slot)?;
    let vn = out(fd, op)?;
    let vnadd2 = inp(fd, op, 1 - slot)?;
    let dups = if lone_descend(fd, vn).is_none() { collect_duplicate_needs(fd, vnadd2)? } else { Vec::new() };
    while let Some(&decop) = fd.vn(vn).descend.first() {
        let j = fd.slot_of(decop, vn).unwrap_or(0);
        let vnadd1 = inp(fd, decop, 1 - j)?;
        let newop = fd.new_op(IntAdd, op_addr(fd, decop));
        let newout = uniq_out(fd, sz(fd, vnadd1), newop)?;
        fd.op_set_input(decop, vni, 0)?;
        fd.op_set_input(decop, newout, 1)?;
        fd.op_set_input(newop, vnadd1, 0)?;
        fd.op_set_input(newop, vnadd2, 1)?;
        fd.op_insert_before(newop, decop)?;
    }
    if !fd.vn(vn).is_auto_live() {
        fd.op_destroy(op);
    }
    for d in dups {
        duplicate_need(fd, d)?;
    }
    Ok(1)
}

/// Port of `RulePtraddUndo`: a PTRADD whose pointer type no longer matches goes back to INT_ADD.
pub(super) fn ptradd_undo(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    if !fd.typerecovery_start {
        return Ok(0);
    }
    let size = i64::from(off(fd, inp(fd, op, 2)?) as i32);
    let dt = facing(fd, inp(fd, op, 0)?)?;
    if let Some(to) = fd.types.ptr_to(dt) {
        if i64::from(fd.types.align_size(to)) == size {
            let ind = inp(fd, op, 1)?;
            if !is_const(fd, ind) || off(fd, ind) != 0 {
                return Ok(0);
            }
        }
    }
    op_undo_ptradd(fd, op)?;
    Ok(1)
}

/// Port of `RulePtrsubUndo::getConstOffsetBack`: (sum of constants, biggest multiplier).
fn const_offset_back(fd: &Funcdata, vn: VarnodeId, terms: &mut i32) -> Result<(i64, i64)> {
    if is_const(fd, vn) {
        return Ok((off(fd, vn) as i64, 0));
    }
    let Some(op) = def(fd, vn) else { return Ok((0, 0)) };
    *terms += 1;
    if *terms > MAX_TERMS {
        return Ok((0, 0));
    }
    let mut multiplier = 0;
    let mut retval = 0i64;
    match code(fd, op) {
        IntAdd => {
            for slot in 0..2 {
                let (v, m) = const_offset_back(fd, inp(fd, op, slot)?, terms)?;
                retval = retval.wrapping_add(v);
                multiplier = multiplier.max(m);
            }
        }
        IntMult => {
            let cvn = inp(fd, op, 1)?;
            if !is_const(fd, cvn) {
                return Ok((0, 0));
            }
            multiplier = off(fd, cvn) as i64;
            let (_, m) = const_offset_back(fd, inp(fd, op, 0)?, terms)?;
            if m > 0 {
                multiplier = multiplier.wrapping_mul(m);
            }
        }
        _ => {}
    }
    Ok((retval, multiplier))
}

/// Port of `RulePtrsubUndo::getExtraOffset`: (extra offset, biggest multiplier).
fn extra_offset(fd: &Funcdata, op: OpId) -> Result<(i64, i64)> {
    let (mut extra, mut multiplier) = (0i64, 0i64);
    let mut outvn = out(fd, op)?;
    let mut cur = lone_descend(fd, outvn);
    while let Some(op) = cur {
        match code(fd, op) {
            IntAdd => {
                let slot = fd.slot_of(op, outvn).unwrap_or(0);
                let mut terms = 0;
                let (v, m) = const_offset_back(fd, inp(fd, op, 1 - slot)?, &mut terms)?;
                extra = extra.wrapping_add(v);
                if terms > MAX_TERMS {
                    return Ok((0, 0));
                }
                multiplier = multiplier.max(m);
            }
            Ptrsub => extra = extra.wrapping_add(off(fd, inp(fd, op, 1)?) as i64),
            Ptradd => {
                if inp(fd, op, 0)? != outvn {
                    break;
                }
                let mut ptraddmult = off(fd, inp(fd, op, 2)?) as i64;
                let invn = inp(fd, op, 1)?;
                if is_const(fd, invn) {
                    extra = extra.wrapping_add(ptraddmult.wrapping_mul(off(fd, invn) as i64));
                }
                let mut terms = 0;
                let (_, m) = const_offset_back(fd, invn, &mut terms)?;
                if terms > MAX_TERMS {
                    return Ok((0, 0));
                }
                if m != 0 {
                    ptraddmult = ptraddmult.wrapping_mul(m);
                }
                multiplier = multiplier.max(ptraddmult);
            }
            _ => break,
        }
        outvn = out(fd, op)?;
        cur = lone_descend(fd, outvn);
    }
    Ok((sext(extra as u64, sz(fd, outvn)), multiplier))
}

/// INT_ADD of a constant becomes a COPY of its other input.
fn add_to_copy(fd: &mut Funcdata, op: OpId) {
    fd.op_remove_input(op, 1);
    fd.op_set_opcode(op, Copy);
}

/// Port of `RulePtrsubUndo::removeLocalAddRecurse`.
fn remove_local_add_recurse(fd: &mut Funcdata, op: OpId, slot: usize, depth: u32) -> Result<i64> {
    if depth > MAX_DEPTH {
        return err("RulePtrsubUndo: add tree too deep");
    }
    let vn = inp(fd, op, slot)?;
    let Some(d) = def(fd, vn) else { return Ok(0) };
    if lone_descend(fd, vn) != Some(op) || code(fd, d) != IntAdd {
        return Ok(0);
    }
    let c = inp(fd, d, 1)?;
    if is_const(fd, c) {
        let v = off(fd, c) as i64;
        add_to_copy(fd, d);
        return Ok(v);
    }
    let a = remove_local_add_recurse(fd, d, 0, depth + 1)?;
    let b = remove_local_add_recurse(fd, d, 1, depth + 1)?;
    Ok(a.wrapping_add(b))
}

/// Port of `RulePtrsubUndo::removeLocalAdds`.
fn remove_local_adds(fd: &mut Funcdata, vn: VarnodeId) -> Result<i64> {
    let mut extra = 0i64;
    let mut next_vn = vn;
    let mut cur = lone_descend(fd, vn);
    while let Some(op) = cur {
        match code(fd, op) {
            IntAdd => {
                let slot = fd.slot_of(op, next_vn).unwrap_or(0);
                let c = inp(fd, op, 1)?;
                if slot == 0 && is_const(fd, c) {
                    extra = extra.wrapping_add(off(fd, c) as i64);
                    add_to_copy(fd, op);
                } else {
                    extra = extra.wrapping_add(remove_local_add_recurse(fd, op, 1 - slot, 0)?);
                }
            }
            Ptrsub => {
                extra = extra.wrapping_add(off(fd, inp(fd, op, 1)?) as i64);
                fd.op_mut(op).flags.clear(OpFlags::STOP_TYPE_PROPAGATION);
                add_to_copy(fd, op);
            }
            Ptradd => {
                if inp(fd, op, 0)? != next_vn {
                    break;
                }
                let ptraddmult = off(fd, inp(fd, op, 2)?) as i64;
                let invn = inp(fd, op, 1)?;
                if is_const(fd, invn) {
                    extra = extra.wrapping_add(ptraddmult.wrapping_mul(off(fd, invn) as i64));
                    fd.op_remove_input(op, 2);
                    fd.op_remove_input(op, 1);
                    fd.op_set_opcode(op, Copy);
                } else {
                    op_undo_ptradd(fd, op)?;
                    extra = extra.wrapping_add(remove_local_add_recurse(fd, op, 1, 0)?);
                }
            }
            _ => break,
        }
        next_vn = out(fd, op)?;
        cur = lone_descend(fd, next_vn);
    }
    if next_vn != vn {
        // Varnode::updateType(Datatype *)
        let t = vn_type(fd, next_vn);
        if !fd.vn(vn).has(VnFlags::TYPELOCK) {
            fd.vn_mut(vn).ty = Some(t);
        }
    }
    Ok(extra)
}

/// Port of `RulePtrsubUndo`: a PTRSUB whose offset no longer matches its pointer's type goes
/// back to INT_ADD.
pub(super) fn ptrsub_undo(fd: &mut Funcdata, op: OpId, arch: &Arch) -> Result<i32> {
    if !fd.typerecovery_start {
        return Ok(0);
    }
    let basevn = inp(fd, op, 0)?;
    let cvn = inp(fd, op, 1)?;
    let val = off(fd, cvn) as i64;
    let (extra, multiplier) = extra_offset(fd, op)?;
    let bt = facing(fd, basevn)?;
    if is_ptrsub_matching(fd, arch, bt, val, extra, multiplier)? {
        return Ok(0);
    }
    fd.op_set_opcode(op, IntAdd);
    fd.op_mut(op).flags.clear(OpFlags::STOP_TYPE_PROPAGATION);
    let o = out(fd, op)?;
    let extra = remove_local_adds(fd, o)?;
    if extra != 0 {
        let size = sz(fd, cvn);
        let c = fd.new_constant(size, val.wrapping_add(extra) as u64 & calc_mask(size));
        fd.op_set_input(op, c, 1)?;
    }
    Ok(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sext_matches_cpp_sign_extend() {
        assert_eq!(sext(0xfffffff0, 4), -16);
        assert_eq!(sext(0x7fffffff, 4), 0x7fffffff);
        assert_eq!(sext(0x80, 1), -128);
    }

    #[test]
    fn add_tree_remainder_and_division_are_signed() {
        // calcSubtype / buildMultiples: C++ `%` and `/` on intb truncate toward zero
        assert_eq!((-12i64).wrapping_rem(8), -4);
        assert_eq!((-16i64).wrapping_div(8) as u64 & calc_mask(4), 0xffff_fffe);
        // buildExtra's uintb_negate(correct - 1, 4) is -correct
        let correct = 0x10u64;
        assert_eq!(!correct.wrapping_sub(1) & calc_mask(4), 0xffff_fff0);
    }
}
