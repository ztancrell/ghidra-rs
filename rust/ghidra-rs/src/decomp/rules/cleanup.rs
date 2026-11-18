//! The rules of the `cleanup` pool that need no data-types (stage R2): `RuleMultNegOne`,
//! `Rule2Comp2Sub` (ruleaction.cc). Superseded: the pool's rules that read data-types are in
//! `typecleanup.rs` (stage R5, slice 4; `RulePtrsubCharConstant` since stage S10).

use super::*;

/// Port of `RuleMultNegOne`: `V * -1  =>  -V`.
pub(super) fn mult_neg_one(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let c = inp(fd, op, 1)?;
    if !const_match(fd, c, calc_mask(sz(fd, c))) {
        return Ok(0);
    }
    fd.op_set_opcode(op, Int2comp);
    fd.op_remove_input(op, 1);
    Ok(1)
}

/// Port of `Rule2Comp2Sub`: `V + -W  =>  V - W`.
pub(super) fn two_comp_2_sub(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    let o = out(fd, op)?;
    let Some(addop) = lone_descend(fd, o).filter(|&a| code(fd, a) == IntAdd) else { return Ok(0) };
    if inp(fd, addop, 0)? == o {
        let other = inp(fd, addop, 1)?;
        fd.op_set_input(addop, other, 0)?;
    }
    let w = inp(fd, op, 0)?;
    fd.op_set_input(addop, w, 1)?;
    fd.op_set_opcode(addop, IntSub);
    fd.op_destroy(op);
    Ok(1)
}
