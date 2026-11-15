//! The `bitfields` rules (stage R5, slice 5): `RuleBitFieldStore`, `RuleBitFieldOut`,
//! `RuleBitFieldLoad`, `RuleBitFieldIn`, `RulePullAbsorb`, `RuleInsertAbsorb` (bitfield.cc), as
//! far as the type store reaches them. No data-type has bit-fields here (`parse line` does not
//! accept them, `Datatype::hasBitfields` is false), so the four transforms never start; INSERT,
//! ZPULL and SPULL ops are made only by those transforms (x86 SLEIGH emits none), so the two
//! absorb rules fail loudly if one is ever met. The transforms (`BitFieldInsertTransform`,
//! `BitFieldPullTransform`) are not ported.

use super::*;

/// Port of `RuleBitFieldStore`, `RuleBitFieldOut`, `RuleBitFieldLoad` and `RuleBitFieldIn`: each
/// starts only for a type with bit-fields (`Datatype::hasBitfields`), and the type store can hold
/// none, so none ever starts.
pub(super) fn bitfield_transform(_: &mut Funcdata, _: OpId, _: &Arch) -> Result<i32> {
    Ok(0)
}

/// Port of `RulePullAbsorb` and `RuleInsertAbsorb`: their ops come only from the transforms.
pub(super) fn bitfield_absorb(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    err(format!("{:?} absorb rules (bitfield.cc) not implemented in ghidra-rs yet", code(fd, op)))
}
