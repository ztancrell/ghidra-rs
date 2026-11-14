//! The `constsequence` rules (stage R5, slice 5): `RuleStringCopy`, `RuleStringStore`
//! (constseq.cc), as far as they run without scopes. `RuleStringCopy` needs a local symbol
//! holding the copied-to storage (`ScopeLocal::queryContainer`); the local scope holds no symbols
//! (`localrecovery` is not ported), so it never matches. `RuleStringStore`'s `HeapSequence` is not
//! ported: reaching it fails loudly. No type is an opaque string (`isOpaqueString`) here.

use super::*;
use crate::decomp::infertypes::vn_type;

/// Port of `RuleStringCopy`: COPYs of characters into a local array (never: no local symbols).
pub(super) fn string_copy(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    if !is_const(fd, inp(fd, op, 0)?) {
        return Ok(0);
    }
    let outvn = out(fd, op)?;
    let ct = vn_type(fd, outvn);
    if !fd.types.is_char_print(ct) || !fd.vn(outvn).has(VnFlags::ADDRTIED) {
        return Ok(0);
    }
    // ScopeLocal::queryContainer: no symbols, no entry
    Ok(0)
}

/// Port of `RuleStringStore`, up to `HeapSequence`, which is not ported.
pub(super) fn string_store(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    if !is_const(fd, inp(fd, op, 2)?) {
        return Ok(0);
    }
    let pt = vn_type(fd, inp(fd, op, 1)?);
    match fd.types.ptr_to(pt) {
        Some(ct) if fd.types.is_char_print(ct) => {
            err("RuleStringStore: HeapSequence (constseq.cc) not implemented in ghidra-rs yet")
        }
        _ => Ok(0),
    }
}
