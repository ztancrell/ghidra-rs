//! The `constsequence` rules (stage R5, slice 5): `RuleStringCopy`, `RuleStringStore`
//! (constseq.cc), up to their sequences. `RuleStringCopy` needs a local symbol holding the
//! copied-to storage (`ScopeLocal::queryContainer`): a locked parameter of the function or a
//! symbol of `restructure_varnode` (superseded: "the local scope's symbols are the locked
//! parameters of the function (`localrecovery` is not ported)"). `StringSequence` is not
//! ported: a character copied into one fails loudly. `RuleStringStore`'s `HeapSequence` is not
//! ported: reaching it fails loudly. No type is an opaque string (`isOpaqueString`) here.

use super::*;
use crate::decomp::infertypes::vn_type;
use crate::decomp::locked::param_symbol;

/// Port of `RuleStringCopy`, up to `StringSequence`, which is not ported.
pub(super) fn string_copy(fd: &mut Funcdata, op: OpId, _: &Arch) -> Result<i32> {
    if !is_const(fd, inp(fd, op, 0)?) {
        return Ok(0);
    }
    let outvn = out(fd, op)?;
    let ct = vn_type(fd, outvn);
    if !fd.types.is_char_print(ct) || !fd.vn(outvn).has(VnFlags::ADDRTIED) {
        return Ok(0);
    }
    // ScopeLocal::queryContainer: a piece of a locked stack parameter fails in heritage, so the
    // entry holding the varnode is the parameter exactly at it
    // (or a symbol of `restructure_varnode` holding it)
    let v = fd.vn(outvn);
    if param_symbol(fd, outvn).is_some() || (v.space == Space::Stack && fd.localmap.has_container(v.offset, v.size)) {
        return err("RuleStringCopy: StringSequence (constseq.cc) not implemented in ghidra-rs yet");
    }
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
