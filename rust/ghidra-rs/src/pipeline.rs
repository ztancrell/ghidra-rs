//! The mercs2 analysis pipeline (milestone 2c): the passes mercs2's Ghidra scripts run after
//! import. See docs/plans/m2c-pipeline.md.

/// Sites where `orig` has `FF 25 <slot>` and `patched` has `E9 rel32 90`: (site, exit),
/// in address order. Both slices are the same section's bytes; `base` is its address.
pub fn slot_rewrites(orig: &[u8], patched: &[u8], base: u32) -> Vec<(u32, u32)> {
    todo!("the project owner's piece: see docs/plans/m2c-pipeline.md")
}
