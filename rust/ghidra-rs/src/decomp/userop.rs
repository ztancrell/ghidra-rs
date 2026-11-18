//! User-defined p-code ops a spec gives a meaning (port of the `SegmentOp`, `JumpAssistOp` and
//! `UserOpManage` parts of `userop.cc`): the `<segmentop>` of a `.pspec` or `.cspec` (segmented
//! addressing, as 16-bit x86's `segment(base, inner)`) and the `<jumpassist>` of a `.pspec`
//! (scripts that list a switch's targets and labels).
//!
//! Their scripts are [`ExecutablePcode`] snippets. Not ported: the other user-op kinds
//! (`<volatile>`, `<callotherfixup>`, the built-in string ops), which no spec ghidra-rs loads
//! declares; `SegmentedResolver` (`Arch::no_segment_resolver` fails loudly where a near
//! pointer would be resolved).

use super::cspec::SleighNames;
use super::fspec::Storage;
use super::inject::ExecutablePcode;
use super::{err, Arch, LowlevelError, Result};
use crate::sleigh::Sleigh;
use crate::xml::Element;

/// Port of `SegmentOp`: the user op that makes a full address from a segment (base) and a near
/// pointer (inner).
#[derive(Debug)]
pub(crate) struct SegmentOp {
    pub(crate) name: String,
    /// the user op's index (CALLOTHER's first input)
    pub(crate) index: u64,
    /// the space the op addresses
    pub(crate) space: u32,
    /// size of the base (segment) value; 0 when the op has only the inner input
    pub(crate) base_size: u32,
    /// size of the near pointer
    pub(crate) inner_size: u32,
    /// `farpointer` is present (`hasFarPointerSupport`; the C++ does not read its value)
    pub(crate) far_pointer: bool,
    script: ExecutablePcode,
}

impl SegmentOp {
    /// Port of `SegmentOp::decode`.
    fn decode(el: &Element, sleigh: &Sleigh, names: &SleighNames) -> Result<SegmentOp> {
        let space = names.space(el.attr("space").ok_or_else(|| err_msg("<segmentop> expecting space attribute"))?)?;
        let name = el.attr("userop").unwrap_or("segment").to_string();
        let index = sleigh.userop_index(&name).ok_or_else(|| err_msg(format!("<segmentop> unknown userop {name}")))?;
        let mut script = None;
        for kid in &el.kids {
            match kid.name.as_str() {
                "constresolve" => {
                    if let Some(v) = kid.kids.first() {
                        // the register a near pointer's base is read from: only
                        // `SegmentedResolver` uses it, which is not ported
                        let Storage::Space { .. } = Storage::decode(v, names)? else {
                            return err("<constresolve>: expected a register or a varnode");
                        };
                    }
                }
                "pcode" => script = Some(ExecutablePcode::decode(names, &format!("{name}_pcode"), kid)?),
                _ => {}
            }
        }
        let script = script.ok_or_else(|| err_msg("Missing <pcode> child in <segmentop> tag"))?;
        if script.outputs.len() != 1 {
            return err("<pcode> child of <segmentop> tag must declare one <output>");
        }
        let (base_size, inner_size) = match script.inputs[..] {
            [inner] => (0, inner),
            [base, inner] => (base, inner),
            _ => return err("<pcode> child of <segmentop> tag must declare one or two <input> tags"),
        };
        Ok(SegmentOp {
            name,
            index,
            space,
            base_size,
            inner_size,
            far_pointer: el.attr("farpointer").is_some(),
            script,
        })
    }

    /// `SegmentOp::getNumVariableTerms`
    pub(crate) fn num_variable_terms(&self) -> usize {
        if self.base_size != 0 {
            2
        } else {
            1
        }
    }

    /// Port of `SegmentOp::execute`: the full address of `input` (base, inner).
    pub(crate) fn execute(&self, arch: &Arch, input: &[u64]) -> Result<u64> {
        self.script.evaluate(arch, input)
    }

    /// Port of `SegmentOp::isConcatenation`: whether the op is a PIECE of its inputs.
    pub(crate) fn is_concatenation(&self, arch: &Arch) -> Result<bool> {
        let mask = super::rangeutil::calc_mask;
        let high = 0xabab_abab_abab_abab & mask(self.base_size);
        let low = 0x1234_5678_1234_5678 & mask(self.inner_size);
        let whole = high.checked_shl(self.inner_size * 8).unwrap_or(0) | low;
        Ok(whole == self.execute(arch, &[high, low])?)
    }
}

/// Port of `JumpAssistOp`: the user op standing for a switch's address calculation, with the
/// scripts that recover its table.
#[derive(Debug)]
pub(crate) struct JumpAssistOp {
    pub(crate) name: String,
    pub(crate) index: u64,
    /// `<case_pcode>`: the label of an index; without it the index is the label
    pub(crate) index2case: Option<ExecutablePcode>,
    /// `<addr_pcode>`: the target of an index
    pub(crate) index2addr: ExecutablePcode,
    /// `<default_pcode>`: the default target
    pub(crate) default_addr: ExecutablePcode,
    /// `<size_pcode>`: the number of indices; without it the op's third input is
    pub(crate) calc_size: Option<ExecutablePcode>,
}

impl JumpAssistOp {
    /// Port of `JumpAssistOp::decode`.
    fn decode(el: &Element, sleigh: &Sleigh, names: &SleighNames) -> Result<JumpAssistOp> {
        let name = el.req("name")?.to_string();
        let mut scripts = [None, None, None, None];
        for kid in &el.kids {
            let (i, suffix) = match kid.name.as_str() {
                "case_pcode" => (0, "index2case"),
                "addr_pcode" => (1, "index2addr"),
                "default_pcode" => (2, "defaultaddr"),
                "size_pcode" => (3, "calcsize"),
                _ => continue,
            };
            if scripts[i].is_some() {
                return err(format!("Too many <{}> tags", kid.name));
            }
            scripts[i] = Some(ExecutablePcode::decode(names, &format!("{name}_{suffix}"), kid)?);
        }
        let [index2case, index2addr, default_addr, calc_size] = scripts;
        let index2addr = index2addr.ok_or_else(|| err_msg(format!("userop: {name} is missing <addr_pcode>")))?;
        let default_addr = default_addr.ok_or_else(|| err_msg(format!("userop: {name} is missing <default_pcode>")))?;
        let index = sleigh
            .userop_index(&name)
            .ok_or_else(|| err_msg(format!("Unknown userop name in <jumpassist>: {name}")))?;
        Ok(JumpAssistOp { name, index, index2case, index2addr, default_addr, calc_size })
    }
}

fn err_msg(m: impl Into<String>) -> LowlevelError {
    LowlevelError(m.into())
}

/// Port of `UserOpManage` for the segment and jump-assist ops.
#[derive(Debug, Default)]
pub(crate) struct UserOps {
    /// by space index (`UserOpManage::segmentop`)
    segment: Vec<Option<SegmentOp>>,
    jumpassist: Vec<JumpAssistOp>,
}

impl UserOps {
    /// Port of `UserOpManage::decodeSegmentOp` and `decodeJumpAssist` (`registerOp`): `el` is a
    /// `<segmentop>` or a `<jumpassist>` element.
    pub(crate) fn decode(&mut self, el: &Element, sleigh: &Sleigh, names: &SleighNames) -> Result<()> {
        if el.name == "jumpassist" {
            let op = JumpAssistOp::decode(el, sleigh, names)?;
            if self.specialized(op.index) {
                return err(format!("<jumpassist> overloads userop with another purpose: {}", op.name));
            }
            self.jumpassist.push(op);
            return Ok(());
        }
        let op = SegmentOp::decode(el, sleigh, names)?;
        if self.specialized(op.index) {
            return err(format!("Redefining userop {}", op.name));
        }
        let i = op.space as usize;
        if self.segment.len() <= i {
            self.segment.resize_with(i + 1, || None);
        }
        if self.segment[i].is_some() {
            return err("Multiple segmentops defined for same space");
        }
        self.segment[i] = Some(op);
        Ok(())
    }

    /// Whether user op `index` already has a meaning (is not an `UnspecializedPcodeOp`).
    fn specialized(&self, index: u64) -> bool {
        self.jump_assist(index).is_some() || self.is_segment(index)
    }

    /// `UserOpManage::getSegmentOp`: the segment op of `space`.
    pub(crate) fn segment_op(&self, space: u32) -> Option<&SegmentOp> {
        self.segment.get(space as usize)?.as_ref()
    }

    /// The segment ops, by space index (`numSegmentOps`, `getSegmentOp(i)`).
    pub(crate) fn segment_ops(&self) -> impl Iterator<Item = &SegmentOp> {
        self.segment.iter().flatten()
    }

    /// Whether user op `index` is a segment op (`getOp(index)->getType() == segment`).
    pub(crate) fn is_segment(&self, index: u64) -> bool {
        self.segment_ops().any(|s| s.index == index)
    }

    /// User op `index` when it is a jump-assist op (`getType() == jumpassist`).
    pub(crate) fn jump_assist(&self, index: u64) -> Option<&JumpAssistOp> {
        self.jumpassist.iter().find(|j| j.index == index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::Image;

    fn arch(pspec: &str) -> Arch {
        let path = Sleigh::sla_path("x86");
        assert!(path.exists(), "{} is missing: run rust/build-sla.sh first", path.display());
        let cspec = std::fs::read_to_string(path.with_file_name("x86-16.cspec")).unwrap();
        let sleigh = Sleigh::load_with_pspec(&path, Some(&path.with_file_name(pspec))).unwrap();
        Arch::new(sleigh, Image::default(), &cspec).unwrap()
    }

    /// The `<segmentop>` of the two 16-bit x86 processor specs: real mode is
    /// `(base << 4) + inner`, protected mode concatenates base and inner. The values are the
    /// scripts' arithmetic done by hand, not decomp_dbg output.
    #[test]
    fn x86_16_segment_ops() {
        let real = arch("x86-16-real.pspec");
        let ram = real.sleigh.code_space();
        let seg = real.userops.segment_op(ram).unwrap();
        assert_eq!((seg.name.as_str(), seg.base_size, seg.inner_size, seg.far_pointer), ("segment", 2, 2, true));
        assert_eq!(seg.num_variable_terms(), 2);
        assert!(real.userops.is_segment(seg.index));
        assert_eq!(seg.execute(&real, &[0x1000, 0x0234]).unwrap(), 0x10234);
        assert!(!seg.is_concatenation(&real).unwrap());
        assert!(seg.execute(&real, &[1]).is_err());

        let protected = arch("x86-16.pspec");
        let seg = protected.userops.segment_op(ram).unwrap();
        assert_eq!(seg.execute(&protected, &[0x1000, 0x0234]).unwrap(), 0x1000_0234);
        assert!(seg.is_concatenation(&protected).unwrap());
    }
}
