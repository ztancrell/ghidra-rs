//! Milestone 3: the decompiler, a port of Ghidra's C++ decompiler
//! (`Ghidra/Features/Decompiler/src/decompile/cpp`). See `docs/plans/m3-decompiler.md`.
//!
//! Stage S1a: the IR (ops and varnodes in arenas, [`Funcdata`]), flow following on the SLEIGH
//! engine of milestone 1 ([`flow`]), basic blocks ([`block`]), the actions that run before
//! `funclink` ([`action`]) and `print raw` ([`print`]).

pub mod action;
pub mod block;
mod flow;
pub mod funcdata;
pub mod op;
pub mod opcode;
mod print;
mod stdsort;
pub mod varnode;

use crate::analysis::Image;
use crate::sleigh::Sleigh;
use std::collections::{BTreeMap, HashMap};

pub use funcdata::Funcdata;
pub use print::print_raw;

/// Port of `LowlevelError` (error.hh): a decompilation that cannot go on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LowlevelError(pub String);

impl std::fmt::Display for LowlevelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for LowlevelError {}

pub type Result<T> = std::result::Result<T, LowlevelError>;

pub(crate) fn err<T>(msg: impl Into<String>) -> Result<T> {
    Err(LowlevelError(msg.into()))
}

/// A register as `SleighBase::varnode_xref` keys it: space, offset, then size with big sizes
/// first (`VarnodeData::operator<`).
type RegKey = (u32, u64, std::cmp::Reverse<u32>);

/// The program-wide state a decompilation reads (the parts of C++ `Architecture` S1a needs):
/// the loaded image, the SLEIGH engine, the functions the console mapped and the processor
/// facts from the `.pspec`/`.cspec`. Shared read-only by every [`Funcdata`].
pub struct Arch {
    pub(crate) sleigh: Sleigh,
    pub(crate) image: Image,
    /// `map function`: entry -> display name (the scope's `queryFunction`)
    pub(crate) functions: HashMap<u64, String>,
    /// the register names, for `Address::printRaw`
    registers: BTreeMap<RegKey, String>,
    /// the stack pointer (`getSpacebase(0)` of the stack space): space, offset, size
    pub(crate) stack_pointer: (u32, u64, u32),
    /// `<tracked_set>` registers: space, offset, size, value (ActionConstbase)
    pub(crate) tracked: Vec<(u32, u64, u32, u64)>,
}

impl Arch {
    /// An architecture for `image` decoded by `sleigh` (x86 32-bit: the stack pointer is ESP).
    pub fn new(sleigh: Sleigh, image: Image) -> Result<Arch> {
        let mut syms = sleigh.varnode_syms();
        // SymbolTree iterates by name, and the first name wins for a shared varnode
        syms.sort_by(|a, b| a.0.cmp(b.0));
        let mut registers = BTreeMap::new();
        for (name, space, off, size) in &syms {
            registers.entry((*space, *off, std::cmp::Reverse(*size))).or_insert_with(|| name.to_string());
        }
        let reg = |name: &str| syms.iter().find(|s| s.0 == name).map(|s| (s.1, s.2, s.3));
        let stack_pointer = reg("ESP").ok_or(LowlevelError("no ESP register".into()))?;
        let tracked = sleigh
            .tracked
            .iter()
            .map(|(name, val)| {
                reg(name)
                    .map(|(s, o, z)| (s, o, z, u64::from(*val)))
                    .ok_or(LowlevelError(format!("unknown tracked register {name}")))
            })
            .collect::<Result<_>>()?;
        Ok(Arch { sleigh, image, functions: HashMap::new(), registers, stack_pointer, tracked })
    }

    /// Port of `SleighBase::getRegisterName`: the register holding the range, as its name, offset
    /// and size.
    pub(crate) fn register_name(&self, space: u32, off: u64, size: u32) -> Option<(&str, u64, u32)> {
        let key = (space, off, std::cmp::Reverse(size));
        let it = self.registers.range(..=key).rev();
        let ((s, base, _), _) = it.clone().next()?;
        if *s != space {
            return None;
        }
        let base = *base;
        // the last entry at or below the key, then larger registers at the same offset
        it.take_while(|((s, o, _), _)| *s == space && *o == base)
            .find(|((_, o, std::cmp::Reverse(z)), _)| o + u64::from(*z) >= off + u64::from(size))
            .map(|((_, o, std::cmp::Reverse(z)), name)| (name.as_str(), *o, *z))
    }

    /// The bytes of the loaded image from `addr` on, as the instruction decoder reads them.
    pub(crate) fn bytes_at(&self, addr: u64) -> Option<&[u8]> {
        let a = u32::try_from(addr).ok()?;
        let sec = self.image.block_of(a)?;
        sec.data.get((a - sec.addr) as usize..)
    }
}
