//! Milestone 3: the decompiler, a port of Ghidra's C++ decompiler
//! (`Ghidra/Features/Decompiler/src/decompile/cpp`). See `docs/plans/m3-decompiler.md`.
//!
//! Stages S1a to S2: the IR (ops and varnodes in arenas, [`Funcdata`]), flow following on
//! the SLEIGH engine of milestone 1 ([`flow`]) with call fixups ([`inject`]), basic blocks
//! ([`block`]), the compiler spec ([`cspec`]) and prototypes ([`fspec`]), the action framework
//! ([`actiontree`]) and the actions up to `paramdouble` ([`action`]), SSA construction
//! ([`heritage`]) and `print raw` ([`print`]). Stage S3: jump-table recovery on a partial
//! function ([`jumptable`], with [`rangeutil`] and [`emulate`]).

pub mod action;
pub mod actiontree;
mod block;
mod coreaction;
mod cparse;
mod cspec;
mod emulate;
mod flow;
mod fspec;
mod funcdata;
mod heritage;
mod infertypes;
mod inject;
mod jumptable;
mod lanedivide;
mod lateres;
mod locked;
mod op;
mod opcode;
mod print;
mod rangeutil;
mod readers;
mod rules;
mod stdsort;
mod subfloat;
mod transform;
mod types;
mod varnode;

use crate::analysis::Image;
use crate::sleigh::Sleigh;
use cspec::{CompilerSpec, SleighNames};
use fspec::FuncProto;
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

/// Spec-reading errors (`crate::xml`) end a decompile like any other.
impl From<String> for LowlevelError {
    fn from(msg: String) -> LowlevelError {
        LowlevelError(msg)
    }
}

pub type Result<T> = std::result::Result<T, LowlevelError>;

pub(crate) fn err<T>(msg: impl Into<String>) -> Result<T> {
    Err(LowlevelError(msg.into()))
}

/// A register as `SleighBase::varnode_xref` keys it: space, offset, then size with big sizes
/// first (`VarnodeData::operator<`).
type RegKey = (u32, u64, std::cmp::Reverse<u32>);

/// Size of an external-reference symbol: a pointer (`ExternRefSymbol::buildNameType`).
const EXTERNREF_SIZE: u64 = 4;

/// How much of a section bfd loads (`Section::zero_tail`).
fn loaded_len(s: &crate::analysis::Section) -> usize {
    s.data.len().saturating_sub(s.zero_tail as usize)
}

/// A function the console mapped (`map function`): its name and prototype (the scope's
/// `Funcdata`, as `queryFunction` finds it).
#[derive(Debug, Clone)]
pub(crate) struct Function {
    pub(crate) name: String,
    pub(crate) proto: FuncProto,
}

/// The program-wide state a decompilation reads (the parts of C++ `Architecture` used so far):
/// the loaded image, the SLEIGH engine, the compiler spec, the functions and symbols the console
/// mapped and the read-only ranges. Shared read-only by every [`Funcdata`].
pub struct Arch {
    pub(crate) sleigh: Sleigh,
    pub(crate) image: Image,
    pub(crate) spec: CompilerSpec,
    /// `map function`: entry -> the function
    pub(crate) functions: HashMap<u64, Function>,
    /// the register names, for `Address::printRaw`
    registers: BTreeMap<RegKey, String>,
    /// `<tracked_set>` registers: space, offset, size, value (ActionConstbase)
    pub(crate) tracked: Vec<(u32, u64, u32, u64)>,
    /// the `<incidentalcopy>` registers (space, offset, size): varnodes starting in them are
    /// `incidental_copy` (`Database::setPropertyRange`)
    pub(crate) incidental: Vec<(u32, u64, u32)>,
    /// the laned register records by whole size, smallest first (`Architecture::lanerecords`)
    pub(crate) laned: Vec<transform::LanedRegister>,
    /// ram ranges `[start, end)` with the `readonly` property: the loader's read-only sections
    /// (`fillinReadOnlyFromLoader`) and the console's `readonly` commands
    readonly: Vec<(u64, u64)>,
    /// `map externalref`: the slots holding a reference to an external function
    /// external-reference slots and the address each refers to (`map externalref`)
    externrefs: HashMap<u64, u64>,
    /// `option readonly`: read-only memory propagates as constants (`readonlypropagate`)
    pub(crate) readonly_propagate: bool,
    /// the program-wide data-types (`Architecture::types`): the core types and those `parse
    /// line` defines; each decompile starts from a copy
    pub(crate) types: types::TypeFactory,
}

impl Arch {
    /// An architecture for `image` decoded by `sleigh`, with the compiler spec `cspec` (the
    /// text of a `.cspec` file).
    pub fn new(sleigh: Sleigh, image: Image, cspec: &str) -> Result<Arch> {
        let mut syms = sleigh.varnode_syms();
        // SymbolTree iterates by name, and the first name wins for a shared varnode
        syms.sort_by(|a, b| a.0.cmp(b.0));
        let mut registers = BTreeMap::new();
        for (name, space, off, size) in &syms {
            registers.entry((*space, *off, std::cmp::Reverse(*size))).or_insert_with(|| name.to_string());
        }
        let names = SleighNames::new(&sleigh);
        let tracked = sleigh
            .tracked
            .iter()
            .map(|(name, val)| names.register(name).map(|(s, o, z)| (s, o, z, u64::from(*val))))
            .collect::<Result<_>>()?;
        let spec = CompilerSpec::parse(cspec, &sleigh, &names)?;
        let mut type_factory = types::TypeFactory::new();
        if let Some(m) = &spec.align_map {
            type_factory.align_map = m.clone();
        }
        let incidental = sleigh.incidental.iter().map(|n| names.register(n)).collect::<Result<_>>()?;
        if sleigh.big_endian {
            // the ported rules, heritage and lane division leave out the big-endian arithmetic
            return err("the decompiler does not support big-endian processors yet");
        }
        let laned = laned_records(&sleigh, &names)?;
        let readonly = image
            .sections
            .iter()
            .filter(|s| s.readonly)
            .map(|s| (u64::from(s.addr), u64::from(s.addr) + loaded_len(s) as u64))
            .collect();
        Ok(Arch {
            sleigh,
            image,
            spec,
            functions: HashMap::new(),
            registers,
            tracked,
            incidental,
            laned,
            readonly,
            externrefs: HashMap::new(),
            readonly_propagate: false,
            types: type_factory,
        })
    }

    /// `TypeFactory::getSizeOfPointer`: the size of the default code space's addresses.
    pub(crate) fn pointer_size(&self) -> u32 {
        self.sleigh.spaces.get(self.sleigh.code_space() as usize).map_or(4, |s| s.size)
    }

    /// `map function`: a function at `entry` with the default (empty) prototype.
    /// The locked prototype of the function at `entry` (`parse line extern`), which a decompile
    /// starts from; an unlocked one starts fresh, as every corpus script decompiles once.
    pub(crate) fn function_proto(&self, entry: u64) -> Option<FuncProto> {
        self.functions.get(&entry).filter(|f| f.proto.locked.is_some()).map(|f| f.proto.clone())
    }

    pub(crate) fn add_function(&mut self, entry: u64, name: String) {
        self.functions.insert(entry, Function { name, proto: FuncProto::default() });
    }

    /// `map externalref <slot> ...`
    pub(crate) fn add_externref(&mut self, slot: u64, target: u64) {
        self.externrefs.insert(slot, target);
    }

    /// The address an external-reference slot refers to (`queryExternalRefFunction`).
    pub(crate) fn externref_target(&self, slot: u64) -> Option<u64> {
        self.externrefs.get(&slot).copied()
    }

    /// `readonly <addr>:<size>` (`Database::setPropertyRange(readonly, ...)`).
    pub(crate) fn add_readonly(&mut self, start: u64, size: u64) {
        self.readonly.push((start, start + size));
    }

    /// `fixup apply <fixup> <function>` (`IfcFixupApply`): calls to the function at `entry`
    /// become the call fixup's p-code.
    pub(crate) fn apply_fixup(&mut self, fixup: &str, entry: u64) -> Result<()> {
        let id =
            self.spec.injects.callfixup_id(fixup).ok_or_else(|| LowlevelError(format!("Unknown fixup: {fixup}")))?;
        let f = self.functions.get_mut(&entry).ok_or_else(|| LowlevelError(format!("no function at 0x{entry:x}")))?;
        f.proto.inject = Some(id);
        Ok(())
    }

    /// Whether a ram varnode at `off` of `size` bytes is read-only, as `Funcdata::newVarnode`
    /// flags it (`Scope::queryProperties`): the property of its first byte, unless an
    /// external-reference symbol contains it (`ScopeInternal::addExternalRef` clears its
    /// read-only flag). A function symbol containing it gives the same answer as the property:
    /// its flags are the property at its entry, and being 1 byte long it contains only a 1-byte
    /// varnode at that entry.
    pub(crate) fn is_readonly(&self, off: u64, size: u32) -> bool {
        let end = off + u64::from(size);
        let in_externref = (off.saturating_sub(EXTERNREF_SIZE - 1)..=off)
            .any(|slot| self.externrefs.contains_key(&slot) && end <= slot + EXTERNREF_SIZE);
        !in_externref && self.readonly.iter().any(|&(s, e)| s <= off && off < e)
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

    /// Port of `LoadImageBfd::loadFill`: `buf.len()` bytes from `addr`, which must be loaded;
    /// past it the read goes on into later sections, and bytes no section holds are zero.
    /// `None` when `addr` itself is not loaded (`DataUnavailError`).
    pub(crate) fn fill_bytes(&self, addr: u64, buf: &mut [u8]) -> Option<()> {
        let byte = |a: u64| {
            let a = u32::try_from(a).ok()?;
            let s = self.image.sections.iter().find(|s| s.addr <= a && ((a - s.addr) as usize) < loaded_len(s))?;
            s.data.get((a - s.addr) as usize).copied()
        };
        buf[0] = byte(addr)?;
        for (i, b) in buf.iter_mut().enumerate().skip(1) {
            *b = byte(addr + i as u64).unwrap_or(0);
        }
        Some(())
    }

    /// The bytes of the loaded image from `addr` on, as the instruction decoder reads them.
    pub(crate) fn bytes_at(&self, addr: u64) -> Option<&[u8]> {
        let a = u32::try_from(addr).ok()?;
        let sec = self.image.block_of(a)?;
        sec.data.get((a - sec.addr) as usize..)
    }
}

/// The laned register records (`Architecture::decodeRegisterData` part): each `.pspec`
/// register with `vector_lane_sizes` adds its lane sizes to the record of its size.
fn laned_records(sleigh: &Sleigh, names: &SleighNames) -> Result<Vec<transform::LanedRegister>> {
    let mut by_size: BTreeMap<u32, u32> = BTreeMap::new();
    for (name, sizes) in &sleigh.laned {
        let (_, _, size) = names.register(name)?;
        if sizes.is_empty() {
            continue; // `Architecture::decodeRegisterData` skips an empty attribute
        }
        let reg = transform::LanedRegister::parse(size, sizes)?;
        *by_size.entry(size).or_default() |= reg.mask;
    }
    Ok(by_size.into_iter().map(|(whole_size, mask)| transform::LanedRegister { whole_size, mask }).collect())
}

/// Port of `IfcParseLine` (`parse_C`): a C declaration. Types (`struct`, `union`, `enum`,
/// `typedef`) join the architecture's types; an `extern` function declaration locks the prototype
/// of the function `find` names (`FuncProto::setPieces`).
pub fn parse_line(arch: &mut Arch, text: &str, find: &dyn Fn(&str) -> Option<u64>) -> Result<()> {
    let ptr_size = arch.spec.stack_pointer.2;
    match cparse::parse_line(&mut arch.types, text, ptr_size)? {
        cparse::Decl::Type(_) => Ok(()),
        cparse::Decl::Function { name, model, output, inputs, dotdotdot } => {
            let addr = find(&name).ok_or_else(|| LowlevelError(format!("Unknown function name: {name}")))?;
            let proto = locked::lock_prototype(arch, model.as_deref(), (String::new(), output), inputs, dotdotdot)?;
            match arch.functions.get_mut(&addr) {
                Some(f) => f.proto = proto,
                None => return err(format!("Unknown function name: {name}")),
            }
            Ok(())
        }
    }
}
