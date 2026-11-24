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
mod blocktransform;
mod cast;
mod collapse;
mod comment;
mod condconst;
mod condexe;
mod coreaction;
mod cover;
mod cparse;
mod cspec;
mod emulate;
mod facts;
mod finalstructure;
mod flow;
mod fspec;
mod funcdata;
mod heritage;
mod heritage_guard;
mod infertypes;
mod inject;
mod jumptable;
mod lanedivide;
mod lateres;
mod locked;
mod mapstate;
mod merge;
mod namevars;
mod nodejoin;
mod op;
mod opcode;
mod prettyprint;
mod print;
mod printc;
mod printlanguage;
mod rangemap;
mod rangeutil;
mod readers;
mod returnsplit;
mod rules;
mod scope;
mod splitflow;
mod stdsort;
mod structure;
mod subfloat;
mod subflow;
mod transform;
mod types;
mod userop;
mod valueset;
mod variable;
mod varmap;
mod varnode;

use crate::analysis::Image;
use crate::sleigh::Sleigh;
use cspec::{CompilerSpec, SleighNames};
use fspec::FuncProto;
use std::collections::{BTreeMap, HashMap};

pub use funcdata::Funcdata;
pub(crate) use infertypes::symbol_types;
pub(crate) use inject::callfixup_pcode;
pub use print::print_raw;
pub(crate) use printc::is_string;
pub use printc::print_c;

/// `print map` (`IfcPrintMap` without a name): the bounds and symbols of the local scope.
pub fn print_map(fd: &Funcdata, arch: &Arch, name: &str) -> std::result::Result<String, LowlevelError> {
    scope::print_map(fd, arch, name)
}

/// `Funcdata::printBlockTree` (`print tree block`): the structured hierarchy, empty before
/// `ActionBlockStructure` ran. Fails as `printCaseExtra` of the reference patch does.
pub fn print_block_tree(fd: &Funcdata) -> std::result::Result<String, LowlevelError> {
    fd.structure.print_tree(fd)
}

/// Port of `LowlevelError` (error.hh): a decompilation that cannot go on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LowlevelError(pub String);

impl LowlevelError {
    /// The error comes from a path ghidra-rs does not port (its text says so), not from the
    /// decompiled code: the reference would not fail there.
    pub(crate) fn is_unported(&self) -> bool {
        ["not implemented", "not ported", "is not supported"].iter().any(|m| self.0.contains(m))
    }
}

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
    /// `FunctionSymbol::consumeSize`: the bytes its symbol covers from the entry (1, or with the
    /// facts the function's size when it is 2 to 8)
    pub(crate) consume: u32,
}

/// The program-wide state a decompilation reads (the parts of C++ `Architecture` used so far):
/// the loaded image, the SLEIGH engine, the compiler spec, the functions and symbols the console
/// mapped and the read-only ranges. Shared read-only by every [`Funcdata`].
pub struct Arch {
    pub(crate) sleigh: Sleigh,
    pub(crate) image: Image,
    pub(crate) spec: CompilerSpec,
    /// the segment and jump-assist user ops of the specs (`Architecture::userops`)
    pub(crate) userops: userop::UserOps,
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
    /// the names `map externalref` gives its slots (`ExternRefSymbol`; without one the symbol
    /// is named after the address it refers to)
    externref_names: HashMap<u64, String>,
    /// `option readonly`: read-only memory propagates as constants (`readonlypropagate`)
    pub(crate) readonly_propagate: bool,
    /// `option nanignore all`: every FLOAT_NAN is taken as false (`nan_ignore_all`)
    pub(crate) nan_ignore_all: bool,
    /// the program-wide data-types (`Architecture::types`): the core types and those `parse
    /// line` defines; each decompile starts from a copy
    pub(crate) types: types::TypeFactory,
    /// `load facts` (stage S10): the facts of a Ghidra program, which stand in for the Java
    /// side of Ghidra's decompiler (names, data symbols, prototypes, memory properties)
    pub(crate) facts: Option<Box<facts::Facts>>,
}

impl Arch {
    /// `load facts <file>`: from here on the program is what the facts say, as Java Ghidra
    /// tells its decompiler: Ghidra's core types replace the console's, the functions and
    /// external references are the listing's, and read-only memory is the listing's too.
    pub fn load_facts(&mut self, text: String) -> Result<()> {
        let f = facts::Facts::load(self, text)?;
        self.facts = Some(Box::new(f));
        Ok(())
    }

    /// What a decompile of `fd` starts from with facts (`Funcdata::decode` of the function's
    /// record and the queries Java answers for it): its prototype, the names recommended for
    /// its variables, the listing's comments, and the tracked registers at its entry
    /// (`ContextGhidra::getTrackedSet`), which replace the processor spec's. Nothing without
    /// facts.
    pub fn start_function(&mut self, fd: &mut Funcdata) -> Result<()> {
        let Some(facts) = &self.facts else { return Ok(()) };
        let f = facts.function(self, &mut fd.types, fd.entry, true)?;
        fd.proto = f.proto;
        fd.name_recs = f.name_recs;
        fd.listing_comments = facts.comments(fd.entry)?;
        self.tracked = facts.tracked(self, fd.entry)?;
        Ok(())
    }

    /// Whether a data symbol of the facts holds the whole of `size` bytes at `off`
    /// (`Scope::queryContainer`): such a varnode is linked to the symbol when it is made, every
    /// data symbol Java Ghidra sends being type-locked.
    pub(crate) fn data_holds(&self, off: u64, size: u32) -> bool {
        let range = self.facts.as_ref().and_then(|f| f.data_range(off));
        range.is_some_and(|(first, len)| off + u64::from(size) <= first + len)
    }

    /// The prototype a call to the function at `entry` starts from (`Scope::queryFunction`
    /// and its `FuncProto`), none without a function there. With facts it is decoded from the
    /// function's record, its data-types into `types`.
    pub(crate) fn callee_proto(&self, types: &mut types::TypeFactory, entry: u64) -> Result<Option<FuncProto>> {
        let Some(f) = self.functions.get(&entry) else { return Ok(None) };
        match &self.facts {
            Some(facts) => Ok(Some(facts.function(self, types, entry, false)?.proto)),
            None => Ok(Some(f.proto.clone())),
        }
    }

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
        // `parseProcessorConfig` (the `.pspec` user ops), then `parseCompilerConfig`
        let mut userops = userop::UserOps::default();
        for el in &sleigh.userop_specs {
            userops.decode(el, &sleigh, &names)?;
        }
        let spec = CompilerSpec::parse(cspec, &sleigh, &names, &mut userops)?;
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
            userops,
            functions: HashMap::new(),
            registers,
            tracked,
            incidental,
            laned,
            readonly,
            externrefs: HashMap::new(),
            externref_names: HashMap::new(),
            readonly_propagate: false,
            nan_ignore_all: false,
            types: type_factory,
            facts: None,
        })
    }

    /// `TypeFactory::getSizeOfPointer`: the size of the default code space's addresses.
    pub(crate) fn pointer_size(&self) -> u32 {
        self.sleigh.spaces.get(self.sleigh.code_space() as usize).map_or(4, |s| s.size)
    }

    /// The space the stack lives in and, when that space has a segment op, the op's base size
    /// and the space's address size (`Funcdata::createStackRef` wraps a stack address in a
    /// SEGMENTOP there).
    pub(crate) fn stack_segment(&self) -> (u32, Option<(u32, u32)>) {
        let ram = self.spec.stack_container;
        let size = self.sleigh.spaces.get(ram as usize).map_or(0, |s| s.size);
        (ram, self.userops.segment_op(ram).map(|s| (s.base_size, size)))
    }

    /// Fails loudly for `what` when a spec declares a segment op: near and far pointers are not
    /// ported (`SegmentedResolver` behind `Architecture::resolveConstant`, `markNearPointers`,
    /// and `TypeFactory`'s `sizeOfPointer` / `sizeOfAltPointer` with the far-pointer rules of
    /// PIECE and SUBPIECE), so types and constant pointers would differ silently.
    pub(crate) fn no_segment_resolver(&self, what: &str) -> Result<()> {
        match self.userops.segment_ops().next() {
            Some(s) => err(format!(
                "{what} with the segment op {}: near and far pointers are not implemented in ghidra-rs yet",
                s.name
            )),
            None => Ok(()),
        }
    }

    /// Fails loudly when the stack space is narrower than the space it lives in (16-bit x86: a
    /// 2-byte `SP` in the 4-byte `ram`): stack offsets wrap and print at the container's size
    /// here, where the C++ `SpacebaseSpace` has the stack pointer's.
    pub(crate) fn no_narrow_stack(&self) -> Result<()> {
        let (sp, container) = (self.spec.stack_pointer.2, self.stack_segment().0);
        match self.sleigh.spaces.get(container as usize) {
            Some(s) if s.size != sp => err(format!(
                "a stack space of {sp} bytes inside the {}-byte space {} is not implemented in ghidra-rs yet",
                s.size, s.name
            )),
            _ => Ok(()),
        }
    }

    /// `map function`: a function at `entry` with the default (empty) prototype.
    /// The locked prototype of the function at `entry` (`parse line extern`), which a decompile
    /// starts from; an unlocked one starts fresh, as every corpus script decompiles once.
    pub(crate) fn function_proto(&self, entry: u64) -> Option<FuncProto> {
        self.functions.get(&entry).filter(|f| f.proto.locked.is_some()).map(|f| f.proto.clone())
    }

    /// The name of the function at `entry`, if one is mapped there.
    pub fn function_name(&self, entry: u64) -> Option<&str> {
        self.functions.get(&entry).map(|f| f.name.as_str())
    }

    pub(crate) fn add_function(&mut self, entry: u64, name: String) {
        // Funcdata's constructor gives its prototype the default model (`FuncProto::setScope`,
        // fspec.cc:3874-3880), and with it the model's extrapop (x86-64-gcc.cspec's 8), which
        // `isCompatible` compares when an indirect call is resolved to this function
        let mut proto = FuncProto::default();
        proto.set_model(&self.spec.models, self.spec.models.default);
        self.functions.insert(entry, Function { name, proto, consume: 1 });
    }

    /// `map externalref <slot> ...`
    pub(crate) fn add_externref(&mut self, slot: u64, target: u64) {
        self.externrefs.insert(slot, target);
    }

    /// The name `map externalref <slot> <refaddr> <name>` gives the slot's symbol.
    pub(crate) fn name_externref(&mut self, slot: u64, name: String) {
        self.externref_names.insert(slot, name);
    }

    /// The name given to the symbol of an external-reference slot, if any.
    pub(crate) fn externref_name(&self, slot: u64) -> Option<&str> {
        self.externref_names.get(&slot).map(String::as_str)
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

    /// Size of an external-reference symbol: a pointer (`ExternRefSymbol::buildNameType`).
    pub(crate) fn externref_size(&self) -> u32 {
        self.spec.stack_pointer.2
    }

    /// Whether a ram varnode at `off` of `size` bytes is read-only, as `Funcdata::newVarnode`
    /// flags it (`Scope::queryProperties`): the property of its first byte, unless an
    /// external-reference symbol contains it (`ScopeInternal::addExternalRef` clears its
    /// read-only flag). A function symbol containing it gives the same answer as the property:
    /// its flags are the property at its entry, and being 1 byte long it contains only a 1-byte
    /// varnode at that entry.
    pub(crate) fn is_readonly(&self, off: u64, size: u32) -> bool {
        let end = off + u64::from(size);
        let ptr = u64::from(self.externref_size());
        let in_externref =
            (off.saturating_sub(ptr - 1)..=off).any(|slot| self.externrefs.contains_key(&slot) && end <= slot + ptr);
        if let Some(facts) = &self.facts {
            return !in_externref && facts.readonly(off);
        }
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

    /// `SleighBase::getExactRegisterName` as a test: a register is exactly this range.
    pub(crate) fn exact_register(&self, space: u32, off: u64, size: u32) -> bool {
        self.registers.contains_key(&(space, off, std::cmp::Reverse(size)))
    }

    /// Port of `LoadImageBfd::loadFill`: `buf.len()` bytes from `addr`, which must be loaded;
    /// past it the read goes on into later sections, and bytes no section holds are zero.
    /// `None` when `addr` itself is not loaded (`DataUnavailError`).
    pub(crate) fn fill_bytes(&self, addr: u64, buf: &mut [u8]) -> Option<()> {
        let byte = |a: u64| {
            let a = u32::try_from(a).ok()?;
            // ELF: bfd reads a section without contents (`.bss`) as zeros (LoadImageBfd::loadFill)
            let len = |s: &crate::analysis::Section| if self.image.elf64 { s.data.len() } else { loaded_len(s) };
            let s = self.image.sections.iter().find(|s| s.addr <= a && ((a - s.addr) as usize) < len(s))?;
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
