//! Prototypes (port of the parts of `fspec.cc` the actions up to `heritage` use): the `.cspec`
//! prototype models (`ProtoModel`, `ParamListStandard`, `ParamEntry`, `EffectRecord`), merged
//! models (`ProtoModelMerged`, `<resolveprototype>`), a function's prototype (`FuncProto`) and
//! a call site's (`FuncCallSpecs`).
//!
//! The console decompiler never locks a prototype (it has no `parse line` types yet), so the
//! locked-parameter paths of the actions are not ported; the models' effect lists and parameter
//! entries are read in full, since heritage (stage S2) and parameter recovery (S4) query them.

use super::cspec::SleighNames;
use super::inject::InjectId;
use super::op::OpId;
use super::varnode::Space;
use super::{err, Arch, LowlevelError, Result};
use crate::xml::Element;

/// Index of a model in [`Models::list`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ModelId(pub(crate) u32);

/// `ProtoModel::extrapop`: how far a call moves the stack pointer, beyond popping the return
/// address (`extrapop_unknown` when the callee decides, as with `__stdcall`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum ExtraPop {
    #[default]
    Unknown,
    Known(i32),
}

/// Where a parameter or an effect lives (the `Address` + size of a `<register>`, `<varnode>` or
/// `<addr>` element).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Storage {
    /// a range of a SLEIGH space (register, ram)
    Space { space: u32, offset: u64, size: u32 },
    /// an offset into the `stack` space, relative to the stack pointer on entry
    Stack { offset: u64, size: u32 },
    /// a `join` of pieces, most significant first (`<addr space="join" piece1=.. piece2=..>`)
    Join(Vec<(u32, u64, u32)>),
}

impl Storage {
    /// `Address::decode` + size: `<register name=..>`, `<varnode space offset size>`,
    /// `<addr space offset [size]>`; a register name or space name is resolved by `regs`.
    pub(crate) fn decode(el: &Element, regs: &SleighNames) -> Result<Storage> {
        if el.name == "register" {
            let (space, offset, size) = regs.register(el.req("name")?)?;
            return Ok(Storage::Space { space, offset, size });
        }
        if el.name != "varnode" && el.name != "addr" {
            return err(format!("<{}>: expected a register, varnode or addr", el.name));
        }
        let size = match el.attr("size") {
            Some(_) => u32::try_from(el.int("size")?).map_err(|_| LowlevelError("bad size".into()))?,
            None => 0,
        };
        match el.req("space")? {
            "join" => {
                let pieces = (1..)
                    .map_while(|i| el.attr(&format!("piece{i}")))
                    .map(|p| regs.register(p))
                    .collect::<Result<Vec<_>>>()?;
                if pieces.is_empty() {
                    return err("join address without pieces");
                }
                Ok(Storage::Join(pieces))
            }
            "stack" => Ok(Storage::Stack { offset: regs.wrap(None, el.int("offset")?), size }),
            name => {
                let space = regs.space(name)?;
                Ok(Storage::Space { space, offset: regs.wrap(Some(space), el.int("offset")?), size })
            }
        }
    }

    /// The key `EffectRecord::compareByAddress` sorts by: space index, then offset. The SLEIGH
    /// spaces come first; `join` follows (made in `Architecture::restoreFromSpec` with `fspec` and
    /// `iop`), then `stack` (made later, in `parseCompilerConfig`).
    fn size(&self) -> u32 {
        match self {
            Storage::Space { size, .. } | Storage::Stack { size, .. } => *size,
            Storage::Join(pieces) => pieces.iter().map(|p| p.2).sum(),
        }
    }

    fn address_key(&self) -> (u32, u64) {
        match self {
            Storage::Space { space, offset, .. } => (*space, *offset),
            Storage::Join(_) => (u32::MAX - 1, 0),
            Storage::Stack { offset, .. } => (u32::MAX, *offset),
        }
    }
}

/// Port of `ParamEntry`: one slot a parameter or return value may occupy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ParamEntry {
    pub(crate) storage: Storage,
    /// `type`: the storage class (`metatype`/`storage` attribute)
    pub(crate) class: TypeClass,
    pub(crate) minsize: i32,
    /// `maxsize`: the size of the slot
    pub(crate) size: i32,
    pub(crate) align: i32,
}

/// `type_class` (`string2typeclass`): which data types a parameter entry takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TypeClass {
    General,
    Float,
    Ptr,
    HiddenRet,
    Vector,
    /// `class1` .. `class4`
    Class(u8),
}

impl TypeClass {
    /// Port of `string2typeclass`.
    fn parse(s: &str) -> Result<TypeClass> {
        Ok(match s {
            "general" => TypeClass::General,
            "float" => TypeClass::Float,
            "ptr" => TypeClass::Ptr,
            "hiddenret" => TypeClass::HiddenRet,
            "vector" => TypeClass::Vector,
            "class1" => TypeClass::Class(1),
            "class2" => TypeClass::Class(2),
            "class3" => TypeClass::Class(3),
            "class4" => TypeClass::Class(4),
            _ => return err(format!("Unknown data-type class: {s}")),
        })
    }
}

impl ParamEntry {
    /// Port of `ParamEntry::decode`. (The `extension` attribute is checked but not kept:
    /// TODO(S4) return recovery reads it, `smallsize_*ext`.)
    fn decode(el: &Element, regs: &SleighNames) -> Result<ParamEntry> {
        for attr in el.attr_names() {
            if !matches!(attr, "minsize" | "maxsize" | "size" | "align" | "metatype" | "storage" | "extension") {
                return err(format!("Unknown <pentry> attribute {attr}"));
            }
        }
        if let Some(ext) = el.attr("extension") {
            if !matches!(ext, "sign" | "zero" | "inttype" | "float" | "none") {
                return err(format!("Bad extension attribute: {ext}"));
            }
        }
        let class = el.attr("metatype").or(el.attr("storage")).map_or(Ok(TypeClass::General), TypeClass::parse)?;
        let num = |name: &str| -> Result<i32> {
            i32::try_from(el.int(name)?).map_err(|_| LowlevelError(format!("<pentry>: {name} out of range")))
        };
        let size = num("maxsize")?;
        let minsize = num("minsize")?;
        let align = match (el.attr("align"), el.attr("size")) {
            (Some(_), _) => num("align")?,
            (None, Some(_)) => num("size")?,
            _ => 0,
        };
        let [addr] = &el.kids[..] else { return err("<pentry> needs exactly one storage element") };
        Ok(ParamEntry {
            storage: Storage::decode(addr, regs)?,
            class,
            minsize,
            size,
            // ParamEntry::decode: an alignment equal to the size means none
            align: if align == size { 0 } else { align },
        })
    }

    /// `isStackSpill`: a stack entry with an alignment (it holds several slots).
    fn is_stack_spill(&self) -> bool {
        matches!(self.storage, Storage::Stack { .. }) && self.align != 0
    }

    /// The entry's space, start and size, as `subsumesDefinition` compares them (a join is
    /// its own space; two joins compare as equal pieces).
    fn range(&self) -> (Option<u32>, u64, u64) {
        let size = self.size as u64;
        match &self.storage {
            Storage::Space { space, offset, .. } => (Some(*space), *offset, size),
            Storage::Stack { offset, .. } => (None, *offset, size),
            Storage::Join(_) => (None, u64::MAX, size),
        }
    }

    /// Port of `ParamEntry::subsumesDefinition`: `other` lies within this entry, same class
    /// (unless this is general) and alignment.
    fn subsumes(&self, other: &ParamEntry) -> bool {
        if self.class != TypeClass::General && other.class != self.class {
            return false;
        }
        let same_space = match (&self.storage, &other.storage) {
            (Storage::Join(a), Storage::Join(b)) => a == b,
            (Storage::Stack { .. }, Storage::Stack { .. }) => true,
            (Storage::Space { space: a, .. }, Storage::Space { space: b, .. }) => a == b,
            _ => false,
        };
        let ((_, base, size), (_, obase, osize)) = (self.range(), other.range());
        same_space
            && obase >= base
            && obase.wrapping_add(osize).wrapping_sub(1) <= base.wrapping_add(size).wrapping_sub(1)
            && self.align == other.align
    }
}

/// Port of `ParamListStandard`: the entries, in order.
#[derive(Debug, Clone, Default)]
pub(crate) struct ParamList {
    pub(crate) entries: Vec<ParamEntry>,
    /// `killedbycall="true"`: a possible output is killed by the call (`autoKilledByCall`)
    pub(crate) killed_by_call: bool,
}

impl ParamList {
    /// Port of `ParamListStandard::decode`: the `<pentry>`s of `<input>`/`<output>`; with
    /// `killedbycall="true"` each entry is also a killed-by-call effect.
    fn decode(el: &Element, regs: &SleighNames, effects: &mut Vec<Effect>) -> Result<ParamList> {
        let entries = el
            .kids
            .iter()
            .map(|k| match k.name.as_str() {
                "pentry" => ParamEntry::decode(k, regs),
                n => err(format!("<{}>: <{n}> is not supported", el.name)),
            })
            .collect::<Result<Vec<_>>>()?;
        if el.flag("killedbycall") {
            effects
                .extend(entries.iter().map(|e| Effect { storage: e.storage.clone(), kind: EffectKind::KilledByCall }));
        }
        Ok(ParamList { entries, killed_by_call: el.flag("killedbycall") })
    }

    /// Port of `ParamListStandard::getSpacebase` (`getStackEntry`): whether the last entry is
    /// a stack spill, the one way parameters reach the stack.
    pub(crate) fn has_stack(&self) -> bool {
        self.entries.last().is_some_and(ParamEntry::is_stack_spill)
    }

    /// Port of `ParamListMerged::foldIn`: an empty list takes `other` whole; else each entry of
    /// `other` is dropped when an entry with the same minimum size contains it, replaces an
    /// entry with the same minimum size it contains, and is appended otherwise.
    fn fold_in(&mut self, other: &ParamList) {
        if self.entries.is_empty() {
            self.entries = other.entries.clone();
            return;
        }
        for op in &other.entries {
            let hit = self.entries.iter().position(|e| e.subsumes(op) || op.subsumes(e));
            match hit {
                Some(i) if self.entries[i].minsize == op.minsize => {
                    if !self.entries[i].subsumes(op) {
                        self.entries[i] = op.clone();
                    }
                }
                _ => self.entries.push(op.clone()),
            }
        }
    }
}

/// `EffectRecord::EffectType`, the kinds the `.cspec` declares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EffectKind {
    Unaffected,
    KilledByCall,
    ReturnAddress,
}

/// Port of `EffectRecord`: what a call does to a storage location.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Effect {
    pub(crate) storage: Storage,
    pub(crate) kind: EffectKind,
}

/// Port of `ProtoModel`, the parts the `.cspec` models use.
#[derive(Debug, Clone)]
pub(crate) struct ProtoModel {
    pub(crate) name: String,
    pub(crate) extrapop: ExtraPop,
    pub(crate) input: ParamList,
    pub(crate) output: ParamList,
    /// sorted by address (`EffectRecord::compareByAddress`)
    pub(crate) effects: Vec<Effect>,
    pub(crate) likelytrash: Vec<Storage>,
}

impl ProtoModel {
    /// Port of `ProtoModel::decode` for a `<prototype>`. `retaddr` is the architecture's
    /// `<returnaddress>`, the model's return-address effect when it declares none.
    pub(crate) fn decode(el: &Element, regs: &SleighNames, retaddr: Option<&Storage>) -> Result<ProtoModel> {
        let name = el.req("name")?.to_string();
        let extrapop = match el.req("extrapop")? {
            "unknown" => ExtraPop::Unknown,
            _ => ExtraPop::Known(
                i32::try_from(el.int("extrapop")?).map_err(|_| LowlevelError("extrapop out of range".into()))?,
            ),
        };
        let mut effects = Vec::new();
        let (mut input, mut output, mut likelytrash) = (ParamList::default(), ParamList::default(), Vec::new());
        let mut saw_retaddr = false;
        for k in &el.kids {
            let mut add = |kind| -> Result<()> {
                for v in &k.kids {
                    effects.push(Effect { storage: Storage::decode(v, regs)?, kind });
                }
                Ok(())
            };
            match k.name.as_str() {
                "input" => input = ParamList::decode(k, regs, &mut effects)?,
                "output" => output = ParamList::decode(k, regs, &mut effects)?,
                "unaffected" => add(EffectKind::Unaffected)?,
                "killedbycall" => add(EffectKind::KilledByCall)?,
                "returnaddress" => {
                    add(EffectKind::ReturnAddress)?;
                    saw_retaddr = true;
                }
                "likelytrash" => {
                    likelytrash = k.kids.iter().map(|v| Storage::decode(v, regs)).collect::<Result<_>>()?;
                }
                n => return err(format!("prototype {name}: <{n}> is not supported")),
            }
        }
        if !saw_retaddr {
            if let Some(r) = retaddr {
                effects.push(Effect { storage: r.clone(), kind: EffectKind::ReturnAddress });
            }
        }
        // stable, as std::sort's result does not matter for distinct addresses
        effects.sort_by_key(|e| e.storage.address_key());
        // VarnodeData::operator<: space, offset, then the larger size first
        likelytrash.sort_by_key(|s: &Storage| (s.address_key(), std::cmp::Reverse(s.size())));
        Ok(ProtoModel { name, extrapop, input, output, effects, likelytrash })
    }

    /// Port of `ProtoModelMerged::decode` + `foldIn`: the models of a `<resolveprototype>`
    /// folded into one (the effects and likely-trash registers they share; extrapop unknown
    /// unless all agree; the input entries of all).
    pub(crate) fn merged(name: &str, members: &[&ProtoModel]) -> Result<ProtoModel> {
        let Some((first, rest)) = members.split_first() else {
            return err(format!("resolveprototype {name}: no models"));
        };
        let mut m = ProtoModel { name: name.to_string(), input: ParamList::default(), ..(*first).clone() };
        m.input.fold_in(&first.input);
        for other in rest {
            m.input.fold_in(&other.input);
            if m.extrapop != other.extrapop {
                m.extrapop = ExtraPop::Unknown;
            }
            m.intersect_effects(&other.effects);
            m.likelytrash.retain(|r| other.likelytrash.contains(r));
        }
        Ok(m)
    }

    /// Port of `ProtoModelMerged::intersectEffects`: keep the effects both sorted lists have.
    fn intersect_effects(&mut self, other: &[Effect]) {
        let mine = std::mem::take(&mut self.effects);
        let (mut i, mut j) = (0, 0);
        while let (Some(a), Some(b)) = (mine.get(i), other.get(j)) {
            match a.storage.address_key().cmp(&b.storage.address_key()) {
                std::cmp::Ordering::Less => i += 1,
                std::cmp::Ordering::Greater => j += 1,
                std::cmp::Ordering::Equal => {
                    if a == b {
                        self.effects.push(a.clone());
                    }
                    i += 1;
                    j += 1;
                }
            }
        }
    }
}

/// The architecture's prototype models (the model part of C++ `Architecture`).
#[derive(Debug)]
pub(crate) struct Models {
    pub(crate) list: Vec<ProtoModel>,
    /// `defaultfp`: `<default_proto>`
    pub(crate) default: ModelId,
    /// `evalfp_current`: `<eval_current_prototype>`, for the function being decompiled
    pub(crate) eval_current: Option<ModelId>,
    /// `evalfp_called`: `<eval_called_prototype>`, for the functions it calls
    pub(crate) eval_called: Option<ModelId>,
}

impl Models {
    pub(crate) fn get(&self, id: ModelId) -> &ProtoModel {
        &self.list[id.0 as usize]
    }

    /// Port of `Architecture::getModel`.
    pub(crate) fn find(&self, name: &str) -> Result<ModelId> {
        self.list
            .iter()
            .position(|m| m.name == name)
            .map(|i| ModelId(i as u32))
            .ok_or_else(|| LowlevelError(format!("Missing prototype model: {name}")))
    }
}

/// Port of `FuncProto`, the fields the actions up to `heritage` read.
#[derive(Debug, Clone, Default)]
pub(crate) struct FuncProto {
    /// `model`: none until `ActionDefaultParams` (a call site) or `ActionPrototypeTypes`
    /// (the function itself) sets one
    pub(crate) model: Option<ModelId>,
    pub(crate) extrapop: ExtraPop,
    /// `modellock`
    pub(crate) model_locked: bool,
    /// `injectid` (with `is_inline`): the call fixup applied in place of a call to this function
    pub(crate) inject: Option<InjectId>,
}

impl FuncProto {
    /// Port of `FuncProto::setModel`: the model and its extrapop, except that a model replacing
    /// another does not overwrite the extrapop with unknown.
    pub(crate) fn set_model(&mut self, models: &Models, id: ModelId) {
        let pop = models.get(id).extrapop;
        if self.model.is_none() || pop != ExtraPop::Unknown {
            self.extrapop = pop;
        }
        self.model = Some(id);
    }

    /// Port of `FuncProto::hasMatchingModel`.
    pub(crate) fn has_matching_model(&self, id: ModelId) -> bool {
        self.model == Some(id)
    }

    /// Port of `FuncProto::copyFlowEffects`: what flow needs before the full copy (the
    /// inject id; no-return comes with prototypes that can say so).
    pub(crate) fn copy_flow_effects(&mut self, other: &FuncProto) {
        self.inject = other.inject;
    }

    /// Port of `FuncProto::copy`: this prototype becomes `other`'s (the call site's own fields
    /// live in `CallSpec`, outside the prototype, so they are kept).
    pub(crate) fn copy(&mut self, other: &FuncProto) {
        *self = other.clone();
    }
}

/// Port of `FuncCallSpecs`: one call site and the prototype it is analyzed with.
#[derive(Debug, Clone)]
pub(crate) struct CallSpec {
    pub(crate) op: OpId,
    /// the called address of a direct call
    pub(crate) entry: Option<u64>,
    /// whether the scope knows a function at `entry` (`setFuncdata`); its name is in
    /// `Arch::functions`
    pub(crate) known: bool,
    pub(crate) proto: FuncProto,
    /// the CALL's input slot holding the stack-pointer placeholder (`stackPlaceholderSlot`)
    pub(crate) stack_placeholder_slot: Option<usize>,
    /// the parameter trials (`activeinput`, `isinputactive`), from `ActionFuncLink` on
    pub(crate) active_input: Option<ParamActive>,
    /// the return-value trials (`activeoutput`, `isoutputactive`), from `ActionFuncLink` on
    pub(crate) active_output: Option<ParamActive>,
}

impl CallSpec {
    /// A call site before analysis (the `FuncCallSpecs` constructor).
    pub(crate) fn new(op: OpId, entry: Option<u64>, known: bool) -> CallSpec {
        CallSpec {
            op,
            entry,
            known,
            proto: FuncProto::default(),
            stack_placeholder_slot: None,
            active_input: None,
            active_output: None,
        }
    }

    /// The callee's entry when the scope knows a function there (`getFuncdata`).
    pub(crate) fn callee(&self) -> Option<u64> {
        self.entry.filter(|_| self.known)
    }
}

/// `ParamEntry::no_containment` .. `contained_by`: how a storage range relates to the
/// parameter entries of a list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Containment {
    None,
    /// an entry contains the range, justified at its start
    ContainsJustified,
    /// an entry contains the range, not justified
    ContainsUnjustified,
    /// the range contains an exclusive entry
    ContainedBy,
}

impl ParamList {
    /// Port of `ParamListStandard::characterizeAsParam` for a range of a SLEIGH space (join and
    /// stack entries live in other spaces). The C++ walks a range map; the answer only depends
    /// on which entries overlap, so this scans them.
    pub(crate) fn characterize(&self, space: u32, off: u64, size: u32) -> Containment {
        let (mut contains, mut contained_by) = (false, false);
        let end = off + u64::from(size) - 1;
        for e in &self.entries {
            if let Storage::Join(pieces) = &e.storage {
                // the resolver lists a join entry under each piece; justifiedContain counts the
                // bytes of the less significant pieces it skips (a join is never contained by)
                let mut skipped = 0;
                for &(s, base, psize) in pieces.iter().rev() {
                    if s == space && base <= off && end < base + u64::from(psize) {
                        if skipped + off - base == 0 {
                            return Containment::ContainsJustified;
                        }
                        contains = true;
                        break;
                    }
                    skipped += u64::from(psize);
                }
                continue;
            }
            let Storage::Space { space: s, offset: base, .. } = e.storage else { continue };
            let eend = base + e.size as u64 - 1;
            if s != space || eend < off || base > end {
                continue;
            }
            // justifiedContain, little endian and alignment 0 (register entries)
            if e.align == 0 && base <= off && end <= eend {
                if off == base {
                    return Containment::ContainsJustified;
                }
                contains = true;
            }
            // isExclusion && containedBy
            if e.align == 0 && base >= off && eend <= end {
                contained_by = true;
            }
        }
        if contains {
            Containment::ContainsUnjustified
        } else if contained_by {
            Containment::ContainedBy
        } else {
            Containment::None
        }
    }
}

impl ProtoModel {
    /// Port of `ProtoModel::lookupEffect` for a range of a SLEIGH space: the effect of the
    /// last record at or before the range when it holds the whole range, else unknown (`None`).
    /// `uniq` is the unique space, always local to the function.
    pub(crate) fn lookup_effect(&self, uniq: u32, space: u32, off: u64, size: u32) -> Option<EffectKind> {
        if space == uniq {
            return Some(EffectKind::Unaffected);
        }
        let at = self.effects.partition_point(|e| e.storage.address_key() <= (space, off));
        let e = self.effects.get(at.checked_sub(1)?)?;
        let Storage::Space { space: s, offset: hit, size: sz } = e.storage else { return None };
        if sz == 0 && s == space {
            return Some(EffectKind::Unaffected);
        }
        let dist = off.checked_sub(hit).filter(|_| s == space)?;
        (dist + u64::from(size) <= u64::from(sz)).then_some(e.kind)
    }
}

/// Port of the trial list of `ParamActive`: the storage ranges seen as possible parameters or
/// return values. Stage S4 analyzes them; heritage only registers them.
#[derive(Debug, Clone, Default)]
pub(crate) struct ParamActive {
    trials: Vec<(Space, u64, u32)>,
}

impl ParamActive {
    /// Port of `ParamActive::whichTrial` (as a test): a trial at exactly this range.
    pub(crate) fn has_trial(&self, space: Space, off: u64, size: u32) -> bool {
        self.trials.contains(&(space, off, size))
    }
    /// Port of `ParamActive::registerTrial`.
    pub(crate) fn register_trial(&mut self, space: Space, off: u64, size: u32) {
        self.trials.push((space, off, size));
    }
}

impl FuncProto {
    /// Port of `FuncProto::hasEffect` (an unlocked prototype has no effect list of its own, so
    /// the model's): `None` is `unknown_effect`.
    pub(crate) fn has_effect(&self, arch: &Arch, space: Space, off: u64, size: u32) -> Option<EffectKind> {
        let Space::Sleigh(s) = space else { return None };
        self.model_of(arch)?.lookup_effect(arch.sleigh.uniq_space(), s, off, size)
    }

    /// The model of an unlocked prototype, as `characterizeAs*` read it.
    fn model_of<'a>(&self, arch: &'a Arch) -> Option<&'a ProtoModel> {
        self.model.map(|m| arch.spec.models.get(m))
    }

    /// Port of `FuncProto::characterizeAsOutput` for an unlocked prototype.
    pub(crate) fn characterize_as_output(&self, arch: &Arch, space: Space, off: u64, size: u32) -> Containment {
        match (self.model_of(arch), space) {
            (Some(m), Space::Sleigh(s)) => m.output.characterize(s, off, size),
            _ => Containment::None,
        }
    }

    /// Port of `FuncProto::characterizeAsInputParam` for an unlocked prototype.
    pub(crate) fn characterize_as_input(&self, arch: &Arch, space: Space, off: u64, size: u32) -> Containment {
        match (self.model_of(arch), space) {
            (Some(m), Space::Sleigh(s)) => m.input.characterize(s, off, size),
            _ => Containment::None,
        }
    }

    /// Port of `FuncProto::isAutoKilledByCall`.
    pub(crate) fn is_auto_killed_by_call(&self, arch: &Arch) -> bool {
        self.model_of(arch).is_some_and(|m| m.output.killed_by_call)
    }
}
