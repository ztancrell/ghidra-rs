//! Prototypes (port of the parts of `fspec.cc` the actions up to `heritage` use): the `.cspec`
//! prototype models (`ProtoModel`, `ParamListStandard`, `ParamEntry`, `EffectRecord`), merged
//! models (`ProtoModelMerged`, `<resolveprototype>`), a function's prototype (`FuncProto`) and
//! a call site's (`FuncCallSpecs`).
//!
//! Superseded: `parse line extern` locks prototypes since stage S6 (`locked.rs`). Before it
//! the console decompiler never locked a prototype (no `parse line` types yet), so the
//! locked-parameter paths of the actions are not ported; the models' effect lists and parameter
//! entries are read in full, since heritage (stage S2) and parameter recovery (S4) query them.

use super::cspec::SleighNames;
use super::inject::InjectId;
use super::op::OpId;
use super::types::TypeId;
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
    /// Port of `ParamListStandard::getMaxDelay`: the largest heritage delay of the entries'
    /// spaces (the stack's is 1, the register space's 0; x86 entries live in no other).
    pub(crate) fn max_delay(&self) -> i32 {
        i32::from(self.entries.iter().any(|e| matches!(e.storage, Storage::Stack { .. })))
    }

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
    /// `ProtoModelMerged::modellist`: the models a `<resolveprototype>` chooses among, in its
    /// order; empty for a plain model
    pub(crate) members: Vec<ModelId>,
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
        Ok(ProtoModel { name, extrapop, input, output, effects, likelytrash, members: Vec::new() })
    }

    /// Port of `ProtoModelMerged::decode` + `foldIn`: the models of a `<resolveprototype>`
    /// folded into one (the effects and likely-trash registers they share; extrapop unknown
    /// unless all agree; the input entries of all).
    pub(crate) fn merged(name: &str, members: &[&ProtoModel], ids: Vec<ModelId>) -> Result<ProtoModel> {
        let Some((first, rest)) = members.split_first() else {
            return err(format!("resolveprototype {name}: no models"));
        };
        let mut m =
            ProtoModel { name: name.to_string(), input: ParamList::default(), members: ids, ..(*first).clone() };
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
    /// the recovered return storage (`deriveOutputMap`), none until return recovery finishes
    pub(crate) output: Option<(Space, u64, u32)>,
    /// a locked prototype (`parse line extern`, stage S6): inputs, output, model locked
    pub(crate) locked: Option<Box<super::locked::Locked>>,
    /// `returnBytesConsumed`: the bytes of the return value the callers are known to use, 0
    /// for all (a hint to dead code, from `RulePiecePathology`)
    /// The C++ resets it in `clearUnlockedOutput` (a decompile restart); restarts are not
    /// ported, and the reset must come with them.
    pub(crate) return_bytes_consumed: u32,
    /// the return value `ActionOutputPrototype` stores (`ProtoStoreSymbol::outparam`): storage and
    /// data-type; none is `void`. The inputs are the local scope's category-0 symbols.
    pub(crate) out_param: Option<(Space, u64, TypeId)>,
}

impl FuncProto {
    /// Port of `FuncProto::setReturnBytesConsumed`: the value only gets smaller.
    pub(crate) fn set_return_bytes_consumed(&mut self, val: u32) -> bool {
        let smaller = val != 0 && (self.return_bytes_consumed == 0 || val < self.return_bytes_consumed);
        if smaller {
            self.return_bytes_consumed = val;
        }
        smaller
    }

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
    /// `effective_extrapop`, from `ActionStackPtrFlow`
    pub(crate) effective_extrapop: Option<i32>,
    /// `inputConsume`: per input slot of the CALL, the bytes the callee is known to use, 0
    /// for all
    pub(crate) input_consume: Vec<u32>,
}

impl CallSpec {
    /// Port of `FuncCallSpecs::setInputBytesConsumed`: the value only gets smaller.
    pub(crate) fn set_input_bytes_consumed(&mut self, slot: usize, val: u32) -> bool {
        if self.input_consume.len() <= slot {
            self.input_consume.resize(slot + 1, 0);
        }
        let smaller = self.input_consume[slot] == 0 || val < self.input_consume[slot];
        if smaller {
            self.input_consume[slot] = val;
        }
        smaller
    }

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
            effective_extrapop: None,
            input_consume: Vec::new(),
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

/// Port of `ParamTrial`: one storage range seen as a possible parameter or return value.
#[derive(Debug, Clone)]
pub(crate) struct ParamTrial {
    pub(crate) space: Space,
    pub(crate) off: u64,
    pub(crate) size: u32,
    /// the input slot of the call (or RETURN) holding it
    pub(crate) slot: usize,
    pub(crate) flags: u32,
    /// the parameter entry it fits (index into the list) and its justified offset in it
    pub(crate) entry: Option<usize>,
    pub(crate) offset: i32,
}

impl ParamTrial {
    pub(crate) const CHECKED: u32 = 1;
    pub(crate) const USED: u32 = 2;
    pub(crate) const DEFNOUSE: u32 = 4;
    pub(crate) const ACTIVE: u32 = 8;
    pub(crate) const KILLEDBYCALL: u32 = 0x20;
    pub(crate) const REM_FORMED: u32 = 0x40;
    pub(crate) const INDCREATE_FORMED: u32 = 0x80;
    pub(crate) const CONDEXE_EFFECT: u32 = 0x100;
    pub(crate) const ANCESTOR_REALISTIC: u32 = 0x200;
    pub(crate) const ANCESTOR_SOLID: u32 = 0x400;

    pub(crate) fn has(&self, f: u32) -> bool {
        self.flags & f != 0
    }
    pub(crate) fn set(&mut self, f: u32) {
        self.flags |= f;
    }
    pub(crate) fn mark_active(&mut self) {
        self.flags |= Self::ACTIVE | Self::CHECKED;
    }
    pub(crate) fn mark_inactive(&mut self) {
        self.flags &= !Self::ACTIVE;
        self.flags |= Self::CHECKED;
    }
    pub(crate) fn mark_no_use(&mut self) {
        self.flags &= !(Self::ACTIVE | Self::USED);
        self.flags |= Self::CHECKED | Self::DEFNOUSE;
    }
    pub(crate) fn is_used(&self) -> bool {
        self.has(Self::USED)
    }
    pub(crate) fn is_active(&self) -> bool {
        self.has(Self::ACTIVE)
    }
    pub(crate) fn is_checked(&self) -> bool {
        self.has(Self::CHECKED)
    }
}

/// Port of `ParamActive`: the trials of one call (or of the function's returns) and the state
/// of their analysis across passes.
#[derive(Debug, Clone)]
pub(crate) struct ParamActive {
    pub(crate) trials: Vec<ParamTrial>,
    slotbase: usize,
    /// `stackplaceholder`: -1 none, -2 freed
    stackplaceholder: i32,
    pub(crate) numpasses: i32,
    pub(crate) maxpass: i32,
    pub(crate) fully_checked: bool,
}

impl ParamActive {
    /// A trial list with at most `maxdelay` extra passes (`initActiveInput`/`initActiveOutput`:
    /// a list holding a space heritaged late waits 3 passes).
    pub(crate) fn new(maxdelay: i32) -> ParamActive {
        ParamActive {
            trials: Vec::new(),
            slotbase: 1,
            stackplaceholder: -1,
            numpasses: 0,
            maxpass: if maxdelay > 0 { 3 } else { 0 },
            fully_checked: false,
        }
    }

    /// Port of `ParamActive::whichTrial`: the first trial overlapping the range.
    pub(crate) fn which_trial(&self, space: Space, off: u64, size: u32) -> Option<usize> {
        let ov = |a: u64, t: &ParamTrial| t.space == space && a.wrapping_sub(t.off) < u64::from(t.size);
        self.trials.iter().position(|t| ov(off, t) || (size > 1 && ov(off + u64::from(size) - 1, t)))
    }
    pub(crate) fn has_trial(&self, space: Space, off: u64, size: u32) -> bool {
        self.which_trial(space, off, size).is_some()
    }
    /// Port of `ParamActive::registerTrial`: every trial outside the stack is assumed killed by
    /// calls.
    pub(crate) fn register_trial(&mut self, space: Space, off: u64, size: u32) {
        let flags = if space == Space::Stack { 0 } else { ParamTrial::KILLEDBYCALL };
        self.trials.push(ParamTrial { space, off, size, slot: self.slotbase, flags, entry: None, offset: -1 });
        self.slotbase += 1;
    }
    /// `setPlaceholderSlot`.
    pub(crate) fn set_placeholder_slot(&mut self) {
        self.stackplaceholder = self.slotbase as i32;
        self.slotbase += 1;
    }
    /// Port of `ParamActive::freePlaceholderSlot`.
    pub(crate) fn free_placeholder_slot(&mut self) {
        for t in &mut self.trials {
            if t.slot as i32 > self.stackplaceholder {
                t.slot -= 1;
            }
        }
        self.stackplaceholder = -2;
        self.slotbase -= 1;
        self.maxpass = 0;
    }
    /// Port of `ParamActive::deleteUnusedTrials`: the used trials, renumbered from slot 1.
    pub(crate) fn delete_unused_trials(&mut self) {
        self.trials.retain(ParamTrial::is_used);
        for (i, t) in self.trials.iter_mut().enumerate() {
            t.slot = i + 1;
        }
    }
    /// Port of `ParamActive::sortTrials` (`ParamTrial::operator<`): by the entry's group, then
    /// address and size; trials without an entry last. (The C++ `std::sort` on these few
    /// trials is an insertion sort, which keeps ties in order, as this stable sort does.)
    pub(crate) fn sort_trials(&mut self, list: &ParamList) {
        self.trials.sort_by(|a, b| match (a.entry, b.entry) {
            (None, None) => std::cmp::Ordering::Equal,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (Some(_), None) => std::cmp::Ordering::Less,
            (Some(ea), Some(eb)) => list
                .group(ea)
                .cmp(&list.group(eb))
                .then((a.space.index(), a.off).cmp(&(b.space.index(), b.off)))
                .then(a.size.cmp(&b.size)),
        });
    }
}

impl ParamList {
    /// `ParamEntry::getGroup`: an entry's resource group (a join takes the group of the first
    /// earlier entry among its pieces).
    pub(crate) fn group(&self, i: usize) -> usize {
        if let Storage::Join(pieces) = &self.entries[i].storage {
            for &(s, o, z) in pieces {
                if let Some(j) =
                    self.entries[..i].iter().position(|e| e.storage == Storage::Space { space: s, offset: o, size: z })
                {
                    return self.group(j);
                }
            }
        }
        i
    }

    /// `isParamCheckLow`/`isParamCheckHigh` of a join entry: which pieces have an entry of
    /// their own (piece 0, the most significant, sets `extracheck_low`).
    fn param_check(&self, i: usize) -> (bool, bool) {
        let Storage::Join(pieces) = &self.entries[i].storage else { return (false, false) };
        let (mut low, mut high) = (false, false);
        for (k, &(s, o, z)) in pieces.iter().enumerate() {
            if self.entries[..i].iter().any(|e| e.storage == Storage::Space { space: s, offset: o, size: z }) {
                if k == 0 {
                    low = true;
                } else {
                    high = true;
                }
            }
        }
        (low, high)
    }

    /// Port of `ParamEntry::justifiedContain` for register and join entries (little endian,
    /// no alignment): the offset of the range within the entry, or `None`.
    pub(crate) fn justified_contain(&self, i: usize, space: Space, off: u64, size: u32) -> Option<i32> {
        let Space::Sleigh(sp) = space else { return None };
        let contain = |s: u32, base: u64, esize: u64| -> Option<i32> {
            (s == sp && base <= off && off + u64::from(size) <= base + esize).then(|| (off - base) as i32)
        };
        match &self.entries[i].storage {
            Storage::Join(pieces) => {
                let mut res = 0;
                for &(s, o, z) in pieces.iter().rev() {
                    match contain(s, o, u64::from(z)) {
                        Some(cur) => return Some(res + cur),
                        None => res += z as i32,
                    }
                }
                None
            }
            Storage::Space { space: s, offset, .. } if self.entries[i].align == 0 => {
                contain(*s, *offset, self.entries[i].size as u64)
            }
            _ => None,
        }
    }

    /// Port of `ParamListStandardOut::fillinMapFallback` with `firstOnly` false (x86 declares no
    /// model rules, so `fillinMap` falls back): the entry best covered by the active trials
    /// decides which trials are used.
    pub(crate) fn fillin_map_output(&self, active: &mut ParamActive) {
        if active.trials.is_empty() {
            return;
        }
        let mut best: Option<usize> = None;
        let (mut bestcover, mut bestclass) = (0, TypeClass::Ptr.rank());
        for e in 0..self.entries.len() {
            let mut putative = false;
            for t in &mut active.trials {
                t.entry = None;
                t.offset = 0;
                if t.is_active() {
                    if let Some(res) = self.justified_contain(e, t.space, t.off, t.size) {
                        t.entry = Some(e);
                        t.offset = res;
                        putative = true;
                    }
                }
            }
            if !putative {
                continue;
            }
            active.sort_trials(self);
            let (low, high) = self.param_check(e);
            let mut offmatch = 0;
            let mut k = 0;
            while k < active.trials.len() {
                let t = &active.trials[k];
                if t.entry.is_none() {
                    k += 1;
                    continue;
                }
                if offmatch != t.offset {
                    break;
                }
                if ((offmatch == 0 && low) || (offmatch != 0 && high))
                    && (t.has(ParamTrial::REM_FORMED) || t.has(ParamTrial::INDCREATE_FORMED))
                {
                    break;
                }
                offmatch += t.size as i32;
                k += 1;
            }
            if offmatch < self.entries[e].minsize {
                k = 0;
            }
            let class = self.entries[e].class.rank();
            if k == active.trials.len() && (class < bestclass || offmatch > bestcover) {
                best = Some(e);
                bestcover = offmatch;
                bestclass = class;
            }
        }
        match best {
            None => active.trials.iter_mut().for_each(ParamTrial::mark_no_use),
            Some(e) => {
                for t in &mut active.trials {
                    let res = if t.is_active() { self.justified_contain(e, t.space, t.off, t.size) } else { None };
                    match res {
                        Some(r) => {
                            t.set(ParamTrial::USED);
                            t.entry = Some(e);
                            t.offset = r;
                        }
                        None => {
                            t.mark_no_use();
                            t.entry = None;
                            t.offset = 0;
                        }
                    }
                }
                active.sort_trials(self);
            }
        }
    }
}

impl TypeClass {
    /// The `type_class` enum value, as `fillinMapFallback` compares classes.
    fn rank(self) -> u32 {
        match self {
            TypeClass::General => 0,
            TypeClass::Float => 1,
            TypeClass::Ptr => 2,
            TypeClass::HiddenRet => 3,
            TypeClass::Vector => 4,
            TypeClass::Class(n) => 4 + u32::from(n),
        }
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
        if let Some(l) = &self.locked {
            return l.characterize_output(space, off, size);
        }
        match (self.model_of(arch), space) {
            (Some(m), Space::Sleigh(s)) => m.output.characterize(s, off, size),
            _ => Containment::None,
        }
    }

    /// Port of `FuncProto::characterizeAsInputParam` for an unlocked prototype.
    pub(crate) fn characterize_as_input(&self, arch: &Arch, space: Space, off: u64, size: u32) -> Containment {
        if let Some(c) = self.locked.as_ref().and_then(|l| l.characterize_input(space, off, size)) {
            return c;
        }
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

// ---- recovering the function's own inputs (ActionInputPrototype, the tail stage) ----

impl ParamTrial {
    pub(crate) const UNREF: u32 = 0x10;

    fn is_def_no_use(&self) -> bool {
        self.has(Self::DEFNOUSE)
    }
}

impl ParamList {
    /// The entry's base offset when it lives in `space` (a join entry lives in none).
    fn base_in(&self, i: usize, space: Space) -> Option<u64> {
        match (&self.entries[i].storage, space) {
            (Storage::Space { space: s, offset, .. }, Space::Sleigh(sp)) if *s == sp => Some(*offset),
            (Storage::Stack { offset, .. }, Space::Stack) => Some(*offset),
            _ => None,
        }
    }

    /// Port of `ParamEntry::justifiedContain` for a register or stack entry (little endian):
    /// the range's offset in the entry, modulo the alignment of a multi-slot entry.
    fn justified_in(&self, i: usize, space: Space, off: u64, size: u32) -> Option<i32> {
        let e = &self.entries[i];
        let base = self.base_in(i, space)?;
        let end = off.checked_add(u64::from(size))?.checked_sub(1)?;
        if off < base || end > base + e.size as u64 - 1 {
            return None;
        }
        let rel = off - base;
        Some(if e.align == 0 { rel as i32 } else { (rel % e.align as u64) as i32 })
    }

    /// Port of `ParamListStandard::findEntry` with `just` true: the first entry holding the
    /// range justified. (The C++ walks a range map; x86's input entries do not overlap.)
    pub(crate) fn find_entry(&self, space: Space, off: u64, size: u32) -> Option<usize> {
        (0..self.entries.len())
            .find(|&i| self.entries[i].minsize <= size as i32 && self.justified_in(i, space, off, size) == Some(0))
    }

    /// Port of `ParamEntry::getSlot`.
    fn get_slot(&self, i: usize, space: Space, off: u64, skip: u32) -> i32 {
        let e = &self.entries[i];
        let mut res = self.group(i) as i32;
        if e.align != 0 {
            let base = self.base_in(i, space).unwrap_or(0);
            res += (off.wrapping_add(u64::from(skip)).wrapping_sub(base) as i32) / e.align;
        }
        res
    }

    /// Port of `ParamListStandard::possibleParamWithSlot`: the slot and slot count of a range.
    fn possible_param_with_slot(&self, space: Space, off: u64, size: u32) -> Option<(i32, i32)> {
        let i = self.find_entry(space, off, size)?;
        let e = &self.entries[i];
        let slotsize = if e.align == 0 { 1 } else { (size as i32 - 1) / e.align + 1 };
        Some((self.get_slot(i, space, off, 0), slotsize))
    }

    /// `resourceStart` (`parsePentry`): the first group of each run of entries of one storage
    /// class, then the number of groups.
    fn resource_start(&self) -> Vec<usize> {
        let mut res = Vec::new();
        let mut last = None;
        for (i, e) in self.entries.iter().enumerate() {
            if last != Some(e.class) {
                res.push(self.group(i));
                last = Some(e.class);
            }
        }
        res.push(self.entries.len());
        res
    }

    /// The address and size of slot `slot` of entry `i`, as `buildTrialMap` asks
    /// `ParamEntry::getAddrBySlot` for an unreferenced trial (little endian, no reverse stack).
    fn slot_address(&self, i: usize, slot: u64) -> Option<(Space, u64, u32)> {
        let e = &self.entries[i];
        let (sz, step) = if e.align == 0 { (e.size, 0) } else { (e.align, e.align as u64 * slot) };
        match &e.storage {
            Storage::Space { space, offset, .. } => Some((Space::Sleigh(*space), offset + step, sz as u32)),
            Storage::Stack { offset, .. } => Some((Space::Stack, offset + step, sz as u32)),
            Storage::Join(_) => None,
        }
    }

    /// Port of `ParamListStandard::selectUnreferenceEntry`.
    fn select_unreference_entry(&self, grp: usize, pref: TypeClass) -> Option<usize> {
        let mut best = None;
        let mut best_score = -1;
        for i in (0..self.entries.len()).filter(|&i| self.group(i) == grp) {
            let score = if self.entries[i].class == pref {
                2
            } else if pref == TypeClass::General {
                1
            } else {
                0
            };
            if score > best_score {
                best_score = score;
                best = Some(i);
            }
        }
        best
    }

    /// Port of `ParamListStandard::buildTrialMap`: each trial gets its entry (none: not used),
    /// groups and slots before a seen one get unreferenced trials, and the trials are sorted.
    fn build_trial_map(&self, active: &mut ParamActive) {
        let mut hitlist: Vec<Option<usize>> = Vec::new();
        let (mut float_count, mut int_count) = (0, 0);
        for t in &mut active.trials {
            match self.find_entry(t.space, t.off, t.size) {
                None => t.mark_no_use(),
                Some(e) => {
                    t.entry = Some(e);
                    t.offset = 0;
                    if t.is_active() {
                        if self.entries[e].class == TypeClass::Float {
                            float_count += 1;
                        } else {
                            int_count += 1;
                        }
                    }
                    let grp = self.group(e);
                    if hitlist.len() <= grp {
                        hitlist.resize(grp + 1, None);
                    }
                    hitlist[grp].get_or_insert(e);
                }
            }
        }
        for (grp, hit) in hitlist.into_iter().enumerate() {
            let Some(cur) = hit else {
                let pref = if float_count > int_count { TypeClass::Float } else { TypeClass::General };
                let Some(cur) = self.select_unreference_entry(grp, pref) else { continue };
                if let Some((space, off, size)) = self.slot_address(cur, 0) {
                    active.register_unref(space, off, size, cur);
                }
                continue;
            };
            if self.entries[cur].align == 0 {
                continue;
            }
            // holes inside a multi-slot entry
            let mut slots: Vec<bool> = Vec::new();
            for t in active.trials.iter().filter(|t| t.entry == Some(cur)) {
                let grp = self.group(cur) as i32;
                let a = self.get_slot(cur, t.space, t.off, 0) - grp;
                let b = self.get_slot(cur, t.space, t.off, t.size - 1) - grp;
                let (lo, hi) = (a.min(b).max(0) as usize, a.max(b).max(0) as usize);
                if slots.len() <= hi {
                    slots.resize(hi + 1, false);
                }
                slots[lo..=hi].iter_mut().for_each(|s| *s = true);
            }
            for (j, _) in slots.iter().enumerate().filter(|(_, &s)| !s) {
                if let Some((space, off, size)) = self.slot_address(cur, j as u64) {
                    active.register_unref(space, off, size, cur);
                }
            }
        }
        active.sort_trials(self);
    }

    /// Port of `ParamListStandard::separateSections`.
    fn separate_sections(&self, active: &ParamActive, starts: &[usize]) -> Result<Vec<usize>> {
        let mut res = vec![0];
        let mut next_group = starts.get(1).copied().unwrap_or(usize::MAX);
        let mut next_section = 2;
        for (i, t) in active.trials.iter().enumerate() {
            let Some(e) = t.entry else { continue };
            if self.group(e) >= next_group {
                next_group =
                    *starts.get(next_section).ok_or_else(|| LowlevelError("Missing next resource start".into()))?;
                next_section += 1;
                res.push(i);
            }
        }
        res.push(active.trials.len());
        Ok(res)
    }

    /// Port of `ParamListStandard::markGroupNoUse` (an entry has one group here).
    fn mark_group_no_use(&self, active: &mut ParamActive, keep: usize, start: usize) {
        let Some(grp) = active.trials[keep].entry.map(|e| self.group(e)) else { return };
        for i in start..active.trials.len() {
            if i == keep || active.trials[i].is_def_no_use() {
                continue;
            }
            if active.trials[i].entry.map(|e| self.group(e)) != Some(grp) {
                break;
            }
            active.trials[i].mark_no_use();
        }
    }

    /// Port of `ParamListStandard::markBestInactive`.
    fn mark_best_inactive(&self, active: &mut ParamActive, group: usize, start: usize, pref: TypeClass) {
        let mut best = None;
        let mut best_score = -1;
        for i in start..active.trials.len() {
            let t = &active.trials[i];
            if t.is_def_no_use() {
                continue;
            }
            let Some(e) = t.entry else { break };
            if self.group(e) != group {
                break;
            }
            let mut score = 0;
            if t.has(ParamTrial::ANCESTOR_REALISTIC) {
                score += 5;
                if t.has(ParamTrial::ANCESTOR_SOLID) {
                    score += 5;
                }
            }
            if self.entries[e].class == pref {
                score += 1;
            }
            if score > best_score {
                best_score = score;
                best = Some(i);
            }
        }
        if let Some(b) = best {
            self.mark_group_no_use(active, b, start);
        }
    }

    /// Port of `ParamListStandard::forceExclusionGroup`.
    fn force_exclusion_group(&self, active: &mut ParamActive) {
        let mut cur_group = None;
        let mut group_start = 0;
        let mut inactive = 0;
        for i in 0..active.trials.len() {
            let t = &active.trials[i];
            let Some(e) = t.entry.filter(|&e| !t.is_def_no_use() && self.entries[e].align == 0) else { continue };
            let grp = self.group(e);
            if cur_group != Some(grp) {
                if let Some(g) = cur_group.filter(|_| inactive > 1) {
                    self.mark_best_inactive(active, g, group_start, TypeClass::General);
                }
                cur_group = Some(grp);
                group_start = i;
                inactive = 0;
            }
            if active.trials[i].is_active() {
                self.mark_group_no_use(active, i, group_start);
            } else {
                inactive += 1;
            }
        }
        if let Some(g) = cur_group.filter(|_| inactive > 1) {
            self.mark_best_inactive(active, g, group_start, TypeClass::General);
        }
    }

    /// Port of `ParamListStandard::forceNoUse`: once a whole group is definitely not used,
    /// every later trial of the section is inactive.
    fn force_no_use(&self, active: &mut ParamActive, start: usize, stop: usize) {
        let (mut seen, mut all) = (false, false);
        let mut cur_group = -1;
        for t in &mut active.trials[start..stop] {
            let Some(e) = t.entry else { continue };
            let grp = self.group(e) as i32;
            if grp <= cur_group && self.entries[e].align == 0 {
                if !t.is_def_no_use() {
                    all = false;
                }
            } else {
                if all {
                    seen = true;
                }
                all = t.is_def_no_use();
                cur_group = grp;
            }
            if seen {
                t.mark_inactive();
            }
        }
    }

    /// Port of `ParamListStandard::forceInactiveChain` for the function's own inputs (not a
    /// sub-call): a chain of more than `maxchain` inactive slots ends the parameters; inactive
    /// trials before the last active one become active.
    fn force_inactive_chain(
        &self,
        active: &mut ParamActive,
        maxchain: i32,
        start: usize,
        stop: usize,
        group_start: i32,
    ) {
        let slot_group = |t: &ParamTrial| t.entry.map_or(0, |e| self.get_slot(e, t.space, t.off, t.size - 1));
        let (mut seen, mut chain) = (false, 0);
        let mut max = None;
        for i in start..stop {
            if active.trials[i].is_def_no_use() {
                continue;
            }
            if !active.trials[i].is_active() {
                chain += if i == start {
                    slot_group(&active.trials[i]) - group_start + 1
                } else {
                    slot_group(&active.trials[i]) - slot_group(&active.trials[i - 1])
                };
                if chain > maxchain {
                    seen = true;
                }
            } else {
                chain = 0;
                if !seen {
                    max = Some(i);
                }
            }
            if seen {
                active.trials[i].mark_inactive();
            }
        }
        if let Some(max) = max {
            for t in &mut active.trials[start..=max] {
                if !t.is_def_no_use() && !t.is_active() {
                    t.mark_active();
                }
            }
        }
    }

    /// Port of `ParamListStandard::fillinMap` (the input list): which trials are parameters.
    pub(crate) fn fillin_map_input(&self, active: &mut ParamActive) -> Result<()> {
        if active.trials.is_empty() {
            return Ok(());
        }
        if self.entries.is_empty() {
            return err("Cannot derive parameter storage for prototype model without parameter entries");
        }
        self.build_trial_map(active);
        self.force_exclusion_group(active);
        let starts = self.resource_start();
        let sections = self.separate_sections(active, &starts)?;
        for w in sections.windows(2) {
            self.force_no_use(active, w[0], w[1]);
        }
        for (i, w) in sections.windows(2).enumerate() {
            self.force_inactive_chain(active, 2, w[0], w[1], starts.get(i).copied().unwrap_or(0) as i32);
        }
        for t in &mut active.trials {
            if t.is_active() {
                t.set(ParamTrial::USED);
            }
        }
        Ok(())
    }

    /// Port of `ScoreProtoModel` for inputs (`addParameter`, `doScore`): how badly the active
    /// trials fit this list; 0 is a perfect fit.
    fn score(&self, active: &ParamActive) -> i32 {
        let mut entries = Vec::new();
        let mut mismatch = 0;
        for t in active.trials.iter().filter(|t| t.is_active()) {
            match self.possible_param_with_slot(t.space, t.off, t.size) {
                Some(p) => entries.push(p),
                None => mismatch += 1,
            }
        }
        entries.sort_by_key(|&(slot, _)| slot);
        const PENALTY: [i32; 4] = [16, 10, 7, 5];
        let (mut next_free, mut base) = (0, 0);
        for (slot, size) in entries {
            if slot > next_free {
                while next_free < slot {
                    base += PENALTY.get(next_free as usize).copied().unwrap_or(3);
                    next_free += 1;
                }
                next_free += size;
            } else if next_free > slot {
                base += 20;
                next_free = next_free.max(slot + size);
            } else {
                next_free = slot + size;
            }
        }
        base + 20 * mismatch
    }

    /// The stack ranges of the entries (`ParamListStandard::getRangeList` for the stack space).
    pub(crate) fn stack_ranges(&self) -> Vec<(u64, u64)> {
        self.entries
            .iter()
            .filter_map(|e| match e.storage {
                Storage::Stack { offset, .. } => Some((offset, offset + e.size as u64 - 1)),
                _ => None,
            })
            .collect()
    }
}

impl ParamActive {
    /// `registerTrial` + `markUnref` + `setEntry`: a trial for a slot nothing in the function reads.
    fn register_unref(&mut self, space: Space, off: u64, size: u32, entry: usize) {
        self.register_trial(space, off, size);
        if let Some(t) = self.trials.last_mut() {
            t.flags |= ParamTrial::UNREF | ParamTrial::CHECKED;
            t.entry = Some(entry);
            t.offset = 0;
        }
    }
}

impl Models {
    /// Port of `ProtoModelMerged::selectModel`: the member of the merged model `id` the active
    /// trials fit best (the first on a tie); `id` itself when it is not merged.
    pub(crate) fn select_model(&self, id: ModelId, active: &ParamActive) -> Result<ModelId> {
        let members = &self.get(id).members;
        if members.is_empty() {
            return Ok(id);
        }
        let mut best = None;
        let mut best_score = 500;
        for &m in members {
            let score = self.get(m).input.score(active);
            if score < best_score {
                best_score = score;
                best = Some(m);
                if score == 0 {
                    break;
                }
            }
        }
        best.ok_or_else(|| LowlevelError("No model matches : missing default".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reg(offset: u64) -> ParamEntry {
        ParamEntry {
            storage: Storage::Space { space: 3, offset, size: 4 },
            class: TypeClass::General,
            minsize: 1,
            size: 4,
            align: 0,
        }
    }
    fn stack() -> ParamEntry {
        ParamEntry {
            storage: Storage::Stack { offset: 4, size: 500 },
            class: TypeClass::General,
            minsize: 1,
            size: 500,
            align: 4,
        }
    }
    fn list(entries: Vec<ParamEntry>) -> ParamList {
        ParamList { entries, killed_by_call: false }
    }
    fn trials(active: &[(Space, u64)]) -> ParamActive {
        let mut a = ParamActive::new(0);
        for &(space, off) in active {
            a.register_trial(space, off, 4);
            a.trials.last_mut().unwrap().mark_active();
        }
        a
    }

    /// x86 `__fastcall` (ECX, EDX, then the stack): a read of ECX and of the second stack slot.
    /// By fspec.cc: EDX (its group has no trial) and the first stack slot (a hole) get
    /// unreferenced trials; both sit before the last active trial with inactive chains of at most
    /// two slots, so `forceInactiveChain` makes them active, and all four are parameters.
    #[test]
    fn fillin_map_fills_holes_before_the_last_active_trial() {
        let l = list(vec![reg(4), reg(8), stack()]);
        let mut a = trials(&[(Space::Sleigh(3), 4), (Space::Stack, 8)]);
        l.fillin_map_input(&mut a).unwrap();
        let got: Vec<_> = a.trials.iter().map(|t| (t.space, t.off, t.is_used(), t.has(ParamTrial::UNREF))).collect();
        assert_eq!(
            got,
            vec![
                (Space::Sleigh(3), 4, true, false),
                (Space::Sleigh(3), 8, true, true),
                (Space::Stack, 4, true, true),
                (Space::Stack, 8, true, false),
            ]
        );
    }

    /// `ScoreProtoModel`: a read of ECX fits a list starting with ECX (0) and misses a
    /// stack-only list (one mismatch, 20); a stack-only read leaves two register slots empty in
    /// the first (16 + 10).
    #[test]
    fn score_prefers_the_model_whose_slots_are_filled() {
        let (fast, std) = (list(vec![reg(4), reg(8), stack()]), list(vec![stack()]));
        let ecx = trials(&[(Space::Sleigh(3), 4)]);
        assert_eq!((fast.score(&ecx), std.score(&ecx)), (0, 20));
        let stk = trials(&[(Space::Stack, 4)]);
        assert_eq!((fast.score(&stk), std.score(&stk)), (26, 0));
    }
}
