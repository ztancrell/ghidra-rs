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
    /// the `<rule>`s after the entries (`modelRules`), in order
    pub(crate) rules: Vec<ModelRule>,
}

/// Port of `ModelRule` (modelrules.cc) as far as the specs read here need it: a
/// `<datatype name="any">` filter (`SizeRestrictedFilter`, `minsize`/`maxsize`) and one action.
/// Other filters, qualifiers, preconditions and side effects fail to decode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ModelRule {
    pub(crate) minsize: u32,
    /// 0: no size filtering (`SizeRestrictedFilter::filterOnSize`)
    pub(crate) maxsize: u32,
    pub(crate) action: AssignAction,
}

/// The `AssignAction`s of a rule (`AssignAction::decodeAction`, modelrules.cc:651-687).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AssignAction {
    /// `<goto_stack/>` (`GotoStack`)
    GotoStack,
    /// `<convert_to_ptr/>` (`ConvertToPointer`)
    ConvertToPointer,
    /// `<hidden_return/>` (`HiddenReturnAssign`); `voidlock` is `hiddenret_specialreg_void`
    HiddenReturn { voidlock: bool },
    /// `<join_dual_class/>` (`MultiSlotDualAssign`, little endian): tiles from `base` registers,
    /// floating-point parts from `alt` ones
    JoinDualClass { base: TypeClass, alt: TypeClass, consume_from_stack: bool },
}

impl AssignAction {
    /// `canAffectFillinOutput` (`fillinOutputActive`, set by the constructors of GotoStack,
    /// MultiSlotDualAssign and the others with a `fillinOutputMap`, modelrules.cc:765-776, 1288-1292)
    fn affects_fillin_output(self) -> bool {
        matches!(self, AssignAction::GotoStack | AssignAction::JoinDualClass { .. })
    }
}

impl ModelRule {
    /// Port of `ModelRule::decode` (modelrules.cc:1820-1853) for the forms above.
    fn decode(el: &Element, list: &ParamList) -> Result<ModelRule> {
        let [filter, action] = &el.kids[..] else {
            return err("<rule>: qualifiers, preconditions and side effects are not supported");
        };
        if filter.name != "datatype" || filter.attr("name") != Some("any") {
            return err(format!("<rule>: the data-type filter {:?} is not supported", filter.attr("name")));
        }
        if filter.attr("sizes").is_some() {
            return err("<rule>: <datatype sizes=...> is not supported");
        }
        let size = |n: &str| -> Result<u32> {
            filter.attr(n).map_or(Ok(0), |_| {
                u32::try_from(filter.int(n)?).map_err(|_| LowlevelError(format!("<datatype>: {n} out of range")))
            })
        };
        let (minsize, maxsize) = (size("minsize")?, size("maxsize")?);
        let action = match action.name.as_str() {
            // GotoStack::initializeEntry (modelrules.cc:755-761)
            "goto_stack" if list.has_stack() => AssignAction::GotoStack,
            "goto_stack" => return err("Cannot find matching <pentry> for action: goto_stack"),
            "convert_to_ptr" => AssignAction::ConvertToPointer,
            "hidden_return" => {
                if action.attr("strategy").is_some() {
                    return err("<hidden_return strategy=...> is not supported");
                }
                AssignAction::HiddenReturn { voidlock: action.attr("voidlock").is_some() }
            }
            "join_dual_class" => {
                // MultiSlotDualAssign::decode (modelrules.cc:1444-1471), little endian
                let mut a = AssignAction::JoinDualClass {
                    base: TypeClass::General,
                    alt: TypeClass::Float,
                    consume_from_stack: false,
                };
                if let AssignAction::JoinDualClass { base, alt, consume_from_stack } = &mut a {
                    for n in action.attr_names() {
                        match n {
                            "reversesignif" | "reversejustify" if !action.flag(n) => {}
                            "storage" | "a" => *base = TypeClass::parse(action.attr(n).unwrap_or_default())?,
                            "b" => *alt = TypeClass::parse(action.attr(n).unwrap_or_default())?,
                            "stackspill" => *consume_from_stack = action.flag(n),
                            _ => return err(format!("<join_dual_class {n}=...> is not supported")),
                        }
                    }
                    // initializeEntries (modelrules.cc:1213-1227)
                    let (bt, at) = (list.tiles(*base), list.tiles(*alt));
                    if bt.is_empty() || at.is_empty() {
                        return err("Could not find matching resources for action: join_dual_class");
                    }
                    if list.entries[bt[0]].size != list.entries[at[0]].size {
                        return err("Storage class register sizes do not match for action: join_dual_class");
                    }
                    if *consume_from_stack && !list.has_stack() {
                        return err("Cannot find matching stack resource for action: join_dual_class");
                    }
                }
                a
            }
            n => return err(format!("<rule>: the action <{n}> is not supported")),
        };
        Ok(ModelRule { minsize, maxsize, action })
    }
}

impl ParamList {
    /// Port of `ParamListStandard::decode`: the `<pentry>`s of `<input>`/`<output>`; with
    /// `killedbycall="true"` each entry is also a killed-by-call effect.
    fn decode(el: &Element, regs: &SleighNames, effects: &mut Vec<Effect>) -> Result<ParamList> {
        // `separatefloat="false"` puts every entry in one resource section; not ported
        if el.attr("separatefloat").is_some() && !el.flag("separatefloat") {
            return err(format!("<{}>: separatefloat=\"false\" is not supported", el.name));
        }
        // the `<rule>`s come after every `<pentry>` (fspec.cc:1470-1494)
        let n = el.kids.iter().position(|k| k.name == "rule").unwrap_or(el.kids.len());
        let entries = el.kids[..n]
            .iter()
            .map(|k| match k.name.as_str() {
                "pentry" => ParamEntry::decode(k, regs),
                n => err(format!("<{}>: <{n}> is not supported", el.name)),
            })
            .collect::<Result<Vec<_>>>()?;
        if el.kids[n..].iter().any(|k| k.name != "rule") {
            return err("<pentry> and <group> elements must come before any <modelrule>");
        }
        if el.attr("pointermax").is_some() {
            return err(format!("<{}>: pointermax is not supported", el.name));
        }
        // parsePentry: the storage classes only go down, each change starting a resource section
        let mut last = TypeClass::Class(4);
        for e in &entries {
            if last.rank() < e.class.rank() {
                return err("parameter list entries must be ordered by storage class");
            }
            last = e.class;
        }
        if el.flag("killedbycall") {
            effects
                .extend(entries.iter().map(|e| Effect { storage: e.storage.clone(), kind: EffectKind::KilledByCall }));
        }
        let mut list = ParamList { entries, killed_by_call: el.flag("killedbycall"), rules: Vec::new() };
        for k in &el.kids[n..] {
            let rule = ModelRule::decode(k, &list)?;
            list.rules.push(rule);
        }
        Ok(list)
    }

    /// Port of `ParamListStandard::extractTiles`: the single-group entries of class `class`
    /// (no `<group>` in the lists read here, so every non-join entry is an exclusion).
    fn tiles(&self, class: TypeClass) -> Vec<usize> {
        (0..self.entries.len())
            .filter(|&i| self.entries[i].class == class && !matches!(self.entries[i].storage, Storage::Join(_)))
            .collect()
    }

    /// `ParamEntry::isFirstInClass` (`resolveFirst`, fspec.cc:77-90): the first entry, or one of
    /// another class than the entry before it.
    fn first_in_class(&self, i: usize) -> bool {
        i == 0 || self.entries[i - 1].class != self.entries[i].class
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
    /// the models whose decode needs what is not ported: name, error
    pub(crate) unported: Vec<(String, String)>,
}

impl Models {
    pub(crate) fn get(&self, id: ModelId) -> &ProtoModel {
        &self.list[id.0 as usize]
    }

    /// Port of `Architecture::getModel`.
    pub(crate) fn find(&self, name: &str) -> Result<ModelId> {
        self.list.iter().position(|m| m.name == name).map(|i| ModelId(i as u32)).ok_or_else(|| {
            match self.unported.iter().find(|u| u.0 == name) {
                Some((_, e)) => LowlevelError(format!("prototype model {name}: {e}")),
                None => LowlevelError(format!("Missing prototype model: {name}")),
            }
        })
    }

    /// Port of `ProtoModel::isCompatible`: the same model, or one is the copy of the other
    /// (`compatModel`). The only copy here is the facts' `unknown` model
    /// (`createUnknownModel`, an `UnknownProtoModel` of the default model); the x86 cspec has no
    /// `<modelalias>`.
    pub(crate) fn is_compatible(&self, a: ModelId, b: ModelId) -> bool {
        let copy_of = |m: ModelId| (self.get(m).name == "unknown" && m != self.default).then_some(self.default);
        a == b || copy_of(a) == Some(b) || copy_of(b) == Some(a)
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
    /// A restart resets it ([`FuncProto::clear_unlocked_output`]).
    pub(crate) return_bytes_consumed: u32,
    /// the return value `ActionOutputPrototype` stores (`ProtoStoreSymbol::outparam`): storage and
    /// data-type; none is `void`. The inputs are the local scope's category-0 symbols.
    pub(crate) out_param: Option<(Space, u64, TypeId)>,
    /// `no_return`: the function does not return to its caller (only the facts of stage S10
    /// say so)
    pub(crate) no_return: bool,
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

    /// Port of `FuncProto::clearUnlockedOutput` (`Funcdata::clear`, a restart): a locked output
    /// stays, a size-locked one back to an unknown data-type of its size (`resetSizeLockType`);
    /// an unlocked output is forgotten (`store->clearOutput`); `returnBytesConsumed` is reset.
    /// The model, extrapop and flags stay as the pass before set them.
    pub(crate) fn clear_unlocked_output(&mut self, types: &mut super::types::TypeFactory) {
        match &mut self.locked {
            Some(l) => {
                if l.output_size_locked && self.model.is_some() {
                    let size = types.size(l.output.ty);
                    l.output.ty = types.base(size, super::types::Meta::Unknown);
                }
            }
            None => {
                self.output = None;
                self.out_param = None;
            }
        }
        self.return_bytes_consumed = 0;
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
        self.no_return = other.no_return;
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
    /// the used trials, renumbered, that `activeinput` keeps once `ActionActiveParam` has rebuilt
    /// the inputs (`clearActiveInput` only turns the recovery off; `checkCallDoubleUse` reads them)
    pub(crate) kept_input: Option<ParamActive>,
    /// the return-value trials (`activeoutput`, `isoutputactive`), from `ActionFuncLink` on
    pub(crate) active_output: Option<ParamActive>,
    /// `effective_extrapop`, from `ActionStackPtrFlow`
    pub(crate) effective_extrapop: Option<i32>,
    /// `isBadJumpTable`: the call stands for an indirect jump whose table was not recovered
    pub(crate) bad_jump_table: bool,
    /// `FuncCallSpecs::stackoffset`: the stack pointer at the call relative to its value on entry
    /// (`None`: `offset_unknown`); set by `resolveSpacebaseRelative` (RuleLoadVarnode, stage R5)
    pub(crate) stack_offset: Option<u64>,
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
            kept_input: None,
            active_output: None,
            effective_extrapop: None,
            bad_jump_table: false,
            input_consume: Vec::new(),
            stack_offset: None,
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

    /// Port of `ParamListStandard::getBiggestContainedParam` (fspec.cc:1358-1391): the offset
    /// and size of the largest entry the range holds (`ParamEntry::containedBy`), when that
    /// entry is exclusive. The C++ walks the resolver's range map from the range's start, so of
    /// two entries of one size the one at the lower address wins.
    pub(crate) fn biggest_contained(&self, space: Space, off: u64, size: u32) -> Option<(u64, u32)> {
        // a wrapped range holds no parameter
        let end = off.checked_add(u64::from(size).checked_sub(1)?)?;
        let mut max: Option<(u64, &ParamEntry)> = None;
        for e in &self.entries {
            let base = match (&e.storage, space) {
                (Storage::Space { space: s, offset, .. }, Space::Sleigh(sp)) if *s == sp => *offset,
                (Storage::Stack { offset, .. }, Space::Stack) => *offset,
                _ => continue,
            };
            let eend = base.wrapping_add(e.size as u64).wrapping_sub(1);
            if base < off || base > end || eend > end {
                continue;
            }
            if max.is_none_or(|(mbase, m)| e.size > m.size || (e.size == m.size && base < mbase)) {
                max = Some((base, e));
            }
        }
        // `isExclusion`
        max.filter(|(_, e)| e.align == 0).map(|(base, e)| (base, e.size as u32))
    }

    /// `ParamListStandard::characterizeAsParam` for a range of the stack space (`mask`: the
    /// space's offset mask; a wrapped range is no parameter).
    pub(crate) fn characterize_stack(&self, off: u64, size: u32, mask: u64) -> Containment {
        let end = off.wrapping_add(u64::from(size)).wrapping_sub(1);
        if end < off || end > mask {
            return Containment::None;
        }
        let (mut contains, mut contained_by) = (false, false);
        for e in &self.entries {
            let Storage::Stack { offset: base, .. } = e.storage else { continue };
            let eend = base.wrapping_add(e.size as u64).wrapping_sub(1);
            match e.stack_justified(base, off, size) {
                Some(0) => return Containment::ContainsJustified,
                Some(_) => contains = true,
                None => {}
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

impl ParamEntry {
    /// Port of `ParamEntry::justifiedContain` (little-endian) for an entry at `base` of the stack
    /// space and the stack range `[off, off + size)`, with the C++'s wrapping offsets: the offset
    /// into an exclusion entry (`alignment == 0`, `Address::justifiedContain`), into the slot of
    /// an aligned one.
    fn stack_justified(&self, base: u64, off: u64, size: u32) -> Option<i32> {
        let end = off.wrapping_add(u64::from(size)).wrapping_sub(1);
        let eend = base.wrapping_add(self.size as u64).wrapping_sub(1);
        if off < base || end > eend || (self.align != 0 && end < off) {
            return None;
        }
        let start = off - base;
        Some(if self.align == 0 { start } else { start % self.align as u64 } as i32)
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

    /// `ProtoModel::lookupEffect` for a stack range (the stack's records sort last).
    pub(crate) fn lookup_stack_effect(&self, off: u64, size: u32) -> Option<EffectKind> {
        let at = self.effects.partition_point(|e| e.storage.address_key() <= (u32::MAX, off));
        let e = self.effects.get(at.checked_sub(1)?)?;
        let Storage::Stack { offset: hit, size: sz } = e.storage else { return None };
        if sz == 0 {
            return Some(EffectKind::Unaffected);
        }
        let dist = off.checked_sub(hit)?;
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
    /// the argument position of a fixed argument of a varargs call, else -1
    pub(crate) fixed_position: i32,
}

impl ParamTrial {
    pub(crate) const CHECKED: u32 = 1;
    pub(crate) const USED: u32 = 2;
    pub(crate) const DEFNOUSE: u32 = 4;
    /// `unref`: no varnode stands for the trial
    pub(crate) const UNREF: u32 = 0x10;
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
    /// `needsfinalcheck`: an active trial may be affected by conditional execution
    pub(crate) needs_final_check: bool,
    /// `recoversubcall`: the trials are a sub-function call's (`initActiveInput` and
    /// `initActiveOutput` of `FuncCallSpecs`), not the function's own
    pub(crate) recover_subcall: bool,
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
            needs_final_check: false,
            recover_subcall: false,
        }
    }

    /// The trial list of a sub-function call (`ParamActive(true)`).
    pub(crate) fn subcall(maxdelay: i32) -> ParamActive {
        ParamActive { recover_subcall: true, ..ParamActive::new(maxdelay) }
    }

    /// Port of `ParamActive::getTrialForInputVarnode`: the trial of the call's input `slot`
    /// by position in the list (input 0 is the call address; the stack placeholder's slot is
    /// skipped), as the C++ indexes it.
    pub(crate) fn trial_for_input_varnode(&self, slot: usize) -> Result<&ParamTrial> {
        let skip = if self.stackplaceholder < 0 || (slot as i32) < self.stackplaceholder { 1 } else { 2 };
        slot.checked_sub(skip)
            .and_then(|i| self.trials.get(i))
            .ok_or_else(|| LowlevelError(format!("getTrialForInputVarnode: no trial for input slot {slot}")))
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
        self.trials.push(ParamTrial {
            space,
            off,
            size,
            slot: self.slotbase,
            flags,
            entry: None,
            offset: -1,
            fixed_position: -1,
        });
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
        self.trials.sort_by(|a, b| trial_order(list, a, b));
    }
    /// Port of `ParamActive::sortFixedPosition` (`ParamTrial::fixedPositionCompare`): the fixed
    /// arguments of a varargs call first, by position, then the rest by `ParamTrial::operator<`.
    pub(crate) fn sort_fixed_position(&mut self, list: &ParamList) {
        self.trials.sort_by(|a, b| match (a.fixed_position, b.fixed_position) {
            (-1, -1) => trial_order(list, a, b),
            (-1, _) => std::cmp::Ordering::Greater,
            (_, -1) => std::cmp::Ordering::Less,
            (pa, pb) => pa.cmp(&pb),
        });
    }
}

/// `ParamTrial::operator<` as an ordering: by the entry's group, then address and size; trials
/// without an entry last.
fn trial_order(list: &ParamList, a: &ParamTrial, b: &ParamTrial) -> std::cmp::Ordering {
    match (a.entry, b.entry) {
        (None, None) => std::cmp::Ordering::Equal,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (Some(_), None) => std::cmp::Ordering::Less,
        (Some(ea), Some(eb)) => list
            .group(ea)
            .cmp(&list.group(eb))
            .then((a.space.index(), a.off).cmp(&(b.space.index(), b.off)))
            .then(a.size.cmp(&b.size)),
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

    /// Port of `ParamEntry::getContainer` (fspec.cc:296-331, little endian) for a range entry
    /// `i` contains: the piece of a join holding it, the whole of an exclusive entry, or its
    /// aligned slots of a stack entry.
    fn container(&self, i: usize, space: Space, off: u64, size: u32) -> Option<(Space, u64, u32)> {
        let e = &self.entries[i];
        let end = off.wrapping_add(u64::from(size) - 1);
        let within = |base: u64, esize: u64| off.wrapping_sub(base) < esize && end.wrapping_sub(base) < esize;
        let base = match (&e.storage, space) {
            (Storage::Join(pieces), Space::Sleigh(sp)) => {
                // from the least significant piece
                let hit = pieces.iter().rev().find(|&&(s, o, z)| s == sp && within(o, u64::from(z)));
                return hit.map(|&(s, o, z)| (Space::Sleigh(s), o, z));
            }
            (Storage::Space { space: s, offset, .. }, Space::Sleigh(sp)) if *s == sp => *offset,
            (Storage::Stack { offset, .. }, Space::Stack) => *offset,
            _ => return None,
        };
        if !within(base, e.size as u64) {
            return None;
        }
        if e.align == 0 {
            return Some((space, base, e.size as u32));
        }
        let align = e.align as u64;
        let start = off - off.wrapping_sub(base) % align;
        let len = (end - start + 1).next_multiple_of(align);
        Some((space, start, len as u32))
    }

    /// Port of `ParamListStandard::unjustifiedContainer` (fspec.cc:1394-1407): the container of a
    /// range the first entry holding it holds unjustified.
    pub(crate) fn unjustified_container(&self, space: Space, off: u64, size: u32) -> Option<(Space, u64, u32)> {
        for (i, e) in self.entries.iter().enumerate() {
            if i64::from(e.minsize) > i64::from(size) {
                continue;
            }
            match self.justified_contain(i, space, off, size) {
                None => continue,
                Some(0) => return None,
                Some(_) => return self.container(i, space, off, size),
            }
        }
        None
    }

    /// Port of `ParamEntry::justifiedContain` (little endian): for a register or join entry
    /// the offset of the range within the entry, for an aligned stack entry its offset within
    /// the slot, or `None`.
    pub(crate) fn justified_contain(&self, i: usize, space: Space, off: u64, size: u32) -> Option<i32> {
        if space == Space::Stack {
            let e = &self.entries[i];
            let Storage::Stack { offset: base, .. } = e.storage else { return None };
            return e.stack_justified(base, off, size);
        }
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

    /// Port of `ParamListStandardOut::fillinMap` (fspec.cc:1711-1750): without a rule that can
    /// affect it (`useFillinFallback`, x86win.cspec) the fallback decides; else each trial gets
    /// the entry it starts in, and the first rule whose `fillinOutputMap` accepts the trials
    /// decides, the fallback with `firstOnly` when none does.
    pub(crate) fn fillin_map_output(&self, active: &mut ParamActive) {
        if active.trials.is_empty() {
            return;
        }
        if !self.rules.iter().any(|r| r.action.affects_fillin_output()) {
            return self.fillin_map_fallback(active, false);
        }
        for t in &mut active.trials {
            t.entry = None;
            t.offset = 0;
            if !t.is_active() {
                continue;
            }
            // findEntry with `just` false: the first entry (list order, as the resolver sorts
            // them) whose range holds the trial's start and whose minimum size it meets
            let found = (0..self.entries.len()).find(|&i| {
                let e = &self.entries[i];
                e.minsize <= t.size as i32
                    && self
                        .base_in(i, t.space)
                        .is_some_and(|b| t.off >= b && t.off <= b.wrapping_add(e.size as u64).wrapping_sub(1))
            });
            let Some(e) = found else {
                t.mark_no_use();
                continue;
            };
            let res = self.justified_contain(e, t.space, t.off, t.size);
            if (t.has(ParamTrial::REM_FORMED) || t.has(ParamTrial::INDCREATE_FORMED)) && !self.first_in_class(e) {
                t.mark_no_use();
                continue;
            }
            // setEntry(entry, res): justifiedContain's -1 when the trial overruns the entry
            t.entry = Some(e);
            t.offset = res.unwrap_or(-1);
        }
        active.sort_trials(self);
        if self.rules.iter().any(|r| self.rule_fillin_output(r.action, active)) {
            for t in &mut active.trials {
                if t.is_active() {
                    t.set(ParamTrial::USED);
                } else {
                    t.mark_no_use();
                    t.entry = None;
                    t.offset = 0;
                }
            }
            return;
        }
        self.fillin_map_fallback(active, true);
    }

    /// `AssignAction::fillinOutputMap` of a rule's action: GotoStack (modelrules.cc:790-805),
    /// MultiSlotDualAssign little endian (modelrules.cc:1386-1442), else none (`false`).
    fn rule_fillin_output(&self, action: AssignAction, active: &ParamActive) -> bool {
        let entries = active.trials.iter().map_while(|t| t.entry.map(|e| (t, e)));
        match action {
            AssignAction::GotoStack => {
                let mut count = 0;
                for (_, e) in entries {
                    if !self.entries[e].is_stack_spill() || count == 1 {
                        return false;
                    }
                    count += 1;
                }
                count == 1
            }
            AssignAction::JoinDualClass { base, alt, .. } => {
                let (mut count, mut cur_group, mut partial) = (0, -1i64, None);
                let mut resource = TypeClass::General;
                for (i, (t, e)) in entries.enumerate() {
                    let class = self.entries[e].class;
                    if count == 0 {
                        resource = class;
                        if (resource != base && resource != alt) || !self.first_in_class(e) {
                            return false;
                        }
                    } else if class != resource || self.group(e) as i64 != cur_group + 1 {
                        return false;
                    }
                    cur_group = self.group(e) as i64;
                    if t.size as i32 != self.entries[e].size {
                        if partial.is_some() {
                            return false;
                        }
                        partial = Some(i);
                    }
                    count += 1;
                }
                // justifyRight and consumeMostSig false (little endian, no `reverse*` attribute):
                // a partial trial is the last one and holds the least significant bytes
                if partial.is_some_and(|p| p != count - 1 || active.trials[p].offset != 0) {
                    return false;
                }
                count != 0
            }
            AssignAction::ConvertToPointer | AssignAction::HiddenReturn { .. } => false,
        }
    }

    /// Port of `ParamListStandardOut::fillinMapFallback`: the entry best covered by the active
    /// trials decides which trials are used.
    fn fillin_map_fallback(&self, active: &mut ParamActive, first_only: bool) {
        let mut best: Option<usize> = None;
        let (mut bestcover, mut bestclass) = (0, TypeClass::Ptr.rank());
        for e in 0..self.entries.len() {
            // not the first entry of its storage class (exclusion, one group)
            if first_only && !self.first_in_class(e) && !matches!(self.entries[e].storage, Storage::Join(_)) {
                continue;
            }
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
        let model = self.model_of(arch)?;
        match space {
            Space::Sleigh(s) => model.lookup_effect(arch.sleigh.uniq_space(), s, off, size),
            Space::Stack => model.lookup_stack_effect(off, size),
            _ => None,
        }
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
            (Some(m), Space::Stack) => m.output.characterize_stack(off, size, super::heritage_guard::stack_mask(arch)),
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
            (Some(m), Space::Stack) => m.input.characterize_stack(off, size, super::heritage_guard::stack_mask(arch)),
            _ => Containment::None,
        }
    }

    /// Port of `FuncProto::isAutoKilledByCall`.
    pub(crate) fn is_auto_killed_by_call(&self, arch: &Arch) -> bool {
        self.model_of(arch).is_some_and(|m| m.output.killed_by_call)
    }

    /// Port of `FuncProto::unjustifiedInputParam` (fspec.cc:4364-4392): the parameter storage
    /// holding the range unjustified. Locked parameters decide when there are any (not varargs).
    pub(crate) fn unjustified_input_param(
        &self,
        arch: &Arch,
        space: Space,
        off: u64,
        size: u32,
    ) -> Result<Option<(Space, u64, u32)>> {
        if let Some(l) = self.locked.as_ref().filter(|l| !l.dotdotdot) {
            // no inputs is `voidinputlock`; every locked parameter with storage is a lock test
            for st in l.inputs.iter().filter_map(|p| p.storage.as_ref()) {
                match super::locked::containment(st, space, off, size) {
                    Containment::ContainsJustified => return Ok(None),
                    Containment::ContainsUnjustified => {
                        return Ok(Some(match st {
                            Storage::Space { space, offset, size } => (Space::Sleigh(*space), *offset, *size),
                            Storage::Stack { offset, size } => (Space::Stack, *offset, *size),
                            Storage::Join(_) => {
                                return err("unjustifiedInputParam: a locked join parameter is not ported")
                            }
                        }))
                    }
                    _ => {}
                }
            }
            if l.inputs.is_empty() || l.inputs.iter().any(|p| p.storage.is_some()) {
                return Ok(None);
            }
        }
        Ok(self.model_of(arch).and_then(|m| m.input.unjustified_container(space, off, size)))
    }

    /// Port of `FuncProto::getBiggestContainedOutput` (fspec.cc:4432-4449) for an unlocked
    /// output: the largest possible return storage the range holds. A locked output is not
    /// ported and fails loudly.
    pub(crate) fn biggest_contained_output(
        &self,
        arch: &Arch,
        space: Space,
        off: u64,
        size: u32,
    ) -> Result<Option<(u64, u32)>> {
        if self.locked.is_some() {
            return err("getBiggestContainedOutput of a locked prototype: not implemented in ghidra-rs yet");
        }
        Ok(self.model_of(arch).and_then(|m| m.output.biggest_contained(space, off, size)))
    }

    /// Port of `FuncProto::getBiggestContainedInputParam` (fspec.cc:4398-4426) where the model
    /// decides (no locked inputs, or varargs). Locked inputs are not ported and fail loudly.
    pub(crate) fn biggest_contained_input(
        &self,
        arch: &Arch,
        space: Space,
        off: u64,
        size: u32,
    ) -> Result<Option<(u64, u32)>> {
        if self.locked.as_ref().is_some_and(|l| !l.dotdotdot) {
            return err("getBiggestContainedInputParam of a locked prototype: not implemented in ghidra-rs yet");
        }
        Ok(self.model_of(arch).and_then(|m| m.input.biggest_contained(space, off, size)))
    }
}

// ---- recovering the function's own inputs (ActionInputPrototype, the tail stage) ----

impl ParamTrial {
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

    /// Port of `ParamEntry::justifiedContain` (little endian): the range's offset in the entry,
    /// modulo the alignment of a multi-slot entry; for a join entry, its offset from the least
    /// significant piece on.
    fn justified_in(&self, i: usize, space: Space, off: u64, size: u32) -> Option<i32> {
        let e = &self.entries[i];
        let end = off.checked_add(u64::from(size))?.checked_sub(1)?;
        if let Storage::Join(pieces) = &e.storage {
            let mut res = 0u32;
            for &(s, o, z) in pieces.iter().rev() {
                if space == Space::Sleigh(s) && off >= o && end <= o.wrapping_add(u64::from(z)).wrapping_sub(1) {
                    return i32::try_from(u64::from(res) + (off - o)).ok();
                }
                res = res.wrapping_add(z);
            }
            return None;
        }
        let base = self.base_in(i, space)?;
        if off < base || end > base.wrapping_add(e.size as u64).wrapping_sub(1) {
            return None;
        }
        let rel = off - base;
        Some(if e.align == 0 { rel as i32 } else { (rel % e.align as u64) as i32 })
    }

    /// Port of `ParamListStandard::findEntry` with `just` true: the first entry holding the
    /// range justified. The C++ walks the resolver's pieces at the offset, which sort by the
    /// entry's position (`ParamEntryRange::getSubsort`), so list order is its order.
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
        res.push((0..self.entries.len()).map(|i| self.group(i) + 1).max().unwrap_or(0)); // numgroup
        res
    }

    /// The address and size of slot `slot` of entry `i`, as `buildTrialMap` asks
    /// `ParamEntry::getAddrBySlot` for an unreferenced trial (little endian, no reverse stack).
    fn slot_address(&self, i: usize, slot: u64) -> Result<(Space, u64, u32)> {
        let e = &self.entries[i];
        let (sz, step) = if e.align == 0 { (e.size, 0) } else { (e.align, (e.align as u64).wrapping_mul(slot)) };
        match &e.storage {
            Storage::Space { space, offset, .. } => Ok((Space::Sleigh(*space), offset.wrapping_add(step), sz as u32)),
            Storage::Stack { offset, .. } => Ok((Space::Stack, offset.wrapping_add(step), sz as u32)),
            Storage::Join(_) => err("buildTrialMap: an unreferenced parameter in a join entry is not ported"),
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
    fn build_trial_map(&self, active: &mut ParamActive) -> Result<()> {
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
                let (space, off, size) = self.slot_address(cur, 0)?;
                active.register_unref(space, off, size, cur);
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
                let b = self.get_slot(cur, t.space, t.off, t.size.wrapping_sub(1)) - grp;
                let (lo, hi) = (a.min(b).max(0) as usize, a.max(b).max(0) as usize);
                if slots.len() <= hi {
                    slots.resize(hi + 1, false);
                }
                slots[lo..=hi].iter_mut().for_each(|s| *s = true);
            }
            for (j, _) in slots.iter().enumerate().filter(|(_, &s)| !s) {
                let (space, off, size) = self.slot_address(cur, j as u64)?;
                active.register_unref(space, off, size, cur);
            }
        }
        active.sort_trials(self);
        Ok(())
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

    /// Port of `ParamListStandard::forceInactiveChain`: a chain of more than `maxchain` inactive
    /// slots ends the parameters; inactive trials before the last active one become active.
    fn force_inactive_chain(
        &self,
        active: &mut ParamActive,
        maxchain: i32,
        start: usize,
        stop: usize,
        group_start: i32,
    ) {
        let slot_group =
            |t: &ParamTrial| t.entry.map_or(0, |e| self.get_slot(e, t.space, t.off, t.size.wrapping_sub(1)));
        let (mut seen, mut chain) = (false, 0);
        let mut max = None;
        for i in start..stop {
            if active.trials[i].is_def_no_use() {
                continue;
            }
            if !active.trials[i].is_active() {
                // a sub-call's unreferenced stack slot ends the chain: only a register can be
                // passed on unread from the caller's own inputs
                let t = &active.trials[i];
                if t.has(ParamTrial::UNREF) && active.recover_subcall && t.space == Space::Stack {
                    seen = true;
                }
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
        self.build_trial_map(active)?;
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

    /// Port of `ParamActive::splitTrial` (with `ParamTrial::splitHi` and `splitLo`, little
    /// endian): trial `i` becomes two, the first of `sz` bytes at its address, the second the
    /// rest in the next slot; both keep the flags and lose the entry.
    pub(crate) fn split_trial(&mut self, i: usize, sz: u32) -> Result<()> {
        if self.stackplaceholder >= 0 {
            return err("Cannot split parameter when the placeholder has not been recovered");
        }
        let t = self.trials[i].clone();
        for (j, other) in self.trials.iter_mut().enumerate() {
            if j != i && other.slot > t.slot {
                other.slot += 1;
            }
        }
        let first = ParamTrial { size: sz, entry: None, offset: -1, fixed_position: -1, ..t.clone() };
        let second = ParamTrial {
            off: t.off.wrapping_add(u64::from(sz)),
            size: t.size - sz,
            slot: t.slot + 1,
            entry: None,
            offset: -1,
            fixed_position: -1,
            ..t
        };
        self.trials.splice(i..=i, [first, second]);
        self.slotbase += 1;
        Ok(())
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
        ParamList { entries, killed_by_call: false, rules: Vec::new() }
    }
    fn trials(active: &[(Space, u64)]) -> ParamActive {
        let mut a = ParamActive::new(0);
        for &(space, off) in active {
            a.register_trial(space, off, 4);
            a.trials.last_mut().unwrap().mark_active();
        }
        a
    }

    /// A range over two registers holds both: the first of the largest wins
    /// (getBiggestContainedParam); a range the stack slots are in holds no exclusive entry. A
    /// byte in the middle of a register sits unjustified in the whole register, in the middle of
    /// a stack slot in that slot (getContainer).
    #[test]
    fn biggest_contained_and_unjustified_container() {
        let l = list(vec![reg(4), reg(8), stack()]);
        assert_eq!(l.biggest_contained(Space::Sleigh(3), 4, 8), Some((4, 4)));
        assert_eq!(l.biggest_contained(Space::Sleigh(3), 6, 8), Some((8, 4)));
        assert_eq!(l.biggest_contained(Space::Sleigh(3), 5, 4), None);
        assert_eq!(l.biggest_contained(Space::Stack, 0, 1000), None);
        assert_eq!(l.unjustified_container(Space::Sleigh(3), 5, 1), Some((Space::Sleigh(3), 4, 4)));
        assert_eq!(l.unjustified_container(Space::Sleigh(3), 4, 2), None);
        assert_eq!(l.unjustified_container(Space::Stack, 9, 1), Some((Space::Stack, 8, 4)));
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

    /// The same trials of a sub-function call (`recoversubcall`): the unreferenced first stack
    /// slot cannot be a caller's input passed on, so it ends the chain; the later stack trial
    /// becomes inactive and only ECX is a parameter (EDX lies after the last active trial).
    #[test]
    fn fillin_map_of_a_call_stops_at_a_stack_hole() {
        let l = list(vec![reg(4), reg(8), stack()]);
        let mut a = trials(&[(Space::Sleigh(3), 4), (Space::Stack, 8)]);
        a.recover_subcall = true;
        l.fillin_map_input(&mut a).unwrap();
        let used: Vec<_> = a.trials.iter().filter(|t| t.is_used()).map(|t| (t.space, t.off)).collect();
        assert_eq!(used, vec![(Space::Sleigh(3), 4)]);
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
