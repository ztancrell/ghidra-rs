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
use super::xml::Element;
use super::{err, LowlevelError, Result};

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
            "stack" => Ok(Storage::Stack { offset: el.int("offset")? as u64, size }),
            name => Ok(Storage::Space { space: regs.space(name)?, offset: el.int("offset")? as u64, size }),
        }
    }

    /// The key `EffectRecord::compareByAddress` sorts by: space (SLEIGH spaces in their index
    /// order, then `stack` and `join`, which the C++ creates after them), then offset.
    fn address_key(&self) -> (u32, u64) {
        match self {
            Storage::Space { space, offset, .. } => (*space, *offset),
            Storage::Stack { offset, .. } => (u32::MAX - 1, *offset),
            Storage::Join(_) => (u32::MAX, 0),
        }
    }
}

/// Port of `ParamEntry`: one slot a parameter or return value may occupy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ParamEntry {
    pub(crate) storage: Storage,
    pub(crate) minsize: i32,
    /// `maxsize`: the size of the slot
    pub(crate) size: i32,
    pub(crate) align: i32,
}

impl ParamEntry {
    /// Port of `ParamEntry::decode`.
    fn decode(el: &Element, regs: &SleighNames) -> Result<ParamEntry> {
        for attr in el.attr_names() {
            if !matches!(attr, "minsize" | "maxsize" | "size" | "align" | "metatype" | "storage" | "extension") {
                return err(format!("Unknown <pentry> attribute {attr}"));
            }
        }
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
            minsize,
            size,
            // ParamEntry::decode: an alignment equal to the size means none
            align: if align == size { 0 } else { align },
        })
    }

    fn is_stack(&self) -> bool {
        matches!(self.storage, Storage::Stack { .. })
    }
}

/// Port of `ParamListStandard`: the entries, in order.
#[derive(Debug, Clone, Default)]
pub(crate) struct ParamList {
    pub(crate) entries: Vec<ParamEntry>,
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
        Ok(ParamList { entries })
    }

    /// Port of `ParamListStandard::getSpacebase`: the stack, when some entry is on it.
    pub(crate) fn has_stack(&self) -> bool {
        self.entries.iter().any(ParamEntry::is_stack)
    }

    /// Port of `ParamListMerged::foldIn`: add the entries not already present.
    fn fold_in(&mut self, other: &ParamList) {
        for e in &other.entries {
            if !self.entries.contains(e) {
                self.entries.push(e.clone());
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
    #[expect(dead_code, reason = "read by return recovery (stage S4)")]
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
    /// Port of `FuncProto::setModel`: the model and its extrapop.
    pub(crate) fn set_model(&mut self, models: &Models, id: ModelId) {
        self.model = Some(id);
        self.extrapop = models.get(id).extrapop;
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

    /// Port of `FuncProto::copy` (`FuncCallSpecs::copy` keeps the call's own fields).
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
    /// the callee's display name, when the scope knows a function there (`setFuncdata`)
    pub(crate) name: Option<String>,
    pub(crate) proto: FuncProto,
    /// the CALL's input slot holding the stack-pointer placeholder (`stackPlaceholderSlot`)
    pub(crate) stack_placeholder_slot: Option<usize>,
}

impl CallSpec {
    /// A call site before analysis (the `FuncCallSpecs` constructor).
    pub(crate) fn new(op: OpId, entry: Option<u64>, name: Option<String>) -> CallSpec {
        CallSpec { op, entry, name, proto: FuncProto::default(), stack_placeholder_slot: None }
    }

    /// The callee's entry when the scope knows a function there (`getFuncdata`).
    pub(crate) fn callee(&self) -> Option<u64> {
        self.name.as_ref().and(self.entry)
    }
}
