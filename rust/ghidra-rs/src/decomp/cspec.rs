//! Reading the compiler specification (`.cspec`): port of the spec part of `architecture.cc`
//! (`Architecture::parseCompilerConfig` and the elements it decodes) for what the decompiler
//! uses so far: the stack pointer, the return address, the prototype models with
//! `<resolveprototype>` and the evaluation models, and the `<callfixup>` snippets.
//!
//! Of `<data_organization>` the size-alignment map is read (struct layout, stage S6); `<global>`
//! (the global scope's ranges) is skipped; any other element is an error, so a spec using
//! something not ported fails at load instead of decompiling wrong.
//! Superseded: until S6 `<data_organization>` was skipped.

/// Port of `TypeFactory::decodeAlignmentMap`: entries by size, the gaps copying the nearest
/// smaller explicit size.
fn decode_alignment_map(el: &Element) -> Result<Vec<u32>> {
    let mut map: Vec<Option<u32>> = Vec::new();
    for e in el.kids.iter().filter(|e| e.name == "entry") {
        let num = |n: &str| -> Result<u32> {
            let v = e.req(n)?;
            v.parse().map_err(|_| LowlevelError(format!("<size_alignment_map>: bad {n} {v}")))
        };
        let (sz, val) = (num("size")? as usize, num("alignment")?);
        if map.len() <= sz {
            map.resize(sz + 1, None);
        }
        map[sz] = Some(val);
    }
    if map.is_empty() {
        return err("Alignment map empty");
    }
    map[0] = Some(1);
    let mut cur = 1;
    Ok(map
        .into_iter()
        .map(|a| {
            cur = a.unwrap_or(cur);
            cur
        })
        .collect())
}

use super::fspec::{ModelId, Models, ProtoModel, Storage};
use super::inject::InjectLibrary;
use super::{err, LowlevelError, Result};
use crate::sleigh::Sleigh;
use crate::xml::{self, Element};
use std::collections::HashMap;

/// The compiler spec, as the architecture keeps it.
#[derive(Debug)]
pub(crate) struct CompilerSpec {
    /// `<stackpointer register=..>`: space, offset, size
    pub(crate) stack_pointer: (u32, u64, u32),
    /// `<stackpointer space=..>`: the space the stack lives in (the stack space's container)
    pub(crate) stack_container: u32,
    pub(crate) models: Models,
    pub(crate) injects: InjectLibrary,
    /// `<data_organization><size_alignment_map>`: the alignment of a primitive of each size
    /// (`TypeFactory::decodeAlignmentMap`), if the spec gives one
    pub(crate) align_map: Option<Vec<u32>>,
}

/// The `.sla`'s register and space names, for resolving the spec's `<register name=..>`.
pub(crate) struct SleighNames<'a> {
    sleigh: &'a Sleigh,
    regs: HashMap<&'a str, (u32, u64, u32)>,
}

impl<'a> SleighNames<'a> {
    pub(crate) fn new(sleigh: &'a Sleigh) -> SleighNames<'a> {
        let regs = sleigh.varnode_syms().into_iter().map(|(n, s, o, z)| (n, (s, o, z))).collect();
        SleighNames { sleigh, regs }
    }
}

impl SleighNames<'_> {
    /// The register `name`: space, offset, size.
    pub(crate) fn register(&self, name: &str) -> Result<(u32, u64, u32)> {
        self.regs.get(name).copied().ok_or_else(|| LowlevelError(format!("Unknown register name: {name}")))
    }

    /// The SLEIGH space `name`.
    pub(crate) fn space(&self, name: &str) -> Result<u32> {
        let i = self.sleigh.spaces.iter().position(|s| s.name == name);
        i.map(|i| i as u32).ok_or_else(|| LowlevelError(format!("Unknown space name: {name}")))
    }

    /// An offset read from the spec, wrapped to the address size of `space` (`AddrSpace::wrapOffset`
    /// for a negative offset such as a stack slot below the stack pointer). `None`: the code
    /// space, whose size the `stack` space shares.
    pub(crate) fn wrap(&self, space: Option<u32>, offset: i64) -> u64 {
        let s = space.unwrap_or_else(|| self.sleigh.code_space());
        let bytes = self.sleigh.spaces.get(s as usize).map_or(8, |sp| sp.size);
        let mask = if bytes >= 8 { u64::MAX } else { (1u64 << (8 * bytes)) - 1 };
        offset as u64 & mask
    }

    /// The unique space, for snippet temporaries.
    pub(crate) fn uniq_space(&self) -> u32 {
        self.sleigh.uniq_space()
    }

    /// The default space of `*` in a snippet.
    pub(crate) fn code_space(&self) -> u32 {
        self.sleigh.code_space()
    }
}

impl CompilerSpec {
    /// Read the `.cspec` text for the language `sleigh` decodes (`names`: its registers and spaces).
    pub(crate) fn parse(text: &str, sleigh: &Sleigh, names: &SleighNames) -> Result<CompilerSpec> {
        let root = xml::parse(text)?;
        if root.name != "compiler_spec" {
            return err(format!("expected <compiler_spec>, found <{}>", root.name));
        }
        let retaddr = match root.kid("returnaddress").map(|r| &r.kids[..]) {
            Some([v]) => Some(Storage::decode(v, names)?),
            Some(_) => return err("<returnaddress> needs exactly one storage element"),
            None => None,
        };
        let mut stack_pointer = None;
        let mut list = Vec::new();
        let mut default = None;
        let (mut eval_current, mut eval_called) = (None, None);
        let mut injects = InjectLibrary::new(sleigh);
        let mut align_map = None;
        for el in &root.kids {
            match el.name.as_str() {
                "stackpointer" => {
                    stack_pointer = Some((names.register(el.req("register")?)?, names.space(el.req("space")?)?));
                }
                "default_proto" => {
                    let [proto] = &el.kids[..] else { return err("<default_proto> needs one <prototype>") };
                    default = Some(ModelId(list.len() as u32));
                    list.push(ProtoModel::decode(proto, names, retaddr.as_ref())?);
                }
                "prototype" => list.push(ProtoModel::decode(el, names, retaddr.as_ref())?),
                "resolveprototype" => {
                    let merged = resolve_prototype(el, &list)?;
                    list.push(merged);
                }
                "eval_current_prototype" => eval_current = Some(el.req("name")?.to_string()),
                "eval_called_prototype" => eval_called = Some(el.req("name")?.to_string()),
                "callfixup" => {
                    let body = el.kid("pcode").and_then(|p| p.kid("body")).ok_or_else(|| {
                        LowlevelError(format!("callfixup {}: missing <pcode><body>", el.attr("name").unwrap_or("?")))
                    })?;
                    injects.add_callfixup(names, el.req("name")?, &body.text)?;
                }
                // read with the prototypes, or later (see the module comment)
                "data_organization" => {
                    if let Some(m) = el.kid("size_alignment_map") {
                        align_map = Some(decode_alignment_map(m)?);
                    }
                }
                "returnaddress" | "global" => {}
                n => return err(format!("<compiler_spec>: <{n}> is not supported")),
            }
        }
        let default = default.ok_or_else(|| LowlevelError("No default prototype specified".into()))?;
        let mut models = Models { list, default, eval_current: None, eval_called: None };
        models.eval_current = eval_current.map(|n| models.find(&n)).transpose()?;
        models.eval_called = eval_called.map(|n| models.find(&n)).transpose()?;
        let (stack_pointer, stack_container) =
            stack_pointer.ok_or_else(|| LowlevelError("No stack pointer specified".into()))?;
        Ok(CompilerSpec { stack_pointer, stack_container, models, injects, align_map })
    }
}

/// Port of `Architecture::decodeProto` for `<resolveprototype>` (`ProtoModelMerged::decode`).
fn resolve_prototype(el: &Element, list: &[ProtoModel]) -> Result<ProtoModel> {
    let members = el
        .kids_named("model")
        .map(|m| {
            let name = m.req("name")?;
            list.iter()
                .find(|p| p.name == name)
                .ok_or_else(|| LowlevelError(format!("Missing prototype model: {name}")))
        })
        .collect::<Result<Vec<_>>>()?;
    ProtoModel::merged(el.req("name")?, &members)
}
