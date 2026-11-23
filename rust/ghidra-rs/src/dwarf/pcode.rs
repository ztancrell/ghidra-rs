//! The DWARF import's functions and data types as Java's decompiler gets them
//! (`PcodeDataTypeManager.encodeType` / `encodeTypeRef`, `FunctionPrototype.encodePrototype`,
//! `HighFunction`'s parameter symbols), for the facts (`factsout`): the parameters of each
//! function the import gives a signature, and the `type` record of every data type they name.
use super::dtm::{Dtm, Id, Kind, B};
use super::{Func, Import, Piece};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Write as _;

/// A parameter of a function's record.
pub struct Param {
    pub name: String,
    /// ` thisptr="true"`, ` hiddenretparm="true"` or nothing
    pub flag: &'static str,
    /// its data type (`encodeTypeRef`)
    pub ty: String,
    /// its storage (`AddressXML.encode`)
    pub addr: String,
    /// in a register: Java gives it the range of the byte before the entry
    pub register: bool,
}

/// The prototype the import gives a function (`DWARFFunction.updateFunctionSignature`).
pub struct Proto {
    /// `__thiscall`: its first parameter is `this` (ThisCallingConventionDWARFFunctionFixup)
    pub this: bool,
    pub params: Vec<Param>,
    /// the return value's storage and data type
    pub ret: (String, String),
    pub varargs: bool,
    pub noreturn: bool,
}

/// What the facts take of a function of the import.
pub struct FuncFacts {
    /// its namespaces, the outermost first
    pub ns: Vec<String>,
    /// its name without them
    pub base: String,
    /// `Err`: what is not ported
    pub proto: Result<Proto, String>,
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&apos;")
}

/// The id a data type of the program's manager is written with. Java's are its database's
/// keys, which `tools/facts-diff.sh` leaves out; these only tie a `<typeref>` to its record.
fn db_id(i: u32) -> u64 {
    0x1000_0000_0000_0000 + u64::from(i) + 1
}

/// Close a `<type ...>` element whose opening tag is the first `open` bytes of `s`: in the tag
/// itself when it has no children, as Java's encoder does.
fn close(mut s: String, open: usize) -> String {
    if s.len() == open {
        s.pop();
        s.push_str("/>");
    } else {
        s.push_str("</type>");
    }
    s
}

/// `PcodeDataTypeManager` over the import's data types.
struct Encoder<'a> {
    d: &'a Dtm,
    /// name -> id of the core types (`encodeCoreTypes`)
    core: &'a HashMap<String, String>,
    /// the types named by a `<typeref>`, to be written as `type` records
    todo: Vec<u32>,
    seen: HashSet<u32>,
}

impl Encoder<'_> {
    fn core_ref(&self, tag: &str, b: &B, rest: &str) -> Result<String, String> {
        let name = b.name();
        let id = self.core.get(&name).ok_or_else(|| format!("the built-in data type {name}"))?;
        Ok(format!("<{tag} name=\"{name}\" id=\"{id}\"{rest}/>"))
    }

    /// `encodeNameIdAttributes` of a data type of the program
    fn name_id(&mut self, id: Id) -> Result<String, String> {
        let Id::Db(i) = id else { return Err("a data type that is not resolved".into()) };
        // DataTypeManagerDB.resolve names a conflicting type `.conflict<n>` in the order Java
        // meets them, which the import does not keep everywhere (README, "The DWARF importer")
        let name = self.d.name(id);
        if name.contains(".conflict") {
            return Err(format!("the data type name {name}"));
        }
        if self.seen.insert(i) {
            self.todo.push(i);
        }
        Ok(format!("name=\"{}\" id=\"0x{:x}\"", esc(&name), db_id(i)))
    }

    /// `encodeTypeRef` (PcodeDataTypeManager.java): void, integers, pointers and arrays in
    /// full, any other data type by name and id.
    fn type_ref(&mut self, id: Id, size: i32) -> Result<String, String> {
        match &self.d.dt(id).kind {
            Kind::Builtin(B::Void) => Ok("<void/>".into()),
            Kind::Builtin(b) if b.int_signed().is_some() => self.encode(id, size),
            Kind::Pointer { .. } | Kind::Array { .. } => self.encode(id, size),
            Kind::Builtin(b) => self.core_ref("typeref", b, ""),
            // a function definition has no length: the reference carries a size of 1
            Kind::FuncDef { .. } => Ok(format!("<typeref {} size=\"1\"/>", self.name_id(id)?)),
            _ if self.d.len(id) <= 0 => self.encode(id, size),
            _ => Ok(format!("<typeref {}/>", self.name_id(id)?)),
        }
    }

    /// `encodeType`
    fn encode(&mut self, id: Id, size: i32) -> Result<String, String> {
        let d = self.d;
        let len = d.len(id);
        match &d.dt(id).kind {
            Kind::Builtin(B::Void) => Ok("<void/>".into()),
            // encodeBooleanDataType, encodeCharDataType, encodeAbstractIntegerDataType
            Kind::Builtin(B::Bool) => self.core_ref("type", &B::Bool, " metatype=\"bool\" size=\"1\""),
            Kind::Builtin(b) => match b.int_signed() {
                Some(signed) => {
                    let meta = if signed { "int" } else { "uint" };
                    let char = match b.name().as_str() {
                        "char" | "uchar" | "schar" if len == 1 => " char=\"true\"",
                        "char" | "uchar" | "schar" => " utf=\"true\"",
                        _ => "",
                    };
                    self.core_ref("type", b, &format!(" metatype=\"{meta}\" size=\"{len}\"{char}"))
                }
                None => Err(format!("the built-in data type {} written in full", b.name())),
            },
            // encodeTypeDef (no pointer-typedef or format settings come from DWARF)
            Kind::Typedef { base } => {
                let sz = if d.len(*base) <= 0 { size } else { d.len(*base) };
                Ok(format!("<def {}>{}</def>", self.name_id(id)?, self.type_ref(*base, sz)?))
            }
            // encodePointer
            Kind::Pointer { to, .. } => {
                let to_len = d.len(*to);
                let inner = match &d.dt(*to).kind {
                    Kind::FuncDef { .. } => self.type_ref(*to, to_len)?,
                    _ if to_len < 0 => self.core_ref("typeref", &B::Undefined(1), "")?,
                    _ => self.type_ref(*to, to_len)?,
                };
                Ok(format!("<type name=\"\" metatype=\"ptr\" size=\"{len}\">{inner}</type>"))
            }
            // encodeArray
            Kind::Array { elem, count, elem_len } => {
                if d.zero_len(id) {
                    return Err("an array of no length (encodeOpaqueDataType)".into());
                }
                let inner = self.type_ref(*elem, *elem_len)?;
                Ok(format!("<type name=\"\" metatype=\"array\" size=\"{len}\" arraysize=\"{count}\">{inner}</type>"))
            }
            // encodeStructure, encodeUnion
            Kind::Composite(c) => {
                let meta = if c.union { "union" } else { "struct" };
                // a structure of no length is sent as an empty one of 1 byte
                if !c.union && c.len == 0 {
                    return Ok(format!("<type {} metatype=\"struct\" size=\"1\" alignment=\"1\"/>", self.name_id(id)?));
                }
                let mut s = format!(
                    "<type {} metatype=\"{meta}\" size=\"{len}\" alignment=\"{}\">",
                    self.name_id(id)?,
                    d.alignment(id)
                );
                let open = s.len();
                // a component's ordinal: in a structure that is not packed the undefined bytes
                // between the defined components count too
                let (mut ordinal, mut end) = (0, 0);
                for (k, comp) in c.comps.iter().enumerate() {
                    if c.union || c.packed {
                        ordinal = k as i32;
                    } else {
                        ordinal += (comp.offset - end).max(0);
                        end = end.max(comp.offset + comp.len);
                    }
                    let ord = ordinal;
                    ordinal += 1;
                    if comp.len == 0 {
                        continue;
                    }
                    // DataTypeComponentImpl.getDefaultFieldName
                    let name = match comp.name.as_deref().filter(|n| !n.is_empty()) {
                        Some(n) => esc(n),
                        None if c.union => format!("field{ord}"),
                        None => format!("field_0x{:x}", comp.offset),
                    };
                    match (comp.bf, c.union) {
                        (Some(_), true) => return Err("a bit field in a union".into()),
                        (Some(bf), false) => {
                            let base = self.type_ref(bf.base, d.len(bf.base))?;
                            let _ = write!(
                                s,
                                "<bitfield name=\"{name}\" id=\"{ord}\" offset=\"{}\" first=\"{}\" size=\"{}\">{base}</bitfield>",
                                comp.offset, bf.bit_offset, bf.bit_size
                            );
                        }
                        (None, union) => {
                            let ty = self.type_ref(comp.ty, comp.len)?;
                            let ord = if union { format!(" id=\"{ord}\"") } else { String::new() };
                            let _ = write!(s, "<field name=\"{name}\" offset=\"{}\"{ord}>{ty}</field>", comp.offset);
                        }
                    }
                }
                Ok(close(s, open))
            }
            // encodeEnum: the names by value, then by name (EnumDB.getNames); signed when a
            // value is negative
            Kind::Enum { vals, .. } => {
                let mut v = vals.clone();
                v.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.encode_utf16().cmp(b.0.encode_utf16())));
                let meta = if v.iter().any(|x| x.1 < 0) { "enum_int" } else { "enum_uint" };
                let mut s = format!("<type {} metatype=\"{meta}\" size=\"{len}\">", self.name_id(id)?);
                let open = s.len();
                for (n, x) in &v {
                    let _ = write!(s, "<val name=\"{}\" value=\"{x}\"/>", esc(n));
                }
                Ok(close(s, open))
            }
            // encodeFunctionDefinition: FunctionPrototype(FunctionSignature) and encodePrototype
            // (FunctionPrototype.java): the default model's extrapop, every parameter locked
            // and without storage
            Kind::FuncDef { ret, params, varargs, noreturn, cc } => {
                let mut s = format!(
                    "<type {} metatype=\"code\" size=\"1\"><prototype extrapop=\"8\" model=\"{}\" modellock=\"true\"",
                    self.name_id(id)?,
                    cc.as_deref().unwrap_or("unknown")
                );
                // no parameters: varargs too (`voidInputIsVarargs`)
                if *varargs || params.is_empty() {
                    s.push_str(" dotdotdot=\"true\"");
                }
                if params.is_empty() {
                    s.push_str(" voidlock=\"true\"");
                }
                if *noreturn {
                    s.push_str(" noreturn=\"true\"");
                }
                let _ = write!(
                    s,
                    "><returnsym typelock=\"true\"><addr/>{}</returnsym>",
                    self.type_ref(*ret, d.len(*ret).max(1))?
                );
                if params.is_empty() {
                    s.push_str("<internallist/>");
                } else {
                    s.push_str("<internallist>");
                    for p in params {
                        let ty = self.type_ref(p.ty, d.len(p.ty).max(1))?;
                        match p.name.as_deref().filter(|n| !n.is_empty()) {
                            Some(n) => {
                                let _ = write!(s, "<param name=\"{}\" typelock=\"true\" namelock=\"true\">", esc(n));
                            }
                            None => s.push_str("<param typelock=\"true\" namelock=\"false\">"),
                        }
                        let _ = write!(s, "<addr/>{ty}</param>");
                    }
                    s.push_str("</internallist>");
                }
                s.push_str("</prototype></type>");
                Ok(s)
            }
        }
    }

    /// `AddressXML.encode` of a storage: one varnode, or a join with the most significant piece
    /// first.
    fn addr(pieces: &[Piece]) -> String {
        let space = |p: &Piece| if p.stack { "stack" } else { "register" };
        match pieces {
            [] => "<addr/>".into(),
            [p] => format!("<addr space=\"{}\" offset=\"0x{:x}\" size=\"{}\"/>", space(p), p.offset, p.size),
            _ => {
                let mut s = "<addr space=\"join\"".to_string();
                for (k, p) in pieces.iter().rev().enumerate() {
                    let _ = write!(s, " piece{}=\"{}:0x{:x}:{}\"", k + 1, space(p), p.offset, p.size);
                }
                s.push_str("/>");
                s
            }
        }
    }

    fn proto(&mut self, f: &Func) -> Result<Proto, String> {
        let (stores, ret_store) = f.storage.clone()?;
        let mut params = Vec::new();
        for (k, ((name, ty), store)) in f.params.iter().zip(&stores).enumerate() {
            // the auto-parameters: `__return_storage_ptr__` first, then `this`
            let flag = match (k, name.as_str()) {
                (0, "__return_storage_ptr__") if f.hidden_ret => " hiddenretparm=\"true\"",
                (_, "this") if k == usize::from(f.hidden_ret) && f.cc.is_some() => " thisptr=\"true\"",
                _ => "",
            };
            params.push(Param {
                name: name.clone(),
                flag,
                ty: self.type_ref(*ty, self.d.len(*ty))?,
                addr: Self::addr(store),
                register: store.iter().all(|p| !p.stack),
            });
        }
        let this = match f.cc.as_deref() {
            Some("__thiscall") => true,
            None => false,
            Some(other) => return Err(format!("the calling convention {other}")),
        };
        let ret = (Self::addr(&ret_store), self.type_ref(f.ret, self.d.len(f.ret).max(1))?);
        Ok(Proto { this, params, ret, varargs: f.varargs, noreturn: f.noreturn })
    }
}

/// The facts of the import's functions by address, and the `type` records (id, text) of the
/// data types their prototypes name, with those these name. `core`: name -> id of the core
/// types.
pub fn facts(
    imp: &Import,
    core: &HashMap<String, String>,
) -> (BTreeMap<u64, FuncFacts>, HashMap<String, Result<String, String>>) {
    let mut enc = Encoder { d: &imp.dtm, core, todo: Vec::new(), seen: HashSet::new() };
    let mut funcs = BTreeMap::new();
    for f in &imp.funcs {
        let proto = enc.proto(f);
        funcs.insert(f.addr, FuncFacts { ns: f.ns.clone(), base: f.base.clone(), proto });
    }
    let mut types = HashMap::new();
    while let Some(i) = enc.todo.pop() {
        let id = Id::Db(i);
        types.insert(format!("{:x}", db_id(i)), enc.encode(id, enc.d.len(id)));
    }
    (funcs, types)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_join_names_the_most_significant_piece_first() {
        let reg = |offset, size| Piece { stack: false, offset, size };
        assert_eq!(Encoder::addr(&[]), "<addr/>");
        assert_eq!(Encoder::addr(&[reg(0x38, 4)]), "<addr space=\"register\" offset=\"0x38\" size=\"4\"/>");
        assert_eq!(
            Encoder::addr(&[reg(0x1200, 8), reg(0x1240, 8)]),
            "<addr space=\"join\" piece1=\"register:0x1240:8\" piece2=\"register:0x1200:8\"/>"
        );
        assert_eq!(close("<type a>".into(), 8), "<type a/>");
        assert_eq!(close("<type a><val/>".into(), 8), "<type a><val/></type>");
    }
}
