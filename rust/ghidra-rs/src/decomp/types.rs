//! Data-types (stage S6): a port of the parts of `type.cc` that type inference reaches with the
//! rules off — base types, pointers, `code`, the space-base type of a stack or global space,
//! arrays — plus structs, unions, enums and typedefs as `parse line` defines them (layout by
//! `TypeStruct::assignFieldOffsets` and the `.cspec`'s alignment map). Partial types,
//! `TypePointerRel` and descending into structs, unions and enums during inference are not
//! ported yet (inference fails loudly there).
//!
//! Types live in an arena in [`TypeFactory`], addressed by [`TypeId`], and are hash-consed the
//! way `TypeFactory::findAdd` dedups them, so two equal types are always the same id (the C++
//! compares `Datatype *` for identity).

use super::varnode::Space;
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct TypeId(u32);

/// `type_metatype` (the ones ported).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Meta {
    Void,
    Spacebase,
    Unknown,
    Int,
    Uint,
    Bool,
    Code,
    Float,
    Ptr,
    Array,
    Struct,
    Union,
}

/// `sub_metatype` values (type.hh), which order types in `Datatype::compare`.
mod sub {
    pub(super) const VOID: u8 = 23;
    pub(super) const SPACEBASE: u8 = 22;
    pub(super) const UNKNOWN: u8 = 21;
    pub(super) const INT_CHAR: u8 = 19;
    pub(super) const INT_PLAIN: u8 = 17;
    pub(super) const UINT_PLAIN: u8 = 16;
    pub(super) const INT_UNICODE: u8 = 12;
    pub(super) const BOOL: u8 = 10;
    pub(super) const CODE: u8 = 9;
    pub(super) const FLOAT: u8 = 8;
    pub(super) const PTR: u8 = 6;
    pub(super) const UINT_ENUM: u8 = 13;
    pub(super) const ARRAY: u8 = 3;
    pub(super) const STRUCT: u8 = 2;
    pub(super) const UNION: u8 = 1;
}

fn base2sub(m: Meta) -> u8 {
    match m {
        Meta::Void => sub::VOID,
        Meta::Spacebase => sub::SPACEBASE,
        Meta::Unknown => sub::UNKNOWN,
        Meta::Int => sub::INT_PLAIN,
        Meta::Uint => sub::UINT_PLAIN,
        Meta::Bool => sub::BOOL,
        Meta::Code => sub::CODE,
        Meta::Float => sub::FLOAT,
        Meta::Ptr => sub::PTR,
        Meta::Array => sub::ARRAY,
        Meta::Struct => sub::STRUCT,
        Meta::Union => sub::UNION,
    }
}

/// What a type is beyond its metatype and size.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum Kind {
    /// `TypeBase`, `TypeVoid`, `TypeChar`, `TypeUnicode`, `TypeCode` without a prototype
    Base,
    /// `TypePointer` (no address space: x86 has one data space)
    Pointer { to: TypeId, wordsize: u32 },
    /// `TypeSpacebase`: the space and the id of the scope mapping it ([`LOCAL_SCOPE`] or
    /// [`GLOBAL_SCOPE`])
    Spacebase { space: Space, scope: u32 },
    /// `TypeArray`
    Array { elem: TypeId, count: u32 },
    /// `TypeStruct` / `TypeUnion`: the fields (name, byte offset, type), from `parse line`
    Fields(Vec<(String, u32, TypeId)>),
    /// `TypeEnum`: the named values, from `parse line`
    Enum(Vec<(String, u64)>),
}

/// The scope id of the global scope (`Database::getGlobalScope`, id 0 in the console).
pub(crate) const GLOBAL_SCOPE: u32 = 0;
/// The scope id of a function's local scope (`ScopeLocal`).
pub(crate) const LOCAL_SCOPE: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct Datatype {
    pub(crate) meta: Meta,
    submeta: u8,
    pub(crate) size: u32,
    name: Option<String>,
    pub(crate) kind: Kind,
}

/// `Architecture::max_basetype_size`.
const MAX_BASETYPE_SIZE: u32 = 10;

/// Port of `TypeFactory` (the ported kinds).
#[derive(Debug, Clone)]
pub(crate) struct TypeFactory {
    types: Vec<Datatype>,
    dedup: HashMap<Datatype, TypeId>,
    /// `typecache` (sizes 0..=8), `typecache10`, `typecache16`
    cache: HashMap<(u32, Meta), TypeId>,
    /// `type_nochar`: the 1-byte signed integer that is not `char`
    nochar: Option<TypeId>,
    /// `alignMap`: the alignment of a primitive by size (`setDefaultAlignmentMap` until the
    /// `.cspec`.s `<data_organization>` replaces it)
    pub(crate) align_map: Vec<u32>,
}

impl Default for TypeFactory {
    fn default() -> TypeFactory {
        TypeFactory::new()
    }
}

impl TypeFactory {
    /// The core types of `SleighArchitecture::buildCoreTypes` (sleigh_arch.cc), cached as
    /// `cacheCoreTypes` does: `char` is preferred over `int1`, wide characters are not cached.
    pub(crate) fn new() -> TypeFactory {
        let mut f = TypeFactory {
            types: Vec::new(),
            dedup: HashMap::new(),
            cache: HashMap::new(),
            nochar: None,
            align_map: vec![1, 1, 2, 2, 4, 4, 4, 4, 8],
        };
        let core: &[(&'static str, u32, Meta, u8)] = &[
            ("void", 1, Meta::Void, sub::VOID),
            ("bool", 1, Meta::Bool, sub::BOOL),
            ("uint1", 1, Meta::Uint, sub::UINT_PLAIN),
            ("uint2", 2, Meta::Uint, sub::UINT_PLAIN),
            ("uint4", 4, Meta::Uint, sub::UINT_PLAIN),
            ("uint8", 8, Meta::Uint, sub::UINT_PLAIN),
            ("int1", 1, Meta::Int, sub::INT_PLAIN),
            ("int2", 2, Meta::Int, sub::INT_PLAIN),
            ("int4", 4, Meta::Int, sub::INT_PLAIN),
            ("int8", 8, Meta::Int, sub::INT_PLAIN),
            ("float4", 4, Meta::Float, sub::FLOAT),
            ("float8", 8, Meta::Float, sub::FLOAT),
            ("float10", 10, Meta::Float, sub::FLOAT),
            ("float16", 16, Meta::Float, sub::FLOAT),
            ("xunknown1", 1, Meta::Unknown, sub::UNKNOWN),
            ("xunknown2", 2, Meta::Unknown, sub::UNKNOWN),
            ("xunknown4", 4, Meta::Unknown, sub::UNKNOWN),
            ("xunknown8", 8, Meta::Unknown, sub::UNKNOWN),
            ("code", 1, Meta::Code, sub::CODE),
            ("char", 1, Meta::Int, sub::INT_CHAR),
            ("wchar2", 2, Meta::Int, sub::INT_UNICODE),
            ("wchar4", 4, Meta::Int, sub::INT_UNICODE),
        ];
        for &(name, size, meta, submeta) in core {
            let id = f.intern(Datatype { meta, submeta, size, name: Some(name.to_string()), kind: Kind::Base });
            match submeta {
                sub::INT_UNICODE => {}
                sub::INT_CHAR => {
                    f.cache.insert((size, meta), id);
                }
                _ => {
                    if name == "int1" {
                        f.nochar = Some(id);
                    }
                    f.cache.entry((size, meta)).or_insert(id);
                }
            }
        }
        f
    }

    fn intern(&mut self, t: Datatype) -> TypeId {
        if let Some(&id) = self.dedup.get(&t) {
            return id;
        }
        let id = TypeId(self.types.len() as u32);
        self.types.push(t.clone());
        self.dedup.insert(t, id);
        id
    }

    pub(crate) fn get(&self, id: TypeId) -> &Datatype {
        &self.types[id.0 as usize]
    }
    pub(crate) fn meta(&self, id: TypeId) -> Meta {
        self.get(id).meta
    }
    pub(crate) fn size(&self, id: TypeId) -> u32 {
        self.get(id).size
    }
    /// `TypePointer::getPtrTo`, for a pointer.
    pub(crate) fn ptr_to(&self, id: TypeId) -> Option<TypeId> {
        match self.get(id).kind {
            Kind::Pointer { to, .. } => Some(to),
            _ => None,
        }
    }
    /// `Datatype::getAlignSize`: the size rounded up to the alignment (`getPrimitiveAlignSize`
    /// for primitives, `calcAlignSize` for aggregates); 0 for a space-base type.
    pub(crate) fn align_size(&self, id: TypeId) -> u32 {
        let t = self.get(id);
        match t.kind {
            // the size is already a multiple of the alignment (calcAlignSize, n * element)
            Kind::Array { .. } | Kind::Fields(_) | Kind::Spacebase { .. } => t.size,
            _ if t.meta == Meta::Code => t.size,
            _ => self.primitive_align_size(t.size),
        }
    }

    /// `TypeFactory::getAlignment`: a primitive's alignment by (aligned) size, the last map
    /// entry for larger sizes.
    fn align_of_size(&self, size: u32) -> u32 {
        let m = &self.align_map;
        m.get(size as usize).or(m.last()).copied().unwrap_or(1)
    }

    /// `TypeFactory::getPrimitiveAlignSize`: the size rounded up to its alignment.
    fn primitive_align_size(&self, size: u32) -> u32 {
        let a = self.align_of_size(size);
        size.div_ceil(a) * a
    }

    /// Port of `TypeFactory::getBase(int4,type_metatype)`.
    pub(crate) fn base(&mut self, size: u32, meta: Meta) -> TypeId {
        if let Some(&id) = self.cache.get(&(size, meta)) {
            return id;
        }
        if size > MAX_BASETYPE_SIZE {
            let elem = self.base(1, Meta::Unknown);
            return self.array(elem, size);
        }
        self.intern(Datatype { meta, submeta: base2sub(meta), size, name: None, kind: Kind::Base })
    }

    /// Port of `TypeFactory::getBaseNoChar`.
    pub(crate) fn base_nochar(&mut self, size: u32, meta: Meta) -> TypeId {
        match self.nochar {
            Some(id) if size == 1 && meta == Meta::Int => id,
            _ => self.base(size, meta),
        }
    }

    /// `TypeFactory::getTypeArray(size / elem size, elem)`.
    fn array(&mut self, elem: TypeId, size: u32) -> TypeId {
        let count = size / self.size(elem).max(1);
        self.intern(Datatype {
            meta: Meta::Array,
            submeta: sub::ARRAY,
            size,
            name: None,
            kind: Kind::Array { elem, count },
        })
    }

    /// Port of `TypeFactory::getTypePointer`.
    pub(crate) fn pointer(&mut self, size: u32, to: TypeId, wordsize: u32) -> TypeId {
        self.intern(Datatype {
            meta: Meta::Ptr,
            submeta: sub::PTR,
            size,
            name: None,
            kind: Kind::Pointer { to, wordsize },
        })
    }

    /// Port of `TypeFactory::getTypePointerStripArray`.
    pub(crate) fn pointer_strip_array(&mut self, size: u32, to: TypeId, wordsize: u32) -> TypeId {
        let to = match self.get(to).kind {
            Kind::Array { elem, .. } => elem,
            _ => to,
        };
        self.pointer(size, to, wordsize)
    }

    /// Port of `TypeFactory::getTypeCode()`: the core `code` type.
    pub(crate) fn code(&mut self) -> TypeId {
        self.base(1, Meta::Code)
    }

    /// Port of `TypeFactory::getTypeSpacebase`.
    pub(crate) fn spacebase(&mut self, space: Space, scope: u32) -> TypeId {
        self.intern(Datatype {
            meta: Meta::Spacebase,
            submeta: sub::SPACEBASE,
            size: 0,
            name: None,
            kind: Kind::Spacebase { space, scope },
        })
    }

    /// Port of `Datatype::getSubType` for the kinds without a scope behind them (arrays); a
    /// space-base type's sub-types come from its scope (see `infertypes`).
    pub(crate) fn sub_type(&self, id: TypeId, off: i64) -> Option<(TypeId, i64)> {
        match self.get(id).kind {
            Kind::Array { elem, .. } if off >= 0 && off < i64::from(self.size(id)) => {
                Some((elem, off % i64::from(self.align_size(elem).max(1))))
            }
            _ => None,
        }
    }

    /// Port of `Datatype::typeOrder`: negative when `a` is the more specific type.
    pub(crate) fn order(&self, a: TypeId, b: TypeId) -> i32 {
        if a == b {
            0
        } else {
            self.compare(a, b, 10)
        }
    }

    /// Port of `Datatype::compare` and its overrides.
    fn compare(&self, a: TypeId, b: TypeId, level: i32) -> i32 {
        let (ta, tb) = (self.get(a), self.get(b));
        if ta.submeta != tb.submeta {
            return if ta.submeta < tb.submeta { -1 } else { 1 };
        }
        if ta.size != tb.size {
            return if tb.size > ta.size { 1 } else { -1 };
        }
        // ponytail: past the level limit the C++ orders by hashed type id; ours is creation order
        let deeper = |x: TypeId, y: TypeId| self.compare(x, y, level - 1);
        match (&ta.kind, &tb.kind) {
            (Kind::Pointer { to: pa, wordsize: wa }, Kind::Pointer { to: pb, wordsize: wb }) => {
                if wa != wb {
                    return if wa < wb { -1 } else { 1 };
                }
                if level - 1 < 0 {
                    return a.cmp(&b) as i32;
                }
                deeper(*pa, *pb)
            }
            (Kind::Array { elem: ea, .. }, Kind::Array { elem: eb, .. }) => {
                if level - 1 < 0 {
                    return a.cmp(&b) as i32;
                }
                deeper(*ea, *eb)
            }
            (Kind::Spacebase { space: sa, scope: ca }, Kind::Spacebase { space: sb, scope: cb }) => {
                if sa != sb {
                    return if sa.index() < sb.index() { -1 } else { 1 };
                }
                (*ca).cmp(cb) as i32
            }
            _ => 0,
        }
    }

    /// Port of `Datatype::printRaw` and its overrides.
    pub(crate) fn print_raw(&self, id: TypeId) -> String {
        let t = self.get(id);
        match t.kind {
            Kind::Pointer { to, .. } => format!("{} *", self.print_raw(to)),
            Kind::Array { elem, count } => format!("{} [{count}]", self.print_raw(elem)),
            _ if t.meta == Meta::Code => format!("{}()", t.name.as_deref().unwrap_or("funcptr")),
            _ => t.name.clone().unwrap_or_else(|| format!("unkbyte{}", t.size)),
        }
    }

    /// The text of a varnode's type: `ty`, or the type every varnode starts with
    /// (`getBase(size, TYPE_UNKNOWN)`) when it has none yet.
    pub(crate) fn print_vn_type(&self, ty: Option<TypeId>, size: u32) -> String {
        if let Some(id) = ty {
            return self.print_raw(id);
        }
        if let Some(&id) = self.cache.get(&(size, Meta::Unknown)) {
            return self.print_raw(id);
        }
        if size > MAX_BASETYPE_SIZE {
            return format!("xunknown1 [{size}]");
        }
        format!("unkbyte{size}")
    }
}

impl TypeFactory {
    /// A type by name (`TypeFactory::findByName`): the last one defined with it.
    pub(crate) fn find_by_name(&self, name: &str) -> Option<TypeId> {
        self.types.iter().rposition(|t| t.name.as_deref() == Some(name)).map(|i| TypeId(i as u32))
    }

    /// `TypeFactory::getTypeArray`: `count` elements of the element's align size.
    pub(crate) fn array_of(&mut self, elem: TypeId, count: u32) -> Result<TypeId, String> {
        let size = self.align_size(elem).checked_mul(count).ok_or("array too large")?;
        Ok(self.intern(Datatype {
            meta: Meta::Array,
            submeta: sub::ARRAY,
            size,
            name: None,
            kind: Kind::Array { elem, count },
        }))
    }

    /// `Datatype::getAlignment`: a primitive's from the alignment map (`TypeFactory::getAlignment`,
    /// the last entry for larger sizes), an array's its element's, an aggregate's its largest
    /// field's.
    pub(crate) fn alignment(&self, id: TypeId) -> u32 {
        let t = self.get(id);
        match &t.kind {
            Kind::Array { elem, .. } => self.alignment(*elem),
            Kind::Fields(fs) => fs.iter().map(|f| self.alignment(f.2)).max().unwrap_or(1),
            Kind::Spacebase { .. } => 1,
            _ if t.meta == Meta::Code => 1,
            // findAdd: alignment = getAlignment(getPrimitiveAlignSize(size))
            _ => self.align_of_size(self.primitive_align_size(t.size)),
        }
    }

    /// `TypeFactory::setFields` for a struct (`union == false`, fields laid out in order) or a
    /// union (every field at offset 0), named `name`.
    pub(crate) fn aggregate(
        &mut self,
        name: &str,
        union: bool,
        members: Vec<(String, TypeId)>,
    ) -> Result<TypeId, String> {
        let overflow = || format!("structure {name} is too large");
        let (mut off, mut align, mut fields) = (0u32, 1u32, Vec::new());
        for (n, t) in members {
            if self.meta(t) == Meta::Void {
                return Err(format!("Illegal field void in structure: {name}"));
            }
            // TypeStruct::assignFieldOffsets: align, then advance by the field's align size
            let (a, cursize) = (self.alignment(t).max(1), self.align_size(t));
            align = align.max(a);
            let at = if union { 0 } else { off.div_ceil(a).checked_mul(a).ok_or_else(overflow)? };
            off = if union { off.max(cursize) } else { at.checked_add(cursize).ok_or_else(overflow)? };
            fields.push((n, at, t));
        }
        // calcAlignSize: the size is padded to the alignment
        let size = off.div_ceil(align).checked_mul(align).ok_or_else(overflow)?;
        let (meta, submeta) = if union { (Meta::Union, sub::UNION) } else { (Meta::Struct, sub::STRUCT) };
        Ok(self.intern(Datatype { meta, submeta, size, name: Some(name.to_string()), kind: Kind::Fields(fields) }))
    }

    /// `TypeFactory::getTypeEnum`: a 4-byte unsigned enumeration.
    pub(crate) fn enumeration(&mut self, name: &str, values: Vec<(String, u64)>) -> TypeId {
        let kind = Kind::Enum(values);
        self.intern(Datatype { meta: Meta::Uint, submeta: sub::UINT_ENUM, size: 4, name: Some(name.to_string()), kind })
    }

    /// `TypeFactory::getTypedef`: a copy of `of` under a new name.
    pub(crate) fn typedef(&mut self, of: TypeId, name: &str) -> TypeId {
        let mut t = self.get(of).clone();
        t.name = Some(name.to_string());
        self.intern(t)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn core_types_and_order() {
        let mut f = TypeFactory::new();
        let c = f.base(1, Meta::Int);
        assert_eq!(f.print_raw(c), "char");
        let i1 = f.base_nochar(1, Meta::Int);
        assert_eq!(f.print_raw(i1), "int1");
        let u3 = f.base(3, Meta::Unknown);
        assert_eq!(f.print_raw(u3), "unkbyte3");
        let x16 = f.base(16, Meta::Unknown);
        assert_eq!(f.print_raw(x16), "xunknown1 [16]");
        assert_eq!(f.print_vn_type(None, 16), "xunknown1 [16]");
        let i4 = f.base(4, Meta::Int);
        let u4 = f.base(4, Meta::Unknown);
        let p = f.pointer(4, u4, 1);
        assert_eq!(f.print_raw(p), "xunknown4 *");
        assert!(f.order(p, i4) < 0 && f.order(i4, u4) < 0);
        let sb = f.spacebase(Space::Stack, LOCAL_SCOPE);
        let sp = f.pointer(4, sb, 1);
        assert_eq!(f.print_raw(sp), "unkbyte0 *");
        let code = f.code();
        let cp = f.pointer(4, code, 1);
        assert_eq!(f.print_raw(cp), "code() *");
        assert_eq!(f.pointer(4, u4, 1), p);
    }

    /// TypeStruct::assignFieldOffsets and findAdd's primitive alignment (default map).
    #[test]
    fn layout() {
        let mut f = TypeFactory::new();
        let (i4, c) = (f.base(4, Meta::Int), f.base(1, Meta::Int));
        let s = f.aggregate("s", false, vec![("a".into(), i4), ("c".into(), c)]).unwrap();
        assert_eq!((f.size(s), f.align_size(s), f.alignment(s)), (8, 8, 4));
        let s2 = f.aggregate("s2", false, vec![("c".into(), c), ("a".into(), i4)]).unwrap();
        assert_eq!(f.size(s2), 8);
        for (size, align_size, align) in [(3, 4, 4), (5, 8, 8), (6, 8, 8), (7, 8, 8), (10, 16, 8)] {
            let t = f.base(size, Meta::Unknown);
            assert_eq!((f.align_size(t), f.alignment(t)), (align_size, align), "size {size}");
        }
        let u3 = f.base(3, Meta::Unknown);
        let arr = f.array_of(u3, 2).unwrap();
        assert_eq!(f.size(arr), 8);
        let void = f.base(1, Meta::Void);
        assert!(f.aggregate("v", false, vec![("v".into(), void)]).is_err());
        assert!(f.array_of(i4, u32::MAX).is_err());
    }
}
