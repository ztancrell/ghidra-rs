//! Data-types (stage S6): a port of the parts of `type.cc` that type inference reaches with the
//! rules off — base types, pointers, `code`, the space-base type of a stack or global space,
//! arrays — plus structs, unions, enums and typedefs as `parse line` defines them (layout by
//! `TypeStruct::assignFieldOffsets` and the `.cspec`'s alignment map), and `TypePartialStruct`,
//! the piece of an array or structure `getExactPiece` makes. Partial unions and enums,
//! `TypePointerRel` and descending into structs, unions and enums during inference are not
//! ported yet (inference fails loudly there). (Superseded: "Partial types ... are not ported".)
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
    /// `TYPE_PARTIALSTRUCT`: part of a structure or array, stored apart from the whole
    PartialStruct,
}

/// `sub_metatype` values (type.hh), which order types in `Datatype::compare`.
mod sub {
    pub(super) const VOID: u8 = 23;
    pub(super) const SPACEBASE: u8 = 22;
    pub(super) const UNKNOWN: u8 = 21;
    pub(super) const PARTIALSTRUCT: u8 = 20;
    pub(super) const INT_CHAR: u8 = 19;
    pub(super) const INT_PLAIN: u8 = 17;
    pub(super) const UINT_PLAIN: u8 = 16;
    pub(super) const INT_UNICODE: u8 = 12;
    pub(super) const BOOL: u8 = 10;
    pub(super) const CODE: u8 = 9;
    pub(super) const FLOAT: u8 = 8;
    pub(super) const PTR: u8 = 6;
    pub(super) const PTR_STRUCT: u8 = 4;
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
        Meta::PartialStruct => sub::PARTIALSTRUCT,
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
    /// `TypePartialStruct`: `size` bytes at `offset` of the array or structure `container`;
    /// `stripped` is the undefined type of that size, for formal use
    PartialStruct { container: TypeId, offset: i32, stripped: TypeId },
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
    /// `Datatype::typedefImm`: the type each typedef names
    typedefs: HashMap<TypeId, TypeId>,
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
            typedefs: HashMap::new(),
        };
        let core: &[(&'static str, u32, Meta, u8)] = &[
            ("void", 0, Meta::Void, sub::VOID),
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
    /// `Datatype::needsResolution`: a union, a one-element array, a structure with one field
    /// filling it, or a pointer to one of those (not through another pointer).
    pub(crate) fn needs_resolution(&self, id: TypeId) -> bool {
        let t = self.get(id);
        match &t.kind {
            _ if t.meta == Meta::Union => true,
            Kind::Array { count, .. } => *count == 1,
            Kind::Fields(f) if t.meta == Meta::Struct => f.len() == 1 && self.size(f[0].2) == t.size,
            Kind::Pointer { to, .. } => self.meta(*to) != Meta::Ptr && self.needs_resolution(*to),
            _ => false,
        }
    }

    /// Whether `Datatype::findResolve` and `resolveInFlow` give `id` itself at every op and
    /// record nothing: a data-type that needs no resolution, or a pointer to anything but a
    /// union (`TypePointer::findResolve`, `TypePointer::resolveInFlow`). The resolutions of
    /// the other kinds (`ResolvedUnion`, unionresolve.cc) are not ported.
    pub(crate) fn resolves_to_self(&self, id: TypeId) -> bool {
        match self.get(id).kind {
            Kind::Pointer { to, .. } => self.meta(to) != Meta::Union,
            _ => !self.needs_resolution(id),
        }
    }

    /// Port of `Datatype::findCompatibleResolve` (`TypePointer`, `TypeArray`, `TypeStruct`,
    /// `TypeUnion`): the index of the form of `id` that is the data-type `ct`, or -1.
    pub(crate) fn find_compatible_resolve(&self, id: TypeId, ct: TypeId) -> i32 {
        let t = self.get(id);
        // the one element of an array, the one field of a structure
        let single = |inner: TypeId| {
            let through = self.needs_resolution(ct)
                && !self.needs_resolution(inner)
                && self.find_compatible_resolve(ct, inner) >= 0;
            if through || inner == ct {
                0
            } else {
                -1
            }
        };
        match &t.kind {
            Kind::Pointer { to, .. } => match self.get(ct).kind {
                Kind::Pointer { to: other, .. } => self.find_compatible_resolve(*to, other),
                _ => -1,
            },
            Kind::Array { elem, .. } => single(*elem),
            Kind::Fields(f) if t.meta == Meta::Struct => f.first().map_or(-1, |fld| single(fld.2)),
            Kind::Fields(f) if t.meta == Meta::Union => {
                let found = if !self.needs_resolution(ct) {
                    f.iter().position(|&(_, off, ft)| ft == ct && off == 0)
                } else {
                    f.iter().position(|&(_, off, ft)| {
                        off == 0
                            && self.size(ft) == self.size(ct)
                            && !self.needs_resolution(ft)
                            && self.find_compatible_resolve(ct, ft) >= 0
                    })
                };
                found.map_or(-1, |i| i as i32)
            }
            _ => -1,
        }
    }

    /// `Datatype::getName` (empty for a pointer or an array).
    pub(crate) fn name(&self, id: TypeId) -> Option<&str> {
        self.get(id).name.as_deref()
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
            // Datatype(sz, 1, TYPE_PARTIALSTRUCT): alignSize is the size (type.cc:140)
            Kind::PartialStruct { .. } => t.size,
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
    pub(crate) fn primitive_align_size(&self, size: u32) -> u32 {
        let a = self.align_of_size(size);
        size.div_ceil(a) * a
    }

    /// `Datatype::isCharPrint`: a `char` or a wide character type.
    pub(crate) fn is_char_print(&self, id: TypeId) -> bool {
        matches!(self.get(id).submeta, sub::INT_CHAR | sub::INT_UNICODE)
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

    /// Port of `TypeFactory::getTypePartialStruct` with the `TypePartialStruct` constructor
    /// (type.cc:2722-2741, 4431-4437): the piece of `size` bytes at `off` of the array or
    /// structure `contain`; a piece of a piece is a piece of the first one's parent.
    pub(crate) fn partial_struct(&mut self, mut contain: TypeId, mut off: i32, size: u32) -> TypeId {
        let stripped = self.base(size, Meta::Unknown);
        if let Kind::PartialStruct { container, offset, .. } = self.get(contain).kind {
            contain = container;
            off += offset;
        }
        self.intern(Datatype {
            meta: Meta::PartialStruct,
            submeta: sub::PARTIALSTRUCT,
            size,
            name: None,
            kind: Kind::PartialStruct { container: contain, offset: off, stripped },
        })
    }

    /// `Datatype::hasStripped` and `getStripped`: the undefined type a partial struct stands
    /// for in formal use, `None` for a type without a stripped form.
    pub(crate) fn stripped(&self, id: TypeId) -> Option<TypeId> {
        match self.get(id).kind {
            Kind::PartialStruct { stripped, .. } => Some(stripped),
            _ => None,
        }
    }

    /// `Datatype::isPieceStructured` (type.hh:989-995): an array, structure, union or partial
    /// struct, put together by separate assignments.
    pub(crate) fn is_piece_structured(&self, id: TypeId) -> bool {
        matches!(self.meta(id), Meta::Array | Meta::Struct | Meta::Union | Meta::PartialStruct)
    }

    /// Port of `TypePartialStruct::getComponentForPtr` (type.cc:2747-2756): the element of the
    /// parent array when the piece starts at one and it is not unknown, else the stripped type.
    pub(crate) fn component_for_ptr(&self, id: TypeId) -> TypeId {
        let Kind::PartialStruct { container, offset, stripped } = self.get(id).kind else { return id };
        if let Kind::Array { elem, .. } = self.get(container).kind {
            if self.meta(elem) != Meta::Unknown && offset % (self.align_size(elem).max(1) as i32) == 0 {
                return elem;
            }
        }
        stripped
    }

    /// Port of `TypeFactory::getTypePointer` (a partial struct is stripped first, type.cc:4372).
    pub(crate) fn pointer(&mut self, size: u32, to: TypeId, wordsize: u32) -> TypeId {
        let to = self.stripped(to).unwrap_or(to);
        // TypePointer::calcSubmeta: a pointer to a struct (unless it needs resolution) or to a
        // union compares as a pointer into a struct
        let submeta = match self.meta(to) {
            Meta::Struct if !self.needs_resolution(to) => sub::PTR_STRUCT,
            Meta::Union => sub::PTR_STRUCT,
            _ => sub::PTR,
        };
        self.intern(Datatype { meta: Meta::Ptr, submeta, size, name: None, kind: Kind::Pointer { to, wordsize } })
    }

    /// Port of `TypeFactory::getTypePointerStripArray`.
    pub(crate) fn pointer_strip_array(&mut self, size: u32, to: TypeId, wordsize: u32) -> TypeId {
        let to = self.stripped(to).unwrap_or(to); // type.cc:4354
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

    /// Port of `Datatype::getSubType` for the kinds without a scope behind them (arrays,
    /// structures, partial structs); a
    /// space-base type's sub-types come from its scope (see `infertypes`).
    pub(crate) fn sub_type(&self, id: TypeId, off: i64) -> Option<(TypeId, i64)> {
        match self.get(id).kind {
            Kind::Array { elem, .. } if off >= 0 && off < i64::from(self.size(id)) => {
                Some((elem, off % i64::from(self.align_size(elem).max(1))))
            }
            // TypeStruct::getSubType: the field holding the offset (getFieldIter); a union
            // has no sub-type (Datatype::getSubType)
            Kind::Fields(ref fields) if self.meta(id) == Meta::Struct => {
                let (mut min, mut max) = (0i64, fields.len() as i64 - 1);
                while min <= max {
                    let mid = (min + max) / 2;
                    let (_, foff, fty) = fields[mid as usize];
                    let foff = i64::from(foff);
                    if foff > off {
                        max = mid - 1;
                    } else if foff + i64::from(self.size(fty)) > off {
                        return Some((fty, off - foff));
                    } else {
                        min = mid + 1;
                    }
                }
                None
            }
            // TypePartialStruct::getSubType (type.cc:2765-2779): the parent's component, a level
            // further down while it reaches past the end of the piece
            Kind::PartialStruct { container, offset, .. } => {
                let size_left = i64::from(self.size(id)) - off;
                let (mut ct, mut off) = (container, off + i64::from(offset));
                loop {
                    (ct, off) = self.sub_type(ct, off)?;
                    if i64::from(self.size(ct)) - off <= size_left {
                        return Some((ct, off));
                    }
                }
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
            // TypePartialStruct::compare (type.cc:2792-2806)
            (
                Kind::PartialStruct { container: ca, offset: oa, .. },
                Kind::PartialStruct { container: cb, offset: ob, .. },
            ) => {
                if oa != ob {
                    return if oa < ob { -1 } else { 1 };
                }
                if level - 1 < 0 {
                    return a.cmp(&b) as i32;
                }
                deeper(*ca, *cb)
            }
            _ => 0,
        }
    }

    /// Port of `Datatype::printNameBase` and its overrides: the prefix a default variable name
    /// takes from its type (`p` per pointer level, `a` per array, then the first letter).
    pub(crate) fn print_name_base(&self, id: TypeId) -> String {
        let t = self.get(id);
        match t.kind {
            Kind::Pointer { to, .. } => format!("p{}", self.print_name_base(to)),
            Kind::Array { elem, .. } => format!("a{}", self.print_name_base(elem)),
            _ => t.name.as_deref().and_then(|n| n.chars().next()).map(String::from).unwrap_or_default(),
        }
    }

    /// Port of `Datatype::printRaw` and its overrides.
    pub(crate) fn print_raw(&self, id: TypeId) -> String {
        let t = self.get(id);
        match t.kind {
            Kind::Pointer { to, .. } => format!("{} *", self.print_raw(to)),
            Kind::Array { elem, count } => format!("{} [{count}]", self.print_raw(elem)),
            Kind::PartialStruct { container, offset, .. } => {
                format!("{}[off={offset},sz={}]", self.print_raw(container), t.size)
            }
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

    /// `Datatype::getTypedef`: the type a typedef names, `None` for any other type.
    pub(crate) fn typedef_of(&self, id: TypeId) -> Option<TypeId> {
        self.typedefs.get(&id).copied()
    }

    /// `while (t->getTypedef() != 0) t = t->getTypedef()`.
    pub(crate) fn strip_typedefs(&self, mut id: TypeId) -> TypeId {
        while let Some(of) = self.typedef_of(id) {
            id = of;
        }
        id
    }

    /// `Datatype::isEnumType`.
    pub(crate) fn is_enum(&self, id: TypeId) -> bool {
        matches!(self.get(id).kind, Kind::Enum(_))
    }

    /// `TypeStruct::beginField` and `TypeArray::getBase`: the first field of a struct (offset
    /// and type), the element of an array.
    pub(crate) fn first_field(&self, id: TypeId) -> Option<(u32, TypeId)> {
        match &self.get(id).kind {
            Kind::Fields(fs) => fs.first().map(|f| (f.1, f.2)),
            Kind::Array { elem, .. } => Some((0, *elem)),
            _ => None,
        }
    }

    /// `TypeFactory::getTypeArray`: `count` elements of the element's align size.
    pub(crate) fn array_of(&mut self, elem: TypeId, count: u32) -> Result<TypeId, String> {
        let elem = self.stripped(elem).unwrap_or(elem); // type.cc:4407
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
            Kind::Spacebase { .. } | Kind::PartialStruct { .. } => 1,
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
        let id = self.intern(t);
        if id != of {
            self.typedefs.entry(id).or_insert(of);
        }
        id
    }
}

/// A core type as Java Ghidra sends it (`<coretypes>`, `TypeFactory::decodeCoreTypes`).
pub(crate) struct CoreType<'a> {
    pub(crate) name: &'a str,
    pub(crate) size: u32,
    pub(crate) meta: Meta,
    /// `char="true"`: the ASCII character type
    pub(crate) ascii: bool,
    /// `utf="true"`: a wide character type
    pub(crate) utf: bool,
    pub(crate) id: u64,
}

/// The types of a facts file (`load facts`, see [`super::facts`]): the core types Java Ghidra
/// names and the kinds its type records hold.
impl TypeFactory {
    /// `TypeFactory::decodeCoreTypes` then `cacheCoreTypes`, in place of the console's core
    /// types: among the core types of one size and metatype the lowest id is the one
    /// `getBase` gives (the order of `DatatypeCompare`), `char` is preferred over the other
    /// 1-byte integers and wide characters are not cached. Returns each type by its id.
    pub(crate) fn set_core(&mut self, core: &mut [CoreType]) -> HashMap<u64, TypeId> {
        let align_map = std::mem::take(&mut self.align_map);
        *self = TypeFactory {
            types: Vec::new(),
            dedup: HashMap::new(),
            cache: HashMap::new(),
            nochar: None,
            align_map,
            typedefs: HashMap::new(),
        };
        core.sort_by_key(|c| c.id);
        let mut ids = HashMap::new();
        for c in core.iter() {
            let submeta = match (c.meta, c.ascii, c.utf) {
                (Meta::Int, true, _) => sub::INT_CHAR,
                (Meta::Int, _, true) => sub::INT_UNICODE,
                _ => base2sub(c.meta),
            };
            // setCoreType makes `void` the TypeVoid (size 0), whatever size the record gives
            let size = if c.meta == Meta::Void { 0 } else { c.size };
            let id =
                self.intern(Datatype { meta: c.meta, submeta, size, name: Some(c.name.to_string()), kind: Kind::Base });
            ids.insert(c.id, id);
            // typecache holds sizes up to 8, typecache10 and typecache16 the long floats
            if size > 8 && !(c.meta == Meta::Float && matches!(size, 10 | 16)) {
                continue;
            }
            match submeta {
                sub::INT_UNICODE => {}
                sub::INT_CHAR => {
                    self.cache.insert((size, c.meta), id);
                }
                _ => {
                    if c.meta == Meta::Int && size == 1 {
                        self.nochar = Some(id);
                    }
                    self.cache.entry((size, c.meta)).or_insert(id);
                }
            }
        }
        ids
    }

    /// A named primitive that is no core type (`TypeBase` from a `<type>` record).
    pub(crate) fn named_base(&mut self, name: &str, size: u32, meta: Meta) -> TypeId {
        self.intern(Datatype { meta, submeta: base2sub(meta), size, name: Some(name.to_string()), kind: Kind::Base })
    }

    /// `TypeFactory::decodeStruct`/`decodeUnion`, first half: the named aggregate without its
    /// fields, so that the fields can point back at it.
    pub(crate) fn declare_aggregate(&mut self, name: &str, union: bool, size: u32) -> TypeId {
        let (meta, submeta) = if union { (Meta::Union, sub::UNION) } else { (Meta::Struct, sub::STRUCT) };
        self.intern(Datatype { meta, submeta, size, name: Some(name.to_string()), kind: Kind::Fields(Vec::new()) })
    }

    /// `TypeFactory::setFields` of a declared aggregate: the fields (name, offset, type) at the
    /// offsets the record states.
    // ponytail: the alignment is the largest field's, not the record's `alignment` (a packed
    // structure differs); read the attribute when a locked parameter of such a type shows up
    pub(crate) fn set_fields(&mut self, id: TypeId, fields: Vec<(String, u32, TypeId)>) {
        let old = self.types[id.0 as usize].clone();
        self.dedup.remove(&old);
        let t = &mut self.types[id.0 as usize];
        t.kind = Kind::Fields(fields);
        self.dedup.insert(t.clone(), id);
    }

    /// `TypeFactory::decodeEnum` for an unsigned enumeration of `size` bytes.
    pub(crate) fn enumeration_sized(&mut self, name: &str, size: u32, values: Vec<(String, u64)>) -> TypeId {
        let kind = Kind::Enum(values);
        self.intern(Datatype { meta: Meta::Uint, submeta: sub::UINT_ENUM, size, name: Some(name.to_string()), kind })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn needs_resolution_kinds() {
        let mut f = TypeFactory::new();
        let i4 = f.base(4, Meta::Int);
        assert!(!f.needs_resolution(i4));
        let one = f.array_of(i4, 1).unwrap();
        let two = f.array_of(i4, 2).unwrap();
        assert!(f.needs_resolution(one) && !f.needs_resolution(two));
        let s1 = f.aggregate("s1", false, vec![("a".into(), i4)]).unwrap();
        let s2 = f.aggregate("s2", false, vec![("a".into(), i4), ("b".into(), i4)]).unwrap();
        let u = f.aggregate("u", true, vec![("a".into(), i4), ("b".into(), i4)]).unwrap();
        assert!(f.needs_resolution(s1) && !f.needs_resolution(s2) && f.needs_resolution(u));
        let p = f.pointer(4, s1, 1);
        let pp = f.pointer(4, p, 1);
        assert!(f.needs_resolution(p) && !f.needs_resolution(pp));
    }

    /// TypePartialStruct: a piece of a piece is a piece of the parent, its components are the
    /// parent's, a pointer to it points at the stripped type.
    #[test]
    fn partial_struct() {
        let mut f = TypeFactory::new();
        let (i4, x16) = (f.base(4, Meta::Int), f.base(16, Meta::Unknown));
        let arr = f.array_of(i4, 4).unwrap();
        let p = f.partial_struct(arr, 4, 8);
        assert_eq!(f.print_raw(p), "int4 [4][off=4,sz=8]");
        assert_eq!((f.sub_type(p, 0), f.sub_type(p, 5), f.sub_type(p, 8)), (Some((i4, 0)), Some((i4, 1)), None));
        let pp = f.partial_struct(p, 4, 4);
        assert_eq!(f.print_raw(pp), "int4 [4][off=8,sz=4]");
        assert_eq!((f.component_for_ptr(p), f.stripped(p)), (i4, Some(f.base(8, Meta::Unknown))));
        let px = f.partial_struct(x16, 8, 8);
        assert_eq!(f.component_for_ptr(px), f.base(8, Meta::Unknown));
        let ptr = f.pointer(8, px, 1);
        assert_eq!(f.ptr_to(ptr), Some(f.base(8, Meta::Unknown)));
        assert!(f.is_piece_structured(p) && !f.needs_resolution(p) && f.order(p, x16) > 0);
        assert_eq!((f.align_size(p), f.alignment(p)), (8, 1));
    }

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
        let void = f.base(0, Meta::Void);
        assert!(f.aggregate("v", false, vec![("v".into(), void)]).is_err());
        assert!(f.array_of(i4, u32::MAX).is_err());
    }

    /// TypePointer::calcSubmeta: struct (not needing resolution) and union pointees give
    /// SUB_PTR_STRUCT, which orders before a plain pointer.
    #[test]
    fn pointer_submeta() {
        let mut f = TypeFactory::new();
        let (i4, c) = (f.base(4, Meta::Int), f.base(1, Meta::Int));
        let s2 = f.aggregate("s2", false, vec![("a".into(), i4), ("c".into(), c)]).unwrap();
        let s1 = f.aggregate("s1", false, vec![("a".into(), i4)]).unwrap();
        let u = f.aggregate("u", true, vec![("a".into(), i4), ("c".into(), c)]).unwrap();
        let a1 = f.array_of(i4, 1).unwrap();
        let sub_of = |f: &mut TypeFactory, to| {
            let p = f.pointer(4, to, 1);
            f.get(p).submeta
        };
        assert_eq!(sub_of(&mut f, s2), sub::PTR_STRUCT);
        assert_eq!(sub_of(&mut f, u), sub::PTR_STRUCT);
        assert_eq!(sub_of(&mut f, s1), sub::PTR);
        assert_eq!(sub_of(&mut f, a1), sub::PTR);
        assert_eq!(sub_of(&mut f, i4), sub::PTR);
        let (ps, pi) = (f.pointer(4, s2, 1), f.pointer(4, i4, 1));
        assert!(f.order(ps, pi) < 0 && f.order(pi, ps) > 0);
    }

    #[test]
    fn ghidra_core_types() {
        let core = |name, size, meta, ascii, id| CoreType { name, size, meta, ascii, utf: false, id };
        let mut list = vec![
            core("long", 4, Meta::Int, false, 0x9b),
            core("int", 4, Meta::Int, false, 0x99),
            core("sbyte", 1, Meta::Int, false, 0xae),
            core("char", 1, Meta::Int, true, 0x7b),
            core("undefined4", 4, Meta::Unknown, false, 0xc0),
            core("uint16", 16, Meta::Uint, false, 0xc8),
            core("float10", 10, Meta::Float, false, 0x84),
        ];
        let mut f = TypeFactory::new();
        let ids = f.set_core(&mut list);
        // the lowest id of a size and metatype is the base type; char is preferred, sbyte is
        // the 1-byte integer that is not char; only sizes up to 8 and the long floats are cached
        let (i4, c, nc, u4) =
            (f.base(4, Meta::Int), f.base(1, Meta::Int), f.base_nochar(1, Meta::Int), f.base(4, Meta::Unknown));
        assert_eq!([i4, c, nc, u4].map(|t| f.print_raw(t)), ["int", "char", "sbyte", "undefined4"]);
        assert_eq!(f.print_raw(ids[&0x9b]), "long");
        assert_eq!(f.print_name_base(u4), "u");
        let (u16, f10) = (f.base(16, Meta::Uint), f.base(10, Meta::Float));
        assert_eq!((f.name(u16), f.print_raw(f10).as_str()), (None, "float10"));
        // a structure that points at itself
        let s = f.declare_aggregate("node", false, 8);
        let p = f.pointer(4, s, 1);
        f.set_fields(s, vec![("next".into(), 0, p), ("value".into(), 4, i4)]);
        assert_eq!((f.first_field(s), f.ptr_to(p), f.size(s)), (Some((0, p)), Some(s), 8));
        assert_eq!(f.declare_aggregate("other", false, 8), TypeId(s.0 + 2));
    }

    #[test]
    fn typedefs_and_resolution() {
        let mut f = TypeFactory::new();
        let (i4, c) = (f.base(4, Meta::Int), f.base(1, Meta::Int));
        let td = f.typedef(i4, "myint");
        assert_eq!((f.typedef_of(td), f.strip_typedefs(td), f.typedef_of(i4)), (Some(i4), i4, None));
        let one = f.aggregate("one", false, vec![("a".into(), i4)]).unwrap();
        let two = f.aggregate("two", false, vec![("a".into(), i4), ("c".into(), c)]).unwrap();
        let un = f.aggregate("u", true, vec![("a".into(), i4), ("c".into(), c)]).unwrap();
        let a1 = f.array_of(i4, 1).unwrap();
        let p1 = f.pointer(4, one, 1);
        let pp = f.pointer(4, p1, 1);
        assert!(f.needs_resolution(one) && f.needs_resolution(un) && f.needs_resolution(a1) && f.needs_resolution(p1));
        assert!(!f.needs_resolution(two) && !f.needs_resolution(pp) && !f.needs_resolution(i4));
        // a pointer to a one-field structure resolves to itself; only a union is scored
        let pu = f.pointer(4, un, 1);
        assert!(
            f.resolves_to_self(p1) && f.resolves_to_self(two) && !f.resolves_to_self(one) && !f.resolves_to_self(pu)
        );
        let pi = f.pointer(4, i4, 1);
        assert_eq!((f.find_compatible_resolve(p1, pi), f.find_compatible_resolve(p1, pp)), (0, -1));
        assert_eq!((f.find_compatible_resolve(un, c), f.find_compatible_resolve(a1, c)), (1, -1));
        assert_eq!((f.find_compatible_resolve(un, i4), f.find_compatible_resolve(one, a1)), (0, 0));
        assert_eq!(f.first_field(two), Some((0, i4)));
    }
}
