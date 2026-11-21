//! Ghidra's packed data-type archives (`.gdt`), read in place and read-only: the database
//! (`db`), the data types of its tables (this module: `DataTypeManagerDB` and its `*DBAdapter*`
//! classes) and what Java's "Apply Data Archives" makes of its function definitions (`protos`).
//! Adapter versions, table kinds and built-in classes not ported fail by name.
pub mod db;
pub mod protos;

use db::{Db, Record, Result};
use std::collections::{BTreeMap, HashMap};

/// `DataTypeManagerDB` table kinds (the top byte of a data-type id, `DATA_TYPE_KIND_SHIFT`).
pub const BUILT_IN: i64 = 0;
pub const COMPOSITE: i64 = 1;
pub const ARRAY: i64 = 3;
pub const POINTER: i64 = 4;
pub const TYPEDEF: i64 = 5;
pub const FUNCTION_DEF: i64 = 6;
pub const ENUM: i64 = 8;
pub const BITFIELD: i64 = 9;
const KIND_SHIFT: u32 = 56;
/// `DataTypeManager.DEFAULT_DATATYPE_ID`: `DataType.DEFAULT` ("undefined").
pub const DEFAULT_ID: i64 = 0;

/// The kind of an id (`DataTypeManagerDB.getTableID`-style split).
pub fn kind(id: i64) -> i64 {
    id >> KIND_SHIFT
}

/// A component of a composite (`DataTypeComponentDB`, `ComponentDBAdapterV0`).
#[derive(Debug, Clone)]
pub struct Component {
    pub ordinal: i32,
    pub offset: i32,
    pub length: i32,
    pub name: Option<String>,
    /// a data-type id; a bitfield is `Bitfield`
    pub ty: i64,
    pub bitfield: Option<Bitfield>,
}

/// `BitFieldDBDataType.getBitFieldDataType`: base type, bit size and bit offset of an id.
#[derive(Debug, Clone, Copy)]
pub struct Bitfield {
    pub base: i64,
    pub bit_size: i32,
    pub bit_offset: i32,
}

/// A parameter of a function definition (`ParameterDefinitionDB`, `ParameterDefinitionDBAdapterV1`).
#[derive(Debug, Clone)]
pub struct Param {
    pub name: Option<String>,
    pub ty: i64,
    pub length: i32,
}

/// A data type of the archive, by kind.
#[derive(Debug, Clone)]
pub enum Kind {
    /// a built-in (`BuiltinDBAdapterV0`): its Java class's simple name
    BuiltIn(String),
    Composite {
        union: bool,
        length: i32,
        alignment: i32,
        components: Vec<Component>,
    },
    Typedef {
        base: i64,
    },
    Pointer {
        to: i64,
        length: i8,
    },
    Array {
        element: i64,
        count: i32,
        element_length: i32,
    },
    Enum {
        size: i8,
        values: Vec<(String, i64)>,
    },
    FunctionDef {
        ret: i64,
        params: Vec<Param>,
        varargs: bool,
        noreturn: bool,
        convention: String,
    },
}

/// One data type: name (empty for pointers and arrays), category id and kind.
#[derive(Debug, Clone)]
pub struct DataType {
    pub name: String,
    pub category: i64,
    pub kind: Kind,
}

/// The data types of one archive by id, and its function definitions in table order.
pub struct Archive {
    pub types: HashMap<i64, DataType>,
    pub function_defs: Vec<i64>,
}

/// The schema version each ported adapter reads (`*DBAdapterV<n>`), by table name.
const ADAPTERS: [(&str, i32); 12] = [
    ("Built-in datatypes", 0),
    ("Calling Conventions", 0),
    ("Categories", 0),
    ("Composite Data Types", 6),
    ("Component Data Types", 0),
    ("Typedefs", 2),
    ("Pointers", 2),
    ("Arrays", 1),
    ("Enumeration Data Types", 1),
    ("Enumeration Values", 1),
    ("Function Definitions", 2),
    ("Function Parameters", 1),
];

/// Typed column access by the column names of the adapter's schema.
struct Cols<'a, 'r> {
    r: &'a Record<'r>,
    names: &'a [String],
}

impl Cols<'_, '_> {
    fn ix(&self, n: &str) -> Result<usize> {
        self.names.iter().position(|c| c == n).ok_or_else(|| format!("no column {n}"))
    }
    fn long(&self, n: &str) -> Result<i64> {
        self.r.long(self.ix(n)?)
    }
    fn int(&self, n: &str) -> Result<i32> {
        self.r.int(self.ix(n)?)
    }
    fn byte(&self, n: &str) -> Result<i8> {
        self.r.byte(self.ix(n)?)
    }
    fn boolean(&self, n: &str) -> Result<bool> {
        self.r.boolean(self.ix(n)?)
    }
    fn string(&self, n: &str) -> Result<Option<String>> {
        Ok(self.r.string(self.ix(n)?)?.map(str::to_string))
    }
}

/// Every record of `table` with its columns, after checking the adapter version is ported.
fn rows<'d>(db: &'d Db, table: &str, f: &mut dyn FnMut(&Cols) -> Result<()>) -> Result<()> {
    let Some(schema) = db.schema(table) else { return Ok(()) };
    let want = ADAPTERS.iter().find(|a| a.0 == table).map(|a| a.1);
    if want != Some(schema.version) {
        return Err(format!("{table}: adapter version {} not ported", schema.version));
    }
    for r in db.records(table)? {
        f(&Cols { r: &r, names: &schema.names }).map_err(|e| format!("{table} record {}: {e}", r.key))?;
    }
    Ok(())
}

fn id(kind: i64, key: i64) -> i64 {
    (kind << KIND_SHIFT) | key
}

/// `BitFieldDBDataType.getBitFieldDataType`: the base (typedef, enum or integer built-in) id.
fn bitfield(v: i64) -> Result<Bitfield> {
    let bit_size = (v & 0xff) as i32;
    let bit_offset = ((v >> 8) & 0xff) as i32;
    let base_kind = ((v >> 16) & 0xff) >> 5 & 3;
    let index = (v >> 24) & 0xffff_ffff;
    let base = match base_kind {
        1 => id(TYPEDEF, index),
        2 => id(ENUM, index),
        3 => id(BUILT_IN, index),
        _ => return Err(format!("bitfield {v:#x}: no base type (integer fallback not ported)")),
    };
    Ok(Bitfield { base, bit_size, bit_offset })
}

impl Archive {
    /// Opens a packed archive (`FileDataTypeManager.openFileArchive`, read-only).
    pub fn open(path: &std::path::Path) -> Result<Archive> {
        Archive::read(&Db::open_packed(path)?).map_err(|e| format!("{}: {e}", path.display()))
    }

    /// Every data type of the database (the adapters of `DataTypeManagerDB`).
    pub fn read(db: &Db) -> Result<Archive> {
        for t in db.tables.keys() {
            let known = ADAPTERS.iter().any(|a| a.0 == t)
                || ["DT_PARENT_CHILD", "Data Type Archive IDs", "DataTypeManager", "Variable Storage"]
                    .contains(&t.as_str())
                || t.starts_with("Default Settings");
            if !known {
                return Err(format!("table {t} not ported"));
            }
        }
        if !db.records("Default Settings")?.is_empty() {
            return Err("data-type settings (Default Settings) not ported".into());
        }
        let mut types = HashMap::new();
        let mut conventions = HashMap::new();
        rows(db, "Calling Conventions", &mut |c| {
            conventions.insert(c.r.key, c.string("Name")?.unwrap_or_default());
            Ok(())
        })?;
        rows(db, "Built-in datatypes", &mut |c| {
            let class = c.string("Class Name")?.unwrap_or_default();
            let simple = class.rsplit('.').next().unwrap_or_default().to_string();
            let name = c.string("Name")?.unwrap_or_default();
            types.insert(
                id(BUILT_IN, c.r.key),
                DataType { name, category: c.long("Category ID")?, kind: Kind::BuiltIn(simple) },
            );
            Ok(())
        })?;
        let mut components: BTreeMap<i64, Vec<Component>> = BTreeMap::new();
        rows(db, "Component Data Types", &mut |c| {
            let ty = c.long("Data Type ID")?;
            let bf = if kind(ty) == BITFIELD { Some(bitfield(ty & !(0xff << KIND_SHIFT))?) } else { None };
            components.entry(c.long("Parent")?).or_default().push(Component {
                ordinal: c.int("Ordinal")?,
                offset: c.int("Offset")?,
                length: c.int("Component Size")?,
                name: c.string("Field Name")?,
                ty,
                bitfield: bf,
            });
            Ok(())
        })?;
        rows(db, "Composite Data Types", &mut |c| {
            let key = id(COMPOSITE, c.r.key);
            let mut comps = components.remove(&key).unwrap_or_default();
            comps.sort_by_key(|x| x.ordinal);
            let kind = Kind::Composite {
                union: c.boolean("Is Union")?,
                length: c.int("Length")?,
                alignment: c.int("Alignment")?,
                components: comps,
            };
            types.insert(
                key,
                DataType { name: c.string("Name")?.unwrap_or_default(), category: c.long("Category ID")?, kind },
            );
            Ok(())
        })?;
        rows(db, "Typedefs", &mut |c| {
            if c.r.short(1)? != 0 {
                return Err("typedef flags (auto-named typedefs) not ported".into());
            }
            let kind = Kind::Typedef { base: c.long("Data Type ID")? };
            types.insert(
                id(TYPEDEF, c.r.key),
                DataType { name: c.string("Name")?.unwrap_or_default(), category: c.long("Category ID")?, kind },
            );
            Ok(())
        })?;
        rows(db, "Pointers", &mut |c| {
            let kind = Kind::Pointer { to: c.long("Data Type ID")?, length: c.byte("Length")? };
            types
                .insert(id(POINTER, c.r.key), DataType { name: String::new(), category: c.long("Category ID")?, kind });
            Ok(())
        })?;
        rows(db, "Arrays", &mut |c| {
            let kind = Kind::Array {
                element: c.long("Data Type ID")?,
                count: c.int("Dimension")?,
                element_length: c.int("Length")?,
            };
            types.insert(id(ARRAY, c.r.key), DataType { name: String::new(), category: c.long("Cat ID")?, kind });
            Ok(())
        })?;
        let mut values: BTreeMap<i64, Vec<(String, i64)>> = BTreeMap::new();
        rows(db, "Enumeration Values", &mut |c| {
            values
                .entry(c.long("Enum ID")?)
                .or_default()
                .push((c.string("Name")?.unwrap_or_default(), c.long("Value")?));
            Ok(())
        })?;
        rows(db, "Enumeration Data Types", &mut |c| {
            let key = id(ENUM, c.r.key);
            let kind = Kind::Enum { size: c.byte("Size")?, values: values.remove(&key).unwrap_or_default() };
            types.insert(
                key,
                DataType { name: c.string("Name")?.unwrap_or_default(), category: c.long("Category ID")?, kind },
            );
            Ok(())
        })?;
        let mut params: BTreeMap<i64, Vec<(i32, Param)>> = BTreeMap::new();
        rows(db, "Function Parameters", &mut |c| {
            let p = Param { name: c.string("Name")?, ty: c.long("Data Type ID")?, length: c.int("Data Type Length")? };
            params.entry(c.long("Parent ID")?).or_default().push((c.int("Ordinal")?, p));
            Ok(())
        })?;
        let mut function_defs = Vec::new();
        rows(db, "Function Definitions", &mut |c| {
            let key = id(FUNCTION_DEF, c.r.key);
            let mut ps = params.remove(&key).unwrap_or_default();
            ps.sort_by_key(|p| p.0);
            let flags = c.byte("Flags")?;
            // DataTypeManagerDB.getCallingConventionName
            let convention = match c.byte("Call Conv ID")? {
                0 => "unknown".to_string(),
                1 => "default".to_string(),
                n => conventions.get(&(n as i64)).cloned().unwrap_or_else(|| "unknown".into()),
            };
            let kind = Kind::FunctionDef {
                ret: c.long("Return Type ID")?,
                params: ps.into_iter().map(|p| p.1).collect(),
                varargs: flags & 1 != 0,
                noreturn: flags & 2 != 0,
                convention,
            };
            types.insert(
                key,
                DataType { name: c.string("Name")?.unwrap_or_default(), category: c.long("Category ID")?, kind },
            );
            function_defs.push(key);
            Ok(())
        })?;
        Ok(Archive { types, function_defs })
    }

    /// The data type of `id`, or an error naming it (DEFAULT has no record).
    pub fn get(&self, id: i64) -> Result<&DataType> {
        self.types.get(&id).ok_or_else(|| format!("no data type {id:#x}"))
    }
}

#[cfg(test)]
mod tests;
