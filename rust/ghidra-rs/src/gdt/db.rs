//! Read-only port of Ghidra's packed database and its tables: the packed file
//! (`ghidra.framework.store.local.ItemDeserializer`, as `PackedDatabase` opens it), the buffer
//! file (`db.buffers.LocalBufferFile`), the database parameters (`db.DBParms`), the master
//! table (`db.MasterTable`, `db.TableRecord`), schemas (`db.Schema`), long-key B-tree nodes
//! (`db.LongKeyInteriorNode`, `db.FixedRecNode`, `db.VarRecNode`), records (`db.DBRecord`,
//! `db.SparseRecord`) and big records (`db.ChainedBuffer`). Nothing is ever written.
//! What is not ported (index tables, other key types, obfuscated chained buffers) fails by name.
use std::collections::{BTreeMap, HashSet};
use std::io::Read;

/// `LocalBufferFile.MAGIC_NUMBER`.
const BUFFER_FILE_MAGIC: i64 = 0x2f30312c34292c2a;
/// `ItemSerializer.MAGIC_NUMBER` and `FORMAT_VERSION`.
const PACKED_MAGIC: i64 = 0x2e30212634e92c20;
const PACKED_FORMAT_VERSION: i32 = 1;
/// `LocalBufferFile.BUFFER_PREFIX_SIZE`: flags and buffer id before each buffer.
const BUFFER_PREFIX: usize = 5;
/// `NodeMgr` node types.
const LONGKEY_INTERIOR_NODE: u8 = 0;
const LONGKEY_VAR_REC_NODE: u8 = 1;
const LONGKEY_FIXED_REC_NODE: u8 = 2;
const FIXEDKEY_INTERIOR_NODE: u8 = 5;
const FIXEDKEY_VAR_REC_NODE: u8 = 6;
const FIXEDKEY_FIXED_REC_NODE: u8 = 7;
const CHAINED_BUFFER_INDEX_NODE: u8 = 8;
const CHAINED_BUFFER_DATA_NODE: u8 = 9;
/// `LongKeyRecordNode.RECORD_LEAF_HEADER_SIZE`: node type, key count, previous and next leaf.
const LEAF_HEADER: usize = 13;
/// How deep a table's B-tree may be (Java has no limit; a real tree is a few levels deep).
const MAX_TREE_DEPTH: usize = 64;
/// `Field` type codes.
const BYTE_TYPE: u8 = 0;
const SHORT_TYPE: u8 = 1;
const INT_TYPE: u8 = 2;
const LONG_TYPE: u8 = 3;
const STRING_TYPE: u8 = 4;
const BINARY_OBJ_TYPE: u8 = 5;
const BOOLEAN_TYPE: u8 = 6;
const FIXED_10_TYPE: u8 = 7;
/// `Schema.FIELD_EXTENSION_INDICATOR`, `Schema.SPARSE_FIELD_LIST_EXTENSION`.
const FIELD_EXTENSION_INDICATOR: u8 = 0xff;
const SPARSE_FIELD_LIST_EXTENSION: u8 = 1;

pub type Result<T> = std::result::Result<T, String>;

fn get(b: &[u8], o: usize, n: usize) -> Result<&[u8]> {
    o.checked_add(n)
        .and_then(|e| b.get(o..e))
        .ok_or_else(|| format!("read of {n} bytes at {o} past the end of a {}-byte buffer", b.len()))
}
fn be_i32(b: &[u8], o: usize) -> Result<i32> {
    Ok(i32::from_be_bytes(get(b, o, 4)?.try_into().map_err(|_| "short read")?))
}
fn be_i64(b: &[u8], o: usize) -> Result<i64> {
    Ok(i64::from_be_bytes(get(b, o, 8)?.try_into().map_err(|_| "short read")?))
}
fn byte(b: &[u8], o: usize) -> Result<u8> {
    b.get(o).copied().ok_or_else(|| format!("read at {o} past the end of a {}-byte buffer", b.len()))
}

/// `ItemDeserializer` + `saveItem`: the buffer file inside a packed file (a Java object-stream
/// header, then a zip entry `FOLDER_ITEM` holding the file).
pub fn unpack(packed: &[u8]) -> Result<Vec<u8>> {
    // ObjectOutputStream: STREAM_MAGIC, STREAM_VERSION, then one TC_BLOCKDATA block
    if get(packed, 0, 4)? != [0xac, 0xed, 0x00, 0x05] || byte(packed, 4)? != 0x77 {
        return Err("not a packed Ghidra file (no Java object stream)".into());
    }
    let block_len = byte(packed, 5)? as usize;
    let blk = get(packed, 6, block_len)?;
    if be_i64(blk, 0)? != PACKED_MAGIC {
        return Err("packed file: invalid data (magic number)".into());
    }
    if be_i32(blk, 8)? != PACKED_FORMAT_VERSION {
        return Err("packed file: unsupported data format".into());
    }
    let mut o = 12;
    for _ in 0..2 {
        // readUTF: item name, content type
        o += 2 + u16::from_be_bytes([byte(blk, o)?, byte(blk, o + 1)?]) as usize;
    }
    let length = be_i64(blk, o + 4)?;
    let zip = &packed[6 + block_len..];
    // ZipInputStream.getNextEntry: the local file header
    if get(zip, 0, 4)? != [0x50, 0x4b, 0x03, 0x04] {
        return Err("packed file: no zip entry".into());
    }
    let method = u16::from_le_bytes([byte(zip, 8)?, byte(zip, 9)?]);
    let name_len = u16::from_le_bytes([byte(zip, 26)?, byte(zip, 27)?]) as usize;
    let extra_len = u16::from_le_bytes([byte(zip, 28)?, byte(zip, 29)?]) as usize;
    if get(zip, 30, name_len)? != b"FOLDER_ITEM" {
        return Err("packed file: data error (zip entry is not FOLDER_ITEM)".into());
    }
    if method != 8 {
        return Err(format!("packed file: zip method {method} not ported (only deflate)"));
    }
    let limit = u64::try_from(length).map_err(|_| "packed file: bad length")?;
    let data = zip.get(30 + name_len + extra_len..).ok_or("packed file: truncated zip entry")?;
    // no more than the header's length (and one byte to tell a longer entry)
    let mut out = Vec::new();
    flate2::read::DeflateDecoder::new(data)
        .take(limit.saturating_add(1))
        .read_to_end(&mut out)
        .map_err(|e| format!("packed file: {e}"))?;
    if out.len() as i64 != length {
        return Err(format!("packed file: {} bytes unpacked, header says {length}", out.len()));
    }
    Ok(out)
}

/// `LocalBufferFile` opened read-only: the header block, then one block per buffer.
pub struct BufferFile {
    data: Vec<u8>,
    block: usize,
}

impl BufferFile {
    /// `LocalBufferFile.readHeader` (format version 1).
    pub fn new(data: Vec<u8>) -> Result<BufferFile> {
        if be_i64(&data, 0)? != BUFFER_FILE_MAGIC || be_i32(&data, 16)? != 1 {
            return Err("not a Ghidra buffer file (unrecognized file format)".into());
        }
        let block = be_i32(&data, 20)?;
        let block = usize::try_from(block).map_err(|_| format!("unsupported block size {block}"))?;
        if block <= BUFFER_PREFIX || !data.len().is_multiple_of(block) {
            return Err(format!("corrupt buffer file (block size {block}, length {})", data.len()));
        }
        Ok(BufferFile { data, block })
    }

    fn buffer_size(&self) -> usize {
        self.block - BUFFER_PREFIX
    }

    /// `LocalBufferFile.get`: buffer `id` is block `id + 1`.
    fn buffer(&self, id: i32) -> Result<&[u8]> {
        let i = usize::try_from(id).map_err(|_| format!("invalid buffer id {id}"))?;
        let start = (i + 1) * self.block;
        let b = self.data.get(start..start + self.block).ok_or_else(|| format!("buffer {id} out of range"))?;
        if b[0] & 1 != 0 {
            return Err(format!("buffer {id} is empty"));
        }
        Ok(&b[BUFFER_PREFIX..])
    }

    /// `ChainedBuffer(BufferMgr, int)` read whole: the bytes of the chained buffer at `id`.
    fn chained(&self, id: i32) -> Result<Vec<u8>> {
        let first = self.buffer(id)?;
        let size = be_i32(first, 1)?;
        if size < 0 {
            return Err(format!("chained buffer {id}: XOR-obfuscated data not ported"));
        }
        let size = size as usize;
        match byte(first, 0)? {
            CHAINED_BUFFER_DATA_NODE => Ok(get(first, 5, size)?.to_vec()),
            CHAINED_BUFFER_INDEX_NODE => {
                // buildIndex: data buffer ids after next-index id, data after the node type
                let bad = || format!("chained buffer {id}: buffer size {} too small", self.buffer_size());
                let space = self.buffer_size().checked_sub(1).filter(|&s| s > 0).ok_or_else(bad)?;
                let per_index = self.buffer_size().checked_sub(9).map(|s| s / 4).filter(|&p| p > 0).ok_or_else(bad)?;
                let count = if size == 0 { 0 } else { (size - 1) / space + 1 };
                let (mut index, mut ix) = (first, 0);
                // `size` is the file's word: no more capacity than the file has bytes
                let mut out = Vec::with_capacity(size.min(self.data.len()));
                for _ in 0..count {
                    if ix == per_index {
                        index = self.buffer(be_i32(index, 5)?)?;
                        ix = 0;
                    }
                    let data_id = be_i32(index, 9 + 4 * ix)?;
                    ix += 1;
                    let n = space.min(size - out.len());
                    if data_id < 0 {
                        out.resize(out.len() + n, 0);
                    } else {
                        let data = self.buffer(data_id)?;
                        if byte(data, 0)? != CHAINED_BUFFER_DATA_NODE {
                            return Err(format!("chained buffer {id}: data buffer {data_id} is not a data node"));
                        }
                        out.extend_from_slice(get(data, 1, n)?);
                    }
                }
                Ok(out)
            }
            t => Err(format!("chained buffer {id}: invalid buffer (node type {t})")),
        }
    }

    /// Every (key, record bytes) of the table rooted at `root`, in key order: the leaves of a
    /// long-key B-tree (`LongKeyInteriorNode`, `FixedRecNode`, `VarRecNode`) or a fixed-key one
    /// (`FixedKeyInteriorNode`, `FixedKeyFixedRecNode`, `FixedKeyVarRecNode`): the same
    /// layouts with a key of `key` bytes. `fixed` is the record length of a fixed-length
    /// schema; records with indirect storage come from their chained buffer.
    fn records(&self, root: i32, key: usize, fixed: Option<usize>, out: &mut Vec<(i64, Vec<u8>)>) -> Result<()> {
        self.walk(root, key, fixed, out, &mut HashSet::new(), 0)
    }

    /// [`Self::records`] below `root` at `depth`; `seen`: the nodes read, so a node referenced
    /// twice (a cycle) or a tree deeper than [`MAX_TREE_DEPTH`] is an error, not a stack overflow.
    fn walk(
        &self,
        root: i32,
        key: usize,
        fixed: Option<usize>,
        out: &mut Vec<(i64, Vec<u8>)>,
        seen: &mut HashSet<i32>,
        depth: usize,
    ) -> Result<()> {
        if root < 0 {
            return Ok(());
        }
        if depth > MAX_TREE_DEPTH || !seen.insert(root) {
            return Err(format!("buffer {root}: corrupt B-tree (a cycle, or deeper than {MAX_TREE_DEPTH})"));
        }
        let b = self.buffer(root)?;
        let n = usize::try_from(be_i32(b, 1)?).map_err(|_| format!("buffer {root}: bad key count"))?;
        let key_at = |o: usize| -> Result<i64> {
            let k = get(b, o, key)?;
            Ok(k.iter().fold(if k[0] & 0x80 != 0 { -1i64 } else { 0 }, |v, &x| (v << 8) | x as i64))
        };
        match (byte(b, 0)?, key == 8) {
            (LONGKEY_INTERIOR_NODE, true) | (FIXEDKEY_INTERIOR_NODE, false) => {
                for i in 0..n {
                    self.walk(be_i32(b, 5 + (key + 4) * i + key)?, key, fixed, out, seen, depth + 1)?;
                }
            }
            (LONGKEY_FIXED_REC_NODE, true) | (FIXEDKEY_FIXED_REC_NODE, false) => {
                let len = fixed
                    .ok_or_else(|| format!("buffer {root}: fixed-length record node in a variable-length table"))?;
                for i in 0..n {
                    let o = LEAF_HEADER + i * (key + len);
                    out.push((key_at(o)?, get(b, o + key, len)?.to_vec()));
                }
            }
            (LONGKEY_VAR_REC_NODE, true) | (FIXEDKEY_VAR_REC_NODE, false) => {
                let entry = key + 5;
                for i in 0..n {
                    let e = LEAF_HEADER + entry * i;
                    let off = be_i32(b, e + key)? as usize;
                    let end = if i == 0 { b.len() } else { be_i32(b, e - entry + key)? as usize };
                    let rec = if byte(b, e + key + 4)? != 0 {
                        self.chained(be_i32(b, off)?)?
                    } else {
                        get(b, off, end.saturating_sub(off))?.to_vec()
                    };
                    out.push((key_at(e)?, rec));
                }
            }
            (t, _) => return Err(format!("buffer {root}: node type {t} not ported for a {key}-byte key")),
        }
        Ok(())
    }
}

/// A field value (`db.Field` subclasses); `Null` for a null string, binary or sparse column.
#[derive(Debug, Clone, PartialEq)]
pub enum Field {
    Byte(i8),
    Short(i16),
    Int(i32),
    Long(i64),
    Bool(bool),
    Str(String),
    Binary(Vec<u8>),
    Fixed10([u8; 10]),
    Null,
}

/// `db.Schema` as parsed from a table record.
#[derive(Debug, Clone)]
pub struct Schema {
    pub version: i32,
    /// key length in bytes (`Field.length` of the key type); 0: a key type not ported
    key: usize,
    pub names: Vec<String>,
    types: Vec<u8>,
    sparse: Vec<usize>,
}

impl Schema {
    /// `Schema(int, byte, byte[], String)`.
    fn parse(version: i32, key_type: i8, encoded: &[u8], names: &str) -> Result<Schema> {
        // fixed-length keys only; IndexField and variable-length keys (VarKey nodes) are not ported
        let key = match key_type as u8 {
            BYTE_TYPE => 1,
            SHORT_TYPE => 2,
            INT_TYPE => 4,
            LONG_TYPE => 8,
            _ => 0, // read by `Db::records` fails
        };
        let mut it = encoded.iter().copied();
        let mut types = Vec::new();
        let mut sparse = Vec::new();
        for b in it.by_ref() {
            if b == FIELD_EXTENSION_INDICATOR {
                break;
            }
            match b {
                BYTE_TYPE | SHORT_TYPE | INT_TYPE | LONG_TYPE | STRING_TYPE | BINARY_OBJ_TYPE | BOOLEAN_TYPE
                | FIXED_10_TYPE => types.push(b),
                t => return Err(format!("field type {t} not ported")),
            }
        }
        while let Some(ext) = it.next() {
            if ext != SPARSE_FIELD_LIST_EXTENSION {
                return Err(format!("unsupported field extension type {ext}"));
            }
            for c in it.by_ref() {
                if c == FIELD_EXTENSION_INDICATOR {
                    break;
                }
                sparse.push(c as usize);
            }
        }
        // parseNames (StringTokenizer: empty names dropped): key name first, ';'-separated
        let names: Vec<String> = names.split(';').filter(|n| !n.is_empty()).skip(1).map(str::to_string).collect();
        if names.len() != types.len() {
            return Err(format!("schema: {} field names for {} column types", names.len(), types.len()));
        }
        Ok(Schema { version, key, names, types, sparse })
    }

    /// The record length of a fixed-length schema (`Schema.getFixedLength`), or `None`.
    fn fixed_length(&self) -> Option<usize> {
        if !self.sparse.is_empty() {
            return None;
        }
        self.types.iter().try_fold(0, |n, t| {
            Some(
                n + match *t {
                    BYTE_TYPE | BOOLEAN_TYPE => 1,
                    SHORT_TYPE => 2,
                    INT_TYPE => 4,
                    LONG_TYPE => 8,
                    FIXED_10_TYPE => 10,
                    _ => return None,
                },
            )
        })
    }

    /// `DBRecord.read` / `SparseRecord.read`.
    fn read(&self, b: &[u8]) -> Result<Vec<Field>> {
        let mut o = 0;
        let mut fields = vec![Field::Null; self.types.len()];
        for (i, &t) in self.types.iter().enumerate() {
            if !self.sparse.contains(&i) {
                fields[i] = read_field(t, b, &mut o)?;
            }
        }
        if !self.sparse.is_empty() {
            let n = byte(b, o)?;
            o += 1;
            for _ in 0..n {
                let i = byte(b, o)? as usize;
                o += 1;
                let t = *self.types.get(i).ok_or_else(|| format!("sparse column {i} out of range"))?;
                fields[i] = read_field(t, b, &mut o)?;
            }
        }
        Ok(fields)
    }
}

/// `Field.read` of each field type.
fn read_field(t: u8, b: &[u8], o: &mut usize) -> Result<Field> {
    let at = *o;
    let (f, n) = match t {
        BYTE_TYPE => (Field::Byte(byte(b, at)? as i8), 1),
        BOOLEAN_TYPE => (Field::Bool(byte(b, at)? != 0), 1),
        SHORT_TYPE => (Field::Short(i16::from_be_bytes([byte(b, at)?, byte(b, at + 1)?])), 2),
        INT_TYPE => (Field::Int(be_i32(b, at)?), 4),
        LONG_TYPE => (Field::Long(be_i64(b, at)?), 8),
        FIXED_10_TYPE => (Field::Fixed10(get(b, at, 10)?.try_into().map_err(|_| "short read")?), 10),
        STRING_TYPE | BINARY_OBJ_TYPE => {
            let len = be_i32(b, at)?;
            if len < 0 {
                (Field::Null, 4)
            } else {
                let bytes = get(b, at + 4, len as usize)?;
                let f = if t == STRING_TYPE {
                    Field::Str(String::from_utf8(bytes.to_vec()).map_err(|e| format!("string field: {e}"))?)
                } else {
                    Field::Binary(bytes.to_vec())
                };
                (f, 4 + len as usize)
            }
        }
        t => return Err(format!("field type {t} not ported")),
    };
    *o += n;
    Ok(f)
}

/// One record: its key and fields, with typed accessors that fail by column name.
#[derive(Debug, Clone)]
pub struct Record<'s> {
    pub key: i64,
    pub fields: Vec<Field>,
    schema: &'s Schema,
}

impl Record<'_> {
    fn col(&self, i: usize) -> Result<&Field> {
        self.fields.get(i).ok_or_else(|| format!("record {}: no column {i}", self.key))
    }
    fn bad(&self, i: usize, want: &str) -> String {
        let name = self.schema.names.get(i).map(String::as_str).unwrap_or("?");
        format!("record {}: column {i} ({name}) is not {want}: {:?}", self.key, self.fields.get(i))
    }
    pub fn long(&self, i: usize) -> Result<i64> {
        match self.col(i)? {
            Field::Long(v) => Ok(*v),
            _ => Err(self.bad(i, "a long")),
        }
    }
    pub fn int(&self, i: usize) -> Result<i32> {
        match self.col(i)? {
            Field::Int(v) => Ok(*v),
            _ => Err(self.bad(i, "an int")),
        }
    }
    pub fn short(&self, i: usize) -> Result<i16> {
        match self.col(i)? {
            Field::Short(v) => Ok(*v),
            _ => Err(self.bad(i, "a short")),
        }
    }
    pub fn byte(&self, i: usize) -> Result<i8> {
        match self.col(i)? {
            Field::Byte(v) => Ok(*v),
            _ => Err(self.bad(i, "a byte")),
        }
    }
    pub fn boolean(&self, i: usize) -> Result<bool> {
        match self.col(i)? {
            Field::Bool(v) => Ok(*v),
            _ => Err(self.bad(i, "a boolean")),
        }
    }
    /// A string column; `None` for null.
    pub fn string(&self, i: usize) -> Result<Option<&str>> {
        match self.col(i)? {
            Field::Str(s) => Ok(Some(s)),
            Field::Null => Ok(None),
            _ => Err(self.bad(i, "a string")),
        }
    }
    /// A binary column; `None` for null.
    pub fn binary(&self, i: usize) -> Result<Option<&[u8]>> {
        match self.col(i)? {
            Field::Binary(b) => Ok(Some(b)),
            Field::Null => Ok(None),
            _ => Err(self.bad(i, "binary")),
        }
    }
}

/// A table of the master table (`TableRecord`): name, schema and root buffer.
#[derive(Debug, Clone)]
pub struct TableInfo {
    pub schema: Schema,
    root: i32,
}

/// An open database (`DBHandle` read-only): its tables by name.
pub struct Db {
    file: BufferFile,
    pub tables: BTreeMap<String, TableInfo>,
}

impl Db {
    /// Opens a packed database (`PackedDatabase`), read-only.
    pub fn open_packed(path: &std::path::Path) -> Result<Db> {
        let packed = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
        Db::new(BufferFile::new(unpack(&packed).map_err(|e| format!("{}: {e}", path.display()))?)?)
            .map_err(|e| format!("{}: {e}", path.display()))
    }

    /// `DBHandle` + `MasterTable`: DBParms in buffer 0 (parameter 0 is the master table's root),
    /// then one `TableRecord` per table (index tables, with an indexed column, are left out).
    fn new(file: BufferFile) -> Result<Db> {
        let parms = file.buffer(0)?;
        if byte(parms, 0)? != CHAINED_BUFFER_DATA_NODE || byte(parms, 5)? != 1 {
            return Err("unexpected DBParms buffer".into());
        }
        let master = be_i32(parms, 6)?;
        let master_schema = Schema::parse(0, LONG_TYPE as i8, &[STRING_TYPE, INT_TYPE, INT_TYPE, BYTE_TYPE, BINARY_OBJ_TYPE, STRING_TYPE, INT_TYPE, LONG_TYPE, INT_TYPE], "TableNum;TableName;SchemaVersion;RootBufferId;KeyType;FieldTypes;FieldNames;IndexColumn;MaxKey;RecordCount")?;
        let mut raw = Vec::new();
        file.records(master, 8, None, &mut raw)?;
        let mut tables = BTreeMap::new();
        for (key, bytes) in raw {
            let r = Record { key, fields: master_schema.read(&bytes)?, schema: &master_schema };
            if r.int(6)? != -1 {
                continue; // an index of a table
            }
            let name = r.string(0)?.ok_or("table without a name")?.to_string();
            let schema = Schema::parse(
                r.int(1)?,
                r.byte(3)?,
                r.binary(4)?.unwrap_or_default(),
                r.string(5)?.unwrap_or_default(),
            )
            .map_err(|e| format!("table {name}: {e}"))?;
            tables.insert(name, TableInfo { schema, root: r.int(2)? });
        }
        Ok(Db { file, tables })
    }

    /// The schema of table `name`, or `None` without that table.
    pub fn schema(&self, name: &str) -> Option<&Schema> {
        self.tables.get(name).map(|t| &t.schema)
    }

    /// Every record of table `name` in key order (`Table.iterator`); no table: no records.
    pub fn records(&self, name: &str) -> Result<Vec<Record<'_>>> {
        let Some(t) = self.tables.get(name) else { return Ok(Vec::new()) };
        if t.schema.key == 0 {
            return Err(format!("table {name}: variable-length keys (VarKey nodes) not ported"));
        }
        let mut raw = Vec::new();
        self.file
            .records(t.root, t.schema.key, t.schema.fixed_length(), &mut raw)
            .map_err(|e| format!("table {name}: {e}"))?;
        raw.into_iter()
            .map(|(key, b)| {
                Ok(Record {
                    key,
                    fields: t.schema.read(&b).map_err(|e| format!("table {name} record {key}: {e}"))?,
                    schema: &t.schema,
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A corrupt file is an error: a B-tree node that is its own child, a chained buffer in
    /// blocks too small for its index, schema names that do not match the columns.
    #[test]
    fn corrupt_is_an_error() {
        // a buffer file of `blocks` blocks of `block` bytes with `node` (type, then a count or
        // size, then an id) in buffer `id`
        let file = |block: usize, blocks: usize, id: usize, node: (u8, i32, i32)| {
            let mut data = vec![0u8; blocks * block];
            data[..8].copy_from_slice(&BUFFER_FILE_MAGIC.to_be_bytes());
            data[16..20].copy_from_slice(&1i32.to_be_bytes());
            data[20..24].copy_from_slice(&(block as i32).to_be_bytes());
            let b = (id + 1) * block + BUFFER_PREFIX;
            data[b] = node.0;
            data[b + 1..b + 5].copy_from_slice(&node.1.to_be_bytes());
            if let Some(d) = data.get_mut(b + 13..b + 17) {
                d.copy_from_slice(&node.2.to_be_bytes());
            }
            BufferFile::new(data).unwrap()
        };
        // a long-key interior node whose one child is itself
        let f = file(32, 2, 0, (LONGKEY_INTERIOR_NODE, 1, 0));
        assert!(f.records(0, 8, None, &mut Vec::new()).unwrap_err().contains("corrupt B-tree"));
        // a chained buffer index node in 12-byte blocks (7 bytes a buffer)
        let f = file(12, 3, 1, (CHAINED_BUFFER_INDEX_NODE, 100, 0));
        assert!(f.chained(1).unwrap_err().contains("too small"));
        assert!(Schema::parse(0, LONG_TYPE as i8, &[INT_TYPE], "Key;A;B;").is_err());
        assert_eq!(Schema::parse(0, LONG_TYPE as i8, &[INT_TYPE], "Key;A;").unwrap().names, ["A"]);
    }
}
