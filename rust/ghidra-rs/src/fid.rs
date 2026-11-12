//! Function ID: port of Ghidra's FID hasher (`MessageDigestFidHasher`), reader for its
//! `.fidbf` databases (Ghidra's buffer file and B-tree tables, `Framework/DB`) and its matching
//! and naming (`FidProgramSeeker`, `ApplyFidEntriesCommand`, `MatchNameAnalysis`).
use crate::analysis::{Analysis, Flow, Image};
use crate::sleigh::{FidObj, Sleigh};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

const FNV_OFFSET: u64 = 0xcbf29ce484222325;
const FNV_PRIME: u64 = 1099511628211;
const SHORT_HASH_CODE_UNITS: i32 = 4;
const MEDIUM_HASH_CODE_UNITS: i32 = 24;
const SCORE_THRESHOLD: f32 = 14.6;
const MULTINAME_SCORE_THRESHOLD: f32 = 30.0;
const MAX_NUM_PARENTS_FOR_SCORE: usize = 500;
const MAGIC_MULTIPLE_MATCH_LIMIT: usize = 10;
const FEEDDEAD: i32 = 0xfeeddead_u32 as i32;

/// Ghidra's Function ID databases for x86:LE:32 (Visual Studio): `$GHIDRA_RS_FID` (a
/// directory), else the data directory of the Ghidra install at /opt/ghidra.
pub fn default_files() -> Vec<std::path::PathBuf> {
    let dir = std::env::var_os("GHIDRA_RS_FID")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| "/opt/ghidra/Ghidra/Features/FunctionID/data".into());
    let mut v: Vec<_> = std::fs::read_dir(dir)
        .map(|d| d.filter_map(|e| Some(e.ok()?.path())).collect())
        .unwrap_or_default();
    v.retain(|p| p.to_string_lossy().ends_with("_x86.fidbf"));
    v.sort();
    v
}

// ---------------------------------------------------------------- FNV-1a 64

struct Fnv(u64);

impl Fnv {
    fn bytes(&mut self, b: &[u8]) {
        for &x in b {
            self.0 = (self.0 ^ x as u64).wrapping_mul(FNV_PRIME);
        }
    }
    fn int(&mut self, v: i32) {
        self.bytes(&v.to_be_bytes());
    }
}

/// FidHashQuad: code units (less calls), full hash, specific constant count, specific hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Quad {
    pub code_units: i16,
    pub full: i64,
    pub specific_count: i8,
    pub specific: i64,
}

/// X86InstructionSkipper: NOPs and `MOV r,r` fillers are not hashed.
fn skipped(b: &[u8]) -> bool {
    const PATTERNS: [&[u8]; 17] = [
        &[0x90],
        &[0x8b, 0xc0],
        &[0x8b, 0xc9],
        &[0x8b, 0xd2],
        &[0x8b, 0xdb],
        &[0x8b, 0xe4],
        &[0x8b, 0xed],
        &[0x8b, 0xf6],
        &[0x8b, 0xff],
        &[0x66, 0x90],
        &[0x0f, 0x1f, 0x00],
        &[0x0f, 0x1f, 0x40, 0x00],
        &[0x0f, 0x1f, 0x44, 0x00, 0x00],
        &[0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00],
        &[0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00],
        &[0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00],
        &[0x66, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00],
    ];
    PATTERNS.contains(&b)
}

/// One instruction as the hasher sees it: its bytes, whether it is a call, and the
/// constants that are addresses (Ghidra adds OperandType.ADDRESS for an operand with a
/// memory reference). The image has no relocations to check (mercs2 has none), so
/// `hasRelocation` is never true.
pub struct HashInsn<'a> {
    pub addr: u32,
    pub bytes: &'a [u8],
    pub call: bool,
    pub addresses: [&'a [u32]; 2],
}

/// MessageDigestFidHasher.hash over a function's instructions in address order.
pub fn hash(sl: &Sleigh, insns: &[HashInsn]) -> Option<Quad> {
    if (insns.len() as i32) < SHORT_HASH_CODE_UNITS {
        return None;
    }
    let mut p = sl.new_parse();
    p.fid = true;
    let (mut full, mut spec) = (Fnv(FNV_OFFSET), Fnv(FNV_OFFSET));
    let (mut specific_count, mut calls, mut units) = (0i32, 0i32, 0i32);
    for i in insns {
        if units >= i16::MAX as i32 - 1 {
            break;
        }
        if skipped(i.bytes) {
            continue;
        }
        units += 1;
        if i.call {
            calls += 1;
        }
        let mut buf = i.bytes.to_vec();
        match sl.decode(&mut p, i.addr as u64, i.bytes).map(|_| sl.fid_parts(&p)) {
            Ok(parts) => {
                for (k, op) in parts.ops.iter().enumerate() {
                    let mut su = (k as i32 + 1).wrapping_mul(7777);
                    let mut fu = su;
                    for o in &op.objs {
                        match *o {
                            FidObj::Scalar(v) => {
                                let address = i.addresses.iter().any(|s| s.contains(&(v as u32)));
                                let val = if op.scalar {
                                    if address { FEEDDEAD as i64 } else { specific_count += 1; v }
                                } else if !(-256 < v && v < 256) {
                                    FEEDDEAD as i64
                                } else {
                                    specific_count += 1;
                                    v
                                };
                                su = su.wrapping_add((val as i32).wrapping_add(1234567).wrapping_mul(67999));
                                fu = fu.wrapping_add(FEEDDEAD);
                            }
                            FidObj::Reg(off) => {
                                let v = (off as i32).wrapping_add(7654321).wrapping_mul(98777);
                                fu = fu.wrapping_add(v);
                                su = su.wrapping_add(v);
                            }
                            FidObj::Addr => {
                                su = su.wrapping_add(FEEDDEAD.wrapping_add(1234567).wrapping_mul(67999));
                                fu = fu.wrapping_add(FEEDDEAD);
                            }
                        }
                    }
                    full.int(fu);
                    spec.int(su);
                }
                for (b, m) in buf.iter_mut().zip(&parts.mask) {
                    *b &= m;
                }
            }
            Err(_) => buf.iter_mut().for_each(|b| *b = 0xa5),
        }
        full.bytes(&buf);
        spec.bytes(&buf);
    }
    if units < SHORT_HASH_CODE_UNITS {
        return None;
    }
    Some(Quad {
        code_units: (units - calls) as i16,
        full: full.0 as i64,
        specific_count: specific_count.min(127) as i8,
        specific: spec.0 as i64,
    })
}

// ---------------------------------------------------------------- .fidbf (Ghidra DB)

const BLOCK_PREFIX: usize = 5; // LocalBufferFile: flags byte and buffer id
const LONGKEY_INTERIOR_NODE: u8 = 0;
const LONGKEY_VAR_REC_NODE: u8 = 1;
const LONGKEY_FIXED_REC_NODE: u8 = 2;
const LEAF_HEADER: usize = 13; // node type, key count, previous and next leaf

fn be_i32(b: &[u8], o: usize) -> i32 {
    i32::from_be_bytes(b[o..o + 4].try_into().unwrap())
}
fn be_i64(b: &[u8], o: usize) -> i64 {
    i64::from_be_bytes(b[o..o + 8].try_into().unwrap())
}

struct BufferFile {
    data: Vec<u8>,
    block: usize,
}

impl BufferFile {
    fn open(path: &std::path::Path) -> Result<BufferFile, String> {
        let data = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
        if data.len() < 24 || be_i64(&data, 0) != 0x2f30312c34292c2a || be_i32(&data, 16) != 1 {
            return Err(format!("{}: not a Ghidra buffer file", path.display()));
        }
        let block = be_i32(&data, 20) as usize;
        if block < 512 || data.len() % block != 0 {
            return Err(format!("{}: bad block size {block}", path.display()));
        }
        Ok(BufferFile { data, block })
    }

    /// Buffer `id` (block id + 1; block 0 is the file header).
    fn buffer(&self, id: i32) -> Result<&[u8], String> {
        let start = (id as usize + 1) * self.block;
        let b = self.data.get(start..start + self.block).ok_or_else(|| format!("buffer {id} out of range"))?;
        if b[0] & 1 != 0 {
            return Err(format!("buffer {id} is empty"));
        }
        Ok(&b[BLOCK_PREFIX..])
    }

    /// Every (key, record bytes) of the long-key table rooted at `root`, in key order.
    /// `fixed` is the record length of a fixed-length table. Records kept in a chained
    /// buffer (larger than a quarter buffer) are skipped; FID records are small.
    fn records(&self, root: i32, fixed: Option<usize>, f: &mut dyn FnMut(i64, &[u8])) -> Result<(), String> {
        if root < 0 {
            return Ok(());
        }
        let b = self.buffer(root)?;
        let n = be_i32(b, 1) as usize;
        match b[0] {
            LONGKEY_INTERIOR_NODE => {
                for i in 0..n {
                    self.records(be_i32(b, 5 + 12 * i + 8), fixed, f)?;
                }
            }
            LONGKEY_FIXED_REC_NODE => {
                let len = fixed.ok_or("fixed-length node in a variable-length table")?;
                for i in 0..n {
                    let o = LEAF_HEADER + i * (8 + len);
                    f(be_i64(b, o), &b[o + 8..o + 8 + len]);
                }
            }
            LONGKEY_VAR_REC_NODE => {
                for i in 0..n {
                    let e = LEAF_HEADER + 13 * i;
                    let off = be_i32(b, e + 8) as usize;
                    let end = if i == 0 { b.len() } else { be_i32(b, e - 13 + 8) as usize };
                    if b[e + 12] == 0 {
                        f(be_i64(b, e), &b[off..end]);
                    }
                }
            }
            t => return Err(format!("buffer {root}: unsupported node type {t}")),
        }
        Ok(())
    }
}

/// StringField.read: length (-1: null) and UTF-8 bytes; returns the rest.
fn string_field(b: &[u8]) -> (String, &[u8]) {
    let n = be_i32(b, 0);
    if n < 0 {
        return (String::new(), &b[4..]);
    }
    let n = n as usize;
    (String::from_utf8_lossy(&b[4..4 + n]).into_owned(), &b[4 + n..])
}

/// A FunctionsTable record (FunctionRecord).
#[derive(Debug, Clone)]
pub struct FidFunction {
    pub key: i64,
    pub code_units: i16,
    pub full: i64,
    pub specific_size: i8,
    pub specific: i64,
    pub library: i64,
    pub name: i64,
    pub flags: u8,
}

const AUTO_PASS: u8 = 2;
const AUTO_FAIL: u8 = 4;
const FORCE_SPECIFIC: u8 = 8;
const FORCE_RELATION: u8 = 16;

/// One `.fidbf` database: functions by full hash, names, and relations.
pub struct FidDb {
    pub functions: Vec<FidFunction>,
    by_full: HashMap<i64, Vec<usize>>,
    pub strings: HashMap<i64, String>,
    superior: HashSet<i64>,
    inferior: HashSet<i64>,
}

impl FidDb {
    pub fn open(path: &std::path::Path) -> Result<FidDb, String> {
        let bf = BufferFile::open(path)?;
        // DBParms (buffer 0): master table root at parameter 0
        let master = be_i32(bf.buffer(0)?, 6);
        let mut tables = HashMap::new();
        bf.records(master, None, &mut |_, r| {
            let (name, r) = string_field(r);
            let root = be_i32(r, 4);
            let r = &r[9..]; // version, root, key type
            let r = &r[4 + be_i32(r, 0) as usize..]; // field types
            let (_, r) = string_field(r); // field names
            if be_i32(r, 0) == -1 {
                tables.insert(name, root); // a table, not one of its indexes
            }
        })?;
        let root = |n: &str| tables.get(n).copied().ok_or_else(|| format!("{}: no table {n}", path.display()));
        let mut db = FidDb { functions: Vec::new(), by_full: HashMap::new(), strings: HashMap::new(), superior: HashSet::new(), inferior: HashSet::new() };
        bf.records(root("Functions Table")?, Some(52), &mut |key, r| {
            db.functions.push(FidFunction {
                key,
                code_units: i16::from_be_bytes([r[0], r[1]]),
                full: be_i64(r, 2),
                specific_size: r[10] as i8,
                specific: be_i64(r, 11),
                library: be_i64(r, 19),
                name: be_i64(r, 27),
                flags: r[51],
            })
        })?;
        for (i, f) in db.functions.iter().enumerate() {
            db.by_full.entry(f.full).or_default().push(i);
        }
        bf.records(root("Strings Table")?, None, &mut |key, r| {
            db.strings.insert(key, string_field(r).0);
        })?;
        bf.records(root("Superior Table")?, Some(0), &mut |key, _| {
            db.superior.insert(key);
        })?;
        bf.records(root("Inferior Table")?, Some(0), &mut |key, _| {
            db.inferior.insert(key);
        })?;
        Ok(db)
    }

    pub fn by_full_hash(&self, h: i64) -> impl Iterator<Item = &FidFunction> {
        self.by_full.get(&h).into_iter().flatten().map(|&i| &self.functions[i])
    }

    fn superior(&self, f: &FidFunction, child: &Quad) -> bool {
        self.superior.contains(&(f.key.wrapping_mul(FNV_PRIME as i64) ^ child.full))
    }

    fn inferior(&self, parent: &Quad, f: &FidFunction) -> bool {
        self.inferior.contains(&(f.key.wrapping_mul(FNV_PRIME as i64) ^ parent.full))
    }
}

// ---------------------------------------------------------------- matching

struct Match<'a> {
    db: &'a FidDb,
    f: &'a FidFunction,
    score: f32,
}

/// FidProgramSeeker.scoreMatch
fn score<'a>(db: &'a FidDb, f: &'a FidFunction, h: &Quad, kids: &[Quad], parents: &[Quad]) -> Option<Match<'a>> {
    if f.flags & AUTO_FAIL != 0 {
        return None;
    }
    let mut units = f.code_units as i32;
    let specific = f.specific == h.specific;
    if f.flags & FORCE_SPECIFIC != 0 && !specific {
        return None;
    }
    if f.flags & AUTO_PASS != 0 && units < MEDIUM_HASH_CODE_UNITS {
        units = MEDIUM_HASH_CODE_UNITS;
    }
    let child: i32 = kids.iter().filter(|k| db.superior(f, k)).map(|k| k.code_units as i32).sum();
    if f.flags & FORCE_RELATION != 0 && child == 0 {
        return None;
    }
    let parent: i32 = if parents.len() < MAX_NUM_PARENTS_FOR_SCORE {
        parents.iter().filter(|q| db.inferior(q, f)).map(|q| q.code_units as i32).sum()
    } else {
        0
    };
    let mut fs = units as f32;
    if specific {
        fs = (fs as f64 + 0.67 * f.specific_size as f64) as f32;
    }
    let total = fs + child as f32 + parent as f32;
    (total >= SCORE_THRESHOLD).then_some(Match { db, f, score: total })
}

/// Java's String.hashCode, for HashSet iteration order.
fn java_hash(s: &str) -> i32 {
    s.encode_utf16().fold(0i32, |h, c| h.wrapping_mul(31).wrapping_add(c as i32))
}

/// Iteration order of a small java.util.HashSet<String> built by inserting `names` in order
/// (16 buckets; up to 12 entries).
fn java_hashset_order(names: &[String]) -> Vec<String> {
    let mut v: Vec<(usize, usize, &String)> = names
        .iter()
        .enumerate()
        .map(|(i, n)| {
            let h = java_hash(n) as u32;
            (((h ^ (h >> 16)) & 15) as usize, i, n)
        })
        .collect();
    v.sort();
    v.into_iter().map(|x| x.2.clone()).collect()
}

/// What Function ID applies at one function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Applied {
    pub name: String, // raw (mangled) name, or "FID_conflict:<demangled base name>"
    pub conflict: bool,
}

/// Run Function ID over every function of `an` (FidAnalyzer with default options) and
/// return the functions it marks, with the name it gives them. Exported functions keep their
/// names (hasUserOrImportedSymbols) and are not marked.
pub fn apply(img: &Image, an: &Analysis, sl: &Sleigh, dbs: &[FidDb], demangle: &dyn Fn(&str) -> String) -> BTreeMap<u32, Applied> {
    let quads = hashes(img, an, sl);
    let mut owner = HashMap::new();
    for (&f, body) in &an.bodies {
        for &a in body {
            owner.entry(a).or_insert(f);
        }
    }
    // children (unique call targets) and parents (unique calling functions)
    let mut kids: HashMap<u32, Vec<u32>> = HashMap::new();
    let mut parents: BTreeMap<u32, BTreeSet<u32>> = BTreeMap::new();
    for (&f, body) in &an.bodies {
        let mut seen = HashSet::new();
        for a in body {
            let i = &an.insns[a];
            if !matches!(i.flow, Flow::Call | Flow::CallInd | Flow::Jump) {
                continue;
            }
            let Some(t) = an.call_target(img, i) else { continue };
            let Some(&g) = owner.get(&t) else { continue };
            if seen.insert(t) {
                kids.entry(f).or_default().push(g);
            }
            parents.entry(t).or_default().insert(f);
        }
    }
    let exports: HashSet<u32> = img.exports.iter().map(|e| e.0).collect();
    let mut primary: HashSet<String> = img.exports.iter().map(|e| e.1.clone()).collect();
    let mut multi: HashSet<String> = HashSet::new();
    let mut out = BTreeMap::new();
    for &f in an.bodies.keys() {
        let Some(h) = quads.get(&f) else { continue };
        let k: Vec<Quad> = kids.get(&f).into_iter().flatten().filter_map(|g| quads.get(g).copied()).collect();
        let par: Vec<Quad> = parents.get(&f).into_iter().flatten().filter_map(|g| quads.get(g).copied()).collect();
        let mut ms: Vec<Match> = dbs.iter().flat_map(|db| db.by_full_hash(h.full).filter_map(|r| score(db, r, h, &k, &par))).collect();
        if ms.is_empty() {
            continue;
        }
        ms.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap()); // stable, like Collections.sort
        let best = ms[0].score;
        ms.retain(|m| m.score >= best);
        // MatchNameAnalysis.analyzeNames, without the demangled variants
        let raw: BTreeSet<String> = ms.iter().filter_map(|m| m.db.strings.get(&m.f.name).cloned()).collect();
        if raw.is_empty() {
            continue;
        }
        let similar: BTreeSet<String> = raw.iter().map(|n| n.trim_start_matches('_').to_string()).collect();
        if raw.len().min(similar.len()) > 1 && best < MULTINAME_SCORE_THRESHOLD {
            continue;
        }
        if exports.contains(&f) {
            continue;
        }
        let names: Vec<String> = if raw.len() == 1 || similar.len() == 1 {
            vec![raw.first().unwrap().clone()]
        } else if raw.len() > similar.len() {
            similar.into_iter().collect()
        } else {
            raw.into_iter().collect()
        };
        if names.len() == 1 {
            primary.insert(names[0].clone());
            out.insert(f, Applied { name: names[0].clone(), conflict: false });
            continue;
        }
        // addFunctionLabelMultipleMatches: names no other function holds, as labels
        let mut unused = Vec::new();
        for n in &names {
            let elsewhere = !multi.contains(n) && [n.clone(), format!("_{n}"), format!("__{n}")].iter().any(|x| primary.contains(x));
            if !elsewhere {
                unused.push(n.clone());
                if unused.len() > MAGIC_MULTIPLE_MATCH_LIMIT {
                    break;
                }
            }
        }
        let unused = java_hashset_order(&unused);
        multi.extend(unused.iter().cloned());
        match unused.len() {
            0 => out.insert(f, Applied { name: String::new(), conflict: false }),
            1 => out.insert(f, Applied { name: unused[0].clone(), conflict: false }),
            _ => {
                // applyConflictLabels: the first label is the primary symbol
                let d = demangle(&unused[0]);
                let base = d.rsplit("::").next().unwrap_or(&d).to_string();
                out.insert(f, Applied { name: format!("FID_conflict:{base}"), conflict: true })
            }
        };
    }
    out
}

/// The FID hash of every function (None for those under 4 code units).
pub fn hashes(img: &Image, an: &Analysis, sl: &Sleigh) -> HashMap<u32, Quad> {
    let mut out = HashMap::new();
    for (&f, body) in &an.bodies {
        let insns: Vec<HashInsn> = body
            .iter()
            .filter_map(|&a| {
                let i = &an.insns[&a];
                let s = img.block_of(a)?;
                let o = (a - s.addr) as usize;
                Some(HashInsn {
                    addr: a,
                    bytes: s.data.get(o..o + i.len as usize)?,
                    // a JMP to a function entry is a call (Shared Return Calls), as in analysis
                    call: matches!(i.flow, Flow::Call | Flow::CallInd) || (i.flow == Flow::Jump && an.call_target(img, i).is_some()),
                    addresses: [&i.refs, &i.code_imms],
                })
            })
            .collect();
        if let Some(q) = hash(sl, &insns) {
            out.insert(f, q);
        }
    }
    out
}
