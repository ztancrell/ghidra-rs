# ghidra-rs

A headless Rust reverse-engineering core that decodes machine code with Ghidra's compiled
SLEIGH specs (`.sla`). Milestone 1: load an ELF/PE/Mach-O x86-64 binary, disassemble it and
lift it to p-code. Milestone 2: function discovery on 32-bit x86 PE files, writing the same files
as the mercs2 project's Ghidra scripts ExportFunctions.java and ExportGaps.java. See `../DESIGN.md` for the scope and plan.

## Layout

- `ghidra-rs/src/sla.rs`: reader for the compressed packed `.sla` format (version 4).
- `ghidra-rs/src/sleigh.rs`: the SLEIGH decode engine: constructor matching, context, operand
  printing and p-code templates. It ports the runtime half of Ghidra's C++ sleigh
  (`Ghidra/Features/Decompiler/src/decompile/cpp`: sleigh.cc, slghsymbol.cc, slghpattern.cc,
  slghpatexpress.cc, context.cc, semantics.cc).
- `ghidra-rs/src/analysis.rs`: PE32 loading and Ghidra-style analysis: disassembly by recursive
  descent, function discovery, switch tables, function bodies, flows and data references.
- `ghidra-rs/src/scripts.rs`: writers for the ExportFunctions and ExportGaps CSV files, plus
  RTTI vftables and a small MSVC name demangler.
- `ghidra-rs/src/main.rs`: the `ghidra-rs` CLI (binary loading via the `object` crate).
- `ghidra-rs/tests/decode.rs`: decodes a fixed byte sequence and checks text and p-code.
- `ghidra-rs/src/abi.rs`: port of CheckAbiCallers.java: per-byte register liveness walks
  over p-code register reads and writes.
- `ghidra-rs/tests/analysis.rs`: function discovery and both CSV writers on a fixed 32-bit blob;
  code constants (no x87 self-reference; a disguised call `PUSH next; PUSH callee; RET`); a
  code pointer hidden as two XORed dwords (`MOV EDI,[a]; XOR EDI,[b]; PUSH EDI`); a call through
  an object's vtable, resolved through a value stored via a symbolic register; whole-function
  propagation, where a vtable stored to the stack survives a call to a `RET 4` function and a
  join; ExportFunctions counting a computed call in `callees` and `callers`.
- `ghidra-rs/src/fid.rs`: Function ID: the FID hasher, a reader for Ghidra's `.fidbf`
  databases, and FID's matching and naming.
- `ghidra-rs/tests/fid.rs`: the FID hash of a known CRT function, and its record in Ghidra's
  databases (skipped when they are not installed).
- `ghidra-rs/tests/abi.rs`: register reads and writes (sub-registers as base-register bytes)
  of a few fixed instructions.
- `build-sla.sh`: builds Ghidra's SLEIGH compiler and compiles `x86-64.sla` and `x86.sla`.
- `tools/sleigh_ref.cc`: a reference disassembler on Ghidra's C++ engine, printing in the
  same format, used to verify the Rust port.
- `ghidra-rs/src/console.rs`: the milestone 3 harness: the decompiler prelude, the Rust side of
  Ghidra's console decompiler (`decompile -i`) and the datatest runner (port of
  `testfunction.cc`). See "Decompiler harness (Milestone 3, stage S0)" below.
- `ghidra-rs/src/xml.rs`: the small XML reader for the `.pspec`/`.cspec` files and the datatests.
- `ghidra-rs/tests/console.rs`: console commands not ported yet fail; a datatest XML parses.
- `ghidra-rs/src/decomp/`: the decompiler (milestone 3), one module per C++ concern:
  `mod.rs` (`Arch`: image, SLEIGH engine, compiler spec, mapped functions and external
  references, read-only ranges, register names; `LowlevelError`), `cspec.rs` (reading
  `x86win.cspec`), `fspec.rs` (prototype models, `FuncProto`, `CallSpec`), `inject.rs` (call
  fixups: the p-code snippet parser),
  `funcdata.rs` (`Funcdata`: op/varnode arenas, readers and the location-sorted varnode set,
  op insertion and input/output edits, stack loads), `op.rs`,
  `varnode.rs`, `readers.rs` (a varnode's reader list, up to 4 inline), `opcode.rs` (opcodes and their `print raw` names), `flow.rs` (`FlowInfo`,
  call-fixup injection), `block.rs` (basic blocks, spanning tree, dominators), `actiontree.rs`
  (the action framework: groups, repeat, breakpoints, `continue`), `heritage.rs` (SSA: phi
  placement and renaming), `action.rs` (the universal
  action up to `paramdouble`), `print.rs` (`print raw`), `stdsort.rs` (libstdc++'s `std::sort`).
  See "Decompiler (Milestone 3)" below.
- `ghidra-rs/tests/decomp.rs`, `tests/data/raw-funclink-*.txt`, `tests/data/raw-heritage-40a110.txt`,
  `tests/data/raw-paramdouble-40ad80.txt` (S2: a loop at `paramdouble`):
  `print raw` at `funclink` and `heritage` against the reference's output, for mercs2's 0x40a110
  (rebuilt from its bytes) and for `INTO; RET` (a relative branch to the end of its own
  instruction). Unit tests in `decomp/action.rs` (`tests/data/raw-heritage-onexit.txt`: mercs2's
  `__onexit` with two call fixups, external references and read-only propagation; read-only
  reads becoming constants) and `decomp/inject.rs` (the snippet parser).
- `tools/stdsort_ref.cc`, `ghidra-rs/tests/data/stdsort-gxx.txt`: libstdc++ `std::sort` tie orders
  that `decomp/stdsort.rs` must reproduce.
- `tools/decomp-ref.sh`, `tools/decomp-ref.patch`: build the reference decompiler `decomp_dbg`.
- `tools/decomp-diff.sh`: runs a corpus on both decompilers and compares; `tools/decomp-show.sh`,
  `tools/decomp-rank.sh`, `tools/decomp-bisect.sh`: the S2 debugging tools (verbose diff,
  easy-first order, first differing step; see "Debugging tools").
- `tools/decomp-corpus.sh`, `tools/corpus/m8.txt`, `tools/corpus/m500.txt`: the mercs2 corpora.

## Build

Needs Rust (stable), and g++, make and zlib headers for the SLEIGH compiler.

```sh
cd rust
./build-sla.sh             # once, and again whenever the x86 .slaspec/.sinc files change
cargo build --release
cargo test --release
```

### The .sla file

`build-sla.sh` copies the C++ sources from `Ghidra/Features/Decompiler/src/decompile/cpp`
into `rust/target/sleigh-build`, builds the `sleigh_opt` target there (using the checked-in
bison/flex outputs, so the upstream tree is not touched) and runs, for `x86-64` and `x86`:

```sh
sleigh_opt Ghidra/Processors/x86/data/languages/x86-64.slaspec \
           Ghidra/Processors/x86/data/languages/x86-64.sla
```

The output (about 500 KB each) lands where Ghidra itself keeps it. Upstream gitignores `*.sla`,
so it is not committed. The file is `"sla"`, a version byte (4), then a zlib stream holding
Ghidra's "packed" element/attribute encoding (`slaformat.cc`, `PackedDecode` in
`marshal.cc`).

`ghidra-rs` finds the `.sla` at that path by default (`x86.sla` for 32-bit binaries,
`x86-64.sla` otherwise). Override it with `--sla <file>` or the `GHIDRA_RS_SLA` environment
variable. The context defaults (`addrsize`, `opsize`, ...) come from the `<context_set>` of the
`.pspec` with the same name next to the `.sla`.

## Usage

```sh
ghidra-rs disasm <binary> [--func <symbol>|--addr <hex>] [--count N] [--pcode] [--sla <file>]
```

- `--func`: start at a symbol (static, dynamic or PE export; a leading `_` is optional for
  Mach-O) and, if the symbol has a size, stop at its end.
- `--addr`: start at a virtual address (hex, `0x` optional).
- Without either, it starts at the entry point.
- `--count`: maximum number of instructions (default 20, or the whole symbol with `--func`).
  The sweep also stops at the end of the containing section.
- `--pcode`: print the p-code ops under each instruction.

Output is `address  bytes  MNEMONIC operands` in Ghidra's spelling. Bytes Ghidra's spec
cannot decode print as `(bad: ...)`, and the sweep moves on one byte.

```
$ ghidra-rs disasm /usr/bin/ls --count 2 --pcode
0000000000005620  f3 0f 1e fa                    ENDBR64
0000000000005624  31 ed                          XOR EBP,EBP
    CF = COPY 0x0:1
    ...
```

Varnodes print as a register name when one matches exactly, `0x5:4` for constants and
`space[offset]:size` otherwise.

## Analysis (Milestone 2): the mercs2 Ghidra scripts

```sh
ghidra-rs analyze <pe32> [--functions <csv>] [--gaps <csv>] [--abi-callers <register_abi.csv> <out.csv> [--data-pointers]]
                         [--decomp-prelude <out>] [--seeds <csv> | --functions-from <csv>]... [--sla <file>]
```

Analyzes a 32-bit x86 PE and writes the files of three headless Ghidra scripts of the mercs2
decomp project (`mercs2-decomp/tools/ghidra`), in the same format:

| ghidra-rs flag | Ghidra script | file |
|---|---|---|
| `--functions` | `ExportFunctions.java` | `address,size,name,exported,fid,vtable_class,lua,callees,callers,data_refs`, one row per `.text` function |
| `--gaps` | `ExportGaps.java` | `address,size,class`: `.text` ranges outside every function body (`padding`, `table`, `unexamined`) |
| `--abi-callers` | `CheckAbiCallers.java` | `address,contract,site,status,register,instruction`: register-ABI contracts checked at every reference (see below) |

It also prints the scripts' summary lines (`exported N functions`, `function coverage: N / M
.text bytes`, `Checked N references into <out>; N output findings; N input findings`).

The mercs2 pipeline does not run plain auto-analysis: after import it runs RecoverFunctions,
AuditRecoveredFunctions, FoldSlotFragments, AddRelocatedEntries and ClearFalseNoReturn
(`tools/ghidra/analysis_pipeline.sh`). ghidra-rs does not port those passes; it takes their
result as input instead:

- `--functions-from <csv>`: use exactly the functions in the first column of the CSV (any
  `0x`-prefixed address list, e.g. a fresh ExportFunctions file of the analysis project).
  Bodies, sizes, xrefs and gaps are still computed by ghidra-rs.
- `--seeds <csv>`: add these entries to what discovery finds.

Replacing the pipeline's export step (mercs2 paths; `build/functions.csv` must be the current
project's function list):

```sh
ghidra-rs analyze orig/Mercenaries2.analysis.exe --functions-from build/functions.csv \
    --functions build/functions-analysis-folded.csv --gaps build/gaps-analysis-folded.csv
```

What discovery does, after Ghidra's analyzers:

- disassembles every executable section by recursive descent from the exports, the entry
  point and RTTI vftable slots (MSVC CompleteObjectLocator -> TypeDescriptor); call targets
  become functions;
- Function Start Search: the definite `x86win_patterns.xml` prologue pairs (`CC`/`90`/`C3`/
  `C9 C3`/`C2 nn 00` or `JMP` before a prologue) in bytes no code covers yet;
- switch tables `JMP [reg*4 + table]`, bounded by a preceding `CMP reg,imm` (else up to 1024
  entries while they point at code in the jump's own section); in a two-level switch
  (`MOVZX reg,byte ptr [idx + bytetable]` between them) the CMP bounds the byte table and the
  jump table has as many entries as its largest byte plus one;
- Create Address Tables: runs of 2+ code pointers in data are disassembled, without making
  functions;
- Shared Return Calls with contiguous functions: an unconditional jump past the next function
  entry (or before the previous one) makes its target a function;
- imports are read from the import directory through the loaded image (the mercs2 image keeps
  its IAT in `.rdata` and the directory in `.securom`);
- `callees`/`callers` count, like Ghidra's `getCalledFunctions`: direct CALLs, JMPs to a
  function entry, `CALL [slot]` through an import slot (one callee per slot) and
  `CALL [global]` whose initial value is a function entry, and indirect calls whose target
  constant propagation finds (Ghidra's `COMPUTED_CALL` references);
- non-returning functions: known imports (ExitProcess, exit, abort, ...), functions whose
  body has no return, and `JMP [slot]` thunks to non-returning imports; calls to them end the
  flow;
- REP string instructions fall through (their p-code branches to themselves);
- data references (`data_refs`): direct memory operands, immediates that point into a
  non-executable section, and code constants (immediates and computed values that point into
  an executable section, e.g. `PUSH offset callback`), as found by constant propagation
  (`Analysis::propagate`, Ghidra's ConstantPropagationAnalyzer, which `--functions` runs).

### Match against Ghidra (Mercenaries2.analysis.exe)

Compared on 2026-11-12 (7.4 MB `.text`), with constant propagation feeding `callees`,
`callers` and `data_refs` (before it, from master 30a12f881a, in brackets). The
`--functions-from` reference is a fresh ExportFunctions/ExportGaps run on the current mercs2
analysis project (37,635 functions, after ClearFalseNoReturn and AddRelocatedEntries); the
pipeline's `build/functions*.csv` from 2026-10-14 predate those steps. Column rates are over the functions both sides have.

| run | reference | functions | size | callees | callers | data_refs | gaps rows |
|---|---|---|---|---|---|---|---|
| plain discovery | `functions-analysis.csv` (import only, 23,323) | 22,388 common, 935 missing, 365 extra | 95.7% | 87.7% (87.6%) | 88.5% (88.4%) | 87.6% (80.4%) | (no reference) |
| `--functions-from` fresh export | fresh export (functions and gaps) | 37,633 of 37,635 | 99.1% | 97.2% (94.6%) | 97.5% (97.2%) | 89.9% (83.1%) | 39,243 of 39,557 identical (ours: 39,368 rows) |

`name`, `exported`, `vtable_class` and `lua` match on 99.9% or more of the rows; `fid` is
always 0. Superseded (branch `fid`): `fid` and the library names come from Function ID, see
below.

Known differences:
- Constant propagation still differs from Ghidra's in places (see CheckAbiCallers below):
  with `--functions-from`, `data_refs` is lower than Ghidra's on 2,251 rows and higher on
  1,556; `callees` lower on 444 and higher on 603. Counting the propagation fixed 2,630
  `data_refs` rows and broke 87 (e.g. SecuROM-split bodies such as 0x407960).
- Ghidra leaves some JMPs to a function entry as jumps (e.g. 0x72cc00 -> 0x4ddaab, a target
  recovered after auto-analysis); ghidra-rs counts every one as a call, which matches Ghidra
  on more rows than counting none.
- Function sets of plain discovery: Ghidra also creates functions from code pointers and
  operand references in some cases; making functions of all such pointers gave more extra
  functions than found ones, so ghidra-rs does not.
- The 2 functions missing with `--functions-from` (0x475541, 0x98248c) start inside an
  instruction that ghidra-rs decoded first from another flow (overlapping code); ghidra-rs
  keeps the first decode and drops the entry.
- Sizes against mercs2's row walk (`./tool fix_sizes --table`, mercs2 docs/notes/row-sizes.md,
  2026-11-12, `analyze --functions` on Mercenaries2.analysis.exe): `size` is a body byte count
  like Ghidra's, so it is short of the extent wherever a body has padding between its pieces
  (1,540 mercs2 rows) and adds the bytes of SecuROM's outlined fragments. Beyond that:
  - shared epilogue left out: 0x51e690 (WeaponAmmo_FireProjectile) 2,112 against 2,121; several
    paths jump to a shared epilogue at 0x51eed0 whose `ret` is at 0x51eed8;
  - slot entries count only the entry jump: 0x4061a0 5 (body 146), 0x41dd60 11 (432);
  - a tail after an outlined fragment is taken into the function (0x478350 1,159 with the
    piece at 0x478794), which is right; mercs2 had two rows there;
  - 44 rows shorter than the code reached even as a byte count (0x444740: 920 of 947)
    and 116 longer than the walk (mostly pieces such as 0x417b10, a switch dispatch whose
    cases lie past the next mercs2 row: 136 against 7; not checked one by one).

Time on the same machine: ghidra-rs `analyze` takes about 9.5 s wall (8.3 s analysis, one
thread), measured before `--functions` ran the whole-function propagation, which adds about
1.5 s on 12 threads (10.5 s to 12.1 s analysis with `--functions-from`). Ghidra's
auto-analysis of the same game (`Mercenaries2.exe`, mercs2 `build/ghidra-import.log`) took
723 s, before the post-scripts. Function ID adds about 3 s (see below).

### Function ID

`--functions` runs Function ID first, as Ghidra's FidAnalyzer does with its default options,
and writes its results to the `fid` and `name` columns (`ghidra-rs/src/fid.rs`):

- Databases: every `*_x86.fidbf` (vs2012, vs2015, vs2017, vs2019, vsOlder) in
  `/opt/ghidra/Ghidra/Features/FunctionID/data`, or in the directory `GHIDRA_RS_FID` names.
  They are read in place: a `.fidbf` is a Ghidra buffer file (`LocalBufferFile`: a header
  block, then 16 KB blocks with a 5-byte prefix) holding Ghidra DB tables (`DBParms` gives the
  master table, whose records give each table's B-tree root; long-key interior, fixed- and
  variable-length record nodes). The Functions, Strings, Superior and Inferior tables are
  loaded; their index tables are not used (ghidra-rs builds its own map by full hash).
- Hash (`MessageDigestFidHasher`): FNV-1a 64 over each instruction of the function body, its
  bytes masked by the instruction mask, plus a per-operand sum of its registers (offset in the
  register space) and constants (a small or whole-operand constant goes into the specific
  hash, an address never). The masks are SleighDebugLogger's: the instruction bits the SLEIGH
  decode matched on (decision-tree bits and matched instruction patterns, recorded by
  `Sleigh::decode` when `Parse::fid` is set), less each operand's value bits
  (`Sleigh::fid_parts`). NOPs and `MOV r,r` fillers (`X86InstructionSkipper`) are left out.
  A constant counts as an address where the instruction has a reference to it (ghidra-rs's
  `refs` and `code_imms`); the mercs2 image has no relocations, so Ghidra's relocation check
  is not ported.
- Matching (`FidProgramSeeker`): records with the same full hash, scored by their code
  units, 0.67 per specific constant if the specific hash matches, and the code units of
  children (call targets) and parents (callers) the database relates to them; at least 14.6
  to match, and the best score wins (ties are all kept). A CALL and a JMP to a function entry
  are calls, as in the rest of the analysis.
- Naming (`ApplyFidEntriesCommand`, `MatchNameAnalysis`): one name (up to leading `_`) is
  applied; several need a score of 30 and give the function each name no other function
  holds, and `FID_conflict:<base name>` when more than one is left (the first of them in
  Java `HashSet` order is the base). Exported functions keep their names and are not marked.
  Names are demangled for the CSV (`@name@4` fastcall names, and `` `vector_deleting_destructor' ``
  and the other compiler helpers, added to `scripts::demangle`).

Not ported: the demangled-name variants of MatchNameAnalysis (`demangledNoTemplate`,
`demangledBaseName`), removing a conflicting label when a later function matches it alone,
thunks, and the library names in plate comments and bookmarks.

Result on 2026-11-12 against the `fid` column of Ghidra's own exports (no new Ghidra run was
needed):

| run | reference | Ghidra's FID rows | identical | other name | missing | extra |
|---|---|---|---|---|---|---|
| `--functions-from build/functions.csv` | `build/functions.csv` | 26 | 24 | 2 | 0 | 0 |
| plain discovery | `functions-analysis.csv` (import only) | 26 | 24 | 2 | 0 | 1 |

The two other names: 0x89c510, a templated `CStringT` constructor that the small demangler
leaves mangled (Ghidra: `ATL::CStringT<wchar_t,...>::CStringT<...>`); and 0x9ee940, which
ghidra-rs names `__chkstk` and Ghidra `__alloca_probe`: the databases hold both names for this
hash, and the `__alloca_probe` record scores lower in ghidra-rs (parent relations; ghidra-rs
finds 101 hashed callers, Ghidra 108). The extra row with plain discovery, 0x9eef98
`__setdefaultprecision`, is a function Ghidra did not make. Plain discovery also names about 1,545
functions outside `.text` (the SecuROM sections), which the CSV does not list; they are not
checked against Ghidra.

Hashes are checked exactly: the hash of `@__security_check_cookie@4` (0x9eec5e) equals its
database record (`tests/fid.rs`). Time: about 3 s (2.5 s with plain discovery, 3.8 s with the
37,596 functions of `--functions-from`), most of it loading the five databases (112 MB).

### CheckAbiCallers (`--abi-callers`)

```sh
ghidra-rs analyze orig/Mercenaries2.analysis.exe --functions-from build/functions.csv \
    --abi-callers config/register_abi.csv config/abi_callers.csv
```

The port follows the script method by method (`ghidra-rs/src/abi.rs`). What it takes from
ghidra-rs instead of a Ghidra project:

- Register reads and writes per instruction come from its p-code, as Ghidra's
  `getInputObjects`/`getResultObjects` compute them: a register-space varnode maps to the
  smallest register at its offset that is at least as large (`RegisterManager`), and a register
  read after the instruction wrote it is no input. Liveness keys are bytes of the base register
  (the largest register containing it: `EAX#1` for AH, `ZMM0#0` for XMM0's low byte). Inputs
  are ordered as Java's `HashSet` iterates them, since the script reports the first live one.
- Instruction text is Ghidra's Java `Instruction.toString`: branch targets and `[0x...]`
  addresses as 8 hex digits, operands joined with a bare `,`.
- Flow types: a CALL to a non-returning function has no fallthrough (CALL_TERMINATOR); a JMP
  to a function entry is a call (CALL_RETURN); `CALL/JMP [ptr]` through an initialised pointer
  to code flows to its value; `JMP [reg*4+table]` flows to the switch cases.
- References to an address: flows (calls, jumps, switch cases, through initialised
  pointers or values the local fold computes), memory operands and addresses the fold
  computes (READ), immediates (DATA; not the x87 constructors' copy of the
  instruction's own address into `FPUInstructionPointer`), the loader's `Entry Point`
  reference to an export (EXTERNAL) and its export address table slot (DATA, an image-base
  offset), and pointers in data sections (DATA); code references first, then data, each by
  source address. Pointers in data are, by default, the ones Ghidra defines: words an
  instruction references, and the address tables of Ghidra's Create Address Tables analyzer
  (`Analysis::address_tables`, ported from `AddressTableAnalyzer`, `AddressTable.getEntry`
  and `checkTable`), in every section, including bytes of executable sections no instruction
  covers. A table is a run of at least `getThresholdRunOfValidPointers` words (5 for the mercs2
  image: one in a billion by chance), 4-aligned, each an address in the image (not 0, not
  below 1024). It ends at a reference into the run after its second word, the next reference
  or instruction after its start, a pointer into the middle of an instruction or to an
  instruction something falls into, a UTF-16 string, or a jump of more than 0xffffff between
  neighbours; a cut that leaves fewer than the minimum skips that entry and tries the rest.
  Not modelled: Ghidra's defined data (strings, structures) and its order of analysis.
  `--data-pointers` takes every aligned word of the data sections equal to the address
  instead (the export directory aside), which finds callers Ghidra misses but no longer
  matches its output.
- Code Ghidra decoded outside the function bodies is decoded too, since its references count:
  code reached through code constants (`PUSH offset callback`, `MOV [g],offset fn`, SecuROM's
  disguised calls `PUSH next; PUSH callee; RET` and `PUSH next; JMP callee`), and the entries
  of address tables that are all code, repeated over what that code reaches. A code constant
  is followed only where Ghidra's `PseudoDisassembler.isValidSubroutine` would accept it (as
  OperandReferenceAnalyzer asks before "Found code from operand reference"): its flow decodes
  without a bad instruction, runs into no existing code, jumps only to instruction starts,
  never branches conditionally to its own fallthrough, and returns, jumps through a register
  or reaches a function; a single instruction must reach a function. Pointers in data are
  followed too (`Analysis::pointer_targets`, OperandReferenceAnalyzer's `checkForPointer`): a
  data word an instruction or address table references, of 4096 or more and with no other
  reference into the rest of the word, and every slot of an address table (also tables that
  mix code and data pointers), is disassembled where `isValidSubroutine(target, true)`
  accepts it (its flow may run through existing code, and one instruction is enough). This
  is how Ghidra reaches code only a vtable names, e.g. the deleting destructor 0x752040. Not
  modelled there: the string check at the word and pointer chains. This code belongs to no
  function and does not change `--functions` or `--gaps`.
- Code constants also come from a local constant fold (a stand-in for Ghidra's constant
  propagation, `SymbolicPropogator`): 4-byte register values from immediates, initialised
  memory and ADD/SUB/XOR/AND/OR, along a straight line of instructions and on into the
  targets of its jumps (the first jump to reach a target hands it the state, as Ghidra's
  first flow wins); a computed value stored to memory that points at code is a code constant
  of the storing instruction. This finds SecuROM's hidden pointers such as `MOV
  EDI,[0x25084c9]; XOR EDI,[0x24d82a0]; XCHG [ESP],EDI` at 0x553217 (0x4793f0). As in
  Ghidra, an unknown register is a symbol (its value where the fold began, plus an offset),
  and values stored through a folded address are kept (the newest 16 on the stack and 64
  elsewhere); a call makes EAX, ECX, EDX and ESP new symbols. So a call through an object's
  vtable, `MOV [ESI],0xbcc47c; MOV ECX,ESI; JMP; MOV EAX,[ECX]; MOV EDX,[EAX+0x14]; CALL
  EDX` (0x66fce0), gives the slot 0xbcc490 a READ reference (the reference that ends the
  address table there after five words, as in Ghidra) and the call its target, read from
  the slot (Ghidra's COMPUTED_CALL reference; it also becomes the call's flow).
  Superseded inside function bodies (branch `constprop`): see the next item; the local fold
  still serves discovery and the code outside every function.
- Whole-function constant propagation (`Analysis::propagate`, a port of
  ConstantPropagationAnalyzer and `SymbolicPropogator.flowConstants`): after disassembly,
  every function is walked from its entry over its body, with the entry's registers as
  symbols, and the references, code constants and computed targets of its instructions are
  the ones these walks find (several walks or functions visiting an instruction add up), in
  place of the local fold's. As in Ghidra, each path keeps its own state: a conditional branch
  goes on with the fallthrough and saves a copy for its target (taken later, last saved
  first); a flow into code already visited runs on for at most 16 instructions or up to a call
  (MAX_EXTRA_INSTRUCTION_FLOW); states are not merged where flows join, so the first flow to
  reach code decides its values; a jump to another function is a tail call. A call pops the
  return address and the callee's purge (the `n` of its `RET n`, where all its returns agree,
  as Ghidra's handleFunctionSideEffects with __stdcall's unknown extrapop); with no known
  purge (imports, computed calls, no body) ESP becomes a new symbol. Memory nothing was
  stored to holds a symbol of its own, so `MOV EBP,[ESP+0xc]` is the third argument and a
  vtable stored through it 450 instructions earlier is still there at `CALL EAX` 0x73b4d1
  (now resolved, as in Ghidra). The fold also gained NOT/NEG, shifts, MUL, `XOR r,r`, byte
  constants and the carry (`STC; ADC EBP,[a]`, `ROL EDX,CL`: SecuROM stubs), and a constant
  stored through a register, `MOV ECX,fn; MOV [EAX*8+t],ECX`, is a code constant of the store
  (Ghidra's addStoredReferences). Walks keep up to 1024 stored values each (the local fold
  16 on the stack and 64 elsewhere). Functions are split over threads and merged in function
  order, so the result does not depend on the thread count. Not modelled: Ghidra's import
  signatures (the purge of a __stdcall import), condition values deciding which branch runs
  first, and call fixups.
- `CALL ESI` counts as an import call when the nearest write of ESI before it in the function
  is `MOV ESI,[import slot]` (a stand-in for Ghidra's constant propagation); outside every
  function, the straight line of instructions falling into the call is searched instead.
  `CALL/JMP [ptr]` whose pointer holds an import thunk (`JMP [import slot]`) counts as that
  import: Ghidra's walk passes `CALL [0xcddff0]` at 0x9deb31 (-> 0x9ee9fe -> `free`) as one,
  which its `violation` at 0x675611 needs.
- Ghidra walks the references to a function in its database order (the order analysis made
  them) and reports the first walk that stops. That order is not reproduced (ours: code
  references by source address, then data), so where a value is live at a function's
  return, a `violation` behind any of its references wins over a walk that stopped
  (`unknown`); otherwise the first stopped walk is reported. Ghidra's own order put
  0x41e69a before 0x401bbc among the callers of 0x41d7a0, which its `violation` rows at
  0x41d7be and 0x41d834 need (the walk from 0x401bbc stops in the relocated body of
  0x41ef50); the same rule also turns 9 rows Ghidra reports `unknown` into `violation`
  (all end at a `PUSH` of the register that is never read back, like the two above; kept,
  see `../DESIGN.md`).
- `securom_functions.csv`, read from the directory of `register_abi.csv` as the script reads
  `config/securom_functions.csv`, gives the relocated bodies; they are made functions, as
  AddRelocatedEntries.java does. Contract entries no analysis reached are disassembled first,
  as the script's `disassemble(entry)` does.

Result on 2026-11-12 with `--functions-from` the fresh 37,635-function export, against
`config/abi_callers.csv`, `config/register_abi.csv` and `config/securom_functions.csv` of
mercs2 commit f14e5c4 (53,511 rows): 52,890 rows identical (98.8%; the file is compared
sorted, since Ghidra lists references in its database order; 52,819 before the
whole-function propagation). ghidra-rs writes 53,634 rows and reports `Checked 36865
references; 2912 output findings; 277 input findings`. (Superseded: against the reference
of 2026-11-11 13:05, 52,922 rows, it was 52,198 identical; 52,000 before the symbolic fold,
51,705 before the coverage changes, 51,099 before the drop-in changes.)

Never-returned bytes (`never_returned`, also CheckAbiCallers' `neverReturned`): an EAX byte
that reaches a RET unwritten on some path is taken as not returned, and dropped from the
output check. A read of EAX stops that walk, so an EAX input is never dropped. A byte the
function's own body never writes is no longer dropped either (Java still drops it): on every
path it is the caller's value or a callee's, passed through, and a caller may read it back
(test `output_check_pass_through_and_input_eax`). On mercs2 (2026-11-13, 38,161 references)
this adds 561 output rows, all from no finding to a stricter one: 556 `unconcluded` and 5
`violation`, the latter all GameFree 0x84af20, whose mutated-call caller 0x5a0dca resumes at
0x5a0dd9 and pushes its own pre-call EAX at 0x5a0de8. Output findings 3,034 → 3,595.

The mercs2 ABI gate reads only `address`, `contract`, `site` and `status` (and the `output`/
`input` marker rows). Projected to those fields and sorted, 215 reference lines are missing
from ours and 338 are extra (285 and 351 before the whole-function propagation; against the
reference of 2026-11-11 13:05: 317 and 362, 491 and 560 before the symbolic fold, the
import-thunk and the violation-first rules; 746 and 784 before the local constant fold, the
address tables in all sections and the valid-subroutine check; 2,189 lines before the x87
self-reference, export and data-pointer rules and the code-constant disassembly). By kind
(missing / extra; before the whole-function propagation in brackets; a site at or above
0xb05000, the start of `.rdata`, counts as data):

| lines | missing | extra |
|---|---|---|
| code sites | 77 (122) | 191 (192) |
| `output:`/`input:` rows | 97 (115) | 77 (80) |
| "no references" rows | 14 (16) | 12 (15) |
| data sites | 27 (32) | 58 (64) |
| of these, `COMPUTED_CALL` rows | 2 (5) | |

The mercs2 project's own second opinion (`tools/ghidra-rs-shadow.sh`: statuses per contract
and site, `--functions-from build/functions.csv`, against its regenerated
`config/abi_callers.csv` of 2026-11-12) gives: same 53,460, differ 56, Java only 162,
ghidra-rs only 299 (53,390, 57, 231 and 312 before the whole-function propagation).

By cause:

- code only ghidra-rs decodes (policy, 31 extra lines): the callers of LtiDebug_Log in
  0x755d30..0x755e13 (reached by a CALL from 0x755f46, code Ghidra has no function or
  instruction for: the walks there end at `live at return` with no function) and of
  VehicleDriver_Send* in 0x5454ea..0x545c3c (0x545a90 has no references in either tool).
  Ghidra writes no row for these sites.
- a site whose status differs (as of the 2026-11-11 reference: 48 code-site lines each way,
  and 2 "no references", 1 data site): 18 `unknown` -> `violation` (9 from the
  violation-first rule, 9 older: walks that stop in Ghidra at relocated SecuROM bodies,
  `enters wrapper code`, or at computed jumps), 24 `unknown` -> `ok` (mostly XMM/ZMM bytes
  Ghidra still finds live at a return, e.g. 0x4bcb5c), 3 `ok` -> `unknown`, 5 `trivial`/`ok`
  swaps.
- a reference only one side has: references in code only one side decoded (most of the
  missing code sites are direct calls), and address tables cut at different places (Ghidra's
  analysis order adds the cutting references before or after a table is made; e.g. 0xbb0b70
  is no longer a table in ours, and the propagation's READ reference to the vtable slot
  0xbcd260 now cuts a table Ghidra keeps; keeping the propagation's references out of the
  cut was tried and matched 9 lines fewer). Two `COMPUTED_CALL` rows remain: `CALL EAX` at
  0x4c07be, which two paths reach with different slots (Ghidra's walk takes the other path
  first), and 0x4c08b3.
- the results of those: `output:`/`input:` rows and "no references" rows whose walks pass
  through the code above or whose references differ, and 14 `output:` rows of 0x42f850 where
  Ghidra loses X87#0 and ours finds it never returned (Ghidra's callee memo spans contracts,
  ours one contract).
- JMPs Ghidra left as jumps (3 `tail jump reference` rows extra, 1 missing).
- inputs: some rows (e.g. 0x54c990 HumanExit_Update) come from mercs2's DefineTableFunctions
  and ClearFalseNoReturn passes, which the `--functions-from` export lacks.

`tools/abi-ledger.csv` judges the shadow diff by safety rather than agreement with Java (see
`../DESIGN.md`). It has one row for each `differ` and `Java-only` row of the shadow run at
ghidra-rs bd56d2f09a against mercs2 395ba6b (58 and 174 rows; that run gave same 55,362, differ
58, Java only 174, ghidra-rs only 309; the ghidra-rs-only rows are not in the ledger yet).
The columns are `address,site,java,ghidra_rs` (from the diff), `truth` (`ok`, `violation`,
`unknown`, `not-a-caller`, or `unverified` for a row grouped but not checked by itself),
`evidence` (the bytes or reasoning behind the truth, or `group:<cause>; checked <site>` naming
a checked row of the group) and `cause` (a kebab-case group). mercs2's abi_test callee trace
(`build/abi_callees.csv`) held one row at that commit, so every truth comes from the
disassembly and the contracts.

Following pointers in data (`pointer_targets`, see the analysis section) gives 17 of the
ledger's `(none)` rows their caller, each now with Java's status: the undecoded tails of
0x5b2950 (0x4b2a50 at 0x5b2afb; 0x59f770 at 0x5b2a56, 0x5b2a98, 0x5b2ad6, 0x5b2aed), 0x84af20
at 0x60f1e0, 0x61bb70 and 0x752050 (the vtable-only deleting destructor 0x752040), and the
nine `trivial` sites of 0x88cdc0. On the shadow run against mercs2 8d38ed4 it moved Java only
from 174 to 157 and same from 55,421 to 55,438 (differ 58, ghidra-rs only 309 unchanged); no
row of ours changed or went away (17 added), and `--functions`/`--gaps` and plain discovery are
byte for byte the same. The `data-pointer-missed` rows (data sites in vtables no instruction
references, e.g. 0xbcd238) are still missing: they need the slot itself as a reference, which
only `--data-pointers` makes.

Every `violation` site of the reference is written with that status: the eight missing
before the coverage changes (0x4793ff, 0x47940e, 0x479440, 0x479445, 0x479450, 0x47945b,
0x479466 through the folded pointer at 0x553224, and 0x6fd52b through the address table at
0x6fe900), and the three of 0x84af20 at 0x41d7be and 0x41d834 (the violation-first rule) and
0x675611 (the import-thunk rule). 25 extra `violation` lines remain where Ghidra says
`unknown` or has no row (16 before the coverage changes; unchanged by the propagation).

It takes about 23 s wall on a 12-thread machine (about 19 s analysis, of which about 2 s are
the whole-function propagation on 12 threads, about 9 s on one; the rest is on one thread:
about 3 s the local fold, 2.3 s checking code constants for valid subroutines, 0.5 s
building address tables; following data pointers adds about 1 s: 18.3 s analysis against
17.1 s before it, one run each; 20 s wall and 15 s analysis before the propagation, measured back
to back on a busy machine; 16 s before the symbolic fold, 14 s before the coverage changes;
3.5 s checking on 12; checking alone is about 25 s on one thread). The contracts are split over
threads (contract `t`, `t+n`, ... to thread `t`), and written in file order;
`GHIDRA_RS_THREADS=<n>` sets the count (default: all cores). The caches (callee walks,
`pushes_float`, never-returned values, input walks) live for one contract, so a result never
depends on which contracts a thread checked before: the output is the same byte for byte with
1, 3 and 12 threads (1 and 12 checked again after the symbolic fold and after the
whole-function propagation). Before 2026-11-11 the check took 38 s on one
thread: each walk step copied and hashed the whole live set (a set of `String`s) to detect
revisits; live keys are now inline (`Key`) and a walk numbers each distinct live set once. The
script's own run time in Ghidra was not measured here.

## Decompiler harness (Milestone 3, stage S0)

The decompiler is checked stage by stage against Ghidra's C++ console decompiler `decomp_dbg`
(plan: `docs/plans/m3-decompiler.md`). This is the harness the stages are measured with; what
is ported is in "Decompiler (Milestone 3)" below.

```sh
rust/tools/decomp-ref.sh                       # builds rust/target/decomp-build/{decomp_dbg,decomp_test_dbg}
ghidra-rs analyze <pe32> --decomp-prelude <out> # the shared prelude (also built by decomp-diff.sh)
ghidra-rs decompile -i <script>                # the Rust console, same scripts as decomp_dbg -i
ghidra-rs datatest [--ref <decomp_dbg>] <test.xml|dir>...
rust/tools/decomp-diff.sh m8|m500|<address file>|d
rust/tools/decomp-diff.sh --script <file>      # one script on both engines, full diff
```

- `decomp-ref.sh` copies the C++ sources into `rust/target/decomp-build` (the upstream tree is
  not touched), applies `tools/decomp-ref.patch` and builds both programs. The patch adds the
  data-type (`<type>`) and the high variable (`{hN}`) to each varnode of `print raw` when the
  environment variable `DECOMP_RAW_EXTRA` is set; without it the output is upstream's. With
  `DECOMP_JT_RAW` set (stage S3), it also prints to stderr the partial function each jump-table
  recovery simplifies (`print raw` form) and the reason a recovery fails. Run `decomp_dbg` by
  absolute path with `SLEIGHHOME=<repository root>`.
- `--decomp-prelude` writes console commands both engines `source` before a function:
  `option readonly on`, `readonly` over `.rdata` (so `.rdata` constants such as floats fold
  instead of printing as `fRam...`), for each IAT slot a `nocode` function named after the
  import plus `map externalref` from the slot to it (so `CALL [slot]` calls the import instead
  of decoding the bound address in the slot, which made 0x40a110 fail), and `map function` for
  every function with its FID or export name. For mercs2: 30,262 `map function` lines (1,022 of
  them import slots), 1,022 `map externalref`.
- `decompile -i` reads `load file`, `source`, `map function`, `map externalref`, `readonly`,
  `option`, `fixup apply`, `load function`, `load addr`, `break start`, `decompile`,
  `print raw`, `continue` and `quit`, and echoes them as `decomp_dbg -i` does. `decompile`
  runs up to the `break start` action (stage S4: at most `assignhigh`, see "Stage S4") and
  `continue` resumes it; a function mapped `nocode` prints `No code for <name>` instead. `print
  C|tree block` fail with "not implemented in ghidra-rs yet (milestone 3, later stages)";
  `parse line` defines types and locks `extern` prototypes (stage S6); any other command fails with "not implemented in ghidra-rs".
  Superseded: until S6, `parse line` failed like `print C`.
  Superseded: until S2, `decompile` stopped at most at `heritage` and `continue` failed. Of the options
  `option readonly on|off` and `option currentaction decompile <group> on|off` have an
  effect (and print the reference's message); the others (`togglerule`: no rule is ported
  yet) are read and ignored. Superseded: until S4, `decompile` stopped at most at
  `paramdouble` and `option currentaction` was ignored. A name mapped twice
  (`map function`) finds its first function, as the C++ `findFirstByName` does.
  Superseded: S0 and S1a ignored `option` and `map externalref`; S1b reads them (read-only
  propagation, external-reference slots).
- `datatest` is the port of `testfunction.cc`: it reads an upstream XML test (`<script>`,
  `<stringmatch>` regexes with `min`/`max`) and checks the script's bulk output. With `--ref` it
  runs the script on `decomp_dbg` (needs `SLEIGHHOME`); without, on the Rust console, which
  cannot load a test's `<binaryimage>` yet, so every file is reported "not run".
- `decomp-diff.sh <corpus>` writes one script per function (`load file`, `source` the prelude,
  `OPTIONS`, `load function <name>`, `break start $BREAK`, `decompile`, `$PRINT`, `quit`) and both
  outputs under `rust/target/decomp-check/<corpus>/`, then prints the functions the reference
  could not decompile, the first differing line of each mismatch and `identical N / M`.
  Corpus `d` runs the datatests on both engines.
- Corpora: `tools/corpus/m8.txt` (the plan's eight hand-picked mercs2 functions; the switch
  function is 0x4042e0, byte table read at 0x4043d5 and jump table at 0x4043dc; the vtable call
  at 0x73b4d1 is in 0x73a340) and `tools/corpus/m500.txt` (500 `.text` functions of mercs2
  `build/functions.csv`, drawn by `tools/decomp-corpus.sh` with seed 20261112; the script
  reproduces the list).

Results on 2026-11-12 (branch `m3-s0`):

| check | reference | ghidra-rs |
|---|---|---|
| `decomp_test_dbg ... datatests` | 665 / 665 checks in 77 files; 16 non-x86 files lack a `.sla` | – |
| corpus d (`ghidra-rs datatest`) | 665 / 665 checks; 16 files not run (non-x86) | 0 checks run; 93 files not run (not ported) |
| corpus m8 | decompiles 8 / 8 | identical 0 / 8 (`decompile` not ported) |
| corpus m500 | decompiles 500 / 500 | identical 0 / 500 |

Superseded: S1a's results are in "Decompiler (Milestone 3)" below.

### Debugging tools

Added in stage S2. All run both engines through `decomp-diff.sh` and keep their outputs under
`rust/target/decomp-check/`.

- `decomp-diff.sh` options, as environment variables:
  - `VERBOSE=1`: for each mismatch, also print the break each side stopped at, any ghidra-rs
    error, the first differing op and its basic block, and 5 lines of context from both sides
    in two columns (`>>` marks the first differing line).
  - `ORDER=easy`: run the corpus simplest first.
  - `STOP=1`: run one function at a time and stop at the first mismatch, printing its verbose
    diff.
  - `CONTINUES=N`: after the print, run `continue` and the print again N times.
  - `OUT=<dir>`: set the output directory.

```sh
BREAK=paramdouble VERBOSE=1 rust/tools/decomp-diff.sh m8
ORDER=easy STOP=1 BREAK=paramdouble rust/tools/decomp-diff.sh m500
```

- `decomp-show.sh <ref-file> <rust-file>` prints that verbose diff for any two outputs, e.g.
  `rust/target/decomp-check/m8/{ref,rust}/0x401000`.
- `decomp-rank.sh <corpus>` ranks a corpus by loops (back edges), then basic blocks, counted in
  ghidra-rs's `print raw` at `break start funclink`. It writes
  `rust/target/decomp-check/<corpus>.ranked` (`0x401000 # 4 blocks 0 loops`), which
  `ORDER=easy` uses and builds if it is missing.
- `decomp-bisect.sh <addr> [continues]` finds the first action, and the first hit of it, at
  which the two engines' `print raw` differ for one function. It breaks at each action of the
  universal order from `start` through mainloop, with `continues` (default 3) further
  `continue`s to reach the repeated mainloop passes, compares hit 1 of every action, then hit
  2, and so on, and prints the first difference with the verbose diff. A ghidra-rs break or
  command that is not ported yet shows as `rust: not supported: ...`.
  `ACTIONS="funclink heritage paramdouble"` limits the list. `unreachable`, `directwrite` and
  `deadcode` are left out because the reference rejects breaks on them (each name is in the
  action tree twice). Outputs: `rust/target/decomp-check/bisect-<addr>/`.

```sh
rust/tools/decomp-bisect.sh 0x401000
ACTIONS="funclink heritage paramdouble" rust/tools/decomp-bisect.sh 0x401000 5
```

- Jump tables (stage S3): `GHIDRA_RS_JT_DEBUG=1 ghidra-rs decompile -i <script>` prints to
  stderr each table ghidra-rs recovers (`jumptable in <function> at <jump>: N targets [...]`)
  or why it fails; `=2` adds the partial function (`print raw`) and the model's paths, guards
  and range. `DECOMP_JT_RAW=1` gives the reference's partial function (see `decomp-ref.sh`
  above), so the two partials can be compared at the switch.

The reference only accepts an absolute script path (`decomp_dbg -i /abs/path`); with a relative
one it fails a libstdc++ assertion and prints nothing.

## Decompiler (Milestone 3)

Stage S1a (branch `m3-s1a`): flow and raw p-code. `decompile` follows the function's flow with
the milestone-1 SLEIGH engine, builds basic blocks and runs the universal action's first
actions (`start`, `constbase`, `normalizesetup`, `defaultparams`, `extrapopsetup`,
`prototypetypes`); `break start funclink` stops there and `print raw` prints the result.
Check:

```sh
BREAK=funclink rust/tools/decomp-diff.sh m8
BREAK=funclink rust/tools/decomp-diff.sh m500
```

| corpus | identical (`print raw` at `break start funclink`) |
|---|---|
| m8 | 8 / 8 |
| m500 | 500 / 500 |

No differences remain. What the port keeps from the C++ because the output depends on it:

- Op sequence numbers count creation, so flow decodes in Ghidra's order: the address stack is
  last-in-first-out, ops after a final branch are deleted (their numbers stay used), halts get
  their numbers when created (an indirect jump that becomes a call gets its `return(#0x1)` only
  after all flow), and the actions' ops (`DF = #0x0:1`, `ESP = ESP [] i...`) come last.
- Blocks are printed in the reverse post-order of `findSpanningTree` (fall-through edge first),
  with irreducible edges skipped as the C++ does.
- Calls are sorted (`sortCallSpecs`) by block index and the op's order key. The key is
  `BlockBasic::insert`'s, not the position: in a block of more than about 280 ops the keys
  saturate at `0xfffffffd` and tie, so the INDIRECTs of `extrapopsetup` come out in the order
  libstdc++'s unstable `std::sort` leaves the ties in (0x73a340); `stdsort.rs` ports it, and
  its unit test pins g++'s exact tie order (`tools/stdsort_ref.cc`, `tests/data/stdsort-gxx.txt`).
- `print raw` writes to a stream whose number base is sticky (an address leaves it hex, a block
  index or register offset decimal); `print.rs` tracks it.

What S1a does not port, because the console reference never reaches it on mercs2: call fixups
and inlining (the console applies no `callfixup` by name), non-returning calls (the console's
functions have no prototypes), p-code injection, multistage jump tables, and flow limits other
than the instruction count and bad-data count. Jump tables (stage S3) have a stand-in: the
MSVC switch `JMP dword ptr [reg*4 + table]` bounded by a `CMP reg,imm` (imm8 sign-extended) with a
`JA` before the jump, possibly through a byte index table, gives one target per switch value in
order, as `JumpBasic` does, and fails past `max_jumptable_size` (1024) entries; any other
indirect jump becomes a call and a halt (`truncateIndirectJump`). It covers the 5 switches in
M8 and M500. Superseded: stage S3 replaces the stand-in with the port of jump-table recovery
("Stage S3" below). As in the C++, an instruction at an unmapped address ends the decompile with an
error (`DataUnavailError`), and only a constructor without p-code counts as unimplemented
(`Sleigh::pcode` returns `PcodeError::Unimplemented` for it, `Invalid` for anything else).
Superseded: "call fixups ... (the console applies no `callfixup` by name)" above: the console
applies none by name, but `fixup apply` sets one, and S1b injects it (below).

### Stage S1b: specs, prototypes, call fixups

Stage S1b (branch `m3-s1b`) runs the universal action up to `heritage`: after `funclink`, the
`fullloop:mainloop` actions `unreachable` and `varnodeprops`; `break start heritage` prints
`Break at universal:fullloop:mainloop:heritage start`. It reads `x86win.cspec` (next to the
`.sla`; `Arch::new` takes its text) and replaces S1a's minimal actions with ports:

- `cspec.rs`: the stack pointer (`<stackpointer>`, replacing S1a's hard-coded ESP), the return
  address, the four prototype models with their parameter entries, unaffected,
  killed-by-call (including `<output killedbycall="true">`) and likely-trash registers,
  `<resolveprototype>` (`ProtoModelMerged`: shared effects and likely trash, input entries
  merged as `ParamListMerged::foldIn` does, by containment and minimum size),
  `<eval_current_prototype>`/`<eval_called_prototype>`, and the ten `<callfixup>` snippets.
  `<data_organization>` and `<global>` are skipped until types (S6) and scopes read them;
  any other element is an error. The tracked `DF = 0` still comes from the `.pspec`.
- `inject.rs`: the snippet parser, a recursive-descent parser for the subset of SLEIGH
  semantics snippets use (assignments to registers and new temporaries, `local`, stores and
  loads with optional space and size, integer and boolean operators, unary `-`, `~`, `!`).
  It follows `PcodeCompile`: each operator and each named temporary takes the next 16-byte
  unique slot, counting from the `.sla`'s unique base + 0x200 across all snippets in file
  order, assignments rename an operator's temporary, sizes propagate as `propagateSize` does.
  User ops, branches, labels, signed and float operators are rejected at load.
- `flow.rs`: a call to a function with a fixup (`fixup apply`) is queued (`injectlist`) and,
  after flow, replaced by the snippet's ops: made at the end of the dead list, walked for
  control flow, moved after the call, and the call deleted (`doInjection`), also in the
  jump-table loop as `generateOps` does.
- `action.rs`: `defaultparams` (each call takes the callee's prototype, with the
  `evalfp_called` or default model), `extrapopsetup` (by the call's extrapop: `SP = SP + n`
  after the call when known, the INDIRECT when unknown), `prototypetypes` (the function takes
  the `evalfp_current` model; RETURN loses its address), `funclink` (a call whose model passes
  parameters on the stack gets the stack-pointer placeholder: `u = ESP + 0`, a 1-byte LOAD,
  as its last input; unique varnodes count from 0x10000000), `unreachable` (nothing to remove
  on the first pass; an unreachable block is an error until block removal is ported in S4),
  `varnodeprops` (with `option readonly on`, a free read of read-only memory becomes the
  constant the image holds there, read as `loadFill` reads: on into later sections, zero where
  none is; the reads are taken in the varnodes' location order, as `beginLoc` walks them). `normalizesetup` and `funclinkoutonly`
  are not in the `decompile` root's groups and are left out.
- Read-only memory is the loader's read-only sections (bfd's `SEC_READONLY`: PE sections
  without `IMAGE_SCN_MEM_WRITE`, `Section::readonly`) plus `readonly` commands; a varnode is
  read-only by the property at its first byte unless an external-reference slot (`map
  externalref`, 4 bytes) contains it, which is how the IAT slots called through stay varnodes.
  A section is as long as bfd loads it (`Section::zero_tail`): the raw size when that is
  smaller than the virtual size, else the virtual size (`_bfd_XXi_swap_scnhdr_in`); in mercs2
  the two are equal for every section.
- The function's prototype is written back to its `map function` entry after `decompile`, as
  the C++ scope keeps its `Funcdata`; a header warning records each injected call fixup
  (`Funcdata::warnings`, for `print C`). A decompile error prints `Low-level ERROR: ...` and
  `Unable to proceed with function: ...` and the script goes on, as in the C++ console.

Check:

```sh
BREAK=heritage rust/tools/decomp-diff.sh m8
BREAK=heritage rust/tools/decomp-diff.sh m500
BREAK=funclink rust/tools/decomp-diff.sh m500   # S1a's check still holds
```

| corpus | identical at `break start heritage` | at `break start funclink` |
|---|---|---|
| m8 | 8 / 8 | 8 / 8 |
| m500 | 500 / 500 | 500 / 500 |

Speed (Mall: every non-import `map function` of the mercs2 prelude, 29,240 functions, one
script, one thread, release build, 2026-11-12): to `break start heritage` in 4.7 s including
loading the PE and the prelude, about 6,200 functions per second; peak RSS 472 MB. 29,139
reach the break, 101 end with the C++'s errors (70 `Unable to load bytes` (flow into unmapped
addresses), 30 `Bad instruction count exceeded`, 1 `Flow exceeded maximum allowable
instructions`); no panics.

No differences remain. Call fixups do not occur in the corpora (the console applies them
only with `fixup apply`); they are checked on mercs2's `__onexit` (0x9ee37a) with
`fixup apply SEH_prolog4 __SEH_prolog4` and `fixup apply EH_epilog3 __SEH_epilog4`
(the unit test `print_raw_at_heritage_with_callfixups`), and by hand with `EH_prolog` and
`alloca_probe` applied to callees of 0x23d8928 (identical but for the reference's "overlaps
object" warning of `load addr`, which the Rust console does not print).

What S1b reads but does not use yet, and what it leaves out:

- The models' output entries (return recovery, S4), the effect lists and likely-trash
  registers (heritage, S2; read now only to merge `<resolveprototype>`), the call's
  placeholder slot (S2). Parameter and return trials (`initActiveInput`/`Output`) are S4.
- Locked prototypes and their paths in `funclink`/`prototypetypes` (no command locks one
  yet: `parse line` is S6, mercs2's `register_abi.csv` as locked custom-storage prototypes
  is plan decision 6, later in milestone 3), no-return calls, inlining, overrides, user-op
  (`callotherfixup`) injection, `uponentry`/`uponreturn` model injections (the x86 specs
  declare none), the `.pspec`'s register data, data types beyond none.
- Superseded: S1b's first commit had read-only ranges over the virtual size; they now follow
  bfd (above).

### Stage S2: heritage (SSA)

Stage S2 (branch `m3-s2`) runs the universal action up to `paramdouble`: after `varnodeprops`,
`heritage` builds SSA form for the spaces of the first pass (register and unique), and
`break start paramdouble` prints `Break at universal:fullloop:mainloop:paramdouble start`.
Modules:

- `actiontree.rs`: the action framework (`Action::perform`, `ActionGroup`,
  `ActionRestartGroup`): statuses, repeat while changing, breakpoints and `continue`, the
  `Break at` path. `action.rs` builds the universal tree from it (S1b's flat list is gone).
- `heritage.rs`: `Heritage::heritage` for pass 0: the disjoint ranges (`LocationMap`,
  `TaskList`), `collect`, refinement (cutting a range read and written in pieces), widening
  smaller reads and writes (`normalizeReadSize`/`normalizeWriteSize`: SUBPIECE, PIECE),
  `guardInput`, call guards (`r = r [] call` for an unknown effect, `[create]` for
  killed-by-call, return-value and parameter trials, a possible parameter as a new call
  input), return guards (the possible return value as a RETURN input), phi placement on the
  augmented dominator tree (`buildADT`, `visitIncr`, `calcMultiequals`) and renaming
  (`renameRecurse`, as an explicit stack).
- `block.rs`: `calcForwardDominator` (with the virtual root of the C++, index 0) and the
  dominator tree and depths. `funcdata.rs`: every input/output edit goes through
  `op_set_input`/`op_set_output`/... which keep the readers (`descend`) and the
  location-sorted varnode set (`loc_tree`: address, size, inputs, written by sequence number,
  free by creation; built at the first heritage pass, kept from then on), input varnodes (`setInputVarnode`), INDIRECT ops (`newIndirectOp`,
  `newIndirectCreation`). `fspec.rs`: effect lookup (`lookupEffect`), `characterizeAsParam`
  (joins included: `EDX` is part of the `EDX:EAX` output), the trial lists (`ParamActive`).
- `print raw` shows inputs (`(i)`) and `[create]`.

Check:

```sh
BREAK=paramdouble rust/tools/decomp-diff.sh m8
BREAK=paramdouble rust/tools/decomp-diff.sh m500
BREAK=heritage rust/tools/decomp-diff.sh m500   # S1b's check still holds
BREAK=funclink rust/tools/decomp-diff.sh m500   # S1a's check still holds
```

| corpus | at `break start paramdouble` | at `heritage` | at `funclink` |
|---|---|---|---|
| m8 | 8 / 8 | 8 / 8 | 8 / 8 |
| m500 | 500 / 500 | 500 / 500 | 500 / 500 |

No differences remain on M8 and M500. The test `print_raw_at_paramdouble_with_a_loop`
(`tests/decomp.rs`, expected output `tests/data/raw-paramdouble-40ad80.txt` from decomp_dbg)
pins a loop function; unit tests in `heritage.rs` check phi placement on hand-built graphs
(diamond, loop, nested loops) and `actiontree.rs` a break inside a repeating group.

Mall (29,240 functions, one script, one thread, release build, 2026-11-12): to
`break start paramdouble` in 19.2 s including loading (about 1,500 functions per second), to
`heritage` in 5.4 s; peak RSS 599 MB, reached by one function in garbage code that decodes
100,000 instructions before it fails (the reader lists cost memory per varnode; the run stays
near 200 MB otherwise); no panics. Each varnode's reader list (`readers.rs`, `Readers`) keeps
up to 4 readers inline in the varnode (24 bytes, a `Vec`'s size) and moves to a `Vec` from the
fifth. Superseded: with a `Vec` per varnode the same runs took 20.9 s and 6.1 s, peak 679 MB
(first measured as 21.2 s, 6.2 s, 682 MB). The location-sorted set is built at the first heritage
pass, since nothing reads it before. Superseded: S2's first commit kept it from varnode
creation on (24.4 s, 11.2 s, 1 GB). 29,131 reach the break, 8 are
`nocode` imports a duplicate name picks first (`No code for`, as the reference), 101 fail. The
101 against decomp_dbg (one run each): 97 fail with the same message. The other 4, all in
the garbage code past 0x2300000, differ in flow: 0x232f745 and 0x2384399 fail on a different
unmapped address, 0x23831b0 exceeds the instruction limit where the reference hits an unmapped
address, and 0x2396e7d fails where the reference recovers a switch at 0x2396eec, which the
S1a jump-table stand-in does not (S3; superseded: S3 recovers it, identical at `heritage`).
Superseded: S1b's "70 `Unable to load bytes`" message
is `Unable to load 512 bytes` now, as `LoadImageBfd::loadFill` words it (it reads 512-byte
chunks), and S1b counted the 8 `nocode` functions among its failures.

What S2 does not port, and why:

- Later heritage passes: ram (pass 1) and the stack (pass 2) are only reached after the main
  loop's other actions and rule pools (`paramdouble` on), which the reference cannot skip, so
  they cannot be compared yet; a later pass fails loudly (`heritage of the ram space: not
  implemented`). With them wait `varmap` (stack ranges), load and store guards, stack
  placeholders (`clearStackPlaceholders`), revisited markers (`removeRevisitedMarkers`),
  `discoverIndexedStackPointers`, scope properties (`addrtied`, `persist`) and the dead-code
  delay warnings.
- `cover.cc`: nothing before `paramdouble` uses covers (they serve merging, S7).
- Overlapping guards (`guardCallOverlappingInput`, `tryOutputOverlapGuard`,
  `guardReturnsOverlapping`) fail loudly; no M500 function needs them. Joins and
  `<prefersplit>` (none in x86) are skipped.
- Prototype state across decompiles (S1b's required item): `fillinExtrapop` belongs to
  `ActionStackPtrFlow`, after `paramdouble` (S4). The 21 datatests that decompile several
  functions cannot be compared yet: the Rust console does not load a test's `<binaryimage>`.

### Stage S3: jump tables

Stage S3 (branch `m3-s3`) replaces S1a's jump-table stand-in with the port of the C++
recovery. When flow meets indirect jumps, `FlowInfo::recoverJumpTables` builds one partial
function (a clone of the function so far, `truncatedFlow`), runs the `jumptable` root action
on it and recovers each table from it (`Funcdata::stageJumpTable`); a jump without a table
becomes a call and a halt, as before. Modules:

- `jumptable.rs` (from jumptable.cc, 2,933 lines): `JumpBasic` and `JumpBasic2`
  (`findDeterminingVarnodes`, `PathMeld`, `analyzeGuards`, `GuardRecord` with `quasiCopy` and
  `valueMatch`, `calcRange`, `findSmallestNormal`, `findNormalized`, `buildAddresses`,
  `sanityCheck`), `JumpValuesRange(Default)`, `JumpTable::recoverAddresses` (`isReachable`,
  `isThunk`), `earlyJumpTableFail`, and `ActionNonzeroMask`'s non-zero masks
  (`Funcdata::calcNZMask`, `PcodeOp::getNZMaskLocal` from funcdata_varnode.cc and op.cc), which
  the guards and strides read.
- `rangeutil.rs` (from rangeutil.cc, 2,605 lines): `CircleRange` (ranges, intersection, union,
  non-zero masks, `pullBack` through unary and binary ops). The value-set solver is not used by
  jump tables and not ported.
- `emulate.rs` (from emulateutil.cc 397, emulate.cc 462, opbehavior.cc): `EmulateFunction` over
  the data flow (`EmulatePcodeOp`, `Emulate::executeCurrentOp`) and the integer and boolean op
  behaviors. memstate.cc (738 lines) is not needed: `EmulateFunction` keeps a value per
  varnode and ignores STOREs. Float ops fail an emulation (no switch in mercs2 uses one).
- Hooks: `action::jumptable_partial` (the `jumptable` root's actions as far as they are
  ported: `start` to `heritage`), `Funcdata` derives `Clone` and keeps the partial's masks
  and folded constants (`nzm`, `folded`), `startProcessing` skips flow for a partial,
  `BlockGraph::is_loop_in`.

In all about 2,200 lines of Rust for about 4,000 lines of C++ ported (jumptable.cc but its
override, assisted and label parts; CircleRange; the emulator parts).

The partial function the C++ analyses has been through the whole rule pool and later heritage
passes (stack, ram); here it has had only what is ported (registers and temporaries in SSA
form, read-only constants). Three stand-ins in `jumptable.rs` read the raw p-code as the rules
leave it, until the rule stages replace them: constants are folded (copies, constant
operations, `xor r,r`, loads from read-only memory: `RulePropagateCopy`,
`RuleCollapseConstants`, `RuleLoadVarnode`); a guard's x86 flag logic (`!(CF || ZF)`,
`OF != SF`, `x - c == 0`) is read as the one comparison the rules turn it into; a commutative
op's constant counts in slot 1 (`RuleTermOrder`). Two C++ details reach the output and are kept:
the non-zero masks (a field `(x << 19) s>> 27` gets an empty range on one varnode, so the C++
gives up on that switch, and so does the port), and a switch variable on the stack matched
through its two LOADs.

Check (`print raw` at `paramdouble`; the switch corpus is every function in which ghidra-rs
meets a jump table, 2,051 of mercs2's 29,240, listed with `GHIDRA_RS_JT_DEBUG`):

```sh
BREAK=paramdouble rust/tools/decomp-diff.sh m8
BREAK=paramdouble rust/tools/decomp-diff.sh m500
cargo test --release -p ghidra-rs --test decomp print_raw_at_paramdouble_with_a_switch
```

| corpus | identical at `break start paramdouble` |
|---|---|
| m8 | 8 / 8 (also at `heritage` and `funclink`) |
| m500 | 500 / 500 (its 4 switch functions included) |
| every switch function (2,051, 0xa4e8c2 left out) | 1,934 / 2,050 |

Of the 116 switch functions that differ, 115 are in the obfuscated code past 0x1000000
(SecuROM layers): jumps through stack slots (`JMP [ESP-0x10]`) and indices the C++ folds
through stack heritage and its rules, which this stage does not have (sampled with
`DECOMP_JT_RAW`). In the game code below 0x1000000 one differs: 0x7c1f30, where the C++ folds
the guard to "always the default" and the index to a constant, and then fails on the garbage
target it reads (`Unable to load 512 bytes at r0x5310ec83`); ghidra-rs recovers the 4 real
targets. 0xa4e8c2 is left out: its partial function has 780,000 ops (flow runs to the
instruction limit); ghidra-rs takes 49 s on it, the reference had not finished after 35 min.
Not ported, and why: `fail_callother` (an address made by a CALLOTHER; ghidra-rs stops with
an error: 2 functions in obfuscated code, 0x1c3c0d9 and 0x1c3c0fa), `fail_return`
(`testForReturnAddress`: the return address is on the stack, not heritaged yet), the retry of
a table whose switch looks unreachable (it needs a guard folded to a constant; it is taken as
complete), `checkUnrolledGuard`, multistage tables, overrides, `JumpAssisted`.

Table targets against `ghidra-rs analyze` (its own MSVC switch pattern, milestone 2): of the
619 jumps both find a table for, 610 have the same set of targets. The other 9 are 3 in
0xa4e8c2 (ghidra-rs reads one more entry), 2 in obfuscated code, and 4 (0x759bf4, 0x76ae9f,
0x7ed762, 0x807b95) where `analyze` has more targets and the decompiler's functions are
identical to decomp_dbg's. Of the 19 tables `analyze` finds and the decompiler does not
recover, 17 are in functions identical to decomp_dbg's (it does not recover them either) and 2
in obfuscated code; the decompiler finds 114 tables `analyze` misses.

Speed (Mall: 29,240 functions to `break start heritage`, one thread, release build): 69.7 s,
peak 652 MB, against 9.4 s and 585 MB before S3 (measured the same day on the same machine).
Of the 60 s added, 49 s is the partial function of 0xa4e8c2; the 2,115 other partial
functions take about 11 s. 29,096 functions reach the break (29,131 before): the others now
follow a recovered table into garbage code, as the reference does for most of them (see the
switch corpus above).

### Stage S4: main-loop actions without rules

Stage S4 (branch `m3-s4`) runs the universal action up to `assignhigh` with every rule and
every group that belongs to a later stage switched off, on both engines:
`tools/corpus/s4-options.txt` turns off the groups `analysis`, `cleanup`, `typerecovery`,
`stackvars`, `subvar`, `floatprecision`, `doubleload`, `doubleprecis`, `segment`,
`blockrecovery`, `localrecovery`, `switchnorm`, `returnsplit`, `splitcopy`, `splitpointer`,
`constsequence`, `bitfields`, `dynamic` and the remaining rules (`earlyremoval`, `push_multi`,
`conditionalmove`, `orpredicate`, `piecepathology`). The rule toggles must come after the group
toggles: each `option currentaction` rebuilds the root action and drops earlier `togglerule`s.
(The plan named only `analysis`, `cleanup`, `typerecovery`; with just those, rules of the other
groups still fire on the reference and structuring (`blockrecovery`) flips branches.)

```sh
BREAK=assignhigh OPTIONS=$PWD/tools/corpus/s4-options.txt rust/tools/decomp-diff.sh m8
BREAK=assignhigh OPTIONS=$PWD/tools/corpus/s4-options.txt TIMEOUT=60 rust/tools/decomp-diff.sh m500
```

Ported (`coreaction.rs`, plus `heritage.rs`, `fspec.rs`, `block.rs`, `funcdata.rs`):

- The tree (`action.rs`): every action of `universalAction` with its group; `option
  currentaction decompile <group> on|off` filters it as `ActionDatabase` does; an action not
  ported fails when it runs with its group on. Rule pools hold no rule.
- Heritage of ram (pass 1): ram is the global scope's, so its varnodes are `persist` and
  `addrtied`; guards for calls (`addrforce` on the INDIRECTs), STOREs (`indirect_store`
  INDIRECTs) and returns (a `persist` COPY before each RETURN). The stack's first pass clears
  the call placeholders (`abortSpacebaseRelative`, which also ends the 3-pass delay of the
  parameter trials). Dead code is tracked per space (`deadRemovalAllowed`, `seenDeadCode`).
- `directwrite`, `activeparam` and `activereturn` (`ParamActive`, `ParamTrial`), `returnrecovery`
  with `AncestorRealistic`, `ancestorOpUse`, `onlyOpUse` and the output `fillinMapFallback`;
  a return value or call output in two pieces gets a join varnode (`j{EDX,EAX}:8`, printed as
  the reference does) and its PIECE/SUBPIECE ops.
- `deadcode` (consume masks, `neverConsumed`, `lastChanceLoad`), the late part of
  `varnodeprops` (auto-live holds), `spacebase` with `splitUses`, `stackptrflow` (`checkClog`,
  `StackSolver`), `deindirect` (calls through an external-reference slot or to a constant
  become direct calls; `lateRestriction` only copies the callee's prototype), `redundbranch`,
  `determinedbranch`, `donothing` (with `pushMultiequals`), `likelytrash`.
- `.pspec` `<incidentalcopy>` (x87 ST0..ST7): copies there are incidental for parameter and
  return recovery. Branch and call targets are code references (`newCodeRef`: one byte,
  annotation), so heritage never links them.
- `decomp-diff.sh`: `TIMEOUT` (default 120 s per engine and function), and a reference that
  printed nothing no longer stops the summary.

| corpus | identical at `break start assignhigh` (S4 options) | at `paramdouble` |
|---|---|---|
| m8 | 8 / 8 | 8 / 8 |
| m500 | 446 / 500 | 500 / 500 |

Remaining differences, by cause:

- 53 functions: the reference splits SSE registers into lanes (`XMM0` into `XMM0_Da` ..
  `XMM0_Dd`, `ActionLaneDivide`, `subflow.cc`/`transform.cc`). It is in group `base`, so no
  option turns it off; the plan puts it in R3. Excluding these, 446 / 447 (every function the reference finishes).
- 0x4c48d0: the reference does not finish within 60 s (`TIMEOUT`), so it is not compared.
- Not ported and failing loudly when reached (no M500 function needs them): removing
  unreachable blocks, `ActionNodeJoin` and `ActionConditionalExe` (a candidate on the same
  condition varnode fails; functionally equal conditions in different varnodes are not looked
  for), `ActionUnjustifiedParams` widening (`adjustInputVarnodes`), heritage after dead-code
  removal in a processor space (needs the restart with a longer dead-code delay), removing a
  revisited marker, parameter trials of calls (calls take `__stdcall`, whose parameters live on
  the stack, and no stack varnode exists before the `stackvars` rules), a varnode consumed by
  nothing but read (`varnodeprops` zero replacement), INSERT/ZPULL/SPULL in dead code.
- `Funcdata::fillinExtrapop` is only called from `callgraph.cc` (not ported), so nothing in a
  decompile records a function's extrapop for later decompiles; `ActionStackPtrFlow` sets only
  the call sites' `effective_extrapop`. Superseded: S1b and S2 placed it in `ActionStackPtrFlow`.
- Kept from the C++ where it orders by pointer: `StackSolver::build` looks variables up with
  `lower_bound` by pointer in a list sorted by location; the port finds the varnode itself
  (the intent, and what the C++ gets while varnodes are allocated in creation order).
- Locked prototypes (plan decision 6, mercs2's `register_abi.csv`): S4 needs none of them;
  their paths (`transferLockedInput`, `commitNewInputs`, locked parameter trials, `paramdouble`
  on stack trials) are still to come.

### Stage S6: types (partial)

Stage S6 (branch `m3-s6`, partial) adds data-types to the IR. The check is `print raw` with
types at `assignhigh`: `DECOMP_RAW_EXTRA=1` makes both engines print each varnode's type after
it (`<int4>`, `<xunknown4 *>`, ...; the reference through `tools/decomp-ref.patch`), and
`tools/corpus/s6-options.txt` is the S4 option set with the `typerecovery` group back on and
its five rules (`ptraddundo`, `ptrsubundo`, `pushptr`, `structoffset0`, `ptrarith`, stage R5)
toggled off:

    DECOMP_RAW_EXTRA=1 BREAK=assignhigh OPTIONS=rust/tools/corpus/s6-options.txt rust/tools/decomp-diff.sh m500

M8 8 / 8, M500 446 / 500: identical on every function the reference finishes (499) except the 53 that use whole SSE registers and wait for `ActionLaneDivide` (R3), as in S4. Ported:

- `decomp/types.rs`: the type store (`TypeFactory`, hash-consed in an arena, so equal types are
  one id as the C++ compares pointers): the core types of `SleighArchitecture::buildCoreTypes`
  with `cacheCoreTypes`' choices (`char` over `int1`), `getBase` (unnamed `unkbyteN`, arrays of
  `xunknown1` past `max_basetype_size`), pointers, `code`, space-base types, `typeOrder`
  (`compare` with its sub-metatype order) and `printRaw`; for `parse line` also structs,
  unions, enums and typedefs.
- `decomp/infertypes.rs`: `ActionStartTypes`, `ActionInferTypes` (local types, edge
  propagation, returns, write-back, the 7-pass limit) and `ActionConstantPtr` with
  `Funcdata::spacebaseConstant`; the local types and `propagateType` of every op the rules-off
  IR has (`typeop.cc`); `TypePointer::downChain`, `TypeSpacebase::getSubType` answered from the
  global scope (functions and external references of the console's `map` commands) and the
  local scope's range; the stack pointer's locked space-base type (`Funcdata::spacebase`); the
  locked types global symbols give the ram varnodes covering them.
- `decomp/cparse.rs`: the `parse line` C declaration parser (replaces `grammar.y`): `struct`,
  `union`, `enum`, `typedef`, `extern` functions, pointers, arrays, function declarators,
  namespaces. 211 of the 232 `parse line` commands of the upstream datatests parse (unit test):
  all but
  `bitfields*.xml` (bit-fields, stage R5) and `pointersub.xml` (a relative pointer type made by
  `pointer setting`). The console's `parse line` defines types and locks prototypes (round two below).

Not ported yet (the S6 remainder): locked prototypes (`parse line extern`, `fspec.cc`'s locked
paths; so no datatest that uses `parse line` passes yet, and they also need C printing, S9),
`cast.cc` (`ActionSetCasts`, after `assignhigh`), `unionresolve`, partial structs/unions/enums
and `TypePointerRel`, `database.cc` beyond the global lookups (scopes are stand-ins), the
`.cspec`'s `<data_organization>` (struct layout uses natural alignment), function types with
prototypes. Each fails loudly where the inference would need it.

Round two (same branch, 2026-11-13):

- Locked prototypes (`locked.rs`): `parse line extern` locks the named function's prototype
  (`FuncProto::setPieces`: storage from the model by `assignAddressFallback`/`getAddrBySlot`,
  join outputs included; a hidden return pointer is not ported). Locked paths ported:
  `ActionPrototypeTypes` (locked return values on every RETURN, register parameters as locked
  inputs), `funcLinkInput`/`funcLinkOutput` (stack parameters as stack loads, register ones,
  the output varnode), `characterizeAs*`/`possibleInputParam`, `ActionDeadCode`'s consumption,
  the locked types of `TypeOpCall`/`TypeOpCallind`/`TypeOpReturn`, and `ActionConstantPtr`'s
  locked checks. A decompile starts from its function's locked prototype.
- Struct layout and `getAlignSize` from the `.cspec`'s `<data_organization>`
  (`<size_alignment_map>`; `setDefaultAlignmentMap` without one). Superseded: the natural
  alignment shortcut of the first slice.
- Check: `rust/tools/decomp-locked-options.sh <type> <file>` writes the S6 options plus a
  locked `<type> name(void)` prototype for every mercs2 function with a C name (28,495), so the
  decompiled function and its callees are locked. M8 5 / 8 with `void` and 5 / 8 with `int4` (the M500 runs had not finished at the commit).
  The misses are calls resolved by `ActionDeindirect` to a locked callee: `lateRestriction`
  (`transferLockedInput/Output`, `commitNewInputs/Outputs`) is not ported and fails loudly.
  Superseded: round three ports `lateRestriction` (M8 8 / 8 for both).
- Not reached: the D bar (`print raw` with types on the datatests using `parse line`). 58 of
  the 69 files are x86-64 (`x86:LE:64`), 8 ARM/AArch64/MIPS; the Rust decompiler is x86-32 only
  and cannot `load test file` yet. The one x86-32 file (`retstruct.xml`) also needs
  `type varnode` (dynamic symbols). So D: 0 checked.
- Still left for S6: `lateRestriction`, locked stack parameters of the decompiled function
  (they need the stack heritage pass), varargs calls to locked prototypes, hidden return
  pointers, the scopes of `database.cc` (parameter symbols, `type varnode`, the global scope
  beyond `map`), `unionresolve`, partial types and `TypePointerRel`, x86-64 and `load test
  file` for the D corpus. `cast.cc`/`ActionSetCasts` belong to S9: they run after `assignhigh`,
  so no S6 check can see them.


Round three (same branch, 2026-11-13):

- `lateres.rs`: `FuncCallSpecs::lateRestriction` for a locked prototype with
  `transferLockedInput/Output` and `commitNewInputs/Outputs` (inputs rebuilt from the trials
  that found them or as stack loads through the placeholder's pointer, `buildParam`; the
  output moved to the call from the INDIRECT that created it, `clearActiveOutput`), so
  `ActionDeindirect` resolving a call to a locked callee works.
- Bar changed (user decision, 2026-11-13): the D-corpus `parse line` check moves to the stage
  that adds x86-64 (58 of its 69 files are x86-64; the Rust decompiler is x86-32 only). S6 is
  checked with the locked-prototype stand-in instead: M8 8 / 8 and M500 at least 95% of the
  non-SSE functions the reference finishes, for both `void` and `int4`. Superseded: the
  "D files using `parse line` pass" bar of the stage table, and round two's 5 / 8 with the
  `lateRestriction` failures.
- Results: unlocked (`s6-options.txt`) M8 8 / 8, M500 446 / 446 non-SSE; locked `void`
  M8 8 / 8, M500 446 / 446 non-SSE; locked `int4` M8 8 / 8, M500 446 / 446 non-SSE; S4 regression M8 8 / 8.
- Left for a later S6b: locked stack parameters of the decompiled function (stack heritage),
  varargs and hidden-return locked prototypes, resizing an output in `commitNewOutputs` and
  truncating a trial in `buildParam`, the restart when a call cannot take a locked prototype,
  the scopes of `database.cc` (parameter symbols, `type varnode`), `unionresolve`, partial
  types and `TypePointerRel`. `cast.cc`/`ActionSetCasts` are S9.


Review fixes (same branch, 2026-11-13), after an independent review of the S6 diff:

- A locked call's first stack parameter is marked as the spacebase placeholder
  (`setSpacebasePlaceholder`, a varnode flag) instead of taking the call's placeholder slot,
  which heritage removes with `abortSpacebaseRelative`: the parameter stayed lost before.
  `getSpacebaseRelative` checks the flag. New check: `decomp-locked-options.sh int4 <file>
  "int4 a"` with `OPTIONS_SKIP_SELF=1` locks only the callees, with one stack parameter each.
- `ActionConstantPtr::isPointer` no longer needs an exact symbol hit for a constant already
  typed as a pointer; its locked-call check reads the locked parameter's metatype.
- Struct layout as `TypeStruct::assignFieldOffsets`: fields advance by their align size, the
  size is padded (`calcAlignSize`), a `void` field is an error; primitives align as
  `findAdd` (`getAlignment(getPrimitiveAlignSize(size))`); arrays are count times the element's
  align size. Sizes and counts from `parse line` are checked for overflow, and its recursion is
  bounded.
- Type propagation into a struct, union or enum pointee, or to a partial enum, fails loudly
  (`TypePointerRel`, `getTypePartialEnum` are not ported) instead of returning a wrong type.
- `commitNewOutputs`/`funcLinkOutput` mark a boolean locked output (`opMarkCalculatedBool`);
  the 7-pass limit sets `typeRecoveryExceeded`; `Funcdata::spacebase` makes its types before
  the loop; an alignment of 0 in the `.cspec` is rejected.
- The "every function locked" checks use `void name(void)` and `int4 name(void)` only (locked
  stack parameters of the decompiled function need stack heritage, S6b).
- Results (final binary): unlocked M8 8 / 8, M500 446 / 446 non-SSE; `void` M8 8 / 8, M500 446 / 446 non-SSE; `int4` M8 8 / 8,
  M500 446 / 446 non-SSE; callees with a stack parameter M8 8 / 8, M500 446 / 446 non-SSE; S4 regression M8 8 / 8.

## Speed

Measured on 2026-11-11 with a release build on a 12-thread machine (one thread used). The
input was the whole `.text` of `/usr/lib/libLLVM.so.21.1`: 97 MB, 21,830,419 instructions,
with output sent to `/dev/null`:

| run | time | instructions/s |
|---|---|---|
| `ghidra-rs disasm` | 20.7 s | about 1.05 M |
| `ghidra-rs disasm --pcode` | 82.6 s | about 264 K |
| C++ `sleigh_ref` (Ghidra's engine, text only) | 19.1 s | about 1.14 M |

## Limits

- One processor family: x86 (`x86-64.sla` and the 32-bit `x86.sla`). `analyze` takes 32-bit
  PE files only.
- Context starts from the `.pspec` defaults. Context commits (`globalset`) are recorded per
  address in the `Parse` and apply to later decodes there (flowing ones from that address on);
  the x86 specs do not use them. Delay slots, `crossbuild`, `inst_next2` and flowref/flowdest
  are not implemented.

## Verifying against the C++ engine

`tools/sleigh_ref.cc` disassembles a raw code file with Ghidra's own C++ engine and prints
in the same format as `ghidra-rs disasm` (bytes column aside). To build it:

```sh
cd rust
make -C target/sleigh-build -o xml.cc -o pcodeparse.cc -o slghparse.cc -o slghparse.hh -o slghscan.cc libsla.a
g++ -O2 -std=c++11 -Itarget/sleigh-build tools/sleigh_ref.cc target/sleigh-build/libsla.a -lz -o target/sleigh_ref
```

To compare the `.text` section of a binary:

```sh
start=$(objdump -h BIN | awk '$2==".text"{print $4}')
objcopy -O binary --only-section=.text BIN /tmp/text.raw
target/sleigh_ref ../Ghidra/Processors/x86/data/languages/x86-64.sla /tmp/text.raw $start pcode > ref.txt
target/release/ghidra-rs disasm BIN --addr $start --count 1000000000 --pcode \
  | sed -E 's/^([0-9a-f]{16})  ([0-9a-f]{2} ?)+ +/\1  /; s/^([0-9a-f]{16})  \(bad.*/\1  (bad)/; s/    <no p-code.*/    <no p-code>/' > rs.txt
diff rs.txt ref.txt
```

Results on 2026-11-11 (text and p-code identical in every case):

| binary | instructions | differing lines |
|---|---|---|
| /usr/bin/ls | 25,109 | 0 (with p-code) |
| /usr/lib/libcrypto.so.3 | 845,611 | 0 (with p-code) |
| /usr/lib/libLLVM.so.21.1 | 21,830,419 | 0 (text only) |

`sleigh_ref` uses the 64-bit context defaults for a `.sla` whose path contains `x86-64`, and
the 32-bit ones of `x86.pspec` (`addrsize=1`, `opsize=1`) otherwise. `ghidra-rs disasm` picks
`x86.sla` by itself for a 32-bit binary.

Results on 2026-11-11 with context read from the `.pspec` (Milestone 2):

| binary | sla | instructions | differing lines |
|---|---|---|---|
| /usr/bin/ls | x86-64 | 25,109 | 0 (with p-code) |
| mercs2 `Mercenaries2.analysis.exe` `.text` (linear sweep) | x86 | 2,470,185 | 4 (with p-code) |

The 4 lines are one 19-byte run of `SS` prefixes at 0xa5ddfe, longer than x86's 15-byte
limit: its displacement lies past the 16-byte instruction buffer, where the C++ engine reads
past the end of its array and ghidra-rs reads zeros.
