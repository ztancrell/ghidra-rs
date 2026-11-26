# ghidra-rs

A headless Rust reverse-engineering core that decodes machine code with Ghidra's compiled
SLEIGH specs (`.sla`). Milestone 1: load an ELF/PE/Mach-O x86-64 binary, disassemble it and
lift it to p-code. Milestone 2: function discovery on 32-bit x86 PE files, writing the same files
as the mercs2 project's Ghidra scripts ExportFunctions.java and ExportGaps.java. MIPS-1 (2026-11-26):
`disasm` also takes little-endian MIPS32, and a PSP PRX with its relocations applied (see "MIPS32
and the PSP (MIPS-1)"). MIPS-2 (2026-11-26): a PSP PRX is decoded as Allegrex, with the VFPU
("Allegrex (MIPS-2)"). MIPS-3 (2026-11-26): `analyze` takes a PSP PRX ("Function discovery on
MIPS (MIPS-3)"). See `../DESIGN.md` for the scope and plan.

## Layout

- `ghidra-rs/src/sla.rs`: reader for the compressed packed `.sla` format (version 4).
- `ghidra-rs/src/sleigh.rs`: the SLEIGH decode engine: constructor matching, context, operand
  printing and p-code templates. It ports the runtime half of Ghidra's C++ sleigh
  (`Ghidra/Features/Decompiler/src/decompile/cpp`: sleigh.cc, slghsymbol.cc, slghpattern.cc,
  slghpatexpress.cc, context.cc, semantics.cc).
- `ghidra-rs/src/analysis.rs`: PE32 loading and Ghidra-style analysis: disassembly by recursive
  descent, function discovery, switch tables, function bodies, flows and data references.
- `ghidra-rs/src/scripts.rs`: writers for the ExportFunctions and ExportGaps CSV files, plus
  RTTI vftables and (since 2026-11-20) Ghidra's Microsoft demangler, `ghidra-rs/src/mdmang.rs`.
- `ghidra-rs/src/store.rs`: the project store: a text file of edits (functions, bodies, no-return
  flags, flow overrides, thunk marks) laid over the analysis, and the script primitives that
  edit both (see "Project store and the editing scripts").
- `ghidra-rs/src/edits.rs`: mercs2's five project-editing scripts (AddRelocatedEntries,
  DefineTableFunctions, RecoverFunctions, ClearFalseNoReturn, FoldSlotFragments) on the store.
- `ghidra-rs/tests/store.rs`: edits on a fixed 32-bit blob, the store's text and its errors.
- `ghidra-rs/src/exports.rs`: mercs2's eight remaining scripts (ExportModHookOwners,
  ExportSlotOwners, InspectBoundaries, ExportCallContexts, AuditRecoveredFunctions,
  ExportLibraryEvidence, ExportBindings, ExportAbiCandidates) as `ghidra-rs export` commands
  (see "The read-only scripts"); `ghidra-rs/tests/exports.rs` runs them on a hand-made image.
- `ghidra-rs/src/main.rs`: the `ghidra-rs` CLI (binary loading via the `object` crate).
- `ghidra-rs/src/psp.rs`: the PSP PRX loader: segments, the PSP relocation sections, the
  count of every relocation by type ("MIPS32 and the PSP (MIPS-1)"); `sceModuleInfo`, the
  import stub table, the export table and the NID names ("PSP module info, imports and NID
  names (MIPS-5)").
- `ghidra-rs/tests/psp.rs`: the PSP relocation rules, and the module tables, on hand-made
  images.
- `tools/mips-ref.sh`: the MIPS-3 check: Java's auto-analysis of a PRX (through `ghidra-rs
  prx-elf` and ghidra-allegrex in a throwaway settings directory) against `analyze --purges`
  ("Function discovery on MIPS (MIPS-3)").
- `tools/mips-decomp.sh`: the MIPS-4 check: the decompiler on a PRX against `decomp_dbg`
  (through `ghidra-rs prx-xml`), on `tools/corpus/socom50.txt` or another list ("The
  decompiler on MIPS (MIPS-4)").
- `ghidra-rs/tests/decode.rs`: decodes a fixed byte sequence and checks text and p-code; a
  MIPS32 `jal` with its delay slot; an Allegrex VFPU `vdot.t` and integer `max`.
- `ghidra-rs/src/abi.rs`: port of CheckAbiCallers.java: per-byte register liveness walks
  over p-code register reads and writes.
- `ghidra-rs/tests/analysis.rs`: function discovery and both CSV writers on a fixed 32-bit blob;
  code constants (no x87 self-reference; a disguised call `PUSH next; PUSH callee; RET`); a
  code pointer hidden as two XORed dwords (`MOV EDI,[a]; XOR EDI,[b]; PUSH EDI`); a call through
  an object's vtable, resolved through a value stored via a symbolic register; whole-function
  propagation, where a vtable stored to the stack survives a call to a `RET 4` function and a
  join; ExportFunctions counting a computed call in `callees` and `callers`.
- `ghidra-rs/src/gdt/`: Ghidra's packed data-type archives (`.gdt`) read in place, read-only, and
  the import prototypes made from them (`--gdt`, `gdt-protos`).
- `ghidra-rs/src/dwarf/`: Ghidra's DWARF importer: the data types and function signatures of an
  ELF's DWARF (`ghidra-rs dwarf`; "The DWARF importer" below).
- `ghidra-rs/src/factsout.rs`: `analyze --facts`: the facts of ghidra-rs's own analysis in the
  format of `tools/ghidra/ExportFacts.java` (stage S10, slices 2 and 3), for `load facts`.
- `ghidra-rs/src/strings.rs`: Ghidra's ASCII Strings analyzer (the string search and the
  trigram model's score), for `analyze --facts` (stage S10, slice 3).
- `ghidra-rs/src/fid.rs`: Function ID: the FID hasher, a reader for Ghidra's `.fidbf`
  databases, and FID's matching and naming.
- `ghidra-rs/tests/fid.rs`: the FID hash of a known CRT function, and its record in Ghidra's
  databases (skipped when they are not installed).
- `ghidra-rs/src/mdmang.rs`: Ghidra's Microsoft demangler (`MDMang`) and the name parts of
  `MicrosoftDemangler` ("The Microsoft demangler").
- `ghidra-rs/tests/mdmang.rs`, `tests/data/mdmang-vectors.tsv`: MDMangBaseTest's vectors,
  extracted by `tools/mdmang-vectors.sh`.
- `ghidra-rs/src/gnudemangle.rs`, `ghidra-rs/src/gnuparse.rs`: Ghidra's GNU (Itanium C++ ABI)
  demangler, its native half (libiberty's `cp-demangle.c` 2.41) and `GnuDemanglerParser` ("The
  GNU demangler"); `tools/gnu-syms.sh` and `tools/ghidra/GnuParseDump.java` check them.
- `ghidra-rs/tests/abi.rs`: register reads and writes (sub-registers as base-register bytes)
  of a few fixed instructions.
- `build-sla.sh`: builds Ghidra's SLEIGH compiler and compiles `x86-64.sla`, `x86.sla`,
  MIPS's `mips32le.sla` and the PSP's `allegrex.sla`.
- `processors/Allegrex/`: the Allegrex (PSP) SLEIGH spec of ghidra-allegrex, copied unmodified
  (`data/languages`), with its `LICENSE` (Apache 2.0) and a `NOTICE` naming the source commit
  ("Allegrex (MIPS-2)").
- `psp-nids/`: PSP NID names extracted from PSPSDK (`pspsdk-nids.txt`), with its `LICENSE`
  (BSD) and a `NOTICE` naming the source commit and the extraction ("PSP module info, imports
  and NID names (MIPS-5)").
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
  fixups and executable scripts: the p-code snippet parser), `userop.rs` (the `<segmentop>` and
  `<jumpassist>` user ops),
  `funcdata.rs` (`Funcdata`: op/varnode arenas, readers and the location-sorted varnode set,
  op insertion and input/output edits, stack loads), `op.rs`,
  `varnode.rs`, `readers.rs` (a varnode's reader list, up to 4 inline), `opcode.rs` (opcodes and their `print raw` names), `flow.rs` (`FlowInfo`,
  call-fixup injection), `block.rs` (basic blocks, spanning tree, dominators), `actiontree.rs`
  (the action framework: groups, repeat, breakpoints, `continue`), `heritage.rs` (SSA: phi
  placement and renaming), `action.rs` (the universal
  action up to `paramdouble`), `print.rs` (`print raw`), `stdsort.rs` (libstdc++'s `std::sort` and `std::list::sort`), `rangemap.rs` (the
  `rangemap` template the scopes' maps use), `scope.rs` (symbols, default names), `namevars.rs`
  (`ActionNameVars`), and `print C` in three layers: `prettyprint.rs` (`EmitPrettyPrint`: tokens,
  line breaking, indents), `printlanguage.rs` (the operator stack, parentheses, number base) and
  `printc.rs` (`PrintC`: declarations, blocks, statements; first slice).
  See "Decompiler (Milestone 3)" below.
- `ghidra-rs/tests/decomp.rs`, `tests/data/raw-funclink-*.txt`, `tests/data/raw-heritage-40a110.txt`,
  `tests/data/raw-paramdouble-40ad80.txt` (S2: a loop at `paramdouble`):
  `print raw` at `funclink` and `heritage` against the reference's output, for mercs2's 0x40a110
  (rebuilt from its bytes) and for `INTO; RET` (a relative branch to the end of its own
  instruction). Unit tests in `decomp/action.rs` (`tests/data/raw-heritage-onexit.txt`: mercs2's
  `__onexit` with two call fixups, external references and read-only propagation; read-only
  reads becoming constants) and `decomp/inject.rs` (the snippet parser).
- `tools/rangemap_ref.cc`: the C++ `rangemap` template on the data of the unit tests of
  `decomp/rangemap.rs` (multiset order, record order, `find`).
- `tools/stdsort_ref.cc`, `ghidra-rs/tests/data/stdsort-gxx.txt`: libstdc++ `std::sort` and `std::list::sort` tie orders
  that `decomp/stdsort.rs` must reproduce.
- `tools/decomp-ref.sh`, `tools/decomp-ref.patch`: build the reference decompiler `decomp_dbg`.
- `tools/decomp-diff.sh`: runs a corpus on both decompilers and compares; `tools/decomp-show.sh`,
  `tools/decomp-rank.sh`, `tools/decomp-bisect.sh`: the S2 debugging tools (verbose diff,
  easy-first order, first differing step; see "Debugging tools").
- `tools/hatred-java-run.sh`: Java 12.3 on Hatred in one headless run, the facts and the C of a
  function list ("Java's C of Hatred, for the full decompile comparison").
- `tools/ghidra-diff.sh`, `tools/ghidra/DecompileRef.java`: the stage S10 check, `print C` against
  the C of Java Ghidra (see "Stage S10").
- `tools/ghidra-facts.sh`, `tools/ghidra/ExportFacts.java`: the facts of the Java project for
  `load facts` (see "Stage S10, slice 1").
- `tools/mercs2-exports.sh`: the four Java-identical `export` commands as a drop-in for mercs2's
  Java scripts, with a `--compare` mode (see "Switching mercs2's export scripts").
- `tools/decomp-corpus.sh`, `tools/corpus/m8.txt`, `tools/corpus/m500.txt`: the mercs2 corpora.

## Build

Needs Rust (stable), and g++, make and zlib headers for the SLEIGH compiler.

```sh
cd rust
./build-sla.sh             # once, and again whenever the x86, MIPS or Allegrex .slaspec/.sinc files change
cargo build --release
cargo test --release
```

### The .sla file

`build-sla.sh` copies the C++ sources from `Ghidra/Features/Decompiler/src/decompile/cpp`
into `rust/target/sleigh-build`, builds the `sleigh_opt` target there (using the checked-in
bison/flex outputs, so the upstream tree is not touched) and runs, for `x86-64`, `x86`,
`mips32le` (in `Ghidra/Processors/MIPS/data/languages`; 166 KB) and `allegrex` (in
`rust/processors/Allegrex/data/languages`; 68 KB):

```sh
sleigh_opt Ghidra/Processors/x86/data/languages/x86-64.slaspec \
           Ghidra/Processors/x86/data/languages/x86-64.sla
```

The output (about 500 KB each for x86) lands next to its `.slaspec`, where Ghidra itself keeps
it. Upstream gitignores `*.sla`, so it is not committed. The file is `"sla"`, a version byte (4), then a zlib stream holding
Ghidra's "packed" element/attribute encoding (`slaformat.cc`, `PackedDecode` in
`marshal.cc`).

`ghidra-rs` finds the `.sla` at that path by default (`x86.sla` for 32-bit binaries,
`x86-64.sla` otherwise). Override it with `--sla <file>` or the `GHIDRA_RS_SLA` environment
variable. The context defaults (`addrsize`, `opsize`, ...) come from the `<context_set>` of the
`.pspec` with the same name next to the `.sla`. A language whose `.pspec` has another name (the
16-bit x86 languages on `x86.sla`) is loaded with `Sleigh::load_with_pspec`; no command line
option selects one yet. A little-endian MIPS binary gets `mips32le.sla` with `mips32.pspec`
(the language `MIPS:LE:32:default` of `mips.ldefs`), unless it is a PSP PRX: that gets
`allegrex.sla` with `allegrex.pspec` ("Allegrex (MIPS-2)"). With `--sla` or `GHIDRA_RS_SLA` a
MIPS file gets the `.pspec` named after the given `.sla` when there is one, `mips32.pspec` next
to it otherwise.

## Usage

```sh
ghidra-rs disasm <binary|psp-prx> [--func <symbol>|--addr <hex>] [--count N] [--pcode] [--sla <file>]
```

The binary is an ELF, PE or Mach-O file for x86-64 or 32-bit x86, a little-endian MIPS32 ELF,
or a PSP PRX (loaded at 0x08804000 with its relocations applied; addresses are loaded
addresses, a line on stderr counts the relocations, and `--func` is refused). For a PRX a
second line on stderr describes the module, a `<name>:` line precedes each import stub and
exported function, and a `j` or `jal` to one ends in `  ; <name>` ("PSP module info, imports
and NID names (MIPS-5)"). No other file gets names in `disasm`.

- `--func`: start at a symbol (static, dynamic or PE export; a leading `_` is optional for
  Mach-O) and, if the symbol has a size, stop at its end.
- `--addr`: start at a virtual address (hex, `0x` optional).
- Without either, it starts at the entry point.
- `--count`: maximum number of instructions (default 20, or the whole symbol with `--func`).
  The sweep also stops at the end of the containing section.
- `--pcode`: print the p-code ops under each instruction.

Output is `address  bytes  MNEMONIC operands` in Ghidra's spelling. Bytes Ghidra's spec
cannot decode print as `(bad: ...)`, and the sweep moves on one byte (on MIPS: the whole
4-byte word).

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
ghidra-rs analyze <pe32|elf64|psp-prx> [--functions <csv>] [--gaps <csv>] [--purges <txt>] [--abi-callers <register_abi.csv> <out.csv> [--data-pointers]]
                         [--decomp-prelude <out>] [--facts <out> [--protos <file>]] [--seeds <csv> | --functions-from <csv>]... [--store <file>] [--sla <file>]
```

`--facts` is stage S10, slices 2 and 3 (below): the facts `load facts` reads, from this
analysis. It reads the strings model `Features/Base/data/stringngrams/StringModel.sng` of the
Ghidra tree the `.sla` file is in, and fails without it.

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

- the order: Ghidra's task queue (`queue.rs`, a port of `AutoAnalysisManager`,
  `AnalysisTaskList`, `AnalysisScheduler` and `AnalysisPriority`; no background commands yet).
  A change notifies the analyzers of its type (blocks, code, functions, data), each queues one
  task at its priority, and the first task of the lowest priority runs next. Discovery's
  analyzers in it: Disassemble Entry Points (200, the seeds), Function Start Search (402),
  Function Start Search After Data (898, after the tables), Create Address Tables (899), X86
  Function Callee Purge (500, on each batch of new functions), jumps through a pointer and
  their thunks (596, see "Plain discovery's silents" below) and Shared Return Calls (398, on
  each batch, as Java; superseded (2026-11-19): a last task at 10000 on all functions). The non-returning
  functions run after the queue (Java: 302). Without the purge analyzer the facts are byte for
  byte the ones of the loop it replaces (both function sets, 2026-11-18); with it see "Ghidra's
  task queue and the purge" below;
- disassembles every executable section by recursive descent from the exports, the entry
  point and RTTI vftable slots (MSVC CompleteObjectLocator -> TypeDescriptor); call targets
  become functions;
- Function Start Search: the definite `x86win_patterns.xml` prologue pairs (`CC`/`90`/`C3`/
  `C9 C3`/`C2 nn 00` or `JMP` before a prologue) in bytes no code covers yet; a pair counts only
  with Ghidra's `totalbits="32" postbits="16"` (PatternPairSet: 16 fixed bits after, 32 in all),
  so `CC` + `SUB ESP,small` (8 + 19 bits) is no start while `CC CC` + it is. Superseded
  (2026-11-18): every pair counted;
- switch tables `JMP [reg*4 + table]`, bounded by a preceding `CMP reg,imm` (else up to 1024
  entries while they point at code in the jump's own section); in a two-level switch
  (`MOVZX reg,byte ptr [idx + bytetable]` between them) the CMP bounds the byte table and the
  jump table has as many entries as its largest byte plus one;
- Create Address Tables: runs of 2+ code pointers in data are disassembled, without making
  functions;
- Shared Return Calls with contiguous functions (`Analysis::shared_returns`, a port of
  SharedReturnAnalysisCmd's walk): the jump scan set is built per function as Java's
  `checkAboveFunction`/`checkBelowFunction` build it, the sources are walked in address order
  with Java's cached "function after / before the source" (whose staleness decides some
  targets), and a target becomes a function when an unconditional jump passes the next
  function entry or goes before the previous one, no conditional flow reaches it, no
  instruction falls into it (a call counts, as `getFallFrom`) and it is not a lone return. The
  functions are made after the walk by CreateFunctionCmd (the body-from-creation path), and
  the analyzer runs, as Java's FUNCTION_ANALYZER at 398, on each batch of functions added or
  with a body set; the functions it walks over are the ones with a body. The CALL_RETURN
  overrides it sets on jumps to a function (`processFunctionJumpReferences`) stay derived
  (`call_return`, at any time, not from the moment the analyzer runs). Superseded (2026-11-19):
  one walk over every function discovery made, after all other analyzers. Superseded (2026-11-17): every unconditional jump past the next entry or before the
  previous one made its target a function, a call did not count as falling into a target, and a
  lone return could become a function;
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

With the Shared Return port (2026-11-17) plain discovery has 22,386 common, 937 missing and
329 extra functions (`.text`, against `functions-analysis.csv`); the other columns were not
measured again. Of the 329 extra, 153 are call targets, 98 Function Start Search hits, 76
Shared Return targets and 2 seeds; 71 of the 98 and 45 of the 153 are functions of the final
Java project (made there by RecoverFunctions). Superseded: 22,388 / 935 / 365 (112 of them
Shared Return targets). Note that `functions-analysis.csv` (2026-10-14) was made by Ghidra
12.1.2_DEV (`/opt/ghidra` is 12.2), the source here is 12.3. Superseded: "made by Ghidra 12.2",
the README's earlier statement; see the 12.2 trace under "Against Java" below.

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
  and the other compiler helpers, added to `scripts::demangle`). Superseded (2026-11-20):
  `scripts::demangle` is the ported Microsoft demangler's applied name ("The Microsoft
  demangler" below).

Not ported: the demangled-name variants of MatchNameAnalysis (`demangledNoTemplate`,
`demangledBaseName`), removing a conflicting label when a later function matches it alone,
thunks, and the library names in plate comments and bookmarks. Superseded (2026-11-20): the
demangled-name variants are ported ("The Microsoft demangler").

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
  Superseded in part (2026-11-17, "Stage S10, slice 3"): an address table an instruction
  refers to becomes pointers and is not disassembled (`createFlowTable`); a code constant is
  followed only where nothing reads or writes it, the instruction is no jump or call and
  does not compute with it; `isValidSubroutine` also has `checkPseudoBody` (no defined data in
  the flow, no reference into the middle of an instruction, and for a code constant no
  reference to the flow but to its entry); the entries of an address table are disassembled
  where each is an instruction start or `isValidCode`, not wherever all lie in an executable
  section. So "Not modelled: Ghidra's defined data" above now leaves out pointers. The shadow
  check after it: same 56,003, differ 60, Java only 152, ghidra-rs only 819 (before: 55,996,
  61, 158, 873).
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
`../DESIGN.md`). It has a row for every row of the shadow run of 2026-11-20 (ghidra-rs
b6b02b2ca5, the script's command and diff reproduced outside the mercs2 tree, against mercs2's
`config/abi_callers.csv` and `config/register_abi.csv` of 2026-11-18 14:43): same 56,099,
differ 124, Java only 152, ghidra-rs only 800, so 1,076 diff rows. 200 of them were judged
before, with the same statuses on both sides (none changed); 76 differ / Java-only rows and the
800 ghidra-rs-only rows are new. 32 older rows no longer differ and stay as history. The
columns are `address,site,java,ghidra_rs` (from the diff), `truth` (`ok`, `violation`,
`unknown`, `not-a-caller`, `trivial`, or `unverified` for a row grouped but not checked by
itself), `evidence` (the bytes or reasoning behind the truth, or `group:<cause>; checked
<site>` naming a checked row of the group) and `cause` (a kebab-case group). `trivial` means
the original's own code (through its entry JMP) writes every clobber, the rule both tools
apply; it is not a path-by-path proof. mercs2's abi_test callee trace (`build/abi_callees.csv`)
lists 19 contracts and their callees but no call sites, so it settles no row: every truth comes
from the disassembly and the contracts. (Superseded: the first ledger, of the run at ghidra-rs
bd56d2f09a against mercs2 395ba6b, had the 58 differ and 174 Java-only rows; same 55,362,
ghidra-rs only 309, not in the ledger then.)

Against the bar (no row where ghidra-rs is wrong on the unsafe side), as of that run:

- No row has truth `violation` where ghidra-rs says `ok`, `trivial` or `(none)`.
- 39 site rows are true callers ghidra-rs has no row for (`missed-code-undecoded` 16,
  `data-pointer-missed` 19, `missed-ref-securom-section` 4; truth `ok` 19, `unknown` 8,
  `unverified` 12). The bar counts a missing true caller as unsafe, so it is not met yet.
- Not settled: 92 rows where ghidra-rs gives no finding or `ok` and the truth is `unknown` or
  `unverified` (38 + 16 `output:`/`input:` rows, 10 "no references" rows, 5 + 23 `ok` sites).
- The 52 `rs-body-lacks-jump-target` rows (0x407aa0, 0x430e40, 0x470be0, 0x4cc830: Java
  `trivial`, ghidra-rs walks the callers) and the 16 `rs-body-has-callee-code` rows (0x470600:
  ghidra-rs `trivial`, right in effect) come from function bodies that differ: ghidra-rs gives
  the code behind an entry JMP (0x6b8f60, 0x4063c0, 0x403f00, 0x527020) to another function or
  to none, where Ghidra gives it to the JMP's function. Safe in all 68 rows; a body that takes
  a callee's code could make `trivial` too loose elsewhere.
- The 703 `rs-only-stricter` rows (626 `unconcluded`, 72 `unknown`, 5 `violation`) are findings
  Java does not make: the safe side whatever the truth, not checked one by one.

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

## Project store and the editing scripts

```sh
ghidra-rs edit <pe32> --store <file> [--new-store] [--seeds <csv> | --functions-from <csv>]... [--sla <file>] <command>
ghidra-rs analyze <pe32> ... --store <file>
```

The project store keeps a project's edits on top of ghidra-rs's own analysis, so mercs2's five
project-editing Ghidra scripts run without a Java Ghidra project. It follows DESIGN.md's
decision of 2026-11-15: plain text in the project's repo, and every run starts from scratch
(load, analyse) and then applies the file. Nothing is reloaded while running. Code:
`ghidra-rs/src/store.rs` (the format, `Store::apply`, and `Project`, the script primitives),
`ghidra-rs/src/edits.rs` (the five scripts), `ghidra-rs/tests/store.rs`.

### The file

One file, one record per line, fields separated by one space, addresses as `0x%08x`. The
first line names what the store was made on: FNV-1a 64 hashes of the binary's bytes and of
the seed set (a byte for `--functions-from`, then the `--seeds`/`--functions-from` entries
sorted without repeats). The records that change what disassembly decodes or reads (`clear`,
`noreturn`, `code`, `switch`, `override`) follow in the order the edits made them, since
replaying them in another order gives another program ("code, then a clear inside what it
decoded"; "code decoded behind a call, then the callee's no-return flag cleared"). The
records that only set the final state (`function`, `body`, `thunk`) come last, sorted by
address within a kind. A command appends to the first part and rewrites the second, so a
change is still a small diff. `Store::apply` replays the file from top to bottom.

```text
ghidra-rs-store 2 binary 0x<16 hex> seeds 0x<16 hex>
clear <first>-<last>               instructions overlapping the range are removed
noreturn <addr> on|off             the no-return flag of a function (or import slot)
switch <jump> <target>...          the targets of a computed jump
code <addr>                        disassemble from here (flow is followed)
override <addr> call_returnreflow <entry>                     fixupFunctionBody: the body is the flow from the entry again
|none   the flow override of an instruction
function <entry> create|remove     a function analysis lacks, or one it has
body <entry> <first>-<last>...     a fixed body in place of the flow from the entry
thunk <entry> off|<target>         the function is (not) a thunk
```

Superseded (2026-11-17, review of `m3-int6`): version 1 (first line `ghidra-rs-store 1`) wrote
every kind sorted by address and applied all `clear`, then all `noreturn`, then all `code`
records, which lost the order of the edits; it named no binary or seed set. Version 1 files
are refused; make them again with `edit --new-store`.

`analyze --store` follows Java's order: discovery and the constants pass (`disassemble` with
constants, which Ghidra's auto-analysis runs before any script), then the store, and the
bodies computed after both; only then the `--abi-callers` contract entries and the
`--facts` passes, so `--functions`, `--gaps`, `--abi-callers`, `--facts` and
`--decomp-prelude` (the decompiler's function list) all see the edited program. `edit` proves
its store on the same base (discovery and the constants pass). Superseded: the store was
applied right after discovery and the constants pass of `--abi-callers` and `--facts` ran
after it, on a program `edit` never proved the store on. Bodies are computed again from the
flow at the end, so a function re-flows whenever a neighbour is created or removed or a flag
changes; only a `body` record pins one, and `edit reflow <addr>` drops that record.
Removing a function re-flows no other body, as Java's FunctionManagerDB.removeFunction (it
deletes the function only); a script that fixes up a neighbour does so itself
(`fold-slot-fragments` re-bodies the owners that jump into a fragment it removes:
`fixupFunctionBody` or `setBody`). `edit reflow` and a script's fixup write a `reflow` record,
so `Store::apply` re-flows the same bodies; `ghidra-rs/tests/store.rs`
(`removing_a_function_leaves_what_falls_into_it`). Superseded (2026-11-20, review of `int8`):
`Project::remove_function` re-flowed the bodies that jump or fall into the removed function and
`Store::apply` copied it for every `function ... remove` record; before that only bodies holding
a record's address were re-flowed, and `fold-slot-fragments` on mercs2 failed with "the store
does not reproduce the edits ... 0x00416c5d".

What fails instead of being skipped: a first line other than version 2's, a store made on
another binary or seed set (`analyze --store` and `edit` both check; note that
`--abi-callers` adds the targets of `securom_functions.csv` to the seeds, so its store must be
made with those seeds too), an unknown record, a malformed address or range, an ordered record
after the `function`/`body`/`thunk` records, two `function`, `body` or `thunk` records for one
address, a `code`, `function`, `switch` or `override` address where no instruction decodes
when its turn comes, a `body` or `thunk` of an address that is no function. There are no comment lines: a command rewrites the whole
file and would drop them.

### What ghidra-rs derives, and what the store overrides

This analysis keeps less state than a Ghidra project, so three things the scripts read are
derived, and the store holds only the exceptions:

- Flow overrides (`Analysis::call_return`): a call of a no-return function and an
  unconditional jump to a function entry count as CALL_RETURN (Ghidra's no-return and
  shared-return analyzers set those). `override ... none` cancels one, `call_return` adds one.
  `--abi-callers` reads the same answer.
- Thunks (`Project::thunked`): a body of one jump to a function, or through an import slot.
  `thunk ... off` cancels that. Only the editing commands read thunk marks.
- Bodies: the flow from the entry up to other function entries. Two functions can share
  instructions (Ghidra's bodies never overlap); "the function containing an address" is the
  function starting there, else the lowest entry.

Not kept at all: defined data (only the slots of address tables count as data), fall-through
overrides, references made by hand.

### Commands

| Command | Script | What it does |
|---|---|---|
| `add-relocated-entries <securom_functions.csv>` | AddRelocatedEntries.java | a function at each entry (first column) that lies in none |
| `define-table-functions <start> <end>...` | DefineTableFunctions.java | a function at every `.text` pointer of the data ranges that lies in none |
| `recover-functions <audit.csv>` | RecoverFunctions.java | functions from pointer runs in `.rdata`/`.data` and direct calls; same audit CSV |
| `clear-false-noreturn <report.csv>` | ClearFalseNoReturn.java | clears no-return where a RET is reached without a call, decodes behind the calls, to a fixpoint |
| `fold-slot-fragments <functions-original.csv> <slot-rewrites.csv> <report.csv>` | FoldSlotFragments.java | folds wrapper-exit fragments into their owners |
| `create-function <addr>`, `remove-function <addr>`, `reflow <addr>` | | single edits |
| `export-bindings <out.csv> --recover` | ExportBindings.java `--recover` | the bindings CSV, and a function at each table target that lies in none |
| `audit-recovered-functions <recovery.csv> <audit.csv> --remove-empty` | AuditRecoveredFunctions.java `--remove-empty` | the audit CSV; a one-byte function without an instruction is removed |

A missing store file is an error; `edit --new-store` makes a new one (and refuses a file that
is there), so a mistyped `--store` path cannot start an empty store unnoticed. Superseded: a
store file that was not there started empty. Each command analyses, applies the store, runs,
and then proves the result: `Project::finish` applies the new store to the untouched analysis
and compares instructions, functions, no-return flags, switch targets and bodies with what
the command left. Any difference is an error and nothing is written. The store is written to
`<file>.part` and then renamed over `<file>`, so a failed write leaves the old store whole.

Superseded: "Not ported, failing by name before anything is loaded: `export-bindings`
(ExportBindings.java `--recover`) and `audit-recovered-functions` (AuditRecoveredFunctions.java
`--remove-empty`)". Both are commands now (`exports.rs`, the last two rows above; without
their option they are read-only and belong to `ghidra-rs export`, see "The read-only scripts").
Inside the ports, loud rather than guessed: a `fold-slot-fragments` switch whose jump has an
8-bit table displacement or a prefix other than a CS, DS, ES or SS override (`not ported:
...`), and a pointer or table word outside the image (Java throws there too). The
`fold-slot-fragments` switch guard is read from the decoded instruction (`CMP <index
register>,<scalar>`, any encoding, as Java's `getRegister(0)` and `getScalar(1)`); a jump
`[base + index*4 + table]` takes the index, as Java takes the last register of the operand.
Superseded: the guard was matched on the bytes `83 /7`, `81 /7` and `3D` only (those are all
the encodings of a 32-bit register compare without a prefix), and a base register failed.
Addresses in the CSVs and arguments read as Java's `Long.decode` (sign, `0x`/`0X`/`#` hex,
leading-`0` octal, decimal) and fields as `String.split(",")` (empty fields at the end
dropped). Superseded: octal and `#` read as decimal or failed, and a trailing comma failed.

Where a port cannot do what Java does:

- Java makes a function of one undefined byte where nothing decodes. Here `create_function`
  refuses; `add-relocated-entries` and `define-table-functions` print the address on stderr,
  go on, and count those in their summary line ("... not created where Java makes a one-byte
  function"), `recover-functions` reports `no_entry_instruction` (it also stands for Java's
  `disassembly_failed`, which Java tells apart by a return value that is true either way).
- `recover-functions` reports `defined_data` only for address-table slots.
- `clear-false-noreturn` has no defined data to clear and no fall-through overrides; the
  cleared item's text is ghidra-rs's disassembly; names are export names or `FUN_<addr>`.
- `fold-slot-fragments`: `setBody` fails as Java's OverlappingFunctionException ("refit
  failed Unable to create function at ... due to overlap with range [...]", the old body
  kept), but only for the instructions the body gains: bodies the flow derives here may share
  instructions, where Java's never do. The range named is the first such instruction, which
  may not be the one Java names. A disassembly here re-flows the bodies that flow into it, so "refit
  before->after" compares with the body at the start of the round (Java's body until
  `setBody`). An owner that its own walk removes ends the command with an error, as Java's
  next call on the deleted function throws. Superseded: `setBody` could not fail, and such an
  owner was skipped.

### Against Java (Mercenaries2.analysis.exe, 2026-11-17)

Run in the order of mercs2's `analysis_pipeline.sh` on a fresh store, from plain discovery
(no `--functions-from`); Java's outputs are `mercs2-decomp/build/*.csv` (2026-10-14) and the
project's facts export (`rust/target/ghidra-ref/mercs2.facts`, 2026-11-17). Java ran
ExportBindings `--recover` and AuditRecoveredFunctions `--remove-empty` in between; here they
are not ported.

| Command | Java | ghidra-rs |
|---|---|---|
| `recover-functions` | 15938 created, 36302 examined | 16150 created, 36909 examined; 15823 created by both, 115 by Java only, 327 here only |
| `fold-slot-fragments` | 2204 removed, 1438 refit, 2 rounds | 2172 removed, 1423 refit, 2 rounds; removed by both 2140 (64 Java only, 32 here only); refit by both 1411, 1237 with the same sizes |
| `add-relocated-entries` | not in mercs2's logs | 43 added |
| `clear-false-noreturn` | not in mercs2's logs (its last report: 25 kept) | 3 cleared, 2 call sites, 608 kept |
| `define-table-functions 0xd16bf0 0xd16d20 0xd17000 0xd1b000` | not saved (a read-only pre-script) | 66 defined |

Java's three `switch` rows of the fold report have no counterpart: ghidra-rs's own switch
recovery already has those jumps' targets. ghidra-rs flags far more functions no-return than
Ghidra (every body without a return); 0x00401740, the one the Java script was written for, is
not flagged here. Superseded (2026-11-20): the no-return rule is now FindNoReturnFunctionsAnalyzer's call-site evidence (see "No-return functions from call-site evidence"); the no-return flag of functions in both plain discovery and Java 12.2 differs in 14 where it did in 52.

The function set in `.text` against the Java project's facts (37635 functions):

| | in both | same body size | Java only | ghidra-rs only |
|---|---|---|---|---|
| plain `analyze` | 20422 | 18663 | 17213 | 2331 |
| with the store, after the four pipeline commands | 36602 | 36178 | 1033 | 180 |

The store after those four commands: 23128 records (18365 `function`, 2471 `override`,
1434 `body`, 812 `thunk`, 43 `code`, 3 `noreturn`; 696 KB). An `edit` run takes 20 to 30 s of CPU on the
shared desktop (the analysis, the command, the store applied twice; about 1.8 GB at the peak);
`clear-false-noreturn` took 115 s of CPU.

Superseded (2026-11-17, review of `m3-int6`): the tables above are from before the review
fixes (store version 1, edits on discovery without the constants pass, `fold-slot-fragments`
skipping an owner its own walk removed); rerun with that build, the four commands give the
same 36602 / 1033 / 180. With the fixes, `fold-slot-fragments` stops on mercs2 with
"FoldSlotFragments: the walk from 0x00861190 removed that owner itself": 0x861190 is a
function in ghidra-rs's discovery (reached by jumps only) and an owner of a rewritten site,
where Java has no function there (not in its facts export, its original functions or its fold
report); the old build removed it in the same way and went on. The pipeline with the
fixes is therefore not comparable yet. Without `fold-slot-fragments` (`recover-functions`,
`add-relocated-entries`, `clear-false-noreturn`), the `.text` functions in both / Java only /
ghidra-rs only are 36864 / 771 / 2338 with the fixes against 36610 / 1025 / 2336 with the old
build: `recover-functions` creates 16406 (16150 before) once it runs after the constants pass.
The fixed store is 16488 lines (16449 `function`, 35 `code`, 3 `noreturn`).

With the Shared Return port (2026-11-17) `fold-slot-fragments` stopped at 0x00861190 (superseded: see "Resolved" below); the
three other commands give 36861 / 774 / 2314 (`recover-functions` creates 16417, the store has
16498 records). Why 0x861190 is still made: 0x8614c7 (`JMP 0x861190`, in 0x8613d0) jumps back
before 0x8613d0; nothing falls into 0x861190 (0x861183-0x86118f is INT3 padding), no
conditional flow reaches it, and 0x8613d0's body has more than one range (it runs on through
0x861190, 0x5110f1 and 0x86119a), so every scan set with 0x8613d0 in it holds the jump. In
Java's plain analysis (`functions-analysis.csv`) 0x5110f1 and 0x86119a are Shared Return
functions and 0x8613d0's body (260 bytes) holds 0x861190-0x861197, but 0x861190 is no function.
Walking SharedReturnAnalysisCmd by hand (also with the cache stale, and with
CreateFunctionCmd's queue and `subtractBodyFromExisting`) creates 0x861190 in every order tried,
so the rule that leaves it out is not found; seeding discovery with all of Java's plain
functions still creates it. Not found, and not needed: see "Resolved" below.

Resolved (2026-11-18): `fold-slot-fragments` no longer stops at 0x00861190. A fresh headless
Ghidra 12.2_DEV run (`rust/tools/ghidra/TraceFunctions.java` logs the analyzers' calls) does
create 0x861190 (a queued CreateFunctionCmd makes it and nothing removes it), so ghidra-rs's
discovery agreeing with Java there was right. `functions-analysis.csv` (2026-10-14) is from Ghidra
12.1.2_DEV, not 12.2, and the 12.2 chain differs: RecoverFunctions 15,938 created,
FoldSlotFragments 2,183 removed and 1,438 refit (12.1.2: 2,204 / 1,438), ClearFalseNoReturn 1
cleared (458 call sites). Plain discovery against that 12.2 trace is 22,390 / 899 / 325 in both /
Java only / ghidra-rs only (against the 12.1.2 CSV 22,386 / 937 / 329). Java 12.2's
FoldSlotFragments removes 0x861190 as an owner of its own walk, writes `0x00861190,removed` and
then `0x00861190,refit failed Object has been deleted.` (the setBody call throws into the script's
catch), and goes on. `fold-slot-fragments` does the same now. The four commands on a fresh store
give: `recover-functions` 16,417 created, `add-relocated-entries` 43, `clear-false-noreturn` 3
cleared (2 call sites; 12.2: 1 cleared, 458 call sites, not explained), `fold-slot-fragments` 2,163
removed, 1,425 refit, 1 refit failed (0x00861190), 2 rounds; the store has 23,398 records. Against
Java 12.2 that is 2,163 against 2,183 removed and 1,425 against 1,438 refit. The final `.text`
function set against the facts export (from the 12.1.2-era project) is 36,856 in both, 779 Java only,
164 ghidra-rs only (36,602 / 1,033 / 180 before the review fixes). Superseded: the text before this
note, which says the fold stops and the rule that leaves 0x861190 out is not found; there is no such rule.

Causes of the plain-discovery differences (2026-11-18). `rust/tools/ghidra/TraceCreators.java`
(pre-script: the analyzer step after or in which each function was made, from the program's
function events; 888 s headless, against about 7 hours for TraceFunctions.java) and
`DumpAddressFacts.java` (post-script: function, instruction, byte before and references at listed
addresses) explain the 899 Java only and 325 ghidra-rs only of the 12.2 trace. Java only: 319 made
after Subroutine References (call targets in code ghidra-rs never decodes), 297 after Reference
(Function Start Search's delayed creator: `<possiblefuncstart after="defined"/>`, `PUSH reg : MOV
reg,[ESP+n]` after filler, at code only a pointer in data or a code constant names, e.g. vtable slot
0xba8a64 -> 0x4129b0 and `MOV ECX,0x4036e0` at 0x402f15), 124 after Function Start Search After
Code, 112 after Shared Return Calls, 27 after Call-Fixup Installer, 15 after Decompiler Switch
Analysis, 4 after Non-Returning Functions - Discovered, 1 in Reference; 864 of them lie in bytes
ghidra-rs never disassembles. ghidra-rs only: 191 where Java has no instruction and no reference,
78 instructions with only DATA references, 49 jump targets, 7 others. Fixed: the pattern-pair bit
threshold (above), 22,358 / 931 / 222 in both / Java only / ghidra-rs only (the 32 new Java only
are call targets Java reaches from code ghidra-rs does not decode yet; they had been found through
`CC` + `SUB ESP`). Not fixed: porting Function Start Search After Code with its delayed creator
over the code the constants pass reaches gave 22,389 / 900 / 272 and made none of the 297, because
the constants pass does not disassemble those targets (0x4036e0, 0x4129b0); that pass comes first.
Superseded: 22,390 / 899 / 325 as the current plain-discovery count. With the fix, own plain facts
(`analyze --protos --facts`, 71 s) against Java: M500 identical 177 / 499 (loud 128, silent 194;
before 177, 122, 200), M8 identical 2 / 7 (loud 2, silent 3, as before). The shadow check's command
(`--functions-from build/functions.csv --abi-callers`) writes 56,888 lines, against 56,918 from
the main checkout's binary of 2026-11-18 11:42 (its commit not recorded); the difference is not
examined.

Not compared: flow overrides against the 3365 of the facts export (ghidra-rs derives them and
has no export of them), functions outside `.text`, body ranges beyond their size. The shadow
check (`mercs2-decomp/tools/ghidra-rs-shadow.sh`: `analyze --functions-from ... --abi-callers`
without a store) writes the same 56966 lines as before this change.

### With the facts of a project

The store is not the facts format (`load facts`, another branch): facts are the answers a
program gives the decompiler, the store is only what a person or a script changed. They
combine in one direction: a facts producer in `analysis` reads the `Analysis` after
`Store::apply`, so its function, body and override records come out with the edits in them.
The store never holds facts records.

## The read-only scripts (`export`)

```sh
ghidra-rs export <pe32> [--store <file>] [--facts <file>] [--seeds <csv> | --functions-from <csv>]... [--sla <file>] <command>
```

mercs2's eight remaining Ghidra scripts, ported statement by statement onto `store::Project`
(`ghidra-rs/src/exports.rs`, `ghidra-rs/tests/exports.rs`). With them all 17 scripts of
`mercs2-decomp/tools/ghidra/` have a ghidra-rs command (`Decompile.java` is `decompile`, which
still needs stage S10 for Java's C). `export` analyses, lays the store over the analysis when
one is given, decodes the code beyond the function bodies with its references (as
`--abi-callers` does) and runs one command. It never writes the store, and it writes an output
file only when the command ran to its end. Two of the scripts have an editing option; those
are `edit` commands (the table of "Commands" above).

| Command | Script | Output |
|---|---|---|
| `mod-hook-owners <sites.csv> <out.csv>` | ExportModHookOwners.java | `address,function_address`: the function containing each address |
| `slot-owners <slots.csv> <out.csv>` | ExportSlotOwners.java | `site,function`: the function containing each captured jump site |
| `boundaries <out.txt> <addr>...` | InspectBoundaries.java | per address: the body ranges and no-return flag of its function and of the function before it; 28 instructions around it with owner and flow override |
| `call-contexts <target> <out.txt>` | ExportCallContexts.java | per reference to the target: its type and owner, up to 6 instructions before and 22 from there on, within the owner |
| `audit-recovered-functions <recovery.csv> <audit.csv>` | AuditRecoveredFunctions.java | `address,size,instructions,instruction_bytes,non_instruction_bytes,outside_text,wrapper_flows,status` of every `created` row |
| `library-evidence <markers.csv> <out.csv>` | ExportLibraryEvidence.java | `address,module,string_address,marker,source`: `.text` functions that refer to a defined string holding a marker |
| `bindings <out.csv>` | ExportBindings.java | `table,index,name,function,library`: tables of four or more (ASCII name, `.text` pointer) pairs in `.rdata` and `.data` |
| `abi-candidates <out.csv> <out.txt> [<verified-c-dir>]` | ExportAbiCandidates.java | `address,size,references,registers,name` and the listing with C of small leaf functions with register parameters |

Each prints its script's summary line. `--facts <file>` is a facts file (`analyze --facts`, or
the Java project's from `tools/ghidra-facts.sh`); `library-evidence` reads the defined strings
from it (the `string` records: Ghidra's strings, or the ported ASCII Strings analyzer's) and
`abi-candidates` the function names.

What is an error instead of a guess:

- **An address in two bodies.** Bodies here can share instructions; Ghidra's never overlap,
  and which function got shared code there depends on the order its analysis made them. A
  command that needs the function containing such an instruction stops with its address
  (unless a function starts at the instruction). `GHIDRA_RS_SHARED=lowest` takes the store's
  rule instead (the lowest entry, as the `edit` commands do) and prints a `shared <address>
  <entries>` line on stderr for each such answer.
- **`call-contexts`: the type of a data reference** from a memory operand, or to an address in
  a block that is not executable (Ghidra's READ, WRITE, INDIRECTION, DATA; the analysis keeps
  one kind). An immediate that points at code is DATA; a flow reference of an instruction with
  a CALL_RETURN override is `CALL_TERMINATOR`, as `InstructionDB.setFlowOverride` retypes it.
- **`library-evidence`**: without `--facts`; a marker that is not ASCII; a referenced string
  that is not plain ASCII (wide, translated, `-` in the facts) whose bytes hold a marker read
  as ASCII or as UTF-16; a referenced string outside the image.
- **`audit-recovered-functions`**: a `created` row that is no function ("missing recovered
  function", as Java throws).
- **`abi-candidates`: the C.** The script greps Java's decompiled C for `in_`/`unaff_`
  register variables, and ghidra-rs does not print Java-identical C for every function yet
  (stage S10). The selection is ported (at most 96 bytes, no thunk, no call or computed jump,
  five or more references); the C of each selected function is then read from
  `<verified-c-dir>/0x<entry>`, where the caller puts output that was verified identical to
  Java's (`tools/ghidra-diff.sh` names its files so). Without the directory or the facts, or
  with one selected function missing there, the command fails with "needs S10 Java-identical
  output", lists each missing address as an `unverified 0x...` line on stderr (a corpus for
  `ghidra-diff.sh`) and writes nothing. It does not decompile by itself.
- `Long.decode` of an address with a leading `0` (octal in Java).

What the ports take from the analysis instead of a Ghidra project (all in "What ghidra-rs
derives" above): bodies are the flow from the entry; flow overrides and thunks are derived or
the store's; a function without an instruction at its entry counts as Java's function of one
undefined byte (size 1, no instruction: what `--remove-empty` removes); defined data is only
known for address-table slots (`export-bindings --recover`); references are listed by address
(Java lists them in the order its analysis made them, `RefListV0`, so `call-contexts` and the
rows of one string in `library-evidence` come in another order). Instruction text is Java's
`Instruction.toString` as `--abi-callers` writes it, with `LEA reg,[0x...]` unpadded as Java
prints it (found here; `--abi-callers` still pads it).

### Against Java (Mercenaries2.analysis.exe, 2026-11-17)

`tools/scripts-ref.sh` runs the eight Java scripts headless and `-readOnly` on a copy of the
mercs2 project (Ghidra 12.2_DEV, one run), `tools/scripts-diff.sh` the commands with
the same inputs on the functions of that project (`--functions-from` the 44990 entries of its
facts; 44983 are functions here, 7 lie inside an instruction ghidra-rs decoded first) and no
store. Inputs: `config/mod_hook_sites.csv` (26 sites, also the addresses of `boundaries`), the
last slot capture (2448 sites), four call targets, `build/recovery-analysis.csv` cut to the
rows whose function the project still has (15937; Java throws at the others), 
`config/library_markers.csv`. Java's files of this run equal the ones saved in
`mercs2-decomp/build` for bindings and library evidence (the saved ABI candidates of
2026-10-15 differ from this run's; both have 168).

| Command | Java | ghidra-rs | What differs |
|---|---|---|---|
| `mod-hook-owners` | 26 rows | the same file | |
| `slot-owners` | 2448 rows | stops at 0x0076d634 (in two bodies); with `GHIDRA_RS_SHARED=lowest` 2446 rows the same | 7 sites lie in two bodies: the lowest entry is Java's owner for 5; 0x0076d634 has no function in Java, 0x00861193 has 0x008613d0 (here 0x008611e0). The 2441 other rows are Java's |
| `boundaries` (26 addresses) | 869 lines | the same file | none: 52 function lines with ranges and no-return flags, 728 instructions with owner and override (1 CALL_RETURN) |
| `call-contexts 0x00568900` | 2 references | the same file | |
| `call-contexts 0x004017b0` | 19 references, 450 lines | the same lines | the order of the references |
| `call-contexts 0x00593c10` | 601 references, 14403 lines | the same lines | the order of the references |
| `call-contexts 0x00401780` | 276 references, 6560 lines | 277 references, 6584 lines; 6553 lines the same | the order; 6 references have no owner in Java and one here (the bodies of 0x00418c80 and 0x0073f4a0 reach further here); 1 reference more (from 0x00427d22, code in no function) |
| `audit-recovered-functions` | 15937 rows | 15936 rows (0x00475541 is no function here: it lies inside an instruction), 15910 the same | 26 rows with another body size |
| `library-evidence`, the Java project's strings | 102 rows | the same 102 rows | the order of 11 rows (references to one string) |
| `library-evidence`, ghidra-rs's strings (`analyze --facts`: 25933 strings, Java 26420) | 102 rows | the same 102 rows | the same order difference |
| `bindings` | 1339 rows, 54 tables | the same file | |
| `abi-candidates`, without C | 168 candidates | fails: "needs S10 Java-identical output", 668 functions selected | |
| `abi-candidates`, with Java's C of the 668 (`scripts-ref.sh --c`) | 168 candidates | 145; 144 in both with the same size, registers and name, 128 of those with the same reference count; their listings and C are the same lines | 24 only in Java: each has a jump to a function entry, which is a call here (the derived CALL_RETURN; Java's project has no override there), so it is no leaf. 1 only here (0x009eed6d, 5 references here). 16 reference counts differ (2 fewer to 13 more here) |

The two editing options, in the order of mercs2's `analysis_pipeline.sh` on a fresh store from
plain discovery (no `--functions-from`), against Java's saved pipeline outputs of 2026-10-14:

| Command | Java | ghidra-rs |
|---|---|---|
| `edit export-bindings --recover` | 1339 bindings; 501 recovered, 0 unresolved | the same CSV; 575 recovered, 0 unresolved (plain discovery starts with fewer functions) |
| `edit recover-functions` (after it) | 15938 created, 36302 examined | 16224 created, 37029 examined |
| `edit audit-recovered-functions --remove-empty` | 15938 retained, none removed | 16224 retained, none removed; 15822 rows in both, 15754 the same, 68 with another size |

Superseded: the `recover-functions` row of the table of "Project store" above ("16150 created,
36909 examined") is the run without `export-bindings --recover` before it.

Not run or not compared: `abi-candidates` with C that ghidra-rs printed (no function's C was
verified for it; the run above feeds it Java's own C to check the selection, the pattern and
the writer); the derived flow overrides against the 3365 of the facts beyond what the outputs
above show; `export` with a store; `--remove-empty` on a function it would remove (none
exists here: `create_function` never makes a function without an instruction, and Java's
saved audit has no `removed_empty` row either). The shadow check
(`mercs2-decomp/tools/ghidra-rs-shadow.sh`: `analyze --functions-from build/functions.csv
--abi-callers`, with the installed x86.sla) writes the same file as a build of the commit
before this one, e384aa0276 (56918 lines, `cmp`; "Project store" above records 56966 lines for
the store branch; that difference is not from this change).

`export --store <file>` takes a store of version 2 only, and only one made on the same binary
and seed set (as `analyze --store`); the store is laid over the analysis after its constants
pass. `--new-store` belongs to `edit`.

### Switching mercs2's export scripts

For the mercs2 session: `tools/mercs2-exports.sh` runs the four exports that are byte-identical
to Java in place of `tools/ghidra/run.sh --analysis <Script.java> ...`. It writes nothing to
mercs2-decomp unless an output path given to it points there.

```sh
cargo build --release -p ghidra-rs            # in rust/; the wrapper runs target/release/ghidra-rs
rust/tools/mercs2-exports.sh --functions <list> [<out-dir>]                  # all four
rust/tools/mercs2-exports.sh --functions <list> --compare <java-dir> [<out-dir>]
rust/tools/mercs2-exports.sh --functions <list> ExportModHookOwners.java config/mod_hook_sites.csv build/mod-hook-owners.csv
rust/tools/mercs2-exports.sh --functions <list> InspectBoundaries.java build/pal-<address>.txt <address>...
rust/tools/mercs2-exports.sh --functions <list> ExportBindings.java build/bindings.csv
rust/tools/mercs2-exports.sh --functions <list> ExportCallContexts.java <address> <out.txt>
```

The one-script form takes Java's arguments. The all-four form writes `mod-hook-owners.csv`,
`boundaries.txt` (the addresses of `config/mod_hook_sites.csv`, or `SITES`), `bindings.csv`
and `contexts-<target>.txt` (`TARGETS`, default the four targets above) to `<out-dir>`
(default `rust/target/mercs2-exports`). These are the names `scripts-ref.sh` gives Java's
files. `--compare` diffs each file against the file of the same name in `<java-dir>`
(`$GHIDRA_REF/scripts/java` after `scripts-ref.sh`). It prints `identical` only for `cmp`-equal
files and exits 1 when any file differs.

Inputs:

- `orig/Mercenaries2.analysis.exe` of `MERCS` (default `~/projects/mercs/mercs2-decomp`): the
  program `run.sh --analysis` opens. `run.sh` without `--analysis` opens `orig/Mercenaries2.exe`,
  which differs from it in 9541 bytes. The wrapper does not run on that program, and nothing
  here was compared on it.
- `--functions <list>`: the function entries of mercs2's Ghidra project (`build/ghidra`) as it
  stands after `analysis_pipeline.sh`'s editing scripts. These four scripts read functions and
  bodies, and ghidra-rs gets Java's set only from this list. The list is either a CSV whose
  `0x` lines start with an entry or the facts file of the project, whose `func` records the
  wrapper takes. Today the list comes from `tools/ghidra-facts.sh`, which runs ExportFacts.java
  headless on a `-readOnly` copy of the project and writes `$GHIDRA_REF/mercs2.facts`.
  `scripts-ref.sh` cuts its `func` records to `$GHIDRA_REF/scripts/functions.csv` (the default),
  which has 44990 entries. mercs2's own `build/functions*.csv` (ExportFunctions.java, 37599
  entries on 2026-10-14) will not do: they list only `.text` functions, and the project has
  changed since then. Run the list again after every change to the project. A store
  (`--store`) cannot stand in for it yet: `fold-slot-fragments` stops on mercs2 (see "Project
  store").
- `config/mod_hook_sites.csv`. The four scripts take no other input.

Against Java (`scripts-ref.sh`, Ghidra 12.2, on the 44990 entries; the table of "Against Java"
above, run again after the merge of the store version 2 on 2026-11-17):

| Script | ghidra-rs |
|---|---|
| ExportModHookOwners.java | identical (26 rows) |
| InspectBoundaries.java (the 26 sites) | identical (869 lines) |
| ExportBindings.java (without `--recover`) | identical (1339 rows) |
| ExportCallContexts.java 0x00568900 | identical (2 references) |
| ExportCallContexts.java 0x004017b0 | not identical: the same 19 references in another order |
| ExportCallContexts.java 0x00593c10 | not identical: the same 601 references in another order |
| ExportCallContexts.java 0x00401780 | not identical: the order, and 277 references here against Java's 276 (6553 of Java's 6560 lines the same) |

The reference order of `call-contexts` is a known difference and is not derived. Java's
`getReferencesTo` returns `RefListV0` in append order, the order in which the project's
history made the references (auto-analysis, then each editing script's clearing and
disassembly). Below `RefList.BIG_REFLIST_THRESHOLD` (1700) nothing in the binary or in the
facts records that order. ghidra-rs lists references by address. For a target with 1700 or
more references Java uses `BigRefListV0`, and its order there was not checked. Use
`call-contexts` output as a set of reference blocks. `--compare` says "the same references in
another order" when only the order differs.

What the mercs2 session changes: replace calls of `tools/ghidra/run.sh --analysis` for these
four scripts with the wrapper's one-script form and pass `--functions`. Keep Java for
`ExportBindings.java --recover`, which edits the project; the wrapper refuses it. For a first
switch, run the all-four form with `--compare` against a fresh `scripts-ref.sh` run and expect
4 identical files and 3 that differ, as in the table above.

Not run: the wrapper on `orig/Mercenaries2.exe`; boundaries on addresses other than the 26
sites; call-contexts on targets other than the four; any target with 1700 or more references.

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
  Superseded (2026-11-23): "without it the output is upstream's" holds for PE files; on an ELF
  the patch always leaves the non-loaded sections out of the image ("The prelude path follows
  Java" below).
- `--decomp-prelude` writes console commands both engines `source` before a function:
  `option readonly on`, `readonly` over `.rdata` (so `.rdata` constants such as floats fold
  instead of printing as `fRam...`), for each IAT slot a `nocode` function named after the
  import plus `map externalref` from the slot to it (so `CALL [slot]` calls the import instead
  of decoding the bound address in the slot, which made 0x40a110 fail), and `map function` for
  every function with its FID or export name. For mercs2: 30,262 `map function` lines (1,022 of
  them import slots), 1,022 `map externalref`.
  Also `override flow <address> callreturn` after a function's `map function`, for its
  CALL_RETURN flow overrides ("The prelude path follows Java" below; ELF first, PE since
  branch `pe-overrides`: 3,369 such lines for mercs2).
- `decompile -i` reads `load file`, `source`, `map function`, `map externalref`, `readonly`,
  `option`, `fixup apply`, `load function`, `load addr`, `break start`, `decompile`,
  `print raw`, `continue` and `quit`, and echoes them as `decomp_dbg -i` does. `decompile`
  runs up to the `break start` action (stage S4: at most `assignhigh`, see "Stage S4") and
  `continue` resumes it; a function mapped `nocode` prints `No code for <name>` instead. `print
  C|tree block` fail with "not implemented in ghidra-rs yet (milestone 3, later stages)";
  `parse line` defines types and locks `extern` prototypes (stage S6); `load facts <file>` (stage S10, not a
  command of `decomp_dbg`) reads the facts of a Ghidra project in place of the prelude; any other command fails with "not implemented in ghidra-rs".
  Superseded: until S6, `parse line` failed like `print C`.
  Since 2026-11-23 also `override flow <address> callreturn`, on the function `map function`
  made last and before it is loaded ("The prelude path follows Java" below).
  Superseded: until S2, `decompile` stopped at most at `heritage` and `continue` failed. Of the options
  `option readonly on|off` and `option currentaction decompile <group> on|off` have an
  effect (and print the reference's message); the others (`togglerule`: no rule is ported
  yet) are read and ignored (superseded at R4: `togglerule` and `nanignore` are read, options
  that only change the printed C are ignored, any other is an error; see "Stage R4"). Superseded: until S4, `decompile` stopped at most at
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
  - `REFCACHE=0`: run the reference for every function. Otherwise each reference output is
    kept in `rust/target/ref-cache/` (one file per run, named by a content hash) and reused
    while that hash is the same: a full pass reruns only ghidra-rs where nothing the reference
    reads has changed. The hash covers `decomp_dbg` itself (so a rebuild from a new
    `decomp-ref.patch` or C++ sources misses; `ref.stamp` only records the committed trees),
    `BIN`, the prelude, every `.sla`, `.ldefs`, `.pspec` and `.cspec` under `SLEIGHHOME`'s
    `Ghidra/Processors`, every `DECOMP_*` variable (`DECOMP_SKIP_ACTIONS`, `DECOMP_RAW_EXTRA`,
    `DECOMP_JT_RAW` and the others the patch reads; set-but-empty counts), the command line,
    and the function's script (address, the options file's lines, `BREAK`, `PRINT`,
    `CONTINUES`). File dates play no part. Only a run that exits 0 and that the reference
    finished (no error, a `Decompilation complete` or `Break at` line) is stored, never a
    timeout, error or crash, since those depend on load; the run's seconds are stored with it
    and a stored run is reused only when it took less than `TIMEOUT`. Writes go to a temporary
    file renamed into place, so a killed run leaves no half entry. Each clone (the Mac's under
    `bars-queue.sh` too) keeps its own cache; delete the directory to empty it. Measured
    2026-11-18 on M500 (`pcc-r pcc-t pcd r5s swfs-r paramdouble`, 12 jobs): 1,416 s with
    `REFCACHE=0`, 1,436 s cold, 1,180 s warm (2,988 files, 255 MB; warm about 18% below cold);
    ghidra-rs's own runs stay and dominate. The warm `pcd` line differed on one function,
    0x4c48d0, at the 120 s timeout edge: the reference finished it in 118 s, then ghidra-rs
    timed out. That is load jitter, not a stale cache entry.

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

### Every check at once: `tools/bars.sh`

`rust/tools/bars.sh` runs every milestone 3 check (each stage's `BREAK`, options and print, as
the sections below give them) through `decomp-diff.sh` and prints one summary line per check.
It is the one copy of the "run every bar" script; a stage that adds a check adds it there.

```sh
CORPORA=m8 rust/tools/bars.sh                          # the fast gate, about 2 minutes
rust/tools/bars.sh                                     # everything: M8, M500, r5d-adc, switch, simple
CHECKS="r1 swfs-r" CORPORA="m500 switch" JOBS=3 rust/tools/bars.sh
```

- `CORPORA`: `m8`, `m500`, `r5d-adc`, `switch`, `simple` (files of `tools/corpus/`) or an
  address file; default all five. Without `CHECKS`, M8 and M500 run all 55 checks, `r5d-adc` the
  four double-rule checks (`r5d r5dt r5dtlock r5dtlocksv`), `switch` the S3 bar (`paramdouble`),
  the six switch checks and `pcc-r pcc-t` (with the `sw` options: `switchnorm` on, as the case
  labels need; superseded: "and the six switch checks"), and `simple` the four `print C` checks. Superseded: "all four",
  "all 45 checks", "all 47", "all 51", "all 53" (before the six `setcasts` checks, `pc-r pc-t`, `pcc-r pcc-t` and the
  `simple` corpus).
- `CHECKS`: names from the script's `case`: `stack stackhigh funclink heritage paramdouble s4
  s6 s6void s6int4 s6callee r1 subvar r4 r5 r5typed s7r s7r2 s7sub s7r4 s7r5 s7t s7t2 s8 s8r`
  (the 24 standard bars), `r5c r5d r5dt r5dtlock r5dtlocksv` (R5 slices 3 to 5), `svlock svs6
  r5slock r5s` (R5 slice 2, `stackvars` on), `pg-r pg-t nm-r nm-t ldn-r ldn-t fs-r fs-t` (tail:
  prototypes and globals, names, `latedonothing`, `finalstructure`; `-r` rules on, `-t` types
  on), `cs-r cs-t fsc-r fsc-t` (S9 `setcasts`: `print raw` after it, and `finalstructure`
  with it on), `swfs-r swfs-t swsn-r swsn-t swfsc-r swfsc-t` (`finalstructure` with case
  labels, `switchnorm`, and `finalstructure` with case labels and `setcasts` on) and
  `pc-r pc-t pcc-r pcc-t` (`print C`, S9 slices 1, 2, 3A, 3B, 4 and 5, `pcc` with `setcasts` on; see "C printing").
  `pcd` is `print C` with the DEFAULT options (no group or rule off, no break), the action leaves
  not ported yet skipped on both engines (the list `D` at the top of `bars.sh`; it shrinks as
  they are ported). It runs on M8, M500 and `simple`: M8 and M500 run 56 checks, `simple` five
  (superseded: "all 55 checks" and "the four `print C` checks" above).
  `pmd` is `print map` and `print raw` with the same options at `break start startcleanup` (the
  local symbols and the typed ops after `mapped_local_sync`); `D` is empty now. M8 and M500 run
  57 checks, `simple` six (superseded: "56 checks" and "five").
- `JOBS` (default `nproc` less 2, left for the desktop), `TIMEOUT` (seconds per function and engine, default 120 as for every bar here; 0x4c48d0 of M500 takes
  the reference about 485 s and ghidra-rs about 600 s alone, so at 120 s it counts as a function
  the reference does not finish), `OUT`
  (default `rust/target/bars`), `KEEP=1` keeps the per-function outputs.
- Output, all under `rust/target/`: `bars/summary.out` (the printed lines, appended),
  `bars/<check>-<corpus>.log` (the `decomp-diff.sh` output) and `.miss` (one line per
  differing function: `loud` with ghidra-rs's error, `silent` with the first differing line,
  `timeout` when ghidra-rs printed nothing or was killed at `TIMEOUT`; and the `reference failed`
  lines, a reference killed at `TIMEOUT` among them with the reason `decomp-diff.sh: timed out
  after N s`). `decomp-diff.sh` checks `timeout`'s exit status (124 or 137) and replaces a
  killed engine's cut-off output with that one line, so a run cut off mid-print never counts as
  finished or as a `silent` difference. A panic or stack overflow of ghidra-rs is `loud`: its
  message (`panicked at`, `has overflowed its stack`) prints before the buffered console
  output, and `decomp-diff.sh` keeps those lines from before the load line (everything else
  there is the shared prelude). Checked with a stand-in engine that prints a panic message and
  cuts its output: `loud`, where it was `silent` before. None occurs in the corpora: the
  `m3-int5` full pass has 6 silent misses, all a type difference and none a panic, and no `timeout`.
- The summary line is `<check>-<corpus>: reference finished F / N, identical I / F (loud L,
  silent S, timeout T), all outputs identical A / N`. `I / F` counts only the functions the
  reference finishes, which is how the README's bars are given. `A / N` is `decomp-diff.sh`'s
  own count, where a function the reference does not finish counts as identical only when both
  engines print the same thing.
- The option files that lock every prototype (`lock-void`, `lock-int4`, `lock-stk`,
  `stack-lock`, and the `stackvars` and R5 variants built on them) hold one `parse line extern`
  per mercs2 function, so they are not committed: `tools/lock-options.sh` writes them to
  `rust/target/locks/` from the prelude (`decomp-locked-options.sh`) and the committed options
  files, and `bars.sh` runs it first. It builds them in a private directory and renames them
  into place, so parallel `bars.sh` runs sharing `rust/target/locks/` never write one file at
  once (they did: interleaved `parse` lines that stopped every script before `load function`,
  so r5slock, r5dtlock, r5dtlocksv and svlock had reference finished 0 / 500 on the Mac).
  Superseded: the hand-made `rust/target/stack-lock.txt`,
  `lock-sv.txt`, `s6-sv.txt`, `r5s-lock.txt`, `r5dt-lock.txt`, `r5dt-lock-sv.txt` of the
  sections below are these files.
- The switch corpus is `tools/corpus/switch.txt` (2,050 functions with a jump table; superseded:
  `rust/target/stk/switch.txt` of an agent's worktree).
- `LIST=1 bars.sh` prints the `<check> <corpus>` pairs it would run and runs nothing.
- The reference's outputs come from `decomp-diff.sh`'s cache (`rust/target/ref-cache/`, see
  `REFCACHE` above) wherever their inputs are unchanged; `REFCACHE=0 bars.sh` runs it everywhere.

### One pass on two machines: `tools/bars-queue.sh`

`rust/tools/bars-queue.sh` shares one `bars.sh` pass between this desktop and a second machine
reached over ssh (the MacBook, `192.168.254.18`). It puts the pairs of `LIST=1 bars.sh` in one
queue, M500, r5d-adc and switch first and M8 last, and runs two workers: local and the Mac. Each
takes the next pair when it is free, so the faster machine runs more of them.

Note (2026-11-18): the script's default `REMOTE` and the git remote `mac` below still say
`192.168.254.18`; the Mac is at `192.168.254.10` since 2026-11-18 (DHCP). Set `REMOTE` until
the default is decided; the script is unchanged.

```sh
NOLOCK=1 CORPORA=m8 rust/tools/bars-queue.sh       # a test: the local worker skips heavy-run
PUSH=1 rust/tools/bars-queue.sh                    # everything; push HEAD to the Mac first
```

- Before it starts it stops loudly unless: both clones are at the same commit with no tracked
  changes and no untracked files in `rust/tools` (`PUSH=1` pushes HEAD to the git remote `mac`
  as branch `bars-queue` and checks it out detached there); no `bars.sh` or `decomp-diff.sh` of
  either clone is running; `cargo build --release` passes on both; both references were built
  from this commit's `decomp-ref.patch` and C++ sources (`decomp-ref.sh` writes the two git
  object ids to `target/decomp-build/ref.stamp`); and the game binary, `x86.sla` and the
  prelude have the same `cksum` on both. It does not rebuild the reference: when the stamp
  differs, run `tools/decomp-ref.sh` on that machine (on the Mac in `~/ghidra-rs/rust`, after
  the push).
- `CORPORA` or `CHECKS` that `LIST=1 bars.sh` rejects (a missing corpus) stop it before any run.
- The local worker runs each pair under `~/.claude/bin/heavy-run 5` with heavy-run's `JOBS`;
  `NOLOCK=1` skips the lock and uses `JOBS=$(heavy-run --jobs)`. The Mac runs each pair with
  `JOBS=16` (`REMOTE_JOBS`) under `caffeinate -i` (the Mac sleeps after a minute idle).
- Output, under `rust/target/bars-queue/` (`OUT`, emptied at the start of each run):
  `summary.out` (the queue's header line, the `bars.sh` summary lines of both machines as they
  finish, then `DONE`, `INCOMPLETE` or `STOPPED`), `times.out` (`<check>-<corpus> <worker>
  <seconds>`), `local/` (the `bars.sh` files) and `mac/` (each pair's output and its `.miss`,
  copied back; a failed copy prints a warning). The Mac keeps its own files under its
  `rust/target/bars-queue/`, also emptied at the start.
- No retry. Only a full summary line counts, ending `all outputs identical A / N`, with the
  reference finishing at least one function. A pair without one (ssh dropped, the Mac gone, a
  run that broke) prints `lost: <check>-<corpus> on <worker>`. A lost Mac pair stops the Mac
  worker and kills its run there; the local worker runs the rest. Any lost pair ends the pass
  `INCOMPLETE` with exit 1, so it never counts as complete.
- Stopping a pass: Ctrl-C, or `kill <pid of bars-queue.sh>` (TERM). Each pair runs in its own
  process group; the script kills both workers' runs (on the Mac the process group of the ssh
  command, recorded in its `target/bars-queue/run.pid`), writes `STOPPED` and exits 1. Do not
  `kill -9` it: that leaves both runs going, and the next pass stops until they end.
- `REMOTE`, `REMOTE_DIR` (the clone, from `~`, default `ghidra-rs`), `REMOTE_BIN` (the game
  binary there), `REMOTE_FID` (the Function ID databases there, default
  `~/ghidra-rs/rust/target/fid`); `CORPORA`, `CHECKS`, `TIMEOUT` as in `bars.sh`.

Setting up the Mac (macOS 26, Intel, Homebrew in `/usr/local`):

- `brew install coreutils gnu-sed grep findutils gawk diffutils binutils`. `decomp-diff.sh` needs
  GNU `sed` and `grep` (`\|` in basic regular expressions), `cmp`, `timeout` and `nproc`; the
  queue puts their `gnubin` folders (diffutils: `bin`) first on the PATH of each ssh command, with `/bin/bash` (3.2) as bash.
- The reference: `rust/tools/decomp-ref.sh` builds on macOS with Homebrew GCC (`g++-16`,
  `REF_CXX`) and libstdc++, never Apple's clang and libc++, and fails when `decomp_dbg` does not
  link libstdc++: `stdsort.rs` keeps libstdc++'s order of equal keys. `tools/stdsort_ref.cc`
  built with `g++-16` prints `tests/data/stdsort-gxx.txt` exactly; built with clang it differs
  from the first line. BFD comes from Homebrew `binutils` (`BINUTILS`), and the console is built
  without `__TERMINAL__`, because macOS's `tcgetattr` on `/dev/null` fails with an errno the
  console does not expect (on Linux it reports "not a terminal" and the console goes on).
- The inputs, copied from the desktop: the game binary to the same place under `~`
  (`decomp-diff.sh`'s `BIN` default is now `~/projects/mercs/mercs2-decomp/orig/...`), the
  compiled `x86.sla` and `x86-64.sla`, and Ghidra's `*_x86.fidbf` Function ID databases to
  `rust/target/fid/` (`GHIDRA_RS_FID`). Without the databases the prelude names no FID
  functions (801,671 bytes instead of 839,707) and every check differs.
- The clone: the desktop has the git remote `mac` (`ssh://192.168.254.18/Users/zpt/ghidra-rs`),
  and the Mac clone has `receive.denyCurrentBranch updateInstead`.

Acceptance on master 95bbb60e89 (2026-11-15), the Mac with `JOBS=16`, `TIMEOUT=120`: all 45 M8
lines equal the desktop's master lines (`r5dtlocksv` and `r5slock` 6 / 8, `r5s` 3 / 8, `fs-*`
7 / 7, the rest 8 / 8), in 278 s. Six M500 checks equal the bars above: `heritage` 500 / 500
(264 s), `s6` 499 / 499 (336 s), `r5` 497 / 498 (338 s), `s7t` 493 / 499 (341 s), `s8r`
498 / 499 (340 s), `fs-t` 489 / 495 (346 s). An M500 check takes about 5.5 minutes there, against
about 4.6 on the desktop alone with `JOBS=12`. The queue on M8 (`NOLOCK=1`, the local worker at
`JOBS=3` while a pass held heavy-run): 45 pairs in 3 min 33 s, 27 on the Mac and 18 local, every
line equal to the desktop's. With the Mac's ssh killed in the middle: `lost: funclink-m8 on mac`,
the other 44 run locally and equal, `INCOMPLETE`, exit 1. Not yet run: a full pass through the
queue, and the local worker under the heavy-run lock.

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
  none is; the reads are taken in the varnodes' location order, as `beginLoc` walks them; an op
  writing read-only memory warns "Read-only address (ram,0x...) is written", see the end of
  "C printing, slice 5"). `normalizesetup` and `funclinkoutonly`
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
  jump tables and not ported. (Superseded: ported for the stack guards, `valueset.rs`, see
  "Value-set analysis and the stack guards".)
- `emulate.rs` (from emulateutil.cc 397, emulate.cc 462, opbehavior.cc): `EmulateFunction` over
  the data flow (`EmulatePcodeOp`, `Emulate::executeCurrentOp`) and the integer and boolean op
  behaviors. memstate.cc (738 lines) is not needed: `EmulateFunction` keeps a value per
  varnode and ignores STOREs. Float ops fail an emulation (no switch in mercs2 uses one).
- Hooks: `action::jumptable_partial` (the `jumptable` root's actions as far as they are
  ported: `start` to `heritage`) (superseded: the whole `jumptable` tree, see "Stage R2"), `Funcdata` derives `Clone` and keeps the partial's masks
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

Superseded (stage R2): the partial function runs the `jumptable` root action with the ported
rules, the guards are read by the C++ loop, and two of the three stand-ins are gone; the fold
through read-only loads stays until `RuleLoadVarnode` (R5). See "Stage R2".

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
(`testForReturnAddress`; superseded: "not heritaged yet": since slice 3B a target traced to
the input at stack offset 0 fails loudly in flow.rs; superseded again: ported on `m3-swsilent`, see "Switch corpus silent misses"), the retry of
a table whose switch looks unreachable (it needs a guard folded to a constant; it is taken as
complete), `checkUnrolledGuard`, multistage tables, overrides, `JumpAssisted` (superseded:
ported, see "Segment and jump-assist user ops").

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
  ported fails when it runs with its group on. Rule pools hold no rule (superseded: R1 fills
  `oppool1`, see "Stage R1").
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
  printed nothing no longer stops the summary. (Superseded: a killed run no longer prints
  nothing but the line `decomp-diff.sh: timed out after N s`; see "Every check at once".)

| corpus | identical at `break start assignhigh` (S4 options) | at `paramdouble` |
|---|---|---|
| m8 | 8 / 8 | 8 / 8 |
| m500 | 446 / 500 | 500 / 500 |

Remaining differences, by cause:

- 53 functions: the reference splits SSE registers into lanes (`XMM0` into `XMM0_Da` ..
  `XMM0_Dd`, `ActionLaneDivide`, `subflow.cc`/`transform.cc`). It is in group `base`, so no
  option turns it off; the plan puts it in R3. Excluding these, 446 / 447 (every function the reference finishes).
  Superseded: stage R3 ported `ActionLaneDivide`; the S4 check is now 498 / 499 (0x4919f0 differs).
- 0x4c48d0: the reference does not finish within 60 s (`TIMEOUT`), so it is not compared.
- Not ported and failing loudly when reached (no M500 function needs them; superseded for
  removing unreachable blocks and the `varnodeprops` zero replacement, both ported in R1): removing
  unreachable blocks, `ActionNodeJoin` and `ActionConditionalExe` (a candidate on the same
  condition varnode fails; functionally equal conditions in different varnodes are not looked
  for), `ActionUnjustifiedParams` widening (`adjustInputVarnodes`), heritage after dead-code
  removal in a processor space (needs the restart with a longer dead-code delay), removing a
  revisited marker, parameter trials of calls (calls take `__stdcall`, whose parameters live on
  the stack, and no stack varnode exists before the `stackvars` rules), a varnode consumed by
  nothing but read (`varnodeprops` zero replacement), INSERT/ZPULL/SPULL in dead code.
  Superseded: parameter trials of calls are ported (branch `m3-ap`, "Parameter trials of calls").
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

Superseded (R3 merged with S6, 2026-11-13): the "446 / 446 non-SSE" and "446 / 500" results in this section predate `ActionLaneDivide`. With it ported and running on both sides, the S6 checks unlocked, locked `void`, locked `int4` and callees `int4(int4 a)` are each M8 8 / 8, M500 498 / 500 (498 / 499 of the functions the reference finishes): the SSE functions are identical but 0x4919f0 (a block the reference empties, also under the S4 options); 0x4c48d0 is the timeout.

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

Merged with R1 (2026-11-13, `master` into `m3-s6`): `infertypes` and `nonzeromask` are both in
the tree; `ActionInferTypes` reads R1's computed non-zero masks (`Funcdata::nzmask`, the C++
`getNZMask`) for its boolean guards. `PcodeOp::stopsTypePropagation` and
`Varnode::stopsUpPropagation` stay unported: only `RulePtrArith`, `RuleStructOffset0` and
`RulePushPtr` (R5) set the flag, and no R1 rule sets it or makes a PTRSUB/PTRADD; both checks
come with R5. Superseded (R5): ported, see "Stage R5 (in part)". Every bar rerun on the merged binary: S6 unlocked, locked `void`, locked `int4`
and callees with a stack parameter each M8 8 / 8, M500 446 / 446 non-SSE (446 / 500; the misses
are the 53 SSE functions and 0x4c48d0, which the reference does not finish); S4 regression
M8 8 / 8; R1 check M8 8 / 8, M500 451 / 453.

### Stage R1: rules for copies, constants, arithmetic

Stage R1 (branch `m3-r1`) adds the rule pools (`ActionPool`: a pool node in `actiontree.rs`, the walk in
`rules::pool_apply`: every op in sequence-number order, dead ops freed on the way, the rules for
an op's opcode in table order (filed by opcode once per pool), from the first again when a rule
changes the opcode) and 19 rules of `oppool1` in `decomp/rules/` (`mod.rs` holds the table;
`copy.rs`, `arith.rs` the rules, `cse.rs` the shared expression helpers, `float.rs` float
folding; the `Funcdata` methods they need are in `funcdata.rs`): `earlyremoval`, `termorder`, `selectcse`, `collect_terms`,
`pullsub_multi`, `push_multi`, `trivialarith`, `trivialbool`, `trivialshift`, `identityel`,
`multicollapse`, `2comp2mult`, `sub2add`, `carryelim`, `addmultcollapse`,
`collapseconstants`, `propagatecopy`, `negateidentity`, `negatenegate`, with the helpers they
need (`TermOrder`, `functionalEqualityLevel`, `cseEliminateList`, `cseElimination`,
`distributeIntMultAdd`, float constant folding through `FloatFormat`). `propagatecopy` marks
immediate-copy edges (`setCopyImmed`), which `donothing` reads (`hasNoImmediateCopy`): a block
emptied by copy propagation stays. Group `analysis` is on, so the main loop's `nonzeromask`
runs (`jumptable::calc_nz_mask`; superseded in R3 part two: `calc_nz_mask_unfolded`, without
the constant folding; superseded again at the R2 merge: `calc_nz_mask` itself no longer folds
and the partial function calls `jumptable::fold_constants` first) and dead code reads its masks (`Funcdata::nzmask`).

The check: `tools/corpus/r1-options.txt` is S4's options with `analysis` on and every rule of
the groups that are on and not ported switched off (97 `togglerule`s at R1, 76 after R3 part one, 75 after part two, 58 after R4, 17 with R2 merged, which also turns group `cleanup` on), written by
`tools/r1-options.sh` from the table in `rules/mod.rs`: rerun it when rules land.
`ghidra-rs decompile` honours `option togglerule`. Group `analysis` also holds three actions
not ported yet, `multicse`, `shadowvar` and `condconst` (`ActionConditionalConst`). A console
command cannot switch an action off, so, as a check-only switch, the reference patch
(`decomp-ref.patch`, `Action::perform`) and `ghidra-rs decompile` both skip the actions named
in `DECOMP_SKIP_ACTIONS`; each action leaves the list when it is ported. `ghidra-rs decompile`
reads the variable on every run (not only in the checks) and fails on a name that is not a
single action of the tree, so the two engines cannot skip different things silently.

```sh
export DECOMP_SKIP_ACTIONS=multicse,shadowvar,condconst
BREAK=assignhigh OPTIONS=$PWD/tools/corpus/r1-options.txt rust/tools/decomp-diff.sh m8
BREAK=assignhigh OPTIONS=$PWD/tools/corpus/r1-options.txt TIMEOUT=60 rust/tools/decomp-diff.sh m500
```

The bar is taken over M500 less the functions that need `ActionLaneDivide` (R3), listed in
`tools/corpus/m500-lanedivide.txt` (46): those whose reference output changes when
`lanedivide` is added to `DECOMP_SKIP_ACTIONS` (rerun the M500 line with `,lanedivide` and
`OUT=.../m500-nolane`, then compare the two `ref/` directories).

| corpus | identical (R1 check) |
|---|---|
| m8 | 8 / 8 |
| m500 | 451 / 500 |
| m500 less `m500-lanedivide.txt`, functions the reference finishes | 451 / 453 (99.6 %, bar 98 %: reached) |

`print raw` at `paramdouble` stays 500 / 500 on M500 (the pool runs after it), and the S4 check
(`s4-options.txt`) is unchanged (446 / 500). Remaining differences, by cause:

- 46 functions need `ActionLaneDivide` (R3).
  Superseded: ported in stage R3, below.
- 0x47a6b0: the reference merges two blocks testing the same condition (`ActionConditionalExe`,
  `condexe.cc`: ghidra-rs only detects a candidate on the same condition varnode and does not
  find this one; R2 or later).
- Superseded (R3 part two): fixed, the main loop's non-zero masks no longer fold constants.
- 0x6fa6e0: `varnodeprops` replaces a never-consumed `BL` by 0 later on the reference (through a
  COPY into a MULTIEQUAL); on ghidra-rs the rules have made it `COPY #0` by then, which the
  replacement skips. Not traced further.
- 0x4c48d0: the reference does not finish within 60 s.

Round three (2026-11-13) found and fixed, with a temporary print of each varnode's consume and
non-zero masks in the reference's dead code (not committed):

- `ActionVarnodeProps` replaces every read of a varnode whose non-zero mask and consume mask
  share no bit by 0 (`totalReplaceConstant`, a COPY for a marker). With `nonzeromask` on, the
  carry flag of `ucomiss`/`fcomp` + `lahf` (non-zero mask 1, consumed 0x44 through `AH & 0x44`)
  is one; ghidra-rs failed loudly on it before only when the consume mask was 0. That fixed
  the 11 x87/SSE compare functions and 0x440590. A varnode over 8 bytes defined by a ZEXT of 0
  (`handleExtendedZero`) still fails loudly.
- Removing unreachable blocks (`removeUnreachableBlocks`, `blockRemoveInternal` for
  unreachable blocks, `descend2Undef`): 0x6c2570. Its header warning prints the block start as
  `ram,0x%08x`, right for 32-bit code only.

Float folding follows `FloatFormat`: a NaN is read as the quiet NaN with its sign and written as
`getNaNEncoding` does; FLOAT_TRUNC gives `0x8000000000000000` for a NaN or an out-of-range value, as
`(intb)val` does on x86. The C++ flushes a result below the smallest denormal to zero where IEEE
would round it up to the smallest one; ghidra-rs rounds as IEEE does (a known difference, not
met in the checks).

Not ported, with no effect on `print raw`: `isPrecisLo`/`isPrecisHi` (set by R5's
double-precision rules; superseded: ported in R5 slice 3), big-endian address arithmetic. A `pullsub_multi` on a join varnode
fails loudly (`Address::renormalize` of join addresses is not ported). The jump-table
stand-ins (`jumptable.rs`) stay as they are: the partial function would need the `jumptable`
root action's pool with R2's comparison rules too.
Superseded: R2 runs that action on the partial function (see "Stage R2").

### Stage R2: rules for bit operations, comparisons, booleans

Stage R2 (branch `m3-r2`) adds 50 rules of `oppool1` and 2 of the `cleanup` pool, in
`decomp/rules/`, each in the C++ pool order with its `getOpList`:

- `bits.rs`: `ormask`, `andmask`, `orconsume`, `orcollapse`, `andorlump`, `shiftbitops`,
  `rightshiftand`, `highorderand`, `anddistribute`, `andcommute`, `andpiece`, `andzext`,
  `andcompare`, `doubleshift`, `doublearithshift`, `leftright`, `shiftcompare`, `signshift`,
  `shift2mult`, `shiftpiece`, `shiftand`, `bitundistribute`, `xorswap`, `popcountboolxor`,
  `lzcountshiftbool`, `orcompare`.
- `compare.rs`: `intlessequal`, `sborrow`, `scarry`, `testsign`, `less2zero`,
  `lessequal2zero`, `sless2zero`, `equal2zero`, `equal2constant`, `xorcollapse`,
  `slesstoless`, `lessequal`, `lessnotequal`, `lessone`, `rangemeld`, with
  `Funcdata::replaceLessequal`, `AddExpression` and `CircleRange::translate2Op`.
- `boolean.rs`: `bxor2notequal`, `notdistribute`, `booleanundistribute`, `booleandedup`,
  `booleannegate`, `boolzext`, `logic2bool`, `condnegate`, `boolnegate`, with `BooleanMatch`,
  `opBoolNegate`, `opNormalizeFlip` and the boolean flips of the opcodes.
- `cleanup.rs` (the `cleanup` pool, table `CLEANUP`): `multnegone`, `2comp2sub`. The pool runs
  just before `assignhigh`, so the check sees it: group `cleanup` is now on in
  `r1-options.txt`, with the pool's nine other rules of that group switched off on the
  reference (`addunsigned`, `subright`, `piecestructure` and `andstructure` read data-types,
  `ptrsubcharconstant` is R5's, `dumptyhumplate` and `extensionpush` R3's, `floatsigncleanup`
  R4's, `expandload` is left for later). `ActionStartCleanUp` only records the varnode create
  index, which nothing ported reads.

Not ported from the table row: `threewaycomp` (`RuleThreeWayCompare`, 64-bit compare
idioms), `conditionalmove` and `orpredicate` (group `conditionalexe`); they stay switched off on the
reference. `r1-options.txt` (from
`tools/r1-options.sh`, which now reads both pools) holds 17 `togglerule`s with R3 and R4 merged (`subvar-options.txt` 18, `r4-options.txt` 17;
all three now have group `cleanup` on).

`isBooleanValue` reads `typerecovery_on` (set by `ActionStartTypes::reset` when the root action
has group `typerecovery`; `Funcdata::typerecovery_on`). `opFlipCondition` flips `boolean_flip`
only. `copySymbol` carries a constant's data-type and type lock to its replacement
(`rules::copy_symbol`, in `replaceLessequal` and `andcompare`); symbols and equates are not
modelled, so `copySymbolIfValid` has nothing to carry. `leftright` on a join-space varnode
fails loudly (`Address::renormalize`). The helpers the rule files share (`insert_new`,
`copy_symbol`, `lsb`, `shl`, `shr`, ...) are in `rules/mod.rs`; `pull_back`, `pcode_left`,
`pcode_right` and `mostsigbit_set` are in `rangeutil.rs` and `is_bool_output` in `opcode.rs`.
Table tests cover `translate_2_op`, `replace_lessequal`, `same_op_complement`, the boolean
flips and the bit helpers.

The partial function of jump-table recovery now runs the real `jumptable` root action
(`action::jumptable_partial`): the tree of `universal` with the `jumptable` groups (`base`,
`noproto`, `localrecovery`, `deadcode`, `stackptrflow`, `stackvars`, `analysis`, `segment`,
`subvar`, `normalizebranches`, `conditionalexe`), every ported rule on (`togglerule` and
`option currentaction` reach only the `decompile` root, on the reference too). Seven actions of
those groups are not ported and are left out of the partial's tree while they are
(`action::PARTIAL_SKIP`: `funclinkoutonly`, `restructure_varnode`, `multicse`,
`shadowvar`, `condconst`, `mapped_local_sync`, `normalizebranches`); an entry is skipped only as
long as its leaf is `not_ported`, so a later port runs in the partial too. Three of them can
change which tables are recovered: `restructure_varnode` (in the partial it also runs
`protectSwitchPaths`), `condconst` and `normalizebranches`. (Superseded, branch
`m3-aliasupdate`: `restructure_varnode` runs in the partial function, see "Alias analysis of the
jump-table partial function"; `action::PARTIAL_SKIP` holds seven actions now, `outputprototype`
among them, and two of the seven can change the tables.) The partial carries
`Funcdata::jumptablerecovery_on` (`isJumptableRecoveryOn`): heritage does not bump the
dead-code delay in it, dead code skips `lastChanceLoad`, and `donothing` removes an empty block
whatever was copied into it. An error of the partial's action fails the table, as in the C++;
when the error comes from a path ghidra-rs does not port (`LowlevelError::is_unported`) it is
also written to stderr, which `decomp-diff.sh` compares, so it cannot pass for a failure the
reference has (none occurs in the switch corpus). `analyzeGuards` is the C++ loop (the CBRANCH
condition, `boolean_flip`, two pull-backs). Two of S3's three stand-ins are gone (x86 flag
logic read as one comparison; a commutative op's constant in slot 0). One is left: constants
folded through a load from read-only memory (`jumptable::fold_constants`), because
`RuleLoadVarnode` is stage R5. The folded constants no longer reach the non-zero masks of the
function itself (`ActionNonzeroMask` used them in R1, which sharpened masks beyond the C++'s).

Found with the merged rules and fixed: removing unreachable blocks failed with "Deleting op
with descendants" when a removed block's value was read in another removed block
(`descendantsOutside` asks for a reader in a block that is not dead; 0x74fae0).

The check is R1's, with the regenerated options and lane division on both sides (R3):

```sh
rust/tools/r1-options.sh
export DECOMP_SKIP_ACTIONS=multicse,shadowvar,condconst
BREAK=assignhigh OPTIONS=$PWD/tools/corpus/r1-options.txt rust/tools/decomp-diff.sh m8
BREAK=assignhigh OPTIONS=$PWD/tools/corpus/r1-options.txt TIMEOUT=60 rust/tools/decomp-diff.sh m500
```

| corpus | identical (R2 check, merged with R3) |
|---|---|
| m8 | 8 / 8 |
| m500 | 498 / 500; 498 / 499 of the functions the reference finishes (99.8 %, bar 98 %: reached; 495 / 499 with R3 alone) |

Superseded: before the merge with R3 the check was 452 / 453 of R1's set (the 46 lane-division
functions left out).

Other checks on the same binary: `paramdouble` (S3) M8 8 / 8, M500 500 / 500, and the
switch corpus (every function in which ghidra-rs meets a jump table, 0xa4e8c2 left out)
1,947 / 2,050 (1,934 with the stand-ins); S4 (`s4-options.txt`) M8 8 / 8, M500 498 / 500;
S6 with types (`s6-options.txt`) M8 8 / 8, M500 498 / 500; locked `void` M8 8 / 8, M500
498 / 500; locked `int4` M8 8 / 8, M500 498 / 500; callees with a stack parameter M8
8 / 8, M500 498 / 500. With R3 part two and R4 merged (2026-11-13) the three rule
checks, all with group `cleanup` on, are each M8 8 / 8 and M500 498 / 499 the reference
finishes: `r1-options.txt`, `subvar-options.txt` and `r4-options.txt` (superseded: 497 / 499 in
"Stage R3" part two and "Stage R4", measured without the R2 rules).

Remaining differences of the R2 check, by cause:

- 0x47a6b0: `ActionConditionalExe` merging two blocks on equal conditions (as in R1).
- 0x4c48d0: the reference does not finish within 60 s.
- The S4 and S6 checks differ on 0x4919f0 (as with R3 alone); the R2 check does not.

Switch corpus: the reference finishes 2,004 of the 2,050 (120 s limit, errors). Of the 103
that differ, 102 are in the obfuscated code past 0x1000000 and one in the game code: 0x7c1f30
(as in S3: the reference reads a garbage target). No partial function fails on an unported path.
0x831db0, which differed after the first R2 round (two tables not recovered), is identical
with the `jumptablerecovery_on` gates and R3's rules in the partial.

### Stage R3 (in part): lane division; extension, concat and sub-piece rules

Stage R3 (branch `m3-r3`) ports `ActionLaneDivide` (`decomp/lanedivide.rs`: the action of
coreaction.cc and `LaneDivide` of subflow.cc) with `transform.cc` (`decomp/transform.rs`:
`TransformManager`, `LaneDescription`, `LanedRegister`): a laned register (the `.pspec`
`vector_lane_sizes` of XMM/YMM/ZMM, read by `sleigh.rs`) whose data-flow only moves whole lanes
becomes one varnode per lane (`XMM0_Da` .. `XMM0_Dd`). `Funcdata` records laned storage as
varnodes are made (`checkForLanedRegister`) and keeps the per-opcode list order of
`PcodeOpBank` (`PcodeOp::list_key`: an op goes to the end of its list on `opSetOpcode`). The
non-zero mask of a SUBPIECE of a varnode wider than 8 bytes follows the C++ extended-precision
branch, and `varnodeprops` has `handleExtendedZero`.

21 more rules of `oppool1`, in `decomp/rules/`: `extend.rs` (`zexteliminate`, `zextsless`,
`zextcommute`, `zextshiftzext`), `piece.rs` (`concatshift`, `concatcommute`, `concatzext`,
`concatzero`, `concatleftshift`, `humptydumpty`, `dumptyhump`, `humptyor`, `piece2zext`,
`piece2sext`), `subpiece.rs` (`doublesub`, `subextcomm`, `subcommute`, `subzext`, `subcancel`,
`shiftsub`, `subnormal`). The table in `rules/mod.rs` now holds 40 rules.

The check is R1's, with `lanedivide` running on both sides (`r1-options.txt` regenerated by
`tools/r1-options.sh`: 76 `togglerule`s; `DECOMP_SKIP_ACTIONS=multicse,shadowvar,condconst`).
Superseded: the bar over M500 less `m500-lanedivide.txt`; the list stays as the record of which
functions exercise lane division.

| corpus | identical (R3 check) |
|---|---|
| m8 | 8 / 8 |
| m500 | 495 / 500; 495 / 499 of the functions the reference finishes (99.2 %, bar 98 %: reached) |
| m500, the 46 of `m500-lanedivide.txt` | 44 / 46 |
| m500, the others the reference finishes | 451 / 453 (as R1) |

`print raw` at `paramdouble` stays 500 / 500 on M500; the S4 check is 498 / 500 (M8 8 / 8).
Remaining differences, by cause:

- 0x47a6b0, 0x6fa6e0: as in stage R1.
  Superseded: 0x6fa6e0 and 0x4891e0 are identical since part two (the non-zero masks).
- 0x4891e0: `varnodeprops` replaces the reads of a MULTIEQUAL of two zeros by 0 one main-loop
  pass before the reference does (an extra `COPY #0` for a MULTIEQUAL reader, so later sequence
  numbers shift): the non-zero mask is 0 earlier on ghidra-rs. Same family as 0x6fa6e0; not
  traced further.
- 0x4919f0: the reference empties a block (the branch at 0x492433 goes) that ghidra-rs keeps;
  it differs under the S4 options too, so no rule is involved. Not traced further.
- 0x4c48d0: the reference does not finish within 60 s.

Not ported in this stage (see the plan, "R3"): the `subvar` group (`RuleSubvar*`,
`RuleSplitFlow`, `SubvariableFlow` and `SplitFlow` of subflow.cc; the group is off in the check),
`RulePiecePathology` (switched off by `togglerule`; needs the consumed-bytes records of
`fspec.cc`) and `prefersplit.cc` (no x86 `.cspec` uses `<prefersplit>`).

Review round (after the merge with S6): `LaneDivide::setReplacement` refuses a type-locked
varnode unless its type is an array, as the C++ (superseded: "no locked types before S6");
`Arch::new` rejects a big-endian processor, which every ported rule and lane division assume
away; `LanedRegister::parse` reads sizes as `parseSizes` does (hex, octal, a trailing comma;
an empty attribute is skipped); `sign_extend` clamps its sizes to 8 bytes; every opcode change
goes through `op_set_opcode`; the transform placeholders fail on an out-of-range lane, slot or
a varnode made before its defining op. `zext_eliminate` leaves out `copySymbolIfValid`: it
copies only an `EquateSymbol`, which only the console's `map convert` makes, and ghidra-rs has
no such command. All bars rerun on the merged binary: R3 check M8 8 / 8, M500 495 / 499 (the
R1 set 451 / 453, the lane-divide set 44 / 46); paramdouble 500 / 500; S4 check M8 8 / 8,
M500 498 / 500; the four S6 checks M8 8 / 8, M500 498 / 500 each.

### Stage R3 part two: the `subvar` group, `RulePiecePathology`

Branch `m3-r3b`. Superseded: "Not ported in this stage: the `subvar` group, `RulePiecePathology`"
above.

- `decomp/subflow.rs`: `SubvariableFlow` (subflow.cc). A logical value in some bits of larger
  varnodes is traced forward and backward; a trace that succeeds gives a `Replacement`, which
  rebuilds the flow on varnodes of the logical size (`doReplacement`).
- `decomp/splitflow.rs`: `SplitFlow`, on `TransformManager` (`transform.rs` gains the two-piece
  `LaneDescription::two`).
- `decomp/rules/subvar.rs`: `subvar_and`, `subvar_subpiece`, `splitflow`, `subvar_compzero`,
  `subvar_shift`, `subvar_zext`, `subvar_sext` (group `subvar`). No trace is aggressive:
  `Varnode::isPtrFlow` needs `RulePtrFlow` (group `subvar`, not ported, switched off by
  `togglerule ptrflow`) and `aggressive_ext_trim` is off for x86.
- `piecepathology` (group `protorecovery`, `rules/piece.rs`) with the hints it writes,
  `FuncProto::return_bytes_consumed` and `CallSpec::input_consume`, which dead code reads
  (`gatherConsumedReturn`, `markConsumedParameters`). It is now on in every rule check.
- `RuleSubfloatConvert` and `SubfloatFlow` are in group `floatprecision`: left to R4.
  `SplitDatatype` (the `splitcopy`/`splitpointer` rules of the cleanup pool) is not ported.
  The table in `rules/mod.rs` holds 48 rules.

Two faults found on the way, both older than this stage:

- `ActionNonzeroMask` on the function itself used the jump-table stand-in that folds inputs
  to constants (`jumptable::calc_nz_mask`), so a mask could be tighter than the reference's
  (`x ^ x` counted as 0 before `trivialarith` rewrote it). It now runs
  `calc_nz_mask_unfolded`; the partial function of jump-table recovery keeps the folding.
  Superseded (R2 merge): `calc_nz_mask_unfolded` is gone; the single `calc_nz_mask` does not
  fold, and the partial function calls `jumptable::fold_constants` before it.
  This was the cause of 0x6fa6e0 and 0x4891e0. Superseded: "a zero replacement the reference
  makes later" in the R1 and R3 notes.
- Removing an unreachable block failed with "Deleting op with descendants" when a reader was
  in another dead block; `descendantsOutside` only counts readers in blocks that are not dead.

The subvar check: `tools/corpus/subvar-options.txt` (written by `tools/r1-options.sh` next to
`r1-options.txt`: groups `analysis` and `subvar` on, 76 `togglerule`s), `print raw` at
`break start assignhigh`, `DECOMP_SKIP_ACTIONS=multicse,shadowvar,condconst`:

```sh
export DECOMP_SKIP_ACTIONS=multicse,shadowvar,condconst
BREAK=assignhigh OPTIONS=$PWD/tools/corpus/subvar-options.txt TIMEOUT=60 rust/tools/decomp-diff.sh m500
```

| check | m8 | m500 |
|---|---|---|
| subvar check (`subvar-options.txt`) | 8 / 8 | 497 / 500; 497 / 499 the reference finishes (99.6 %, bar 98 %: reached) |
| R3 check (`r1-options.txt`, now 75 `togglerule`s) | 8 / 8 | 497 / 500 (was 495); R1 set 452 / 453, lane-divide set 45 / 46 |
| paramdouble | – | 500 / 500 |
| S4 check | 8 / 8 | 498 / 500 |
| S6: unlocked, `void`, `int4`, callees `int4(int4 a)` | 8 / 8 each | 498 / 500 each |

Remaining differences: 0x47a6b0 (`ActionConditionalExe`, as in R1; rule checks only),
0x4919f0 (a block the reference empties; every check), 0x4c48d0 (reference timeout).

### Stage R4: division, remainder, sign and float rules

Stage R4 (branch `m3-r4`) adds 20 rules of `oppool1` (the table in `rules/mod.rs` now holds
68 with R3 part two's): `rules/div.rs` (`positivediv`, `divtermadd`, `divtermadd2`, `divopt`, `signdiv2`,
`divchain`, with `Varnode::isConstantExtended` and `Funcdata::newExtendedConstant`),
`rules/modulo.rs` (`signform`, `signform2`, `signnearmult`, `modopt`, `signmod2nopt`,
`signmod2nopt2`, `signmod2opt`), `rules/floatrules.rs` (`floatrange`, `floatsign`,
`floatcast`, `ignorenan`, `unsigned2float`, `int2floatcollapse`) and `decomp/subfloat.rs`
(`subfloat_convert`: `RuleSubfloatConvert` and `SubfloatFlow` of subflow.cc, with
`FloatFormat::convertEncoding`; in its own file because `subflow.rs` is stage R3b's).
`floatcast`, `ignorenan` and `subfloat_convert` are group `floatprecision`, the rest
`analysis`. The 128-bit arithmetic of the division rules is `u128` (additions and shifts wrap
as the C++; a division by zero fails as `udiv128` throws); C++ shifts by a count of 64 or
more are taken mod 64, as x86 does. `RuleSignForm2` reports no change after making one, as the
C++. Helpers added elsewhere: `BlockGraph::find_condition` (`FlowBlock::findCondition`),
`TransformManager::new_piece`/`get_piece`/`preexisting_guard` (the subclass's
`preserveAddress` is passed in), `jumptable::is_bool_output` made crate-visible. Shared after the merge with R3 part two:
`rangeutil::mostsigbit_set`, `subflow::preferred_zext_size` and `subflow::repeat_slot`, and
`infertypes::float_sign_manipulation` (one port of `TypeOp::floatSignManipulation` for type
inference and `floatsign`); `TransformManager::has_def` became `var_def`. `option nanignore` (`OptionNanIgnore`) is read: `compare` (the default) and `all`
enable `ignorenan`, `all` also makes every FLOAT_NAN a COPY of 0 (`nan_ignore_all`), `none`
switches the rule off. Superseded: the console no longer reads and ignores every other option;
those that only change the printed C (`nullprinting`, `inplaceops`, `conventionprinting`,
`nocastprinting`, `maxlinewidth`, `indentincrement`, `commentindent`, `commentstyle`,
`commentheader`, `commentinstruction`, `integerformat`, `braceformat`, `namespacestrategy`,
`forloops`) still are, any other one not ported is an error. Not ported: `RuleFloatSignCleanup`
(the `cleanup` pool, R2).


The check is R1's with group `floatprecision` on: `tools/corpus/r4-options.txt`, written by
`tools/r1-options.sh` next to `r1-options.txt` (59 `togglerule`s; 58 after the merge with R3 part two, which ports `piecepathology`).

```sh
export DECOMP_SKIP_ACTIONS=multicse,shadowvar,condconst
BREAK=assignhigh OPTIONS=$PWD/rust/tools/corpus/r4-options.txt rust/tools/decomp-diff.sh m8
BREAK=assignhigh OPTIONS=$PWD/rust/tools/corpus/r4-options.txt TIMEOUT=60 rust/tools/decomp-diff.sh m500
```

| corpus | identical (R4 check) |
|---|---|
| m8 | 8 / 8 |
| m500 | 495 / 500; 495 / 499 of the functions the reference finishes (99.2 %, bar 98 %: reached) |
| m500, the 90 whose reference output changes with the R4 rules off | 89 / 90 (7 with a division or remainder, 83 float) |

Misses: 0x47a6b0, 0x4891e0, 0x4919f0, 0x6fa6e0 as in stage R3 (none caused by an R4 rule;
0x4891e0 is among the 90), and 0x4c48d0 does not finish on the reference within 60 s.
Other checks on the R4 binary: S3 paramdouble M500 500 / 500; S4 check M500 498 / 500; S6 unlocked,
locked `void` and locked `int4` M500 498 / 500 each (misses 0x4919f0 and 0x4c48d0, as before);
callees `int4(int4 a)` 497 / 500: 0x4919f0, 0x4c48d0 (ghidra-rs over 60 s with two checks running
side by side) and 0x5b59c0, where the reference aborts (a `std::string` assertion in the C++, with a
prelude regenerated by this branch's `analyze`), so ghidra-rs prints a function the reference does not.

Merged with R3 part two (`master` into `m3-r4`, 2026-11-13); every bar rerun on the merged binary:
R4 check M8 8 / 8, M500 497 / 499 (the misses 0x47a6b0, 0x4919f0; 0x4c48d0 the reference does
not finish); subvar check and R3 check 497 / 499 each; paramdouble 500 / 500; S4 check and the
four S6 checks (unlocked, `void`, `int4`, callees) 498 / 500 each (0x4919f0; 0x4c48d0).
Superseded: the 495 / 499 above (0x4891e0 and 0x6fa6e0 are fixed by part two's non-zero masks)
and the callee check's 497 (the reference ran 0x5b59c0 this time).
### Stage S8 (in part): structuring

Stage S8 (branch `m3-s8`) ports `ActionBlockStructure`: `decomp/structure.rs` (the structured
block hierarchy of block.cc as an arena with a block-kind enum, `buildCopy`,
`installSwitchDefaults`, the `newBlock*` constructors, `negateCondition`, `printTree`) and
`decomp/collapse.rs` (`CollapseStructure`, `LoopBody`, `TraceDAG`, `FloatingEdge` of
blockaction.cc). `print tree block` prints the hierarchy (nothing before `blockstructure` ran),
and `print raw` prints a flipped CBRANCH as `== 0`, as `TypeOpCbranch::printRaw` does.

Check: `print tree block` and `print raw` at `break start assignhigh`, group `blockrecovery` on
(`tools/corpus/s8-options.txt`, `s8-r-options.txt`: the S4 and rule-stage options without the
`blockrecovery off` line), with `prefercomplement` and `structuretransform` skipped on both
sides (`DECOMP_SKIP_ACTIONS`). The commands and the reasons are in
`docs/plans/m3-decompiler.md`, "S8".

| corpus | rule groups off | rule-stage options |
|---|---|---|
| m8 | 8 / 8 | 8 / 8 |
| m500 | 499 / 500 (499 / 499 the reference finishes) | 496 / 500 (496 / 499; the misses are R3's 0x47a6b0, 0x4891e0, 0x6fa6e0) |

The miss is 0x4c48d0 (neither engine finishes within the timeout). After the R2 merge the
rule-stage column was 463 / 499: the reference joined branches whose conditions `RuleCondNegate`
made equal (`ActionNodeJoin`), which ghidra-rs did not port. Superseded: `ActionNodeJoin` is now
ported (`decomp/nodejoin.rs`, `ConditionalJoin` and `nodeJoinCreateBlock`), and the rule-stage
column is 498 / 499 with `nodejoin` on (it changes 35 M500 outputs; all match). The S4 and S6 checks rise to 499 / 500 with it (0x4919f0). Not ported yet:
`prefercomplement` and `structuretransform` (R2's flip helpers they need are now on master), `finalstructure`,
`returnsplit` and structured `printRaw`.

New flag bit: `OpFlags::FALLTHRU_TRUE` (`1 << 16`).

Part two (branch `m3-s8b`): `ActionPreferComplement` and `ActionStructureTransform`
(`decomp/blocktransform.rs`, with the for-loop recovery of `BlockWhileDo::finalTransform` and
`opFlipInPlaceTest`/`Execute`) run in both S8 checks now (no longer in `DECOMP_SKIP_ACTIONS`):
rules off M8 8 / 8, M500 499 / 499; rule-stage options M8 8 / 8, M500 498 / 499. They change 137
and 10 reference outputs; all match. `ActionReturnSplit` (`decomp/returnsplit.rs`) runs in both
checks too (group `returnsplit` now on in the S8 option files; it changes 52 reference outputs, all
match). `ActionFinalStructure` and structured `printRaw` are not ported: after the S7 merge they still
need `latedonothing`, the prototype and cast actions and switch labels before a fair check exists
(plan, "S8 part two"). Superseded: `latedonothing`, the prototype actions, `mapglobals` and `ActionFinalStructure` are ported (section "Tail" below). The second `prefercomplement`/`structuretransform` instances (without op
modifications) are wired to the rows after `copymarker` since the S7 merge. Superseded: "Not ported yet: `prefercomplement` and `structuretransform`" above.

Review round: `ActionNodeJoin` skips a CBRANCH with `boolean_flip` set (`findDups`), the switch
leaf check of `newBlockSwitch`, no recursion in `printTree`, `negateCondition`, `isComplex`, and
unit tests on hand-built graphs (`structure.rs`). Details in the plan, "S8".
### Stage S7 (in part): merging varnodes into high variables

Stage S7 (branch `m3-s7`) ports the merge range of the universal action, `assignhigh` through
`copymarker`: `decomp/merge.rs` (merge.cc and the merge actions of coreaction.cc:
`ActionAssignHigh`, `ActionMergeRequired`, `ActionMarkExplicit`, `ActionMarkImplied`,
`ActionMergeMultiEntry`, `ActionMergeCopy`, `ActionDominantCopy`, `ActionMarkIndirectOnly`,
`ActionMergeAdjacent`, `ActionMergeType`, `ActionHideShadow`, `ActionCopyMarker`),
`decomp/variable.rs` (`HighVariable` in a `HighId` arena, `HighIntersectTest`, the copy-shadow
tests of varnode.cc) and `decomp/cover.rs` (`Cover`, `CoverBlock`; unit tests for the
intersection logic). The COPYs merging puts in (`snipReads`, `trimOpInput`, `trimOpOutput`,
`snipOutputInterference`, dominant COPYs) are made in the C++ order, and the alive-list order
the actions walk is kept (`PcodeOp::alive_key`). A fix found on the way: `ActionPrototypeTypes`
walks the RETURN ops in creation order (it walked block order), which decides the create
indices of the `return(#0x0)` constants.

Check: `print raw` with types and high variables (`DECOMP_RAW_EXTRA=1`) at `break start
inputprototype` (when S7 landed, the first action after `copymarker` with its group on and not ported; superseded: it is ported, section "Tail"; the break point stays). The
reference patch numbers each high variable by its first appearance in that print (`{hN}`,
reset per print), the Rust side the same. `{hN}` is a canonical labelling of the merge
partition of the printed varnodes: it shows which printed varnodes share a high, but not
create indices, name or type representatives, covers, or highs no printed varnode belongs to.
`DECOMP_RAW_EXTRA=2` also prints each varnode's create index (`{cN}`) on both engines; those
feed `compareCopyByInVarnode`, the location and definition orders and later naming, so a
difference there is a real one. Between `assignhigh` and `inputprototype` the options switch
off `blockrecovery` (`latedonothing`, `blockstructure`, `prefercomplement`,
`structuretransform`), `localrecovery` (`outputprototype`) and `dynamic` (`dynamicsymbols`) on
both sides, so nothing else needs skipping:

```sh
cd rust
DECOMP_RAW_EXTRA=1 DECOMP_SKIP_ACTIONS=multicse,shadowvar,condconst BREAK=inputprototype \
  OPTIONS=tools/corpus/r1-options.txt tools/decomp-diff.sh m500   # rules on
DECOMP_RAW_EXTRA=1 BREAK=inputprototype OPTIONS=tools/corpus/s6-options.txt tools/decomp-diff.sh m500   # types on
# DECOMP_RAW_EXTRA=2 for the same two with create indices
```

| options | M8 | M500 (of the 499 the reference finishes) | with create indices |
|---|---|---|---|
| `r1-options.txt` (rules on) | 8 / 8 | 492 / 499 (98.6 %) | 492 / 499 |
| `s6-options.txt` (types on) | 8 / 8 | 492 / 499 (98.6 %) | 492 / 499 |

Misses: with `r1-options` 3 need `VariablePiece` (0x402c20, 0x405990, 0x62f0d0: overlapping
address-tied varnodes of different sizes; they fail loudly) and 4 are the R1/R3 misses
(0x47a6b0, 0x4891e0, 0x4919f0, 0x6fa6e0); with `s6-options` 6 need `VariablePiece` (also
0x4c0070, 0x757810, 0x7586e0) and 0x4919f0 (as in S4). The create-index mode adds none.

Fixed with the review (round two): `Cover::intersect(PcodeOpSet)` is ported with its walk
(`OpSet` in `cover.rs`: calls sorted by block, block starts, and the C++ quirk that skips the
set block after one it tested; unit test `op_set_walk`); `ActionExtraPopSetup` makes an
unknown-extrapop INDIRECT through `newIndirect` (iop varnode first), which was the varnode
create-index difference of 0x401080 and 0x9eec5e; `ActionPrototypeTypes` skips dead RETURNs;
global symbol types (`code *` of external references) are applied at `assignhigh` too, as the
C++ gives them when a varnode is made (with `typerecovery` off no inference pass applied them:
0x48a430, 0x5c5940, 0x6b3730); `groupPartials` fails loudly on a registered proto-partial root
(`register_proto_partial_root`, for `SplitDatatype::buildOutConcats` and `RulePieceStructure`, neither ported yet: R3b's `SplitFlow` makes no proto-partials); a missing common dominator in `buildDominantCopy` is an
error; storage end offsets wrap as `uintb`; cover-dirty marking matches the C++ (`totalReplace`
dirties only through its `opSetInput`s).

Not ported (each fails loudly, or cannot arise with the ported rules): `VariablePiece` and
`VariableGroup` (overlapping address-tied varnodes of different sizes, proto-partial PIECEs),
symbols and `mergeMultiEntry`'s multi-entry symbols (the local scope holds none), union
resolution of trimmed COPYs, `stripType`, join padding records (`markPurePaddingCopies`),
`dynamic.cc` (only `ActionDynamicSymbols` needs it, group `dynamic` is off), the STORE guards of
`StackAffectingOps` (stack heritage). Regressions on the final binary: R3 check 495 / 499, S3 paramdouble 500 / 500, S4 check 498 / 500, S6 check 498 / 500, all unchanged (the varnode creation-order fix shows only in create indices, which those checks do not print).

Merged with master (R3 part two, R4, R2; 2026-11-13). The jumptable root now runs the whole
tree on the partial function, so `outputprototype` (group `localrecovery`, on there) joins
`PARTIAL_SKIP`: it only sets the output prototype's types, which no recovered address reads
(without it 4 tables failed: S3 fell to 496 / 500). `register_proto_partial_root` stays
unused: in the C++ only `SplitDatatype::buildOutConcats` (`RuleSplitCopy/Load/Store`) and
`RulePieceStructure` make proto-partials, neither ported; R3b's `SplitFlow` makes none. The
paths needing `VariablePiece` (`mergeAddrTied` overlaps, `groupPartials`) still fail loudly.
Results on the merged binary: M8 8 / 8 in all five S7 runs; M500 types on (`s6-options`)
492 / 499; rules on (`r1-options`) 481 / 499, the same with create indices, `subvar-options`
482 / 499, `r4-options` 481 / 499. The rules-on drop is a type difference from before merging
that only this check prints (it is there at `break start assignhigh` with
`DECOMP_RAW_EXTRA=1`): a mask constant of R2's rules (`X & #0x1`) carries the 1-byte type of
the varnode it came from on the reference (`<xunknown1>`) and its own size's on ghidra-rs, in
13 functions; 0x571cc0, 0x746320 and 0x74fae0 also differ in sequence numbers there (not
traced). Rule bars on the merged binary: R3, subvar and R4 checks 498 / 499, S3 500 / 500,
S4 and S6 498 / 500.

### Stage R5 (in part): pointer rules

Stage R5 slice 1 (branch `m3-r5`) ports the pointer rules of group `typerecovery` in
`rules/ptrarith.rs`: `ptrarith` (`RulePtrArith` with `AddTreeState`), `structoffset0`, `pushptr`
(the `oppool2` pool, which runs after `constantptr` in the main loop; until now an empty leaf;
table `OPPOOL2` in `rules/mod.rs`), `ptraddundo` and `ptrsubundo` (`oppool1`, before
`piecepathology`), with `Funcdata::opUndoPtradd`, `collapseIntMultMult`, `newOpBefore` and the
type queries the rules make (`isPtrsubMatching`, `isOffsetValid` of arrays, code and space-base
types, `testForArraySlack`). Type inference now reads the two flags the rules set:
`PcodeOp::stopsTypePropagation` (`OpFlags::STOP_TYPE_PROPAGATION`, bit 1 << 17) in
`getLocalType` and `Varnode::stopsUpPropagation` (`VnFlags::STOP_UPPROPAGATION`, bit 1 << 26)
in `propagateTypeEdge`; PTRADD propagates types (`TypeOpPtradd::propagateType`) and prints in
`print raw` as `out = p + i(*size)`. Not ported, failing loudly: `TypePointerRel`, struct
sub-types and `nearestArrayedComponent` of structs, unions (`needsResolution`),
`assignPropagatedType` (after type recovery gives up). Documented difference: the C++ recursion over add trees
and local adds is unbounded; ghidra-rs fails with an error past depth 1,000 (`MAX_DEPTH`). `tools/r1-options.sh` also reads `oppool2` (skipping commented
`addRule` lines) and writes `tools/corpus/r5-options.txt` (groups `analysis`, `cleanup`,
`typerecovery`); `tools/corpus/s6-options.txt` no longer switches the five rules off.

| check (`r5-options.txt`) | identical |
|---|---|
| M8, types printed | 8 / 8 |
| M500, `print raw` without types | 497 / 500; 497 / 498 of the functions the reference finishes (99.8 %) |
| M500, types printed (`DECOMP_RAW_EXTRA=1`) | 487 / 500; 487 / 498 (97.8 %, bar 95 %: reached) |
| S6 check (`s6-options.txt`, the five rules now on), M500 | 498 / 500 (as before: 0x4919f0; 0x4c48d0 the reference does not finish) |

The reference does not finish 0x4c48d0 and 0x6b21e0 (on 0x6b21e0 ghidra-rs stops at
`assignPropagatedType`: type recovery gave up). Misses: 0x47a6b0 (`ActionConditionalExe`, as in
R1); with types, ten more, all one cause: the constant of an INT_SUB that the `cleanup` pool's
`2comp2sub` builds after the last inference pass (`#0x1 - x`) is `int4` on the reference and
`xunknown4` here (0x40ff50, 0x442c90, 0x479ac0, 0x494400, 0x4ea3ba, 0x5dec80, 0x5ffba0, 0x6b0260,
0x74c9b0, 0x75e5a9). Not caused by R5: the same ten differ with the five rules switched off on
both sides (488 / 499); no earlier check ran `analysis`, `cleanup` and `typerecovery` together
with types printed. Not traced further.
Superseded (fix round, 2026-11-13): traced and fixed. `Funcdata::opSetInput` clones a constant
that already has a reader with `copySymbol` (type and type lock) unless it is a space base;
`unshared_constant` made a bare constant. After the fix: R5 check M500 typed 497 / 498 and
untyped 497 / 498 (miss 0x47a6b0; 0x4c48d0 and 0x6b21e0 the reference does not finish), M8
8 / 8, the ten functions 10 / 10; S6 unlocked 498 / 500 (0x4919f0; 0x4c48d0); R1 check
(`r1-options.txt`) 498 / 499 (0x47a6b0). S3 paramdouble 500 / 500; S4 498 / 500 and the locked S6
checks (`void`, `int4`, callees `int4(int4 a)`) 498 / 500 each (0x4919f0; 0x4c48d0). Switch
corpus not rerun (`typerecovery` is off in the jump-table partial function).
Merged with S8 part one (`master` into `m3-r5`, 2026-11-13); every bar rerun on the merged binary:
R5 check M8 8 / 8, M500 497 / 498 with and without types (0x47a6b0); R1 check 498 / 499;
S8 rules-off 499 / 499 and S8 rule-stage 498 / 499 (neither S8 options file turns
`typerecovery` on, so the pointer rules do not run there); S3 paramdouble 500 / 500; S4 and S6
unlocked 499 / 500 each (0x4c48d0, which the reference does not finish); switch corpus
1,947 / 2,050, the same misses as before. Superseded: "Switch corpus not rerun" above.
The bar is meaningful: 326 of the M500 reference outputs (with types) change when the five rules
are switched off. Not rerun at
the commit (bars whose options leave the new code off: `typerecovery` is off in the R1, subvar,
R4, S3 and S4 options and in the jump-table partial function): r1/subvar/r4 498 / 499,
paramdouble 500 / 500, switch corpus 1,947 / 2,050, S4 498 / 500. The locked S6 checks (`void`,
`int4`, callees) were still running at the commit.

Left for R5: `RuleLoadVarnode`/`RuleStoreVarnode` and removing `jumptable::fold_constants`
(stack loads need the stack heritage pass), double.cc, constseq.cc, bitfield.cc and the
`cleanup` rules that read types (see the plan, "R5"). Superseded: double.cc is ported (R5
slice 3, below).

**R5 slice 3 (double.cc)**, branch `m3-r5-double`. `ghidra-rs/src/decomp/rules/double/`:
`split.rs` (`SplitVarnode` and its static helpers), `forms.rs` (`AddForm`, `SubForm`,
`LogicalForm`, `Equal1Form`, `Equal2Form`, `Equal3Form`, `ShiftForm`, `MultForm`, `PhiForm`,
`IndirectForm`, `CopyForceForm`), `less.rs` (`LessThreeWay`, `LessConstForm`), `mod.rs`
(`RuleDoubleIn`, `RuleDoubleOut`, `RuleDoubleLoad`, `RuleDoubleStore`, `applyRuleIn`, and
`ActionParamDouble`), `tests.rs`. The four rules end `OPPOOL1` in the C++ order (`doubleload`
group `doubleload`, the others `doubleprecis`). New varnode marks `VnFlags::PRECIS_LO` (1 << 27)
and `PRECIS_HI` (1 << 28); the readers that test them are in place: `RulePullsubMulti`,
`RuleSubCommute`, `RuleSubNormal`, `RuleSplitFlow` and `SplitFlow::traceForward`;
`buildOutputFromTrials` sets them on a two-piece call output when double precision is on.
`RuleDoubleIn::reset` is `ActionTree::double_precis` (the `decompile` root has group
`doubleprecis` on), which `ActionTree::perform` copies into `Funcdata::double_precis_on`
(`doublePrecisRecovery`; set even when `togglerule doublein off`, as `ActionPool::reset` resets
every rule). `Funcdata::combine_input_varnodes` is new (`RuleDoubleOut`). Not modelled: symbol
entries (`getSymbolEntry` is null: `isAddrTiedContiguous` tests storage only), big-endian spaces;
erroring paths: `ActionParamDouble` joining two call inputs that are the pieces of one whole
(`checkInputJoin`/`doInputJoin` not ported), and `isPrimitiveWhole` of a type-locked struct or
array whole. The check (options `rust/tools/corpus/r5d-options.txt`: r1's with `doubleload` and
`doubleprecis` on; corpus `rust/tools/corpus/r5d-adc.txt`: the 215 mercs2 functions under 600
bytes with an ADC, SHLD or SHRD), from the worktree root with
`DECOMP_SKIP_ACTIONS=multicse,shadowvar,condconst`:
`BREAK=assignhigh OPTIONS=$PWD/rust/tools/corpus/r5d-options.txt OUT=$PWD/rust/target/r5d-m8 rust/tools/decomp-diff.sh m8`
(and `m500` with `TIMEOUT=120`, and `rust/tools/corpus/r5d-adc.txt`). Results: M8 8 / 8, M500
498 / 499 the reference finishes (0x47a6b0, the known `ActionConditionalExe` miss; 0x4c48d0
never finishes), r5d-adc 215 / 215. Exercise: on M500 the double rules change no reference
output; on r5d-adc they change 23 of the 215 reference outputs (rules on against r1-options), and
ghidra-rs's output changes on the same 23 and matches the reference on all of them (for
example 0x7b8f10: `AddForm` on a call's `j{EDX,EAX}` output, then `RuleDoubleStore`).
R1 check (`r1-options.txt`) rerun on the branch: M500 498 / 499 (0x47a6b0). `cargo test --release`
and `cargo clippy --release --all-targets -- -D warnings` clean.

R5 slices 4 and 5 (branch `m3-r5b`, 2026-11-13). Superseded: "constseq.cc, bitfield.cc and the
`cleanup` rules that read types" in the list above (slice 3, double.cc, is on its own branch).

- Slice 4, `rules/typecleanup.rs`: the `cleanup` rules `addunsigned`, `dumptyhumplate`
  (subflow.cc), `subright`, `floatsigncleanup`, `expandload`, `extensionpush`, `piecestructure`,
  `andstructure`, in the `CLEANUP` table in the C++ order, with `Funcdata::opDestroyRecursive`,
  `opUnlink`, `Datatype::findSmallestContainer` and `TypeFactory::is_char_print`
  (`isCharPrint`). Symbols are not modelled: no equate stops `addunsigned`, `getStructuredType`
  is the varnode's type, `isNameLock` is false. Failing loudly where reached: the CONCAT tree
  rewrite of `piecestructure` (`PieceNode::gatherPieces` onward; proto-partials need
  `VariablePiece`, so `registerProtoPartialRoot` has no caller yet), join addresses in
  `andstructure`, struct sub-types, unions. Not ported: `ptrsubcharconstant` (string detection,
  `StringManager::isString`, S9: three M500 functions reach it, 0x4bff10, 0x74d520, 0x766350),
  so the check still switches it off. `threewaycomp`, `conditionalmove`, `orpredicate` (oppool1)
  are not in the plan's R5 row and stay off.
  Superseded: "Not ported: `ptrsubcharconstant`". Stage S10, slice 1 ports it
  (`rules/typecleanup.rs`, `printc::is_string`) for the strings of the facts; the option files
  of the checks still switch it off (`kept_off` in `tools/r1-options.sh`, which would drop the
  line otherwise), and no check against `decomp_dbg` runs it. (Superseded on `m3-int6`: the
  `kept_off` list is gone, the rule is an `r(...)` entry of `rules/mod.rs` and runs in every
  check whose group `cleanup` is on; see "Integration `m3-int6`".)
- Slice 5, `rules/constseq.rs`, `rules/bitfield.rs`: the groups `constsequence` and `bitfields`
  as far as they run without scopes and bit-field types. `stringcopy` never matches (no local
  symbols), `stringstore` fails at `HeapSequence` (not ported); no type has bit-fields, so the four
  `bitfield_*` transforms never start, and `pull_absorb`/`insert_absorb` fail on their ops (made
  only by those transforms).
- Checks: `r1-options.sh` regenerated (9 `togglerule`s in `r1-options.txt`) and writes
  `r5c-options.txt` (`r5-options.txt` plus `constsequence`, `bitfields`).

```sh
export DECOMP_SKIP_ACTIONS=multicse,shadowvar,condconst
BREAK=assignhigh OPTIONS=$PWD/rust/tools/corpus/r1-options.txt TIMEOUT=120 rust/tools/decomp-diff.sh m500
DECOMP_RAW_EXTRA=1 BREAK=assignhigh OPTIONS=$PWD/rust/tools/corpus/r5-options.txt TIMEOUT=120 rust/tools/decomp-diff.sh m500
DECOMP_RAW_EXTRA=1 BREAK=assignhigh OPTIONS=$PWD/rust/tools/corpus/r5c-options.txt TIMEOUT=120 rust/tools/decomp-diff.sh m500
```

| check (M500, at `assignhigh`) | identical |
|---|---|
| R1 check (`r1-options.txt`), M8 / M500 | 8 / 8; 498 / 499 the reference finishes (0x47a6b0) |
| R5 typed (`r5-options.txt`, types printed), M8 / M500 | 8 / 8; 497 / 498 (0x47a6b0) |
| R5c (`r5c-options.txt`, types printed) | 494 / 498 (99.2 %, bar 95 %): 0x47a6b0 and three functions where `stringstore` reaches `HeapSequence` (0x41f7f0, 0x4c1230, 0x766350) |

Exercise: with the slice 4 rules switched off on both sides as the control, they change 23 M500
reference outputs under the R1 options and 66 under the R5 (typed) options; all 23 and 63 of the
66 are identical, the other three were `ptrsubcharconstant`'s, which is off again. The reference
does not finish 0x4c48d0 (and 0x6b21e0 in the typed runs).

Merged with S8 part one and R5 slice one (2026-11-13). Superseded: the rules-on 481 / 499 above.
The `X & #0x1` constant-type misses were `copySymbol` on an untyped source: every C++ varnode
has a type, so `RuleAndCompare`'s wider mask constant keeps the 1-byte constant's `xunknown1`;
here `ty: None` means "the unknown type of my size", so copying it gave `xunknown4`.
`Funcdata::copy_symbol` now gives the copy the source's own-size type. R5's
`unshared_constant` fix alone did not change them (tested on a scratch copy). The three
sequence-number differences (0x571cc0, 0x746320, 0x74fae0) had the same cause and match now.
Results on the merged binary: M8 8 / 8 in all six S7 runs; M500 rules on (`r1-options`)
498 / 499, the same with create indices, `subvar-options` 498 / 499, `r4-options` 498 / 499,
`r5-options` 497 / 498; types on (`s6-options`, the five pointer rules now on) 493 / 499.
Misses: 0x47a6b0 (the rule-stage miss of every check); with types on, 6 `VariablePiece`
functions (0x402c20, 0x405990, 0x4c0070, 0x62f0d0, 0x757810, 0x7586e0; with the rules on, the
rules remove those overlaps); with R5, 0x6b21e0 (R5's unported `assignPropagatedType`).
Existing bars on the merged binary: R3, subvar and R4 checks 498 / 499, R5 typed 497 / 498,
S3 500 / 500, S4 and S6 499 / 500, S8 rules off 499 / 499 and rule stage 498 / 499.

**R5 slice 2 (in part) and the merge with stack heritage** (branch `m3-r5b`, 2026-11-14).
Superseded: "Left for R5: `RuleLoadVarnode`/`RuleStoreVarnode`" above, and "LOADs and STOREs
through the stack pointer stay unconverted until R5's `RuleLoadVarnode`/`RuleStoreVarnode`" in
"Stack heritage" below. `master` 836d04baee is merged in (one conflict, `tools/r1-options.sh`,
both sides kept).

- `ghidra-rs/src/decomp/rules/stackvars.rs`: the rules `loadvarnode` and `storevarnode` (group
  `stackvars`, the end of `OPPOOL2`): a LOAD or STORE at a constant address, or at the stack
  pointer plus a constant, becomes a COPY from or to a varnode of that space. With them:
  `resolveSpacebaseRelative` (a call's stack offset), `opCollapseIndirectsForCopy`, the
  `stack_store` mark (`VnFlags::STACK_STORE`) read by `ActionDirectWrite`,
  `propagateSpacebaseRef`/`propagateRef` with `getExactPiece` in `infertypes.rs`, and stack
  entries in `characterizeAsParam` (`ParamList::characterize_stack` in `fspec.rs`).
- Open, failing loudly: a
  partly overlapping INDIRECT in `opCollapseIndirectsForCopy`; partial structs, arrays and
  unions in `getExactPiece`. The jump-table partial function runs without the two rules and
  keeps `jumptable::fold_constants`. Superseded: stack parameter trials of a call
  (`ActionActiveParam` with trials) are ported, "Parameter trials of calls (branch `m3-ap`)".
- `tools/r1-options.sh` also writes `tools/corpus/r5s-options.txt` (`r5-options.txt` with
  `stackvars` on).

Checks (from the repository root, types printed, `break start assignhigh`):

```sh
rust/tools/decomp-locked-options.sh void rust/target/stack-lock.txt "int4 a, int4 b"
grep -v 'decompile stackvars off' rust/target/stack-lock.txt > rust/target/lock-sv.txt
grep -v 'decompile stackvars off' rust/tools/corpus/s6-options.txt > rust/target/s6-sv.txt
{ cat rust/tools/corpus/r5s-options.txt; grep '^parse line' rust/target/stack-lock.txt; } > rust/target/r5s-lock.txt
DECOMP_RAW_EXTRA=1 BREAK=assignhigh OPTIONS=rust/target/lock-sv.txt rust/tools/decomp-diff.sh m500
DECOMP_RAW_EXTRA=1 BREAK=assignhigh OPTIONS=rust/target/s6-sv.txt rust/tools/decomp-diff.sh m500
export DECOMP_SKIP_ACTIONS=multicse,shadowvar,condconst
DECOMP_RAW_EXTRA=1 BREAK=assignhigh OPTIONS=rust/target/r5s-lock.txt rust/tools/decomp-diff.sh m500
DECOMP_RAW_EXTRA=1 BREAK=assignhigh OPTIONS=rust/tools/corpus/r5s-options.txt rust/tools/decomp-diff.sh m500
```

| slice 2 check (`stackvars` on) | M8 | M500 |
|---|---|---|
| stack-lock options (every prototype locked, rules off) | 8 / 8 | 473 / 499 |
| S6 options (unlocked, rules off) | 8 / 8 | 499 / 499 |
| R5 options plus the locks (rules and types on, every prototype locked) | 6 / 8 | 323 / 498 |
| R5 options (`r5s-options.txt`: rules and types on, unlocked) | 3 / 8 | 132 / 498 |

Every miss that is not listed is a loud "not implemented" error. Stack-lock options: 26 misses
(16 parameter trials of a call that stays unlocked, mostly indirect calls; 9 "a piece of a locked
stack parameter"; 1 the load-guard value-set error). S6 options: no miss among the 499 the
reference finishes. R5 options plus the locks: 171 loud (125 parameter trials, 32 pieces of a
locked stack parameter, 14 heritage errors), 0x47a6b0 (the rule-stage miss of every check), and
5 silent differences with one cause, not traced: at a call, the INDIRECT for the stack slot
`s0xfffffffc` is an indirect creation (`= [create]`) on the reference and an ordinary INDIRECT
of `ECX(i)` here (0x5cc020, 0x5cee30, 0x5d1dd0, 0x5da930, 0x5db590). R5 options unlocked: 350
parameter trials, 17 heritage errors, 0x47a6b0; M8 fails on the trials in 5 of 8, and with the
locks in 2 of 8 (0x4042e0, 0x73a340). The reference does not finish 0x4c48d0 (nor 0x6b21e0 with
the R5 options). Found by these checks and fixed: `ParamEntry::justifiedContain` had no stack
entries, so `possibleInputParam` was false for a stack parameter of the function, its INDIRECT
at a call lost `addrforce` in `ActionDeadCode` and was removed (26 functions of the S6-options
check).

Every older bar was rerun on the merged binary (M8 8 / 8 in all 26 checks, M500 unchanged in all 28: no bar fell), and the stack check, S4, S6 unlocked and callees, `r1-options`, R5 typed, S7 with `s6-options` and the S8 rule stage again on the final binary, unchanged. The table of every bar is in `docs/plans/m3-decompiler.md`, "R5 slice 2".

**R5 review fixes** (branch `m3-r5b`, 2026-11-14; superseded: "paused before the final pass finished": the full pass ran on `m3-int`, "Integration of `m3-tail` and `m3-r5b`" below; see
"Not rerun" below). Superseded: in "R5 slice 3" above, "Not modelled: symbol entries
(`getSymbolEntry` is null: `isAddrTiedContiguous` tests storage only)" and the description of
`ActionParamDouble`; in "R5 slices 4 and 5", "`stringcopy` never matches (no local symbols)";
in "R5 slice 2", "5 silent differences with one cause, not traced".

- `ActionLikelyTrash` (`coreaction.rs`): `countMarks` is ported (`count_marks`: an input of a
  MULTIEQUAL or PIECE counts when it is marked or a chain of INDIRECTs leads back to a marked
  varnode or to the op itself), and the test `isTypeLock() || isNameLock()` (`name_locked`).
  `countMarks` was the cause of the 5 silent differences of the slice 2 check (0x5cc020,
  0x5cee30, 0x5d1dd0, 0x5da930, 0x5db590): all 5 are identical now with `r5s-lock.txt`.
- `ActionParamDouble` (`rules/double/mod.rs`, `param_double`): the locked-function branch is
  ported (the half-size SUBPIECEs of a primitive locked parameter of at least the default size
  get `precislo` / `precishi`, with `Datatype::isPrimitiveWhole` as `primitive_whole`); the
  join search runs only for a call with neither trials nor a locked prototype; the first branch
  (splitting a stack trial that is a PIECE: `checkInputSplit`, `ParamActive::splitTrial`) is a
  loud error. Still erroring: the join itself (`checkInputJoin` / `doInputJoin`).
- Symbol entries in the double rules: `rules/double/split.rs` `same_symbol` is the symbol test of
  `RuleDoubleOut::attemptMarking` and `SplitVarnode::isAddrTiedContiguous`, over the symbols
  there are: functions and external references of the global scope
  (`infertypes::query_global(arch, addr, size)`, now with a size) and the locked parameters of
  the function (`locked::param_symbol`, shared with `merge.rs` and `ActionLikelyTrash`).
- `rules/constseq.rs` `string_copy`: a character copied into a locked parameter (the local
  scope's only symbols, `ScopeLocal::queryContainer`) is a loud error (`StringSequence` is not
  ported); it returned 0 before.
- `fspec.rs`: `ParamEntry::justifiedContain` for stack entries is one helper
  (`ParamEntry::stack_justified`) with the C++'s wrapping offsets; an exclusion entry
  (`alignment == 0`) returns the offset into the entry, not 0.
- No panic on bad input: wrapping last-byte offsets in `opCollapseIndirectsForCopy`
  (`rules/stackvars.rs`), a checked size difference in `convertZextToPiece`
  (`rules/typecleanup.rs`).
- `heritage.rs` `abort_spacebase_relative`: the placeholder's LOAD goes only when the
  placeholder is in the unique space (`IPTR_INTERNAL`), not in any SLEIGH space.
- Removed: `has_bitfields()` in `rules/bitfield.rs` (a constant `false`). Kept:
  `sub_right_op` and `dumpty_hump_late_op` in `rules/typecleanup.rs`, which the unit tests call
  (no `Arch` can be built there).
- New check: `tools/r1-options.sh` also writes `tools/corpus/r5dt-options.txt`
  (`r5-options.txt` with `doubleload`, `doubleprecis` on: the double rules with types), run
  unlocked, with every prototype locked, and locked with `stackvars` on:

```sh
{ cat rust/tools/corpus/r5dt-options.txt; grep '^parse line' rust/target/stack-lock.txt; } > rust/target/r5dt-lock.txt
grep -v 'decompile stackvars off' rust/target/r5dt-lock.txt > rust/target/r5dt-lock-sv.txt
export DECOMP_SKIP_ACTIONS=multicse,shadowvar,condconst
DECOMP_RAW_EXTRA=1 BREAK=assignhigh OPTIONS=rust/tools/corpus/r5dt-options.txt rust/tools/decomp-diff.sh m500
DECOMP_RAW_EXTRA=1 BREAK=assignhigh OPTIONS=rust/target/r5dt-lock.txt rust/tools/decomp-diff.sh rust/tools/corpus/r5d-adc.txt
DECOMP_RAW_EXTRA=1 BREAK=assignhigh OPTIONS=rust/target/r5dt-lock-sv.txt rust/tools/decomp-diff.sh rust/tools/corpus/r5d-adc.txt
```

| typed double-rule check (types printed) | M8 | r5d-adc (215) | M500 |
|---|---|---|---|
| `r5dt-options.txt`, unlocked | 8 / 8 | 215 / 215 | 497 / 498 (0x47a6b0) |
| plus the locks (`int4 a, int4 b`) | 8 / 8 | 209 / 215 | not run |
| plus the locks and `stackvars` | 6 / 8 | 143 / 215 | not run |

Every miss on r5d-adc and M8 is a loud "not implemented" error, none a silent difference: with
the locks, 6 load-guard value-set errors (0x895f60, 0x9995b0, 0x9e94a3, 0x9e962c, 0x9e9762,
0x9e98c3); with `stackvars` too, 52 parameter trials, 12 pieces of a locked stack parameter and
8 load-guard errors (M8: 2 parameter trials). On M500 the reference does not finish 0x4c48d0
and 0x6b21e0; they count as different, so "/ 498" is of the functions the reference finishes.

Bars on the binary of this commit (M500; M8 is 8 / 8 in all 30 checks without `stackvars`, and
6 / 8, 6 / 8, 3 / 8 in the three with it, as before):

| check | README number | this commit |
|---|---|---|
| stack check, S7 print with `stack-lock.txt` | 498 / 499, 492 / 499 | 498 / 499, 492 / 499 |
| `funclink`, `heritage`, `paramdouble` | 500 / 500 each | 500 / 500 each |
| S4, S6 unlocked, locked `void`, locked `int4`, callees | 499 / 500 each | 499 / 500 each |
| R1/R2/R3, subvar, R4 | 498 / 499 each | 498 / 499 each |
| R5 untyped, R5 typed | 497 / 498 each | 497 / 498 each |
| S7 `r1-options` (also with create indices), `subvar-options`, `r4-options` | 498 / 499 each | 498 / 499 each |
| S7 `r5-options` | 497 / 498 | 497 / 498 |
| S7 `s6-options` (also with create indices) | 493 / 499 | 493 / 499 |
| S8 rules off, S8 rule stage | 499 / 499, 498 / 499 | 499 / 499, 498 / 499 |
| R5c (`r5c-options`) | 494 / 498 | 494 / 498 |
| R5d (`r5d-options`) | 498 / 499 | 498 / 499 |
| R5d on `r5d-adc.txt` | 215 / 215 | not rerun |
| S3 switch corpus | 1,947 / 2,050 | not rerun |
| slice 2: stack-lock options with `stackvars` | 473 / 499 | not rerun |
| slice 2: S6 options with `stackvars` | 499 / 499 | not rerun |
| slice 2: R5 options plus the locks | 323 / 498 | not rerun (the 5 silent differences rerun: 5 / 5 identical) |
| slice 2: R5 options unlocked (`r5s-options.txt`) | 132 / 498 | not rerun |

No bar that ran fell. Not rerun: the pass was stopped before the last eight M500 runs (superseded: every row was rerun on `m3-int`, and the counts below are recounted there, "Integration of `m3-tail` and `m3-r5b`"). Open
from the review: the slice 2 counts above do not add up ("323 / 498" with 171 + 1 + 5 misses,
"132 / 498" with 350 + 17 + 1) and were not recounted: the misses very likely include the two
functions the reference does not finish, which `decomp-diff.sh` counts as different, but that
needs the rerun. The locked branch of `ActionParamDouble` and the symbol tests changed no
output of a check that ran; no unit test covers them. `cargo test --release` 89 tests,
`cargo clippy --release --all-targets -- -D warnings` and `cargo fmt --check` clean.

### Stack heritage (slice one, branch `m3-stack`)

The stack space is heritaged from pass 1 on (`heritage.rs`, `heritage_guard.rs`, `varmap.rs`).
Locked stack parameters of the decompiled function are now supported (S6 failed on them).
Check, with every function and callee locked:
`tools/decomp-locked-options.sh void target/stack-lock.txt "int4 a, int4 b"`, then
`DECOMP_RAW_EXTRA=1 BREAK=assignhigh OPTIONS=target/stack-lock.txt tools/decomp-diff.sh m8`
(M8 8 / 8; M500 496 / 499, 319 reference outputs with stack SSA varnodes; misses 0x4919f0,
shared by every M500 check, 0x4098c0, sequence numbers, and 0x40ad80, the load-guard error).
Bars held: S4 and the four S6 checks 498 / 500, paramdouble 500 / 500, switch corpus
1,947 / 2,050, r1 / subvar / r4 498 / 499. LOADs and STOREs through the stack pointer stay unconverted until R5's
`RuleLoadVarnode`/`RuleStoreVarnode`. Not ported, fails loudly: the load-guard value-set
analysis, revisited markers, the dead-code restart, `ActionRestructureVarnode`. Details and
the M500 numbers in `docs/plans/m3-decompiler.md`, "Stack heritage". (Superseded:
`ActionRestructureVarnode` is ported, for the partial function of jump-table recovery on
branch `m3-aliasupdate` and for the `decompile` root in "Local symbols". Superseded: "the
load-guard value-set analysis" in that list, and the "load-guard error" of 0x40ad80 above; see
"Value-set analysis and the stack guards".)


Review fixes and merges (2026-11-14). 0x4098c0 is fixed: the heritage location map rebuilt a
stored stack index as a SLEIGH space, so stack ranges counted as new at every pass. Also:
`split_uses` leaves the original op as the C++ does, touching ranges of the local scope stay
apart, and three more unported cases fail loudly (a call's locked stack return value,
`RulePtrArith` into a locked struct/union/array stack parameter, `StackAffectingOps` while a
STORE guard exists). The merge tests of S7 read the symbols of locked parameters
(`high_symbol` in `decomp/merge.rs`: different symbols never merge, two name-locked highs do
not merge speculatively); the S7 print with `target/stack-lock.txt`
(`BREAK=inputprototype`) is M8 8 / 8, M500 492 / 499 (6 `VariablePiece` functions and
0x40ad80), the same count as before those tests, so M500 has no case where they decide.
Superseded: "symbols" in stage S7's not-ported list (for locked parameters only) and
"the STORE guards of `StackAffectingOps`" there (now a loud error).

Merged with master 9272a2f7d4 (S7 part one, S8 part two) and every bar rerun on the merged
binary: M8 8 / 8 in all 24 checks; M500 stack check 498 / 499 (miss 0x40ad80; superseded:
496 / 499 above), `funclink` and `heritage` 500 / 500, S3 paramdouble 500 / 500, switch corpus
1,947 / 2,050, S4 and the four S6 checks 499 / 500 each (0x4c48d0, which the reference does not
finish; superseded: 498 / 500 above, measured before `nodejoin`), `r1-options`, subvar and R4
498 / 499 each, R5 497 / 498 with and without types, S7 498 / 499 with `r1-options` (also with
create indices), `subvar-options` and `r4-options`, 497 / 498 with `r5-options`, 493 / 499 with
`s6-options` (also with create indices), S8 499 / 499 rules off and 498 / 499 rule stage. No
bar fell; the table is in `docs/plans/m3-decompiler.md`, "Stack heritage".
### Tail (in part): `latedonothing`, prototypes, `mapglobals`, `finalstructure`

- `coreaction.rs`: `ActionLateDoNothing` (`late_do_nothing`, `removingCreatesRedundancy`);
  `ActionDoNothing` now sets and clears the delayed mark (`BlockBasic::delayed_donothing`) and
  `isDoNothing` tests switch predecessors as the C++ does. `ActionOutputPrototype`
  (`output_prototype`), `ActionInputPrototype` (`input_prototype`), `ActionMapGlobals`
  (`map_globals`, with `coverVarnodes`).
- `fspec.rs`: the input side of `ParamListStandard` (`find_entry`, `fillin_map_input` with
  `buildTrialMap`, `forceExclusionGroup`, `forceNoUse`, `forceInactiveChain`), `ScoreProtoModel`
  and `Models::select_model` (a merged model keeps its `members`).
- `scope.rs`, wired as `Funcdata::symtab` (a global and a local scope per function): symbols,
  map entries (one `rangemap.rs` map per space, in the C++ order), categories, `print map`, the
  default variable names (`build_variable_name`).
- `namevars.rs`: `ActionNameVars` (`linkSymbol` with conflict entries, `linkSymbolReference` for
  the stack, `getNameRepresentative`, `hasName`, `buildDefaultName`, `assignDefaultNames`).
- `finalstructure.rs`: `ActionFinalStructure` (`orderBlocks`, `finalizePrinting` for while-do and
  switch blocks, `scopeBreak`, `markUnstructured`, `markLabelBumpUp`), `moveRespectingCover`,
  `markExpression`, the switch's `CaseOrder` list (`structure.rs` calls `grab_cases` in
  `new_switch`); `SBlock` has `goto_type` and `cases`. A switch with cases fails loudly: its
  labels need `switchnorm` (`recoverLabels`), not ported.
- Console: `print map` (the local scope of the current function).
- Check devices (same in `decomp-ref.patch`): `DECOMP_TREE_EXTRA=1` (`print tree block` also
  shows the final-structure flags, goto types, switch cases and for-loop ops) and
  `DECOMP_MAP_EXTRA=1` (`print map` also shows the prototype, each parameter's name and storage,
  the return storage, the attributes of each symbol and the global data symbols).
- Tools: `decomp-diff.sh` takes `DECOMP` and `GHIDRA_RS` from the environment, `decomp-ref.sh`
  takes `DECOMP_BUILD` and `JOBS`; `r1-options.sh` also writes `s8-t-options.txt`,
  `tail-r-options.txt` and `tail-t-options.txt`.
- The leaves `restructure_varnode` and `mapped_local_sync` carry their C++ names
  (superseded: `restructurevarnode`, `mappedlocalsync`; and "unported": see "Local symbols").

Checks and commands: docs/plans/m3-decompiler.md, "Tail". Results (M8; M500 of the functions the
reference finishes): prototypes and globals 8 / 8, 498 / 499 (99.8 %) (rules on) and 8 / 8, 493 / 499 (98.8 %) (types
on); `latedonothing` 8 / 8, 498 / 499 (99.8 %) and 8 / 8, 493 / 499 (98.8 %); `finalstructure` 7 / 7, 494 / 495 (99.8 %) and
7 / 7, 489 / 495 (98.8 %) (switch functions do not finish on the reference with `switchnorm` off).
Existing bars on the final binary: R1/R3, subvar and R4 checks 498 / 499, R5 typed 497 / 498, S7 rules on 498 / 499 and types on 493 / 499, S8 rules off 499 / 499 and rule stage 498 / 499, S3 paramdouble 500 / 500, S4 and S6 499 / 500, switch corpus 1,947 / 2,050: all unchanged. Superseded: the switch corpus measured again on `m3-int` after `switchnorm` and the review fixes, 1,947 / 2,050, unchanged (`checkUnrolledGuard` and the empty-range stop of `findSmallestNormal` could have moved it); every bar: "Integration of `m3-tail` and `m3-r5b`" below.
Every bar was rerun on the final binary, M8 and M500 (stack check, S1 to S8, R1 to R5, the switch
corpus, the tail and names checks): none fell. The table is in docs/plans/m3-decompiler.md, "Tail".
Open before S9: `setcasts`, and finishing the case labels (superseded: `setcasts` is ported,
section "Casts" below). Superseded: "`switchnorm`, not
started" and "a switch with cases fails loudly" above: `switchnorm` and the case labels of
`finalstructure` are ported (`jumptable.rs`, `finalstructure.rs`) but the work is paused before
its full verification: M8 8 / 8 in the four switch checks, switch corpus `finalstructure`
1,937 / 2,004 (rules on) and 1,929 / 2,004 (types on), `switchnorm` rules on 1,943 / 2,004;
M500 and the other bars were not rerun on that tree (superseded: verified on `m3-int`, every bar rerun, `switchnorm` types on 1,947 / 2,004, M500 in all four; "Integration of `m3-tail` and `m3-r5b`" below). State and next steps:
docs/plans/m3-decompiler.md, "Tail", "Switch case labels". Superseded: `namevars` in this list (ported: names check, `print map` after
`namevars`, M8 8 / 8 and 8 / 8, M500 498 / 499 (99.8 %) rules on and 493 / 499 (98.8 %) types on).

Merged with master 836d04baee (stack heritage): `print map` and the use-limit test of
`inputprototype` read the local scope's real ranges (`Funcdata::localmap`), and `restrictlocal`
runs in the prototype checks on both engines. The six tail checks are unchanged on the merged
binary (numbers above); details in docs/plans/m3-decompiler.md, "Tail".

Review fixes (same section of the plan): the scopes' maps are a port of `rangemap`, a symbol
without a use limit is address-tied, a size-locked output is ported, the compiler spec's
`<global>` ranges are read (x86's `MXCSR` is a global), `orderBlocks` uses the `std::sort` port,
the do-nothing loop warning is recorded, unsupported parameter-list forms fail loudly, and the
prototype checks compare parameter names, storage and symbol attributes. The six tail checks
are unchanged after them, and the 24 other bars are 8 / 8 on M8.

Second review (seven findings, listed in the plan): `RangeMap::insert` keeps the C++ quirk of a
record that is in the multiset twice (`tools/rangemap_ref.cc` prints the C++ template's order),
`namevars` fails loudly on a function with locked parameters (their symbols are not in the
local scope), the symbol offset wraps to the space, `overrideSizeLockType` has its errors, an
indirect jump made a call is warned about. One finding was not real: a named parameter of a
locked callee is name-locked in the C++ (`ParameterSymbol::setTypeLock`), and the reference
renames the arguments as ghidra-rs does (M8 with locked `__fastcall` callees: 5 / 8 identical,
three fail loudly in `deindirect`). The eight tail checks are unchanged on M8; on M500 the
three finished so far are unchanged (prototypes and globals, names with rules on).

### Integration of `m3-tail` and `m3-r5b` (branch `m3-int`, 2026-11-14)

Both paused branches merged into one tree and verified by one pass. Superseded: the "paused"
and "not rerun" notes of "R5 review fixes" above and of this section ("work is paused before its
full verification", "M500 and the other bars were not rerun"); the numbers below replace them.

- Merge: `m3-tail` first, then `m3-r5b`. Conflicts: `Funcdata` keeps both new fields
  (`symtab`, `double_precis_on`); `infertypes::query_global` takes `m3-r5b`'s size argument
  (`queryContainer(addr, size)`) and `m3-tail`'s two callers in `coreaction.rs` pass 1 (the
  C++ `queryContainer(addr, 1)` of `getSymbolEntry`); `Entry`'s fields stay `pub(crate)` for
  them; the `ParamTrial::UNREF` both sides added is kept once; `r1-options.sh` writes all
  fifteen files of both. `r1-options.sh` rerun: `tail-r-options.txt` and `sw-r-options.txt`
  lose eight `togglerule` lines for the rules `m3-r5b` ported.
- Review fixes of the switch work: `fold_in_one_guard` / `fold_in_guards` (`jumptable.rs`) find
  the table again by its BRANCHIND after `push_branch` (its `structure_reset` drops dead tables
  and moves the others; the C++ keeps a `JumpTable *`), and `switch_norm` reads the table count
  each time round as `ActionSwitchNorm::apply` does; `splice_block` (`block.rs`) clears
  `f_flip_path`, the mark and the do-nothing flags (`bl->flags = fl1 | fl2`); `print tree block`
  fails when a case's labels cannot be read (`printCaseExtra` throws) instead of printing none.
  None changed a number below.
- `tools/bars.sh`, `tools/lock-options.sh`, `tools/corpus/switch.txt`: see "Every check at once".

The pass: every check on M500, r5d-adc and the switch corpus, `JOBS=12` on the 12-thread
machine with nothing else heavy running: 9 h 22 min (M500 8 h 38 min, r5d-adc 1 min, switch
corpus 44 min), with `TIMEOUT=600`. Most of the M500 time went to one function, 0x4c48d0: alone
the reference takes 485 s on it and ghidra-rs 599 s, with identical output (3,895,241 lines of
the S7 types-on print), not a hang; each check waited for both runs of it at its end. With 600 s
the reference finishes it, so the pass's counts are of 500 where the bars above are of 499; the
table gives both. The default of `bars.sh` is 120 s again, as for every bar above; at 120 s an
M500 check takes about 4 to 5 minutes. After the review fixes the four switch checks (M8, M500
at 120 s, switch corpus) and the S3 switch bar were rerun, and the M8 gate and the M500 checks
that read the flags `splice_block` now clears: M8 all 45 as before; M500 S4 499 / 499, S8 rule stage
498 / 499, `latedonothing` 498 / 499 and 493 / 499, `finalstructure` 494 / 495 and 489 / 495, prototypes rules
on 498 / 499, names types on 493 / 499: each equal to its bar above (4.6 minutes per M500 check).

| check | before (README or branch) | pass (`TIMEOUT=600`) | difference |
|---|---|---|---|
| M8, all 45 checks | 8 / 8; `fs-*` 7 / 7; `r5dtlocksv`, `r5slock` 6 / 8; `r5s` 3 / 8 | the same | none |
| stack check, S7 print with `stack-lock.txt` | 498 / 499, 492 / 499 | 499 / 500, 493 / 500 | 0x4c48d0 finishes, identical |
| `funclink`, `heritage`, `paramdouble` | 500 / 500 each | 500 / 500 each | none |
| S4, S6 unlocked, locked `void`, `int4`, callees | 499 / 500 each | 500 / 500 each | 0x4c48d0 identical |
| R1/R2/R3, subvar, R4 | 498 / 499 each | 499 / 500 each | 0x4c48d0 identical; miss 0x47a6b0 |
| R5 untyped, typed | 497 / 498 each | 498 / 499 each | 0x4c48d0 identical |
| S7 `r1`, `r1` with create indices, `subvar`, `r4` | 498 / 499 each | 498 / 500 each | 0x4c48d0: ghidra-rs past 600 s |
| S7 `r5-options` | 497 / 498 | 497 / 499 | 0x4c48d0: ghidra-rs past 600 s |
| S7 `s6-options` (also with create indices) | 493 / 499 | 494 / 500 | 0x4c48d0 identical |
| S8 rules off, rule stage | 499 / 499, 498 / 499 | 500 / 500, 499 / 500 | 0x4c48d0 identical |
| R5c | 494 / 498 | 495 / 499 | 0x4c48d0 identical |
| R5d, R5d on r5d-adc | 498 / 499, 215 / 215 | 499 / 500, 215 / 215 | 0x4c48d0 identical |
| R5dt; on r5d-adc | 497 / 498; 215 / 215 | 498 / 499; 215 / 215 | 0x4c48d0 identical |
| R5dt locked; on r5d-adc | M500 not run; 209 / 215 | 482 / 499; 209 / 215 | new on M500 |
| R5dt locked with `stackvars`; on r5d-adc | M500 not run; 143 / 215 | 328 / 499; 143 / 215 | new on M500 |
| slice 2: stack-lock options with `stackvars` | 473 / 499 | 474 / 500 | 0x4c48d0 identical |
| slice 2: S6 options with `stackvars` | 499 / 499 | 500 / 500 | 0x4c48d0 identical |
| slice 2: R5 options plus the locks | 323 / 498 | 328 / 499 | the 5 `countMarks` functions now match |
| slice 2: R5 options unlocked | 132 / 498 | 132 / 499 | 0x4c48d0 fails loudly |
| prototypes and globals, rules on / types on | 498 / 499, 493 / 499 | 498 / 500, 494 / 500 | rules on: 0x4c48d0 past 600 s |
| names, rules on / types on | 498 / 499, 493 / 499 | 498 / 500, 494 / 500 | the same |
| `latedonothing`, rules on / types on | 498 / 499, 493 / 499 | 498 / 500, 494 / 500 | the same |
| `finalstructure` (`switchnorm` off), rules on / types on | 494 / 495, 489 / 495 | 494 / 496, 489 / 496 | 0x4c48d0: ghidra-rs past 600 s |
| S3 switch corpus (`paramdouble`) | 1,947 / 2,050 | 1,947 / 2,050 (1,947 / 2,004 the reference finishes) | none |
| switch `finalstructure`, rules on: M500; switch corpus | not run; 1,937 / 2,004 | 498 / 500; 1,937 / 2,004 | none |
| switch `finalstructure`, types on: M500; switch corpus | not run; 1,929 / 2,004 | 494 / 500; 1,929 / 2,004 | none |
| `switchnorm`, rules on: M500; switch corpus | not run; 1,943 / 2,004 | 496 / 500; 1,943 / 2,004 | none |
| `switchnorm`, types on: M500; switch corpus | not run; stopped | 500 / 500; 1,947 / 2,004 | new |

No bar fell. After the review fixes, at 120 s: the four switch checks M8 8 / 8 each; M500
498 / 499, 493 / 499, 495 / 499, 499 / 499 (rules on and types on `finalstructure`, then
`switchnorm`; 0x4c48d0 counts as not finished); switch corpus 1,937, 1,929, 1,943, 1,947 of
2,004; S3 switch bar 1,947 / 2,050. The S3 bar could have moved with two changes to the guard
analysis of `m3-tail`, `checkUnrolledGuard` and the stop of `findSmallestNormal` at an empty
range (`find_smallest_normal`, as the C++); it did not.

How the slice 2 rows count (the open item of "R5 review fixes" above): the summary line of
`bars.sh` counts only the functions the reference finishes, and splits the misses into loud
(ghidra-rs printed an error), silent and timeout. R5 options plus the locks: 499 finished
(0x6b21e0 is not finished with the R5 options), 328 identical, 170 loud, 1 silent (0x47a6b0):
328 + 170 + 1 = 499. R5 options unlocked: 132 + 366 loud + 1 silent = 499. The old "323 / 498"
and "132 / 498" were `decomp-diff.sh`'s count over all 500, where a function the reference does
not finish counts as different unless both engines print the same thing; their miss lists also
mixed the error kinds.

Misses explained, none new from the merge (each is in a branch's own miss list):

- `switchnorm` rules on, M500: 0x47a6b0 (the rule-stage miss of every check) and 0x48a430,
  0x5c5940, 0x6b3730; switch corpus: also 0x8d8f40, 0x8eabe0, 0x8ead90 (the "3 not looked at"
  of the plan) and 0x5a3c30 (conditional execution, known). The six differ only in the type of
  the INDIRECTs on an import slot (`r0x00b05370<code() *>` on the reference, `<xunknown4>`
  here). The C++ gives a varnode its global symbol's type when it is made (`newVarnode` ->
  `setSymbolProperties`); ghidra-rs does it lazily (`infertypes::symbol_types`, before each type
  inference pass and before merging), and this check is the only one that prints types, with
  `typerecovery` off, at a break (`returnsplit`) before both. At `inputprototype` the three M500
  functions are identical. Open: set the symbol properties when a varnode is made.
  (Superseded: `print raw` applies the symbol types first and the six are identical; see the
  end of "C printing, slice 5".)
- switch `finalstructure` types on: 0x4f3366 keeps a call's join output (`j{EDX,EAX}`) the
  reference does not have; in `m3-tail`'s list, not traced. Open.
- The 57 switch-corpus functions that differ at flow time (S3), `VariablePiece` (7 rules on, 15
  types on), 0x1cdee32 and 0x1cdf675 (128-entry flow-time tables): as in the plan, "Switch case
  labels".
- Open: ghidra-rs is about 1.25 times slower than the reference on 0x4c48d0 (merging and dead
  code over a function whose print has 3.9 million lines); with `TIMEOUT=600` it passes the
  limit when the machine is loaded.

`cargo test --release`: 105 tests (86 unit tests in the library, 19 in `tests/`: the count of
`#[test]` functions: `m3-tail` had 76 + 19, `m3-r5b` 70 + 19, so its "89" was the total and `m3-tail`'s "76" the library only), `cargo clippy --release
--all-targets -- -D warnings` and `cargo fmt --check` clean.

### Parameter trials of calls (branch `m3-ap`, 2026-11-14)

Slice 1: `ActionActiveParam` checks the trials of each call (`coreaction.rs`):
`FuncCallSpecs::checkInputTrialUse` (stack trials: `AliasChecker` in `varmap.rs`, the local
range, a callee-popped extrapop, then `AncestorRealistic` and `ancestorOpUse`; register trials
with conditional execution allowed), `finalInputCheck` and the pass counting. Also ported for it:
`Funcdata::checkCallDoubleUse` with trials (reading a finished call's kept trials,
`CallSpec::kept_input`, as the C++ reads `activeinput` after `clearActiveInput`),
`ParamActive::getTrialForInputVarnode` (by position, as the C++), the type-locked input case of
`ancestorOpUse`, and the sub-call stack-hole rule of `forceInactiveChain` (`recoversubcall`).
Check device (same in `decomp-ref.patch`): `DECOMP_TRIALS_EXTRA=1` makes `print raw` end with
each call whose input recovery is active, its passes, maximum, `isFullyChecked`,
`needsFinalCheck`, and each trial's space, offset, size, slot and flags.

```sh
# the trials before the first two activeparam passes, R5 options with stackvars
DECOMP_TRIALS_EXTRA=1 DECOMP_SKIP_ACTIONS=multicse,shadowvar,condconst BREAK=activeparam CONTINUES=1 \
  OPTIONS=rust/tools/corpus/r5s-options.txt rust/tools/decomp-diff.sh m500
```

Slice 1 alone still fails loudly where a call with trials is fully checked (rebuilding its
inputs is slice 2), so the print compares before the first two passes: M8 8 / 8, M500 446 / 500,
the 54 others are 53 loud (36 `ActionParamDouble` splitting a stack trial that is a PIECE, 17
heritage indexed stack loads; unported paths reached after the first pass) and 0x47a6b0 (a block
order difference that master has at the same point, before any trial). In every one of the 54
the trial lines ghidra-rs prints match the reference's. M8 gate (`bars.sh`, 45 checks) unchanged.
Superseded (slice 2): a fully checked call with trials no longer fails.

Slice 2: once a call's trials are fully checked, `FuncProto::resolveModel` (a merged model
becomes the member `selectModel` scores best), `deriveInputMap` (`ParamListStandard::fillinMap`,
`fillin_map_input`, the same code as the function's own inputs) and
`FuncCallSpecs::buildInputFromTrials` (the used trials become the call's inputs: a new varnode
for an unreferenced trial, a SUBPIECE before the call for a varnode bigger than its trial, the
stack range of a stack parameter `markNotMapped`; the used trials renumbered and kept). Failing
loudly: a locked varargs call (`sortFixedPosition`), a stack trial of a call whose stack offset
is unknown, and `getTrialForInputVarnode` past the end of a call's trials (the C++ reads past the
end; an empty list is taken as no match, as before).

| check (`bars.sh`, M500, of the functions the reference finishes in 120 s) | before | slice 2 |
|---|---|---|
| `r5s` (R5 options with `stackvars`, unlocked) | 132 / 499 (366 loud) | 446 / 499 (52 loud, 1 silent) |
| `r5slock` (the same with every prototype locked) | 328 / 499 (170 loud) | 450 / 498 (47 loud, 1 silent) |
| `r5dtlocksv` (typed double rules, locked, `stackvars`) | 328 / 499 (170 loud) | 451 / 499 (47 loud, 1 silent) |

Every remaining loud miss is a path that was not reached before: `ActionParamDouble` splitting a
stack trial that is a PIECE (36 in `r5s`), heritage's indexed stack LOAD that may read an
address-tied range (16 in `r5s`), a piece of a locked stack parameter (31 in `r5slock`). The
silent miss is 0x47a6b0, the rule-stage miss of every check. 0x6b21e0 is not finished by the
reference (and in this `r5slock` run 0x4c48d0, 120 s under load).

Regression guards, M500 at `bars.sh`'s 120 s (0x4c48d0 counts as not finished; the integration
pass used 600 s): `r5c` 494 / 498 (3 HeapSequence, 0x47a6b0; 0x6b21e0 not finished by the
reference this run), `r5d` 498 / 499, `s7r` 498 / 499, `s8r` 498 / 499, `fs-r` 494 / 495, `fs-t`
489 / 495 (6 `mergeAddrTied` VariablePiece), `swsn-r` 495 / 499 (0x47a6b0 and the three lazy
global-type misses): every miss is one the integration pass lists. M8 gate: all 45 checks
identical (`r5s`, `r5slock`, `r5dtlocksv` now 8 / 8, were 3, 6, 6). Not run: the other M500
checks, r5d-adc and the switch corpus.

Review fixes (same branch):
- A locked call holds trials too: `funcLinkInput` (`locked::func_link`) and `commitNewInputs`
  (`lateres.rs`) register one active trial per parameter with storage (none for a parameter
  without storage, as the C++), kept in `CallSpec::kept_input` with recovery off; the placeholder
  slot `commitNewInputs` sets while recovery is on is recorded. `checkCallDoubleUse`'s
  same-function test reads them.
- `markNotMapped` widens the parameter extent before looking at symbols (the C++ order), and
  fails loudly over a local symbol other than a locked parameter (the C++ removes it, or keeps
  the range for a `fake_input`); ghidra-rs's local scope holds none while it runs.
- `AncestorRealistic`'s COPY walk: `isStoreUnmapped` cannot hold there (only STOREs carry it);
  `PcodeOp::isIncidentalCopy` needs a call fixup declaring `incidentalcopy`, which the cspec
  reader now refuses loudly.
- The callee-pop test wraps `size - 1` as the C++ `int`.
- Local and parameter ranges are the defaults (`ProtoModel::decode` already refuses
  `<localrange>` and `<paramrange>`; Superseded, MIPS-4: `<localrange>` is read); without a model the alias boundary is `deriveBoundaries`'
  0x1000000 and a stack trial fails loudly (`getLocalRange` needs the model).
- Open: the C++ wraps an error inside `ActionActiveParam` as "Error processing <name> called at
  <seq>: ..."; ghidra-rs prints the inner message, so such an error differs in text (it is loud
  on both sides).

After the fixes: M8 gate all 45 identical; M500 `r5s` 446 / 499, `r5slock` 450 / 498,
`r5dtlocksv` 450 / 498 (the same misses by kind and count as before the fixes; 0x4c48d0 did not
finish on the reference in 120 s this run, it was identical in the earlier one).

### Casts: `setcasts` (branch `m3-cast`, 2026-11-15)

- `cast.rs`: `ActionSetCasts` (`set_casts`: `castInput`, `castOutput`, `insertPtrsubZero`,
  `testStructOffset0`, `isOpIdentical`, `checkPointerIssues`, the PTRADD and PTRSUB undo of
  `apply`), `CastStrategyC` (`castStandard`, `arithmeticOutputStandard`, `intPromotionType`,
  `localExtensionType`, `checkIntPromotionForCompare`/`ForExtension`, `markExplicitUnsigned`,
  `markExplicitLongSize`) and the `getInputCast`/`getOutputToken` overrides of typeop.cc.
- `types.rs`: `getTypedef` (the type a typedef names), `needsResolution`, `isEnumType`, the
  first field of a struct; `varnode.rs`: `unsignedprint` and `longprint`; `opUndoPtradd` takes
  `finalize`; `print raw` prints `(cast)`.
- Fail loudly: union resolution (any data-type that `needsResolution`: union, one-field struct,
  one-element array, a pointer to one), `findTruncation` of a struct or union SUBPIECE, the cast
  rules of SEGMENTOP, INSERT, ZPULL, SPULL. Left out (printer only): `isExtensionCastImplied`,
  `isSubpieceCast`, `isSextCast`, `isZextCast`, `CastStrategyJava`; `startCastPhase` (nothing
  reads it); pointer space attributes (no ported pointer has one).
- Checks (`bars.sh`): `cs-r`/`cs-t`, `print raw` with types at `BREAK=finalstructure`, the
  tail's skipped leaves less `setcasts` (`SC`); `fsc-r`/`fsc-t` and `swfsc-r`/`swfsc-t`,
  `fs-*`/`swfs-*` with `setcasts` on.

Results (M8; M500 of the functions the reference finishes), rules on and types on: `cs` 8 / 8 and
8 / 8, 498 / 499 (99.8 %) and 493 / 499 (98.8 %); `fsc` 7 / 7 and 7 / 7, 494 / 495 (99.8 %) and 489 / 495
(98.8 %), the same as `fs-r`/`fs-t` with `setcasts` skipped; `swfsc` 8 / 8 and 8 / 8, M500 498 / 499 and 493 / 499 (as `swfs-r`/`swfs-t`). Every
miss is one the earlier bars have: 0x47a6b0 (rules on) differs before `setcasts` already, the six
types-on misses are the loud `mergeAddrTied` `VariablePiece` error. The M8 outputs have 6 to 628
CAST ops a function. M8 gate: all 51 checks identical. Not run: the switch corpus with `setcasts`
on, the full M500 pass of the other bars.
### C printing, slice 1 (branch `m3-print1`, 2026-11-15)

`print C` (`IfcPrintCStruct`, `PrintC::docFunction`) prints a straight-line function, ported in
the three layers of the C++:

- `decomp/prettyprint.rs`: `EmitPrettyPrint` over `EmitNoMarkup`. Tokens (strings, breaks,
  group begins and ends, indents, comments) wait in a queue until the breaker knows whether a
  group fits the 100-column line; a break that saves fewer than 10 columns is not taken, an
  overflow raises the indents to half the width, comments refill with three spaces. Unit tests
  pin a short line, a broken expression, an absolute-indent comment and the missing-group error.
- `decomp/printlanguage.rs`: the `PrintLanguage` reverse-Polish stack (`pushOp`, `pushAtom`,
  `pushVn`, `recurse`), `parentheses`, `emitOp`, `opBinary`/`opUnary`, the modifier stack and
  `mostNaturalBase`.
- `decomp/printc.rs`: the `PrintC` tokens and what a straight-line function reaches: the header
  warnings (`emitCommentFuncHeader`, `emitLineComment`), the declaration (return type, a
  prototype model other than the default, the parameters as declarations, `void`), the local
  declarations (`emitScopeVarDecls` on the local scope), the root graph, lists and basic blocks
  (`emitBlockLs`, `emitBlockBasic`), statements of assignments, `*p` loads and stores, direct
  calls, returns and special halts, the arithmetic, logic, shift, comparison and boolean
  operators (a negated comparison prints flipped), integer and boolean constants (a pointer
  constant with its cast), named and unnamed variables (`register_ESP`, `unique0x00017200`),
  pointer and array types in declarations.

Every other construct fails loudly with the C++ name: `BlockIf`, `BlockDoWhile`,
`BlockWhileDo`, `BlockInfLoop`, `BlockSwitch`, `BlockGoto` and the other block kinds, labels,
comments inside the body (warnings at an address), array and field access (`PTRSUB`, `PTRADD`),
the operators not listed (extensions, `SUBPIECE`, `PIECE`, `CALLIND`, `CALLOTHER`, float
conversions, ...), float, character, string, enum and function-pointer constants, equates,
partial symbols and symbols or constants whose data-type needs resolution (`needsResolution`:
a union, a one-element array, a one-field structure, a pointer to one), a global name a local
name hides (a `::` scope prefix), anonymous and function types, locked prototypes. Casts are not
printed yet: `setcasts` (`cast.cc`) is ported separately, so the checks skip it on both engines
and neither prints a cast. Superseded: the blocks, labels, gotos and casts are printed since slice 2
(below, "C printing, slice 2"). Superseded too: array and field access (`PTRSUB`, `PTRADD`), partial symbols and
character constants are printed since slice 3A (below, "C printing, slice 3A").

Checks (`tools/bars.sh`), at `break start prototypewarnings` with `print C`, `setcasts` and the
`localrecovery` leaves skipped on both engines: `pc-r` (rules on, `tail-r-options.txt`) and `pc-t`
(types on, `tail-t-options.txt`); corpora M8, M500 and `tools/corpus/simple.txt` (200 small
functions: every 27th of the 5,443 mercs2 functions at most 32 bytes before the next mapped one).

Older stages fixed on the way, found by silent `print C` differences or by the review
(superseded: "two older stages"):

- `namevars` now links a persistent variable to the global data symbol holding it
  (`linkSymbol` through `queryProperties`), so globals print by name (`iRam0256f88a`) rather
  than as `ram0x0256f88a`. As `findContainer`, the smallest entry holding the first byte wins:
  when a function (one byte) or an external reference (a pointer), kept in `Arch` and not in
  the global scope, is smaller, the variable stays unlinked and the printer fails on it; a
  data symbol of the same size fails loudly in `namevars`.
  With globals linked, `lookForBadJumpTables` renames only a symbol of the local scope to
  `UNRECOVERED_JUMPTABLE`, as the C++ does (renaming the global target cost 18 `nm-r` functions
  on M500 before this).
- `mapglobals` asks whether a varnode is already linked with the varnode's size, as
  `setSymbolProperties` does: a 4-byte varnode at an import's slot is held by the external
  reference, not by the 1-byte function symbol there, so it no longer raises the "Globals
  starting with '_' overlap smaller symbols" header warning the reference does not print.
- Warnings carry their prefix where they are made (`WARNING: `, or `WARNING (jumptable): ` in
  jump-table recovery's partial function), and the warnings the partial function adds are
  carried over to the function, as the C++ comment database the two share keeps them; flow
  records the bad and unimplemented instruction warnings.
- `mergeMultiEntry` fails loudly on a local symbol with several whole entries (none is made
  while `localrecovery` is not ported) instead of doing nothing.

Numbers (functions the reference finishes):

| check | M8 | M500 | simple |
|---|---|---|---|
| `pc-r` | 0 / 7 (loud 7) | 47 / 495 (loud 448, silent 0) | 54 / 194 (loud 140, silent 0) |
| `pc-t` | 0 / 7 (loud 7) | 24 / 495 (loud 471, silent 0) | 34 / 194 (loud 160, silent 0) |

The silent miss of both, 0x1c8c780, was the header warning of a bad instruction, which flow
did not record; `FlowInfo` now records it (and the body warning, so the function fails loudly;; `simple` rerun after it and the review fixes).
The loud misses on M500, `pc-t`: `BlockIf` 376, array or field access 25, comments in the body
20, `PTRADD` 8, `BlockDoWhile` 7, `mergeAddrTied`, `SUBPIECE` and `FLOAT2FLOAT` 6 each, `PTRSUB` and
float constants 4, `INT_ZEXT` 3, `PIECE` 2, `SQRT`, `CALLIND`, `BlockInfLoop` and an anonymous
data-type 1 each; `pc-r`: `BlockIf` 332, an anonymous data-type 40, comments in the body 20,
`FLOAT2FLOAT` 14, `BlockDoWhile` 12, `BlockWhileDo` 10, then 5 or fewer each. Both rerun after the
review fixes (superseded: `pc-t` measured before the flow fix, the same 24 / 495). The checks the
`namevars` and `mapglobals` fixes could move, on M500 after the review fixes: `pg-r` 498 / 499,
`pg-t` 493 / 499, `nm-r` 498 / 499, `nm-t` 493 / 499, as before (the misses: 0x47a6b0 rules on,
the six `VariablePiece` functions types on). The loud misses on `simple`, `pc-t`: `BlockIf` 83, comments in the body 30, array or field
access 15, `INT_ZEXT` 5, `BlockDoWhile` 4, `SUBPIECE`, `PTRADD`, `FLOAT2FLOAT`, `BlockWhileDo`,
`BlockInfLoop` and the `mergeAddrTied` error 3 each, `PTRSUB` 2, `PIECE` and `CALLOTHER` 1; `pc-r`:
`BlockIf` 73, comments 30, an anonymous data-type 13, `INT_ZEXT` 6, then 4 or fewer each. On M8 the
45 older checks are identical as before (8 / 8, `fs-r` and `fs-t` 7 / 7) after the fixes below,
also after the review fixes; `pc-r` and `pc-t` are 0 / 7, all loud (superseded: "all 47 checks
on M8 identical"). Not rerun: the older checks on M500 and the other corpora.

Merged with `m3-cast` on `m3-s9` (2026-11-15): M8 the 51 checks other than `pc-r`/`pc-t` identical, those two 0 / 7, all loud; M500 not rerun on the merge.

### Review fixes and `print C` with casts (branch `m3-s9`, 2026-11-15)

- `checkPointerIssues` warns "Load size is inaccurate" / "Store size is inaccurate", the
  TypeOp name with its first letter upper-cased, as coreaction.cc (superseded: "LOAD size").
- `TypeFactory::getTypePointer` ports `TypePointer::calcSubmeta`: a pointer to a struct that
  does not need resolution, or to a union, gets `SUB_PTR_STRUCT` (4) and orders before a plain
  pointer (6). No check moves: no prelude, options or lock file declares a struct or union
  (`parse line` is the only maker of one), so every pointer of the checks keeps `SUB_PTR`.
- `getInputCast` of CPOOLREF and NEW never casts (typeop.hh); `opUndoPtradd`'s finalize branch
  fails loudly on any type that `needsResolution`, not only a union (`getTypeReadFacing`).
- `print C` prints the `U` of a constant `setcasts` marks `isUnsignedPrint` (cleared when
  printed signed, as `pushConstant`); a constant marked `isLongPrint` fails loudly (the suffix
  depends on the data organization's long size, not ported); a CAST op fails loudly. (Superseded: printed since slice 2.)
- Checks `pcc-r`, `pcc-t` (`bars.sh`): `pc-r`, `pc-t` with `setcasts` on.

Numbers (functions the reference finishes): M8 all 51 checks before `pc-*` identical, `pc-*`
and `pcc-*` 0 / 7 loud. M500 `pcc-r` 10 / 495 (loud 485: `BlockIf` 332, CAST 86, an anonymous
data-type 40, body comments 20; silent 0) against `pc-r` 47 / 495; `pcc-t` 8 / 495 (loud 487:
`BlockIf` 376, CAST 66, body comments 20; silent 0) against `pc-t` 24 / 495. `cs-t` 493 / 499, `fsc-t` and `fs-t` 489 / 495, as
before (the six `mergeAddrTied` `VariablePiece` misses).
Not run: the other M500 type checks (`s6*`, `r5typed`, `s7t*`, `pg-t`, `nm-t`, `ldn-t`, `pc-*`,
unchanged by construction: no struct or union reaches them), the `simple` and switch corpora.

### C printing, slice 2: blocks and casts (branch `m3-print2`, 2026-11-15)

- `printc.rs`: every structured block of printc.cc: `emitBlockGraph`, `emitBlockCopy`,
  `emitBlockGoto` (`gotoPrints`), `BlockMultiGoto`, `emitBlockLs` (with `only_branch`),
  `emitBlockCondition` (`&&`/`||` in parentheses; a condition never negated keeps the
  `INT_AND`/`INT_OR` of `newBlockCondition` and prints `||`, as the C++), `emitBlockIf` for
  if, if/else, if-no-exit and if-goto with the `else if` merge (`PendingBrace`),
  `emitBlockWhileDo` (plain, `while( true )` with `if (..) break;` for `f_whiledo_overflow`,
  and `emitForLoop`), `emitBlockDoWhile`, `emitBlockInfLoop`, `emitBlockSwitch` and
  `emitSwitchCase` (`default:`, one `case` line per label of the case's first basic block in
  the switch variable's type, an explicit `break` for a case that exits), `emitGotoStatement`
  (`break`, `continue`, `goto`), `emitLabel` (`code_`, `joined_`, `dup_` and the entry
  address), `emitLabelStatement`, `emitAnyLabelStatement` (`f_label_bumpup`). Statements in a
  condition are comma separated (`comma_separate`); `opCbranch`, `opBranch` and `opBranchind`
  (structured printing).
- Casts: `opTypeCast`, and `opIntZext`, `opIntSext`, `opSubpiece` with the four printer-only
  functions of cast.cc now in `cast.rs` (`isZextCast`, `isSextCast`, `isSubpieceCast`,
  `isExtensionCastImplied`): an extension or SUBPIECE prints as a cast, hidden (the
  `hiddenfunction` token, `option_hide_exts` on) when C promotes it anyway, or as
  `ZEXT14(x)`/`SEXT14(x)`/`SUB41(x,0)` (`opFunc`). The pending varnodes now keep the op reading
  them (`readOp`), which `isExtensionCastImplied` needs.
- `prettyprint.rs`: the `same_line` brace style, `openBrace`, and the pending print of a brace
  (`setPendingPrint`, emitted by the next line break).
- `flow.rs`: `FlowInfo::reinterpreted` gives its header warning (once a function).
- The basic blocks keep `f_joined_block` (`nodeJoinCreateBlock`) and `f_duplicate_block`
  (`nodeSplitBlockEdge`, which also copies the spliced mark with the cover) for the labels;
  `spliceBlock` clears both, as block.cc keeps only `f_unstructured_targ`, `f_entry_point` and
  `f_switch_out` (superseded: "not kept, only printing reads it").
- Fail loudly: a cast to a pointer to an array (`checkAddressOfCast`), a SUBPIECE with special
  printing (a field extraction), the label of a block `spliceBlockBasic` merged (the C++ cover
  may hold two ranges, and `getEntryAddr` picks the one of the first op: ghidra-rs keeps one
  range), block nesting deeper than 1000: an addition of ghidra-rs (the C++ recurses without a limit), so
  a deep function fails loudly instead of overflowing the stack; the front leaf of a label that is
  not a block copy. Comments in the
  body, anonymous data-types, the long suffix and the operators of slice 1 stay loud. (Superseded
  in part: slice 3B, below, prints the body comments, anonymous data-types, `CALLIND` and the
  float operators and constants.)
- `bars.sh`: `pcc-r` and `pcc-t` also run on the switch corpus, with the `sw` options there
  (`switchnorm` on: the case labels come from it; with it off the reference fails on every
  switch in `finalizePrinting`).

Numbers (functions the reference finishes; before = slice 1 with the `m3-s9` review fixes):

| check | M8 | M500 before | M500 after | simple after | switch after |
|---|---|---|---|---|---|
| `pcc-r` | 2 / 7 | 10 / 495 | 235 / 495 (loud 259, silent 1) | 109 / 194 (loud 85) | 153 / 2005 (loud 1852, silent 0) |
| `pcc-t` | 0 / 7 | 8 / 495 | 58 / 495 (loud 437, silent 0) | 57 / 194 (loud 137) | not finished (29 done, all loud) |
| `pc-r` | 2 / 7 | 47 / 495 | 244 / 495 (loud 250, silent 1) | 110 / 194 (loud 84) | |
| `pc-t` | 0 / 7 | 24 / 495 | 45 / 495 (loud 450, silent 0) | 49 / 194 (loud 145) | |

On the switch corpus (`pcc-r`): comments in the body 1,453 (mostly jump-table warnings), `CALLIND` 125, an
anonymous data-type 110, `FLOAT2FLOAT` 40, `FLOAT_NAN` 35, the label of a spliced block 30, then 13 or
fewer each. Fixed on the way (the three silent switch misses, 0x1a7a2ac, 0x1d1472a, 0x1e9cbc6): flow
now gives the header warning of `FlowInfo::reinterpreted`, "Instruction at (ram,..) overlaps
instruction at (ram,..)" with its trailing newline, once a function (`reinterpreted_present`, copied
into the jump-table partial function), as the earlier bad-instruction fix.
No block kind is a loud miss any more. The one silent miss of `pcc-r` and `pc-r` is 0x47a6b0,
the known rules-on miss: it differs from `r1` on (`print raw` at `assignhigh`: the block
numbering after the rules), so `finalstructure` and the printer see another function.
The loud misses on M500, `pcc-r`: `CALLIND` 77, an anonymous data-type 45, `FLOAT2FLOAT` 36,
`FLOAT_NAN` 29, comments in the body 20, float constants 12, a SUBPIECE field extraction 9,
`PIECE` 8, then 4 or fewer each (one spliced-block label); `pcc-t`: array or field access 188,
`PTRADD` 88, character constants 33, `PIECE` 24, comments 20, `INT_SBORROW` 16, `CALLIND` 14, float
constants 14, `FLOAT2FLOAT` 11, `PTRSUB` 8, `FLOAT_NAN` 7, the `mergeAddrTied` error 6, then 2 or
fewer. `pc-t` (no casts): array or field access 270, `PTRADD` 34, character constants 30, `PIECE`
23, comments 20.
On `simple` (before: `pc-r` 54, `pc-t` 34 / 194) every miss is loud; the most: comments in the body 31,
`CALLIND` 16 and an anonymous data-type 15 (`pcc-r`), array or field access 34 and `PTRADD` 21 (`pcc-t`).
M8: the 51 checks other than the print checks identical (8 / 8, `fs`, `fsc` 7 / 7); `pc-r`, `pcc-r` 2 / 7,
`pc-t`, `pcc-t` 0 / 7, all misses loud (superseded: 0 / 7 each).
Unit tests: the `else if` brace (`pending_brace_else_if`), the switch brace
(`switch_brace_has_no_indent`), the printer-only casts (`printer_casts`); the block kinds
themselves are covered by the corpus checks (a printed block needs a decompiled function).
`pcc-t` on the switch corpus was stopped after 29 of 2,050 functions (all loud, silent 0): the machine
was loaded by the `m3-s9` queue pass. Rerun after the flow fix, the review fixes and the merge of master's `decomp-diff.sh` timeout fix
(superseded: "not rerun after the flow fix"): M500 and `simple`, all four print checks, the same
counts as the table; M8 all 55 checks as before. Not run: the full pass (`bars-queue.sh`), the other checks on M500, simple and switch.

### C printing, slice 3B: calls, floats, comments, anonymous types (branch `m3-print3b`, 2026-11-15)

- `printc.rs`: `opCallind` (`(*fn)(args)`, the pointer under a dereference; `hide_thisparam`
  is set only by the Java printer, so no `this` slot is hidden); the float operators of
  printc.hh: `NAN`, `ABS`, `SQRT`, `CEIL`, `FLOOR`, `ROUND` in functional syntax (`opFunc` with
  the operator name alone), `FLOAT2FLOAT` and `TRUNC` as casts, `opFloatInt2Float` (a cast of
  the input, or of the implied INT_ZEXT's input it absorbs); the float compare and arithmetic
  operators as before.
- Float constants (`push_float`): `INFINITY`, `NAN` with their sign, else
  `FloatFormat::printDecimal`: `ostream << double` (`%.*g`) at precision 6 to 9 (size 4) or 15
  to 17 (size 8) until the text reads back as the value (as a float for size 4; libstdc++ reads
  an overflow as the largest finite value), `.0` added to a token without `.` or `e`. Sizes
  other than 4 and 8 print `FLOAT_UNKNOWN` (the x86 translator has no other float format).
  Unit tests pin the tokens against the C++ (a small program printed them; 6,000 random
  encodings also matched before the test was cut to the listed ones).
- `genericTypeName`: a data-type without a name prints `unkbyte3`, `unkint3`, `unkuint3`,
  `unkfloat3`, `BADSPACEBASE` or `BADTYPE`.
- Body comments: `comment.rs` ports `CommentSorter` (`setupFunctionList`, `findPosition`,
  `setupBlockList`, `setupOpList`) over `Funcdata::comments` in database order (address, then
  the order added); `printc.rs` `emitCommentGroup` (before each statement and at the end of a
  basic block, at indent 20) and `emitCommentBlockTree` (before an `if`, `for` or `while` line).
  `Funcdata::main_ops_around` is `beginOpMain` and the op before it, INDIRECTs left out as the
  C++ `optree`. A header warning and a body warning at the entry with the same text are one
  comment (`addCommentNoDuplicate` checks both). The header stays `Funcdata::warnings`.
- `BlockBasic::cover`: the ranges `spliceBlockBasic` merges (`mergeRange`), copied by
  `nodeSplit`, so `contains` sees the gap between them (the label of a spliced block stays loud).
- Fixed on the way (the 19 silent misses of the first run): flow now records the jump-table
  failure warning (`stageJumpTable`'s `warning(err.explain, op->getAddr())`, "Could not recover
  jumptable at .. Too many branches" and the other `fail_normal` messages) before "Treating
  indirect jump as call".
- Review fixes (second commit on the branch):
  - A jump-table failure whose message ghidra-rs makes on a path it does not port
    (`is_unported`) ends the decompile instead of becoming a body warning and a CALLIND: an
    unported error of the partial function's action, and the emulation errors the C++ does
    not have (emulating an op not ported, an op without output, the load image read after the
    emulated path, whose C++ message is the load image's own). Superseded: "reported on
    stderr" for the partial's unported errors.
  - After the partial function's action failed, a second table of the same function fails
    loudly: the C++ marks the partial before the action runs and reads the half-simplified
    clone for the next table; ghidra-rs made a fresh one.
  - The partial's header warnings go through `add_header`, so the header and body dedupe
    applies to them too.
  - Body and header warnings that were dropped: "ptrarith problems" (`RulePtrArith`),
    "Call to offcut address within same function" and the header "Possible PIC construction at
    ..: Changing call to branch" (`checkContainedCall`), "Sanity check requires truncation of
    jumptable" (`JumpTable::sanityCheck`, with the jumptable prefix of the partial).
  - `testForReturnAddress` (`fail_return`, "Treating indirect jump as return") fails loudly
    when the jump's target traces through COPY, INDIRECT and INT_AND by a constant to the
    input at stack offset 0.
    Superseded (branch `m3-swsilent`): ported, the jump becomes a RETURN with that warning.
  - Audited and not reachable: "Subroutine does not return" and "Does not return" (ghidra-rs
    has no non-returning prototype, and `fail_callother` fails loudly), "Function flow out of
    bounds" (flow covers the whole space and inlining is not ported), `ActionPrototypeWarnings`
    (the checks break before `prototypewarnings`, which is `not_ported`), "Second-stage recovery
    error" (a table that looks unreachable is taken as complete, so `recoverMultistage` never
    runs; a multistage restart in `matchModel` fails loudly) and "Switch is manually
    overridden" (the console sets no override).

Numbers (functions the reference finishes; before = slice 2):

| check | M8 before | M8 after | M500 before | M500 after | simple before | simple after |
|---|---|---|---|---|---|---|
| `pcc-r` | 2 / 7 | 6 / 7 | 235 / 495 | 441 / 495 (loud 53, silent 1) | 109 / 194 | 174 / 194 (loud 20) |
| `pc-r` | 2 / 7 | 6 / 7 | 244 / 495 | 442 / 495 (loud 52, silent 1) | 110 / 194 | 174 / 194 (loud 20) |
| `pcc-t` | 0 / 7 | 1 / 7 | 58 / 495 | 94 / 495 (loud 401) | 57 / 194 | 91 / 194 (loud 103) |
| `pc-t` | 0 / 7 | 1 / 7 | 45 / 495 | 72 / 495 (loud 423) | 49 / 194 | 83 / 194 (loud 111) |

The four checks on M500 and `simple` and M8 every check were rerun in full after the review
fixes, with the same counts (superseded: the first commit counted a rerun of the three functions
the `cover` fix moves, 0x4f15d0, 0x9e0b71 and 0xa714b0).

Switch corpus `pcc-r`: not finished at the commit (about 291 of 2,005 functions done after an hour on a loaded machine; none of the finished ones was a silent miss).

The silent miss is 0x47a6b0 alone (rules on), the known one that differs from `r1` on. The
loud misses, M500 `pcc-r`: a SUBPIECE field extraction 19, `PIECE` 14, `CALLOTHER` 5,
`POPCOUNT` 4, the label of a spliced block 3, `INT_SBORROW` 3, `INT_SCARRY` 2, a variable
linked to a function or an external reference 2, a character constant 1;
`pcc-t`: array or field access 205, `PTRADD` 94,
character constants 35 (with 0x4f15d0), `PIECE` 28, `INT_SBORROW` 19, `PTRSUB` 8, the `mergeAddrTied` error 6,
then 3 or fewer. `simple` `pcc-r`: `CALLOTHER` 8, `PIECE`, `INT_SBORROW` and the field
extraction 3 each, comments in a spliced block 2 (printed since the fix). No comment, `CALLIND`,
float or anonymous data-type error is left. M8: the 51 other checks identical (8 / 8, `fs*`
7 / 7); the M8 misses are `INT_SBORROW` (`pcc-r`) and array or field access (`pcc-t`).

### C printing, slice 3A: array and field access, characters (branch `m3-print3a`, 2026-11-15)

- `printc.rs` (its own `impl` block): `checkArrayDeref` (a LOAD or STORE through an implied
  `PTRSUB` or `PTRADD`, also behind a SEGMENTOP, prints the value, `print_load_value` /
  `print_store_value`), `opPtradd` (`p[i]`, or `p + i` for the pointer), `opPtrsub` with
  `isValueFlexible` and its cases: a structure field (`&p->x`, `p->x`, `&(..).x`, `(..).x`,
  `[0]` for an array field, `field_0x..` past the named fields), a symbol of a space (`&name`,
  `name` for an array or code symbol, `name[0]`, a part of a symbol, the unnamed location
  `ram0x..` / `stack0x..`), the first element of an array (`*p`, `p[0]`); `pushPartialSymbol`
  (`sym.field`, `sym[i]`, `sym._off_size_`, the SUBPIECE-style cast of a read), now also reached
  from `pushSymbolDetail` for a variable that is part of its symbol; the tokens `.`, `->`,
  `[ ]` (`subscript`) and `&` with printc.cc's precedences.
- `namevars` links the offset of a space-base PTRSUB to what it refers to, as
  `ActionNameVars::linkSpacebaseSymbol` and `linkSymbolReference` do (`queryContainer` without a
  use point in the stack's or the global scope, in `linkSymbols`' order, kept in
  `Funcdata::symref` with the offset into the symbol); the printer reads the link, and an offset
  without one prints as the unnamed location. The global lookup (`global_container`: the
  smallest of a data symbol, a function, an external reference) is shared with `linkSymbol`. A
  function prints by its name (the `FunctionSymbol`, as `opCall` names it:
  `*(code **)p = func_0x008244e0;`); an external reference fails loudly in the printer.
  Superseded: "found where the printer reads it", a lookup at print time that could find a stack
  symbol made after the link (review fix).
- Character constants: `pushCharConstant` with display format 0 (a byte of 0x80 or more as an
  integer, `L'..'` for a wide character) and `printUnicode` (`unicodeNeedsEscape`, the named
  escapes, `printCharHexEscape` with 2, 4 or 8 digits), unit tested (`character_constants`).
- Fail loudly: a PTRSUB into a union (`getUnionField`) or an external reference, a part of a
  symbol through a union or a structure that needs resolution (`findResolve`), a variable past
  the end of its symbol (`pushMismatchSymbol`), a character constant with a symbol (an equate).
  `TypePointerRel` is not ported, so its parts of `opPtrsub` never apply. `PIECE` stays loud
  (none of these forms needs it).

Numbers (functions the reference finishes; before = slice 2 on `m3-print2`, as measured there):

| check | M8 before | M8 after | M500 before | M500 after | simple before | simple after |
|---|---|---|---|---|---|---|
| `pcc-t` | 0 / 7 | 2 / 7 | 58 / 495 | 143 / 495 (loud 352, silent 0) | 57 / 194 | 95 / 194 (loud 99) |
| `pc-t` | 0 / 7 | 2 / 7 | 45 / 495 | 143 / 495 (loud 352, silent 0) | 49 / 194 | 95 / 194 (loud 99) |
| `pcc-r` | 2 / 7 | 2 / 7 | 235 / 495 | 235 / 495 (loud 259, silent 1) | 109 / 194 | 109 / 194 (loud 85) |
| `pc-r` | 2 / 7 | 2 / 7 | 244 / 495 | 244 / 495 (loud 250, silent 1) | 110 / 194 | 110 / 194 (loud 84) |

No miss of any check is an array, field or character error any more: of the slice 2 blockers
of `pcc-t` (array or field access 188, `PTRADD` 88, character constants 33, `PTRSUB` 8) none is
left, and no silent miss came with them. The one silent miss (`pcc-r`, `pc-r`) is 0x47a6b0, the
known rules-on miss that differs from `r1` on. With the array forms printed, more functions
reach the next construct: the loud misses on M500, `pcc-t`: `INT_SBORROW` 100, `PIECE` 71, `CALLIND` 60, `FLOAT2FLOAT` 34, float constants 25, comments in the body 20, `FLOAT_NAN` 17, then 6 or fewer each; `pc-t`: `INT_SBORROW` 100, `PIECE` 71,
`CALLIND` 60, `FLOAT2FLOAT` 37, float constants 22, comments in the body 20, `FLOAT_NAN` 17,
then 6 or fewer each. The rules-on checks do not move: an array or field miss they had in slice 2 (4 or fewer
each there) now fails on another construct (their misses: `CALLIND` 78, an anonymous
data-type 45, `FLOAT2FLOAT` 36, `FLOAT_NAN` 29, comments 20 for `pcc-r`). On `simple`, `pcc-t` and
`pc-t`: comments in the body 31, `PIECE` 17, `INT_SBORROW` 17, `CALLIND` 10, `FLOAT2FLOAT` 9, then
6 or fewer. M8: the 51 checks other than the print checks identical (8 / 8, `fs`, `fsc` 7 / 7);
the print checks' 5 misses each are loud (`INT_SBORROW`, `FLOAT_NAN`, comments, `PIECE` or
`CALLIND`, a float constant or an anonymous data-type).
`INT_SBORROW` (`opFunc`, `SBORROW4(a,b)`) and `PIECE` are now the largest types-on blockers;
neither is in this slice (`PIECE` is not needed by the array and field forms).
Not run: the switch corpus, the full pass (`bars-queue.sh`), the other checks on M500 and
`simple`. The `pcc-t` "before" split (slice 2) was not rerun here. The M500 and the
other M8 numbers are from a build before one last fix (a written part of a symbol takes no
cast, `is_read`; no check reached it: no silent miss); the four M8 print checks and `pcc-t`,
`pc-t` on `simple` were rerun with the final build, the same counts.

Review fixes (same branch): the PTRSUB symbol link moved from the printer to `namevars` (above),
`isValueFlexible` reads the COPY input through the checked accessor, and a part of a symbol
without a data-type fails as such. Rerun on the final build with every count as above: M8 all
55 checks (the 51 others identical, the print checks 2 / 7 each, loud 5, silent 0); M500
`nm-r` 498 / 499 (silent: 0x47a6b0) and `nm-t` 493 / 499 (the six loud `mergeAddrTied`
misses), unchanged; M500 `pcc-t` and `pc-t` 143 / 495 (silent 0), `pcc-r` 235 and `pc-r` 244 / 495 (silent: 0x47a6b0);
`simple` `pcc-t` and `pc-t` 95, `pcc-r` 109, `pc-r` 110 / 194 (silent 0). Not run: the switch corpus,
the full pass.

### C printing, slices 3A and 3B merged (branch `m3-print3`, 2026-11-16)

Slice 3A (array and field access, `PTRADD`, `PTRSUB`, character constants, the `namevars` link
of a space-base PTRSUB) and slice 3B (indirect calls, floats, body comments, anonymous types,
the flow and jump-table warnings) together. No code changed in the merge: the two slices touch
different arms of `push_constant` (3A the character arm, 3B the `Meta::Float` arm) and of the
`push_opcode` dispatch (3A `Ptradd`, `Ptrsub`; 3B `Callind` and the float operators), and
`funcdata.rs` keeps 3A's `symref` beside 3B's `add_header`. Not ported yet, still loud: the long
suffix of a constant, `checkAddressOfCast`, labels of spliced blocks, strings, unions,
`TypePointerRel` and the remaining operators (superseded: the "Not ported" lists and the
"Next" lines of the two slice sections above, each written without the other slice).

| check | M8 | M500 3A | M500 3B | M500 merged | simple 3A | simple 3B | simple merged |
|---|---|---|---|---|---|---|---|
| `pcc-r` | 6 / 7 | 235 | 441 | 442 / 495 (loud 52, silent 1) | 109 | 174 | 174 / 194 (loud 20) |
| `pc-r` | 6 / 7 | 244 | 442 | 442 / 495 (loud 52, silent 1) | 110 | 174 | 174 / 194 (loud 20) |
| `pcc-t` | 5 / 7 | 143 | 94 | 257 / 495 (loud 238, silent 0) | 95 | 91 | 138 / 194 (loud 56) |
| `pc-t` | 5 / 7 | 143 | 72 | 257 / 495 (loud 238, silent 0) | 95 | 83 | 138 / 194 (loud 56) |

The one silent miss is 0x47a6b0 (`pcc-r`, `pc-r`), the known rules-on miss. 0x4f15d0, which 3B
failed with types on on a character constant, prints identically. The loud misses on M500,
`pcc-t` and `pc-t`: `INT_SBORROW` 119, `PIECE` 96, `POPCOUNT` 8, `mergeAddrTied` 6, `CALLOTHER` 4,
`INT_CARRY` 2, a variable linked to a function or external reference 2, `INT_SCARRY` 1; `pcc-r`
and `pc-r`: a SUBPIECE field extraction 19, `PIECE` 14, `CALLOTHER` 5, `POPCOUNT` 4, the label of
a spliced block 3, `INT_SBORROW` 3, `INT_SCARRY` 2, a variable linked to a function 2. `simple`
`pcc-t`: `PIECE` 23, `INT_SBORROW` 21, `CALLOTHER` 6, `mergeAddrTied` 3, `POPCOUNT` 3. M8: the 51
other checks identical; the print misses are loud (`PIECE` at 0x73a340 types on, `INT_SBORROW`
at 0x9eec5e). A CALLIND through a LOAD (`(**(code **)(iVar1 + 0x50))()`) prints identically in 2 functions of
`simple` (`pcc-t`, outputs kept for the count); every other function there with an indirect call
is identical or loud. No call through a structure field (`(*p->fn)()`) was in the `simple` outputs searched; M500 was not searched for one.
Not run: the switch corpus, the full pass (`bars-queue.sh`), the other checks on M500 and `simple`.

### C printing, slice 4: functional operators, CALLOTHER, SUBPIECE fields (branch `m3-print4`, 2026-11-16)

- `printc.rs`: `opIntCarry`, `opIntScarry`, `opIntSborrow` and `opPiece` (`opFunc` under
  `getOperatorName`: the name and the input sizes, `CARRY4`, `SBORROW4`, `CONCAT44`), `opPopcountOp`
  and `opLzcountOp` (`POPCOUNT`, `LZCOUNT`), `opCallother` for a SLEIGH user-op (display 0:
  functional syntax under the op's name, the inputs after the index), and the field extraction
  of `opSubpiece` (`doesSpecialPrinting` on a structured input: `pushPartialSymbol` with the cast
  allowed for an explicit variable with a symbol, else `x.field` when `findTruncation` gives a
  formal structure field at offset 0, else the cast or `SUB41` as before).
- Loud: a CALLOTHER whose index is not a SLEIGH user-op (the built-in ones: volatile read and
  write, string data, the only ones with another display); a SUBPIECE input whose data-type
  needs resolution (a union: `findTruncation` with the artificial slot reads the union
  resolution, not ported). `INT_CARRY` and `LZCOUNT` were not in the slice's list; they take the
  same `opFunc` path.

| check | M8 | M500 before | M500 |
|---|---|---|---|
| `pcc-r` | 7 / 7 | 442 / 495 (loud 52, silent 1) | 487 / 495 (loud 7, silent 1) |
| `pc-r` | 7 / 7 | 442 / 495 (loud 52, silent 1) | 487 / 495 (loud 7, silent 1) |
| `pcc-t` | 7 / 7 | 257 / 495 (loud 238, silent 0) | 479 / 495 (loud 16, silent 0) |
| `pc-t` | 7 / 7 | 257 / 495 (loud 238, silent 0) | 479 / 495 (loud 16, silent 0) |

The one silent miss is still 0x47a6b0 (`pcc-r`, `pc-r`), the known rules-on miss. The loud misses
left on M500, `pcc-r` and `pc-r`: the label of a spliced block 4, a variable linked to a function
or external reference 3; `pcc-t` and `pc-t`: `mergeAddrTied` 6, the label of a spliced block 5, a
variable linked to a function or external reference 3, string constants 2 (superseded: the M500
and M8 miss lists of the merged section above). M8: all 55 checks identical on the functions the
reference finishes. Full pass (`bars-queue.sh`, 127 pairs on 0f53a714b9, desktop and Mac): every non-print check
at its baseline; `simple` `pcc-r` and `pc-r` 174 -> 190 / 194 (loud 4), `pcc-t` and `pc-t` 138 -> 188 / 194 (loud
6), silent 0; switch `pcc-r` 1734 -> 1810 / 2005 (loud 270 -> 135, silent 1 -> 60), `pcc-t` 1351 -> 1817 / 2005
(loud 654 -> 128, silent 0 -> 60). Each switch silent is a function an older switch check already lists as
silent (`swfs-r`, `swsn-r`, `swfs-t`; for example 0x4f3366 in `swfs-t`): slice 4 lets them print, the
divergence is in an earlier stage. Two M500 pairs run on the Mac (`r5dtlocksv`, `r5slock`) lost
0x6b21e0 to the 120 s reference timeout (450 / 498); rerun alone on the desktop with `TIMEOUT=600`, both are at their baseline (451 / 499;
0x6b21e0 does not finish in the reference within 600 s, as in the baseline). No unit test was added: the printer has none that builds a function; the
M500 misses above that now print identically are the check. Not seen in a check: `LZCOUNT` (no
M500 function failed on it before), and which of the two field-extraction forms (`sym.field`,
`x.field`) the 19 functions take.

### Switch corpus silent misses (branch `m3-swsilent`, 2026-11-16)

The 60 silent misses of `swfs-r` and `swfsc-r` on the switch corpus (the same 60 functions), by
cause:

| cause | functions | now |
|---|---|---|
| the jump-table partial function ran without the `stackvars` rules, so a jump through a stack slot (SecuROM code past 0x1000000) was not recovered ("Too many branches", the jump became a call) | 56 | identical |
| the same, and the jump goes to the return address (`testForReturnAddress`, `fail_return`) | 1 (0x1b0d29d) | identical |
| the same, and the stack heritage of the partial function needs the value-set range of an indexed stack LOAD (`LoadGuard`, not ported) | 1 (0x1b0c190) | loud |
| the same, and the jump reads a stack varnode through the INDIRECT of a STORE that `RuleAliasUpdate` collapses in the C++ (`ActionRestructureVarnode`, not ported) | 1 (0x1c69c5a) | loud |
| `ActionConditionalExe` (not ported) removes a block re-testing an equal condition held in another varnode | 1 (0x5a3c30) | loud |

(Superseded, branch `m3-aliasupdate`: `RuleAliasUpdate` and the action run in the partial
function; 0x1c69c5a stays loud, on the value-set range of the store guard its STORE has.)

What changed:

- The partial function of jump-table recovery runs with `RuleLoadVarnode` and `RuleStoreVarnode`,
  as in the C++ (`action.rs`; superseded: "runs without the `stackvars` rules" in "Stage R5" and
  the notes on `jumptable::fold_constants` above). When its stack heritage fails on a path not
  ported, flow.rs builds the partial function without the two rules (`Flow::build_partial`, with
  `fold_constants`, as before this branch). A table that one does not give either ends the
  decompile with the first error when the jump depends on the stack pointer; otherwise the jump
  fails as in the C++ (warning, the jump becomes a call).
- A table that fails while the jump reads a stack varnode through the INDIRECT of a STORE is tried
  on the partial function without the stack rules, and fails loudly when that gives none. The
  INDIRECT of a call is not checked.
- `fail_return` is ported: the jump becomes a RETURN, with "Treating indirect jump as return".
- The loud test of `ActionConditionalExe` compares the two conditions as `verifySameCondition`
  does (`BooleanMatch`, same or complementary), not only one shared varnode, and passes a block
  holding an op `testRemovability` never moves (a call, LOAD, STORE, INDIRECT, an address-tied
  output), which the C++ leaves alone. In the partial function the test stays one shared varnode.
- `ActionDeadCode` covers the join space (never heritaged, dead code after the first pass): an
  unused `j{EDX,EAX}:8` call output goes, as in the reference (0x4f3366 in `swfs-t`).

Switch corpus, of the 2,004 functions the reference finishes (before: the full pass on
8f3c8d178c; after: the reference outputs of one `bars.sh` run, ghidra-rs rerun on them with the
final build):

| check | before | after |
|---|---|---|
| `paramdouble` | 1947 (loud 0, silent 57) | 1999 (loud 5, silent 0) |
| `swsn-r` | 1943 (loud 0, silent 61) | 1994 (loud 7, silent 3) |
| `swfs-r` | 1937 (loud 7, silent 60) | 1991 (loud 13, silent 0) |

Identical before and loud now: 0x546d40, 0x5629d0, 0x78e7d0 (no table from either partial
function, the jump depends on the stack pointer, the indexed stack LOAD error; the reference fails
these tables too) and 0x23f4238 in `swsn-r` (a multistage table, `switchnorm` not ported; in
`swfs-r` it was loud before, `mergeAddrTied`). The 3 silent left in `swsn-r` (0x8d8f40, 0x8eabe0,
0x8ead90: the global at 0x00b0511c prints as `code() *` in the reference, `xunknown4` in
ghidra-rs) are not in the 60 and were not traced; the count says they were silent before (61 = 58
of the 60 + 3). M8: all 55 checks identical. Not run on the final build: `swfsc-r`, `swfs-t`, `swsn-t`, `pcc-*` on
the switch corpus, and M500 (0x4f3366 alone is identical in `swfs-t`). No unit test was added: the
functions above are the check. A panic of ghidra-rs prints before the buffered console output,
so `decomp-diff.sh` cuts its message and `bars.sh` counts it as silent, not loud. (Superseded:
`decomp-diff.sh` keeps a panic or stack overflow message and `bars.sh` counts it as `loud`; see
the output notes of "Every check at once: `tools/bars.sh`".)

Review fixes (second commit on `m3-swsilent`). A review of the first commit found paths that could
still differ silently; each now fails loudly. Superseded by this paragraph: "the stack offset 0"
of `fail_return`, "is tried on the partial function without the stack rules", "The INDIRECT of a
call is not checked", "In the partial function the test stays one shared varnode", and the counts
above.

- `fail_return` compares with the spec's `<returnaddress>` (`CompilerSpec::return_address`, the
  C++ `defaultReturnAddr`: space, offset and size), not a fixed 4-byte stack offset 0.
- INDIRECTs of stack varnodes (of a STORE or of a call; `RuleAliasUpdate` after
  `ActionRestructureVarnode`, neither ported): the table is recovered a second time on a copy of
  the partial function with all of them removed. A different result (another table, or a table
  against none) fails loudly, and so does a table that fails while the jump reads one. There is no
  retry on the partial function without the stack rules any more. Not proven: that removing only
  some of them (what the C++ alias analysis may do) gives the same table when removing all or none
  does.
  Superseded (branch `m3-aliasupdate`): both run in the partial function; this test is left for
  the partial function made without them, see "Alias analysis of the jump-table partial
  function".
- The partial function without the stack rules (the fallback when the stack heritage is not
  ported): a table from it also fails loudly when a guard (`analyzeGuards`,
  `jumptable::guard_conditions`) reads the stack through a LOAD the jump does not read.
- `ActionConditionalExe`: the wider test (`BooleanMatch`) also in the partial function, where the
  C++ runs `multicse`.

On the 124 functions whose state the first commit changed or left not identical (every check of
the table above, `bars.sh` on that list), against the first commit: 6 identical -> loud on the
INDIRECT test (0x1cdbf0e, 0x7913d0, 0x7bb710, 0x7bf170, 0x898690, 0x898850; the reference fails
these tables too), 0x502b80 and 0x5c37f0 identical -> loud on the guard test (0x5c37f0 was loud in
`swfs-r` already), 0x5a3c30 identical -> loud in `paramdouble` (it was loud in the two later
checks). No function became silent, none became identical. On the list: `paramdouble` 110 / 124
(loud 14), `swsn-r` 106 / 124 (loud 15, silent 3: the three above), `swfs-r` 104 / 124 (loud 20).
Outside that list, the whole switch corpus at `paramdouble`, the first commit's ghidra-rs against
this one (`decomp-diff.sh` with the old build in the reference's place): 2036 / 2050 outputs equal;
the 14 that differ all end in an error now: the 9 above, 0x1c69c5a (loud before, new wording),
0x807a80 (identical -> loud, `ActionConditionalExe` in the partial function), 0x831db0 (identical ->
loud, the INDIRECT test), and 0x2285c9b and 0x7c1f30, which the reference does not finish. Counts
from that, of the 2,004: `paramdouble` 1999 -> 1988 (loud 16, silent 0; confirmed by `bars.sh`),
`swsn-r` 1994 -> 1984 (loud 17, silent 3), `swfs-r` 1991 -> 1982 (loud 22, silent 0); against
master 1947, 1943, 1937.
M8: all 55 checks identical. M500 (`bars.sh`): `s8r` and `swfs-r` 498 / 499 as before, their one miss
0x47a6b0 loud now (silent before: the wider `ActionConditionalExe` test); `swfs-t` 493 / 499 and
`fs-t` 489 / 495 (loud 6 each, `mergeAddrTied`), unchanged. Not rerun: `swsn-r`, `swfs-r` on the
whole switch corpus, and the other switch checks.

### C printing, slice 5: spliced labels, linked variables, VariablePiece, strings (branch `m3-print5`, 2026-11-16)

- `block.rs`, `printc.rs`: the label of a spliced block. `BlockBasic::entry_addr` is
  `getEntryAddr`: the cover's ranges joined as `RangeList::insertRange` joins them (overlapping
  ranges, not touching ones), then the start of the one range, or of the range holding the first
  op. The `spliced` mark of a block is gone; the cover is kept as before.
- `printc.rs`: a global variable whose storage is a whole function (one byte) or a whole external
  reference (a pointer) prints as that symbol's name (`pushSymbolDetail`, the type-locked symbol
  `setSymbolProperties` links when the varnode is made). `map externalref`'s third word, the
  name, is now kept (`Arch::externref_name`); without one the name is the address and `_exref`.
- `variable.rs`, `merge.rs`: `VariablePiece` and `VariableGroup`. `mergeAddrTied` groups
  overlapping address-tied varnodes of different sizes (`groupWith`); the extended cover,
  `HighVariable::merge` with pieces (`transferPiece`, `mergeGroups`), `blockIntersection`,
  `mergeTestRequired`, `mergeTestAdjacent`, `collectInputs`, `inflateTest` and the PIECE and
  SUBPIECE cases of `markInternalCopies` read them.
- `printc.rs`: string constants (`pushPtrCharConstant`, `printCharacterConstant`): a constant
  pointer to characters in read-only memory prints as the quoted string, read 32 bytes at a time
  up to 2048 as `StringManagerUnicode::getStringData` reads it, escaped by `printUnicode`.
  Function pointer constants (`pushPtrCodeConstant`): the name of the function at the address.
  The second was not in the slice's list; the switch sample showed it (4 and 5 of 287).
- Still loud: a variable that is part of an external reference or larger than the function or
  external reference at its address (`pushPartialSymbol` of a code pointer,
  `pushMismatchSymbol`), the label of a block of several ranges without ops, the groups of
  proto-partial PIECEs (`groupPartials`). Not checked against the C++: a segmented constant
  (`resolveConstant` with a segment op) and opaque strings; neither exists in the checks.

| check | M8 | M500 before | M500 | switch before | switch |
|---|---|---|---|---|---|
| `pcc-r` | 7 / 7 | 487 / 495 (loud 7, silent 1) | 494 / 495 (loud 0, silent 1) | 1810 / 2005 (loud 135, silent 60) | 1944 / 2005 (loud 0, silent 61) |
| `pc-r` | 7 / 7 | 487 / 495 (loud 7, silent 1) | 494 / 495 (loud 0, silent 1) | not run | not run |
| `pcc-t` | 7 / 7 | 479 / 495 (loud 16, silent 0) | 495 / 495 (loud 0, silent 0) | 1817 / 2005 (loud 128, silent 60) | 1943 / 2005 (loud 0, silent 62) |
| `pc-t` | 7 / 7 | 479 / 495 (loud 16, silent 0) | 495 / 495 (loud 0, silent 0) | not run | not run |

The M500 silent miss is still 0x47a6b0 (`pcc-r`, `pc-r`). No loud miss is left on M500 or the
switch corpus (superseded: the loud lists of the slice 4 section above). M8: all 55 checks
identical on the functions the reference finishes. The seven functions that failed in
`mergeAddrTied` (0x402c20, 0x405990, 0x4c0070, 0x62f0d0, 0x757810, 0x7586e0 of M500 and one of
the switch sample) were run on all 55 checks: no silent miss; five loud misses, all older
errors before merging (0x62f0d0 an indexed stack LOAD in `r5dtlock`, `r5dtlocksv`, `r5slock`,
`r5s`; 0x4c0070 `ActionParamDouble` in `r5s`).

Switch silents: the 61 of `pcc-r` are all silent in `swfs-r`, `swsn-r` or `swfsc-r` (those three
rerun on the 63 silent functions). Of the 62 of `pcc-t`, 61 are silent in `swfs-t`, `swsn-t` or
`swfsc-t`; one is new and is not covered by an older check: 0x23caea8 prints without the
reference's comments `WARNING (jumptable): Read-only address (ram,0x00429700) is written` and
`WARNING: Read-only address ... is written` (6 lines, 3 addresses). The warning of
`Funcdata::fillinReadOnly` for a written read-only varnode is not ported (`action.rs`,
`varnode_props`, folds only the reads); the function was loud before this slice, so the gap did
not show. It is open: port the warning or make the case loud. A first try that warned for every
written read-only varnode before heritage printed too many warnings and was dropped.

Not run: the other 51 checks on M500, `simple`, `r5d-adc`, `pc-r` and `pc-t` on the switch
corpus, the full pass (`bars-queue.sh`), the Mac. Not seen in a check: a wide string (`L"..."`),
a truncated string, a function symbol as a one-byte variable, a big-endian PIECE or SUBPIECE in
`markInternalCopies`. Unit tests added: `entry_addr_of_a_spliced_cover` (block.rs) and
`codepoints` (printc.rs).

Follow-up on the same branch: the written read-only address is loud. `print C` fails with "the
warning for a written read-only address (fillinReadOnly) is not ported" when, with `option
readonly on`, an op that is not a marker writes read-only memory, before heritage
(`Funcdata::readonly_write`, set in `varnode_props`) or at the print (`action.rs`,
`readonly_written`). The test is wider than the C++ one: it leaves out `!isAddrForce() ||
!hasNoDescend()` and the one warning per op. Cost: one function, 0x23caea8 on switch `pcc-t`,
silent before and loud now; nothing else changed. Switch `pcc-t` 1943 / 2005 (loud 1, silent 61),
`pcc-r` 1944 / 2005 (loud 0, silent 61, as before: 0x23caea8 prints identically with rules on);
M500 `pcc-r` and `pc-r` 494 / 495 (silent 1: 0x47a6b0), `pcc-t` and `pc-t` 495 / 495, no loud
miss; M8 print checks 7 / 7. Every switch silent is now silent in an older switch check.
(Superseded: "silent 62" of `pcc-t` in the table, "one is new" and "It is open" above.) Not
rerun after the follow-up: the 51 other checks on M8, which the change cannot reach (only
`print C` reads the flag). (Superseded: the warning is ported and the loud failure, the flag
`Funcdata::readonly_write` and the whole-function test are gone; see "After `m3-int5`" at the
end of this section. `action.rs`, `readonly_written`, is now the written branch of
`fillinReadOnly`.)

Review fixes on the same branch:

- `variable.rs`: `vn_cover_dirty` goes through `h_cover_dirty` (`HighVariable::coverDirty`), so
  a varnode whose cover goes stale also marks the extended covers of the pieces its high
  intersects (`markExtendCoverDirty`). Before, only the high's own cover was marked.
- `console.rs`: `load addr` adds the function to the global scope (`IfcAddrrangeLoad`,
  `addFunction`), as `map function` does; `decomp-diff.sh` uses it for a function the prelude
  lacks. A function already mapped at the address stays as it is (the C++ warns of the overlap
  and adds a second symbol; not ported).
- `printc.rs`, `printlanguage.rs`: the string read at an address is kept (`PrintC::strings`,
  `StringManager::stringMap`), so a second constant at the address prints the same characters
  whatever its character size. The C++ keeps the map for the session, this for one `print C`.
- `mod.rs`: one size for an external-reference symbol, `Arch::externref_size` (the pointer
  size; superseded: the constant `EXTERNREF_SIZE`, 4, beside `stack_pointer.2`).
- `action.rs`: `readonly_written` moved out of the doc comment of `varnode_props`.

After them: M8 all 55 checks identical, each line equal to the run before the fixes. M500
`pcc-r` and `pc-r` 494 / 495 (silent 1: 0x47a6b0), `pcc-t` and `pc-t` 495 / 495, `nm-r`
498 / 499 (silent 1: 0x47a6b0, its baseline), `nm-t` 499 / 499 (baseline 493 / 499, loud 6: the
six `mergeAddrTied` functions of this slice). No function changed state with the fixes, though
`load addr` is live: the prelude lacks 1 function of M8, 98 of M500 and 25 of `r5d-adc` (none of
`switch` or `simple`). Not run after them: the switch corpus, `r5d-adc`, the other M500 checks,
the full pass. Not seen to change an output: a constant or variable at the address of a
function loaded with `load addr`, two character sizes at one string address, a stale cover of a
grouped variable.

Integration of `m3-swsilent` and `m3-print5` (branch `m3-int5`, 2026-11-17). Full pass
(`bars-queue.sh`), 127 pairs: 126 ran (desktop and Mac), and `s6void-m500`, lost when the Mac
was taken out of the pass, ran again on the desktop. No pair has fewer identical functions, more
silent misses or a different reference count than the slice 4 baseline. Switch corpus, of 2,004
(2,005 for print): `pcc-r` 1987 (loud 18, silent 0), `pcc-t` 1986 (loud 19, silent 0),
`paramdouble` 1988 (loud 16), `swfs-r`, `swfs-t`, `swfsc-r`, `swfsc-t` and `swsn-t` 1987 (loud
17), `swsn-r` 1984 (loud 17, silent 3: 0x8d8f40, 0x8eabe0, 0x8ead90, silent before). `simple`
print checks 194 / 194. M500 `pcc-r` and `pc-r` 494 / 495 (loud 1), `pcc-t` and `pc-t`
495 / 495. The only silent misses left in the pass are in `swsn-r`: those three on switch and 3 on
M500 (4 in the baseline); 0x47a6b0 is loud in every check. (Superseded: the switch counts of `m3-swsilent` and
slice 5 above, which were derived or from single checks.) Varies with load: the "all outputs
identical" count of `s6void-m500` is 499 / 500 here and 500 / 500 in the baseline (a reference
timeout; identical 499 / 499 in both).

After `m3-int5` (2026-11-17): the read-only write warning. `varnodeprops` has the written branch
of `Funcdata::fillinReadOnly` (`action.rs`, `readonly_written`). With `option readonly on`, an
op that writes read-only memory warns `Read-only address (ram,0x...) is written` at its
address, once (`OpFlags::WARNING`, the C++ `PcodeOp::warning`), unless the varnode is
address-forced and nothing reads it (`!isAddrForce() || !hasNoDescend()`). A marker (INDIRECT,
MULTIEQUAL) is only flagged. The warning goes through `Funcdata::warning`, so a jump-table
partial function adds its own `WARNING (jumptable):` line. A written read-only varnode also
skips the zero replacement of the same action, as in the C++, where the read-only branch comes
first. `print C` no longer fails on the case. 0x23caea8 is identical in switch `pcc-t` and
`pcc-r` (6 warning lines at 3 addresses). Switch `pcc-t` 1987 / 2005 (loud 18, silent 0; `m3-int5`
1986, loud 19). M500 `pcc-r` and `pc-r` 494 / 495 (loud 1),
`pcc-t` and `pc-t` 495 / 495; M8 all 55 checks as the baseline. Not run: `pcc-r` on the whole
switch corpus, `simple`, the full pass. Not seen: a marker writing read-only memory, an
address-forced write of it that nothing reads, a second visit of a warned op (0x23caea8 is the
only function of the corpora known to write read-only memory). Still wider than the C++: the
zero replacement runs for a read-only varnode that is only read, or with `option readonly off`.

After `m3-int5` (2026-11-17): the silent misses of `swsn-r`. All six (switch 0x8d8f40,
0x8eabe0, 0x8ead90; M500 0x48a430, 0x5c5940, 0x6b3730) have one cause, the one named in the
`m3-int` section: a ram varnode at an import slot (0x00b0511c, 0x00b05128, 0x00b05370,
0x00b052ec) that outlives the call through it, here the INDIRECTs and MULTIEQUALs on the slot,
prints `<code() *>` on the reference and `<xunknown4>` in ghidra-rs, and nothing else differs
(435 lines in 0x8eabe0, 9 or 10 in the M500 three). The C++ types the varnode from its
external-reference symbol when it is made; ghidra-rs applies the symbol types
(`infertypes::symbol_types`) before each inference pass and before merging, and with
`typerecovery` off neither has run at `break start returnsplit`. Fix: the console's `print raw`
applies them first (`console.rs`), as merging does. `swsn-r`: switch 1987 / 2004 (loud 17,
silent 0; before 1984, silent 3), M500 498 / 499 (loud 1: 0x47a6b0; before 495, silent 3). No
silent miss is left in the checks run: M8 all 55 as the baseline; M500 `swsn-r`, the four
print checks, `s6` 499 / 499 and `r5typed` 497 / 498 (loud 1); switch `swsn-r` and `pcc-t`.
Not run: the other M500 and switch checks, `simple`, `r5d-adc`, the full pass. Still open: the
type is not set when the varnode is made, so an action that reads a symbol's type or type lock
with `typerecovery` off before merging would not see it (none is known to; no check shows one).
(Superseded: "Open: set the symbol properties when a varnode is made" as the cause of a miss,
and "the only silent misses left in the pass are in `swsn-r`" above.)

### Segment and jump-assist user ops (branch `worktree-agent-a852cab363d8d01f3`, 2026-11-17)

The spec tags `<segmentop>` (`.pspec` and `.cspec`) and `<jumpassist>` (`.pspec`) are read
and their user ops ported. Before, a `.pspec` with either tag loaded with the tag ignored: the
user op stayed a plain CALLOTHER, silently. No command could reach such a spec (the console
loads `x86.pspec` and `x86win.cspec` only), so no output changed for 32-bit x86.

Ported:

- `Sleigh::load_with_pspec` loads a `.sla` with a `.pspec` of another name (16-bit x86 is
  `x86.sla` with `x86-16-real.pspec` or `x86-16.pspec`) and keeps the two kinds of elements.
- `decomp/userop.rs`: `SegmentOp`, `JumpAssistOp` and the part of `UserOpManage` that registers
  them (one segment op per space, one meaning per user op), with the C++ decode errors.
- `decomp/inject.rs`: `ExecutablePcode`, a snippet with `<input>` and `<output>` parameters run
  on values (`EmulateSnippet`); a LOAD reads the image. The snippet parser gained `zext(e)` and
  `sext(e)`. A script outside the parser's subset (a branch, a label) is an error when the spec
  is read.
- `ActionSegmentize` (`coreaction::segmentize`, once per function), `RuleSegment`
  (`rules/segment.rs`, group `segment`), `SEGMENTOP` in `print raw`, in the jump-table emulator
  (`executeSegmentOp`) and around a stack address made by `createStackRef` (`op_stack_load`).
- `JumpAssisted` in `jumptable.rs`: tried first when a CALLOTHER makes the switch address, on
  the partial function (addresses) and on the function (labels, `foldInNormalization`,
  `foldInGuards`). `earlyJumpTableFail` stops at a `jumpassist` or segment user op.

Fails loudly, on a spec with a segment op:

- Type recovery and constant pointers (`ActionInferTypes`, `ActionConstantPtr`): near and far
  pointers are not ported (`SegmentedResolver`, `markNearPointers`, `sizeOfPointer` /
  `sizeOfAltPointer`, the far-pointer rules of PIECE and SUBPIECE).
- The stack rules (`RuleLoadVarnode`, `RuleStoreVarnode`) when the stack space is narrower than
  the space it lives in (16-bit x86: a 2-byte `SP` in the 4-byte `ram`): stack offsets wrap and
  print at the container's size here. Found with the reference's `s0x0002:2(i)` against
  ghidra-rs's `s0x00000002:2(i)`.
- `setcasts` and `print C` on a `SEGMENTOP` (as before).
- A `jumpassist` table whose op no longer matches on the function (the C++ goes on to
  `JumpBasic` with the saved model); `funcptr_align` is taken as 0.
  Superseded (MIPS-4): `<funcptr>` is read and both kinds of table mask their targets by it.

So a 16-bit x86 function decompiles up to the first of these (with the default groups: type
recovery), and no further. No console command selects a 16-bit language or loads a raw image;
the checks below are unit tests.

Checked against `decomp_dbg` (`load test file` on the same bytes, language
`x86:LE:16:Real Mode:default`), byte-identical `print raw`:

- `action::tests::segmentize_x86_16_real_mode`: a 7-instruction function at
  `break start segmentize` and at the next `break start internalstorage`.
- `action::tests::rule_segment_folds_constants_x86_16`: `segment(0x40, 0x6c)` becomes
  `#0x46c` (`RuleSegment` and the script), at `break start deindirect`.

Not checked against `decomp_dbg`: `JumpAssisted` and the `<jumpassist>` scripts (only JVM and
Dalvik declare one; neither can be loaded here). `jumptable::tests::jump_assisted_model_runs_the_scripts`
runs a hand-made `<jumpassist>` on x86's `segment` user op: size, targets, labels, by hand.
`userop::tests::x86_16_segment_ops` checks the real and protected mode scripts' arithmetic by
hand. Also not run: `RuleSegment`'s far-pointer branch, `createStackRef`'s SEGMENTOP,
`executeSegmentOp`, a `<segmentop>` in a `.cspec`, and the Z80 and HCS12 specs.

Gate (2026-11-17, against the baseline `m3-int5-116d9d34da`): the 55 M8 checks give the same
summary lines as the baseline (every function the reference finishes is identical). M500
`pcc-r` 494 / 495 (loud 1), `pcc-t` 495 / 495, `swfs-r` 498 / 499 (loud 1): the baseline's
lines. `cargo test`: 138 passed. Not run: the other M500 checks, the switch and simple corpora,
the full pass.

### Default options: the check `pcd`, five action leaves, six rules (branch `m3-default`, 2026-11-17)

The check `pcd` runs `print C` with the default options: no group off and no break. Two lists
say what is still left out, on both engines:

- `D` at the top of `bars.sh`: the action leaves not ported. Now empty. (Superseded: "Now
  `restructure_varnode` and `mapped_local_sync`"; both are ported, see "Local symbols" below.)
- `tools/corpus/default-options.txt` (written by `r1-options.sh` from the rule tables): the
  rules of the three pools not ported. Now none: the file is empty since `m3-int6`.
  (Superseded: "Now eight: `aliasupdate`, `switchsingle`, `ptrflow`, `segment`,
  `ptrsubcharconstant`, `splitcopy`, `splitload`, `splitstore`", then two, `segment` and
  `ptrsubcharconstant`; see "Pool rules" and "Integration `m3-int6`" below.)

(Superseded: the next paragraph. A `decompile` run now fails while an unported rule is on; see
"Pool rules: every rule listed, a missing one fails" below.)

Not loud yet: without those `togglerule ... off` lines ghidra-rs runs the default options
*without* the eight rules and says nothing (a rule missing from the tables is simply not in the
pool). The seven silent misses of the first `pcd` run on M500 were all this (`conditionalmove`
and others missing). Every older rule check switches the missing rules off through its options
file, so only a run with the plain defaults is affected. Open decision: fail every
default-options decompile while a rule is missing, or keep it as it is.

Ported on the branch:

- `ActionMultiCse`, `ActionShadowVar` (`coreaction.rs`), `ActionConditionalConst`
  (`condconst.rs`). They run in the jump-table partial function too, as in the C++; the
  partial honours `DECOMP_SKIP_ACTIONS`, because the reference patch skips an action by name in
  every tree. The older checks keep `multicse,shadowvar,condconst` in their skip list (`S3` in
  `bars.sh`), so they stay comparable with their baselines.
- `ActionDynamicSymbols` and `ActionPrototypeWarnings` have nothing to do here (`action.rs`
  says why: no console command makes a dynamic symbol; every source of a prototype warning
  fails loudly earlier).
- Rules: `pullsub_indirect`, `conditionalmove`, `orpredicate`, `threewaycomp`; `transformcpool`
  fails on a CPOOLREF (the constant pool is not ported); `funcptrencoding` has nothing to do
  while no spec declares `<funcptr>` (cspec.rs refuses it; Superseded, MIPS-4: cspec.rs reads
  it and the rule is ported, "The decompiler on MIPS (MIPS-4)"). `CloneBlockOps::cloneExpression`
  (`returnsplit.rs`) for `conditionalmove`.
- `ActionParamDouble`: a stack trial that is a PIECE is split in two (`checkInputSplit`,
  `ParamActive::splitTrial`).
- `ActionConditionalExe` (`condexe.rs`, all of `ConditionalExecution`): a block testing a
  condition again is removed and its values flow to the matching side
  (`BlockGraph::removeFromFlowSplit` in `block.rs`). Before, finding such a block failed
  loudly. Still loud: a read of a removed op from inside the removed block (`opUnsetInput`).
- `TypeSpacebase::getSubType` reads the local scope's symbols (`infertypes::sub_type`), so
  `setcasts` casts the address of a named stack variable as the C++ does.

Counts: see the plan, "Default options". Superseded by this section: "not ported yet,
`multicse`, `shadowvar` and `condconst`" (stage R1), "Not ported from the table row:
`threewaycomp` ... `conditionalmove` and `orpredicate`" (stages R2 and R5), the
`PARTIAL_SKIP` list with `multicse`, `shadowvar`, `condconst` (stage S3), "`prototypewarnings`,
which is `not_ported`" (C printing), "splitting a stack trial that is a PIECE" as a loud
miss (stage R5 slice 3), and "0x47a6b0 is loud in every check" (the `ActionConditionalExe`
removal, integration `m3-int5`).

### Alias analysis of the jump-table partial function (branch `m3-aliasupdate`, 2026-11-17)

`RuleAliasUpdate` itself is three lines: it runs `Funcdata::opCollapseIndirectsForAlias` on a
STORE or call marked `store_aliasupdate`. What it collapses is decided elsewhere, by
`ActionRestructureVarnode` (the `nolocalalias` flag of a stack varnode) and by the value-set
range of a store guard. In the partial function the C++ runs all of it (`aliasyes` from the
second pass on), and after it `protectSwitchPaths` keeps one INDIRECT on a path from a constant
to the switch. Ported, for the partial function only:

- `rules/copy.rs`, `rules/mod.rs`: `RuleAliasUpdate` (`aliasupdate`, group `analysis`, after
  `multicollapse` in `oppool1`).
- `mapstate.rs` (new): `opCollapseIndirectsForAlias`, `syncVarnodesWithSymbols` with
  `markIndirectAliasUpdate`, `ScopeLocal::restructureVarnode` (`MapState::gatherVarnodes`,
  `gatherOpen`, `initialize` with `reconcileDatatypes`, `RangeHint::merge`, `absorb`,
  `attemptJoin`, `adjustFit`, `createEntry`, `fakeInputSymbols`, `markUnaliased`) and
  `protectSwitchPaths`. The partial function has no data-types, so a hint's type is the unknown
  type of its size, and a symbol is a bare entry (`varmap::LocalSym`: offset, size,
  `nolocalalias`, the `fake_input` category) in a `RangeMap` (`rangemap.rs` gains
  `find_overlap`).
- `varnode.rs`, `op.rs`: the varnode flags `mapped` and `nolocalalias` (`VnFlags` is 64 bits
  wide now), the op flags `store_aliasupdate` and `no_indirect_collapse`.
  `heritage_guard.rs` marks a STORE that gets a store guard (`analyzeNewLoadGuards`).
- `funcdata.rs`, `heritage.rs`: a new stack varnode inside one of these symbols takes the
  symbol's flags (`setSymbolProperties`: `SymbolEntry::getAllFlags`, so `mapped`, `addrtied`,
  and `nolocalalias` once `markUnaliased` set it), and the heritage guard reads `addrtied` from
  the symbol. (Superseded: "takes no property from the scope"; see "Review fixes" below.)
- `varmap.rs`: `markNotMapped` removes the symbols under its range, and a `fake_input` one
  keeps the range mapped.
- `varmap.rs`: `AliasChecker::gatherAdditiveBase` keeps the index term (`AddBase::index`).

Not ported, each failing with an error that names it: a valid load or store guard
(`MapState::addGuard` and `LoadGuard::isGuarded` read the value-set ranges; `ValueSetSolver`
is not ported), an open hint outside the local ranges and the parameter range
(`adjustOutOfRange` with `getNearestRange`), a locked prototype, a typed stack varnode or one
above `max_basetype_size`, a RETURN of a stack varnode (`checkUnaliasedReturn`),
`annotateRawStackPtr` once type recovery has started. (Superseded, see "Local symbols" below:
of these only a locked prototype with parameters is left, and the action runs
in the `decompile` root. Superseded (2026-11-24, branch `dwarf-params`): only one with a
parameter on the stack or in a join is left, see "Round 2: locked parameters as symbols".) The action of the `decompile` root
stays unported (`restructure_varnode` fails there as before), and `r1-options.sh` keeps
`aliasupdate` off in the function itself: there the rule fails on the INDIRECTs of an indexed
stack STORE. Without an options file the rule is on in the `decompile` root too:
`heritage_guard.rs` marks a STORE that gets a store guard in every root, so there the rule
fails loudly on a guarded STORE with INDIRECTs and otherwise collapses nothing (no varnode of
the function itself is `nolocalalias`). (Superseded: "a valid load or store guard" in the list
above, the mark set when the guard is made, and the rule failing on a guarded STORE; the guard
ranges are analysed and read now, see "Value-set analysis and the stack guards" below.)

`flow.rs` makes the partial function three ways (`Mode`): as the C++ does (`Exact`); without the
action and the rule when they reach one of the paths above (`NoAlias`), where the test of
`m3-swsilent` on the INDIRECTs of stack varnodes still decides, its error now naming the path
that was not ported; and without the `stackvars` rules as before (`NoStack`). In `Exact` no test
is made: the table is the one the partial function gives. The reference patch skips an action by
name in every root, so with `DECOMP_SKIP_ACTIONS=restructure_varnode` (the print checks) its
partial function runs without the action; ghidra-rs then leaves it out too
(`action::jumptable_partial`), and only the rule runs.

The 17 functions of the switch corpus that were loud on master (`paramdouble`, `swsn-r`,
`swfs-r`), before and after:

| functions | cause | now |
|---|---|---|
| 0x1cdbf0e, 0x7913d0, 0x7bb710, 0x7bf170, 0x831db0, 0x898690, 0x898850 | the test on the INDIRECTs of stack varnodes: the C++ collapses them all but the one `protectSwitchPaths` keeps, and the table fails on that one | identical |
| 0x1c69c5a | an indexed stack STORE in the partial function: its INDIRECTs go by the value-set range of the store guard | loud |
| 0x546d40, 0x5629d0, 0x78e7d0, 0x1b0c190, 0x502b80, 0x5c37f0 | an indexed stack LOAD on an address-tied range in the partial function (`guardLoads` needs the value-set range) | loud |
| 0x5a3c30, 0x807a80 | `ActionConditionalExe` is not ported | loud |
| 0x23f4238 | a multistage table (`switchnorm`); identical in `paramdouble`, loud from `swsn-r` on | loud |

What is left needs three ports: `ValueSetSolver` with the guard ranges (rangeutil.cc, about
1,500 lines; 7 functions), `ActionConditionalExe` (condexe.cc; 2) and the multistage recovery
(1). (Superseded: the first of the three is done and its 7 functions are identical, see
"Value-set analysis and the stack guards" below; `ActionConditionalExe` was ported on
`m3-default`.)

Checks. The master build stands in the reference's place (`decomp-diff.sh` with `DECOMP` set
to a wrapper of it), so a run lists the functions whose output the branch changes; the checks
against the reference then run on those. Nothing outside the partial function changes in the
function itself (the symbols exist only there, and in the `decompile` root of every check the
rule or its group is off, or the check stops before the stack is heritaged), so a function with
the same output at `paramdouble` has the same tables.

- Switch corpus, 2,050 functions at `paramdouble`, once with the action on and once with
  `DECOMP_SKIP_ACTIONS=restructure_varnode,mapped_local_sync` (what `pcc-r` and `pcc-t` set): 10
  outputs change in each run, the same 10. They are the seven of the first row above,
  0x2285c9b and 0x7c1f30, which the reference does not finish with the action on, and
  0x1c69c5a, still loud, with the new wording of its error.
- The first 9 against the reference: `paramdouble`, `swfs-r`, `swfs-t`, `swsn-r`, `swsn-t`,
  `swfsc-r`, `swfsc-t` 7 / 7 identical; `pcc-r` and `pcc-t` 8 / 8 (the reference finishes
  0x7c1f30 there). The 17 of the table in `paramdouble`, `swfs-r`, `swsn-r`, `pcc-r`, `pcc-t`:
  8, 7, 7, 7, 7 identical, the rest loud as the table says.
- Counts from that and the `m3-int5` pass, not from a run of the whole corpus against the
  reference: `paramdouble` 1988 -> 1995 / 2004 (loud 9), `swfs-r`, `swfs-t`, `swfsc-r`,
  `swfsc-t` and `swsn-t` 1987 -> 1994 (loud 10), `swsn-r` 1984 -> 1991 (loud 10, silent 3 as
  before), `pcc-r` 1987 -> 1995 / 2005 (loud 10), `pcc-t` 1986 -> 1994 / 2005 (loud 11). No
  function identical on master changes, none becomes silent.
- The two the reference does not finish. 0x7c1f30 now ends in the reference's error ("Unable to
  load 512 bytes at r0x5310ec83"; the reference meets it at `load function`, ghidra-rs at
  `decompile`). 0x2285c9b was loud and now prints a function, while the reference fails with
  "Unable to load 512 bytes at r0xc6bb1000": both engines fail the first table the same way,
  then the reference recovers the table at 0x2286023 and follows it out of the image, and
  ghidra-rs fails that table ("Could not emulate address calculation"). The loud test hid this
  difference; it is open and not traced.
- M8: all 55 checks against the reference, every summary line equal to the `m3-int5`
  baseline's (identical in each; in `fs-*`, `fsc-*`, `pc-*` and `pcc-*` the reference finishes 7
  of the 8, as before), and old against new 8 / 8 outputs equal in all 55. M500, old against new, `s8r`,
  `swfs-r`, `swfs-t`, `fs-t`, `paramdouble`, `pcc-r`, `pcc-t`, `r5s`, `r5slock`: 500 / 500
  outputs equal in each, so their counts are those of the `m3-int5` pass.
- The partial function against the reference's (`DECOMP_JT_RAW`, the INDIRECT ops of both), a
  sample of 140 switch functions: 125 equal; 8 made without the action (an indexed stack LOAD
  or a guard); 7 differ as
  they did on master, by fewer lines (the reference has `AL` for `EAX`, one byte of a stack
  slot; not traced, the partial function still runs without `multicse`, `shadowvar`,
  `condconst` and `normalizebranches`). Of 700 functions of the corpus, 672 are made
  the C++ way and 28 fall back (25 on an indexed stack LOAD in the stack heritage, 3 on a
  guard in the action).
- Not run: the full pass, the switch checks on the whole corpus and M500 against the
  reference, the Mac. One unit test (`mapstate.rs`): overlapping hints merge into an open
  range, and an alias offset reaches the symbols at and above it.

Review fixes (branch `m3-default`, 2026-11-17), from an independent review of the port:

- A new stack varnode inside a symbol of `restructureVarnode` got no flag; in the C++ it takes
  the symbol's (`Varnode::setSymbolProperties` sets `getAllFlags` whatever `updateType`
  returns): `mapped`, `addrtied`, and `nolocalalias` after `markUnaliased`. With the flags
  missing, the next `syncVarnodesWithSymbols` saw a change and marked the varnode's INDIRECT
  for `RuleAliasUpdate`, which the C++ does not.
- `markNotMapped` ignored the symbols of `restructureVarnode`: it now removes those under the
  range and keeps the range for a `fake_input` one, as the C++; a locked parameter under the
  range while such symbols exist, or a range wrapping the space, fails loudly.
- A partial function that fails with a normal error after it was made without the action and
  the rule (`NoAlias`) no longer gives a failed table ("Treating indirect jump as call"): the
  decompile ends with an error naming the path not ported. The same case for the partial
  function without the `stackvars` rules (`NoStack`) is as before and not reviewed.
- Checks, the build before the fixes against the one after: `paramdouble`, `swfs-r`, `swsn-r`,
  `pcc-r`, `pcc-t` on the switch corpus (2,050 / 2,050 outputs equal in each), all 56 checks on
  M8 (8 / 8 in each), `pcd`, `paramdouble`, `swfs-r`, `pcc-r`, `pcc-t`, `r5s` on M500
  (500 / 500 in each). No function changes state; none of the three paths changes an output of
  these corpora, so the fixes are tested only by one unit test (`varmap.rs`: the symbols under
  a range and the fake input).
- The same checks against the reference, the whole corpus (Superseded: the derived switch
  counts above): `paramdouble` 1995 / 2004 (loud 9), `swfs-r` 1996 / 2004 (loud 8), `swsn-r`
  1993 / 2004 (loud 8, silent 3 as before), `pcc-r` 1997 / 2005 (loud 8), `pcc-t` 1996 / 2005
  (loud 9). M8: 56 checks, the 55 summary lines of the `m3-int5` baseline unchanged, `pcd`
  8 / 8. M500: `pcd` 422 / 497 (loud 75), `paramdouble` 500 / 500, `swfs-r` 499 / 499, `pcc-r`
  and `pcc-t` 495 / 495, `r5s` 483 / 499 (loud 16). Loud on the switch corpus: the six indexed
  stack LOADs and 0x1c69c5a in all five, 0x23f4238 from `swfs-r` on, 0x23caea8 in `pcc-t`
  (`fillinReadOnly`), and in `paramdouble` only 0x5861aa and 0x7c74c0 ("a second table after
  the partial function's action failed is not ported"). Those two were identical in the
  `m3-int5` pass and are loud in the build before these fixes too: not traced. (Superseded:
  traced, see the next section.)

### Value-set analysis and the stack guards (branch `worktree-agent-af2329329d4027b82`, 2026-11-17)

An indexed LOAD or STORE through the stack pointer gets a guard record at the stack's first
heritage pass. The C++ then finds the stack range each one can reach with the value-set
analysis, and four places read that range. All of it is ported:

- `valueset.rs` (new, from rangeutil.cc): `ValueSet`, `ValueSetRead`, `WidenerFull`,
  `WidenerNone`, `ValueSetSolver` (`establishValueSets`, the constraints of the conditional
  branches with `applyConstraints`, `generateRelativeConstraint` and the landmarks,
  Bourdoncle's iteration order, `solve`). A varnode's set is found through a map in the
  solver; a varnode with a set is the C++ marked varnode.
- `rangeutil.rs`: the rest of `CircleRange` the solver needs (`pushForwardUnary`, `Binary`,
  `Trinary`, `minimalContainer`, `contains` of a range, `widen`, `invert`, `getMaxInfo`,
  `normalize`). Not ported: `setStride` (nothing calls it).
- `heritage_guard.rs`: `analyzeNewLoadGuards` with `LoadGuard::establishRange` and
  `finalizeRange`, `guardLoads` (a COPY of an address-tied range before each LOAD that may read
  it), `handleNewLoadCopies` with `findAddressForces` and `propagateCopyAway`. The
  `store_aliasupdate` mark of a guarded STORE is set by the analysis, as in the C++.
- The readers: `LoadGuard::isGuarded` in `opCollapseIndirectsForAlias` and `MapState::addGuard`
  in `gatherOpen` (`mapstate.rs`), `StackAffectingOps::populate` and `affectsTest` in the merge
  test (`variable.rs`, `cover.rs`).

Fails loudly: new guards after analysed ones (the C++ loop reads a missing value set there), a
value set read for a varnode that has none, a constant with more than one reader as a root.
`GHIDRA_RS_GUARD_DEBUG=<file>` appends one line per analysed guard (function, op, range, step,
state) to the file.

The two functions of `paramdouble` named above, 0x5861aa and 0x7c74c0, are not a guard case.
The reference's partial function fails in its action too ("Overlapping input varnodes", the
warning of the first table in `print C`), and the C++ then recovers the two later tables from
the half-simplified clone ("Too many branches" for both). ghidra-rs matches the first failure
and stops at the second table, which is the path not ported. They counted as identical in the
`m3-int5` pass only because `print raw` shows no warning and every table failed either way;
in `pcc-r`, `pcc-t` (`restructure_varnode` skipped) and the three `-r` switch checks they are
identical (why the action does not fail under the `-r` options was not traced). Left loud: taking a table from a clone whose action stopped
half way needs that state to be equal op for op, which no check shows.

Checks (reference `decomp_dbg`, same options as the bars):

- The 22 functions of M500 that were loud in `pcd` on a guard (16 "indexed stack LOAD", 6
  "STORE guard" in the merge), all 56 checks: 52 checks 22 / 22 identical; `pcd` 18 / 22 (loud:
  3 `getExactPiece`, 1 `HeapSequence`), `r5c` 21 / 22 (`HeapSequence`), `r5slock` and
  `r5dtlocksv` 19 / 22 (a piece of a locked stack parameter). Silent 0. (That run used a build
  that differs from the commit by comments, a dead field, two clippy rewrites and the debug
  line.)
- The 7 switch functions blocked on guard ranges (0x1c69c5a, 0x546d40, 0x5629d0, 0x78e7d0,
  0x1b0c190, 0x502b80, 0x5c37f0) with 0x5861aa and 0x7c74c0, in `paramdouble`, `pcc-r`,
  `pcc-t`, `swfs-r`, `swfs-t`, `swsn-r`, `swsn-t`, `swfsc-r`, `swfsc-t`: the 7 identical in all
  nine; the other two identical in `pcc-r`, `pcc-t`, `swfs-r`, `swsn-r`, `swfsc-r`, loud in
  `paramdouble`, `swfs-t`, `swsn-t`, `swfsc-t`.
- The whole corpora, in two steps (the committed build). A function with no load or store
  guard takes no new code path, so its result is that of the `m3-default` pass. Step one runs
  the check with ghidra-rs alone and `GHIDRA_RS_GUARD_DEBUG` and lists the functions with a
  guard, in the function or its partial function; step two runs those against the reference.
  Switch corpus (2,050): `paramdouble` 68 with a guard, 66 / 66 identical (the reference does
  not finish 2); `pcc-r` 98, 96 / 96; `pcc-t` 68, 66 / 66; `swsn-t` 68, 66 / 66. M500 `pcd`: 26
  with a guard, 18 / 25 identical, 7 loud (6 `getExactPiece`, 1 `HeapSequence`, all loud before;
  the reference times out on 0x6b21e0). Silent 0 in all five, no function identical before is
  anything else now.
- Counts derived from that and the `m3-default` pass, not from a run of every function against
  the reference: switch `paramdouble` 1995 -> 2002 / 2004 (loud 2: 0x5861aa, 0x7c74c0), `pcc-r`
  1997 -> 2004 / 2005 (loud 1), `pcc-t` 1996 -> 2003 / 2005 (loud 2); M500 `pcd` 422 -> 440 / 497
  (loud 75 -> 57: 18 of the 22 guard functions are identical, 4 are loud on another port).
- M8, 11 checks (`heritage`, `paramdouble`, `s4`, `r5`, `s7t`, `s8r`, `r5s`, `fs-t`, `pcc-r`,
  `pcc-t`, `pcd`): identical in each. Not run: the other 45 checks on M8, the other switch
  checks on the whole corpus, M500 beyond `pcd`.
- One unit test (`rangeutil.rs`, `value_set_ranges`): push-forward, container and widening on
  hand-computed ranges. The solver has no unit test; it is checked only through the functions
  above.

### Default options: pieces of symbols at naming and printing, `HeapSequence` validity (2026-11-17)

The 51 `pcd` M500 functions loud in `namevars` and the two loud in `RuleStringStore`:

- `namevars.rs`: `HighVariable::finalizeDatatype` asks `TypeFactory::getExactPiece`
  (`infertypes::exact_piece`) for the piece of the symbol's data-type the variable covers. No
  piece (a part of a scalar), or an unknown one, leaves the variable's type alone, as the C++.
  Still loud: a piece whose type differs from the variable's (nothing ported reads
  `type_finalized`), and a partial struct, array, union or enum. Superseded: "`finalizeDatatype`
  of a piece of a symbol (`getExactPiece`) fails loudly". (Superseded by "Local symbols" below,
  joined on `m3-int6`: the piece's type is kept, `type_finalized` is read by
  `variable::h_type`; only the partial types stay loud.)
- `printc.rs`: `PrintC::pushMismatchSymbol` for a variable running past the end of its local or
  data symbol: `_name` at the symbol's start, else the unnamed location (`stack0x...`).
  Superseded: "a variable past the end of its symbol (`pushMismatchSymbol`)" in the loud list of
  slice 3A. The case of a function or external reference symbol stays loud.
- `rules/constseq.rs`: the `HeapSequence` constructor (`findBasePointer`,
  `findDuplicateBases`, `findInitialStores`, `collectStoreOps`, `checkInterference`,
  `formByteArray`). A STORE of a character constant that roots no sequence of four characters
  is left alone; a valid sequence fails loudly (`HeapSequence::transform`: the built-in string
  copy user-op, its internal string and their printing are not ported). Superseded:
  "`stringstore` fails at `HeapSequence` (not ported)" (stage R5 slice 5) and the three
  HeapSequence misses of `r5c` (0x41f7f0, 0x4c1230, 0x766350: none is a valid sequence).
- `merge.rs`, `snipOutputInterference`: the C++ sorts the reads by `HighVariable` address
  (`PcodeOpNode::compareByHigh`). With reads of several variables of one group the order is
  the allocator's (a new `HighVariable` reuses freed memory) and it numbers the copies made.
  ghidra-rs sorted by creation order, which gave 0x4130d0 two copies swapped once naming let
  it through; such a snip now fails loudly. Reads of a single variable are unchanged.

Counts, M500: `pcd` 474 / 497 (loud 23, silent 0; before 422, loud 75). 50 of the 51 and both
`RuleStringStore` functions are identical; 0x4130d0 is loud in `snipOutputInterference`. Left:
16 indexed stack LOADs, 6 STORE guards, that one. `nm-r`, `nm-t`, `s7r` 499 / 499, `pcc-r`,
`pcc-t` 495 / 495, `r5c` 498 / 498 (494 in the `m3-int5` pass: the three HeapSequence
functions here; the fourth, 0x47a6b0, is identical too, and `r5c` was not run on `m3-default`,
so where it changed is not measured). M8: the 56 summary lines unchanged.
Not run: the switch and `simple` corpora, and the other M500 checks.

### Local symbols: `restructure_varnode` and `mapped_local_sync` in the `decompile` root (2026-11-17)

The last two action leaves of the default pipeline run in the `decompile` root. `D` in
`bars.sh` is empty: `pcd` skips no action. (Superseded: "Now `restructure_varnode` and
`mapped_local_sync`" in "Default options: the check `pcd`" above, and "The action of the
`decompile` root stays unported" in the alias analysis section above.)

One port serves the root and the jump-table partial function (`mapstate.rs`; the partial
function's hints simply have unknown types):

- Range hints carry data-types: `RangeHint::reconcile`, `isConstAbsorbable`, `preferred` with
  `typeOrder`, `attemptJoin` through pointers, `reconcileDatatypes`; `createEntry` makes an
  array when more than one element fits. `MapState::adjustOutOfRange` with
  `RangeList::getNearestRange` and the backfill hints (`attemptBackfill`, `backfillOpen`)
  replace the loud "open range hint outside the local ranges".
- A symbol is an entry of `LocalMap` (range, `nolocalalias`, the `fake_input` category) with a
  typed, unnamed symbol of the local scope behind it (`Funcdata::add_local_sym`), so the
  `$$undef` names count up as in the C++. `markNotMapped`, `clearUnlockedCategory(-1)` and
  `clearCategory(fake_input)` remove both.
- `checkUnaliasedReturn` (through `markNotMapped`) and `annotateRawStackPtr` (a `PTRSUB(sp, #0)`
  and a symbol at stack offset 0) are ported. (Superseded: the two loud paths of the same
  names.)
- `syncVarnodesWithSymbols` with `updateDatatypes`: `ActionMappedLocalSync` gives a stack
  varnode the data-type of its place in its symbol (`TypeFactory::getExactPiece`). The action
  runs in the partial function too (it left `action::PARTIAL_SKIP`).
- `ActionInputPrototype` clears the fake inputs first; a reference into the stack parameters
  that no input covers is a trial (`gatherParamSpacebaseRefs`, `markActiveInputRefs`) or gets a
  symbol (`addRefOnlySymbols`).

Readers of the symbols that changed with them:

- `RulePtrArith` asks `TypeSpacebase::nearestArrayedComponentForward` and `Backward` for an
  array symbol near a stack offset (`infertypes::nearest_arrayed_component`, with
  `ScopeInternal::findSymbolAfter` and `findSymbolBefore`; `rangemap.rs` gains `after` and
  `before`). It assumed no array symbol exists, which was a silent difference (0x4042e0:
  `axStack_4a + -6`).
- `HighIntersectTest::testUntiedCallIntersection` reads `hasNoLocalAlias`; `baseExplicit` reads
  `isMapped` for a varnode that is not address-tied.
- `finalizeDatatype` takes the type of the variable's place in its symbol and keeps it
  (`type_finalized`, read by `variable::h_type`). (Superseded: "`finalizeDatatype` of a piece
  of a symbol (`getExactPiece`) fails loudly" and "changing the data-type of a variable is not
  ported".)
- `PrintC::pushMismatchSymbol` for a variable larger than the symbol at its address
  (`_xStack00000000`).
- `linkSymbol` fails loudly where `handleSymbolConflict` would make a dynamic symbol.
  (Superseded: the reference, Ghidra 12.3, has no `handleSymbolConflict`; `linkSymbol` links any
  entry that is not a conflict, see "Integration `m3-int6`: review fixes".)
- `RuleStringCopy` fails loudly on a character copied into a symbol of `restructure_varnode`
  (`StringSequence` is not ported). (Superseded: `StringSequence` is ported up to its validity; a
  valid sequence stays loud, see "Java-facts gap, continued".)
- Fixed on the way: `subflow.rs` and `subfloat.rs` read the size of a locked varnode's type
  from the architecture's type factory instead of the function's (a panic once the stack
  pointer's space-base type was reached; `bars.sh` counted it as silent).

Not ported, each failing with an error that names it: a structure or union among the hints, a
locked prototype with parameters, a piece of an array symbol as a data-type
(`getTypePartialStruct`), a reference into the stack parameters of a locked prototype, a load or
store guard whose pointer points to a union (since "Integration `m3-int6`: review fixes": whose
pointer has a data-type that `needsResolution`, or points to a union). (Superseded: "a valid load or store guard
(`MapState::addGuard`, the value-set ranges)" in this list: the integration `m3-int6` joined
this port with `MapState::addGuard` of "Value-set analysis and the stack guards"; in the
`decompile` root the guard's hint takes the data-type its pointer points to, see "Integration
`m3-int6`" below.)

The check `pmd` (new in `bars.sh`): `print map` and `print raw` at `break start startcleanup`
with the default options, so the symbols (their `$$undef` names, ranges, types, attributes) and
the typed ops are compared right after `mapped_local_sync`, before naming and printing. It
found a silent difference `pcd` hid behind a later error (0x581bf6 of `simple`):
`ActionUnjustifiedParams` looked at register inputs only and passed over a stack input in the
middle of a parameter slot, which the C++ widens (`adjustInputVarnodes`, not ported). A stack
input fails loudly there now.

Counts: see the plan, "Local symbols".

### Pool rules: every rule listed, a missing one fails (branch `worktree-agent-ab53ef4e46d4bec80`, 2026-11-17)

Behaviour change: a `decompile` run fails while a pool rule that is not ported is on. Before, a
rule missing from the rule tables was simply not in the pool, and a run with the default
options gave a result without it and said nothing (superseded: "Not loud yet" and the open
decision in "Default options" above).

- The tables `OPPOOL1`, `OPPOOL2` and `CLEANUP` (`rules/mod.rs`) now list every rule of the C++
  pools, in the C++ order: a ported rule as `r(...)`, one that is not as `u(...)` (name, group,
  op list). A unit test reads `coreaction.cc` and the rule constructors in the `.hh` files and
  compares names, groups and order, so a rule the C++ gains or one dropped here fails
  `cargo test`.
- The `decompile` root (`pool::select` with `strict`): a pool holding a `u` rule whose group is
  on and that `option togglerule <rule> off` did not switch off fails when it is first applied:
  "pool rules not ported to ghidra-rs yet are on: ...". Switching the rule off on both engines
  is the only way to run, and `tools/corpus/default-options.txt` (the `pcd` skip list) is where
  the checks do it. A run that stops at a break before the pool is not affected.
- The `jumptable` root, which no option reaches: the `u` rule is in the pool and fails on the
  first op of its op list (for `segment`: a SEGMENTOP in the partial function).
- `r1-options.sh` reads the `r(` entries as the ported rules.

Two rules are `u` entries, both ported on other branches and left for integration (replace the
`u` line by the `r` line there): `segment` (branch `worktree-agent-a852cab363d8d01f3`) and
`ptrsubcharconstant` (branch `worktree-agent-af954dab401167074`). `default-options.txt` holds
these two (superseded: eight). (Superseded on `m3-int6`: both are `r(...)` entries now, no
table holds a `u` rule, `default-options.txt` is empty; `u` stays for the unit test and for a
rule the C++ pools gain.)

Ported here:

- `switchsingle` (`RuleSwitchSingle`, `rules/mod.rs`): a BRANCHIND whose block has one out edge
  and whose table has its labels becomes a BRANCH to the one destination, the table is removed
  and the structure cleared; the header warning "Switch with 1 destination removed at ..." as
  in the C++.
- `ptrflow` (`RulePtrFlow`): its op list is empty unless the default data space is truncated
  (`<truncate_space>` in the `.ldefs`, which ghidra-rs does not read). The console now refuses
  a `.sla` that a language with a `<truncate_space>` uses in an `.ldefs` next to it
  (`Sleigh::refuse_truncated`; no x86 language has one), so the rule has nothing to do. The
  truncation itself (`SleighArchitecture::modifySpaces`, `truncatePointer`) is not ported.
- `splitcopy`, `splitload`, `splitstore` (`SplitDatatype`, `rules/split.rs`): a COPY, LOAD or
  STORE of a structure or array becomes one op per component (`getValueDatatype`,
  `categorizeDatatype`, `getComponent` with holes, `testDatatypeCompatibility`,
  `RootPointer::find` and `backUpPointer`, `buildPointers`, `buildInConstants`,
  `buildInSubpieces` with `generateConstants`, `buildOutVarnodes`). Each of these fails with
  an error naming it: a data-type that needs resolution (unionresolve.cc is not ported, so the
  `ResolveCache` is left out), a piece of a structure or array (`TypePartialStruct` from
  `getExactPiece`), the CONCAT of split outputs (`buildOutConcats`: proto-partial pieces need
  `VariablePiece`), so a COPY or LOAD is split only when nothing reads its output, a value in
  the join space. A STORE through an address-tied root pointer copies it to a temporary first
  (`Funcdata::buildCopyTemp`).
  `TypePointerRel` is not a ghidra-rs type.
- `aliasupdate` in the `decompile` root: the rule was already in the root's pool (branch
  `m3-aliasupdate`); `default-options.txt` no longer switches it off, so `pcd` runs it on both
  engines. What the root still lacks is not in the rule: the value-set range of a store guard
  (a guarded STORE with INDIRECTs fails loudly) and `restructure_varnode` (`nolocalalias`).
  The older rule checks keep it off (`r1-options.sh`), as before. (Superseded on `m3-int6`:
  the root has both, "Value-set analysis and the stack guards" and "Local symbols"; the older
  rule checks still keep the rule off, as their baselines were made.)

The options files of the rule checks lose `togglerule switchsingle off` (and
`subvar-options.txt` `ptrflow off`), so those checks run `switchsingle` on both engines now.

Counts: see the plan, "Pool rules".

### Stage S10 (reference and inventory only; blocked), branch `worktree-agent-a6369f440dde42a16` (2026-11-17)

Nothing of the decompiler changed in this slice. It adds the S10 check and records why the S10
gate (M8 identical to Java Ghidra) cannot be reached yet.

The check, `tools/ghidra-diff.sh <corpus>`: `tools/ghidra/DecompileRef.java` (the
`DecompInterface` call of mercs2's `Decompile.java`, one output file per address) runs in
headless Ghidra on a copy of the mercs2 Ghidra project, opened `-readOnly`; the console side is
`print C` with default options, from ghidra-rs or, with `ENGINE=ref`, from `decomp_dbg`. The
Java output is kept under `rust/target/ghidra-ref/java/<corpus>/` (the installed Ghidra is 12.2,
the sources of this repository 12.3; superseded: the reference is now 12.3 built from this
repository, see "The 12.3 reference" below). Summary line: `java finished F / N, identical I / F (loud
L, silent S)`.

Results:

| run | result |
|---|---|
| `ghidra-diff.sh m8` (ghidra-rs) | java finished 7 / 8 (no function at 0x54c990 in the Java project), identical 0 / 7, loud 7: "action restructure_varnode is not implemented" |
| `ENGINE=ref ghidra-diff.sh m8` | identical 0 / 7 (the inventory below) |
| `ENGINE=ref ghidra-diff.sh m500` | java finished 499 / 500 (0x4c48d0: 60 s timeout), identical 0 / 499 |
| `decomp-diff.sh m8`, `print C`, default options | ghidra-rs loud 8 / 8 |
| the same with the eight unported actions skipped on both engines | M8 identical 8 / 8; M500 reference ran 498 / 500, identical 410 / 500, loud 78, silent 11, and 0x4c48d0 (reference timeout) |

Why it is blocked: Java Ghidra runs the default `decompile` action, every group on. ghidra-rs
does not finish it for any function. The print checks of S9 (`pc-*`, `pcc-*`) run with the
`tail-t` options (14 groups and 5 rules off) and with `restructure_varnode` and
`mapped_local_sync` skipped. With default options eight leaves of `action.rs` are `not_ported`
and fail loudly: `restructure_varnode` and `mapped_local_sync` (group `localrecovery`:
`ScopeLocal::restructureVarnode`, `MapState`, `RangeHint`, `markUnaliased`, `fakeInputSymbols`,
`remapSymbol`, the name recommendations of `varmap.cc`, about 1,100 lines of C++ not in
`varmap.rs`), `multicse`, `shadowvar`, `condconst` (group `analysis`), `directwrite`
(`protorecovery_b`), `dynamicsymbols` (`dynamic`) and `prototypewarnings` (`protorecovery`).

With those eight skipped on both engines (`DECOMP_SKIP_ACTIONS`), default options otherwise:
of the 78 loud M500 functions 36 fail at "ActionParamDouble: splitting a stack trial that is a
PIECE", 17 at "heritage: an indexed stack LOAD ..." (one of them 0x6b21e0, where
the reference timed out), 14 at "namevars: finalizeDatatype of a
piece of a symbol (getExactPiece)", 5 at "merge: a STORE guard of the stack heritage pass", 3 at
"subflow: a logical value in a join varnode", 2 at `RuleStringStore` (`HeapSequence`), 1 at
`ActionConditionalExe`. 11 are silent, which no check of
`bars.sh` runs: 0x40dc10 (`extraout_EDX` against `pfVar2`), 0x434f70, 0x494400 and 0x5b8ca0 (a
missing `(xunknown1 *)` cast of a stack address), 0x45ec20, 0x571cc0, 0x5d3c90, 0x5d4050 and
0x74c9b0 (other local declarations), 0x5c5ba0 (`in_XMM0_Da` against `in_XMM0_Qa`), 0x6fa6e0
(`param_1[9]` against `param_1[8]`). Not looked into.

What Java Ghidra prints that `decomp_dbg` does not (M8 and M500, `ENGINE=ref`), the S10 work
proper, none of it ported:

- Core type names: `undefined4`, `undefined1`, `int`, `uint`, `byte`, `float` for `xunknown4`,
  `xunknown1`, `int4`, `uint4`, `uint1`, `float4`; with them the variable prefixes (`uVar1`,
  `auStack_c0`, `puVar1` for `xVar1`, `axStack_c0`, `pxVar1`).
- Function names: `FUN_00401000` for `func_0x00401000`; a thunk to an import by the import's
  name (`D3DXVec3TransformNormal` for `func_0x0096bd76`); FID names without decoration
  (`__security_check_cookie` for `@__security_check_cookie@4`).
- Global names from the listing: `DAT_00cde2b0`, `_DAT_0256f88a`, `PTR_FUN_00bd2f98` for
  `iRam00cde2b0`.
- Read-only data: Java prints `DAT_00b9b664` and `DAT_00b97eec` where `decomp_dbg`, with the
  prelude's `readonly` range, prints the constants `1.0` and `0.01`.
- Stack locals: `local_bc` where `decomp_dbg` prints `iStack_bc` (the local range of the
  prototype; 117 of the 499 M500 functions have a `local_`), and other pieces
  (`auStack_4a [6]`, `uStack_44` for `axStack_4a [2]`, `xStack_48`).
- Prototypes of the project: import parameter types (`LeaveCriticalSection((LPCRITICAL_SECTION)
  ...)`), stored calling conventions and parameters of callees (`FUN_...(in_EAX)`, 152 of the
  499 print a convention), no-return callees ("WARNING: Subroutine does not return").
- Function set: 0x54c990 is no function in the Java project; in 0x9eec5e Java prints the jump
  to `___report_gsfailure` as a call that does not return, where `decomp_dbg` follows the jump
  and prints that function's body.
- Comments: the FID plate comment ("Library Function - Single Match"), "WARNING: Globals
  starting with '_' overlap smaller symbols at the same address" (80 of the 499).
- Frame: Java's text ends with a blank line; `ghidra-diff.sh` drops blank lines before and
  after the function on both sides.

Not run: the checks of `bars.sh` (no Rust source changed), `ghidra-diff.sh` on the other
corpora. Not decided: how ghidra-rs gets the Java project's facts (names, prototypes, data
types, listing data), and the name of the output mode.

Superseded: "none of it ported" and "Not decided" above. The next slice ports the list (see
"Stage S10, slice 1"); the facts come from an export of the Ghidra project and the mode is the
console command `load facts`. The eight actions are still not ported, so the gate is still out
of reach.

### Stage S10, slice 1: the facts of a Ghidra project and `load facts`, branch `worktree-agent-af954dab401167074` (2026-11-17)

Java Ghidra's decompiler is the same C++ as `decomp_dbg`; what differs is what Java feeds it.
This slice records those answers once and lets ghidra-rs read them, so the list of the slice
above comes out of the ported C++ paths rather than out of new printing code.

**The facts** (where they come from is not the user's decision yet; this is the choice made
here). `tools/ghidra/ExportFacts.java`, run headless by `tools/ghidra-facts.sh` on the copy of
the Java project (`-readOnly`), calls `DecompileCallback` and `PcodeDataTypeManager` as
`DecompInterface` does and writes each answer as the XML Java would send, one record per line,
fields separated by tabs, to `$GHIDRA_REF/mercs2.facts` (127 MB for mercs2, about two minutes;
the file is version 2, see "Review fixes" below):

| record | what | mercs2 |
|---|---|---|
| `coretypes <xml>` | `encodeCoreTypes` | 1 |
| `block <first> <last> <r\|w>[v]` | a memory block: writable or not, volatile | 14 |
| `wref <addr>` | an address of a non-writable block with a write reference | 265 |
| `func <entry> <xml>` | `getMappedSymbols(entry)` while that function is decompiled | 44,990 |
| `body <entry> <first>-<last> ...` | the ranges of the function's body | 44,990 |
| `tracked <entry> <xml>` | `getTrackedRegisters(entry)`, written when it differs from the function before | 37 |
| `comments <entry> <xml>` | `getComments(entry)`, when there is one | 1,613 |
| `data <first> <length> <xml>` | `getMappedSymbols` of defined or labelled data | 271,502 |
| `extref <addr> <xml>` | `getExternalRef` of a pointer to an external location | 1,022 |
| `label <addr> <name> [<entry>]` | `getCodeLabel` of a primary symbol at an instruction; with `<entry>`, the name only that function's decompile gets | 218,095 (0 with an entry) |
| `depth <entry> <to> <change>` | a stack-depth-change override at a call site of the function | 0 |
| `string <first> <length> <n\|->` | defined string data; `n` characters when a raw read gives what `getStringData` gives | 26,420 (213 `-`) |
| `undef <first> <last> <prefix>` | undefined bytes of a block that is not writable | 58,069 (`UNK_`) |
| `override <addr> <kind>` | an instruction with a flow, fall-through or length override | 3,365 |
| `type <id> <xml>` | `getDataType` of each `<typeref>` in the records | 376 |
| `ns <id> <xml>` | `getNamespacePath` of each namespace id in the records | 798 |

`load facts <file>` (`decomp/facts.rs`) indexes the file by address (about 0.5 s) and reads
the core types and the `type` records; every other record's XML is parsed when a decompile asks
for it. The loader is one module behind `Arch::load_facts`, `Arch::callee_proto`,
`Arch::start_function`, `Arch::is_readonly`, `Arch::data_holds` and `facts::query_symbol`, so
another source of facts can replace it.

**What `load facts` changes** (nothing changes without it; the checks against `decomp_dbg` use
the prelude as before):

- Core types: Ghidra's (`TypeFactory::set_core`, the cache rule of `cacheCoreTypes` with
  Ghidra's ids), so `undefined4`, `int`, `uint`, `byte`, `float`, and with them `uVar1`,
  `puVar1`, `auStack_c0`.
- Functions: the listing's, with their names (`FUN_00401000`, a thunk by its import's name,
  FID names); `load addr` takes the listing's name. An external reference is the pointer's
  record with the function Java hangs on it (the import's locked prototype).
- Prototypes (`Facts::function`, `FuncProto::decode`): the model (`unknown` is a copy of the
  default model, `createUnknownModel`), the model lock, the extrapop Ghidra computed, call
  fixups, locked parameters and return value with the storage Java gives, and no-return: a
  call to such a function is followed by an artificial halt (`checkForFlowModification`,
  `Halt::NoReturn`, never printed) and "WARNING: Subroutine does not return".
- Flow overrides: `CALL_RETURN` on a jump (`PcodeEmit.dumpCallOverride`): the jump is a call,
  followed by `RETURN #0`.
- The function's own record: its prototype, the tracked registers at its entry in place of the
  processor spec's (`FS_OFFSET` and `DF` for mercs2), the listing's comments (the plate comment
  at the entry is a header comment after the warnings, a pre comment is printed at its
  address; `CommentDatabaseGhidra::fillCache`), and its stack variables as name
  recommendations (`ScopeLocal::collectNameRecs`, `recoverNameRecommendationsForSymbols`:
  `local_bc`).
- Data symbols (`ScopeGhidra::removeQuery`): the symbol holding an address joins the function's
  global scope when `mapGlobals`, `linkSymbol` or `linkSymbolReference` ask (`DAT_00cde2b0`);
  a variable larger than the symbol at its address prints `_DAT_0256f88a` with the header
  warning (`pushMismatchSymbol`); a locked data-type types the varnodes the symbol holds; the varnodes
  a data symbol or a label holds are isolated from speculative merging (Java sends `typelock`
  and `merge="false"` with every `HighCodeSymbol` and `HighLabelSymbol`).
  Superseded: "every data symbol is isolated" (it did not name the labels, which Java isolates
  too: 17,878 `<labelsym>` records of mercs2, each with `merge="false"`).
- Pointers to data symbols (`ActionConstantPtr`): `&PTR_FUN_00bd2f98`, an array by its name
  (`hkpEntityListener::vftable`), a string through `RulePtrsubCharConstant` (ported here:
  `"AimMovementNodes"`).
- Read-only memory is the listing's (`Facts::readonly`: a symbol's flag; a block that is not
  writable unless the address has a write reference; in a function's body past the first 8
  bytes). Java Ghidra sends no options from `DecompileRef.java`, so read-only memory does not
  fold to constants (`DAT_00b9b664` stays).
- Names of symbols in namespaces: the namespace path before the name (`pushSymbolScope` from a
  function of the global namespace).
- Labels: the listing's label at a block (`queryCodeLabel`, `LAB_00401178`).

**Fails loudly with facts** (each an error when a decompile reaches it): a data symbol of
struct or union type, or an array read as a variable, or a pointer into one (not its start;
strings excepted); struct, union or array symbols near an address `RulePtrArith` looks at
(`TypeSpacebase::nearestArrayedComponent`); a string that is not plain ASCII, or of wide
characters (Java reads strings with the listing's character sets, `getStringData`); a function
data-type with a prototype used for an indirect call (`forceSet`); the decompile of a function
in a namespace (superseded, 2026-11-23, branch `fix-hatred-facts`: it is ported, see "Namespaces
and DWARF prototypes in the ELF facts"); a prototype with only its inputs or only its output locked, an unlocked
varargs prototype, custom storage, hidden return parameters, `inline`, prototype and
jump-table overrides; names recommended for register variables; locked local variables;
every flow override but `CALL_RETURN` on a jump or a call; volatile memory; signed
enumerations, pointer-relative data-types, bit fields, display formats. The declaration of a
function with a locked prototype was not ported before and is not now.

**The check.** `tools/ghidra-diff.sh` now gives ghidra-rs the facts (`FACTS=0`: the prelude,
as before; since 2026-11-18 a `FACTS=<file>` that is missing or empty stops the run with
`<corpus>: FACTS missing: <file>` or `FACTS empty: <file>` and exit 1, before any Java or
ghidra-rs work; before, a missing file fell back to the Java facts and an empty one ran with no
facts, both silently) and, with `CLASSIFY=<actions>`, marks each miss `skip` or `own`: `decomp_dbg` runs
with the prelude twice, with and without those actions, and a function whose two outputs
differ needs the actions (`skip`). It is a guide: `decomp_dbg` has no data symbols, so an
action can matter with the facts and not without them (0x73a340: `multicse` on a read-only
global that the prelude folded).

Results (`GHIDRA_REF` holding the Java C of the slice above; "the eight skipped" is
`SKIP=restructure_varnode,mapped_local_sync,multicse,shadowvar,condconst,directwrite,dynamicsymbols,prototypewarnings`,
which only ghidra-rs skips here: Java runs them):

| run | result |
|---|---|
| `ghidra-diff.sh m8` | java finished 7 / 8, identical 0 / 7, loud 7 ("action restructure_varnode is not implemented") |
| `ghidra-diff.sh m8`, the eight skipped, `CLASSIFY` | identical 3 / 7 (0x40a110, 0x58d030, 0x9eec5e), silent 4, all four marked `skip` |
| `ghidra-diff.sh m500` | java finished 499 / 500, identical 0 / 499, loud 499 (498 the same action; 0x403060 a function in a namespace) |
| `ghidra-diff.sh m500`, the eight skipped | identical 192 / 499 (loud 72, silent 235) |
| `bars.sh`, `CORPORA=m8`, every check | 55 lines, each equal to the baseline's (`m3-int5-116d9d34da.summary`) |
| `bars.sh`, M500 `pcc-r`, `pcc-t`, `pc-r`, `pc-t`, `nm-r`, `nm-t` | `pcc-r` 494 / 495 (loud 1), `pcc-t` 495 / 495, `pc-r` 494 / 495 (loud 1), `pc-t` 495 / 495, `nm-r` 498 / 499 (loud 1), `nm-t` 499 / 499: the six lines equal the baseline |

What is left of the four M8 misses is what the eight actions do in Java and not here: the
store to `_DAT_0256f88a` in 0x401000 (`directwrite`), the stack variables of 0x401080 and
0x4042e0 (`restructure_varnode`: `auStack_c0 [4]`, `local_90 [40]`; the names the facts
recommend are there, `local_bc`), and `uVar1 = DAT_00b9b664` in 0x73a340 (`multicse`). Their
other lines are Java's.

The M500 misses with the eight skipped. Loud 72: 54 are the misses default options reach
without facts (`ActionParamDouble` on a PIECE 26, an indexed stack LOAD 13, `getExactPiece`
in `namevars` 8, a STORE guard in `merge` 4, `subflow` 1, `HeapSequence` 1,
`ActionConditionalExe` 1), and 18 come with the facts: "restarting for a locked prototype the
call cannot take" in `deindirect` 9 (imports now have locked prototypes), the decompile of a
function in a namespace 3, type propagation into a struct or array 2, a join storage 1, and
three fixed after this run (2 panics where a callee's data-type was read from the
architecture's types, now 1 "locked varargs prototype" and 1 silent; 1 function counted loud
because its C holds the word ERROR in a string, the script now looks for the engines' error
lines). Silent 235: not classified with the final build. An earlier run of this slice
(before namespaces, arrays and strings; `CLASSIFY` with the prelude's read-only folding)
classified 331 of the 500: of its 196 silent misses 191 were `skip` and 5 `own`, and of
those five 0x425020 and 0x493730 are `multicse` on a read-only global and 0x45ec20 is a
silent default-options miss of the slice above. Seen in the silent misses, all of them the
eight's: stores to globals removed (`directwrite`), stack variables (`restructure_varnode`,
`mapped_local_sync`), repeated reads of a global not shared (`multicse`), parameters and
return values of the function itself (0x402820: `void` for `undefined4 *`).

Decisions made here, for the user to confirm ("Claude's call"): the facts are an export of the
Ghidra project, as recorded answers of `DecompileCallback` (XML, one record per line), indexed
by address and parsed on demand; the mode is the console command `load facts <file>`, no
option; `ghidra-diff.sh` uses the facts unless `FACTS=0`; read-only memory does not fold with
facts, because `DecompileRef.java` sends no options; only plain ASCII strings are taken as
the same in Java; `pushMismatchSymbol` and the string rule's string test follow Java only with
facts (without facts the old error stays, no check against `decomp_dbg` reaches it;
superseded on `m3-int6` for `pushMismatchSymbol`, which runs without facts too, checked by `pcd`); a
function symbol covers its entry byte (Java's covers up to 8 bytes of a small function).

Not run: `bars.sh` beyond the checks named above (no full pass), the Mac, `ghidra-diff.sh` on
the other corpora. Not done: the eight actions, the struct and union paths, and the items
under "Fails loudly with facts".

### Stage S10, slice 1: review fixes, branch `worktree-agent-af954dab401167074` (2026-11-17)

An independent review of the slice above; each finding was checked against the Java and C++
sources before a change. The facts file is now version 2 (`ghidra-rs-facts 2`): a file of
version 1 fails at `load facts` and `tools/ghidra-facts.sh` writes it again.

Fixed:

- Panics with facts: `SubfloatFlow::set_replacement`, `SubvariableFlow::set_replacement` and
  `LaneDivide` read the size or metatype of a locked varnode's data-type from the
  architecture's types; the id is one of the function's (`fd.types`). No M8 or M500 function
  reached them.
- `ghidra-diff.sh`: `FACTS=0` was cleared before it was tested, so the facts were always
  loaded. Superseded: "`FACTS=0`: the prelude, as before" was not true until this fix.
- Strings (`printc::java_reads_the_same`): `DecompileCallback.getStringData` reads the
  listing's defined string data holding the address (its length, an offset into it, its
  character set, a translation), and the raw bytes only where there is none. The `string`
  records name the defined strings and, for each the export found plain (one-byte ASCII, the
  data's own first bytes, zeros after them, no translation shown), its number of characters.
  A string is printed when it is plain ASCII and either lies outside defined string data or
  ends where a plain defined string ends; a raw read that finds no string inside defined string
  data, a defined string of another form (213 of the 26,420 of mercs2) and a raw read of
  another length fail. Superseded: "only plain ASCII strings are taken as the same in Java".
- Labels: `getCodeLabel` answers for any address, so the `label` records are now the primary
  symbols at every instruction (in a body, at an entry, outside every function), not only
  those inside a body, where `print C` printed `code_r0x...` for Java's `LAB_...`. A label of
  a function's namespace has a prefixed name outside that function's decompile
  (`getNamespacePrefix`); the record then carries the function's entry and another function
  reaching it fails (none in mercs2).
- Undefined bytes of a block that is not writable (`encodeData`): Java sends a read-only
  1-byte symbol of type `undefined` for each one without a primary symbol, named by
  `SymbolUtilities.getDynamicName` (`UNK_00400128` in mercs2, not `DAT_`). The `undef` records
  give the ranges and the prefix; `Facts::data_symbol` writes the symbol's XML, and the export
  compares that text with Java's for the first such byte of every range (it stops on a
  difference).
- `RulePtrsubCharConstant::pushConstFurther`: the sum is not masked to the constant's size,
  as in the C++.
- `r1-options.sh`: `ptrsubcharconstant` is in `rules/mod.rs` now, so a rerun dropped its
  `togglerule ... off` from the option files. The script keeps a list of rules that are ported
  and stay off (`kept_off`): no check against `decomp_dbg` has run with the rule on. A rerun
  leaves the fifteen option files unchanged. (Superseded on `m3-int6`: `kept_off` is removed and
  the rerun dropped the line from the option files, sixteen with `default-options.txt`; the
  checks against `decomp_dbg` with the rule on are in "Integration `m3-int6`".)

Fails loudly now (was silent):

- A stack-depth-change override at a call site (`getExtraPopOverride`,
  `CallDepthChangeInfo`): the `depth` records name the functions that have one, and their
  decompile fails. mercs2 has none.
- A core character data-type that is no `int` (Java's `uchar` is a `uint` with
  `char="true"`): fails at `load facts`. The core types of mercs2 have none; outside the core
  types it failed before.
- A variable larger than its symbol when the symbol is in a namespace: the C++ prints `_` and
  the name without its namespaces; the port keeps both as one string.
- A calling convention name the compiler spec does not have, other than `unknown`: the C++
  keeps the name (`createUnknownModel`) and prints it in the declaration. mercs2 has
  `__cdecl`, `__fastcall`, `__stdcall`, `__thiscall` and `unknown` only.

Not changed: the review took `HighLabelSymbol` as not type-locked. It is
(`super(0, nm, DataType.DEFAULT, true, true, dtmanage)`, and `isIsolated` is the type lock), all
17,878 `<labelsym>` records of mercs2 carry `typelock="true"` and `merge="false"`, and
`LabSymbol::decode` reads them with `decodeHeader`: labels stay isolated, as Java's are.

Results (the Java C and `SKIP` as above; "before" is the slice's build with the facts of
version 1):

| run | before | after |
|---|---|---|
| `ghidra-diff.sh m8`, the eight skipped | identical 3 / 7 (loud 0, silent 4) | the same |
| `ghidra-diff.sh m500`, the eight skipped | identical 192 / 499 (loud 70, silent 237) | the same; no function changed state |
| `bars.sh`, `CORPORA=m8`, every check | 55 lines equal to the baseline (`m3-int5-116d9d34da.summary`) | the same 55 lines |
| `bars.sh`, M500 `pcc-r`, `pcc-t`, `pc-r`, `pc-t`, `nm-r`, `nm-t` | the six lines equal the baseline | the same: `pcc-r` 494 / 495 (loud 1), `pcc-t` 495 / 495, `pc-r` 494 / 495 (loud 1), `pc-t` 495 / 495, `nm-r` 498 / 499 (loud 1), `nm-t` 499 / 499 |

The console output of all 500 M500 functions is byte for byte the slice's (0x4c48d0, which
Java does not finish, timed out in the loaded run and gave the same text alone). So no M8 or
M500 function reaches a fixed path: the Java C of the two corpora has no `UNK_` name and no
label that was `code_r0x` here, and the loud cases are reached by none. What checks the
`undef` symbols is the export's comparison with Java's XML; what checks the `string` records
is the export's comparison of the string with the data's bytes. `FACTS=0 ghidra-diff.sh m8`
now runs the prelude: identical 0 / 7 (silent 7).

Superseded: "identical 192 / 499 (loud 72, silent 235)" in the slice above is the run before
its last three fixes; its final build gives loud 70, silent 237.

Not done: outside defined string data, bytes with no terminator within 2,048 are no string
here and are taken as none in Java, whose limit may differ by one character; a label of
another function's namespace and the four loud cases above are not ported; no unit test
covers the new records (they need a loaded architecture). Not run: `ghidra-diff.sh` on the
other corpora, a full pass, the Mac.

### Stage S10, slice 2: the facts from ghidra-rs's own analysis (`analyze --facts`), branch `worktree-agent-ad70960380034c8df` (2026-11-17)

The facts of slice 1 come from a Java Ghidra project. This slice writes the same file from
ghidra-rs's own analysis of the binary, so `load facts` needs no project:

```sh
ghidra-rs analyze <pe32> --facts <out> [--protos <file> | --gdt <archive>] [--seeds <csv> | --functions-from <csv>]
ghidra-rs gdt-protos <archive.gdt> <out>   # the same file as ghidra-protos.sh, from the archive
ghidra-rs dwarf <elf> <out>                 # the DWARF import's data types and signatures, as DumpDwarf.java
tools/facts-own.sh            # mercs2: writes rust/target/facts/mercs2.facts and compares it
tools/ghidra-protos.sh        # once per Ghidra version: $GHIDRA_REF/win32.protos
```

`ghidra-rs/src/factsout.rs` writes each record as Java's `DecompileCallback` would send it for
a listing holding what the analysis found. With `--facts`, `analyze` runs discovery with
Create Address Tables and constant propagation (`Analysis::disassemble` with constants) and
Function ID; mercs2 takes about 55 s with plain discovery and 50 to 130 s with
`--functions-from` (discovery runs twice, see below; the desktop was shared), the file is 86 to 89 MB.

| record | where it comes from |
|---|---|
| `coretypes` | Ghidra's built-in data-types for x86:LE:32 Windows, a copy of one export (`src/facts_coretypes.xml`); they do not depend on the program |
| `block` | the PE sections and headers, writable or not; the TEB block of Ghidra's "Windows x86 Thread Environment Block" analyzer (`0xffdff000`) |
| `wref` | an address of a block that is not writable which an instruction writes |
| `func`, `body` | the functions and their bodies as address ranges. Names: an export's, Function ID's (`@name@4` is `name` with `__fastcall` locked, `_name` is `name` with `__cdecl` locked, as the demangler leaves them), a thunk's (one `JMP` to a function, through an import slot, or through a pointer that holds a function's entry: `thunk_FUN_...`, or the name and prototype of the import), else `FUN_<address>`. `extrapop`: Ghidra's `FunctionPurgeAnalysisCmd` (`Analysis::ret_purge`: the first RET by address, else the function the last jump out calls). No-return: the analysis's set. Call fixups: the compiler spec's `<callfixup>` targets by name. Stack variables: Ghidra's stack analysis (`Exporter::locals`, below) |
| `tracked` | the `.pspec`'s tracked registers (`DF = 0`) and `FS_OFFSET = 0xffdff000`, once: they hold for every function |
| `extref`, `data` (`<externrefsymbol>`) | the import slots. The prototype is the archive's (`--protos`), with no-return added from the analysis's set |
| `data` | at every reference target that is not code: a pointer (`PTR_<what it points to>_<address>`: the slots of Create Address Tables, and the Reference analyzer's `checkForPointer`, followed from pointer to pointer), a string (below), `DAT_<address>` typed `undefinedN` where a COPY from memory or a LOAD or STORE through a constant sizes it (constant propagation's `createData`; only a COPY's direct read counts, as in `SymbolicPropogator`), else `DAT_<address>` of one `undefined` byte. A label at code outside every function is a `<labelsym>` |
| `string` | the Reference analyzer's strings (`OperandReferenceAnalyzer.checkForAscii`, `checkForUnicode`): 5 or more ASCII characters with a terminator, or more than 3 UTF-16 ones, at a reference target outside executable blocks, with no reference into them; named `s_<text>` and `u_<text>` (`makeStringLabel`) |
| `undef` | the bytes of the blocks that are not writable which no instruction, typed data or import slot covers, as ranges |
| `label` | a function's name at its entry, `LAB_<address>` at an instruction something refers to |
| `override` | `CALL_RETURN` on a jump to another function (not a thunk's) and on a call of a function that does not return |
| `type` | the data-types of the archive's prototypes that are used, and `undefined` |
| `underived <address> <what>` | what this analysis does not derive (new with this slice, below) |

**Absent loudly.** What ghidra-rs does not derive is named, and the loader (`Facts::derived`)
fails when a decompile reads it:

| `underived` | when | mercs2 (plain discovery) |
|---|---|---|
| `function` | a function with a C++ name (an export or a Function ID name the small demangler leaves: Java has its namespace and the prototype of its mangling); an import, or a thunk to one, whose name the archive does not have (Java gives 220 of the 1,022 imports no prototype either, but an `extrapop` it works out at the call sites) | 699 |
| `comments` | a function Function ID names (Java's plate comment lists the libraries, which `fid.rs` does not load) or with a C++ name (the demangler's comment) | 1,638 |
| `label` | a switch case (Java: `caseD_3` in a `switchD_...` namespace, from its decompiler switch analysis) | 7,969 |

**Function prototypes of the imports.** Java takes them from its data-type archive
(`Ghidra/Features/Base/data/typeinfo/win32/windows_vs12_32.gdt`, in this repo). The archive is
a Ghidra database (a packed buffer file like the `.fidbf` files, with the tables of
`DataTypeManagerDB`), and a prototype's facts need its data-types (17,957 are used by the prototypes) encoded as the decompiler's
XML: reading it in Rust means porting the data-type tables and `PcodeDataTypeManager`'s
encoder. Not done here. Instead `tools/ghidra/ExportArchiveProtos.java` (run once per Ghidra
version by `tools/ghidra-protos.sh`, about a minute) applies every function definition of the
archive to an external function of a scratch program as the "Apply Data Archives" analyzer
does (`ApplyFunctionSignatureCmd`, source IMPORTED) and records what
`DecompileCallback.getExternalRef` answers: `$GHIDRA_REF/win32.protos`, 22,825 prototypes and
17,957 data-types, 41 MB, for every 32-bit Windows program. It reads no program and no project
of the user's. Without `--protos` every import is `underived`.
Superseded (2026-11-20): "Not done here"; the archive is now read in place, see "The archive
read in Rust (`--gdt`)" below. The export stays as the reference it is checked against.

**The archive read in Rust (`--gdt`, `ghidra-rs/src/gdt/`).** `analyze --facts --gdt <archive>`
takes the archive itself; `ghidra-rs gdt-protos <archive> <out>` writes the prototype file
`ghidra-protos.sh` makes. Nothing is ever written to the archive.
- `gdt/db.rs`, the database read-only: the packed file (`ItemDeserializer`: Java object-stream
  header, zip entry `FOLDER_ITEM`, deflate), the buffer file (`LocalBufferFile`, version 1),
  `DBParms`, the master table (`TableRecord`), schemas (`Schema`, sparse columns), long-key and
  fixed-key B-tree nodes (`LongKeyInteriorNode`, `FixedRecNode`, `VarRecNode`, the `FixedKey*`
  nodes), records and big records (`DBRecord`, `SparseRecord`, `ChainedBuffer`). Not ported, and
  failing by name: variable-length keys (`VarKey*` nodes; the `DataTypeManager` options table),
  index tables, XOR-obfuscated chained buffers, field types past `FIXED_10`.
- `gdt/mod.rs`, the data types (`DataTypeManagerDB`'s adapters, by column name, versions checked):
  built-ins V0, calling conventions V0, categories V0, composites V6 and components V0 (with
  `BitFieldDBDataType` ids), typedefs V2, pointers V2, arrays V1, enums and values V1, function
  definitions V2 and parameters V1. Another version, an unknown table, auto-named typedefs or
  default settings fail by name. `windows_vs12_32.gdt` has 22,825 function definitions, 6,065
  composites, 9,441 typedefs, 18,114 pointers, 379 arrays, 32,504 enums, 16 built-ins.
- `gdt/protos.rs`, what `ExportArchiveProtos.java` writes, simulated: each definition applied as
  `ApplyFunctionSignatureCmd` does (`settleCDataType`, unknown conventions left unknown, the
  stack purge), the program's data-type keys in `DataTypeManagerDB.resolve`'s order (a typedef's
  base first; a composite or function definition first, its pointers last through the
  post-resolve queue, smallest key first), symbol ids (function, then each parameter), the
  storage of `x86win.cspec`'s `__stdcall`, `__cdecl` and `__fastcall` (`ParamListStandard`
  fallback, `ParamEntry.getAddrBySlot`, the hidden return pointer), the symbol order of
  `LocalSymbolMap`'s `HashMap`, and `PcodeDataTypeManager`'s, `FunctionPrototype`'s and
  `HighSymbol`'s encoders. Written into the code, not read: the registers and pentries of
  `x86win.cspec` (a `ponytail:` note names the upgrade) and the ids of the built-ins `long`,
  `uchar` and `ulong`, which `facts_coretypes.xml` lacks (the order of Java's class search).
  The archive's `default` convention (id 1) is the cspec's default model: model `default`,
  `modellock`, `__stdcall`'s storage (`getCallingConvention("default")`,
  `FunctionPrototype.grabFromFunction`); `windows_vs12_32.gdt` has no definition with it, so
  this is not checked against Java. `__thiscall` (which `x86win.cspec` has: `ECX`,
  `thisbeforeretpointer`), a `__return_storage_ptr__` parameter and other built-in classes
  fail by name. Superseded: before, a `__thiscall` definition silently got model `unknown`
  and `__stdcall`'s storage, and `default` got `unknown`. A corrupt archive is an error, not a
  crash: a B-tree with a cycle or deeper than 64, lengths and sizes past the file, block sizes
  too small for a chained buffer, a data buffer of another node type, schema names that do not
  match the columns. Duplication: `fid.rs` has its own small buffer-file and B-tree reader for
  the `.fidbf` files; it is left as it is.
  The archive's types are not put in `decomp/types.rs`: that store is the C++ decompiler's
  type factory and is filled from this XML by `facts.rs` as before.
- Result: `gdt-protos` of `windows_vs12_32.gdt` is byte-identical to the 12.3 Java export
  (`rust/target/ref123/win32.protos`, 40,783 lines, 41 MB), in 1.4 s. The test `gdt::tests`
  checks the table counts and a slice of the export.

**Stack variables** (`Exporter::locals`, `Analysis::flow_walk`): a port of
`NewFunctionStackAnalysisCmd` with its defaults (locals, no parameters) on the constant
propagation walk, with ESP at the entry as the stack's origin. A read or write through a stack
address that an operand names makes a variable of the bytes the instruction's last LOAD or
STORE moves (`getRefSize`); an `LEA` of a stack address makes one without a data-type;
a variable that meets others becomes one over them all (`accumulateVariable`, with its "same
length" test); `AND ESP,mask` keeps the stack address. Approximations: "an operand names the
address" is "not the slot a PUSH, POP or CALL uses itself"; a call whose callee's purge the
analysis does not know ends the tracking of its path, where Ghidra goes by the purge the
callee has when the caller is analysed (unknown for a function it makes later:
`local_res0`).

**Seeds.** The Java project of mercs2 is not plain auto-analysis: its pipeline makes 18,483
functions afterwards (`RecoverFunctions` and others), and Ghidra's purge, stack and constant
propagation analyzers did not run on most of them (16,632 of them have `extrapop="unknown"`
and no stack variables in the Java facts). `--facts` with `--seeds` or `--functions-from`
models that: discovery runs once without the seeds, and a function only the seeds bring gets
no `extrapop`, no stack variables, and its instructions size no data.

**The comparison** (`tools/facts-diff.sh <ours> <java>`): per record kind, `equal` (the same
key and text), `different`, `missing` (only Java) and `extra` (only ours), with every such
record in `rust/target/facts-diff/<kind>.<state>`. A record's key is its kind and address.
Ghidra's database ids are left out, the symbols of a function are compared in one order, and
`tracked` is spread over the functions. `tools/facts-func-why.sh` and
`tools/facts-data-why.sh` count the differing `func`, `extref` and `data` records by what
differs. mercs2 against `$GHIDRA_REF/mercs2.facts` (Java's 44,990 functions):

| kind | Java | with Java's functions (`FUNCS=java`): equal / different / missing / extra | equal | plain discovery: equal / different / missing / extra | equal |
|---|---|---|---|---|---|
| `func` | 44,990 | 36,282 / 8,701 / 7 / 0 | 80.6% | 19,905 / 6,602 / 18,483 / 2,733 | 44.2% |
| `body` | 44,990 | 44,123 / 860 / 7 / 0 | 98.1% | 24,380 / 2,127 / 18,483 / 2,733 | 54.2% |
| `extref` | 1,022 | 920 / 102 / 0 / 0 | 90.0% | 920 / 102 / 0 / 0 | 90.0% |
| `data` | 271,502 | 127,777 / 13,553 / 130,172 / 17,037 | 47.1% | 101,255 / 38,582 / 131,665 / 42,693 | 37.3% |
| `label` | 218,095 | 206,920 / 1,149 / 10,026 / 13,405 | 94.9% | 182,798 / 22,207 / 13,090 / 13,179 | 83.8% |
| `string` | 26,420 | 13,635 / 1,466 / 11,319 / 112 | 51.6% | 13,623 / 1,467 / 11,330 / 111 | 51.6% |
| `undef` | 58,069 | 53,779 / 1,097 / 3,193 / 3,214 | 92.6% | 53,577 / 1,178 / 3,314 / 3,239 | 92.3% |
| `block` | 14 | 14 / 0 / 0 / 0 | 100% | 14 / 0 / 0 / 0 | 100% |
| `wref` | 265 | 166 / 0 / 99 / 0 | 62.6% | 183 / 0 / 82 / 5 | 69.1% |
| `tracked` (per function) | 44,990 | 44,963 / 20 / 7 / 0 | 99.9% | 26,498 / 9 / 18,483 / 2,733 | 58.9% |
| `override` | 3,365 | 2,510 / 0 / 855 / 1,059 | 74.6% | 2,260 / 0 / 1,105 / 2,486 | 67.2% |
| `comments` | 1,613 | 0 / 0 / 1,613 / 0 | 0% | the same | 0% |
| `coretypes` | 1 | 1 / 0 / 0 / 0 | 100% | the same | 100% |
| `type` (by name) | 365 | 263 / 0 / 102 / 2 | 72.1% | the same | 72.1% |
| `ns` | 797 | 0 / 0 / 797 / 0 | 0% | the same | 0% |
| `underived` | 0 | 10,414 extra | | 10,306 extra | |

Plain discovery finds 29,240 functions, 26,507 of Java's 44,990 (superseded on `m3-int7`: 29,186
with the Shared Return port; the share of Java's not measured again, see "Integration
`m3-int7`"). The mercs2 pipeline makes
functions after auto-analysis (see "Analysis" above), and `--functions-from` takes such a
list: `FUNCS=java` gives it the entries of the Java facts, so that column measures everything
but the function set. It is not a run without Java: the list comes from the Java project.

What differs, with Java's functions (the counts of `facts-func-why.sh` and
`facts-data-why.sh`):

- `func` (8,701): stack variables that differ 1,754 + 143 + 110, only in Java 503 + 461,
  only here 497 + 178 (not looked at one by one; two seen: the purge Ghidra had for a callee
  when it analysed the caller, see above); `extrapop` known only in Java 1,843 + 461 and only
  here 1,752 + 497 + 143 (not looked at; among the functions the seeds bring, Java has an
  `extrapop` for 1,851 and none for 16,632); no-return only here 395; names, models and
  return types of C++ functions 268 + 213 + 110 (`underived` here).
- `data`: 90,750 pointers of SecuROM's `Sdata` and `Srdata` are missing: those sections
  are flagged as code, `Analysis::address_tables` takes a pointer into an executable section
  as code and disassembles there, so the tables that follow collide with it (Ghidra asks its
  pseudo-disassembler). 7,412 + 2,656 labels and 5,212 pointers of ours are that code.
  10,664 strings are missing: Ghidra's ASCII Strings analyzer finds them without a
  reference, by its trigram model (`StringModel.sng`), not ported. 6,442 `BYTE_` and about
  2,200 `WORD_`/`DWORD_` records are Java's typed switch and loader tables. 2,401 + 907 `DAT_`
  symbols are sized in Java through a register-held address the walk here does not size; of
  the symbols sized here 54 differ. The loader's structures (`IMAGE_DOS_HEADER`, resources)
  and the RTTI structures (about 1,400) are not derived.
- `extref`: 102 differ, most of them in the `extrapop` Java has for an import without an
  archive prototype (`underived` here). An import keeps its name where the archive has it
  (`_cexit`) and takes the demangler's otherwise (`_initterm` is `initterm`, `__cdecl`).
- `label`: missing switch cases (`underived`) and labels in code Ghidra reaches and
  ghidra-rs does not; extra labels in SecuROM's sections (above).
- `comments`, `ns`: not derived (1,553 of the 1,613 comments are Function ID's).

**The end effect** (`tools/ghidra-diff.sh` with `FACTS=<file>`, new: another facts file than
the Java project's; the eight actions skipped as in slice 1):

| facts | M8 | M500 |
|---|---|---|
| the Java project's (slice 1) | identical 3 / 7 (loud 0, silent 4) | identical 192 / 499 (loud 70, silent 237) |
| ghidra-rs's own, with Java's functions | identical 2 / 7 (loud 2, silent 3) | identical 171 / 499 (loud 71, silent 257) |
| ghidra-rs's own, plain discovery | identical 1 / 7 (loud 2, silent 4) | identical 90 / 499 (loud 156, silent 253) |

Superseded (2026-11-18): the three rows above are with the eight actions skipped, before they
were ported; the counts of `m3-int7` with default options are in "Integration `m3-int7`", the
own-facts gap.

With Java's functions the console output of ghidra-rs is byte for byte the output it gives
with the Java facts on 377 of the 500 M500 functions, and on M8 on all five that print:
0x40a110 and 0x58d030 are Java's C, and 0x401000, 0x73a340 and 0x4042e0 miss it in the same
way with either facts (the eight actions). The two loud M8 functions are what is not derived:
0x401080 calls `D3DXVec3TransformNormal` through a thunk (an import the archive does not
have: `underived function`), and 0x9eec5e, `__security_check_cookie`, has Function ID's plate
comment (`underived comments`); with the Java facts it is the third identical one. Of the 71
loud M500 functions 12 read an `underived` function and the others are the misses the Java
facts reach too. With plain discovery 98 of the 156 loud ones are "no function at": the M500
function, or one it calls, is a function only the mercs2 pipeline makes; 0x40a110 is a
thunk there (`thunk_FUN_004a8660`), since discovery makes the jump's target a function.

The checks against `decomp_dbg` do not read the facts: `bars.sh` with `CORPORA=m8` gives 55
lines, each equal to the baseline's (`m3-int5-116d9d34da.summary`). `cargo test`: 140 pass.

Decisions made here, for the user to confirm ("Claude's call"): the command is the `analyze`
option `--facts <out>` (as `--functions`, `--decomp-prelude`); the `underived` records and
the loader failing on them; a seeded function stands for one a script made after
auto-analysis; the archive's prototypes come from a one-time headless export, not from a
`.gdt` reader in Rust; the core types are a copied file; a rule of Ghidra's analyzers that is
ported with an approximation (the stack variables, the strings and pointers at references,
the data sizes) is written without an `underived` mark and measured by `facts-diff.sh`
instead: a mark on every such record would make every decompile fail.

Not done: the ASCII Strings analyzer, Function ID's comments, the demangler's namespaces and
prototypes, switch-case labels, the structures of the loader and of RTTI, a `.gdt` reader,
the order of Ghidra's analysis. Not fixed: `address_tables` on sections flagged as code (it
feeds `--abi-callers` and `--functions` too, so it needs their gates). Not run: a full
`bars.sh` pass, `ghidra-diff.sh` on the corpora other than M8 and M500, the Mac.

Superseded (2026-11-17, slice 3 below): the ASCII Strings analyzer and Function ID's comments (for
names that are not mangled) are ported, and `address_tables` no longer disassembles data of
sections flagged as code; the counts of this section are those of slice 2's build, the current
ones are in slice 3. Also superseded there: "at a reference target outside executable blocks"
(the `string` row), "a call whose callee's purge the analysis does not know" for imports and
`__cdecl` functions (Stack variables), "only a COPY's direct read counts" for an address a
register holds (the `data` row), and `underived comments` for a Function ID name that is not
mangled.

### Stage S10, slice 3: Ghidra's analyzers ported for `analyze --facts`, branch `worktree-agent-aa1e28b7594b072e7` (2026-11-17)

The user's decision of 2026-11-17 (`../DESIGN.md`, Decided): the facts ghidra-rs derives come
from ports of Ghidra's Java analyzers, not from approximations. This slice ports five pieces
and measures each with `tools/facts-diff.sh` against the Java facts of mercs2 (Java's
functions, `FUNCS=java`). What is still approximated is listed at the end and stays measured.

**1. Address tables and code in SecuROM's sections** (`analysis.rs`: `Analysis::disassemble`,
`table_entry`, `make_table`, `address_tables`, `valid_subroutine`, `used_for_calculation`).
`Srdata` and `Sdata` are data with the execute flag, in Ghidra too (`PeLoader` takes
`IMAGE_SCN_MEM_EXECUTE`). Ghidra keeps their pointers as data by rules that were missing here:

- `OperandReferenceAnalyzer.getAddressTable` and `createFlowTable`: where an instruction
  refers to the start of a run of addresses (`AddressTable.getEntry`, at least 3, and at least
  the analyzer's minimum), the run becomes pointers and nothing is disassembled there. A jump
  or call that refers to one makes no table ("Switch Table References" is off) and is not
  looked at further.
- The "Subroutine References" test before `isValidSubroutine`: not where a memory operand
  reads or writes the target (`hasDataAccessReferences`), not from a jump or call, not a
  value the instruction computes with (`isUsedForCalculation`, on the p-code).
- `PseudoDisassembler.checkPseudoBody`: no defined data in the flow (a pointer is data now,
  and stops a later disassembly), no reference into the middle of one of its instructions,
  and without existing code no reference to the flow but to its entry.
- `AddressTable.getFunctionEntries` with `PseudoDisassembler.isValidCode`: Create Address
  Tables disassembles a table's entries only when every one of them lies in an executable
  block and is the start of an instruction or, where nothing is defined, valid code. An entry
  at defined data (a pointer of the same or another table) is not. Superseded: "valid code is
  in an executable section" (`ponytail` note of `address_tables`) and "Not fixed:
  `address_tables` on sections flagged as code" (slice 2).

**2. Purges at call sites** (`factsout::call_purges`, `Analysis::swap_call_purges`, the fold
of `Analysis::decode`). The stack analysis (`NewFunctionStackAnalysisCmd` on
`SymbolicPropogator`) moves ESP after a call by `SymbolicPropogator.getFunctionPurge`: 0 for a
convention with a known extrapop (`__cdecl`), whatever the function's purge is; the
prototype's for an import of the archive, also through `CALL [slot]` and through a thunk; else
the purge `FunctionPurgeAnalysisCmd` stored (the first RET by address, `Analysis::ret_purge`),
which only a function of auto-analysis has. Superseded: "a call whose callee's purge the
analysis does not know ends the tracking" as far as imports and `__cdecl` functions go
(slice 2 used the purge of functions whose RETs all agree, for every function with a body).

**3. ASCII Strings analyzer** (`strings.rs`, `Exporter::ascii_strings`). A port of
`StringsAnalyzer` with its defaults: the search of `StringSearcher`
(`MinLengthCharSequenceMatcher`, `MultiByteCharMatcher`: ASCII and UTF-16 at both byte
offsets, 5 characters, a terminator), `StringAndScores` (lower case, trimmed, runs of spaces
and of tabs as one), `NGramUtils` (the trigram model
`Ghidra/Features/Base/data/stringngrams/StringModel.sng`, read from the Ghidra tree the
`.sla` file is in; `--facts` fails without it; the score leaves out the first trigram, as
Java's does), `createStringIfValid` (undefined bytes, or a string of the same kind at its end
that it takes over; the zero bytes up to the next multiple of 4 belong to it). It runs after
the reference analysis, over each run of sections that follow one another. With it, a string
at a reference in an executable block is made as `checkForAscii` makes it (Java's
`isValidInstruction` is always false). Superseded: "`string` ... at a reference target
outside executable blocks" and "Not done: the ASCII Strings analyzer" (slice 2).

**4. Data through an address a register holds** (`Fold::data`, the walk in
`factsout::export`). `SymbolicPropogator` makes a reference, and constant propagation data of
the bytes moved, at a LOAD or STORE through a constant a register holds. `Analysis::decode`
records these of each instruction, and the facts walk every function of auto-analysis for
them. Before, only an instruction's own constant sized data. A write through a register into
a block that is not writable is a `wref` now.

**5. Function ID's plate comments** (`fid.rs`: `plate_comment`, the Libraries table).
`ApplyFidEntriesCommand.generateComment` with `MatchNameAnalysis.analyzeLibraries`: the kind
of match, up to four names, the libraries (family, version, variant; shortened from 5
libraries on). Only where no matched name is mangled: Java shows the demangler's full form of
a mangled name, which is not ported, and such a function keeps its `underived comments`
record. "Multiple Matches With Same Base Name" (`numNames() > 1` and
`getMostOptimisticCount() == 1`) is not ported, checked in the `m3-int6` review: with no
mangled name the final list is the raw or the underscore-stripped names, whichever is
shorter, so the count can reach 1 only through the demangled sets, and those are dropped
as soon as one name does not demangle. That holds while the Microsoft demangler demangles no
name without `?` or `@` (the test `fid.rs` uses for "mangled"), which was not checked in the
demangler's sources. Superseded (2026-11-20): `fid.rs` demangles every name with the ported
demangler and ports the demangled sets and "Multiple Matches With Same Base Name" ("The
Microsoft demangler").

**Against Java** (mercs2, `FUNCS=java`; equal records and their share of Java's; each row adds
its piece to the rows above it):

| | `func` | `data` | `label` | `string` | `undef` | `wref` | `comments` |
|---|---|---|---|---|---|---|---|
| Java has | 44,990 | 271,502 | 218,095 | 26,420 | 58,069 | 265 | 1,613 |
| before (slice 2) | 36,282 (80.6%) | 127,777 (47.1%) | 206,920 (94.9%) | 13,635 (51.6%) | 53,779 (92.6%) | 166 (62.6%) | 0 |
| 1. tables | 36,282 | 217,776 (80.2%) | 206,468 (94.7%) | 13,636 | 53,841 (92.7%) | 166 | 0 |
| 2. call purges | 36,553 (81.2%) | 217,776 | 206,468 | 13,636 | 53,841 | 166 | 0 |
| 3. strings | 36,553 | 227,804 (83.9%) | 206,468 | 23,203 (87.8%) | 54,711 (94.2%) | 166 | 0 |
| 4. register data | 36,553 | 229,590 (84.6%) | 206,472 | 23,242 (88.0%) | 54,839 (94.4%) | 225 (84.9%) | 0 |
| 5. FID comments | 36,553 | 229,590 | 206,472 | 23,242 | 54,839 | 225 | 1,145 (71.0%) |
| strings at references in executable blocks | 36,553 | 230,456 (84.9%) | 206,472 | 23,918 (90.5%) | 55,514 (95.6%) | 225 | 1,145 |

The whole table of the final build:

| kind | Java | with Java's functions (`FUNCS=java`): equal / different / missing / extra | equal | slice 2 | plain discovery: equal / different / missing / extra | equal | slice 2 |
|---|---|---|---|---|---|---|---|
| `func` | 44,990 | 36,553 / 8,430 / 7 / 0 | 81.2% | 80.6% | 19,838 / 6,669 / 18,483 / 2,733 | 44.1% | 44.2% |
| `body` | 44,990 | 44,123 / 860 / 7 / 0 | 98.1% | 98.1% | 24,380 / 2,127 / 18,483 / 2,733 | 54.2% | 54.2% |
| `extref` | 1,022 | 920 / 102 / 0 / 0 | 90.0% | 90.0% | 920 / 102 / 0 / 0 | 90.0% | 90.0% |
| `data` | 271,502 | 230,456 / 11,796 / 29,250 / 12,963 | 84.9% | 47.1% | 204,465 / 36,563 / 30,474 / 38,581 | 75.3% | 37.3% |
| `label` | 218,095 | 206,472 / 1,140 / 10,483 / 7,455 | 94.7% | 94.9% | 182,399 / 22,194 / 13,502 / 7,110 | 83.6% | 83.8% |
| `string` | 26,420 | 23,918 / 1,984 / 518 / 31 | 90.5% | 51.6% | 23,903 / 1,999 / 518 / 33 | 90.5% | 51.6% |
| `undef` | 58,069 | 55,514 / 708 / 1,847 / 3,036 | 95.6% | 92.6% | 55,288 / 799 / 1,982 / 3,076 | 95.2% | 92.3% |
| `block` | 14 | 14 / 0 / 0 / 0 | 100% | 100% | 14 / 0 / 0 / 0 | 100% | 100% |
| `wref` | 265 | 225 / 0 / 40 / 3 | 84.9% | 62.6% | 242 / 0 / 23 / 10 | 91.3% | 69.1% |
| `tracked` (per function) | 44,990 | 44,963 / 20 / 7 / 0 | 99.9% | 99.9% | 26,498 / 9 / 18,483 / 2,733 | 58.9% | 58.9% |
| `override` | 3,365 | 2,478 / 0 / 887 / 1,008 | 73.6% | 74.6% | 2,239 / 0 / 1,126 / 2,448 | 66.5% | 67.2% |
| `comments` | 1,613 | 1,145 / 8 / 460 / 43 | 71.0% | 0% | 1,138 / 7 / 468 / 30 | 70.6% | 0% |
| `coretypes` | 1 | 1 / 0 / 0 / 0 | 100% | 100% | the same | 100% | 100% |
| `type` (by name) | 365 | 263 / 0 / 102 / 2 | 72.1% | 72.1% | the same | 72.1% | 72.1% |
| `ns` | 797 | 0 / 0 / 797 / 0 | 0% | 0% | the same | 0% | 0% |
| `underived` | 0 | 9,209 extra | | 10,414 | 9,122 extra | | 10,306 |

Three kinds lose a little: `label` (the 452 below), `override` (32 `CALL_RETURN` records, which
piece 1 changes; not looked at one by one) and, with plain discovery only, `func` (67
functions, not traced; there every function is one "of auto-analysis", so every callee has
its purge at a call, see `func` below). The analysis takes about 115 to 130 s on the shared
desktop (slice 2: 50 to 130 s) and the facts 40 to 50 s (17 s): the Strings search and the
second walk of every function.

What still differs, by cause:

- **The code ghidra-rs has and Java does not, and the other way.** 7,455 labels are extra
  and 10,483 missing (before: 13,405 and 10,026). The tables took 5,952 extra labels away
  (code that was data of SecuROM) and 452 equal ones: 610 labels that Java has are no longer
  reached (581 of them in SecuROM's `Stext`) and 149 others are, because `checkPseudoBody`
  meets a reference into the flow (seen: 0x1b10da0, where an immediate of other code is an
  address inside it). Java's reference came after its disassembly there: its analysis asks in
  small steps from the entry points, ghidra-rs asks with the references of all the code
  discovery found. Extra code also makes strings at its references that Java's Strings
  analyzer makes instead (longer by the zero bytes: 0x88f47c `PUSH 0xb12ce4` lies in bytes
  Java leaves undefined), and the other way round: 1,984 strings differ in length and nothing
  else.
- **`func`**: unchanged but for the stack variables. `facts-func-why.sh`: stack variables
  differ in 1,610 functions that differ in nothing else (before 1,754): Java has variables
  ghidra-rs lacks in 191 (before 567), ghidra-rs has variables Java lacks in 668 (before 470),
  both in 748 (variables on one side only: Java 274 functions, before 503; ghidra-rs 280,
  before 178). Seen in 0x49ab40: Java tracks ESP up to `CALL 0x401740` and not after it,
  though that function has a purge in the Java facts (`RET`, extrapop 4): when Java analysed
  the caller it did not have it. Which functions Ghidra had made when its stack analyzer ran
  on a caller is not derived (the functions "of auto-analysis" here are those plain discovery
  finds). `extrapop` known only in Java (1,843 + 461) or only here (1,736 + 510) is the same
  question: which functions auto-analysis made and which the mercs2 pipeline made later.
- **`data`**: 29,250 missing, 12,963 extra, 11,796 different. Not looked at one by one after
  the ports; the kinds slice 2 lists remain (typed switch and loader tables, the loader's and
  RTTI structures, pointers and labels at code only one side has).
- **`comments`**: Java has 1,553 of Function ID (1,188 with names that are not mangled) and
  60 of the demangler. 460 are missing: the 365 with a mangled name, the 60, and 35 with
  plain names at functions Function ID does not mark here. 43 are extra (functions it marks
  only here) and 8 name other libraries (seen: 0x1cdc1f5, Visual Studio 2003 here, 2017 and
  2019 in Java; not traced: the installed Ghidra is 12.2, the repo's databases are 12.3's).
- `ns`, `type`, `extref`, `override`, `tracked`, `body`: as slice 2.

**Still approximated** (written without a mark, measured by `facts-diff.sh`):

- the order of Ghidra's analysis: which references and which functions exist when an analyzer
  asks (the code constants, `checkPseudoBody`, the purge of a callee in the stack analysis,
  the purge of a function whose last jump goes to another function);
- the stack analysis's "an operand names the address" (`getStackOpIndex`);
- Create Address Tables' disassembly between one table and the next (here after a whole pass),
  and Ghidra's defined data other than pointers, strings and switch tables;
- the pointers at references (`checkForPointer`: the string check at the word is in the
  facts, not in `Analysis::pointer_targets`);
- the Strings analyzer's listing (the loader's and RTTI structures are not derived, so a
  string inside one is made here), and `log10` of Rust's `f64` against Java's at a score that
  equals its threshold to the last bit;
- data sizes where two accesses disagree (the last one in the order of the functions wins).

Not ported: the demangler (names, namespaces, prototypes and comments of C++ functions: `ns`
0 of 797, `underived function` and `comments`; superseded 2026-11-20: the demangler and its
comments are ported, the namespaces and prototypes it applies are not, "The Microsoft
demangler"), switch-case labels, the loader's and RTTI
structures, a `.gdt` reader, Ghidra's task queue (the order above; superseded 2026-11-18: the queue
is ported with discovery and the purge in it, "Ghidra's task queue and the purge").

**The end effect** (`tools/ghidra-diff.sh` with `FACTS=<file>`, the eight actions skipped as
in slice 1; both rows run with this build):

| own facts, Java's functions | M8 | M500 |
|---|---|---|
| before (the facts of slice 2) | identical 2 / 7 (loud 2, silent 3) | identical 171 / 499 (loud 71, silent 257) |
| after | identical 2 / 7 (loud 2, silent 3) | identical 173 / 499 (loud 71, silent 255) |

Superseded (2026-11-18): see the own-facts gap of "Integration `m3-int7`" (328 / 499 with
Java's functions, default options).

M500: 0x4e9230 and 0x6ee4c0 were silent and are identical; no other function changes its
state. M8: the same seven states. 0x401080 still reads an `underived` function (an import the
archive does not have). 0x9eec5e still reads `underived comments`: its Function ID name is
`@__security_check_cookie@4`, and Java's comment ends with the demangler's line `__fastcall
__security_check_cookie,4`. A name with `@` counts as mangled here; of the 23 such names in
Java's comments 22 are `_name@N`, which Java shows as they are (so those 22 comments could be
written; not done).

**The shadow check** (mercs2's `tools/ghidra-rs-shadow.sh` logic: `analyze --functions-from
build/functions.csv --abi-callers` against `config/abi_callers.csv`, mercs2 only read): same
56,003, differ 60, Java only 152, ghidra-rs only 819. Before: same 55,996, differ 61, Java
only 158, ghidra-rs only 873. Only piece 1 reaches it. Every changed row: 54 rows Java does
not have are gone (29 `trivial`, 14 `unconcluded`, 7 `violation`, 4 `unknown`: call sites in
bytes that are data now); 7 rows Java has are new with Java's status (4 `trivial`, 2
`unknown`, 1 `unconcluded`); 1 row went from `ok` to Java's `unknown`; 1 row Java has is gone
(0x56d910 called at 0x550c94, `ok` on both sides before: that code is no longer reached).
Why (traced in the `m3-int6` review): ghidra-rs had reached 0x550c94 from an offcut table
entry, 0x550c74, in the `.securom` pointer run at 0x24d7780. Java's real entry there is
0x550be0, reached through a pointer at 0xd17218 that ghidra-rs does not see: the only
reference to that table is `PUSH 0xd17200` in `.securom` code at 0x24f5a6a, which ghidra-rs
leaves undecoded. Superseded: "that code is no longer reached" gave no cause. `--functions` and `--gaps` give the same files, byte for byte.

The checks against `decomp_dbg` do not read the facts: `bars.sh` with `CORPORA=m8` gives 55
lines, each equal to the baseline's (`m3-int5-116d9d34da.summary`). `cargo fmt` and `clippy -D
warnings` are clean. `cargo test`: 145 pass (3 new: the string search, the trigram score, an
address table in executable data).

Decisions made here, for the user to confirm ("Claude's call"): Java's `checkPseudoBody` is
ported whole, though with the references of all discovered code it loses 452 equal labels of
SecuROM's code while it wins the tables (the alternative, a check against flow and memory
references only, was measured: it kept the labels and lost 86,619 equal `data` records);
`--facts` fails when the strings
model file is not in the Ghidra tree of the `.sla` file; a Function ID comment is written
only where no name is mangled, any other stays `underived`; the purges of imports come from
the archive export (`--protos`), so without it a call of an import ends the stack tracking
as before.

Not run: a full `bars.sh` pass (M8 only), `ghidra-diff.sh` on corpora other than M8 and
M500, plain discovery under `ghidra-diff.sh`, the Mac. Not measured apart: each piece's share
of the `ghidra-diff.sh` change.

### Integration `m3-int6` (2026-11-17)

Eight branches merged on `m3-int6`, in this order: the small items after `m3-int5`
(59a40e44b5: panics counted loud, the `fillinReadOnly` warning, the `swsn-r` silents), "Segment
and jump-assist user ops" (ef3d3c7f7e), `m3-default` (eecc410c3b), "Value-set analysis and the
stack guards" (a8fae53df4), "pieces of symbols" (b42e25269c), "Local symbols" (24dd65cc1d),
"Pool rules" (e9ab60a763) and the analyzers branch (e384aa0276: stage S10 with its three
slices, and the project store). The sections above describe each branch as it was on its own;
their counts are each branch's, on its own base. Where two branches met, the code is now:

- `mapstate.rs`: the typed range hints of "Local symbols" with `MapState::addGuard` of
  "Value-set analysis and the stack guards", instead of the loud "a load or store guard". In
  the `decompile` root the guard's hint takes the data-type its pointer points to (down to the
  element of an array) when that has the step's size, else unknown bytes of the step's size, as
  the C++; in the partial function it is always the unknown type. New here, on neither branch:
  the typed case, and a loud error for a pointer to a union (`getTypeReadFacing` needs the
  union's resolution; widened in "review fixes" below to any type that `needsResolution`).
- `namevars.rs`, `finalizeDatatype`: `getExactPiece` of "pieces of symbols"
  (`infertypes::exact_piece`), and the piece's type is kept as in "Local symbols"
  (`type_finalized`). The loud "changing the data-type of a variable" is gone.
- `printc.rs`, `pushMismatchSymbol`: the unnamed location of "pieces of symbols" for a variable
  past the end of its symbol; it runs without facts too (stage S10 had kept it behind
  `load facts`), and S10's loud case of a symbol name in a namespace stays.
- `variable.rs`, `testUntiedCallIntersection`: the `hasNoLocalAlias` test of "Local symbols"
  and the store-guard test of the value-set branch.
- `rules/ptrarith.rs`: S10's loud test of a composite data symbol near the address, then
  `nearestArrayedComponent` over the local symbols.
- `rules/mod.rs`: `segment` and `ptrsubcharconstant` are `r(...)` entries. No table holds a
  `u(...)` rule now, so no default run can fail on an unported pool rule; `u` stays for its
  unit test and for a rule the C++ pools gain.
- `r1-options.sh`: S10's `kept_off` list is removed. Rerun, the script leaves
  `default-options.txt` empty (`pcd` and `pmd` run the plain default options, nothing switched
  off) and drops `togglerule ptrsubcharconstant off` from the eleven rule option files that had
  it, so those checks run the rule on both engines.

Counts on the tip of the branch, one machine (the desktop), `TIMEOUT` 120:

- `cargo test`: 157 passed. `tables_list_every_rule_of_the_cpp_pools` passes. `cargo fmt
  --check` and `cargo clippy -D warnings` are clean.
- M8, all 57 checks: the 55 lines of the `m3-int5` baseline unchanged (every function the
  reference finishes identical), `pcd` 8 / 8, `pmd` 8 / 8, silent 0.
- M500, seven checks (the `m3-int5` baseline in brackets; `pcd` and `pmd` have none):

  | check | identical / reference finished | loud | silent |
  |---|---|---|---|
  | `pcd` | 493 / 499 | 6 | 0 |
  | `pmd` | 497 / 500 | 3 | 0 |
  | `pcc-r` | 495 / 495 (494 / 495, loud 1) | 0 | 0 |
  | `pcc-t` | 495 / 495 (495 / 495) | 0 | 0 |
  | `r5s` | 498 / 498 (446 / 499, loud 53) | 0 | 0 |
  | `paramdouble` | 500 / 500 (500 / 500) | 0 | 0 |
  | `swsn-r` | 499 / 499 (495 / 499, loud 1, silent 3) | 0 | 0 |

  The six loud of `pcd`: 0x53a040, 0x5a9b80, 0x766350 (`RuleStringCopy`: `StringSequence` is
  not ported) and 0x5cee30, 0x5d8680, 0x5d87c0 (`subflow`: a logical value in a join varnode);
  the three of `pmd` are the `subflow` three. 0x4c48d0 is the function the reference does not
  finish in 120 s. In `r5s` the reference also does not finish 0x6b21e0, in 120 s or, run
  alone, in 600 s; the `m3-int5` baseline finished it (identical there), so it is not compared
  now. The same timeout is in the `r5s` miss lists of `m3-default`, "Pool rules" and "Local
  symbols", so it is older than this integration; which change of the `r5s` run makes the
  reference slow there is not traced.
- No function identical in the baseline is loud or silent in these five baseline checks
  (0x6b21e0 of `r5s` aside: not compared), and no silent miss is left in the checks run. Against the branches' own miss lists: all six `pcd` misses
  were loud on "Local symbols" already, five with the same error and 0x766350 earlier, at an
  indexed stack LOAD (it now gets as far as `StringSequence`); the other five were identical on
  "pieces of symbols", which did not have the local symbols.

Superseded by this section: `pcd` M500 415, 422, 440 and 474 / 497 and 463 / 499, `pmd` M500
470 / 499 (the branch sections above and the plan); "`default-options.txt` holds two rules";
"Open: `ValueSetSolver` (26 of the 36 loud)" of "Local symbols"; "Left: 16 indexed stack
LOADs, 6 STORE guards" of "pieces of symbols"; the blocked "eight actions of the default
`decompile` are not ported" of stage S10 (all are ported or have nothing to do; the S10 checks
against Java Ghidra were not rerun with them on).

Not run on `m3-int6`: the other 50 checks on M500, the switch, `simple` and `r5d-adc` corpora
(the full pass), the Mac, `ghidra-diff.sh` and `facts-diff.sh` (stage S10: they need the Java
Ghidra project). Not seen in a check: whether any function of M8 or M500 reaches the typed
guard hint with a pointer whose target has the step's size (the code new in this merge), and
`ptrsubcharconstant` changing an output without facts (the checks with it on give the counts
above, and no line of the M8 baseline moved).

Full pass (2026-11-18, `bars-queue.sh` on `ff58230822`, desktop and Mac): 132 of 133 pairs, the Mac dropped off the network and lost `swsn-t-switch`, rerun on the desktop: 2001 / 2004 (loud 3, silent 0). Silent 0 in every pair. No pair has fewer identical functions or more silent misses than the `m3-int5` baseline; `r5s`, `r5slock` and `r5dtlocksv` M500 have reference finished 498 instead of 499 (0x6b21e0, the reference no longer finishes it), while their identical counts rose (`r5s` 446 -> 498, `r5slock` and `r5dtlocksv` 451 -> 467). Switch: `paramdouble` 2002 / 2004, `swfs-r` 2003, `swsn-r` 2003, `swfs-t` and `swsn-t` 2001. Superseded: "Not run: the full pass" above. Superseded (full pass of `m3-int7`): the reference finished 499 in all three `r5s`, `r5slock` and `r5dtlocksv` M500 lines; see "Integration `m3-int7`".

### Integration `m3-int6`: review fixes (2026-11-17)

Six review findings on `m3-int6`, each checked against the C++ of this tree (Ghidra 12.3):

- `namevars.rs`, `linkSymbol`: the reviewer read a newer Ghidra's `handleSymbolConflict`; this
  tree's `Funcdata::linkSymbol` has none (it links any entry from `queryProperties` that is not a
  conflict). The loud "a variable in the storage of another one's symbol (buildDynamicSymbol)"
  (only for a symbol valid everywhere) is removed, so the port links as the reference does. It
  fired on no M8 or M500 function.
- `mapstate.rs`, `checkUnaliasedReturn`: the alias test is the C++ `alias <= off + (size - 1)`
  (wrapping), not `alias < off + size`, which could overflow.
- `getTypeReadFacing` / `getTypeDefFacing` (`infertypes::vn_type_facing`): `MapState::addGuard`,
  `RuleStringCopy`, `RuleStringStore` and `gatherParamSpacebaseRefs` read the varnode's own
  type, where the C++ resolves a type that `needsResolution` (a union, a pointer to one, a
  one-element array, a one-field structure). `unionresolve.cc` is not ported, so such a type now
  fails loudly there instead of being used unresolved.
- `coreaction.rs`, `gatherParamSpacebaseRefs`: `refs.sort()` is `std::list::sort` with
  `InputRef::operator<`, whose `typeOrder <= 0` holds both ways on a tie (a comparator a Rust
  sort may panic on). `stdsort::list_sort` ports libstdc++'s bottom-up list merge sort, so the
  order is the reference's in every case; its unit test pins g++'s order for a strict and a
  non-strict `less` (`tools/stdsort_ref.cc`).
- `RuleSwitchSingle`: the header warning prints the address with `AddrSpace::printRaw`
  (`printc::raw_offset`), not a fixed eight digits.
- `recoverNameRecommendationsForSymbols`: `findOverlap` is `ScopeInternal::findOverlap` on the
  scope's `rangemap` (`Scope::find_overlap`): the first sub-range in the map's order, where the
  port took the lowest entry offset and then the lowest symbol id.

Counts, the desktop, `TIMEOUT` 120: `cargo test` 158 passed (157 and the new `list_sort_matches_gxx`);
`cargo fmt` and `cargo clippy -D warnings` clean. M8, all 57 checks: every line equal to the
`m3-int6` run. M500: `pcd` 493 / 499 (loud 6, silent 0), the same six misses; `pmd` 496 / 499
with the reference timing out on 0x4c48d0 under load (another full pass ran on the machine),
which rerun alone (`TIMEOUT` 600) is identical, so 497 / 500 (loud 3, silent 0) as before. No
function changed state. Not run: the other 55 checks on M500, the switch, `simple` and
`r5d-adc` corpora, the Mac. Not seen in a check: a type needing resolution at the four readers
(no function failed there), a tie of `typeOrder` in `gatherParamSpacebaseRefs`, a `findOverlap`
whose first sub-range differs from the lowest offset, a `RuleSwitchSingle` warning (the address
format is the same for a 4-byte space).

### Integration `m3-int7` (2026-11-18)

Two branches merged on `m3-int7` (71ba24757c), on `m3-int6` (1c9dc419e3): f9ace1f270 (the
Shared Return port d28ab90681 and the `fold-slot-fragments` fix for "refit failed Object has
been deleted.", both on fc68a96873, the review fixes of the section above) and fbb2abc40d (the
`export` commands and `tools/mercs2-exports.sh`). Counts on 71ba24757c, the desktop, `TIMEOUT`
120:

- `cargo fmt --check` and `cargo clippy --all-targets -- -D warnings` clean; `cargo test` (debug
  profile) 164 passed, 0 failed.
- Prelude (`decomp-diff.sh --prelude`, plain discovery on mercs2): 29,186 functions (1,022
  imports), Function ID names 1,577; with the `m3-int6` binary 29,240 and 1,572. Of the `map
  function` lines, 54 unnamed functions of `m3-int6` are gone, and five unnamed ones are now
  named `_raise` by Function ID: 0x01ce7585, 0x022a83cd, 0x0232d0e0, 0x02396b42 and 0x023dff92.
  For each of the five, the function 0x14d bytes on (0x01ce76d2, 0x022a851a, 0x0232d22d,
  0x02396c8f, 0x023e00df) is among the 54. The only discovery change in the merge is the Shared
  Return port, which makes fewer targets functions (see "What discovery does"); which of its
  rules drops each of the 54 was not traced one by one. None of the eight M8 functions is in
  the changed lines.
- M8, all 57 checks: every line equal to the `m3-int6` baseline (`m3-int6-1c9dc419e3.summary`),
  silent 0. No line moved.
- Shadow check (`analyze orig/Mercenaries2.analysis.exe --functions-from build/functions.csv
  --abi-callers config/register_abi.csv`, as mercs2's `tools/ghidra-rs-shadow.sh`): the output
  of this binary and of the `m3-int6` binary are byte-identical (56,918 lines; both 37,926
  functions, 38,546 references checked). With Java's function list as seeds the port changes
  nothing there.
- `tools/mercs2-exports.sh --functions $GHIDRA_REF/scripts/functions.csv --compare
  $GHIDRA_REF/scripts/java`: `bindings.csv`, `mod-hook-owners.csv`, `boundaries.txt` and
  `contexts-568900.txt` identical; `contexts-4017b0.txt` and `contexts-593c10.txt` the same
  references in another order; `contexts-401780.txt` not identical (Java 6,560 lines, here
  6,584, 6,553 in both), as in the table of "Switching mercs2's export scripts". All seven
  files are byte-identical to the export branch's own run.

Superseded by this section: "Plain discovery finds 29,240 functions" of stage S10 (now 29,186;
the Mall speed counts of 29,240 are measurements of their dates). Not run on `m3-int7`: M500
and the full pass (the switch, `simple` and `r5d-adc` corpora), the Mac, `cargo test
--release`, `ghidra-diff.sh` and `facts-diff.sh`, and the shadow diff against Java's
`config/abi_callers.csv` (only the two ghidra-rs binaries were compared).

Full pass (2026-11-18, `bars.sh` on 249c32cf94, the tip of `m3-int7`, `TIMEOUT` 120; summary
`rust/target/baselines/m3-int7-249c32cf94.summary`, 133 lines, compared with
`m3-int6-1c9dc419e3.summary`): 133 / 133 pairs, silent 0 in every pair, no pair with fewer
identical functions or more silent misses than `m3-int6`. Lines that moved:

- `r5s-m500`: reference finished 498 -> 499, identical 498 -> 499.
- `r5slock-m500` and `r5dtlocksv-m500`: reference finished 498 -> 499, identical 467 -> 469,
  loud 31 -> 30.
- `pmd-m500`: reference finished 499 -> 500, identical 496 -> 497 (loud 3).
- "all outputs identical" one lower in 16 M500 lines: 500 -> 499 in `r4`, `r5d`, `s6`,
  `s6callee`, `s6int4`, `s6void`, `s8`, `s8r`, `subvar`, `svs6`, `swsn-r` and `swsn-t`;
  499 -> 498 in `r5`, `r5c` and `r5typed`; 491 -> 490 in `svlock`. `stack-m500` outputs with
  stack SSA 319 -> 318. Their reference-finished, identical, loud and silent counts did not
  move; which function each lost was not traced.

The `m3-int6` note that `r5s`, `r5slock` and `r5dtlocksv` M500 have reference finished 498
instead of 499 (0x6b21e0) did not show on this pass: all three finished 499. 0x6b21e0 still
times out; another function, which timed out before, finished instead. Reference timeouts at
120 s move with machine load by about one function per run.

How the pass ran: 109 pairs on the desktop, then a power cut; the 24 missing pairs ran under
`bars-queue.sh`, 13 on the desktop and 11 on the Mac. The Mac first matched the desktop on
`pc-r-m500` (the same summary line, the same 5 misses). The Mac's prelude was stale (from
before the Shared Return port) and was regenerated; it now matches the desktop's (`cksum`
285336359).

Superseded: "Not run on `m3-int7`: M500 and the full pass ..., the Mac" above (the rest of that
list still holds: `cargo test --release`, `ghidra-diff.sh`, `facts-diff.sh` and the shadow diff
against Java were not run).

The own-facts gap (2026-11-18, `ghidra-diff.sh` on 249c32cf94, the same code as master's, the
full pipeline against Java Ghidra with default options; inputs kept in `rust/target/gap7/`):

| facts | M8 | M500 |
|---|---|---|
| the Java project's | identical 7 / 7 (loud 0, silent 0) | Java finished 499 / 500, identical 461 / 499 (loud 22, silent 16) |
| ghidra-rs's own, Java's function list (`analyze --functions-from`, 73 s) | identical 4 / 7 (loud 2, silent 1) | identical 328 / 499 (loud 31, silent 140) |
| ghidra-rs's own, plain discovery (65 s) | identical 2 / 7 (loud 2, silent 3) | identical 177 / 499 (loud 122, silent 200) |

Java-facts gap (2026-11-20, branch `gap-javafacts`, M500 identical of 499): 461 (loud 22, silent 16) -> 467 (loud 23, silent 9), M8 7 / 7, the 57 M8 bars as `analysis-queue`. Fixed: `void` is the size-0 TypeVoid (3 silent), a function symbol covers its facts size of 2 to 8 bytes (`FunctionSymbol::consumeSize`; 2 silent, 1 silent now loud), `isString` takes the empty string (1 silent). Of the 9 silent left, 8 are reference-version differences: `/opt/ghidra` is 12.3 and its decompiler lacks GP-7356 (`register0x00000010` for `register_ESP`) and GP-7474 (`_BinkPause_8`); the repo C++ replaying Java's debug XML (`DecompileRef.java` with `DECOMP_DEBUG_DIR`) prints what ghidra-rs prints. The ninth (0x47f890, variable numbering) is open. Superseded: the 461 / 16 counts above.

Java-facts gap, continued (2026-11-20, branch `gap-javafacts2`, M500 identical of 499): 467 (loud 23, silent 9) -> 469 (loud 21, silent 9), M8 7 / 7. The deindirect restart is ported: `ActionDeindirect` records the call as an override (`Override::insertDeindirect`) and asks for a restart when the callee does not return, is inlined, or has a locked prototype the call cannot take; the `universal` group (`ActionRestartGroup`, at most 1 restart) clears the function (`clearAnalysis`) and runs again, and the flow makes the call direct (`Override::applyIndirect`). The restart starts from the prototype the decompile started with, where the C++ clears only the unlocked inputs and output of the one it has. Of the 9 functions that stopped there, 2 are identical; 7 stop at later not-ported paths: a call to a locked varargs prototype 4, a logical value in a join varnode (subflow) 2, a data-type needing resolution in `setcasts` 1. 0x47f890 is a reference-version difference too: decomp_dbg built from this repo's C++, on Java's debug XML with Java's options, prints `auStack_82 [2]` where Java prints `uStack_90` and `unaff_EDI`, as ghidra-rs does; so all 9 silent are reference-version differences. Correction: `/opt/ghidra` is 12.2 (its application.properties) and this repo's source is 12.3. Superseded: the 467 / 23 counts, "`/opt/ghidra` is 12.3" and "0x47f890 is open" above. Then a logical value in a join varnode (`SubvariableFlow::getReplacementAddress` with `renormalizeJoinAddress`, little-endian) is ported: 469 (loud 21, silent 9) -> 470 (loud 20, silent 9), M8 7 / 7; 0x5cee30 is identical, 0x5d8680 and 0x5d87c0 now stop at a call to a locked varargs prototype, which 7 functions stop at. 0x4098c0 stops at type propagation into a union. Superseded: the 469 / 21 counts. Then a call to a locked varargs prototype is ported (`funcLinkInput` with `initActiveInput` and the fixed position of each locked parameter, `sortFixedPosition` in `buildInputFromTrials`; `lateRestriction` refuses to give a varargs call a non-varargs prototype, as `isCompatible` does, and a varargs call taking a varargs prototype stays loud), and the name recommendations stay for a restart (the C++ keeps `nameRecommend`; the restart lost `local_80` of 0x6c3cb0): 470 (loud 20, silent 9) -> 473 (loud 16, silent 10), M8 7 / 7, the M8 bars unchanged (57 lines). 0x4b8e50, 0x5d84e0 and 0x5d87c0 are identical; 0x5d8680 stops at StringSequence, 0x5e66c0 at `getTypePartialStruct`, 0x74d520 at type propagation into a struct. 0x6c3cb0 is newly silent and no version difference (the repo C++ on Java's debug XML prints Java's C): in the pass after the restart the C++ gives the COPYs in the split return blocks the global's types (`char`, `float`) where ghidra-rs keeps `undefined1` / `undefined4`, so ghidra-rs prints `DAT_014e0432 = 1` for `'\x01'` three times; the first passes agree, and keeping the global scope's symbols over the restart did not change it. Superseded: the 470 / 20 counts. Then the global scope keeps its symbols over a restart (`Funcdata::clear` clears the local scope only) and a type-locked data symbol of an unknown data-type is size-locked (`Symbol::checkSizeTypeLock`), so `ActionNameVars` gives it the type of its high variable (`overrideSizeLockType`) and the varnodes of the pass after the restart take that type from the symbol (`setSymbolProperties`, the global scope before the facts): 473 (loud 16, silent 10) -> 474 (loud 16, silent 9), M8 7 / 7, the M8 bars unchanged (57 lines); 0x6c3cb0 is identical. Superseded: the 473 / 10 counts and "0x6c3cb0 is newly silent" above. Then `StringSequence` is ported up to its validity (the constructor: `collectCopyOps`, `checkInterference`, `formByteArray`); a COPY that roots no sequence of four characters in an array of the symbol is left alone, a valid one and a symbol of a struct or union stay loud (`StringSequence::transform` is not ported): 474 (loud 16, silent 9) -> 478 (loud 11, silent 10), M8 7 / 7, the M8 bars unchanged (57 lines). 0x5a9b80, 0x5bed50, 0x5d8680 and 0x740a90 are identical. 0x5d9a20 is newly silent and a reference-version difference: decomp_dbg built from this repo's C++, on Java's debug XML, prints what ghidra-rs prints (early returns where Java nests if / else); which 12.3 change it is was not traced (GP-7115, which splits out `BlockIfNoExit`, is a candidate). Superseded: the 474 / 16 counts. On the 12.3 reference (`rust/target/ref123/`, Ghidra 12.3 built from this repository, `GHIDRA` names the install) the row is 487 (loud 11, silent 1: 0x5c64a0), M8 7 / 7. Superseded: the 478 / 10 counts (12.2) as the measure. With Java's facts loaded, name tokens (function, variable, type, field and label names, not constants) print as Java's `PrettyPrinter` prints them through `IllegalCharCppTransformer` (`DecompileResults.getDecompiledFunction`; a namespace prefix, printed by `emitSymbolScope` as syntax, is kept): `_BinkPause@8` -> `_BinkPause_8`, 488 (loud 11, silent 0), M8 7 / 7; without facts names print as the C++ console prints them (M8 bars unchanged, 57 lines). A non-ASCII letter in a name fails loudly (`Character.isLetter` is not ported). `lateRestriction` is ported for every prototype a deindirected call takes, locked or not, with `FuncProto::isCompatible` (`ProtoModel::isCompatible`: the facts' `unknown` model is compatible with the default; both outputs locked compare storage and data-type; extrapop; varargs, where an unlocked call may take a varargs prototype; call fixup; no-return), so an unlocked callee that is not compatible restarts as in the C++, no longer copied; a varargs prototype onto a call still recovering its inputs fails loudly (`collectUnlockedTrials`), one onto a call not recovering them restarts. A call fixup no longer stands for `isInline` (no prototype is inline: the facts refuse the flag); a prototype with its own effect or likely-trash list is refused by the facts. Java-facts row on 12.3 unchanged: 488 (loud 11, silent 0), M8 7 / 7; M8 bars unchanged. A restart keeps the prototype as the pass before left it (model, extrapop, flags, as `Funcdata::clear` keeps `funcp`) and clears only its unlocked output and `returnBytesConsumed` (`FuncProto::clearUnlockedOutput`; a size-locked output back to an unknown data-type, `resetSizeLockType`). Superseded: "the restart starts from the prototype" above. Small fixes after a review: a restart keeps the join records (global in the C++, `AddrSpaceManager`); `renormalizeJoinAddress` in SubvariableFlow fails loudly on a constant piece (`!addr1.isConstant()`) and on a big-endian target; a function record's malformed `size` attribute is a facts error, no longer read as 0; a cached global symbol without a data-type fails loudly instead of skipping the facts. Not done: `findContainer`'s smallest container in `query_global` (functions are still checked before external references) and the split of `string_sequence_valid` (constseq.rs).

The first attempt's own-facts counts were not valid: `ghidra-diff.sh` was given facts paths
that did not resolve, fell back to the Java facts without a word and printed the Java row.
`ghidra-diff.sh` now stops on a missing or empty `FACTS` file (see "Stage S10, slice 1").
Superseded: the own-facts M500 counts 171 and 173 / 499 (Java's functions) and 90 / 499 (plain
discovery) of S10 slices 2 and 3, with the eight actions skipped, and `ghidra-diff.sh` in the
"Not run" list above.

### The own-facts gap with Java's function list: causes and a first fix, branch `worktree-agent-a628570747560462f` (2026-11-18)

**Attribution.** The 133 M500 functions that miss with ghidra-rs's own facts (Java's function
list, `gap7/own-java.facts`) and not with the Java project's facts (125 silent, 8 loud) were
traced by swapping one record kind at a time: the own facts with all of Java's records of that
kind in their place (`underived` records of the kind dropped; `type` records a union), then
`ghidra-diff.sh m500`. The unchanged own facts give 328 / 499 (loud 31, silent 140) again.

| swapped in from Java | M500 identical (loud, silent) |
|---|---|
| nothing | 328 (31, 140) |
| `func` with `type` and `ns` | 375 (21, 103) |
| `data` | 371 (36, 92) |
| only the `extrapop` of each `func` record | 351 (30, 118) |
| only the `<symbollist>` (stack variables) of each `func` record | 343 (31, 125) |
| `override` | 333 (31, 135) |
| `data`, `func` with `type` and `ns`, and `override` together | 429 (21, 49) |
| `body`, `label`, `string`, `undef`, `comments`, `wref`, `tracked` | 328 (31, 140) each |

`extref` could not be swapped alone (its records name Java's namespace ids); not measured.
Per function, the swaps that make it identical (`rust/target/gap-row2/causes.txt`):

| cause | functions | example |
|---|---|---|
| `data` records (sizes and types of referenced data) | 43 (12 fixed below) | 0x402c20 |
| `extrapop` (the function purge) | 23 | 0x404710 |
| stack variables (`<symbollist>`) | 17 | 0x40dc10 |
| the `func` record, neither part alone (both, or the prototype otherwise) | 14 silent, 4 loud | 0x40e770 |
| `override` (CALL_RETURN: no-return and Shared Return, discovery's side) | 5 | 0x4f0370 |
| no single kind (11 of them identical with `data`, `func` and `override` swapped together) | 23 silent, 4 loud | 0x402820 |

Why `extrapop` and the stack variables differ (of 44,983 `func` records, 12,454 differ as text, symbol order included; the
`extrapop` of 4,888): Java's `FunctionPurgeAnalysisCmd` runs when a function is added and never
again. A function made before the code its body reaches was disassembled keeps an unknown purge
although its finished body has a RET (0x4b6580: Java `unknown`, the RET at 0x57b7b8), and a
CALL_RETURN tail takes the callee's purge as it is at that moment. 2,185 functions of Java's
own auto-analysis (`functions-analysis.csv`) have an unknown purge in Java's facts where
ghidra-rs derives one; 1,167 functions Java has a purge for are, here, seeded (not found by
plain discovery) and get none. Both need the order of Ghidra's analysis queue, which is not
ported; the `ponytail` notes of `Analysis::ret_purge` and `Exporter::locals` stand.
Superseded (2026-11-18, branch `analysis-queue`): the queue is ported and the purge runs in it
(`Analysis::callee_purge`; `ret_purge` is removed); 0x4b6580 (`JMP 0x57b780`, size 5 in Java's
facts) was made right after 0x57b780 in Java 12.2's trace (`gap-row3-java/creators.log`), as
CreateFunctionCmd makes a thunk's target first; it is no function made before its code. On the
merged base the count is 2,182, then 1,743 and 1,769, now 1,778 (superseded: "now 1,743", "now 1,769"); see "Ghidra's task queue and the purge".

**Fix 1: INT_ZEXT and INT_SEXT size data** (`Exporter::accesses`). `SymbolicPropogator`'s
INT_ZEXT and INT_SEXT cases make a READ reference with the input varnode, as its COPY case does;
ghidra-rs sized only COPY. A `MOVSX`/`MOVZX` of a direct address now sizes the data
(0xdf5c2c: `undefined2`, as Java). Facts (`facts-diff.sh`, Java's functions): `data` equal
230,455 -> 230,932 (84.9% -> 85.1%); 487 `data` and 24 `undef` records changed, nothing else.
M500 own facts with Java's functions: 328 -> 340 / 499, loud 31 -> 31, silent 140 -> 128 (12
functions fixed, none newly missing); M8 4 / 7 (loud 2, silent 1), unchanged. The decompiler is
not touched; the Java-facts row is not affected.

Superseded: "328 / 499 (loud 31, silent 140)" for own facts with Java's function list in the
table of "Integration `m3-int7`" (now 340, loud 31, silent 128). Not run: plain discovery's
own-facts row, the full pass, the Mac.

### Ghidra's task queue and the purge, branch `analysis-queue` (2026-11-18)

Base: the branch above merged with the Function Start Search fix (`22d5918c63`, PatternPairSet
bits). Own facts with Java's function list: M500 343 / 499 (loud 31, silent 125), M8 4 / 7
(loud 2, silent 1); plain discovery: M500 187 / 499 (loud 128, silent 184), M8 2 / 7 (loud 2,
silent 3).

**The queue** (`queue.rs`, see "What discovery does"). Discovery runs through it; with only
discovery's analyzers the facts of both function sets are byte for byte the base's.

**X86 Function Callee Purge in the queue** (`Analysis::callee_purge`). Java's
`FunctionPurgeAnalysisCmd` runs on each batch of new functions at priority 500, in address
order, and sets a purge only where it finds one: the first RET (or RETF) of the body by
address, among its first 2048 instructions; without one, the purge the function its last
CALL_RETURN flow reaches has at that moment (so a thunk-like `JMP` to a function later in the
same batch gets none). A known purge is never set again (superseded: "a purge is never set
again"; an unknown one is looked for again, see "Body changes" below). 471 functions go from a purge to Java's
`unknown` (0x402fb0: base 4), 42 the other way (below). ghidra-rs worked the purge out
from the finished body, the callee first
(`Analysis::ret_purge`, removed). The `extrapop` of the facts is now the purge of that turn,
of the run without seeds where seeds were given (`Inputs::purges`); the stack analysis goes by
those purges too. An IRET does not end the search (Java looks for `ret`/`retf`).

| auto-analysis functions (`functions-analysis.csv`), Java's function list | base | queue |
|---|---|---|
| `extrapop` equal | 17,602 | 18,004 |
| Java `unknown`, ghidra-rs known | 2,182 | 1,743 |
| Java known, ghidra-rs `unknown` | 1,352 | 1,388 |
| both known, different | 4 | 5 |
| stack variables (`<symbollist>`) equal | 12,201 | 12,218 |

(Plain discovery: Java `unknown` here known 2,179 -> 1,722, equal 17,540 -> 17,966.) Two
`data` records change with Java's function list (0x1532024, 0x1532028: size 4 -> 1, as Java),
two disappear in plain discovery's facts; nothing else but `func` records.

| own facts | M8 | M500 |
|---|---|---|
| Java's function list, base | 4 / 7 (loud 2, silent 1) | 343 / 499 (loud 31, silent 125) |
| Java's function list, queue | 4 / 7 (loud 2, silent 1) | 347 / 499 (loud 31, silent 121) |
| plain discovery, base | 2 / 7 (loud 2, silent 3) | 187 / 499 (loud 128, silent 184) |
| plain discovery, queue | 2 / 7 (loud 2, silent 3) | 189 / 499 (loud 128, silent 182) |

No M500 function newly misses (4 and 2 fixed). The decompiler is not touched; the Java-facts
row is not affected. `analyze --facts` with Java's function list takes 77 s (base 61 s): each
purge turn recomputes the bodies and the non-returning functions of that moment; plain 53 s
(base 47 s), measured under the same load, one run each.

**Body changes** (`analysis-queue`, after `52566ad440`). Java's AutoAnalysisManager sends
FUNCTION_ADDED and FUNCTION_BODY_CHANGED alike to `functionDefined`, so the purge analyzer
gets a function again when its body changes, and `analyzeFunction` looks again where the purge
is still unknown (or past 128). After each task the bodies are computed as a purge turn
computes them (`Analysis::turn_bodies`), and a function whose body differs from the last
notification is notified; the purge turn uses those bodies. Superseded (2026-11-19): bodies are kept from creation
and set only where Java sets them; see "Bodies from creation" below. Bodies and the non-returning
functions of a turn now take only functions with an instruction (CreateFunctionCmd makes none
without one): 45 to 51 call targets that were never decoded counted as empty, non-returning
functions before; alone, this changes no record. The fallback to a CALL_RETURN flow also takes
a computed jump (COMPUTED_CALL_TERMINATOR).

| auto-analysis functions, Java's function list | queue | body changes |
|---|---|---|
| `extrapop` equal | 18,004 | 17,979 |
| Java `unknown`, ghidra-rs known | 1,743 | 1,769 |
| Java known, ghidra-rs `unknown` | 1,388 | 1,387 |
| stack variables equal | 12,218 | 12,215 |

(Plain discovery: equal 17,966 both; Java `unknown` here known 1,722 -> 1,723; Java known here
`unknown` 534 -> 533.) 29 records change: 3 non-thunks get Java's purge (both the facts and a
fresh Java 12.2 analysis agree); 26 are 5-byte thunks whose target's purge Java leaves
unknown. Here their `JMP` to a function is a derived CALL_RETURN, so the retry takes the
target's purge once the target has one; in Java a thunk has no purge of its own
(`FunctionDB.getStackPurgeSize` returns the thunked function's). These 26 wait for the thunk
port (below). Own facts: M8 4 / 7 and 2 / 7 unchanged; M500 with Java's function list 346 / 499
(loud 31, silent 122), plain discovery 189 / 499 (loud 128, silent 182). The one newly silent
function, 0x5409f0, calls 0x536700, one of the 26 (`unknown` -> 8). `analyze --facts` takes
82 s with Java's function list and 78 s plain, under a heavier load than the runs above (load
average 11), one run each.

**Java's own purges are not the facts' on thunks.** A fresh Java 12.2 auto-analysis
(`rust/target/gap-row3-java/proj`, dumped by `tools/ghidra/DumpPurges.java`;
`extrapop` = purge + 4) and the facts (`mercs2.facts`, mercs2's project after its pipeline)
disagree on 663 thunks of the auto-analysis functions. Of the 702 5-byte functions in the
1,743, Java 12.2 gives 594 the purge ghidra-rs has (0x4b6580: thunk of 0x57b780, purge 0;
the facts say `unknown`), and leaves 99 unknown. 489 thunks of the 1,388 are known in both
the facts and Java 12.2. A faithful thunk port can therefore move about 99 of the 1,743 and
about 489 of the 1,388, not the 702.

**The RTTI analyzer at 599** (`Task::Rtti`, after `e26bc48850`). Java's Windows x86 PE RTTI
Analyzer is a byte analyzer at `REFERENCE_ANALYSIS.before()` (599), so it makes its functions
(`EHDataTypeUtilities.createFunctionIfNeeded`: disassemble, then CreateFunctionCmd) after the
first purge turn; the vftable slots are no longer seeds of Disassemble Entry Points. Superseded:
"here its functions are seeds of the first turn". With Java's function list: `extrapop` equal
17,979 -> 17,997, Java known here `unknown` 1,387 -> 1,360, Java `unknown` here known 1,769 ->
1,778, stack variables equal 12,215 (unchanged); 0x417290 (`ADD ECX,8; JMP`) now 4, as Java.
The 9 new Java-`unknown` ones (0x8d6470 .. 0x8e8f10, e.g. 0x8dc8b0 `SUB ECX,8; JMP 0x8dc8f0`,
made by the RTTI analyzer in Java 12.2's trace) are adjustor stubs whose `JMP` reaches a
function that has a purge by the later turn; here such a jump is a derived CALL_RETURN, in Java
only Shared Return Calls makes it one (below), and Java 12.2 leaves them `unknown` too. Plain
discovery: equal 17,966 -> 17,983, Java known here `unknown` 533 -> 506, Java `unknown` here
known 1,723 -> 1,733. The function lists do not change (plain discovery against Java 12.2,
`func` records of the facts in `.text`: 22,353 / 931 / 227 before and after). M8 and M500 the
same for both rows (346 / 499 and 189 / 499), no function newly misses. `analyze --facts`
111 s with Java's function list, 57 s plain, one run each under varying load.

Not modelled, ranked by what is left of the 1,743:

Superseded (2026-11-19) for the first two items: see "Bodies from creation" below.

- CreateFunctionCmd's thunks: a new function that is a `JMP` makes a function at its target
  first (`CreateThunkFunctionCmd.getReferencedFunction`), so the thunk's purge is the target's,
  unknown in the same batch. 702 of the 1,743 are 5-byte functions. 0x4b6580 (`JMP 0x57b780`, Java
  `unknown`) keeps 4: 0x57b780 is no function at its turn here, so its body runs on to the RET. A first port (the simple
  flow only, bodies of the turn) brought 1,743 to 1,418 but made 313 functions Java does not
  have (plain discovery against Java 12.2's list); not kept. A faithful port needs the body
  each function had when it was made (`getFunctionContaining` and the body containment check of
  `CreateThunkFunctionCmd.applyTo` run on it) and `getThunkedAddr`'s p-code register tracking.
- Shared Return Calls at 398 on each batch, the non-returning functions at 302, and the body
  each function had when it was made (here: the body of the turn, the non-returning functions
  of this analysis's rule on that turn's bodies, kept for the turn only).
- the Stack analyzer (903) on each later batch: here every purge turn comes before it.
- discovery's analyzers are the old discovery at Java's priorities, not ports of Java's analyzers
  (labelled in `Analysis::run`): Disassemble Entry Points puts every seed in at 200
  (EntryPointAnalyzer's do-later set of suspect entries, at 599, is not modelled); Function Start
  Search disassembles inline and repeats until nothing is new (Java searches once and queues
  DisassembleCommand and CreateFunctionCmd at 400 and 401); Function Start Search After Data
  sweeps everything and ignores its set (Java's FunctionStartDataPostAnalyzer searches the added
  data for the `after="data"` patterns), and is notified with the table targets, not new data.
- `RET n` is read unsigned: Java (the facts and Java 12.2) has extrapop 33175 for 0x1f682c0 (`RET 0x8193`, 0x8193 + 4),
  so `getScalar(0).getSignedValue()` gives the positive value there.

Not run: the full pass, the Mac, the shadow check (what `--abi` reads, the functions, bodies,
non-returning functions and `Analysis::purge`, is unchanged). Superseded (2026-11-19): with
the bodies below, the functions, bodies and non-returning functions change; the shadow check
was not run on them.

#### Bodies from creation, and CreateFunctionCmd's thunks (2026-11-19)

**Oracles** (the user's decision, DESIGN.md "Decided" 2026-11-19): analysis alone is checked
against a plain Java 12.2 auto-analysis (`rust/target/aq-java/purges.txt` of the main checkout,
dumped by `tools/ghidra/DumpPurges.java`: entry, purge, thunked function, body min / max /
address count, no-return); analysis with the ported mercs2 edit scripts against `mercs2.facts`.

**The body model** (`Analysis::create_function`). A function's body is set when the function is
made and changed only where Java changes it; `Analysis::bodies` is no longer recomputed from the
flow after each task. After each task (the purge excepted) the functions without a body are
made in address order, as CreateFunctionCmd: the flow from the entry up to the entries of the
functions made so far (`Analysis::walk`, getFunctionBody), less what other bodies hold;
each function whose body overlaps loses the part from the new entry to the new body's end (it
lies before) or up to its own entry (it lies after) (subtractBodyFromExisting). Bodies never
overlap during the run (`body_owner`). The functions made and the bodies set are notified to the
function analyzers (FUNCTION_ADDED, FUNCTION_BODY_CHANGED). With `--functions-from`, only the
listed functions are made.

Java's sites that set a body, and what is ported:

| Java site | here |
|---|---|
| CreateFunctionCmd.createFunction, subtractBodyFromExisting | ported (`create_function`, `subtract_existing`) |
| CreateFunctionCmd.resolveThunk, CreateThunkFunctionCmd.applyTo | ported for a direct `JMP` at the entry (getSimpleFlow), `resolve_thunk` |
| CreateFunctionCmd.fixupFunctionBody | ported (`fixup_body`); its thunk case only for a target that is a function already and a new body that overlaps no other, and not where the target's thunk chain leads back to the function (setThunkedFunction refuses a cycle). A thunk chain past 16 thunks prints a warning (`analyze`, `edit`); on mercs2 it does not show. Superseded (2026-11-20): the 4-round no-return warning went with the body rule |
| FindNoReturnFunctionsAnalyzer (added, detectNoReturn, checkNonReturningIndicators, targetOnlyCallsNoReturn, setNoFallThru, fixCallingFunctionBody) | ported (`find_noreturn`), run after each batch of functions made where Java's instruction analyzer runs on instructions added; not ported: "Repair Flow Damage" (below), a function made at a target that is none, the call-fixup exception. Superseded (2026-11-20): only fixCallingFunctionBody, for a rule of this analysis on the bodies |
| CreateFunctionCmd with findEntryPoint (setBody of a given body) | not ported: no ported analyzer makes functions that way |
| CallFixupAnalyzer.fixCallingFunctionBody | not ported (no call-fixup analyzer here) |
| EntryPointAnalyzer (recreate after the do-later set) | not ported (the do-later set is not modelled) |
| AddressTable.fixupFunctionBody, DecompilerSwitchAnalyzer / DecompilerSwitchAnalysisCmd | not ported: switch cases are disassembled here before the function is made, so its first body holds them |
| ClearFlowAndRepairCmd | not ported: FindNoReturnFunctionsAnalyzer runs it on the flow after a new non-returning call ("Repair Flow Damage", on by default: `repairDamagedLocations`), clearing code and refixing bodies; nothing here clears flow, and nothing reports where Java would. Superseded (2026-11-19): "no analyzer here clears flow" read as if Java's did not either. Superseded (2026-11-21): ported, see "Repair Flow Damage, branch `repairflow`" |
| the edit scripts (`store.rs`) | `Store::apply` recomputes only the bodies its edits touch (functions made, removed, given a body or thunk mark; bodies holding a cleared, overridden, switch or new-entry address) from the flow (`body_of`, an approximation of Java re-running its commands); the rest keep their creation bodies. Superseded (2026-11-19): it recomputed every body (`compute_bodies`, removed) |

Also not ported: getThunkedAddr's p-code register tracking (thunks of more than one
instruction, e.g. adjustor stubs), CALL_TERMINATOR thunks, getThunkedAddr stepping over an entry
instruction without p-code (Superseded, 2026-11-23, branch `fix-hatred-analysis`: ported,
`Analysis::thunk_insn`; `NOP; JMP x` is a thunk of x; mercs2 has none, so the warning that
counted them is gone), the one-byte placeholder body of a
function made before its code, the no-return analyzer per batch. Superseded (2026-11-19):
Shared Return Calls now runs per batch at 398; see "Shared Return Calls per batch" below.

**Thunks.** A function whose first instruction is a direct `JMP` is made a thunk of the target,
the target made first where it is no function yet, unless the target lies in another body, has
no instruction or is a thunk on the way; the thunk's body is its body less the target's
(0x4b6580: `JMP 0x57b780`, body 5 bytes, as Java 12.2). A thunk body that would hold code of a
third function (made with the target) is refused, as createThunkFunction's
OverlappingFunctionException, and CreateFunctionCmd tries again (2026-11-19 fix).
Two thunk definitions remain: the purges go by the thunks made here (`Analysis::thunk_of`), the
facts' thunk names and `Project::thunked` by a body of one direct jump to a function. `run`
counts where they disagree and `analyze` and `edit` print it (`warning: thunks disagree`):
mercs2 plain discovery 10 one-jump bodies not made thunks (8 of them thunks in Java 12.2, e.g.
0x4cefc0 -> 0x6a5590; 0x430e40 and 0x6b3010 not), none the other way; with Java's list none.
Taking `thunk_of` in the facts was tried and left out: it lost those 8 Java thunks (plain purges
differing 824 -> 827). A thunk's purge is its thunked
function's, read and set (`FunctionDB.getStackPurgeSize`); `callee_purges` gives each thunk its
target's purge when `run` ends. The purge analyzer looks in the body, then in the flow from the
entry (`locatePurgeInstruction`).

**No-return rule on the bodies set.** A jump out of the body counts as returning unless its
target is a non-returning function (a body no longer runs on into code another function holds).
Non-returning functions are kept once found, as Java's flag. Superseded (2026-11-19): "as
Java's flag" was misleading. The rule is an approximation: Java's FindNoReturnFunctionsAnalyzer
decides from call-site evidence against a threshold, never from a body without a RET, and a
wrong mark here is never cleared. Since 2026-11-19 a conditional jump out of the body and a
fallthrough out of it (into another function's body) count as returning too, so a function cut
by one made inside it is not marked for falling into it; numbers in "Shared Return Calls per
batch" below. Superseded (2026-11-20): this body rule is gone; see "No-return functions from call-site evidence" below.

Against Java 12.2 (`j12body.sh`, `rust/target/aq/` of this worktree; functions in both lists;
"auto" = `functions-analysis.csv`):

| | before | after |
|---|---|---|
| plain discovery: functions both / Java only / here only | 28,434 / 2,214 / 315 | 28,751 / 1,897 / 316 |
| plain, purge differs (auto) | 1,925 (1,763) | 1,891 (1,806) |
| plain, body differs (auto) | 1,275 (919) | 824 (677) |
| plain, no-return differs (auto) | 437 (28) | 125 (38) |
| Java's list, purge differs (auto) | 3,714 (2,523) | 3,274 (2,526) |
| Java's list, body differs (auto) | 2,604 (2,092) | 2,358 (2,002) |
| Java's list, no-return differs (auto) | 557 (21) | 218 (34) |

Against `mercs2.facts` (`purgecmp.sh`, auto-analysis functions, Java's list): Java `unknown`
here known 1,778 -> 1,808, Java known here `unknown` 1,360 -> 1,354, equal 17,997 -> 17,973,
stack variables equal 12,215 -> 12,238; plain discovery: 1,733 -> 1,808, 506 -> 506, equal
17,983 -> 17,911. 5-byte functions whose purge differs from Java 12.2 (auto, Java's list):
Java `unknown` here known 128 -> 117, Java known here `unknown` 41 -> 28; plain discovery
88 -> 118 and 17 -> 3.

The plain purge loss (about 100 functions Java leaves `unknown` that now get one, e.g.
0x40363f `JMP 0x416bb6`) comes from Shared Return Calls at 10000: 0x416bb6 is made a function
by it after the first purge turn, so 0x40363f's first body runs on to 0x416bb6's RET; in Java
Shared Return Calls runs at 398, before the purge. Porting it per batch is the next step.
Superseded (2026-11-19): ported, see below.

Own facts (`ghidra-diff.sh`): Java's function list M500 346 -> 347 / 499 (loud 31, silent
122 -> 121; 0x5409f0 fixed, none newly missing), M8 4 / 7 (loud 2, silent 1) unchanged; plain
discovery M500 189 / 499 (loud 128, silent 182) and M8 2 / 7 (loud 2, silent 3) unchanged.
`analyze --facts` 81 s with Java's list, 63 s plain, one run each. The facts of two runs are
byte for byte the same. Not done: the Stack analyzer (903) on later batches. Not run: the full
pass, the Mac, the shadow check, `--functions` / `--gaps` exports.

#### Shared Return Calls per batch (2026-11-19)

Shared Return Calls is a FUNCTION_ANALYZER at `CODE_ANALYSIS.before().before()` = 398
(`SharedReturnAnalyzer`), so it runs on each batch of functions added or with a body set
(AutoAnalysisManager's FUNCTION_ADDED / FUNCTION_BODY_CHANGED), before the purge (500). Its
targets are made by CreateFunctionCmd after the task (Java schedules them at 397, before any
other task), through `create_function`: a body that held the target is cut (a body change
event, so the function goes to Shared Return Calls and the purge again). 0x40363f
(`JMP 0x416bb6`): body 0x40363f-0x403653 and purge `unknown`, as Java 12.2 (was 4).

| `j12body.sh` against Java 12.2 | before (f0f80bdab6) | after |
|---|---|---|
| plain: functions both / Java only / here only | 28,751 / 1,897 / 316 | 28,742 / 1,906 / 271 |
| plain, purge differs (auto) | 1,891 (1,806) | 846 (761) |
| plain, body differs (auto) | 824 (677) | 824 (677) |
| plain, no-return differs (auto) | 125 (38) | 125 (38) |
| Java's list, purge differs (auto) | 3,274 (2,526) | 2,316 (1,568) |
| Java's list, body differs (auto) | 2,358 (2,002) | 2,358 (2,002) |
| Java's list, no-return differs (auto) | 218 (34) | 218 (34) |

Own facts (`ghidra-diff.sh`): Java's function list M500 347 -> 381 / 499 (loud 31 -> 30,
silent 121 -> 88), M8 4 / 7 unchanged; plain discovery M500 189 -> 208 / 499 (loud 128,
silent 182 -> 163), M8 2 / 7 unchanged. Not run: the full pass, the Mac, the shadow check.

The no-return rule with conditional jumps and fallthroughs out of the body counting as returning
(fix, same day; plain, then Java's list, all (auto)): no-return differing 125 (38) -> 50 (22)
and 218 (34) -> 54 (24); bodies differing 824 (677) -> 756 (674) and 2,358 (2,002) -> 2,288
(1,997); purges differing 846 (761) -> 824 (761) and 2,316 (1,568) -> 2,294 (1,568); M500 381
and 208, M8 4 / 7 and 2 / 7 unchanged.

#### Plain discovery's silents and the SecuROM slot thunks, branch `gap-plain` (2026-11-20)

The 163 M500 silents of own facts with plain discovery (master f4881c73da: 208 / 499, loud 128,
silent 163), by their outcome in the other rows: 85 are identical with Java's function list (a
discovery cause), 64 silent with it and identical or loud with Java's facts (the facts' own
causes, above), 13 silent in all three rows, 1 loud in both. The 85 by the C lines that differ,
checked against Java 12.2's plain auto-analysis (`rust/target/aq-java/purges.txt`) and the
mercs2 project's facts (table in `rust/target/gap-plain/causes.txt` of the branch):

| cause | silents | example |
|---|---|---|
| mercs2's pipeline, no analyzer: a callee (or its JMP target) is a function in Java 12.2's plain analysis and here, not in the mercs2 project (fold-slot-fragments, RecoverFunctions and the audits) | 43 | 0x402d60 (0x407b60 -> 0x517180) |
| mercs2's pipeline: a pointer in data to a function of the mercs2 project that Java 12.2's plain analysis does not make | 20 | 0x405c40 (0xba8958 -> 0x40b580) |
| `JMP [slot]` thunks into `.securom` (below) | 18 | 0x417230 |
| the slot typed a pointer here, undefined in Java (only an INDIRECTION reference) | 2 | 0x48cc40 |
| a pointer in data to a Java 12.2 function | 1 | 0x495db0 |
| not traced | 1 | 0x4919f0 |

So 63 of the 85 cannot be closed by porting analyzers: Java's own plain analysis agrees with
ghidra-rs there. They need mercs2's edits (`analyze --store`) or a reference made from Java's
plain analysis.

**Jumps through a pointer** (`Analysis::slot_jumps`, a Function analyzer at
REFERENCE_ANALYSIS - 4 = 596, ConstantPropagationAnalyzer's place). A SecuROM slot in `Sdata`
(executable, writable) holds the entry of a `.securom` stub: `0x4172e0 JMP [0x24d7e8c]` ->
0x2562160. Java's propagation reads the slot (VarnodeContext; "trust writable memory" is on by
default), makes a COMPUTED_JUMP reference and disassembles the target
(ConstantPropagationContextEvaluator.evaluateReference); the Reference analyzer then makes a
function whose entry is such a jump a thunk, and its target a function
(OperandReferenceAnalyzer, CreateThunkFunctionCmd.getThunkedAddr: getSimpleFlow over the flow
reference). Java 12.2's project has both references (INDIRECTION to the slot, COMPUTED_JUMP to
the target). Here the task disassembles each such target of the batch's bodies and makes the
thunks after the task's new functions. Not ported (`ponytail` note): the slot's value is the
image's (Java's propagation would see a store to the slot earlier in the flow), only a direct
slot, and the thunk step runs at 596 where Java's Reference analyzer runs at 600 on code added.
`thunks disagree` now counts a one-instruction `JMP [slot]` body to a function as a one-jump body.

| | before | after |
|---|---|---|
| plain: functions both / Java 12.2 only / here only | 28,742 / 1,906 / 271 | 29,431 / 1,217 / 284 |
| own facts, plain discovery, M500 | 208 (loud 128, silent 163) | 226 (loud 128, silent 145) |
| own facts, plain discovery, M8 | 2 / 7 (loud 2, silent 3) | unchanged |
| own facts, Java's function list, M500 | 381 (loud 30, silent 88) | 381 (loud 30, silent 88): 0x5d9cb0 fixed, 0x5dc8f0 newly silent (the purge of `thunk_FUN_0256c420`, now its target's) |
| own facts, Java's function list, M8 | 4 / 7 (loud 2, silent 1) | unchanged |

The 18 fixed are the 18 of the table; none newly missing in the plain row. The Java-facts row
reads no ghidra-rs analysis and was not rerun (461, loud 22, silent 16 on the base). The 13
functions made here that Java 12.2 does not make were not traced. Not run: the full pass, the
Mac, the shadow check.

#### No-return functions from call-site evidence, branch `gap-plain2` (2026-11-20)

0x5dc8f0, newly silent with Java's function list on `gap-plain` (above), calls
`thunk_FUN_0256c420` (0x6a4870, `JMP [0x24d6f7c]`, made a thunk of 0x256c420 by the slot-jump
port). 0x256c420 is `PUSH 0x256c42a; CALL 0x1b950a0` and then bytes that are no code; 0x1b950a0
is `JMP [0x2299230]`, a thunk of 0x2ab0000 (`JMP 0x2ab0028`). In Java 12.2's plain analysis
(`rust/target/aq-java/purges.txt`) all three are no-return, so 0x256c420's body ends at the
call (0x256c420-0x256c429) and its purge is unknown. Here 0x2ab0028 (no RET, but a fallthrough
out of its body) was not marked by the body rule, the body ran on to `RET 0x7b` at 0x256c456
and the thunk took that purge of 123. Java marks 0x1b950a0 from its call sites (a function or
no instruction right after the call, on at least 3 of them), and the mark goes to the thunked
function.

`find_noreturn` is now FindNoReturnFunctionsAnalyzer: the calls of the instructions it has not
looked at; at each, checkNonReturningIndicators from the fallthrough on while instructions fall
through (a function starts there or inside the instruction, no instruction, a read or write from
earlier in the calling function or a call refers to it, an address table, an INT3); 3 call sites
with such evidence (the default threshold) or a target that only calls non-returning functions
(targetOnlyCallsNoReturn, SimpleBlockModel's walk) mark the target, a second pass if some stayed
suspicious. A mark on a thunk is its thunked function's, and so every thunk of it (FunctionDB);
callers' bodies are fixed up as before. Not ported (`ponytail` note): it runs after each batch of
functions made, where Java's instruction analyzer runs at DISASSEMBLY + 2 on instructions added,
so it may see other functions; Repair Flow Damage; a function made at a target that is none; the
call-fixup exception. Superseded (2026-11-21) for Repair Flow Damage: see "Repair Flow Damage,
branch `repairflow`".

| | before | after |
|---|---|---|
| no-return flag, functions in plain discovery and Java 12.2: here only / Java only | 33 / 19 | 2 / 12 |
| own facts, Java's function list, M500 | 381 (loud 30, silent 88) | 382 (loud 30, silent 87): 0x5dc8f0 fixed, nothing else moved |
| own facts, Java's function list, M8 | 4 / 7 (loud 2, silent 1) | unchanged |
| own facts, plain discovery, M500 | 226 (loud 128, silent 145) | unchanged, the same misses |
| own facts, plain discovery, M8 | 2 / 7 (loud 2, silent 3) | unchanged |

Superseded: "0x5dc8f0 newly silent" in the table above. The 12 Java-only no-return functions
(0x401740 among them, the one ClearFalseNoReturn was written for) were not traced. Not run: the
Java-facts row (reads no ghidra-rs analysis), the full pass, the Mac, the shadow check.

#### The store row: plain discovery with mercs2's edits, branch `gap-plain2` (2026-11-20)

A third own-facts row: plain discovery, then mercs2's `analysis_pipeline.sh` edit scripts
replayed on a fresh store in its order (`edit --new-store export-bindings <csv> --recover`,
`recover-functions`, `audit-recovered-functions --remove-empty`, `fold-slot-fragments` with
`build/functions-original.csv` and `build/slot-rewrites.csv`, `add-relocated-entries
config/securom_functions.csv`, `clear-false-noreturn`), then `analyze --store <store> --protos
<win32.protos> --facts <out>` and `ghidra-diff.sh` with `FACTS=<out>`. The run scripts are
`rust/target/gap-plain2/store.sh` and `rows.sh` (not kept in the repo). Store: 24,083 records
(19,320 `function`, 2,468 `override`, 1,451 `body`, 810 `thunk`, 34 `code`), 44,772 functions;
recover-functions 16,513 created, fold-slot-fragments 2,159 removed and 1,431 refit in 2 rounds,
add-relocated-entries 43, clear-false-noreturn 0 cleared. Each `edit` takes 60 to 70 s, `analyze
--store` 86 s. `fold-slot-fragments` needed the `Store::apply` fix above.

| row (own facts) | M500 identical (loud, silent) | M8 |
|---|---|---|
| Java's function list | 382 (30, 87) | 4 / 7 (loud 2, silent 1) |
| plain discovery | 226 (128, 145) | 2 / 7 (loud 2, silent 3) |
| plain discovery with the store | 365 (33, 101) | 4 / 7 (loud 2, silent 1) |

The store row's 101 silents: 82 are silent with Java's function list too (77 of those also
with plain discovery); 17 are functions the store creates (all 17 have a `function ... create`
record: RecoverFunctions, ExportBindings `--recover`), where the own facts give stack locals
(`local_c`) and mercs2's project has none, since its scripts create those functions without
analysis (Java prints `fStack_c`); 2 (0x40ad80, 0x442c90) are silent with plain discovery and
identical or loud with Java's function list.

#### Slots read only by a computed jump or call get no pointer, branch `gap-plain2` (2026-11-20)

The 87 M500 silents with Java's function list, by the record kind that makes each identical when
Java's records of that kind replace the own ones (`rust/target/gap-plain2/swap.sh`, run on those 87
only): `data` 38, Java's whole facts only (no single kind) 12, `func` with the stack variables 8,
`override` 5, `func` 4, stack variables 3, `func` with the purge 2; 15 stay silent with Java's
facts. Of the 38 `data` cases, 15 were a pointer (`PTR_FUN_024dd2e4`) where Java has an undefined
`DAT_` at a SecuROM slot that only `JMP [slot]` thunks read. Java 12.2's plain analysis (dumped from
`gap-row3-java/proj`) has only INDIRECTION references to those slots. OperandReferenceAnalyzer
skips such a reference before its string and pointer checks ("assume someone else will handle this
correctly": a jump or call instruction, and the target has no read or write reference,
`hasDataAccessReferences`). The slots Java makes pointers also have a DATA reference (`PUSH slot`
in `.securom`). `Exporter::reference_data` now skips a target whose references are all the memory
operand of a computed jump or call, unless an immediate refers to it as well. JMP-thunk slots in
`.text`: Java makes 38 pointers, the own facts made 746 before this change.

| row (own facts) | M500 before | M500 after | M8 |
|---|---|---|---|
| Java's function list | 382 (30, 87) | 395 (30, 74) | 4 / 7, unchanged |
| plain discovery | 226 (128, 145) | 238 (128, 133) | 2 / 7, unchanged |
| plain discovery with the store | 365 (33, 101) | 377 (33, 89) | 4 / 7, unchanged |

No row has a new silent function. A first try without the immediate made 0x6ee4c0 silent (slot
0x24db55c, which `PUSH 0x24db55c` at 0x25612bb also refers to). Superseded: the store row's 365 / 101
in the section above.

Causes left among the `data` cases, not fixed: 7 are SecuROM counters in `.securom`
(0x256facf and others). Here they lie inside instructions decoded after a call of a no-return
function (0x256f870 `PUSH; CALL 0x1b950a0`, then `ADD [EAX],AL` runs). Java clears those
instructions with FindNoReturnFunctionsAnalyzer's Repair Flow Damage (ClearFlowAndRepairCmd, about
1,000 lines, not ported), so they are data there. Superseded (2026-11-21): ported; the 7 are
data here too, see "Repair Flow Damage, branch `repairflow`". Others: a size Java gives (`undefined4` at
0x198c758, here `undefined`), labels outside the image (`DAT_9fe1234a`, `DAT_00000004`: 5),
`ThreadLocalStoragePointer` (1). Not run: the full pass, the Mac, the shadow check. Measured
against Java 12.2's outputs, not 12.3.

#### Full pass of `analysis-queue` (2026-11-19)

`bars-queue.sh` on 83ee6a86e6 (the tip then; the same tree is 82b968548a since a merge message got its trailers), desktop and Mac, `TIMEOUT` 120; summary (with the rerun)
`rust/target/baselines/analysis-queue-83ee6a86e6.summary`, 133 lines, compared with
`m3-int7-249c32cf94.summary`. The prelude changes with the analysis: `cksum` 3436140667, 835,201
bytes, 30,084 `map function` lines (`m3-int7`: 285336359, 838,446, 30,208); the Mac's was
regenerated and matched. 132 of 133 pairs in 3 h 54 min, 103 on the desktop (13,455 s busy) and
29 on the Mac (12,738 s); the Mac dropped off the network during `pcc-t-switch` (`lost`,
`INCOMPLETE`), rerun on the desktop: 2004 / 2005 (loud 1, silent 0), the baseline line. Silent 0
in every pair. Lines that moved:

- `pmd-m500` (Mac): reference finished 500 -> 499, identical 497 -> 496 (loud 3);
  `r5slock-m500` (desktop) and `r5dtlocksv-m500` (Mac): reference finished 499 -> 498,
  identical 469 -> 468 (loud 30). In all three the reference timed out at 120 s on 0x4c48d0
  (the 120 s timeout edge noted under `REFCACHE`). Run alone with `TIMEOUT` 400, 0x4c48d0 is
  identical in all three checks, so no function the port decompiles got worse.
- "all outputs identical" one higher in 11 M500 lines: 498 -> 499 in `r5`, `r5c`, `r5dt` and
  `r5typed`; 499 -> 500 in `r5d`, `s6`, `s6int4`, `s8r`, `subvar` and `svs6`; 490 -> 491 in
  `svlock`. `stack-m500` outputs with stack SSA 318 -> 312. Not traced.

Every other line equals the baseline. Superseded: "Not run: the full pass, the Mac" in the
sections of this branch above (the shadow check and the `--functions` / `--gaps` exports are
still not run).

### The 12.3 reference (2026-11-20)

The Java reference is Ghidra 12.3 built from this repository's source (DESIGN.md, "Decided"
2026-11-20), not the installed 12.2 (`/opt/ghidra`). The tools take the Ghidra install from
`GHIDRA` (default `/opt/ghidra`, unchanged) and Java from `JAVA_HOME` or `PATH`; 12.3 needs
Java 25. `ghidra-diff.sh` also takes the ghidra-rs binary from `GHIDRA_RS` (as `decomp-diff.sh`),
so another branch's build can be checked without writing into its worktree. The reference
(main checkout, `rust/target/`; Ghidra refuses a project path with a `.` component):

```
export GHIDRA=$PWD/rust/target/java123/ghidra_12.3_DEV JAVA_HOME=/usr/lib/jvm/java-25-openjdk
export PATH=$JAVA_HOME/bin:$PATH GHIDRA_REF=$PWD/rust/target/ref123
rust/tools/ghidra-facts.sh; rust/tools/ghidra-protos.sh   # proj/ (a copy of mercs2's project), mercs2.facts, win32.protos
rust/tools/ghidra-diff.sh m8; rust/tools/ghidra-diff.sh m500   # java/m8, java/m500
```

`proj/` is a copy of `mercs2-decomp/build/ghidra`; 12.3 opens it `-readOnly`, upgrades the
language (x86 4.9) in memory and discards it on each run, so the copy stays a 12.2 project and
mercs2's own is never opened. `ref123/java-funcs.csv` is the `func` entries of the facts (Java's
function list, equal to `gap7/java-funcs.csv`). The plain auto-analysis oracle is
`ref123/aq/purges.txt` (`DumpPurges.java` on a fresh import of `orig/Mercenaries2.analysis.exe`,
646 s; project `ref123/aq/proj`). Superseded: `rust/target/aq-java/purges.txt` (12.2) and
`ghidra-ref/` (12.2) as the reference; both are kept for comparison.

12.2 against 12.3, the Java outputs:

- `mercs2.facts`: 671,558 -> 671,557 lines; 242 `label` names lose a library prefix
  (`MSVCR80.DLL_malloc` -> `malloc`), the `type_info` namespace record goes, 3 records name
  it by another id. `win32.protos` is the same file.
- M8: the C of all 7 functions is the same. M500: 10 of 500 differ: 0x53d340, 0x5e1190,
  0x63c040, 0x732ef0, 0x741460, 0x746320 (`register0x00000010` -> `register_ESP`, GP-7356);
  0x47f890, 0x5d58c0 (locals and their types); 0x5d9a20 (an `if` block); 0x4c48d0 fails in
  both (12.2 a timeout, 12.3 "Response buffer size exceeded").
- plain auto-analysis: 30,648 -> 30,631 functions, 25 only in 12.2, 8 only in 12.3; of the
  30,623 in both, 10 differ (purge 3, body size 8). The 12.2 run also had a `TraceCreators.java`
  pre-script; not checked whether it changes anything.

`ghidra-diff.sh`, M500 identical of 499 (loud, silent), M8 of 7, 12.2 -> 12.3:

| build | row | M500 12.2 | M500 12.3 | M8 |
|---|---|---|---|---|
| master b6b02b2ca5 | Java facts | 461 (22, 16) | 469 (22, 8) | 7 / 7 both |
| `gap-javafacts2` 3dfa4de4d6 | Java facts | 478 (11, 10) | 487 (11, 1) | 7 / 7 both |
| `gap-plain2` 20fac3a4db | own facts, Java's list | 394 (30, 75) | 400 (30, 69) | 4 / 7 both |
| `gap-plain2` 20fac3a4db | own facts, plain | 237 (128, 134) | 240 (128, 131) | 2 / 7 both |
| `gap-plain2` 20fac3a4db | own facts, store | 376 (33, 90) | 382 (33, 84) | 4 / 7 both |

(the `gap-plain2` 12.2 numbers are that worktree's `gap-plain2/r2.log`, the same binary.)
Superseded: master's 461 (loud 22, silent 16) as the Java-facts row; with 12.3 the silents
are 0x401890, 0x4173a0, 0x429b80, 0x494400, 0x4b6f5a, 0x4c0070, 0x5c64a0, 0x6b0260. On
`gap-javafacts2` the one silent left is 0x5c64a0: ghidra-rs prints the call `_BinkPause@8`
(the facts' name), Java `_BinkPause_8`; not traced. The nine 12.2 silents of that branch are
gone, 0x5d9a20 with them (so not GP-7115 in the port: 12.3 prints what ghidra-rs prints).
Superseded: the `gap-javafacts2` 3dfa4de4d6 and `gap-plain2` 20fac3a4db rows as the current
numbers; see "Integration `int8`" below for the merged build against 12.3.

### The Microsoft demangler, branch `demangler` (2026-11-20)

`ghidra-rs/src/mdmang.rs` ports `Ghidra/Features/MicrosoftDmang` (`MDMang` and its object
model: the parser over the mangled characters, with `MDContext`'s back references, and the
`insert`/`append` printing of `MDParsableItem.toString()`) and the name parts of
`MicrosoftDemangler` / `MicrosoftDemanglerUtil` (`microsoft_demangle`: the original demangled
string, `DemangledObject`'s name, demangled name, namespace nodes and calling convention, with
`MicrosoftDemanglerOptions`' defaults: error on remaining characters, only known patterns, the
encoded anonymous namespace and no UDT tag for the conversion). Back references share one data
type (`Rc`) and `MDFunctionType.setFromModifier`, which printing calls, sticks (`Cell`), as in
Java. A Java runtime exception (a `null` type name, an empty context stack, a negative string
length) fails the demangle. Data types and C++ objects nested deeper than 200 (`MAX_DEPTH`) fail
the demangle, where Java recurses until its `StackOverflowError` (a depth set by the JVM stack;
`AbstractDemanglerAnalyzer` catches it as a failed demangle). The VS2013/VS2015, parse-info
and genericize variants of `MDMang` are not ported.

**The oracle.** `tools/mdmang-vectors.sh` (awk) extracts the 1,696 calls of `demangleAndTest*`
of `MDMangBaseTest.java` (mangled input, `mdTruth`, architecture, JUnit status) into
`ghidra-rs/tests/data/mdmang-vectors.tsv`; `tests/mdmang.rs` runs them as
`MDBaseTestConfiguration` does (the output against `mdTruth`, and a `.?A` name must give an
`MDDataType`). Of the 1,665 tests JUnit runs: 1,665 pass. The 23 in
`MDMangFailingTestCategory` (Ghidra fails them too) fail here; whether this port's output for
them equals Java's actual output is not checked (Java was not run on them). Of the 8 methods
JUnit does not run (`@Ignore`, no `@Test`) 5 pass, 3 fail (`testCatch_2`: `__catch$_main$0`
does not parse; `testLLVMWeakPrefixDefaultXmmSuffix` and `testMangledTypeWithNamespaceSuffix`:
characters remain, so no `MDDataType` for the latter), as Ghidra's would by the same code paths
(not run in Java either). Superseded: "1,664 tests JUnit runs" and "9 methods JUnit does not
run"; the extraction carried the "not run" status of `setUp()` (no `@Test`) into the next
method, `testTripleQ0`, which JUnit runs.

**Wired.**
- Function ID (`fid.rs`): `NameVersions.generate` (the full demangled form, the name without
  its first template arguments, `constructBaseName`) for every matched name, through
  `DemanglerUtil.demangle(program, name)`'s context (architecture 0, not a function);
  `MatchNameAnalysis`'s demangled sets, the most optimistic count and name (the threshold, and
  "Multiple Matches With Same Base Name" with its single label); the plate comment shows each
  name's demangled form; the `FID_conflict:` base is the demangled `getName()`. A name whose
  conversion is not ported keeps the function's `underived comments`.
- The Demangler analyzer's plate comment (`factsout.rs`, `plate_comment`): the original
  demangled string of a function's export or Function ID name (a function of a 32-bit
  program), appended to Function ID's comment on its own line unless the comment holds it
  (`applyPlateCommentOnly`). So `@__security_check_cookie@4` gets `__fastcall
  __security_check_cookie,4` and `_memset` gets nothing (`memset` is in the comment).
- `scripts::demangle` (the `--functions` CSV's names) is the analyzer's applied name: the
  namespaces' and the object's safe names. Where the small demangler had matched it is the
  same; a `_name` Function ID name is now `name` (Java's `MDObjectC` with `__cdecl`), and a
  name the port cannot demangle stays raw (the small one guessed a partial name). The CSV was
  not compared with Ghidra's again.

**Measured** (`facts-own.sh`, plain discovery, against the 12.3 facts; before is this branch's
build without the wiring, the same analysis):

| kind | before: equal / different / missing / extra | after |
|---|---|---|
| `comments` (Java 1,613) | 1,151 / 0 / 462 / 13 | 1,532 / 65 / 16 / 33 |
| `func` (Java 44,990) | 22,682 / 3,978 / 18,330 / 2,353 | 22,692 / 3,968 / 18,330 / 2,353 |
| `label` (Java 218,095) | 182,832 / 21,697 / 13,566 / 5,028 | 182,842 / 21,687 / 13,566 / 5,028 |
| `underived` | 9,053 extra | 8,609 extra |

Of the 65 different comments 59 equal Java's once Java's second comment (`user2`, the PE
loader's `0x<rva>  <ordinal>  <name>` of an export, not ported) is left out; 5 differ in the
kind of match and 1 in the matches (Function ID's scores). The 33 extra and 16 missing are
functions Function ID matches on one side only. Of the 142 distinct demangled names in
ghidra-rs's comments, 139 appear verbatim in Java's comments; the 3 others are names of matches
Java does not make.

Not ported (loud or listed): applying the demangled object (`DemangledFunction.applyTo`: the
namespaces as Ghidra symbols, the signature, return and parameter types, calling convention;
so a C++ name keeps `underived function` and `ns` stays 0 of 797), `processDataType` (a
variable of a pointer to `std::nullptr_t` fails as "not ported"), the import names
(`Func::named` keeps its rules for them), the RTTI class names (`scripts::vftables` keeps its
own reader), `ensureNameLength`, and Java's `Character.isLetter`/`isDigit` outside ASCII
(Rust's `is_alphabetic`/`is_numeric` are used). A mangled name with a character past U+FFFF
fails as "not ported" (Java reads UTF-16 units, a surrogate pair is two; this port reads `char`s).
A "not ported" failure is loud everywhere: Function ID's and the plate comment's `underived
comments`, an error that stops `--functions` (`scripts::demangle`) and Function ID
(`fid::apply`, the `FID_conflict:` base name); a genuine failure (Java's `null` or
`MDException`) keeps the raw name, as Ghidra does.

### The GNU demangler, branch `gnudemangle` (2026-11-21)

For Hatred's Linux build (DESIGN.md, 2026-11-21). Ghidra's GNU demangler is two parts, both ported:

- `ghidra-rs/src/gnudemangle.rs`: the native program `demangler_gnu_v2_41`
  (`GPL/DemanglerGnu/src/demangler_gnu_v2_41`): libiberty's `cp-demangle.c` (binutils 2.41) as
  its `cxxfilt.c` drives it without options (`GnuDemanglerNativeProcess` passes none): one line
  in, one line out, `cplus_demangle` in the auto style with `DMGL_PARAMS | DMGL_ANSI |
  DMGL_VERBOSE`. The parse keeps the C's fixed component array (`2 * strlen` components, `strlen`
  substitutions, slots reused after a backtrack) and its in-place edits; the printer keeps the
  modifier and template lists as indices. Its limits are the C's: a name longer than 1,024
  characters fails (`2 * strlen > DEMANGLE_RECURSION_LIMIT`), as do the printer's recursion
  counts. Java gives the native process 3 s a name (GnuDemanglerOptions.java:51,
  GnuDemanglerNativeProcess.java:152-162) and then has no demangling; a wall-clock bound would
  make the output depend on the machine, so the stand-in is a fixed one: a text that passes
  1 MiB (`OUT_LIMIT`) fails loudly as "not demangled: limit", and the printer stops there (a
  256-character name of doubling template arguments reaches it in 0.01 s; no name of the
  corpora comes near). `native_demangle`, `cplus_demangle` and `gnu_demangle` run on a thread
  of their own with a 256 MiB stack (`STACK`, reserved, touched only as deep as the recursion
  goes), so a hostile name cannot overflow a caller's stack. Not ported: the Rust demangler that the auto style tries first (`rust-demangle.c`; a
  name it would take, v0 `_R` or legacy `_ZN...17h<hash>E`, fails as "not ported"), and the
  options `cxxfilt` never sets here (`DMGL_JAVA`, `DMGL_TYPES`, the return postfix).
- `ghidra-rs/src/gnuparse.rs`: `GnuDemanglerParser` with the standard replacements
  (`default.gnu.demangler.replacements.txt`, read in place), the `Demangled*` objects it builds
  (kind, names, namespace nodes, signature, return type, parameters, calling convention, const,
  virtual, static, thunk, template) and `GnuDemangler.demangle`'s wrapping (skip rules,
  `_GLOBAL_` / `__Z` / `._Z` / `DW.ref.` prefixes, the failure checks), with the analyzer's
  options. Not ported (each fails loudly, none met in the corpora): non-ASCII text (checked at
  the parse's start, and `substring` gives the same error, never a panic, where a byte index
  falls inside a character), a
  `DemangledVariable` without a name, an object as a namespace inside a `DemangledType`, an
  unclosed `[` (Java loops forever there). A function pointer's `FuncDef<counter>` name is
  `FuncDef` (never printed).
- `gnudemangle::gnu_demangle(name)` is both together (`GnuDemangler.demangle`). Nothing in
  `analyze` calls it yet: the Demangler analyzer picks the GNU demangler for ELF and Mach-O
  programs (`GnuDemangler.canDemangle`), and `analyze` loads only PE32 until the ELF64 loader
  lands; the PE path keeps `mdmang::microsoft_demangle`.
- CLI: `ghidra-rs gnu-demangle <names.txt>` (the native half, one line per name) and `ghidra-rs
  gnu-parse <tsv>` (`mangled<TAB>native text`, the line format of `GnuParseDump.java`).

**The oracle.** The native demangler of the 12.3 reference
(`ghidra_12.3_DEV/GPL/DemanglerGnu/os/linux_x86_64/demangler_gnu_v2_41`) for the text, and
`tools/ghidra/GnuParseDump.java` (Ghidra 12.3's `GnuDemanglerParser` from its jars, with
`GnuDemangler`'s private wrapping copied) for the parse. Names: `tools/gnu-syms.sh <binary>...`
(the unique `_Z` names of `nm -a` and `nm -D`), into `rust/target/gnudem/`, never committed.
Running the Java harness (from `rust/`):

```
export JAVA_HOME=/usr/lib/jvm/java-25-openjdk PATH=$JAVA_HOME/bin:$PATH
G=<the 12.3 install>; D=target/gnudem; CP="$(find $G/Ghidra -name '*.jar' | tr '\n' :)"
javac -nowarn -cp "$CP" -d $D/classes tools/ghidra/GnuParseDump.java
paste $D/hatred.syms $D/hatred.ref > $D/hatred.tsv
java -cp "$CP$D/classes" GnuParseDump < $D/hatred.tsv | grep -v '^INFO ' > $D/hatred.java
target/release/ghidra-rs gnu-parse $D/hatred.tsv | cmp - $D/hatred.java
```

**Measured** (2026-11-21):

| corpus | names | text identical | parse identical | failed |
|---|---|---|---|---|
| Hatred `Hatred-Linux-Shipping` (GCC 4.4.7, UE4) | 217,716 | 217,716 | 217,716 | 0 |
| libstdc++.so.6 and libLLVM.so | 52,312 | 52,312 | 52,312 | 0 |
| libQt6Core, libQt6Widgets, libboost_* (text only) | 70,358 | 70,358 | not run | 0 |
| every prefix (3 characters on) of every 50th name above (text only) | 501,011 | 501,011 | not run | 0 |

"Identical" is the whole output file (`cmp`). Of Hatred's names the native demangler leaves 192
unchanged; the parse gives 217,519 objects, 195 `null`s and 2 Java exceptions
(`IllegalArgumentException`, two `physx::Sq::AABBTree::walk` local names), which the port
gives as the same errors. libstdc++ and libLLVM: 52,297 objects, 8 `null`s, 2
`IllegalArgumentException` and 5 `StringIndexOutOfBoundsException` (`llvm::make_filter_range`
names with `decltype`), the same in the port. The prefix corpus exercises the failure paths:
484,186 of its lines do not demangle, on both sides. GCC 4.4 makes no lambdas (they came with
GCC 4.5); the lambda grammar is checked by the LLVM, Qt and boost names and a unit test.

Checks: `cargo fmt --check`, `cargo clippy --release --all-targets -- -D warnings` clean;
`cargo test --release` 187 passed, 0 failed (unit tests of the grammar: substitutions,
template arguments, ctor/dtor, operators, function pointers, lambdas, local names, the length
limit; and of the parser: templated `operator>>`, `operator<<` with a function-pointer
parameter, conversion operators). `bars.sh` with `CORPORA=m8`: 57 lines, each equal to
`int8-c730b2db7d.summary`'s (the PE path is unchanged).

After the limit and the stack thread (review fixes, 2026-11-21): Hatred 217,716 / 217,716 and
libstdc++ with libLLVM 52,312 / 52,312 names text and parse identical again (the native
demangler and GnuParseDump.java rerun), 0 errors; `cargo test --release` 187 passed, 0 failed;
fmt and clippy clean. `gnu-demangle` takes 14.1 s for Hatred's names on the desktop (one
thread spawned a call; the time before was not measured). Not measured: the stack the deepest
Hatred name uses. Not run: M8 bars (no PE code changed).

### Integration `int8` (2026-11-20)

`int8` merges, from master b6b02b2ca5 and in this order, `ref123` (57d7ac31ac), `gap-javafacts2`
(ba1b0c37cd), `gap-plain2` (f64489e2e1), `demangler` (7e4c3ea5c3), `gdt` (cd4945f9c8) and
`abi-ledger2` (ae9e0d6f84). Conflicts: only in docs (this file and DESIGN.md: two new
sections each side, both kept) and `lib.rs` (`pub mod gdt` and `pub mod mdmang`, both kept).
`cargo fmt --check`, `cargo clippy --release --all-targets -- -D warnings` clean; `cargo test
--release` 177 passed, 0 failed.

Measured on the merged binary against the 12.3 reference (`GHIDRA_RS` the `int8` build,
`GHIDRA_REF` the main checkout's `rust/target/ref123`, desktop, `JOBS` 10, `TIMEOUT` 120),
M500 identical of 499 (loud, silent), M8 of 7:

| row | `int8` M500 | `int8` M8 | the row's branch, M500 | M8 |
|---|---|---|---|---|
| Java facts | 488 (11, 0) | 7 (0, 0) | `gap-javafacts2` ba1b0c37cd, 12.3: 488 (11, 0) | 7 |
| own facts, Java's list | 413 (18, 68) | 4 (1, 2) | `gap-plain2` f64489e2e1, 12.2: 395 (30, 74) | 4 (2, 1) |
| own facts, plain | 246 (120, 133) | 2 (1, 4) | `gap-plain2` f64489e2e1, 12.2: 238 (128, 133) | 2 (2, 3) |
| own facts, store | 391 (21, 87) | 4 (1, 2) | `gap-plain2` f64489e2e1, 12.2: 377 (33, 89) | 4 (2, 1) |

(the `gap-plain2` f64489e2e1 numbers are against 12.2, its `gap-plain2/r3` outputs; that
build was not measured against 12.3.) Every function silent on `int8` and not silent on the
row's branch was loud there, none identical: the decompiler fixes of `gap-javafacts2` (the
deindirect restart for a locked prototype, `StringSequence`, the join logical value in
SubvariableFlow) and the demangler's plate comment take away the error that hid a difference
in the own facts. With Java's facts all of them are identical.

- Java's list: 0x4b8e50, 0x6c3cb0 (were deindirect restart), 0x5d9a20 (was `StringSequence`;
  one of the 10 functions whose Java C changed from 12.2 to 12.3); M8 0x9eec5e.
- plain: 0x4b8e50, 0x4c1230, 0x6c3cb0 (deindirect restart), 0x5a9b80, 0x5d9a20
  (`StringSequence`); M8 0x9eec5e.
- store: 0x4b8e50, 0x5d84e0, 0x5d8680, 0x5d87c0, 0x6c3cb0 (deindirect restart), 0x5cee30
  (subflow join logical value), 0x5d9a20 (`StringSequence`); M8 0x9eec5e.
- 0x9eec5e (`__security_check_cookie`, all three rows) was loud ("the comments are not
  derived"); with the demangler's comment it prints, and differs in the flow: the own facts
  do not make `___report_gsfailure` no-return. Not traced further.

The archive: `gdt-protos` of `windows_vs12_32.gdt` is byte-identical to
`ref123/win32.protos`; `analyze --facts` with `--gdt` that archive and with `--protos` that file
(plain discovery) write byte-identical facts.

M8 bars (`CORPORA=m8 bars.sh`, `JOBS` 10, a new prelude from the `int8` analysis: cksum
3963700924, 29,768 functions): all 57 lines equal those of
`baselines/analysis-queue-83ee6a86e6.summary` (the newest) and of `m3-int7-249c32cf94.summary`.
Not run: M500 bars, the full 133-pair pass, the Mac. Superseded: see "Full pass of `int8`" below.

### Review fixes on `int8` (2026-11-20)

An independent review of the analysis commits of `int8` (814facc891, 22c02f4701, 20fac3a4db,
f64489e2e1); each finding checked against the Java first. The rows rerun with
`rust/target/int8/rows.sh` (12.3 reference; M500 identical of 499 (loud, silent), M8 of 7):

| fix | Java facts | Java's list | plain | store |
|---|---|---|---|---|
| `int8` (before) | 488 (11, 0), M8 7 | 413 (18, 68), M8 4 | 246 (120, 133), M8 2 | 391 (21, 87), M8 4 |
| targetOnlyCallsNoReturn follows computed jumps | unchanged | unchanged | unchanged | unchanged |
| setNoFallThru only on the calls of the addresses found | unchanged | unchanged | unchanged | unchanged |
| removing a function re-flows no other body | unchanged | unchanged | unchanged | unchanged |
| Repair Flow Damage warning | unchanged | unchanged | unchanged | unchanged (run with the next fix) |
| the low findings (below) | unchanged | unchanged | unchanged | unchanged |

- `only_calls_noreturn` (targetOnlyCallsNoReturn) now follows a computed jump's destinations,
  its switch cases and a computed target: Java skips only a destination whose flow type is
  INDIRECTION (`isIndirect`), and a COMPUTED_JUMP one is not. Before, a function with a switch
  whose cases return could be marked non-returning when another path called a non-returning
  function. No row moved; `only_calls_noreturn_follows_switch_cases` covers it.
- `find_noreturn`: Java's setNoFallThru and fixCallingFunctionBody act on the calls of the
  addresses the analyzer found (`noReturnSet`) only. The mark itself is the thunked function's
  (FunctionDB), so every thunk of it reads as non-returning, and the disassembler overrides the
  calls it makes afterwards (`Disassembler.isNoReturnCall`); but a call made before the mark to
  another thunk of the function, or to the thunked function, keeps its fallthrough there
  (CreateFunctionCmd's body walk goes by the override only). Here such calls are kept in
  `Analysis::fallthru` and `call_return` lets them fall through; only the functions holding a
  call of an address found get their bodies fixed up. Superseded: every thunk's callers lost
  the fallthrough and were fixed up. No facts file of the three rows changed; the test
  `noreturn_takes_three_call_sites_of_evidence` covers a call of a thunk made before the mark.
- `Project::remove_function` and `Store::apply` no longer re-flow the bodies that jump or fall
  into a removed function (FunctionManagerDB.removeFunction deletes the function only); mercs2's
  `FoldSlotFragments.java` fixes up the jump sources itself, and that fixup (`Project::reflow`)
  now writes a `reflow` record (3 in the store row) so the replay gives the same bodies. Store
  row facts: 12 bodies changed, 11 of them now the reference's (0x406120, 0x416c5d, 0x4ea606,
  ...), one no longer: 0x5442e9 (`MOV; JMP 0x7f57a5`) loses the `RET` at 0x7f57a5, which plain
  discovery's body lacks too and the store's re-flow had added; 11 `data` lines and 1 `func`
  line moved with them. No function outside M500's counts moved, no silent is new.
- A run-time warning counts where Java's Repair Flow Damage (ClearFlowAndRepairCmd, on by
  default, not ported) would clear flow: a call of a function the no-return analyzer found
  (not an import's flag, not a call that keeps its fallthrough) whose fallthrough holds an
  instruction no jump, call or switch case refers to; findRepairLocations' NOP skip and external
  entries are not counted. mercs2: 308 such calls with plain discovery, 317 with Java's list.
  Output unchanged (plain and Java-list facts byte-identical). Superseded (2026-11-21): the
  command is ported and this warning is gone; see "Repair Flow Damage, branch `repairflow`".
- checkNonReturningIndicators of a call under a CALL_RETURN override is false (Java's
  `getFallThrough` is null), where the walk went on from the call's end. The Reference
  analyzer's thunk step for a jump through a slot (`slot_jumps`) also needs `memRefs.length <= 2`;
  a jump past its function's entry, where Java asks CreateThunkFunctionCmd.isThunk of the holding
  function, is not ported and counted in a warning (mercs2: 1 jump with plain discovery, 10 with
  Java's list). The INDIRECTION skip of `reference_data` needs no more guards: its comment says why
  Java's (subroutinesEnabled, isUndefinedStuff, doneSubTest) hold there. The empty stray file
  `src/store.rs.new` (dbd27b429e) is gone. All three rows' facts byte-identical.
- 0x9eec5e (`__security_check_cookie`, M8 silent) is not explained by these fixes: Java marks
  `___report_gsfailure` (0x9ef1dc) non-returning from the archive's `__report_gsfailure`
  prototype (ApplyFunctionDataTypesCmd.lookupSymbol also tries `_` + the name), and here a
  prototype of the archive goes only to an import (`factsout.rs`); not fixed.

#### Full pass of `int8` (2026-11-21)

The pass ran on c730b2db7d with `TIMEOUT` 120. The summary is
`rust/target/baselines/int8-c730b2db7d.summary` (133 lines), compared with
`analysis-queue-83ee6a86e6.summary`. The inputs on both machines were the 12.3 `x86.sla`
(cksum 114282992, 439,217 bytes, the `java123` build's; the Mac's earlier 444,359-byte file was
replaced) and the `int8` prelude (cksum 3963700924, 851,045 bytes, 29,768 functions).

- The queue started on both machines: the desktop at `JOBS` 6 under `taskset -c 0-7`, the Mac at 16. It was
  stopped after 8 M500 pairs (5 desktop, 3 Mac) because the desktop ran low on memory.
- The other 125 pairs ran on the Mac only, as two direct `bars.sh` runs (`JOBS` 16, about 9 h).
- Match check: `s4-m500` was rerun on the Mac. Its reference-finished, identical, loud, silent and
  timeout counts and its `.miss` (0x4c48d0 a reference timeout) equal the desktop's. "All outputs
  identical" is 500 on the Mac against 499 on the desktop, a difference only on 0x4c48d0, which
  the reference does not finish.

Silent 0 in every pair. Lines that moved:

- `r5s-m500`: reference finished 499 -> 498, identical 499 -> 498 (loud 0). The reference times
  out on 0x6b21e0. It does not finish there alone on the Mac at `TIMEOUT` 400 (also with the
  `analysis-queue` prelude, and with that prelude and the old `x86.sla`) or at 1500. It is the
  known reference timeout of the `m3-int6` pass (0x6b21e0 of `r5s` not compared there either),
  and the other eight R5 checks count it as not finished, as in the baseline.
- `pcd-m500`: identical 493 -> 499 (loud 6 -> 0). `pmd-m500`: identical 496 -> 499 (loud 3 -> 0).
- "all outputs identical" 499 -> 500 in `s6void`, `s6callee`, `r1`, `r4`, `s8`, `swsn-r` and
  `swsn-t` (M500): all on 0x4c48d0, which the reference does not finish. `stack-m500` outputs with stack SSA 312 -> 313.

Every other line equals the baseline. Superseded: "Not run: M500 bars, the full 133-pair pass,
the Mac" under "Integration `int8`" above.

### Repair Flow Damage, branch `repairflow` (2026-11-21)

`ghidra-rs/src/analysis/repair.rs` ports FindNoReturnFunctionsAnalyzer's "Repair Flow Damage"
step (`repairDamagedLocations`, on by default): for each address the analyzer found,
`findRepairLocations` (the fallthroughs of its calls that hold an instruction no flow refers to,
`skipNOPS` and the external entries included), then ClearFlowAndRepairCmd with `clearData`,
without `clearLabels`, the found addresses protected: `findInstructionFlow` over
SimpleBlockModel's blocks (a block starts at a symbol or reference and after any flow other than
a fallthrough; blocks something outside flows into are pruned), `addDereferencedInstructionStarts`,
ClearCmd (instructions with their references and flow overrides, functions whose entry is
cleared, with their thunks), `repairFallThroughsInto` and `repairFlowsInto` (disassembly at the
fallthroughs into the cleared bytes and at cleared addresses a flow still refers to; the sources
of data references into them go to codeDefined, so the no-return analyzer sees them again),
and `repairFunctions` (MultEntSubModel's subroutines over the code disassembled again: functions
not at an entry are removed, the others get their body less the cleared bytes plus the flow from
the entry, the other entries become functions). After a repair the run loop makes the functions
its disassembly found and runs the no-return analyzer on the new instructions. The offcut checks
of the command never fire here (the listing holds no overlapping instructions).

Counted in warnings, not ported: clearing data (pointer data only cleared code refers to, where
Java clears it: here the pointer data of `table_slots` and the switch tables; 0 on mercs2. Superseded:
"mercs2 plain 273 addresses, Java's list 287" counted every referenced address without an
instruction, where Java goes on only at defined pointer or Undefined data); a body that keeps the cleared bytes in Java (here a body holds instructions
only; 0 on mercs2); a repaired body that overlaps another function (0). Not modelled: names of
USER_DEFINED source (the flow stops at a function of IMPORTED or higher name: here the exports
and the entry only); the vertex order of the prune (address order where Java walks a Hashtable;
a prune takes every block it reaches, so a later check it made true is covered). The warning of
9057ffa2d3 (308 calls plain, 317 Java's list) is gone. mercs2 plain: 10 runs, 6,858 instructions
cleared, 6 functions removed, 16 instructions disassembled again; Java's list: 7,349, 14, 11.

Rows against the 12.3 reference (`rust/target/rf/rows.sh`, the `int8` rows.sh with `JOBS` 4,
desktop; M500 identical of 499 (loud, silent), M8 of 7):

| row | before (master 04739accdd) | after |
|---|---|---|
| Java facts | 488 (11, 0), M8 7 | 488 (11, 0), M8 7 |
| own facts, Java's list | 413 (18, 68), M8 4 | 419 (18, 62), M8 5 |
| own facts, plain | 246 (120, 133), M8 2 | 246 (120, 133), M8 2 |
| own facts, store | 391 (21, 87), M8 4 | 397 (21, 81), M8 5 |

No function is newly silent. Now identical in Java's list and store: 0x4078a0, 0x415ae0,
0x41d560, 0x4312e0, 0x434f00, 0x4f1770; M8 0x401000. The 7 SecuROM counters of `.securom`
(0x256facf and others) are `data` as in Java's facts; of the 10 plain `undef` ranges that
moved, 9 now equal Java's facts (0x407769 now ends at 0x40776f: a new label 0x407770 from
code disassembled again; not traced). Plain against Java 12.3's auto-analysis
(`ref123/aq/purges.txt`, the facts' `body` records): functions in both 29,433 -> 29,433, Java
only 1,198 -> 1,198, here only 286 -> 288 (0x250d37f, 0x25600d0, 0x256cae0 new in `.securom`,
0x256f77d merged into 0x256f770), body size differs 671 -> 671.
Superseded: "Repair Flow Damage ... not ported" in the ported-analyzers table, under "No-return
functions from call-site evidence", in "Causes left among the `data` cases" and the warning
bullet of "Review fixes on `int8`".

Review fixes on `repairflow` (an independent review; each finding checked against the Java first):

- repairFunctions makes the entries left in a subroutine in the order Java's
  `HashSet<Address>` walks them (`java_hash_set_order`: GenericAddress.hashCode over `ram`,
  HashMap's spread, table size and resize), where it went in address order; CreateFunctionCmd
  stops at entries that exist, so the order can change bodies. The test checks orders printed by
  OpenJDK 25's HashSet. A treeified bucket (9 or more entries in one bucket of a 64-entry table)
  is counted in a warning, not reproduced.
- Data references from code pointers in data are not modelled here outside Create Address Tables'
  runs (`table_slots`). Where Java may have one (an aligned code pointer in a data section) and it
  would change a prune, a dereferenced start or a block start, the address is counted in a
  warning (0 on mercs2, all three rows).
- The data count follows addDereferencedInstructionStarts: only pointer data (above).
- An instruction's data references are READ or WRITE where a memory operand makes them
  (`Ins::rw`), DATA for immediates; repairFlowsInto skips a DATA reference at `ignoreStart` only.
- skipNOPS returns an error where an instruction of the listing does not decode or has no
  p-code, where it counted as a NOP.
- `Repair` groups what the command works with; findInstructionFlow and repairFlowsInto are split
  into smaller functions; tests for the prune, the protected split and repairFunctions.

Rows unchanged (Java facts 488 (11, 0) M8 7; Java's list 419 (18, 62) M8 5; plain 246 (120,
133) M8 2; store 397 (21, 81) M8 5), no function newly silent in any row; the Repair Flow Damage
run counts unchanged (plain 10 runs, 6,858 cleared, 6 removed, 16 disassembled again; Java's list
7,349, 14, 11).

## ELF64 analysis: Hatred's Linux build (branch `elf64`, 2026-11-21)

`analyze` takes an ELF x86-64 file (DESIGN.md, 2026-11-21) with language x86:LE:64:default
and its gcc compiler spec: `x86-64.sla` (the `--sla` or `GHIDRA_RS_SLA` given, else the one
next to `x86.sla`) with `x86-64.pspec`, and `x86-64-gcc.cspec` read as data at build time.
`--functions`, `--gaps`, `--purges`, `--decomp-prelude` and `--facts` work; `--abi-callers`
and `--store` fail loudly on ELF. Superseded (2026-11-22, branch `m3-x64`): "`--decomp-prelude`
and `--facts` fail on ELF; the decompiler reads x86:LE:32:default:windows only"; see "The
decompiler on x86-64" and "Facts on ELF x86-64" below. `--purges <txt>` writes what `tools/ghidra/DumpPurges.java`
writes (entry, purge, thunked function, body min, max, address count, no-return), on PE and ELF.

The loader, `Image::from_elf` (ElfProgramBuilder.load, the parts analysis reads):

- a memory block per allocated section, execute and write from the section flags, `.bss`
  zero-filled and unmapped for the decompiler, `.tbss` left out (it overlaps the next section),
  the `.got` blocks read-only (processGOTSections); image base 0x100000 for a shared object or
  PIE whose lowest PT_LOAD of the first 20 program headers is at 0 (ElfHeader.findImageBase,
  ElfLoaderOptionsFactory.IMAGE64_BASE_DEFAULT); every section must end below 4 GiB
  (`Analysis` keeps `u32` addresses), checked before a `.bss` is allocated, else the load
  fails; a relocatable object (ET_REL, `.o`) fails as not ported (Java packs its sections,
  ElfProgramBuilder.java:3490-3500);
- the dynamic relocations of X86_64_ElfRelocationHandler: RELATIVE, RELATIVE64, IRELATIVE and
  the packed RELR form (image base adjustment plus addend; a prelinked RELATIVE adds it to the
  word in place, ElfHeader.isPreLinked), R_X86_64_64, GLOB_DAT and JUMP_SLOT to a defined symbol
  (its address plus the addend); GLOB_DAT and JUMP_SLOT to an undefined symbol make the GOT slot
  an import of `<EXTERNAL>`, as an IAT slot of a PE. They, and R_X86_64_64 to an undefined
  symbol, write the symbol's EXTERNAL entry plus the addend, as Java does
  (X86_64_ElfRelocationHandler.java:119-121, 168-171). The entry is in no block of this image
  (see "The GOT import slots in the image"). An undefined symbol without an entry leaves the
  word as the file has it (AbstractElfRelocationHandler.java:160-183, where Java marks it
  unhandled). Superseded (2026-11-22, branch `fix-gotslots`): "write 0 there where Java writes
  the address of its EXTERNAL block". The rest, and those at no 8 bytes of a section, are
  counted in a warning (Hatred: 10, the COPY relocations, which Java does not apply either);
- one-byte functions at every STT_FUNC symbol of `.symtab` and `.dynsym` (evaluateElfSymbol;
  `.cold` parts, names matching ElfSymbol's `.+\.cold((\.[0-9]+)?)`, are none), at the entry point and at DT_INIT, DT_FINI and the init, preinit and
  fini array entries (processEntryPoints); global and weak ones are the exports;
- `.plt` past its first 16 bytes disassembled at load, following flows (processPLTSection).

Not made: Ghidra's artificial EXTERNAL block and its functions (a PLT entry's thunk is written
`EXTERNAL` in `--purges`), the GOT/PLT pointer markup, the ELF Scalar Operand References.

Analysis on x86-64 (`Analysis::run` with `Image::elf64`):

- no-return names from `Features/Base/data/ElfFunctionsThatDoNotReturn` (NoReturnFunctionAnalyzer:
  leading `_` stripped, a `*` suffix a prefix), on import slots and symbol functions; a function
  of one `JMP [slot]` through such a slot, or of `ENDBR64; BND JMP [slot]` (`.plt.sec` of
  `-fcf-protection`: getThunkedAddr steps over an entry instruction without p-code,
  CreateThunkFunctionCmd.java:568-572; the no-return flag and the `EXTERNAL` column of
  `--purges` only, `resolve_thunk` still does not), is no-return (a thunk takes its external's flag);
  a `CALL [GOT slot]` of a non-returning import does not end the flow (measured on libtcl,
  where it brought 743 body sizes to Java's). Traced on libtcl with Java 12.3 (a probe script
  over the analyzed program): Java ends the flow at 4 such calls (`abort`, `exit`, `_exit`,
  `pthread_exit`, one call each, override CALL_RETURN) and goes on at all 904 calls of
  `__stack_chk_fail`, though that external's flag is set too. Every one of the 908 calls has
  operand reference type READ, not INDIRECTION, so Disassembler.checkForIndirectCallFlow
  (Disassembler.java:1321-1337, `isIndirect()`) never fires on them; what overrides the 4 was not
  found. The rule stays (DESIGN.md, 2026-11-21): right for 904 of the 908 calls;
- the local fold works on 8-byte registers; a call kills the `<killedbycall>` registers of
  x86-64-gcc.cspec's default prototype (RAX, RDX) and moves RSP by its `stackshift` (8), as
  SymbolicPropogator.getDefaultStackDepthChange does for a model with a known extrapop;
  constants are 64-bit; offsets from a register's start value stay 32-bit (modulo 2^32); a
  value past 32 bits, a sign-extended disp32 like 0xffffffff80401000 among them, is in no
  block, so it makes no reference, slot, code constant or table (Java makes none outside
  memory); a direct flow past 32 bits makes no target and is counted in a warning (8-byte
  right shifts are not folded). Superseded: "values stay 32-bit (an 8-byte constant is cut to
  its low half)", the code before this fix;
- switch tables `JMP qword ptr [reg*8 + table]` (with REX prefixes; a negative disp32 is no
  table); Create Address Tables, the pointer check of the Reference analyzer
  (OperandReferenceAnalyzer.checkForPointer), the jumps and calls through a slot read
  8-byte pointers (getDefaultPointerSize; AddressTable.java:1074-1100), the tables start
  4-aligned and checkTable tests `top + 4 * i` as Java does (AddressTableAnalyzer.java:401-407).
  Superseded: before this fix only the switch tables and the scan for runs of code pointers
  read 8 bytes, the rest 4;
- Function Start Search with `x86-64gcc_patterns.xml`: see "Function Start Search on x86-64"
  below. Superseded (2026-11-23): "not run: Function Start Search (`x86-64gcc_patterns.xml` is
  not ported)";
- not run: the RTTI analyzer (MSVC's: RttiAnalyzer.canAnalyze takes Visual Studio and clang PE
  files only; Java 12.3 has no analyzer for GCC's RTTI or vtables, its
  RecoverClassesFromRTTIScript is a script, not auto-analysis), X86 Function Callee Purge (Java's `canAnalyze` refuses 64-bit), Function ID (the
  databases are x86:LE:32's). Not ported: purges from data-type archives, DWARF, the
  relocation guide of Create Address Tables (AddressTable.getEntry takes only relocated words
  where the program has relocations), the Disassembler's thunk-aware no-return test
  (isNoReturnCall reads Function.hasNoReturn, which follows a thunk, FunctionDB.java:1217-1222;
  `descend` reads the no-return set alone, before bodies and thunks exist). Superseded
  (2026-11-23, branch `fix-hatred-analysis`): "Not ported: PIC switch tables, getThunkedAddr
  past a no-p-code entry instruction in `resolve_thunk`"; see "Thunks and PIC switches on
  x86-64" below.

Check: `tools/elf64-ref.sh [extra binaries]` builds `tools/corpus/elf64/*.c` with gcc -O2
(non-PIE, PIE, and PIE with `-fcf-protection=full` as `-cet`, no `-g`: Java takes no-return flags from DWARF, which ghidra-rs does not read
yet), runs Java 12.3's plain auto-analysis with `DumpPurges.java` once (kept in
`rust/target/elf64/`) and `analyze --purges`, and compares the lines (Java's EXTERNAL-block
functions left out). Against Java 12.3 (gcc 15, the desktop):

| binary | Java | ghidra-rs | entries in both | identical lines | identical but the purge |
|---|---|---|---|---|---|
| t1 | 22 | 22 | 22 | 11 | 18 |
| t1-pie | 20 | 19 | 19 | 8 | 14 |
| t1-cet | 19 | 18 | 18 | 7 | 13 |
| t2 | 24 | 24 | 24 | 15 | 22 |
| t2-pie | 22 | 22 | 22 | 13 | 20 |
| t2-cet | 21 | 21 | 21 | 12 | 19 |
| `/usr/lib/libtcl8.6.so` | 2,535 | 2,533 | 2,533 | 2,438 | 2,444 |

The causes: purges (Java's 0 on PLT thunks and `_init`, from data-type archives); PIC switch
tables (t1-pie's `sw`, so its tail call makes no `puts` thunk; most of libtcl's 57 body
counts); `NOP; JMP` and `ENDBR64; JMP [slot]` thunks (`frame_dummy` in each; 34 thunk
columns of libtcl); Java's no-return on `_start` (its `hlt` after `__libc_start_main`) and
on t1-pie's `die`, not traced; libtcl's 2 functions Java has more (0x1bf2cd, 0x1c4cca, odd
addresses not traced).

After the review fixes (2026-11-21: pointer size, values past 32 bits, ET_REL, ENDBR64 PLT
thunks, EXTERNAL slots, IRELATIVE and RELATIVE64, section bounds): t1, t1-pie, t2 and t2-pie
unchanged; libtcl 2,442 -> 2,444 identical but the purge (2,438 identical lines, unchanged),
17 relocations counted not applied (the count before was not recorded). In the new `-cet`
binaries the `ENDBR64; BND JMP [slot]` thunks of `abort` and `exit` are `EXTERNAL` and
no-return as in Java; t1-cet's other differences are the causes above (`puts` thunk from the
PIC switch's tail call, an `ENDBR64; JMP` thunk `resolve_thunk` does not make) and two body
sizes and one no-return flag, not traced.

Hatred (`Hatred-Linux-Shipping`, 508 MB, ELF x86-64 EXEC, 45 MB `.text`, the desktop, one
thread): 10,488,140 instructions, 180,033 functions (407 imports), analysis 54.5 s, 87 s with
`--functions`, `--gaps` and `--purges`; every one of its 179,630 defined STT_FUNC symbols is a
function, 403 functions are at no symbol; `.text` coverage 43,002,764 / 45,177,887 bytes.
Warnings: 10 relocations not applied, 22 slot jumps past an entry, 566 Repair Flow Damage
calls. Java was not run on it (14 GB of RAM for a 508 MB binary; not tried). Superseded:
"not rerun after the review fixes". Rerun on master 7ab9dc2b7c (int9, with Repair Flow Damage;
2026-11-22, desktop, one thread): 10,484,883 instructions, 180,026 functions (407 imports),
analysis 96.5 s; 179,636 functions exported; `.text` coverage 43,001,858 / 45,177,887 bytes.
Warnings: 10 relocations not applied, 22 slot jumps past an entry; Repair Flow Damage now runs:
8 runs, 3,257 instructions cleared, 7 functions removed, 5 data-pointer cases not modelled. The
slower analysis (54.5 s before) was not traced (Repair Flow Damage, or load on the desktop).

#### Thunks and PIC switches on x86-64 (branch `fix-hatred-analysis`, 2026-11-23)

- Thunks behind an entry instruction without p-code. `resolve_thunk` and `fixup_body` test
  the instruction getThunkedAddr tests: the entry's, or the next one in address order where the
  entry's has no p-code (`Analysis::thunk_insn`, CreateThunkFunctionCmd.java:565-572). So
  `NOP; JMP x` and `ENDBR64; JMP x` are thunks of x (`frame_dummy`). The facts name a thunk by
  the same body (`Analysis::thunk_jump`: one jump, or one after such an entry instruction).
  On every processor: mercs2 has no such function. Not ported, as before: getThunkedAddr's
  walk over up to three instructions with its register tracking.
- PIC switch tables (`Analysis::pic_switch_table`): `LEA base,[RIP + table]`, `MOVSXD
  r,dword ptr [base + index*4]`, `ADD r,base` or `LEA r,[r + base]`, `JMP r` (a NOTRACK prefix
  allowed). The table holds 4-byte offsets from its own start. The count comes from the `CMP
  index,imm` before it, the index followed back through register moves and `MOVZX r32,r8`
  (then a byte compare), over the straight-line history and the history of the first jump
  that reached the run. Every case must lie in the jump's section. This is a byte pattern, as
  `switch_table` is, where Java runs the decompiler's jump-table recovery
  (DecompilerSwitchAnalyzer, DecompilerSwitchAnalysisCmd). A jump of this form whose table,
  bound or cases the pattern does not find stays unresolved and is counted in a warning (`not
  ported: the decompiler's jump-table recovery`). An instruction with a p-code branch inside
  (`MINSS`, `CMOVcc`; `Ins::inner`) between the compare and the jump makes it unresolved too:
  the switch block then has two in-edges, where the decompiler's guard search stops
  (JumpBasic::analyzeGuards). Hatred's 0x3835ec1 is such a jump, and Java does not recover it.
  Not checked by the pattern: another jump into the instructions between the compare and the
  switch.

Measured before the merge of master (Superseded for the current counts by "Measured after master 7469505ff1 was merged in" below) against Java 12.3's facts (the body records; functions outside Java's EXTERNAL
block), Hatred, the desktop:

| | master 3a5ba15656 | with both |
|---|---|---|
| functions Java / ghidra-rs | 180,038 / 180,026 | 180,038 / 180,026 |
| in both / Java only / ghidra-rs only | 180,024 / 14 / 2 | 180,024 / 14 / 2 |
| bodies different (Java larger / ghidra-rs larger) | 237 (224 / 13) | 105 (92 / 13) |
| PIC switch jumps counted unresolved | not counted | 67 |

The 13 bodies ghidra-rs has larger are the same before and after. Not traced: the 92 Java has
larger (67 are at most the unresolved jumps). The function set, traced:
- Java only, 7 in `.plt` (0x15bdd00 `__cxa_pure_virtual`, ...): PLT entries no instruction
  refers to (likely made by Java's PLT markup, not ported; not traced);
- Java only, 7 in `.text` at STT_FUNC symbols (0x3582df0 `SDL_TicksQuit`, ...): Repair Flow
  Damage removes 7 functions here (the same count; not checked one by one);
- ghidra-rs only, 0x1b25ce4 and 0x1b2dc44: the targets of an entry `JMP` into the function's
  own body (0x1b25cd0, 0x1b2dc30), thunks here. Likely cause, read from the source and not
  traced in Java: the function exists with its DWARF body before analysis, so the target
  lies in a function and CreateThunkFunctionCmd refuses
  (getFunctionContaining, CreateThunkFunctionCmd.java:352-356); the analysis does not read
  DWARF bodies.

Superseded (see "Measured after master 7469505ff1 was merged in" below): the 14 small binaries (`--facts` against Java's, equal records): body 1,013 -> 1,029 / 1,112,
label 4,645 -> 4,993 / 7,315, undef 1,034 -> 1,090 / 1,407, data 724 -> 740, override 770 ->
782, func 209 -> 210; 2 PIC switch jumps counted unresolved (cpp binaries).

#### Function Start Search on x86-64 (branch `fix-hatred-analysis`, 2026-11-23)

`Analysis::start_search_gcc64` runs where the PE's `start_search` runs (Function Start Search
and its After Data pass). It reads `x86-64gcc_patterns.xml` itself (`start_patterns`, built
in with `include_str!`): `ditted` is DittedBitSequence.initFromDittedStringData, and
`StartSet::hit` the pair rule of PatternPairSet.createFinalPatterns (`totalbits="40"
postbits="24"`). At undefined bytes, as the PE's:
- a pair of the `<funcstart/>` set makes a function and disassembles it;
- the `ENDBR64` pair of `<codeboundary/>` is disassembled, no function made.

Not ported, counted in a warning: the 20 `<pattern>` elements with `<funcstart
after="defined" .../>` (checkAfterName's reference tests, `validcode`'s
PseudoDisassembler.checkValidSubroutine with an instruction limit). `run` counts their matches
at undefined bytes right after an instruction or data, or at a block's start. Not ported and
not counted: a match at an instruction that lies in no function (checkAlreadyInFunctionAbove),
as in the PE's port. A pattern file with another action or rule fails the analysis.

Measured before the merge of master (Superseded by "Measured after master 7469505ff1 was merged in" below): Hatred one more function, 0x35840d0 `SDL_AssertionsQuit`, which Java has too (in
both 180,025, Java only 13, ghidra-rs only 2; bodies different 105, unchanged); no
`after="defined"` match counted. The 14 small binaries: every record count unchanged, none
counted.

#### Measured after master 7469505ff1 was merged in (branch `fix-hatred-analysis`, 2026-11-23)

Merge a95796c6ab against master 7469505ff1 on the same inputs. This replaces the counts of the
two sections above.

Hatred, `--facts` against Java 12.3's facts (`tools/facts-diff.sh`, MacBook, the Java run of
`hatred-java2`; equal / different / missing / extra, of Java's 180,433 functions):

| record | master | branch |
|---|---|---|
| body | 180,181 / 237 / 15 / 2 | 180,314 / 105 / 14 / 2 |
| func | 9,582 / 170,836 / 15 / 2 | 9,595 / 170,824 / 14 / 2 |
| tracked | 180,418 / 0 / 15 / 2 | 180,419 / 0 / 14 / 2 |
| label | 714,835 / 144,566 / 24,010 / 33 | 717,043 / 144,507 / 21,861 / 32 |
| undef | 227,281 / 878 / 7,246 / 6,655 | 227,813 / 831 / 6,761 / 6,492 |
| data | 496,778 / 80,387 / 1,499,157 / 55,279 | 496,844 / 80,333 / 1,499,145 / 55,259 |
| string | 196,587 / 369 / 29,362 / 400 | 196,648 / 310 / 29,360 / 400 |
| override | 31,356 / 0 / 2,507 / 3,972 | 31,399 / 0 / 2,464 / 3,972 |
| ns | 22,813 / 0 / 22,139 / 48 | the same |
| type | 1,282 / 3 / 37,108 / 4 | the same |
| `underived` (function / label / comments) | 170,854 / 8,682 / 170,920 | 170,856 / 10,189 / 170,921 |
| silent func | 131 | 119 |

- No func record is newly silent. The 119 are among master's 131
  (`rust/target/baselines/archives-131.txt`); the other 12 are equal now (0x33c81c0,
  0x33fffa0, 0x340fcb0, 0x3410400, 0x3420a90, 0x342c930, 0x342d070, 0x3444680, 0x3466360,
  0x34c6fc0, 0x34da270, 0x34deae0; why each became equal was not traced).
- No body is newly different: the 105 are among master's 237. The function only Java had
  and both have now is 0x35840d0 (Function Start Search); the 2 only ghidra-rs has are
  0x1b25ce4 and 0x1b2dc44, as above.
- 67 PIC switch jumps are counted unresolved (the warning), first at 0x33c2ca5. How many
  PIC switches the pattern resolved, and how many Java recovered, was not counted: the facts
  have no jump-table record; the measure is the body row.
- 1,507 more labels are `underived` (loud; which rule marks them was not traced). `block`,
  `wref`, `comments` and `coretypes` rows are unchanged. `--facts` took 372 s, maximum
  RSS 4.98 GB (master: 362 s, 5.61 GB).

The 14 small binaries (desktop, equal / Java's records, master -> branch): body 1,013 -> 1,029
/ 1,112, func 339 -> 352 / 1,112, tracked 1,057 -> 1,059 / 1,112, label 4,648 -> 4,996 /
7,315, undef 1,034 -> 1,090 / 1,407, data 724 -> 740 / 12,072, override 770 -> 782 / 1,259; ns
190 / 295 and type 67 / 1,107 the same; `underived` records 1,313 -> 1,401. Silent func 15 ->
1: the 14 `.plt.sec` thunks of the two `-cet` builds (`ENDBR64; JMP [slot]`) are no longer
silent; the one left is master's. 2 PIC switch jumps counted unresolved (cpp3-gcc); no
`after="defined"` match counted.

Checks on the merge (desktop): `cargo fmt --check` and `cargo clippy --release --all-targets
-- -D warnings` clean; `cargo test --release` 210 passed (master 208; the two new ones are
this branch's pattern-file and PIC-switch tests); `CORPORA=m8 tools/bars.sh` 57 of 57 lines
equal to `pe-overrides-77ab900fd4.summary`, reference rebuilt; `simple`: pc-r, pc-t, pcc-r,
pcc-t 194 / 194, pcd 198 / 200 (loud 2), pmd 199 / 200 (loud 1), silent 0, as master;
`tools/elf64-decomp.sh`: 817 functions (master 815; the two new ones, 0x1010a0 of t1-cet and
0x101040 of t1-pie, are identical), the reference ran 815, identical 809 (master 807), loud 6
(5 `downChain`, 1 jump table through a CALLOTHER, as master), silent 0. Not run: M500, the
Hatred camera corpus, mercs2's facts, anything on Windows binaries beyond M8 and `simple`.

#### GCC exception tables: not ported (read 2026-11-23, branch `fix-hatred-analysis`)

GccExceptionAnalyzer (`.eh_frame_hdr`, `.eh_frame`, `.gcc_except_table`) is not ported; the
facts keep every DWARF plate comment `underived` on an image with a non-empty
`.gcc_except_table` (above). What a port has to do, read from Java 12.3's source
(`Ghidra/Features/Base/.../exceptionhandlers/gcc`, 6,751 lines), none of it measured here:
- it runs early (FORMAT_ANALYSIS.after().after()) and makes no function;
- per FDE: a DATA reference to PcBegin, and PcBegin disassembled where no function starts
  there (FrameDescriptionEntry.java:252-286, 474-477); a pointer of 8 bytes is read for
  PcRange (createPcRange, FrameDescriptionEntry.java:288-346);
- per call-site record with a landing pad: the call site's start and the landing pad are
  disassembled where they are not (GccExceptionAnalyzer.java:210-239, 272-290), DATA
  references to both (LSDACallSiteRecord.java:104-112), a PRE comment `try { // try from A to
  B has its CatchHandler @ L` at the start, a POST comment `} // end try from A to B` at the
  code unit holding the last address, a PRE comment `catch(type#N @ T, ...) { ... } // from
  try @ A with catch @ L` at the landing pad (GccExceptionAnalyzer.java:292-345);
- labels (`cie_<address>`, `lsda_exception_table_<address>`, the FDE's), plate and EOL comments and data in
  the three sections (AbstractFrameSection.java:141-181, LSDAHeader.java:228-246, and the
  `create*` methods of Cie, FrameDescriptionEntry and the LSDA classes).
Java's Hatred facts have a `try {` comment in 1,275 `comments` records (3,831 comments).
The `underived` mark can be lifted from a function once the call-site records are read: it
is needed only where a call-site start, the unit of its last address or a landing pad lies in
the function's body. A function without a DWARF plate that has such a comment has no
`comments` record and no `underived` mark today: silent.
Superseded (2026-11-24, branch `hatred-facts`): the call-site records and the three comments are
ported (`gccexcept.rs`), and a plate comment is no longer `underived` for the exception tables;
the labels, data, references and disassembly listed above are still not ported ("GCC exception
tables ported" below).

The PE path: `cargo test --release` 178 passed, 0 failed; `cargo fmt --check` and `cargo clippy
--release --all-targets -- -D warnings` clean; M8 bars (`CORPORA=m8 bars.sh`, the 12.3 `x86.sla`,
a new prelude: cksum 3963700924, 29,768 functions, as `int8`'s) all 57 lines equal those of
`baselines/int8-c730b2db7d.summary`. Not run: M500 bars, the Mac. After the review fixes: `cargo test
--release` 178 passed, 0 failed; fmt and clippy clean; M8 bars 57 / 57 lines equal to the baseline.

### The DWARF importer, branch `dwarf` (2026-11-21)

`ghidra-rs/src/dwarf/` ports the part of Ghidra 12.3's DWARF analyzer
(`ghidra.app.util.bin.format.dwarf`, run as `DWARFAnalyzer.added` does with the default
`DWARFImportOptions`) that makes data types and function signatures. `ghidra-rs dwarf <elf> <out>`
writes them in the form of `tools/ghidra/DumpDwarf.java`: one line per data type under `/DWARF`
(structures and unions with their components, typedefs, enums, function definitions; pointers
and arrays appear by name), one per function whose signature the import set, sorted.
- `dwarf/read.rs`: unit headers (versions 2-5 read; DWARF 5's indexed forms `strx`, `addrx`,
  `rnglistx` and its line and range tables are not), abbreviations, the DIE index of
  `DIEContainer` (offsets, parents, siblings, the targets of `DW_AT_abstract_origin` /
  `DW_AT_specification`), attribute values by form class (`DWARFNumericAttribute` with its
  signedness guess for `data<n>`), the file table of a v2-v4 line header, `.debug_ranges`, and
  the constant operations of `DWARFExpressionEvaluator` that member offsets and bounds use.
  Raw parsing is its own code, not `gimli` (as asked); attributes are decoded on demand from
  the section bytes.
- `dwarf/expr.rs` (2026-11-24, branch `dwarf-params`): location expressions, read, printed and
  evaluated as the importer does for parameters and local variables; `.debug_loc` lists are in
  `dwarf/read.rs`. See "DWARF parameter storage and local variables".
- `dwarf/dtm.rs`: the data-type model the importer drives: built-ins with x86-64 GCC's data
  organization (sizes, the size-alignment map), pointers, arrays, typedefs, non-packed
  structures (`StructureDataType.replace`, `insertAtOffset`, `insertBitFieldAt` with its
  conflict shift), unions, packing (`AlignedComponentPacker` with GCC's bitfield rules),
  enums, function definitions; `DataTypeManagerDB.resolve` for types without a source archive
  (same-location equivalence, `.conflict` names, replace in place) and
  `DWARFDataTypeConflictHandler`.
- `dwarf/mod.rs`: `DIEAggregate`, `DWARFProgram.getName` (namespaces from mangled and linkage
  names, the anonymous names: struct layout fingerprints, `_for_<member>`, `.dwarf_<offset>`),
  `DWARFDataTypeManager` (base types, `getTypedefReplacement`), `DWARFDataTypeImporter` (every
  tag it handles), `DataTypeGraphComparator`'s offset caching, `DWARFFunctionImporter` /
  `DWARFFunction` (bodies from `low_pc`/`high_pc` or `.debug_ranges`, the `this` and
  parameter-name fixups, the function definition of `createFuncSignatures`) and
  `DWARFImporter.moveTypesIntoSourceFolders`.
- What a Ghidra `Function` adds: the return's rules of x86-64-gcc.cspec's default prototype
  (x86-64-gcc.cspec:105-112) are ported: up to 16 bytes `join_dual_class`
  (`MultiSlotDualAssign.assignAddress` with `PrimitiveExtractor`, so an x87 `long double` or a
  struct of one, which no 8-byte tile holds, fails it), else `hidden_return`: the return becomes
  a pointer and a first parameter `__return_storage_ptr__`. Still copied from what the 12.3 run
  shows, not from ported code: `__thiscall` (not in that cspec) keeps `this` an ordinary first
  parameter after that pointer, and a parameter named `param_<n>` shows the default name of its
  ordinal after `this` and that pointer. Superseded (2026-11-22): "a return over 16 bytes becomes
  a pointer" was the whole rule before; `dwarf/mod.rs` `join_dual_class` is the current one. The
  full calling convention is the `x86-64 System V` piece of DESIGN.md (2026-11-21).
- Malformed input (review fixes, 2026-11-22): what Java logs with `Msg.error` and skips is
  skipped and counted as a warning (`ghidra-rs dwarf` prints the count and the first 20): a DIE
  that cannot be read ends its unit (DIEContainer.java:402-409), a type that fails is skipped
  (DWARFDataTypeManager.java:578-598), a function that fails is skipped
  (DWARFFunctionImporter.java:109-143). Where Java's stack overflows (a nameless typedef of
  itself, or two of each other), a depth bound of 256 on `getDWARFName` fails that type; a
  member without a parent fails it as Java's NullPointerException does. A unit length past
  `.debug_info` reads until a DIE fails; one that wraps Java's long leaves an empty unit and ends
  the unit list; an empty first unit maps no DIE (`compUnitDieIndex` as Java's TreeMap). Java's
  `int` and `long` arithmetic wraps (`wrapping_*`), an enum of more than 8 bytes fails its type
  (EnumDataType.java:57). `DW_FORM_indirect`, nested lexical blocks and `markAllChildrenAsProcessed`
  are iterated, so hostile nesting cannot exhaust the stack. The GNU forms 0x1f01, 0x1f02,
  0x1f20, 0x1f21 (DWARFForm.java:243-246) are read. `getDataTypesByBaseName` lists the base
  type, then the `.conflict` types in Java's HashMap order (CategoryDB.java:575-646); bitfield
  bases compare by `getPrimitiveBaseDataType` (BitFieldDataType.java:241-253).

Checked with `tools/dwarf-diff.sh` (builds `tools/dwarf/*.c*` with GCC 16.2.1 and clang 23.1.5,
`-gdwarf-3` as Hatred's units, then `DumpDwarf.java` on 12.3 with `-noanalysis` and `ghidra-rs
dwarf`, compared by key). Ten corpora (c1, cpp1 at -O0; c2 two units with conflicting layouts,
cpp2 and cpp3 standard-library heavy, at -O2; each with GCC and clang): data types 5,760 of
5,761 identical, 0 missing, 0 extra; function signatures 522 of 522 identical. The one
difference (`cpp2-gcc`, `std::pair<std::_Rb_tree_node_base*, ...>`): Java's two members point
through a `_Rb_tree_node_base *` that stayed in `/DWARF/_UNCATEGORIZED_/std` when its base type
moved to `stl_tree.h` (a pointer record keeps its own category in `DataTypeManagerDB`); in
ghidra-rs a pointer's category follows its base. Not traced further.

Hatred (`Hatred-Linux-Shipping`, 508 MB; its DWARF 3 is clang 3.5.0's, the `.comment` lists GCC
4.4.7 and 4.8.1 for linked libraries): 461 units, 15,334,680 DIEs, 276,572 data types (75,832
structures, 162 unions, 53,623 typedefs, 5,551 enums, 141,404 function definitions; 3,180
`.conflict` names), 142,793 function signatures, in 35.6 s and 1.67 GB peak memory. Java on
Hatred did not finish: `DumpDwarf.java` with a 3 GB heap (`GHIDRA_HEADLESS_MAXMEM`, the
desktop's free memory with another agent building) was still importing types after 29 minutes
at 3.4 GB resident when the desktop ran out of memory (the game itself was started) and it was
stopped. So Hatred is not compared with Java; no subset of its units was compared either.

Not ported: local and global variables and their storage (so the STORAGE / FORMAL commit modes,
the parameter spill and storage-verification fixups, and the cspec's `convert_to_ptr` for
parameters), location lists and expressions beyond constants, line programs and source maps,
macros (`DWARFMacroEnumCreator`), comments, descriptions and bookmarks, external debug files,
Go and Rust special cases, the conflict queue's post-pass and `replace` of a type of another
kind, inlined-function comments, a function's no-return from earlier analysis. Also not
ported (review findings left open, 2026-11-22): the STORAGE commit mode
(`StorageVerificationDWARFFunctionFixup`, the CUSTOM_STORAGE path of
`updateFunctionSignature`, the location expressions of parameters at entry); the parameter
names `this` / `param_<n>` from `PrototypeModel` / `VariableSymbolDB` / `ParameterDB` source
(still from the 12.3 output); a removal from a conflict map or a treeified bucket in the HashMap
order (`java_hashmap_order`); a `long double` member's 16-byte component and packing in a union
(`cpp4`'s union `U`, below). Low review findings left as they are (2026-11-22): zero-width
bitfields are not skipped in `composite_part` (Java skips them, `BitFieldDataType.isZeroLength`);
an enum with an unnamed enumerator keeps the others (Java's `add(null, ..)` throws and drops the
enum); a negative array bound gives one element (Java's `ArrayDataType` throws); DWARF 5 type,
partial and skeleton units are skipped or read (Java throws, `DWARFUnitHeader.java:61-72`);
`line_strp` and `strp_sup` read as empty strings; abbreviation tag and attribute codes are cut
to 16 bits.

Rerun after the merge into master (2026-11-22, with `int9`'s ELF64 and demangler and Repair Flow
Damage): `cargo test --release` 195 passed, 0 failed; fmt and clippy clean; `dwarf-diff.sh rust
cmp` on the ten corpora (the branch's binaries and Java dumps, reused) gives the same counts as
above: data types 5,760 of 5,761 identical, function signatures 522 of 522. Java was not rerun.

Review fixes (branch `dwarf-fixes`, 2026-11-22; "Malformed input" above, and `join_dual_class`):
the Java dumps of the ten corpora rerun on 12.3, same counts before and after the fixes (data
types 5,760 of 5,761, function signatures 522 of 522, 0 warnings). A new corpus `cpp4`
(`tools/dwarf/cpp4.cpp`, -O2, GCC and clang: a method returning a 24-byte struct with an
unnamed parameter, `long double` returns, small structs and unions returned in registers):
data types 32 of 34 identical, function signatures 17 of 18 (before `join_dual_class`: 14 of
18; `K::ld` and `mk_ld` return `long double` through `__return_storage_ptr__` in Java). The
three left: union `U` (`long double` member, both compilers: Java's component is 16 bytes and
the union packed, ghidra-rs's 10 and not packed), and GCC's `mk_ld`, which Java gives the
pointer return but no `__return_storage_ptr__` parameter (likely the STORAGE commit mode, not
ported; not traced). Hatred: the same 461 units, 15,334,680 DIEs, 276,565 data type lines and
142,793 signatures of the dump, 0 warnings, 32.8 s and 1.66 GB peak (before: 30.0 s, 1.66 GB);
one typedef names another `.conflict` (`FFuncPtr` of `TBaseStaticDelegateInstance<const
FSceneViewport *()>`: `_func_RetValType.conflict8`, was `.conflict11`: the HashMap order), and
42 signatures now return through `__return_storage_ptr__` (`join_dual_class` fails: empty
structs such as `TStatId` / `FNothing`, `TOptional<T>` whose packed `TTypeCompatibleBytes`
leaves a hole). Hatred is still not compared with Java, so these 43 are unverified.
`cargo test --release` and `cargo test` (debug) 201 passed, 0 failed each (six new malformed-input
tests in `dwarf/tests.rs`); fmt and clippy clean; `CORPORA=m8 tools/bars.sh` 57 of 57 lines equal
to the int9 baseline.

### The decompiler on x86-64 (branch `m3-x64`, 2026-11-22)

The console's `load file` takes an ELF x86-64 file as x86:LE:64:default:gcc, as the reference's
`BfdArchitecture::resolveArchitecture` picks it (bfd_arch.cc:88-110): `x86-64.sla` next to the
`GHIDRA_RS_SLA` given, `x86-64.pspec`, `x86-64-gcc.cspec`. `analyze <elf64> --decomp-prelude`
writes the prelude: `adjust vma 0x100000` for a PIE linked at 0 (where Ghidra loads it; the
read-only sections then marked again), `.got`/`.got.plt` read-only, the GOT import slots and
every function. What it needed:

- the compiler spec's model rules (modelrules.cc): `<rule>` with `<datatype name="any">` and
  `goto_stack`, `join_dual_class`, `hidden_return`, `convert_to_ptr`; return recovery goes
  through `ParamListStandardOut::fillinMap`'s rule path. Storage assigned by a rule
  (`ModelRule::assignAddress`, so locked prototypes) fails loudly; a model using what is not
  ported (MSABI: `<group>`, `pointermax`) fails when chosen;
- `goto [..]`, `call [..]`, `return [..]` in p-code snippets (the `x86_*_thunk` callfixups);
- `print raw` and heritage's SUBPIECE offsets sized by the address size (8), not 4.

`tools/elf64-decomp.sh` builds `tools/corpus/elf64/*.c` (non-PIE, PIE, `-cet`) and
`tools/dwarf/cpp*.cpp` (clang++ and g++ -O2) and runs `decomp-diff.sh` on every function. Against
decomp_dbg: 815 functions, the reference ran 805, identical 670; 105 loud (85 heritage output
overlap guard, 10 `RulePieceStructure`'s CONCAT tree, 8 overlapping return value guard, 1
overlapping parameter guard, 1 jump table through a CALLOTHER), 36 silent. The silent ones: 26
where the ops a heritage pass makes for persistent globals are numbered one lower (the reference
makes and deletes one op more first; not found yet), 9 where the reference casts `AL` before the
`return`, 1 other. Hatred, 50 of its own camera and view functions
(`tools/corpus/hatred-camera.txt`, prelude in 68 s): the reference ran 50, identical 31, loud 15
(11 output overlap guard, 2 joined contiguous pieces, 2 overlapping parameter guard), silent 4
(ghidra-rs guards `.bss` globals at calls the reference does not, and one numbering shift). Not
compared with Java: see "Facts on ELF x86-64" below. Superseded: "`--facts` on ELF is not
ported" (it is, in part, below). The 32-bit path is unchanged:
`CORPORA=m8 tools/bars.sh` 57 of 57 lines equal to the int9 baseline; `cargo test --release`
201 passed; fmt and clippy clean.

Neither console takes a file path with whitespace: `IfcLoadFile` reads `load file` word by word
(consolemain.cc:53-57; two words are a target and the file), and so does ghidra-rs's. Hatred's
path (`.../Extra Storage/...`) gave both engines no output, which `decomp-diff.sh` counted as
identical (50 / 50). Now `decomp-diff.sh` reaches such a `BIN` through a link in its output
directory, and an output that is empty from the load line on is written as `decomp-diff.sh:
error: no output ...`: the reference counts as failed, ghidra-rs as loud (bars.sh), never
identical. On Hatred's real path the camera corpus gives the same 31 / 15 / 4.

The three silent causes, found by tracing the reference (a copy of decomp_dbg with an op-creation
backtrace):
- the shifted op numbers came from a restart only ghidra-rs made. A function mapped by `map
  function` had no model, so its extrapop was unknown, and resolving `CALL RAX` to it failed
  `isCompatible` against the call's 8. The C++ Funcdata gives its prototype the default model
  (`FuncProto::setScope`, fspec.cc:3874-3880), and now `add_function` does too.
- the `AL` cast: `TypeOpReturn::getInputLocal` takes the function's output type, locked or not
  (typeop.cc:915-921); ghidra-rs took a locked one only.
- the `.bss` guards: bfd makes the non-loaded `.comment` and `.debug_*` sections sections at 0, and
  `LoadImageBfd::getReadonly` marks them read-only. Hatred's `.debug_info` (182 MB) so covers
  `.bss`, which bfd reads as zeros (`loadFill`). The console's image now has those ranges
  (`Image::bfd_readonly`) and reads `.bss` as zeros. This is the reference's loader, not Java's,
  which does not map them.
  Superseded (2026-11-23, branch `fix-prelude`): `Image::bfd_readonly` is gone; the reference
  skips these sections instead ("The prelude path follows Java" below).

After the three: small ELF corpus identical 700 / 815 (was 670), loud 105, silent 0 (the reference
ran 805; 10 it did not finish, 5 of them timed out at 120 s); Hatred camera identical 35 / 50 (was
31), loud 15, silent 0 (was 4). `CORPORA=m8 tools/bars.sh` stays 57 of 57 equal to int9.

### Facts on ELF x86-64 (branch `m3-x64`, 2026-11-22)

`analyze <elf64> --facts <out>` writes the facts file of 32-bit PE, with x86:LE:64's parts:
- the core types record of x86:LE:64 with the gcc compiler spec (`facts_coretypes64.xml`, copied
  from a Java export, as the 32-bit one is);
- 8-byte pointers;
- no TEB block and no `FS_OFFSET`;
- `x86-64-gcc.cspec` read for the call fixups;
- extrapop 8 where a function has no purge, the default model's (the callee purge analyzer does
  not run on x86-64);
- names from the symbol tables, local ones too.

Superseded in part (2026-11-23, branch `fix-hatred-facts`, "Namespaces and DWARF prototypes in
the ELF facts" below): namespaces are written, and the DWARF prototype where its storage is
known. Not ported, written as `underived ... function`, which the loader fails on:
- a GNU-mangled name (`gnudemangle::gnu_demangle`, picked by the program format as
  `DemanglerAnalyzer` does): Java puts the function in its namespaces and gives it the
  mangling's signature; its plate comment is `underived ... comments`;
- a function the DWARF importer (`src/dwarf/`) gives a signature: Java's DWARF analyzer applies
  its types and parameters.

The DWARF importer's plate comment of a function (branch `x64-facts`, 2026-11-22;
`dwarf::Func::plate`, DWARFFunctionImporter.java:168-176, 223-358,
FunctionDefinitionDataType.java:261-295, DWARFUtil.java:343-359, DWARFFunction.java:284-287,
501-517, DWARFImportOptions.java:124-145) is written; on a GNU name in a namespace it stands
for the demangler's (DemangledObject.java:400-420). It is `underived ... comments` where the
function has a local variable or label DIE, a body of several ranges, another DIE at the same
address, or a `.conflict` type in its prototype, and on every function of an image with a
non-empty `.gcc_except_table` (GccExceptionAnalyzer's `try {` comments are not ported;
superseded 2026-11-24, branch `hatred-facts`: they are, and that image-wide mark is gone, "GCC
exception tables ported" below). On PIE
binaries the DWARF addresses got the image base twice (the import applies
programBaseAddressFixup itself), so their DWARF functions were written as plain `func`
records; they are `underived` now.

Prototypes from the 64-bit data-type archives (Java gives `_init` `int _init(EVP_PKEY_CTX *)`)
are not read.
Superseded in part (2026-11-23, branch `fix-prelude`): still not applied, but a function the
archive names is `underived ... function` ("Archive prototypes are loud" below).
Superseded (2026-11-23, branch `fix-hatred-archives`): applied where ported ("Archive prototypes
applied" below).

The EXTERNAL block and the GOT (branch `x64-facts`, 2026-11-22), in the facts only (the
analysis and the decompiler have no block there). Superseded (2026-11-22, branch
`fix-gotslots`): "the analysis and the decompiler still see 0 in the import slots"; the slots
hold the entries' addresses now (see "The GOT import slots in the image" below):
- Java's EXTERNAL block: an 8-byte entry per undefined symbol in symbol-table order (a sized
  object its size), from the first 0x1000 boundary past the highest block; a versioned name
  (`puts@GLIBC_2.2.5`) of an entry made before is that entry's PRE comment (`comments`,
  `user2`), another name made before is that entry (ElfProgramBuilder.java:1511-1568,
  1685-1713, 1945-2041). The block record is writable. It matched Java's on all 14 binaries;
- a one-byte function at each STT_FUNC entry (ElfProgramBuilder.java:2140-2152), with the
  default model's extrapop and the no-return analyzers' mark: its prototype comes from the
  archives, so each is `underived ... function`. Superseded (2026-11-23, branch
  `fix-hatred-archives`): only a GNU name or a definition that is not ported is;
- GLOB_DAT and JUMP_SLOT slots of an undefined symbol hold its entry plus the addend
  (X86_64_ElfRelocationHandler.java:168-171), and every word of a `.got*` block is a pointer
  (ElfDefaultGotPltMarkup.java:78-93, 360-415), named `PTR_<pointee>_<address>`, or
  `PTR_<address>` where the value is no memory address (isValidPointer); a symbol of the symbol
  tables at the slot (`_GLOBAL_OFFSET_TABLE_`) or a pointer into the middle of an entry is
  `underived ... label`. ELF has no `extref` records any more (Java has none: the slots point
  into memory);
- a pointer's data record is 8 bytes on x86-64 (it was 4).

Not ported: the functions Java has at the EXTERNAL entries of STT_NOTYPE symbols
(`__gmon_start__`, `_ITM_registerTMCloneTable`, `_ITM_deregisterTMCloneTable`: 84 records of
the 14 binaries; which analysis makes them was not traced), data at object entries, and the
PLT thunks of PIE binaries (`puts` at the PLT).

`tools/elf64-facts.sh` runs Java 12.3's plain auto-analysis with ExportFacts.java on the 14
binaries of the small corpus (the cpp ones with `-g -gdwarf-3`) and compares with
`facts-diff.sh`. `PROJ` puts the Java projects elsewhere, since Ghidra refuses this worktree's
`.claude` path. ExportFacts.java now writes blocks, data and labels of the default address
space only. ELF's non-loaded sections (`.comment`, `.debug_*`, in OTHER) collided with ram's
offsets, and their undefined bytes made the script fail on every binary with DWARF; PE programs
have no such blocks.

On the MacBook (2026-11-22) the script runs in an Arch Linux container (colima): the
binaries are built there (gcc 16.2.1, clang 23.1.5, the desktop's versions) and Java is the
Linux 12.3 DEV build (`build/dist/ghidra_12.3_DEV_20261120.zip`) on OpenJDK 25.0.5.1;
ghidra-rs and `facts-diff.sh` run on macOS with the Java facts it left. The 14 binaries took
Java 6 min 42 s.

Totals of the 14 against Java (equal / Java's records), master 13b1dffecf and branch
`x64-facts` on the same binaries and Java facts:

| record | master | x64-facts | rate |
|---|---|---|---|
| coretypes | 14 / 14 | 14 / 14 | 100% |
| tracked | 815 / 1,112 | 1,057 / 1,112 | 95.1% |
| body | 771 / 1,112 | 1,013 / 1,112 | 91.1% |
| block | 326 / 417 | 340 / 417 | 81.5% |
| undef | 1,034 / 1,407 | 1,034 / 1,407 | 73.5% |
| string | 500 / 751 | 500 / 751 | 66.6% |
| label | 4,645 / 7,315 | 4,645 / 7,315 | 63.5% |
| override | 770 / 1,259 | 770 / 1,259 | 61.2% |
| comments | 0 / 646 | 251 / 646 | 38.9% |
| func | 113 / 1,112 | 177 / 1,112 | 15.9% |
| data | 531 / 12,072 | 724 / 12,072 | 6.0% |
| type | 14 / 1,107 | 14 / 1,107 | 1.3% |
| ns | 0 / 295 | 0 / 295 | 0% |

Superseded (2026-11-22): the desktop run's master figures (string 499, label 4,558, data 530;
the binaries were rebuilt since). Superseded (2026-11-22, the DWARF plate comments): comments
242 / 646 (37.5%) and 1,488 `underived`; no comments record differs from Java's.

ghidra-rs writes 1,495 `underived` records (master: 1,501, and 286 `extref`), which Java
does not have. Superseded: the causes below were master's; the EXTERNAL block's are ported
above. The causes:
- Java's EXTERNAL block functions: 297 func, body and tracked records ghidra-rs has as `extref`
  of GOT slots;
- ELF markup and DWARF data types, most of the missing `data` and `type`;
- archive and DWARF prototypes, and GNU namespaces: `func`, `ns`, `comments`.

On Hatred, `analyze --facts` was killed twice (out of memory, about 7 GB free on the desktop)
after the analysis, 76 s and 107 s in; no Hatred facts were written. The prelude run (no
address tables) fits. Superseded (2026-11-22): on the MacBook (32 GB) it completes. Peak RSS
there: `--decomp-prelude` 4.6 GB; `--functions` 10.85 GB before, 9.42 GB after constant
propagation merges a chunk of functions at a time (the output is byte-identical); `--facts`
11.17 GB before, 10.01 GB after, 354 s (the writer 187 s). The rest is the analysis itself
(7.9 GB while it runs), so the desktop still lacks the memory. Superseded (2026-11-22, branch
`x64-facts`): the 10.01 GB and 354 s. Constant propagation now merges each chunk straight into
the instructions (a per-byte "reached" mark), not into a copy of every reached instruction.
`--facts` on the MacBook, `/usr/bin/time -l`: maximum RSS 9.98 GB before, 6.96 GB and 7.14 GB
after (two runs); peak memory footprint 6.59 GB before, 4.39 GB and 4.43 GB after; the analysis
110.2 s before, 101.1 s and 101.2 s after; total 361 s before, 357 s and 356 s after. The facts
are byte-identical (`cmp`). Not tried on the desktop. Hatred's facts: 180,026 func
and body records, 636,140 data, 859,434 label, 197,543 string, 475,155 undef, 35,328
override, 407 extref. 343,951 are `underived`: 171,714 function, 166,125 comments, 6,112
label. There is no Java comparison: Java was not run on Hatred. Superseded (2026-11-22,
branch `x64-facts`): the counts above, and "Java was not run on Hatred".

Java 12.3 on Hatred (the Linux DEV build in a Linux container on the MacBook, `-Xmx24G`, plain
auto-analysis with ExportFacts.java): exit 0, 7,721 s, cgroup `memory.peak` 25.97 GB
(25,969,389,568 B). ghidra-rs (MacBook, the same code as the small corpus above): 356 s,
7.14 GB maximum RSS. `facts-diff.sh` of the two:

| record | equal | different | missing | extra | Java | equal / Java |
|---|---|---|---|---|---|---|
| coretypes | 1 | 0 | 0 | 0 | 1 | 100% |
| wref | 36 | 0 | 0 | 0 | 36 | 100% |
| tracked | 180,418 | 0 | 15 | 2 | 180,433 | 100.0% |
| body | 180,181 | 237 | 15 | 2 | 180,433 | 99.9% |
| block | 30 | 0 | 1 | 0 | 31 | 96.8% |
| undef | 227,281 | 878 | 7,246 | 6,655 | 235,405 | 96.5% |
| override | 31,356 | 0 | 2,507 | 3,972 | 33,863 | 92.6% |
| string | 196,587 | 369 | 29,362 | 400 | 226,318 | 86.9% |
| label | 711,278 | 148,123 | 24,010 | 33 | 883,411 | 80.5% |
| data | 492,177 | 84,988 | 1,499,157 | 55,279 | 2,076,322 | 23.7% |
| func | 2,657 | 177,761 | 15 | 2 | 180,433 | 1.5% |
| comments | 345 | 0 | 148,608 | 0 | 148,953 | 0.2% |
| type | 1 | 0 | 38,392 | 0 | 38,393 | 0.0% |
| ns | 0 | 0 | 44,952 | 0 | 44,952 | 0% |

ghidra-rs writes 351,303 `underived` records. Known limits, not fixed:
- 6,209 `func` records differ from Java's by an extra stack local `local_8` (undefined8 at
  stack -8) and are not marked `underived`: a silent difference. Superseded (branch
  `fix-local8`, below): the x86-64 stack locals are fixed; the 6,209 had other causes too;
- 75 of Java's `comments` records have no record of ghidra-rs, derived or `underived`; one
  cause is a function ghidra-rs does not find (0x3582f90);
- `func_children` drops the DWARF function process_subprogram makes for a call site; it may be
  silent;
- superseded in part (branch `fix-hatred-facts`, below): namespaces and some DWARF prototypes
  are written. Was: not ported: DWARF and demangled function signatures, parameter storage, namespaces (`ns`
  records).

#### The GOT import slots in the image (branch `fix-gotslots`, 2026-11-22)

`Image::from_elf` writes Java's value into a GOT slot bound to an undefined symbol: its EXTERNAL
entry plus the addend (X86_64_ElfRelocationHandler.java:119-121, 168-171), where it wrote 0.
The analysis, the console and the facts' decompiler all read it. Per path:
- facts path (`load facts`, compared with Java): the slot is read-only in Java's facts, so a
  load from it folds to the entry's address, as in Java. On `t1-pie`'s `__do_global_dtors_aux`
  with Java's facts and `option readonly on`, ghidra-rs read 0 before the fix, folded the test
  away and dropped the call silently (`/* WARNING: Removing unreachable block */`). Now it
  prints `__cxa_finalize(__dso_handle);`, the line Java 12.3 prints with "respect read-only"
  on (DecompileOptions.setRespectReadOnly; the DecompileRef.java default, off, prints
  `if (PTR___cxa_finalize_00103fe0 != ...)` on both engines);
- prelude path (compared with decomp_dbg, which reads the file through bfd, no relocations):
  the slot is an `externalref` of the prelude, and that clears its read-only flag
  (`Arch::is_readonly`), so neither engine reads its value. No output changed;
- the analysis: the entry is in no block of the image, like 0, so nothing changed. The 14
  small binaries' `--facts` are byte-identical before and after. Hatred's facts-diff table
  (above) is unchanged, and so is Hatred's `--decomp-prelude` (`cmp`). The function list is
  the same.

Hatred's `_ZN24AHeroCharacterControllerD0Ev` (0x1752ff0) printing
`(**(code **)(iRam0000000000000000 + 0x30))(0,param_1);` on the prelude path is not this. Its
causes:
- the prelude has no flow overrides. Java's facts (and ghidra-rs's) have `override 1752ffd
  CALL_RETURN`, so Java stops at the tail `JMP operator delete`. The console follows it
  (flow.cc:299-315) through `_ZdlPv` into `FMemory::Free`, where `JMP RAX` (0x18ded87, a
  vtable call) gives the "Could not recover jumptable" warning. The reference does the same;
- `GMalloc` (0x515e4b0, `.bss`) is read-only on that path. bfd's `.debug_info` at 0
  (0xad6042f bytes, `Image::bfd_readonly`, LoadImageBfd::getReadonly) covers `.bss`, so the load
  folds to 0. In Java `.bss` is writable;
- the reference then reads `*(0 + 0x30)` from `.comment`'s bytes at 0 (LoadImageBfd::findSection
  and loadFill take any section, loaded or not) and prints `(*pcRam726328203a434377)(0,param_1);`.
  ghidra-rs has no bytes at 0 and prints `iRam0000000000000000`. This is a silent difference
  from the reference, and it is older than this fix (master f69e2a1869 prints the same). The
  Hatred camera corpus did not show it: `decomp-diff.sh` with only `BIN` set takes the mercs2
  prelude, and decomp-diff.sh's own prelude run fails on ELF ("no register RSP", from
  `GHIDRA_RS_SLA=x86.sla`).

The facts path, which would follow Java here, fails loudly on both functions ("the decompile
of a function in a namespace is not ported").
Superseded (2026-11-23, branch `fix-prelude`): the function prints as in Java at the tail jump
now, and `GMalloc` is not folded ("The prelude path follows Java" below).

Checks: small ELF decompile 815, identical 701, loud 110, silent 0, 4 reference timeouts.
Every ghidra-rs output is byte-identical to master's except 4 cpp3-clang functions that timed
out at 120 s there and finish here (previous: 697 / 106 / 0, 12 reference timeouts or load
errors). Hatred camera 35 / 15 / 0 with the mercs2 prelude, outputs identical to master's. The
same 35 / 15 / 0 with Hatred's own prelude.

The stack locals of x86-64 (branch `fix-local8`, 2026-11-22). The Stack analyzer's port
(`factsout::locals`, NewFunctionStackAnalysisCmd) read x86's 32-bit register layout on x86-64:
ESP at 0x10 (RDX there) and 4-byte registers, so it took the slot a `PUSH` or `POP` uses
itself for one an operand names. That gave `local_8` at every `POP RBP` and `local_res0` at
`_start`'s `POP RSI`. It now reads RSP (0x20), 8-byte registers, a REX prefix (R8-R15 from
0x80, ia.sinc:19-24) and parameters from 8 up (x86-64-gcc.cspec's stack pentry). As in Java:
checkForX86 compares the pointer size in bytes with 32 (NewFunctionStackAnalysisCmd.java:147-152),
so the LEA rule holds on x86-64 too; `PUSH RSP` names its own slot (RSP is lowered before the
STORE, where SymbolicPropogator.makeReference calls evaluateSymbolicReference), Java's
`local_10` of `_start`. A stack offset is written 64 bits wide (`0xfffffffffffffff8`, as Java
writes it). The 32-bit path is unchanged. Small corpus: func 177 -> 209 / 1,112, every other
kind unchanged. Hatred: func 2,657 -> 5,623 equal (174,795 different), every other row as in
the table above; maximum RSS 6.76 GB (1,095 s, the MacBook loaded by other runs). Superseded:
the func row above.

Hatred's silent `func` records (different from Java's, no `underived ... function` record at
the entry): 6,209 -> 3,243, all of them among the 6,209. What is left, none marked `underived`:
- 3,085 where Java has a prototype with a locked return type (2,619 `__stdcall`, 466 of the
  unknown model; C library names: `CRYPTO_*`, ICU's `ucal_*_53`, curl), and 52 with a
  `__stdcall` or `__thiscall` model and no locked return: prototypes ghidra-rs does not
  have (the 64-bit data-type archives are not read, above);
- 100 whose stack locals still differ (locals only ghidra-rs has, only Java has, or both): not
  traced;
- `_start`: Java gives it the `processEntry` model (extrapop 0), ghidra-rs `unknown`;
- 4 other (2 names, 2 locals).
The small corpus's 47 silent: 14 `_start` (`processEntry`), the archive prototypes of `_init`
and of the `-cet` `.plt.sec` thunks (Java names them after the external with its prototype,
ghidra-rs `FUN_`), 4 no-return flags Java sets (`die.constprop.0`), 3 `main` with a call
override Java writes (`protooverride` of a varargs call).

Superseded (2026-11-23, branch `fix-prelude`): the 3,243 and the small corpus's 47; a function
the archive names is `underived` now ("Archive prototypes are loud" below).

#### The prelude path follows Java: non-loaded sections, flow overrides (branch `fix-prelude`, 2026-11-23)

Hatred's `_ZN24AHeroCharacterControllerD0Ev` printed `iRam0000000000000000` on the prelude path
for three reasons (above). The user's decision: fix all three. What tracing found and what was
done:

- Non-loaded sections. Java's ELF loader puts a section without SHF_ALLOC (`.comment`,
  `.debug_*`) in the OTHER space, never in ram (ElfProgramBuilder.java:2948-2957). ghidra-rs's
  image never had these sections: the bytes at 0 were only the reference's, where bfd gives
  such a section the address 0 and `LoadImageBfd::findSection` and `getReadonly` take any
  section. So the port is in the reference: `tools/decomp-ref.patch` adds `notInImage` to
  loadimage_bfd.cc, and an ELF section without SEC_ALLOC is neither read nor marked read-only.
  The test is for bfd's ELF flavour, so a PE file loads as before.
- `Image::bfd_readonly` is removed. It copied the reference's read-only marking of those
  sections; with the reference patched nothing marks `.bss` read-only, as in Java. The two
  were one cause seen from two sides: ghidra-rs never mapped a non-loaded section at 0, it
  only had their ranges as read-only.
- Flow overrides. `analyze <elf64> --decomp-prelude` writes, after a function's `map function`,
  `override flow <address> callreturn` for each instruction of its body with a CALL_RETURN
  override in the facts (`factsout::call_returns`, the rule `--facts` writes its `override`
  records by: Shared Return Calls' jump to another function, and a call that does not
  return). `map function` makes the function the current one (IfcMapfunction sets `dcp->fd`;
  the console's `map function` now does too), the order the upstream datatests use. After
  `load function` the reference has followed the flow already (`IfaceDecompData::followFlow`)
  and an override does nothing until a second `decompile`, so ghidra-rs's console refuses one
  there. The console ports `IfcFlowOverride` for `callreturn` (another kind fails) and
  `Override::CallReturn::performOverride` with `Funcdata::findPrimaryBranch` (override.cc:507-524,
  flow.cc:477-478; `Flow::call_return_flow`): the branch becomes a CALL, a BRANCHIND or RETURN
  a CALLIND, and a `RETURN #0` follows. Hatred's prelude: 215,775 lines, 34,932 of them
  overrides.

Limits of the overrides:
- the PE prelude has none. Java has them on PE too, but they would change the mercs2 prelude
  (its `cksum` is a `bars-queue.sh` check) and every baseline built on it; not done here.
  Superseded (branch `pe-overrides`): the PE prelude writes them, see "The PE prelude gets
  the flow overrides" below;
- they are ghidra-rs's own, not Java's: on Hatred `facts-diff.sh` has 31,356 `override`
  records equal, 2,507 only Java has and 3,972 only ghidra-rs has (0x16a0590, a function of
  one jump, is one);
- a function gets the overrides of its body's instructions; flow that leaves the body finds
  none.

`analyze` on an ELF takes `x86-64.sla` next to a `GHIDRA_RS_SLA` that names x86's, as the
console's `load file` does (`--sla` is taken as given), so `decomp-diff.sh` writes an ELF
prelude itself. It failed there with "no register RSP": the script exports
`GHIDRA_RS_SLA=x86.sla`.

Checks (MacBook; the reference rebuilt with the patch, every run with the binary's own
prelude):
- Hatred `_ZN24AHeroCharacterControllerD0Ev` (0x1752ff0), `print C`: both engines print
  `_ZN24AHeroCharacterControllerD2Ev(); func_0x016a0590(param_1); return;`, the call and return
  Java has at the tail jump, and no flow into `FMemory::Free`;
- `FMemory::Free` (0x18ded60) itself: both engines print
  `if (piRam000000000515e4b0 == (int8 *)0x0)` and
  `(**(code **)(*piRam000000000515e4b0 + 0x30))(piRam000000000515e4b0,param_1);`. `GMalloc`
  is a global again, not the constant 0. The prelude names no data, so it prints by address
  where Java prints `GMalloc`;
- small ELF decompile corpus, 815 functions: identical 728 (was 701), loud 87 (was 110),
  silent 0, no timeout (were 4). The reference ran 813; the 2 it fails at `load function`
  ("Unable to load 512 bytes", as before) are loud in ghidra-rs. The loud ones: 63 heritage
  output overlap guard, 12 `RulePieceStructure`'s CONCAT tree, 8 overlapping return value
  guard, 1 overlapping parameter guard, 1 jump table through a CALLOTHER, and the 2 above;
- Hatred camera corpus, 50 functions, Hatred's own prelude: identical 37 (was 35), loud 13
  (was 15), silent 0;
- the mercs2 prelude is byte-identical (`cksum` 805048874, 851,093 bytes; no `override` line);
  `CORPORA=m8 tools/bars.sh`: 57 of 57 lines equal to the baseline;
- `cargo test --release` 202 passed (201 and the one new test), `cargo clippy --all-targets
  -- -D warnings` and `cargo fmt --check` clean.

Not checked: Java's own C for these functions (the facts path still fails loudly on a function
in a namespace); the desktop's reference, which must be rebuilt (`tools/decomp-ref.sh`) before
its next `decomp-diff.sh` or `bars-queue.sh` run, since the patch changed.

#### The PE prelude gets the flow overrides (branch `pe-overrides`, 2026-11-23)

The user's decision: the PE prelude writes the CALL_RETURN flow overrides as the ELF prelude
does. `console::prelude` no longer asks for an ELF: after each function's `map function` it
writes `override flow <address> callreturn` for the instructions of its body that
`factsout::call_returns` gives. The mercs2 prelude: 35,185 lines (was 31,816), 3,369 of them
overrides; without the `override` lines it is the old file, byte for byte. Superseded: "the
mercs2 prelude is byte-identical (`cksum` 805048874 ...)" above, which holds for the prelude
before this branch.

The rule is ghidra-rs's own on PE too, not Java's set. Measured against the facts of the Java
project (`$GHIDRA_REF/mercs2.facts`, Java 12.3 after the mercs2 pipeline, 3,365 `override`
records, all CALL_RETURN):

| ghidra-rs | records | equal | only Java | only ghidra-rs |
|---|---|---|---|---|
| `analyze --facts`, plain discovery (`tools/facts-own.sh`, `facts-diff.sh`) | 4,556 | 2,666 | 699 | 1,890 |
| the prelude's lines (`analyze --decomp-prelude`, by address) | 3,369 | 1,650 | 1,715 | 1,719 |

The two rows differ because `--facts` runs discovery with Create Address Tables and constant
propagation and the prelude does not, and the prelude writes only the instructions of a
function's body. What makes each record only Java's or only ghidra-rs's was not traced here
(the function set and the no-return set both differ, see "The comparison"). The difference is
not silent in the decompile checks: both engines read the same prelude. It is one more way the
prelude path differs from Java's own decompile, which the facts path measures.

Checks (desktop, the reference rebuilt in the worktree, old and new prelude from the same
build):
- `CORPORA=m8 tools/bars.sh`: 57 of 57 lines the same with the old and the new prelude, and
  equal to the M8 lines of baseline `x64-13b1dffecf`; silent 0. One M8 function has an override
  (0x9eec5e, at 0x9eec68);
- M500: 39 of the 500 functions get an override line (39 lines; 21 of the addresses are
  Java's too). An override belongs to its function (`Override` of the `Funcdata` in the C++,
  `Console::call_returns` by entry here), so only these 39 read a different script. All 57
  M500 checks on the 39 with the new prelude (`TIMEOUT=30`): 39 / 39 identical in each,
  loud 0, silent 0, timeout 0. With the old prelude, on the 38 without 0x4c48d0: 38 / 38 in
  54 checks, 35 / 38 in `r5slock` and `r5dtlocksv` (loud 3: 0x48c986, 0x608500, 0x7874d0) and
  36 / 38 in `svlock` (loud 2: 0x48c986, 0x608500), all "a piece of a locked stack
  parameter", a path not ported; with the override flow no longer runs past the overridden
  instruction into that path, so the three checks gain these functions. 0x4c48d0 is the function the reference did not
  finish in 120 s (`cs-r`, old prelude); with the overrides both engines finish it;
- full M500 checks run with the new prelude (baseline `x64-13b1dffecf` -> now):
  `pcd` 499 / 499, reference finished 499 / 500 -> 500 / 500 of 500; `r5dtlocksv` and
  `r5slock` 469 / 499 (loud 30) -> 472 / 499 (loud 27, all "a piece of a locked stack
  parameter"; the reference does not finish 0x6b21e0 in 120 s); silent 0, timeout 0 in each.
  The three agree with the baseline plus the change on the 39 functions;
- small ELF decompile corpus (`tools/elf64-decomp.sh`), 815 functions: identical 790, loud 23
  (16 CONCAT tree, 5 type propagation, 1 partial struct, 1 jump table through a CALLOTHER),
  silent 0, the reference ran 813: unchanged;
- `cargo test --release` 203 passed, `cargo clippy --all-targets -- -D warnings` and
  `cargo fmt --check` clean.

Not run: the other 53 M500 checks in full (only their 39 functions with an override, above),
the r5d-adc, switch and simple corpora, the Mac, Java's own C. Every baseline of a mercs2
check moves with the prelude; `rust/target/baselines/pe-overrides-<hash>.summary` holds the
new M8 lines.

#### Archive prototypes are loud (branch `fix-prelude`, 2026-11-23)

Java's Apply Data Archives analyzer gives a function the prototype of a function definition
of its archive, `generic_clib_64` for an ELF x86-64 program (DataTypeArchiveUtility.java:114-142;
Java's log on Hatred: "Applied data type archive: generic_clib_64"). The definition is found by
name: the last identifier of a symbol's name, or that with one `_` before it
(ApplyFunctionDataTypesCmd.java:138-176, 405-424). ghidra-rs does not apply these prototypes
(the user's decision: not ported now), so its `func` record of such a function differed from
Java's silently. Now `analyze <elf64> --facts` reads the names of the archive's function
definitions (`Features/Base/data/typeinfo/generic/generic_clib_64.gdt` in the Ghidra
tree the `.sla` is in, through `gdt::Archive`; the run fails without the file) and writes
`underived <entry> function` for a function a symbol-table name of which matches
(`factsout::archive_named`), and for a thunk of one. Nothing else of the record changes. The PE
path does not read the archive.

Hatred, `facts-diff.sh` against Java's facts: silent `func` records 3,243 -> 236; `underived`
records 351,303 -> 354,311 (`function`: 171,701 -> 174,709); every row of the table above is
unchanged (func 5,623 equal). 3,007 of the 3,243 had an archive name; among the functions not
`underived` before, 1 with an archive name was equal to Java's and is loud now. `--facts`
took 468 s, maximum RSS 7.27 GB. Small corpus (14 binaries): silent 47 -> 33 (the 14 `_init`),
`underived` 1,495 -> 1,509, func 209 / 1,112 as before.

Premise found wrong: the 3,137 counted as "archive prototypes" (above) were counted by what
Java's record has, a locked prototype or a model; 3,007 have an archive name. The 236 left,
none `underived`:
- 104 with a locked prototype in Java and no archive name (60 `unknown`, 23 `__thiscall`,
  21 `__stdcall`: `default_malloc_ex`, `str_free`, `err_state_LHASH_COMP`,
  `uset_closeOver_53`): not traced; many are callbacks passed to archive functions;
- 131 without one (105 `unknown`, 21 `__thiscall`, 5 `__stdcall`), the stack-local
  differences among them: not traced;
- `_start` (`processEntry`).
Also not covered: a second name of a function. `Image::elf_funcs` keeps one name per entry, so
an alias only Java sees can still match the archive.
Superseded (2026-11-23, branch `fix-hatred-archives`): the prototypes are applied, the 236 are
traced in part and every name of a function counts ("Archive prototypes applied" below).
#### Archive prototypes applied (branch `fix-hatred-archives`, 2026-11-23)

`analyze <elf64> --facts` applies the function definitions of `generic_clib_64.gdt` as Java's
Apply Data Archives analyzer does (ApplyDataArchiveAnalyzer, ApplyFunctionDataTypesCmd,
ApplyFunctionSignatureCmd), where it wrote `underived ... function` for every function the
archive names. What is ported:
- which definition goes where (`factsout::archive_applied`): symbols are looked up by the last
  identifier of their name, under the definition's name, or with one `_` before it when no
  symbol has the name itself. The symbols are every named symbol of the symbol tables
  (`Image::elf_symbols`, so a second name of a function counts), the entries and the EXTERNAL
  block's. Superseded: "`Image::elf_funcs` keeps one name per entry, so an alias only Java sees
  can still match the archive";
- the source priority: the analyzer applies with `SourceType.IMPORTED` to a function whose
  signature has a lower source. A function the DWARF importer gave a signature (`IMPORTED`)
  keeps it. A GNU name is still mangled when the analyzer runs (the demangler comes later), so
  it matches no definition; a thunk is skipped and shows the prototype of its target;
- the prototype (`gdt::protos::export_elf64`, the exporter of the 32-bit archive with the
  x86-64 gcc data organization): return type, parameters, varargs, the storage of
  `x86-64-gcc.cspec`'s `__stdcall` for integers, pointers and enums up to 8 bytes (RDI, RSI,
  RDX, RCX, R8, R9, then the stack from 8; RAX), a register parameter's range from the address
  before the entry, the `type` records of the types named. The function keeps its name and
  its stack locals;
- Java's Call Convention ID analyzer after it (DecompilerCallConventionAnalyzer): a function
  in memory with a parameter of a defined type gets `__stdcall`, locked; a function of the
  EXTERNAL block and a thunk of one keep `unknown`;
- the EXTERNAL block's functions and the thunks through a GOT slot are written without
  `underived` when their name is no GNU mangling: with the archive's prototype, or plain;
- a function with a symbol whose body is one jump to another function has the prototype of
  that function (Java makes it a thunk, as one without a symbol);
- the entry function has `processEntry`, locked, extrapop 0 (ElfProgramBuilder.java:651-668:
  an executable or shared object whose OS/ABI is Linux or none; `Image::elf_process_entry`).

Still `underived ... function` (loud):
- a definition with a float, a composite, a type over 8 bytes or an `undefined` type in its
  prototype (the cspec's `<rule>`s and XMM storage are not ported), one whose types fail to
  encode, and a name two definitions have (Java applies one of two equivalent definitions and
  neither of two others; `isEquivalent` is not ported);
- an address two definitions reach (Java applies the first of a `HashMap`'s order);
- a match through the `_` form on an image with DWARF: the DWARF importer's labels are
  symbols too, and one named as the definition takes it from the `_` form (Hatred's `_init`
  has no prototype in Java);
- a function with a call fixup, and a thunk that itself has a symbol the archive names;
- a function that calls one the archive gives a variable argument list: Java's Variadic
  Function Signature Override analyzer (FormatStringAnalyzer) writes a prototype override at
  such calls, which is not ported.

Known limits, silent:
- Call Convention ID is taken to succeed. Java runs the decompiler on the function (60 s limit)
  and leaves `unknown` where that fails. On Hatred all 2,602 such functions got `__stdcall`.
  A function Java's decompiler fails on would differ silently;
- a parameter is written name-locked whatever its name, as Java's facts have it (`param_1` of
  `isspace`); the rule in Java was not traced;
- a symbol of the archive at an address with no function: Java may make a function there
  (ApplyFunctionDataTypesCmd.java:218-262); ghidra-rs does not, and writes no record.

Hatred, `facts-diff.sh` against Java's facts, before (master 3a5ba15656, measured again) and
after: func equal 5,623 -> 9,098 of 180,433; silent func 236 -> 131; `underived` records
354,311 -> 350,871 (`function` 174,709 -> 171,269); type 1 -> 933 equal (1 different, `fn`:
the two sides have
different function types of that name; 3 only ghidra-rs has: `double`, `undefined1`, `wchar_t`); every other
row unchanged. `--facts` took 427 s, maximum RSS 7.25 GB. Small corpus (14 binaries): func equal
209 -> 333 of 1,112; silent 33 -> 15; `underived` 1,509 -> 1,315.

Of the 236 silent before: 21 are equal now, 106 are `underived` (the callers of functions with
a variable argument list among them), 109 are still silent. The 131 silent now, by what differs:
- 119 stack locals (100 of the 236, 19 in functions that were `underived` before): locals only
  one side has, or of another size. Not traced;
- 5 with a prototype override in Java at a call the rule above does not reach (`ENGINE_ctrl`,
  `GENERAL_NAME_print`, `i2v_GENERAL_NAME`, `long_print`, `dump_value_LHASH_DOALL_ARG`; one of
  them with other locals too): 2 of the 236, 3 new;
- 3 thunks of more than one instruction (`default_malloc_ex`, `default_realloc_ex`,
  `default_malloc_locked_ex`: 9 bytes, Java's CreateThunkFunctionCmd takes them, ghidra-rs's
  one-jump rule does not);
- 3 names: `__fstat` where Java has `fstat` (the primary symbol of two), `FUN_034924a1` and
  `FUN_03492be7` where Java has the names of symbols that are no STT_FUNC
  (`_vpaes_schedule_low_round`, `_bsaes_encrypt8_bitslice`);
- 1 type of a local (`undefined1` where Java has `undefined`, `uloc_toLanguageTag_53`).
Premise found wrong: the 104 "with a locked prototype in Java and no archive name" were not shown
to be callbacks typed from archive parameters. The ones traced are a thunk with a symbol
(`default_malloc_ex`: `malloc`'s prototype) and callers with a prototype override; the 21 now
equal and the 106 now `underived` were not looked at one by one.
The 22 newly silent records (loud before, derived now, different for causes older than this
branch): 19 stack locals (the cause of the 100 older ones, `factsout::locals`), 2 prototype
overrides and 1 more with other locals too (the cause of the 2 older ones, and of the small
corpus's `main`). They do not block the merge: the user's decision of 2026-11-16 ("progress that
exposes bugs", DESIGN.md), applied here by the coordinating session. The addresses are in
`rust/target/baselines/archives-131.txt`.
The small corpus's 15 silent: 7 in each `-cet` build (`.plt.sec` thunks, which ghidra-rs names
`FUN_` and Java after the external, seen at `t1-cet` 0x1010c0; the others not looked at one by
one) and `__clang_call_terminate` of `cpp2-clang` (a no-return flag Java sets).


#### Hatred's loud stops: heritage overlaps, contiguous joins, unjustified inputs, `&` casts (branch `fix-hatred-rules`, 2026-11-23)

Six of the seven stops a full decompile of Hatred's own module hit most are ported; the
largest, `RulePieceStructure`'s CONCAT tree, is not (below).

- heritage, a range larger than a call's possible return storage (`XMM0` over `XMM0_Qa`):
  `Heritage::tryOutputOverlapGuard` and `guardOutputOverlap` (heritage.cc:1249-1310). The
  return storage and the bytes around it are INDIRECT creations, concatenated after the call;
- heritage, a range larger than any parameter of a call: `guardCallOverlappingInput`
  (heritage.cc:1211-1236), a SUBPIECE before the call as the trial;
- heritage, a range larger than the function's own return storage: `guardReturnsOverlapping`
  (heritage.cc:1610-1637), a SUBPIECE before each RETURN.
  The three read `ParamListStandard::getBiggestContainedParam` (fspec.cc:1358-1391,
  `ParamList::biggest_contained`). A locked prototype there fails loudly
  (`getBiggestContainedOutput`, `getBiggestContainedInputParam` of a locked prototype);
- `AddrSpaceManager::joinPieces` with `JoinRecord::mergeSequence` (translate.cc:199-232,
  783-792; `Funcdata::join_address`): contiguous pieces that make a register are that
  register, no join. Its callers are the return value in two pieces, a call's output from its
  trials and the double-precision whole. `join_pieces` is `findAddJoin` and no longer refuses
  contiguous pieces (a decoded join and `renormalizeJoinAddress` make a record of them in the
  C++ too);
- `ActionUnjustifiedParams` (coreaction.cc:5179-5223) with `Funcdata::adjustInputVarnodes`
  (funcdata_varnode.cc:508-549), `ParamListStandard::unjustifiedContainer`,
  `ParamEntry::getContainer` and `FuncProto::unjustifiedInputParam` (fspec.cc:296-331,
  1394-1407, 4364-4392): an input inside a parameter's storage, not justified, becomes a
  SUBPIECE of one input of the whole storage. Superseded: "`ActionUnjustifiedParams` widening
  (`adjustInputVarnodes`)" in the not-ported list of stage S4, and "A stack input fails loudly
  there now" ("Local symbols");
- `PrintC::checkAddressOfCast` (printc.cc:395-437): a CAST to a pointer to an array prints as
  `&` when its input is the whole symbol of that array type or a PTRSUB to such a field, else
  as the cast. Superseded: "Fail loudly: a cast to a pointer to an array" (print slice 2) and
  `checkAddressOfCast` in the not-ported list of print slice 3.

Not ported: the CONCAT tree rewrite of `RulePieceStructure` (ruleaction.cc:7515-7607). It needs
`TypeFactory::getExactPiece`'s partial struct (`TypePartialStruct`: an 8-byte piece of
`undefined1[16]`, the type of every 16-byte XMM value), the proto-partial flag in the merge
tests (merge.cc:136-146, 261), `Merge::groupPartials` (merge.cc:967-976, 1375-1405),
`ActionMarkExplicit::baseExplicit` (coreaction.cc:3205-3231), `Funcdata::linkProtoPartial`
(funcdata_varnode.cc:1197-1214) and `HighVariable::setSymbol`'s group offset
(variable.cc:258-260). It stays loud, and so does the partial struct on its own
("getExactPiece: ... (getTypePartialStruct) is not ported"). Superseded: ported on branch
`fix-concat` (the section after this one).

`tools/decomp-status.sh` runs ghidra-rs alone (`decompile`, `print C`, default options) on a
list of functions and writes a status table by cause. Hatred's module here is the 9,994
functions the prelude maps in 0x169e000-0x18a3250 (from the first function of the game module
to `UInt8Property`, where the engine's code goes on); the list of the 10,011 counted on
13b1dffecf was not kept, so the two counts are not the same list. Same prelude (master
3a5ba15656's, 34,932 flow overrides), desktop:

| | master 3a5ba15656 | this branch |
|---|---|---|
| functions run | 3,128 | the 452 loud ones, and 267 of the ok ones |
| ok | 2,676 | 3,009 (333 of the 452; the 267 print byte-identical C) |
| loud | 452 | 119 |
| timeout (120 s) | 0 | 0 |

Loud on master, by cause, and how many of them print now: output overlap guard 191 (111),
joined contiguous pieces 126 (125), overlapping parameter guard 65 (59), CONCAT tree 29 (0),
`adjustInputVarnodes` 14 (14), cast to a pointer to an array 13 (13), overlapping return value
guard 12 (11), jump table through a CALLOTHER 2 (0). The 119 still loud: 83 CONCAT tree (54 of
them were behind a ported stop), 21 partial struct, 11 type propagation into an array
(`downChain`), 2 heritage after dead-code removal in the stack space, 2 CALLOTHER jump tables.


Only the first 3,128 functions of the list (0x169e020-0x17562f0) were run: the desktop was
swapping under other runs and the MacBook was loaded, so the full list on both builds did not
fit. The other 6,866 were not run on either build. The 2,409 ok functions not run again are
taken as unchanged because every path changed was a loud error before; this was not measured.


Checks:
- against the reference (decomp_dbg with this branch's patch, `print raw` and `print C`):
  0x1725600 (the camera path), 0x16a8680 and 0x169e020 are identical in both; 0x16a27b0 and
  0x16e38f0 pass the overlap guard and stop at the CONCAT tree and the partial struct;
  47 of the functions that were loud on master (8 to 10 of each cause but the contiguous
  pieces, 5), `print C`: the reference ran 47, identical 41, loud 6 (4 CONCAT tree, 2
  `downChain`), silent 0;
- small ELF decompile corpus, 815 functions: identical 790 (was 728), loud 23 (was 87: 16
  CONCAT tree, 5 type propagation into an array, 1 partial struct, 1 jump table through a
  CALLOTHER), silent 0. The reference ran 813; the 2 it cannot load ("Unable to load 512
  bytes") were loud and now decompile in ghidra-rs, with nothing to compare them to;
- Hatred camera corpus, 50 functions: identical 47 (was 37), loud 3 (was 13: CONCAT tree,
  partial struct, `downChain`), silent 0;
- `CORPORA=m8 tools/bars.sh` (desktop, reference rebuilt with the patch): 57 of 57 lines equal
  to the baseline (`x64-13b1dffecf.summary`). No M500 check was run;
- `cargo test --release` 203 passed (202 and the one new test), `cargo clippy --all-targets
  -- -D warnings` and `cargo fmt --check` clean.

Kept from before, not this branch's: `ParamActive::which_trial` tests every trial for a
one-byte range, where the C++ returns after the first (fspec.cc:1981-1991).

#### `RulePieceStructure`'s CONCAT tree, partial structs and proto-partial pieces (branch `fix-concat`, 2026-11-23)

The largest of Hatred's loud stops is ported, with what it needs. A value put together by
PIECEs whose data-type is an array, structure or union (every 16-byte XMM value is
`undefined1[16]`) now prints as one assignment per piece (`axVar11._4_4_ = ...;`), as the C++
prints it.

- `TypePartialStruct` (type.cc:2714-2817, `getTypePartialStruct` 4431-4437): a piece of an
  array, in types.rs (`Meta::PartialStruct`, `Kind::PartialStruct`: the parent, the offset, the
  stripped type), with `getSubType`, `compare`, `printRaw`, `getComponentForPtr`,
  `getHoleSize` (split.rs), `isPieceStructured`, and the strip of a partial in
  `getTypePointer`, `getTypePointerStripArray` and `getTypeArray`. `getExactPiece`
  (type.cc:4607-4639) makes one in its three ports (`infertypes::exact_piece`,
  `Funcdata::exact_piece` in mapstate.rs, split.rs). Only a piece of an array: a piece of a
  structure, union or enum still fails loudly (`TypeStruct::getSubType` is not in types.rs);
- what reads the metatype: the cast rules (cast.cc:49-56, 90, 146, 341-374, 417),
  `TypeOp::propagateToPointer` (typeop.cc:195-197), `MapState::addFixedType`
  (varmap.cc:1052-1082: an open hint of the element, a fixed undefined one for a copied
  constant), `SplitDatatype` (`categorizeDatatype`, `RootPointer::find` and the tests of the
  three rules, subflow.cc:2146, 2258-2272, 2967-3011), the type-lock tests of `SubvariableFlow`,
  `SplitFlow` and `SubfloatFlow` (subflow.cc:103, 114, 1757, 3248), `RuleAndStructure`,
  `RuleExpandLoad`, `isPrimitiveWhole`, `ScopeInternal::retypeSymbol`;
- `HighVariable::stripType` (variable.cc:304-322) in `variable::h_type`: a partial struct is
  the undefined type of its size unless a structured symbol backs the variable as a piece. The
  C++ caches a variable's type and does not recompute it when a symbol is linked, so what
  `stripType` did is cached the same way (`HighVariable::stripped`, dirtied by a merge, a
  removed member and `Varnode::updateType`), and `mergeTestRequired` asks for the type of its
  second variable only when the first is locked, as the C++ does (merge.cc:107-109);
- `RulePieceStructure` (ruleaction.cc:7369-7607): `determineDatatype` (with
  `Varnode::getStructuredType`), `spanningRange`, `findReplaceZext`, `separateSymbol` and the
  tree rewrite of `applyOp`: each piece of the tree goes to its offset in the storage of the
  whole, a leaf elsewhere through a COPY, an inner varnode by a new varnode, and the pieces
  that are not address-tied are marked proto-partial (`Varnode::proto_partial`,
  `PcodeOp::concat_root`);
- `PieceNode` (op.cc:843-918) in merge.rs: `isLeaf`, `gatherPieces`, and `findRoot` through
  proto-partial varnodes;
- `Address::renormalize` for a tree in the join space (`renormalizeJoinAddress` with
  `JoinRecord::getEquivalentAddress`, translate.cc:145-175, 908-953; `Funcdata::renormalize_join`):
  a piece of a join is its register, a range over several pieces their join. A join with a
  constant piece fails loudly;
- the proto-partial flag in `mergeTestRequired` and `mergeTestBasic` (merge.cc:136-146, 261),
  `Merge::groupPartials` and `groupPartialRoot` (merge.cc:967-976, 1375-1405);
- `ActionMarkExplicit::baseExplicit` (coreaction.cc:3204-3231): the pieces of a partial root
  and the base of its PIECEs are explicit;
- `Funcdata::linkProtoPartial` (funcdata_varnode.cc:1197-1214), `HighVariable::setSymbol`'s
  group offset (variable.cc:258-260), `establishGroupSymbolOffset` (625-636) and the
  proto-partial preference of `compareName` (472-473).

Superseded: "Not ported: the CONCAT tree rewrite of `RulePieceStructure`" and "the partial
struct on its own" (the section above); "`groupPartials` fails loudly on a registered
proto-partial root" and "`stripType`" in the not-ported list of stage S7; "the CONCAT tree
rewrite of `piecestructure`" (R5 slice 4); "a piece of an array symbol as a data-type
(`getTypePartialStruct`)" ("Local symbols"); "a partial struct, array" in `finalizeDatatype`;
"a piece of a structure or array (`TypePartialStruct`...)" in the split rules, for arrays.

Still loud:
- type propagation into an array (`TypePointer::downChain`): its callers make a
  `TypePointerRel` of the parent (`propagateAddIn2Out`, typeop.cc), a data-type ghidra-rs does
  not have, with its own printing and pointer arithmetic. Not a small step; left as it is;
- a constant that is a piece of a structured symbol (`PrintC::pushConstant` of a partial
  struct: a cast to the type);
- `SplitDatatype::buildOutConcats` (the other maker of proto-partials), partial unions and
  enums, a piece of a structure, a join with a constant piece.

The first 3,128 functions of Hatred's module (the list and prelude of the section above:
`0x169e020`-`0x17562f0`, 34,932 flow overrides), `tools/decomp-status.sh`:

| | master f91fd31ed2 (desktop) | this branch on fe4043a333 (desktop) |
|---|---|---|
| ok | 3,009 | 3,113 |
| loud | 119 | 15 |
| timeout (120 s) | 0 | 0 |

Loud on master, by cause, and how many print now: CONCAT tree 83 (83), partial struct 21
(21), `downChain` 11 (0), heritage after dead-code removal in the stack space 2 (0), jump
table through a CALLOTHER 2 (0). The 15 still loud: 11 `downChain`, 2 heritage after dead-code removal, 2 CALLOTHER jump tables. The 3,009 ok on master are ok still.

Checks:
- against the reference (decomp_dbg with this branch's patch, `print C`), all 119 functions
  loud on master: the reference ran 119, identical 104 (every one that prints), loud 15 (the 15 above), silent 0. Run on the MacBook, after 0x16a27b0 and 0x16e38f0 gave the same bytes there as on the desktop, on both engines; with the branch before it was moved onto fe4043a333, whose changes touch no decompiler source;
- small ELF decompile corpus, 815 functions: identical 807 (was 790), loud 6 (was 23:
  5 `downChain`, 1 jump table through a CALLOTHER left), silent 0; the reference ran 813 (the 2 it cannot load decompile in ghidra-rs,
  with nothing to compare them to);
- Hatred camera corpus, 50 functions: identical 49 (was 47), loud 1 (was 3; `downChain` left), silent 0;
- `CORPORA=m8 tools/bars.sh` (desktop, reference rebuilt): 57 of 57 lines equal to the baseline (`x64-13b1dffecf.summary`); `simple`: pc-r, pc-t, pcc-r, pcc-t 194 / 194, pcd 198 / 200, pmd 199 / 200; `r5d-adc`: r5d, r5dt, r5dtlock 215 / 215, r5dtlocksv 202 / 215, all as before. No M500 check was run;
- `cargo test --release` 206 passed (two of them new: `partial_struct`, `join_ranges`),
  `cargo clippy --all-targets -- -D warnings` and `cargo fmt --check` clean.

Not measured: the other 6,866 functions of the module. Not looked for in the compared functions,
so possibly never run: a tree in the join space over more than two pieces, a zero extension
inside a tree (`findReplaceZext`), a piece of a symbol with an entry (`determineDatatype`'s
partial case: no symbol is linked before `ActionNameVars`), a stripped type cached before the
symbol was linked.

#### Java's C of Hatred, for the full decompile comparison (branch `hatred-java-run`, 2026-11-23)

`tools/hatred-java-run.sh [<list>]` is the Java side: one headless run of Ghidra 12.3 that
imports Hatred, auto-analyzes it, writes the facts (`ExportFacts.java`, as before) and Java's C
of every function of a list (`DecompileRef.java`), in the Linux container on the MacBook. The
project is kept (docker volume `hatred-java2`), so a later run with another list, or after a
failed script, skips the import and the analysis (`-process -noanalysis -readOnly`) and captures only
the addresses without a file. The script's header lists its variables and output files.
`DecompileRef.java` now also takes `@<file>` (a file of addresses) and `all` (every function
Java has), adds one line per function to `<output directory>.status` (`ok`, `failed`,
`timeout`, `nofunc`, and the milliseconds) and prints a progress line every 100 functions; a
result is written when its function is done, none is held. Its decompiler calls are unchanged
(no options sent, 60 s), so the C is that of `ghidra-diff.sh`'s Java side.

The run, on the MacBook (docker reachable: `colima start`), and the comparison with ghidra-rs,
which is `ghidra-diff.sh` with the run's output directory as `GHIDRA_REF` (every address of
the list has a file there, so it starts no Java) and Java's facts as `FACTS`:

```
PATH=/usr/local/bin:$PATH caffeinate -i rust/tools/hatred-java-run.sh <list>
H=~/ghidra-rs/rust/target/hatred-java2
GHIDRA_REF=$H BIN=~/hatred/Hatred-Linux-Shipping FACTS=$H/Hatred-Linux-Shipping.java.facts \
    PRELUDE=<Hatred's prelude> OUT=<directory> rust/tools/ghidra-diff.sh <list>
```

`<list>` is the same file on both sides (its name without `.txt` names `java/<list>/`). The
summary line and `<list>.miss` are `ghidra-diff.sh`'s: identical, loud, silent, and `java
failed` for a function Java did not finish. `PRELUDE` must be set: `ghidra-diff.sh` writes a
missing prelude at its default path, which is mercs2's.

Checked on the desktop without the container (`DOCKER=0`, Ghidra 12.3 of
`rust/target/java123`), on the small corpus's `t1` (non-PIE): the import run with `all` wrote
the facts and 32 functions (26 s); a second run with the 22 functions the prelude maps with
code took the kept project (13 s, 22 `ok`) and a third had nothing to do. The 22 files are
byte-identical (`cmp`) to those of the import run and to those of master's `DecompileRef.java`
given the 22 addresses on the same project. `ghidra-diff.sh` on them: java finished 22 / 22,
identical 12 (loud 10, silent 0). An address without a function is `nofunc` in the status
file and `java failed` in `ghidra-diff.sh`. Not run: the container path (colima was stopped;
on the MacBook the script was run only up to its docker check, bash 3.2), a timeout or a
failed function, and Hatred itself, neither the Java run nor `ghidra-diff.sh` with its 1.1 GB
facts (one `load facts` per function). The last Hatred run (import, analysis and facts) took
7,721 s and 26.0 GB; the decompile step adds to that, by how much is not measured. No function
list is in the repository: the list is whatever the ghidra-rs Hatred run used.

#### Namespaces and DWARF prototypes in the ELF facts (branch `fix-hatred-facts`, 2026-11-23)

What Java's decompiler gets for a C++ ELF, in three parts.

**Namespaces.** A `func` record is in the namespaces of Java's primary symbol (`<doc id>`,
`<parent id>`), and each namespace a record is in has its `ns` record (`getNamespacePath`):
- a function of the DWARF import: the DWARF name and its namespaces. The importer's label is
  made primary (DWARFFunction.java:389-395); the Demangler analyzer's name is then only one
  more symbol (AbstractDemanglerAnalyzer.java:157-177, DemangledFunction.java:466-474);
- a GNU name without DWARF: the demangler's namespaces (DemangledObject.createNamespace,
  DemangledObject.java:600-660; a name over 2,000 UTF-16 units cut by `ensureNameLength`). Its
  signature is still not written, so the record stays `underived ... function`;
- a thunk takes the namespaces of its end with its name.
The `label` record of a DWARF function has the DWARF name.

**Functions in a namespace on the facts path** (`load facts`). The loader no longer fails on
"the decompile of a function in a namespace". The declaration prints every namespace
(`emitSymbolScope` with no current scope); after it a name prints the scopes of its symbol from
the first one the function is not in (`Symbol::getResolutionDepth`,
`Scope::findDistinguishingScope`; `Facts::scoped_name`). Where the first printed name (the
symbol's own when no scope is printed) is the name of a namespace, function or data symbol in a
namespace between the function and the shared scope, Java prints one more scope
(`DecompileCallback.isNameUsed`): that fails loudly ("is hidden by a name of the namespace").
Two namespaces whose `ns` texts are equal fail loudly too. Not looked for, as before: a local
variable of that name.

**DWARF prototypes** (`dwarf/pcode.rs`, `dwarf::Func::storage`). The prototype the DWARF
import gives a function is written as Java's `HighFunction` sends it: each parameter a locked
`cat="0"` symbol with its data type and storage (`this` and `__return_storage_ptr__` as
auto-parameters), the locked return value, `__thiscall` locked or `unknown`, `voidlock`,
`dotdotdot`. Storage is the calling convention's (FORMAL commit mode,
`ParamListStandard.assignMap` with x86-64-gcc.cspec: `join_dual_class` up to 16 bytes from RDI,
RSI, RDX, RCX, R8, R9 and XMM0-7, else the stack from offset 8; the return from RAX/RDX and
XMM0/XMM1, a hidden return's pointer in RAX). The data types the prototypes name are `type`
records (`PcodeDataTypeManager.encodeType`: structures with bit fields, unions, enums,
typedefs, pointers, arrays, function definitions).

A function of the DWARF import stays `underived ... function` where the port does not know
what Java has (each with the reason in `dwarf::Func::storage`'s error):
- a parameter, or a variable below the function, with a `DW_AT_location`: Java may read a
  storage from it (STORAGE commit mode and custom storage, a `<name>_local` parameter spill, a
  local variable of the function). Location expressions and lists are not evaluated;
  Superseded (2026-11-24, branch `dwarf-params`): they are evaluated, see "DWARF parameter
  storage and local variables";
- no `this` and a parameter or a namespace: Java has the default model's name locked
  (`__stdcall`) on most of these and `unknown` on others. The setter is likely Java's Call
  Convention ID analyzer ("Archive prototypes applied" above), which decompiles the function;
  when it leaves `unknown` (`main`, libstdc++'s sort helpers) was not traced;
- a GNU name at the entry whose demangled name is not the DWARF name in a namespace
  (`isAlreadyDemangled` false): the demangler goes on to its calling convention and signature;
- a `.conflict` data type name anywhere under the prototype (the order Java resolves conflicts
  in is not kept everywhere), an array of no length, a bit field in a union, a built-in type
  without a core type, storage past the 500 bytes of the stack entry;
- a thunk (as before), and a DWARF function that takes a prototype of the archive or of the
  function it jumps to (Hatred's `SDL_ThreadID_REAL`, one `JMP pthread_self`: Java keeps the
  DWARF signature there; the rule was not traced).

Measured against Java 12.3 (MacBook; master 3a5ba15656 and the branch before master
fe4043a333, `fix-hatred-archives`, was merged into it, on the same inputs;
`tools/facts-diff.sh`, equal / Java's records):

| | record | master | branch |
|---|---|---|---|
| small corpus (14) | func | 209 / 1,112 | 213 / 1,112 |
| | ns | 0 / 295 | 189 / 295 |
| | type | 14 / 1,107 | 16 / 1,107 |
| | label | 4,645 / 7,315 | 4,648 / 7,315 |
| | silent func | 33 | 33, the same ones |
| Hatred | func | 5,623 / 180,433 | 6,108 / 180,433 |
| | ns | 0 / 44,952 | 22,814 / 44,952 (48 extra) |
| | type | 1 / 38,393 | 358 / 38,393 (3 different) |
| | label | 711,278 / 883,411 | 714,835 / 883,411 |
| | data | 492,177 / 2,076,322 | 496,778 / 2,076,322 |
| | `underived ... function` | 174,709 | 174,292 |
| | silent func | 236 | 236, the same ones |

Every other row of both tables is unchanged. Superseded: the `ns` rows 0 / 295 and 0 / 44,952
and the func rows of the tables above. The `ns` records still missing are those of data
symbols (vtables, statics) and of functions ghidra-rs names otherwise; the 48 extra were not
traced. `type` records are keyed by name in `facts-diff.sh`, so types of one name in two
categories show as different.

After master fe4043a333 (`fix-hatred-archives`) was merged into the branch, against that master
on the same inputs (MacBook): small corpus func 333 -> 339 / 1,112, ns 0 -> 190 / 295, type 65
-> 67, silent func 15 -> 15 (the same); Hatred func 9,098 -> 9,582 / 180,433, ns 0 -> 22,813 /
44,952 (48 extra), type 933 -> 1,282 / 38,393, `underived ... function` 171,269 -> 170,854,
silent func 131 -> 131 (the same), label and data as in the table. `cargo test --release` 206
passed; fmt and clippy clean; mercs2 M500 with Java facts 488 -> 489 identical of 499 (loud 11
-> 10, silent 0); `CORPORA=m8 tools/bars.sh` 57 lines equal to that master's; the PE facts of
mercs2 byte-identical (before the last ELF-only guard). Not obtained: `tools/elf64-decomp.sh`
(it stopped at the first binary in this worktree's setup on the MacBook; not diagnosed), and
the loud / silent split of the Hatred camera corpus (identical 46 of 50, the reference ran 50;
that master's own count was not taken).

The guards cost most of the possible gain,
 and what they hide is measured. With a location
list (`DW_FORM_data4`/`data8`) taken as "no storage", Hatred's equal `func` records were
63,423 (type 26,562), with 2,063 new silent ones: 1,691 the locked `__stdcall` of functions
without `this`, about 150 a `join` of more than 16 bytes (fixed: the rule's `maxsize`), about
95 `.conflict` names, and about 70 with Java's DWARF locals or `_local` spills. With the
entry looked up in `.debug_loc` (unit base `DW_AT_low_pc`, as DWARFLocationList.readV4) the
count fell to 9,283 and 21 of the locals were still silent, so that reading does not match
Java's and was dropped. Open: port DWARFVariable.readStorage with DWARFExpressionEvaluator
(which lists give a storage at the entry), and Call Convention ID on DWARF functions.
Superseded (2026-11-24, branch `dwarf-params`): readStorage and the evaluator are ported. The
`.debug_loc` reading above was right; what it missed is that Java's evaluator cannot read a
register's value (`DW_OP_reg<n>` and `DW_OP_breg<n>` throw, RBP excepted), so a parameter in a
register has no storage and the function is FORMAL. See "DWARF parameter storage and local
variables". Call Convention ID stays open.

mercs2 with Java's facts against Java's C (`ghidra-diff.sh m500`, MacBook, the desktop's
12.3 facts and captured C): identical 488 -> 489 of 499, loud 11 -> 10, silent 0 -> 0. A
function in a namespace now decompiles.

Not ported (item 4 of the task, not started): DWARF types on the prelude path (0x16e1920 still
prints `xunknown4` at `param_1+0x9c` there).

#### GCC exception tables ported (branch `hatred-facts`, 2026-11-24)

`gccexcept.rs` ports the part of GccExceptionAnalyzer (Java 12.3) the facts records of a
function body depend on: `.eh_frame`'s CIEs and FDEs (EhFrameSection.analyze, Cie.create,
FrameDescriptionEntry.create), each FDE's LSDA in `.gcc_except_table` (LSDAHeader,
LSDACallSiteTable, LSDAActionTable, LSDATypeTable, with the DWARF EH pointer decoders of
DwarfDecoderFactory), and for each call-site record with a landing pad the three comments of
processCallSiteRecord: PRE `try { // try from A to B has its CatchHandler @ L` at the call
site, POST `} // end try from A to B` at the code unit holding B, PRE `catch(type#N @ T, ...)
{ ... } // from try @ A with catch @ L` at the landing pad, merged as StringUtilities.mergeStrings
does. Java's quirks are kept: the type table base one byte low (LSDAHeader.java:154), the LSDA's
LPStart with its low four bits set, an action offset taken as a byte offset, `zLR` (an `L` at
index 1) not reading an LSDA, an omitted TType encoding read as a signed byte (never equal to
0xFF), and an exception anywhere in `.eh_frame` ending the analyzer before any comment.

The facts writer puts them into the function's `comments` record as DecompileCallback.
encodeComments does: the header, then the PRE (`user2`) and POST (`user3`) comments in the
body by address. The POST comment's code unit is the instruction of the finished analysis, or
the address itself where none holds it (Java's is the listing at the analyzer's turn, early in
auto-analysis). Where the port stops (an exception Java may not have), `--facts` warns and every
function's comments are `underived`, as every DWARF plate was before.

Not ported: the labels (`cie_`, `fde_`, `lsda_exception_table_`), data, plate and EOL comments
and references in the three sections, `.eh_frame_hdr` and `.debug_frame` (neither gives a call
site), the disassembly at each PcBegin, call site and landing pad, and the relocation check of
an `absptr` value's image base adjustment.

Measured against Java 12.3 (`tools/facts-diff.sh`, master 3e44b31ec6 -> branch, equal /
different / missing / extra):

| | record | master | branch |
|---|---|---|---|
| Hatred (MacBook) | comments | 345 / 0 / 148,608 / 0 | 57,971 / 0 / 90,982 / 0 |
| | `underived` records | 351,966 | 284,136 |
| | missing comments with no `underived` mark (silent) | 74 | 3 |
| | Java's 1,275 records with a `try {`: equal / `underived` / silent | 0 / 1,204 / 71 | 71 / 1,204 / 0 |
| small corpus (14, desktop) | comments | 251 / 0 / 395 / 0 | 292 / 2 / 352 / 0 |
| | `underived` records | 1,401 | 1,321 |

Every other row of both is unchanged. The 3 silent ones are functions ghidra-rs does not find
(0x3582f90, 0x35836e0, 0x3584210). The 2 different on the small corpus (0x106f30 of
cpp3-clang, 0x104816 of cpp3-gcc) are bodies that differ: ghidra-rs's runs on to the landing
pad, so its record has the `catch` comment Java's body leaves out (their `body` records were
different before). With every call site written whatever the bodies, the four cpp binaries give
all 546 of Java's `try`/`catch` PRE comments, 545 the same text; the other is merged after a
DWARF `Unresolved local var` comment (the DWARF importer runs first) in a function whose
comments are `underived` for its locals. Hatred: no exception ended the port (no warning).

Hatred's game module (the 4,024 functions of `hatred-decomp`'s `funcs.tsv`): `underived ...
comments` 4,024 -> 2,450 (1,475 of those where Java's record has the DWARF importer's
`Unresolved local var` comments, 960 for the other DWARF plate guards above, 15 with no Java
record); none of them has a `try` comment in Java. `underived ... function` stays on 4,022, so
none of the 4,024 loads with `load facts` yet. Its reasons (`GHIDRA_RS_UNDERIVED_DEBUG=1` prints
one `underived-function` line per function on stderr, `factsout::export`):

| reasons | functions |
|---|---|
| a parameter's DWARF location (STORAGE commit mode, parameter spill) | 3,824 |
| the same, and a body of one jump whose prototype is not known (`def` in the writer) | 146 |
| the same, and a call of a function with a variable argument list (FormatStringAnalyzer) | 27 |
| the calling convention of a function without `this` (parameters or a namespace) | 14 |
| the local variables of the DWARF import (commitLocalVariable) | 9 |
| the demangler's signature on a DWARF function (one with a `def` too) | 2 |

The location guard is checked first in `dwarf::Func::storage`, so the guards behind it on those
3,997 are not counted. Superseded (2026-11-24, branch `dwarf-params`): the location guard and
the `Unresolved local var` guard are gone; the current reasons are in "DWARF parameter storage
and local variables". `--facts` on the MacBook: 215 s for the writer, 7.10 GB maximum RSS.

Checks (desktop): `cargo test --release` 211 passed (master 210; the new one is
`gccexcept::tests::one_call_site`); `cargo fmt --check` and `cargo clippy --release
--all-targets -- -D warnings` clean; mercs2's PE facts byte-identical to master's (`cmp`; the
PE path has no exception tables); `CORPORA=m8 tools/bars.sh` 57 of 57 lines equal to
`baselines/master-3e44b31ec6.summary`. Not run: the other 76 checks of that baseline (M500,
switch, simple, r5d-adc) and `elf64-decomp.sh` (neither the prelude nor the decompiler
changed), the loader on a Hatred function.

#### DWARF parameter storage and local variables (branch `dwarf-params`, 2026-11-24)

What the DWARF importer (Java 12.3) reads from `DW_AT_location`, ported:
- `dwarf/expr.rs`: `DWARFExpression.read` and `toString(cu)` (DWARFExpression.java:59-80,
  169-208; the opcodes and operand types of DWARFExpressionOpCode.java:29-195) and
  `DWARFExpressionEvaluator.evaluate` (DWARFExpressionEvaluator.java:352-687) with the value
  reader the importer sets (`withStaticStackRegisterValues(null, -8)`, x86-64.dwarf's
  `stack_frame` RBP at -8 and `call_frame_cfa` 8). A register's value is not known to it:
  `DW_OP_reg<n>` and `DW_OP_breg<n>` of any register but RBP fail with a value exception, and
  `DW_OP_fbreg` falls through into `DW_OP_dup` (no `break`), as in Java.
- `read.rs`: `.debug_loc` lists (DWARFLocationList.readV4, the unit's `DW_AT_low_pc` as base).
- `dwarf/mod.rs`: the frame base at the entry (DWARFFunction.java:97-119), readParamStorage,
  readLocalVariableStorage and readStorage (DWARFVariable.java:258-375: the location holding the
  DWARF entry, `lexicalOffset` from the function's address, the terminal `DW_OP_deref` of a
  local), processFuncChildren with its lexical blocks and inlined subroutines
  (DWARFFunctionImporter.java:330-383), ParamSpillDWARFFunctionFixup (a parameter on the stack
  below 0 becomes a local `<name>_local` and loses its storage) and
  StorageVerificationDWARFFunctionFixup (STORAGE only when every parameter has a storage valid
  at the entry; no parameter, or one without storage, is FORMAL).
- the `Unresolved local var: <type> <name>@[<expression or ???>]` PRE comments of a local
  without storage, at the start of its block (DWARFUtil.appendComment: a comment the code unit
  has is not added again; AppendCommentCmd joins with a newline). `factsout` puts them before
  the exception analyzer's comments (`gccexcept::comments` merges into them), at the start of
  the instruction holding the address, as the POST comments.

So a function whose parameters are in registers (on Hatred nearly all) is FORMAL, and its
prototype is the calling convention's, which the facts already wrote. Still `underived ...
function`, with the reason: a parameter or local whose location is not ported (DWARF 5 lists,
`DW_OP_addrx`, a frame base not ported), a zero-length parameter (usesZeroLengthComponent;
cpp3-clang's `_Scanner` with a `std::locale` not yet defined has no locked prototype in Java at
all, not traced), STORAGE mode (custom storage), a local with a storage (commitLocalVariable,
a `_local` spill included; a static local goes to the globals and does not count). A comment
whose type has a `.conflict` twin, or whose location is not ported, makes the comments of the
body it falls in `underived`. A data type with a `.conflict` twin in a prototype is now
`underived` too (Hatred's FT_Face of 0x1cbd140 was `FT_Face.conflict` in Java). The plate
comment is no longer `underived` for a variable or label below the function.

`decomp/facts.rs`: `Architecture::createUnknownModel` for any model name of the facts the cspec
lacks (x86-64-gcc.cspec has no `__thiscall`, which the DWARF import sets): a copy of the default
model, compatible with it, its name printed in the declaration as the C++ does. Before, `load
facts` failed on every such function. Not changed: the printer prints `unknown` in a
declaration too, where the C++ does not (setPrintInDecl(false)); not seen in a check.

Measured against Java 12.3 (`tools/facts-diff.sh`, master 14ba1171b8 -> branch, equal /
different / missing / extra; MacBook, which matched the desktop before):

| | record | master | branch |
|---|---|---|---|
| Hatred | func | 9,595 / 170,824 / 14 / 2 | 110,178 / 70,241 / 14 / 2 (of 180,433) |
| | comments | 57,971 / 0 / 90,982 / 0 | 91,724 / 96 / 57,133 / 1 |
| | type | 1,282 / 3 / 37,108 / 4 | 27,748 / 204 / 10,441 / 4 |
| | `underived` records | 284,136 | 150,886 |
| | func different or missing, not `underived` (silent) | 133 | 284 |
| | comments different or missing, silent | 3 | 99 |
| small corpus (14) | func | 352 / 707 / 53 / 0 | 583 / 476 / 53 / 0 (of 1,112) |
| | comments | 292 / 2 / 352 / 0 | 524 / 6 / 116 / 0 |
| | type | 67 / 0 / 1,040 / 0 | 650 / 30 / 427 / 9 |
| | `underived` records | 1,321 | 873 |

Every other row (data, label, ns) is unchanged. The new silent records are not prototypes:
148 of the 151 new silent Hatred `func` records differ only in the stack locals of the
analysis (`local_<n>` sizes, cat -1), which the DWARF guard hid before; 3 (0x1a615a0,
0x1a616c0, 0x1a61760) have `this` as `TAsyncRunnable<void> *` where Java has
`TAsyncRunnable<int> *` (not traced). Of the 96 different comments, 80 have a type that is
`<name>.conflict` in Java and plain here (the import makes no `.conflict` twin there, so the
guard above does not see it), 16 a comment at another block address or a body that differs
(not traced). On the small corpus the 4 new different comments are bodies that differ (as
0x106f30 and 0x104816 before: 0x1012b0 of cpp2-clang, 0x11a720 of cpp3-clang, whose body
here stops at 0x11a791, 0x107b10 of cpp3-gcc's POST comment); the 30 different and 9 extra
`type` records were not looked at.

Hatred's game module (the 4,024 functions of `hatred-decomp`'s `funcs.tsv`): `underived ...
function` 4,022 -> 796, so 3,228 have a derived `func` record (all 19 of `AHatredDoor` equal to
Java's: `this` in RDI, `float DeltaSeconds` in XMM0 for `Tick`); different `func` records 4,022
-> 605, of which 3 silent (0x16ee820, 0x16f5cd0, 0x1760b00: stack locals only); `underived ...
comments` 2,450 -> 1,190, none silent. The reasons left (`GHIDRA_RS_UNDERIVED_DEBUG=1`):

| reasons | functions |
|---|---|
| one jump to another function, with the archive definition of what it jumps to | 140 |
| the calling convention of a function without `this` (parameters or a namespace) | 116 (+6 with an archive definition) |
| a data type that is not written | 27 |
| a call of a function with a variable argument list (FormatStringAnalyzer) | 27 |
| a demangled `_ZThn` thunk name that is no function | 11 |
| the demangler's signature on a DWARF function | 3 |
| a data type with a `.conflict` twin (`FDataType`) | 2 |
| others, one reason each | the rest of the 796 |

`load facts` with the branch's facts, one console per function (`decompile`, `print C`), on a
sample of 60 game functions (the 19 of `AHatredDoor` and 41 at random): none decompiles. Before,
all 19 door functions failed on their own `underived` record; now: a called function's record
is `underived` (24; for `Tick` 0x195a500), `restructure_varnode: a locked prototype with
parameters` not ported (16), the function's comments `underived` (5), a `type` record missing
for an id the prototype names (5: the `int32` typedef 0xd000000000000021 points at an
`int32` 0xd00000000000001f the facts do not write), a locked float return value needing an
extension (2), `isPrimitiveWhole` of a struct (1), a `join` storage (1). The full 4,024 were
not run.

`--facts` on Hatred (MacBook): 411 s, 7.83 GB maximum RSS (master: 396 s, 5.59 GB in the same
run, the two in parallel).

Checks (desktop): `cargo test --release` 212 passed (master 211; the new one is
`dwarf::expr::tests::locations`); `cargo fmt --check` and `cargo clippy --release --all-targets
-- -D warnings` clean; mercs2's PE facts byte-identical to master's (`cmp`); `CORPORA=m8
tools/bars.sh` 57 of 57 lines equal to `baselines/master-3e44b31ec6.summary`, silent 0 (run
before the `createUnknownModel` change, which only the facts path reads). Of the other 76
checks, 5 of M500 ran (equal to the baseline); the run was stopped (about 5 minutes a check).
Not run: `elf64-decomp.sh`, the 4,024 game functions in the console (60 sampled), Java's C
against the branch's (`ghidra-diff.sh`).

#### Round 2: locked parameters as symbols, precise `underived` marks (branch `dwarf-params`, 2026-11-24)

What changed for `load facts` (the C++ references are `Ghidra/Features/Decompiler/src/decompile/cpp/`):
- A locked prototype's parameters are symbols of the local scope, as `ProtoStoreSymbol::setInput`
  makes them (fspec.cc:3143-3179): category 0 at their index, type-locked, name-locked as the
  record says, valid everywhere where the scope owns the storage and else at the restricted use
  point before the entry, then `FuncProto::updateThisPointer` (fspec.cc:3567-3579)
  (`locked::param_symbols`, at `ActionPrototypeTypes`). So `ActionNameVars` links the input
  varnodes to them (the guard there is gone) and `ScopeLocal::restructureVarnode`
  (varmap.cc:1389-1418) runs for a locked prototype whose parameters are all in registers:
  such a symbol is in no stack range, so `gatherSymbols` (varmap.cc:1170-1186) and
  `fakeInputSymbols` (varmap.cc:1527-1580) see nothing of it. A parameter on the stack or in a
  join still fails there (`a locked prototype with a parameter on the stack or in a join`).
  Superseded: "a locked prototype with parameters" in "Local symbols" and in `mapstate.rs`.
- `print C` declares a locked prototype (`PrintC::emitPrototypeOutput`, `emitPrototypeInputs`
  with `...`, printc.cc:2303-2336) and leaves out the model name `unknown`
  (`Architecture::createUnknownModel`, architecture.cc:1160-1168). Superseded: "Not changed: the
  printer prints `unknown` in a declaration too" above.
- A `join` storage in a record (`piece<n>="space:offset:size"`) is read; a locked join parameter
  of a call still fails later (`a locked join parameter of a call`).

What changed in `analyze --facts`:
- Two more `underived` words, which only the function's own decompile reads (`Facts::function`
  with `own`): `locals` (the DWARF import's committed locals, `commitLocalVariable`; and the stack
  variables below) and `overrides` (a call of a function with a variable argument list,
  FormatStringAnalyzer). Before, both made the whole `function` record `underived`, so every
  caller of such a function failed too. A caller reads only the prototype.
- A non-core built-in type under a typedef (Hatred's `int32` -> `sdword`) is written in full, as
  Java does (`<type name="sdword" metatype="int" size="4">`); before, its record was missing and
  `load facts` failed on `no data-type with id 0xd00000000000001f`. A record that refers to a
  record that is not written, directly or not, now makes every prototype naming it `underived`
  (`bad_types`); before, only the first function to reach it was.
- New precise marks for the silent groups of round 1: the stack variables of a function whose
  variables change with the stack references a jump-table case's walk makes past code already
  walked (`locals`; Java's walk of 0x16ee820 makes none there, VarnodeContext.flowStart not
  traced; ELF only: on mercs2 3 of the 9 such functions have Java's variables, so it is not
  Java's rule); a method whose `this` points to a class of another name (`TAsyncRunnable<int>::Run`
  with `TAsyncRunnable<void> *`); a typedef of a pointer to a structure (FreeType's `FT_Module`,
  `FT_Face`: Java has a `.conflict` twin the import does not make) in a prototype's own types,
  a plate or an `Unresolved local var` comment; a local of a subroutine inlined more than once in
  the function (Java's comment is at another instance, 0x1af9650).

Measured against Java 12.3 (`tools/facts-diff.sh`, MacBook; master 14ba1171b8, round 1
9d417db2f3, this round; equal / different / missing / extra; silent: different or missing with
no `underived` record covering it, `function`, `locals` or `overrides` for `func`):

| | record | master | round 1 | round 2 |
|---|---|---|---|---|
| Hatred | func | 9,595 / 170,824 / 14 / 2 | 110,178 / 70,241 / 14 / 2 | 109,800 / 70,619 / 14 / 2 |
| | comments | 57,971 / 0 / 90,982 / 0 | 91,724 / 96 / 57,133 / 1 | 84,469 / 4 / 64,480 / 1 |
| | type | 1,282 / 3 / 37,108 / 4 | 27,748 / 204 / 10,441 / 4 | 28,083 / 211 / 10,099 / 4 |
| | `underived` records | 284,136 | 150,886 | 176,867 |
| | silent func | 133 | 284 (151 new) | 227 (94 new) |
| | silent comments | 3 | 99 (96 new) | 7 (4 new) |
| small corpus (14) | func | 352 / 707 / 53 / 0 | 583 / 476 / 53 / 0 | 583 / 476 / 53 / 0 |
| | comments | 292 / 2 / 352 / 0 | 524 / 6 / 116 / 0 | 443 / 4 / 199 / 0 |
| | type | 67 / 0 / 1,040 / 0 | 650 / 30 / 427 / 9 | 703 / 30 / 374 / 9 |
| | `underived` records | 1,321 | 873 | 960 |
| | new silent (func, comments) | | 1, 4 | 1, 2 |

Not reached: no new silent record. Left: 94 Hatred `func` records that differ from Java's only in
the stack variables of the analysis (`local_*`: variables only one side has, or of another
size; several patterns, none traced; the DWARF guard hid them on master), 4 Hatred comments
records (0x1b25cd0, 0x2cbc6c0: a comment one side has; 0x2c15350, 0x2c158b0: other locals in
the comment), and on the small corpus cpp3-gcc's 0x110820 (stack variables and a comment) and
cpp3-clang's 0x11a720 (a comment). The comments marks cost equal records: 91,724 -> 84,469
equal comments on Hatred. Hatred's game module: `underived ... function` 796 -> 2,958, of which
2,215 for `a data type that is not written`: the prototype names a record that refers, directly
or not, to one that is not written (`bad_types`). In round 1 those records were written as
derived and failed at load (`no data-type with id`); which unwritten types are behind them was
not traced.
`--facts` on Hatred (MacBook): 889 s, 4.18 GB maximum RSS, in parallel with a `load facts` run.

Checks (desktop): `cargo test --release` 212 passed; `cargo fmt --check` and `cargo clippy
--release --all-targets -- -D warnings` clean; mercs2's PE facts byte-identical to master's
(`cmp`); `CORPORA=m8 tools/bars.sh` 57 of 57 lines equal to `baselines/master-3e44b31ec6.summary`.
The full `tools/bars.sh` (133 checks, all corpora) was started under `heavy-run` with the
branch's binary (`rust/target/dp2/bars-full/summary.out`); its first 74 lines are equal to the
baseline, the rest had not finished when this was written. The 4,024 game functions with
`load facts` and Java's C of 20 of them were running on the MacBook, not measured here.

#### Round 3: getStackOpIndex, PIC switch misses loud (branch `dwarf-params`, 2026-11-24)

- `factsout::stack_op_index` ports NewFunctionStackAnalysisCmd.getStackOpIndex
  (NewFunctionStackAnalysisCmd.java:548-590): a LOAD or STORE through a stack address makes a
  reference only on the first operand whose objects (`Instruction.getOpObjects`, the Function ID
  port of `sleigh::fid_parts`) add up to the address, a register counting only where it held a
  stack address when the LOAD or STORE ran (`Fold::stack_regs`), a scalar signed; and the POP
  `*BP` exception. An operand that has a stack reference already adds to the variable at that
  reference's offset (defineFuncVariable). Superseded: the ponytail "an operand names the
  address is not the slot a PUSH, POP or CALL uses itself" of `Exporter::locals`. Hatred's
  0x199b200 (`MOV [RBX + RAX*4],0` with RAX -1) no longer makes `local_83c`.
- A function holding a PIC switch jump whose table the pattern did not find
  (`pic_switch_misses`; Java recovers it with DecompilerSwitchAnalyzer) has `underived ...
  locals` and `underived ... comments`: its body, so its stack variables and the blocks its
  comments fall in, are not known (cpp3-gcc 0x110820; cpp3-clang 0x11a720, whose computed jump is not counted a miss, stays silent).
- `GHIDRA_RS_UNDERIVED_DEBUG` names the record not written behind "a data type that is not
  written". On Hatred (all functions): 17,471 such reasons are `the data type name <x>` (a type
  with a `.conflict` twin, which the import does not name in Java's order), 21 `the built-in data
  type float4`, 12 `a bit field in a union`. So the 2,215 game prototypes of round 2 are, by
  that count, mostly the `.conflict` naming (DataTypeManagerDB.resolve order), not a small port.

Measured against Java 12.3 (`tools/facts-diff.sh`, MacBook; master 14ba1171b8 again, round 2
61b2a3a1a7 again, this round; silent: different or missing with no covering `underived`):

| | record | master | round 2 | round 3 |
|---|---|---|---|---|
| Hatred | func equal | 9,595 | 109,800 | 109,931 |
| | comments equal | 57,971 | 84,469 | 84,468 |
| | silent func | 133 | 227 (94 new) | 121 (59 new) |
| | silent comments | 3 | 7 (4 new) | 7 (4 new) |
| mercs2 (PE, Java's `ref123/mercs2.facts`) | func equal | 22,892 | not run | 23,191 |
| | silent func | 21,921 | not run | 21,622 (15 new) |

Not reached: no new silent record, and mercs2's PE facts are no longer byte-identical to
master's (446 `func` records change: 299 more equal to Java, 15 newly different). The 15 are
`local_<n>` of 4 bytes where Java has 1 (an LEA's): after a `_chkstk` call (0x1b10260) the walk's
ESP is not Java's, and a PUSH of the LEA's register lands on that address. Of the 59 new silent
Hatred `func` records, 54 were among round 2's 94 (stack variables larger than Java's, as
`local_9d8` 40 bytes where Java has 32; or only one side has them); not traced. The 4 comments:
0x1b25cd0 and 0x2cbc6c0 have a body other than Java's (older cause); 0x2c15350 and 0x2c158b0
write `Unresolved local var: ... NumFrames` at 0x2c153fd (a lexical block of an inlined
subroutine, location lists not covering the entry) where Java writes none; why was not traced.
Checks (desktop, before the user's rule of 2026-11-24 that all compute runs on the MacBook):
`cargo test --release` 212 passed and `cargo clippy --release --all-targets -- -D warnings` clean
before the new test `stack_op_index_adds_up_registers_and_scalars`, which passes alone; `cargo fmt
--check` clean. Small corpus (MacBook): silent 56 -> 57 against master, the new one cpp3-clang
0x11a720's comments (cpp3-gcc 0x110820 is loud now). Not run on this round: `CORPORA=m8
tools/bars.sh`, the full bars, `elf64-decomp.sh`.

#### Round 4: call fixups in the stack walk (branch `dwarf-params`, 2026-11-24)

- The stack analysis's walk runs a function's call fixup in place of a direct call to it, as
  SymbolicPropogator does (`checkForCallFixup`, `injectPcode`): the fixup's p-code from the
  compiler spec (`decomp::callfixup_pcode`, the decompiler's snippet compiler) replaces the
  CALL op, and the call has none of its side effects. `__chkstk` / `__alloca_probe` run
  `ESP = ESP + 4 - EAX`, so the stack pointer after the call is the entry's minus the frame
  size in EAX. `factsout::call_fixups` gives the walk the fixup of each function by its name
  (CallFixupAnalyzer.getCallFixupNameForFunction: without a `libID_conflict_` prefix, else
  with `_` or `__` before it); the facts' `<inject>` uses the same rule. Only the facts' walks
  run fixups (`Analysis::swap_call_fixups`, as the call purges); the analysis's own constant
  propagation does not, and a call through a pointer runs none.
- A PIC switch `MOVSXD r,[base + index*4]` with a base of RBP or R13 (encoded with a zero 8-bit
  displacement) is the pattern's form too, so its table is found or the jump is counted a miss
  (cpp3-clang 0x11a7e2).

Measured on the MacBook, master b0738cc3a7 (code as 14ba1171b8) and this round, each built and
run the same way: Hatred and the small corpus with `tools/facts-diff.sh` against Java 12.3;
mercs2 with `analyze --facts` (Function ID databases in `GHIDRA_RS_FID`, no `--protos`) and
`tools/facts-diff.sh` against `ref123/mercs2.facts`. Round 3's mercs2 numbers ran without the
Function ID databases (`function id: 0 functions named`), so `__chkstk` had no name and no
fixup there; Superseded: its 22,892 / 23,191 and "15 newly different" as the measure.

| | record | master | round 4 |
|---|---|---|---|
| Hatred | func equal | 9,595 | 109,932 |
| | silent func | 133 | 118 (59 new) |
| | silent comments | 3 | 7 (4 new) |
| small corpus | silent | 56 | 56 (0 new) |
| mercs2 (PE) | func equal | 23,543 | 24,072 |
| | records equal on master, not on round 4 | - | 3 `label` |

The 15 `_chkstk` records of round 3 equal Java's (0x1b10260 and the rest), and no `func`
record equal on master differs. Not reached: 3 `label` records equal on master differ: extra
`LAB_023c59d9` and `LAB_023c59db` (the return address of a `__chkstk` call at 0x23c59d4) and
missing `LAB_01f3cb1f` (the return address of a call at 0x1f3cb1a); not traced. The 59 new
silent Hatred `func` records and the 4 comments are round 3's (same addresses); not traced:
the stack variables differ in size from Java's (`local_f0` 40 bytes, Java 32, at 0x1a8eee0,
where a `MOVUPS [RSP+0x70]` store makes ours longer), and the `Unresolved local var` of
0x2c153fd. The func equal of 9,595 on master is no other scope: master writes no DWARF
parameters, so 170,824 of its 180,433 `func` records differ from Java's.

#### Round 5: Constant Propagation runs only the call fixups installed before it (branch `dwarf-params`, 2026-11-24)

- A call fixup is installed when its function gets its name (the Call-Fixup Installer, priority
  301), and a name from Function ID comes at 799, after Constant Propagation (596). So the
  facts' Constant Propagation walk (the LOAD and STORE references through registers) runs only
  the fixups of functions named without Function ID; the Stack analyzer's walk (903, the
  `stack_and` walk) runs every one. `factsout::call_fixups` marks each fixup with that
  (`analysis::Fixups`). Superseded: round 4's "only the facts' walks run fixups" for the
  Constant Propagation walk. On mercs2, `__chkstk` is named by Function ID: with its fixup the
  walk kept the CALL's pushed return address in the frame (`ESP = ESP + 4 - EAX` leaves it
  above ESP), so `MOV EAX,[EBP-4]; MOVZX ECX,word ptr [EAX+2]` at 0x23c5ba1 read it and made
  `LAB_023c59d9` and `LAB_023c59db`; Java's Constant Propagation ran before `__chkstk` had a name.
  ELF has no Function ID names, so its facts do not change.

Measured on the MacBook against Java 12.3 as round 4 (`tools/facts-diff.sh`; mercs2 with
`GHIDRA_RS_FID`):

| | record | master | round 4 | round 5 |
|---|---|---|---|---|
| mercs2 (PE) | func equal | 23,543 | 24,072 | 24,072 |
| | records equal on master, not on the branch | - | 3 `label` | 0 |
| Hatred | func equal | 9,595 | 109,932 | 109,932 |
| | silent func | 133 | 118 (59 new) | 118 (59 new, same list) |
| | silent comments | 3 | 7 (4 new) | 7 (4 new, same) |

Not reached: zero new silent. The 59 Hatred `func` records, by how our stack variables differ
from Java's: a variable larger than Java's, ours merged over a 16-byte `MOVUPS`/`MOVAPS` store
that Java's variables do not cover (`local_f0` 40 / 32 and the like, 11); one larger variable
over several of Java's or past Java's end (`local_1b8` 104 where Java has five; `local_88` 32
where Java has 20; 13); an LEA's 1-byte variable and a 16-byte one next to it where Java has
one of 20 bytes (`local_58` at 0x21e5220, 7); variables only one side has (21); other sizes
and splits (7). At 0x21e5220 the walk is straight-line code and its references are
in Java's order; Java's 20 bytes at -0x58 come out of `accumulateVariable` only if the
`MOVUPS xmmword ptr [RSP+0x144],XMM0` store (after `XORPS XMM0,XMM0`) makes no stack reference
there, while the `MOVAPS [RSP+0x140]` four instructions on does; why was not traced. The 4
comments: 0x2c15350 and 0x2c158b0 write `Unresolved local var` for `NumFrames` and
`FramesPerSecond` at 0x2c153fd (and its twin), the innermost lexical block of the last child of
the function, an inlined `ProcessKeyToFrameTable` (inlined 3 times in its compile unit); their
location lists do not cover the entry, so Java's processFuncChildren should write the comment,
and Java's function has its DWARF parameters, so no exception stopped it; why it writes none was
not traced. 0x1b25cd0 and 0x2cbc6c0 are the older body difference.
Checks (MacBook): `cargo fmt --check` and `cargo clippy --release --all-targets -- -D warnings`
clean, `cargo test --release` 213 passed. Not run: the small corpus, `CORPORA=m8
tools/bars.sh`, `elf64-decomp.sh` and the full bars (the fixup change does not reach ELF).
Superseded (round 6): "why was not traced" for 0x21e5220's `local_58` and the 0x2c153fd comments; see below.

#### Round 6: Java traced live; CMOVcc flows, getVariablesIntersecting (branch `dwarf-params`, 2026-11-24)

How Java was traced: a throwaway copy of the Ghidra 12.3 install (`rust/target/r6/ghidra` on the
MacBook) with print lines in copies of `NewFunctionStackAnalysisCmd` and `DWARFFunctionImporter`
compiled into its `Ghidra/patch` (loaded before the release jars), and a script run on the kept
Hatred project (`-process -noanalysis -readOnly`, so nothing is saved) that clears the stack
references and default stack variables of the 59 functions and runs the command again, then runs
the DWARF import again. The rerun gives Java's facts' stack variables for all 59 (byte for byte
by name and size), so the walk alone explains them. Nothing of this is in the repository.

- A CBRANCH to the next instruction (CMOVcc's `if (!cc) goto inst_next`) saves the state at the
  CBRANCH as a flow to the next instruction (SymbolicPropogator.applyPcode, condition not known
  true); taken later, that flow runs through visited code, so up to MAX_EXTRA_INSTRUCTION_FLOW
  instructions are walked again (`Analysis::flow_walk`, `Fold::to_next`). At 0x21e5220 the
  `CMOVLE` at 0x21e5233 walks 0x21e5236-0x21e52a0 again; the second `MOVAPS [RSP+0x140]` then
  meets the LEA's 1-byte variable and the `MOVUPS` 16-byte one: 20 bytes.
- getVariablesIntersecting moves its probe by the length of the variable it finds, from the
  probe and not from the variable's end, so a variable past it is missed and the variables can
  overlap; addStackLocalVariables then leaves out one that overlaps one added before it
  (0x19f14c0 `local_9d8` 32 bytes, no `local_9c0`).
- defineFuncVariable makes no stack reference on an operand whose primary reference is another
  kind: an instruction with a memory reference from the walks (`Ins::rw`) gets none. Partial:
  `rw` has the WRITE references through a folded address and direct memory operands, not READs
  through a register (0x1d461d0 `MOVUPS XMM0,[RCX]`, RCX 0x51ce518 past a CMOVNZ, stays). Superseded (round 7): a
  READ of any size through a folded address is in `rw` (`Ins::load`); 0x1d46180 equals Java's.
- `underived ... locals` (ELF) also where an operand adds a register the walk does not know to
  a stack address and makes no reference (`[RSP + R8*4 + 0x10]`): Java's VarnodeContext knows
  such a loop counter on some paths (0x1bb8950, 0x25c8930). 1,102 functions get the mark; 311 of
  their `func` records equal Java's.
- The DWARF importer does write `Unresolved local var` for NumFrames at 0x2c153fd (the trace
  prints it). The comment is lost later: 0x2c153e0 is `CALL AssertFailed`, which Java learns does
  not return after the import; Find Non-Returning Functions repairs the flow after the call
  (ClearFlowAndRepairCmd, `ClearOptions(true)`: comments too) and the code is disassembled again
  from another reference. The kept project has no comment stored at any address of
  0x2c153e0-0x2c15440. A DWARF comment in code that flows from the fallthrough of a call to a
  non-returning function is now not derived (`underived ... comments`): 23 functions, 21 of their
  comments records equal Java's.

Measured on the MacBook against Java 12.3 as round 5 (`tools/facts-diff.sh`, silent lists by
`target/dp4/silent.sh`, master's `target/dp4/silent-m.txt`):

| | record | master | round 5 | round 6 |
|---|---|---|---|---|
| Hatred | func equal | 9,595 | 109,932 | 110,007 |
| | comments equal | 57,971 | 84,468 | 84,447 |
| | new silent func | - | 59 | 8 |
| | new silent comments | - | 4 | 2 |
| mercs2 (PE) | func equal | 23,543 | 24,072 | 24,072 |
| | records equal on master, not on the branch | - | 0 | 0 |
| small corpus | silent | 56 | not run | 56 |

Not reached: zero new silent. The 8 `func`: 0x1d46180 (a READ reference through RCX, above),
0x190bc60, 0x1a180d0, 0x1d00a00, 0x24163f0, 0x2997830, 0x2b43cf0, 0x2b7ea80, not traced this
round (the stack-reference sequences of 0x1d00a00 and 0x2b7ea80 equal Java's, so the cause is in
defineFuncVariable or the adding, as 0x1d46180's). The 2 comments are 0x1b25cd0 and 0x2cbc6c0
(older body difference). The small corpus was compared by count only (master's per-record lists
were not kept). Checks (MacBook): `cargo fmt --check`, `cargo clippy --release --all-targets --
-D warnings` clean, `cargo test --release` 213 passed. Not run: `CORPORA=m8 tools/bars.sh`,
`elf64-decomp.sh`, the full bars.

#### Round 7: READ references of any LOAD size; three changes dropped (branch `dwarf-params`, 2026-11-25)

Four changes to the walk were tried together: (1) a READ reference for a LOAD of any size
through a folded address, (2) memory values kept with their size, (3) comparisons and boolean
operations folded on constants, (4) a branch whose condition is known true walked first. All
four gave Hatred 7 new silent `func` records (5 of round 6's 8 fixed, 3 new: 0x263c5d0,
0x2932fe0, 0x29961c0) and broke the mercs2 gate. Each was then built on top of the ones before
it and measured on mercs2's PE facts (`target/dp4/pe.sh`, records not equal to Java's that are
not in master's list of such records):

| built | records newly in the list | of them equal on master |
|---|---|---|
| 1 | 25 | 17 |
| 1, 2 | 42 | not split |
| 1, 2, 3 | 42 | not split |
| 1, 2, 3, 4 | 229 | 198 |

Kept, in a smaller form: change 1. SymbolicPropogator's LOAD case makes its READ reference
with the size of the output, whatever it is (`addLoadStoreReference`, SymbolicPropogator.java:
927-947). `Analysis::decode_ops` now records a LOAD of another size than a pointer's through a
folded address in the instruction's `rw` (the memory references defineFuncVariable asks
about) and its size in `Ins::load`. This closes round 6's "Partial": the READ through a
register (0x1d461d0 `MOVUPS XMM0,[RCX]`) is there, and the instruction gets no stack reference.

Not kept from change 1: the same reference as a data reference of the listing (`Ins::refs`:
labels, data, the Reference analyzer's targets). On mercs2 it made 17 records wrong that are
equal on master, all traced to five places where the reference changes what the facts' Reference
analyzer makes: the strings at 0xb642d4, 0xb642e4 and 0xb642ec (a byte LOAD of the second
character at 0x9bbdb3 and the like stops the 13-byte string; the Strings analyzer then makes it
16 bytes with its padding), a pointer made at 0xb604a9 (Java: `undefined1`) and the label it
gives 0x4e494f, the table slot 0x616518 (a byte LOAD of 0x61651b at 0x6159cd stops the pointer)
and `DAT_00400200` inside Java's IMAGE_NT_HEADERS32 (a 2-byte LOAD at 0x9ee748). In Java these
references are either not there when the Reference analyzer looks or not made; which, and why,
was not traced (it needs a trace of Java's analysis of mercs2). The other 8 of the 25 are data
Java has and master does not: the record is there now, without the size (`undefined` where Java
has `undefined1` or `undefined2`). Writing the size and the data from the facts' side was
tried and changed no record (the facts of both builds are byte-identical), so it is not in.

Dropped, with the reason:

- Change 4 (known-true branches first, SymbolicPropogator.java:1160-1250): 187 more mercs2
  records, 31 `func` among them, and the 3 new silent Hatred functions. Java's order depends on
  `evaluator.followFalseConditionalBranches()` and on what `VarnodeContext.getConstant` gives
  for the condition; the port took one case of it. Not traced further.
- Change 2 (sized memory values, VarnodeContext.getMemoryValue): 17 more mercs2 records. Its
  own note says the bytes of several stores are not assembled as Java does. Not traced further.
- Change 3 (folded comparisons): no record changes without change 4, which is its only reader.

The three are not in the repository; their patches are kept outside it (`rust/target/r7-patches/
c2.patch`, `c3.patch`, `c4.patch` on the desktop, each against the one before, `c1.patch` the
full change 1).

Measured on the MacBook against Java 12.3 as round 6:

| | record | master | round 6 | round 7 |
|---|---|---|---|---|
| Hatred | func equal | 9,595 | 110,007 | 110,010 |
| | comments equal | 57,971 | 84,447 | 84,447 |
| | new silent func | - | 8 | 6 |
| | new silent comments | - | 2 | 2 |
| mercs2 (PE) | func equal | 23,543 | 24,072 | 24,072 |
| | records equal on master, not on the branch | - | 0 | 0 |


Not reached: zero new silent. The 6 `func`: 0x190bc60, 0x1a180d0, 0x24163f0, 0x2997830,
0x2b43cf0, 0x2b7ea80, not traced this round (0x1d46180 and 0x1d00a00 of round 6's 8 equal
Java's now). The 2 comments are 0x1b25cd0 and 0x2cbc6c0, as in round 6. Small corpus: 56 silent
records, as master. Checks (MacBook, the machine shared with another full pass): `cargo fmt
--check` and `cargo clippy --release --all-targets -- -D warnings` clean, `cargo test --release`
213 passed; `CORPORA=m8 tools/bars.sh`: the 57 lines equal those of
`target/baselines/master-3e44b31ec6.summary`; `elf64-decomp.sh`'s loop over the 14 binaries
already built on the MacBook (`target/x64f/elf64/bin`): 817 functions, the reference ran 815,
identical 809, the counts of master in "ELF64 analysis". The full bars were not run again as a
whole: the pass of 61b2a3a1a7 (round 2, the last commit that changes what the decompiler
prints) gave 124 of the 133 lines, each equal to the baseline's, and since then the decompiler
only gained `decomp::callfixup_pcode`, which the analysis calls; the mercs2 prelude the bars
read is the one this build writes (`cksum` 304429596). The nine pairs that pass did not reach
(`pc-r pc-t pcc-r pcc-t pcd pmd` on `simple`, `pcc-r pcc-t swfsc-t` on `switch`) are run for
the merge. No unit test was added for the new branch of `decode_ops` (the tests have no
fixture with a folded-address LOAD); its check is Hatred's 0x1d46180 in the facts comparison.
## MIPS32 and the PSP (MIPS-1, branch `mips-m1`, 2026-11-26)

The first MIPS target is SOCOM U.S. Navy SEALs Fireteam Bravo's `BOOT.BIN` (`../DESIGN.md`,
2026-11-26; the plan and the later milestones are in `../docs/plans/mips-psp.md`). MIPS-1 is
`disasm` only: load, relocate, disassemble, p-code. `analyze` and the decompiler do not take
MIPS. Superseded (2026-11-26, branch `mips-m3`): `analyze` takes a PSP PRX, see "Function
discovery on MIPS (MIPS-3)"; the decompiler still does not.

### The PRX loader (`psp.rs`)

A PSP PRX is an ELF32 little-endian MIPS file of type 0xffa0, linked at address 0 and
relocated when loaded. `psp::load`:

1. lays the `PT_LOAD` segments out at their link addresses in one block (memory past a
   segment's file bytes, `.bss`, is zero);
2. applies every section of type 0x700000a0 (`SHT_MIPS_PSPREL`) that belongs to a loaded
   section, for the load base;
3. lists the loaded sections at their loaded addresses, for `disasm`.

The load base is `psp::DEFAULT_BASE`, 0x08804000. Ghidra has no rule to port here:
`MIPS_ElfExtension.java` names the file type and the section type, applies nothing
("relocations not supported") and leaves the image at its link address. The base is the one
the ghidra-allegrex loader's README recommends for games; PPSSPP allocates the module in user
memory (from 0x08800000). No option changes it yet.

A relocation entry is an `Elf32_Rel`. Its `r_info` holds the type (bits 0-7), the program
header the offset is relative to (bits 8-15) and the program header whose loaded address is
added (bits 16-23); the words in the file are relative to that second segment's start. The
rules follow PPSSPP's `ElfReader::LoadRelocations` (read 2026-11-26):

| type | rule |
|---|---|
| `R_MIPS_32` (2) | the word plus the segment's loaded address |
| `R_MIPS_26` (4) | the 26-bit jump field plus that address / 4 |
| `R_MIPS_HI16` (5) | with the next `R_MIPS_LO16` entry of its section: the high half of (high << 16) + signed low + address, rounded for the signed low half |
| `R_MIPS_LO16` (6) | the low 16 bits plus the address |
| `R_MIPS_NONE` (0) | nothing |

Every word is read before any is changed (PPSSPP's two passes). Nothing is skipped silently:
an entry of any other type is counted under "unknown type" and left as it is (`R_MIPS_16` and
`R_MIPS_GPREL16`, which PPSSPP handles, are among them: no file to check them on yet), as are
a `HI16` with no `LO16` after it, an entry outside the image, and the entries of standard
`SHT_REL`/`SHT_RELA` sections (they need symbols; not applied). Type B relocations (program
header 0x700000a1) fail the load.

On `BOOT.BIN` (4,708,752 bytes; 9 relocation sections):

| | entries |
|---|---|
| `R_MIPS_32` | 12,661 |
| `R_MIPS_26` | 44,782 |
| `R_MIPS_HI16` | 22,821 |
| `R_MIPS_LO16` | 27,496 |
| applied | 107,760 |
| unknown type, `HI16` without `LO16`, outside the image, standard REL/RELA | 0 each |

95,099 of `.text`'s 868,720 words change (its 26, HI16 and LO16 entries).

### Delay slots (`sleigh.rs`)

A MIPS branch executes the instruction after it first. As in the C++ engine
(`Sleigh::oneInstruction`, `SleighBuilder::delaySlot`): `decode` returns the branch's own
length (4), also decodes the delay slot instruction from the bytes after it, and `pcode` puts
that instruction's whole p-code where the branch's template says, with `inst_next` past the
slot (`Parse::fall` is the length with the slot). The sweep then decodes the slot instruction
again on its own, as Ghidra's listing shows it. A branch whose slot does not decode, or is
itself a branch with a slot, has no p-code, as in the C++ engine.

### Against the C++ engine (2026-11-26)

`tools/sleigh_ref.cc` takes `mips32le.sla` (the context defaults of `mips32.pspec`; a word
that does not decode is skipped whole, as in `disasm`). The whole relocated `.text` of
`BOOT.BIN` at 0x08804000, linear sweep, text and p-code (the raw file is rebuilt from the
bytes column, so both decode the same relocated bytes). Superseded (2026-11-26, branch
`mips-m2`): `disasm` now takes `allegrex.sla` for a PRX, so the stock numbers below need
`--sla ../../../Ghidra/Processors/MIPS/data/languages/mips32le.sla` on the `disasm` line; the
current check and numbers are in "Allegrex (MIPS-2)". The stock run was repeated on 2026-11-26
for the mnemonics only (2,436 words not decodable, as below), not for p-code.

```sh
cd target && mkdir -p mips-check && cd mips-check
../release/ghidra-rs disasm BOOT.BIN --addr 8804000 --count 1000000000 --pcode > rs-full.txt
grep '^0' rs-full.txt | cut -c19-49 | sed 's/(bad.*//' | xxd -r -p > text.raw
../sleigh_ref ../../../Ghidra/Processors/MIPS/data/languages/mips32le.sla text.raw 8804000 pcode > ref.txt
sed -E 's/^([0-9a-f]{16})  ([0-9a-f]{2} ?)+ +/\1  /; s/^([0-9a-f]{16})  \(bad.*/\1  (bad)/; s/    <no p-code.*/    <no p-code>/' rs-full.txt > rs.txt
cmp rs.txt ref.txt
```

Superseded (2026-11-26, branch `mips-m5`): `disasm` now prints names on a PRX, so the last
`sed` of this check needs two more expressions, `/^[^0 ]/d; s/  ; .*//` (see "PSP module info,
imports and NID names (MIPS-5)").

| | words |
|---|---|
| `.text` | 868,720 |
| decoded, text and p-code identical to the C++ engine | 866,259 |
| decoded, no p-code in either (`bc2tl` with a slot that does not decode) | 25 |
| not decodable in either | 2,436 |
| differing lines (of 3,252,586) | 0 |

The stock spec is plain MIPS32: it has none of Allegrex's own instructions. Superseded
(2026-11-26): "MIPS-2, not started"; with the Allegrex spec all of these words decode, and the
right-hand column below is checked ("Allegrex (MIPS-2)"). The 2,436 words that do not decode,
by opcode bits (bits 31-26):

| opcode | words | on Allegrex (from the PSP opcode map as remembered, not checked here) |
|---|---|---|
| 0x34 (110100) | 1,652 | VFPU |
| 0x3c (111100) | 282 | VFPU |
| 0x1b (011011) | 259 | VFPU |
| 0x37 (110111) | 229 | VFPU |
| 0x00, function 0x16 | 12 | an Allegrex integer instruction |
| 0x1f, function 0x20, shift field 3 | 2 | an Allegrex integer instruction |

More words decode, identically in both engines, as an instruction the PSP does not have,
because Allegrex reuses the encoding: `daddiu` 757 and `daddi` 27 (opcodes 0x19, 0x18), `dadd`
7 and `daddu` 25 (function 0x2c, 0x2d), `lwc2` 1,522, `swc2` 1,535, `ldc2` 1,948, `sdc2`
1,194, `bc2t` 7, `bc2tl` 25. These are counted from the mnemonics; what each really is waits
for the Allegrex spec. Superseded (2026-11-26): see the table in "Allegrex (MIPS-2)".

Not checked: a little-endian MIPS32 ELF that is not a PRX (no such file was at hand; it takes
the path of the x86 files, with no relocations), big-endian MIPS, MIPS16 and microMIPS code
(the spec has them; none was decoded here), and Java Ghidra's listing (the check is against
the C++ engine only).

## Allegrex (MIPS-2, branch `mips-m2`, 2026-11-26)

The PSP's CPU has instructions plain MIPS32 lacks: the VFPU (a vector and matrix unit) and a
few integer ones. Their definitions are the SLEIGH spec of ghidra-allegrex
(https://github.com/kotcrab/ghidra-allegrex, commit `4e46aa146a6e8fc3369cf4a7e4053f3ea5b05a1d`,
tag `v21.6`, Apache License 2.0), copied unmodified to `processors/Allegrex/data/languages`
and compiled by `build-sla.sh` like Ghidra's own specs (`../DESIGN.md`, 2026-11-26;
`processors/Allegrex/NOTICE`). `disasm` takes `allegrex.sla` and `allegrex.pspec` for a PSP PRX
(`psp::is_prx`); `--sla` still selects the stock `mips32le.sla`. Only the spec is used: what
ghidra-allegrex does in Java and Kotlin is listed in `../docs/plans/mips-psp.md`, MIPS-2. In
p-code a VFPU operation is a `CALLOTHER` user op (the spec defines 340 user ops in all); the
helper ops that read and write vector registers are not expanded.

### Against the C++ engine

The check of MIPS-1 with `allegrex.sla` in both engines (`sleigh_ref` takes the context
default of `allegrex.pspec` for a path containing `allegrex.sla`):

```sh
cd target && mkdir -p mips-check && cd mips-check
../release/ghidra-rs disasm BOOT.BIN --addr 8804000 --count 1000000000 --pcode > rs-full.txt
grep '^0' rs-full.txt | cut -c19-49 | sed 's/(bad.*//' | xxd -r -p > text.raw
../sleigh_ref ../../processors/Allegrex/data/languages/allegrex.sla text.raw 8804000 pcode > ref.txt
sed -E 's/^([0-9a-f]{16})  ([0-9a-f]{2} ?)+ +/\1  /; s/^([0-9a-f]{16})  \(bad.*/\1  (bad)/; s/    <no p-code.*/    <no p-code>/' rs-full.txt > rs.txt
cmp rs.txt ref.txt
```

Superseded (2026-11-26, branch `mips-m5`): `disasm` now prints names on a PRX, so the last
`sed` of this check needs two more expressions, `/^[^0 ]/d; s/  ; .*//` (see "PSP module info,
imports and NID names (MIPS-5)").

| | words |
|---|---|
| `.text` | 868,720 |
| decoded, text and p-code identical to the C++ engine | 868,720 |
| decoded, no p-code | 0 |
| not decodable | 0 |
| differing lines (of 3,170,155) | 0 |

No word is left undecodable, so there is nothing to sort into data or spec gaps; whether
`.text` holds data words that happen to decode is not known (the sweep is linear).

What the words the stock spec got wrong are, by mnemonic in the same sweep with each spec:

| stock `mips32le.sla` | words | with `allegrex.sla` |
|---|---|---|
| not decodable | 2,436 | `vsqrt.s` 298, `vcmp.s` 259, `vzero.s` 239, `vrsq.s` 228, `vpfxd` 227, `vcmovt.s` 227, `vcst.s` 188, `vtfm4.q` 159, `vone.s` 147, `vcos.s` 70, `vocp.s` 66, `vsin.s` 57, `vmmul.q` 52, `vasin.s` 50, `vsgn.s` 25, `vmidt.q` 24, `vneg.t` 20, `vzero.t` 19, `vtfm3.t` 19, `vcrsp.t` 16, `clz` 12, `vrot.p` 11, `vlog2.s` 7, `vexp2.s` 4, `wsbw` 2, `vrcp.s` 2, `vpfxs` 2, `vi2f.q` 2, `vqmul.q` 1, `vmov.t` 1, `vi2uc.q` 1, `vf2in.q` 1 |
| `daddiu` | 757 | `vdot.t` 304, `vscl.t` 232, `vmul.s` 215, `vscl.p` 3, `vscl.q` 2, `vdot.p` 1 |
| `daddi` | 27 | `vdiv.s` 11, `vsub.t` 7, `vsub.s` 4, `vadd.t` 3, `vadd.p` 1, `vadd.q` 1 |
| `dadd` | 7 | `max` |
| `daddu` | 25 | `min` |
| `lwc2` | 1,522 | `lv.s` |
| `swc2` | 1,535 | `sv.s` |
| `ldc2` | 1,948 | `lv.q` |
| `sdc2` | 1,194 | `sv.q` |
| `bc2t` | 7 | `bvt` |
| `bc2tl` | 25 | `bvtl` (with p-code now: the delay slots decode) |

So the grouping MIPS-1 gave from memory holds: opcodes 0x34, 0x3c, 0x1b and 0x37 are VFPU, and
the 14 other words are `clz` (function 0x16) and `wsbw`. In all, 9,437 words are VFPU
instructions (48 mnemonics), all of them among the 9,483 words above; the other 46 are `clz`,
`wsbw`, `max` and `min`.

Another 136,701 words keep their meaning and change their text only, because ghidra-allegrex
names them differently from Ghidra's MIPS spec: `or` to `move` (65,385) or `li` (8,997), `ori`
to `li` (33,936), `clear` to `li` (1,952), and the single-precision float instructions in
lower case (`mul.S` to `mul.s` and 13 more, 26,431). Their p-code was not compared between the
two specs.

### Against PPSSPP's tables

The C++ engine checks the engine, not the spec. For the spec, PPSSPP's instruction tables
(`Core/MIPS/MIPSTables.cpp`, with `MIPSDisVFPU.cpp` and `MIPSVFPUUtils.cpp`, master at
`c771d8544180c3cf0d10e83073b50e188b02cd11`, fetched 2026-11-26 and read as data) were walked
by a throwaway script the way `MIPSGetInstruction` walks them, for every word of `.text`:

- Instruction name: PPSSPP has an instruction for each of the 868,720 words, and its name is
  the Allegrex mnemonic (without the `.s`/`.p`/`.t`/`.q` size suffix PPSSPP adds when
  printing) for all but aliases: `move`, `li`, `nop`, `b` (PPSSPP's tables name the plain
  `or`, `ori`, `addiu`, `addu`, `sll`, `beq`), `rotr` (51, under `srl`), `vcmovt` (227, under
  `vcmov`), `vtfm3`/`vtfm4` (178, under `v(h)tfm3`/`v(h)tfm4`) and `vcrsp`/`vqmul` (17, one
  entry).
- VFPU register operands: PPSSPP's notation rules (`GetVectorNotation`, `GetMatrixNotation`
  and the operand order of 16 of its `Dis_` functions), transcribed into the script, give the
  same register names in the same order as `disasm` prints for 9,084 of the 9,437 VFPU words
  (41 mnemonics: `lv.s`, `sv.s`, `lv.q`, `sv.q`, `vdot`, `vscl`, `vmul`, `vadd`, `vsub`,
  `vdiv`, `vsqrt`, `vrsq`, `vcmp`, `vcmovt`, `vcst`, `vzero`, `vone`, `vtfm3`, `vtfm4`,
  `vmmul`, `vmidt`, `vrot`, `vcrsp`, `vqmul`, `vi2f`, `vf2in` and the other two-operand ones),
  with no difference. Example: 0x64808001 is `vdot.t S010, C000, C000` in both.

Not checked: the register operands of the other 353 VFPU words (`vpfxd`, `vocp.s`, `vsgn.s`,
`bvt`, `bvtl`, `vpfxs`, `vi2uc.q`); immediates, offsets, condition and constant names (`LT`,
`2/PI`); and all p-code semantics of the Allegrex spec. The comparison is with a transcription
of PPSSPP's rules, not with PPSSPP running, and on this one file. Java Ghidra with the
ghidra-allegrex extension was not run.

## Function discovery on MIPS (MIPS-3, branch `mips-m3`, 2026-11-26)

`ghidra-rs analyze` takes a PSP PRX: the image `disasm` loads (`psp::load`, relocated at
0x08804000), decoded as Allegrex, through the same task queue, analyzers and writers as the x86
images (`--functions`, `--gaps`, `--purges`; `--facts`, `--decomp-prelude`, `--store` and
`--abi-callers` refuse a PRX: MIPS-4; still so after MIPS-4's first step, whose check builds its
own prelude). `analysis::Image` took the PRX with one new flag, `mips`
(`Image::from_prx`: the loaded sections as blocks, read-only and zero-filled as the section
headers say, the ELF entry point as the only entry). No export, import or `sceModuleInfo` is
read: that is MIPS-5.

```sh
ghidra-rs analyze BOOT.BIN --functions functions.csv --gaps gaps.csv --purges purges.txt
```

What is MIPS's own in the analysis (`analysis.rs`; the rest is the code the x86 images run):

- **Delay slots.** A branch and its delay slot instruction are one unit, 8 bytes, with the
  p-code the engine gives the branch (the slot's p-code inside it). Bodies, sizes and gaps are
  the ones Java's two instructions give. A flow into a delay slot is lost and counted in a
  warning (none on `BOOT.BIN`).
- **Flow types** come from the p-code as on x86: `jal`/`bal` a call, `jalr` a computed call,
  `jr ra` a return (the spec's `RETURN`), another `jr` a computed jump, `j`/`b` a jump. A
  branch-likely or `bc1t`/`bvt` (`if (!cond) goto inst_next; ...; goto target`) is a
  conditional jump. A branch to itself (`b .`) is a jump, not x86's `REP`.
- **Constants** (Java: the Allegrex Constant Reference Analyzer, ghidra-allegrex's copy of
  `MipsAddressAnalyzer`, over `SymbolicPropogator`): the fold of the x86 analysis with `sp`,
  the `<killedbycall>` registers `at`, `v0`, `v1` and the stack shift 0 of `allegrex.cspec`'s
  default prototype (the names are written in `analysis.rs`: the cspec is not in this repo
  yet). The address a `lui`/`addiu` or `lui`/`ori` pair makes (an `INT_ADD` or `INT_OR` of a
  register's constant and an immediate) is a reference of the instruction: a data reference,
  or a code constant when it points into an executable section.
- **Computed calls.** A `jalr` whose register the constants give calls a function there
  (Java: its COMPUTED_CALL reference, then Subroutine References). An instruction can have
  several targets, one per flow that reaches it (`Analysis::computed_calls`).
- **Reference task** (Java: the Reference and Data Reference analyzers; priority 600, on each
  batch of functions, MIPS only): `Analysis::disassemble` with constants, inside the queue. It
  disassembles, without making a function, the code at code constants (callbacks passed in a
  register) and at pointers in referenced data, by the rules it already had for x86; the calls
  in that code make their functions.
- **Function Start Search** with ghidra-allegrex's `Allegrex_patterns.xml`
  (`processors/Allegrex/data/patterns`, copied unmodified, read at build time): one search at
  4-byte alignment; a `<funcstart/>` match at undefined bytes is disassembled and made a
  function; a `<possiblefuncstart/>` match is disassembled and made a function later
  ("Function Start Search delayed", priority 701) if it is in no function and no conditional
  jump goes there, as `PossibleDelayedFunctionCreator`.
- **Switch tables** (`Analysis::mips_switch_table`): a pattern over the instruction words,
  where Java uses the decompiler (Decompiler Switch Analysis): `lw r,lo(x)` of a table word,
  `x` a `lui`/`addiu` constant plus a register, then `jr r`; the entry count from the
  `slti`/`sltiu` whose `beq`/`bne` on the flag guards it, through an `addiu` that moves the
  index, in the straight-line history and that of the first jump that reached the block. A
  `jr` it does not resolve is counted in a warning.
- Not run on MIPS: the callee purge analyzer (x86's), RTTI, Function ID.

Not ported: the `gp` value and the `t9` assumption of the address analyzer (`gp` stays an
unknown register here; the module's `gp` is in `sceModuleInfo`, MIPS-5), its
`ra`-constant call override, `MIPS UnAlligned Instruction Fix` (`lwl`/`lwr` pairs: no flow),
a pattern match at an instruction outside every function, and the decompiler's jump-table
recovery.

### Against Java (`BOOT.BIN`, 2026-11-26)

Java cannot relocate a PRX, so the reference is Java on the image ghidra-rs loads:
`ghidra-rs prx-elf` writes it as a plain ELF32 executable (the two `PT_LOAD` segments and the
50 loaded sections at their loaded addresses, the file's names, flags and `e_flags`, the
loaded entry point), and headless Ghidra 12.2 (`/opt/ghidra`, build 2026-11-10) imports it as
`Allegrex:LE:32:default` and runs its plain auto-analysis. The language is ghidra-allegrex's:
its release v21.6 for Ghidra 12.2 (`ghidra_12.2_PUBLIC_20261031_ghidra-allegrex.zip`, whose
`allegrex.sla` is byte for byte the one `build-sla.sh` compiles) is unpacked into a throwaway
settings directory (`XDG_CONFIG_HOME` and `XDG_CACHE_HOME` set for the run), not into
`~/.config/ghidra` or the install. With the extension present Ghidra picked its loader for
the ELF ("PSP Executable (ELF)"), not the stock ELF loader; what that loader does beyond the
stock one on a file with no relocation sections was not examined.

```sh
JAVA_HOME=/usr/lib/jvm/java-25-openjdk OUT=<a path with no component starting with "."> \
    tools/mips-ref.sh BOOT.BIN
```

The script compares `tools/ghidra/DumpPurges.java`'s lines with `analyze --purges` (entry,
purge, thunk, body minimum, body maximum, address count, no-return):

| | functions |
|---|---|
| Java | 11,399 |
| ghidra-rs | 11,399 |
| entry in both | 11,398 |
| only Java | 1 (0x08add548) |
| only ghidra-rs | 1 (0x08add92c) |
| in both, the whole line identical | 11,384 |
| in both, the body differs | 14 |

Java's analysis took 64 s by its own report, ghidra-rs's 3.6 to 4.0 s (one run each, not a
benchmark). `--functions` writes 11,164 rows (the functions in `.text`; the other 235 are in
the `.sceStub.text.*` sections) and reports a coverage of 3,373,992 of 3,474,880 `.text`
bytes; `--gaps` writes 16 `padding` and 1,575 `unexamined` ranges (120 and 100,768 bytes).

How the functions came, step by step (each row adds to the one before):

| | ghidra-rs | in both | only Java |
|---|---|---|---|
| the entry point, calls, patterns, address tables, shared returns, switch pattern | 11,276 | 11,276 | 123 |
| `jalr` targets of the local fold | 11,296 | 11,295 | 104 |
| the Reference task: code at `lui`/`addiu` constants and at pointers in data | 11,378 | 11,377 | 22 |
| every flow's `jalr` target; the constants of a delay slot count as the slot's | 11,399 | 11,398 | 1 |

The causes of what is left, each looked at in the bytes:

- **The two functions** (one each way) are two cases of one dispatcher that set `t0` and share
  a tail into the same `jalr t0` at 0x08add054:
  `08add108 lui v1,0x8ae` (`ae 08 03 3c`), `08add10c addiu t0,v1,-0x2ab8` (`48 d5 68 24`),
  falling into `08add114 bne a0,v0,...` (`d5 ff 82 14`) and `08add11c j 0x8add044`; and
  `08add1e0 lui v1,0x8ae`, `08add1e4 addiu t0,v1,-0x26d4` (`2c d9 68 24`),
  `08add1e8 j 0x8add114` (`45 74 2b 0a`). The constant propagation of each side carries only
  the first of the two flows through 0x08add114 on to the `jalr`: Java the first
  (0x08add548), ghidra-rs the second (0x08add92c). The order in which Java's
  `SymbolicPropogator` takes the saved flows is not reproduced.
- **The 14 bodies** all hold a `jr` through a table. Of the 282 `jr` of a register other than
  `ra` a linear sweep of `.text` shows (243 `jr at`, 39 `jr a0`), 272 are instructions in
  Java: 267 with computed-jump references, 5 without. ghidra-rs resolves 268 and counts 5 as
  not resolved. The number of distinct targets is the same at 251 of Java's 272 (the count
  was compared, not each target). The 14:
  - 4 where Java's body is larger: the pattern finds no bound (0x0896b514, 0x089746e8,
    0x08a50928, 0x08adddf4). Example: `0896b4f4 sltiu a0,a0,0xa` (`0a 00 84 2c`) overwrites the
    index with the flag, and `0896b500 lw a0,0x1b0(sp)` (`b0 01 a4 8f`) reloads it from the
    stack before `sll`: tying the bound to the index needs the stack values the decompiler
    tracks. (The fifth miss, 0x0896083c, has one target in Java; its body is the same.)
  - 4 where ghidra-rs's body is larger because Java has no table at the `jr` (0x0885213c,
    0x089ea45c, 0x08a10b68, 0x08ad58c4). Example: 0x0885213c lies behind a comparison tree
    (`088520e8 slti a2,a1,0x3c`, `088520f4 slti a2,a1,0x12`, `088520fc slti a2,a1,0x21`, then
    `08852124 bne a2,zero,...`, `08852128 addiu a1,a1,-0x21`): the pattern reads 0x3c - 0x21 =
    27 entries from it. Why Java's decompiler recovers none there was not found.
  - 6 where ghidra-rs's body is larger and Java's targets at the `jr` are others: one target
    in Java at 0x088f79c0, 0x0897ed80, 0x089811cc, 0x08a4ac78 and 0x08a4ad88; at 0x0899f5f0
    Java has 7 distinct targets and the pattern 3. Java logs decompiler warnings in two of
    these functions (0x08a4abe0, 0x08a4acf0: "Unable to read bytes"). Which side has the
    table right was not worked out.

  The pattern is a stand-in, so where it finds a table Java does not, that is its imprecision,
  not a fix to keep: the decompiler's jump-table recovery on MIPS (MIPS-4) replaces it.

Not checked: Java's instruction set against ghidra-rs's (only functions and bodies were
compared; one `jr`, 0x08b06148, is an instruction with a table here and no instruction in
Java), references, the `callees`, `callers` and `data_refs` columns of `--functions` (no Java
export was made for them), any other PRX, and a MIPS ELF that is not a PRX (`analyze` takes
only the PRX). Function names, imports and exports are MIPS-5.
## PSP module info, imports and NID names (MIPS-5, branch `mips-m5`, 2026-11-26)

`psp::load` now also reads the module's own tables from the relocated image
(`psp::parse_module`; `Prx::module`), and `disasm` prints the names they give. `analyze` does
not use them yet (`Module::names` is there for it).

### The tables (`psp.rs`)

The layouts are PPSSPP's `PspModuleInfo` (`Core/HLE/sceKernelModule.h`), `PspLibStubEntry` and
`PspLibEntEntry` and the loops over them in `Core/HLE/sceKernelModule.cpp` (master at
`c771d8544180c3cf0d10e83073b50e188b02cd11`, read as data 2026-11-26), with PSPSDK's
`_sceModuleInfo` (`src/user/pspmoduleinfo.h`) for the same first structure. All pointers are
loaded addresses: the relocations of MIPS-1 have already rebased them.

- `sceModuleInfo` (52 bytes) is found from the first program header, as PPSSPP does when no
  section names it: the physical address field is the structure's file offset, so its address
  is virtual address + physical address - file offset. It holds the attributes and version
  (16 bits each), the name (28 bytes), `gp`, and the start and end of the export table and of
  the import stub table.
- The import stub table has one entry per library, of 5, 6 or 7 words: the name's address,
  version and flags, the entry's size in words, the count of variables (8 bits) and of
  functions (16 bits), the address of the NIDs (one word per function) and the address of the
  first stub. Function `i` has stub `first + 8 * i`: two instructions (`jr ra` and `nop` in the
  file) that the firmware replaces. From 6 words on there is a table of variables, (address of
  the list of references, NID) pairs.
- The export table has entries of 4 or 5 words: name (0 for the module's own exports, listed
  under the module's name), version and flags, size, the counts, and the address of a table
  of all NIDs followed by as many addresses, functions first.

The section headers (`.rodata.sceModuleInfo`, `.lib.ent`, `.lib.stub`) are a cross-check only:
a section that differs from what `sceModuleInfo` gives is a note. Nothing is skipped silently:
an entry that cannot be read as above (a size below the format's, an address outside the
image) is a note printed on stderr, and its table is cut off there; only an unreadable
`sceModuleInfo` leaves `Prx::module` an error, and the image still loads. A name from the file
keeps printable ASCII only (anything else becomes `_`) and ends at 255 bytes. More than
65,536 imports or exports are not read (a `lean:` limit against tables made to overlap).
`.rodata.sceNid` and `.sceStub.text.*` are not looked up by name: the entries point into them.

### Names

An import is `<library>_0x<NID>` (eight upper-case hex digits), or the name PSPSDK gives that
NID in that library. The table is `psp-nids/pspsdk-nids.txt`, compiled into the binary: the
3,159 `IMPORT_FUNC` lines of PSPSDK's 101 import files (https://github.com/pspdev/pspsdk,
commit `40da14ada3342368ebdfaac8fd3f769e99fd26ac`, BSD licence; `psp-nids/NOTICE` has the
extraction command). A lookup is by library and NID, never by NID alone. A NID PSPSDK does not
list is then looked up in `SEARCHED_NIDS` (`psp.rs`): names found by hashing candidate names,
since a NID is the first four bytes of its name's SHA-1, little-endian. It holds one,
`sceMpeg` 0x4571CC64 `sceMpegAvcDecodeFlush`: on 2026-11-26 the only match among 39,449,440
names of the form `sceMpeg` + 1 to 4 parts from a fixed word list (chance matches expected for
that many tries: 39,449,440 / 2^32, about 0.009). It is computed, like the `module_*` names
below, not copied from any source. PSPSDK's name wins when both have one. Imported variables
are not in PSPSDK's files and keep the NID form. The module's own exports are named from ten
fixed NIDs (`module_start`, `module_stop`, `module_info` and the like: PPSSPP's `NID_MODULE_*`
constants; each is the first four bytes, little-endian, of the SHA-1 of its name, which was
checked for all ten).

`disasm` on a PRX prints, besides the relocation line, one line on stderr with the module's
name, attributes, version, `gp` and the counts, then each note. In the listing a `<name>:`
line stands before the instruction at an import stub or an exported function, and a `j` or
`jal` whose target is one ends in `  ; <name>`. x86 files print no names in `disasm`, so there
was no format to follow; this is the minimum (Claude's call). The target is read from the
instruction word, so a call through a register gets no name.

```
$ ghidra-rs disasm BOOT.BIN --addr 8b545c0 --count 4
sceUsbStart:
0000000008b545c0  08 00 e0 03                    jr ra
0000000008b545c4  00 00 00 00                    nop 
sceUsbStop:
0000000008b545c8  08 00 e0 03                    jr ra
0000000008b545cc  00 00 00 00                    nop 
```

### On `BOOT.BIN` (2026-11-26)

| | |
|---|---|
| module name | `APP_APPLICATION_NAME` |
| attributes, version | 0x0000 (user), 0x0101 |
| `gp` | 0 (the field is zero in the file and has no relocation) |
| `sceModuleInfo` | 0x08b55018, as the section `.rodata.sceModuleInfo` |
| import libraries | 32 (as many as `.sceStub.text.*` sections) |
| imported functions | 247 (the stub sections hold 247 stubs, 1,976 bytes) |
| imported variables | 0 |
| named from the PSPSDK table | 246 |
| named by SHA-1 search | 1 (`sceMpegAvcDecodeFlush`, NID 0x4571CC64; branch `mips-m5-hash`) |
| by NID only | 0 |
| exported functions | 2: NID 0xD632ACDB (`module_start`) twice, at 0x0880435c and at 0x08808d60 (the ELF entry point) |
| exported variables | 1 (`module_info`, at `sceModuleInfo`) |
| notes | 0 |
| `jal` to an import stub in `.text` | 539, to 236 of the 247 stubs |
| `<name>:` lines in `.text` | 2 (the two exports) |

245 of the 246 names give their NID by SHA-1; `sceImposeBatteryIconStatus` (0x8C943191) does
not, so it is PSPSDK's name, not a verified one.

Superseded: "by NID only: 1 (`sceMpeg_0x4571CC64`)" (as merged from `mips-m5-uofw`). With
`SEARCHED_NIDS` (branch `mips-m5-hash`) `disasm`'s stderr line reads "247 named by NID table,
0 by NID only", and the one `jal` to that stub (at 0x08936044) ends in
`; sceMpegAvcDecodeFlush`. The 539 named `jal`s are unchanged.

With the names filtered out (`sed -E '/^[^0 ]/d; s/  ; .*//'`), the `--pcode` listing of the
whole `.text` is the 3,170,155 lines the `disasm` of branch `mips-m3`'s build prints (a build
from before this change; byte-identical). The check against the C++ engine ("Allegrex
(MIPS-2)") was not rerun: `sleigh_ref` was not built here.

### NID sources looked at (2026-11-26)

| source | licence | used |
|---|---|---|
| PSPSDK, `src/*/*.S` (pspdev/pspsdk, `40da14ad`) | BSD 3-clause (`LICENSE`; `tools/PrxEncrypter` is GPL-3, not touched) | yes: the table above |
| ghidra-allegrex (`4e46aa14`) | Apache-2.0 | nothing to use: it ships no NID data (two scripts for PPSSPP `.sym` files) |
| PPSSPP, the HLE function tables in `Core/HLE` (`c771d854`) | GPL-2.0 or later (file headers) | no: not compatible with Apache-2.0. Read for the structure layouts only |
| pspdev/psp-ghidra-scripts (`f6bf867a`), `ppsspp_niddb*.xml`, `500_psplibdoc_191008.xml` | repository `LICENSE` is Apache-2.0, but its README says the XML files are from the PSP PRX Libraries Documentation Project, and the file names say PPSSPP | no: the data's own licence is not clear |
| mathieulh/PSP-PRX-Libraries-Documentation-Project (`3a129e46`), Spenon-dev/PSPLibDoc (`c2834ef4`) | GPL-2.0 (as GitHub reports them; the files were not read) | no |
| uOFW (uofw/uofw, `f7b06231`) | MIT, with PSPSDK parts under BSD (`COPYING` and README) | no: compatible, but has no name for the one NID PSPSDK lacks here (`sceMpeg` 0x4571CC64): read 2026-11-26, the NID is in no file and no `exports.exp` has a library `sceMpeg` (`src/kd/avcodec` exports `sceMpegbase` only); its `kirk`, `power` and `gh-pages` branches neither |

Superseded: the uOFW row's "only the licence was read; whether it holds a usable NID list was
not looked at" (as merged from `mips-m5`). uOFW was then read for 0x4571CC64 on branch
`mips-m5-uofw` (`docs/plans/mips-psp.md`, MIPS-5); `sceMpeg_0x4571CC64` keeps the NID form.
Superseded (branch `mips-m5-hash`): the NID is now named `sceMpegAvcDecodeFlush` by SHA-1
search (Names, above), not from a NID source.

Not done: names for imported variables and for other modules' exports beyond the PSPSDK
table; a second table for what PSPSDK lacks (Superseded in part: `SEARCHED_NIDS`, branch
`mips-m5-hash`, names the one NID SOCOM's `BOOT.BIN` needed); a PRX with imported variables, with entries of 7
words or with named export libraries (the target has none, so those paths are only run by the
hand-made test, which covers one variable import and the module's own export entry).

## The decompiler on MIPS (MIPS-4, branch `mips-m4`, 2026-11-26)

First step: both engines decompile functions of a relocated PSP PRX with the Allegrex language
and ghidra-allegrex's `allegrex.cspec`, and are compared on samples of SOCOM FTB's `BOOT.BIN`.
The decisions (the calling convention, the VFPU user ops) and their evidence are in
`docs/plans/mips-psp.md`, "MIPS-4".

```sh
rust/build-sla.sh                                # allegrex.sla, with the others
rust/tools/decomp-ref.sh                         # decomp_dbg, as for x86
rust/tools/mips-decomp.sh <psp-prx> [corpus]     # default corpus: tools/corpus/socom50.txt
ghidra-rs prx-xml <psp-prx> <out.xml>            # the image both engines load
ghidra-rs decompile -i <script>                  # `load file` takes the PRX or the .xml
```

### How the reference runs

- The system's libbfd reads no MIPS ELF (`objdump -i` lists no MIPS target), so `decomp_dbg`
  cannot `load file` the PRX or the ELF of `prx-elf`. It loads a `<binaryimage>` file instead
  (`LoadImageXml`, the format of the upstream datatests): `ghidra-rs prx-xml` writes the image
  `Image::from_prx` loads (relocated at 0x08804000), one `<bytechunk>` per section, `readonly`
  as the section is, without the bytes of `SHT_NOBITS` sections (unmapped on both engines).
  For `BOOT.BIN` the file is 7.8 MB.
- Its `arch` is `Allegrex:LE:32:default:default`, which `decomp_dbg` resolves through
  `allegrex.ldefs`. The language directory is given with `-s <dir>`: `mips-decomp.sh` makes
  one under its output directory, with links to `allegrex.sla`, `allegrex.pspec` and
  `allegrex.ldefs` and a copy of `allegrex.cspec` without its 15 `<callotherfixup>` elements.
  Those are `dynamic` (Java's `AllegrexPcodeInjectLibrary` supplies their p-code) and
  `decomp_dbg` stops with "Missing dynamic inject" at the first VFPU user op that has one. The
  files in `rust/processors/Allegrex` stay as copied.
- The prelude is `map function <address>` for each row of `analyze --functions`, then `map
  function <address> <name>` for each import stub a `jal` of `.text` reaches (the names
  `disasm` prints). `analyze --decomp-prelude` still refuses a PRX.
- `mips-decomp.sh` then calls `decomp-diff.sh` unchanged (one script per function for both
  engines, `PRINT` defaulting to `print C`, the reference cache off).

### What ghidra-rs took

- `console.rs`: `load file` takes a PSP PRX (`Image::from_prx`) or a `<binaryimage>` of the
  arch above; either is Allegrex with `allegrex.cspec`. A `<binaryimage>` with another arch or
  a `<symbol>` is refused, so the upstream datatests still do not load.
- `flow.rs`: an instruction's length is `Sleigh::oneInstruction`'s, with the delay slot. Before,
  the fall-through of a branch or call was its delay slot, whose p-code then ran a second time
  (a store in a `jal`'s delay slot printed before and after the call).
- `cspec.rs`: `<funcptr align=..>` (`funcptr_align`: `ActionDeindirect` drops the low bits of
  a constant call target, `RuleFuncPtrEncoding` removes the AND that clears them, `JumpBasic`
  and `JumpAssisted` mask their targets); a prototype's `<localrange>` (`LocalMap`, the
  local scope's ranges and `getLocalRange`; refused in a `<resolveprototype>`);
  `<spacebase>` is read, and a function whose p-code holds a varnode at that register (`gp`)
  is refused: the second spacebase space is not ported; a `dynamic` `<callotherfixup>` is
  skipped, which leaves its user op a `CALLOTHER`, as in the reference's spec.
- Nothing else: the return address in `ra`, the float and `join` parameter entries, jump-table
  recovery and the constant folding that joins `lui`/`addiu` pairs ran as ported for x86.

### On `BOOT.BIN` (2026-11-26)

`print C`, with the reference of `decomp-ref.sh` at master `ed70ec7cd2`:

| corpus | reference ran | identical | differs | ghidra-rs fails | reference fails |
|---|---|---|---|---|---|
| `socom50` (stratified) | 50 / 50 | 50 | 0 | 0 | 0 |
| `socom500` (random) | 500 / 500 | 497 | 1 | 2 | 0 |

- `socom50`: 14 leaf functions of 8 to 96 bytes, 12 with a `jal` to a named import, 12 with a
  `jr` of another register than `ra`, 12 with a VFPU instruction (the criteria are in the
  file). Of the 12 with a `jr`, 11 print a `switch`; in one both engines print the same
  "Could not recover jumptable ... Too many branches".
- `socom500`: the two failures are "ActionParamDouble: joining double-precision call inputs
  not implemented in ghidra-rs yet" (0x089200a8, 0x089ecbbc); the difference is `return
  (bool)0;` for the reference's `return false;` (0x08a6fecc). Both are in the shared
  decompiler, not in MIPS code.
- x86 after the change: `PRINT="print C" decomp-diff.sh m8` 8 / 8, `m500` 500 / 500.
- Test: `mips_delay_slot_print_c` (`tests/console.rs`) decompiles a hand-made function from
  `tests/data/mips-delay.xml` and compares with `decomp_dbg`'s C.

Not done: the other 10,664 functions; `gp` (no function of this PRX uses it, so the refusal
never fired); the VFPU injection (the user ops print as calls: `axVar1 = vfpuReadT(fVar3);`);
`--decomp-prelude` and `--facts` for a PRX; a comparison with Java Ghidra's C.

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

- Two processor families: x86 (`x86-64.sla` and the 32-bit `x86.sla`) and, in `disasm` only,
  little-endian MIPS32 (`mips32le.sla`, stock) and the PSP's Allegrex (`allegrex.sla`, for a
  PRX). Superseded (2026-11-26, branch `mips-m1`): "One processor family: x86". Superseded
  (2026-11-26, branch `mips-m2`): "stock: no Allegrex instructions". `analyze` takes 32-bit
  PE files and ELF x86-64 files (functions, bodies, gaps; see "ELF64 analysis"); `--decomp-prelude`
  and the decompiler take both (see "The decompiler on x86-64"); `--abi-callers`, `--store`,
  `edit` and `export` take 32-bit PE files only. Superseded (2026-11-21): "`analyze` takes 32-bit
  PE files only". Superseded (2026-11-22, branch `m3-x64`): "`--decomp-prelude` and the
  decompiler take 32-bit PE files only".
- Context starts from the `.pspec` defaults. Context commits (`globalset`) are recorded per
  address in the `Parse` and apply to later decodes there (flowing ones from that address on);
  the x86 specs do not use them. `crossbuild`, `inst_next2` and flowref/flowdest are not
  implemented. Superseded (2026-11-26, branch `mips-m1`): "Delay slots ... are not
  implemented"; they are ("MIPS32 and the PSP (MIPS-1)").

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

`sleigh_ref` uses the 64-bit context defaults for a `.sla` whose path contains `x86-64`, those
of `allegrex.pspec` for one whose path contains `allegrex.sla`, of `mips32.pspec` for another one
whose path contains `mips` (see "MIPS32 and the PSP (MIPS-1)"; a directory named `mips...` on
the path counts too, so an x86 `.sla` under one gets the wrong defaults), and
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
