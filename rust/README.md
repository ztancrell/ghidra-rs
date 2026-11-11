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
  code constants (no x87 self-reference; a disguised call `PUSH next; PUSH callee; RET`).
- `ghidra-rs/tests/abi.rs`: register reads and writes (sub-registers as base-register bytes)
  of a few fixed instructions.
- `build-sla.sh`: builds Ghidra's SLEIGH compiler and compiles `x86-64.sla` and `x86.sla`.
- `tools/sleigh_ref.cc`: a reference disassembler on Ghidra's C++ engine, printing in the
  same format, used to verify the Rust port.

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
                         [--seeds <csv> | --functions-from <csv>]... [--sla <file>]
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
  `CALL [global]` whose initial value is a function entry;
- non-returning functions: known imports (ExitProcess, exit, abort, ...), functions whose
  body has no return, and `JMP [slot]` thunks to non-returning imports; calls to them end the
  flow;
- REP string instructions fall through (their p-code branches to themselves);
- data references: direct memory operands, and immediates that point into a non-executable
  section.

### Match against Ghidra (Mercenaries2.analysis.exe)

Compared on 2026-11-11 (7.4 MB `.text`). The `--functions-from` reference is a fresh
ExportFunctions/ExportGaps run on the current mercs2 analysis project (37,635 functions, after
ClearFalseNoReturn and AddRelocatedEntries); the pipeline's `build/functions*.csv` from
2026-10-14 predate those steps. Column rates are over the functions both sides have.

| run | reference | functions | size | callees | callers | data_refs | gaps rows |
|---|---|---|---|---|---|---|---|
| plain discovery | `functions-analysis.csv` (import only, 23,323) | 22,388 common, 935 missing, 365 extra | 95.7% | 87.6% | 88.4% | 76.3% | (no reference) |
| `--functions-from` fresh export | fresh export (functions and gaps) | 37,633 of 37,635 | 99.1% | 94.6% | 97.2% | 80.5% | 39,243 of 39,557 identical (ours: 39,368 rows) |

`name`, `exported`, `vtable_class` and `lua` match on 99.9% or more of the rows; `fid` is
always 0.

Known differences:

- Function ID (FID) is not implemented: `fid` is 0 and FID library names are missing.
- Indirect calls and memory operands that Ghidra resolves by constant propagation (`CALL EDX`
  after `MOV EDX,[vtable+n]`, `[ESI+n]` with known ESI) are not resolved: fewer `callees` and
  `data_refs`.
- Ghidra leaves some JMPs to a function entry as jumps (e.g. 0x72cc00 -> 0x4ddaab, a target
  recovered after auto-analysis); ghidra-rs counts every one as a call, which matches Ghidra
  on more rows than counting none.
- Function sets of plain discovery: Ghidra also creates functions from code pointers and
  operand references in some cases; making functions of all such pointers gave more extra
  functions than found ones, so ghidra-rs does not.
- The 2 functions missing with `--functions-from` (0x475541, 0x98248c) start inside an
  instruction that ghidra-rs decoded first from another flow (overlapping code); ghidra-rs
  keeps the first decode and drops the entry.

Time on the same machine: ghidra-rs `analyze` takes about 9.5 s wall (8.3 s analysis, one
thread). Ghidra's auto-analysis of the same game (`Mercenaries2.exe`, mercs2
`build/ghidra-import.log`) took 723 s, before the post-scripts.

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
  pointers), memory operands (READ), immediates (DATA; not the x87 constructors' copy of the
  instruction's own address into `FPUInstructionPointer`), the loader's `Entry Point`
  reference to an export (EXTERNAL) and its export address table slot (DATA, an image-base
  offset), and pointers in data sections (DATA); code references first, then data, each by
  source address. Pointers in data are, by default, the ones Ghidra defines: words an
  instruction references, and runs of 4 or more aligned words that are all addresses in the
  image (Create Address Tables). `--data-pointers` takes every aligned word equal to the
  address instead (the export directory aside), which finds callers Ghidra misses but no
  longer matches its output.
- Code Ghidra decoded outside the function bodies is decoded too, since its references count:
  code reached through code constants (`PUSH offset callback`, `MOV [g],offset fn`, SecuROM's
  disguised calls `PUSH next; PUSH callee; RET` and `PUSH next; JMP callee`), repeated over
  what that code reaches. It belongs to no function and does not change `--functions` or
  `--gaps`.
- `CALL ESI` counts as an import call when the nearest write of ESI before it in the function
  is `MOV ESI,[import slot]` (a stand-in for Ghidra's constant propagation).
- `securom_functions.csv`, read from the directory of `register_abi.csv` as the script reads
  `config/securom_functions.csv`, gives the relocated bodies; they are made functions, as
  AddRelocatedEntries.java does. Contract entries no analysis reached are disassembled first,
  as the script's `disassemble(entry)` does.

Result on 2026-11-11 with `--functions-from` the fresh 37,635-function export, against
`config/abi_callers.csv` and `config/register_abi.csv` as of 2026-11-11 13:05 (52,922 rows):
51,705 rows identical (97.7%; the file is compared sorted, since Ghidra lists references in
its database order; 51,099 before the changes below). ghidra-rs writes 52,960 rows and reports
`Checked 36525 references; 2889 output findings; 293 input findings`.

The mercs2 ABI gate reads only `address`, `contract`, `site` and `status` (and the `output`/
`input` marker rows). Projected to those fields and sorted, 746 reference lines are missing
from ours and 784 are extra (2,189 lines before 2026-11-11: the x87 self-reference, export
and data-pointer rules and the code-constant disassembly above). By cause:

- pointers in data Ghidra did not define (201 of 10,049 data-section sites, about 300 lines,
  and most of the 123 contracts where Ghidra writes the `""` "no references" row and we do
  not): runs of 4+ addresses where Ghidra left some slots undefined, e.g. the per-class
  records at 0xbcc480 (`[0x4ccd40, 0x45e6d0, 0x4ccd40, 0x45e6d0, 0x54cde0, A, B, C,
  0x66c150]`, Ghidra references the shared entries and not A, B, C) and 0xba894c. No rule
  found yet separates them.
- code one side decoded and the other did not (about 680 text-site lines, 140 SecuROM-site
  lines): SecuROM wrapper chains (`PUSH next; JMP callee` links in `.securom`) whose head
  ghidra-rs does not reach, e.g. 0x24e77xx, which leads to 0x6ba410 and on to the code at
  0x6fd500..0x6fe85a (Object_ExistsByGuid's caller 0x6fe62a); code Ghidra decoded by means
  not found here, e.g. 0x4793f0..0x4794ff (6 `violation` rows of 0x84af20 and 0x407af0), which
  nothing references by address; and code ghidra-rs decodes that Ghidra did not, e.g. the
  callers of LtiDebug_Log at 0x755d30 (reached by a CALL from 0x755f46) and of
  VehicleDriver_Send* at 0x545a90 (from 0x545e98): real callers, reported as `unknown` where
  Ghidra writes no row.
- the results of those differences: `output:`/`input:` rows (about 260 lines) and the `""`
  rows (136), whose walks pass through the code above.
- JMPs Ghidra left as jumps (28 `tail jump reference` rows) and computed references from
  constant propagation (18 `COMPUTED_CALL` rows).

Of the 23 `violation` sites of the reference that ghidra-rs did not write before, 8 remain
missing (the 0x4793f0 region and 0x6fd52b above).

It takes about 14 s wall on a 12-thread machine (about 10 s analysis on one thread, of which about
2 s decode the 1.1 M instructions reached through code constants; 12.2 s before; 2.6 s
checking on 12; checking alone is about 11 s on one thread). The contracts are split over
threads (contract `t`, `t+n`, ... to thread `t`), and written in file order;
`GHIDRA_RS_THREADS=<n>` sets the count (default: all cores). The caches (callee walks,
`pushes_float`, never-returned values, input walks) live for one contract, so a result never
depends on which contracts a thread checked before: the output is the same byte for byte with
1, 3 and 12 threads. Before 2026-11-11 the check took 38 s on one
thread: each walk step copied and hashed the whole live set (a set of `String`s) to detect
revisits; live keys are now inline (`Key`) and a walk numbers each distinct live set once. The
script's own run time in Ghidra was not measured here.

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
