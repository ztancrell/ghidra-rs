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
  join.
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
| `--functions-from` fresh export | fresh export (functions and gaps) | 37,633 of 37,635 | 99.1% | 94.6% | 97.2% | 82.9% | 39,243 of 39,557 identical (ours: 39,368 rows) |

`name`, `exported`, `vtable_class` and `lua` match on 99.9% or more of the rows; `fid` is
always 0.

Known differences:

- Function ID (FID) is not implemented: `fid` is 0 and FID library names are missing.
- Indirect calls and memory operands that Ghidra resolves by constant propagation (`CALL EDX`
  after `MOV EDX,[vtable+n]`, `[ESI+n]` with known ESI) are resolved only by the local fold
  here: fewer `callees` and `data_refs`. The whole-function propagation (see CheckAbiCallers
  below) runs only with `--abi-callers`, so these rates are unchanged by it. Calls it resolves
  are not counted as `callees`.
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
  or reaches a function; a single instruction must reach a function. This code belongs to no
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

Every `violation` site of the reference is written with that status: the eight missing
before the coverage changes (0x4793ff, 0x47940e, 0x479440, 0x479445, 0x479450, 0x47945b,
0x479466 through the folded pointer at 0x553224, and 0x6fd52b through the address table at
0x6fe900), and the three of 0x84af20 at 0x41d7be and 0x41d834 (the violation-first rule) and
0x675611 (the import-thunk rule). 25 extra `violation` lines remain where Ghidra says
`unknown` or has no row (16 before the coverage changes; unchanged by the propagation).

It takes about 23 s wall on a 12-thread machine (about 19 s analysis, of which about 2 s are
the whole-function propagation on 12 threads, about 9 s on one; the rest is on one thread:
about 3 s the local fold, 2.3 s checking code constants for valid subroutines, 0.5 s
building address tables; 20 s wall and 15 s analysis before the propagation, measured back
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
