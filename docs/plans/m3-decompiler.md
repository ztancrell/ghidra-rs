# Milestone 3 plan: the decompiler

Written 2026-11-12 as a plan. Built so far: S0, S1a and S1b (see their sections below).

## Goal

A decompiler in Rust, inside `ghidra-rs`, that turns a function of a 32-bit MSVC PE (mercs2,
`orig/Mercenaries2.analysis.exe`) into the same C that Ghidra prints. Ghidra's C++ decompiler
(`Ghidra/Features/Decompiler/src/decompile/cpp/`) is the reference, the way `rust/tools/sleigh_ref.cc`
was for SLEIGH. No FFI. The port is staged so that every stage's output can be diffed against the
C++ output on a fixed corpus.

## How the C++ decompiler works

One function at a time, `Funcdata` holds the p-code ops, varnodes and basic blocks. A tree of
Actions and Rules (`coreaction.cc`, `ActionDatabase::universalAction`) runs over it in a fixed
order until nothing changes:

1. **Flow and p-code** (`flow.cc`, `funcdata*.cc`): follow the instructions, build basic blocks,
   inject call-fixup p-code from the `.cspec` (`pcodeinject.cc`, `inject_sleigh.cc`), make a
   `FuncCallSpecs` for each call (`fspec.cc`, `modelrules.cc`). Jump tables are recovered here,
   with a partial decompile of the switch (`jumptable.cc`, `rangeutil.cc`, `emulateutil.cc`).
2. **Heritage / SSA** (`heritage.cc`, `cover.cc`): place MULTIEQUAL and INDIRECT ops, rename to
   SSA, refine stack and register pieces. Runs again whenever a new address space becomes
   heritable (the stack after `ActionSpacebase`), so it sits inside the main loop.
3. **Main loop** (`mainloop` group): prototype recovery (`ActionActiveParam`,
   `ActionReturnRecovery`, `paramid.cc`), dead code, stack-pointer flow, unreachable blocks, and
   the rule pool `oppool1`: about 160 rules (`ruleaction.cc`, `subflow.cc`, `double.cc`,
   `condexe.cc`, `bitfield.cc`, `constseq.cc`, `transform.cc`) applied op by op until stable.
   Copy propagation is a rule (`RulePropagateCopy`); dead code is an action (`ActionDeadCode`).
4. **Types** (`type.cc`, `typeop.cc`, `cast.cc`, `ActionInferTypes`): propagate data types along
   the data flow; `oppool2` rules then turn pointer arithmetic into field and array accesses.
5. **Cleanup pool** (about 25 rules), **merge** (`merge.cc`, `variable.cc`): group SSA varnodes
   into high-level variables.
6. **Structuring** (`block.cc`, `blockaction.cc`): collapse the CFG into if/else, loops, switch.
7. **Printing** (`printc.cc`, `printlanguage.cc`, `prettyprint.cc`): names, casts, C text.

The order matters: the output depends on which rule fires first, so the port keeps the same
action tree and rule order.

### Sizes (lines)

The decompiler core (Makefile group `DECCORE`) is 105,458 lines of `.cc` and 23,546 of `.hh`.
The biggest files:

| file | lines | part |
|---|---|---|
| ruleaction.cc | 11,020 | rules |
| coreaction.cc | 6,151 | actions |
| fspec.cc | 5,928 | prototypes, calls |
| type.cc | 5,230 | data types |
| subflow.cc | 4,179 | sub-variable flow rules |
| block.cc | 3,846 | blocks, structured blocks |
| double.cc | 3,630 | split 64-bit values |
| database.cc | 3,619 | scopes, symbols |
| printc.cc | 3,556 | C printer |
| grammar.cc | 3,180 | C declaration parser |
| jumptable.cc | 2,933 | switches |
| heritage.cc | 2,877 | SSA |
| typeop.cc | 2,762 | op type rules |
| rangeutil.cc | 2,605 | value ranges |
| bitfield.cc | 2,418 | bitfields |
| blockaction.cc | 2,375 | structuring |
| funcdata_varnode.cc | 2,334 | |
| varnode.cc | 2,047 | |
| modelrules.cc | 1,975 | `.cspec` model rules |
| varmap.cc | 1,759 | stack locals |
| merge.cc | 1,728 | |
| funcdata_op.cc | 1,668 | |
| architecture.cc | 1,564 | spec loading |
| flow.cc | 1,459 | |

Not ported: the Java protocol (`ghidra_process.cc`, `*_ghidra.cc`), `printjava.cc`,
`signature.cc` (BSim), `callgraph.cc`, `rulecompile.cc`/`unify.cc`, `graph.cc`, the console.
Milestone 1 ported 7,400 lines of SLEIGH `.cc` into about 2,000 lines of Rust; the decompiler is
denser, so the estimates below assume about 0.55 Rust lines per C++ line: **about 60k lines of
Rust in all**.

## Reference output (verified 2026-11-12)

### Main route: the console decompiler `decomp_dbg`

Built from the upstream sources in about a minute (12 cores); needs g++, make, zlib and libbfd:

```sh
cp -r Ghidra/Features/Decompiler/src/decompile/cpp rust/target/decomp-build
make -C rust/target/decomp-build -j12 decomp_dbg decomp_test_dbg
```

- `decomp_test_dbg -sleighpath <repo> -path Ghidra/Features/Decompiler/src/decompile/datatests datatests`
  runs the upstream XML tests in 4.5 s. All 665 checks in the 67 test files whose `.sla` exists
  (the x86 ones) pass; the 26 ARM/MIPS/PowerPC files fail with "Could not find .sla file", which is expected.
  Superseded: the datatests directory has 93 files; 77 run (665 checks) and 16 (non-x86) lack a
  `.sla`. The 26 counted the "Could not find .sla" lines, which the failure summary repeats.
- `decomp_dbg` loads the whole mercs2 PE through libbfd (it picks `x86:LE:32:default:windows`,
  so `x86win.cspec`) and decompiles one function in about 0.2 s:

```sh
cat > s.txt <<'EOF'
load file /home/zpt/projects/mercs/mercs2-decomp/orig/Mercenaries2.analysis.exe
load addr 0x58d030 f_58d030
break start paramdouble
decompile
print raw
quit
EOF
SLEIGHHOME=/home/zpt/projects/ghidra-rs /abs/path/decomp_dbg -i s.txt </dev/null
```

What makes this usable as a per-stage reference:

- `break start <action>` stops just before any action (`funclink`, `heritage`, `paramdouble`,
  `assignhigh`, ...); `print raw` then prints the SSA p-code with sequence numbers. The break stays set (the main
  loop hits it again on `continue`), so the final `print C` comes from a second run without a
  break. (`break action` stops only after an action that changed something.)
- `option currentaction <group> off` switches off whole groups (`analysis`, `cleanup`,
  `typerecovery`, ...) and `option togglerule <rule> off` single rules. The decompiler still
  completes. So the reference can run with exactly the rules the Rust side has ported.
- `print tree block` prints the structured block tree; `print C` the final C.

Gotchas found: run `decomp_dbg` by absolute path (a relative `argv[0]` dies in an assertion);
`load test file` needs at least one `<stringmatch>` in the XML; the console prints core type
names (`int4`, `xunknown4`, `func_0x...`, `iRam...`) instead of Ghidra's (`int`, `undefined4`,
`FUN_...`, `DAT_...`).

What the console lacks, compared with Ghidra: symbols, import prototypes and read-only memory.
0x40a110 fails with "Unable to load 512 bytes at r0x7c9010ed" (a bound IAT entry); `.rdata`
floats print as `fRam00b9b664`. S0 below fixes this with a generated prelude.

### Final check: Ghidra headless on the existing mercs2 project

mercs2's `tools/ghidra/Decompile.java` prints Ghidra's C for given addresses. Read-only, no
analysis, works:

```sh
cd /home/zpt/projects/mercs/mercs2-decomp
GHIDRA_HEADLESS_MAXMEM=6G _JAVA_OPTIONS=-Djava.io.tmpdir=$HOME/.cache/ghidra-tmp \
/opt/ghidra/support/analyzeHeadless build/ghidra mercs2 -readOnly -scriptPath tools/ghidra \
  -process Mercenaries2.analysis.exe -noanalysis -postScript Decompile.java 0x401000 0x58d030
```

It took 99 s for three functions, most of it a language upgrade Ghidra 12.2 repeats on every
read-only open. The first try died with "No space left on device" because `/tmp` (7.5 GB tmpfs)
was full, hence the `java.io.tmpdir` override. Use it for the final acceptance on a batch of
functions at once, not per edit. 0x401000 and 0x58d030 give the same structure in both
references; only names and types differ.

## Corpora

- **D**: the upstream x86 datatests (77 files, 665 checks; "67" before 2026-11-12 was a miscount). Our test runner reads the same XML.
- **M8**: mercs2 hand-picked: 0x401000 (global counter), 0x401080 (x87 floats, stack arrays),
  0x40a110 (import call through a thunk), 0x58d030 (bit tests), 0x9eec5e
  (`__security_check_cookie`, FID), 0x54c990 (`HumanExit_Update`), the function holding the
  vtable call at 0x73b4d1, and one switch function with a two-level table (picked in S0 from
  `ghidra-rs analyze`'s switch tables).
- **M500**: 500 `.text` functions drawn once with a fixed seed from `build/functions.csv` and
  committed as an address list.
- **Mall**: all 37,600 `.text` functions (speed and crash check only).

## Stages

"Identical" means byte-identical text, sequence numbers included, as in milestone 1. Each stage
lists the differences it leaves in `rust/README.md` with a cause. Sizes are C++ `.cc` lines
ported, then estimated Rust lines.

| | stage | ports | C++ → Rust | check | pass bar | needs |
|---|---|---|---|---|---|---|
| S0 | Harness | none | → 1.0k | the same console script runs on both engines; `diff` | D, M8 scripts run on the reference | – |
| S1a | IR, flow, raw p-code | `funcdata*.cc`, `varnode`, `op`, `flow`, basic blocks of `block`, `opbehavior`, op names from `typeop`, `action.cc` | 16k → 8k | `print raw` at `break start funclink` | M8 identical; M500 ≥ 99% | S0 |
| S1b | Specs, prototypes, call fixups | `fspec`, `modelrules`, spec part of `architecture`, `pcodeinject`, `inject_sleigh`, snippet part of `pcodecompile`, `override`, `userop`, core types of `type` | 12k → 6k | `print raw` at `break start heritage` | M8 identical; M500 ≥ 99% | S1a |
| S2 | Heritage / SSA | `heritage`, `cover`, `varmap` (stack ranges), the base actions | 6k → 3.5k | `print raw` at `break start paramdouble` | M8 identical; M500 ≥ 99% | S1b |
| S3 | Jump tables | `jumptable`, `rangeutil`, `emulateutil`, `emulate`, `memstate` | 7k → 4k | `print raw` at `paramdouble` on switch functions; table targets also against `ghidra-rs analyze` | all M500 switches identical | S2 |
| S4 | Core actions without rules | rest of `coreaction` (dead code, param/return recovery, stack-pointer flow, deindirect, branch cleanup, nodejoin, multicse), `condexe`, `paramid` | 6k → 3k | `print raw` at `break start assignhigh` with groups `analysis`, `cleanup`, `typerecovery` off on both sides | M500 ≥ 98% | S2 |
| R1 | Rules: copy, constants, arithmetic | `RulePropagateCopy`, `EarlyRemoval`, `TermOrder`, `CollectTerms`, `Trivial*`, `IdentityEl`, `CollapseConstants`, `AddMultCollapse`, `Sub2Add`, `PullsubMulti`, `PushMulti`, `SelectCse`, ... | 4k → 2k | as S4, with only the ported rules on (`togglerule` for the rest) | M500 ≥ 98% | S4 |
| R2 | Rules: bit ops, compares, booleans, cleanup pool | `And*`, `Or*`, `Less*`, `Equal*`, `Bool*`, `CondNegate`, `RangeMeld`, the `cleanup` group | 4k → 2k | same | M500 ≥ 98% | S4 |
| R3 | Rules: extension, concat, sub-pieces | `Zext*`, `Concat*`, `Piece*`, `HumptyDumpty`, `Subvar*`, `SplitFlow`, `ActionLaneDivide`; `subflow`, `transform`, `prefersplit` | 9k → 4.5k | same | M500 ≥ 98% | S4 |
| R4 | Rules: division, modulo, float | `DivOpt`, `ModOpt`, `Sign*`, `Float*`, `floatprecision` group; `float.cc` | 4k → 2k | same | M500 ≥ 98% | S4 |
| S6 | Types | `type`, `cast`, type parts of `typeop`, `ActionInferTypes` and friends, `database` (scopes), `unionresolve`, a C declaration parser (replaces `grammar.cc`) | 14k → 7k | `print raw` with types (see below) at `assignhigh`; `parse line` datatests | D files using `parse line` pass; M500 ≥ 95% | S2 |
| R5 | Rules needing types; 64-bit splits; strings; bitfields | `typerecovery`/`stackvars` rules (`PtrArith`, `StructOffset0`, `PushPtr`, `LoadVarnode`, ...), `double.cc`, `constseq`, `bitfield` | 10k → 5k | as R1 | M500 ≥ 95% | S6, R1–R4 |
| S7 | Merge, high variables | `merge`, `variable`, merge actions, `dynamic` (hashes, needed for saved locals) | 5k → 2.5k | `print raw` with high-variable ids after `copymarker` | M500 ≥ 95% | S6 |
| S8 | Structuring | rest of `block`, `blockaction`, CFG edits of `funcdata_block` | 5k → 3k | `print tree block` at the end, rules off and then on | M500 ≥ 98% | S4 |
| S9 | C printing | `printc`, `printlanguage`, `prettyprint`, `comment`, `stringmanage`, naming and cast actions | 7k → 4k | `print C` | all of D passes in our runner; M500 ≥ 95% identical to `decomp_dbg` | S7, S8, R5 |
| S10 | Ghidra-facing output | Ghidra names (`FUN_`, `DAT_`, `undefined4`), import prototypes, read-only blocks | → 1.5k | our C against `Decompile.java` | M8 identical; M500 ≥ 90% with differences listed | S9 |

"Print raw with types" and "with high-variable ids" need a small patch to the reference copy
(`Varnode::printRaw` in `varnode.cc`, about 20 lines), kept under `rust/tools/` and applied by the
build script. The Rust side prints the same.

### S0 in detail

- `rust/tools/decomp-ref.sh`: copies the C++ sources into `rust/target/decomp-build` (like
  `build-sla.sh`), applies the patch, builds `decomp_dbg` and `decomp_test_dbg`.
- `ghidra-rs decompile -i <script>`: reads the console commands the corpora need (`load file`,
  `load addr`, `map function`, `map externalref`, `readonly`, `parse line`, `option`,
  `break start`, `continue`, `print raw`, `print tree block`, `print C`, `quit`) and prints in the
  same format. Unported commands fail loudly. A script runs unchanged on both engines.
- `ghidra-rs analyze --decomp-prelude <out>`: writes the shared prelude from ghidra-rs's own
  analysis: `map function` for every function (FID names included), `map externalref` for each
  IAT slot with the import's name, `readonly` for `.rdata`. Both engines read it.
- `rust/tools/decomp-diff.sh <corpus>`: runs both, diffs per function and prints
  `identical N / M` plus the first differing line of each mismatch.
- The datatest runner (port of `testfunction.cc`, 399 lines) for corpus D.

Done on branch `m3-s0` (2026-11-12); the commands and results are in `rust/README.md`,
"Decompiler harness". Where it differs from the list above:

- Functions are selected with `load function <name>` (name from the prelude) rather than
  `load addr`: `load addr` on an address the prelude already maps makes a second function and a
  "overlaps object" warning, and loses the FID name. The console reads both.
- The `print raw` patch is active only with `DECOMP_RAW_EXTRA` set, so the default output is
  upstream's and the early stages compare without types.
- The datatest runner is `ghidra-rs datatest [--ref <decomp_dbg>]`; `decomp-diff.sh d` runs it on
  both engines. On the reference it reproduces `decomp_test_dbg`'s 665 / 665.

### S1a: done on branch `m3-s1a` (2026-11-12)

M8 8 / 8 and M500 500 / 500 identical at `break start funclink`; details in `rust/README.md`,
"Decompiler (Milestone 3)". Where it differs from the table row:

- Jump tables are needed already: flow recovers them (`FlowInfo::recoverJumpTables`) and an
  indirect jump without one becomes a call plus a halt. S1a has a stand-in (the MSVC
  `JMP [reg*4 + table]` switch bounded by its `CMP`, one target per value as `JumpBasic`
  gives); S3 replaces it with the real recovery.
- `action.cc` is ported only as far as a sequence with `break start`: the universal action's
  first six actions. The repeat/restart groups and rule pools come with the main loop (S2).
- `print raw` at `funclink` already shows three actions before it: `ActionConstbase` (the
  tracked `DF = 0`), `ActionExtraPopSetup` (`ESP = ESP [] <call>` before every call, since every
  callee's extrapop is unknown without prototypes) and `ActionPrototypeTypes` (`return(#0x0)`).
  They are ported in that minimal form; S1b owns the rest of them.
- Two C++ details reach the output and are ported as such: `BlockBasic::insert`'s order keys,
  which tie in long blocks, and libstdc++'s `std::sort`, which `sortCallSpecs` uses on them.

Superseded: the minimal `ActionConstbase`, `ActionExtraPopSetup` and `ActionPrototypeTypes`
above are replaced by S1b's ports (`rust/ghidra-rs/src/decomp/action.rs`).

### S1b: done on branch `m3-s1b` (2026-11-12)

M8 8 / 8 and M500 500 / 500 identical at `break start heritage`; the funclink check stays
8 / 8 and 500 / 500. Details in `rust/README.md`, "Stage S1b". Between `funclink` and
`heritage` two things reach the output: the stack-pointer placeholder of every call
(`ActionFuncLink`) and read-only memory turned into constants (`ActionVarnodeProps` with the
prelude's `option readonly on`). Where it differs from the table row:

- `.cspec` reading, prototype models (`ProtoModel`, `ProtoModelMerged`, parameter entries,
  effects, likely trash), `FuncProto`/`FuncCallSpecs` and the actions are ported for unlocked
  prototypes only: the console locks none (`parse line` is S6; mercs2's `register_abi.csv` as
  locked custom-storage prototypes, decision 6, comes later in milestone 3 and plugs into
  `FuncProto`). Parameter and return trials (`ParamActive`) move to S4, where they are used.
- Call fixups: the console applies them only with `fixup apply` (never by callee name), so the
  corpora contain none; `ghidra-rs decompile` reads `fixup apply`, and a unit test checks
  mercs2's `__onexit` with two fixups against the reference. The snippet parser covers the
  subset of SLEIGH semantics snippets use and rejects the rest at load.
- Not ported because nothing for x86 or the console reaches them: `modelrules` (x86win.cspec
  has no `<modelrule>`), `override` (no override commands in the corpora), `userop` (x86-32
  declares no segment op and no `callotherfixup`), the core types of `type` (prototypes keep no
  types until S6), the `.pspec`'s register data (read by later stages).
- `<data_organization>` and `<global>` are skipped (types S6, scopes); any other unknown
  `.cspec` element is an error.
- Review fixes (second commit): `setModel` keeps a known extrapop, `getSpacebase` looks only at
  the last entry (a stack spill), `ParamListMerged::foldIn` by containment, join before stack
  in effect order, `loadFill` semantics and bfd section sizes for read-only memory, constants
  made in location order, the snippet parser rejects chained comparisons; one XML reader
  (`src/xml.rs`) for `.pspec`, `.cspec` and datatests. Mall (29,240 functions to `heritage`):
  about 6,200 functions per second on one thread, no panics.
- Required in S2/S4 (prototype state across decompiles): the C++ scope keeps each function's
  `funcp`; `ActionPrototypeTypes` sets its model, and `ActionStackPtrFlow`/
  `Funcdata::fillinExtrapop` (coreaction.cc, funcdata.cc) record its extrapop, which later
  decompiles of callers copy (`ActionDefaultParams` → `FuncCallSpecs::copy`). The Rust console
  now writes `fd.proto` back to the function's `map function` entry after `decompile`; S2/S4
  must port `fillinExtrapop` and check the 21 datatests that decompile more than one function
  per script (the decomp-diff corpora decompile one).
- Harness fix: a name mapped twice finds its first function, as the C++ does (mercs2 has
  several `__onexit`, `__SEH_prolog`, ...).

## Running stages in parallel

Strict chain first: S0 → S1a → S1b → S2. After S2 the work fans out. Under the cap of two
agents at a time, a sensible order:

1. S3 and S4
2. R1 and S6
3. R2 and R3
4. R4 and S8
5. R5 and S7
6. S9, then S10

Each rule batch is independent: the reference turns off every rule the Rust side does not have,
so batches can land in any order. Two batches touching the same pool only conflict in the rule
list, which is one table in one file.

## What the decompiler needs that ghidra-rs does not have

- **`.cspec`** (`x86win.cspec`): data organization (sizes, alignment), the four prototype models
  (`__stdcall` default, `__cdecl`, `__fastcall`, `__thiscall`) and `resolveprototype`, unaffected,
  killed-by-call and likely-trash registers, stack pointer and return address, and the 10
  `callfixup` snippets (`SEH_prolog`, `EH_prolog3`, `alloca_probe`, `security_check_cookie`, ...).
  The snippets are p-code source, so S1b needs a small parser for that syntax (not the whole
  SLEIGH compiler).
- **`.pspec`** (`x86.pspec`): today only `<context_set>` is read; the decompiler also wants the
  register data (hidden registers, `incidentalcopy`), and `volatile` ranges if any.
- **Data types**: a type store (core types, pointers, arrays, structs, unions, enums, typedefs,
  function types), in memory first, persisted in milestone 4.
- **Windows API types**: Ghidra applies prototypes from `windows_vs12_32.gdt` (7.6 MB) at import,
  which is why Ghidra prints `LeaveCriticalSection((LPCRITICAL_SECTION)...)`. A `.gdt` is a
  Ghidra database file, not a text format. Cheapest: export it once to a C header with a headless
  Ghidra script and read it with the C declaration parser S6 needs anyway (see Open decisions).
- **Symbols**: function names and entries (ghidra-rs has these), import names per IAT slot,
  global data labels and their types.

## What milestone 4's project DB has to keep

Everything a person changes while reversing, so a rerun keeps it:

- names: functions, globals, labels, namespaces/classes (RTTI gives these for mercs2);
- function prototypes: calling convention, parameter and return types and storage, including
  custom storage (mercs2 passes values in registers such as EAX: `in_EAX` above; its
  `register_abi.csv` contracts should become locked prototypes), no-return flags;
- local variables: name and type keyed the way Ghidra keys them (storage plus first-use address,
  or the dynamic hash from `dynamic.cc`);
- data types: the user's structs, enums, typedefs, function types, with stable ids, plus the
  imported Windows types;
- types of global data, and string/array definitions;
- comments (pre, post, end-of-line, plate) by address; the decompiler prints pre and plate ones;
- overrides: jump tables, flow overrides, call-site prototypes, equates/display formats;
- for each fact, whether a person set it or analysis guessed it, so analysis never overwrites a
  person's edit.

The decompiler only reads this through one query interface (like the C++ `Scope`/`Database`),
so milestone 3 can keep it in memory and milestone 4 swaps in the store.

## Where to diverge from Ghidra, and where not

Keep exactly as Ghidra:

- the action tree, rule order and every rule's conditions: the output depends on them;
- sequence numbers and the order ops and varnodes are created, so diffs stay exact;
- `.cspec`/`.pspec` semantics and the printed C format;
- where C++ orders something by pointer value, use a fixed order and write it down (and check
  whether the C++ output depends on it).

Diverge where it costs nothing in output:

- one library, in process: no XML protocol to a separate `decompile` process, no Java side;
- arenas and indices instead of pointers;
- decompile many functions in parallel (one `Funcdata` per thread, shared read-only
  architecture); Ghidra runs a few processes;
- skip what game work does not need: Java printing, BSim signatures, user rule compiler, graphs.

Later, behind options, never by default: improvements over Ghidra (for example x87 or
custom-ABI handling). They come after the port matches, so every difference is a choice.

## Decisions (2026-11-12)

1. **Direction:** Rust decompiler, C++ as reference, no FFI. Confirmed by the user.
2. **Gate:** `decomp_dbg` gates every stage; Ghidra headless only for S10 and final acceptance.
   (Claude's call, following the recommendation.)
3. **Exactness:** identical `print raw`, sequence numbers included. (Claude's call.)
4. **Windows types:** export `windows_vs12_32.gdt` once to a C header with a headless Ghidra
   script and read it with the S6 declaration parser. User's decision.
5. **Default names:** Ghidra's (`FUN_00401000`, `undefined4`). (Claude's call.)
6. **mercs2 register ABI:** `register_abi.csv` becomes locked custom-storage prototypes in
   milestone 3. User's decision.
7. **Reference patch:** keep the 20-line `print raw` patch for types and high variables under
   `rust/tools/`, so S6 and S7 are checked directly. User's decision.
