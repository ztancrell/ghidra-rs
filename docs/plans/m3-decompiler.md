# Milestone 3 plan: the decompiler

Written 2026-11-12 as a plan. Built so far: S0, S1a, S1b, S2, S3 and S4 (see their sections below).

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
| S6 | Types | `type`, `cast`, type parts of `typeop`, `ActionInferTypes` and friends, `database` (scopes), `unionresolve`, a C declaration parser (replaces `grammar.cc`) | 14k → 7k | `print raw` with types (see below) at `assignhigh`, also with locked prototypes (`decomp-locked-options.sh`) | M500 ≥ 95% and locked-prototype M500 ≥ 95% of non-SSE (superseded: "D files using `parse line` pass", moved to the x86-64 stage) | S2 |
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
  Superseded: S2 does not reach it; it moves to S4 (see "S2: done" below).
- Harness fix: a name mapped twice finds its first function, as the C++ does (mercs2 has
  several `__onexit`, `__SEH_prolog`, ...).

### S2: done on branch `m3-s2` (2026-11-12)

M8 8 / 8 and M500 500 / 500 identical at `break start paramdouble`; the heritage and funclink
checks stay 8 / 8 and 500 / 500. Details in `rust/README.md`, "Stage S2" and "Debugging
tools". Where it differs from the table row:

- Debugging tools first (`rust/tools/`): `VERBOSE=1`/`ORDER=easy`/`STOP=1`/`CONTINUES=N` for
  `decomp-diff.sh`, `decomp-show.sh` (side-by-side diff at the first differing op),
  `decomp-rank.sh` (corpus by loops and blocks), `decomp-bisect.sh` (first action and hit where
  the engines differ).
- `break start paramdouble` stops after the first heritage pass only, which links the register
  and unique spaces (SLEIGH gives ram a delay of 1, the stack 2). The second pass is reached
  only after `paramdouble` and the rest of the main loop with its rule pools; the reference
  cannot skip them (`option currentaction` turns off groups, but the stack pass needs base
  actions such as `ActionSpacebase`), so "compare at every heritage pass" has to wait for S4
  and the rule stages. Ported: pass 0 in full; a later pass fails loudly.
- Not ported, for that reason: `varmap` (stack ranges), the stack and ram paths of heritage
  (load/store guards, placeholders, revisited markers, indexed stack pointers, scope
  properties), and `cover` (nothing before merging, S7, uses it).
- The action framework (`actiontree.rs`) is ported in full except rule pools: statuses,
  repeat, restart (nothing asks for one yet), breakpoints, `continue`.
- The varnode bank keeps readers for every edit and the location order from the first
  heritage pass on (built there in one go; S1 code now edits
  through `op_set_input`/`op_set_output`), as heritage reads both.
- The S1b required item (prototype state across decompiles) moves to S4: `fillinExtrapop` is
  in `ActionStackPtrFlow`, after `paramdouble`, and the 21 multi-function datatests need the
  Rust console to load a `<binaryimage>` first.
- Console fixes found with the Mall check: a `nocode` function prints `No code for <name>`
  (8 duplicate names pick an import first), and an unmapped address reads `Unable to load 512
  bytes` as the C++ loader words it. Of the 101 Mall failures, 97 match decomp_dbg; 4 in
  garbage code differ in flow (one verified: a switch the S1a stand-in does not recover, S3).

### S3: done on branch m3-s3 (2026-11-12)

M8 8 / 8 and M500 500 / 500 identical at `break start paramdouble`; every function in which
ghidra-rs meets a jump table (2,051 of mercs2's functions) 1,934 / 2,050 (0xa4e8c2 left out:
the reference had not finished it after 35 min); the 116 others are 115 in obfuscated code
past 0x1000000 and 0x7c1f30, where the reference reads a garbage target. Details in
`rust/README.md`, "Stage S3". Where it differs from the table row:

- The partial function the C++ recovers a table from has been through the rule pool and the
  later heritage passes. Neither exists yet, so `jumptable.rs` has three stand-ins that read
  the raw p-code as the rules leave it (constant folding, x86 guard flag logic as one
  comparison, constants in slot 1). R1/R2 replace them: when those rules land, the partial
  should run them (`action::jumptable_partial`) and the stand-ins should go. Superseded
  (R2): the partial runs the `jumptable` root action and two stand-ins are gone; the fold
  through read-only loads stays until R5 (see "R2" below). The 115
  obfuscated-code differences need stack heritage (S4 and later).
- Superseded (R3 part two): the main loop runs `calc_nz_mask_unfolded`, without the constant
  folding the partial function needs. Superseded (R2 merge): `calc_nz_mask` no longer folds;
  the partial function calls `jumptable::fold_constants` first.
- `ActionNonzeroMask` is ported inside `jumptable.rs` (`calc_nz_mask`), because the guards
  read the masks; the main loop's `ActionNonzeroMask` (group `analysis`, which S4
  leaves off and unported; the R-stages) should call it and
  `Funcdata::nzm` then holds the masks of the function itself.
- memstate.cc and most of emulate.cc are not needed (the jump-table emulator keeps a value per
  varnode); the value-set solver of rangeutil.cc is not used by jump tables. Not ported:
  `fail_callother` (stops with an error; 2 functions in obfuscated code), `fail_return`,
  retrying an unreachable-looking table, unrolled guards, multistage tables, overrides,
  `JumpAssisted`, label recovery and guard folding (`recoverLabels`, after `paramdouble`).
- Debugging: `GHIDRA_RS_JT_DEBUG=1|2` on ghidra-rs, and the reference patch's `DECOMP_JT_RAW`
  prints the C++ partial function.
- Speed: Mall to `heritage` 9.4 s → 69.7 s; 49 s of it is one function (0xa4e8c2, a partial
  function of 780,000 ops), the other 2,115 partial functions about 11 s.

### S4: done on branch `m3-s4` (2026-11-12)

`print raw` at `break start assignhigh` with `rust/tools/corpus/s4-options.txt` on both sides:
M8 8 / 8, M500 446 / 500 (53 functions need `ActionLaneDivide`, below); the
paramdouble check stays 500 / 500. Details in `rust/README.md`, "Stage S4". Where it
differs from the table row:

- The check switches off every group of a later stage and the remaining rules, not only
  `analysis`, `cleanup`, `typerecovery` (those three leave the `subvar`, `stackvars`,
  `blockrecovery`, ... groups on, whose rules and structuring change the output).
- `ActionLaneDivide` (R3 in the table) is in group `base` and cannot be switched off: the
  M500 functions using whole SSE registers differ until R3 ports it. Superseded: R3 ported it (498 / 499 now).
  Pass bar: 446 / 447 (every function the reference finishes)
  identical without them; with them the bar is not reached.
- `multicse` and `conditionalconst` are in group `analysis` (off), so they wait for the rule
  stages; `paramid.cc` belongs to the `paramid` root action, which the console's `decompile`
  does not run, so it is not ported. `condexe.cc` and `ActionNodeJoin` are detected only: a
  candidate fails loudly (none in M500).
- Also needed and ported: the ram heritage pass (store and return guards, call placeholders),
  join varnodes for two-piece outputs, the `.pspec` `<incidentalcopy>` registers, code
  references as annotations, and the CFG edits of `funcdata_block.cc` the actions use.
- The S1b/S2 required item: `fillinExtrapop` is only called from `callgraph.cc`, so a
  decompile records no extrapop for later ones; nothing to port for the console.
  Superseded: "S2/S4 must port `fillinExtrapop`" above.
- Locked prototypes (decision 6) are not needed by S4; the locked paths of `fspec.cc` remain.

### S6: partial on branch `m3-s6` (2026-11-13)

`print raw` with types at `break start assignhigh` (`DECOMP_RAW_EXTRA=1`,
`rust/tools/corpus/s6-options.txt`: the S4 options with `typerecovery` on and its five R5 rules
toggled off; superseded (R5): they are on now): M8 8 / 8, M500 446 / 500: identical on every function the reference finishes (499) except the 53 that use whole SSE registers and wait for `ActionLaneDivide` (R3), as in S4. Superseded: with R3 merged, 498 / 499 (0x4919f0 differs), see "R3". Details in `rust/README.md`, "Stage S6". Where it differs
from the table row:

- Ported: the type store (`types.rs`, the kinds inference reaches with the rules off, plus
  structs, unions, enums and typedefs for `parse line`), `ActionStartTypes`,
  `ActionInferTypes`, `ActionConstantPtr` and the type parts of `typeop.cc` for every op the
  rules-off IR has (`infertypes.rs`), and the `parse line` declaration parser (`cparse.rs`).
  `database.cc` is a stand-in: the global scope answers from the console's `map function` and
  `map externalref`, the local scope holds no symbols (`localrecovery` is off) and has the
  default local range plus x86win's stack parameter range.
- Bar not reached for `parse line`: every D `parse line` but bit-fields (R5) and one
  `pointer setting` type parses, but an `extern` declaration locks a prototype, which is not
  ported, so the console fails on it; the datatests also print C (S9), so none can pass yet.
  Superseded: round two locks prototypes, and round three moves the D check to the x86-64
  stage.
- Left for the S6 remainder: locked prototypes (`fspec.cc` locked paths, also decision 6's
  register ABI), `cast.cc` and `ActionSetCasts` (after `assignhigh`, checked with S9),
  `unionresolve`, partial types and `TypePointerRel`, `<data_organization>` (struct layout),
  function types with prototypes, the scopes of `database.cc`.
  Superseded: rounds two and three port locked prototypes and `<data_organization>`; see
  round three for what is left.
- Types are one factory per function (copied from the architecture's at `decompile`), so the
  C++ order by hashed type id, reached only for pointer chains ten deep, is creation order here.

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
come with R5. Superseded (R5): ported, see "R5". Every bar rerun on the merged binary: S6 unlocked, locked `void`, locked `int4`
and callees with a stack parameter each M8 8 / 8, M500 446 / 446 non-SSE (446 / 500; the misses
are the 53 SSE functions and 0x4c48d0, which the reference does not finish); S4 regression
M8 8 / 8; R1 check M8 8 / 8, M500 451 / 453.

### R1: done on branch `m3-r1` (2026-11-13)

The rule pool and 19 rules (list in `rust/README.md`, "Stage R1"). Check: `print raw` at
`break start assignhigh` with `rust/tools/corpus/r1-options.txt` (S4's groups, `analysis` on,
the 97 unported rules of the groups that are on switched off) and
`DECOMP_SKIP_ACTIONS=multicse,shadowvar,condconst` (the three `analysis` actions not
ported; a check-only switch the reference patch reads too, and each action leaves the list
when it is ported). The options come from `rust/tools/r1-options.sh`.

Bar (user decision 2026-11-13): M500 ≥ 98 % identical among the functions that do not need
`ActionLaneDivide` (R3), listed in `rust/tools/corpus/m500-lanedivide.txt` (46: the reference
output changes when `lanedivide` is skipped too). M8 8 / 8; M500 451 / 453 (99.6 %) of the
others the reference finishes (451 / 500 in all): the bar is reached; S3's paramdouble check stays
500 / 500. Fixed in round two: the action is `condconst`, not `conditionalconst` (the skip
missed it), `setCopyImmed`/`hasNoImmediateCopy` (blocks emptied by copy propagation stay), dead
code reads the computed non-zero masks. Round three: `varnodeprops` replaces reads of a varnode
whose non-zero and consume masks share no bit by 0 (the x87/SSE carry flags, 11 functions, and
0x440590), and removing unreachable blocks is ported (0x6c2570). Left: 0x47a6b0
(`ActionConditionalExe` merging two blocks on equal conditions) and 0x6fa6e0 (a zero
replacement the reference makes later than ghidra-rs). The jump-table stand-ins stay until R2 (the
partial function needs the comparison rules too).

### R2: done on branch `m3-r2` (2026-11-13)

50 rules of `oppool1` (26 bit and shift, 15 comparison, 9 boolean) and 2 of the `cleanup` pool
(list in `rust/README.md`, "Stage R2"), in `rules/bits.rs`, `compare.rs`, `boolean.rs`,
`cleanup.rs`. Check as R1, with `r1-options.txt` regenerated (group `cleanup` on, its nine other
rules off; 17 `togglerule`s with R3 and R4 merged) and lane division on both sides: M8 8 / 8; M500
498 / 499 of the functions the reference finishes (99.8 %, bar 98 %: reached; 495 / 499 with
R3 alone). Superseded: 452 / 453 of R1's set before the merge with R3. Where it differs from the
table row:

- Not ported: `threewaycomp`, `conditionalmove`, `orpredicate`, and the `cleanup` rules that read
  data-types (`addunsigned`, `subright`, `piecestructure`, `andstructure`) or belong to R3 to R5.
- The partial function of jump-table recovery runs the `jumptable` root action (the tree of
  `universal` with its groups; eight actions left out while they are not ported, of which
  `restructurevarnode`, `condconst` and `normalizebranches` can change table recovery) instead of
  S3's stand-ins, with `jumptablerecovery_on` gating heritage's dead-code delay, `lastChanceLoad`
  and `donothing`; `analyzeGuards` is the C++ loop. Left: the fold through read-only loads
  (`RuleLoadVarnode`, R5). S3 recheck at `paramdouble`: M8 8 / 8, M500 500 / 500, switch
  corpus 1,947 / 2,050 (1,934 before).
- With R3 part two and R4 merged: the R1/R2/R3 check, the subvar check and the R4 check (all
  with group `cleanup` on) are each M8 8 / 8, M500 498 / 499 (497 / 499 before the merge).
- `ActionNonzeroMask` on the function itself no longer reads folded constants (an R1
  shortcut that sharpened masks beyond the C++'s).
- Fixed on the way: removing unreachable blocks whose values are read in other removed blocks
  (`descendantsOutside`, 0x74fae0).
- S4 M8 8 / 8, M500 498 / 500; S6 unlocked M8 8 / 8, M500 498 / 500; locked `void`
  498 / 500, `int4` 498 / 500, callees with a stack parameter 498 / 500.
- Left: 0x47a6b0 (`ActionConditionalExe`, as in R1).

### R3: in part on branch `m3-r3` (2026-11-13)

Ported: `ActionLaneDivide` (`decomp/lanedivide.rs`: the action and `LaneDivide` of `subflow.cc`),
`transform.cc` (`decomp/transform.rs`), the `.pspec` `vector_lane_sizes` records, and 21 rules of
`oppool1` (list in `rust/README.md`, "Stage R3"), plus `ActionVarnodeProps::handleExtendedZero`.
Superseded: the `lanedivide` exception of S4 and R1 (an action that did nothing) and the bar taken
over M500 less `m500-lanedivide.txt`; `lanedivide` now runs on both sides.

Check as R1 (`r1-options.txt` regenerated: 76 `togglerule`s; `DECOMP_SKIP_ACTIONS` unchanged):
M8 8 / 8; M500 495 / 499 of the functions the reference finishes (99.2 %, bar 98 %: reached).
Of the 46 lane-divide functions 44 are identical; of the other 453, 451 as in R1. S3's
paramdouble check stays 500 / 500; the S4 check is now 498 / 499 (was 446). Misses: 0x47a6b0
and 0x6fa6e0 as in R1; 0x4891e0 (a zero replacement ghidra-rs makes one main-loop pass before
the reference, the cause of 0x6fa6e0 seen from the other side); 0x4919f0 (the reference empties
a block whose branch ghidra-rs keeps, also under the S4 options, so not a rule).

Not ported, left for a follow-up (R3b):

- The `subvar` group: `RuleSubvarAnd`, `RuleSubvarSubpiece`, `RuleSubvarCompZero`,
  `RuleSubvarShift`, `RuleSubvarZext`, `RuleSubvarSext`, `RuleSplitFlow` and their engines in
  `subflow.cc` (`SubvariableFlow`, `SplitFlow`; `SubfloatFlow` is R4's). The group is off in the
  check on both sides, so the bar does not see them; porting them needs a check with `subvar` on.
- `RulePiecePathology` (group `protorecovery`, switched off by `togglerule`): it needs
  `setInputBytesConsumed`/`setReturnBytesConsumed` in `fspec.rs` and their readers in dead code.
- `prefersplit.cc`: no x86 `.cspec` has `<prefersplit>`, so nothing runs it; not ported.
- Superseded: "`LaneDivide::setReplacement`'s type-lock test is left out". It is ported
  (review round, after the merge with S6), with the other review fixes listed in
  `rust/README.md`, "Stage R3".

Merged with S6 (`master` into `m3-r3`, 2026-11-13); every bar rerun on the merged binary: R3
check M8 8 / 8, M500 495 / 499; R1 set 451 / 453; paramdouble 500 / 500; S4 check M8 8 / 8,
M500 498 / 500; S6 unlocked, locked `void`, locked `int4` and callees `int4(int4 a)` each
M8 8 / 8, M500 498 / 500 (498 / 499 the reference finishes; the miss is 0x4919f0).
Superseded: the "446 / 446 non-SSE" results of the S6 section above.

### R3 part two: done on branch `m3-r3b` (2026-11-13)

The `subvar` group: `SubvariableFlow` (`decomp/subflow.rs`), `SplitFlow` (`decomp/splitflow.rs`,
on `transform.rs`), the rules `subvar_and`, `subvar_subpiece`, `splitflow`, `subvar_compzero`,
`subvar_shift`, `subvar_zext`, `subvar_sext` (`rules/subvar.rs`), and `piecepathology` with the
consumed-bytes hints dead code reads. Superseded: the "Not ported, left for a follow-up (R3b)"
items above for the `subvar` rules and `RulePiecePathology`. Still not ported: `RulePtrFlow`
(group `subvar`; switched off in the check), `RuleSubfloatConvert`/`SubfloatFlow` (group
`floatprecision`, R4), `SplitDatatype` (cleanup pool), `prefersplit.cc` (no x86 use).

New check, group `subvar` on (`rust/tools/corpus/subvar-options.txt`, from `r1-options.sh`):
M8 8 / 8, M500 497 / 499 (99.6 %, bar 98 %: reached). Existing bars: R3 check 497 / 499 (was
495; R1 set 452 / 453, lane-divide set 45 / 46), paramdouble 500 / 500, S4 and the four S6
checks 498 / 500 each. Two older faults fixed on the way (details in `rust/README.md`, "Stage
R3 part two"): the main loop's non-zero masks folded constants (0x6fa6e0, 0x4891e0), and
unreachable-block removal refused readers in other dead blocks. Left: 0x47a6b0
(`ActionConditionalExe`), 0x4919f0 (a block the reference empties).

### R4: done on branch `m3-r4` (2026-11-13)

Ported: the 20 division, remainder, sign and float rules of `oppool1` (list in
`rust/README.md`, "Stage R4"): `rules/div.rs`, `rules/modulo.rs`, `rules/floatrules.rs`, and
`RuleSubfloatConvert` with `SubfloatFlow` and `FloatFormat::convertEncoding` in
`decomp/subfloat.rs` (its own file: `subflow.rs` is R3b's). The 128-bit arithmetic of
`RuleDivOpt` and `RuleDivTermAdd*` is `u128`; a division by zero fails as `udiv128` throws.
`RuleFloatSignCleanup` belongs to the `cleanup` pool (R2) and is not ported here.

Check as R1 with group `floatprecision` on: `rust/tools/corpus/r4-options.txt` (written by
`r1-options.sh` next to `r1-options.txt`, now 59 `togglerule`s, 58 after the merge with R3 part two). M8 8 / 8; M500 495 / 499 of
the functions the reference finishes (99.2 %, bar 98 %: reached), the same four misses as R3
(0x47a6b0, 0x4891e0, 0x4919f0, 0x6fa6e0) and 0x4c48d0 not finishing on the reference. The bar
is meaningful: 90 M500 reference outputs change when the R4 rules are switched off (and
`floatprecision` is off), 7 with a division or remainder, 83 float; 89 of them are identical
(the miss is 0x4891e0, a miss of R3 already). S3 paramdouble 500 / 500; S4 and the four S6
checks: see `rust/README.md`, "Stage R4".

Merged with R3 part two (`master` into `m3-r4`, 2026-11-13); every bar rerun on the merged binary:
R4 check M8 8 / 8, M500 497 / 499 (the misses 0x47a6b0, 0x4919f0; 0x4c48d0 the reference does
not finish); subvar check and R3 check 497 / 499 each; paramdouble 500 / 500; S4 check and the
four S6 checks (unlocked, `void`, `int4`, callees) 498 / 500 each (0x4919f0; 0x4c48d0).
Superseded: the 495 / 499 above (0x4891e0 and 0x6fa6e0 are fixed by part two's non-zero masks)
and the callee check's 497 (the reference ran 0x5b59c0 this time).
### S8: in part on branch `m3-s8` (2026-11-13)

Ported: `ActionBlockStructure` end to end. `decomp/structure.rs` holds the structured hierarchy
(`Funcdata::sblocks`) as an arena of blocks with an enum for the `FlowBlock` subclass (graph,
copy, goto, multi-goto, list, condition, if, if/else, if-no-exit, if-goto, while-do, do-while,
infinite loop, switch), the edge edits of `FlowBlock`/`BlockGraph`, every `newBlock*`,
`buildCopy` with `installSwitchDefaults`, `isComplex`, `negateCondition` (which flips the basic
block's CBRANCH: `boolean_flip`, `fallthru_true` and the basic out edges) and `printTree`.
`decomp/collapse.rs` ports `CollapseStructure` (every rule, in the C++ order), `LoopBody`,
`TraceDAG` and `FloatingEdge`. `structureReset` clears the structure, as the C++ does.

Check (from `rust/`):

```sh
PRINT=$'print tree block\nprint raw' BREAK=assignhigh \
  DECOMP_SKIP_ACTIONS=prefercomplement,structuretransform \
  OPTIONS=tools/corpus/s8-options.txt tools/decomp-diff.sh m500
PRINT=$'print tree block\nprint raw' BREAK=assignhigh \
  DECOMP_SKIP_ACTIONS=multicse,shadowvar,condconst,prefercomplement,structuretransform \
  OPTIONS=tools/corpus/s8-r-options.txt tools/decomp-diff.sh m500
```

`s8-options.txt` is `s4-options.txt` and `s8-r-options.txt` is `r1-options.txt`, each without
the `blockrecovery off` line (`tools/r1-options.sh` writes both). Where it
breaks and why that is fair: `blockstructure` runs in the main loop, so `break start assignhigh`
stops after it and after the later main-loop passes that read the flipped branches. The two
`blockrecovery` actions between `cleanup` and `assignhigh`, `prefercomplement` and
`structuretransform`, are skipped on both sides: they only rework the finished structure
(swap if/else clauses, normalize flipped conditions, move for-loop ops), so both engines
compare the structure `blockstructure` built. `finalstructure` comes after the merge and cast
actions (S7, S9), so no break can reach it yet. Printing `print raw` too checks the CBRANCH flips
and edge swaps of the collapse rules on the basic blocks.

| check | M8 | M500 |
|---|---|---|
| rule groups off (`s8-options.txt`) | 8 / 8 | 499 / 500; 499 / 499 of the functions the reference finishes |
| rule-stage options (`s8-r-options.txt`) | 8 / 8 | 496 / 500; 496 / 499 of the functions the reference finishes (99.4 %) |

The miss in both is 0x4c48d0, which neither engine finishes within the timeout. The other
misses with the rule-stage options are R3's, unchanged: 0x47a6b0 (`ActionConditionalExe`), 0x4891e0
and 0x6fa6e0 (a zero replacement one main-loop pass apart). R3's fourth miss, 0x4919f0, is identical
here: it differs only with `blockrecovery` off. Existing bars on this branch: the R3 check M500 495 / 500 (495 / 499),
paramdouble 500 / 500, the S4 check 498 / 500, the S6 check (unlocked) 498 / 500: unchanged. Those
checks keep `blockrecovery` off, so `blockstructure` never runs in them.

After merging R2 (2026-11-13; `cleanup` on, `condnegate` ported): rules off M8 8 / 8, M500 499 / 499;
rule-stage options M8 8 / 8, M500 463 / 499. Superseded by the `ConditionalJoin` port below. The 35
new misses came from `ActionNodeJoin`:
`RuleCondNegate` now turns the flips `blockstructure` sets into BOOL_NEGATE ops, so two branches
get functionally equal conditions in different varnodes and the reference joins them
(`ConditionalJoin`), which ghidra-rs does not port (its detection only sees one shared varnode,
so it misses them silently). With `nodejoin` skipped on both sides the rule-stage check is
498 / 499 (miss 0x47a6b0, `ActionConditionalExe`). Ported since (below):
(`functionalEqualityLevel`, `nodeJoinCreateBlock`).

`ActionNodeJoin` is now ported (`decomp/nodejoin.rs`: `ConditionalJoin` with `findDups`,
`checkExitBlock`, `setupMultiequals`, `moveCbranch`, `cutDownMultiequals`, and
`Funcdata::nodeJoinCreateBlock`; it reuses R2's `functionalEqualityLevel`), replacing S4's
detection. With `nodejoin` running on both sides: rules off M8 8 / 8, M500 499 / 499; rule-stage
options M8 8 / 8, M500 498 / 499 (miss 0x47a6b0, `ActionConditionalExe`). The action changes the
reference output of 35 M500 functions under the rule-stage options; all 35 are identical.
Other bars on the same binary: R3 check 498 / 499, subvar and R4 checks 498 / 499, paramdouble
500 / 500; the S4 and S6 (unlocked) checks rise to 499 / 500 (499 / 499 the reference finishes):
0x4919f0, the miss R3 left "not traced", is a join of two branches on one condition, which S4's
detection let through.

Not ported, left for part two:

- Superseded (part two, below): `prefercomplement` and `structuretransform`: they need `opFlipInPlaceTest/Execute`,
  `opNormalizeFlip`, `replaceLessequal` and the boolean-flip table, which R2 ports
  (`rules/boolean.rs`, `rules/compare.rs` on `m3-r2`). Superseded: "blocked until R2 merges"; R2 is on master now, so they are next. The for-loop part
  of `BlockWhileDo::finalTransform` (`findLoopVariable`, `findInitializer`,
  `PcodeOp::isMoveable`) also comes with it.
- `finalstructure` (`orderBlocks`, `finalizePrinting`, `scopeBreak`, `markUnstructured`,
  `markLabelBumpUp`), `nextFlowAfter`, the case data of `BlockSwitch` (`grabCaseBasic`) and
  structured `printRaw`: needed by S9 only.
- `returnsplit` (group off in the check; needs `Funcdata::nodeSplit` and `gotoPrints`).
- `normalizebranches` needs nothing: its group is not in the `decompile` root's groups, so the
  console never runs it.

Review round (independent review of `collapse.rs` and `structure.rs` against the C++):
`ActionNodeJoin`'s detection skips a pair when either CBRANCH has `boolean_flip` set, as
`ConditionalJoin::findDups` does (`blockstructure` sets the flag earlier in the same main-loop
pass; before, ghidra-rs failed where the C++ skips); `newBlockSwitch` fails with "Could not get
switch leaf" when the switch's exit leaf (`getExitLeaf`) is not a copy; `printTree`,
`negateCondition` and `isComplex` use a work stack or a loop instead of recursion (deep nesting
is input-reachable); unit tests on hand-built graphs (if/else, a negated proper if, an
irreducible two-entry loop, a switch with a duplicated table target and a skip edge to the
exit; expected trees derived by hand from the C++). Bars after the round, unchanged: S8 M8 8 / 8,
M500 499 / 499 (rules off) and 496 / 499 (rule-stage options); R3 check 495 / 499; S4 and S6
checks 498 / 500.

### R5: in part on branch `m3-r5` (2026-11-13)

Slice 1 of five (the plan's suggested slices: pointer rules; `RuleLoadVarnode`/`RuleStoreVarnode`
and removing `jumptable::fold_constants`; double.cc; the `cleanup` leftovers; constseq and
bitfield). Ported: the `typerecovery` pointer rules `RulePtrArith` (with `AddTreeState`),
`RuleStructOffset0`, `RulePushPtr` (pool `oppool2`, until now an empty leaf) and `RulePtraddUndo`,
`RulePtrsubUndo` (`oppool1`), in `rules/ptrarith.rs`; `PcodeOp::stopsTypePropagation` in
`getLocalType` and `Varnode::stopsUpPropagation` in `propagateTypeEdge` (they land with the rules
that set them); `TypeOpPtradd::propagateType` (S6 failed on it) and `print raw` of PTRADD.
Superseded: the S6 notes "`stopsTypePropagation`/`stopsUpPropagation` stay unported" and "five
R5 rules toggled off" (`s6-options.txt` no longer switches them off).

Not ported, failing loudly where reached: `TypePointerRel` (the type store never makes one, so
`isFormalPointerRel` is false), struct sub-types inside the rules (`TypeStruct::getSubType`,
`isOffsetValid`, `nearestArrayedComponent`), unions (`needsResolution`), and
`AddTreeState::assignPropagatedType` (only after type recovery gives up). Documented difference: the add-tree and
local-add recursions, unbounded in the C++, fail with an error past depth 1,000 (`MAX_DEPTH`). Space-base types answer
`nearestArrayedComponent` with false: their scopes hold only functions and external references,
neither arrayed.

Check: `rust/tools/corpus/r5-options.txt` from `r1-options.sh` (groups `analysis`, `cleanup`,
`typerecovery` on; the script now also reads `oppool2`), with and without types:

```sh
export DECOMP_SKIP_ACTIONS=multicse,shadowvar,condconst
DECOMP_RAW_EXTRA=1 BREAK=assignhigh OPTIONS=$PWD/rust/tools/corpus/r5-options.txt rust/tools/decomp-diff.sh m8
DECOMP_RAW_EXTRA=1 BREAK=assignhigh OPTIONS=$PWD/rust/tools/corpus/r5-options.txt TIMEOUT=60 rust/tools/decomp-diff.sh m500
BREAK=assignhigh OPTIONS=$PWD/rust/tools/corpus/r5-options.txt TIMEOUT=60 rust/tools/decomp-diff.sh m500
```

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

Left for R5 (slices 2 to 5, not started): `RuleLoadVarnode`/`RuleStoreVarnode` (group
`stackvars`; a load or store through the stack pointer makes a stack-space varnode, which needs
the stack heritage pass, not ported; the constant-pointer path also needs `fillinReadOnly` after
the ram pass to replace `fold_constants` in the jump-table partial function, where `stackvars` is
on), double.cc, constseq.cc, bitfield.cc, and the `cleanup` rules that read types.

### S8 part two: in part on branch `m3-s8b` (2026-11-13)

Ported (`decomp/blocktransform.rs`): `ActionPreferComplement` and `ActionStructureTransform`
with `getSplitPoint`, the blocks' `flipInPlaceTest`/`flipInPlaceExecute`,
`BlockIfElse`/`BlockIfNoExit::preferComplement` (with `leafCount`, `structureDepth` and
`getHaltType` on the hierarchy), `finalTransform` (the basic block's `opNormalizeFlip`, R2's,
and `BlockWhileDo`'s for-loop recovery: `findLoopVariable`, `findInitializer`,
`PcodeOp::isMoveable`), and `Funcdata::opFlipInPlaceTest`/`opFlipInPlaceExecute` (with R2's
boolean-flip table and `replaceLessequal`). Superseded: part one's "`prefercomplement` and
`structuretransform` ... not ported" and the two names in the S8 checks' skip list.

Check (from `rust/`), as part one's with the two actions running on both engines:

```sh
PRINT=$'print tree block\nprint raw' BREAK=assignhigh DECOMP_SKIP_ACTIONS= \
  OPTIONS=tools/corpus/s8-options.txt tools/decomp-diff.sh m500
PRINT=$'print tree block\nprint raw' BREAK=assignhigh DECOMP_SKIP_ACTIONS=multicse,shadowvar,condconst \
  OPTIONS=tools/corpus/s8-r-options.txt tools/decomp-diff.sh m500
```

| check | M8 | M500 |
|---|---|---|
| rule groups off | 8 / 8 | 499 / 499 the reference finishes (0x4c48d0 times out) |
| rule-stage options | 8 / 8 | 498 / 499 (miss 0x47a6b0, `ActionConditionalExe`) |

Under the rule-stage options `prefercomplement` changes the reference output of 137 M500
functions and `structuretransform` of 10 (reference runs with and without each skipped);
all are identical. Unit tests: a for loop (flip normalization, loop variable, iterate op
moved, initializer), an if/else complemented in place, and a goto chosen by `TraceDAG`
(`structure.rs`; that expected tree is pinned from this port, not derived by hand).

`ActionReturnSplit` (`decomp/returnsplit.rs`: `gatherReturnGotos`, `isSplittable`, `gotoPrints`,
`nextFlowAfter` per kind with the switch's cases in `grabCaseBasic` order, `Funcdata::nodeSplit`
and `CloneBlockOps`) is ported with a unit test (a goto into a RETURN block split off); superseded: "its group is off in the S8 option files". Group `returnsplit` is now on in both S8
option files (`tools/r1-options.sh`); with it running on both sides: rules off M8 8 / 8, M500
499 / 499; rule-stage options M8 8 / 8, M500 498 / 499; it changes 52 reference outputs, all
identical. Fixed with it: `DECOMP_SKIP_ACTIONS` was ignored for the `fullloop` actions on the
ghidra-rs side (`action.rs`). The rule check stays 498 / 499. The case data of `BlockSwitch`
(`grabCaseBasic` labels, `compareCase`) is not needed by these actions (`nextFlowAfter` reads only
the case order, which is the components' and the goto edges'), so it waits for printing.
Review follow-ups: the C++ runs `ActionPreferComplement` and `ActionStructureTransform` a second
time after the second `ActionBlockStructure` without op modifications (coreaction.cc 6138-6139);
their entry points (`prefer_complement_no_mods`, `structure_transform_no_mods`) are ready and get
their rows with S7's tree past `assignhigh`. CAST is moveable (its eval type is unary). Left for
later stages: the `f_flip_path` toggle of `swapEdges` (read by jumptable.cc's guard folding:
`switchnorm`), `f_duplicate_block` and `f_joined_block` (read by printc.cc's labels), the data type
of the code reference `CloneBlockOps` makes for an annotation (printing), and the `nonprinting` and
`special_print` bits `buildOpClone` keeps (S7 adds them).
Part three (`ActionFinalStructure`, structured `printRaw`) waits for S7: the actions between
`structuretransform` and `finalstructure` are the merge, prototype, naming and cast actions, and
`finalizePrinting` reads what they set (`isExplicit`, high variables), so a check that skips them
would only compare a state the C++ never prints.

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
