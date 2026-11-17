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
- **Switch**: every function in which ghidra-rs meets a jump table (2,050; 0xa4e8c2 left out),
  `rust/tools/corpus/switch.txt` (S3). **r5d-adc**: 215 functions under 600 bytes with an ADC,
  SHLD or SHRD (64-bit arithmetic in register pairs), `rust/tools/corpus/r5d-adc.txt` (R5 slice 3).
- Every check on these corpora runs from one script, `rust/tools/bars.sh` (rust/README.md,
  "Every check at once").
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
  Superseded (stack heritage, below): the stack pass, its stack-pointer tracing and the
  stack part of the local scope are ported; revisited markers and the load-guard analysis are not.
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
  (superseded: ported on `m3-cast`, "Casts: `setcasts`" below)
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
- Left for a later S6b: locked stack parameters of the decompiled function (stack heritage;
  Superseded: done with stack heritage, below), varargs and hidden-return locked prototypes, resizing an output in `commitNewOutputs` and
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
  `restructure_varnode`, `condconst` and `normalizebranches` can change table recovery) instead of
  S3's stand-ins, with `jumptablerecovery_on` gating heritage's dead-code delay, `lastChanceLoad`
  and `donothing`; `analyzeGuards` is the C++ loop. Left: the fold through read-only loads
  (`RuleLoadVarnode`, R5). S3 recheck at `paramdouble`: M8 8 / 8, M500 500 / 500, switch
  corpus 1,947 / 2,050 (1,934 before).
  Superseded (branch `m3-aliasupdate`): `restructure_varnode` runs in the partial function
  (`mapstate.rs`); seven actions are left out, of which `condconst` and `normalizebranches` can
  change table recovery.
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
### S7: in part on branch `m3-s7` (2026-11-13)

Ported: the merge range `assignhigh` .. `copymarker` (`merge.rs`, `variable.rs`, `cover.rs`;
list in `rust/README.md`, "Stage S7"). Check: `print raw` with types and high variables at
`break start inputprototype` (then the first action after `copymarker` whose group is on and that
was not ported; superseded: ported in "Tail", the break point stays), `DECOMP_RAW_EXTRA=1`:

```sh
cd rust
DECOMP_RAW_EXTRA=1 DECOMP_SKIP_ACTIONS=multicse,shadowvar,condconst BREAK=inputprototype \
  OPTIONS=tools/corpus/r1-options.txt tools/decomp-diff.sh m500
DECOMP_RAW_EXTRA=1 BREAK=inputprototype OPTIONS=tools/corpus/s6-options.txt tools/decomp-diff.sh m500
```

- High-variable ids: `rust/tools/decomp-ref.patch` now numbers each high by its first appearance
  in one `print raw` (`{hN}`, reset by `Funcdata::printRaw`), and `print.rs` does the same.
  Superseded: the first scheme, the create index of the high's name representative, which also
  compared varnode create indices from before merging (it found one real bug, the RETURN order
  of `ActionPrototypeTypes`, fixed; and one left, below).
- Nothing extra is skipped: between `assignhigh` and `inputprototype` the actions not ported are
  in groups the options switch off on both sides (`blockrecovery`: `latedonothing`,
  `blockstructure`, `prefercomplement`, `structuretransform`; `localrecovery`:
  `outputprototype`; `dynamic`: `dynamicsymbols`).
- Results: M8 8 / 8 with both option files; M500 (of the 499 the reference finishes)
  `r1-options` 489 / 499 (98.0 %), `s6-options` 492 / 499 (98.6 %). Bar (95 %): reached with both.
- Misses by cause: misses with `r1-options`: 3 need `VariablePiece` (0x402c20, 0x405990, 0x62f0d0: overlapping address-tied varnodes of different sizes, fail loudly); 4 are the R1/R3 misses (0x47a6b0, 0x4891e0, 0x4919f0, 0x6fa6e0); 3 print `<code() *>` on the reference for a global INDIRECT output where ghidra-rs keeps `xunknown4` (0x48a430, 0x5c5940, 0x6b3730: a type set before merging that only this check shows, as the R1/R3 check prints no types). With `s6-options`: 6 need `VariablePiece` (0x402c20, 0x405990, 0x4c0070, 0x62f0d0, 0x757810, 0x7586e0) and 0x4919f0 (as in S4).
- Left for S7b: `VariablePiece`/`VariableGroup` (`groupWith`; needed by overlapping
  address-tied varnodes of different sizes, the main miss), `dynamic.cc` and
  `ActionDynamicSymbols`, symbols and `mergeMultiEntry` (needs the local scope of `database.cc`),
  union resolution of trimmed COPYs, `stripType`, `markPurePaddingCopies`, the STORE guards of
  `StackAffectingOps` (stack heritage). A varnode create-index difference before merging
  (an `ESP = ESP(i) + c` output created one varnode earlier than the reference in 0x401080 and
  0x9eec5e) is not visible with the first-appearance ids; its cause is not found yet.
- Regressions on the final binary: R3 check 495 / 499, S3 paramdouble 500 / 500, S4 498 / 500, S6
  498 / 500.

Review round (same branch, 2026-11-13), after an independent line-by-line review:

- `Cover::intersect(PcodeOpSet)` ported with its exact walk (sorted set, block starts, the
  skipped set block after a tested one); the first round answered "any call strictly inside
  the cover", which refused merges the C++ allows. Superseded: "the C++ sort by block is left
  out".
- The create-index difference above was `ActionExtraPopSetup` making the unknown-extrapop
  INDIRECT's iop varnode last (the C++ `newIndirect` makes it first); fixed. Superseded: "its
  cause is not found yet".
- The `<code() *>` misses were global symbol types: the C++ gives them when a varnode is made,
  ghidra-rs before each inference pass, and with `typerecovery` off none runs; `assignhigh` now
  applies them too. Superseded: the 3 type misses above.
- Also: dead RETURNs skipped in `ActionPrototypeTypes`; `groupPartials` fails loudly on a
  registered proto-partial root; no common dominator is an error; wrapping end offsets; cover
  dirtying as the C++ (`totalReplace` only through `opSetInput`).
- New check mode `DECOMP_RAW_EXTRA=2`: also each varnode's create index (`{cN}`), since `{hN}`
  only labels the merge partition of printed varnodes (no create indices, representatives,
  covers or unprinted highs).
- Results: M8 8 / 8 in all four runs; M500 `r1-options` 492 / 499, `s6-options` 492 / 499, the
  same with create indices (no extra difference). Misses: `VariablePiece` (3 rules on, 6 types
  on), and the R1/R3 misses (0x47a6b0, 0x4891e0, 0x4919f0, 0x6fa6e0; only 0x4919f0 with
  types on). Superseded: 489 / 499 above. Regressions: R3 check 495 / 499, S3 paramdouble 500 / 500, S4 check 498 / 500, S6 check 498 / 500, all unchanged (the varnode creation-order fix shows only in create indices, which those checks do not print).

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
Superseded: double.cc is ported (slice 3, below).

**R5 slice 3 (double.cc)**, branch `m3-r5-double` (2026-11-13). Ported in the C++ order and
conditions: `SplitVarnode` and every form (`AddForm`, `SubForm`, `LogicalForm`, `Equal1Form`,
`Equal2Form`, `Equal3Form`, `LessThreeWay`, `LessConstForm`, `ShiftForm`, `MultForm`, `PhiForm`,
`IndirectForm`, `CopyForceForm`), `RuleDoubleIn` (its `reset`: `Funcdata::double_precis_on`, set
from `ActionTree::perform`), `RuleDoubleOut` (with `Funcdata::combine_input_varnodes`),
`RuleDoubleLoad`, `RuleDoubleStore`, the `precislo`/`precishi` marks (`VnFlags` 1 << 27, 1 << 28)
and their readers (`RulePullsubMulti`, `RuleSubCommute`, `RuleSubNormal`, `RuleSplitFlow`,
`SplitFlow::traceForward`, the setter in `buildOutputFromTrials`), and `ActionParamDouble`
(unported join path errors). Code in `rust/ghidra-rs/src/decomp/rules/double/`; details and
check commands in `rust/README.md`, "R5 slice 3". Not modelled: symbol entries, big-endian.
Check (`r5d-options.txt`, break `assignhigh`): M8 8 / 8, M500 498 / 499 (0x47a6b0), exercise
corpus `r5d-adc.txt` 215 / 215; the double rules change 0 M500 reference outputs and 23 of the
215 r5d-adc ones, all matched. R1 check (`r1-options.txt`) rerun on the branch: M500 498 / 499.

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
Superseded: "Left for R5 (slices 2 to 5, not started): `RuleLoadVarnode`/`RuleStoreVarnode`"
above, and in "Stack heritage" below "Invisible to the check until R5: every LOAD/STORE through
the stack pointer" and "`resolveSpacebaseRelative` is R5's".

`master` 836d04baee (S8 part two, stack heritage) is merged into `m3-r5b`. One conflict,
`rust/tools/r1-options.sh`: both sides kept (this branch's `r5c-options.txt` and
`r5d-options.txt` lines, master's S8 lines that also switch `returnsplit` on).

Ported (`rules/stackvars.rs`, group `stackvars`, the last two rules of `OPPOOL2` as in
`universalAction`): `RuleLoadVarnode` and `RuleStoreVarnode` with `correctSpacebase`,
`vnSpacebase`, `checkSpacebase`, `FuncCallSpecs::resolveSpacebaseRelative` (a call's stack
offset from its placeholder, or from the first stack parameter of a locked prototype) and
`Funcdata::opCollapseIndirectsForCopy`; the `stack_store` mark (`VnFlags::STACK_STORE`,
1 << 29) and its reader in `ActionDirectWrite`; `ActionInferTypes::propagateSpacebaseRef` and
`propagateRef` with `TypeFactory::getExactPiece` (until now a loud error once an unlocked stack
varnode existed); `ParamListStandard::characterizeAsParam` for stack entries
(`ParamList::characterize_stack`), so a call whose stack offset is known registers stack trials
in `guardCalls`.

Open, failing loudly:

- Stack parameter trials of a call that has no locked prototype: `ActionActiveParam` with
  trials (`checkInputTrialUse` with `AliasChecker`, `finalInputCheck`, `fillinMap`,
  `buildInputFromTrials`) is not ported. With the rules on, almost every function that pushes
  arguments reaches it, so the unlocked check below is far from its bar. This is the next piece.
  Superseded: ported on branch `m3-ap`, "Parameter trials of calls" below.
- An INDIRECT of the old STORE that overlaps the new COPY in part (the PIECE/SUBPIECE rebuild
  of `opCollapseIndirectsForCopy`); partial structs, arrays and unions in `getExactPiece`.
- Not modelled: `PcodeOp::isStoreUnmapped` (set only by `ActionRestructureVarnode`, not
  ported), word sizes other than 1.
  Superseded: `ActionInternalStorage` sets that mark, and no x86 model declares internal
  storage; `ActionRestructureVarnode` never did.
- The jump-table partial function still runs without the two rules and with
  `jumptable::fold_constants` (the C++ has `stackvars` on there and `fillinReadOnly`); the tree
  builder leaves them out of the `jumptable` root (`action.rs`).
  Superseded (branch `m3-swsilent`): the partial function runs with the two rules; without them
  and with `fold_constants` only as the fallback when its stack heritage reaches a path not
  ported (`Flow::build_partial`, flow.rs).

Checks, at `break start assignhigh` with types printed (`DECOMP_RAW_EXTRA=1`).
`r1-options.sh` now also writes `rust/tools/corpus/r5s-options.txt` (`r5-options.txt` with
`stackvars` on):

    rust/tools/decomp-locked-options.sh void rust/target/stack-lock.txt "int4 a, int4 b"
    grep -v 'decompile stackvars off' rust/target/stack-lock.txt > rust/target/lock-sv.txt
    grep -v 'decompile stackvars off' rust/tools/corpus/s6-options.txt > rust/target/s6-sv.txt
    { cat rust/tools/corpus/r5s-options.txt; grep '^parse line' rust/target/stack-lock.txt; } > rust/target/r5s-lock.txt
    DECOMP_RAW_EXTRA=1 BREAK=assignhigh OPTIONS=rust/target/lock-sv.txt rust/tools/decomp-diff.sh m500
    DECOMP_RAW_EXTRA=1 BREAK=assignhigh OPTIONS=rust/target/s6-sv.txt rust/tools/decomp-diff.sh m500
    export DECOMP_SKIP_ACTIONS=multicse,shadowvar,condconst
    DECOMP_RAW_EXTRA=1 BREAK=assignhigh OPTIONS=rust/target/r5s-lock.txt rust/tools/decomp-diff.sh m500
    DECOMP_RAW_EXTRA=1 BREAK=assignhigh OPTIONS=rust/tools/corpus/r5s-options.txt rust/tools/decomp-diff.sh m500

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

Bars on the merged tree (M500; M8 is 8 / 8 in every check). "Merged" is the binary of the
merge alone, "final" the binary of this commit (merge plus slice 2):

| check | before | merged | final |
|---|---|---|---|
| R5 untyped (`r5-options`) | 497 / 498 | 497 / 498 | not rerun |
| R5 typed | 497 / 498 | 497 / 498 | 497 / 498 |
| R5c (`r5c-options`) | 494 / 498 | 494 / 498 | not rerun |
| R5d (`r5d-options`), `r5d-adc.txt` | 498 / 499, 215 / 215 | 498 / 499, 215 / 215 | not rerun |
| stack check (`stack-lock.txt` at `assignhigh`) | 498 / 499 | 498 / 499 | 498 / 499 |
| S7 print with `stack-lock.txt` | 492 / 499 | 492 / 499 | 492 / 499 |
| `funclink`, `heritage` | 500 / 500 | 500 / 500 | not rerun |
| S3 `paramdouble` | 500 / 500 | 500 / 500 | not rerun |
| S3 switch corpus | 1,947 / 2,050 | 1,947 / 2,050 | not rerun |
| S4 | 499 / 500 | 499 / 500 | 499 / 500 |
| S6 unlocked | 499 / 500 | 499 / 500 | 499 / 500 |
| S6 locked `void`, locked `int4` | 499 / 500 each | 499 / 500 each | not rerun |
| S6 callees with a stack parameter | 499 / 500 | 499 / 500 | 499 / 500 |
| R1/R2/R3 (`r1-options`) | 498 / 499 | 498 / 499 | 498 / 499 |
| subvar, R4 | 498 / 499 each | 498 / 499 each | not rerun |
| S7 `r1-options` (also with create indices), `subvar-options`, `r4-options` | 498 / 499 | 498 / 499 | not rerun |
| S7 `r5-options` | 497 / 498 | 497 / 498 | not rerun |
| S7 `s6-options` | 493 / 499 | 493 / 499 | 493 / 499 |
| S7 `s6-options` with create indices | 493 / 499 | 493 / 499 | not rerun |
| S8 rules off | 499 / 499 | 499 / 499 | not rerun |
| S8 rule stage | 498 / 499 | 498 / 499 | 498 / 499 |

No bar fell, and the misses are the known ones (0x4c48d0 in every "/ 500"; 0x47a6b0 in the
rule stages; 0x40ad80 in the stack check; the 6 `VariablePiece` functions in S7 with types;
the three `HeapSequence` functions in R5c). M8 is 8 / 8 in all 26 checks on the merged binary.
"Not rerun" on the final binary: the options of those checks leave `stackvars` off, and the
jump-table partial function runs without the two rules, so the slice 2 code they can reach is
`propagateRef` (typed checks only) and the stack case of `justifiedContain`; they were measured
on the merged binary only. `cargo test --release` 89 tests, `cargo clippy --release
--all-targets -- -D warnings` and `cargo fmt --check` clean.

**R5 review fixes** (branch `m3-r5b`, 2026-11-14; superseded: "paused before the final pass finished": the full pass ran on `m3-int`, "Integration: `m3-tail` and `m3-r5b`" below; see
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

No bar that ran fell. Not rerun: the pass was stopped before the last eight M500 runs (superseded: every row rerun and recounted on `m3-int`, "Integration: `m3-tail` and `m3-r5b`" below). Open
from the review: the slice 2 counts above do not add up ("323 / 498" with 171 + 1 + 5 misses,
"132 / 498" with 350 + 17 + 1) and were not recounted: the misses very likely include the two
functions the reference does not finish, which `decomp-diff.sh` counts as different, but that
needs the rerun. The locked branch of `ActionParamDouble` and the symbol tests changed no
output of a check that ran; no unit test covers them. `cargo test --release` 89 tests,
`cargo clippy --release --all-targets -- -D warnings` and `cargo fmt --check` clean.

### Stack heritage: slice one on branch `m3-stack` (2026-11-13)

Check: `print raw` with types at `break start assignhigh`, every function and callee locked
with two stack parameters, so stack varnodes exist without the R5 rules:

    rust/tools/decomp-locked-options.sh void rust/target/stack-lock.txt "int4 a, int4 b"
    DECOMP_RAW_EXTRA=1 BREAK=assignhigh OPTIONS=rust/target/stack-lock.txt rust/tools/decomp-diff.sh m500

The options are `s6-options.txt` (no new group switch): `stackvars` holds only
`RuleLoadVarnode`/`RuleStoreVarnode` (R5) and stays off, `localrecovery` stays off because
`ActionRestructureVarnode` builds local symbols. M8 8 / 8 (the reference shows SSA stack
varnodes in 4 of 8: call INDIRECTs and MULTIEQUALs of `s0x4`/`s0x8`). M500 496 / 499 (the
reference finishes 499; 319 of its outputs hold stack varnodes in SSA form). Misses: 0x4919f0
(the block-numbering difference every M500 check has), 0x4098c0 (sequence numbers two higher
from 0x409ae2 on, not yet traced), 0x40ad80 (the load-guard error below). Bars held, same
binary: S4 498 / 500, S6 unlocked / `void` / `int4` / callees with a stack parameter each
498 / 500 (the callee check's output did not change: its callers have no stack parameters of
their own), paramdouble 500 / 500, switch corpus 1,947 / 2,050; the rule checks (r1, subvar, r4,
with `DECOMP_SKIP_ACTIONS=multicse,shadowvar,condconst`, without types) each 498 / 499.
The load-guard value-set analysis (`ValueSetSolver`) is hit by 1 function (0x40ad80);
`removeRevisitedMarkers`, the dead-code restart and pieces of a locked parameter by none, so
none of them was ported in this round.
Verification found and fixed: the local scope's parameter range is the model's stack
`<pentry>` ranges (`ParamListStandard::getRangeList`, offsets 4 to 503 on x86win), its local
range the upper half of the stack (`defaultLocalRange`); and `TypeSpacebase::getSubType` now
answers a locked stack parameter's type (10 functions typed `ESP + 4` as `int4 *`).

- Ported: the stack space in the heritage pass loop (delay 1, dead-code delay 1, dead code
  and `deadRemovalAllowedSeen` per space incl. the stack), `discoverIndexedStackPointers`,
  `protectFreeStores`, `reprocessFreeStores`, load/store guard records (`heritage_guard.rs`),
  stack ranges in `guard` (address-tied in the local scope, call guards with the callee's
  stack offset, STORE guards through `spacebase_ptr`), stack effects (`lookupEffect`),
  `ScopeLocal`'s stack ranges and `markNotMapped`, `ActionRestrictLocal` (`varmap.rs`),
  locked stack parameters of the function itself (inputs, typelocked symbol properties), and
  `clearDeadVarnodes` keeping locked inputs.
- Invisible to the check until R5: every LOAD/STORE through the stack pointer (locals,
  pushed call arguments, saved registers), so no call gets stack trials and every call's stack
  offset stays unknown (`resolveSpacebaseRelative` is R5's).
- Not ported, fails loudly: the value-set analysis of load guards (`ValueSetSolver`;
  `guardLoads` on an address-tied stack range with an indexed stack LOAD), revisited markers
  (`removeRevisitedMarkers`), the restart after heritage following dead-code removal
  (`bumpDeadcodeDelay`), pieces of a locked stack parameter, `ActionRestructureVarnode`
  (MapState, RangeHint, AliasChecker, symbols), `ActionMappedLocalSync`.
  Superseded (branch `m3-aliasupdate`): `ActionRestructureVarnode` is ported for the partial
  function of jump-table recovery (`mapstate.rs`), not for the function itself.

Review fixes and merges (2026-11-14). Fixed after an independent review:

- 0x4098c0: `LocationMap` rebuilt a stored stack index as a SLEIGH space, so every stack range
  counted as new at every pass and was guarded and given MULTIEQUALs again. The map keeps the
  space as stored (unit test `location_map_finds_stack_ranges_of_earlier_passes`).
  Superseded: "0x4098c0 (sequence numbers two higher from 0x409ae2 on, not yet traced)" above.
- `split_uses` leaves the original op in place, without readers, as the C++ does (dead code
  removes it). Touching ranges of the local scope stay apart (`RangeList::insertRange` joins
  only overlapping ones).
- New loud errors: guarding a call's locked stack return value (`tryOutputStackGuard`);
  `RulePtrArith` into a locked stack parameter of struct, union or array type
  (`TypeSpacebase::nearestArrayedComponent`); `StackAffectingOps` (S7) while a valid STORE
  guard exists (`heritage_guard::has_valid_guards`), since `affectsTest` reads the guard's
  range, which needs the value-set analysis.
- S7's symbol tests for locked parameters: `mergeTestRequired` refuses two highs mapped to
  different symbols, `mergeTestAdjacent` two name-locked highs (`high_symbol` in `merge.rs`:
  a stack parameter's symbol covers every varnode exactly at it, a register parameter's only
  its input varnode; it is name-locked when declared with a name, as
  `ParameterSymbol::setTypeLock` does). Check: the S7 print with the stack-lock options
  (`DECOMP_RAW_EXTRA=1 BREAK=inputprototype OPTIONS=rust/target/stack-lock.txt`), M8 8 / 8,
  M500 492 / 499. The 7 misses fail loudly: 6 need `VariablePiece` (0x402c20, 0x405990,
  0x4c0070, 0x62f0d0, 0x757810, 0x7586e0) and 0x40ad80 is the load-guard error. The count was
  492 before the symbol tests too, so no M500 function shows them deciding a merge: they are
  checked only as far as "no output changed". Superseded, for locked parameters only:
  "symbols" in S7's not-ported list. Still open: the other readers of the name lock
  (coreaction.cc, ruleaction.cc, the name representative of variable.cc), `join`-stored
  parameters, and the "assigned to the same variable" error of `HighVariable::setSymbol`.

Merged with master 9272a2f7d4 (S7 part one, S8 part two; no conflicts), and every bar rerun on
the merged binary. M8 8 / 8 in all 24 checks. M500:

| check | before | now |
|---|---|---|
| stack check (`stack-lock.txt` at `assignhigh`) | 496 / 499 | 498 / 499 (miss 0x40ad80) |
| S7 print with `stack-lock.txt` (`inputprototype`) | new | 492 / 499 |
| `funclink`, `heritage` (S1a, S1b) | 500 / 500 | 500 / 500 |
| S3 `paramdouble` | 500 / 500 | 500 / 500 |
| S3 switch corpus | 1,947 / 2,050 | 1,947 / 2,050 |
| S4 | 499 / 500 | 499 / 500 |
| S6 unlocked | 499 / 500 | 499 / 500 |
| S6 locked `void`, locked `int4`, callees with a stack parameter | 498 / 500 each | 499 / 500 each |
| R1/R2/R3 (`r1-options`), subvar, R4 | 498 / 499 each | 498 / 499 each |
| R5, with and without types | 497 / 498 | 497 / 498 |
| S7 `r1-options` (also with create indices), `subvar-options`, `r4-options` | 498 / 499 | 498 / 499 |
| S7 `r5-options` | 497 / 498 | 497 / 498 |
| S7 `s6-options` (also with create indices) | 493 / 499 | 493 / 499 |
| S8 rules off, rule stage | 499 / 499, 498 / 499 | 499 / 499, 498 / 499 |

No bar fell. The stack check gains 0x4098c0 (the fix above) and 0x4919f0 (`ActionNodeJoin`, from
master, as in S4 and S6; the locked S6 checks rise for the same reason). Superseded: the stack
check's 496 / 499 and the 498 / 500 bars above. The misses are the known ones: 0x4c48d0 (the
reference does not finish) in every "/ 500"; 0x47a6b0 in the rule stages; 0x6b21e0 not finished
by the reference with `r5-options`; the 6 `VariablePiece` functions with `s6-options` in S7.

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
their entry points are `prefer_complement_no_mods` and `structure_transform_no_mods`. Superseded:
"they get their rows with S7"; after the merge with S7 the rows after `copymarker` are wired to them,
and the second `blockstructure` row to `block_structure` (the same action: nothing to do once
structured). None of these reads high variables or `isExplicit` (only `finalizePrinting` does). CAST is moveable (its eval type is unary). Left for
later stages: the `f_flip_path` toggle of `swapEdges` (read by jumptable.cc's guard folding:
`switchnorm`), `f_duplicate_block` and `f_joined_block` (read by printc.cc's labels), the data type
of the code reference `CloneBlockOps` makes for an annotation (printing), and the `nonprinting` and
`special_print` bits `buildOpClone` keeps (superseded: now kept, with S7's flags).
Part three (`ActionFinalStructure`, structured `printRaw`) waits for S7: the actions between
`structuretransform` and `finalstructure` are the merge, prototype, naming and cast actions, and
`finalizePrinting` reads what they set (`isExplicit`, high variables), so a check that skips them
would only compare a state the C++ never prints.
After the merge with S7 the leaves between `copymarker` and `finalstructure` still block a fair
check: `latedonothing` (needs the delayed do-nothing mark of `ActionDoNothing` and
`removingCreatesRedundancy`; it changes the CFG, so it cannot be skipped fairly), `outputprototype`,
`inputprototype`, `mapglobals`, `namevars`, `setcasts` (S9: CAST ops `print raw` shows; superseded:
ported, see "Casts: `setcasts`" below), and
`BlockSwitch::finalizePrinting` needs the case labels of `switchnorm` (`recoverLabels`, not ported).
Bars after the S7 merge: S8 rules off M500 499 / 499, rule-stage 498 / 499 (prefercomplement,
structuretransform, returnsplit and nodejoin on both sides); S7 checks (their own options,
`blockrecovery` off) rules on 498 / 499, types on 493 / 499, unchanged. Part three stays open until those land. The S7 checks keep `blockrecovery` off (their option files
are S4's); with it on they would reach `latedonothing`, which ghidra-rs does not port, so
none of the S8 actions runs inside them. Superseded by "Tail" below: `latedonothing`, the
prototype actions, `mapglobals` and `finalstructure` are ported.

### Tail: in part on branch `m3-tail` (2026-11-14)

The leaves between `copymarker` and `stop`. Ported:

- `latedonothing` (`ActionLateDoNothing`, with `ActionDoNothing`'s delayed mark and
  `removingCreatesRedundancy`; `coreaction.rs`). Fixed with it: `isDoNothing` now tests a switch
  predecessor as the C++ does (a BRANCHIND block, and only when the successor joins edges); S4
  refused any predecessor with more than two out edges.
- `outputprototype` (`ActionOutputPrototype`, `updateOutputTypes`: the first input of the first
  RETURN that is not a special halt, with its high variable's type) and `inputprototype`
  (`ActionInputPrototype`: the input varnodes the model could pass become trials,
  `ProtoModelMerged::selectModel` with `ScoreProtoModel` resolves the merged
  `__fastcall/__thiscall/__stdcall` model, `ParamListStandard::fillinMap` with `buildTrialMap`,
  `forceExclusionGroup`, `forceNoUse`, `forceInactiveChain` picks the parameters,
  `updateInputTypes` stores them as symbols of category 0 in the local scope, `clearDeadVarnodes`);
  `coreaction.rs`, `fspec.rs`.
- Scopes and symbols, the part these need (`scope.rs`, wired as `Funcdata::symtab`: a global and a
  local scope per function): symbols with map entries and use limits, categories
  (`setCategory`, `clearCategory`, `removeSymbol`), `$$undef` names, `findContainer`, the local
  scope's ranges (`resetLocalWindow`: the model's stack parameter range and the default local
  range), `print map`. Functions and external references stay in `Arch` (`query_global`).
- `mapglobals` (`ActionMapGlobals`, `Funcdata::mapGlobals` with `coverVarnodes`): data symbols
  of the global scope, named by `buildVariableName` (`iRam0256f88a`).
- `finalstructure` (`ActionFinalStructure`: `orderBlocks`, `finalizePrinting` with
  `BlockWhileDo::testTerminal`/`testIterateForm`, `Funcdata::moveRespectingCover`,
  `HighVariable::markExpression`, `BlockSwitch` cases (`grabCaseBasic`/`addCase` at
  `newBlockSwitch`, the basic-block part, fall-through chains, the label sort), `scopeBreak`,
  `markUnstructured`, `markLabelBumpUp`; `finalstructure.rs`).

Also fixed: the action table named two unported leaves `restructurevarnode` and
`mappedlocalsync`; the C++ names are `restructure_varnode` and `mapped_local_sync` (they are what
`break start` and `DECOMP_SKIP_ACTIONS` take).
Superseded: S8 part two's "part three waits" and "`latedonothing` ... cannot be skipped fairly".

Not ported (left `not_ported`): `dynamicsymbols` (group `dynamic`, off), `namevars` (superseded:
ported, see "`namevars`" below)
(`Funcdata::linkSymbol` with `detectSymbolConflicts` and `MapEntryConflict`, `linkSymbolReference`,
`HighVariable::getNameRepresentative`/`hasName`, `buildDefaultName`, `assignDefaultNames`; the name
scheme itself, `buildVariableName` with `iVar1`, `param_1`, `in_EAX`, `unaff_ESI`,
`extraout_EAX`, `iStack_14`, is in `scope.rs` and unit tested, not wired), `setcasts` (S9),
`prototypewarnings` (warnings only), and the case labels: `switchnorm` (`matchModel`,
`recoverLabels`, `foldInNormalization`, `foldInGuards`) is not ported, so `finalstructure` fails
loudly on a switch with cases. The reference with `switchnorm` off fails there too (an assertion
on the empty label table), so switch functions count as "the reference does not finish" in the
`finalstructure` checks. Known gaps in what is ported, each failing loudly or marked in the code:
a persistent input as a parameter (`findDisjointCover`), the open parameter references and fake
inputs of `restructure_varnode`, `print map` of a locked prototype,
`coverVarnodes` inside an external reference.

Check design. `decomp-ref.patch` gains two devices. `DECOMP_TREE_EXTRA=1` (`FlowBlock::printTree`,
`BlockCopy::printTree`; `structure.rs` prints the same) adds to each `print tree block` line what
`finalstructure` sets: `{f<flags>` (`f_unstructured_targ` 0x20, `f_label_bumpup` 0x1000),
` g<gototype>` for goto and if-goto blocks, ` c<index>:<gototype>` for each switch case in order,
` it<time>`/` in<time>` for a while-do's for-loop ops, `}`. `DECOMP_MAP_EXTRA=1` (`IfcPrintMap`)
makes `print map` of the current function start with its prototype (`FuncProto::printRaw`: model,
return type, parameter types, extrapop; since the review also one `param <i>: <name> : <storage>:<size>`
line per parameter with `typelock`, `namelock`, `this`, and an `output:` line with the return
storage) and end with the data symbols of the global scope (`Global data`; functions, labels and
external references left out); each mapped symbol also gets an `attributes <name> :` line
(`addrtied`, `typelock`, `namelock`, `this`, `category <n>:<index>`). Option files, all from
`tools/r1-options.sh`: `s8-r-options.txt` (rules on), the new `s8-t-options.txt` (types on:
`s6-options` with `blockrecovery`, `returnsplit` on), and the new `tail-r-options.txt` /
`tail-t-options.txt` (the same two with `localrecovery` on, so that `outputprototype` runs; the
group's two other unported actions are skipped on both engines). `decomp-diff.sh` takes `DECOMP` and
`GHIDRA_RS` from the environment, `decomp-ref.sh` takes `DECOMP_BUILD` and `JOBS`. Run
`decomp_dbg` by its absolute path: its `discoverGhidraRoot` aborts on a relative `argv[0]`.

```sh
cd rust; export DECOMP_RAW_EXTRA=1
S3=multicse,shadowvar,condconst
L=restructure_varnode,mapped_local_sync
S=inputprototype,mapglobals,namevars,setcasts
# prototypes and globals: everything before namevars runs on both engines
export DECOMP_MAP_EXTRA=1 PRINT=$'print map\nprint raw'
DECOMP_SKIP_ACTIONS=$S3,$L BREAK=namevars OPTIONS=$PWD/tools/corpus/tail-r-options.txt tools/decomp-diff.sh m500
DECOMP_SKIP_ACTIONS=$L BREAK=namevars OPTIONS=$PWD/tools/corpus/tail-t-options.txt tools/decomp-diff.sh m500
# latedonothing: everything before inputprototype
export DECOMP_TREE_EXTRA=1 PRINT=$'print tree block\nprint raw'
DECOMP_SKIP_ACTIONS=$S3 BREAK=inputprototype OPTIONS=$PWD/tools/corpus/s8-r-options.txt tools/decomp-diff.sh m500
DECOMP_SKIP_ACTIONS= BREAK=inputprototype OPTIONS=$PWD/tools/corpus/s8-t-options.txt tools/decomp-diff.sh m500
# finalstructure: the four leaves before it skipped on both engines
DECOMP_SKIP_ACTIONS=$S3,$S BREAK=prototypewarnings OPTIONS=$PWD/tools/corpus/s8-r-options.txt tools/decomp-diff.sh m500
DECOMP_SKIP_ACTIONS=$S BREAK=prototypewarnings OPTIONS=$PWD/tools/corpus/s8-t-options.txt tools/decomp-diff.sh m500
```

Why skipping the four before `finalstructure` is fair: `finalizePrinting` reads high variables,
`isExplicit`, `notPrinted` and the op order; `inputprototype`, `mapglobals` and `namevars` change
prototypes, symbols and names only, and `setcasts` inserts CAST ops that `moveRespectingCover`
and `testTerminal` could meet. Measured on the reference over M500 (the tree with the extras, the
four running against skipped): 0 / 500 outputs differ, rules on and types on; with only
`setcasts` skipped, rules on, 0 / 500.

| check | M8 | M500 (of the functions the reference finishes) |
|---|---|---|
| prototypes and globals, rules on | 8 / 8 | 498 / 499 (99.8 %) |
| prototypes and globals, types on | 8 / 8 | 493 / 499 (98.8 %) |
| `latedonothing`, rules on | 8 / 8 | 498 / 499 (99.8 %) |
| `latedonothing`, types on | 8 / 8 | 493 / 499 (98.8 %) |
| `finalstructure`, rules on | 7 / 7 (0x4042e0: switch) | 494 / 495 (99.8 %) |
| `finalstructure`, types on | 7 / 7 (0x4042e0: switch) | 489 / 495 (98.8 %) |

How much M500 exercises each (reference outputs): `latedonothing` changes 9 / 500 with rules on
and 0 / 500 with types on (that check only shows it does no harm there); `finalstructure` changes
151 / 500 (rules on) and 173 / 500 (types on); with types on, 229 of the 499 functions get
parameters (all resolve to `__fastcall`; none to `__thiscall`, so `updateThisPointer` is not
exercised), 235 a return value and 234 at least one global data symbol.
Misses: the six types-on misses are S7's (`mergeAddrTied` needs `VariablePiece`: 0x402c20, 0x405990, 0x4c0070, 0x62f0d0, 0x757810, 0x7586e0), the rules-on miss is 0x47a6b0 (the known block-order difference from R3); no miss is new, and none is in the ported tail actions. 0x4c48d0 the reference does not finish; with `finalstructure` neither the four switch functions 0x4173a0, 0x442c90, 0x5f40b0, 0x5f8f30.
Existing bars on this branch (final binary): R1/R3, subvar and R4 checks 498 / 499, R5 typed 497 / 498, S7 rules on 498 / 499 and types on 493 / 499, S8 rules off 499 / 499 and rule stage 498 / 499, S3 paramdouble 500 / 500, S4 and S6 499 / 500, switch corpus 1,947 / 2,050: all unchanged. Superseded: measured again on `m3-int` with `switchnorm` and the review fixes, 1,947 / 2,050, unchanged ("Integration: `m3-tail` and `m3-r5b`" below).

Merged with master 836d04baee (stack heritage) on 2026-11-14. One conflict, `rust/README.md`: both
sides had added a section at the same place, both are kept (stack heritage first). After the merge
the tail code reads the local scope's real stack ranges (`Funcdata::localmap`, `LocalMap::ranges`
and `in_scope` in `varmap.rs`): the bounds `print map` prints and the use-limit test of
`inputprototype` (`discoverScope`). Superseded: `scope::local_ranges` and
`ParamList::stack_ranges`, which computed static ranges from the default model.
`restrictlocal` (`varmap::restrict_local`) now runs in the prototype checks on both engines and
the reference agrees; `L` below no longer names it. Tail checks on the merged binary, M8 then
M500: prototypes and globals 8 / 8, 498 / 499 (rules on) and 8 / 8, 493 / 499 (types on);
`latedonothing` 8 / 8, 498 / 499 and 8 / 8, 493 / 499; `finalstructure` 7 / 7, 494 / 495 and
7 / 7, 489 / 495: unchanged.

Review fixes (2026-11-14, after an independent review reading the Rust against the C++):

- `rangemap.rs` ports the `rangemap` template (the sub-range multiset with libstdc++'s placement
  of equal keys, `insert` with `unzip`, `erase` with `zip`, `find`). A scope's map is one per
  space, so `printEntries` and `findContainer` meet entries in the C++ order: a record sorts by
  its last offset and goes before an equal one (a symbol inside an earlier one is listed first).
  Superseded: the list sorted by first offset, sub-sort and insertion.
- `Scope::addMap`: a symbol whose entry has no use limit is address-tied (stack parameters too,
  not only the globals); the rangemap sub-sort is the first range of the use limit.
- `ActionOutputPrototype`: a size-locked output (locked with an unknown type) takes the type of
  a return value at its storage (`overrideSizeLockType`); with high variables off the output is
  an unknown of the varnode's size (`updateOutputNoTypes`). `mapGlobals` fails without high
  variables, as `Varnode::getHigh` does.
- `ActionInputPrototype` replaces the model only when it is merged (`resolveModel`).
- `orderBlocks` sorts with the port of `std::sort` (`stdsort.rs`) and the literal
  `compareFinalOrder`, which is not a strict order.
- `mapGlobals` names a persistent register by its register name (`getRegisterName` first).
- `ActionDoNothing` and `ActionLateDoNothing` give the warning "Do nothing block with infinite
  loop" once per block (`Funcdata::warning`, kept in `Funcdata::comments` for the printer; no
  compared output shows warnings yet); `isDoNothing` accepts any branch op (`hasOnlyMarkers`).
- The compiler spec's `<global>` is read: its ranges belong to the global scope
  (`CompilerSpec::global`, `Funcdata::in_global_scope`), so a varnode on x86's `MXCSR` register is
  persistent and address-tied as in the C++. Superseded: "the global scope owns ram" only.
- `fspec.rs`: `justifiedContain` handles a join entry; `resourceStart` ends with the group count;
  loud errors for `separatefloat="false"`, entries not ordered by storage class, an
  unreferenced parameter in a join entry, a stack growing up or `reversejustify`.
  `findEntry` in list order is the C++ order (the resolver sub-sorts by entry position).
- Arithmetic on untrusted input wraps where the C++ wraps (`mapGlobals`, `justifiedContain`,
  slot addresses) and is checked elsewhere (the for-loop head's other in edge).
- `print map` prints an address as `AddrSpace::printRaw` does (padded to the space's address
  size; `print::shortcut` is shared with `print raw`).
- An unported action's error names the action. `action::PARTIAL_SKIP` no longer names
  `restrictlocal` (ported on the stack branch; the entry had no effect).
- Dead code removed: `Scope::name`/`parent`, `find_overlap`; the blanket `allow(dead_code)` on
  `scope.rs` is gone.
- Known limit, not changed: the symbol database is per function (`Database::for_function`),
  the C++ has one global scope per process. The checks run one process per function, so a
  global symbol made by an earlier decompilation is never seen.

Check coverage: with the extended `DECOMP_MAP_EXTRA` print the prototype checks also compare the
order of the parameters, their names and storage, the return storage and the symbol attributes.
Tail checks after these fixes (reference rebuilt with the new patch), M8 then M500: prototypes
and globals 8 / 8, 498 / 499 (rules on) and 8 / 8, 493 / 499 (types on); `latedonothing` 8 / 8,
498 / 499 and 8 / 8, 493 / 499; `finalstructure` 7 / 7, 494 / 495 and 7 / 7, 489 / 495: unchanged.
The 24 other bars on M8: 8 / 8 each.

`namevars` (2026-11-14, `namevars.rs`). Ported: `ActionNameVars::apply` with `linkSymbols`,
`linkSpacebaseSymbol`, `lookForBadJumpTables` and `lookForFuncParamNames`;
`Funcdata::linkSymbol` (the high's symbol, else an entry of the local scope holding the first
byte at the use point, else a new local symbol), `detectSymbolConflicts` with `MapEntryConflict`
entries (`SymbolEntry::conflict`; `print map` shows ` (conflicts)` where the C++ does, after the
line end of the bounds), `linkSymbolReference` for stack addresses, `Varnode::getUsePoint`,
`HighVariable::getNameRepresentative` (`compareName`), `hasName`, `getSymbol`,
`getSymbolOffset`, `Scope::buildDefaultName` and `ScopeInternal::assignDefaultNames`. The name
scheme of `scope.rs` is wired (`iVar1`, `param_1`, `in_EAX`, `unaff_EBP`, `extraout_EAX`,
`iStack_14`, `UNRECOVERED_JUMPTABLE`); `ScopeLocal`'s stack data comes with each request
(`NameRequest::stack`, from `Funcdata::localmap`), a call made from a failed jump table carries
`CallSpec::bad_jump_table`, and `Funcdata::mapentry` is `Varnode::mapentry`. Superseded:
"`namevars` ... not wired" above and `Scope::stack`.
Left out, each without effect on the compared output or failing loudly (listed in the module
comment): the link of a persistent varnode to its global symbol (read by the printer only),
name recommendations (the scope holds none), CAST ops and proto-partial varnodes (do not exist
yet), `finalizeDatatype` of a piece of a symbol (loud error).

Check: `print map` with `DECOMP_MAP_EXTRA=1` after `namevars` (`BREAK=setcasts`), the options
and skip lists of the prototype checks: the names, storage, types and use limits of every local
symbol, the conflict marks, the parameter names of the prototype and the symbol attributes.

```sh
export DECOMP_MAP_EXTRA=1 PRINT=$'print map\nprint raw'
DECOMP_SKIP_ACTIONS=$S3,$L BREAK=setcasts OPTIONS=$PWD/tools/corpus/tail-r-options.txt tools/decomp-diff.sh m500
DECOMP_SKIP_ACTIONS=$L BREAK=setcasts OPTIONS=$PWD/tools/corpus/tail-t-options.txt tools/decomp-diff.sh m500
```

| check | M8 | M500 (of the functions the reference finishes) |
|---|---|---|
| names, rules on | 8 / 8 | 498 / 499 (99.8 %) |
| names, types on | 8 / 8 | 493 / 499 (98.8 %) |

Misses: rules on 0x47a6b0 (the known block-order difference from R3); types on the six
`VariablePiece` functions of S7 (0x402c20, 0x405990, 0x4c0070, 0x62f0d0, 0x757810, 0x7586e0);
none is in `namevars`. 0x4c48d0 the reference does not finish. The first M500 run found two
things, both fixed: a symbol stored in the join space (13 functions failed; `Scope::addMap` maps
each piece of the join too, `SymbolEntry::piece`, and `print map` prints a join by its pieces),
and a destroyed varnode staying a member of its high variable (0x43d846 failed in `hasName`;
`Funcdata::delete_varnode` now takes it out, as `Varnode::~Varnode` does).
Not exercised by these checks: `lookForFuncParamNames` (no callee has a locked, named
prototype in the tail option files) and `updateThisPointer` (no M500 function resolves to
`__thiscall`).

Every bar on the final binary of this branch (2026-11-14, the tree of the `namevars` commit;
reference rebuilt with the new `decomp-ref.patch`). M8: 8 / 8 in the 24 checks of the table,
the prototype, `latedonothing` and names checks, 7 / 7 in `finalstructure`. M500:

| check | before | now |
|---|---|---|
| stack check (`stack-lock.txt` at `assignhigh`) | 498 / 499 | 498 / 499 |
| S7 print with `stack-lock.txt` (`inputprototype`) | 492 / 499 | 492 / 499 |
| `funclink`, `heritage` (S1a, S1b) | 500 / 500 | 500 / 500, 500 / 500 |
| S3 `paramdouble` | 500 / 500 | 500 / 500 |
| S3 switch corpus | 1,947 / 2,050 | 1,947 / 2,050 |
| S4 | 499 / 500 | 499 / 500 |
| S6 unlocked | 499 / 500 | 499 / 500 |
| S6 locked `void`, locked `int4`, callees with a stack parameter | 499 / 500 each | 499 / 500 each |
| R1/R2/R3 (`r1-options`), subvar, R4 | 498 / 499 each | 498 / 499 each |
| R5, with and without types | 497 / 498 | 497 / 498 |
| S7 `r1-options` (also with create indices), `subvar-options`, `r4-options` | 498 / 499 | 498 / 499 |
| S7 `r5-options` | 497 / 498 | 497 / 498 |
| S7 `s6-options` (also with create indices) | 493 / 499 | 493 / 499 |
| S8 rules off, rule stage | 499 / 499, 498 / 499 | 499 / 499, 498 / 499 |
| prototypes and globals, rules on, types on | 498 / 499, 493 / 499 | 498 / 499, 493 / 499 |
| `latedonothing`, rules on, types on | 498 / 499, 493 / 499 | 498 / 499, 493 / 499 |
| `finalstructure`, rules on, types on | 494 / 495, 489 / 495 | 494 / 495, 489 / 495 |
| names (`print map` after `namevars`), rules on, types on | new | 498 / 499, 493 / 499 |

No bar fell. The switch functions were not compared for real in `finalstructure` and the switch
corpus got no `finalstructure` run: both wait for `switchnorm`.

Second review (2026-11-14), seven findings read against the C++:

1. Not real: `lookForFuncParamNames` treating a named parameter of a locked callee as
   name-locked. `FuncProto::setPieces` ends with `setInputLock(true)`, and
   `ParameterSymbol::setTypeLock` (fspec.cc) sets `namelock` with `typelock` on every parameter
   whose symbol has a name, so the reference does rename. Shown on M8 with every callee declared
   `parse line extern __fastcall void f(int4 count);` (the names check with `OPTIONS_SKIP_SELF=1`):
   the reference names 6 variables of 0x401080, 57 of 0x73a340 and 2 of 0x9eec5e `count`,
   `count_00`, ...; ghidra-rs is identical on 5 / 8, with the same names in 0x401080 and
   0x73a340, and fails loudly on the other three (0x4042e0, 0x40a110, 0x9eec5e: "deindirect:
   restarting for a locked prototype the call cannot take", a known gap of S6). Only the comment
   in `namevars.rs` changed. Superseded: "Not exercised by these checks: `lookForFuncParamNames`".
2. `RangeMap::insert` returned when the record's last piece ended on an existing sub-range;
   the C++ breaks with `f` unchanged and inserts `[f, b]` once more, so such a record is in the
   multiset twice. Ported; the unit test's expected values are the output of the C++ template
   on the same data (`tools/rangemap_ref.cc`: tree `3 1 3 2 2`). `findContainer` is unchanged by
   it (an entry seen twice passes the strict size test once).
3. `namevars` on a function with locked parameters now fails loudly ("the parameter symbols of
   a locked prototype are not ported"): the C++ keeps them as symbols of the local scope
   (type-locked, name-locked when named), which `linkSymbol` and `compareName` read. Putting
   them in the scope is not small (`print map`, `merge.rs` and `varmap.rs` each stand in for
   them in their own way). A locked prototype without parameters still runs.
4. `truncateIndirectJump` records "Treating indirect jump as call" (`Funcdata::warning`) and
   reuses `setup_callind_specs`.
5. `HighVariable::getSymbolOffset`: the distance to the entry wraps to the space
   (`AddrSpace::overlapJoin`, `wrapOffset`), not to 64 bits.
6. `Scope::overrideSizeLockType` has its two errors ("not size locked", "different type size").
   No symbol is size-locked yet (no locked parameter is in the scope), so it cannot run.
7. The comment of `action.rs` names `namevars` as ported; `print_map` reuses `space_info`;
   `find_container` returns an error for a map record without its entry, and
   `name_representative` and `symbol_offset` no longer index unchecked.

Tail checks after these. M8: prototypes and globals, names and `latedonothing` 8 / 8 each (rules
on and types on), `finalstructure` 7 / 7 and 7 / 7. M500 (of the functions the reference
finishes): prototypes and globals 498 / 499 and 493 / 499, names with rules on 498 / 499:
unchanged. The other five M500 checks (names with types on, `latedonothing`, `finalstructure`)
were still running when this was written; their numbers are with the switch work below.

Switch case labels: work in progress, paused on 2026-11-14 (superseded: "paused": verified on `m3-int`, "Integration: `m3-tail` and `m3-r5b`" below, where the "3 more `switchnorm` misses" are explained; superseded: "Not started" below,
kept for the list of what the port needed). Ported: `ActionSwitchNorm` (`jumptable.rs`:
`JumpTable::matchModel`, `recoverLabels` with `findUnnormalized`, `buildLabels` and
`backup2Switch`, `foldInNormalization`, `foldInGuards` with `foldInOneGuard`, `pushBranch`,
`addBlockToSwitch`, `noInterveningStatement`, `JumpModelTrivial`; `checkUnrolledGuard` and
`markFoldableGuards` in the guard analysis; `findSmallestNormal` against the earlier range);
`JumpTable` keeps the values of the flow-time model and its `switchOver` state
(`funcdata.rs`, `flow.rs`); `switchVarConsume` is read by dead code; `f_flip_path` flips with
`swapEdges`; the default edge of a switch block is a flag on the basic-block edge that stays
until the block gets another default (`installSwitchDefaults`); `structureReset` drops jump
tables whose BRANCHIND is dead; `ActionRedundBranch` no longer splices a single-exit switch
block; `BlockSwitch::finalizePrinting` labels and sorts the cases (`finalstructure.rs`) and
`nextFlowAfter` of a switch follows the sorted case order. `decomp-ref.patch`
(`BlockSwitch::printCaseExtra`) and `print tree block` add to each case of a labelled switch
`:<d><x>:<chain>:<depth>:<labels in hex>` (default, exit, chain, depth); compared after
`finalstructure` only. `r1-options.sh` also writes `sw-r-options.txt` and `sw-t-options.txt`
(`s8-r`/`s8-t` with group `switchnorm` on).

Checks, with the `sw-*` option files and the reference built from the new patch
(`rust/target/decomp-build2`): `finalstructure` as before (`BREAK=prototypewarnings`,
`print tree block` and `print raw`), `switchnorm` as `print raw` at `BREAK=returnsplit` (the
first break after the action). Run on the tree of this commit: M8 8 / 8 in all four
(`finalstructure` and `switchnorm`, rules on and types on; 0x4042e0 is now compared for real).
Switch corpus (2,050 functions, the reference finishes 2,004): `finalstructure` rules on
1,937 / 2,004 (96.7 %), types on 1,929 / 2,004 (96.3 %); `switchnorm` rules on 1,943 / 2,004
(97.0 %); `switchnorm` types on was stopped before it finished. Misses by cause: 57 in each
check already differ at flow time (the S3 switch-corpus misses, jump tables into garbage code);
`mergeAddrTied` needing `VariablePiece` 7 (rules on) and 15 (types on) in `finalstructure`; 2
functions (0x1cdee32, 0x1cdf675) whose flow-time table has 128 entries where the reference has
8 (the guard's constant is kept on the stack and the partial function does not fold it), so
their labels differ; 1 function (0x5a3c30) that already differs before `switchnorm`
(conditional execution); 3 more `switchnorm` misses with rules on were not looked at.
On an earlier binary of this work (before the last three fixes: the sorted case order in
`nextFlowAfter`, `structureReset`, `ActionRedundBranch`): the four M500 switch functions 4 / 4
in all four checks, and `finalstructure` rules on over M500 498 / 499 (the miss is 0x47a6b0).
Not run on this tree: M500 in any check, `switchnorm` types on over the switch corpus, the S3
switch-corpus bar (the guard analysis changed: `checkUnrolledGuard`), and every other bar; the
full pass of all bars is still to do. Of the second review's tail checks on M500, names with
types on, `latedonothing` and `finalstructure` were stopped before they finished.
Superseded: "Not run on this tree" and "Next" (done on `m3-int`, with `rust/tools/bars.sh` as the driver). Next: rerun the four switch checks on M500 and the switch corpus on this tree, then every bar
(`rust/target/chk/final.sh` is the driver, if the target folder is kept), then the README and
DESIGN.md numbers.

Not started: the case labels. `switchnorm` needs, beyond `matchModel`/`recoverLabels`/
`foldInNormalization`/`foldInGuards` themselves: the flow-time model's value range kept on the
`JumpTable` (`buildLabels` walks the range of the model the addresses were recovered with),
`JumpTable::switchOver` state (`block2addr`, `defaultBlock`, `lastBlock`, now recomputed in
`structure::switch_defaults`), guard records with their CBRANCH, read op, path and the
`unrolled` mark (`checkUnrolledGuard`, `markFoldableGuards`; `jumptable.rs` returns early where
the C++ checks unrolled guards), `findSmallestNormal` matching the earlier range,
`findUnnormalized` with op marks, `backup2Switch` with `TypeOp::recoverInputBinary/Unary`
(not in `emulate.rs`), `switchVarConsume` in dead code, `FlowBlock::getFlipPath` (`f_flip_path`
is not kept by `swap_edges`), `BlockBasic::noInterveningStatement`, `Funcdata::pushBranch`,
`JumpTable::addBlockToSwitch`, and a print of the labels in the reference patch. Until then a
switch with cases fails loudly in `finalstructure` and the five switch functions (0x4042e0 in
M8; 0x4173a0, 0x442c90, 0x5f40b0, 0x5f8f30 in M500) stay "the reference does not finish" there.

### Integration: `m3-tail` and `m3-r5b` on `m3-int` (2026-11-14)

The two paused branches merged into one tree (`m3-tail`, then `m3-r5b`) and verified by one
pass of every check, run by the new `rust/tools/bars.sh` (the one "run every bar" script; the
switch corpus is committed as `rust/tools/corpus/switch.txt`, the lock option files are written
by `rust/tools/lock-options.sh`). Conflicts, the review fixes of the switch work, the full table
and the explained misses: rust/README.md, "Integration of `m3-tail` and `m3-r5b`".

- M8 gate: all 45 checks equal the branches' M8 numbers (2 minutes).
- Pass: M500, r5d-adc and the switch corpus, `JOBS=12`, alone on the machine: 9 h 22 min, with
  `TIMEOUT=600`. 0x4c48d0 takes the reference 485 s and ghidra-rs 599 s alone (identical
  output, not a hang), so most of the 8 h 38 min of M500 was each check waiting for it; at the
  120 s default of `bars.sh` (as every earlier bar) an M500 check takes about 4 to 5 minutes.
- No bar fell. New: `switchnorm` types on over the switch corpus 1,947 / 2,004, the four switch
  checks on M500 (498, 493, 495, 499 of the 499 the reference finishes in 120 s), the locked
  typed double checks on M500 (482 / 499, 328 / 499). The S3 switch bar stays 1,947 / 2,050
  through `checkUnrolledGuard` and the empty-range stop of `findSmallestNormal`. Slice 2 with
  the locks and rules: 328 / 499 (was 323 / 498: the five `countMarks` functions match, and the
  count is now of the functions the reference finishes).
- Open: the type a global symbol gives a new varnode is set lazily (`infertypes::symbol_types`),
  so `switchnorm` rules on differs in 0x48a430, 0x5c5940, 0x6b3730 (M500) and 0x8d8f40,
  0x8eabe0, 0x8ead90 (switch corpus) at `returnsplit`; 0x4f3366 (switch `finalstructure` types
  on) keeps a call's join output; ghidra-rs is about 1.25 times slower than the reference on
  0x4c48d0.

### Parameter trials of calls: branch `m3-ap` (2026-11-14)

`ActionActiveParam` for calls with trials, in two slices (details and numbers: rust/README.md,
"Parameter trials of calls"). Slice 1: `checkInputTrialUse` with the `AliasChecker`,
`finalInputCheck`, the pass counting, `checkCallDoubleUse` with trials; check device
`DECOMP_TRIALS_EXTRA` (`print raw` ends with each active call's trials), compared at
`BREAK=activeparam` with `CONTINUES=1` (slice 1 alone cannot go further): M8 8 / 8, M500 446 / 500
with the trial lines equal in all 500. Slice 2: `resolveModel`, `deriveInputMap`
(`fillin_map_input`), `buildInputFromTrials`. `r5s` 132 / 499 to 446 / 499, `r5slock` 328 / 499 to
450 / 498, `r5dtlocksv` 328 / 499 to 451 / 499; M8 all 45 checks identical. Open, failing loudly (newly reached):
`ActionParamDouble` splitting a stack trial that is a PIECE, heritage's indexed stack LOAD that
may read an address-tied range, a piece of a locked stack parameter.
Review fixes: locked calls register their parameters' trials (`funcLinkInput`,
`commitNewInputs`), `markNotMapped` widens the parameter extent first, the unreachable or
unported branches of `AncestorRealistic` and the range defaults fail loudly; the three checks
hold (446 / 499, 450 / 498, 450 / 498). Open: the "Error processing <name> called at <seq>: "
wrapper of `ActionActiveParam`'s errors.

### Casts: `setcasts` on branch `m3-cast` (2026-11-15)

`cast.cc` (`CastStrategyC`, the parts `setcasts` calls) and `ActionSetCasts`, in `cast.rs`, with
the `getInputCast`/`getOutputToken` overrides of typeop.cc (details and numbers: rust/README.md,
"Casts"). Checks in `bars.sh`: `cs-r`/`cs-t` (`print raw` with types at `BREAK=finalstructure`,
skipping `inputprototype,mapglobals,namevars` and, rules on, the S3 actions) and `fsc-r`/`fsc-t`,
`swfsc-r`/`swfsc-t` (`fs-*`, `swfs-*` with `setcasts` on). M8 `cs` and `swfsc` 8 / 8, `fsc` 7 / 7 (0x4042e0 is outside `fs`; superseded: "8 / 8 in all six"); M500 `cs`
498 / 499 and 493 / 499, `fsc` 494 / 495 and 489 / 495 (no new miss), `swfsc` 498 / 499 and 493 / 499 (as `swfs`). Fail
loudly: union resolution (every type that `needsResolution`), struct or union SUBPIECE truncation,
SEGMENTOP/INSERT/ZPULL/SPULL casts. Printer-only parts of `cast.cc` (`isSubpieceCast`,
`isSextCast`, `isZextCast`, `isExtensionCastImplied`) come with the C printer. Not run: the
switch corpus with `setcasts` on.
### S9 slice 1: the C printer for straight-line functions, branch `m3-print1` (2026-11-15)

`print C` through the three layers (`prettyprint.rs`: `EmitPrettyPrint`; `printlanguage.rs`: the
operator stack and parentheses; `printc.rs`: `PrintC` for the header warnings, the declaration,
the local declarations, lists of basic blocks and the plain statements and operators). Details:
rust/README.md, "C printing, slice 1". Checks `pc-r` and `pc-t` in `tools/bars.sh` (at
`break start prototypewarnings`, `setcasts` skipped on both engines: no casts are printed yet)
and the corpus `tools/corpus/simple.txt`. M8 0 / 7 loud (every M8 function has an `if` or more); M500 `pc-t` 24 / 495 identical, loud 471
(`BlockIf` 376), silent 0; `pc-r` 47 / 495 (loud 448, silent 0); `pg-r`, `pg-t`, `nm-r`, `nm-t` on
M500 unchanged after the fixes (498, 493, 498, 493 / 499); `simple` 54 / 194 (rules on) and
34 / 194 (types on), no silent miss left after the fixes; M8: the 45 older checks identical, `pc-r` and `pc-t` 0 / 7
loud (superseded: "M8 all 47 checks identical"). Fixed on the
way: `namevars` links globals to their data symbols, `mapglobals` asks with the varnode's size
whether a varnode is already linked, flow records the bad-instruction warnings.
Next slices (superseded in part: blocks and casts are slice 2): if/else, loops, switch, gotos and labels; comments in the body (the comment
sorter); casts once `setcasts` lands; field and array access; strings and characters; the rest
of `printc.cc`.

Merged with `m3-cast` on `m3-s9` (2026-11-15): M8 the 51 checks other than `pc-r`/`pc-t` identical, those two 0 / 7, all loud; M500 not rerun on the merge.

Review fixes on `m3-s9` (details: rust/README.md, "Review fixes and `print C` with casts"):
`checkPointerIssues` warns "Load size is inaccurate" as the C++; `calcSubmeta` (a pointer to a
struct or union is `SUB_PTR_STRUCT`; no check moves, none declares a struct or union);
CPOOLREF and NEW never cast; `opUndoPtradd` fails on every `needsResolution` type; `print C`
prints the `U` suffix, fails loudly on the long suffix and on a CAST op. (Superseded: slice 2 prints it.) New checks `pcc-r`,
`pcc-t` (`print C` with `setcasts` on): M500 10 / 495 and 8 / 495 identical, silent 0 (CAST 86
and 66 loud), against `pc-r` 47 and `pc-t` 24 / 495; M500 `cs-t`, `fsc-t`, `fs-t` unchanged.
Next for casts in the printer: `PrintC::opTypeCast` and the extension casts of `cast.cc`
(superseded: done in slice 2, below).

### S9 slice 2: structured blocks and casts in the printer, branch `m3-print2` (2026-11-15)

Every structured block of printc.cc (if/else with the `else if` merge, while, for,
`while( true )` overflow, do-while, infinite loop, `&&`/`||` conditions, switch and case labels,
gotos, labels, break, continue), the branch ops, and casts: `opTypeCast`, `opIntZext`,
`opIntSext`, `opSubpiece` with `isZextCast`, `isSextCast`, `isSubpieceCast` and
`isExtensionCastImplied` (`cast.rs`). Details: rust/README.md, "C printing, slice 2". `pcc-r` and
`pcc-t` also run on the switch corpus (with the `sw` options, `switchnorm` on). M500 `pcc-r` 235 /
495 (was 10), `pcc-t` 58 / 495 (was 8), `pc-r` 244 / 495 (was 47), `pc-t` 45 / 495 (was 24); no
block kind is a loud miss; silent: only 0x47a6b0 rules on, which differs from `r1` on. `simple`
109, 57, 110, 49 / 194; switch `pcc-r` 153 / 2005 (silent 0 after the flow fix for the "overlaps instruction" header warning), `pcc-t` not finished. M8: the 51 other checks identical, `pc-r`/`pcc-r` 2 / 7.
Next: the loud blockers left: `CALLIND`, array and field access (`PTRSUB`, `PTRADD`),
anonymous data-types, comments in the body, float and character constants, `PIECE`,
`FLOAT2FLOAT`, `FLOAT_NAN`; labels of spliced blocks (several cover ranges).
(Superseded in part: slice 3A, below, does array and field access and character constants;
slice 3B, below, does `CALLIND`, anonymous data-types, the body comments, the float operators
and float constants; both are merged on `m3-print3`.)

### S9 slice 3A: array and field access, characters in the printer, branch `m3-print3a` (2026-11-15)

`checkArrayDeref`, `opPtradd`, `opPtrsub` (structure fields, space-base symbols and their parts,
array elements; no `TypePointerRel`), `pushPartialSymbol`, the `.`, `->`, `[ ]`, `&` tokens, the
symbol a space-base PTRSUB points at (linked by `namevars` as `linkSymbolReference`, read by the
printer; a function prints by its name), and
character constants (`pushCharConstant`, `printUnicode`, unit tested). Details: rust/README.md,
"C printing, slice 3A". M500 `pcc-t` 143 / 495 (was 58), `pc-t` 143 / 495 (was 45), `pcc-r` 235 and
`pc-r` 244 / 495 (unchanged); no array, field or character miss is left; silent only 0x47a6b0
(rules on). `simple` 95, 95, 109, 110 / 194; the same after the review fixes (the PTRSUB link in
`namevars`; `nm-r`, `nm-t` on M500 unchanged, 498 and 493 / 499); M8 the 51 other checks identical, the four print
checks 2 / 7. Next: `INT_SBORROW` (types on: 100 on M500 `pc-t`) and `PIECE` (71), with slice 3B's
`CALLIND`, float ops and constants, comments in the body and anonymous data-types.
(Superseded: slice 3B is merged with it on `m3-print3`, below.)

### S9 slice 3B: indirect calls, floats, body comments, anonymous types, branch `m3-print3b` (2026-11-15)

`opCallind`; the float operators (`NAN`, `ABS`, `SQRT`, `CEIL`, `FLOOR`, `ROUND` as functions,
`FLOAT2FLOAT` and `TRUNC` as casts, `opFloatInt2Float` absorbing an implied INT_ZEXT); float
constants as `FloatFormat::printDecimal` prints them (unit tested against the C++);
`genericTypeName`; the body comments through `CommentSorter` (`comment.rs`), `emitCommentGroup`
and `emitCommentBlockTree`; `BlockBasic::cover` keeps the ranges of a spliced block for
`contains`. Fixed on the way: flow records the jump-table failure warning (`stageJumpTable`), the
cause of the 19 silent misses the comments first showed. Details: rust/README.md, "C printing,
slice 3B". M500 `pcc-r` 441 / 495 (was 235), `pc-r` 442 (was 244), `pcc-t` 94 (was 58), `pc-t` 72
(was 45); `simple` 174, 174, 91, 83 / 194 (were 109, 110, 57, 49); M8 `pc-r`/`pcc-r` 6 / 7, the
51 other checks identical; silent only 0x47a6b0 (rules on). Switch `pcc-r` not finished at the commit.
Review fixes: an unported jump-table failure (the partial action's or emulation's) fails the
decompile instead of warning; a second table after a failed partial action fails loudly; the
dropped warnings ("ptrarith problems", offcut call, PIC construction, jump-table truncation) are
recorded; `fail_return` fails loudly. Rerun: the same counts.
Next: `PIECE`, the SUBPIECE field extraction, `CALLOTHER`, `POPCOUNT`, `INT_SBORROW` and
`INT_SCARRY`, labels of spliced blocks, and the array and field access of slice 3A.
(Superseded: slice 3A is merged with it on `m3-print3`, below.)

### S9 slices 3A and 3B merged, branch `m3-print3` (2026-11-15)

Both slices, no code change in the merge (their edits to `push_constant`, the opcode dispatch
and `funcdata.rs` sit side by side). Details: rust/README.md, "C printing, slices 3A and 3B
merged". M500 `pcc-r` and `pc-r` 442 / 495, `pcc-t` and `pc-t` 257 / 495; `simple` 174, 174, 138,
138 / 194; silent only 0x47a6b0 (rules on); M8 the 51 other checks identical, the print checks 6 / 7
(`-r`) and 5 / 7 (`-t`). Next, by M500 `pcc-t` misses: `INT_SBORROW` 119, `PIECE` 96, `POPCOUNT` 8;
with rules on, the SUBPIECE field extraction 19 and `PIECE` 14; then `CALLOTHER`, `INT_CARRY`,
`INT_SCARRY` and labels of spliced blocks.

### S9 slice 4, branch `m3-print4` (2026-11-16)

`INT_CARRY`, `INT_SCARRY`, `INT_SBORROW`, `PIECE`, `POPCOUNT` and `LZCOUNT` in functional syntax,
CALLOTHER of a SLEIGH user-op, and the SUBPIECE field extraction. Details: rust/README.md, "C
printing, slice 4". M500 `pcc-r` and `pc-r` 487 / 495 (loud 7, silent 1: 0x47a6b0), `pcc-t` and
`pc-t` 479 / 495 (loud 16); M8 all 55 checks identical, the print checks 7 / 7. Full pass: `simple`
190, 190, 188, 188 / 194; switch `pcc-r` 1810 / 2005, `pcc-t` 1817 / 2005 (60 silent each, all already silent in
older switch checks). Next, by M500 misses: `mergeAddrTied` (VariablePiece) 6 with types on, labels of spliced
blocks 5, a variable linked to a function or external reference 3, string constants 2.
(Superseded: the "Next" list of the merged section above.)

### S9 slice 5, branch `m3-print5` (2026-11-16)

Labels of spliced blocks (`getEntryAddr`), variables that are a whole function or external
reference symbol, `VariablePiece` groups (`mergeAddrTied`, `groupWith`), string constants and
function pointer constants. Details: rust/README.md, "C printing, slice 5". M500 `pcc-r` and
`pc-r` 494 / 495 (loud 0, silent 1: 0x47a6b0), `pcc-t` and `pc-t` 495 / 495; M8 all 55 checks
identical. Switch `pcc-r` 1944 / 2005 (loud 0, silent 61), `pcc-t` 1943 / 2005 (loud 0, silent 62);
all silents are in older switch checks except 0x23caea8 (`pcc-t`), open: the "Read-only address
is written" warning of `fillinReadOnly` is not ported. Not run: the full pass. Next: that warning;
then the switch silents of the earlier stages.
Follow-up: 0x23caea8 is loud (`print C` fails on a written read-only address, the unported
warning): switch `pcc-t` 1943 / 2005 (loud 1, silent 61), every switch silent in an older check.
Next: port the `fillinReadOnly` warning. (Superseded: "silent 62" and "open" above.)
(Superseded: the counts and the "Next" list of the slice 4 section above.)

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

### Default options: the check `pcd`, branch `m3-default` (2026-11-17)

`pcd` in `bars.sh` runs `print C` with no group or rule switched off and no break, with the
action leaves not ported yet skipped on both engines (the list `D` in `bars.sh`). Baseline with
seven leaves skipped (`restructure_varnode`, `mapped_local_sync`, `multicse`, `shadowvar`,
`condconst`, `dynamicsymbols`, `prototypewarnings`): M8 6 / 8 (silent 2), M500 339 / 497 (loud
83, silent 75; 66 of the silent are one missing cast of a stack address, `(xunknown1 *)&stack...`).
Next: port the seven leaves in the C++ order and shrink `D`. (Superseded: five are done, below.)

Progress on the branch (details: rust/README.md, "Default options"):

1. `multicse`, `shadowvar` ported, and `TypeSpacebase::getSubType` reads the local symbols (the
   missing stack-address cast): M8 8 / 8, M500 407 / 497 (loud 83, silent 7).
2. `condconst` ported; `dynamicsymbols` and `prototypewarnings` have nothing to do in the
   console. `D` is `restructure_varnode,mapped_local_sync`. M500 407 / 497 (loud 83, silent 7).
3. The 7 silent misses had one cause: rules of the default pools that are not ported are
   missing from the pool without a word (`conditionalmove` in 0x608500; the other six not traced
   to a rule each). `pcd` now switches the unported rules off on both engines
   (`tools/corpus/default-options.txt`, written by `r1-options.sh`); the 7 are identical with
   that. The first two counts above were measured without it. M500 415 / 497 (loud 82, silent 0)
   with 11 rules off.
4. Rules ported: `pullsub_indirect`, `conditionalmove`, `orpredicate`, `threewaycomp`, plus
   `transformcpool` (fails on a CPOOLREF) and `funcptrencoding` (nothing to do on these specs).
   Eight rules stay off: `aliasupdate`, `switchsingle`, `ptrflow`, `segment`,
   `ptrsubcharconstant`, `splitcopy`, `splitload`, `splitstore`. (Superseded: two stay off,
   `segment` and `ptrsubcharconstant`; see "Pool rules" below.)
5. `ActionParamDouble` splits a stack trial that is a PIECE (35 loud functions of M500: 6
   identical in `pcd`, 29 loud later in `namevars`; all 35 identical in `print raw` at
   `break start namevars`).

Not done: `restructure_varnode` and `mapped_local_sync`. They need the local symbols of
varmap.cc (`MapState`, `RangeHint`, the full `AliasChecker`, `createEntry`,
`fakeInputSymbols`, `markUnaliased`, `annotateRawStackPtr`) and then
`Funcdata::syncVarnodesWithSymbols` with the varnode flags ghidra-rs does not model yet
(`mapped`, `nolocalalias`, type locks from symbols), which heritage guards, type propagation,
`namevars` (symbols that exist before it) and the printer read. Also open: the loud misses
`pcd` reaches (`namevars` `getExactPiece`, indexed stack LOADs in heritage, STORE guards in
merge, `HeapSequence`, `ActionConditionalExe`), and whether a default-options run should fail
while a pool rule is missing. (Superseded: `ActionConditionalExe` is ported, `condexe.rs`; a
run now fails while a pool rule is missing, see "Pool rules" below.)

End sweep of the branch before the merge of `m3-aliasupdate` (final build): all 56 checks on
M8 identical. M500: `pcd` 422 / 497 (loud 75, silent 0: 51 `namevars` `getExactPiece`, 16
indexed stack LOAD, 6 STORE guard in merge, 2 `HeapSequence`), `paramdouble` 500 / 500, `r1`
499 / 499 (baseline 498), `r5s` 483 / 499 (baseline 446), `s7r` 499 / 499 (498), `pcc-r`
495 / 495 (494), `pcc-t` 495 / 495. `simple`: `pcd` 184 / 200 (loud 16), `pcc-r` and `pcc-t`
194 / 194. Switch `pcc-t` 1988 / 2005 (baseline 1986, silent 0). Not run: the other M500 and
switch checks (the full pass). `m3-aliasupdate` is merged into the branch after that sweep
(its `mapstate.rs` runs in the jump-table partial only; the decompile-root leaf is still
`not_ported`, so `D` is unchanged); what was rerun on the merge is in the merge commit.

Alias analysis of the jump-table partial function (branch `m3-aliasupdate`, 2026-11-17).
`RuleAliasUpdate` only runs `opCollapseIndirectsForAlias`; what that collapses comes from
`ActionRestructureVarnode` (`nolocalalias`) and from the value-set range of a store guard. Ported
for the partial function (`mapstate.rs`): the rule, `opCollapseIndirectsForAlias`,
`syncVarnodesWithSymbols`, `ScopeLocal::restructureVarnode` without data-types (MapState,
RangeHint, `fakeInputSymbols`, `markUnaliased`) and `protectSwitchPaths`. `flow.rs` makes the
partial function as the C++ does and takes its table as it is; where the action or the rule
reaches a path not ported (a load or store guard, `adjustOutOfRange`, a locked prototype, a typed
or large stack varnode, `checkUnaliasedReturn`) it falls back to the partial function without
them and the test of `m3-swsilent`. The action of the `decompile` root stays unported.
Switch corpus: 0x1cdbf0e, 0x7913d0, 0x7bb710, 0x7bf170, 0x831db0, 0x898690 and 0x898850 loud ->
identical in `paramdouble`, the six switch checks, `pcc-r` and `pcc-t` (each checked against the
reference); 0x7c1f30 loud -> identical in `pcc-r` and `pcc-t`. Derived counts: `paramdouble`
1995 / 2004 (loud 9), `swfs-r`, `swfs-t`, `swfsc-r`, `swfsc-t`, `swsn-t` 1994 (loud 10), `swsn-r`
1991 (loud 10, silent 3), `pcc-r` 1995 / 2005 (loud 10), `pcc-t` 1994 / 2005 (loud 11). Every
other switch output at `paramdouble`, all 55 checks on M8 and nine checks on M500 are byte-equal
to master's. Still loud, by missing port: `ValueSetSolver` and the guard ranges (0x1c69c5a,
0x546d40, 0x5629d0, 0x78e7d0, 0x1b0c190, 0x502b80, 0x5c37f0), `ActionConditionalExe` (0x5a3c30,
0x807a80), multistage tables (0x23f4238). Open: 0x2285c9b, which the reference does not finish,
prints a function now. Details in `rust/README.md`, "Alias analysis of the jump-table partial
function". (Superseded: the switch counts of the `m3-int5` paragraph above.)

Review fixes of that port (branch `m3-default`, 2026-11-17): a new stack varnode inside a symbol
of `restructureVarnode` takes the symbol's flags (`mapped`, `addrtied`, `nolocalalias`);
`markNotMapped` removes the symbols under its range and stops at a `fake_input` one; a partial
function made without the action and the rule that fails with a normal error ends the decompile
loudly. No output changes: the build before against the one after is equal on the switch corpus
(`paramdouble`, `swfs-r`, `swsn-r`, `pcc-r`, `pcc-t`), M8 (56 checks) and M500 (`pcd`,
`paramdouble`, `swfs-r`, `pcc-r`, `pcc-t`, `r5s`). Measured against the reference on the whole
switch corpus (Superseded: the derived counts above): `paramdouble` 1995 / 2004 (loud 9),
`swfs-r` 1996 (loud 8), `swsn-r` 1993 (loud 8, silent 3), `pcc-r` 1997 / 2005 (loud 8), `pcc-t`
1996 / 2005 (loud 9). Open: 0x5861aa and 0x7c74c0, identical at `paramdouble` in the `m3-int5`
pass, are loud there before and after these fixes ("a second table after the partial function's
action failed"). Details in `rust/README.md`, "Review fixes" of the alias analysis section.

Pool rules (branch `worktree-agent-ab53ef4e46d4bec80`, 2026-11-17). Behaviour change: the
`decompile` root fails while a pool rule that is not ported is on (the rule tables list every
C++ rule, `r` ported or `u` not; a unit test compares them with coreaction.cc), so
`default-options.txt` is the only way to run without one. Ported: `switchsingle`, `ptrflow`
(nothing to do without a `<truncate_space>`, which the console refuses), `splitcopy`,
`splitload`, `splitstore` (`SplitDatatype`, `rules/split.rs`; loud on a type needing
resolution, a partial structure, the CONCAT of split outputs, an address-tied root pointer).
`aliasupdate` is no longer switched off in `pcd`. `default-options.txt` holds two rules:
`segment` and `ptrsubcharconstant`, ported on other branches and `u` entries here until those
merge. Checks:
- `pcd` M500 422 / 497 (loud 75, silent 0), the same 75 functions as before; the six with a
  STORE guard now fail in `RuleAliasUpdate` instead of in merge.
- The reference alone on M500 with the six rules on against the eight off: three outputs
  change (0x4130d0, 0x494200, 0x5bed50), all by `aliasupdate`, all loud in ghidra-rs. So
  `switchsingle` and the split rules change nothing on M500.

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
