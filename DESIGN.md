# ghidra-rs design

## Idea

A fast, headless reverse-engineering core in Rust that lives next to upstream Ghidra.
It reuses Ghidra's processor specs (SLEIGH) as data and doesn't rewrite Ghidra 1:1.
It covers load → disassemble → p-code → function/xref analysis, as a CLI and a library,
so large binaries and batch runs are much faster than Ghidra's Java pipeline.

## Decided

- 2026-11-11: Scope is a headless Rust core, not a full rewrite. No GUI for now.
- 2026-11-11: Rust code lives in `rust/` (a Cargo workspace). The upstream Java/C++ tree stays as it is.
- 2026-11-11: Processor support comes from compiled `.sla` files that Ghidra's existing
  SLEIGH compiler builds. Rust reads `.sla` and doesn't parse `.slaspec`. We start with x86-64.
- 2026-11-11: Speed claims need a benchmark against Ghidra's `analyzeHeadless` on the same binaries.
- 2026-11-11: `analyze --abi-callers` matches Ghidra by default: a pointer in data is a reference
  only where Ghidra would define one (a word an instruction references, or a run of 4+ image
  addresses). The wider scan (every aligned word in `.rdata`/`.data`/SecuROM data equal to a
  function entry), which finds callers Ghidra misses, stays behind `--data-pointers`.
  Superseded (same day, branch `coverage`): "a run of 4+ image addresses" is now Ghidra's own
  Create Address Tables rule, ported (`Analysis::address_tables`, see `rust/README.md`).
- 2026-11-11: To reach the code Ghidra reaches, ghidra-rs improves its own disassembly
  coverage (a local constant fold, Ghidra's address tables in every section, Ghidra's
  valid-subroutine check on code constants). It does not import Ghidra's instruction set
  (no `--code-from` option).
- 2026-11-11: The SecuROM stub `PUSH EDX; ...; XCHG [ESP],EDX` stays an EDX use, as in Ghidra
  (its `violation` at 0x4793ff, overridden in mercs2). ghidra-rs keeps matching Ghidra here
  and does not model the save/restore.
- 2026-11-11: `--abi-callers` keeps the violation-first rule: a `violation` behind any reference
  wins over a stopped walk, since Ghidra's database order of references isn't reproduced.
  It finds Ghidra's violations at 0x41d7be and 0x41d834, and gives `violation` on 9 rows
  Ghidra reports `unknown`. Checked by hand: all 11 end at a `PUSH` of the watched register
  that is never read back (8 at the `4e1259` SecuROM stub, see the stub decision above), so
  they are consistent with treating PUSH as a use. mercs2 overrides all but 0x59d660 at
  0x70043d. Not taken: letting a violation win only over "enters wrapper code" stops (drops
  8 of the 9 but is fitted to these rows).
- 2026-11-11: Change of direction: the goal is a full headless Rust Ghidra for decompiling
  and rewriting old video games (mercs2 first), through milestone 4. This supersedes "a
  headless Rust core, not a full rewrite" above. Still no GUI.
- 2026-11-12: The decompiler (milestone 3) is written in Rust, and Ghidra's C++ decompiler is
  the reference its output is checked against, as `rust/tools/sleigh_ref.cc` was for SLEIGH.
  No FFI stopgap. Confirmed by the user. The plan and its other decisions (Windows types from
  a one-time C header export, mercs2's register ABI as locked prototypes in milestone 3, a
  small `print raw` patch on the reference) are in `docs/plans/m3-decompiler.md`.
- 2026-11-12: CLI only for now: no server or other way for Ghidra's GUI to use this core. User's
  decision; may be revisited later.
- 2026-11-12: No direct `.gpr`/`.rep` support (Ghidra's undocumented, version-bound database).
  Data moves between Ghidra projects and ghidra-rs as plain files exported by headless Ghidra
  scripts (as mercs2 already does with `functions.csv` and `register_abi.csv`), in both
  directions. Milestone 4's project DB is ghidra-rs's own format. User's decision.

- 2026-11-12: Beating Ghidra's decompiler: parity first, then fixes. The mercs2 rewrite found the
  C++ decompiler dropping values (stores after cursor pushes at 0x006664eb, a steer value in
  0x005460a0), and an exact port copies those drops. The port stays byte-identical through S10;
  after that, ghidra-rs fixes such drops inside its own decompiler behind options, never by
  default (as the plan's "Where to diverge" says). Each fix names the Ghidra behaviour it changes
  and a mercs2 function that shows it. User's decision (chosen over a separate p-code checker
  first).


- 2026-11-12: Goal: ghidra-rs replaces Java CheckAbiCallers as the decider of mercs2's caller check
  (today a second opinion, `tools/ghidra-rs-shadow.sh` in mercs2). It goes before the pending
  R1/S6 decompiler decision, since mercs2 uses the check daily. Claude's decisions (the user left
  them to Claude, not being a reverse engineer):
  - What counts: safety, not agreement with Java. The check exists so a rewrite never clobbers a
    register a caller relies on. The costly error is a missed `violation` (a real caller missing,
    or `ok` where a register is read). An extra caller or `unknown` only costs a manual look.
  - Who judges a disagreement: not Java. In order: (1) mercs2's abi_test trace of calls the
    original actually made, which proves a caller exists but never that one doesn't; (2) the
    bytes at the call site, checked by hand (disassembly and the callee's contract). Each verdict
    goes in a ledger in this repo (`rust/tools/abi-ledger.csv`: address, site, java, ghidra_rs,
    truth, evidence), grouped by cause.
  - The bar to switch: every row of the shadow diff is in the ledger, and in none is ghidra-rs
    wrong on the unsafe side (missing a true caller, or `ok`/`(none)` where the truth is
    `violation`). Then three mercs2 sweeps with the roles swapped (ghidra-rs decides, Java shadows)
    with no new unsafe-side error. mercs2's own DESIGN.md records the switch; this repo doesn't
    write there.
  - Speed is not part of the bar (already seconds against minutes); timing is reported, not gated.
- 2026-11-13: Change of direction (the user's decision): the goal widens from "a headless Rust
  Ghidra for old games, mercs2 first" to Java Ghidra's completeness on the fast Rust engine, as
  far as that is reachable. Old games and mercs2 stay the first user and the test bed. Still no
  GUI. How it is pursued:
  - Knowledge is reused as data, never rewritten: Ghidra's processor specs (`.sla`, `.pspec`,
    `.cspec`), Function ID databases and (not started) data-type archives are read as they are.
  - Engines are ported, not features: the instruction decoder, the analysis core and the
    decompiler, each checked against Ghidra's own output. Java Ghidra and the C++ decompiler stay
    the oracle; parity first, improvements behind options (the 2026-11-12 decision).
  - Breadth is picked by real work: what a real project needs next is built next.
  - Files are exchanged with Ghidra both ways where possible, so Ghidra covers the rare case and
    ghidra-rs the fast bulk work; full parity with everything Ghidra does is not the bar.
  - Speed claims still need a measurement on the same input (the 2026-11-11 decision); the
    decompiler's speed is unmeasured until it prints C.
- 2026-11-14: Order of breadth after the decompiler prints C (the user's decision, on Claude's
  recommendation): (a) every Ghidra script mercs2 uses (17 in `mercs2-decomp/tools/ghidra/`;
  13 not started: 8 read-only exports, 5 project-editing), so one real project runs without
  Java; then (c) a project store and scripting, designed from what (a) showed it must hold;
  then (b) more processors and file formats, when a second game asks for them. The 8 export
  scripts need nothing else and come first. Superseded: the open question "which breadth
  comes first" (asked 2026-11-13).
- 2026-11-15: The edits of mercs2's five project-editing scripts (renames, types, comments) live
  as plain text files in the mercs2 repo. Each ghidra-rs run starts from scratch (load, about
  10 s of analysis), then applies those files; nothing is reloaded while running. Edits stay
  readable and diffable in git, and the editing scripts can move off Java Ghidra after S10
  instead of waiting for milestone 4's project store. User's decision (first leaning to wait
  for the store, changed once it was clear no hot reloading is involved). Superseded: the open
  question "where the edits live" (asked 2026-11-13).
- 2026-11-16: A printer slice that lets older silent misses reach the C output counts as progress,
  not a regression, when each new silent function is already silent in an older check (the
  divergence is in an earlier stage). A new silent function that no older check lists is still a
  regression and blocks the merge. First case: slice 4 on the switch corpus (`pcc-r` and `pcc-t`
  silent 1 and 0 -> 60, all listed by `swfs-r`, `swsn-r` or `swfs-t`). User's decision
  ("progress that exposes bugs"); the guard against unlisted silents is Claude's wording.
- 2026-11-17: The facts ghidra-rs derives itself (`analyze --facts`) come from faithful ports of
  Ghidra's Java analyzers, not from approximations of them. Asked whether approximated facts
  (stack variables, data sizes, strings and pointers at references) may silently change the
  decompiled C, the user answered: "I would port the Ghidra analyzer next to Rust." Each record a
  port makes exact loses its approximation; whatever is still approximated stays written and
  measured (`tools/facts-diff.sh`) and is listed in `rust/README.md`, "Stage S10, slice 3".
  Superseded: the part of the open question of S10 slice 2 that let "a rule of Ghidra's analyzers
  ported with an approximation" stand as the way to go.

## Milestones

1. Load ELF/PE/Mach-O, decode x86-64 via `.sla`, and lift to p-code. A CLI dumps the disassembly and p-code.
   Done on branch `m1-sleigh-x86` (see `rust/README.md`). Output matches Ghidra's C++ SLEIGH
   engine exactly (text and p-code) on ls, libcrypto and libLLVM, checked with `rust/tools/sleigh_ref.cc`.
2. Function discovery, CFG, xrefs, strings, symbols. Benchmark against `analyzeHeadless`.
   First user: the mercs2 decomp project's headless Ghidra scripts on a 32-bit PE (x86:LE:32).
   On branch `m2-analysis`: 32-bit x86 (`x86.sla`), context defaults read from the `.pspec`,
   context commits (`globalset`) carried to later addresses, and `ghidra-rs analyze`, which
   writes the files of ExportFunctions.java and ExportGaps.java (match rates in
   `rust/README.md`; about 9.5 s against Ghidra's 723 s auto-analysis). On branch
   `m2b-abi-callers`: two-level switch tables, imports read through the image, call-through-
   pointer callees and non-returning import thunks. On branch `fid`: Function ID (the FID
   hasher, Ghidra's `.fidbf` databases read in place, matching and naming): of Ghidra's 26 FID
   functions in mercs2's `.text`, 24 get the same name, 2 another, none missing (details in
   `rust/README.md`). On branch `constprop`: Ghidra's constant propagation
   (`Analysis::propagate`, whole-function walks with callee purges), used by `--abi-callers`.
   On branch `constprop-functions`: it also feeds `--functions` (computed calls in
   `callees`/`callers`, code constants in `data_refs`): against the fresh ExportFunctions
   export, `callees` 97.2% (94.6% before), `callers` 97.5% (97.2%), `data_refs` 89.9% (83.1%).
2b. CheckAbiCallers.java (register liveness over p-code), the mercs2 pipeline's per-batch
   check: `ghidra-rs analyze --abi-callers`. On branch `m2b-abi-callers`: 96.5% of the
   reference rows identical. On branch `abi-dropin` (a drop-in for the script, judged by the
   mercs2 ABI gate): 97.7% identical, output independent of the thread count (details, timing
   and the causes of the rest in `rust/README.md`). On branch `coverage` (more of the code
   Ghidra reaches: folded SecuROM pointers, address tables in code sections, Ghidra's
   valid-subroutine check): 98.3% identical, and every reference `violation` the gate missed
   before is found. On branch `abi-rest` (the local fold keeps unknown registers as symbols
   and stored values, and follows jumps, so vtable calls resolve; pointers to import thunks
   count as imports; a `violation` behind any reference wins over a stopped walk): 98.6%
   identical, and the last three missing `violation` rows (0x84af20 at 0x41d7be, 0x41d834,
   0x675611) are found. On branch `constprop` (whole-function constant propagation, see
   milestone 2): 98.8% identical against the reference of mercs2 f14e5c4, and `CALL EAX` at
   0x73b4d1 resolves.
3. Decompilation: a Rust decompiler, checked against Ghidra's C++ one.
   Plan: `docs/plans/m3-decompiler.md` (stages, reference checks, decisions).
   S0 (harness) done on branch `m3-s0`: the reference `decomp_dbg` builds with the `print raw`
   patch and passes all 665 datatest checks, also through our runner (`ghidra-rs datatest`);
   the prelude (`analyze --decomp-prelude`) lets it decompile all of corpus M8; `ghidra-rs
   decompile -i` runs the same scripts and stops at `decompile` (not ported: identical 0 / 8).
   S1a (IR, flow, raw p-code) done on branch `m3-s1a`: `print raw` at `break start funclink`
   is identical on M8 (8 / 8) and M500 (500 / 500); jump tables use a stand-in until S3.
   S1b (specs, prototypes, call fixups) done on branch `m3-s1b`: reads `x86win.cspec`
   (prototype models, call-fixup snippets), `print raw` at `break start heritage` identical on
   M8 (8 / 8) and M500 (500 / 500); locked prototypes (the register ABI) still to come.
   S2 (heritage / SSA, first pass) done on branch `m3-s2`: the action framework with
   breakpoints and `continue`, phi placement and renaming for registers and temporaries;
   `print raw` at `break start paramdouble` identical on M8 (8 / 8) and M500 (500 / 500);
   later heritage passes (ram, stack) wait for the main loop's other actions (S4 on). Debugging
   tools: verbose diff, easy-first order, first-differing-step bisect (`rust/tools/`).
   S3 (jump tables) done on branch `m3-s3`: the C++ recovery (`JumpBasic`, `JumpBasic2`,
   `CircleRange`, the emulator, non-zero masks) on a partial function replaces S1a's stand-in;
   `print raw` at `paramdouble` identical on M8 (8 / 8), M500 (500 / 500) and 1,934 of the
   2,050 functions with a jump table (the rest: obfuscated code needing stack heritage, and one
   garbage target the reference reads). Rule-pool stand-ins in `jumptable.rs` wait for R1/R2.
   Superseded: R2 runs the real `jumptable` action on the partial function.
   S4 (main-loop actions without rules) done on branch `m3-s4`: dead code, parameter and
   return recovery, stack-pointer flow, deindirect, branch cleanup, the ram heritage pass;
   `print raw` at `break start assignhigh` with every later stage's groups off identical on
   M8 (8 / 8) and M500 (446 / 500); the rest need `ActionLaneDivide` (R3).
   S6 (types) done on branch `m3-s6`, with an S6b left: the data-type store (`types.rs`,
   struct layout from `<data_organization>`), type inference (`ActionStartTypes`,
   `ActionInferTypes`, `ActionConstantPtr`, `infertypes.rs`), the `parse line` declaration
   parser (`cparse.rs`) and locked prototypes (`locked.rs`, `lateres.rs`). `print raw` with
   types at `assignhigh`: M8 8 / 8, M500 446 / 446 non-SSE (the 53 SSE functions wait for
   `ActionLaneDivide`, R3); with every mercs2 function locked (`decomp-locked-options.sh`,
   `void` and `int4`): M8 8 / 8 and M500 446 / 446 non-SSE each. Bar changed by the user
   (2026-11-13): the D-corpus `parse line` check moves to the stage that adds x86-64 (58 of
   its 69 files are x86-64), the locked-prototype stand-in replaces it. Superseded: "D files
   using `parse line` pass". S6b: locked stack parameters of the decompiled function, varargs
   and hidden-return prototypes, scopes, unions, partial types; casts are S9.
   R1 (rule pools; 19 copy, constant and arithmetic rules) done on branch `m3-r1`: M8 8 / 8;
   M500 less the 46 `ActionLaneDivide` functions 451 / 453 (99.6 %, bar 98 %). S6 and R1 are
   merged on `m3-s6`: every S6 and R1 number above holds on the merged binary.
   R2 (50 bit, shift, comparison and boolean rules; 2 `cleanup` rules; the jump-table partial
   function runs the real `jumptable` action) done on branch `m3-r2`, merged with R3: M8 8 / 8;
   M500 498 / 499 the reference finishes (99.8 %, bar 98 %; 495 / 499 with R3 alone); S3
   recheck M500 500 / 500, switch corpus 1,947 / 2,050 (1,934 before); S4 498 / 500 and
   the S6 checks 498 / 500.
   With R3 part two and R4 merged, the R1-R3, subvar and R4 checks are each 498 / 499.
   R3 (in part) on branch `m3-r3`: `ActionLaneDivide` with `transform.cc`, and 21 extension,
   concat and sub-piece rules; same check with `lanedivide` on both sides: M8 8 / 8, M500
   495 / 499 (99.2 %, bar 98 %). Open: the `subvar` rules (`Subvar*`, `SplitFlow`; the rest of
   `subflow.cc`) and `RulePiecePathology` are not ported.
   Merged with S6: the S6 checks (unlocked, `void`, `int4`, callees) are M8 8 / 8, M500
   498 / 499 each with lane division on. Superseded: "446 / 446 non-SSE" above.
   R3 part two on branch `m3-r3b`: the `subvar` group (`SubvariableFlow`, `SplitFlow`, seven
   rules) and `RulePiecePathology`; new check with `subvar` on: M8 8 / 8, M500 497 / 499;
   R3 check now 497 / 499. Superseded: "Open: the `subvar` rules ... are not ported" above.
   R4 on branch `m3-r4`: 20 division, remainder, sign and float rules, `floatprecision`
   (`SubfloatFlow`) included; the R1 check with `floatprecision` on: M8 8 / 8, M500 495 / 499
   (99.2 %, bar 98 %); 90 M500 functions exercise the rules, 89 of them identical. Merged with R3 part two:
   R4 check M500 497 / 499; subvar, R3, S3, S4 and S6 bars all held.
   Stack heritage slice one on branch `m3-stack`: the stack heritage pass, stack-pointer
   tracing, the local scope's stack ranges, `ActionRestrictLocal`, locked stack parameters of
   the function; check with every function locked with two stack parameters, M8 8 / 8,
   M500 496 / 499 (498 / 499 after the review fixes and the merge with S7 and S8 part two,
   2026-11-14; the merge tests read the symbols of locked parameters); every older bar held.
   R5 (in part) on branch `m3-r5`: the five `typerecovery` pointer rules (`RulePtrArith` with
   `AddTreeState`, `RuleStructOffset0`, `RulePushPtr` in `oppool2`, `RulePtraddUndo`,
   `RulePtrsubUndo`) and the stop-propagation flags; R5 check M8 8 / 8, M500 497 / 498 without
   types, 487 / 498 with types (bar 95 %; 497 / 498 after the `opSetInput` fix); S6 check 498 / 500 with the rules on. Open: stack
   loads/stores, double.cc, constseq, bitfield, typed `cleanup` rules. Superseded: "double.cc" is ported (R5 slice 3, `rules/double/`).
   R5 slices 4 and 5 on branch `m3-r5b`: eight `cleanup` rules that read types (`ptrsubcharconstant`
   waits for string detection, S9) and the `constsequence`/`bitfields` entry tests; R1 check 498 / 499,
   R5 typed 497 / 498, new `r5c` check 494 / 498. Superseded: "constseq, bitfield, typed `cleanup` rules" above.
   R5 slice 2 in part on `m3-r5b` (2026-11-14, merged with stack heritage): `RuleLoadVarnode` and
   `RuleStoreVarnode` (`rules/stackvars.rs`), the call's stack offset, `propagateRef`; with
   `stackvars` on: M500 499 / 499 unlocked without rules, 473 / 499 with every prototype locked, 323 / 498 locked with rules and types, 132 / 498 unlocked with rules (the rest fail loudly, 5 silent differences not traced); every older bar held. Open: stack parameter trials of
   unlocked calls (`ActionActiveParam` with trials), `stackvars` in the jump-table partial function.
   Superseded: "Open: stack loads/stores" above.
   Superseded (branch `m3-ap`, 2026-11-14): `ActionActiveParam` with trials is ported
   (`checkInputTrialUse`, `AliasChecker`, `finalInputCheck`, `resolveModel`, `deriveInputMap`,
   `buildInputFromTrials`, `checkCallDoubleUse`); `r5s` 446 / 499, `r5slock` 450 / 498,
   `r5dtlocksv` 451 / 499 (were 132, 328, 328), M8 all 45 checks identical. Open, failing loudly:
   `ActionParamDouble` on a stack PIECE, heritage's indexed stack LOAD, a piece of a locked stack parameter.
   R5 review fixes on `m3-r5b` (2026-11-14): `ActionLikelyTrash::countMarks` and its lock test
   (superseded: "5 silent differences not traced" above; the 5 match now), the locked branch of
   `ActionParamDouble`, symbol tests in the double rules, `justifiedContain` for exclusion stack
   entries; new typed double-rule check (`r5dt-options.txt`): M8 8 / 8, r5d-adc 215 / 215,
   M500 497 / 498. The 27 M500 bars that ran held; the four `stackvars` checks, R5d on r5d-adc and
   the switch corpus were not rerun (work paused). Superseded: all rerun on `m3-int` (2026-11-14, merged with
   `m3-tail`): no bar fell; slice 2 with the locks and rules 328 / 499 (was 323 / 498: the 5 match, and
   the count is of the functions the reference finishes), R5dt locked on M500 482 / 499.
   S8 (structuring, in part) on branch `m3-s8`: `ActionBlockStructure` (`CollapseStructure`,
   `LoopBody`, `TraceDAG`; `structure.rs`, `collapse.rs`) and `print tree block`; `print tree
   block` plus `print raw` at `assignhigh` with `blockrecovery` on: M8 8 / 8, M500 499 / 499 the
   reference finishes (bar 98 %); with the rule-stage options M8 8 / 8, M500 496 / 499 before R2, 463 / 499 after R2 until `ConditionalJoin` was ported, 498 / 499 now (`ActionNodeJoin` ported, `nodejoin.rs`). Open: `prefercomplement` and
   `structuretransform` (R2's flip helpers they need are now on master), `finalstructure`, `returnsplit`.
   Part two on `m3-s8b`: `prefercomplement`, `structuretransform` (for loops) and `returnsplit`
   ported; both S8 checks unchanged with them on (499 / 499, 498 / 499). Superseded: the earlier
   "Open: `prefercomplement`, `structuretransform`" (their second, no-mods instances are wired since the S7 merge). Part three
   (`finalstructure`) is blocked by `latedonothing`, the prototype and cast actions, and switch labels. Open: `finalstructure`,
   structured `printRaw`. Superseded (tail, branch `m3-tail`, 2026-11-14): `latedonothing`, `outputprototype`,
   `inputprototype`, `mapglobals` and `finalstructure` are ported, with the scopes and symbols they need
   (`scope.rs`, `finalstructure.rs`). Checks (M8; M500 of the functions the reference finishes), rules on and types on:
   prototypes and globals (`print map` with `DECOMP_MAP_EXTRA`) 8 / 8, 498 / 499 and 493 / 499; `latedonothing` 8 / 8,
   498 / 499 and 493 / 499; `finalstructure` (`print tree block` with `DECOMP_TREE_EXTRA`) 7 / 7, 494 / 495 and 489 / 495.
   After a review the scopes' maps follow the C++ `rangemap` order, the compiler spec's `<global>` ranges are read and the prototype checks also compare parameter names, storage and symbol attributes; the six checks are unchanged.
   `namevars` is ported (`namevars.rs`: symbols linked to the named variables, Ghidra's default names); its check (`print map`
   after `namevars`) is M8 8 / 8, M500 498 / 499 (99.8 %) rules on and 493 / 499 (98.8 %) types on.
   Open: `setcasts` (S9; superseded: ported on `m3-cast`, below). `switchnorm` and the case labels are ported but paused before full verification (2026-11-14: M8 8 / 8,
   switch corpus `finalstructure` 1,937 / 2,004 rules on; M500 and the other bars not rerun; see the plan, "Switch case labels").
   Superseded: "paused before full verification": verified on `m3-int` (2026-11-14) with every bar in one
   pass (`rust/tools/bars.sh`, 9 h 22 min alone on the machine): no bar fell; switch corpus `finalstructure`
   1,937 and 1,929 / 2,004, `switchnorm` 1,943 and 1,947 / 2,004 (rules on, types on), S3 bar 1,947 / 2,050;
   M500 498, 493, 495, 499 / 499. Open: global symbol types on new varnodes are set lazily (six
   `switchnorm` rules-on misses), 0x4f3366. Structured `printRaw` is not reachable from the
   console (`print raw` prints the basic blocks), so it waits for S9's printer.
   S9 casts (branch `m3-cast`, 2026-11-15): `cast.cc` and `ActionSetCasts` are ported (`cast.rs`);
   checks `cs` (`print raw` after `setcasts`), `fsc`, `swfsc` (`finalstructure` with it on): M8 `cs`, `swfsc` 8 / 8 and
   `fsc` 7 / 7 (0x4042e0 is outside `fs`; superseded: "8 / 8 in all six"), M500 `cs` 498 / 499 and 493 / 499, `fsc` 494 / 495 and 489 / 495 (rules on, types on; no new
   miss), `swfsc` 498 / 499 and 493 / 499 (as `swfs`); M8 all 51 checks identical. Union resolution fails loudly.
   S9 slice 1 on branch `m3-print1` (2026-11-15): `print C` for straight-line functions in the
   three layers (`prettyprint.rs`, `printlanguage.rs`, `printc.rs`); every construct not ported
   (if, loops, switch, gotos, comments in the body, field and array access, the remaining
   operators and constants) fails loudly. Casts are not printed yet (`setcasts` skipped on both
   engines). Checks `pc-r`, `pc-t` (`tools/bars.sh`): `simple` corpus 54 / 194 and 34 / 194
   identical, the rest loud; M500 `pc-t` 24 / 495 (loud 471, 376 of them `BlockIf`, silent 0),
   `pc-r` 47 / 495 (loud 448, silent 0); `pg-*` and `nm-*` on M500 unchanged after its
   `namevars` and `mapglobals` fixes;
   M8 0 / 7, all loud.
   Both merged on `m3-s9` (2026-11-15): M8 all 51 checks before `pc-*` identical, `pc-r` and `pc-t` 0 / 7, all loud.
   Review fixes on `m3-s9`: `print C` with `setcasts` on (`pcc-r`, `pcc-t`) M500 10 / 495 and 8 / 495, silent 0 (a CAST op fails loudly).
   S9 slice 2 on branch `m3-print2` (2026-11-15): every structured block (if/else, loops, switch, gotos,
   labels) and casts in `print C` (superseded: "fails loudly" for those and for a CAST op); M500 `pcc-r` 235 / 495,
   `pcc-t` 58 / 495, `pc-r` 244 / 495, `pc-t` 45 / 495, silent only 0x47a6b0 (differs from `r1` on); switch
   `pcc-r` 153 / 2005 (silent 0; flow now warns of overlapping instructions); M8 the 51 other checks identical.
   S9 slice 3A on branch `m3-print3a` (2026-11-15): array and field access (`PTRADD`, `PTRSUB`,
   parts of symbols) and character constants in `print C` (superseded: "fails loudly" for those);
   M500 `pcc-t` 143 / 495, `pc-t` 143 / 495, `pcc-r` 235 and `pc-r` 244 / 495 (unchanged), silent only
   0x47a6b0; `simple` `pcc-t` and `pc-t` 95 / 194; M8 the 51 other checks identical.
   S9 slice 3B on branch `m3-print3b` (2026-11-15): indirect calls, the float operators and float
   constants (`printDecimal`), anonymous data-types (`genericTypeName`) and the body comments
   (`CommentSorter`, `comment.rs`) in `print C` (superseded: "fails loudly" for those); flow records
   the jump-table failure warning. M500 `pcc-r` 441 / 495, `pc-r` 442, `pcc-t` 94, `pc-t` 72;
   `simple` 174, 174, 91, 83 / 194; silent only 0x47a6b0; M8 the 51 other checks identical. Switch `pcc-r` not finished.
   Review fixes on it: unported jump-table failures fail loudly, four dropped warnings recorded; same counts.
   Slices 3A and 3B merged on branch `m3-print3` (2026-11-16): M500 `pcc-r` and `pc-r` 442 / 495, `pcc-t`
   and `pc-t` 257 / 495; `simple` 174, 174, 138, 138 / 194; silent only 0x47a6b0; M8 the 51 other checks
   identical, the print checks 6 / 7 (`-r`) and 5 / 7 (`-t`).
   Slice 4 on branch `m3-print4` (2026-11-16): `INT_CARRY`, `INT_SCARRY`, `INT_SBORROW`, `PIECE`, `POPCOUNT`,
   `LZCOUNT`, CALLOTHER of a SLEIGH user-op and the SUBPIECE field extraction. M500 `pcc-r` and `pc-r`
   487 / 495, `pcc-t` and `pc-t` 479 / 495; silent only 0x47a6b0; M8 all 55 checks identical (print 7 / 7).
   Full pass: `simple` 190, 190, 188, 188 / 194; switch `pcc-r` 1810 / 2005, `pcc-t` 1817 / 2005, each with 60
   silent that older switch checks already list (see the Decided entry of 2026-11-16).
   Branch `m3-swsilent` (2026-11-16): the jump-table partial function runs with the `stackvars` rules
   (fallback without them when its stack heritage is not ported), `fail_return`, a wider loud test of
   `ActionConditionalExe`, dead code in the join space. Switch corpus `paramdouble` 1947 -> 1999 / 2004
   (silent 57 -> 0), `swsn-r` 1943 -> 1994 (silent 61 -> 3), `swfs-r` 1937 -> 1991 (silent 60 -> 0, loud 7 -> 13);
   3 functions identical before are loud now (4 in `swsn-r`). The other switch checks and M500 not rerun.
   Superseded by the review fixes on the same branch (a recovered table must not depend on an INDIRECT of a
   stack varnode the unported `RuleAliasUpdate` may remove, or, in the fallback, on a guard reading the stack;
   `fail_return` uses the spec's `<returnaddress>`): `paramdouble` 1988, `swsn-r` 1984 (silent 3), `swfs-r` 1982
   (silent 0) of 2004; 12 functions identical on master are loud in `swfs-r` (14 in `swsn-r` and
   `paramdouble`). M500 `s8r`, `swfs-r`, `swfs-t`, `fs-t` at their counts, 0x47a6b0 loud instead of silent.
   Slice 5 on branch `m3-print5` (2026-11-16): labels of spliced blocks, function and external reference
   symbols as variables, `VariablePiece` groups, string and function pointer constants. M500 `pcc-r` and `pc-r`
   494 / 495, `pcc-t` and `pc-t` 495 / 495, no loud miss, silent only 0x47a6b0; M8 all 55 checks identical.
   Switch `pcc-r` 1944 / 2005 (silent 61), `pcc-t` 1943 / 2005 (silent 62); all in older switch checks except
   0x23caea8 (`pcc-t`), open: the read-only write warning of `fillinReadOnly` is not ported.
   Superseded: the slice 4 counts above.
   Follow-up: that case is loud now (`print C` fails on a written read-only address); switch `pcc-t` loud 1,
   silent 61, every switch silent in an older check. Superseded: "silent 62" and "open" in the two lines above.
   Integration `m3-int5` (2026-11-17), full pass clean against the slice 4 baseline: switch `pcc-r` 1987 / 2005,
   `pcc-t` 1986 / 2005, silent 0; the other switch checks 1984 to 1988 of 2004; `simple` print 194 / 194; the only
   silent misses left are in `swsn-r` (3 on switch, 3 on M500). Superseded: the switch counts in the lines above.
   After `m3-int5` (2026-11-17): the `fillinReadOnly` write warning is ported, 0x23caea8 identical; switch
   `pcc-t` 1987 / 2005 (loud 18, silent 0). Superseded: "that case is loud now" and `pcc-t` 1986 above.
   `print raw` applies the global symbol types first: `swsn-r` switch 1987 / 2004, M500 498 / 499, silent 0.
   No silent miss is left in the checks run. Superseded: "the only silent misses left are in `swsn-r`" above.
   Default options, branch `m3-default` (2026-11-17): the new check `pcd` (`print C`, no option off, the seven
   unported leaves `restructure_varnode`, `mapped_local_sync`, `multicse`, `shadowvar`, `condconst`, `dynamicsymbols`,
   `prototypewarnings` skipped on both engines) starts at M8 6 / 8 (silent 2), M500 339 / 497 (loud 83, silent 75).
   Then on the branch: five of the seven leaves done (`restructure_varnode` and `mapped_local_sync` stay skipped),
   the unported pool rules switched off on both engines (`default-options.txt`: 14, then 8 after six rules landed):
   M8 8 / 8, M500 415 / 497 (loud 82, silent 0) with 11 rules off. Open decision: a run with the plain default
   options still leaves the 8 unported rules out without a word.
   Branch `m3-aliasupdate` (2026-11-17): `RuleAliasUpdate` and `ActionRestructureVarnode` (untyped) run in the
   jump-table partial function, so its table is taken as it is; the older test on INDIRECTs of stack varnodes is
   left for the partial function made without them (a load or store guard, a locked prototype). 7 functions
   loud -> identical in every switch check, 8 in `pcc-r` and `pcc-t`. Derived from the 9 changed functions and
   the `m3-int5` pass: `paramdouble` 1995, `swsn-r` 1991 (silent 3), the other switch checks 1994 of 2004;
   `pcc-r` 1995, `pcc-t` 1994 of 2005. Superseded: the switch counts of the line above, and "the unported
   `RuleAliasUpdate`" in the `m3-swsilent` lines.
   Review fixes (2026-11-17): symbol flags on a new stack varnode, `markNotMapped` over the symbols, no failed
   table from a partial function made without the alias analysis; no output changes. Measured on the whole switch
   corpus: `paramdouble` 1995 / 2004, `swfs-r` 1996, `swsn-r` 1993 (silent 3), `pcc-r` 1997 / 2005, `pcc-t`
   1996 / 2005 (Superseded: the derived counts of the line above). Open: 0x5861aa and 0x7c74c0 loud at `paramdouble`.
   Value-set analysis and the stack guards (2026-11-17): `ValueSetSolver` and the load and store guard ranges
   (`valueset.rs`, `heritage_guard.rs`) with their readers in the alias rule, the range hints and the merge test.
   Derived from the functions with a guard run against the reference: switch `paramdouble` 2002 / 2004, `pcc-r`
   2004 / 2005, `pcc-t` 2003 / 2005; M500 `pcd` 440 / 497 (loud 57), silent 0. 0x5861aa and 0x7c74c0 traced: the
   reference's partial function fails too and its later tables come from the half-simplified clone, left loud.
   Superseded: the switch counts and "Open" of the line above, `pcd` 415 / 497 in the `m3-default` line.
   Pieces of symbols (2026-11-17): `finalizeDatatype` through `getExactPiece`, `pushMismatchSymbol`, the validity
   test of `HeapSequence`: `pcd` M500 474 / 497 (loud 23, silent 0; was 422, loud 75), `r5c` M500 498 / 498.
   Where the C++ orders by `HighVariable` address (`snipOutputInterference` over several variables of a
   group) ghidra-rs fails loudly (0x4130d0): Claude's call, see "Open questions". (Superseded: this was
   written here as "Decided"; only the user decides.)
   Local symbols (2026-11-17): `restructure_varnode` and `mapped_local_sync` run in the `decompile` root (typed range
   hints, symbols of the local scope, `syncVarnodesWithSymbols` with data-types), so `pcd` skips no action: M8
   8 / 8, M500 463 / 499 (loud 36, silent 0), simple 188 / 200 (loud 12, silent 0). New check `pmd` (symbols and typed
   ops after `mapped_local_sync`): M8 8 / 8, M500 470 / 499 (loud 29, silent 0). 47 M500 functions loud -> identical,
   6 identical -> loud (join `subflow` 3, `StringSequence` 2, an indexed stack LOAD 1). Switch corpus unchanged
   (`paramdouble` 1995 / 2004, `swfs-r` 1996, `swsn-r` 1993 with the 3 silent, `pcc-t` 1996 / 2005). Superseded: "`restructure_varnode`
   and `mapped_local_sync` stay skipped" and "M500 415 / 497" above. Open: `ValueSetSolver` (26 of the 36 loud),
   `StringSequence`, `adjustInputVarnodes` (0x581bf6 was silent in `pmd`, loud now).
   Pool rules (branch `worktree-agent-ab53ef4e46d4bec80`, 2026-11-17): the `decompile` root now fails while a
   pool rule that is not ported is on (Superseded: the open decision in the `m3-default` lines above); the rule
   tables list every C++ rule and a unit test compares them with coreaction.cc. `switchsingle`, `ptrflow`,
   `splitcopy`, `splitload`, `splitstore` ported, `aliasupdate` on in `pcd`; `default-options.txt` holds 2 rules
   (`segment`, `ptrsubcharconstant`, ported on other branches). `pcd` M500 422 / 497 (loud 75, silent 0), unchanged;
   M8 56 checks unchanged; M500 rule checks equal or better, silent 0; switch `pcc-r` 1997 / 2005, `swsn-r` 1993 / 2004
   (silent 3) unchanged. First `pcd` on the switch corpus: 1788 / 1994 (loud 199, silent 7, all 7 older than the branch);
   the new rules change 81 reference outputs there, 55 identical here, 25 loud, 1 of the 7 silent.
   S10 (2026-11-17), check and inventory only: `tools/ghidra-diff.sh` against Java Ghidra, M8 identical 0 / 7
   (loud 7; Java has no function at 0x54c990), M500 Java finishes 499 / 500. Blocked: eight actions of the
   default `decompile` are not ported (`restructure_varnode`, `mapped_local_sync`, `multicse`, `shadowvar`,
   `condconst`, `directwrite`, `dynamicsymbols`, `prototypewarnings`); with them skipped on both engines and
   default options, M8 8 / 8 and M500 410 / 500 against `decomp_dbg` (loud 78, silent 11, in no `bars.sh`
   check). See `rust/README.md`, "Stage S10".
   S10 slice 1 (2026-11-17): the facts of the Ghidra project (`tools/ghidra/ExportFacts.java`: what Java
   answers its decompiler, recorded as XML) and the console command `load facts` (`decomp/facts.rs`): Ghidra's
   type names, function and data names, prototypes, read-only memory, comments, labels, `local_` names. With the
   eight actions skipped: M8 identical 3 / 7 (the other four need the eight), M500 identical 192 / 499 (loud 72, silent 235). Still
   blocked on the eight. See `rust/README.md`, "Stage S10, slice 1".
   Review fixes (2026-11-17): panics with facts, strings read as Java reads them, labels at every instruction,
   undefined read-only bytes, `FACTS=0`; four silent cases made loud; facts file version 2. Superseded: "loud 72,
   silent 235" (the slice's final build: loud 70, silent 237; the same after the fixes). See `rust/README.md`,
   "Stage S10, slice 1: review fixes". The checks against `decomp_dbg` (M8 all 55, M500 six) equal the baseline.
   S10 slice 2 (2026-11-17): `ghidra-rs analyze --facts` writes the same facts from ghidra-rs's own analysis
   (`factsout.rs`), so `load facts` needs no Java project: functions, bodies, names, purge, stack variables,
   imports with the prototypes of Ghidra's Windows archive (a one-time headless export,
   `tools/ghidra-protos.sh`), data symbols, strings and pointers at references, labels, read-only blocks,
   tracked registers, flow overrides. What it does not derive is an `underived` record and fails when a
   decompile reads it. `tools/facts-diff.sh` compares with the Java facts per record kind (mercs2, with
   Java's function set: `func` 80.6%, `body` 98.1%, `extref` 90.0%, `data` 47.1%, `label` 94.9% equal; `ghidra-diff.sh` M8 identical 2 / 7 against 3 / 7 with the Java facts, M500 171 / 499 against 192 / 499). See `rust/README.md`, "Stage S10, slice 2".
   S10 slice 3 (2026-11-17), after the decision "port the Ghidra analyzer" (see Decided): five pieces of Ghidra's
   analyzers ported for `analyze --facts`: address tables at instruction references and the pseudo-disassembler's
   body checks (`OperandReferenceAnalyzer`, `AddressTable`, `PseudoDisassembler`), the purges the stack analysis has
   at a call (`SymbolicPropogator.getFunctionPurge`), the ASCII Strings analyzer with its trigram model
   (`strings.rs`), data through an address a register holds, Function ID's plate comments. mercs2 with Java's
   function set: `func` 81.2%, `data` 84.9%, `string` 90.5%, `undef` 95.6%, `wref` 84.9%, `comments` 71.0% equal
   (slice 2: 80.6%, 47.1%, 51.6%, 92.6%, 62.6%, 0%); `label` 94.7% (94.9%). `ghidra-diff.sh` M8 identical 2 / 7,
   M500 173 / 499 (171). Shadow check: same 56,003, differ 60 (55,996, 61). Still approximated: Ghidra's order of
   analysis. See `rust/README.md`, "Stage S10, slice 3".
   Integration `m3-int6` (2026-11-17): the eight branches of the lines above merged (small items, segment user
   ops, `m3-default`, value sets, pieces of symbols, local symbols, pool rules, S10 with the project store). No
   pool rule is unported and `default-options.txt` is empty, so `pcd` and `pmd` run the plain default options. M8
   all 57 checks identical (the 55 baseline lines unchanged, `pcd` and `pmd` 8 / 8). M500: `pcd` 493 / 499 (loud 6,
   silent 0), `pmd` 497 / 500 (loud 3), `pcc-r` and `pcc-t` 495 / 495, `r5s` 498 / 498, `paramdouble` 500 / 500,
   `swsn-r` 499 / 499; no function of the `m3-int5` baseline got worse. Superseded: the `pcd` and `pmd` M500
   counts of the lines above, "`default-options.txt` holds 2 rules", "Open: `ValueSetSolver`", and "Blocked: eight
   actions" of S10 (ported; the checks against Java Ghidra not rerun). Not run: the full pass. See
   `rust/README.md`, "Integration `m3-int6`".
   S7 (merging into high variables) in part on branch `m3-s7`: the merge actions `assignhigh`
   .. `copymarker` (`merge.rs`, `variable.rs`, `cover.rs`); `print raw` with high variables at
   `break start inputprototype`: M8 8 / 8, M500 492 / 499 (rules on) and 492 / 499 (types on), also with create indices.
   Merged with R3b, R4, R2, S8, R5: rules on 498 / 499, types on 493 / 499 (a copySymbol type fix;
   superseded: 481 / 499). Open: `VariablePiece` groups, `dynamic.cc`, symbols.
4. More processors (ARM/AArch64, MIPS, ...), batch mode, a persistent project DB.
   Will need the engine parts not ported yet: delay slots, `crossbuild`, `inst_next2` and
   flowref/flowdest.
   In part on branch `worktree-agent-af1e2713bbdee8eab` (2026-11-17): the project store as one plain
   text file (`store.rs`: created and removed functions, fixed bodies, no-return flags, flow
   overrides, thunk marks, switch targets, laid over a fresh analysis by `analyze --store`) and
   mercs2's five project-editing scripts as `ghidra-rs edit` commands (`edits.rs`). On
   Mercenaries2.analysis.exe the store brings the `.text` functions shared with the Java project
   from 20422 to 36602 of 37635 (36178 with the same body size). Not ported, failing by name:
   ExportBindings `--recover`, AuditRecoveredFunctions `--remove-empty`. Details in
   `rust/README.md`, "Project store and the editing scripts".

## Open questions

Superseded: "None open" (until 2026-11-17) and "where the edits of mercs2's five project-editing
scripts live", decided 2026-11-15 (plain files, see Decided).

- 2026-11-17: Where does ghidra-rs take the facts of a Java Ghidra project from (function and data
  names, prototypes, data-types, listing data)? S10 slice 1 chose, without the user: an export from
  the Ghidra project by a headless script, read with the console command `load facts`. The
  alternative is ghidra-rs's own analysis plus the edit files of the 2026-11-15 decision, which
  cannot match Java's C wherever Java's analysis differs. To confirm or change.
  S10 slice 2 built that alternative next to the export (`analyze --facts`, the same file format) and
  measured it; both exist, the question stays open.
- 2026-11-17: Choices of S10 slice 2 made without the user, to confirm or change: a part of the facts
  ghidra-rs does not derive is named (`underived`) and fails the decompile that reads it, while a
  rule of Ghidra's analyzers ported with an approximation is written and measured instead; a
  function given by `--seeds` or `--functions-from` that discovery does not find stands for one a
  script made after auto-analysis (no purge, no stack variables); the import prototypes come from a
  one-time headless export of Ghidra's archive, not from a `.gdt` reader in Rust (the 2026-11-13
  decision names data-type archives as data to read in place: not started).
  Superseded in part: "a rule ... ported with an approximation is written and measured instead" is
  decided (2026-11-17, see Decided): approximations give way to ports; the other choices stay open.
- 2026-11-17: Choices of S10 slice 3 made without the user, to confirm or change (`rust/README.md`,
  "Stage S10, slice 3"): `PseudoDisassembler.checkPseudoBody` is ported whole although, with the
  references of all discovered code at once, it loses 452 labels of SecuROM's code that Java has
  (Ghidra's order of analysis is not ported: its task queue would be the next port); `--facts`
  fails without Ghidra's strings model file; a Function ID comment with a mangled name stays
  `underived` until the demangler is ported.
- 2026-11-17: Claude's call (1d, "Pieces of symbols"), awaiting the user: where the C++ orders by
  `HighVariable` address (`snipOutputInterference` over reads of several variables of one group),
  ghidra-rs fails loudly instead of guessing the snip order. The order is the C++ allocator's (a
  new `HighVariable` reuses freed memory) and cannot be reproduced; a guess would be a silent
  difference (0x4130d0 had two copies swapped). To confirm or change.

Open (asked 2026-11-17, with the project store):

- The Decided entry of 2026-11-15 describes the five editing scripts as "renames, types,
  comments" and lets them move off Java "after S10". They edit function boundaries, no-return
  flags and flow overrides, and the store built for them needs no S10. The entry is left as
  written; a corrected wording waits for the user.
- The store's choices marked "Claude's call" wait for a yes or no: one file per project, passed
  as `--store` (not a directory); final state, not a log of edits; a function is not created
  where nothing decodes (Java makes a one-byte function); derived flow overrides and thunks
  with only the exceptions stored.
- Whether ExportBindings `--recover` and AuditRecoveredFunctions `--remove-empty` get ported
  (both fail by name now), and whether mercs2 switches its pipeline to the store.
