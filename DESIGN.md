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
    `.cspec`), Function ID databases and data-type archives (`.gdt`, `rust/ghidra-rs/src/gdt/`) are
    read as they are.
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
- 2026-11-17: Functions ghidra-rs's discovery makes and Java Ghidra does not are fixed in
  discovery, not accepted as exceptions. FoldSlotFragments stopped with "the walk from
  0x00861190 removed that owner itself": 0x861190 is a function of ghidra-rs's own discovery
  (reached only by jumps) where Java has none. Asked whether to change discovery or accept an
  exception, the user said: "Fix function and any related problems so it prevents it down the
  line." First step (`rust/README.md`, "What discovery does"): Shared Return Calls is a port of
  SharedReturnAnalysisCmd's walk. Resolved (2026-11-18): Java 12.2 also makes 0x861190 and its FoldSlotFragments removes it as its own owner ("refit failed Object has been deleted.") and goes on; `fold-slot-fragments` does the same now (`rust/README.md`, "Resolved (2026-11-18)"). Superseded: "0x861190 itself is still made (open)".
- 2026-11-18: The check tooling caches the reference decompiler's outputs. The user: "I would
  first check to make sure the files need rebuilt or not. If so build. If not, dont build."
  Confirmed: each reference output is kept under a content hash of every input that can affect
  it (the reference build, the binary, the `.sla` files, options, prelude, the function's
  script, the command line, the `DECOMP_*` environment); the same hash reuses it, a new one
  reruns; file dates are not enough. A timeout or any failed or incomplete reference run is
  never cached. ghidra-rs always reruns. `REFCACHE=0` turns it off (`decomp-diff.sh`,
  rust/README.md).
- 2026-11-19: Bodies are kept from creation. Each function keeps the body CreateFunctionCmd
  gave it, changed only where Java sets a body (fixupFunctionBody, the cut of an overlapping body
  when a function is made, thunk creation, the no-return repairs); ghidra-rs no longer recomputes
  bodies from the flow after each task. Then CreateFunctionCmd's thunks and the Stack analyzer on
  later batches. Oracles split: analysis alone is checked against a plain Java 12.2
  auto-analysis (`DumpPurges.java`); analysis with the ported mercs2 edit scripts against
  `mercs2.facts`, which is mercs2's project after its own pipeline, not plain Java analysis
  (0x4b6580: purge 0 in Java 12.2, `unknown` in the facts). See `rust/README.md`, "Bodies from
  creation".
- 2026-11-20: The Java reference is Ghidra built from this repo's own source (12.3), not the
  installed 12.2 (`/opt/ghidra`). ghidra-rs ports the 12.3 source, so comparing it with 12.2
  showed version differences as silent misses (GP-7356 register names such as `register_ESP`
  against `register0x00000010`, GP-7474; 7-8 of the M500 Java-facts silents). With the reference
  built from the same source, every difference is a port bug or a loud gap. User's decision
  ("the most logical"), chosen over listing the version differences as known. The Java reference
  outputs (ghidra-diff, `DumpPurges`, the Java 12.2 project of the analysis oracle) are made again
  with 12.3; mercs2's own project is copied, never upgraded in place. Superseded: "plain Java 12.2
  auto-analysis" in the entry above means plain Java 12.3 auto-analysis once the outputs are made
  again.
- 2026-11-21: Hatred (native Linux build, `Hatred-Linux-Shipping`, ELF x86-64, GCC, with DWARF)
  is the second game, and its needs start now, ahead of the rest of (a) and (c) in the
  2026-11-14 order. Four pieces, all requested by the user: the ELF64 loader feeding `analyze`,
  the x86-64 System V calling convention (`x86-64-gcc.cspec`), the GNU (Itanium) demangler and
  a DWARF types reader. Each is a port of Ghidra's own code, checked against the 12.3
  reference, as before. mercs2 stays a test bed. The rewrite project itself lives in
  `~/projects/hatred-decomp`.
- 2026-11-21: Two ELF-only rules of branch `elf64` stay, although they were measured, not
  traced in Java: a PLT function of one `JMP [slot]` takes its import's no-return flag, and a
  `CALL [GOT slot]` to a no-return import does not end the flow (on libtcl it brought 743 body
  sizes to Java's). User's decision ("Keep"); an exception to the 2026-11-17 "faithful ports,
  not approximations" rule, marked as such in the code and `rust/README.md`.
- 2026-11-21: Next for Hatred: the decompiler on x86-64 Linux (facts writer, core types,
  System V prototypes, decompiler language x86:LE:64:default:gcc), checked against Java 12.3.
  User's decision. Addresses stay 32-bit for now (Hatred's highest is about 0x5300000; past
  4 GiB fails loudly); widening to 64-bit waits for a binary that needs it.

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
   0x73b4d1 resolves. Ledger (2026-11-20, ghidra-rs b6b02b2ca5, `rust/tools/abi-ledger.csv`):
   all 1,076 rows of the shadow diff are in it; no row has ghidra-rs `ok`/`(none)` where the
   truth is `violation`, but 39 true call sites are missing on our side (undecoded code, vtable
   slots, SecuROM sections) and 92 rows where we are the looser side are still `unknown` or
   `unverified`, so the bar to switch is not met; the swapped sweeps have not started.
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
   `swsn-r` 499 / 499; no function of the `m3-int5` baseline got worse (0x6b21e0 of `r5s` not compared: the
   reference no longer finishes it, as on the branches). Superseded: the `pcd` and `pmd` M500
   counts of the lines above, "`default-options.txt` holds 2 rules", "Open: `ValueSetSolver`", and "Blocked: eight
   actions" of S10 (ported; the checks against Java Ghidra not rerun). Full pass 2026-11-18: silent 0 in every pair, none worse than the baseline (Superseded: "Not run: the full pass"). See
   `rust/README.md`, "Integration `m3-int6`".
   Integration `m3-int7` (2026-11-18): the Shared Return port with the `fold-slot-fragments` fix and the `export`
   commands with `rust/tools/mercs2-exports.sh` merged. `cargo test` 164 passed; M8 all 57 checks equal to the
   `m3-int6` baseline (silent 0); plain discovery on mercs2 makes 29,186 functions (superseded: 29,240), no M8
   function changed; the mercs2 shadow check is byte-identical to `m3-int6`'s; `mercs2-exports.sh --compare` 4
   identical, 2 call-contexts the same references in another order, 0x00401780 not identical (one reference more),
   as on the export branch. Not run: M500, the full pass. See `rust/README.md`, "Integration `m3-int7`".
   Java-facts gap (2026-11-20, branch `gap-javafacts`, M500 identical of 499): 461 (loud 22, silent 16) -> 467 (loud 23, silent 9), M8 7 / 7, the 57 M8 bars as `analysis-queue`. Fixed: `void` is the size-0 TypeVoid (3 silent), a function symbol covers its facts size of 2 to 8 bytes (`FunctionSymbol::consumeSize`; 2 silent, 1 silent now loud), `isString` takes the empty string (1 silent). Of the 9 silent left, 8 are reference-version differences: `/opt/ghidra` is 12.3 and its decompiler lacks GP-7356 (`register0x00000010` for `register_ESP`) and GP-7474 (`_BinkPause_8`); the repo C++ replaying Java's debug XML (`DecompileRef.java` with `DECOMP_DEBUG_DIR`) prints what ghidra-rs prints. The ninth (0x47f890, variable numbering) is open. Superseded: the 461 / 16 counts above.
   Java-facts gap, continued (2026-11-20, branch `gap-javafacts2`, M500 identical of 499): 467 (loud 23, silent 9) -> 469 (loud 21, silent 9), M8 7 / 7. The deindirect restart is ported: `ActionDeindirect` records the call as an override (`Override::insertDeindirect`) and asks for a restart when the callee does not return, is inlined, or has a locked prototype the call cannot take; the `universal` group (`ActionRestartGroup`, at most 1 restart) clears the function (`clearAnalysis`) and runs again, and the flow makes the call direct (`Override::applyIndirect`). The restart starts from the prototype the decompile started with, where the C++ clears only the unlocked inputs and output of the one it has. Of the 9 functions that stopped there, 2 are identical; 7 stop at later not-ported paths: a call to a locked varargs prototype 4, a logical value in a join varnode (subflow) 2, a data-type needing resolution in `setcasts` 1. 0x47f890 is a reference-version difference too: decomp_dbg built from this repo's C++, on Java's debug XML with Java's options, prints `auStack_82 [2]` where Java prints `uStack_90` and `unaff_EDI`, as ghidra-rs does; so all 9 silent are reference-version differences. Correction: `/opt/ghidra` is 12.2 (its application.properties) and this repo's source is 12.3. Superseded: the 467 / 23 counts, "`/opt/ghidra` is 12.3" and "0x47f890 is open" above. Then a logical value in a join varnode (`SubvariableFlow::getReplacementAddress` with `renormalizeJoinAddress`, little-endian) is ported: 469 (loud 21, silent 9) -> 470 (loud 20, silent 9), M8 7 / 7; 0x5cee30 is identical, 0x5d8680 and 0x5d87c0 now stop at a call to a locked varargs prototype, which 7 functions stop at. 0x4098c0 stops at type propagation into a union. Superseded: the 469 / 21 counts. Then a call to a locked varargs prototype is ported (`funcLinkInput` with `initActiveInput` and the fixed position of each locked parameter, `sortFixedPosition` in `buildInputFromTrials`; `lateRestriction` refuses to give a varargs call a non-varargs prototype, as `isCompatible` does, and a varargs call taking a varargs prototype stays loud), and the name recommendations stay for a restart (the C++ keeps `nameRecommend`; the restart lost `local_80` of 0x6c3cb0): 470 (loud 20, silent 9) -> 473 (loud 16, silent 10), M8 7 / 7, the M8 bars unchanged (57 lines). 0x4b8e50, 0x5d84e0 and 0x5d87c0 are identical; 0x5d8680 stops at StringSequence, 0x5e66c0 at `getTypePartialStruct`, 0x74d520 at type propagation into a struct. 0x6c3cb0 is newly silent and no version difference (the repo C++ on Java's debug XML prints Java's C): in the pass after the restart the C++ gives the COPYs in the split return blocks the global's types (`char`, `float`) where ghidra-rs keeps `undefined1` / `undefined4`, so ghidra-rs prints `DAT_014e0432 = 1` for `'\x01'` three times; the first passes agree, and keeping the global scope's symbols over the restart did not change it. Superseded: the 470 / 20 counts. Then the global scope keeps its symbols over a restart (`Funcdata::clear` clears the local scope only) and a type-locked data symbol of an unknown data-type is size-locked (`Symbol::checkSizeTypeLock`), so `ActionNameVars` gives it the type of its high variable (`overrideSizeLockType`) and the varnodes of the pass after the restart take that type from the symbol (`setSymbolProperties`, the global scope before the facts): 473 (loud 16, silent 10) -> 474 (loud 16, silent 9), M8 7 / 7, the M8 bars unchanged (57 lines); 0x6c3cb0 is identical. Superseded: the 473 / 10 counts and "0x6c3cb0 is newly silent" above. Then `StringSequence` is ported up to its validity (the constructor: `collectCopyOps`, `checkInterference`, `formByteArray`); a COPY that roots no sequence of four characters in an array of the symbol is left alone, a valid one and a symbol of a struct or union stay loud (`StringSequence::transform` is not ported): 474 (loud 16, silent 9) -> 478 (loud 11, silent 10), M8 7 / 7, the M8 bars unchanged (57 lines). 0x5a9b80, 0x5bed50, 0x5d8680 and 0x740a90 are identical. 0x5d9a20 is newly silent and a reference-version difference: decomp_dbg built from this repo's C++, on Java's debug XML, prints what ghidra-rs prints (early returns where Java nests if / else); which 12.3 change it is was not traced (GP-7115, which splits out `BlockIfNoExit`, is a candidate). Superseded: the 474 / 16 counts. On the 12.3 reference (`rust/target/ref123/`, Ghidra 12.3 built from this repository, `GHIDRA` names the install) the row is 487 (loud 11, silent 1: 0x5c64a0), M8 7 / 7. Superseded: the 478 / 10 counts (12.2) as the measure. With Java's facts loaded, name tokens (function, variable, type, field and label names, not constants) print as Java's `PrettyPrinter` prints them through `IllegalCharCppTransformer` (`DecompileResults.getDecompiledFunction`; a namespace prefix, printed by `emitSymbolScope` as syntax, is kept): `_BinkPause@8` -> `_BinkPause_8`, 488 (loud 11, silent 0), M8 7 / 7; without facts names print as the C++ console prints them (M8 bars unchanged, 57 lines). A non-ASCII letter in a name fails loudly (`Character.isLetter` is not ported). `lateRestriction` is ported for every prototype a deindirected call takes, locked or not, with `FuncProto::isCompatible` (`ProtoModel::isCompatible`: the facts' `unknown` model is compatible with the default; both outputs locked compare storage and data-type; extrapop; varargs, where an unlocked call may take a varargs prototype; call fixup; no-return), so an unlocked callee that is not compatible restarts as in the C++, no longer copied; a varargs prototype onto a call still recovering its inputs fails loudly (`collectUnlockedTrials`), one onto a call not recovering them restarts. A call fixup no longer stands for `isInline` (no prototype is inline: the facts refuse the flag); a prototype with its own effect or likely-trash list is refused by the facts. Java-facts row on 12.3 unchanged: 488 (loud 11, silent 0), M8 7 / 7; M8 bars unchanged. A restart keeps the prototype as the pass before left it (model, extrapop, flags, as `Funcdata::clear` keeps `funcp`) and clears only its unlocked output and `returnBytesConsumed` (`FuncProto::clearUnlockedOutput`; a size-locked output back to an unknown data-type, `resetSizeLockType`). Superseded: "the restart starts from the prototype" above. Small fixes after a review: a restart keeps the join records (global in the C++, `AddrSpaceManager`); `renormalizeJoinAddress` in SubvariableFlow fails loudly on a constant piece (`!addr1.isConstant()`) and on a big-endian target; a function record's malformed `size` attribute is a facts error, no longer read as 0; a cached global symbol without a data-type fails loudly instead of skipping the facts. Not done: `findContainer`'s smallest container in `query_global` (functions are still checked before external references) and the split of `string_sequence_valid` (constseq.rs).
   Full pass 2026-11-18 (249c32cf94): 133 / 133 pairs, silent 0 in every pair, none worse than `m3-int6`;
   `r5s`, `r5slock`, `r5dtlocksv` and `pmd` M500 gained identical functions. Superseded: "Not run: M500, the full
   pass". Merged to master with the reference-output cache of `decomp-diff.sh`.
   Own-facts gap 2026-11-18 (`ghidra-diff.sh`, 249c32cf94, default options, M500 identical of 499): Java facts
   461 (loud 22, silent 16); own facts with Java's function list 328 (loud 31, silent 140); own facts with plain
   discovery 177 (loud 122, silent 200). A first attempt was invalid (`ghidra-diff.sh` fell back to the Java facts;
   it now stops on a missing or empty `FACTS` file). Superseded: the own-facts M500 counts 171 and 173 of S10 slices
   2 and 3 above (eight actions skipped). See `rust/README.md`, "Integration `m3-int7`".
   Row 2 traced by swapping record kinds (`data` 43 functions, `extrapop` 23, stack variables 17, the
   `func` record otherwise 18, `override` 5, no single kind 27); fix 1 (INT_ZEXT/INT_SEXT size data, as
   `SymbolicPropogator`) gives 340 (loud 31, silent 128). Superseded: the 328 above. `extrapop` and stack
   variables need the order of Ghidra's analysis queue, not ported.
   Ghidra's task queue ported (`queue.rs`, branch `analysis-queue`, on the base merged with the
   Function Start Search bits fix: 343, loud 31, silent 125); X86 Function Callee Purge runs in it:
   347 (loud 31, silent 121), plain discovery 187 -> 189; Java-unknown purges derived here 2,182 ->
   1,743. Superseded: "not ported" above. Left: CreateFunctionCmd's thunks, the RTTI analyzer's
   priority, Shared Return and no-return per batch.
   Body changes notify the purge analyzer again (FUNCTION_BODY_CHANGED; an unknown purge is looked
   for again): 346 (loud 31, silent 122), Java-unknown derived here 1,769; the 26 new ones and
   0x5409f0 are thunks whose purge Java takes from the target. Superseded: 347 and 1,743 above.
   Java 12.2's own analysis and the facts disagree on 663 thunks (`rust/README.md`, "Body changes").
   The RTTI analyzer runs at 599, after the first purge turn: Java-known derived `unknown` 1,387 ->
   1,360, Java-unknown derived 1,769 -> 1,778 (9 adjustor stubs, a derived CALL_RETURN); M500 346.
   Superseded: "Left: ... the RTTI analyzer's priority" above.
   Bodies kept from creation and set only at Java's sites, and CreateFunctionCmd's thunks (a
   direct `JMP`): M500 347 (loud 31, silent 121), plain 189; plain discovery against Java 12.2
   28,751 / 1,897 / 316 (was 28,434 / 2,214 / 315), bodies differing 1,275 -> 824. Superseded:
   346 above. Left: Shared Return Calls and no-return per batch, the Stack analyzer per batch,
   getThunkedAddr's register tracking.
   Shared Return Calls per batch at 398 (a FUNCTION_ANALYZER, its targets made by
   CreateFunctionCmd): M500 381 (loud 30, silent 88), plain 208 (silent 163); plain purges
   differing from Java 12.2 on auto-analysis functions 1,806 -> 761. Superseded: 347 and 189
   above, and "Shared Return Calls ... per batch" in "Left".
   Plain discovery's 163 M500 silents traced (branch `gap-plain`, 2026-11-20): 85 are discovery's, and 63 of
   those come from mercs2's pipeline edits, not auto-analysis (Java 12.2's plain analysis agrees with
   ghidra-rs there). Jumps through SecuROM slots (`JMP [slot]`) are disassembled and made thunks, as
   ConstantPropagationAnalyzer and the Reference analyzer: plain 208 -> 226 (silent 163 -> 145); Java's
   list 381 (silent 88) and M8 unchanged. Superseded: plain 208 above. See `rust/README.md`,
   "Plain discovery's silents".
   No-return functions from call-site evidence (branch `gap-plain2`, 2026-11-20): FindNoReturnFunctionsAnalyzer
   ported in place of the body rule; 0x5dc8f0, newly silent with Java's list on `gap-plain`, fixed: Java's list
   382 (silent 87), plain 226 (silent 145) and M8 unchanged. See `rust/README.md`, "No-return functions
   from call-site evidence".
   The store row (branch `gap-plain2`, 2026-11-20): plain discovery with mercs2's edit scripts replayed
   on a fresh store (`edit`, then `analyze --store --facts`): M500 365 (loud 33, silent 101), M8 4 / 7.
   `Store::apply` now re-flows the bodies that jump or fall into a removed function, as the live edit
   does. See `rust/README.md`, "The store row".
   Slots read only by a computed jump or call get no pointer (OperandReferenceAnalyzer's INDIRECTION
   skip): Java's list 382 -> 395 (silent 87 -> 74), plain 226 -> 238 (145 -> 133), store 365 -> 377
   (101 -> 89), M8 unchanged, no new silent. Superseded: the 365 / 101 above. See `rust/README.md`,
   "Slots read only by a computed jump or call".
   Full pass 2026-11-19 (83ee6a86e6, the tree of 82b968548a, desktop and Mac): 133 / 133 pairs, silent 0 in every pair, none
   worse than `m3-int7` once 0x4c48d0 (a reference timeout at 120 s in `pmd`, `r5slock`,
   `r5dtlocksv` M500) is run with `TIMEOUT` 400. Superseded: "Not run: the full pass, the Mac" for
   this branch (`rust/README.md`).
   The 12.3 reference made (2026-11-20, `rust/target/ref123/`, `GHIDRA` names the install): Java
   12.2 and 12.3 print different C for 10 of 500 M500 functions, none of M8. Java-facts row M500:
   master 461 (loud 22, silent 16) -> 469 (loud 22, silent 8); `gap-javafacts2` 478 (11, 10) ->
   487 (11, 1, 0x5c64a0). Own facts (`gap-plain2`): Java's list 394 -> 400, plain 237 -> 240, store
   376 -> 382. Superseded: the 12.2 numbers above as the measure. See `rust/README.md`, "The 12.3
   reference".
   The Microsoft demangler on branch `demangler` (2026-11-20, user's decision): `mdmang.rs` ports
   `MDMang` and the name parts of `MicrosoftDemangler`; MDMangBaseTest's vectors 1,665 / 1,665 (Superseded: 1,664, the extraction mislabelled `testTripleQ0`) of
   the tests JUnit runs. Wired into Function ID (`NameVersions`, the demangled sets of
   `MatchNameAnalysis`), the Demangler analyzer's plate comment and the `--functions` names:
   own facts `comments` 1,151 -> 1,532 of 1,613 equal, `underived` 9,053 -> 8,609. Applying the
   demangled signatures and namespaces is not ported. See `rust/README.md`, "The Microsoft
   demangler".
   Integration `int8` (2026-11-20: `ref123`, `gap-javafacts2`, `gap-plain2`, `demangler`, `gdt`,
   `abi-ledger2` on master b6b02b2ca5), against the 12.3 reference, M500 identical of 499 (loud,
   silent): Java facts 488 (11, 0), Java's list 413 (18, 68), plain 246 (120, 133), store 391
   (21, 87); M8 7, 4, 2, 4 of 7. Every new silent was a loud on its branch (an error the
   decompiler fixes or the demangler's comment took away); 0x9eec5e in M8 is one. `gdt-protos`
   byte-identical to the 12.3 export, `--gdt` and `--protos` facts identical; the 57 M8 bars as
   `analysis-queue` on a new prelude (29,768 functions; `analysis-queue` 30,084). Superseded:
   the per-branch 12.3 numbers above as the current measure. See `rust/README.md`, "Integration
   `int8`".
   Review fixes on `int8` (2026-11-20): targetOnlyCallsNoReturn follows a computed jump's switch
   cases and computed target (Java skips only INDIRECTION); setNoFallThru and the body
   fixup act on the calls of the addresses found only, other thunks' earlier calls keep their
   fallthrough; removing a function re-flows no other body (a script's fixup is a `reflow`
   record); superseded: "`Store::apply` now re-flows the bodies that jump or fall into a removed
   function" above; a warning counts the calls whose flow Java's Repair Flow Damage would clear
   (mercs2 plain 308); the low findings (a CALL_RETURN call has no indicators, the slot thunk's
   memRefs bound, a warning for isThunk past the entry) leave the rows unchanged; rows unchanged. See `rust/README.md`,
   "Review fixes on `int8`".
   Full pass 2026-11-21 (c730b2db7d, the 12.3 `x86.sla`, 8 pairs on the desktop and Mac, 125 on the Mac only):
   133 / 133 pairs, silent 0 in every pair. Against `analysis-queue`: `r5s-m500` 499 -> 498 (the
   known reference timeout on 0x6b21e0; it does not finish in 1500 s), `pcd-m500` 493 -> 499 and
   `pmd-m500` 496 -> 499 (loud 0). The rest are equal apart from "all outputs identical" on 0x4c48d0.
   Superseded: "Not run: the full pass" for `int8`. See `rust/README.md`, "Full pass of `int8`".
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
   `rust/README.md`, "Project store and the editing scripts". Superseded in part (review of
   `m3-int6`, 2026-11-17): store version 2 replays its records in edit order, names its binary
   and seed set, and is applied after the constants pass; with those fixes
   `fold-slot-fragments` reports an owner its own walk removes as "refit failed Object has been
   deleted." and goes on, as Java 12.2 does (2026-11-18; before it stopped loudly at 0x861190), so the 36602 is the old build's count (now 36856 / 779 / 164).
   Superseded: "Not ported, failing by name: ExportBindings `--recover`, AuditRecoveredFunctions
   `--remove-empty`". On branch `worktree-agent-adca953958c1688b0` (2026-11-17) mercs2's eight
   remaining scripts are commands (`exports.rs`): the read-only ones under `ghidra-rs export`,
   the two editing options under `edit`. So each of the 17 scripts of
   `mercs2-decomp/tools/ghidra/` has a command; `Decompile.java` and the C that
   ExportAbiCandidates greps still wait for S10 (`abi-candidates` fails loudly without C verified
   identical to Java's). On the Java project's functions seven of the eight outputs have Java's
   rows but for body and reference differences of the analysis; where Ghidra's answer cannot be
   known (an instruction in two bodies here) a command stops. Details and counts in
   `rust/README.md`, "The read-only scripts". The four outputs that are byte-identical to
   Java (mod-hook-owners, boundaries, bindings, call-contexts of 0x00568900) have a drop-in
   wrapper for mercs2, `rust/tools/mercs2-exports.sh`. It needs the Java project's function
   list. `call-contexts` reference order (Java's creation order) stays a known difference.
   See `rust/README.md`, "Switching mercs2's export scripts".

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
  Superseded (2026-11-20, the user's decision "port the .gdt reader now"): the archive is read in
  place (`rust/ghidra-rs/src/gdt/`, `analyze --facts --gdt <archive>`, `ghidra-rs gdt-protos`);
  its prototype file is byte-identical to the 12.3 Java export, which stays only as the reference
  (`rust/README.md`, "The archive read in Rust").
  Superseded in part: "a rule ... ported with an approximation is written and measured instead" is
  decided (2026-11-17, see Decided): approximations give way to ports; the other choices stay open.
- 2026-11-17: Choices of S10 slice 3 made without the user, to confirm or change (`rust/README.md`,
  "Stage S10, slice 3"): `PseudoDisassembler.checkPseudoBody` is ported whole although, with the
  references of all discovered code at once, it loses 452 labels of SecuROM's code that Java has
  (Ghidra's order of analysis is not ported: its task queue would be the next port; superseded
  2026-11-18: the queue is ported, `queue.rs`, with discovery and the purge in it); `--facts`
  fails without Ghidra's strings model file; a Function ID comment with a mangled name stays
  `underived` until the demangler is ported. Superseded (2026-11-20): the demangler is ported
  (`mdmang.rs`); such a comment is written, and stays `underived` only where a name's
  conversion is not ported (`rust/README.md`, "The Microsoft demangler").
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
