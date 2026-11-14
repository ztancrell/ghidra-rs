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
   R5 (in part) on branch `m3-r5`: the five `typerecovery` pointer rules (`RulePtrArith` with
   `AddTreeState`, `RuleStructOffset0`, `RulePushPtr` in `oppool2`, `RulePtraddUndo`,
   `RulePtrsubUndo`) and the stop-propagation flags; R5 check M8 8 / 8, M500 497 / 498 without
   types, 487 / 498 with types (bar 95 %; 497 / 498 after the `opSetInput` fix); S6 check 498 / 500 with the rules on. Open: stack
   loads/stores, double.cc, constseq, bitfield, typed `cleanup` rules.
   S8 (structuring, in part) on branch `m3-s8`: `ActionBlockStructure` (`CollapseStructure`,
   `LoopBody`, `TraceDAG`; `structure.rs`, `collapse.rs`) and `print tree block`; `print tree
   block` plus `print raw` at `assignhigh` with `blockrecovery` on: M8 8 / 8, M500 499 / 499 the
   reference finishes (bar 98 %); with the rule-stage options M8 8 / 8, M500 496 / 499 before R2, 463 / 499 after R2 until `ConditionalJoin` was ported, 498 / 499 now (`ActionNodeJoin` ported, `nodejoin.rs`). Part two on `m3-s8b`: `prefercomplement`, `structuretransform` (for loops) and `returnsplit`
   ported; both S8 checks unchanged with them on (499 / 499, 498 / 499). Superseded: the earlier
   "Open: `prefercomplement`, `structuretransform`". Open: `finalstructure`, structured `printRaw`.
4. More processors (ARM/AArch64, MIPS, ...), batch mode, a persistent project DB.
   Will need the engine parts not ported yet: delay slots, `crossbuild`, `inst_next2` and
   flowref/flowdest.

## Open questions

- None right now.
