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
- 2026-11-11 (Claude's call, not yet confirmed): the decompiler (milestone 3) is written in
  Rust, and Ghidra's C++ decompiler is the reference its output is checked against, as
  `rust/tools/sleigh_ref.cc` was for SLEIGH. No FFI stopgap.

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
   pointer callees and non-returning import thunks. Not done yet: Function ID, constant
   propagation.
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
   0x675611) are found.
3. Decompilation: a Rust decompiler, or FFI to the existing C++ decompiler as a stopgap.
4. More processors (ARM/AArch64, MIPS, ...), batch mode, a persistent project DB.
   Will need the engine parts not ported yet: delay slots, `crossbuild`, `inst_next2` and
   flowref/flowdest.

## Open questions

- Should Ghidra's GUI ever be able to use this core (e.g. via a server), or does it stay CLI-only?
- Project DB format: does it need to read or write Ghidra `.gpr` projects?
