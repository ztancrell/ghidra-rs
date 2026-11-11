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
   reference rows identical, about 48 s (details and the causes of the rest in `rust/README.md`).
3. Decompilation: a Rust decompiler, or FFI to the existing C++ decompiler as a stopgap.
4. More processors (ARM/AArch64, MIPS, ...), batch mode, a persistent project DB.
   Will need the engine parts not ported yet: delay slots, `crossbuild`, `inst_next2` and
   flowref/flowdest.

## Open questions

- Decompiler: rewrite it in Rust, or use FFI to the C++ one first?
- Should Ghidra's GUI ever be able to use this core (e.g. via a server), or does it stay CLI-only?
- Project DB format: does it need to read or write Ghidra `.gpr` projects?
