# MIPS32 / PSP plan

Written 2026-11-26, with the user's decision of that day (`DESIGN.md`, Decided): ghidra-rs
takes MIPS32 little-endian for the PSP ("Allegrex"). First target: SOCOM U.S. Navy SEALs
Fireteam Bravo, multiplayer public beta (UCUS-98637), `PSP_GAME/SYSDIR/BOOT.BIN`, toward a PC
port. The file is not in this repo.

## The target, as read from the file (2026-11-26)

- ELF32 little-endian MIPS, type 0xffa0 (`ET_MIPS_PSP_PRX`), not encrypted, 4,708,752 bytes.
- Two `PT_LOAD` segments, linked at 0: code and read-only data at 0 (0x3a8920 bytes), data and
  `.bss` at 0x3a8920 (0x18e4 bytes in the file, 0x15dc0c in memory).
- `.text`: 0x3505c0 bytes at address 0 (868,720 words). Import stubs in 32
  `.sceStub.text.<library>` sections, `.lib.ent`, `.lib.stub`, `.rodata.sceModuleInfo` (module
  name `APP_APPLICATION_NAME`), `.rodata.sceNid`.
- Nine relocation sections, all of type 0x700000a0 (`SHT_MIPS_PSPREL`), 107,760 entries; no
  standard `SHT_REL`/`SHT_RELA` section. `.symtab` holds only the null symbol.

## Milestones

### MIPS-1: load, relocate, disassemble, p-code (done, branch `mips-m1`, 2026-11-26)

- `rust/build-sla.sh` also builds Ghidra's stock `mips32le.sla` (language `MIPS:LE:32:default`,
  processor spec `mips32.pspec`). The `.sla` reader took it unchanged.
- The SLEIGH engine got delay slots (`Sleigh::oneInstruction`, `SleighBuilder::delaySlot`).
- `rust/ghidra-rs/src/psp.rs` loads a PRX and applies the PSP relocations; `ghidra-rs disasm`
  takes a PRX and little-endian MIPS32 ELF files.
- Checked against the C++ engine (`rust/tools/sleigh_ref.cc`) on the whole relocated `.text`:
  identical, text and p-code. Numbers in `rust/README.md`, "MIPS32 and the PSP (MIPS-1)".

Choices made in MIPS-1 without the user (to confirm or change):

- Load base 0x08804000. Ghidra has no rule to port: it names the PRX type and the relocation
  section type but applies nothing (`MIPS_ElfExtension.java`: "relocations not supported") and
  would leave the image at its link address, 0. PPSSPP allocates the module in user memory
  (from 0x08800000) with no fixed default. 0x08804000 is what the ghidra-allegrex loader's
  README recommends "to match the usual address where games are loaded". It is a constant
  (`psp::DEFAULT_BASE`), not an option yet.
- The relocation rules follow PPSSPP's `ElfReader::LoadRelocations` (read 2026-11-26), since
  Ghidra has none. Only the types the file uses have a rule (`R_MIPS_32`, `R_MIPS_26`,
  `R_MIPS_HI16`, `R_MIPS_LO16`, and `R_MIPS_NONE`); any other type is counted and reported,
  not applied.
- A word that does not decode is skipped whole (4 bytes) on MIPS, in `ghidra-rs disasm` and in
  `sleigh_ref` alike; on x86 the sweep still moves one byte.

### MIPS-2: Allegrex instructions (done, branch `mips-m2`, 2026-11-26)

The user's decision (2026-11-26, `DESIGN.md`): the Allegrex instructions come from the SLEIGH
spec of ghidra-allegrex, used as data. The spec is not written here.

- Source: https://github.com/kotcrab/ghidra-allegrex, commit
  `4e46aa146a6e8fc3369cf4a7e4053f3ea5b05a1d` (2026-10-31, tag `v21.6`), `data/languages`.
- Licence: Apache License 2.0 (its `LICENSE`, read 2026-11-26; the same text as this repo's
  `LICENSE` apart from the brackets of the appendix's placeholder). No `NOTICE` file, no header
  lines in the spec files. Its README: "Derived from Ghidra MIPS module licensed under Apache
  License 2.0".
- Copied, unmodified, to `rust/processors/Allegrex/data/languages`: `allegrex.slaspec`, its six
  `.sinc` files and `allegrex.pspec`. The licence text is `rust/processors/Allegrex/LICENSE`;
  `rust/processors/Allegrex/NOTICE` names the source, the commit and what was left out.
- `rust/build-sla.sh` compiles `allegrex.sla` (68 KB) with Ghidra's SLEIGH compiler; the spec
  compiled as it is. `ghidra-rs disasm` takes it for a PSP PRX; any other little-endian MIPS
  file, or `--sla`, still gets the stock `mips32le.sla`.
- On SOCOM's `.text` every one of the 868,720 words decodes, text and p-code identical to the
  C++ engine on the same `.sla`. The 2,436 words the stock spec could not decode and the 7,047
  it decoded as `daddiu`, `lwc2` and the like are VFPU instructions, `clz`, `wsbw`, `max` and
  `min`. Numbers and the comparison with PPSSPP's tables are in `rust/README.md`, "Allegrex
  (MIPS-2)".

Superseded: "MIPS-2 (not started)" and its two open questions. Where the spec comes from is
decided (above). What checks the spec itself: PPSSPP's instruction tables were read as data
for one comparison (README); no check of the spec's p-code semantics exists.

Not copied, and not reproduced (ghidra-allegrex's Java, Kotlin and Python side):

- `AllegrexPcodeInjectLibrary` and its payloads: in Ghidra the decompiler replaces the spec's
  helper user ops (`vfpuReadP/T/Q`, `vfpuWriteP/T/Q`, `vfpuLoadQ`, `vfpuLoadQPart`,
  `vfpuSaveQPart`, the matrix reads and writes) with p-code that reads and writes the VFPU
  registers. Here they stay `CALLOTHER` ops, as the C++ engine prints them. MIPS-4 will need
  them, with `allegrex.cspec` (the PSP calling convention and the `<callotherfixup>` entries),
  which is not copied yet.
- `AllegrexEmulateInstructionStateModifier` (emulation), `AllegrexAddressAnalyzer` and
  `AllegrexPreAnalyzer` (analysis), `Allegrex_patterns.xml` (function start patterns).
- `PspElfLoader`, `Allegrex_ElfExtension` and the relocation classes (type A and B relocations,
  rebasing), `Allegrex.opinion`, `allegrex.ldefs`: ghidra-rs has its own loader (`psp.rs`,
  MIPS-1, type A only, rules from PPSSPP).
- The relocatable kernel object exporter and the PPSSPP `.sym` scripts.
- The spec's own stated limits (its README): `vpfxs`, `vpfxt` and `vpfxd` are not modelled in
  p-code, and the half-float operand of `vfim.s` prints as an integer.

### MIPS-3: function discovery on MIPS (not started)

`ghidra-rs analyze` is x86 only: recursive descent, switch tables, function bodies and
references all read x86 p-code patterns and a 32-bit PE or ELF x86-64 image.

Open questions:

- Port Ghidra's MIPS analyzers (`MipsAddressAnalyzer`, the `gp` and `lui`/`addiu` constant
  pairs, MIPS switch tables) as the x86 ones were, with Java Ghidra as the reference? Java
  cannot relocate a PRX, so the reference would need the image relocated first or loaded at 0.
- Whether the image type of `analyze` (`analysis::Image`, 32-bit addresses) takes a PRX as it
  is.

### MIPS-4: the decompiler on MIPS (not started)

Open questions:

- The calling convention: `mips32le.cspec` (o32) as it is, or a PSP one (the PSP ABI passes
  more arguments in registers than o32 does; not verified here). ghidra-allegrex has an
  `allegrex.cspec` (same source and licence as the spec of MIPS-2; not copied, not read here).
- Delay slots, `lui`/`addiu` pairs and `gp`-relative data in the decompiler's own passes
  (which C++ actions are MIPS-specific has not been inventoried).

### MIPS-5: PSP module info, import stubs and names (done, branch `mips-m5`, 2026-11-26)

- `psp::load` reads `sceModuleInfo`, the import stub table and the export table from the
  relocated image (`psp::parse_module`), by the pointers of `sceModuleInfo`; the section
  headers only cross-check. Layouts from PPSSPP's `Core/HLE/sceKernelModule.{h,cpp}` and
  PSPSDK's `pspmoduleinfo.h`, read as data.
- An import stub is named `<library>_0x<NID>`, or as PSPSDK names it: 3,159 library, NID, name
  lines extracted from PSPSDK's import files (BSD licence) are in `rust/psp-nids`, with the
  licence and a `NOTICE`.
- `ghidra-rs disasm` prints the names at the stubs and exported functions and after a `j` or
  `jal` to one. `analyze` does not use them yet (`psp::Module::names` is there for MIPS-3).
- On SOCOM's `BOOT.BIN`: module `APP_APPLICATION_NAME`, `gp` 0, 32 libraries, 247 imported
  functions (246 named, `sceMpeg_0x4571CC64` by NID only), no imported variables, 2 exported
  functions (both `module_start`, NID 0xD632ACDB) and 1 exported variable (`module_info`);
  539 `jal`s in `.text` go to 236 of the stubs. Details and the sources looked at are in
  `rust/README.md`, "PSP module info, imports and NID names (MIPS-5)".

Superseded: "MIPS-5 (not started)" and its two open questions. The NID table comes from PSPSDK
(above; PPSSPP's tables and the PSP library documentation projects are GPL and were not
copied). The loader parses `sceModuleInfo`, `.lib.ent` and `.lib.stub`.

Open questions:

- A second NID source for what PSPSDK lacks (1 of 247 here): uOFW is MIT but was not read for
  one; the GPL sources stay out unless the user decides otherwise.
- `gp` is 0 in this module's `sceModuleInfo`; whether the code sets `gp` itself matters to
  MIPS-3 and MIPS-4 and was not looked at.
