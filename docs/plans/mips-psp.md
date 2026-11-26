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
  Superseded (2026-11-26, MIPS-3): `Allegrex_patterns.xml` is copied, unmodified, as data.
- `PspElfLoader`, `Allegrex_ElfExtension` and the relocation classes (type A and B relocations,
  rebasing), `Allegrex.opinion`, `allegrex.ldefs`: ghidra-rs has its own loader (`psp.rs`,
  MIPS-1, type A only, rules from PPSSPP).
- The relocatable kernel object exporter and the PPSSPP `.sym` scripts.
- The spec's own stated limits (its README): `vpfxs`, `vpfxt` and `vpfxd` are not modelled in
  p-code, and the half-float operand of `vfim.s` prints as an integer.

### MIPS-3: function discovery on MIPS (done but for the switch tables, branch `mips-m3`, 2026-11-26)

`ghidra-rs analyze` takes a PSP PRX and writes the files it writes for x86 (`--functions`,
`--gaps`, `--purges`). What was ported and how is in `rust/README.md`, "Function discovery on
MIPS (MIPS-3)".

- On SOCOM's `BOOT.BIN`, against Java Ghidra 12.2 with ghidra-allegrex v21.6 on the same
  relocated image: 11,399 functions on each side, 11,398 the same entries (one only in Java,
  one only in ghidra-rs: two flows into one `jalr`), 11,384 with the same body, thunk and
  no-return flag, 14 with another body.
- Partial: the switch tables. Java recovers them with the decompiler; ghidra-rs has a pattern
  over the instruction words until the decompiler runs on MIPS (MIPS-4). All 14 body
  differences hold a `jr` through a table: 4 the pattern does not resolve, 4 it resolves and
  Java does not, 6 where the targets differ.
- The reference: `rust/tools/mips-ref.sh` (`ghidra-rs prx-elf` writes the relocated image as
  an ELF; the extension goes into a throwaway settings directory).
- `Allegrex_patterns.xml` (function start patterns) is copied from ghidra-allegrex as data,
  like the spec (`rust/processors/Allegrex/NOTICE`).

Superseded: "MIPS-3 (not started)" and its two open questions. Answered (2026-11-26, Claude's
call; the user approved doing MIPS-3): Ghidra's MIPS analysis is ported as the x86 analyzers
were, with Java as the reference on the image ghidra-rs relocated; and `analysis::Image` takes
a PRX with one new flag (`mips`) and a constructor (`Image::from_prx`), nothing else changed.

Waits for MIPS-5: entry points beyond the ELF entry (`module_start` and the exports of
`.lib.ent`), the module's `gp` value (`sceModuleInfo`), the names of the import stubs. The
stubs in `.sceStub.text.*` are analyzed as ordinary code.

Not done: the `gp` and `t9` assumptions of the address analyzer, a comparison of instruction
sets and references with Java (functions and bodies only), any PRX but this one.

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
  functions (247 named: 246 by PSPSDK, `sceMpegAvcDecodeFlush` by SHA-1 search, below), no
  imported variables, 2 exported
  functions (both `module_start`, NID 0xD632ACDB) and 1 exported variable (`module_info`);
  539 `jal`s in `.text` go to 236 of the stubs. Details and the sources looked at are in
  `rust/README.md`, "PSP module info, imports and NID names (MIPS-5)".

Superseded: "MIPS-5 (not started)" and its two open questions. The NID table comes from PSPSDK
(above; PPSSPP's tables and the PSP library documentation projects are GPL and were not
copied). The loader parses `sceModuleInfo`, `.lib.ent` and `.lib.stub`.

Open questions:

- A second NID source for what PSPSDK lacks (1 of 247 here): uOFW (MIT) has no name for it
  (below); the GPL sources stay out unless the user decides otherwise. Superseded for SOCOM
  (branch `mips-m5-hash`): the one NID is named by SHA-1 search (below); other modules may
  still need a source.

uOFW read for `sceMpeg` 0x4571CC64 (2026-11-26, branch `mips-m5-uofw`): no name, so no code
changed. At uofw/uofw `f7b0623168` (master; licence MIT, `COPYING`, with PSPSDK parts under
BSD per its README) the NID is in no file, and no file has a library `sceMpeg`: its 48
`exports.exp` files (166 libraries, 2,866 exported functions) cover the kernel modules it
reimplements, and the nearest, `src/kd/avcodec/exports.exp`, exports `sceMpegbase` and
`sceMpegbase_driver` only; `include/video/lib_mpeg.h` has error codes, no NIDs. Its other
branches (`kirk` bd83a599a4, `power` 675fe009dc, `gh-pages` 86e4f5a415) have neither the NID
nor `sceMpeg`. SOCOM's `BOOT.BIN` stays at 246 of 247 named.
Superseded (branch `mips-m5-hash`): 247 of 247 named. A NID is the first four bytes of its
name's SHA-1, little-endian; on 2026-11-26 a search of 39,449,440 names of the form `sceMpeg`
+ 1 to 4 parts from a fixed word list found one match for 0x4571CC64, `sceMpegAvcDecodeFlush`
(chance matches expected: 39,449,440 / 2^32, about 0.009). It is computed, not copied, and sits
in `SEARCHED_NIDS` in `psp.rs`, looked up after PSPSDK's table; the test `psp_module_tables`
checks the lookup. `disasm` prints "247 named by NID table, 0 by NID only"; the one `jal` to
the stub (0x08936044) names it. Superseded with it: "246 named, `sceMpeg_0x4571CC64` by NID
only" (the summary above, as merged from `mips-m5`).
Superseded: "uOFW is MIT but was not read for one" (the open question above, as written on
`mips-m5`).
- `gp` is 0 in this module's `sceModuleInfo`; whether the code sets `gp` itself matters to
  MIPS-3 and MIPS-4 and was not looked at.
