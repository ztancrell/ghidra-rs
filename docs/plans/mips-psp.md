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

### MIPS-2: Allegrex instructions (not started)

The stock spec has no VFPU and none of Allegrex's extra integer opcodes. On SOCOM's `.text`
2,436 words do not decode, and more decode as an instruction Allegrex does not have (`daddiu`
784 words with `daddi`, `lwc2`/`swc2`/`ldc2`/`sdc2` 6,199; see the README's tables).

Open questions (the user's to decide):

- Where the Allegrex spec comes from: written here as `.sinc` additions to Ghidra's MIPS
  spec, or taken from an existing one (ghidra-allegrex has one; its licence and fit are not
  checked). Either way it is data read through `.sla`, per the 2026-11-13 decision.
- What the reference is, once the spec is not Ghidra's: the C++ engine still checks the
  engine against the same `.sla`, but nothing in this repo checks the spec itself (PPSSPP's
  disassembler could).

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
  more arguments in registers than o32 does; not verified here).
- Delay slots, `lui`/`addiu` pairs and `gp`-relative data in the decompiler's own passes
  (which C++ actions are MIPS-specific has not been inventoried).

### MIPS-5: PSP import stubs and names (not started)

The stubs in `.sceStub.text.*` are named by library in the section names; the functions are
identified by NID (`.rodata.sceNid`, `.lib.stub`).

Open questions:

- Where NID-to-name tables come from (none is in this repo or in Ghidra).
- Whether `sceModuleInfo`, `.lib.ent` and `.lib.stub` are parsed by the loader (MIPS-1 reads
  none of them: it needs only the segments and the relocation sections).
