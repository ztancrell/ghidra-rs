# Milestone 2c: the mercs2 analysis pipeline in ghidra-rs

Written 2026-11-12 as a plan. Built so far: the reference run (`rust/tools/m2c-reference.sh`); no Rust code.

## Goal

`ghidra-rs analyze orig/Mercenaries2.analysis.exe --pipeline ...` builds mercs2's full function
list itself: no Java Ghidra, no `--functions-from`. The reference is Java Ghidra running
mercs2's `tools/ghidra/analysis_pipeline.sh` (auto-analysis, then six scripts, about 530 lines
of Java). Java stays the reference until each stage passes its bar; nothing in mercs2's
`tools/ghidra/` is removed before that (mercs2 `DESIGN.md`, 2026-11-12).

Today: with `--functions-from` (Java's list as input) 37,633 of 37,635 functions match. Plain
discovery against Java's import-only list: 22,388 common, 935 missing, 365 extra.

The target is the **final** list (after all six scripts), not the import-only list. The
import-only list contains damage the scripts later undo (a false no-return flag on 0x401740
hides 182,409 bytes behind 458 calls; jumps read as tail calls create about 2,200 fragment
functions). Some of ghidra-rs's 365 "extra" functions may be right against the final list.

## What the Java pipeline does

Source: `mercs2-rearmed/tools/ghidra/` (`F:n` below is file:line there). Read in full on
2026-11-12; nothing was run. Ghidra-internal behaviour marked *(to verify)* was described
from memory and must be read from the Java source in this repo before porting (list in
"Ghidra sources to read").

### Before the scripts

- The input image `orig/Mercenaries2.analysis.exe` is made by mercs2's `./tool resolve_slots
  ... --write-analysis`: the pinned exe with 1,593 SecuROM slot jumps `FF 25 <slot>` rewritten
  to `E9 rel32; 90`, PE checksum and `AddressOfEntryPoint` zeroed (so no entry-point seed).
  It needs a runtime capture and an emulator, not Ghidra.
- `run.sh --analysis import`: stock `analyzeHeadless -import -overwrite`, default analysis
  options, no pre-script. `.text` is 0x00401000, size 0x704000.
- Then one `-process ... -noanalysis` session runs the scripts below in order, followed by
  ExportFunctions and ExportGaps. Changes are saved to the project.

### 1. ExportBindings.java `--recover` (82 lines)

- **Input:** memory only (`.rdata`, then `.data`).
- **Scan:** from each 4-aligned address, read pairs (name pointer, function pointer), step 8.
  The function pointer must be in `.text` (checked first); the name pointer must point into
  an initialized non-executable block at a NUL-ended string of 1 to 255 bytes, all in
  32..=126. A maximal run of 4 or more pairs is a table; the scan resumes right after it.
  Needs 8 readable bytes (`start + 7 <= end`, block end inclusive).
- **Output:** `table,index,name,function,library` (library always empty), one row per pair.
- **Recovery (`:62-69`):** for each target, first time seen, with no function at it, create
  one if all hold in this order: no function contains it; no defined data contains it; it is
  not strictly inside an instruction; an instruction is there or `disassemble(target)`
  succeeds; `createFunction(target, null)` succeeds. Else count it unresolved.
- **Side effects:** `disassemble` (follows flow, including call targets *(to verify)*),
  `createFunction` (`CreateFunctionCmd`). No wrapper-stub exclusion here.
- **Known numbers (original image):** 54 tables, 1,339 rows, 501 created, 0 unresolved.

### 2. RecoverFunctions.java (107 lines)

- **Input:** memory and the listing.
- **Pass 0, pointer runs:** in `.rdata` then `.data`, maximal runs of consecutive 4-aligned
  dwords that point into `.text` (needs 4 readable bytes). A run of 4 or more with at least
  one member that is already a function entry makes every member a candidate. All candidates
  are collected first, then processed in ascending address order.
- **Passes 1-4, direct calls:** every non-computed call instruction in `.text`; each flow
  target in `.text` is a candidate (lowest call site is the evidence). Repeat until a pass
  creates nothing, at most 4 passes.
- **`recover(target)` (`:24-43`), first match wins:** `existing`; `inside_function`;
  `defined_data`; `inside_instruction`; `wrapper_entry` (bytes `FF 25` and the slot lies in
  the block named `.securom`); `disassembly_failed`; `no_entry_instruction`;
  `creation_failed`; `created`. Each address is tried once.
- **Output:** `pass,address,evidence,result` with evidence `pointer_run@0x...` or
  `direct_call@0x...`.
- **Side effects:** `disassemble`, `createFunction`. Never clears or removes.
- **Order dependence:** a candidate's result depends on the bodies given to lower candidates
  (`inside_function`). This is the main risk for exact parity.
- **Known numbers (original image):** 15,948 created (15,910 pointer runs, 38 direct calls),
  18,372 existing, 223 inside_function, 15 wrapper_entry, 3 defined_data, 1
  inside_instruction; 19 more functions appeared "during subsequent Ghidra processing".

### 3. AuditRecoveredFunctions.java `--remove-empty` (50 lines)

- **Input:** the recovery CSV (`,created` rows). Throws if a created function is gone.
- **Output:** `address,size,instructions,instruction_bytes,non_instruction_bytes,outside_text,
  wrapper_flows,status` (`retained` or `removed_empty`).
- **Side effect:** removes a function with 0 instructions and a 1-address body. Probably a
  no-op since RecoverFunctions gained `no_entry_instruction` (one case ever, 0x004c554a).

### 4. FoldSlotFragments.java (211 lines)

- **Why it exists:** Ghidra reads a jump to a non-adjacent target as a tail call: it sets a
  `CALL_RETURN` flow override, creates a function at the target, and turns a lone-jump owner
  into a thunk. After the slot rewrite that splits real functions into fragments.
- **Inputs:** `build/functions-original.csv` (column 0, the `original` entry set) and
  `build/slot-rewrites.csv` (`site,exit`). See "Inputs and circular dependencies".
- **Rounds (at most 8, stop when no body changed):**
  - *Sites, file order:* clear a `CALL_RETURN` override at the site; `owner` = function
    containing the site; skip if none or if `exit` is an original entry; un-thunk the owner;
    `walk(exit, owner)` and add the result to the owner's flow.
  - *`walk`* (FIFO, 20,000 steps): skip visited; skip original entries other than the start;
    skip addresses with no instruction (it does not disassemble); `fold(at)`; skip if another
    function contains it; add the instruction; clear its override; follow jump targets not in
    `original` (log `tail to original` otherwise); for a computed jump with no flows, use
    `switchTargets`; follow fall-through (also after calls; calls are not entered).
  - *`fold(entry)`:* nothing if no function there or it is original. If any reference to it
    is not a jump, log `kept <type> from <addr>` and keep it. Otherwise un-thunk and mark the
    functions containing the jump sources as owners, remove the function, log `removed`.
  - *`switchTargets`:* `JMP [reg*4 + table]`, a `CMP reg, bound` within the 3 instructions
    before it in address order, bound 0..=1024, all `bound+1` entries in `.text` or none;
    adds references and disassembles the targets.
  - *Owners, ascending:* re-walk from the owner's entry; `setBody(old ∪ flow)` if it has
    flow, else `CreateFunctionCmd.fixupFunctionBody`; log `refit B->A round R`.
- **Output:** `entry,action` (`removed`, `kept ...`, `tail to original ...`, `switch N
  targets`, `refit ...`, `refit failed ...`).
- **Side effects:** remove functions, set bodies (only ever grow), clear overrides and
  thunks, add references, disassemble.
- **Known numbers:** 2,204 removed, 1,438 owners refit, 106 kept.

### 5. AddRelocatedEntries.java (22 lines)

- **Input:** `config/securom_functions.csv`, column `site` (330 rows).
- **Per site:** skip if a function contains it; if no instruction starts there, clear 6 bytes
  and disassemble; create a function. Expected: a 6-byte function at each `FF 25` stub.
- **Known number:** 37 sites had no function before.

### 6. ClearFalseNoReturn.java (138 lines)

- **Input:** the no-return flags left by Ghidra's analyzers.
- **Fixpoint over all functions, ascending:** a flagged, non-external, non-thunk function
  whose entry `reachesRet` gets the flag cleared.
- **`reachesRet`:** from the entry over fall-through and jumps (20,000 cap), disassembling
  where needed; a `CALL` ends the path; mnemonic `RET` means true.
- **On clearing:** for each `CALL` reference to the entry, clear the call's overrides and
  `decodeThrough` its return address (follow fall-through and jumps, continue past calls);
  then `fixupFunctionBody` on each calling function. Creates no functions.
- **`clearFor`** (when decoding is blocked): pseudo-disassemble; the blocking code units are
  removed unless one is an instruction inside a function it does not start, or is the target
  of a flow from `.text`. A function starting exactly at a removed unit is removed.
- **Output:** `address,name,action,detail` with `cleared`, `cleared_in_flow`, `decode_failed`
  and one `kept` row per function still flagged (CRT exits, `_CxxThrowException`,
  `___report_gsfailure`, `luaD_throw` 0x00868230, 0x0086be30, the wrapper's own).
- **Addresses** are 8 hex digits without `0x`.

### After the scripts

ExportFunctions writes `build/functions-analysis-folded.csv` (only `address` and `size` matter
for this milestone); ExportGaps writes `build/gaps-analysis-folded.csv`. `DefineTableFunctions`
is not part of the pipeline.

## Inputs and circular dependencies

| Input | Used by | From Ghidra? | Plan |
|---|---|---|---|
| `build/functions-original.csv` | FoldSlotFragments | **Yes**: ExportFunctions of the *original* image after import, bindings, recovery and audit (37,345 functions) | Circular. Until S3 passes, read Java's file. Then ghidra-rs makes its own by running stages S1-S2 on `orig/Mercenaries2.exe` (S6). |
| `build/slot-rewrites.csv` | FoldSlotFragments | No. No tool in mercs2 writes it today (gitignored, producer lost) | Derive from the two exes: every site where the original has `FF 25` and the analysis image has `E9 rel32 90`; `exit = site + 5 + rel32`. This is the user's piece (below). Check: equals the 1,593 `resolved_jump`/`direct_text` rows of `config/slot_resolution.csv`. |
| `config/securom_functions.csv` | AddRelocatedEntries | No: runtime captures plus hand-kept columns | Read as is. |
| `orig/Mercenaries2.analysis.exe` | everything | No: `./tool resolve_slots --write-analysis` | Read as is. |
| No-return flags, thunks, `CALL_RETURN` overrides | scripts 4 and 6 | Yes: auto-analysis state | Not imported. See decision 2. |

## Where it fits in ghidra-rs, and what is missing

Today (`rust/ghidra-rs/src/analysis.rs`, 1,237 lines): `Analysis::run` (:275) is the only
discovery entry. State is `insns: BTreeMap<u32, Ins>`, `funcs: BTreeSet<u32>`, `bodies`
(may overlap), `noreturn`, `tables`, `table_slots`. There is no per-function record, no
reverse reference index, no defined-data model and no editing API. `analyze` in `main.rs`
runs `run` at :264; the pipeline goes between :264 and :265.

New file `rust/ghidra-rs/src/pipeline.rs`: the six passes and their CSV writers. Changes in
`analysis.rs`:

| Needed by the scripts | Today | To add |
|---|---|---|
| `getFunctionContaining` | Three different tie-breaks (`scripts.rs:147`, `abi.rs:502`, `fid.rs:429`) over overlapping bodies | One `Analysis::function_containing(addr)`, used by all three. Ghidra's bodies are disjoint; decision 3. |
| `createFunction` | Insert into `funcs`; `compute_bodies` (:1005, private) recomputes every function | `create_function(addr)` with CreateFunctionCmd's body rule, per-function body compute, refresh of `purge` |
| `removeFunction` | `funcs.remove` only | `remove_function(addr)` that also drops `bodies`, `noreturn`, `purge` and recomputes neighbours |
| `disassemble(addr)` after the main pass | `disassemble` (:654) restores `funcs`, leaves bodies stale, rebuilds `owner` and loses switch marks | Keep the `owner` map in `Analysis`; a `disassemble_at` that keeps what it finds |
| `getInstructionContaining`, `getDataContaining` | Only via the local `owner` map; data = `table_slots`, switch tables, import/export tables | Stored `owner` map; "defined data" = those tables (measure `defined_data` rows in S2: 3 on the original image) |
| `getReferencesTo(entry)` with jump/call/data type | No reverse index | `refs_to: HashMap<u32, Vec<(u32, Kind)>>` built once from `insns` and data pointers, updated on disassembly |
| `clearListing(range)` | Instructions cannot be removed | `clear(range)` (AddRelocatedEntries, `clearFor`) |
| No-return flags that can be cleared and stay cleared | Recomputed inline in `run` (:378-402) | Move the rounds into a function; a `noreturn_cleared` set they respect |
| Flow overrides, thunks | None. "Tail call" = jump target is in `funcs` (`shared_returns` :971) | Nothing new if decision 2 holds |

The decompiler (milestone 3, `decomp/`) uses only `Image` and `Section` and gets its function
list as text, so none of this touches it. `abi.rs` and `fid.rs` read `funcs`, `bodies`,
`insns` and `noreturn` and must keep working: their tests run in every stage.

## The discovery gap: likely causes

No document or measurement breaks the 935 / 365 down by cause. The ranking below is from
reading the code; S0's evidence export replaces it with counts before any of it is built.

**Missing (935)**

1. Functions Ghidra creates from code pointers, operand references and address tables
   (the only documented cause, `rust/README.md:223-225`). The filters Ghidra applies exist
   now (`valid_subroutine`, `address_tables`) but create no functions. RecoverFunctions'
   pass 0 (15,910 created) will absorb an unknown share of these.
2. Exception-handling data (unwind funclets, catch handlers): nothing ported.
3. Computed-call targets from constant propagation: `propagate` runs after the set is final.
4. Function Start Search: only the two definite pattern pairs are ported; `possiblefuncstart`,
   the labelled CRT patterns and the match-on-existing-instruction rule are not.
5. Switch shapes the byte-pattern recovery misses.
6. Overlapping decodes, first decode wins (two known cases).
7. Fuller shared-return rules.

**Extra (365)**

1. No-return timing: ghidra-rs decodes past calls to no-return local functions and keeps the
   call targets found there; Ghidra stops there. Against the final list (after
   ClearFalseNoReturn) part of this is correct.
2. Pointer runs of 2 or more are disassembled in `run`; Ghidra's threshold computes to 5.
3. Switch tables without a `CMP` bound run up to 1,024 entries.
4. Simplified shared-return rule.
5. Call targets found in decoded wrapper-section code.
6. Pattern hits are descended at once with no validity check.

## Reference data (run 2026-11-12)

Made on the desktop with `rust/tools/m2c-reference.sh` (Ghidra 12.2, mercs2 395ba6b), in its
own project `build/ghidra-m2c`, and copied to the Mac's `mercs2-rearmed/build/m2c-ref/`
(27 MB, gitignored; never enters either repo). It is the pipeline with an ExportFunctions and
ExportGaps snapshot after every script, for both images. The script in the repo is the two
runs below merged into one file; in that merged form it has not been run.

| Snapshot | After | Functions | Script's own summary |
|---|---|---|---|
| `a0-import` | import (12 min) | 23,289 | |
| `a1-bindings` | ExportBindings `--recover` | 23,790 | 54 tables, 1,339 rows, 501 created, 0 unresolved |
| `a2-recover` | RecoverFunctions, audit | 39,748 | 15,938 created, 36,270 candidates, 2 direct-call passes |
| `a3-fold` | FoldSlotFragments (patched) | 37,583 | 2,183 removed, 1,438 owners refit, 106 kept, 1 refit failed |
| `a4-relocated` | AddRelocatedEntries | 37,620 | 37 added |
| `a5-final` | ClearFalseNoReturn | 37,619 | 1 cleared, 458 call sites, 182,403 bytes added, 25 kept, 79 cleared_in_flow; 39,557 gap rows |
| `o0-import` | import of the original image | 20,866 | |
| `o1-bindings` | ExportBindings `--recover` | 21,367 | 501 created |
| `o2-recover` | RecoverFunctions, audit | 37,331 | 15,948 created |

Findings from the run:

- **mercs2's FoldSlotFragments.java crashes on today's state.** First run: a
  `ConcurrentModificationException` at `FoldSlotFragments.java:179` in round 1. The owners
  loop re-walks each owner; at 0x00861190 the walk folded the owner itself (`removed`, then
  `refit failed Object has been deleted`) and `fold` added owners to the set being iterated.
  Ghidra went on to the next scripts, so the crashed run still produced exports (kept in
  `build/m2c-ref/crashed/`, not a reference). The second run used a patched copy of the
  script (a worklist loop, `build/m2c-ref/fold.patch`; identical when nothing is added) and
  completed in two rounds. mercs2's tracked script is unchanged; fixed there since (decision 11).
- **The reference moved since October.** The desktop's October log shows the unpatched script
  completing with 2,204 removed; now 2,183. Import counts moved too (original image 20,866
  against the documented 20,878; analysis image 23,289 against the README's 23,323), and the
  final list is 37,619 against the README's 37,635. Cause not established (Ghidra version is
  the first suspect). `build/functions-original.csv` (37,345, from October) is therefore
  older than this run's own `o2-recover` (37,331); the fold above read the October file.
- Auto-analysis logs two `ERROR` lines per import (a failed function creation at 0x00492370,
  an RTTI locator without a vtable at 0x00bf0014). They are Ghidra's own and part of the
  reference.
- The project state just before the fold is kept on the desktop (`build/ghidra-m2c-a2`), so
  scripts 4-6 can be re-run without the import.

On the Mac since 2026-11-12: both exes (`mercs2-rearmed/orig/`, sha1 of `Mercenaries2.exe`
matches `config/sha1.txt`), `build/functions-original.csv`, `build/slot-rewrites.csv` (1,593
rows), the reference folder, and Ghidra 12.2 with Java 25 (`~/ghidra`, `~/jdk`; natives built
locally), so reference runs can also be made here. Still missing: a built `.sla`
(`rust/build-sla.sh` calls `nproc`, which macOS lacks; S0 fixes that).

S0 adds the evidence export: a small read-only Java script,
`rust/tools/ExportFunctionEvidence.java`, writing per function of `a0-import` and `a5-final`:
thunk flag, no-return flag, counts of call / jump / data references to the entry, and the
analysis bookmarks at the entry (which analyzer created it). That turns the ranked guesses
above into counts.

## Stages

"Identical" for a function list means the same set of entry addresses; sizes are reported
separately. Every stage is measured two ways:

- **Isolated:** start from Java's snapshot before the stage (`--functions-from
  <previous>-functions.csv`), run only that pass, compare with Java's snapshot after it and
  with the script's own report CSV. Shows the pass is ported right.
- **Chained:** start from ghidra-rs's own state after the earlier stages, compare with the
  same Java snapshot. Shows where the whole thing stands.

Isolation is approximate: `--functions-from` carries entries, not Ghidra's instructions,
thunks or flags.

| Stage | Ports | Check (isolated) | Pass bar | Needs |
|---|---|---|---|---|
| S0 | Harness: `rust/tools/m2c-compare.sh` (common / missing / extra, size rate, gaps rows identical, report-CSV row diff), the evidence script, `build-sla.sh` on macOS, the `--pipeline` flag skeleton | Today's numbers re-measured on the Mac against the new reference: `--functions-from a5-final` (was 37,633 / 37,635), plain discovery against `a0-import` (was 22,388 / 935 / 365) | New numbers recorded in `rust/README.md`; any drop from the old ones explained | Done: reference data |
| S1 | ExportBindings: table scan, then `--recover`. Mutation API part 1: `function_containing`, stored `owner` map, `create_function`, `disassemble_at` | `a1-bindings.csv` byte-identical; created set vs `a1 − a0` | CSV identical; created set identical | S0 |
| S2 | RecoverFunctions and the audit: pointer runs, direct-call passes, the nine results | `a2-recovery.csv` rows (address, result); function set vs `a2-recover` | Rows 99% identical; set 99.5% common, each remaining row with a named cause | S1 |
| S3 | FoldSlotFragments: `refs_to` index, `remove_function`, the walk, kept / removed rules | `removed` and `kept` sets of `a3-fold.csv`; function set vs `a3-fold`; sizes of refit owners | Removed and kept sets 98%; set 99.5% common; refit-owner sizes 95% | S2, the user's piece |
| S4 | AddRelocatedEntries (`clear`) and ClearFalseNoReturn (`reachesRet`, clearable flags, re-flow) | Set vs `a4-relocated`, then `cleared` and `kept` rows of `a5-noreturn.csv`, set and gaps vs `a5-final` | Relocated: set identical. No-return: `cleared` and `kept` sets identical; gaps rows 99% | S3 |
| S5 | The discovery gap: chained run, no `--functions-from`, against `a5-final`. Work the causes in the order the evidence export gives | Chained set vs `a5-final`; `--gaps` rows; `--abi-callers` rate does not drop | Missing + extra ≤ 0.5% of 37,619 (≤ 188), each one classified; sizes 97% | S4, evidence export |
| S6 | Remove the circular input: run S1-S2 on `orig/Mercenaries2.exe`, use the result as `functions-original` | Own list vs `o2-recover`; S5's numbers with the own list | S5's bar still holds | S5 |

Each stage: one branch (`m2c-s0` ...), merged into `m2c-pipeline` when its bar is met, docs
(`rust/README.md`, `DESIGN.md`, this file's "Sx: done" section) in the same commit, pushed
after the merge. Narrow test runs while building; the full suite once before a merge.

Order under the two-agent cap: S0 alone. Then S1 → S2 → S3 → S4 in sequence (each needs the
mutation API of the one before). A second agent can run alongside from S1 on: first the
evidence classification of the gap (read-only), then S5's causes that do not touch the
mutation API (start patterns, exception data, address-table threshold).

### The user's piece (S3 input): slot rewrites from the two images

In `rust/ghidra-rs/src/pipeline.rs`, about 30 lines plus a test in
`rust/ghidra-rs/tests/pipeline.rs`:

```rust
/// Sites where `orig` has `FF 25 <slot>` and `patched` has `E9 rel32 90`: (site, exit),
/// in address order. Both slices are the same section's bytes; `base` is its address.
pub fn slot_rewrites(orig: &[u8], patched: &[u8], base: u32) -> Vec<(u32, u32)>
```

The test to make pass:

```rust
#[test]
fn slot_rewrites_finds_rewritten_jumps_only() {
    let mut orig = vec![0x90u8; 32];
    let mut patched = orig.clone();
    // site at offset 2: jmp [0x00d01000] became jmp +0x100; nop
    orig[2..8].copy_from_slice(&[0xFF, 0x25, 0x00, 0x10, 0xD0, 0x00]);
    patched[2..8].copy_from_slice(&[0xE9, 0x00, 0x01, 0x00, 0x00, 0x90]);
    // site at offset 12: a slot jump left alone in both images
    orig[12..18].copy_from_slice(&[0xFF, 0x25, 0x04, 0x10, 0xD0, 0x00]);
    patched[12..18].copy_from_slice(&[0xFF, 0x25, 0x04, 0x10, 0xD0, 0x00]);
    // site at offset 20: rewritten to a backward jump (rel32 = -0x20)
    orig[20..26].copy_from_slice(&[0xFF, 0x25, 0x08, 0x10, 0xD0, 0x00]);
    patched[20..26].copy_from_slice(&[0xE9, 0xE0, 0xFF, 0xFF, 0xFF, 0x90]);
    assert_eq!(
        slot_rewrites(&orig, &patched, 0x0040_1000),
        vec![(0x0040_1002, 0x0040_1107), (0x0040_1014, 0x0040_0FF9)]
    );
    // a site cut off by the end of the section is not reported, and nothing panics
    assert_eq!(slot_rewrites(&orig[..5], &patched[..5], 0x0040_1000), vec![]);
}
```

Things to work out while writing it: why the exit is `site + 5 + rel32` and not `+ 6`; what
type the `rel32` has to be read as for the backward jump to come out right; how to walk two
slices in step without indexing past the end. The real check comes after: on the two exes
the result must be the 1,593 `resolved_jump` / `direct_text` rows (`site`, `exit`) of
mercs2's `config/slot_resolution.csv`. Claude reviews it; an agent wires it to the CLI.

## Ghidra sources to read (in this repo) before porting

| For | File |
|---|---|
| Function bodies, thunk-on-lone-jump, overlap handling, `fixupFunctionBody` | `Ghidra/Features/Base/src/main/java/ghidra/app/cmd/function/CreateFunctionCmd.java` |
| What `disassemble` follows and where it stops | `.../app/cmd/disassemble/DisassembleCommand.java` |
| Jump-as-tail-call, `CALL_RETURN` | `.../app/cmd/analysis/SharedReturnAnalysisCmd.java` |
| No-return: known and discovered | `.../plugin/core/analysis/NoReturnFunctionAnalyzer.java`, `FindNoReturnFunctionsAnalyzer.java`, `.../plugin/core/clear/ClearFlowAndRepairCmd.java` |
| Functions from operand references and address tables | `.../plugin/core/analysis/OperandReferenceAnalyzer.java`, `.../plugin/core/disassembler/AddressTable.java` |
| Function Start Search | `Ghidra/Features/BytePatterns/.../FunctionStartAnalyzer.java`, `Ghidra/Processors/x86/data/patterns/x86win_patterns.xml` |
| Exception data | `Ghidra/Features/MicrosoftCodeAnalyzer/.../EHDataTypeUtilities.java` |
| Whether analysis reacts to script changes under `-noanalysis` | `GhidraScript.java`, the headless analyzer |

## Where to diverge from Ghidra, and where not

Keep exactly: the function entry set, body sizes, the gaps file, the report CSVs of scripts
1, 2 and 4-6 (same rows, same result words), so mercs2's tools read them unchanged.

Diverge where it costs nothing: iteration orders Java leaves unspecified (`HashSet` of
callers in ClearFalseNoReturn); the round-by-round `refit` log lines of the fold (the final
bodies are compared, not the log); the 19 functions the original image gained "during
subsequent Ghidra processing" until their cause is known.

## Decisions (2026-11-12)

1. **User's decision:** first milestone is this pipeline port; Java Ghidra scripts are
   replaced by ghidra-rs as each reaches parity and Java stays the reference until then
   (recorded in mercs2's `DESIGN.md`).
2. **Claude's call, to confirm:** do not reproduce Ghidra's mistakes in order to undo them.
   ghidra-rs has no `CALL_RETURN` overrides, thunks or false no-return on 0x401740. S3 and S4
   port each script's *outcome rules* (which functions are removed, kept, cleared; which
   bodies grow) onto ghidra-rs's own state, and are judged on Java's after-snapshots and
   report rows. The alternative (port the tail-call and no-return analyzers faithfully, then
   the corrections) costs far more and its only gain is matching intermediate states nobody
   uses. If S3's bar cannot be met this way, the analyzers are ported then.
3. **Claude's call, to confirm:** `function_containing` gets Ghidra's meaning (bodies behave
   as disjoint: an address belongs to one function) through one shared rule, chosen in S1
   after reading `CreateFunctionCmd`; `bodies` itself may keep overlapping until a stage
   needs otherwise.
4. **Claude's call:** the target is the final list (`a5-final`); the import-only numbers
   (935 / 365) are tracked but have no bar.
5. **Claude's call:** the passes are generic code with mercs2's inputs as arguments, behind
   one `--pipeline` option; no mercs2 address is hard-coded. Section names (`.text`,
   `.rdata`, `.data`, `.securom`) stay as in the scripts.

Answered by the user on 2026-11-12 (questions A-H of the first draft):

6. **User's decision (A):** outcome rules first, as in decision 2; the faithful analyzers
   only if S3's bar cannot be met.
7. **User's decision (B):** the pass bars in the stage table stand; the end bar is missing +
   extra ≤ 188 of 37,619, each one classified.
8. **User's decision (C):** the report CSVs stay readable by mercs2's tools unchanged.
9. **D, answered by the run:** the desktop and the Mac run Ghidra 12.2; this repo's source
   tree is 12.3. Stage agents check `git log` of each Java file they port for changes
   between the two.
10. **User's decision (F):** after S6, mercs2's `analysis_pipeline.sh` calls ghidra-rs, with
    the Java scripts kept one more cycle as a cross-check.
11. **User's decision (G):** the worklist fix went into mercs2's own
    `FoldSlotFragments.java` (mercs2 fe682dc). Checked: run from the saved pre-fold state,
    the fixed script's `a3-fold.csv`, function list and gaps file are byte-identical to the
    reference. `rust/tools/m2c-reference.sh` still patches a pre-fix checkout; on a fixed
    one its `sed` matches nothing and `fold.patch` comes out empty.
12. **User's decision (H, E):** the fold keeps reading October's
    `build/functions-original.csv` (37,345 functions), as mercs2 does, not today's
    `o2-recover` (37,331). S6's own list is compared with `o2-recover`, and S6 also reports
    how the final list changes when the fold reads the own list instead of October's.

Open questions: none.
