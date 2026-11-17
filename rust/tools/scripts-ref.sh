#!/bin/bash
# The Java side of the check of the `export` commands (README "The read-only scripts"): mercs2's
# eight remaining Ghidra scripts, run headless and -readOnly on a copy of the mercs2 project, in
# one run. Nothing is written to mercs2-decomp.
#
#   scripts-ref.sh          writes $GHIDRA_REF/scripts/java/* and leaves the project copy
#   scripts-ref.sh --c <file>  Java's C of the addresses in <file> (tools/ghidra/DecompileRef.java),
#                           one file each in $GHIDRA_REF/scripts/c: what `export abi-candidates`
#                           reads as verified C in scripts-diff.sh (CDIR)
#   scripts-ref.sh --clean  removes the project copy ($GHIDRA_REF/scripts/proj)
#
#   GHIDRA_REF  default rust/target/ghidra-ref; Ghidra refuses a path component starting with
#               '.', so in a worktree under .claude/ set it to a path without one
#   GHIDRA, PROJECT, MERCS  the Ghidra install, the project to copy, the mercs2-decomp checkout
#   FACTS       the project's facts (ghidra-facts.sh): the functions the audit can look at
set -e
rust=$(cd "$(dirname "$0")/.." && pwd)
ref=${GHIDRA_REF:-$rust/target/ghidra-ref}/scripts
case $ref in */.*) echo "GHIDRA_REF $ref: Ghidra refuses a path component starting with '.'" >&2; exit 1 ;; esac
if [ "$1" = --clean ]; then rm -rf "$ref/proj"; exit 0; fi
M=${MERCS:-$HOME/projects/mercs/mercs2-decomp}
facts=${FACTS:-$(dirname "$ref")/mercs2.facts}
j=$ref/java
mkdir -p "$j"
[ -d "$ref/proj" ] || cp -r "${PROJECT:-$M/build/ghidra}" "$ref/proj"
if [ "$1" = --c ]; then
    mkdir -p "$ref/c"
    # shellcheck disable=SC2046
    GHIDRA_HEADLESS_MAXMEM=${GHIDRA_HEADLESS_MAXMEM:-6G} "${GHIDRA:-/opt/ghidra}/support/analyzeHeadless" \
        "$ref/proj" mercs2 -readOnly -scriptPath "$rust/tools/ghidra" -process Mercenaries2.analysis.exe -noanalysis \
        -postScript DecompileRef.java "$ref/c" $(cat "$2") > "$ref/c.log" 2>&1
    exit 0
fi
# AuditRecoveredFunctions throws at a recovered entry that is no function any more (the fold
# removed some): only the rows whose function the project still has
awk -F'\t' '$1 == "func" { printf "0x%08x\n", strtonum("0x" $2) }' "$facts" > "$ref/functions.csv"
awk -F, 'NR == FNR { f[$1]; next } /,created$/ && ($2 in f)' "$ref/functions.csv" "$M/build/recovery-analysis.csv" > "$ref/recovery.csv"
slots=$(ls "$M"/build/slot-captures/*/slots.csv | tail -n 1)
sites=$(awk -F, 'NR > 1 { print $1 }' "$M/config/mod_hook_sites.csv")
# shellcheck disable=SC2086
GHIDRA_HEADLESS_MAXMEM=${GHIDRA_HEADLESS_MAXMEM:-6G} "${GHIDRA:-/opt/ghidra}/support/analyzeHeadless" \
    "$ref/proj" mercs2 -readOnly -scriptPath "$M/tools/ghidra" -process Mercenaries2.analysis.exe -noanalysis \
    -postScript ExportModHookOwners.java "$M/config/mod_hook_sites.csv" "$j/mod-hook-owners.csv" \
    -postScript ExportSlotOwners.java "$slots" "$j/slot-owners.csv" \
    -postScript InspectBoundaries.java "$j/boundaries.txt" $sites \
    -postScript ExportCallContexts.java 0x00401780 "$j/contexts-401780.txt" \
    -postScript ExportCallContexts.java 0x004017b0 "$j/contexts-4017b0.txt" \
    -postScript ExportCallContexts.java 0x00568900 "$j/contexts-568900.txt" \
    -postScript ExportCallContexts.java 0x00593c10 "$j/contexts-593c10.txt" \
    -postScript AuditRecoveredFunctions.java "$ref/recovery.csv" "$j/audit.csv" \
    -postScript ExportLibraryEvidence.java "$M/config/library_markers.csv" "$j/library-evidence.csv" \
    -postScript ExportBindings.java "$j/bindings.csv" \
    -postScript ExportAbiCandidates.java "$j/abi-candidates.csv" "$j/abi-candidates.txt" > "$ref/java.log" 2>&1
if grep -q 'SCRIPT ERROR\|error:' "$ref/java.log"; then
    echo "headless Ghidra failed: see $ref/java.log" >&2
    exit 1
fi
grep -o '[A-Za-z]*\.java> .*' "$ref/java.log" | sed 's/ (GhidraScript) *$//'
