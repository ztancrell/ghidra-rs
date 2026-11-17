#!/bin/bash
# The facts of the mercs2 Ghidra project for `load facts` (stage S10): one headless run of
# tools/ghidra/ExportFacts.java on a copy of the project, opened -readOnly.
#
#   ghidra-facts.sh        writes $GHIDRA_REF/mercs2.facts unless it is there
#
#   GHIDRA_REF, GHIDRA, PROJECT, BIN   as ghidra-diff.sh
# Writes only under GHIDRA_REF (default rust/target/ghidra-ref): the facts, facts.log and proj/.
set -e
rust=$(cd "$(dirname "$0")/.." && pwd)
ref=${GHIDRA_REF:-$rust/target/ghidra-ref}
case $ref in */.*) echo "GHIDRA_REF $ref: Ghidra refuses a path component starting with '.'" >&2; exit 1 ;; esac
BIN=${BIN:-$HOME/projects/mercs/mercs2-decomp/orig/Mercenaries2.analysis.exe}
[ -f "$ref/mercs2.facts" ] && exit 0
mkdir -p "$ref"
[ -d "$ref/proj" ] || cp -r "${PROJECT:-$HOME/projects/mercs/mercs2-decomp/build/ghidra}" "$ref/proj"
# written under another name and renamed, so a run cut short leaves no half file
GHIDRA_HEADLESS_MAXMEM=${GHIDRA_HEADLESS_MAXMEM:-6G} "${GHIDRA:-/opt/ghidra}/support/analyzeHeadless" \
    "$ref/proj" mercs2 -readOnly -scriptPath "$rust/tools/ghidra" -process "$(basename "$BIN")" \
    -noanalysis -postScript ExportFacts.java "$ref/mercs2.facts.part" > "$ref/facts.log" 2>&1
if grep -q 'SCRIPT ERROR\|error:' "$ref/facts.log" || [ ! -s "$ref/mercs2.facts.part" ]; then
    echo "headless Ghidra failed: see $ref/facts.log" >&2
    exit 1
fi
mv "$ref/mercs2.facts.part" "$ref/mercs2.facts"
