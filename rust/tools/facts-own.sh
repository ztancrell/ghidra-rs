#!/bin/bash
# The facts of mercs2 from ghidra-rs's own analysis (`analyze --facts`), and their comparison
# with the facts of the Java project (tools/ghidra-facts.sh, facts-diff.sh).
#
#   facts-own.sh           writes rust/target/facts/mercs2.facts and prints the comparison
#
#   FUNCS=plain    the functions ghidra-rs discovers (default)
#   FUNCS=java     the function entries of the Java facts (`--functions-from`): the mercs2
#                  pipeline makes functions after auto-analysis that discovery does not find
#   PROTOS         the prototypes of Ghidra's data-type archives (tools/ghidra-protos.sh;
#                  default $GHIDRA_REF/win32.protos when it is there)
#   DIFF=0         no comparison
#   GHIDRA_REF, BIN  as ghidra-diff.sh;  SAMPLES, WIDTH  as facts-diff.sh
# Writes only under rust/target/.
set -e
rust=$(cd "$(dirname "$0")/.." && pwd)
ref=${GHIDRA_REF:-$rust/target/ghidra-ref}
BIN=${BIN:-$HOME/projects/mercs/mercs2-decomp/orig/Mercenaries2.analysis.exe}
PROTOS=${PROTOS:-$ref/win32.protos}
out=$rust/target/facts
mkdir -p "$out"
args=()
if [ "$FUNCS" = java ]; then
    awk -F'\t' '$1 == "func" { print "0x" $2 }' "$ref/mercs2.facts" > "$out/java-funcs.csv"
    args+=(--functions-from "$out/java-funcs.csv")
fi
[ -f "$PROTOS" ] && args+=(--protos "$PROTOS")
"$rust/target/release/ghidra-rs" analyze "$BIN" "${args[@]}" --facts "$out/mercs2.facts.part"
mv "$out/mercs2.facts.part" "$out/mercs2.facts"
[ "$DIFF" = 0 ] || "$rust/tools/facts-diff.sh" "$out/mercs2.facts" "$ref/mercs2.facts"
