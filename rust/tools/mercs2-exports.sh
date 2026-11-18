#!/bin/bash
# Drop-in for mercs2's four read-only Ghidra exports (README "Switching mercs2's export
# scripts"): ghidra-rs `export` on orig/Mercenaries2.analysis.exe (what `tools/ghidra/run.sh
# --analysis` opens), with the functions of mercs2's Ghidra project as seeds. Nothing is
# written to mercs2-decomp.
#
#   mercs2-exports.sh [--functions <file>] [--compare <java-dir>] [<out-dir>]
#       all four with mercs2's inputs, into <out-dir> (default rust/target/mercs2-exports):
#       mod-hook-owners.csv  ExportModHookOwners.java config/mod_hook_sites.csv
#       boundaries.txt       InspectBoundaries.java, the addresses of mod_hook_sites.csv (SITES)
#       bindings.csv         ExportBindings.java (no --recover: that one edits, `ghidra-rs edit`)
#       contexts-<t>.txt     ExportCallContexts.java <t> for each target of TARGETS
#       --compare: each file against the file of the same name in <java-dir> (scripts-ref.sh
#       writes them so); one line each, exit 1 when any is not byte-identical
#   mercs2-exports.sh [--functions <file>] <Script.java> <script args...>
#       one script with Java's arguments, as `tools/ghidra/run.sh --analysis` takes them
#
#   --functions  Java's function entries: a CSV whose 0x-lines start with an entry, or a facts
#                file of the project (tools/ghidra-facts.sh; its `func` records are taken).
#                Default $GHIDRA_REF/scripts/functions.csv (scripts-ref.sh writes it)
#   MERCS        the mercs2-decomp checkout (default ~/projects/mercs/mercs2-decomp)
#   GHIDRA_REF   default rust/target/ghidra-ref
#   SITES        addresses for boundaries (default the first column of mod_hook_sites.csv)
#   TARGETS      call-contexts targets (default 0x00401780 0x004017b0 0x00568900 0x00593c10)
#   JOBS         commands at a time (default 2; each holds about 2 GB)
set -e
rust=$(cd "$(dirname "$0")/.." && pwd)
M=${MERCS:-$HOME/projects/mercs/mercs2-decomp}
exe=$M/orig/Mercenaries2.analysis.exe
bin=$rust/target/release/ghidra-rs
functions=${GHIDRA_REF:-$rust/target/ghidra-ref}/scripts/functions.csv
compare=
while [ $# -gt 0 ]; do
    case $1 in
    --functions) functions=$2; shift 2 ;;
    --compare) compare=$2; shift 2 ;;
    *) break ;;
    esac
done
[ -x "$bin" ] || { echo "no $bin: cargo build --release -p ghidra-rs" >&2; exit 1; }
[ -f "$exe" ] || { echo "no $exe" >&2; exit 1; }
[ -f "$functions" ] || { echo "no function list $functions (--functions; README \"Switching mercs2's export scripts\")" >&2; exit 1; }
seeds=$functions
if [ "$(head -c 15 "$functions")" = ghidra-rs-facts ]; then
    seeds=$rust/target/mercs2-exports.functions.csv
    awk -F'\t' '$1 == "func" { printf "0x%08x\n", strtonum("0x" $2) }' "$functions" > "$seeds"
fi
export_() { "$bin" export "$exe" --functions-from "$seeds" "$@"; }

# one script, Java's arguments
case $1 in
ExportModHookOwners.java) shift; export_ mod-hook-owners "$@"; exit ;;
InspectBoundaries.java) shift; export_ boundaries "$@"; exit ;;
ExportBindings.java)
    shift
    case " $* " in *" --recover "*) echo "--recover edits the project: ghidra-rs edit export-bindings" >&2; exit 1 ;; esac
    export_ bindings "$@"; exit ;;
ExportCallContexts.java) shift; export_ call-contexts "$@"; exit ;;
*.java) echo "$1: not one of the four (ExportModHookOwners, InspectBoundaries, ExportBindings, ExportCallContexts)" >&2; exit 1 ;;
esac

out=${1:-$rust/target/mercs2-exports}
mkdir -p "$out"
sites=${SITES:-$(awk -F, 'NR > 1 { print $1 }' "$M/config/mod_hook_sites.csv")}
targets=${TARGETS:-0x00401780 0x004017b0 0x00568900 0x00593c10}
fail=0
n=0
go() {
    name=$1
    shift
    rm -f "$out/$name" # a command that fails writes nothing: no file of an earlier run
    { export_ "$@" > "$out/$name.log" 2>&1 || echo "$name: FAILED: $(grep '^error' "$out/$name.log" | cut -c1-300)"; } &
    n=$((n + 1))
    [ $((n % ${JOBS:-2})) -ne 0 ] || wait
}
go mod-hook-owners.csv mod-hook-owners "$M/config/mod_hook_sites.csv" "$out/mod-hook-owners.csv"
# shellcheck disable=SC2086
go boundaries.txt boundaries "$out/boundaries.txt" $sites
go bindings.csv bindings "$out/bindings.csv"
for t in $targets; do
    go "contexts-${t#0x00}.txt" call-contexts "$t" "$out/contexts-${t#0x00}.txt"
done
wait
for t in mod-hook-owners.csv boundaries.txt bindings.csv $(for t in $targets; do echo "contexts-${t#0x00}.txt"; done); do
    [ -f "$out/$t" ] || { echo "$t: missing (see $out/$t.log)"; fail=1; }
done
[ -n "$compare" ] || exit $fail
# blocks of one reference each (call-contexts), one per line, sorted: the same set in another order
blocks() { awk 'BEGIN { RS = ""; ORS = "\n" } { gsub(/\n/, "|"); print }' "$1" | sort; }
for f in "$out"/*.csv "$out"/*.txt; do
    name=$(basename "$f")
    java=$compare/$name
    if [ ! -f "$java" ]; then
        echo "$name: no $java"
        fail=1
    elif cmp -s "$java" "$f"; then
        echo "$name: identical"
    else
        fail=1
        case $name in
        contexts-*) if cmp -s <(blocks "$java") <(blocks "$f"); then
            echo "$name: NOT identical: the same references in another order (Java lists them in creation order, RefListV0)"
            continue
        fi ;;
        esac
        printf '%s: NOT identical: java %d lines, ghidra-rs %d, in both %d\n' "$name" "$(wc -l < "$java")" \
            "$(wc -l < "$f")" "$(comm -12 <(sort "$java") <(sort "$f") | wc -l)"
    fi
done
exit $fail
