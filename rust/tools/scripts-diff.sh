#!/bin/bash
# The `export` commands of ghidra-rs against mercs2's Java scripts (README "The read-only
# scripts"): the same inputs as tools/scripts-ref.sh, on the functions of the Java project
# (--functions-from), and one line per output: the lines of each side and the lines they share.
#
#   scripts-diff.sh         needs scripts-ref.sh's output and a release build
#
#   GHIDRA_REF, MERCS, FACTS  as scripts-ref.sh (FACTS: where library-evidence reads the strings
#                             and abi-candidates the names; OWN_FACTS: ghidra-rs's own facts
#                             from `analyze --facts`, for a second library-evidence run)
#   OUT    output directory (default rust/target/scripts-diff)
#   JOBS   commands at a time (default 2; each holds about 2 GB)
#   ONLY   run only these (names of the output files without their ending)
#   CDIR   the directory of verified C for abi-candidates (scripts-ref.sh --c writes Java's own
#          to $GHIDRA_REF/scripts/c); without it abi-candidates fails, as it must
#   GHIDRA_RS_SHARED=lowest reaches the commands: slot-owners stops at a site in two bodies without it
set -e
rust=$(cd "$(dirname "$0")/.." && pwd)
ref=${GHIDRA_REF:-$rust/target/ghidra-ref}/scripts
M=${MERCS:-$HOME/projects/mercs/mercs2-decomp}
facts=${FACTS:-$(dirname "$ref")/mercs2.facts}
out=${OUT:-$rust/target/scripts-diff}
j=$ref/java
mkdir -p "$out"
slots=$(ls "$M"/build/slot-captures/*/slots.csv | tail -n 1)
sites=$(awk -F, 'NR > 1 { print $1 }' "$M/config/mod_hook_sites.csv")
run() {
    name=$1
    shift
    "$rust/target/release/ghidra-rs" export "$M/orig/Mercenaries2.analysis.exe" --functions-from "$ref/functions.csv" \
        "$@" > "$out/$name.log" 2>&1 || echo "$name: FAILED: $(grep '^error' "$out/$name.log" | cut -c1-300)"
}
n=0
go() {
    case " ${ONLY:-$1} " in *" $1 "*) ;; *) return ;; esac
    rm -f "$out/$1.csv" "$out/$1.txt" # a command that fails writes nothing: no file of an earlier run
    run "$@" &
    n=$((n + 1))
    [ $((n % ${JOBS:-2})) -ne 0 ] || wait
}
go mod-hook-owners mod-hook-owners "$M/config/mod_hook_sites.csv" "$out/mod-hook-owners.csv"
go slot-owners slot-owners "$slots" "$out/slot-owners.csv"
# shellcheck disable=SC2086
go boundaries boundaries "$out/boundaries.txt" $sites
for t in 401780 4017b0 568900 593c10; do go contexts-$t call-contexts 0x00$t "$out/contexts-$t.txt"; done
# --functions-from leaves out an entry where no instruction decodes here, and the audit stops at
# the first function it misses, as Java does: only the rows of functions ghidra-rs has
case " ${ONLY:-audit} " in *" audit "*)
    "$rust/target/release/ghidra-rs" analyze "$M/orig/Mercenaries2.analysis.exe" --functions-from "$ref/functions.csv" \
        --functions "$out/functions.csv" > "$out/functions.log" 2>&1
    awk -F, 'NR == FNR { f[$1]; next } ($2 in f)' "$out/functions.csv" "$ref/recovery.csv" > "$out/recovery.csv"
    echo "audit: $(wc -l < "$ref/recovery.csv") rows for Java, $(wc -l < "$out/recovery.csv") of them functions here"
    ;;
esac
go audit audit-recovered-functions "$out/recovery.csv" "$out/audit.csv"
go library-evidence --facts "$facts" library-evidence "$M/config/library_markers.csv" "$out/library-evidence.csv"
[ -z "$OWN_FACTS" ] || go library-evidence-own --facts "$OWN_FACTS" library-evidence "$M/config/library_markers.csv" "$out/library-evidence-own.csv"
go bindings bindings "$out/bindings.csv"
# the C of Java itself stands for verified C, when it is there (CDIR: one file 0x<entry> each)
go abi-candidates --facts "$facts" abi-candidates "$out/abi-candidates.csv" "$out/abi-candidates.txt" ${CDIR:+"$CDIR"}
wait
for f in "$out"/*.csv "$out"/*.txt; do
    name=$(basename "$f")
    java=$j/${name/-own.csv/.csv}
    [ -f "$java" ] || continue
    printf '%s: java %d lines, ghidra-rs %d, in both %d\n' "$name" "$(wc -l < "$java")" "$(wc -l < "$f")" \
        "$(comm -12 <(sort "$java") <(sort "$f") | wc -l)"
done
