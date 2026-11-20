#!/bin/bash
# Stage S10 check: the C of Java Ghidra (tools/ghidra/DecompileRef.java, the output of mercs2's
# Decompile.java) against `print C` of ghidra-rs, per function, with default options on both.
#
#   ghidra-diff.sh <corpus>     corpus: m8, m500, ... (tools/corpus/) or a file of addresses
#
# ghidra-rs reads the facts of the Java project (`load facts`, written once by ghidra-facts.sh)
# in place of the prelude.
#
#   ENGINE=ref   compare Java with decomp_dbg instead of ghidra-rs (what Java Ghidra adds to the
#                console decompiler: names, types, prototypes, comments)
#   FACTS=0      ghidra-rs without the facts (the prelude, as decomp_dbg)
#   FACTS=<file> ghidra-rs with another facts file, such as the one ghidra-rs derives itself
#                (`analyze --facts`, tools/facts-own.sh). A missing or empty file prints
#                `<corpus>: FACTS missing: <file>` (or `FACTS empty`) in place of the summary
#                line, before any Java or ghidra-rs work, and exits 1 (no fallback to Java's facts)
#   SKIP         DECOMP_SKIP_ACTIONS for the console engine (actions left out; none by default)
#   CLASSIFY=<actions>  also run decomp_dbg with the prelude (and `option readonly off`) twice,
#                as it is and with these actions skipped, and mark each miss `skip` when the
#                two differ (the function needs the actions, whatever else differs) and `own`
#                when they are the same; the summary counts both. A guide only: decomp_dbg has
#                no data symbols or prototypes, so an action can matter with the facts and not
#                without them
#   GHIDRA_REF   where the Java side lives (default rust/target/ghidra-ref): proj/ (a copy of the
#                mercs2 Ghidra project, made once; the original is only read) and
#                java/<corpus>/<address> (the captured C, kept: delete a file to capture it
#                again). Ghidra refuses a project path with a component starting with `.`, so in
#                a worktree under .claude/ set GHIDRA_REF to a path without one
#   GHIDRA_RS    the ghidra-rs binary (default rust/target/release/ghidra-rs), as decomp-diff.sh
#   GHIDRA       the Ghidra install (default /opt/ghidra; the reference is 12.3, README "The 12.3
#                reference"); its analyzeHeadless finds Java through JAVA_HOME or PATH
#   PROJECT      the mercs2 Ghidra project to copy (default ~/projects/mercs/mercs2-decomp/build/ghidra)
#   OUT          output directory (default rust/target/ghidra-diff/<corpus>): con/<address> (the
#                console engine's C), <corpus>.miss (one line per function that differs)
#   JOBS, TIMEOUT  as decomp-diff.sh
#
# Summary line: `<corpus>: java finished F / N, identical I / F (loud L, silent S)`. F leaves
# out addresses without a function in the Java project and functions Java does not decompile.
# The two sides are compared from the function's first line to its closing brace: blank lines
# before and after are dropped on both.
# Writes only under rust/target/ (and GHIDRA_REF). Needs decomp-diff.sh's prelude and a release build.
set -e
rust=$(cd "$(dirname "$0")/.." && pwd)
root=$(cd "$rust/.." && pwd)
corpus=$1
[ -f "$corpus" ] || corpus=$rust/tools/corpus/$1.txt
[ -f "$corpus" ] || { echo "no corpus $1" >&2; exit 1; }
name=$(basename "$corpus" .txt)
list=$(grep -v '^#' "$corpus" | awk 'NF { print $1 }')
ref=${GHIDRA_REF:-$rust/target/ghidra-ref}
case $ref in */.*) echo "GHIDRA_REF $ref: Ghidra refuses a path component starting with '.'" >&2; exit 1 ;; esac
if [ "$ENGINE" != ref ] && [ -n "$FACTS" ] && [ "$FACTS" != 0 ]; then
    [ -f "$FACTS" ] || { echo "$name: FACTS missing: $FACTS"; exit 1; }
    [ -s "$FACTS" ] || { echo "$name: FACTS empty: $FACTS"; exit 1; }
fi
export SLEIGHHOME=$root TIMEOUT=${TIMEOUT:-120}
export BIN=${BIN:-$HOME/projects/mercs/mercs2-decomp/orig/Mercenaries2.analysis.exe}
export PRELUDE=${PRELUDE:-$rust/target/decomp-check/mercs2.prelude}
export out=${OUT:-$rust/target/ghidra-diff/$name}
if [ "$ENGINE" = ref ]; then eng="$rust/target/decomp-build/decomp_dbg"; else eng="${GHIDRA_RS:-$rust/target/release/ghidra-rs} decompile"; fi
export eng DECOMP_SKIP_ACTIONS=$SKIP
"$rust/tools/decomp-diff.sh" --prelude
facts=$FACTS
export FACTS=
if [ "$ENGINE" != ref ] && [ -f "$facts" ]; then
    FACTS=$facts
elif [ "$ENGINE" != ref ] && [ "$facts" != 0 ]; then
    GHIDRA_REF=$ref "$rust/tools/ghidra-facts.sh"
    FACTS=$ref/mercs2.facts
fi

# the Java side: capture what is missing, in one headless run
java=$ref/java/$name
mkdir -p "$java"
need=$(for a in $list; do [ -f "$java/$a" ] || echo "$a"; done)
if [ -n "$need" ]; then
    [ -d "$ref/proj" ] || cp -r "${PROJECT:-$HOME/projects/mercs/mercs2-decomp/build/ghidra}" "$ref/proj"
    # shellcheck disable=SC2086
    GHIDRA_HEADLESS_MAXMEM=${GHIDRA_HEADLESS_MAXMEM:-6G} "${GHIDRA:-/opt/ghidra}/support/analyzeHeadless" \
        "$ref/proj" mercs2 -readOnly -scriptPath "$rust/tools/ghidra" -process "$(basename "$BIN")" \
        -noanalysis -postScript DecompileRef.java "$java" $need > "$ref/$name.log" 2>&1 ||
        { echo "headless Ghidra failed: see $ref/$name.log" >&2; exit 1; }
fi

# the console side: `print C` with default options
rm -rf "$out"
mkdir -p "$out/con"
one() {
    a=$1
    {
        echo "load file $BIN"
        if [ -n "$FACTS" ]; then
            echo "load facts $FACTS"
            echo "load addr $a"
        else
            echo "source $PRELUDE"
            awk -v a="$(printf "0x%08x" "$a")" '$1 == "map" && $2 == "function" && $3 == a { n = ($4 == "" || $4 == "nocode") ? "func_" a : $4 } END { print (n == "" ? "load addr " a : "load function " n) }' "$PRELUDE"
        fi
        printf 'decompile\nprint C\nquit\n'
    } > "$out/con/$a.script"
    # shellcheck disable=SC2086
    timeout "$TIMEOUT" $eng -i "$out/con/$a.script" </dev/null > "$out/con/$a.log" 2>&1 || true
    rm "$out/con/$a.script"
}
# CLASSIFY: decomp_dbg with the prelude, as it is (cls/<address>.all) and with the actions
# skipped (cls/<address>.skip); read-only memory does not fold to constants, as in Java Ghidra
# without options
classify() {
    a=$1
    {
        echo "load file $BIN"
        echo "source $PRELUDE"
        echo "option readonly off"
        awk -v a="$(printf "0x%08x" "$a")" '$1 == "map" && $2 == "function" && $3 == a { n = ($4 == "" || $4 == "nocode") ? "func_" a : $4 } END { print (n == "" ? "load addr " a : "load function " n) }' "$PRELUDE"
        printf 'decompile\nprint C\nquit\n'
    } > "$out/cls/$a.script"
    dbg=$rust/target/decomp-build/decomp_dbg
    DECOMP_SKIP_ACTIONS='' timeout "$TIMEOUT" "$dbg" -i "$out/cls/$a.script" </dev/null 2>&1 | sed -n '/^init> print C/,$p' > "$out/cls/$a.all" || true
    DECOMP_SKIP_ACTIONS=$CLASSIFY timeout "$TIMEOUT" "$dbg" -i "$out/cls/$a.script" </dev/null 2>&1 | sed -n '/^init> print C/,$p' > "$out/cls/$a.skip" || true
    rm "$out/cls/$a.script"
}
export -f one classify
export CLASSIFY rust
xargs -P "${JOBS:-$(nproc --ignore=2)}" -I{} bash -c 'one "$1"' _ {} <<<"$list"
if [ -n "$CLASSIFY" ]; then
    mkdir -p "$out/cls"
    xargs -P "${JOBS:-$(nproc --ignore=2)}" -I{} bash -c 'classify "$1"' _ {} <<<"$list"
fi
# the mark of a miss: `skip` when the function needs the CLASSIFY actions (or decomp_dbg did
# not print it with them), `own` otherwise
mark() {
    [ -n "$CLASSIFY" ] || return 0
    if [ -s "$out/cls/$1.all" ] && cmp -s "$out/cls/$1.all" "$out/cls/$1.skip"; then echo " own"; else echo " skip"; fi
}

# the function alone: blank lines before and after dropped
body() { awk 'NF { for (; b > 0; b--) print ""; print; s = 1; next } s { b++ }' "$1"; }
n=0 fin=0 same=0 loud=0 silent=0
# an engine's error lines (at the start of a line: the C may hold these words in a string)
errors='^Low-level ERROR\|^error:\|panicked at\|^Execution error\|^Command parsing error'
for a in $list; do
    n=$((n + 1))
    grep -q '^{' "$java/$a" || { echo "java failed $a: $(head -c 160 "$java/$a" | head -1)"; continue; }
    fin=$((fin + 1))
    if grep -q "$errors" "$out/con/$a.log" || ! grep -q '^init> print C' "$out/con/$a.log"; then
        loud=$((loud + 1)); echo "loud$(mark "$a") $a: $(grep -m1 "$errors" "$out/con/$a.log" | cut -c1-160)"
    elif cmp -s <(body "$java/$a") <(sed -n '/^init> print C/,/^init> quit/p' "$out/con/$a.log" | sed '1d;$d' | body /dev/stdin); then
        same=$((same + 1))
    else
        silent=$((silent + 1)); echo "silent$(mark "$a") $a"
    fi
done > "$out/$name.miss"
echo "$name: java finished $fin / $n, identical $same / $fin (loud $loud, silent $silent)"
if [ -n "$CLASSIFY" ]; then
    echo "$name: of the misses, $(grep -c '^[a-z]* own ' "$out/$name.miss") own (the CLASSIFY actions change nothing in decomp_dbg) and $(grep -c '^[a-z]* skip ' "$out/$name.miss") skip"
fi
