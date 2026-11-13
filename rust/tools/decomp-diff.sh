#!/bin/bash
# Milestone 3 stage check: run the same console script on the reference decompiler (decomp_dbg,
# built by decomp-ref.sh) and on ghidra-rs (`ghidra-rs decompile -i`), per function, and compare.
#
#   decomp-diff.sh <corpus>        corpus: m8, m500, a file of addresses (one per line, `#` comments), or d
#   decomp-diff.sh --script <file> one script, both engines, full diff
#
# A corpus run writes, per function, a script and both outputs under rust/target/decomp-check/<corpus>/
# and prints `identical N / M`, the functions the reference could not decompile, and the first
# differing line of each mismatch. The stage is set by environment variables:
#   BREAK    action to stop before (`break start`), e.g. funclink, heritage, paramdouble; empty: none
#   PRINT    what to print after `decompile` (default: print raw)
#   OPTIONS  file of extra commands run before `load function` (option togglerule ..., option currentaction ...)
#   JOBS     parallel runs (default: nproc)
#   CONTINUES  after the print, this many times `continue` and the print again (next hit of BREAK)
#   OPTIONS_SKIP_SELF=1  drop the OPTIONS lines declaring the decompiled function (`<name>(`), so
#            a `decomp-locked-options.sh` file locks only its callees
#   VERBOSE=1  for each mismatch, also the break lines, first differing op's block and context (decomp-show.sh)
#   ORDER=easy run the corpus simplest first (decomp-rank.sh, cached at rust/target/decomp-check/<corpus>.ranked)
#   STOP=1     one function at a time, in corpus order, stopping at the first mismatch the reference ran
#   OUT        output directory (default: rust/target/decomp-check/<corpus>)
#   TIMEOUT    seconds each engine may take per function (default 120; a killed run prints nothing)
# Each function is selected with `load function <name>`, its name taken from the prelude (which maps
# every function, FID names included; `load addr` for one it lacks). Outputs are compared from that
# line on: everything before it is the shared prelude.
# Corpus d runs the upstream datatests through `ghidra-rs datatest`, on the reference and on ghidra-rs.
set -e
rust=$(cd "$(dirname "$0")/.." && pwd)
root=$(cd "$rust/.." && pwd)
export SLEIGHHOME=$root
export DECOMP=$rust/target/decomp-build/decomp_dbg
export GHIDRA_RS=$rust/target/release/ghidra-rs
export GHIDRA_RS_SLA=${GHIDRA_RS_SLA:-$root/Ghidra/Processors/x86/data/languages/x86.sla}
export BIN=${BIN:-/home/zpt/projects/mercs/mercs2-decomp/orig/Mercenaries2.analysis.exe}
export PRELUDE=${PRELUDE:-$rust/target/decomp-check/mercs2.prelude}
export BREAK PRINT=${PRINT:-print raw} OPTIONS CONTINUES=${CONTINUES:-0} TIMEOUT=${TIMEOUT:-120}
[ -x "$DECOMP" ] || { echo "no reference: run rust/tools/decomp-ref.sh" >&2; exit 1; }
[ -x "$GHIDRA_RS" ] || (cd "$rust" && cargo build --release)

if [ "$1" = d ]; then
    dt=$root/Ghidra/Features/Decompiler/src/decompile/datatests
    for side in ref rust; do
        flag=; [ $side = ref ] && flag="--ref $DECOMP"
        out=$("$GHIDRA_RS" datatest $flag "$dt" 2>&1 || true)
        echo "d on $side: $(grep -o 'Total passing tests = [0-9]*' <<<"$out" | grep -o '[0-9]*$') / $(grep -o 'Total tests applied = [0-9]*' <<<"$out" | grep -o '[0-9]*$') checks pass, $(grep -c '^Error' <<<"$out") files not run"
    done
    echo "(files not run on ref: tests for processors without a built .sla)"
    exit 0
fi

if [ ! -f "$PRELUDE" ]; then
    mkdir -p "$(dirname "$PRELUDE")"
    # written to a temporary file and renamed, so parallel runs (decomp-bisect.sh) never read half of it
    "$GHIDRA_RS" analyze "$BIN" --decomp-prelude "$PRELUDE.$$" >&2
    mv "$PRELUDE.$$" "$PRELUDE"
fi

if [ "$1" = --script ]; then
    diff <("$DECOMP" -i "$2" </dev/null 2>&1) <("$GHIDRA_RS" decompile -i "$2" 2>&1) && echo identical
    exit 0
fi

corpus=$1
[ -f "$corpus" ] || corpus=$rust/tools/corpus/$1.txt
name=$(basename "$corpus" .txt)
list=$(grep -v '^#' "$corpus" | awk 'NF { print $1 }')
if [ "$ORDER" = easy ]; then
    ranked=$rust/target/decomp-check/$name.ranked
    [ -f "$ranked" ] || "$rust/tools/decomp-rank.sh" "$corpus" >/dev/null
    list=$(awk '!/^#/ && NF { print $1 }' "$ranked")
fi
export out=${OUT:-$rust/target/decomp-check/$name}
rm -rf "$out"
mkdir -p "$out"/scripts "$out"/ref "$out"/rust

one() {
    a=$1
    s=$out/scripts/$a.txt
    {
        echo "load file $BIN"
        echo "source $PRELUDE"
        if [ -n "$OPTIONS" ] && [ -n "$OPTIONS_SKIP_SELF" ]; then
            # leave out the lines declaring the decompiled function (`parse line extern ... name(`),
            # so only its callees get a locked prototype
            self=$(awk -v a="$(printf "0x%08x" "$a")" '$1 == "map" && $2 == "function" && $3 == a { n = ($4 == "" || $4 == "nocode") ? "func_" a : $4 } END { print n }' "$PRELUDE")
            grep -v -F " $self(" "$OPTIONS"
        elif [ -n "$OPTIONS" ]; then
            cat "$OPTIONS"
        fi
        awk -v a="$(printf "0x%08x" "$a")" '$1 == "map" && $2 == "function" && $3 == a { n = ($4 == "" || $4 == "nocode") ? "func_" a : $4 } END { print (n == "" ? "load addr " a : "load function " n) }' "$PRELUDE"
        [ -n "$BREAK" ] && echo "break start $BREAK"
        echo decompile
        echo "$PRINT"
        for ((i = 0; i < CONTINUES; i++)); do echo continue; echo "$PRINT"; done
        echo quit
    } > "$s"
    timeout "$TIMEOUT" "$DECOMP" -i "$s" </dev/null 2>&1 | sed -n '/^init> load \(function\|addr\)/,$p' > "$out/ref/$a"
    timeout "$TIMEOUT" "$GHIDRA_RS" decompile -i "$s" 2>&1 | sed -n '/^init> load \(function\|addr\)/,$p' > "$out/rust/$a"
}
export -f one
# the reference failed: an error, or no decompile result
refbad() {
    grep -q 'Low-level ERROR\|Unable to proceed\|Execution error\|parsing error' "$1" ||
        ! grep -q '^Decompilation complete\|^Break at' "$1"
}
if [ -n "$STOP" ]; then
    for a in $list; do
        one "$a"
        refbad "$out/ref/$a" || cmp -s "$out/ref/$a" "$out/rust/$a" || { echo "stopped at $a"; break; }
    done
else
    xargs -P "${JOBS:-$(nproc)}" -I{} bash -c 'one "$1"' _ {} <<<"$list"
fi

total=0 same=0 refok=0
for f in "$out"/ref/*; do
    a=$(basename "$f")
    total=$((total + 1))
    if refbad "$f"; then
        echo "reference failed $a: $(grep -m1 'ERROR\|Unable\|error' "$f")"
    else
        refok=$((refok + 1))
    fi
    if cmp -s "$f" "$out/rust/$a"; then
        same=$((same + 1))
    else
        # first differing line: cmp's line number (at EOF, the line after the shorter file's last)
        c=$(cmp "$f" "$out/rust/$a" 2>&1 || true)
        n=$(grep -o 'line [0-9]*' <<<"$c" | grep -o '[0-9]*' || echo 1)
        grep -q EOF <<<"$c" && n=$((n + 1))
        echo "different $a, line $n: ref: $(sed -n "${n}p" "$f") | rust: $(sed -n "${n}p" "$out/rust/$a")"
        if [ -n "$VERBOSE$STOP" ]; then "$rust/tools/decomp-show.sh" "$f" "$out/rust/$a"; fi
    fi
done
echo "$name: reference ran $refok / $total"
echo "$name: identical $same / $total"
