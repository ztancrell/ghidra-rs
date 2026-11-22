#!/bin/bash
# Milestone 3 stage check: run the same console script on the reference decompiler (decomp_dbg,
# built by decomp-ref.sh) and on ghidra-rs (`ghidra-rs decompile -i`), per function, and compare.
#
#   decomp-diff.sh <corpus>        corpus: m8, m500, a file of addresses (one per line, `#` comments), or d
#   decomp-diff.sh --script <file> one script, both engines, full diff
#   decomp-diff.sh --prelude       only write the prelude (below) when it is missing
#
# A corpus run writes, per function, a script and both outputs under rust/target/decomp-check/<corpus>/
# and prints `identical N / M`, the functions the reference could not decompile, and the first
# differing line of each mismatch. The stage is set by environment variables:
#   BREAK    action to stop before (`break start`), e.g. funclink, heritage, paramdouble; empty: none
#   PRINT    what to print after `decompile` (default: print raw)
#   OPTIONS  file of extra commands run before `load function` (option togglerule ..., option currentaction ...)
#   JOBS     parallel runs (default: nproc less 2, left for the desktop)
#   CONTINUES  after the print, this many times `continue` and the print again (next hit of BREAK)
#   OPTIONS_SKIP_SELF=1  drop the OPTIONS lines declaring the decompiled function (`<name>(`), so
#            a `decomp-locked-options.sh` file locks only its callees
#   VERBOSE=1  for each mismatch, also the break lines, first differing op's block and context (decomp-show.sh)
#   ORDER=easy run the corpus simplest first (decomp-rank.sh, cached at rust/target/decomp-check/<corpus>.ranked)
#   STOP=1     one function at a time, in corpus order, stopping at the first mismatch the reference ran
#   OUT        output directory (default: rust/target/decomp-check/<corpus>)
#   TIMEOUT    seconds each engine may take per function (default 120). A killed run (timeout's
#              status 124 or 137) keeps only the line `decomp-diff.sh: timed out after N s`, so a
#              reference cut off mid-print counts as failed, never as finished
#   BIN        the game binary (default ~/projects/mercs/mercs2-decomp/orig/Mercenaries2.analysis.exe);
#              a path with whitespace is reached through OUT/bin (`load file` reads words)
# An engine output empty from the load line on becomes `decomp-diff.sh: error: no output ...` and
# never counts as identical.
#   REFCACHE=0 run the reference for every function; otherwise its output is reused from
#              rust/target/ref-cache/ when the content hash of all its inputs matches a stored run:
#              decomp_dbg, BIN, the prelude, the .sla/.ldefs/.pspec/.cspec files under SLEIGHHOME,
#              every DECOMP_* variable (the patch reads them), the command line and the function's
#              script (address, options, break, print). Only a finished run with exit status 0
#              that refbad (below) accepts is stored, never a timeout, error or crash; a stored run
#              is reused only when it took less than TIMEOUT. ghidra-rs always runs
# Each function is selected with `load function <name>`, its name taken from the prelude (which maps
# every function, FID names included; `load addr` for one it lacks). Outputs are compared from that
# line on: everything before it is the shared prelude.
# Corpus d runs the upstream datatests through `ghidra-rs datatest`, on the reference and on ghidra-rs.
set -e
rust=$(cd "$(dirname "$0")/.." && pwd)
root=$(cd "$rust/.." && pwd)
export SLEIGHHOME=$root
export DECOMP=${DECOMP:-$rust/target/decomp-build/decomp_dbg}
export GHIDRA_RS=${GHIDRA_RS:-$rust/target/release/ghidra-rs}
export GHIDRA_RS_SLA=${GHIDRA_RS_SLA:-$root/Ghidra/Processors/x86/data/languages/x86.sla}
export BIN=${BIN:-$HOME/projects/mercs/mercs2-decomp/orig/Mercenaries2.analysis.exe}
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

[ "$1" = --prelude ] && exit 0
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
# both consoles read `load file` word by word (IfcLoadFile, consolemain.cc:53-57: two words are
# a target and the file), so neither can open a path with whitespace: such a BIN is reached
# through a link in the output directory
case $BIN in *[[:space:]]*) ln -sfn "$BIN" "$out/bin" && export BIN=$out/bin ;; esac

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
    refeng "$out/ref/$a" "$s"
    eng "$out/rust/$a" "$GHIDRA_RS" decompile -i "$s"
}
# refeng <output> <script>: the reference through the cache (REFCACHE above). A cache file is the
# run's seconds on line 1, then its output; written to a temporary file and renamed, so a killed
# run never leaves half of one
refeng() {
    local o=$1 s=$2 k t
    [ "$REFCACHE" = 0 ] && { eng "$o" "$DECOMP" -i "$s"; return; }
    k=$refcache/$({ echo "$refkey"; cat "$s"; } | sha256sum | cut -c1-64)
    if [ -f "$k" ] && [ "$(head -1 "$k")" -lt "$TIMEOUT" ] 2>/dev/null; then
        tail -n +2 "$k" > "$o"
        return
    fi
    t=$(date +%s)
    eng "$o" "$DECOMP" -i "$s"
    t=$(($(date +%s) - t))
    if [ "$st" = 0 ] && ! refbad "$o"; then
        { echo "$t"; cat "$o"; } > "$k.$$" && mv "$k.$$" "$k"
    fi
}
# eng <output> <engine command...>: run one engine under TIMEOUT, keep its output from the load line,
# and from before it only a panic or stack overflow message (ghidra-rs prints one ahead of the
# buffered console output; bars.sh counts it as loud); when timeout killed it, replace the cut-off
# output with the one timed-out line
eng() {
    local o=$1; shift
    timeout "$TIMEOUT" "$@" </dev/null > "$o.raw" 2>&1
    st=$?
    sed -n -e '/^init> load \(function\|addr\)/,$p' \
        -e '/^init> load \(function\|addr\)/,$!{/panicked at\|has overflowed its stack/p}' "$o.raw" > "$o"
    case $st in 124|137) echo "decomp-diff.sh: timed out after $TIMEOUT s" > "$o" ;; esac
    # nothing from the load line on (the program or prelude did not load): an error, never an
    # output to compare; the first line the engine printed after the script's own echoes says why
    [ -s "$o" ] || echo "decomp-diff.sh: error: no output from the load line on: $(grep -v -m1 '^init> ' "$o.raw" | cut -c1-200)" > "$o"
    rm -f "$o.raw"
}
# the reference failed: an error, or no decompile result (a timed-out run has none)
refbad() {
    grep -q 'Low-level ERROR\|Unable to proceed\|Execution error\|parsing error' "$1" ||
        ! grep -q '^Decompilation complete\|^Break at' "$1"
}
export -f one refeng eng refbad
export refcache=$rust/target/ref-cache
if [ "$REFCACHE" != 0 ]; then
    mkdir -p "$refcache"
    # the inputs shared by every function of this run (refeng adds the function's script)
    export refkey=$(
        {
            echo "ref-cache 1: $DECOMP -i <script> </dev/null"
            sha256sum "$DECOMP" "$BIN" "$PRELUDE" | cut -c1-64
            find "$SLEIGHHOME/Ghidra/Processors" -path '*/data/languages/*' -type f \( -name '*.sla' -o \
                -name '*.ldefs' -o -name '*.pspec' -o -name '*.cspec' \) | LC_ALL=C sort | xargs sha256sum
            env | grep '^DECOMP_' | LC_ALL=C sort
        } | sha256sum | cut -c1-64)
fi
if [ -n "$STOP" ]; then
    for a in $list; do
        one "$a"
        refbad "$out/ref/$a" || cmp -s "$out/ref/$a" "$out/rust/$a" || { echo "stopped at $a"; break; }
    done
else
    xargs -P "${JOBS:-$(nproc --ignore=2)}" -I{} bash -c 'one "$1"' _ {} <<<"$list"
fi

total=0 same=0 refok=0
for f in "$out"/ref/*; do
    a=$(basename "$f")
    total=$((total + 1))
    if refbad "$f"; then
        echo "reference failed $a: $(grep -m1 'ERROR\|Unable\|error\|^decomp-diff.sh: timed out' "$f")"
    else
        refok=$((refok + 1))
    fi
    if [ ! -s "$out/rust/$a" ] || grep -q '^decomp-diff.sh: error: no output' "$f" "$out/rust/$a"; then
        # a missing or empty output on either side is never identical
        echo "no output $a: ref: $(head -1 "$f") | rust: $(head -1 "$out/rust/$a" 2>/dev/null)"
    elif cmp -s "$f" "$out/rust/$a"; then
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
