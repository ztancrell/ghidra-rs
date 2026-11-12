#!/bin/bash
# Find the first decompiler step at which ghidra-rs and the reference disagree, for one function.
#
#   decomp-bisect.sh <addr> [continues]
#
# For each action in ACTIONS (default: universal order from start through the end of mainloop's
# actions; unreachable, directwrite and deadcode are left out: they occur twice in the action tree
# and the reference rejects `break start` on them, reported as skipped if named), runs
# decomp-diff.sh with `break start <action>`, `print raw` (PRINT), then <continues>
# (default 3) times `continue` and the print again, to see the action's later hits (mainloop
# repeats). Outputs: rust/target/decomp-check/bisect-<addr>/<action>/{ref,rust}/<addr>, and the
# per-hit chunks compared as <action>/{ref,rust}.<hit>.
# Hits are compared in execution order: hit 1 of every action in order, then hit 2, and so on. A hit
# the reference does not reach (`Decompilation complete` instead of a break) is skipped, unless
# ghidra-rs breaks there. Prints the first differing (action, hit) with decomp-show.sh's context,
# or that all compared hits are identical. Exit status 1 on a difference.
set -e
rust=$(cd "$(dirname "$0")/.." && pwd)
a=$1 n=${2:-3}
[ -n "$a" ] || { echo "usage: decomp-bisect.sh <addr> [continues]" >&2; exit 1; }
ACTIONS=${ACTIONS:-start constbase defaultparams extrapopsetup prototypetypes funclink varnodeprops
    heritage paramdouble segmentize internalstorage forcegoto activeparam returnrecovery
    restrictlocal dynamicmapping spacebase nonzeromask infertypes restructure_varnode}
b=$rust/target/decomp-check/bisect-$a
rm -rf "$b"
mkdir -p "$b"
echo "$a" > "$b/corpus.txt"
export b n rust
# shellcheck disable=SC2016
xargs -n1 -P "${JOBS:-$(nproc)}" bash -c 'env -u ORDER -u STOP -u VERBOSE OUT="$b/$1" BREAK="$1" CONTINUES="$n" \
    "$rust/tools/decomp-diff.sh" "$b/corpus.txt" >/dev/null' _ <<<"$ACTIONS"

for ((h = 0; h <= n; h++)); do
    same=
    for act in $ACTIONS; do
        for side in ref rust; do
            awk -v h="$h" '/^init> continue$/ { c++ } c == h' "$b/$act/$side/$a" > "$b/$act/$side.$h"
        done
        r=$b/$act/ref.$h s=$b/$act/rust.$h
        if grep -q 'Bad action/rule specifier' "$r"; then
            [ "$h" = 0 ] && echo "$a: skipped $act: the reference rejects the break ($(grep -m1 'Bad action' "$r"))"
            continue
        fi
        grep -q '^Break at' "$r" || grep -q '^Break at' "$s" || continue
        if cmp -s "$r" "$s"; then
            same="$same $act"
        else
            [ -n "$same" ] && echo "$a: hit $((h + 1)) identical at:$same"
            echo "$a: first difference: $act, hit $((h + 1))"
            "$rust/tools/decomp-show.sh" "$r" "$s"
            exit 1
        fi
    done
    [ -n "$same" ] && echo "$a: hit $((h + 1)) identical at:$same"
done
echo "$a: identical at every break compared (actions: $(echo $ACTIONS), hits 1 to $((n + 1)))"
