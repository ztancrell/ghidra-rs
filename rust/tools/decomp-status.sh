#!/bin/bash
# ghidra-rs alone on a list of functions (no reference): `decompile` and `print C` with the
# default options, per function, and a status table by cause.
#
#   BIN=<binary> PRELUDE=<prelude> OUT=<dir> decomp-status.sh <file of addresses>
#
# The file is one 0x%08x address per line (`#` comments), each a `map function` of the prelude.
# Writes OUT/c/<address> (the output from the load line on) and OUT/status.tsv (address, status,
# cause): `ok`, `loud` with the first error line, or `timeout` (TIMEOUT seconds, default 120).
# Prints the totals and the loud causes by count. JOBS as in decomp-diff.sh.
set -e
rust=$(cd "$(dirname "$0")/.." && pwd)
export GHIDRA_RS=${GHIDRA_RS:-$rust/target/release/ghidra-rs}
export BIN PRELUDE TIMEOUT=${TIMEOUT:-120}
export out=${OUT:?OUT}
rm -rf "$out"
mkdir -p "$out/c"
grep '^map function' "$PRELUDE" | awk '{ print $3, ($4 == "" || $4 == "nocode") ? "func_" $3 : $4 }' > "$out/names"
one() {
    n=$(awk -v a="$1" '$1 == a { print $2; exit }' "$out/names")
    s=$(printf 'load file %s\nsource %s\nload function %s\ndecompile\nprint C\nquit\n' "$BIN" "$PRELUDE" "$n")
    timeout "$TIMEOUT" "$GHIDRA_RS" decompile -i <(echo "$s") </dev/null 2>&1 |
        sed -n -e '/^init> load function/,$p' -e '/^init> load function/,$!{/panicked at\|has overflowed its stack/p}' > "$out/c/$1"
    case ${PIPESTATUS[0]} in 124|137) echo "timed out" > "$out/c/$1" ;; esac
}
export -f one
grep -v '^#' "$1" | awk 'NF { print $1 }' | xargs -P "${JOBS:-$(nproc --ignore=2)}" -I{} bash -c 'one "$1"' _ {}
for f in "$out"/c/*; do
    if [ "$(cat "$f")" = "timed out" ]; then
        printf '%s\ttimeout\t\n' "$(basename "$f")"
    elif grep -q '^Decompilation complete' "$f" && ! grep -q 'ERROR\|^error\|panicked at\|has overflowed its stack' "$f"; then
        printf '%s\tok\t\n' "$(basename "$f")"
    else
        printf '%s\tloud\t%s\n' "$(basename "$f")" "$(grep -m1 'ERROR\|^error\|panicked at\|has overflowed its stack' "$f" || echo 'no output')"
    fi
done > "$out/status.tsv"
cut -f2 "$out/status.tsv" | sort | uniq -c
awk -F'\t' '$2 == "loud" { print $3 }' "$out/status.tsv" | sort | uniq -c | sort -rn
