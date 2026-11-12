#!/bin/bash
# Explain the first difference between a reference and a ghidra-rs console output (as written by
# decomp-diff.sh under rust/target/decomp-check/<corpus>/{ref,rust}/<addr>):
#
#   decomp-show.sh <ref-file> <rust-file>
#
# Prints the break each side stopped at (last `Break at` / `Decompilation complete` up to the first
# differing line), a ghidra-rs error if it gave one, the address of the first differing op and the
# `Basic Block` it is in, and CONTEXT (default 5) lines around it from both sides in two columns
# (WIDTH characters each, default 80; `|` marks differing lines, `>>` the first one).
set -e
ref=$1 rs=$2
[ -f "$ref" ] && [ -f "$rs" ] || { echo "usage: decomp-show.sh <ref-file> <rust-file>" >&2; exit 1; }
cmp -s "$ref" "$rs" && { echo "  identical"; exit 0; }
# first differing line: cmp's line number (at EOF, the line after the shorter file's last)
c=$(cmp "$ref" "$rs" 2>&1 || true)
n=$(grep -o 'line [0-9]*' <<<"$c" | grep -o '[0-9]*')
grep -q EOF <<<"$c" && n=$((n + 1))

last() { r=$(head -n "$n" "$2" | grep "$1" | tail -1 || true); echo "${r:-(none)}"; }
echo "  break: ref: $(last '^Break at\|^Decompilation complete' "$ref") | rust: $(last '^Break at\|^Decompilation complete' "$rs")"
e=$(grep -m1 'not implemented\|not supported\|not ported' "$rs" || grep -m1 'ERROR\|^error\|Unable to proceed' "$rs" || true)
e=${e#error: } e=${e#Low-level ERROR: }
if grep -q 'not implemented\|not supported\|not ported' <<<"$e"; then
    echo "  rust: not supported: $e"
elif [ -n "$e" ]; then
    echo "  rust: error: $e"
fi
op=$(sed -n "${n}p" "$ref" | grep -o '^0x[0-9a-f]*:[0-9a-f]*' || sed -n "${n}p" "$rs" | grep -o '^0x[0-9a-f]*:[0-9a-f]*' || true)
echo "  first difference: line $n, op ${op:-(none)}, ref in $(last '^Basic Block' "$ref") | rust in $(last '^Basic Block' "$rs")"
awk -v n="$n" -v k="${CONTEXT:-5}" -v w="${WIDTH:-80}" '
    { f = FILENAME == ARGV[1] ? 1 : 2 }
    { l[f, FNR] = $0; if (FNR > m[f]) m[f] = FNR }
    END {
        fmt = "  %-2s %-" w "s %s %s\n"
        printf fmt, "", "ref", "|", "rust"
        for (i = n - k; i <= n + k; i++) {
            if (i < 1 || (i > m[1] && i > m[2])) continue
            a = l[1, i]; b = l[2, i]
            gsub(/\t/, " ", a); gsub(/\t/, " ", b); a = substr(a, 1, w); b = substr(b, 1, w)
            printf fmt, (i == n ? ">>" : ""), a, (l[1, i] == l[2, i] ? " " : "|"), b
        }
    }' "$ref" "$rs"
