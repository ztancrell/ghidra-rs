#!/bin/bash
# Draw corpus M500 (500 .text functions of mercs2) with a fixed seed and print it; the
# committed list is rust/tools/corpus/m500.txt. Needs GNU shuf (its output for a given
# --random-source is fixed). Usage: decomp-corpus.sh <mercs2>/build/functions.csv > m500.txt
set -e
csv=${1:?usage: decomp-corpus.sh <functions.csv>}
echo "# M500: 500 .text functions (0x401000-0xb05000) of mercs2 build/functions.csv, drawn by rust/tools/decomp-corpus.sh (seed 20261112)"
awk -F, 'NR > 1 { a = strtonum($1); if (a >= 0x401000 && a < 0xb05000) printf "0x%x\n", a }' "$csv" |
    shuf -n 500 --random-source=<(yes 20261112) | sort
