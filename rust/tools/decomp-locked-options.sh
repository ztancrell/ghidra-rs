#!/bin/sh
# Stage S6 locked-prototype check: write an OPTIONS file for decomp-diff.sh that is
# tools/corpus/s6-options.txt plus `parse line extern <type> <name>(void);` for every function
# of the mercs2 prelude with a C-identifier name (unnamed ones as func_0x........), so the
# decompiled function and every callee have a locked prototype.
#
#   decomp-locked-options.sh <type> <out>      e.g. void, int4
#   DECOMP_RAW_EXTRA=1 BREAK=assignhigh OPTIONS=<out> rust/tools/decomp-diff.sh m500
set -e
rust=$(cd "$(dirname "$0")/.." && pwd)
prelude=${PRELUDE:-$rust/target/decomp-check/mercs2.prelude}
cat "$rust/tools/corpus/s6-options.txt" > "$2"
awk -v t="$1" '$1=="map" && $2=="function" {
    n = (NF >= 4 && $4 != "nocode") ? $4 : "func_" $3
    if (n ~ /^[A-Za-z_][A-Za-z0-9_]*$/ && !seen[n]++) print "parse line extern " t " " n "(void);"
}' "$prelude" >> "$2"
