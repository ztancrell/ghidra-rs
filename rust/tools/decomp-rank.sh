#!/bin/bash
# Rank a decomp-diff.sh corpus from simplest to hardest, for running it easy-first (ORDER=easy).
#
#   decomp-rank.sh <corpus>        corpus: m8, m500, or a file of addresses (as decomp-diff.sh)
#
# Runs decomp-diff.sh at `break start funclink` (outputs in rust/target/decomp-check/<corpus>-funclink/)
# and counts, in ghidra-rs's `print raw`, the basic blocks and the loops: back edges, a `Block_N`
# branch target whose index is not above the block it is in (blocks print in reverse post-order).
# Sorts by loops, then blocks (ties keep corpus order); functions with no output go last.
# Writes rust/target/decomp-check/<corpus>.ranked and prints it: `0x401000 # 4 blocks 0 loops`.
set -e
rust=$(cd "$(dirname "$0")/.." && pwd)
corpus=$1
[ -f "$corpus" ] || corpus=$rust/tools/corpus/$1.txt
[ -f "$corpus" ] || { echo "usage: decomp-rank.sh <corpus>" >&2; exit 1; }
name=$(basename "$corpus" .txt)
chk=$rust/target/decomp-check
mkdir -p "$chk"
cp "$corpus" "$chk/$name-funclink.txt"
env -u ORDER -u STOP -u VERBOSE -u CONTINUES -u OPTIONS -u OUT BREAK=funclink PRINT='print raw' \
    "$rust/tools/decomp-diff.sh" "$chk/$name-funclink.txt" >/dev/null
for a in $(grep -v '^#' "$corpus" | awk 'NF { print $1 }'); do
    awk -v a="$a" '
        /^Basic Block / { b = $3; nb++ }
        /^0x.*Block_[0-9]/ {
            s = $0
            while (match(s, /Block_[0-9]+/)) {
                if (substr(s, RSTART + 6, RLENGTH - 6) + 0 <= b) loops++
                s = substr(s, RSTART + RLENGTH)
            }
        }
        END { if (nb) print loops + 0, nb, a " # " nb " blocks " loops + 0 " loops"; else print 1e9, 0, a " # no funclink output" }
    ' "$chk/$name-funclink/rust/$a" 2>/dev/null || echo "1e9 0 $a # no funclink output"
done | sort -s -g -k1,1 -k2,2 | cut -d' ' -f3- > "$chk/$name.ranked"
cat "$chk/$name.ranked"
