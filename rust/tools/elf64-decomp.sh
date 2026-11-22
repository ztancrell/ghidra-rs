#!/bin/bash
# The decompiler on ELF x86-64 against the reference decomp_dbg (x86:LE:64:default:gcc), per
# function, with decomp-diff.sh: builds tools/corpus/elf64/*.c (gcc -O2: non-PIE, PIE, PIE with
# -fcf-protection=full as -cet) and tools/dwarf/cpp*.cpp (clang++ and g++ -O2) into OUT (default
# rust/target/x64/elf64), writes each binary's prelude (`analyze --decomp-prelude`) and runs every
# function the prelude maps with code. Extra binaries may be given as arguments. Prints, per
# binary, decomp-diff.sh's `reference ran` and `identical` lines.
set -e
rust=$(cd "$(dirname "$0")/.." && pwd)
OUT=${OUT:-$rust/target/x64/elf64}
mkdir -p "$OUT/bin"
cd "$rust"
bins=
for c in tools/corpus/elf64/*.c; do
    t=$(basename "$c" .c)
    gcc -O2 -fno-pie -no-pie -fcf-protection=none -o "$OUT/bin/$t" "$c"
    gcc -O2 -fcf-protection=none -o "$OUT/bin/$t-pie" "$c"
    gcc -O2 -fcf-protection=full -o "$OUT/bin/$t-cet" "$c"
    bins="$bins $OUT/bin/$t $OUT/bin/$t-pie $OUT/bin/$t-cet"
done
for c in tools/dwarf/cpp*.cpp; do
    t=$(basename "$c" .cpp)
    clang++ -std=c++17 -O2 -o "$OUT/bin/$t-clang" "$c"
    g++ -std=c++17 -O2 -o "$OUT/bin/$t-gcc" "$c"
    bins="$bins $OUT/bin/$t-clang $OUT/bin/$t-gcc"
done
[ -x target/release/ghidra-rs ] || cargo build --release
for b in $bins "$@"; do
    n=$(basename "$b")
    target/release/ghidra-rs analyze "$b" --decomp-prelude "$OUT/$n.prelude" >/dev/null 2>&1
    grep '^map function' "$OUT/$n.prelude" | grep -v nocode | awk '{ print $3 }' > "$OUT/$n.txt"
    BIN=$b PRELUDE=$OUT/$n.prelude OUT=$OUT/check/$n tools/decomp-diff.sh "$OUT/$n.txt" > "$OUT/$n.diff" 2>&1 || true
    grep -E 'reference ran|identical' "$OUT/$n.diff"
done
