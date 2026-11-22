#!/bin/bash
# `analyze --facts` on ELF x86-64 against Java 12.3: for each binary, Java's plain auto-analysis
# (DWARF included) with tools/ghidra/ExportFacts.java, run once and kept, then ghidra-rs's facts
# and tools/facts-diff.sh on the two. Binaries: the arguments, default the non-PIE, PIE and -cet
# builds of tools/corpus/elf64/*.c and tools/dwarf/cpp*.cpp (-g -gdwarf-3 -O2, clang++ and g++)
# under OUT (default rust/target/x64/facts). Prints each binary's facts-diff table.
#
#   GHIDRA   the Java Ghidra install (default /opt/ghidra)
#   PROJ     where the Java projects go (default OUT; Ghidra refuses a path component starting
#            with ".", as a worktree under .claude has)
set -e
rust=$(cd "$(dirname "$0")/.." && pwd)
OUT=${OUT:-$rust/target/x64/facts}
mkdir -p "$OUT/bin"
cd "$rust"
bins=("$@")
if [ ${#bins[@]} = 0 ]; then
    for c in tools/corpus/elf64/*.c; do
        t=$(basename "$c" .c)
        gcc -O2 -fno-pie -no-pie -fcf-protection=none -o "$OUT/bin/$t" "$c"
        gcc -O2 -fcf-protection=none -o "$OUT/bin/$t-pie" "$c"
        gcc -O2 -fcf-protection=full -o "$OUT/bin/$t-cet" "$c"
        bins+=("$OUT/bin/$t" "$OUT/bin/$t-pie" "$OUT/bin/$t-cet")
    done
    for c in tools/dwarf/cpp*.cpp; do
        t=$(basename "$c" .cpp)
        clang++ -std=c++17 -g -gdwarf-3 -O2 -o "$OUT/bin/$t-clang" "$c" 2>/dev/null
        g++ -std=c++17 -g -gdwarf-3 -O2 -o "$OUT/bin/$t-gcc" "$c" 2>/dev/null
        bins+=("$OUT/bin/$t-clang" "$OUT/bin/$t-gcc")
    done
fi
[ -x target/release/ghidra-rs ] || cargo build --release
for b in "${bins[@]}"; do
    n=$(basename "$b")
    if [ ! -s "$OUT/$n.java.facts" ]; then
        rm -rf "${PROJ:-$OUT}/proj-$n"
        mkdir -p "${PROJ:-$OUT}/proj-$n"
        GHIDRA_HEADLESS_MAXMEM=${GHIDRA_HEADLESS_MAXMEM:-3G} "${GHIDRA:-/opt/ghidra}/support/analyzeHeadless" \
            "${PROJ:-$OUT}/proj-$n" p -import "$b" -scriptPath "$rust/tools/ghidra" -deleteProject \
            -postScript ExportFacts.java "$OUT/$n.java.facts.part" > "$OUT/$n.java.log" 2>&1
        grep -q 'SCRIPT ERROR' "$OUT/$n.java.log" && { echo "$n: Java failed, see $OUT/$n.java.log" >&2; continue; }
        mv "$OUT/$n.java.facts.part" "$OUT/$n.java.facts"
    fi
    target/release/ghidra-rs analyze "$b" --facts "$OUT/$n.facts" > "$OUT/$n.rs.log" 2>&1 ||
        { echo "$n: ghidra-rs failed: $(tail -1 "$OUT/$n.rs.log")"; continue; }
    echo "== $n"
    SAMPLES=0 OUT=$OUT/diff-$n tools/facts-diff.sh "$OUT/$n.facts" "$OUT/$n.java.facts"
done
