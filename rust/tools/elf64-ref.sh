#!/bin/sh
# The ELF64 analysis check (rust/README.md, "ELF64 analysis"): builds the GCC x86-64 test
# programs of tools/corpus/elf64 under rust/target/elf64/ (non-PIE, PIE, and PIE with
# -fcf-protection=full, whose .plt.sec thunks start ENDBR64; without -g: DWARF
# is not read by ghidra-rs yet, and Java takes no-return flags from it), runs Java's plain
# auto-analysis on each (DumpPurges.java; once, the output is kept) and ghidra-rs
# `analyze --purges`, and compares the function lists.
#
# Java's functions in its artificial EXTERNAL block are left out, and a thunk of one is
# written `EXTERNAL`, as ghidra-rs writes a jump through an import slot. Columns: entry, purge,
# thunk, body min, body max, address count, no-return.
#
# Environment: GHIDRA (the 12.3 install), JAVA_HOME, GHIDRA_RS (default the release build),
# SLA (default the install's x86-64.sla). Extra binaries may be given as arguments.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
out=$(cd "$here/.." && pwd)/target/elf64
rs=${GHIDRA_RS:-$out/../release/ghidra-rs}
sla=${SLA:-$GHIDRA/Ghidra/Processors/x86/data/languages/x86-64.sla}
mkdir -p "$out"
bins=""
for c in "$here"/corpus/elf64/*.c; do
    t=$(basename "$c" .c)
    gcc -O2 -fno-pie -no-pie -fcf-protection=none -o "$out/$t" "$c"
    gcc -O2 -fcf-protection=none -o "$out/$t-pie" "$c"
    gcc -O2 -fcf-protection=full -o "$out/$t-cet" "$c"
    bins="$bins $out/$t $out/$t-pie $out/$t-cet"
done
for b in $bins "$@"; do
    t=$(basename "$b")
    if [ ! -s "$out/$t.java" ]; then
        mkdir -p "$out/proj-$t"
        "$GHIDRA/support/analyzeHeadless" "$out/proj-$t" p -import "$b" -scriptPath "$here/ghidra" \
            -postScript DumpPurges.java "$out/$t.java" >"$out/$t.java.log" 2>&1
        rm -r "$out/proj-$t"
    fi
    "$rs" analyze "$b" --sla "$sla" --purges "$out/$t.rs" 2>"$out/$t.rs.log" >/dev/null
    awk '$3 ~ /^EXTERNAL:/ { ext[$1] = 1; next } { rows[++n] = $0 }
        END { for (i = 1; i <= n; i++) { split(rows[i], f, " "); if (f[3] in ext) sub(" " f[3] " ", " EXTERNAL ", rows[i]); print rows[i] } }' \
        "$out/$t.java" >"$out/$t.java.n"
    j=$(wc -l <"$out/$t.java.n")
    r=$(wc -l <"$out/$t.rs")
    same=$(comm -12 "$out/$t.java.n" "$out/$t.rs" | wc -l)
    both=$(cut -d' ' -f1 "$out/$t.java.n" | comm -12 - "$(cut -d' ' -f1 "$out/$t.rs" >"$out/$t.e"; echo "$out/$t.e")" | wc -l)
    # the same less the purge column
    nop=$(cut -d' ' -f1,3- "$out/$t.java.n" | comm -12 - "$(cut -d' ' -f1,3- "$out/$t.rs" >"$out/$t.e"; echo "$out/$t.e")" | wc -l)
    echo "$t: java $j, ghidra-rs $r, entries in both $both, identical $same, identical but the purge $nop"
    rm -f "$out/$t.e"
done
