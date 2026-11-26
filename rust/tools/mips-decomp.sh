#!/bin/bash
# The MIPS-4 check (rust/README.md, "The decompiler on MIPS (MIPS-4)"): the decompiler on a PSP
# PRX against the reference decomp_dbg, per function, with decomp-diff.sh.
#
# The system's libbfd reads no MIPS ELF, so both engines load the image `ghidra-rs prx-xml`
# writes (relocated at 0x08804000, a <binaryimage> of arch Allegrex:LE:32:default:default). The
# reference finds the language through `-s <dir>`: OUT/lang holds links to allegrex.sla, .pspec
# and .ldefs of rust/processors/Allegrex and a copy of allegrex.cspec without its
# <callotherfixup> elements. Those are `dynamic` (Java's AllegrexPcodeInjectLibrary supplies the
# p-code) and decomp_dbg stops at the first VFPU user op with "Missing dynamic inject"; without
# them the user ops stay CALLOTHER calls, which is how ghidra-rs reads the unmodified spec.
# The prelude maps every function `analyze --functions` finds, and names the import stubs the
# `jal`s of .text reach (`disasm` prints the name after such a `jal`).
#
# Usage: tools/mips-decomp.sh <psp-prx> [corpus]      (corpus: default tools/corpus/socom50.txt)
# Environment: OUT (default rust/target/mips-decomp), DECOMP_REF (the built decomp_dbg, default
# rust/target/decomp-build/decomp_dbg), and decomp-diff.sh's (PRINT defaults to `print C` here,
# REFCACHE to 0: the cache does not hash OUT/lang).
set -e
rust=$(cd "$(dirname "$0")/.." && pwd)
b=$1
corpus=${2:-$rust/tools/corpus/socom50.txt}
OUT=${OUT:-$rust/target/mips-decomp}
ref=${DECOMP_REF:-$rust/target/decomp-build/decomp_dbg}
rs=${GHIDRA_RS:-$rust/target/release/ghidra-rs}
lang=$rust/processors/Allegrex/data/languages
t=$(basename "$b")
mkdir -p "$OUT/lang"
for f in allegrex.sla allegrex.pspec allegrex.ldefs; do ln -sf "$lang/$f" "$OUT/lang/$f"; done
awk '/<callotherfixup/ { skip = 1 } !skip { print } /<\/callotherfixup>/ { skip = 0 }' "$lang/allegrex.cspec" > "$OUT/lang/allegrex.cspec"
printf '#!/bin/sh\nexec "%s" -s "%s" "$@"\n' "$ref" "$OUT/lang" > "$OUT/decomp_dbg"
chmod +x "$OUT/decomp_dbg"
"$rs" prx-xml "$b" "$OUT/$t.xml"
"$rs" analyze "$b" --functions "$OUT/$t.functions" >/dev/null 2>&1
{
    # every function, then the names (a later `map function` of an address renames it)
    awk -F, 'NR > 1 { print "map function " $1 }' "$OUT/$t.functions"
    "$rs" disasm "$b" --addr 8804000 --count 100000000 2>/dev/null |
        sed -n 's/.* jal 0x\([0-9a-f]*\)  *; \(.*\)$/\1 \2/p' | sort -u |
        awk '{ printf "map function 0x%08x %s\n", strtonum("0x" $1), $2 }'
} > "$OUT/$t.prelude"
rm -f "$OUT/$t.functions"
BIN=$OUT/$t.xml PRELUDE=$OUT/$t.prelude DECOMP=$OUT/decomp_dbg GHIDRA_RS=$rs PRINT=${PRINT:-print C} \
    REFCACHE=${REFCACHE:-0} OUT=$OUT/check "$rust/tools/decomp-diff.sh" "$corpus"
