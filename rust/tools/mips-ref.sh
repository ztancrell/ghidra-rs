#!/bin/sh
# The MIPS-3 check (rust/README.md, "Function discovery on MIPS (MIPS-3)"): Java's plain
# auto-analysis of a PSP PRX, against `ghidra-rs analyze --purges`.
#
# Java cannot relocate a PRX, so it gets the image ghidra-rs loads: `ghidra-rs prx-elf` writes
# it, relocated at 0x08804000, as a plain ELF, which Java imports as Allegrex:LE:32:default
# (with the extension present its "PSP Executable (ELF)" loader takes the file, not the stock
# ELF loader). That language is ghidra-allegrex's: its release for the installed
# Ghidra (https://github.com/kotcrab/ghidra-allegrex, fetched with `gh`, read-only) is unpacked
# into a throwaway settings directory under rust/target/mips-ref (XDG_CONFIG_HOME and
# XDG_CACHE_HOME point there), never into ~/.config/ghidra or the install.
#
# Usage: tools/mips-ref.sh <psp-prx>
# Environment: GHIDRA (default /opt/ghidra), JAVA_HOME, GHIDRA_RS (default the release build),
# ALLEGREX_TAG and ALLEGREX_ZIP (the release of ghidra-allegrex: default v21.6 and its zip for
# Ghidra 12.2), OUT (default rust/target/mips-ref; Ghidra refuses a project path with a
# component starting with `.`, so in a worktree under .claude/ set OUT to a path without one).
# Java's output (<name>.java, DumpPurges.java's lines) is kept: delete it to run Java again.
# The Ghidra project is kept too (OUT/proj-<name>), for further scripts; delete it when done.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
out=${OUT:-$(cd "$here/.." && pwd)/target/mips-ref}
rs=${GHIDRA_RS:-$here/../target/release/ghidra-rs}
ghidra=${GHIDRA:-/opt/ghidra}
tag=${ALLEGREX_TAG:-v21.6}
zip=${ALLEGREX_ZIP:-ghidra_12.2_PUBLIC_20261031_ghidra-allegrex.zip}
b=$1
t=$(basename "$b")
mkdir -p "$out/dl"
"$rs" prx-elf "$b" "$out/$t.elf"
if [ ! -s "$out/$t.java" ]; then
    [ -s "$out/dl/$zip" ] || gh release download "$tag" -R kotcrab/ghidra-allegrex -p "$zip" -D "$out/dl"
    ver=$(sed -n 's/^application.version=//p' "$ghidra/Ghidra/application.properties")
    rel=$(sed -n 's/^application.release.name=//p' "$ghidra/Ghidra/application.properties")
    ext="$out/config/ghidra/ghidra_${ver}_$rel/Extensions"
    mkdir -p "$ext" "$out/cache" "$out/proj-$t"
    [ -d "$ext/ghidra-allegrex" ] || unzip -q "$out/dl/$zip" -d "$ext"
    XDG_CONFIG_HOME="$out/config" XDG_CACHE_HOME="$out/cache" \
        "$ghidra/support/analyzeHeadless" "$out/proj-$t" p -import "$out/$t.elf" \
        -processor Allegrex:LE:32:default -cspec default -scriptPath "$here/ghidra" \
        -postScript DumpPurges.java "$out/$t.java" >"$out/$t.java.log" 2>&1
fi
"$rs" analyze "$b" --purges "$out/$t.rs" 2>"$out/$t.rs.log" >/dev/null
cut -d' ' -f1 "$out/$t.java" | sort >"$out/$t.java.e"
cut -d' ' -f1 "$out/$t.rs" | sort >"$out/$t.rs.e"
comm -13 "$out/$t.java.e" "$out/$t.rs.e" >"$out/$t.only-rs"
comm -23 "$out/$t.java.e" "$out/$t.rs.e" >"$out/$t.only-java"
sort "$out/$t.java" >"$out/$t.java.s"
sort "$out/$t.rs" >"$out/$t.rs.s"
echo "$t: java $(wc -l <"$out/$t.java"), ghidra-rs $(wc -l <"$out/$t.rs"), entries in both $(comm -12 "$out/$t.java.e" "$out/$t.rs.e" | wc -l), only ghidra-rs $(wc -l <"$out/$t.only-rs"), only java $(wc -l <"$out/$t.only-java"), identical lines $(comm -12 "$out/$t.java.s" "$out/$t.rs.s" | wc -l)"
rm -f "$out/$t.java.e" "$out/$t.rs.e" "$out/$t.java.s" "$out/$t.rs.s"
