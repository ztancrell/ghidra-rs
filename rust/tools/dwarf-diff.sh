#!/bin/sh
# The DWARF importer against Java: builds the test programs of tools/dwarf/ (GCC and clang,
# -gdwarf-3, as Hatred's DWARF 3), runs DumpDwarf.java (12.3, -noanalysis) and
# `ghidra-rs dwarf` on each and compares the two dumps by key (a type's path, a function's
# entry): identical, different, missing (only in Java), extra (only in ghidra-rs).
#   tools/dwarf-diff.sh [build|java|rust|cmp]...   (default: all four)
#   DWARF_BINS="name=/path/to/elf ..." replaces the built corpus (paths without spaces: link
#   others under target/dwarf/ first).
# Outputs: target/dwarf/<name>.java, <name>.rs, <name>.cmp. Needs GHIDRA (the 12.3 build) and
# JAVA_HOME as in README "The 12.3 reference".
set -eu
cd "$(dirname "$0")/.."
OUT=target/dwarf
mkdir -p "$OUT"
steps=${*:-build java rust cmp}
names="c1-gcc cpp1-gcc c1-clang cpp1-clang c2-gcc c2-clang cpp2-gcc cpp2-clang cpp3-gcc cpp3-clang"
bins=${DWARF_BINS:-$(for n in $names; do printf "%s=%s/%s " "$n" "$OUT" "$n"; done)}
GHIDRA_RS=${GHIDRA_RS:-target/release/ghidra-rs}

for step in $steps; do
    case $step in
    build)
        gcc -g -gdwarf-3 -O0 -o "$OUT/c1-gcc" tools/dwarf/c1.c
        g++ -std=c++17 -g -gdwarf-3 -O0 -o "$OUT/cpp1-gcc" tools/dwarf/cpp1.cpp
        clang -g -gdwarf-3 -O0 -o "$OUT/c1-clang" tools/dwarf/c1.c
        clang++ -std=c++17 -g -gdwarf-3 -O0 -o "$OUT/cpp1-clang" tools/dwarf/cpp1.cpp
        gcc -g -gdwarf-3 -O2 -o "$OUT/c2-gcc" tools/dwarf/c2a.c tools/dwarf/c2b.c
        clang -g -gdwarf-3 -O2 -o "$OUT/c2-clang" tools/dwarf/c2a.c tools/dwarf/c2b.c
        g++ -std=c++17 -g -gdwarf-3 -O2 -o "$OUT/cpp2-gcc" tools/dwarf/cpp2.cpp
        clang++ -std=c++17 -g -gdwarf-3 -O2 -o "$OUT/cpp2-clang" tools/dwarf/cpp2.cpp
        g++ -std=c++17 -g -gdwarf-3 -O2 -o "$OUT/cpp3-gcc" tools/dwarf/cpp3.cpp
        clang++ -std=c++17 -g -gdwarf-3 -O2 -o "$OUT/cpp3-clang" tools/dwarf/cpp3.cpp
        ;;
    java)
        for nb in $bins; do
            n=${nb%%=*} b=${nb#*=}
            rm -rf "$OUT/proj-$n"
            mkdir -p "$OUT/proj-$n"
            "${GHIDRA:-/opt/ghidra}/support/analyzeHeadless" "$OUT/proj-$n" p -import "$b" \
                -noanalysis -scriptPath tools/ghidra -postScript DumpDwarf.java "$PWD/$OUT/$n.java" \
                -deleteProject >"$OUT/$n.java.log" 2>&1 || { echo "$n: java failed, see $OUT/$n.java.log"; continue; }
            rm -rf "$OUT/proj-$n"
        done
        ;;
    rust)
        for nb in $bins; do
            n=${nb%%=*} b=${nb#*=}
            "$GHIDRA_RS" dwarf "$b" "$OUT/$n.rs"
        done
        ;;
    cmp)
        for nb in $bins; do
            n=${nb%%=*}
            [ -f "$OUT/$n.java" ] && [ -f "$OUT/$n.rs" ] || { echo "$n: missing dump"; continue; }
            # key = first field up to the tab; same line = identical
            awk -F'\t' -v n="$n" '
                FNR == NR { j[$1] = $0; next }
                { r[$1] = $0 }
                END {
                    for (k in j) { t = substr(k, 1, 1)
                        if (!(k in r)) { miss[t]++; print "missing\t" j[k] > (n ".cmp") }
                        else if (r[k] == j[k]) same[t]++
                        else { diff[t]++; print "java\t" j[k] "\nrust\t" r[k] > (n ".cmp") } }
                    for (k in r) if (!(k in j)) { t = substr(k, 1, 1); extra[t]++; print "extra\t" r[k] > (n ".cmp") }
                    printf "%s: types identical %d different %d missing %d extra %d; functions identical %d different %d missing %d extra %d\n",
                        n, same["T"], diff["T"], miss["T"], extra["T"], same["F"], diff["F"], miss["F"], extra["F"]
                }' "$OUT/$n.java" "$OUT/$n.rs"
            [ -f "$n.cmp" ] && mv "$n.cmp" "$OUT/$n.cmp" || : >"$OUT/$n.cmp"
        done
        ;;
    esac
done
