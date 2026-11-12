#!/bin/sh
# Build the milestone 3 reference: Ghidra's console decompiler decomp_dbg and its datatest runner
# decomp_test_dbg, from the upstream C++ sources copied into rust/target/decomp-build, with
# rust/tools/decomp-ref.patch applied (print raw also shows types and high variables when
# DECOMP_RAW_EXTRA is set). The upstream tree is not modified. Builds x86.sla first when it is
# missing: decomp_dbg finds it through SLEIGHHOME (the repository root).
set -e
here=$(cd "$(dirname "$0")/.." && pwd)
root=$(cd "$here/.." && pwd)
src="$root/Ghidra/Features/Decompiler/src/decompile/cpp"
build="$here/target/decomp-build"
[ -f "$root/Ghidra/Processors/x86/data/languages/x86.sla" ] || "$here/build-sla.sh"
mkdir -p "$build"
cp "$src"/*.cc "$src"/*.hh "$src"/*.h "$src"/*.y "$src"/*.l "$src"/Makefile "$build"/
patch -s -d "$build" -p1 < "$here/tools/decomp-ref.patch"
# -o: use the checked-in bison/flex outputs instead of regenerating them
make -C "$build" -j"$(nproc)" -o xml.cc -o pcodeparse.cc -o slghparse.cc -o slghparse.hh -o slghscan.cc \
    -o grammar.cc -o ruleparse.cc decomp_dbg decomp_test_dbg
ls -l "$build/decomp_dbg" "$build/decomp_test_dbg"
