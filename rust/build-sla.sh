#!/bin/sh
# Rebuild Ghidra's C++ SLEIGH compiler out of tree (in target/sleigh-build) and use it to
# compile x86-64.slaspec and x86.slaspec into .sla files next to the specs, where Ghidra keeps them (*.sla is
# gitignored upstream). The upstream source tree is not modified.
set -e
here=$(cd "$(dirname "$0")" && pwd)
root="$here/.."
src="$root/Ghidra/Features/Decompiler/src/decompile/cpp"
lang="$root/Ghidra/Processors/x86/data/languages"
build="$here/target/sleigh-build"
mkdir -p "$build"
cp "$src"/*.cc "$src"/*.hh "$src"/*.h "$src"/*.y "$src"/*.l "$src"/Makefile "$build"/
# -o: use the checked-in bison/flex outputs instead of regenerating them
make -C "$build" -j"$(nproc 2>/dev/null || sysctl -n hw.ncpu)" -o xml.cc -o pcodeparse.cc -o slghparse.cc -o slghparse.hh -o slghscan.cc sleigh_opt
for spec in x86-64 x86; do
    "$build/sleigh_opt" "$lang/$spec.slaspec" "$lang/$spec.sla"
done
ls -l "$lang/x86-64.sla" "$lang/x86.sla"
