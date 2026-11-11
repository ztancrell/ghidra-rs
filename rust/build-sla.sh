#!/bin/sh
# Rebuild Ghidra's C++ SLEIGH compiler out of tree (in target/sleigh-build) and use it to
# compile x86-64.slaspec into x86-64.sla next to the spec, where Ghidra keeps it (*.sla is
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
make -C "$build" -j"$(nproc)" -o xml.cc -o pcodeparse.cc -o slghparse.cc -o slghparse.hh -o slghscan.cc sleigh_opt
"$build/sleigh_opt" "$lang/x86-64.slaspec" "$lang/x86-64.sla"
ls -l "$lang/x86-64.sla"
