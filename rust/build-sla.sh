#!/bin/sh
# Rebuild Ghidra's C++ SLEIGH compiler out of tree (in target/sleigh-build) and use it to
# compile x86-64.slaspec, x86.slaspec and MIPS's mips32le.slaspec into .sla files next to the specs, where
# Ghidra keeps them (*.sla is gitignored upstream). The upstream source tree is not modified.
# JOBS (as ~/.claude/bin/heavy-run exports it) sets the parallel jobs; default: all cores.
set -e
here=$(cd "$(dirname "$0")" && pwd)
root="$here/.."
src="$root/Ghidra/Features/Decompiler/src/decompile/cpp"
proc="$root/Ghidra/Processors"
build="$here/target/sleigh-build"
mkdir -p "$build"
cp "$src"/*.cc "$src"/*.hh "$src"/*.h "$src"/*.y "$src"/*.l "$src"/Makefile "$build"/
# -o: use the checked-in bison/flex outputs instead of regenerating them
make -C "$build" -j"${JOBS:-$(nproc)}" -o xml.cc -o pcodeparse.cc -o slghparse.cc -o slghparse.hh -o slghscan.cc sleigh_opt
for spec in x86/data/languages/x86-64 x86/data/languages/x86 MIPS/data/languages/mips32le; do
    "$build/sleigh_opt" "$proc/$spec.slaspec" "$proc/$spec.sla"
    ls -l "$proc/$spec.sla"
done
