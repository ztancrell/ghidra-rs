#!/bin/sh
# Rebuild Ghidra's C++ SLEIGH compiler out of tree (in target/sleigh-build) and use it to
# compile x86-64.slaspec, x86.slaspec and MIPS's mips32le.slaspec into .sla files next to the specs, where
# Ghidra keeps them (*.sla is gitignored upstream). The upstream source tree is not modified.
# It also compiles the PSP's allegrex.slaspec (rust/processors/Allegrex, from ghidra-allegrex).
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
for spec in "$proc/x86/data/languages/x86-64" "$proc/x86/data/languages/x86" "$proc/MIPS/data/languages/mips32le" \
    "$here/processors/Allegrex/data/languages/allegrex"; do
    "$build/sleigh_opt" "$spec.slaspec" "$spec.sla"
    ls -l "$spec.sla"
done
