#!/bin/sh
# Build the milestone 3 reference: Ghidra's console decompiler decomp_dbg and its datatest runner
# decomp_test_dbg, from the upstream C++ sources copied into rust/target/decomp-build, with
# rust/tools/decomp-ref.patch applied (print raw also shows types and high variables, numbered by first appearance, when
# DECOMP_RAW_EXTRA is set). The upstream tree is not modified. Builds x86.sla first when it is
# missing: decomp_dbg finds it through SLEIGHHOME (the repository root).
#
# On macOS it builds with Homebrew GCC (REF_CXX, default g++-16) and libstdc++, never Apple's
# clang and libc++: stdsort.rs matches libstdc++'s order of equal keys, which libc++ does not
# keep. It fails when decomp_dbg does not link libstdc++.
set -e
here=$(cd "$(dirname "$0")/.." && pwd)
root=$(cd "$here/.." && pwd)
src="$root/Ghidra/Features/Decompiler/src/decompile/cpp"
build="${DECOMP_BUILD:-$here/target/decomp-build}"
[ -f "$root/Ghidra/Processors/x86/data/languages/x86.sla" ] || "$here/build-sla.sh"
mkdir -p "$build"
cp "$src"/*.cc "$src"/*.hh "$src"/*.h "$src"/*.y "$src"/*.l "$src"/Makefile "$build"/
patch -s -d "$build" -p1 < "$here/tools/decomp-ref.patch"
# -o: use the checked-in bison/flex outputs instead of regenerating them
set -- -o xml.cc -o pcodeparse.cc -o slghparse.cc -o slghparse.hh -o slghscan.cc -o grammar.cc -o ruleparse.cc
if [ "$(uname -s)" = Darwin ]; then
    # the Makefile's Darwin flags (-arch, -mmacosx-version-min) are Apple compiler flags; BFD
    # (the console's `load file`) from Homebrew binutils (keg-only; its libbfd.a lacks libiberty,
    # so the versioned dylib); no __TERMINAL__: tcgetattr on /dev/null fails there with an errno
    # other than ENOTTY and the console stops (on Linux it only sets is_terminal false)
    bu=${BINUTILS:-/usr/local/opt/binutils}
    set -- "$@" CXX="${REF_CXX:-g++-16} -std=c++11" ARCH_TYPE=-m64 \
        ADDITIONAL_FLAGS=-I$bu/include BFDLIB="$(echo "$bu"/lib/libbfd-*.dylib)" \
        COMMANDLINE_DEBUG=-DCPUI_DEBUG TEST_DEBUG=
fi
make -C "$build" -j"${JOBS:-$(nproc)}" "$@" decomp_dbg decomp_test_dbg
if [ "$(uname -s)" = Darwin ]; then
    otool -L "$build/decomp_dbg" | grep -q libstdc++ || { echo "decomp_dbg does not link libstdc++" >&2; exit 1; }
fi
ls -l "$build/decomp_dbg" "$build/decomp_test_dbg"
