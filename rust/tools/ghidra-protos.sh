#!/bin/bash
# The function prototypes of Ghidra's Windows data-type archive for `ghidra-rs analyze --facts
# --protos <file>` (stage S10): one headless run of tools/ghidra/ExportArchiveProtos.java. It
# reads the archive of the Ghidra install (Ghidra/Features/Base/data/typeinfo/win32), not a
# program: a scratch file is imported as raw x86:LE:32:default:windows bytes only to give the
# script a program of that language, in a project that is deleted afterwards. Run once per
# Ghidra version; the file holds for every 32-bit Windows program.
#
#   ghidra-protos.sh       writes $GHIDRA_REF/win32.protos unless it is there
#
#   ARCHIVE      the archive's name (default windows_vs12_32)
#   GHIDRA_REF, GHIDRA   as ghidra-diff.sh
# Writes only under GHIDRA_REF (default rust/target/ghidra-ref): win32.protos, protos.log.
set -e
rust=$(cd "$(dirname "$0")/.." && pwd)
ref=${GHIDRA_REF:-$rust/target/ghidra-ref}
case $ref in */.*) echo "GHIDRA_REF $ref: Ghidra refuses a path component starting with '.'" >&2; exit 1 ;; esac
[ "$(head -n 1 "$ref/win32.protos" 2>/dev/null)" = "ghidra-rs-protos 1" ] && exit 0
mkdir -p "$ref/protos-proj"
head -c 4096 /dev/zero > "$ref/protos-proj/scratch.bin"
GHIDRA_HEADLESS_MAXMEM=${GHIDRA_HEADLESS_MAXMEM:-4G} "${GHIDRA:-/opt/ghidra}/support/analyzeHeadless" \
    "$ref/protos-proj" protos -import "$ref/protos-proj/scratch.bin" -loader BinaryLoader \
    -processor x86:LE:32:default -cspec windows -noanalysis -deleteProject \
    -scriptPath "$rust/tools/ghidra" -postScript ExportArchiveProtos.java "$ref/win32.protos.part" \
    ${ARCHIVE:+"$ARCHIVE"} > "$ref/protos.log" 2>&1 || true
rm -rf "$ref/protos-proj"
if grep -q 'SCRIPT ERROR\|error:' "$ref/protos.log" || [ ! -s "$ref/win32.protos.part" ]; then
    echo "headless Ghidra failed: see $ref/protos.log" >&2
    exit 1
fi
mv "$ref/win32.protos.part" "$ref/win32.protos"
