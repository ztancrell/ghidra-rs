#!/bin/bash
# Java 12.3 on Hatred for the full decompile comparison: one headless run that imports the
# binary, auto-analyzes it, writes the facts (tools/ghidra/ExportFacts.java) and Java's C of each
# function of a list (tools/ghidra/DecompileRef.java, the options and 60 s of ghidra-diff.sh's
# Java side), in a Linux container on the MacBook (the Ghidra there is the Linux DEV build). The
# project is kept: a later run skips the import and the analysis (-process -noanalysis
# -readOnly) and does only what is missing, the facts or the C of the list's addresses that
# have no file (delete a file to capture it again).
#
#   hatred-java-run.sh [<list>]   list: a file of addresses (one per line, `#` comments, as a
#                                 corpus of ghidra-diff.sh), or `all` for every function Java
#                                 has; no list: the import, the analysis and the facts only
#
#   BIN      the binary (default ~/hatred/Hatred-Linux-Shipping)
#   OUT      output directory (default ~/ghidra-rs/rust/target/hatred-java2):
#            <binary>.java.facts, java/<list>/<address> (the C, or Java's error message),
#            java/<list>.status (`<address> <ok|failed|timeout|nofunc> <milliseconds>` per
#            function), java.log (the import run; rerun.log for a later one: the DecompileRef
#            progress lines are there), result.txt (exit status, seconds and the container's
#            memory.peak of each run), project (written when the import run exits 0: its
#            presence makes the next run a rerun). OUT is a GHIDRA_REF for ghidra-diff.sh
#   GHIDRA   the Ghidra 12.3 install (default ~/ghidra-rs/rust/target/x64f/ghidra_12.3_DEV)
#   GHIDRA_HEADLESS_MAXMEM  Java's heap (default 24G; the last Hatred run peaked at 26.0 GB)
#   IMAGE    the container image (default x64f-linux25: Arch with jdk25-openjdk, built when
#            missing). Docker must be reachable (`colima start`; this script does not start it).
#            Paths are mounted as they are ($HOME); the project is on the docker volume
#            hatred-java2 (/work/proj in the container), not on the host mount
#   DOCKER=0 no container: this machine's analyzeHeadless (Java from JAVA_HOME or PATH)
#   PROJ     the project directory with DOCKER=0 (default OUT/proj; Ghidra refuses a path
#            component starting with `.`, as a worktree under .claude has)
set -e
rust=$(cd "$(dirname "$0")/.." && pwd)
bin=${BIN:-$HOME/hatred/Hatred-Linux-Shipping}
out=${OUT:-$HOME/ghidra-rs/rust/target/hatred-java2}
ghidra=${GHIDRA:-$HOME/ghidra-rs/rust/target/x64f/ghidra_12.3_DEV}
image=${IMAGE:-x64f-linux25}
export GHIDRA_HEADLESS_MAXMEM=${GHIDRA_HEADLESS_MAXMEM:-24G}
[ -f "$bin" ] || { echo "no binary $bin" >&2; exit 1; }
[ -x "$ghidra/support/analyzeHeadless" ] || { echo "no Ghidra at $ghidra" >&2; exit 1; }
n=$(basename "$bin")
facts=$out/$n.java.facts
mkdir -p "$out"

scripts=()
[ -s "$facts" ] || scripts+=(-postScript ExportFacts.java "$facts.part")
if [ -n "$1" ]; then
    name=$(basename "$1" .txt)
    mkdir -p "$out/java/$name"
    if [ "$1" = all ]; then
        scripts+=(-postScript DecompileRef.java "$out/java/all" all)
    else
        [ -f "$1" ] || { echo "no list $1" >&2; exit 1; }
        need=$out/java/$name.need
        grep -v '^#' "$1" | awk 'NF { print $1 }' | while read -r a; do [ -f "$out/java/$name/$a" ] || echo "$a"; done > "$need"
        [ -s "$need" ] && scripts+=(-postScript DecompileRef.java "$out/java/$name" "@$need")
    fi
fi
[ ${#scripts[@]} = 0 ] && { echo "$n: nothing to do: the facts and every file of the list are there"; exit 0; }

if [ "$DOCKER" = 0 ]; then
    proj=${PROJ:-$out/proj}
    case $proj in */.*) echo "PROJ $proj: Ghidra refuses a path component starting with '.'" >&2; exit 1 ;; esac
    pre=()
else
    proj=/work/proj
    docker info > /dev/null 2>&1 || { echo "docker is not reachable: colima start" >&2; exit 1; }
    docker image inspect "$image" > /dev/null 2>&1 ||
        printf 'FROM archlinux:latest\nRUN pacman -Syu --noconfirm jdk25-openjdk && pacman -Scc --noconfirm\n' | docker build -t "$image" -
    pre=(docker run --rm -v "$HOME:$HOME" -v hatred-java2:/work -e GHIDRA_HEADLESS_MAXMEM
        -e JAVA_HOME=/usr/lib/jvm/java-25-openjdk "$image")
fi
if [ -f "$out/project" ]; then
    log=$out/rerun.log
    mode=(-process "$n" -noanalysis -readOnly)
else
    log=$out/java.log
    mode=(-import "$bin" -overwrite)
fi
# the run, in the container or not: the log, then one result line (memory.peak is the
# container's cgroup; empty without one)
# shellcheck disable=SC2016
res=$("${pre[@]}" bash -c '[ -n "$JAVA_HOME" ] && PATH=$JAVA_HOME/bin:$PATH
    log=$1; shift; mkdir -p "$2"; s=$(date +%s); "$@" > "$log" 2>&1
    echo "exit $? seconds $(($(date +%s) - s)) memory.peak $(cat /sys/fs/cgroup/memory.peak 2>/dev/null)"' _ \
    "$log" "$ghidra/support/analyzeHeadless" "$proj" p "${mode[@]}" -scriptPath "$rust/tools/ghidra" "${scripts[@]}") || true
echo "$(date +%F\ %T) $(basename "$log") $res" | tee -a "$out/result.txt"
case $res in "exit 0 "*) ;; *) echo "$n: headless Ghidra failed: see $log" >&2; exit 1 ;; esac
# the project is saved (and kept) even when a script failed after the analysis
if [ ! -f "$out/project" ] && grep -q "Save succeeded" "$log"; then echo "$n" > "$out/project"; fi
if grep -q -e 'SCRIPT ERROR' -e 'Import failed' -e 'ERROR REPORT' "$log"; then echo "$n: Java failed: see $log" >&2; exit 1; fi
[ -f "$facts.part" ] && mv "$facts.part" "$facts"
[ -n "$name" ] && [ -f "$out/java/$name.status" ] && echo "$name: $(cut -f2 "$out/java/$name.status" | sort | uniq -c | awk '{ printf "%s%s %s", s, $2, $1; s = ", " }')"
exit 0
