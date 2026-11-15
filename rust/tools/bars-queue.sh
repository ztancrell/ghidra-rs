#!/bin/bash
# Shares one bars.sh pass between this machine and a second one over ssh (the Mac). One queue of
# the check-corpus pairs bars.sh would run (`LIST=1 bars.sh`), M500, r5d-adc and switch first,
# M8 last, and two workers, local and remote: each takes the next pair when it is free. Every
# summary line goes to one file here. No retry: a remote pair that ends without its summary line
# (ssh dropped, Mac gone) prints `lost: <check>-<corpus> on mac`, the remote worker stops, the
# rest runs locally, and the pass exits 1 so it never counts as complete.
#
#   bars-queue.sh                          every pair (CORPORA, CHECKS, TIMEOUT as in bars.sh)
#   PUSH=1 CORPORA=m500 bars-queue.sh      push HEAD to the remote first
#   NOLOCK=1 CORPORA=m8 bars-queue.sh      a test: the local worker skips heavy-run
#
#   REMOTE       ssh host (default 192.168.254.18); REMOTE_DIR its clone, from ~ (default ghidra-rs)
#   REMOTE_JOBS  parallel functions there (default 16); REMOTE_BIN the game binary there
#                (default ~/projects/mercs/mercs2-decomp/orig/Mercenaries2.analysis.exe)
#   REMOTE_FID   the Function ID databases there (`*_x86.fidbf`, GHIDRA_RS_FID; default
#                REMOTE_DIR/rust/target/fid), which name 1,572 functions of the prelude
#   PUSH=1       `git push -f mac HEAD:refs/heads/bars-queue` and check that commit out (detached)
#                in the remote clone; needs the git remote `mac` pointing at REMOTE_DIR
#   NOLOCK=1     run each local pair without ~/.claude/bin/heavy-run, JOBS=$(heavy-run --jobs);
#                otherwise each local pair waits its turn there and runs with its JOBS
#   OUT          default rust/target/bars-queue: summary.out (the lines, appended), times.out
#                (`<check>-<corpus> <worker> <seconds>`), local/ and mac/ (each pair's output and
#                bars.sh files; mac/ gets the .miss files back). The remote writes under its
#                rust/target/bars-queue.
# Before it starts: both clones at the same commit with no tracked changes, `cargo build --release`
# on both and the same prelude on both (else it stops). The reference (decomp-ref.sh) must be built
# on both.
cd "$(dirname "$0")/.." || exit 1
die() { echo "bars-queue: $*" >&2; exit 1; }
R=${REMOTE:-192.168.254.18} RD=${REMOTE_DIR:-ghidra-rs}
RB=${REMOTE_BIN:-'$HOME/projects/mercs/mercs2-decomp/orig/Mercenaries2.analysis.exe'}
RF=${REMOTE_FID:-'$HOME/'$RD/rust/target/fid}
# GNU tools first (decomp-diff.sh needs GNU sed and grep, timeout, nproc), then /bin's bash
g=/usr/local/opt
RP="$g/coreutils/libexec/gnubin:$g/gnu-sed/libexec/gnubin:$g/grep/libexec/gnubin:$g/findutils/libexec/gnubin:$g/gawk/libexec/gnubin:/usr/bin:/bin:/usr/local/bin:\$HOME/.cargo/bin"
o=${OUT:-$PWD/target/bars-queue}
rsh() { ssh -o BatchMode=yes -o ServerAliveInterval=15 -o ServerAliveCountMax=4 "$R" "$@"; }

head=$(git rev-parse HEAD)
[ -z "$(git status --porcelain -uno)" ] || die "tracked changes here: commit them first"
if [ -n "$PUSH" ]; then
    git push -q -f mac HEAD:refs/heads/bars-queue && rsh "cd $RD && git checkout -q --detach $head" ||
        die "push to mac failed"
fi
there=$(rsh "cd $RD && git status --porcelain -uno; git rev-parse HEAD") || die "no ssh to $R"
[ "$there" = "$head" ] || die "mac is not at $head with a clean tree: $there"
cargo build --release -q || die "local build failed"
rsh "cd $RD/rust && PATH=$RP caffeinate -i cargo build --release -q" || die "mac build failed"
tools/decomp-diff.sh --prelude || die "no prelude here"
rsh "cd $RD/rust && PATH=$RP GHIDRA_RS_FID=$RF BIN=$RB tools/decomp-diff.sh --prelude" || die "no prelude on mac"
p=target/decomp-check/mercs2.prelude
[ "$(cksum < $p)" = "$(rsh "cksum < $RD/rust/$p")" ] || die "the preludes differ (Function ID databases?)"

mapfile -t q < <(LIST=1 tools/bars.sh | awk '$2 != "m8"'; LIST=1 tools/bars.sh | awk '$2 == "m8"')
[ ${#q[@]} -gt 0 ] || die "no pairs"
mkdir -p "$o/local" "$o/mac"
echo "queue $head: ${#q[@]} pairs, $(date +%T)" | tee -a "$o/summary.out"

# run <worker> <check> <corpus>: bars.sh for one pair
run() {
    if [ "$1" = mac ]; then
        rsh "cd $RD/rust && PATH=$RP exec caffeinate -i env GHIDRA_RS_FID=$RF JOBS=${REMOTE_JOBS:-16} TIMEOUT=${TIMEOUT:-120} CHECKS=$2 CORPORA=$3 BIN=$RB OUT=target/bars-queue tools/bars.sh"
    elif [ -n "$NOLOCK" ]; then
        JOBS=$(~/.claude/bin/heavy-run --jobs) CHECKS=$2 CORPORA=$3 OUT=$o/local tools/bars.sh
    else
        # ponytail: weight 5 minutes per pair (an M500 check at 120 s); M8 pairs take seconds
        env -u JOBS CHECKS="$2" CORPORA="$3" OUT="$o/local" ~/.claude/bin/heavy-run 5 tools/bars.sh
    fi
}
declare -A job
i=0 fail=0 mac=1
give() {
    [ $i -lt ${#q[@]} ] || return
    local k=${q[i]% *} c=${q[i]#* }
    i=$((i + 1))
    run "$1" "$k" "$c" > "$o/$1/$k-$(basename "$c" .txt).out" 2>&1 &
    job[$!]="$1 $k-$(basename "$c" .txt) $SECONDS"
}
give local
give mac
while [ ${#job[@]} -gt 0 ]; do
    wait -n -p pid
    read -r w name t0 <<<"${job[$pid]}"
    unset "job[$pid]"
    line=$(grep "^$name: reference finished" "$o/$w/$name.out")
    if [ -n "$line" ]; then
        echo "$line" | tee -a "$o/summary.out"
        echo "$name $w $((SECONDS - t0))" >> "$o/times.out"
        [ $w = mac ] && rsh "cat $RD/rust/target/bars-queue/$name.miss" > "$o/mac/$name.miss"
    else
        echo "lost: $name on $w" | tee -a "$o/summary.out"
        fail=1
        [ $w = mac ] && mac=
    fi
    [ $w = mac ] && [ -z "$mac" ] || give $w
done
if [ $fail = 0 ]; then echo "DONE $(date +%T)"; else echo "INCOMPLETE $(date +%T)"; fi | tee -a "$o/summary.out"
exit $fail
