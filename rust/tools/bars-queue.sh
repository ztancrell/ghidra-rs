#!/bin/bash
# Shares one bars.sh pass between this machine and a second one over ssh (the Mac). One queue of
# the check-corpus pairs bars.sh would run (`LIST=1 bars.sh`), M500, r5d-adc and switch first,
# M8 last, and two workers, local and remote: each takes the next pair when it is free. Every
# summary line goes to one file here. No retry: a pair that ends without a full summary line
# (ssh dropped, Mac gone, the reference finished nothing) prints `lost: <check>-<corpus> on <worker>`;
# a lost Mac pair stops the remote worker and the rest runs locally. Any lost pair makes the pass
# end INCOMPLETE with exit 1, so it never counts as complete.
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
#   OUT          default rust/target/bars-queue, emptied at the start: summary.out (the lines),
#                times.out (`<check>-<corpus> <worker> <seconds>`), local/ and mac/ (each pair's
#                output and bars.sh files; mac/ gets the .miss files back). The remote writes under
#                its rust/target/bars-queue, also emptied.
# Before it starts it stops unless: both clones are at the same commit with no tracked changes and
# no untracked files in rust/tools; no bars.sh or decomp-diff.sh of either clone is running; both
# release builds pass; both references were built from this commit's decomp-ref.patch and C++
# sources (decomp-build/ref.stamp, written by decomp-ref.sh); BIN, x86.sla and the prelude are
# the same on both. Ctrl-C or kill (TERM) stops the pass and the runs of both workers.
cd "$(dirname "$0")/.." || exit 1
die() { echo "bars-queue: $*" >&2; exit 1; }
R=${REMOTE:-192.168.254.18} RD=${REMOTE_DIR:-ghidra-rs}
RB=${REMOTE_BIN:-'$HOME/projects/mercs/mercs2-decomp/orig/Mercenaries2.analysis.exe'}
RF=${REMOTE_FID:-'$HOME/'$RD/rust/target/fid}
BIN=${BIN:-$HOME/projects/mercs/mercs2-decomp/orig/Mercenaries2.analysis.exe}
# GNU tools first (decomp-diff.sh needs GNU sed, grep and cmp, timeout, nproc), then /bin's bash
g=/usr/local/opt
RP="$g/coreutils/libexec/gnubin:$g/gnu-sed/libexec/gnubin:$g/grep/libexec/gnubin:$g/findutils/libexec/gnubin:$g/gawk/libexec/gnubin:$g/diffutils/bin:/usr/bin:/bin:/usr/local/bin:\$HOME/.cargo/bin"
o=${OUT:-$PWD/target/bars-queue}
rsh() { ssh -n -o BatchMode=yes -o ConnectTimeout=15 -o ServerAliveInterval=15 -o ServerAliveCountMax=4 "$R" "$@"; }
sla=../Ghidra/Processors/x86/data/languages/x86.sla
stamp=target/decomp-build/ref.stamp
running="/$RD/rust/tools/(bars|decomp-diff)\.sh"

head=$(git rev-parse HEAD)
[ -z "$(git status --porcelain -uno)$(git ls-files -o --exclude-standard tools)" ] ||
    die "tracked changes or untracked files in rust/tools here: commit them first"
pgrep -f "$PWD/tools/(bars|decomp-diff)\.sh" >/dev/null && die "a bars.sh or decomp-diff.sh of this clone is running here"
if [ -n "$PUSH" ]; then
    git push -q -f mac HEAD:refs/heads/bars-queue && rsh "cd $RD && git checkout -q --detach $head" ||
        die "push to mac failed"
fi
there=$(rsh "cd $RD && git status --porcelain -uno; git ls-files -o --exclude-standard rust/tools; git rev-parse HEAD") ||
    die "no ssh to $R"
[ "$there" = "$head" ] || die "mac is not at $head with a clean tree: $there"
rsh "pgrep -f '$running'" >/dev/null && die "a bars.sh or decomp-diff.sh of ~/$RD is running on mac"
cargo build --release -q || die "local build failed"
rsh "cd $RD/rust && PATH=$RP caffeinate -i cargo build --release -q" || die "mac build failed"
want=$(git rev-parse HEAD:rust/tools/decomp-ref.patch HEAD:Ghidra/Features/Decompiler/src/decompile/cpp)
[ "$(cat $stamp 2>/dev/null)" = "$want" ] || die "the reference here is not built from this commit: run tools/decomp-ref.sh"
[ "$(rsh "cat $RD/rust/$stamp")" = "$want" ] || die "the reference on mac is not built from this commit: run tools/decomp-ref.sh there"
[ "$(cksum < "$BIN")" = "$(rsh "cksum < $RB")" ] || die "the game binaries differ"
[ "$(cksum < $sla)" = "$(rsh "cksum < $RD/rust/$sla")" ] || die "the x86.sla files differ"
BIN=$BIN tools/decomp-diff.sh --prelude || die "no prelude here"
rsh "cd $RD/rust && PATH=$RP GHIDRA_RS_FID=$RF BIN=$RB tools/decomp-diff.sh --prelude" || die "no prelude on mac"
p=target/decomp-check/mercs2.prelude
[ "$(cksum < $p)" = "$(rsh "cksum < $RD/rust/$p")" ] || die "the preludes differ (Function ID databases?)"

pairs=$(LIST=1 tools/bars.sh) || die "bars.sh cannot list the pairs (CORPORA, CHECKS?)"
mapfile -t q < <(awk '$2 != "m8"' <<<"$pairs"; awk '$2 == "m8"' <<<"$pairs")
[ ${#q[@]} -gt 0 ] || die "no pairs"
rm -rf "${o:?}" && mkdir -p "$o/local" "$o/mac" || die "cannot write $o"
rsh "rm -rf $RD/rust/target/bars-queue && mkdir -p $RD/rust/target/bars-queue" || die "cannot write on mac"
echo "queue $head: ${#q[@]} pairs, $(date +%T)" | tee "$o/summary.out"
: > "$o/times.out"

# run <worker> <check> <corpus>: bars.sh for one pair. The Mac run's shell is its session and
# group leader (sshd), so its pid file names the group to kill.
run() {
    if [ "$1" = mac ]; then
        rsh "cd $RD/rust && echo \$\$ > target/bars-queue/run.pid && PATH=$RP exec caffeinate -i env GHIDRA_RS_FID=$RF JOBS=${REMOTE_JOBS:-16} TIMEOUT=${TIMEOUT:-120} CHECKS=$2 CORPORA=$3 BIN=$RB OUT=target/bars-queue \$PWD/tools/bars.sh"
    elif [ -n "$NOLOCK" ]; then
        BIN=$BIN JOBS=$(~/.claude/bin/heavy-run --jobs) CHECKS=$2 CORPORA=$3 OUT=$o/local "$PWD/tools/bars.sh"
    else
        # ponytail: weight 5 minutes per pair (an M500 check at 120 s); M8 pairs take seconds
        env -u JOBS BIN="$BIN" CHECKS="$2" CORPORA="$3" OUT="$o/local" ~/.claude/bin/heavy-run 5 "$PWD/tools/bars.sh"
    fi
}
stopmac() { rsh "kill -TERM -- -\$(cat $RD/rust/target/bars-queue/run.pid)" 2>/dev/null; }
declare -A job
i=0 fail=0 mac=1
# job control: each pair runs in its own process group, so a kill reaches decomp-diff.sh's workers
set -m
stop() {
    trap - EXIT INT TERM
    for pid in "${!job[@]}"; do
        kill -TERM -- -"$pid" 2>/dev/null
        [ "${job[$pid]%% *}" = mac ] && stopmac
    done
    echo "STOPPED $(date +%T)" | tee -a "$o/summary.out"
    exit 1
}
trap stop EXIT INT TERM
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
    # only the full line counts, and only when the reference finished something
    line=$(grep -E "^$name: reference finished [1-9][0-9]* / [0-9]+, identical [0-9]+ / [0-9]+ \(loud [0-9]+, silent [0-9]+, timeout [0-9]+\), all outputs identical [0-9]+ / [0-9]+(, outputs with stack SSA [0-9]+)?$" "$o/$w/$name.out")
    if [ -n "$line" ]; then
        echo "$line" | tee -a "$o/summary.out"
        echo "$name $w $((SECONDS - t0))" >> "$o/times.out"
        if [ $w = mac ]; then
            rsh "cat $RD/rust/target/bars-queue/$name.miss" > "$o/mac/$name.miss" ||
                echo "bars-queue: warning: no .miss of $name from mac" >&2
        fi
    else
        echo "lost: $name on $w" | tee -a "$o/summary.out"
        fail=1
        [ $w = mac ] && { mac=; stopmac; }
    fi
    [ $w = mac ] && [ -z "$mac" ] || give $w
done
trap - EXIT INT TERM
if [ $fail = 0 ]; then echo "DONE $(date +%T)"; else echo "INCOMPLETE $(date +%T)"; fi | tee -a "$o/summary.out"
exit $fail
