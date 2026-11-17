#!/bin/bash
# Runs every milestone 3 check (decomp-diff.sh with each check's stage, options and print) and
# prints one summary line per check. The one copy of "run every bar": add a check here when a
# stage adds one.
#
#   bars.sh                              every check on every corpus it applies to
#   CORPORA="m8" bars.sh                 the fast gate (minutes)
#   CHECKS="r1 s7t" CORPORA=m500 bars.sh exactly these checks on these corpora
#
#   CORPORA  m8, m500, r5d-adc, switch, simple (files of tools/corpus/) or a file of addresses.
#            Default: all five. Without CHECKS, r5d-adc runs only the double-rule checks,
#            switch only the S3 bar (paramdouble), the six switch checks and pcc-r, pcc-t (with
#            `switchnorm` on: the sw options), and simple only the print C checks.
#   CHECKS   names from the `case` below. Default: every check that applies to the corpus.
#   JOBS     parallel functions per check (default: nproc); TIMEOUT seconds per function and
#            engine (default 600)
#   OUT      output directory (default rust/target/bars): summary.out (the lines printed, appended),
#            <check>-<corpus>.log (decomp-diff.sh's output) and .miss (one line per function that
#            differs: `loud` when ghidra-rs printed an error, `silent` otherwise, `timeout` when
#            it printed nothing or was killed at TIMEOUT; `reference failed` lines for those the
#            reference does not finish, a reference killed at TIMEOUT among them)
#   KEEP=1   keep the per-function outputs (OUT/<check>-<corpus>/), deleted otherwise
#   LIST=1   only print the check-corpus pairs it would run, one `<check> <corpus>` per line
#            (bars-queue.sh shares them between two machines)
#
# Summary line: `<check>-<corpus>: reference finished F / N, identical I / F (loud L, silent S,
# timeout T), all outputs identical A / N`. I counts only functions the reference finishes; A is
# decomp-diff.sh's count over all N (a function the reference does not finish is identical there
# when both engines print the same error).
# Writes only under rust/target/. Needs the reference (decomp-ref.sh) and a release build.
cd "$(dirname "$0")/.." || exit 1
t=$PWD/tools; c=$t/corpus; o=${OUT:-$PWD/target/bars}; l=$PWD/target/locks
export JOBS=${JOBS:-$(nproc)} TIMEOUT=${TIMEOUT:-120}
mkdir -p "$o"
S3=multicse,shadowvar,condconst                   # rule-stage actions not ported, skipped on both engines
L=restructure_varnode,mapped_local_sync           # the same for `localrecovery`
S=inputprototype,mapglobals,namevars,setcasts     # the leaves before finalstructure
SC=inputprototype,mapglobals,namevars          # the same with `setcasts` on (stage S9)
# default options (`pcd`): every action leaf not ported yet, skipped on both engines. Shrinks as
# each is ported; empty when the default pipeline is whole.
D=restructure_varnode,mapped_local_sync,multicse,shadowvar,condconst,dynamicsymbols,prototypewarnings
TP=$'print tree block\nprint raw'; MP=$'print map\nprint raw'

# run <check> <corpus> <env assignments...>
run() {
    local name=$1-$(basename "$2" .txt) corpus=$2 a f fin=0 n=0 same=0 loud=0 silent=0 tmo=0 all extra=
    shift 2
    env "$@" OUT="$o/$name" "$t/decomp-diff.sh" "$corpus" > "$o/$name.log" 2>&1
    grep '^reference failed' "$o/$name.log" > "$o/$name.miss"
    for f in "$o/$name"/ref/*; do
        a=$(basename "$f"); n=$((n + 1))
        grep -q "^reference failed $a:" "$o/$name.miss" && continue
        fin=$((fin + 1))
        if cmp -s "$f" "$o/$name/rust/$a"; then same=$((same + 1)); continue; fi
        if [ ! -s "$o/$name/rust/$a" ] || grep -q '^decomp-diff.sh: timed out' "$o/$name/rust/$a"; then
            tmo=$((tmo + 1)); echo "timeout $a"
        elif grep -q 'ERROR\|error:\|panicked' "$o/$name/rust/$a"; then
            loud=$((loud + 1)); echo "loud $a: $(grep -m1 'ERROR\|error:\|panicked' "$o/$name/rust/$a" | cut -c1-160)"
        else silent=$((silent + 1)); echo "silent $a: $(grep -m1 "^different $a," "$o/$name.log" | cut -c1-200)"
        fi
    done >> "$o/$name.miss"
    all=$(grep -o 'identical [0-9]* / [0-9]*' "$o/$name.log" | grep -o '[0-9]* / [0-9]*')
    # the stack check is only a check when the reference prints stack SSA
    case $name in stack-*) extra=", outputs with stack SSA $(grep -l s0x "$o/$name"/ref/* | wc -l)" ;; esac
    echo "$name: reference finished $fin / $n, identical $same / $fin (loud $loud, silent $silent, timeout $tmo), all outputs identical ${all:-none: see $o/$name.log}$extra" | tee -a "$o/summary.out"
    [ -n "$KEEP" ] || rm -rf "${o:?}/$name"
}

std="stack stackhigh funclink heritage paramdouble s4 s6 s6void s6int4 s6callee r1 subvar r4 r5 r5typed s7r s7r2 s7sub s7r4 s7r5 s7t s7t2 s8 s8r"
dbl="r5d r5dt r5dtlock r5dtlocksv"
sw="swfs-r swfs-t swsn-r swsn-t swfsc-r swfsc-t"
pc="pc-r pc-t pcc-r pcc-t pcd"
all="$std r5c $dbl svlock svs6 r5slock r5s pg-r pg-t nm-r nm-t ldn-r ldn-t fs-r fs-t cs-r cs-t fsc-r fsc-t $sw $pc"
[ -n "$LIST" ] || "$t/lock-options.sh" "$l" || exit 1
for C in ${CORPORA:-m8 m500 r5d-adc switch simple}; do
    C0=$C
    [ -f "$C" ] || C=$c/$C.txt
    [ -f "$C" ] || { echo "no corpus $C" >&2; exit 1; }
    # print C with casts: switch cases need `switchnorm` (the case labels), on in the sw options
    po=tail; [ "$(basename "$C" .txt)" = switch ] && po=sw
    case $(basename "$C" .txt) in r5d-adc) def=$dbl ;; switch) def="paramdouble $sw pcc-r pcc-t" ;; simple) def=$pc ;; *) def=$all ;; esac
    for k in ${CHECKS:-$def}; do
        [ -n "$LIST" ] && { echo "$k $C0"; continue; }
        case $k in
        # stack heritage: every prototype locked with two stack parameters
        stack) run $k "$C" DECOMP_RAW_EXTRA=1 BREAK=assignhigh OPTIONS=$l/stack-lock.txt ;;
        stackhigh) run $k "$C" DECOMP_RAW_EXTRA=1 BREAK=inputprototype OPTIONS=$l/stack-lock.txt ;;
        # S1 to S3 (paramdouble on the switch corpus is the S3 switch bar)
        funclink | heritage | paramdouble) run $k "$C" BREAK=$k ;;
        # S4, S6
        s4) run $k "$C" BREAK=assignhigh OPTIONS=$c/s4-options.txt ;;
        s6) run $k "$C" DECOMP_RAW_EXTRA=1 BREAK=assignhigh OPTIONS=$c/s6-options.txt ;;
        s6void) run $k "$C" DECOMP_RAW_EXTRA=1 BREAK=assignhigh OPTIONS=$l/lock-void.txt ;;
        s6int4) run $k "$C" DECOMP_RAW_EXTRA=1 BREAK=assignhigh OPTIONS=$l/lock-int4.txt ;;
        s6callee) run $k "$C" DECOMP_RAW_EXTRA=1 BREAK=assignhigh OPTIONS_SKIP_SELF=1 OPTIONS=$l/lock-stk.txt ;;
        # R1 to R5
        r1) run $k "$C" DECOMP_SKIP_ACTIONS=$S3 BREAK=assignhigh OPTIONS=$c/r1-options.txt ;;
        subvar) run $k "$C" DECOMP_SKIP_ACTIONS=$S3 BREAK=assignhigh OPTIONS=$c/subvar-options.txt ;;
        r4) run $k "$C" DECOMP_SKIP_ACTIONS=$S3 BREAK=assignhigh OPTIONS=$c/r4-options.txt ;;
        r5) run $k "$C" DECOMP_SKIP_ACTIONS=$S3 BREAK=assignhigh OPTIONS=$c/r5-options.txt ;;
        r5typed) run $k "$C" DECOMP_SKIP_ACTIONS=$S3 DECOMP_RAW_EXTRA=1 BREAK=assignhigh OPTIONS=$c/r5-options.txt ;;
        r5c) run $k "$C" DECOMP_SKIP_ACTIONS=$S3 DECOMP_RAW_EXTRA=1 BREAK=assignhigh OPTIONS=$c/r5c-options.txt ;;
        r5d) run $k "$C" DECOMP_SKIP_ACTIONS=$S3 BREAK=assignhigh OPTIONS=$c/r5d-options.txt ;;
        r5dt) run $k "$C" DECOMP_SKIP_ACTIONS=$S3 DECOMP_RAW_EXTRA=1 BREAK=assignhigh OPTIONS=$c/r5dt-options.txt ;;
        r5dtlock) run $k "$C" DECOMP_SKIP_ACTIONS=$S3 DECOMP_RAW_EXTRA=1 BREAK=assignhigh OPTIONS=$l/r5dt-lock.txt ;;
        r5dtlocksv) run $k "$C" DECOMP_SKIP_ACTIONS=$S3 DECOMP_RAW_EXTRA=1 BREAK=assignhigh OPTIONS=$l/r5dt-lock-sv.txt ;;
        # R5 slice 2: the four checks with `stackvars` on
        svlock) run $k "$C" DECOMP_RAW_EXTRA=1 BREAK=assignhigh OPTIONS=$l/lock-sv.txt ;;
        svs6) run $k "$C" DECOMP_RAW_EXTRA=1 BREAK=assignhigh OPTIONS=$l/s6-sv.txt ;;
        r5slock) run $k "$C" DECOMP_SKIP_ACTIONS=$S3 DECOMP_RAW_EXTRA=1 BREAK=assignhigh OPTIONS=$l/r5s-lock.txt ;;
        r5s) run $k "$C" DECOMP_SKIP_ACTIONS=$S3 DECOMP_RAW_EXTRA=1 BREAK=assignhigh OPTIONS=$c/r5s-options.txt ;;
        # S7 (high variables; the 2 variants also print create indices)
        s7r) run $k "$C" DECOMP_SKIP_ACTIONS=$S3 DECOMP_RAW_EXTRA=1 BREAK=inputprototype OPTIONS=$c/r1-options.txt ;;
        s7r2) run $k "$C" DECOMP_SKIP_ACTIONS=$S3 DECOMP_RAW_EXTRA=2 BREAK=inputprototype OPTIONS=$c/r1-options.txt ;;
        s7sub) run $k "$C" DECOMP_SKIP_ACTIONS=$S3 DECOMP_RAW_EXTRA=1 BREAK=inputprototype OPTIONS=$c/subvar-options.txt ;;
        s7r4) run $k "$C" DECOMP_SKIP_ACTIONS=$S3 DECOMP_RAW_EXTRA=1 BREAK=inputprototype OPTIONS=$c/r4-options.txt ;;
        s7r5) run $k "$C" DECOMP_SKIP_ACTIONS=$S3 DECOMP_RAW_EXTRA=1 BREAK=inputprototype OPTIONS=$c/r5-options.txt ;;
        s7t) run $k "$C" DECOMP_RAW_EXTRA=1 BREAK=inputprototype OPTIONS=$c/s6-options.txt ;;
        s7t2) run $k "$C" DECOMP_RAW_EXTRA=2 BREAK=inputprototype OPTIONS=$c/s6-options.txt ;;
        # S8 (structuring), rules off and rule stage
        s8) run $k "$C" "PRINT=$TP" BREAK=assignhigh DECOMP_SKIP_ACTIONS= OPTIONS=$c/s8-options.txt ;;
        s8r) run $k "$C" "PRINT=$TP" BREAK=assignhigh DECOMP_SKIP_ACTIONS=$S3 OPTIONS=$c/s8-r-options.txt ;;
        # tail, rules on (-r) and types on (-t): prototypes and globals, names, latedonothing,
        # finalstructure with `switchnorm` off
        pg-r) run $k "$C" DECOMP_RAW_EXTRA=1 DECOMP_MAP_EXTRA=1 "PRINT=$MP" DECOMP_SKIP_ACTIONS=$S3,$L BREAK=namevars OPTIONS=$c/tail-r-options.txt ;;
        pg-t) run $k "$C" DECOMP_RAW_EXTRA=1 DECOMP_MAP_EXTRA=1 "PRINT=$MP" DECOMP_SKIP_ACTIONS=$L BREAK=namevars OPTIONS=$c/tail-t-options.txt ;;
        nm-r) run $k "$C" DECOMP_RAW_EXTRA=1 DECOMP_MAP_EXTRA=1 "PRINT=$MP" DECOMP_SKIP_ACTIONS=$S3,$L BREAK=setcasts OPTIONS=$c/tail-r-options.txt ;;
        nm-t) run $k "$C" DECOMP_RAW_EXTRA=1 DECOMP_MAP_EXTRA=1 "PRINT=$MP" DECOMP_SKIP_ACTIONS=$L BREAK=setcasts OPTIONS=$c/tail-t-options.txt ;;
        ldn-r) run $k "$C" DECOMP_RAW_EXTRA=1 DECOMP_TREE_EXTRA=1 "PRINT=$TP" DECOMP_SKIP_ACTIONS=$S3 BREAK=inputprototype OPTIONS=$c/s8-r-options.txt ;;
        ldn-t) run $k "$C" DECOMP_RAW_EXTRA=1 DECOMP_TREE_EXTRA=1 "PRINT=$TP" DECOMP_SKIP_ACTIONS= BREAK=inputprototype OPTIONS=$c/s8-t-options.txt ;;
        fs-r) run $k "$C" DECOMP_RAW_EXTRA=1 DECOMP_TREE_EXTRA=1 "PRINT=$TP" DECOMP_SKIP_ACTIONS=$S3,$S BREAK=prototypewarnings OPTIONS=$c/s8-r-options.txt ;;
        fs-t) run $k "$C" DECOMP_RAW_EXTRA=1 DECOMP_TREE_EXTRA=1 "PRINT=$TP" DECOMP_SKIP_ACTIONS=$S BREAK=prototypewarnings OPTIONS=$c/s8-t-options.txt ;;
        # setcasts (stage S9): `print raw` after it (the CAST ops), and finalstructure with it on
        cs-r) run $k "$C" DECOMP_RAW_EXTRA=1 DECOMP_SKIP_ACTIONS=$S3,$SC BREAK=finalstructure OPTIONS=$c/s8-r-options.txt ;;
        cs-t) run $k "$C" DECOMP_RAW_EXTRA=1 DECOMP_SKIP_ACTIONS=$SC BREAK=finalstructure OPTIONS=$c/s8-t-options.txt ;;
        fsc-r) run $k "$C" DECOMP_RAW_EXTRA=1 DECOMP_TREE_EXTRA=1 "PRINT=$TP" DECOMP_SKIP_ACTIONS=$S3,$SC BREAK=prototypewarnings OPTIONS=$c/s8-r-options.txt ;;
        fsc-t) run $k "$C" DECOMP_RAW_EXTRA=1 DECOMP_TREE_EXTRA=1 "PRINT=$TP" DECOMP_SKIP_ACTIONS=$SC BREAK=prototypewarnings OPTIONS=$c/s8-t-options.txt ;;
        # the six switch checks (`switchnorm` on): finalstructure with case labels, and
        # switchnorm as `print raw` at the first break after it
        swfs-r) run $k "$C" DECOMP_RAW_EXTRA=1 DECOMP_TREE_EXTRA=1 "PRINT=$TP" DECOMP_SKIP_ACTIONS=$S3,$S BREAK=prototypewarnings OPTIONS=$c/sw-r-options.txt ;;
        swfs-t) run $k "$C" DECOMP_RAW_EXTRA=1 DECOMP_TREE_EXTRA=1 "PRINT=$TP" DECOMP_SKIP_ACTIONS=$S BREAK=prototypewarnings OPTIONS=$c/sw-t-options.txt ;;
        swsn-r) run $k "$C" DECOMP_RAW_EXTRA=1 DECOMP_SKIP_ACTIONS=$S3 BREAK=returnsplit OPTIONS=$c/sw-r-options.txt ;;
        swsn-t) run $k "$C" DECOMP_RAW_EXTRA=1 DECOMP_SKIP_ACTIONS= BREAK=returnsplit OPTIONS=$c/sw-t-options.txt ;;
        swfsc-r) run $k "$C" DECOMP_RAW_EXTRA=1 DECOMP_TREE_EXTRA=1 "PRINT=$TP" DECOMP_SKIP_ACTIONS=$S3,$SC BREAK=prototypewarnings OPTIONS=$c/sw-r-options.txt ;;
        swfsc-t) run $k "$C" DECOMP_RAW_EXTRA=1 DECOMP_TREE_EXTRA=1 "PRINT=$TP" DECOMP_SKIP_ACTIONS=$SC BREAK=prototypewarnings OPTIONS=$c/sw-t-options.txt ;;
        # S9 slice 1: `print C` at the end of the ported actions, `setcasts` skipped on both
        # engines (no casts printed)
        pc-r) run $k "$C" "PRINT=print C" DECOMP_SKIP_ACTIONS=$S3,$L,setcasts BREAK=prototypewarnings OPTIONS=$c/tail-r-options.txt ;;
        pc-t) run $k "$C" "PRINT=print C" DECOMP_SKIP_ACTIONS=$L,setcasts BREAK=prototypewarnings OPTIONS=$c/tail-t-options.txt ;;
        # pcc-r, pcc-t: the same with `setcasts` on (casts printed); on the switch corpus with the
        # sw options (`switchnorm` on, `localrecovery` off)
        pcc-r) run $k "$C" "PRINT=print C" DECOMP_SKIP_ACTIONS=$S3,$L BREAK=prototypewarnings OPTIONS=$c/$po-r-options.txt ;;
        pcc-t) run $k "$C" "PRINT=print C" DECOMP_SKIP_ACTIONS=$L BREAK=prototypewarnings OPTIONS=$c/$po-t-options.txt ;;
        # pcd: `print C` with the DEFAULT options (no group or rule off, no break), less the
        # actions of $D
        pcd) run $k "$C" "PRINT=print C" DECOMP_SKIP_ACTIONS=$D BREAK= OPTIONS= ;;
        *) echo "unknown check $k" >&2; exit 1 ;;
        esac
    done
done
[ -n "$LIST" ] && exit 0
echo "DONE $(date +%T)" | tee -a "$o/summary.out"
