#!/bin/bash
# Writes the option files of the checks that lock prototypes or switch `stackvars` on, for
# bars.sh. They hold a `parse line extern` for each of the 28,000 functions of the mercs2 prelude,
# so they are generated, not committed. Rerun after r1-options.sh changes an options file.
#
#   lock-options.sh [<dir>]     default rust/target/locks
#
#   lock-void.txt      s6-options.txt, every prototype `void f(void)` (S6 locked)
#   lock-int4.txt      s6-options.txt, every prototype `int4 f(void)` (S6 locked)
#   lock-stk.txt       s6-options.txt, every prototype `void f(int4 a)` (S6 callees)
#   stack-lock.txt     s6-options.txt, every prototype `void f(int4 a, int4 b)` (stack heritage)
#   lock-sv.txt        stack-lock.txt with `stackvars` on (R5 slice 2)
#   s6-sv.txt          s6-options.txt with `stackvars` on, unlocked (R5 slice 2)
#   r5s-lock.txt       r5s-options.txt plus the locks of stack-lock.txt (R5 slice 2)
#   r5dt-lock.txt      r5dt-options.txt plus the locks of stack-lock.txt (typed double rules)
#   r5dt-lock-sv.txt   r5dt-lock.txt with `stackvars` on
set -e
rust=$(cd "$(dirname "$0")/.." && pwd)
c=$rust/tools/corpus
d=${1:-$rust/target/locks}
export PRELUDE=${PRELUDE:-$rust/target/decomp-check/mercs2.prelude}
"$rust/tools/decomp-diff.sh" --prelude
mkdir -p "$d"
# built in a private directory and renamed into $d, so parallel bars.sh runs (each calls this)
# never write the same file at once nor read half of one
f=$(mktemp -d "$d.tmp.XXXXXX")
trap 'rm -rf "$f"' EXIT
sv() { grep -v 'decompile stackvars off' "$1" > "$2"; }
"$rust/tools/decomp-locked-options.sh" void "$f/lock-void.txt"
"$rust/tools/decomp-locked-options.sh" int4 "$f/lock-int4.txt"
"$rust/tools/decomp-locked-options.sh" void "$f/lock-stk.txt" "int4 a"
"$rust/tools/decomp-locked-options.sh" void "$f/stack-lock.txt" "int4 a, int4 b"
sv "$f/stack-lock.txt" "$f/lock-sv.txt"
sv "$c/s6-options.txt" "$f/s6-sv.txt"
{ cat "$c/r5s-options.txt"; grep '^parse line' "$f/stack-lock.txt"; } > "$f/r5s-lock.txt"
{ cat "$c/r5dt-options.txt"; grep '^parse line' "$f/stack-lock.txt"; } > "$f/r5dt-lock.txt"
sv "$f/r5dt-lock.txt" "$f/r5dt-lock-sv.txt"
mv "$f"/* "$d"/
