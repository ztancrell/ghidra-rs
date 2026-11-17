#!/bin/bash
# What differs in the `func` (or `extref`) records facts-diff.sh found different: counts per
# set of differing parts (name, size, noreturn, extrapop, model, locals, return, inject).
#   facts-func-why.sh [<kind>.different]   (default rust/target/facts-diff/func.different)
rust=$(cd "$(dirname "$0")/.." && pwd)
LC_ALL=C awk '
function part(x, re) { return match(x, re) ? substr(x, RSTART, RLENGTH) : "" }
BEGIN {
    q = "\"[^\"]*\""
    name = "<function name=" q; size = name " size=" q; pop = "extrapop=" q
    model = "model=" q "( modellock=\"true\")?"; locals = "<symbollist>.*</symbollist>"
    ret = "<returnsym.*</returnsym>"; inject = "<inject>[^<]*"
}
/^  ours: / { o = $0; next }
/^  java: / {
    j = $0; w = ""
    if (part(o, name) != part(j, name)) w = w " name"
    else if (part(o, size) != part(j, size)) w = w " size"
    if ((o ~ /noreturn=/) != (j ~ /noreturn=/)) w = w ((o ~ /noreturn=/) ? " noreturn(ours)" : " noreturn(java)")
    eo = part(o, pop); ej = part(j, pop)
    if (eo != ej) w = w ((eo ~ /unknown/) ? " extrapop(ours-unknown)" : (ej ~ /unknown/) ? " extrapop(java-unknown)" : " extrapop(value)")
    if (part(o, model) != part(j, model)) w = w " model"
    lo = (o ~ /<symbollist\/>/); lj = (j ~ /<symbollist\/>/)
    if (lo != lj) w = w (lj ? " locals(ours-only)" : " locals(java-only)")
    else if (!lo && part(o, locals) != part(j, locals)) w = w " locals(differ)"
    if (part(o, ret) != part(j, ret)) w = w " return"
    if (part(o, inject) != part(j, inject)) w = w " inject"
    if (w == "") w = " other"
    c[w]++
}
END { for (k in c) printf "%7d %s\n", c[k], k }' "${1:-$rust/target/facts-diff/func.different}" | sort -rn
