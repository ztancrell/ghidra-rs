#!/bin/bash
# The `data` records facts-diff.sh found different, missing or extra, counted by what each
# side has there: the symbol's name prefix (`DAT`, `PTR`, `s`, a name), its data-type and
# whether it is read-only, as `ours -> java`.
#   facts-data-why.sh [<lines>]   (default 40 lines; reads rust/target/facts-diff/data.*)
rust=$(cd "$(dirname "$0")/.." && pwd)
cat "$rust"/target/facts-diff/data.{different,missing,extra} 2>/dev/null | LC_ALL=C awk '
function cls(x,    tag, n, t, r) {
    if (x == "") return "-"
    if (!match(x, "<(symbol|labelsym|externrefsymbol) name=\"[^\"]*\"")) return "?"
    n = substr(x, RSTART, RLENGTH); tag = n; sub(/ .*/, "", tag); sub(/.*name="/, "", n); sub(/"$/, "", n)
    if (n ~ /^(s|u)_.*_[0-9a-f]+$/) n = substr(n, 1, 1) "_"
    else if (n ~ /^PTR_.*_[0-9a-f]+$/) n = "PTR"
    else if (n ~ /^[A-Za-z]+_[0-9a-f]+$/) sub(/_[0-9a-f]+$/, "", n)
    else n = "NAMED"
    t = ""
    if (match(x, "metatype=\"[a-z_]*\"")) t = substr(x, RSTART + 10, RLENGTH - 11)
    else if (match(x, "<typeref name=\"[^\"]*\"")) t = substr(x, RSTART + 15, RLENGTH - 16)
    if (tag == "<labelsym") t = "label"
    if (tag == "<externrefsymbol") t = "extern"
    return n ":" t ((x ~ /readonly="true"/) ? ":ro" : "")
}
/^  ours: / { o = substr($0, 9); sub(/^[0-9]+ /, "", o); next }
/^  java: / { j = substr($0, 9); sub(/^[0-9]+ /, "", j); c[cls(o) " -> " cls(j)]++ }
END { for (k in c) printf "%7d %s\n", c[k], k }' | sort -rn | head -"${1:-40}"
