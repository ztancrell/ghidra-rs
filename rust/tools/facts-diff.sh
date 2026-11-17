#!/bin/bash
# Two facts files compared record by record (stage S10): the facts ghidra-rs derives itself
# (`ghidra-rs analyze <pe32> --facts <out>`) against those of a Java Ghidra project
# (tools/ghidra-facts.sh).
#
#   facts-diff.sh <ours.facts> <java.facts>
#
# A record's key is its kind and address (a `type` record: the data-type's name; an `ns`
# record: its text). Per kind: `equal` (the same key and the same text), `different` (the same
# key, another text), `missing` (only Java has the key), `extra` (only ours has it). The ids
# Ghidra's database gives symbols, data-types and namespaces are left out of the comparison
# (`<doc id>` is kept as global or not), and the symbols of a function are compared in one
# order. The `tracked` records are compared after each is
# spread over the functions it holds for, so their keys are function entries.
#
#   OUT      output directory (default rust/target/facts-diff): <kind>.different, <kind>.missing,
#            <kind>.extra (every such record: key, then ours and Java's text) and summary.txt
#   SAMPLES  records printed per kind and state (default 2; 0 for the table alone)
#   WIDTH    characters of a sample's text (default 240)
# Writes only under OUT.
set -e
[ -f "$1" ] && [ -f "$2" ] || { echo "usage: facts-diff.sh <ours.facts> <java.facts>" >&2; exit 1; }
rust=$(cd "$(dirname "$0")/.." && pwd)
out=${OUT:-$rust/target/facts-diff}
mkdir -p "$out"
rm -f "$out"/*.different "$out"/*.missing "$out"/*.extra

# one line per record: kind, key, text
norm() {
    LC_ALL=C awk -F'\t' -v OFS='\t' '
    function strip(x) {
        gsub(/<doc id="0x0">/, "<doc global>", x)
        gsub(/<doc id="0x[0-9a-f]+">/, "<doc ns>", x)
        gsub(/ id="0x[0-9a-f]+"/, "", x)
        return syms(x)
    }
    # the symbols of a function in one order (Java writes them in the order of its database)
    function syms(x,    pre, mid, post, n, i, parts) {
        if (!match(x, /<symbollist>.*<\/symbollist>/)) return x
        pre = substr(x, 1, RSTART + 11); mid = substr(x, RSTART + 12, RLENGTH - 25); post = substr(x, RSTART + RLENGTH - 13)
        n = split(mid, parts, "</mapsym>")
        delete parts[n]
        n = asort(parts)
        mid = ""
        for (i = 1; i <= n; i++) mid = mid parts[i] "</mapsym>"
        return pre mid post
    }
    function rest(from,    s, i) {
        s = $from
        for (i = from + 1; i <= NF; i++) s = s " " $i
        return s
    }
    # the tracked registers hold from their record to the next: one line per function
    function spread(entry) {
        if (tracked != "") print "tracked", entry, tracked
    }
    $1 == "func" { funcs[++nf] = $2; print $1, $2, strip($3); next }
    $1 == "tracked" { x = strip($3); sub(/ offset="0x[0-9a-f]+"/, "", x); change[$2] = x; next }
    $1 == "coretypes" { print $1, "-", strip($2); next }
    $1 == "block" || $1 == "body" || $1 == "label" || $1 == "string" || $1 == "undef" || $1 == "depth" {
        print $1, $2, rest(3); next
    }
    $1 == "wref" { print $1, $2, ""; next }
    $1 == "override" { print $1, $2 " " $3, ""; next }
    $1 == "comments" || $1 == "extref" { print $1, $2, strip($3); next }
    $1 == "data" { print $1, $2, $3 " " strip($4); next }
    $1 == "type" { x = strip($3); n = x; sub(/^<[a-z]+ name="/, "", n); sub(/".*/, "", n); print $1, n, x; next }
    $1 == "ns" { print $1, strip($3), ""; next }
    $1 == "underived" { print $1, $2 " " $3, ""; next }
    END {
        for (i = 1; i <= nf; i++) {
            if (funcs[i] in change) tracked = change[funcs[i]]
            spread(funcs[i])
        }
    }' "$1" | LC_ALL=C sort -t$'\t' -k1,2 -u
}
norm "$1" > "$out/ours.norm"
norm "$2" > "$out/java.norm"

LC_ALL=C awk -F'\t' -v out="$out" -v samples="${SAMPLES:-2}" -v width="${WIDTH:-240}" '
function note(state, kind, key, ours, java,    f) {
    n[kind, state]++
    kinds[kind] = 1
    if (state == "equal") return
    f = out "/" kind "." state
    print key "\n  ours: " ours "\n  java: " java > f
    if (shown[kind, state]++ < samples)
        sample[kind] = sample[kind] sprintf("  %s %s %s\n    ours: %s\n    java: %s\n", state, kind, key, substr(ours, 1, width), substr(java, 1, width))
}
FNR == NR { ours[$1 FS $2] = $3; next }
{
    k = $1 FS $2
    if (k in ours) {
        note(ours[k] == $3 ? "equal" : "different", $1, $2, ours[k], $3)
        delete ours[k]
    } else note("missing", $1, $2, "", $3)
}
END {
    for (k in ours) { split(k, p, FS); note("extra", p[1], p[2], ours[k], "") }
    order = "func body extref data label string undef block wref tracked override comments depth coretypes type ns underived"
    m = split(order, o, " ")
    printf "%-10s %8s %9s %8s %8s %8s  %s\n", "kind", "equal", "different", "missing", "extra", "java", "equal/java"
    for (i = 1; i <= m; i++) {
        k = o[i]
        if (!(k in kinds)) continue
        e = n[k, "equal"] + 0; d = n[k, "different"] + 0; mi = n[k, "missing"] + 0; x = n[k, "extra"] + 0
        j = e + d + mi
        printf "%-10s %8d %9d %8d %8d %8d  %s\n", k, e, d, mi, x, j, j ? sprintf("%.1f%%", 100 * e / j) : "-"
    }
    if (samples > 0) for (i = 1; i <= m; i++) if (o[i] in sample) printf "%s", sample[o[i]]
}' "$out/ours.norm" "$out/java.norm" | tee "$out/summary.txt"
rm "$out/ours.norm" "$out/java.norm"
