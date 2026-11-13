#!/bin/sh
# Compare ghidra-rs output with a Java Ghidra reference (milestone 2c, docs/plans/m2c-pipeline.md).
#   m2c-compare.sh functions <ours.csv> <ref.csv>   ExportFunctions files: common / missing / extra
#       entries, and over the common rows the rate of identical size, callees, callers, data_refs.
#       Writes <ours.csv>.missing (in ref only) and <ours.csv>.extra (in ours only).
#   m2c-compare.sh gaps <ours.csv> <ref.csv>        ExportGaps files: rows identical as whole lines.
#   m2c-compare.sh rows <ours.csv> <ref.csv> <key-col> <value-col>
#       report CSVs (1-based columns, plain comma split): common keys and how many have the same value.
# The first line of every file is a header. Names are quoted and may contain commas, so the
# functions mode only uses the first two fields and the last three.
set -e
usage() { sed -n '2,10p' "$0" >&2; exit 2; }
[ $# -ge 3 ] || usage
mode=$1 ours=$2 ref=$3
[ -r "$ours" ] && [ -r "$ref" ] || { echo "m2c-compare: cannot read $ours or $ref" >&2; exit 2; }
case $mode in
functions)
    awk -F, -v miss="$ours.missing" -v extra="$ours.extra" '
        { sub(/\r$/, "") }
        FNR == 1 { next }
        FNR == NR { r[$1] = $2 FS $(NF-2) FS $(NF-1) FS $NF; nref++; next }
        { nours++
          if (!($1 in r)) { print $1 > extra; nextra++; next }
          split(r[$1], v, FS); seen[$1] = 1; common++
          if (v[1] == $2) size++
          if (v[2] == $(NF-2)) callees++
          if (v[3] == $(NF-1)) callers++
          if (v[4] == $NF) refs++ }
        function pct(n) { return common ? sprintf("%d (%.1f%%)", n, 100 * n / common) : "0 (n/a)" }
        END {
          printf "" > miss; printf "" >> extra
          for (a in r) if (!(a in seen)) { print a > miss; nmiss++ }
          printf "functions: ref %d, ours %d\n", nref, nours
          printf "common %d, missing %d, extra %d\n", common, nmiss, nextra
          printf "over common rows: size %s, callees %s, callers %s, data_refs %s\n",
                 pct(size), pct(callees), pct(callers), pct(refs) }
    ' "$ref" "$ours"
    for f in "$ours.missing" "$ours.extra"; do sort -o "$f" "$f"; done
    ;;
gaps)
    awk '{ sub(/\r$/, "") } FNR == 1 { next }
         FNR == NR { r[$0] = 1; nref++; next }
         { nours++; if ($0 in r) same++ }
         END { printf "gaps: ref %d rows, ours %d rows, identical %d (%.1f%% of ref)\n",
                      nref, nours, same, nref ? 100 * same / nref : 0 }' "$ref" "$ours"
    ;;
rows)
    [ $# -eq 5 ] || usage
    awk -F, -v k="$4" -v v="$5" '{ sub(/\r$/, "") } FNR == 1 { next }
         FNR == NR { r[$k] = $v; nref++; next }
         { nours++; if ($k in r) { common++; if (r[$k] == $v) same++ } }
         END { printf "rows: ref %d, ours %d, common keys %d, same value %d (%.1f%% of common)\n",
                      nref, nours, common, same, common ? 100 * same / common : 0 }' "$ref" "$ours"
    ;;
*) usage ;;
esac
