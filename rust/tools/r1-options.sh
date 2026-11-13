#!/bin/bash
# Writes rust/tools/corpus/r1-options.txt, the options of the rule-stage check: S4's options
# (s4-options.txt) with group `analysis` on, and `option togglerule <rule> off` for every rule of
# `oppool1` whose group is on and which ghidra-rs does not port yet (the table in
# ghidra-rs/src/decomp/rules/mod.rs). Rerun it when rules land.
set -e
rust=$(cd "$(dirname "$0")/.." && pwd)
cpp=$rust/../Ghidra/Features/Decompiler/src/decompile/cpp
ported=" $(grep -o '"[a-z0-9_]*", "[a-z]*", &\[' "$rust/ghidra-rs/src/decomp/rules/mod.rs" | cut -d'"' -f2 | tr '\n' ' ') "
# class -> rule name, from the constructors `RuleX(const string &g) : Rule(g, 0, "name")`
names=$(grep -ho 'Rule[A-Za-z0-9]*(const string &g[^)]*) : Rule( *g *, *[^,]*, *"[a-z0-9_]*")' "$cpp"/*.hh |
    sed 's/(.*"\([a-z0-9_]*\)")/ \1/')
{
    grep -v "decompile analysis off\|togglerule" "$rust/tools/corpus/s4-options.txt"
    sed -n '/actprop = new ActionPool/,/actstackstall->addAction( actprop )/p' "$cpp/coreaction.cc" |
        grep -o 'new Rule[A-Za-z0-9]*("[a-z_]*"' | sed 's/new //; s/("/ /; s/"//' |
        while read -r cls grp; do
            case " analysis deadcode nodejoin conditionalexe protorecovery " in *" $grp "*) ;; *) continue ;; esac
            n=$(awk -v c="$cls" '$1==c{print $2}' <<<"$names")
            [ -n "$n" ] || { echo "no rule name for $cls" >&2; exit 1; }
            case "$ported" in *" $n "*) ;; *) echo "option togglerule $n off" ;; esac
        done
} > "$rust/tools/corpus/r1-options.txt"
echo "ported:$ported"
echo "togglerules: $(grep -c togglerule "$rust/tools/corpus/r1-options.txt")"
