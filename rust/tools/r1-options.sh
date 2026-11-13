#!/bin/bash
# Writes rust/tools/corpus/r1-options.txt, the options of the rule-stage check: S4's options
# (s4-options.txt) with groups `analysis` and `cleanup` on, and `option togglerule <rule> off` for
# every rule of `oppool1` and of the `cleanup` pool whose group is on and which ghidra-rs does not
# port yet (the tables in ghidra-rs/src/decomp/rules/mod.rs). Rerun it when rules land.
set -e
rust=$(cd "$(dirname "$0")/.." && pwd)
cpp=$rust/../Ghidra/Features/Decompiler/src/decompile/cpp
ported=" $(grep -o '"[a-z0-9_]*", "[a-z]*", &\[' "$rust/ghidra-rs/src/decomp/rules/mod.rs" | cut -d'"' -f2 | tr '\n' ' ') "
# class -> rule name, from the constructors `RuleX(const string &g) : Rule(g, 0, "name")`
names=$(grep -ho 'Rule[A-Za-z0-9]*(const string &g[^)]*) : Rule( *g *, *[^,]*, *"[a-z0-9_]*")' "$cpp"/*.hh |
    sed 's/(.*"\([a-z0-9_]*\)")/ \1/')
# the unported rules of one pool: its `addRule` lines in coreaction.cc, between two patterns
pool() {
    sed -n "/$1/,/$2/p" "$cpp/coreaction.cc" |
        grep -o 'new Rule[A-Za-z0-9]*("[a-z_]*"' | sed 's/new //; s/("/ /; s/"//' |
        while read -r cls grp; do
            case " analysis deadcode nodejoin conditionalexe protorecovery cleanup " in *" $grp "*) ;; *) continue ;; esac
            n=$(awk -v c="$cls" '$1==c{print $2}' <<<"$names")
            [ -n "$n" ] || { echo "no rule name for $cls" >&2; exit 1; }
            case "$ported" in *" $n "*) ;; *) echo "option togglerule $n off" ;; esac
        done
}
{
    grep -v "decompile analysis off\|decompile cleanup off\|togglerule" "$rust/tools/corpus/s4-options.txt"
    pool 'actprop = new ActionPool' 'actstackstall->addAction( actprop )'
    pool 'actcleanup = new ActionPool' 'act->addAction( actcleanup )'
} > "$rust/tools/corpus/r1-options.txt"
echo "ported:$ported"
echo "togglerules: $(grep -c togglerule "$rust/tools/corpus/r1-options.txt")"
