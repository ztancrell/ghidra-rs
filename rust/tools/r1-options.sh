#!/bin/bash
# Writes the options of the rule-stage checks: S4's options (s4-options.txt) with more groups on,
# and `option togglerule <rule> off` for every rule of `oppool1` whose group is on and which
# ghidra-rs does not port yet (the table in ghidra-rs/src/decomp/rules/mod.rs). Rerun it when
# rules land. It writes both files:
#   rust/tools/corpus/r1-options.txt      group `analysis` on (the R1/R3 check)
#   rust/tools/corpus/subvar-options.txt  groups `analysis` and `subvar` on (the R3 subvar check)
set -e
rust=$(cd "$(dirname "$0")/.." && pwd)
cpp=$rust/../Ghidra/Features/Decompiler/src/decompile/cpp
ported=" $(grep -o '"[a-z0-9_]*", "[a-z]*", &\[' "$rust/ghidra-rs/src/decomp/rules/mod.rs" | cut -d'"' -f2 | tr '\n' ' ') "
# class -> rule name, from the constructors `RuleX(const string &g) : Rule(g, 0, "name")`
names=$(grep -ho 'Rule[A-Za-z0-9]*(const string &g[^)]*) : Rule( *g *, *[^,]*, *"[a-z0-9_]*")' "$cpp"/*.hh |
    sed 's/(.*"\([a-z0-9_]*\)")/ \1/')
# RulePtrFlow's constructor is in ruleaction.cc (it takes the architecture too)
names="$names
RulePtrFlow ptrflow"
# write <file> <groups switched on in addition to S4's>
write() {
    local out=$rust/tools/corpus/$1 on=" $2 deadcode nodejoin conditionalexe protorecovery " off
    off=$(for g in $2; do printf 'decompile %s off\\|' "$g"; done)
    {
        grep -v "${off}togglerule" "$rust/tools/corpus/s4-options.txt"
        sed -n '/actprop = new ActionPool/,/actstackstall->addAction( actprop )/p' "$cpp/coreaction.cc" |
            grep -o 'new Rule[A-Za-z0-9]*("[a-z_]*"' | sed 's/new //; s/("/ /; s/"//' |
            while read -r cls grp; do
                case "$on" in *" $grp "*) ;; *) continue ;; esac
                n=$(awk -v c="$cls" '$1==c{print $2}' <<<"$names")
                [ -n "$n" ] || { echo "no rule name for $cls" >&2; exit 1; }
                case "$ported" in *" $n "*) ;; *) echo "option togglerule $n off" ;; esac
            done
    } > "$out"
    echo "$1 togglerules: $(grep -c togglerule "$out")"
}
echo "ported:$ported"
write r1-options.txt "analysis"
write subvar-options.txt "analysis subvar"
