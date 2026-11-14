#!/bin/bash
# Writes the options of the rule-stage checks: S4's options (s4-options.txt) with more groups on,
# and `option togglerule <rule> off` for every rule of `oppool1` and of the `cleanup` pool whose
# group is on and which ghidra-rs does not port yet, and of `oppool2` (the tables in
# ghidra-rs/src/decomp/rules/mod.rs). Rerun it when rules land. It writes six files:
#   rust/tools/corpus/r1-options.txt      groups `analysis`, `cleanup` on (the R1/R2/R3 check)
#   rust/tools/corpus/subvar-options.txt  also `subvar` on (the R3 subvar check)
#   rust/tools/corpus/r4-options.txt      also `floatprecision` on (the R4 check)
#   rust/tools/corpus/s8-options.txt      s4-options.txt with `blockrecovery` on (the S8 check)
#   rust/tools/corpus/s8-r-options.txt    r1-options.txt with `blockrecovery` on (S8, rule stages)
#   rust/tools/corpus/r5-options.txt      also `typerecovery` on (the R5 check: pointer rules)
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
# pool <groups on> <first line pattern> <last line pattern>: the unported rules of one pool, from
# its `addRule` lines in coreaction.cc
pool() {
    sed -n "/$2/,/$3/p" "$cpp/coreaction.cc" | grep -v '^[[:space:]]*//' |
        grep -o 'new Rule[A-Za-z0-9]*("[a-z_]*"' | sed 's/new //; s/("/ /; s/"//' |
        while read -r cls grp; do
            case "$1" in *" $grp "*) ;; *) continue ;; esac
            n=$(awk -v c="$cls" '$1==c{print $2}' <<<"$names")
            [ -n "$n" ] || { echo "no rule name for $cls" >&2; exit 1; }
            case "$ported" in *" $n "*) ;; *) echo "option togglerule $n off" ;; esac
        done
}
# write <file> <groups switched on in addition to S4's>
write() {
    local out=$rust/tools/corpus/$1 on=" $2 deadcode nodejoin conditionalexe protorecovery " off
    off=$(for g in $2; do printf 'decompile %s off\\|' "$g"; done)
    {
        grep -v "${off}togglerule" "$rust/tools/corpus/s4-options.txt"
        pool "$on" 'actprop = new ActionPool' 'actstackstall->addAction( actprop )'
        pool "$on" 'actprop2 = new ActionPool' 'actmainloop->addAction( actprop2 )'
        pool "$on" 'actcleanup = new ActionPool' 'act->addAction( actcleanup )'
    } > "$out"
    echo "$1 togglerules: $(grep -c togglerule "$out")"
}
echo "ported:$ported"
write r1-options.txt "analysis cleanup"
write subvar-options.txt "analysis cleanup subvar"
write r4-options.txt "analysis cleanup floatprecision"
write r5-options.txt "analysis cleanup typerecovery"
# stage S8's checks: the S4 and rule-stage options with group `blockrecovery` on
grep -v "decompile blockrecovery off" "$rust/tools/corpus/s4-options.txt" > "$rust/tools/corpus/s8-options.txt"
grep -v "decompile blockrecovery off" "$rust/tools/corpus/r1-options.txt" > "$rust/tools/corpus/s8-r-options.txt"
echo "s8-options.txt, s8-r-options.txt: blockrecovery on"
