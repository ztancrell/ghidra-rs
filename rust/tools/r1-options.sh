#!/bin/bash
# Writes the options of the rule-stage checks: S4's options (s4-options.txt) with more groups on,
# and `option togglerule <rule> off` for every rule of `oppool1` and of the `cleanup` pool whose
# group is on and which ghidra-rs does not port yet, and of `oppool2` (the tables in
# ghidra-rs/src/decomp/rules/mod.rs). Rerun it when rules land. It writes sixteen files (the last, default-options.txt, holds only
# the unported rules of every group, for the default-options check `pcd`); each line
# names the file it is built on:
#   rust/tools/corpus/r1-options.txt      s4-options.txt with groups `analysis`, `cleanup` on (the R1/R2/R3 check)
#   rust/tools/corpus/subvar-options.txt  r1-options.txt with `subvar` on (the R3 subvar check)
#   rust/tools/corpus/r4-options.txt      r1-options.txt with `floatprecision` on (the R4 check)
#   rust/tools/corpus/s8-options.txt      s4-options.txt with `blockrecovery`, `returnsplit` on (S8)
#   rust/tools/corpus/s8-r-options.txt    r1-options.txt with them on (S8, rule stages)
#   rust/tools/corpus/r5-options.txt      r1-options.txt with `typerecovery` on (the R5 check: pointer rules)
#   rust/tools/corpus/r5c-options.txt     r5-options.txt with `constsequence`, `bitfields` on (R5 slice 5)
#   rust/tools/corpus/r5d-options.txt     r1-options.txt with `doubleload`, `doubleprecis` on (R5 slice 3: double.cc, untyped)
#   rust/tools/corpus/r5dt-options.txt    r5-options.txt with `doubleload`, `doubleprecis` on (double.cc with types)
#   rust/tools/corpus/r5s-options.txt     r5-options.txt with `stackvars` on (R5 slice 2: stack loads/stores)
#   rust/tools/corpus/s8-t-options.txt    s6-options.txt with `blockrecovery`, `returnsplit` on (tail)
#   rust/tools/corpus/tail-r-options.txt  s8-r-options.txt with `localrecovery` on (tail, prototypes)
#   rust/tools/corpus/tail-t-options.txt  s8-t-options.txt with `localrecovery` on (tail, prototypes)
#   rust/tools/corpus/sw-r-options.txt    s8-r-options.txt with `switchnorm` on (switchnorm, finalstructure)
#   rust/tools/corpus/sw-t-options.txt    s8-t-options.txt with `switchnorm` on (switchnorm, finalstructure)
set -e
rust=$(cd "$(dirname "$0")/.." && pwd)
cpp=$rust/../Ghidra/Features/Decompiler/src/decompile/cpp
ported=" $(grep -o '"[a-z0-9_]*", "[a-z]*", &\[' "$rust/ghidra-rs/src/decomp/rules/mod.rs" | cut -d'"' -f2 | tr '\n' ' ') "
# `aliasupdate` is ported for the partial function of jump-table recovery, where the `decompile`
# options do not reach. In the function itself it fails on the INDIRECTs of an indexed stack STORE
# (the value-set range of the store guard is not ported), so the checks keep it off there.
ported=${ported/ aliasupdate / }
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
write r5c-options.txt "analysis cleanup typerecovery constsequence bitfields"
write r5d-options.txt "analysis cleanup doubleload doubleprecis"
write r5dt-options.txt "analysis cleanup typerecovery doubleload doubleprecis"
write r5s-options.txt "analysis cleanup typerecovery stackvars"
# stage S8's checks: the S4 and rule-stage options with groups `blockrecovery` and `returnsplit` on
grep -v "decompile blockrecovery off\|decompile returnsplit off" "$rust/tools/corpus/s4-options.txt" > "$rust/tools/corpus/s8-options.txt"
grep -v "decompile blockrecovery off\|decompile returnsplit off" "$rust/tools/corpus/r1-options.txt" > "$rust/tools/corpus/s8-r-options.txt"
echo "s8-options.txt, s8-r-options.txt: blockrecovery and returnsplit on"
# the tail checks (latedonothing .. finalstructure): S7's types-on options with the same two groups
# on; the rules-on tail check uses s8-r-options.txt
grep -v "decompile blockrecovery off\|decompile returnsplit off" "$rust/tools/corpus/s6-options.txt" > "$rust/tools/corpus/s8-t-options.txt"
echo "s8-t-options.txt: s6-options.txt with blockrecovery and returnsplit on"
# the prototype checks (outputprototype, inputprototype, mapglobals): the same two with group
# `localrecovery` on, so that `outputprototype` runs; its two unported actions are skipped on both
# engines (DECOMP_SKIP_ACTIONS=restructure_varnode,mapped_local_sync)
grep -v "decompile localrecovery off" "$rust/tools/corpus/s8-r-options.txt" > "$rust/tools/corpus/tail-r-options.txt"
grep -v "decompile localrecovery off" "$rust/tools/corpus/s8-t-options.txt" > "$rust/tools/corpus/tail-t-options.txt"
echo "tail-r-options.txt, tail-t-options.txt: s8-r/s8-t with localrecovery on"
# the switch checks (switchnorm, and finalstructure with case labels): s8-r/s8-t with group
# `switchnorm` on
grep -v "decompile switchnorm off" "$rust/tools/corpus/s8-r-options.txt" > "$rust/tools/corpus/sw-r-options.txt"
grep -v "decompile switchnorm off" "$rust/tools/corpus/s8-t-options.txt" > "$rust/tools/corpus/sw-t-options.txt"
echo "sw-r-options.txt, sw-t-options.txt: s8-r/s8-t with switchnorm on"
# the default-options check (pcd): no group off, only the rules not ported yet (of every group)
all=" analysis cleanup subvar floatprecision typerecovery constsequence bitfields doubleload doubleprecis stackvars deadcode nodejoin conditionalexe protorecovery segment splitcopy splitpointer "
{
    pool "$all" 'actprop = new ActionPool' 'actstackstall->addAction( actprop )'
    pool "$all" 'actprop2 = new ActionPool' 'actmainloop->addAction( actprop2 )'
    pool "$all" 'actcleanup = new ActionPool' 'act->addAction( actcleanup )'
} > "$rust/tools/corpus/default-options.txt"
echo "default-options.txt togglerules: $(grep -c togglerule "$rust/tools/corpus/default-options.txt")"
