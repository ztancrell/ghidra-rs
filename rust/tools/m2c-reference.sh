#!/bin/bash
# Reference run for milestone 2c (docs/plans/m2c-pipeline.md): mercs2's analysis pipeline in
# Java Ghidra, with an ExportFunctions + ExportGaps snapshot after every script, for the
# analysis image (a0..a5) and the original image (o0..o2).
#
# Run from the mercs2 checkout:  bash <ghidra-rs>/rust/tools/m2c-reference.sh
# Needs GHIDRA_HOME (default /opt/ghidra), orig/Mercenaries2.exe, orig/Mercenaries2.analysis.exe,
# build/functions-original.csv, build/slot-rewrites.csv. About 26 minutes (two imports).
# Uses its own project (build/ghidra-m2c); mercs2's build/ghidra and build/functions.csv are
# not touched. Output: build/m2c-ref/. The project state before the fold is kept in
# build/ghidra-m2c-a2 for cheap retries of the later scripts.
#
# The scripts run from copies in build/m2c-ref/scripts, with one patch: FoldSlotFragments.java
# iterates `owners` while fold() adds to it and throws ConcurrentModificationException on
# Ghidra 12.2 (mercs2 395ba6b). The patch makes that loop a worklist; it is identical when
# nothing is added. Drop the patch once mercs2's script is fixed.
set -u
G=${GHIDRA_HOME:-/opt/ghidra}; R=build/m2c-ref
export GHIDRA_HEADLESS_MAXMEM=6G
mkdir -p $R/scripts
grep -h version $G/Ghidra/application.properties > $R/ghidra-version.txt
git rev-parse HEAD > $R/mercs2-commit.txt
cp tools/ghidra/*.java $R/scripts/
sed -i.bak 's|^            for (Address a : owners) {$|            java.util.Set<Address> done = new java.util.HashSet<>(); while (true) { Address a = null; for (Address c : owners) if (done.add(c)) { a = c; break; } if (a == null) break; // m2c patch|' $R/scripts/FoldSlotFragments.java
rm -f $R/scripts/*.bak
diff tools/ghidra/FoldSlotFragments.java $R/scripts/FoldSlotFragments.java > $R/fold.patch
H=("$G/support/analyzeHeadless" build/ghidra-m2c m2c -scriptPath $R/scripts)
snap() { SNAP=(-postScript ExportFunctions.java $R/$1-functions.csv -postScript ExportGaps.java $R/$1-gaps.csv); }
step() { echo "$(date +%T) $1" >> $R/progress.txt; }

step "a import"
snap a0-import; "${H[@]}" -import orig/Mercenaries2.analysis.exe -overwrite "${SNAP[@]}" > $R/a-import.log 2>&1
step "a recover"
snap a1-bindings; S1=("${SNAP[@]}"); snap a2-recover; S2=("${SNAP[@]}")
"${H[@]}" -process Mercenaries2.analysis.exe -noanalysis \
  -postScript ExportBindings.java $R/a1-bindings.csv --recover "${S1[@]}" \
  -postScript RecoverFunctions.java $R/a2-recovery.csv \
  -postScript AuditRecoveredFunctions.java $R/a2-recovery.csv $R/a2-audit.csv --remove-empty "${S2[@]}" > $R/a-recover.log 2>&1
rm -rf build/ghidra-m2c-a2; cp -a build/ghidra-m2c build/ghidra-m2c-a2
step "a fold, relocated, no-return"
snap a3-fold; S3=("${SNAP[@]}"); snap a4-relocated; S4=("${SNAP[@]}"); snap a5-final; S5=("${SNAP[@]}")
"${H[@]}" -process Mercenaries2.analysis.exe -noanalysis \
  -postScript FoldSlotFragments.java build/functions-original.csv build/slot-rewrites.csv $R/a3-fold.csv "${S3[@]}" \
  -postScript AddRelocatedEntries.java config/securom_functions.csv "${S4[@]}" \
  -postScript ClearFalseNoReturn.java $R/a5-noreturn.csv "${S5[@]}" > $R/a-chain.log 2>&1

step "o import"
snap o0-import; "${H[@]}" -import orig/Mercenaries2.exe -overwrite "${SNAP[@]}" > $R/o-import.log 2>&1
step "o recover"
snap o1-bindings; S1=("${SNAP[@]}"); snap o2-recover; S2=("${SNAP[@]}")
"${H[@]}" -process Mercenaries2.exe -noanalysis \
  -postScript ExportBindings.java $R/o1-bindings.csv --recover "${S1[@]}" \
  -postScript RecoverFunctions.java $R/o2-recovery.csv \
  -postScript AuditRecoveredFunctions.java $R/o2-recovery.csv $R/o2-audit.csv --remove-empty "${S2[@]}" > $R/o-chain.log 2>&1
cp build/functions-original.csv build/slot-rewrites.csv $R/
step "DONE"
grep -c ERROR $R/*.log
wc -l $R/*-functions.csv
