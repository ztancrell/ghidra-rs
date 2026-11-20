#!/bin/sh
# Extract the test vectors of Ghidra's Microsoft demangler test suite (MDMangBaseTest.java):
# one line per test method that calls demangleAndTest*():
#   name <TAB> mode <TAB> status <TAB> mangled <TAB> mdTruth
# mode: 64 (demangleAndTest, the configuration's default architecture), F32 (as a 32-bit
# function), 16 (16-bit). status: 0 a test JUnit runs, 1 one in MDMangFailingTestCategory
# (Ghidra fails it too), 2 one JUnit does not run (no @Test, or @Ignore). The strings are the
# Java literal contents (escapes kept, concatenations joined, trailing comments dropped); NULL
# is a truth the method never set. `new String(new byte[] {...}, charset)` is written as what
# Java decodes it to: \uFFFD for the one invalid UTF-8 byte, \uXXXX per UTF-16 byte pair.
# The default (MDBaseTestConfiguration) compares MDMang's output with mdTruth.
# usage: mdmang-vectors.sh [MDMangBaseTest.java] > rust/ghidra-rs/tests/data/mdmang-vectors.tsv
set -eu
src=${1:-"$(dirname "$0")/../../Ghidra/Features/MicrosoftDmang/src/test/java/mdemangler/MDMangBaseTest.java"}
awk '
# the statement up to its ";" (string literals skipped), without a trailing comment
function code(s,   out, c, i, q) {
	out = ""; q = 0
	for (i = 1; i <= length(s); i++) {
		c = substr(s, i, 1)
		if (q && c == "\\") { out = out c substr(s, i + 1, 1); i++; continue }
		if (c == "\"") q = !q
		if (!q && c == ";") return out
		out = out c
	}
	return out
}
function lits(s,   out) {
	out = ""
	while (match(s, /"(\\.|[^"\\])*"/)) {
		out = out substr(s, RSTART + 1, RLENGTH - 2)
		s = substr(s, RSTART + RLENGTH)
	}
	return out
}
function bytes(s,   n, b, i, out) {
	n = split(s, b, /0x/)
	if (s ~ /UTF-16/) {
		out = ""
		for (i = 2; i < n; i += 2) out = out "\\u" toupper(substr(b[i], 1, 2) substr(b[i + 1], 1, 2))
		return out
	}
	return "\\uFFFD"
}
function assign(stmt,   var, rhs) {
	var = stmt; sub(/^[ \t]*/, "", var); sub(/[ \t]*=.*/, "", var)
	rhs = stmt; sub(/^[^=]*=[ \t]*/, "", rhs)
	if (rhs ~ /^[A-Za-z0-9]+[ \t]*=[^=]/) { assign(rhs); sub(/[ \t]*=.*/, "", rhs); v[var] = v[rhs] }
	else if (rhs ~ /^"/) v[var] = lits(rhs)
	else if (rhs ~ /^new String\(new byte\[\]/) v[var] = bytes(rhs)
	else { sub(/[ \t]+$/, "", rhs); v[var] = (rhs in v) ? v[rhs] : "NULL" }
}
/^[ \t]*\/\// { next }
/@Category\(MDMangFailingTestCategory/ { failing = 1 }
/^[ \t]*@Test/ { istest = 1 }
/^[ \t]*@Ignore/ { ignored = 1 }
/public void [A-Za-z0-9_]+\(\)/ {
	name = $0; sub(/.*public void /, "", name); sub(/\(.*/, "", name)
	split("", v); stmt = ""
	if (!istest || ignored) failing = 2
	istest = 0; ignored = 0
}
stmt != "" { stmt = stmt " " $0; sub(/^[ \t]+/, "", stmt) }
stmt == "" && /^[ \t]*(mangled|msTruth|mdTruth|ghTruth|dbTruth|ms2013Truth)[ \t]*=/ { stmt = $0 }
stmt != "" {
	c = code(stmt)
	if (c != stmt) { assign(c); stmt = "" }
}
/demangleAndTest[A-Za-z0-9]*\(\);/ {
	mode = "64"
	if ($0 ~ /Function32Bit/) mode = "F32"
	if ($0 ~ /16Bit/) mode = "16"
	m = ("mangled" in v) ? v["mangled"] : "NULL"
	t = ("mdTruth" in v) ? v["mdTruth"] : "NULL"
	printf "%s\t%s\t%d\t%s\t%s\n", name, mode, failing, m, t
	failing = 0
}
' "$src"
