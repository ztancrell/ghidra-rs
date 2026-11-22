#!/bin/sh
# Writes the unique `_Z` symbol names (symbol table and dynamic symbols, defined or not,
# without version suffixes) of each binary given, one per line, to stdout.
# Usage: gnu-syms.sh BINARY... > names.txt
for f in "$@"; do
	nm -a "$f" 2>/dev/null
	nm -D --without-symbol-versions "$f" 2>/dev/null
done | awk '{print $NF}' | grep '^_Z' | LC_ALL=C sort -u
