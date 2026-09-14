#!/bin/sh
# openssl-rs FRF AUTHORITY side: report name@version for each symbol named in the
# fixture list, read from the admitted authority's own libcrypto.so.3.
#
# The court's subject is the ABI surface: the fixture names the symbols, and each
# side reports what ITS library binds them to. A divergence in the reported
# version is a binary-compatibility divergence with no runtime symptom -- the
# exact class of defect that a symbol-count check cannot see.
#
# The fixture argument is REQUIRED: an FRF court whose arguments do not reference
# {fixture} cannot be challenged (the mutant wrapper cannot locate the reference;
# docs/DECISIONS.md D13), so the fixture is genuinely the query list.
set -eu
LIB=/work/forensics/authorities/prefix/openssl-3.6.4-production/lib/libcrypto.so.3
LIST="${1:?usage: authority-abi-report.sh <symbol-list>}"
TMP=$(mktemp)
nm -D --defined-only --with-symbol-versions "$LIB" | sed 's/.* //' | sort > "$TMP"
while IFS= read -r sym; do
  [ -n "$sym" ] || continue
  hit=$(grep -m1 "^${sym}@@" "$TMP" || true)
  if [ -n "$hit" ]; then printf '%s\t%s\n' "$sym" "$hit"
  else printf '%s\tUNRESOLVED\n' "$sym"; fi
done < "$LIST"
rm -f "$TMP"
exit 0
