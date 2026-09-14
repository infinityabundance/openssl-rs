#!/bin/sh
# openssl-rs FRF AUTHORITY side: CLI inventory membership for a fixture name list.
#
# Both sides of this court are REAL OpenSSL binaries (the admitted 3.6.3
# historical authority and the 3.6.4 production authority), so the court is
# fixture-driven without needing a candidate CLI that does not exist yet.
#
# WHY IT IS FIXTURE-DRIVEN: an FRF court whose arguments do not reference
# {fixture} cannot be challenged -- the mutant wrapper cannot locate the
# reference object (docs/DECISIONS.md D13) -- so its sensitivity evidence is
# unobtainable. The fixture here is the query list, which makes the court
# challengeable and replaces the two earlier courts whose sensitivity evidence
# could not be produced.
set -eu
PREFIX=/work/forensics/authorities/prefix/openssl-3.6.3-historical
export LD_LIBRARY_PATH="$PREFIX/lib"
export OPENSSL_MODULES="$PREFIX/lib/ossl-modules"
export OPENSSL_CONF=/dev/null

LIST="${1:?usage: authority-cli-inventory.sh <name-list>}"

DIS="$(  "$PREFIX/bin/openssl" list -disabled 2>/dev/null | sed -n 's/^Disabled algorithms: *//p' )"
CIP="$(  "$PREFIX/bin/openssl" list -cipher-algorithms -1 2>/dev/null | sed 's/ @ .*//' )"

while IFS= read -r name; do
  [ -n "$name" ] || continue
  if printf '%s\n' "$DIS" | tr ' ' '\n' | grep -qx -- "$name"; then
    printf '%s\tDISABLED\n' "$name"
  elif printf '%s\n' "$CIP" | grep -qx -- "$name"; then
    printf '%s\tCIPHER\n' "$name"
  else
    printf '%s\tABSENT\n' "$name"
  fi
done < "$LIST"
exit 0
