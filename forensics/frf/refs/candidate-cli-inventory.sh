#!/bin/sh
# openssl-rs FRF CANDIDATE side: CLI inventory membership for a fixture name list.
#
# See authority-cli-inventory.sh. This side is the 3.6.4 production authority, so
# the pair is the oracle-vs-oracle trajectory court required by
# docs/SECURITY_DIVERGENCE_POLICY.md §1, exercised over the build-configuration
# and cipher-inventory surfaces -- now in a form that can be challenged.
set -eu
PREFIX=/work/forensics/authorities/prefix/openssl-3.6.4-production
export LD_LIBRARY_PATH="$PREFIX/lib"
export OPENSSL_MODULES="$PREFIX/lib/ossl-modules"
export OPENSSL_CONF=/dev/null

LIST="${1:?usage: candidate-cli-inventory.sh <name-list>}"

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
