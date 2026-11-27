#!/usr/bin/env bash
# PFP-4 / W3 — reproduce the bound in BOUND.md.
#
# Run inside the court (docker/openssl-rs-court.sh exec ...), from /work.
# The subject is the PFP-3 post-fix DSO at digest ecbefb7d; the authority is
# the pinned OpenSSL 3.6.4 prefix. Nothing here changes src/.
set -euo pipefail

ROOT=/work
CAND="$ROOT/court/tmp/pfp3-d/distribution"
AUTH_INC="$ROOT/forensics/authorities/prefix/openssl-3.6.4-production/include"
HARNESS="$ROOT/evidence/performance-frontier/campaigns/PFP-4/profile"
OUT="$HARNESS"

cc -O2 -g -Wno-deprecated-declarations -Wall -Wextra -I "$AUTH_INC" \
   "$OUT/pfp4_profile.c" "$CAND/libcrypto.so.3" -ldl -o /tmp/pfp4_profile

# Wall decomposition: sign, k*G, s-expression, order inverse, reductions.
taskset -c 1 env LD_LIBRARY_PATH="$CAND" /tmp/pfp4_profile all 3000 \
   "$CAND/libcrypto.so.3" | tee "$OUT/profile-wall.txt"

# Independent instruction attribution (no hardware PMU is available here).
taskset -c 1 env LD_LIBRARY_PATH="$CAND" \
   valgrind --tool=callgrind --callgrind-out-file="$OUT/callgrind-sign.out" \
   /tmp/pfp4_profile sign 60 >/dev/null
callgrind_annotate --inclusive=yes --threshold=99.5 "$OUT/callgrind-sign.out" \
   | head -70

# Root-owned court output is chowned back to the checkout owner.
chown -R "$(stat -c %u "$ROOT/.git")":"$(stat -c %g "$ROOT/.git")" "$OUT" || true
