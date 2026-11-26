#!/bin/sh
# b_equivalence.sh — check that the mutation-control DSO B computes the same
# points as the 3.6.4 authority.
#
# The mutation control is only meaningful if B is a valid population rather than
# a broken build.  This uses the campaign's DSO-bound differential harness (the
# one that produced dso-differential-pfp20) with its recorded seed, at a reduced
# count, against B and the authority, and compares the serialised points.  A
# single mismatch is a STOP.
#
#   bash docker/openssl-rs-court.sh exec sh \
#     evidence/performance-frontier/campaigns/PFP-2/ctgrind/pfp21-2026-11-26/b_equivalence.sh
set -eu

cd /work
# shellcheck source=/dev/null
. /work/forensics/tools/require_court.sh

EV=/work/evidence/performance-frontier/campaigns/PFP-2/ctgrind/pfp21-2026-11-26
H=/work/evidence/performance-frontier/campaigns/PFP-2/dso-differential-pfp20/build/pfp2_dso_differential
B=/work/court/tmp/pfp21/b/distribution/libcrypto.so.3
AUTH=/work/forensics/authorities/prefix/openssl-3.6.4-production/lib/libcrypto.so.3
SEED=0x5046503250485032
COUNT=256

EXPECT_B=86bc63a6746e2e7bad628f7e7e6df477c3355759582e0611109af3e08156765e
[ "$(sha256sum "$B" | awk '{print $1}')" = "$EXPECT_B" ] || {
    echo "PFP21 STOP: control B digest" >&2
    exit 1
}

{
    printf 'control_b_sha256=%s\n' "$(sha256sum "$B" | awk '{print $1}')"
    printf 'authority_sha256=%s\n' "$(sha256sum "$AUTH" | awk '{print $1}')"
    printf 'seed=%s count=%s\n' "$SEED" "$COUNT"
    for m in mul-g mul-p; do
        "$H" --lib "$B" --seed "$SEED" --mode "$m" --count "$COUNT" \
            >"$EV/raw/beq-b-$m.out" 2>"$EV/raw/beq-b-$m.err"
        "$H" --lib "$AUTH" --seed "$SEED" --mode "$m" --count "$COUNT" \
            >"$EV/raw/beq-auth-$m.out" 2>"$EV/raw/beq-auth-$m.err"
        bp=$(grep -c '^POINT ' "$EV/raw/beq-b-$m.out")
        ap=$(grep -c '^POINT ' "$EV/raw/beq-auth-$m.out")
        [ "$bp" = "$COUNT" ] || { echo "PFP21 STOP: $m B points $bp" >&2; exit 1; }
        [ "$ap" = "$COUNT" ] || { echo "PFP21 STOP: $m authority points $ap" >&2; exit 1; }
        grep '^POINT ' "$EV/raw/beq-b-$m.out" >"$EV/raw/beq-b-$m.pts"
        grep '^POINT ' "$EV/raw/beq-auth-$m.out" >"$EV/raw/beq-auth-$m.pts"
        if cmp -s "$EV/raw/beq-b-$m.pts" "$EV/raw/beq-auth-$m.pts"; then
            printf '%s compared=%s mismatches=0\n' "$m" "$COUNT"
        else
            printf '%s MISMATCH\n' "$m"
            exit 1
        fi
        grep '^LOADED ' "$EV/raw/beq-b-$m.out" | sed "s/^/$m b /"
    done
} | tee "$EV/raw/b-equivalence.txt"
echo "PASS: mutation-control DSO B is point-identical to the authority"
