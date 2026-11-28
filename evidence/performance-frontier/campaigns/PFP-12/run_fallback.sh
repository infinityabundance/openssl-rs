#!/bin/sh
# run_fallback.sh — prove the portable arm is live and measure it.
#
# The candidate is run with `OPENSSL_ia32cap=":~0x20000000"`, which clears the
# CPUID SHA extension bit (7.0.EBX bit 29) through the crate's `~` clear-mask
# support, forcing the portable SHA-256 compression. The same KAT/differential
# and the same paired timing are then run, against the unmodified authority.
set -eu
cd /work
. /work/forensics/tools/require_court.sh

EV=/work/evidence/performance-frontier/campaigns/PFP-12
OUT=${PFP12_OUT:-/work/court/tmp/pfp12}
CAND=$OUT/distribution/libcrypto.so.3
AUTH=/work/forensics/authorities/prefix/openssl-3.6.4-production/lib/libcrypto.so.3
B=$OUT/bench_pfp12
D=$OUT/fallback
T=$OUT/fallback-timing
CPU=${PFP12_CPU:-1}
REPS=${PFP12_REPS:-15}

mkdir -p "$D" "$T"
rm -f "$D"/*.out "$D"/*.err "$T"/*.out "$T"/*.err

for op in aes128gcm-64 aes128gcm-16k aes256gcm-64 aes256gcm-16k \
          chachapoly-64 chachapoly-16k sha256-16k sha512-16k; do
    OPENSSL_ia32cap=':~0x20000000' "$B" --lib "$CAND" --once --op "$op" \
        >"$D/cand-$op.out" 2>"$D/cand-$op.err"
    "$B" --lib "$AUTH" --once --op "$op" >"$D/auth-$op.out" 2>"$D/auth-$op.err"
done
OPENSSL_ia32cap=':~0x20000000' "$B" --lib "$CAND" --kat \
    >"$D/cand-kat.out" 2>"$D/cand-kat.err"
"$B" --lib "$AUTH" --kat >"$D/auth-kat.out" 2>"$D/auth-kat.err"
python3 "$EV/compare_diff.py" --dir "$D" --out "$EV/raw/fallback-diff.json"

rep=1
while [ "$rep" -le "$REPS" ]; do
    if [ $((rep % 2)) -eq 1 ]; then order="cand auth"; else order="auth cand"; fi
    for tag in $order; do
        case "$tag" in
            cand)
                OPENSSL_ia32cap=':~0x20000000' taskset -c "$CPU" "$B" --lib "$CAND" \
                    --op sha256-16k --iters 64 --runs 5 \
                    >"$T/cand-sha256-16k-r$(printf %02d "$rep").out" \
                    2>"$T/cand-sha256-16k-r$(printf %02d "$rep").err"
                ;;
            auth)
                taskset -c "$CPU" "$B" --lib "$AUTH" \
                    --op sha256-16k --iters 64 --runs 5 \
                    >"$T/auth-sha256-16k-r$(printf %02d "$rep").out" \
                    2>"$T/auth-sha256-16k-r$(printf %02d "$rep").err"
                ;;
        esac
    done
    echo "fallback rep $rep/$REPS done"
    rep=$((rep + 1))
done
python3 "$EV/analyse_timing.py" --dir "$T" --ops sha256-16k \
    --out "$EV/raw/fallback-timing.json"
echo FALLBACK_OK
