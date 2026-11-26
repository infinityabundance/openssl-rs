#!/usr/bin/env bash
# run_alloc_row.sh — the `ecdsa256` allocation row, with the existing instruments.
#
# This is `courts/phase18/timing/bench_api.c` and
# `courts/phase18/timing/alloc_probe.c` compiled and invoked exactly as
# `timing-553e1b8c/run_timing.sh` compiles and invokes them, in `--alloc` mode,
# with the same fixtures and the same `--lib <subject>`. It reads only the
# `ALLOC ecdsa256` line, so it measures the recorded row and nothing else.
# Several alternating repetitions per subject, because the count is
# value-dependent (the reductions' limb lengths vary between signatures).
#
#   OPENSSL_RS_COURT_MEM=8g OPENSSL_RS_COURT_MEMSWAP=8g \
#     bash docker/openssl-rs-court.sh exec env CARGO_BUILD_JOBS=4 \
#       bash evidence/performance-frontier/campaigns/PFP-2/alloc-profile/run_alloc_row.sh
set -euo pipefail

ROOT=/work
# shellcheck source=/dev/null
. "$ROOT/forensics/tools/require_court.sh"

WORK="$ROOT/evidence/performance-frontier/campaigns/PFP-2/alloc-profile"
FIX="$ROOT/evidence/performance-frontier/campaigns/PFP-2/timing-553e1b8c/fixtures"
RSA_DER="$ROOT/courts/phase18/timing/fixtures/rsa2048.der"
BUILD="$ROOT/court/tmp/pfp24/alloc-row"

OLD="${PFP24_OLD_DSO:-$ROOT/court/tmp/pfp21/a/distribution/libcrypto.so.3}"
NEW="${PFP24_NEW_DSO:-$ROOT/court/tmp/pfp24/distribution/libcrypto.so.3}"
REPS="${PFP24_ALLOC_REPS:-7}"

mkdir -p "$BUILD" "$WORK/raw-24"
cc -O2 -g -Wall -Wextra -I "$ROOT/forensics/authorities/prefix/openssl-3.6.4-production/include" \
   "$ROOT/courts/phase18/timing/bench_api.c" -ldl -lm -o "$BUILD/bench_api"
cc -O2 -fPIC -shared "$ROOT/courts/phase18/timing/alloc_probe.c" -ldl \
   -o "$BUILD/alloc_probe.so"

COMMON=(--rsa-der "$RSA_DER"
        --dh-ffdhe2048 "$FIX/ffdhe2048.hex"
        --dh-ffdhe3072 "$FIX/ffdhe3072.hex"
        --dh-modp2048 "$FIX/modp2048.hex")

: >"$WORK/raw-24/alloc-row.tsv"
printf 'rep\tsubject\tdso_sha256\tallocs_per_op\titers\n' >>"$WORK/raw-24/alloc-row.tsv"

run() { # rep subject dso
    local rep=$1 subject=$2 dso=$3 out
    out="$BUILD/$rep-$subject.out"
    LD_PRELOAD="$BUILD/alloc_probe.so" LD_LIBRARY_PATH="$(dirname "$dso")" \
        taskset -c 1 "$BUILD/bench_api" --lib "$dso" "${COMMON[@]}" --alloc >"$out"
    grep -q "^LOADED " "$out" || { echo "no LOADED line in $out" >&2; exit 1; }
    local n
    n="$(sed -n 's/^ALLOC ecdsa256 allocs_per_op=\([0-9.]*\).*/\1/p' "$out")"
    [ -n "$n" ] || { echo "no ALLOC ecdsa256 line in $out" >&2; exit 1; }
    printf '%s\t%s\t%s\t%s\t5\n' "$rep" "$subject" \
        "$(sha256sum "$dso" | awk '{print $1}')" "$n" >>"$WORK/raw-24/alloc-row.tsv"
}

for rep in $(seq -w 0 $((REPS - 1))); do
    if [ $((10#$rep % 2)) -eq 0 ]; then
        run "$rep" old "$OLD"; run "$rep" new "$NEW"
    else
        run "$rep" new "$NEW"; run "$rep" old "$OLD"
    fi
done

python3 - "$WORK/raw-24/alloc-row.tsv" <<'PY'
import statistics, sys
rows = [l.split("\t") for l in open(sys.argv[1]).read().splitlines()[1:]]
by = {}
for rep, subj, sha, n, iters in rows:
    by.setdefault(subj, []).append(float(n))
for subj in ("old", "new"):
    xs = by[subj]
    print("%s: %s  min=%.3f max=%.3f median=%.3f  (n=%d)"
          % (subj, " ".join("%.3f" % x for x in xs), min(xs), max(xs),
             statistics.median(xs), len(xs)))
if "old" in by and "new" in by:
    print("median ratio new/old = %.4f" %
          (statistics.median(by["new"]) / statistics.median(by["old"])))
PY
