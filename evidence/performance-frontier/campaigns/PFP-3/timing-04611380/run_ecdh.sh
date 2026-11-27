#!/bin/sh
# run_ecdh.sh — PFP-3 `ecdh` at 04611380 with the campaign conventions.
#
# The WORKLOADS timing campaign has no `ecdh` row, so this uses the PFP-29
# per-path harness (`pfp29_paths.c`) — the instrument that produced the 226 µs
# figure — with ONE timing-only change: the candidate-layout taint is disabled
# when `--iters > 0`, because it is invalid on the authority DSO and irrelevant
# to wall timing.  The diff is recorded.  The conventions are the campaign's:
# 15 repetitions, taskset -c 1, paired candidate/authority ratios, percentile
# bootstrap CI (20000 resamples, seed 0x50465030), identity checked against
# stat(2).
#
#   OPENSSL_RS_COURT_MEM=4g OPENSSL_RS_COURT_MEMSWAP=4g \
#     bash docker/openssl-rs-court.sh exec sh \
#       evidence/performance-frontier/campaigns/PFP-3/timing-04611380/run_ecdh.sh
set -eu

cd /work
# shellcheck source=/dev/null
. /work/forensics/tools/require_court.sh

EV=/work/evidence/performance-frontier/campaigns/PFP-3/timing-04611380
OUT=/work/court/tmp/pfp3-ecdh
HARNESS=/work/evidence/performance-frontier/campaigns/PFP-3/timing-04611380/pfp3_ecdh_paths.c
PFP29_HARNESS=/work/evidence/performance-frontier/campaigns/PFP-29/pfp29_paths.c
A=/work/court/tmp/pfp3-c/distribution/libcrypto.so.3
AUTH=/work/forensics/authorities/prefix/openssl-3.6.4-production/lib/libcrypto.so.3
EXPECT_A=04611380847a708a591a9786734915c4295cc0e164d94025dc937b797ffb15d4
EXPECT_AUTH=611e511db4273c4b6b522031fd171efce71b80661bb8310c2a21dfd18ec0efd2
REPS=15
PIN_CPU=1
ITERS=20

fail() { printf 'PFP3-ECDH STOP: %s\n' "$*" >&2; exit 1; }
sha() { sha256sum "$1" | awk '{print $1}'; }

[ -f "$A" ] || fail "missing $A"
[ -f "$AUTH" ] || fail "missing $AUTH"
[ "$(sha "$A")" = "$EXPECT_A" ] || fail "A digest $(sha "$A")"
[ "$(sha "$AUTH")" = "$EXPECT_AUTH" ] || fail "authority digest $(sha "$AUTH")"

mkdir -p "$OUT/instrument" "$EV/raw"
diff -u "$PFP29_HARNESS" "$HARNESS" >"$EV/raw/ecdh-harness.diff" || true
cc -O1 -g -Wall -Wextra -o "$OUT/instrument/pfp29_paths" "$HARNESS" -ldl

verify_loaded() { # stdout expected_dso label
    f=$1; dso=$2; label=$3
    rp=$(sed -n 's/^LOADED realpath=\([^ ]*\) .*/\1/p' "$f")
    dev=$(sed -n 's/^LOADED .* dev=\([0-9]*\) .*/\1/p' "$f")
    ino=$(sed -n 's/^LOADED .* ino=\([0-9]*\) .*/\1/p' "$f")
    [ -n "$rp" ] || fail "$label: no LOADED line"
    erp=$(realpath "$dso")
    edev=$(stat -c %d "$erp"); eino=$(stat -c %i "$erp")
    [ "$rp" = "$erp" ] || fail "$label: mapped $rp, expected $erp"
    [ "$dev" = "$edev" ] || fail "$label: dev $dev != $edev"
    [ "$ino" = "$eino" ] || fail "$label: ino $ino != $eino"
}

: >"$EV/raw/ecdh-timing.tsv"
rep=1
while [ "$rep" -le "$REPS" ]; do
    # balanced order: odd reps candidate first, even reps authority first
    if [ $((rep % 2)) -eq 1 ]; then first=candidate; else first=authority; fi
    if [ "$first" = candidate ]; then second=authority; else second=candidate; fi
    for subject in "$first" "$second"; do
        if [ "$subject" = candidate ]; then dso="$A"; else dso="$AUTH"; fi
        taskset -c "$PIN_CPU" "$OUT/instrument/pfp29_paths" \
            --lib "$dso" --mode ecdh --iters "$ITERS" \
            >"$EV/raw/ecdh-$rep-$subject.stdout" 2>&1
        verify_loaded "$EV/raw/ecdh-$rep-$subject.stdout" "$dso" "ecdh/$rep/$subject"
        grep -q '^RESULT mode=ecdh ok=1' "$EV/raw/ecdh-$rep-$subject.stdout" \
            || fail "ecdh/$rep/$subject: operation failed"
        ns=$(sed -n 's/^TIME .* ns_per_op=\([0-9.]*\).*/\1/p' "$EV/raw/ecdh-$rep-$subject.stdout")
        [ -n "$ns" ] || fail "ecdh/$rep/$subject: no timing"
        printf '%s\t%s\t%s\n' "$rep" "$subject" "$ns" >>"$EV/raw/ecdh-timing.tsv"
    done
    rep=$((rep + 1))
done

python3 - "$EV/raw/ecdh-timing.tsv" "$EV/raw/ecdh-timing.json" "$EXPECT_A" <<'PY'
import json, random, statistics, sys
src, out = sys.argv[1], sys.argv[2]
rows = {}
for line in open(src):
    rep, subject, ns = line.split("\t")
    rows.setdefault(int(rep), {})[subject] = float(ns)
ratios, cand, auth = [], [], []
for rep in sorted(rows):
    c, a = rows[rep]["candidate"], rows[rep]["authority"]
    ratios.append(c / a); cand.append(c); auth.append(a)
med_ratio = statistics.median(ratios)
rng = random.Random(0x50465030)
boot = []
for _ in range(20000):
    sample = [ratios[rng.randrange(len(ratios))] for _ in ratios]
    boot.append(statistics.median(sample))
boot.sort()
doc = {
    "workload": "ecdh",
    "digest": sys.argv[3],
    "candidate_us_median": statistics.median(cand) / 1000.0,
    "authority_us_median": statistics.median(auth) / 1000.0,
    "ratio_median": med_ratio,
    "ci95": [boot[int(0.025 * len(boot))], boot[int(0.975 * len(boot))]],
    "repetitions": len(ratios),
    "iters_per_rep": 20,
    "bootstrap": {"resamples": 20000, "seed": "0x50465030", "statistic": "median paired ratio"},
}
open(out, "w").write(json.dumps(doc, indent=2, sort_keys=True) + "\n")
print(json.dumps(doc, indent=2, sort_keys=True))
PY

[ "$(sha "$A")" = "$EXPECT_A" ] || fail "A changed during the run"
[ "$(sha "$AUTH")" = "$EXPECT_AUTH" ] || fail "authority changed during the run"
echo "PASS: ecdh timing completed at $EXPECT_A"
