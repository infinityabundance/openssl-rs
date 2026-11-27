#!/usr/bin/env bash
# PFP-7 timing at the candidate digest: 15 paired process repetitions per arm,
# pinned to one core.  For each repetition the harness reports per-call samples,
# from which three statistics are derived in the same process:
#   latency    = min per-call time (the steady-state op, no blinding refresh)
#   throughput = 1 / mean per-call time (sustained loop, refresh amortised)
#   blockmed   = median of five 20-call batch means after 5 warm-up calls
#                (the PFP-0/PFP-6 row statistic, reproduced here)
set -euo pipefail
ROOT=/work
BUILD=${BUILD:-/work/court/tmp/pfp7/build}
DIR=/work/court/tmp/pfp7/timing
DSO="$BUILD/distribution/libcrypto.so.3"
AUTH="$ROOT/forensics/authorities/prefix/openssl-3.6.4-production/lib/libcrypto.so.3"
AUTH_INC="$ROOT/forensics/authorities/prefix/openssl-3.6.4-production/include"
RSA_DER="$ROOT/courts/phase18/timing/fixtures/rsa2048.der"
CPU="${PFP7_PIN_CPU:-1}"
REPS="${PFP7_REPS:-15}"
mkdir -p "$DIR"
cc -O2 -g -Wall -Wextra -I "$AUTH_INC" \
   "$ROOT/evidence/performance-frontier/campaigns/PFP-7/harness/pfp7_rsa.c" \
   -ldl -o "$DIR/pfp7_rsa"
sha256sum "$DSO" "$AUTH" >"$DIR/identity.sha256"
for ((r = 1; r <= REPS; r++)); do
    if (( r % 2 )); then order="candidate authority"; else order="authority candidate"; fi
    for arm in $order; do
        if [ "$arm" = candidate ]; then dso="$DSO"; else dso="$AUTH"; fi
        taskset -c "$CPU" "$DIR/pfp7_rsa" --lib "$dso" --rsa-der "$RSA_DER" \
            --mode priv-nopad --iters 205 >"$DIR/$arm-r$(printf %02d "$r").out" 2>&1
    done
    echo "rep $r/$REPS"
done
python3 - "$DIR" <<'PY'
import glob, re, statistics, sys
d = sys.argv[1]
def parse(arm):
    rows = []
    for p in sorted(glob.glob(f'{d}/{arm}-r*.out')):
        t = open(p).read()
        m = re.search(r'min_ns=([\d.]+) median_ns=([\d.]+) mean_ns=([\d.]+)', t)
        b = re.search(r'BLOCKMED ns=([\d.]+)', t)
        o = re.search(r'OUTLIER count=(\d+) of (\d+)', t)
        if m and b:
            rows.append(dict(arm=arm, lat=float(m.group(1)), med=float(m.group(2)),
                             mean=float(m.group(3)), blockmed=float(b.group(1)),
                             outl=int(o.group(1)), n=int(o.group(2))))
    return rows
cand, auth = parse('candidate'), parse('authority')
def ci(vals, seed=0x50465037):
    import random
    rnd = random.Random(seed)
    bs = sorted(sum(rnd.choices(vals, k=len(vals)))/len(vals) for _ in range(20000))
    return bs[int(0.025*len(bs))], bs[int(0.975*len(bs))]
for name, key in (('latency_ns', 'lat'), ('blockmed_ns', 'blockmed'),
                  ('sustained_mean_ns', 'mean')):
    c = [r[key] for r in cand]; a = [r[key] for r in auth]
    lo, hi = ci([x/y for x, y in zip(c, a)])
    print(f'{name}: candidate median={statistics.median(c):.1f} authority median={statistics.median(a):.1f} '
          f'ratio={statistics.median(c)/statistics.median(a):.4f} ci95=[{lo:.4f},{hi:.4f}]')
    print(f'  candidate 95% ci of median: {ci(c)}  authority: {ci(a)}')
for r in cand[:3]:
    print('candidate rep:', r)
print('candidate outlier calls (of n):', sorted({(r['outl'], r['n']) for r in cand}))
print('authority outlier calls (of n):', sorted({(r['outl'], r['n']) for r in auth}))
tp_c = 1e9/statistics.median([r['mean'] for r in cand])
tp_a = 1e9/statistics.median([r['mean'] for r in auth])
print(f'throughput_ops_per_s candidate={tp_c:.1f} authority={tp_a:.1f} ratio={tp_a/tp_c:.4f}')
PY
echo TIMING_OK
