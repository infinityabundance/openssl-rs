#!/usr/bin/env python3
"""PFP-5 timing analysis: paired candidate/authority ratios over 15 repetitions.

Reads rep-XX-{candidate,authority}.out. For each workload present in both, forms
the per-repetition ratio candidate/authority, then reports the median ratio and a
percentile bootstrap 95% interval (20000 resamples, seed 0x50465035). Absolute
medians are the median of the per-repetition batch medians.
"""
import glob
import json
import random
import statistics
import sys

OUT = sys.argv[1] if len(sys.argv) > 1 else "."


def parse(path):
    rows = {}
    with open(path) as f:
        for line in f:
            if line.startswith("RESULT "):
                parts = line.split()
                ident = parts[1]
                med = None
                for p in parts:
                    if p.startswith("median_us="):
                        med = float(p.split("=", 1)[1])
                if med is not None:
                    rows[ident] = med
    return rows


cand, auth = {}, {}
for path in sorted(glob.glob(f"{OUT}/rep-*-candidate.out")):
    rep = path.split("/rep-")[1].split("-")[0]
    cand[rep] = parse(path)
for path in sorted(glob.glob(f"{OUT}/rep-*-authority.out")):
    rep = path.split("/rep-")[1].split("-")[0]
    auth[rep] = parse(path)

ids = sorted(set.intersection(*(set(v) for v in cand.values())) &
             set.intersection(*(set(v) for v in auth.values())))
rng = random.Random(0x50465035)
res = {}
for ident in ids:
    c = [cand[r][ident] for r in sorted(cand)]
    a = [auth[r][ident] for r in sorted(auth)]
    ratios = [x / y for x, y in zip(c, a)]
    ratios_sorted = sorted(ratios)
    boot = []
    n = len(ratios)
    for _ in range(20000):
        s = sorted(rng.choice(ratios) for _ in range(n))
        boot.append(s[n // 2])
    boot.sort()
    res[ident] = {
        "candidate_us": statistics.median(c),
        "authority_us": statistics.median(a),
        "ratio": statistics.median(ratios),
        "ci95": [boot[int(0.025 * len(boot))], boot[int(0.975 * len(boot))]],
        "n": n,
    }

print(json.dumps(res, indent=2))
