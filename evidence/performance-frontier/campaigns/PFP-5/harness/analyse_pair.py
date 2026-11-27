#!/usr/bin/env python3
"""Paired before/after: base(digest 4e6ec312) vs candidate(842efa27)."""
import glob, json, random, statistics, sys

D = sys.argv[1] if len(sys.argv) > 1 else "."

def parse(path):
    rows = {}
    with open(path) as f:
        for line in f:
            if line.startswith("RESULT "):
                p = line.split()
                ident = p[1]
                med = None
                for x in p:
                    if x.startswith("median_us="):
                        med = float(x.split("=", 1)[1])
                if med is not None:
                    rows[ident] = med
    return rows

base, cand = {}, {}
for p in sorted(glob.glob(f"{D}/rep-*-base.out")):
    r = p.split("/rep-")[1].split("-")[0]
    base[r] = parse(p)
for p in sorted(glob.glob(f"{D}/rep-*-candidate.out")):
    r = p.split("/rep-")[1].split("-")[0]
    cand[r] = parse(p)

ids = sorted(set.intersection(*(set(v) for v in base.values())) &
             set.intersection(*(set(v) for v in cand.values())))
rng = random.Random(0x50465036)
out = {}
for ident in ids:
    b = [base[r][ident] for r in sorted(base)]
    c = [cand[r][ident] for r in sorted(cand)]
    speed = [x / y for x, y in zip(b, c)]          # base/candidate
    boots = []
    n = len(speed)
    for _ in range(20000):
        s = sorted(rng.choice(speed) for _ in range(n))
        boots.append(s[n // 2])
    boots.sort()
    out[ident] = {
        "base_us": statistics.median(b),
        "candidate_us": statistics.median(c),
        "speedup_base_over_candidate": statistics.median(speed),
        "speedup_ci95": [boots[int(0.025 * len(boots))], boots[int(0.975 * len(boots))]],
        "removed_percent": 100.0 * (1.0 - 1.0 / statistics.median(speed)),
        "n": n,
    }
print(json.dumps(out, indent=2))
