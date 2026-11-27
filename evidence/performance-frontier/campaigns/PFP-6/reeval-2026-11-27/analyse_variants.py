#!/usr/bin/env python3
"""analyse_variants.py — paired ratios for the PFP-6 re-evaluation.

Reads `timing/raw/<tag>-rNN.out`, extracts each workload's `RESULT ... median_us`,
and for every ordered pair reports:
  - absolute medians of the per-repetition process medians
  - median of the paired ratio (numerator / denominator) over the 15 repetitions
  - a 95% percentile bootstrap CI (20,000 resamples, fixed seed)
A ratio < 1 means the numerator (the first-named arm) is faster.
"""
import glob, json, os, random, statistics, sys

HERE = os.path.dirname(os.path.abspath(__file__))
RAW = os.path.join(HERE, "timing", "raw")
TAGS = ["a", "b", "c", "d"]
LABEL = {
    "a": "A: window + SOS multiply-for-square (production default)",
    "b": "B: window + dedicated squaring (SOS multiply)",
    "c": "C: window + CIOS for every Montgomery operation",
    "d": "D: window + CIOS multiply + dedicated squaring",
}
PAIRS = [
    ("b_over_a", "b", "a"),
    ("c_over_a", "c", "a"),
    ("d_over_a", "d", "a"),
    ("b_over_c", "b", "c"),
    ("d_over_c", "d", "c"),
    ("c_over_b", "c", "b"),
    ("d_over_b", "d", "b"),
]


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


def main():
    by = {t: {} for t in TAGS}
    for t in TAGS:
        for path in sorted(glob.glob(os.path.join(RAW, f"{t}-r*.out"))):
            rep = os.path.basename(path).split("-r")[1].split(".")[0]
            by[t][rep] = parse(path)
    common = sorted(set.intersection(*(set(v) for t in TAGS for v in by[t].values())))
    rng = random.Random(0x50465036)
    out = {"arms": LABEL, "repetitions": len(by["a"]), "workloads": {}}
    for ident in common:
        rec = {"absolute_us": {}}
        for t in TAGS:
            rec["absolute_us"][t] = statistics.median(
                by[t][r][ident] for r in sorted(by[t])
            )
        for name, num, den in PAIRS:
            ratios = [
                by[num][r][ident] / by[den][r][ident] for r in sorted(by[num])
            ]
            boots = []
            n = len(ratios)
            for _ in range(20000):
                s = sorted(rng.choice(ratios) for _ in range(n))
                boots.append(s[n // 2])
            boots.sort()
            rec[name] = {
                "median_ratio": statistics.median(ratios),
                "ci95": [boots[int(0.025 * len(boots))], boots[int(0.975 * len(boots))]],
                "n": n,
            }
        out["workloads"][ident] = rec
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
