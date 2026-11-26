#!/usr/bin/env python3
"""analyse_timing.py — paired ratio CIOS/SOS from the interleaved timing run.

Input TSV: rep, order, tag, iters, ns_per_op.
Method (the PFP-6 statistical method): each repetition gives a paired ratio
B/A = ns_per_op(CIOS) / ns_per_op(SOS); report the median of the per-repetition
means, the ratio of the per-tag medians, and a 95% percentile bootstrap CI over
the paired ratios (20,000 resamples with replacement).  A ratio above 1 means
CIOS is slower.
"""
import json, random, statistics, sys

BOOT = 20000
SEED = 0x50465032_37  # fixed: the CI must be reproducible


def main(path):
    rows = []
    for line in open(path):
        rep, order, tag, iters, ns = line.rstrip("\n").split("\t")
        rows.append((int(rep), tag, float(ns)))
    reps = sorted({r for r, _, _ in rows})
    by = {}
    for rep, tag, ns in rows:
        by.setdefault(rep, {})[tag] = ns
    pairs = [(by[r]["b"] / by[r]["a"], by[r]["a"], by[r]["b"]) for r in reps if "a" in by[r] and "b" in by[r]]
    if len(pairs) != len(reps):
        sys.exit("FATAL: unpaired repetition")

    ratios = [p[0] for p in pairs]
    a_vals = [p[1] for p in pairs]
    b_vals = [p[2] for p in pairs]

    rng = random.Random(SEED)
    boot = []
    n = len(ratios)
    for _ in range(BOOT):
        sample = [ratios[rng.randrange(n)] for _ in range(n)]
        boot.append(statistics.median(sample))
    boot.sort()
    lo = boot[int(0.025 * BOOT)]
    hi = boot[int(0.975 * BOOT) - 1]

    out = {
        "reps": n,
        "sos_ns_per_op_median": round(statistics.median(a_vals), 1),
        "cios_ns_per_op_median": round(statistics.median(b_vals), 1),
        "cios_over_sos_median_of_paired_ratios": round(statistics.median(ratios), 5),
        "cios_over_sos_ratio_of_medians": round(statistics.median(b_vals) / statistics.median(a_vals), 5),
        "ci95_percentile": [round(lo, 5), round(hi, 5)],
        "ci_excludes_1": (lo > 1.0) or (hi < 1.0),
        "per_rep_ratios": [round(r, 5) for r in ratios],
        "method": "paired per-repetition ratio; median of per-repetition means; "
                  "%d-resample percentile bootstrap, seed %d" % (BOOT, SEED),
    }
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main(sys.argv[1])
