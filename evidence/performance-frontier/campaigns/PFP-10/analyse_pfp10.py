#!/usr/bin/env python3
"""PFP-10 crossover analysis.

Reads `raw-samples.tsv` (domain, bits, candidate, repetition, ns/op) and reports,
per domain and size:

  * the median of the 15 per-repetition batch means, with a 95 % percentile
    bootstrap interval;
  * paired ratios (candidate / Fermat) with a 95 % percentile bootstrap interval,
    resampling whole repetitions so the pairing is preserved;
  * the winner by median.

This is the same statistic and bootstrap as PFP-0/PFP-6; it measures the
crate's own test binary at a fixed build identity, not a DSO.
"""

import collections
import json
import random
import statistics
import sys

RESAMPLES = 20_000
SEED = 0x5046503130  # "PFP10"


def median_ci(samples, rng):
    med = statistics.median(samples)
    n = len(samples)
    boot = sorted(statistics.median([rng.choice(samples) for _ in range(n)]) for _ in range(RESAMPLES))
    return med, boot[int(0.025 * RESAMPLES)], boot[int(0.975 * RESAMPLES) - 1]


def ratio_ci(num, den, rng):
    ratios = [a / b for a, b in zip(num, den)]
    med = statistics.median(ratios)
    n = len(ratios)
    boot = sorted(statistics.median([rng.choice(ratios) for _ in range(n)]) for _ in range(RESAMPLES))
    return med, boot[int(0.025 * RESAMPLES)], boot[int(0.975 * RESAMPLES) - 1]


def main(path):
    rng = random.Random(SEED)
    rows = collections.defaultdict(list)
    with open(path) as fh:
        for line in fh:
            domain, bits, candidate, rep, ns = line.rstrip("\n").split("\t")
            rows[(domain, int(bits), candidate)].append(float(ns))
    cases = sorted({(d, b) for d, b, _ in rows})
    out = {"resamples": RESAMPLES, "seed": SEED, "cases": []}
    for domain, bits in cases:
        entry = {"domain": domain, "bits": bits, "candidates": {}}
        for cand in ("fermat", "gcd", "divstep"):
            samples = rows[(domain, bits, cand)]
            med, lo, hi = median_ci(samples, rng)
            entry["candidates"][cand] = {
                "repetitions": len(samples),
                "median_ns": med,
                "ci95_ns": [lo, hi],
            }
        for num, den, name in (
            ("divstep", "fermat", "divstep_over_fermat"),
            ("gcd", "fermat", "gcd_over_fermat"),
            ("divstep", "gcd", "divstep_over_gcd"),
        ):
            med, lo, hi = ratio_ci(rows[(domain, bits, num)], rows[(domain, bits, den)], rng)
            entry[name] = {"median": med, "ci95": [lo, hi]}
        entry["winner"] = min(
            entry["candidates"].items(), key=lambda kv: kv[1]["median_ns"]
        )[0]
        out["cases"].append(entry)
    json.dump(out, sys.stdout, indent=1)
    print()


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "raw-samples.tsv")
