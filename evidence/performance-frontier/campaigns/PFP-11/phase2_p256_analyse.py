#!/usr/bin/env python3
"""phase2_p256_analyse.py — paired cand/auth ratio for the P-256 control.

Reads `RESULT ecdsa256 ... median_us=...` lines from `cand-*`/`auth-*` files,
pairs by repetition, and reports the median per-process time and the median
paired ratio with a percentile-bootstrap interval.
"""
import argparse
import json
import os
import random
import re
import statistics

RESULT_RE = re.compile(r"^RESULT (\S+) .*median_us=([0-9.]+)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    values = {}
    for name in os.listdir(args.dir):
        if not name.endswith(".out"):
            continue
        arm, rest = name.split("-", 1)
        rep = int(re.search(r"-r(\d+)\.out$", name).group(1))
        with open(os.path.join(args.dir, name), encoding="utf-8") as fh:
            for line in fh:
                m = RESULT_RE.match(line)
                if m:
                    values.setdefault(arm, {})[rep] = float(m.group(2))

    reps = sorted(set(values.get("cand", {})) & set(values.get("auth", {})))
    ratios = [values["cand"][r] / values["auth"][r] for r in reps]
    rng = random.Random(0x50465031)
    boots = sorted(
        statistics.median(rng.choices(ratios, k=len(ratios))) for _ in range(20000)
    )
    lo, hi = boots[int(0.025 * 20000)], boots[int(0.975 * 20000) - 1]
    report = {
        "ratio_direction": "cand/auth (>1 = candidate slower)",
        "op": "ecdsa256-sign",
        "n_pairs": len(reps),
        "cand_median_us": statistics.median(values["cand"][r] for r in reps),
        "auth_median_us": statistics.median(values["auth"][r] for r in reps),
        "ratio_median": statistics.median(ratios),
        "ratio_ci95": [lo, hi],
        "per_rep_ratios": ratios,
    }
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, sort_keys=True)
        fh.write("\n")
    print(
        "ecdsa256-sign cand=%.3f auth=%.3f ratio=%.3f [%.3f, %.3f]"
        % (
            report["cand_median_us"],
            report["auth_median_us"],
            report["ratio_median"],
            lo,
            hi,
        )
    )


if __name__ == "__main__":
    main()
