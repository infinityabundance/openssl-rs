#!/usr/bin/env python3
"""PFP-59 paired timing analysis: before, after, authority.

Reads one RESULT line per (arm, operation, repetition) process. Pairs the arms
by repetition and reports, for each operation:

  * median per-call time per arm;
  * the median of the per-repetition ratios `before/auth`, `after/auth`;
  * the P-384 speedup `(before/auth) / (after/auth)`;
  * a percentile-bootstrap interval for the after/auth ratio;
  * the authority arm's own relative half-range as an observed noise floor.

A ratio is always arm/authority, so >1 means the arm is slower.
"""
import argparse
import json
import os
import random
import re
import statistics

OPS = [
    "ecdsa-sign-p384",
    "ecdsa-verify-p384",
    "ecdsa-sign-p521",
    "ecdsa-verify-p521",
    "ecdsa256",
]

RESULT_RE = re.compile(r"^RESULT (\S+) .*median_us=([0-9.]+)")
NAME_RE = re.compile(r"-(r\d+)\.out$")


def load(directory):
    values = {}
    for name in os.listdir(directory):
        if not name.endswith(".out"):
            continue
        m = NAME_RE.search(name)
        if not m:
            continue
        rep = m.group(1)
        head = name[: -len(m.group(0))]
        arm, op = head.split("-", 1)
        if op not in OPS:
            continue
        path = os.path.join(directory, name)
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                r = RESULT_RE.match(line)
                if r:
                    values.setdefault(op, {}).setdefault(rep, {})[arm] = float(
                        r.group(2)
                    )
    return values


def bootstrap_ci(samples, rng, n=2000):
    if len(samples) < 2:
        return [None, None]
    meds = []
    for _ in range(n):
        meds.append(statistics.median(rng.choices(samples, k=len(samples))))
    meds.sort()
    return [meds[int(0.025 * len(meds))], meds[int(0.975 * len(meds)) - 1]]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    values = load(args.dir)
    rng = random.Random(59)
    report = {"operations": {}}
    for op in OPS:
        reps = values.get(op, {})
        before = [reps[r]["before"] / reps[r]["auth"] for r in reps
                  if "before" in reps[r] and "auth" in reps[r]]
        after = [reps[r]["after"] / reps[r]["auth"] for r in reps
                 if "after" in reps[r] and "auth" in reps[r]]
        if not before or not after:
            report["operations"][op] = {"status": "MISSING",
                                        "reps": sorted(reps)}
            continue
        med = lambda xs: statistics.median(xs)
        auth_meds = [reps[r]["auth"] for r in reps if "auth" in reps[r]]
        floor = (max(auth_meds) - min(auth_meds)) / med(auth_meds) if auth_meds else None
        after_ci = bootstrap_ci(after, rng)
        before_ci = bootstrap_ci(before, rng)
        report["operations"][op] = {
            "reps": len(after),
            "before_ratio": round(med(before), 4),
            "after_ratio": round(med(after), 4),
            "speedup_before_over_after": round(med(before) / med(after), 4),
            "after_ci95": None if after_ci[0] is None else [round(x, 4) for x in after_ci],
            "before_ci95": None if before_ci[0] is None else [round(x, 4) for x in before_ci],
            "median_us": {
                "before": round(med([reps[r]["before"] for r in reps
                                     if "before" in reps[r]]), 3),
                "after": round(med([reps[r]["after"] for r in reps
                                    if "after" in reps[r]]), 3),
                "auth": round(med(auth_meds), 3),
            },
            "authority_noise_floor": round(floor, 4) if floor is not None else None,
            "status": "OK",
        }
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, sort_keys=True)
        fh.write("\n")
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
