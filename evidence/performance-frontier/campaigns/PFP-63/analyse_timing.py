#!/usr/bin/env python3
"""PFP-12 paired timing analysis.

Reads one RESULT line per (arm, operation, repetition) process, pairs cand with
auth by repetition, and reports:

  * the median per-call time of each arm (microseconds per complete AEAD
    operation, or per 16 KiB digest);
  * the median cand/auth ratio over paired repetitions;
  * a 95% percentile-bootstrap interval for that ratio;
  * the authority arm's own relative half-range ((max-min)/median over its 15
    process medians) as the instrument's observed noise floor.

A ratio is always cand/auth, so >1 means the candidate is slower. The two
message regimes are reported as separate rows and are never averaged.
"""
import argparse
import json
import os
import random
import re
import statistics

OPS = [
    "aes128gcm-64",
    "aes128gcm-16k",
    "aes256gcm-64",
    "aes256gcm-16k",
    "chachapoly-64",
    "chachapoly-16k",
    "sha256-16k",
    "sha512-16k",
]

RESULT_RE = re.compile(r"^RESULT (\S+) .*median_us=([0-9.]+)")


def load(directory):
    values = {}
    for name in os.listdir(directory):
        if not name.endswith(".out"):
            continue
        path = os.path.join(directory, name)
        arm, rest = name.split("-", 1)
        m_rep = re.search(r"-r(\d+)\.out$", name)
        if m_rep is None:
            continue
        rep = int(m_rep.group(1))
        op = rest[: -len("-r%02d.out" % rep)]
        if op not in OPS:
            continue
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                m = RESULT_RE.match(line)
                if m:
                    values.setdefault(op, {}).setdefault(arm, {})[rep] = float(m.group(2))
    return values


def bootstrap_ci(xs, seed=0x50465031, n=20000):
    rng = random.Random(seed)
    meds = []
    k = len(xs)
    for _ in range(n):
        meds.append(statistics.median(rng.choices(xs, k=k)))
    meds.sort()
    return meds[int(0.025 * n)], meds[int(0.975 * n) - 1]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--ops", default="",
                    help="comma-separated subset of operations (default: all)")
    args = ap.parse_args()
    ops = [o for o in args.ops.split(",") if o] or OPS

    data = load(args.dir)
    report = {"ratio_direction": "cand/auth (>1 = candidate slower)", "ops": {}}
    rows = []
    for op in ops:
        arms = data.get(op)
        if not arms or "cand" not in arms or "auth" not in arms:
            report["ops"][op] = {"status": "MISSING"}
            rows.append((op, "MISSING", "", "", "", "", ""))
            continue
        reps = sorted(set(arms["cand"]) & set(arms["auth"]))
        ratios = [arms["cand"][r] / arms["auth"][r] for r in reps]
        cand_meds = [arms["cand"][r] for r in reps]
        auth_meds = [arms["auth"][r] for r in reps]
        c_med = statistics.median(cand_meds)
        a_med = statistics.median(auth_meds)
        r_med = statistics.median(ratios)
        lo, hi = bootstrap_ci(ratios)
        auth_noise = (max(auth_meds) - min(auth_meds)) / a_med
        cand_noise = (max(cand_meds) - min(cand_meds)) / c_med
        report["ops"][op] = {
            "status": "OK",
            "n_pairs": len(reps),
            "cand_median_us": c_med,
            "auth_median_us": a_med,
            "ratio_median": r_med,
            "ratio_ci95": [lo, hi],
            "per_rep_ratios": ratios,
            "auth_noise_floor_rel_half_range": auth_noise,
            "cand_noise_floor_rel_half_range": cand_noise,
        }
        rows.append(
            (
                op,
                "%.4f" % c_med,
                "%.4f" % a_med,
                "%.3f" % r_med,
                "[%.3f, %.3f]" % (lo, hi),
                "%.4f" % auth_noise,
                "%.4f" % cand_noise,
            )
        )

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, sort_keys=True)
        fh.write("\n")

    print("op                cand_us    auth_us    ratio  ci95              auth_noise cand_noise")
    for row in rows:
        print("%-16s %9s %9s %7s  %-16s %s %s" % row)


if __name__ == "__main__":
    main()
