#!/usr/bin/env python3
"""phase2_compare.py — three-arm paired comparison (head/cand/auth).

Reports, per operation, the per-arm median and the median paired ratios
`cand/auth`, `head/auth` and `cand/head` with percentile-bootstrap intervals.
`head` is the pristine HEAD (the phase-1 candidate), so `head/cand` is the
phase-2 speedup and `cand/head` on the P-256 control is the untouched check.
"""
import argparse
import json
import os
import random
import re
import statistics

RESULT_RE = re.compile(r"^RESULT (\S+) .*median_us=([0-9.]+)")


def load(directory):
    values = {}
    for name in os.listdir(directory):
        if not name.endswith(".out"):
            continue
        arm, rest = name.split("-", 1)
        rep = int(re.search(r"-r(\d+)\.out$", name).group(1))
        op = rest[: -len("-r%02d.out" % rep)]
        with open(os.path.join(directory, name), encoding="utf-8") as fh:
            for line in fh:
                m = RESULT_RE.match(line)
                if m:
                    values.setdefault(op, {}).setdefault(arm, {})[rep] = float(
                        m.group(2)
                    )
    return values


def ci(xs, seed):
    rng = random.Random(seed)
    n = len(xs)
    boots = sorted(statistics.median(rng.choices(xs, k=n)) for _ in range(20000))
    return boots[int(0.025 * 20000)], boots[int(0.975 * 20000) - 1]


def summary(values, op, arms):
    data = values.get(op)
    if not data or any(a not in data for a in arms):
        return {"status": "MISSING"}
    reps = sorted(set.intersection(*(set(data[a]) for a in arms)))
    out = {"status": "OK", "n_pairs": len(reps), "medians_us": {}}
    for a in arms:
        out["medians_us"][a] = statistics.median(data[a][r] for r in reps)
    for label, num, den, seed in [
        ("cand_auth", "cand", "auth", 0x50465031),
        ("head_auth", "head", "auth", 0x50465032),
        ("cand_head", "cand", "head", 0x50465033),
    ]:
        ratios = [data[num][r] / data[den][r] for r in reps]
        lo, hi = ci(ratios, seed)
        out[label] = {
            "median": statistics.median(ratios),
            "ci95": [lo, hi],
            "per_rep": ratios,
        }
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--p521", required=True)
    ap.add_argument("--p256", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    p521 = load(args.p521)
    p256 = load(args.p256)
    arms = ["head", "cand", "auth"]
    report = {
        "ratio_direction": "num/den (>1 = numerator slower)",
        "p521": {
            op: summary(p521, op, arms)
            for op in ("ecdsa-sign-p521", "ecdsa-verify-p521")
        },
        "p256": {"ecdsa256": summary(p256, "ecdsa256", arms)},
    }
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, sort_keys=True)
        fh.write("\n")

    for group in ("p521", "p256"):
        for op, r in report[group].items():
            if r.get("status") != "OK":
                print("%-22s MISSING" % op)
                continue
            print(
                "%-22s head=%.3f cand=%.3f auth=%.3f | cand/auth=%.3f "
                "[%.3f,%.3f] head/auth=%.3f cand/head=%.3f | speedup head/cand=%.3f"
                % (
                    op,
                    r["medians_us"]["head"],
                    r["medians_us"]["cand"],
                    r["medians_us"]["auth"],
                    r["cand_auth"]["median"],
                    r["cand_auth"]["ci95"][0],
                    r["cand_auth"]["ci95"][1],
                    r["head_auth"]["median"],
                    r["cand_head"]["median"],
                    1.0 / r["cand_head"]["median"],
                )
            )


if __name__ == "__main__":
    main()
