#!/usr/bin/env python3
"""PFP8-WIDTH-POLICY paired timing analysis: per-repetition ratios and a
percentile bootstrap.

Reads evidence/performance-frontier/campaigns/PFP-8/width-policy/timing/raw/
{tag}-{workload}-rNN.out and writes results.json plus a compact text table.
"""

from __future__ import annotations

import json
import random
import re
import statistics
from pathlib import Path

EV = Path("/work/evidence/performance-frontier/campaigns/PFP-8/width-policy")
RAW = EV / "timing" / "raw"
RESULT = re.compile(
    r"^RESULT \S+ op=\S+ median_us=([0-9.]+) min_us=([0-9.]+) "
    r"max_us=([0-9.]+) spread=[0-9.]+ iters=(\d+) runs=(\d+)",
    re.MULTILINE,
)
REPS = 15
ARMS = ("cand", "prev", "auth")
WORKLOADS = ("keygen", "keygen3072", "compute225", "compute2048", "compute275")
SEED = 0x50465038


def read_arm(tag: str, workload: str) -> list[float]:
    vals = []
    for rep in range(1, REPS + 1):
        path = RAW / f"{tag}-{workload}-r{rep:02d}.out"
        text = path.read_text()
        match = RESULT.search(text)
        if match is None:
            raise SystemExit(f"missing RESULT in {path}")
        vals.append(float(match.group(1)))
    return vals


def bootstrap_median_ci(values: list[float]) -> tuple[float, float]:
    rng = random.Random(SEED)
    meds = []
    n = len(values)
    for _ in range(20000):
        sample = [values[rng.randrange(n)] for _ in range(n)]
        meds.append(statistics.median(sample))
    meds.sort()
    return meds[int(0.025 * len(meds))], meds[int(0.975 * len(meds)) - 1]


def main() -> int:
    out = {"seed": SEED, "repetitions": REPS, "workloads": {}}
    for workload in WORKLOADS:
        samples = {tag: read_arm(tag, workload) for tag in ARMS}
        row = {}
        for numerator, denominator in (
            ("cand", "auth"),
            ("prev", "auth"),
            ("cand", "prev"),
        ):
            ratios = [a / b for a, b in zip(samples[numerator], samples[denominator])]
            lo, hi = bootstrap_median_ci(ratios)
            row[f"{numerator}_over_{denominator}"] = {
                "median": statistics.median(ratios),
                "ci95": [lo, hi],
                "raw": ratios,
            }
        row["median_us"] = {tag: statistics.median(samples[tag]) for tag in ARMS}
        out["workloads"][workload] = row

    (EV / "timing" / "results.json").write_text(
        json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="ascii"
    )

    print(f"{'workload':14s} {'cand_us':>10s} {'prev_us':>10s} {'auth_us':>10s} "
          f"{'cand/auth':>22s} {'prev/auth':>22s} {'cand/prev':>22s}")
    for workload in WORKLOADS:
        row = out["workloads"][workload]
        med = row["median_us"]
        print(
            f"{workload:14s} {med['cand']:10.1f} {med['prev']:10.1f} "
            f"{med['auth']:10.1f} "
            f"{row['cand_over_auth']['median']:9.4f} "
            f"[{row['cand_over_auth']['ci95'][0]:.4f},"
            f"{row['cand_over_auth']['ci95'][1]:.4f}] "
            f"{row['prev_over_auth']['median']:9.4f} "
            f"[{row['prev_over_auth']['ci95'][0]:.4f},"
            f"{row['prev_over_auth']['ci95'][1]:.4f}] "
            f"{row['cand_over_prev']['median']:9.4f} "
            f"[{row['cand_over_prev']['ci95'][0]:.4f},"
            f"{row['cand_over_prev']['ci95'][1]:.4f}]"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
