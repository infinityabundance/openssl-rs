#!/usr/bin/env python3
"""PFP-1 analysis: setup-inclusive versus prepared-key latency.

Consumes the harness output written by ``run_pfp1_perf.sh`` and applies the
PFP-0 statistic (``docs/PERFORMANCE-METHODOLOGY.md`` §6) to a within-candidate
paired comparison:

    ratio_w = median_r ( setup_us(w, r) / prepared_us(w, r) )

The per-repetition ratios are paired by repetition. The report includes the
paired ratio median, every realised ratio, the ratio of the medians, a
percentile bootstrap interval (20 000 resamples, seed ``0x50465030``), and the
candidate median and interquartile range for each arm. No observation is
excluded and no population is changed.

``ecdsa256`` has no prepared/setup distinction in PFP-1; both processes run the
same operation and its ``mode=unchanged`` line is reported as a consistency
control, never as a speedup.
"""

import argparse
import json
import math
import random
import re
import statistics
import sys
from pathlib import Path

RESULT_RE = re.compile(
    r"^RESULT\s+(?P<id>\S+)\s+mode=(?P<mode>\S+)\s+"
    r"median_us=(?P<med>[-0-9.]+)\s+min_us=(?P<mn>[-0-9.]+)\s+"
    r"max_us=(?P<mx>[-0-9.]+)\s+spread=(?P<spread>[-0-9.]+)\s+"
    r"iters=(?P<iters>\d+)\s+runs=(?P<runs>\d+)"
)
BOOTSTRAP_RESAMPLES = 20000
BOOTSTRAP_SEED = 0x50465030


def parse_process(path):
    rows = {}
    for line in path.read_text().splitlines():
        m = RESULT_RE.match(line)
        if m:
            rows.setdefault(m.group("mode"), {})[m.group("id")] = {
                "median_us": float(m.group("med")),
                "min_us": float(m.group("mn")),
                "max_us": float(m.group("mx")),
                "spread": float(m.group("spread")),
                "iters": int(m.group("iters")),
                "runs": int(m.group("runs")),
            }
    return rows


def percentile(sorted_values, q):
    if not sorted_values:
        return float("nan")
    pos = (len(sorted_values) - 1) * q
    lo = math.floor(pos)
    hi = math.ceil(pos)
    if lo == hi:
        return sorted_values[lo]
    return sorted_values[lo] + (sorted_values[hi] - sorted_values[lo]) * (pos - lo)


def bootstrap_ci(values, seed, resamples=BOOTSTRAP_RESAMPLES):
    rng = random.Random(seed)
    medians = []
    n = len(values)
    for _ in range(resamples):
        sample = [values[rng.randrange(n)] for _ in range(n)]
        medians.append(statistics.median(sample))
    medians.sort()
    return percentile(medians, 0.025), percentile(medians, 0.975)


def sign_test_p(values):
    """Two-sided exact sign test for median == 1 (zeros omitted)."""
    below = sum(1 for v in values if v < 1.0)
    above = sum(1 for v in values if v > 1.0)
    n = below + above
    if n == 0:
        return 1.0
    k = min(below, above)
    tail = sum(math.comb(n, i) for i in range(0, k + 1)) / (2 ** n)
    return min(1.0, 2.0 * tail)


def analyse(work, workloads_path):
    workloads = json.loads(Path(workloads_path).read_text())
    ids = [w["id"] for w in workloads["workloads"]]

    order = []
    for line in (work / "raw" / "run-order.tsv").read_text().splitlines():
        if not line.strip():
            continue
        rep, first, second = line.split("\t")
        order.append((rep, first, second))

    runs = {}
    for rep, first, second in order:
        per_mode = {}
        for mode in (first, second):
            path = work / "raw" / f"rep-{rep}-{mode}.out"
            if not path.exists():
                raise SystemExit(f"missing {path}")
            per_mode.update(parse_process(path))
        runs[rep] = per_mode

    rows = []
    for wid in sorted(ids):
        setup_values = []
        prepared_values = []
        spent = []
        if wid == "ecdsa256":
            # Both arms are the same operation; report the realised medians as a
            # control and do not compute a speedup.
            for rep in sorted(runs):
                per_mode = runs[rep]
                vals = [per_mode[m]["ecdsa256"]["median_us"] for m in per_mode
                        if "ecdsa256" in per_mode[m]]
                spent.extend(vals)
            row = {
                "id": wid,
                "kind": "control",
                "setup_median_us": statistics.median(spent) if spent else None,
                "prepared_median_us": statistics.median(spent) if spent else None,
                "paired_ratio_setup_over_prepared": 1.0,
                "note": "no prepared/setup distinction in PFP-1; both processes run the same operation",
            }
            rows.append(row)
            continue

        for rep in sorted(runs):
            per_mode = runs[rep]
            s = per_mode.get("setup", {}).get(wid)
            p = per_mode.get("prepared", {}).get(wid)
            if s is None or p is None:
                raise SystemExit(f"{wid}: missing arm in repetition {rep}")
            setup_values.append(s["median_us"])
            prepared_values.append(p["median_us"])

        ratios = [s / p for s, p in zip(setup_values, prepared_values) if p > 0]
        ratios_sorted = sorted(ratios)
        ci_lo, ci_hi = bootstrap_ci(ratios_sorted, BOOTSTRAP_SEED)
        row = {
            "id": wid,
            "kind": "paired",
            "repetitions": len(ratios),
            "setup_median_us": statistics.median(setup_values),
            "prepared_median_us": statistics.median(prepared_values),
            "setup_iqr_us": (
                percentile(sorted(setup_values), 0.75)
                - percentile(sorted(setup_values), 0.25)
            ),
            "prepared_iqr_us": (
                percentile(sorted(prepared_values), 0.75)
                - percentile(sorted(prepared_values), 0.25)
            ),
            "paired_ratios": ratios,
            "paired_ratio_median": statistics.median(ratios),
            "paired_ratio_bootstrap_95": [ci_lo, ci_hi],
            "ratio_of_medians": statistics.median(setup_values)
            / statistics.median(prepared_values),
            "sign_test_p_ratio_eq_1": sign_test_p(ratios),
            "direction": "setup slower" if statistics.median(ratios) > 1.0 else (
                "prepared slower" if statistics.median(ratios) < 1.0 else "equal"
            ),
        }
        rows.append(row)

    doc = {
        "schema": "openssl-rs/performance/pfp1/v1",
        "campaign": "PFP-1",
        "protocol": "docs/PERFORMANCE-METHODOLOGY.md §6 applied to a within-candidate paired comparison",
        "classification": "SCOPED_OBSERVATION",
        "venue_has_pmu": False,
        "repetitions": len(order),
        "statistic": "median over repetitions of setup_us / prepared_us",
        "uncertainty": {
            "method": "percentile bootstrap over the realised paired ratios",
            "resamples": BOOTSTRAP_RESAMPLES,
            "seed": hex(BOOTSTRAP_SEED),
        },
        "family": sorted(ids),
        "rows": rows,
        "note": "a performance result never discharges a timing obligation; see the receipt",
    }
    return doc


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--work", required=True)
    ap.add_argument("--workloads", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    doc = analyse(Path(args.work), args.workloads)
    Path(args.out).write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
    print(json.dumps(doc, indent=2, sort_keys=True))


if __name__ == "__main__":
    sys.exit(main())
