#!/usr/bin/env python3
"""PFP-6 crossover analyser.

Reads `raw-samples.txt` from `bench_mont.c` and writes `results.json` and
`CROSSOVER.md`. Statistics: per-(schedule,bits) median of the 15 repetitions and
a 95% percentile-bootstrap CI for the median. Because the harness interleaves
every schedule within a repetition, comparisons use the **paired** per-repetition
ratio `A/B` (median over 15, 95% percentile bootstrap), which removes slow drift
common to both arms.

A ratio below 1 means A is faster. This analyses the C schedule transcriptions;
it is not a measurement of the crate's kernels. Deterministic: a fixed bootstrap
seed; no timestamps.
"""

from __future__ import annotations

import json
import random
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
RAW = HERE / "raw-samples.txt"
OUT_JSON = HERE / "results.json"
OUT_MD = HERE / "CROSSOVER.md"

RESAMPLES = 20000
SEED = 0x50465036
NAMES = (
    "mont_sos",
    "mont_cios",
    "mont_comba",
    "mont_sqr",
    "mont_mul_for_sqr",
    "product_schoolbook",
    "product_karatsuba",
)
PAIRS = (
    ("cios_over_sos", "mont_cios", "mont_sos"),
    ("comba_over_sos", "mont_comba", "mont_sos"),
    ("sqr_over_mul", "mont_sqr", "mont_mul_for_sqr"),
    ("karatsuba_over_schoolbook", "product_karatsuba", "product_schoolbook"),
)

SAMPLE_RE = re.compile(
    r"^SAMPLE (?P<name>\S+) limbs=(?P<limbs>\d+) bits=(?P<bits>\d+) "
    r"rep=(?P<rep>\d+) ns=(?P<ns>[0-9.]+)$"
)
DIFF_RE = re.compile(
    r"^DIFFERENTIAL (?P<kernel>\S+) bits=(?P<bits>\d+) cases=(?P<cases>\d+) "
    r"mismatches=(?P<mm>\d+)$"
)


def median(xs):
    s = sorted(xs)
    n = len(s)
    return s[n // 2] if n & 1 else 0.5 * (s[n // 2 - 1] + s[n // 2])


def bootstrap_median_ci(xs, rng):
    n = len(xs)
    stats = sorted(median([xs[rng.randrange(n)] for _ in range(n)])
                   for _ in range(RESAMPLES))
    return stats[int(0.025 * RESAMPLES)], stats[int(0.975 * RESAMPLES) - 1]


def main():
    samples = {}   # name -> bits -> list[(rep, ns)]
    diffs = {}
    for line in RAW.read_text().splitlines():
        m = SAMPLE_RE.match(line)
        if m:
            name, bits = m.group("name"), int(m.group("bits"))
            samples.setdefault(name, {}).setdefault(bits, []).append(
                (int(m.group("rep")), float(m.group("ns"))))
            continue
        m = DIFF_RE.match(line)
        if m:
            kernel, bits = m.group("kernel"), int(m.group("bits"))
            diffs.setdefault(kernel, {})[bits] = {
                "cases": int(m.group("cases")),
                "mismatches": int(m.group("mm")),
            }

    sizes = sorted({b for d in samples.values() for b in d})
    rng = random.Random(SEED)
    result = {"sizes": sizes, "schedules": {}, "comparisons": {},
              "differential": diffs}

    for name in NAMES:
        per = {}
        for bits in sizes:
            series = sorted(samples[name][bits])
            vals = [v for _, v in series]
            reps = [r for r, _ in series]
            assert reps == list(range(len(vals))), (name, bits, reps)
            lo, hi = bootstrap_median_ci(vals, rng)
            per[str(bits)] = {
                "median_ns": median(vals),
                "ci95": [lo, hi],
                "min_ns": min(vals),
                "reps": len(vals),
            }
        result["schedules"][name] = per

    for key, a, b in PAIRS:
        per = {}
        for bits in sizes:
            av = dict(samples[a][bits])
            bv = dict(samples[b][bits])
            reps = sorted(set(av) & set(bv))
            ratios = [av[r] / bv[r] for r in reps]
            lo, hi = bootstrap_median_ci(ratios, rng)
            per[str(bits)] = {
                "median_ratio": median(ratios),
                "ci95": [lo, hi],
                "a": a,
                "b": b,
                "reps": len(ratios),
            }
        result["comparisons"][key] = per

    OUT_JSON.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")

    lines = []
    lines.append("# PFP-6 schedule crossover (C transcription, taskset -c 1)")
    lines.append("")
    lines.append("15 interleaved repetitions per size; median of per-repetition "
                 "means; 95% percentile bootstrap CI (20,000 resamples, paired "
                 "ratios). Ratio < 1 means the named kernel is faster. This is a "
                 "measurement of the C schedules in `bench_mont.c`, not of the "
                 "crate's kernels.")
    lines.append("")
    lines.append("## Absolute medians (ns per operation)")
    lines.append("")
    header = "| bits | " + " | ".join(NAMES) + " |"
    lines.append(header)
    lines.append("|" + "---|" * (len(NAMES) + 1))
    for bits in sizes:
        cells = []
        for name in NAMES:
            d = result["schedules"][name][str(bits)]
            cells.append(f"{d['median_ns']:.1f} [{d['ci95'][0]:.1f}, "
                         f"{d['ci95'][1]:.1f}]")
        lines.append(f"| {bits} | " + " | ".join(cells) + " |")
    lines.append("")
    lines.append("## Paired ratios")
    lines.append("")
    lines.append("| bits | " + " | ".join(k for k, _, _ in PAIRS) + " |")
    lines.append("|" + "---|" * (len(PAIRS) + 1))
    for bits in sizes:
        cells = []
        for key, _, _ in PAIRS:
            d = result["comparisons"][key][str(bits)]
            cells.append(f"{d['median_ratio']:.4f} "
                         f"[{d['ci95'][0]:.4f}, {d['ci95'][1]:.4f}]")
        lines.append(f"| {bits} | " + " | ".join(cells) + " |")
    lines.append("")
    lines.append("## Winners by median")
    lines.append("")
    lines.append("| bits | multiply | squaring | product |")
    lines.append("|---|---|---|---|")
    for bits in sizes:
        mul_winner = min(("mont_sos", "mont_cios", "mont_comba"),
                         key=lambda nm: result["schedules"][nm][str(bits)]["median_ns"])
        sq = result["schedules"]["mont_sqr"][str(bits)]["median_ns"]
        mq = result["schedules"]["mont_mul_for_sqr"][str(bits)]["median_ns"]
        sq_winner = "mont_sqr" if sq < mq else "mont_mul_for_sqr"
        sk = result["schedules"]["product_schoolbook"][str(bits)]["median_ns"]
        kk = result["schedules"]["product_karatsuba"][str(bits)]["median_ns"]
        prod_winner = "product_schoolbook" if sk < kk else "product_karatsuba"
        lines.append(f"| {bits} | {mul_winner} | {sq_winner} | {prod_winner} |")
    lines.append("")
    lines.append("## Differential (per kernel)")
    lines.append("")
    lines.append("| kernel | bits | cases | mismatches |")
    lines.append("|---|---|---|---|")
    for kernel in sorted(diffs):
        for bits in times_sorted(diffs[kernel]):
            d = diffs[kernel][bits]
            lines.append(f"| {kernel} | {bits} | {d['cases']} | {d['mismatches']} |")
    lines.append("")
    OUT_MD.write_text("\n".join(lines))
    print("\n".join(lines))


def times_sorted(d):
    return sorted(int(b) for b in d)


if __name__ == "__main__":
    main()
