#!/usr/bin/env python3
"""analyse_pfp2.py — PFP-2 paired ratios and bootstrap intervals.

Reads the raw samples written by `run_pfp2_perf.sh` and applies the PFP-0
statistic: one median per process (already computed by the harness), a paired
ratio per repetition, the median of the paired ratios, a percentile bootstrap
interval (20 000 resamples, seed 0x50465030) and an exact two-sided sign test.

Two evidence families are produced:

  * kernels: SOLINAS/MONT and ARCH/MONT for each of mul, sqr, add, sub, reduce
    and the end-to-end ladder.
  * mutation control: candidate/before for `ecdsa256` and `p256-mul`.

The output is a description of this sample. It is not a proof, and no row is a
frontier claim.
"""

from __future__ import annotations

import argparse
import json
import random
import statistics
from pathlib import Path


SEED = 0x50465030
RESAMPLES = 20000
OPS = ["mul", "sqr", "add", "sub", "reduce", "ladder"]


def median(values):
    return statistics.median(values)


def bootstrap_ci(values):
    rng = random.Random(SEED)
    n = len(values)
    medians = []
    for _ in range(RESAMPLES):
        sample = [values[rng.randrange(n)] for _ in range(n)]
        medians.append(statistics.median(sample))
    medians.sort()
    lo = medians[int(0.025 * RESAMPLES)]
    hi = medians[int(0.975 * RESAMPLES) - 1]
    return lo, hi


def sign_test_p(values):
    """Two-sided exact sign test against a median ratio of one."""
    n = len(values)
    positives = sum(1 for v in values if v > 1.0)
    negatives = sum(1 for v in values if v < 1.0)
    if positives + negatives == 0:
        return 1.0
    # Exact binomial with p = 1/2 on the smaller tail, doubled.
    from math import comb

    k = min(positives, negatives)
    tail = sum(comb(n, i) for i in range(0, k + 1)) / (2**n)
    return min(1.0, 2 * tail)


def read_kernels(work: Path, reps: int):
    samples = {}
    for rep in range(reps):
        path = work / "raw" / f"kernels-rep-{rep:02d}.tsv"
        if not path.exists():
            raise SystemExit(f"missing {path}")
        for line in path.read_text().splitlines():
            if not line.strip():
                continue
            parts = line.split("\t")
            if len(parts) < 5:
                continue
            _, label, op, med, raw = parts[:5]
            samples.setdefault((label, op), {})[rep] = {
                "median": float(med),
                "samples": [float(v) for v in raw.split(",") if v],
            }
    return samples


def read_dso(work: Path, reps: int):
    out = {}
    for rep in range(reps):
        for arm in ("candidate", "before"):
            path = work / "raw" / f"dso-rep-{rep:02d}-{arm}.out"
            if not path.exists():
                raise SystemExit(f"missing {path}")
            for line in path.read_text().splitlines():
                if not line.startswith("RESULT "):
                    continue
                fields = line.split("\t")
                workload = fields[0].split()[1]
                med = None
                raw = None
                for field in fields[1:]:
                    if field.startswith("median_us="):
                        med = float(field.split("=", 1)[1])
                    elif field.startswith("samples="):
                        raw = [float(v) for v in field.split("=", 1)[1].split(",") if v]
                if med is not None:
                    out.setdefault((workload, arm), {})[rep] = {
                        "median": med,
                        "samples": raw or [],
                    }
    return out


def paired(dict_a, dict_b, reps):
    """Per-repetition ratios a/b, dropping a pair if a sample is absent."""
    ratios = []
    for rep in range(reps):
        if rep in dict_a and rep in dict_b:
            ratios.append(dict_a[rep]["median"] / dict_b[rep]["median"])
    return ratios


def summarise(ratios):
    if not ratios:
        return None
    lo, hi = bootstrap_ci(ratios)
    return {
        "n": len(ratios),
        "per_repetition": ratios,
        "median_ratio": median(ratios),
        "ci95": [lo, hi],
        "sign_test_p": sign_test_p(ratios),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--work", required=True)
    ap.add_argument("--reps", type=int, default=15)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    work = Path(args.work)
    kernels = read_kernels(work, args.reps)
    dso = read_dso(work, args.reps)

    doc = {
        "schema": "openssl-rs/performance/pfp2/v1",
        "campaign": "PFP-2",
        "claim_class": "SCOPED_OBSERVATION",
        "repetitions": args.reps,
        "bootstrap": {"resamples": RESAMPLES, "seed": hex(SEED)},
        "kernels": {},
        "mutation_control": {},
    }

    for op in OPS:
        mont = kernels.get(("MONT", op), {})
        solinas = kernels.get(("SOLINAS", op), {})
        arch = kernels.get(("ARCH", op), {})
        entry = {
            "MONT_median": median([v["median"] for v in mont.values()]) if mont else None,
            "SOLINAS_median": median([v["median"] for v in solinas.values()])
            if solinas
            else None,
            "ARCH_median": median([v["median"] for v in arch.values()]) if arch else None,
            "SOLINAS_over_MONT": summarise(paired(solinas, mont, args.reps)),
            "ARCH_over_MONT": summarise(paired(arch, mont, args.reps)),
        }
        doc["kernels"][op] = entry

    # Per-repetition raw medians, retained so a reader can recompute everything.
    doc["raw_kernel_medians"] = {
        f"{label}/{op}": {str(rep): v["median"] for rep, v in by_rep.items()}
        for (label, op), by_rep in kernels.items()
    }
    doc["raw_kernel_samples"] = {
        f"{label}/{op}": {str(rep): v["samples"] for rep, v in by_rep.items()}
        for (label, op), by_rep in kernels.items()
    }

    for workload in ("ecdsa256", "p256-mul"):
        cand = dso.get((workload, "candidate"), {})
        before = dso.get((workload, "before"), {})
        doc["mutation_control"][workload] = {
            "candidate_median_us": median([v["median"] for v in cand.values()])
            if cand
            else None,
            "before_median_us": median([v["median"] for v in before.values()])
            if before
            else None,
            "candidate_over_before": summarise(paired(cand, before, args.reps)),
            "candidate_samples": {
                str(rep): v for rep, v in cand.items()
            },
            "before_samples": {str(rep): v for rep, v in before.items()},
        }

    Path(args.out).write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
    print(json.dumps({k: v for k, v in doc.items() if k != "raw_kernel_samples"},
                     indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
