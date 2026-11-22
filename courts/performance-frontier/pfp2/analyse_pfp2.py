#!/usr/bin/env python3
"""analyse_pfp2.py — PFP-2 paired ratios, intervals and population checks.

Reads the raw samples written by `run_pfp2_perf.sh` and applies the PFP-0
statistic: one median per process (already computed by the harness), a paired
ratio per repetition, the median of the paired ratios, a percentile bootstrap
interval (20 000 resamples, seed 0x50465030) and an exact two-sided sign test.

Evidence families:

  * kernels: SOLINAS/MONT and ARCH/MONT for each of mul, sqr, add, sub, reduce
    and the end-to-end ladder.
  * end to end: each candidate DSO (default and one per forced kernel) against
    the admitted authority for `ecdsa256` and `p256-mul`, with the PFP-0
    `ecdsa256` ratio named as the comparator.
  * mutation control: the before-control (the pre-engine generic ladder) against
    the authority and against the default candidate.

Population rules, mirroring the hardened PFP-0 analyser: the repetition set must
be exactly 0..N-1 once each, every repetition must carry every arm and both
workloads, every file must contain exactly one RESULT line for its workload and a
non-empty CHECK population, all arms' CHECK lines within a repetition must be
identical, and the realised order must be the preregistered balanced one. A
violation is a refusal, not a warning.

The output is a description of this sample. It is not a proof, and no row is a
frontier claim.
"""

from __future__ import annotations

import argparse
import json
import random
import statistics
import sys
from math import comb
from pathlib import Path


SEED = 0x50465030
RESAMPLES = 20000
OPS = ["mul", "sqr", "add", "sub", "reduce", "ladder"]
ARM_VARIANTS = ["default", "mont", "solinas", "arch", "before"]
ARMS = ARM_VARIANTS + ["authority"]
WORKLOADS = {"ecdsa": "ecdsa256", "mul": "p256-mul"}

# PFP-0 `ecdsa256` row: candidate/authority median ratio and its unadjusted
# bootstrap interval, plus the candidate allocations measured there.
PFP0_ECDSA = {"ratio": 34.651, "ci": [34.563, 34.716], "allocations": 277}


class Refusal(Exception):
    pass


def refuse(message: str) -> None:
    raise Refusal(message)


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
    k = min(positives, negatives)
    tail = sum(comb(n, i) for i in range(0, k + 1)) / (2**n)
    return min(1.0, 2 * tail)


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


def read_order(work: Path, reps: int):
    path = work / "raw" / "run-order.tsv"
    if not path.exists():
        refuse(f"missing {path}")
    rows = []
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) != 3:
            refuse(f"{path}: malformed row {line!r}")
        rows.append((int(parts[0]), parts[1], int(parts[2])))
    ids = [r[0] for r in rows]
    if ids != list(range(reps)):
        refuse(f"{path}: repetition population {ids} != 0..{reps - 1}")
    firsts = [r[1] for r in rows]
    if any(f not in ("candidate", "authority") for f in firsts):
        refuse(f"{path}: unexpected first-subject label")
    expected_authority_first = reps // 2 + reps % 2
    if firsts.count("authority") != expected_authority_first:
        refuse(
            f"{path}: {firsts.count('authority')} authority-first repetitions, "
            f"expected {expected_authority_first}"
        )
    return rows


def read_kernels(work: Path, reps: int):
    samples = {}
    for rep in range(reps):
        path = work / "raw" / f"kernels-rep-{rep:02d}.tsv"
        if not path.exists():
            refuse(f"missing {path}")
        seen = set()
        for line in path.read_text().splitlines():
            if not line.strip():
                continue
            parts = line.split("\t")
            if len(parts) < 5:
                continue
            _, label, op, med, raw = parts[:5]
            key = (label, op)
            if key in seen:
                refuse(f"{path}: duplicate {label}/{op}")
            seen.add(key)
            samples.setdefault(key, {})[rep] = {
                "median": float(med),
                "samples": [float(v) for v in raw.split(",") if v],
            }
    for op in OPS:
        for label in ("MONT", "SOLINAS", "ARCH"):
            key = (label, op)
            if key in samples and len(samples[key]) != reps:
                refuse(f"kernel population {label}/{op} has {len(samples[key])} repetitions")
    return samples


def read_dso(work: Path, reps: int):
    out = {}
    checks = {}
    for rep in range(reps):
        check_sets = {}
        for arm in ARMS:
            for wl, expected_name in WORKLOADS.items():
                path = work / "raw" / f"dso-rep-{rep:02d}-{arm}-{wl}.out"
                if not path.exists():
                    refuse(f"missing {path}")
                result = None
                check_lines = []
                for line in path.read_text().splitlines():
                    if line.startswith("CHECK "):
                        check_lines.append(line)
                    if not line.startswith("RESULT "):
                        continue
                    fields = line.split("\t")
                    name = fields[0].split()[1]
                    if name != expected_name:
                        refuse(f"{path}: RESULT {name}, expected {expected_name}")
                    if result is not None:
                        refuse(f"{path}: duplicate RESULT line")
                    med = None
                    raw = None
                    for field in fields[1:]:
                        if field.startswith("median_us="):
                            med = float(field.split("=", 1)[1])
                        elif field.startswith("samples="):
                            raw = [float(v) for v in field.split("=", 1)[1].split(",") if v]
                    result = {"median": med, "samples": raw or []}
                if result is None:
                    refuse(f"{path}: no RESULT line")
                if not check_lines:
                    refuse(f"{path}: empty CHECK population")
                out.setdefault((wl, arm), {})[rep] = result
                check_sets[(arm, wl)] = check_lines
        for wl in WORKLOADS:
            reference = check_sets[("authority", wl)]
            for arm in ARM_VARIANTS:
                if check_sets[(arm, wl)] != reference:
                    refuse(f"rep-{rep:02d} {arm} {wl}: CHECK population differs from the authority")
        checks[rep] = {f"{arm}/{wl}": check_sets[(arm, wl)] for arm in ARMS for wl in WORKLOADS}
    return out, checks


def read_alloc(work: Path, arm: str):
    path = work / "raw" / f"alloc-{arm}.out"
    if not path.exists():
        return None
    for line in path.read_text().splitlines():
        if line.startswith("ALLOC "):
            fields = line.split()
            name = fields[1]
            values = {}
            for field in fields[2:]:
                if "=" in field:
                    k, v = field.split("=", 1)
                    values[k] = v
            return {"workload": name, **values}
    return None


def paired(dict_a, dict_b, reps):
    ratios = []
    for rep in range(reps):
        if rep in dict_a and rep in dict_b:
            ratios.append(dict_a[rep]["median"] / dict_b[rep]["median"])
    return ratios


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--work", required=True)
    ap.add_argument("--reps", type=int, default=15)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    work = Path(args.work)
    try:
        order = read_order(work, args.reps)
        kernels = read_kernels(work, args.reps)
        dso, checks = read_dso(work, args.reps)
    except Refusal as exc:
        print(f"analyse_pfp2: REFUSED: {exc}", file=sys.stderr)
        return 2

    doc = {
        "schema": "openssl-rs/performance/pfp2/v1",
        "campaign": "PFP-2",
        "claim_class": "SCOPED_OBSERVATION",
        "repetitions": args.reps,
        "bootstrap": {"resamples": RESAMPLES, "seed": hex(SEED)},
        "ordering": [
            {"repetition": r, "first": f, "rotation": k} for r, f, k in order
        ],
        "population": {
            "repetitions": args.reps,
            "arms": ARMS,
            "workloads": sorted(WORKLOADS.values()),
            "checks_equal_across_arms": True,
        },
        "kernels": {},
        "end_to_end": {},
        "mutation_control": {},
        "allocations": {},
        "pfp0_comparator": PFP0_ECDSA,
    }

    for op in OPS:
        mont = kernels.get(("MONT", op), {})
        solinas = kernels.get(("SOLINAS", op), {})
        arch = kernels.get(("ARCH", op), {})
        doc["kernels"][op] = {
            "MONT_median": median([v["median"] for v in mont.values()]) if mont else None,
            "SOLINAS_median": median([v["median"] for v in solinas.values()])
            if solinas
            else None,
            "ARCH_median": median([v["median"] for v in arch.values()]) if arch else None,
            "SOLINAS_over_MONT": summarise(paired(solinas, mont, args.reps)),
            "ARCH_over_MONT": summarise(paired(arch, mont, args.reps)),
        }

    doc["raw_kernel_medians"] = {
        f"{label}/{op}": {str(rep): v["median"] for rep, v in by_rep.items()}
        for (label, op), by_rep in kernels.items()
    }
    doc["raw_kernel_samples"] = {
        f"{label}/{op}": {str(rep): v["samples"] for rep, v in by_rep.items()}
        for (label, op), by_rep in kernels.items()
    }

    authority = {wl: dso.get((wl, "authority"), {}) for wl in WORKLOADS}
    for wl in WORKLOADS:
        entry = {}
        for arm in ARM_VARIANTS:
            candidate = dso.get((wl, arm), {})
            ratios = paired(candidate, authority[wl], args.reps)
            entry[arm] = {
                "arm_median_us": median([v["median"] for v in candidate.values()])
                if candidate
                else None,
                "authority_median_us": median(
                    [v["median"] for v in authority[wl].values()]
                )
                if authority[wl]
                else None,
                "ratio_over_authority": summarise(ratios),
            }
        doc["end_to_end"][wl] = entry

    # Mutation control: the default (engine) against the before-control (generic
    # ladder). A ratio above one means the engine is faster.
    for wl in WORKLOADS:
        default = dso.get((wl, "default"), {})
        before = dso.get((wl, "before"), {})
        doc["mutation_control"][wl] = {
            "default_over_before": summarise(paired(default, before, args.reps)),
            "before_over_default": summarise(paired(before, default, args.reps)),
        }

    for arm in ("default", "before"):
        doc["allocations"][arm] = read_alloc(work, arm)

    # The PFP-0 comparator applies to the default arm's `ecdsa256` ratio.
    ecdsa_default = doc["end_to_end"]["ecdsa256"]["default"]["ratio_over_authority"]
    if ecdsa_default is not None:
        ratio = ecdsa_default["median_ratio"]
        lo, hi = ecdsa_default["ci95"]
        doc["pfp0_comparison"] = {
            "row": "ecdsa256 default/authority",
            "pfp0_ratio": PFP0_ECDSA["ratio"],
            "pfp0_ci": PFP0_ECDSA["ci"],
            "measured_ratio": ratio,
            "measured_ci": [lo, hi],
            "delta_vs_pfp0": ratio - PFP0_ECDSA["ratio"],
            "pfp0_inside_measured_ci": lo <= PFP0_ECDSA["ratio"] <= hi,
            "candidate_allocations": doc["allocations"].get("default"),
            "pfp0_candidate_allocations": PFP0_ECDSA["allocations"],
        }

    Path(args.out).write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
    print(
        json.dumps(
            {k: v for k, v in doc.items() if k not in ("raw_kernel_samples",)},
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
