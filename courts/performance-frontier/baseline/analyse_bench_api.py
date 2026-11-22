#!/usr/bin/env python3
"""Analyse a completed PFP-0 campaign.

Reads only the raw outputs written by `courts/phase18/timing/run_bench_api.sh`
and the frozen population in `forensics/performance/WORKLOADS.json`.  It refuses
to emit `results.json` if the population, correctness, identity or
cross-verification checks fail; a failed campaign is BLOCKED, never PASS.

Statistics are the preregistered ones:

  * the unit of replication is one process per subject per repetition;
  * the primary statistic is the median of the paired per-repetition ratios
    `candidate_us / authority_us`;
  * uncertainty is a percentile bootstrap over those paired ratios (20000
    resamples, seed 0x50465030);
  * multiplicity is handled with Holm-Bonferroni over the sign-test p-values for
    the declared workload family, and a Bonferroni family-wise confidence level
    is reported alongside the unadjusted 95% interval.

No outlier is removed and no comparison is added after execution.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
import re
import statistics
import sys
from pathlib import Path

RESULT_RE = re.compile(
    r"^RESULT (\S+) median_us=([0-9.]+) min_us=([0-9.]+) max_us=([0-9.]+) "
    r"spread=([0-9.]+) iters=(\d+) runs=(\d+)$"
)
ALLOC_RE = re.compile(
    r"^ALLOC (\S+) allocs_per_op=([0-9.]+|n/a) malloc_per_op=([0-9.]+|n/a) "
    r"iters=(\d+)$"
)
LOADED_RE = re.compile(
    r"^LOADED realpath=(\S+) dev=(\d+) ino=(\d+) size=(\d+)$"
)
CROSS_RE = re.compile(r"^CROSS (sign|verify) path=\S+ (?:bytes=\d+ )?pub=([0-9a-f]+)$")
CROSS_VERIFY_RE = re.compile(r"^CROSS verify path=\S+ ok=([01]) pub=([0-9a-f]+)$")

BOOTSTRAP_SEED = 0x50465030
BOOTSTRAP_RESAMPLES = 20000
FAMILY_ALPHA = 0.05


def fail(message: str) -> None:
    print(f"analyse_bench_api: FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def median(values: list[float]) -> float:
    return statistics.median(values)


def percentile(sorted_values: list[float], pct: float) -> float:
    if not sorted_values:
        fail("percentile of an empty sample")
    if len(sorted_values) == 1:
        return sorted_values[0]
    rank = (len(sorted_values) - 1) * (pct / 100.0)
    lower = math.floor(rank)
    upper = math.ceil(rank)
    if lower == upper:
        return sorted_values[lower]
    return sorted_values[lower] + (sorted_values[upper] - sorted_values[lower]) * (
        rank - lower
    )


def bootstrap_median_ci(
    values: list[float], level: float, rng: random.Random
) -> tuple[float, float]:
    n = len(values)
    estimates = []
    for _ in range(BOOTSTRAP_RESAMPLES):
        sample = [values[rng.randrange(n)] for _ in range(n)]
        estimates.append(median(sample))
    estimates.sort()
    tail = (1.0 - level) / 2.0 * 100.0
    return percentile(estimates, tail), percentile(estimates, 100.0 - tail)


def sign_test_p(ratios: list[float]) -> float:
    above = sum(1 for value in ratios if value > 1.0)
    below = sum(1 for value in ratios if value < 1.0)
    n = above + below
    if n == 0:
        return 1.0
    k = min(above, below)
    p = sum(math.comb(n, i) for i in range(k + 1)) / (2**n)
    return min(1.0, 2.0 * p)


def holm(p_values: list[float]) -> list[float]:
    m = len(p_values)
    order = sorted(range(m), key=lambda i: p_values[i])
    adjusted = [1.0] * m
    running = 0.0
    for rank, index in enumerate(order):
        value = min(1.0, p_values[index] * (m - rank))
        running = max(running, value)
        adjusted[index] = running
    return adjusted


def parse_results(path: Path) -> dict[str, dict]:
    parsed = {}
    for line in path.read_text().splitlines():
        match = RESULT_RE.match(line)
        if not match:
            continue
        name = match.group(1)
        if name in parsed:
            fail(f"{path}: duplicate RESULT line for {name}")
        parsed[name] = {
            "median_us": float(match.group(2)),
            "min_us": float(match.group(3)),
            "max_us": float(match.group(4)),
            "spread": float(match.group(5)),
            "iters": int(match.group(6)),
            "runs": int(match.group(7)),
        }
    return parsed


def parse_allocs(path: Path) -> dict[str, dict]:
    parsed = {}
    for line in path.read_text().splitlines():
        match = ALLOC_RE.match(line)
        if not match:
            continue
        name = match.group(1)
        if name in parsed:
            fail(f"{path}: duplicate ALLOC line for {name}")
        parsed[name] = {
            "allocs_per_op": None
            if match.group(2) == "n/a"
            else float(match.group(2)),
            "malloc_class_per_op": None
            if match.group(3) == "n/a"
            else float(match.group(3)),
            "iters": int(match.group(4)),
        }
    return parsed


def parse_tsv(path: Path) -> list[dict]:
    lines = path.read_text().splitlines()
    if not lines:
        fail(f"{path}: empty")
    header = lines[0].split("\t")
    return [dict(zip(header, line.split("\t"))) for line in lines[1:]]


def read_env(path: Path) -> dict:
    doc = {}
    if not path.is_file():
        return doc
    for line in path.read_text().splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            doc[key] = value
    return doc


def check_population(
    parsed: dict, expected: list[str], label: str
) -> None:
    if sorted(parsed) != expected:
        missing = sorted(set(expected) - set(parsed))
        extra = sorted(set(parsed) - set(expected))
        fail(f"{label}: population mismatch; missing={missing} extra={extra}")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--workloads", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)

    work = args.work
    raw = work / "raw"
    if (work / "BLOCKED").exists():
        fail("campaign has a BLOCKED marker")

    workloads_doc = json.loads(args.workloads.read_text())
    workloads = {item["id"]: item for item in workloads_doc["workloads"]}
    expected = sorted(workloads)
    build_identity = json.loads((work / "build-identity.json").read_text())
    preregistration = json.loads((work / "preregistration.json").read_text())

    order = []
    for line in (raw / "run-order.tsv").read_text().splitlines():
        rep, first, second = line.split("\t")
        order.append({"repetition": rep, "first": first, "second": second})
    if len(order) != preregistration["repetitions"]:
        fail(f"order has {len(order)} repetitions, preregistered "
             f"{preregistration['repetitions']}")
    candidate_first = sum(1 for row in order if row["first"] == "candidate")
    if candidate_first != preregistration["ordering"]["candidate_first_blocks"]:
        fail("order is not the preregistered balanced sequence")

    # --- identity ---------------------------------------------------------
    identity_rows = parse_tsv(raw / "identity-check.tsv")
    if not identity_rows:
        fail("no loaded-artefact checks")
    artefact_digests = {
        "candidate": build_identity["artefacts"]["distribution_dso"]["sha256"],
        "authority": build_identity["artefacts"]["authority_dso"]["sha256"],
    }
    identity_failures = []
    for row in identity_rows:
        subject = row["subject"]
        expected_digest = artefact_digests.get(subject)
        ok = (
            row["status"] == "ok"
            and int(row["maps_entries"]) >= 1
            and row["expected_realpath"] == row["reported_realpath"]
            and row["expected_dev"] == row["reported_dev"]
            and row["expected_ino"] == row["reported_ino"]
            and (expected_digest is None or row["dso_sha256"] == expected_digest)
        )
        if not ok:
            identity_failures.append(row)
    if identity_failures:
        fail(f"loaded-artefact verification failed: {identity_failures[:3]}")

    # --- repetitions ------------------------------------------------------
    sample_table = []
    per_workload_ratios: dict[str, list[float]] = {name: [] for name in expected}
    per_workload_candidate: dict[str, list[float]] = {name: [] for name in expected}
    per_workload_authority: dict[str, list[float]] = {name: [] for name in expected}
    checks_ok = True

    for row in order:
        rep = row["repetition"]
        entry = {"repetition": rep, "order": [row["first"], row["second"]],
                 "subjects": {}}
        for subject in ("candidate", "authority"):
            out = raw / f"rep-{rep}-{subject}.out"
            if not out.is_file():
                fail(f"missing {out}")
            parsed = parse_results(out)
            check_population(parsed, expected, f"{out.name}")
            entry["subjects"][subject] = parsed
        cand_checks = (raw / f"rep-{rep}-candidate.check").read_text().splitlines()
        auth_checks = (raw / f"rep-{rep}-authority.check").read_text().splitlines()
        if cand_checks != auth_checks:
            fail(f"repetition {rep}: CHECK lines differ")
        entry["checks_match"] = True
        entry["check_lines"] = len(cand_checks)
        sample_table.append(entry)

        for name in expected:
            c = entry["subjects"]["candidate"][name]["median_us"]
            a = entry["subjects"]["authority"][name]["median_us"]
            if a <= 0:
                fail(f"repetition {rep}: non-positive authority time for {name}")
            per_workload_candidate[name].append(c)
            per_workload_authority[name].append(a)
            per_workload_ratios[name].append(c / a)

    # --- allocations ------------------------------------------------------
    alloc_candidate = parse_allocs(raw / "alloc-candidate.out")
    alloc_authority = parse_allocs(raw / "alloc-authority.out")
    check_population(alloc_candidate, expected, "alloc-candidate")
    check_population(alloc_authority, expected, "alloc-authority")
    for name in expected:
        if alloc_candidate[name]["allocs_per_op"] is None:
            fail(f"allocation probe did not observe {name} for the candidate")
        if alloc_authority[name]["allocs_per_op"] is None:
            fail(f"allocation probe did not observe {name} for the authority")

    # --- cross verification ----------------------------------------------
    cross_rows = parse_tsv(work / "cross-verification.tsv")
    expected_cross = len(preregistration["cross_verification_repetitions"]) * 2
    if len(cross_rows) != expected_cross:
        fail(f"cross-verification has {len(cross_rows)} rows, expected {expected_cross}")
    if any(row["verified"] != "1" for row in cross_rows):
        fail("a cross-library signature was rejected")
    pubs = {row["public_key"] for row in cross_rows}
    if len(pubs) != 1:
        fail("cross-library public keys differ")

    # --- statistics -------------------------------------------------------
    rng = random.Random(BOOTSTRAP_SEED)
    family_level = 1.0 - FAMILY_ALPHA / len(expected)
    timing = {}
    p_values = []
    for name in expected:
        ratios = per_workload_ratios[name]
        cand = per_workload_candidate[name]
        auth = per_workload_authority[name]
        ratio_median = median(ratios)
        ci95 = bootstrap_median_ci(ratios, 0.95, rng)
        ci_family = bootstrap_median_ci(ratios, family_level, rng)
        p_value = sign_test_p(ratios)
        p_values.append(p_value)

        def rel_mad(values: list[float]) -> float:
            med = median(values)
            mad = median([abs(value - med) for value in values])
            return mad / med if med else float("inf")

        timing[name] = {
            "n_pairs": len(ratios),
            "candidate_us": cand,
            "authority_us": auth,
            "candidate_median_us": median(cand),
            "authority_median_us": median(auth),
            "candidate_iqr_us": [
                percentile(sorted(cand), 25.0),
                percentile(sorted(cand), 75.0),
            ],
            "authority_iqr_us": [
                percentile(sorted(auth), 25.0),
                percentile(sorted(auth), 75.0),
            ],
            "candidate_relative_mad": rel_mad(cand),
            "authority_relative_mad": rel_mad(auth),
            "paired_ratios": ratios,
            "paired_ratio_median": ratio_median,
            "paired_ratio_ci95": list(ci95),
            "paired_ratio_ci_familywise": list(ci_family),
            "ratio_of_medians": median(cand) / median(auth),
            "sign_test_p_two_sided": p_value,
        }

    adjusted = holm(p_values)
    for name, p_adjusted in zip(expected, adjusted):
        timing[name]["holm_adjusted_p"] = p_adjusted
        timing[name]["significant_after_holm"] = p_adjusted < FAMILY_ALPHA

    allocations = {}
    for name in expected:
        c = alloc_candidate[name]
        a = alloc_authority[name]
        allocations[name] = {
            "candidate": c,
            "authority": a,
            "allocs_ratio": (
                c["allocs_per_op"] / a["allocs_per_op"]
                if a["allocs_per_op"]
                else None
            ),
            "malloc_class_ratio": (
                c["malloc_class_per_op"] / a["malloc_class_per_op"]
                if a["malloc_class_per_op"]
                else None
            ),
        }

    # --- discrepancies against previously reported rows -------------------
    discrepancies = []
    for name in expected:
        for previous in workloads[name].get("previous_reported", []):
            old_ratio = previous.get("ratio")
            old_candidate_alloc = previous.get("candidate_allocations")
            old_authority_alloc = previous.get("authority_allocations")
            row = {
                "workload": name,
                "source": previous.get("source"),
                "previously_reported_ratio": old_ratio,
                "measured_ratio_median": timing[name]["paired_ratio_median"],
                "ratio_ci95": timing[name]["paired_ratio_ci95"],
            }
            if old_ratio is not None:
                lo, hi = timing[name]["paired_ratio_ci95"]
                row["delta"] = timing[name]["paired_ratio_median"] - old_ratio
                row["delta_percent"] = (
                    100.0 * row["delta"] / old_ratio if old_ratio else None
                )
                row["previous_inside_ci95"] = lo <= old_ratio <= hi
                row["direction"] = (
                    "candidate_worse"
                    if timing[name]["paired_ratio_median"] > old_ratio
                    else "candidate_better"
                    if timing[name]["paired_ratio_median"] < old_ratio
                    else "unchanged"
                )
            row["previously_reported_candidate_allocations"] = old_candidate_alloc
            row["measured_candidate_allocations"] = allocations[name]["candidate"][
                "malloc_class_per_op"
            ]
            row["previously_reported_authority_allocations"] = old_authority_alloc
            row["measured_authority_allocations"] = allocations[name]["authority"][
                "malloc_class_per_op"
            ]
            if old_candidate_alloc is not None:
                row["candidate_allocation_delta"] = (
                    allocations[name]["candidate"]["malloc_class_per_op"]
                    - old_candidate_alloc
                )
            if old_authority_alloc is not None:
                row["authority_allocation_delta"] = (
                    allocations[name]["authority"]["malloc_class_per_op"]
                    - old_authority_alloc
                )
            discrepancies.append(row)

    # --- output -----------------------------------------------------------
    venue = read_env(work / "venue.txt")
    pmu = {
        "cpu_event_source": venue.get("cpu_event_source"),
        "perf_event_paranoid": venue.get("perf_event_paranoid"),
        "probe": (raw / "pmu-probe.txt").read_text(),
        "perf": (raw / "pmu-perf.txt").read_text(),
    }
    pmu["cpu_event_source"] = (
        "present"
        if "cpu_event_source=present" in (raw / "pmu-perf.txt").read_text()
        else "absent"
    )

    doc = {
        "schema": "openssl-rs/performance/results/v1",
        "campaign": "PFP-0",
        "classification": "SCOPED_OBSERVATION",
        "frontier_claim": False,
        "not_a_frontier_result": True,
        "venue": {
            "description": (
                f"virtualised court container {venue.get('court_image', 'unknown')} "
                f"on kernel {venue.get('kernel', 'unknown')}, CPU "
                f"{venue.get('cpu_model', 'unknown')}, cgroup memory "
                f"{venue.get('cgroup_memory_max', 'unknown')} bytes, cgroup CPU "
                f"{venue.get('cgroup_cpu_max', 'unknown')}, one core pinned with "
                f"taskset -c {venue.get('taskset_cpu', 'unknown')}; no exposed PMU"
            ),
            "env": venue,
        },
        "identity": {
            "source": build_identity["source"],
            "artefacts": build_identity["artefacts"],
            "harness": build_identity["harness"],
            "tools": build_identity["tools"],
            "shell_generation": build_identity.get("shell_generation"),
            "loaded_verification": {
                "all_ok": True,
                "checks": len(identity_rows),
                "file": "raw/identity-check.tsv",
                "candidate_sha256": artefact_digests["candidate"],
                "authority_sha256": artefact_digests["authority"],
            },
        },
        "protocol": preregistration,
        "ordering": order,
        "population": {
            "expected": expected,
            "result_lines_per_process": 1,
            "all_checked": True,
            "check_lines_per_process": len(expected),
        },
        "correctness": {
            "check_lines_match_all_repetitions": checks_ok,
            "repetitions_checked": len(order),
            "cross_verification": cross_rows,
            "cross_public_keys_equal": len(pubs) == 1,
        },
        "timing": timing,
        "allocations": allocations,
        "multiplicity": {
            "family": expected,
            "method": "Holm-Bonferroni over two-sided sign-test p-values; "
                      "Bonferroni family-wise interval for each ratio",
            "family_alpha": FAMILY_ALPHA,
            "per_comparison_alpha": FAMILY_ALPHA / len(expected),
            "familywise_interval_level": family_level,
        },
        "bootstrap": {
            "resamples": BOOTSTRAP_RESAMPLES,
            "seed": hex(BOOTSTRAP_SEED),
            "statistic": "median of paired ratios",
        },
        "discrepancies": discrepancies,
        "pmu": pmu,
        "raw_samples": "raw/rep-*.out",
        "blocked": False,
    }

    # Recompute the on-disk digests and refuse a post-hoc substitution.
    for key, rel in (
        ("distribution_dso", build_identity["artefacts"]["distribution_dso"]["path"]),
        ("authority_dso", build_identity["artefacts"]["authority_dso"]["path"]),
    ):
        candidate = Path(rel)
        if not candidate.is_absolute():
            candidate = Path("/work") / rel
        if candidate.is_file():
            if sha256_file(candidate) != build_identity["artefacts"][key]["sha256"]:
                fail(f"{key} on disk no longer matches build-identity.json")

    args.out.write_text(json.dumps(doc, indent=2, sort_keys=False) + "\n")
    print(f"results: {args.out}")
    print(f"{'workload':16s} {'cand_us':>12s} {'auth_us':>12s} "
          f"{'ratio':>8s} {'ci95':>20s} {'allocs c/a':>16s}")
    for name in expected:
        t = timing[name]
        a = allocations[name]
        print(
            f"{name:16s} {t['candidate_median_us']:12.3f} "
            f"{t['authority_median_us']:12.3f} {t['paired_ratio_median']:8.2f} "
            f"[{t['paired_ratio_ci95'][0]:7.2f},{t['paired_ratio_ci95'][1]:7.2f}] "
            f"{a['candidate']['malloc_class_per_op']:7.2f}/"
            f"{a['authority']['malloc_class_per_op']:6.2f}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
