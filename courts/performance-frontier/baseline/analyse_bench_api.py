#!/usr/bin/env python3
"""Analyse a completed PFP-0 campaign.

Reads only the raw outputs written by `courts/phase18/timing/run_bench_api.sh`
and the frozen population in `forensics/performance/WORKLOADS.json`.  It refuses
to emit `results.json` if the population, correctness, identity, ordering or
cross-verification checks fail; a failed campaign is BLOCKED, never PASS.

Every refusal names a stable rule identifier and the specific gap:

  * `PFP_IDENTITY_POPULATION`  the process identity rows are not exactly the
    preregistered repetition x subject x phase population;
  * `PFP_ORDERING_IDENTITY`    the realised repetitions are not exactly the
    preregistered identifiers, once each;
  * `PFP_ORDERING_PAIR`        a repetition is not one candidate/authority pair;
  * `PFP_ORDERING_BALANCE`     the realised first-subject counts are not the
    preregistered balanced sequence;
  * `PFP_CHECK_POPULATION`     a side has no CHECK lines, or does not carry every
    declared workload check exactly the declared number of times;
  * `PFP_CROSS_POPULATION`     the cross-verification rows are not exactly the
    declared (repetition, signer, verifier) tuples;
  * `PFP_JSON_DUPLICATE_KEY` / `PFP_JSON_NON_FINITE`  a campaign or workload
    document is ambiguous or carries a non-finite number.

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
from typing import Any

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
CHECK_RE = re.compile(r"^CHECK (\S+)(?:[ \t].*)?$")

BOOTSTRAP_SEED = 0x50465030
BOOTSTRAP_RESAMPLES = 20000
FAMILY_ALPHA = 0.05

SUBJECTS = ("candidate", "authority")


class CampaignRefusal(Exception):
    """A campaign reconstruction refusal with a stable rule identifier."""

    def __init__(self, rule: str, detail: str) -> None:
        super().__init__(f"{rule}: {detail}")
        self.rule = rule
        self.detail = detail


def fail(rule: str, message: str) -> None:
    print(f"analyse_bench_api: FAIL: {rule}: {message}", file=sys.stderr)
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
        raise CampaignRefusal("PFP_STATISTIC", "percentile of an empty sample")
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


# ---------------------------------------------------------------------------
# Strict JSON: duplicate object keys and non-finite numbers are refusals
# ---------------------------------------------------------------------------


class _JsonPairs:
    """An object's ordered key/value pairs, kept before duplicate keys collapse."""

    __slots__ = ("pairs",)

    def __init__(self, pairs: list[tuple[str, Any]]) -> None:
        self.pairs = pairs


class _JsonNonFinite:
    """A NaN or Infinity token, retained so its JSON pointer can be reported."""

    __slots__ = ("token",)

    def __init__(self, token: str) -> None:
        self.token = token


def _ptr(path: str, token: str) -> str:
    return f"{path}/{token}"


def _normalise_json(
    value: Any, path: str, findings: list[tuple[str, str, str]]
) -> Any:
    if isinstance(value, _JsonPairs):
        rebuilt: dict[str, Any] = {}
        for key, item in value.pairs:
            if key in rebuilt:
                findings.append(
                    (
                        "PFP_JSON_DUPLICATE_KEY",
                        _ptr(path, key),
                        f"duplicate object key at {_ptr(path, key)}; a repeated "
                        "key makes the document ambiguous",
                    )
                )
            rebuilt[key] = _normalise_json(item, _ptr(path, key), findings)
        return rebuilt
    if isinstance(value, list):
        return [
            _normalise_json(item, _ptr(path, str(index)), findings)
            for index, item in enumerate(value)
        ]
    if isinstance(value, _JsonNonFinite):
        findings.append(
            (
                "PFP_JSON_NON_FINITE",
                path,
                f"non-finite number {value.token!r} at {path}; JSON numbers must "
                "be finite",
            )
        )
        return None
    if isinstance(value, float) and not math.isfinite(value):
        findings.append(
            (
                "PFP_JSON_NON_FINITE",
                path,
                f"non-finite number {value!r} at {path}; JSON numbers must be finite",
            )
        )
        return None
    return value


def load_json_strict(path: Path) -> Any:
    try:
        parsed = json.loads(
            path.read_text(),
            object_pairs_hook=_JsonPairs,
            parse_constant=_JsonNonFinite,
        )
    except json.JSONDecodeError as exc:
        raise CampaignRefusal(
            "PFP_JSON_MALFORMED",
            f"{path}: malformed JSON at line {exc.lineno} column {exc.colno}: "
            f"{exc.msg}",
        ) from exc
    findings: list[tuple[str, str, str]] = []
    document = _normalise_json(parsed, "$", findings)
    if findings:
        rule, location, detail = sorted(findings)[0]
        raise CampaignRefusal(rule, f"{path}: {detail} ({location})")
    return document


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


def parse_results(path: Path) -> dict[str, dict]:
    parsed = {}
    for line in path.read_text().splitlines():
        match = RESULT_RE.match(line)
        if not match:
            continue
        name = match.group(1)
        if name in parsed:
            raise CampaignRefusal(
                "PFP_RESULT_POPULATION", f"{path}: duplicate RESULT line for {name}"
            )
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
            raise CampaignRefusal(
                "PFP_ALLOCATION", f"{path}: duplicate ALLOC line for {name}"
            )
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


def parse_tsv(path: Path, columns: tuple[str, ...]) -> list[dict]:
    lines = path.read_text().splitlines()
    if not lines:
        raise CampaignRefusal("PFP_POPULATION", f"{path}: empty")
    header = lines[0].split("\t")
    missing = [name for name in columns if name not in header]
    if missing:
        raise CampaignRefusal(
            "PFP_POPULATION", f"{path}: missing column(s) {missing}"
        )
    rows = []
    for number, line in enumerate(lines[1:], start=2):
        fields = line.split("\t")
        if len(fields) != len(header):
            raise CampaignRefusal(
                "PFP_POPULATION",
                f"{path}:{number}: expected {len(header)} tab-separated fields, "
                f"got {len(fields)}",
            )
        rows.append(dict(zip(header, fields)))
    return rows


def parse_order(path: Path) -> list[dict]:
    rows = []
    for number, line in enumerate(path.read_text().splitlines(), start=1):
        fields = line.split("\t")
        if len(fields) != 3:
            raise CampaignRefusal(
                "PFP_ORDERING_IDENTITY",
                f"{path}:{number}: expected repetition, first, second",
            )
        rows.append(
            {"repetition": fields[0], "first": fields[1], "second": fields[2]}
        )
    return rows


def parse_check_ids(path: Path) -> list[str]:
    identifiers = []
    for number, line in enumerate(path.read_text().splitlines(), start=1):
        match = CHECK_RE.match(line)
        if not match:
            raise CampaignRefusal(
                "PFP_CHECK_POPULATION",
                f"{path}:{number}: line is not a CHECK record",
            )
        identifiers.append(match.group(1))
    return identifiers


def read_env(path: Path) -> dict:
    doc = {}
    if not path.is_file():
        return doc
    for line in path.read_text().splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            doc[key] = value
    return doc


# ---------------------------------------------------------------------------
# Preregistered populations
# ---------------------------------------------------------------------------


def expected_repetition_ids(preregistration: dict) -> list[str]:
    count = preregistration.get("repetitions")
    if not isinstance(count, int) or isinstance(count, bool) or count < 1:
        raise CampaignRefusal(
            "PFP_PREREGISTRATION", "repetitions must be a positive integer"
        )
    return [f"{index:02d}" for index in range(count)]


def cross_repetitions(preregistration: dict, repetitions: list[str]) -> list[str]:
    declared = preregistration.get("cross_verification_repetitions")
    if (
        not isinstance(declared, list)
        or not declared
        or not all(isinstance(item, str) and item for item in declared)
        or len(set(declared)) != len(declared)
    ):
        raise CampaignRefusal(
            "PFP_PREREGISTRATION",
            "cross_verification_repetitions must be distinct non-empty identifiers",
        )
    unknown = sorted(set(declared) - set(repetitions))
    if unknown:
        raise CampaignRefusal(
            "PFP_PREREGISTRATION",
            f"cross-verification names repetition(s) not declared as measured: {unknown}",
        )
    return list(declared)


def expected_identity_population(preregistration: dict) -> list[tuple[str, str]]:
    """Every process identity the preregistered phases require, once each."""
    repetitions = expected_repetition_ids(preregistration)
    cross = cross_repetitions(preregistration, repetitions)
    labels = ["warmup", *[f"rep-{rep}" for rep in repetitions], "alloc"]
    for rep in cross:
        for signer in SUBJECTS:
            labels.append(f"cross-{rep}-{signer}")
    return [(label, subject) for label in labels for subject in SUBJECTS]


def check_identity_population(preregistration: dict, rows: list[dict]) -> None:
    expected = expected_identity_population(preregistration)
    actual = [(row.get("label"), row.get("subject")) for row in rows]
    counts: dict[tuple, int] = {}
    for pair in actual:
        counts[pair] = counts.get(pair, 0) + 1
    duplicated = sorted(pair for pair, count in counts.items() if count > 1)
    expected_set = set(expected)
    actual_set = set(actual)
    missing = sorted(expected_set - actual_set)
    extra = sorted(actual_set - expected_set)
    substituted = []
    for label in sorted({label for label, _ in expected}):
        expected_subjects = {s for item, s in expected if item == label}
        actual_subjects = {s for item, s in actual if item == label}
        if actual_subjects and actual_subjects != expected_subjects:
            substituted.append(
                (label, sorted(expected_subjects), sorted(actual_subjects))
            )
    if missing or duplicated or extra or substituted:
        raise CampaignRefusal(
            "PFP_IDENTITY_POPULATION",
            "process identity population mismatch; "
            f"missing={missing} duplicated={duplicated} extra={extra} "
            f"substituted={substituted}",
        )


def check_order(preregistration: dict, order: list[dict]) -> None:
    repetitions = expected_repetition_ids(preregistration)
    actual = [row.get("repetition") for row in order]
    counts: dict[str, int] = {}
    for rep in actual:
        counts[rep] = counts.get(rep, 0) + 1
    duplicated = sorted(rep for rep, count in counts.items() if count > 1)
    missing = sorted(set(repetitions) - set(actual))
    extra = sorted(set(actual) - set(repetitions))
    if sorted(actual) != repetitions:
        raise CampaignRefusal(
            "PFP_ORDERING_IDENTITY",
            "realised repetition population mismatch; "
            f"missing={missing} duplicated={duplicated} extra={extra} "
            f"count={len(actual)} expected={len(repetitions)}",
        )
    for row in order:
        pair = (row.get("first"), row.get("second"))
        if pair not in (
            ("candidate", "authority"),
            ("authority", "candidate"),
        ):
            raise CampaignRefusal(
                "PFP_ORDERING_PAIR",
                f"repetition {row.get('repetition')}: order {pair} is not one "
                "candidate/authority pair",
            )
    ordering = preregistration.get("ordering")
    if not isinstance(ordering, dict):
        raise CampaignRefusal(
            "PFP_PREREGISTRATION", "ordering must be a declared object"
        )
    if ordering.get("kind") != "balanced pseudo-random within each repetition":
        raise CampaignRefusal(
            "PFP_ORDERING_BALANCE",
            "declared ordering property is not a balanced within-repetition sequence",
        )
    candidate_declared = ordering.get("candidate_first_blocks")
    authority_declared = ordering.get("authority_first_blocks")
    if (
        not isinstance(candidate_declared, int)
        or isinstance(candidate_declared, bool)
        or not isinstance(authority_declared, int)
        or isinstance(authority_declared, bool)
    ):
        raise CampaignRefusal(
            "PFP_ORDERING_BALANCE",
            "candidate_first_blocks and authority_first_blocks must be integers",
        )
    if candidate_declared + authority_declared != len(repetitions):
        raise CampaignRefusal(
            "PFP_ORDERING_BALANCE",
            "declared first-subject counts do not partition the repetition count",
        )
    if abs(candidate_declared - authority_declared) > 1:
        raise CampaignRefusal(
            "PFP_ORDERING_BALANCE",
            "declared sequence is not balanced; the blocks differ by more than one",
        )
    candidate_first = sum(1 for row in order if row.get("first") == "candidate")
    authority_first = len(order) - candidate_first
    if (
        candidate_first != candidate_declared
        or authority_first != authority_declared
    ):
        raise CampaignRefusal(
            "PFP_ORDERING_BALANCE",
            "realised per-repetition order does not match the declared balanced "
            f"sequence; candidate_first={candidate_first} (declared "
            f"{candidate_declared}), authority_first={authority_first} (declared "
            f"{authority_declared})",
        )


def expected_check_counts(workloads_document: dict) -> dict[str, int]:
    workloads = workloads_document.get("workloads")
    if not isinstance(workloads, list) or not workloads:
        raise CampaignRefusal("PFP_PREREGISTRATION", "no workloads are declared")
    counts: dict[str, int] = {}
    for workload in workloads:
        name = workload.get("id")
        count = workload.get("check_line_count_per_process")
        if not isinstance(name, str) or not name:
            raise CampaignRefusal(
                "PFP_PREREGISTRATION", "a workload has no identifier"
            )
        if not isinstance(count, int) or isinstance(count, bool) or count < 1:
            raise CampaignRefusal(
                "PFP_PREREGISTRATION",
                f"workload {name} does not declare a positive check population",
            )
        counts[name] = count
    return counts


def check_check_population(
    repetition: str, side: str, identifiers: list[str], expected: dict[str, int]
) -> None:
    path = f"repetition {repetition} {side}"
    if not identifiers:
        raise CampaignRefusal(
            "PFP_CHECK_POPULATION", f"{path}: no CHECK lines; an empty side is empty"
        )
    observed: dict[str, int] = {}
    for identifier in identifiers:
        observed[identifier] = observed.get(identifier, 0) + 1
    missing = sorted(name for name, count in expected.items() if observed.get(name, 0) < count)
    duplicated = sorted(name for name, count in expected.items() if observed.get(name, 0) > count)
    extra = sorted(set(identifiers) - set(expected))
    if missing or duplicated or extra:
        raise CampaignRefusal(
            "PFP_CHECK_POPULATION",
            f"{path}: population mismatch; missing={missing} "
            f"duplicated={duplicated} extra={extra}",
        )


def expected_cross_population(preregistration: dict) -> set[tuple[str, str, str]]:
    repetitions = expected_repetition_ids(preregistration)
    cross = cross_repetitions(preregistration, repetitions)
    tuples = set()
    for rep in cross:
        tuples.add((rep, "candidate", "authority"))
        tuples.add((rep, "authority", "candidate"))
    return tuples


def check_cross_population(preregistration: dict, rows: list[dict]) -> None:
    expected = expected_cross_population(preregistration)
    actual = []
    for index, row in enumerate(rows):
        try:
            actual.append(
                (row["repetition"], row["signer"], row["verifier"])
            )
        except KeyError:
            raise CampaignRefusal(
                "PFP_CROSS_POPULATION",
                f"cross-verification row {index} lacks a repetition, signer or verifier",
            )
    counts: dict[tuple, int] = {}
    for item in actual:
        counts[item] = counts.get(item, 0) + 1
    duplicated = sorted(item for item, count in counts.items() if count > 1)
    missing = sorted(expected - set(actual))
    extra = sorted(set(actual) - expected)
    substituted = sorted(
        item for item in set(actual) if item not in expected
    )
    if missing or duplicated or extra:
        raise CampaignRefusal(
            "PFP_CROSS_POPULATION",
            "cross-verification population mismatch; "
            f"missing={missing} duplicated={duplicated} extra={extra} "
            f"substituted={substituted}",
        )


def check_population(parsed: dict, expected: list[str], label: str) -> None:
    if sorted(parsed) != expected:
        missing = sorted(set(expected) - set(parsed))
        extra = sorted(set(parsed) - set(expected))
        raise CampaignRefusal(
            "PFP_POPULATION", f"{label}: population mismatch; missing={missing} extra={extra}"
        )


# ---------------------------------------------------------------------------
# Campaign
# ---------------------------------------------------------------------------


def analyse(args: argparse.Namespace) -> dict:
    work = args.work
    raw = work / "raw"
    if (work / "BLOCKED").exists():
        raise CampaignRefusal(
            "PFP_BLOCKED", "campaign has a BLOCKED marker; a blocked run is not a pass"
        )

    workloads_doc = load_json_strict(args.workloads)
    workloads = {item["id"]: item for item in workloads_doc["workloads"]}
    expected = sorted(workloads)
    check_counts = expected_check_counts(workloads_doc)
    build_identity = load_json_strict(work / "build-identity.json")
    preregistration = load_json_strict(work / "preregistration.json")

    order = parse_order(raw / "run-order.tsv")
    check_order(preregistration, order)

    # --- identity ---------------------------------------------------------
    identity_rows = parse_tsv(
        raw / "identity-check.tsv", ("label", "subject")
    )
    check_identity_population(preregistration, identity_rows)
    artefact_digests = {
        "candidate": build_identity["artefacts"]["distribution_dso"]["sha256"],
        "authority": build_identity["artefacts"]["authority_dso"]["sha256"],
    }
    identity_failures = []
    for row in identity_rows:
        subject = row["subject"]
        expected_digest = artefact_digests.get(subject)
        try:
            maps_entries = int(row["maps_entries"])
        except (KeyError, ValueError):
            raise CampaignRefusal(
                "PFP_IDENTITY_MISMATCH",
                f"identity row {row.get('label')}/{subject} has no integer maps entry count",
            )
        ok = (
            row.get("status") == "ok"
            and maps_entries >= 1
            and row.get("expected_realpath") == row.get("reported_realpath")
            and row.get("expected_dev") == row.get("reported_dev")
            and row.get("expected_ino") == row.get("reported_ino")
            and (expected_digest is None or row.get("dso_sha256") == expected_digest)
        )
        if not ok:
            identity_failures.append(row)
    if identity_failures:
        raise CampaignRefusal(
            "PFP_IDENTITY_MISMATCH",
            f"loaded-artefact verification failed: {identity_failures[:3]}",
        )

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
        for subject in SUBJECTS:
            out = raw / f"rep-{rep}-{subject}.out"
            if not out.is_file():
                raise CampaignRefusal("PFP_POPULATION", f"missing {out}")
            parsed = parse_results(out)
            check_population(parsed, expected, f"{out.name}")
            entry["subjects"][subject] = parsed
        cand_check_path = raw / f"rep-{rep}-candidate.check"
        auth_check_path = raw / f"rep-{rep}-authority.check"
        for side, path in (
            ("candidate", cand_check_path),
            ("authority", auth_check_path),
        ):
            check_check_population(rep, side, parse_check_ids(path), check_counts)
        cand_checks = cand_check_path.read_text().splitlines()
        auth_checks = auth_check_path.read_text().splitlines()
        if cand_checks != auth_checks:
            raise CampaignRefusal(
                "PFP_CHECK_CONTENT", f"repetition {rep}: CHECK lines differ"
            )
        entry["checks_match"] = True
        entry["check_lines"] = len(cand_checks)
        sample_table.append(entry)

        for name in expected:
            c = entry["subjects"]["candidate"][name]["median_us"]
            a = entry["subjects"]["authority"][name]["median_us"]
            if a <= 0:
                raise CampaignRefusal(
                    "PFP_RESULT_VALUE",
                    f"repetition {rep}: non-positive authority time for {name}",
                )
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
            raise CampaignRefusal(
                "PFP_ALLOCATION",
                f"allocation probe did not observe {name} for the candidate",
            )
        if alloc_authority[name]["allocs_per_op"] is None:
            raise CampaignRefusal(
                "PFP_ALLOCATION",
                f"allocation probe did not observe {name} for the authority",
            )

    # --- cross verification ----------------------------------------------
    cross_rows = parse_tsv(
        work / "cross-verification.tsv",
        ("repetition", "signer", "verifier", "verified", "public_key"),
    )
    check_cross_population(preregistration, cross_rows)
    if any(row["verified"] != "1" for row in cross_rows):
        raise CampaignRefusal(
            "PFP_CROSS_VERIFICATION", "a cross-library signature was rejected"
        )
    pubs = {row["public_key"] for row in cross_rows}
    if len(pubs) != 1:
        raise CampaignRefusal(
            "PFP_CROSS_VERIFICATION", "cross-library public keys differ"
        )

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
                raise CampaignRefusal(
                    "PFP_ARTEFACT",
                    f"{key} on disk no longer matches build-identity.json",
                )

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
    return doc


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--workloads", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        analyse(args)
    except CampaignRefusal as exc:
        fail(exc.rule, exc.detail)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
