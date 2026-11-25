#!/usr/bin/env python3
"""PFP-18 performance classification binding validator.

The problem this tool exists for
--------------------------------
`docs/PERFORMANCE-FRONTIER.md` §10 defines seven performance classifications and
requires each of them to be a typed claim: candidate identity, instrument
identity, population, scope, security model, venue and obligations. The queue
preamble says the same thing again. Neither sentence was executable, so a record
could say `FRONTIER_LEADING` and leave out the instrument, the population or the
obligations it does not discharge, and nothing refused it.

This tool makes the binding executable. It reads a claim record of type
`openssl-rs/performance/claim-record/v1` and refuses, by name, a record whose
classification is not supported by the fields the programme requires:

* an unknown or absent classification, candidate identity, instrument identity,
  population, scope, security model, venue, authority, comparator population or
  obligation set;
* a population whose realised identifiers are missing, duplicated or undeclared;
* a `VIRTUALISED_COURT` record classified `AHEAD` or above, and any frontier
  class without bare-metal controls on every platform claimed;
* a frontier record with a comparator that was not measured, or with no frozen
  qualified population;
* `COMPETITIVE`, `PARITY_ESTABLISHED`, `AHEAD` and the frontier classes without
  the preregistered criterion they are defined against;
* any record whose obligations are used to discharge a timing obligation;
* any record that also carries a safety or compatibility verdict: the
  performance classifications are disjoint from `SAFE_COMPATIBLE` and from
  semantic assurance, so the two must not share a record;
* a cited reference that is absent, or whose bytes do not match the recorded
  digest.

What this tool does not decide
------------------------------
It does not execute a benchmark, and it does not decide whether a cited
experiment occurred. It checks the record's form, its internal laws and the
digests of the files it cites. A record that passes is a well-bound claim, not a
true measurement: the raw samples, the venue and the instrument may still be
inadequate, and the record's own `producer.limits` and `obligations.open` are
where that is stated. It does not compare a record against a campaign result:
that cross-binding lives in `forensics/tools/tests/test_performance_classification.py`
so that the campaign-specific shape stays visible next to the campaign.

Exit codes
----------
  0  every record accepted
  1  at least one record refused
  2  usage error

Determinism
-----------
Problems are sorted by `(pointer, code, detail)`; JSON is serialised with sorted
keys and fixed separators; no timestamp is written. The same input produces
byte-identical output.

Usage
-----
    python3 forensics/tools/performance_classification.py check
    python3 forensics/tools/performance_classification.py check --record PATH
    python3 forensics/tools/performance_classification.py rules [--json]
    python3 forensics/tools/performance_classification.py self-test

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = Path(__file__).resolve()
DEFAULT_RECORDS = REPO_ROOT / "evidence" / "performance-frontier" / "claims"

SCHEMA = "openssl-rs/performance/claim-record/v1"

# Ordered from weakest to strongest. The order is used only to name the ceiling
# a venue supports; it is never combined into a score.
CLASSIFICATIONS = (
    "SCOPED_OBSERVATION",
    "MEASURED",
    "COMPETITIVE",
    "PARITY_ESTABLISHED",
    "AHEAD",
    "FRONTIER_LEADING",
    "INDEPENDENTLY_REPRODUCED_FRONTIER",
)
FRONTIER_CLASSES = {
    "FRONTIER_LEADING",
    "INDEPENDENTLY_REPRODUCED_FRONTIER",
}
# A virtualised court may support a ratio, a reproducibility statement or a
# preregistered equivalence. It may not support a lead: a lead measured without
# pinned frequency, disabled turbo/SMT and core isolation is not distinguishable
# from venue noise. This is stricter than "not a frontier result" and is stated
# as a conversion decision in PERFORMANCE-FRONTIER.md §15.
CONTROLLED_ONLY_CLASSES = {"AHEAD"} | FRONTIER_CLASSES

VENUE_CLASSES = {"VIRTUALISED_COURT", "BARE_METAL_PMU"}
SCOPE_LEVELS = ("L1", "L2", "L3", "L4", "L5")
COMPARATOR_STATUSES = {"MEASURED", "UNAVAILABLE", "NOT_APPLICABLE"}
SECRET_CLASSES = {
    "PUBLIC_DATA",
    "SECRET_DATA",
    "SECRET_DEPENDENT_CONTROL",
    "CLEANSING_REQUIRED",
    "DECLASSIFICATION_BOUNDARY",
}
CONTROL_KEYS = ("frequency_pinned", "turbo_disabled", "smt_disabled", "core_isolation")
# A performance record may not carry a safety or compatibility conclusion. The
# keys are refused wherever they appear, so a nested `assurance` object cannot
# smuggle one in.
FORBIDDEN_KEYS = {
    "safe_compatible",
    "safety_discharged",
    "semantic_assurance",
    "verdict",
    "graduation",
}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{7,40}$")

# ---------------------------------------------------------------------------
# Refusal codes. Every code has a control in `_controls` or in the loader
# controls, and the test module asserts the set is covered.
# ---------------------------------------------------------------------------

PF_JSON_MALFORMED = "PF_JSON_MALFORMED"
PF_JSON_DUPLICATE_KEY = "PF_JSON_DUPLICATE_KEY"
PF_JSON_NON_FINITE = "PF_JSON_NON_FINITE"
PF_SCHEMA = "PF_SCHEMA"
PF_CLASSIFICATION_UNKNOWN = "PF_CLASSIFICATION_UNKNOWN"
PF_PRODUCER_ABSENT = "PF_PRODUCER_ABSENT"
PF_PRODUCER_LIMITS_ABSENT = "PF_PRODUCER_LIMITS_ABSENT"
PF_PRODUCER_UNBOUND = "PF_PRODUCER_UNBOUND"
PF_CANDIDATE_IDENTITY_ABSENT = "PF_CANDIDATE_IDENTITY_ABSENT"
PF_CANDIDATE_IDENTITY_MULTIPLE = "PF_CANDIDATE_IDENTITY_MULTIPLE"
PF_INSTRUMENT_IDENTITY_ABSENT = "PF_INSTRUMENT_IDENTITY_ABSENT"
PF_INSTRUMENT_SAMPLES_ABSENT = "PF_INSTRUMENT_SAMPLES_ABSENT"
PF_ABSENCE_UNRECORDED = "PF_ABSENCE_UNRECORDED"
PF_POPULATION_ABSENT = "PF_POPULATION_ABSENT"
PF_POPULATION_INCOMPLETE = "PF_POPULATION_INCOMPLETE"
PF_POPULATION_DECLARATION_MISMATCH = "PF_POPULATION_DECLARATION_MISMATCH"
PF_SCOPE_ABSENT = "PF_SCOPE_ABSENT"
PF_THREAT_MODEL_ABSENT = "PF_THREAT_MODEL_ABSENT"
PF_OBLIGATIONS_ABSENT = "PF_OBLIGATIONS_ABSENT"
PF_TIMING_OBLIGATION_DISCHARGED_BY_PERFORMANCE = (
    "PF_TIMING_OBLIGATION_DISCHARGED_BY_PERFORMANCE"
)
PF_VENUE_ABSENT = "PF_VENUE_ABSENT"
PF_VENUE_EVIDENCE_CONTRADICTS = "PF_VENUE_EVIDENCE_CONTRADICTS"
PF_VENUE_CLASS_INSUFFICIENT = "PF_VENUE_CLASS_INSUFFICIENT"
PF_BARE_METAL_CONTROLS_ABSENT = "PF_BARE_METAL_CONTROLS_ABSENT"
PF_AUTHORITY_ABSENT = "PF_AUTHORITY_ABSENT"
PF_COMPARATOR_POPULATION_ABSENT = "PF_COMPARATOR_POPULATION_ABSENT"
PF_COMPARATOR_IDENTITY_ABSENT = "PF_COMPARATOR_IDENTITY_ABSENT"
PF_COMPARATOR_NOT_QUALIFIED = "PF_COMPARATOR_NOT_QUALIFIED"
PF_PREREGISTRATION_ABSENT = "PF_PREREGISTRATION_ABSENT"
PF_STATISTICAL_SUPPORT_ABSENT = "PF_STATISTICAL_SUPPORT_ABSENT"
PF_INDEPENDENCE_SELF_ASSERTED = "PF_INDEPENDENCE_SELF_ASSERTED"
PF_INDEPENDENT_RECEIPT_ABSENT = "PF_INDEPENDENT_RECEIPT_ABSENT"
PF_REFERENCE_ABSENT = "PF_REFERENCE_ABSENT"
PF_REFERENCE_DIGEST_MISMATCH = "PF_REFERENCE_DIGEST_MISMATCH"
PF_REFERENCE_UNRESOLVED = "PF_REFERENCE_UNRESOLVED"
PF_CLASSIFICATION_CONFLATES_ASSURANCE = "PF_CLASSIFICATION_CONFLATES_ASSURANCE"
PF_DUPLICATE_RECORD_ID = "PF_DUPLICATE_RECORD_ID"

CODES = (
    PF_JSON_MALFORMED,
    PF_JSON_DUPLICATE_KEY,
    PF_JSON_NON_FINITE,
    PF_SCHEMA,
    PF_CLASSIFICATION_UNKNOWN,
    PF_PRODUCER_ABSENT,
    PF_PRODUCER_LIMITS_ABSENT,
    PF_PRODUCER_UNBOUND,
    PF_CANDIDATE_IDENTITY_ABSENT,
    PF_CANDIDATE_IDENTITY_MULTIPLE,
    PF_INSTRUMENT_IDENTITY_ABSENT,
    PF_INSTRUMENT_SAMPLES_ABSENT,
    PF_ABSENCE_UNRECORDED,
    PF_POPULATION_ABSENT,
    PF_POPULATION_INCOMPLETE,
    PF_POPULATION_DECLARATION_MISMATCH,
    PF_SCOPE_ABSENT,
    PF_THREAT_MODEL_ABSENT,
    PF_OBLIGATIONS_ABSENT,
    PF_TIMING_OBLIGATION_DISCHARGED_BY_PERFORMANCE,
    PF_VENUE_ABSENT,
    PF_VENUE_EVIDENCE_CONTRADICTS,
    PF_VENUE_CLASS_INSUFFICIENT,
    PF_BARE_METAL_CONTROLS_ABSENT,
    PF_AUTHORITY_ABSENT,
    PF_COMPARATOR_POPULATION_ABSENT,
    PF_COMPARATOR_IDENTITY_ABSENT,
    PF_COMPARATOR_NOT_QUALIFIED,
    PF_PREREGISTRATION_ABSENT,
    PF_STATISTICAL_SUPPORT_ABSENT,
    PF_INDEPENDENCE_SELF_ASSERTED,
    PF_INDEPENDENT_RECEIPT_ABSENT,
    PF_REFERENCE_ABSENT,
    PF_REFERENCE_DIGEST_MISMATCH,
    PF_REFERENCE_UNRESOLVED,
    PF_CLASSIFICATION_CONFLATES_ASSURANCE,
    PF_DUPLICATE_RECORD_ID,
)

RULES: dict[str, str] = {
    PF_JSON_MALFORMED: "the record is not parseable JSON",
    PF_JSON_DUPLICATE_KEY: "the record repeats an object key",
    PF_JSON_NON_FINITE: "the record carries NaN or Infinity",
    PF_SCHEMA: "the record is not an object of the declared schema, or names no id",
    PF_CLASSIFICATION_UNKNOWN: "the classification is not one of the seven §10 values",
    PF_PRODUCER_ABSENT: "the record names no producer",
    PF_PRODUCER_LIMITS_ABSENT: "the producer states no limit on what the record establishes",
    PF_PRODUCER_UNBOUND: "the producer digest does not match the named tool",
    PF_CANDIDATE_IDENTITY_ABSENT: "no candidate commit, artefact digest or build identity",
    PF_CANDIDATE_IDENTITY_MULTIPLE: "several candidates without a stated relationship",
    PF_INSTRUMENT_IDENTITY_ABSENT: "no instrument identity, measure, unit or procedure",
    PF_INSTRUMENT_SAMPLES_ABSENT: "no sample location, repetition count or statistic",
    PF_ABSENCE_UNRECORDED: "an artefact or sample is declared absent with no obligation",
    PF_POPULATION_ABSENT: "no frozen population and no realised identifier set",
    PF_POPULATION_INCOMPLETE: "a realised population misses, repeats or adds an identifier",
    PF_POPULATION_DECLARATION_MISMATCH: "a declared population list disagrees with the derived one",
    PF_SCOPE_ABSENT: "no level, workload set, security profile or explicit exclusion list",
    PF_THREAT_MODEL_ABSENT: "no secret classification, statement or observation model",
    PF_OBLIGATIONS_ABSENT: "no obligation set, or an empty one with no reason stated",
    PF_TIMING_OBLIGATION_DISCHARGED_BY_PERFORMANCE: (
        "the record uses performance evidence to discharge a timing obligation"
    ),
    PF_VENUE_ABSENT: "no venue class, control record or PMU statement",
    PF_VENUE_EVIDENCE_CONTRADICTS: "the venue class contradicts the campaign's PMU record",
    PF_VENUE_CLASS_INSUFFICIENT: "the classification exceeds what the venue class supports",
    PF_BARE_METAL_CONTROLS_ABSENT: (
        "a bare-metal or frontier claim omits a required control on some platform"
    ),
    PF_AUTHORITY_ABSENT: "no compatibility authority identity",
    PF_COMPARATOR_POPULATION_ABSENT: "no comparator, or no measured comparator",
    PF_COMPARATOR_IDENTITY_ABSENT: "a measured comparator names no identity",
    PF_COMPARATOR_NOT_QUALIFIED: "a frontier claim includes an unmeasured comparator",
    PF_PREREGISTRATION_ABSENT: "a relative classification has no preregistered criterion",
    PF_STATISTICAL_SUPPORT_ABSENT: "an advantage claim has no margin-excluding interval",
    PF_INDEPENDENCE_SELF_ASSERTED: "an independent reproduction names its own author",
    PF_INDEPENDENT_RECEIPT_ABSENT: "an independently reproduced claim names no external receipt",
    PF_REFERENCE_ABSENT: "a cited reference path does not exist",
    PF_REFERENCE_DIGEST_MISMATCH: "a cited reference's bytes differ from its recorded digest",
    PF_REFERENCE_UNRESOLVED: "a reference has no path or no digest",
    PF_CLASSIFICATION_CONFLATES_ASSURANCE: (
        "the record also carries a safety, graduation or compatibility verdict"
    ),
    PF_DUPLICATE_RECORD_ID: "two records share a record id",
}

CLASSIFICATION_REQUIREMENTS: dict[str, str] = {
    "SCOPED_OBSERVATION": (
        "a complete binding at any venue; never a frontier, lead or competitive claim"
    ),
    "MEASURED": "a reproducible benchmark with retained samples and >= 1 measured comparator",
    "COMPETITIVE": "MEASURED plus a preregistered competitiveness margin",
    "PARITY_ESTABLISHED": "MEASURED plus a preregistered equivalence or noninferiority criterion",
    "AHEAD": (
        "COMPETITIVE prerequisites plus a preregistered practical margin and a "
        "confidence interval that excludes it, on a controlled bare-metal venue"
    ),
    "FRONTIER_LEADING": (
        "AHEAD prerequisites, every qualified comparator measured in the frozen "
        "population, and bare-metal controls on every platform claimed"
    ),
    "INDEPENDENTLY_REPRODUCED_FRONTIER": (
        "FRONTIER_LEADING prerequisites plus an external receipt from a distinct "
        "party at the same candidate digest"
    ),
}


class Refusal(Exception):
    """A named, deterministic loading refusal."""

    def __init__(self, code: str, pointer: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.pointer = pointer
        self.detail = detail


@dataclass(frozen=True)
class Problem:
    code: str
    pointer: str
    detail: str

    def sort_key(self) -> tuple[str, str, str]:
        return (self.pointer, self.code, self.detail)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def canonical(document: Any) -> str:
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def dump(document: Any) -> str:
    return json.dumps(document, sort_keys=True, indent=2, ensure_ascii=False) + "\n"


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    seen: dict[str, Any] = {}
    for key, value in pairs:
        if key in seen:
            raise Refusal(PF_JSON_DUPLICATE_KEY, "", f"duplicate object key {key!r}")
        seen[key] = value
    return seen


def _reject_constant(name: str) -> Any:
    raise Refusal(PF_JSON_NON_FINITE, "", f"non-finite number {name!r}")


def loads_document(text: str) -> Any:
    try:
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except json.JSONDecodeError as exc:
        raise Refusal(PF_JSON_MALFORMED, "", f"not parseable JSON: {exc}") from exc


def load_document(path: Path) -> Any:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise Refusal(PF_JSON_MALFORMED, "", f"{path}: {exc}") from exc
    return loads_document(text)


# ---------------------------------------------------------------------------
# Small predicates
# ---------------------------------------------------------------------------


def _text(value: Any) -> bool:
    return isinstance(value, str) and value.strip() != ""


def _bool(value: Any) -> bool:
    return isinstance(value, bool)


def _sha(value: Any) -> bool:
    return isinstance(value, str) and SHA256_RE.match(value) is not None


def _commit(value: Any) -> bool:
    return isinstance(value, str) and COMMIT_RE.match(value) is not None


def _string_list(value: Any) -> bool:
    return isinstance(value, list) and all(_text(item) for item in value)


def _unique(items: Iterable[str]) -> bool:
    values = list(items)
    return len(values) == len(set(values))


def _add(problems: list[Problem], code: str, pointer: str, detail: str) -> None:
    problems.append(Problem(code, pointer, detail))


def _scan_forbidden(node: Any, pointer: str, problems: list[Problem]) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            here = f"{pointer}/{key}"
            if key in FORBIDDEN_KEYS:
                _add(
                    problems,
                    PF_CLASSIFICATION_CONFLATES_ASSURANCE,
                    here,
                    f"key {key!r} asserts a safety or compatibility conclusion",
                )
            _scan_forbidden(value, here, problems)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            _scan_forbidden(value, f"{pointer}/{index}", problems)


# ---------------------------------------------------------------------------
# References
# ---------------------------------------------------------------------------


def check_reference(
    reference: Any,
    pointer: str,
    problems: list[Problem],
    repo_root: Path,
) -> None:
    if not isinstance(reference, dict):
        _add(problems, PF_REFERENCE_UNRESOLVED, pointer, "reference is not an object")
        return
    path = reference.get("path")
    digest = reference.get("sha256")
    present = reference.get("present", True)
    if not _text(path) or not _sha(digest):
        _add(
            problems,
            PF_REFERENCE_UNRESOLVED,
            pointer,
            "reference needs a path and a full SHA-256 digest",
        )
        return
    if not _bool(present):
        _add(problems, PF_REFERENCE_UNRESOLVED, pointer, "'present' is not a boolean")
        return
    if not present:
        return
    target = repo_root / path
    if not target.is_file():
        _add(problems, PF_REFERENCE_ABSENT, pointer, f"{path} does not exist")
        return
    actual = sha256_file(target)
    if actual != digest:
        _add(
            problems,
            PF_REFERENCE_DIGEST_MISMATCH,
            pointer,
            f"{path}: recorded {digest}, actual {actual}",
        )


# ---------------------------------------------------------------------------
# Axis checks
# ---------------------------------------------------------------------------


def _check_producer(record: dict, problems: list[Problem], repo_root: Path) -> None:
    pointer = "/producer"
    producer = record.get("producer")
    if not isinstance(producer, dict):
        _add(problems, PF_PRODUCER_ABSENT, pointer, "producer must be an object")
        return
    for key in ("name", "version", "tool_path"):
        if not _text(producer.get(key)):
            _add(problems, PF_PRODUCER_ABSENT, f"{pointer}/{key}", "missing or empty")
    limits = producer.get("limits")
    if not _string_list(limits) or not limits:
        _add(
            problems,
            PF_PRODUCER_LIMITS_ABSENT,
            f"{pointer}/limits",
            "limits must be a non-empty array of statements",
        )
    tool_path = producer.get("tool_path")
    tool_digest = producer.get("tool_sha256")
    if not _text(tool_path) or not _sha(tool_digest):
        _add(problems, PF_PRODUCER_UNBOUND, pointer, "tool_path and tool_sha256 are required")
    else:
        target = repo_root / tool_path
        if not target.is_file():
            _add(problems, PF_PRODUCER_UNBOUND, f"{pointer}/tool_path", f"{tool_path} missing")
        elif sha256_file(target) != tool_digest:
            _add(
                problems,
                PF_PRODUCER_UNBOUND,
                f"{pointer}/tool_sha256",
                f"recorded {tool_digest}, actual {sha256_file(target)}",
            )
        if target.resolve() != TOOL_PATH and repo_root.resolve() == REPO_ROOT:
            _add(
                problems,
                PF_PRODUCER_UNBOUND,
                f"{pointer}/tool_path",
                "the producer must be this validator",
            )
    inputs = producer.get("inputs")
    if not isinstance(inputs, list) or not inputs:
        _add(problems, PF_PRODUCER_UNBOUND, f"{pointer}/inputs", "no bound inputs")
    else:
        for index, reference in enumerate(inputs):
            check_reference(reference, f"{pointer}/inputs/{index}", problems, repo_root)


def _check_candidate(
    record: dict,
    problems: list[Problem],
    repo_root: Path,
) -> None:
    pointer = "/candidate"
    candidate = record.get("candidate")
    if not isinstance(candidate, dict):
        _add(problems, PF_CANDIDATE_IDENTITY_ABSENT, pointer, "candidate must be an object")
        return
    entries: list[tuple[str, Any]] = [(pointer, candidate)]
    additional = candidate.get("additional_candidates")
    if additional is not None:
        if not isinstance(additional, list) or not additional:
            _add(
                problems,
                PF_CANDIDATE_IDENTITY_MULTIPLE,
                f"{pointer}/additional_candidates",
                "must be a non-empty array",
            )
        else:
            if not _text(candidate.get("candidate_relationship")):
                _add(
                    problems,
                    PF_CANDIDATE_IDENTITY_MULTIPLE,
                    f"{pointer}/candidate_relationship",
                    "several candidates need a stated relationship",
                )
            entries.extend(
                (f"{pointer}/additional_candidates/{index}", item)
                for index, item in enumerate(additional)
            )
    for where, entry in entries:
        if not isinstance(entry, dict):
            _add(problems, PF_CANDIDATE_IDENTITY_ABSENT, where, "candidate entry is not an object")
            continue
        if not _commit(entry.get("source_commit")):
            _add(
                problems,
                PF_CANDIDATE_IDENTITY_ABSENT,
                f"{where}/source_commit",
                "missing or not a commit id",
            )
        artefact = entry.get("artefact")
        if not isinstance(artefact, dict):
            _add(
                problems,
                PF_CANDIDATE_IDENTITY_ABSENT,
                f"{where}/artefact",
                "artefact must be an object",
            )
        else:
            for key in ("label", "sha256"):
                if not _text(artefact.get(key)) or (key == "sha256" and not _sha(artefact.get(key))):
                    _add(
                        problems,
                        PF_CANDIDATE_IDENTITY_ABSENT,
                        f"{where}/artefact/{key}",
                        "missing or not a full SHA-256",
                    )
            present = artefact.get("present_in_repository")
            if not _bool(present):
                _add(
                    problems,
                    PF_CANDIDATE_IDENTITY_ABSENT,
                    f"{where}/artefact/present_in_repository",
                    "must state whether the bytes are in the repository",
                )
            elif present:
                check_reference(
                    {
                        "path": artefact.get("path"),
                        "sha256": artefact.get("sha256"),
                        "present": True,
                    },
                    f"{where}/artefact",
                    problems,
                    repo_root,
                )
            elif not _text(artefact.get("obligation")):
                _add(
                    problems,
                    PF_ABSENCE_UNRECORDED,
                    f"{where}/artefact/obligation",
                    "an absent artefact needs an obligation",
                )
        build = entry.get("build")
        if not isinstance(build, dict) or not _text(build.get("profile")) or not _text(
            build.get("target")
        ):
            _add(
                problems,
                PF_CANDIDATE_IDENTITY_ABSENT,
                f"{where}/build",
                "build needs a profile and a target",
            )


def _check_instrument(record: dict, problems: list[Problem], repo_root: Path) -> None:
    pointer = "/instrument"
    instrument = record.get("instrument")
    if not isinstance(instrument, dict):
        _add(problems, PF_INSTRUMENT_IDENTITY_ABSENT, pointer, "instrument must be an object")
        return
    if not _text(instrument.get("name")):
        _add(problems, PF_INSTRUMENT_IDENTITY_ABSENT, f"{pointer}/name", "missing or empty")
    identity = instrument.get("identity")
    if (
        not isinstance(identity, dict)
        or not identity
        or not any(_text(value) or _sha(value) for value in identity.values())
    ):
        _add(
            problems,
            PF_INSTRUMENT_IDENTITY_ABSENT,
            f"{pointer}/identity",
            "instrument identity is empty",
        )
    if not _string_list(instrument.get("measures")) or not instrument["measures"]:
        _add(
            problems,
            PF_INSTRUMENT_IDENTITY_ABSENT,
            f"{pointer}/measures",
            "measures must be a non-empty array",
        )
    for key in ("unit", "procedure"):
        if not _text(instrument.get(key)):
            _add(problems, PF_INSTRUMENT_IDENTITY_ABSENT, f"{pointer}/{key}", "missing or empty")
    samples = instrument.get("samples")
    if not isinstance(samples, dict):
        _add(problems, PF_INSTRUMENT_SAMPLES_ABSENT, f"{pointer}/samples", "not an object")
    else:
        for key in ("location", "unit_of_replication", "statistic"):
            if not _text(samples.get(key)):
                _add(
                    problems,
                    PF_INSTRUMENT_SAMPLES_ABSENT,
                    f"{pointer}/samples/{key}",
                    "missing or empty",
                )
        repetitions = samples.get("repetitions")
        if not isinstance(repetitions, int) or isinstance(repetitions, bool) or repetitions < 1:
            _add(
                problems,
                PF_INSTRUMENT_SAMPLES_ABSENT,
                f"{pointer}/samples/repetitions",
                "must be an integer >= 1",
            )
        present = samples.get("present_in_repository")
        if not _bool(present):
            _add(
                problems,
                PF_INSTRUMENT_SAMPLES_ABSENT,
                f"{pointer}/samples/present_in_repository",
                "must state whether the samples are in the repository",
            )
        elif present:
            check_reference(
                {
                    "path": samples.get("path"),
                    "sha256": samples.get("sha256"),
                    "present": True,
                },
                f"{pointer}/samples",
                problems,
                repo_root,
            )
        elif not _text(samples.get("obligation")):
            _add(
                problems,
                PF_ABSENCE_UNRECORDED,
                f"{pointer}/samples/obligation",
                "absent samples need an obligation",
            )
    reference = instrument.get("preregistration")
    if not isinstance(reference, dict):
        _add(
            problems,
            PF_PREREGISTRATION_ABSENT,
            f"{pointer}/preregistration",
            "preregistration reference is required",
        )
    else:
        check_reference(reference, f"{pointer}/preregistration", problems, repo_root)
        if reference.get("present") is not True:
            _add(
                problems,
                PF_PREREGISTRATION_ABSENT,
                f"{pointer}/preregistration/present",
                "a preregistration cited as absent is not a preregistration",
            )


def _check_population(record: dict, problems: list[Problem]) -> list[str]:
    pointer = "/population"
    population = record.get("population")
    if not isinstance(population, dict):
        _add(problems, PF_POPULATION_ABSENT, pointer, "population must be an object")
        return []
    expected = population.get("expected")
    realised = population.get("realised")
    if not _text(population.get("frozen_at")) or not _text(population.get("completeness_rule")):
        _add(
            problems,
            PF_POPULATION_ABSENT,
            pointer,
            "frozen_at and completeness_rule are required",
        )
    if not _string_list(expected) or not expected:
        _add(
            problems,
            PF_POPULATION_ABSENT,
            f"{pointer}/expected",
            "expected identifiers must be a non-empty array",
        )
        expected = []
    if not _string_list(realised) or not realised:
        _add(
            problems,
            PF_POPULATION_ABSENT,
            f"{pointer}/realised",
            "realised identifiers must be a non-empty array",
        )
        realised = []
    if not _unique(expected):
        _add(
            problems,
            PF_POPULATION_INCOMPLETE,
            f"{pointer}/expected",
            "the expected identifiers are not unique",
        )
    derived = {
        "missing": sorted(set(expected) - set(realised)),
        "duplicate": sorted({item for item in realised if realised.count(item) > 1}),
        "undeclared": sorted(set(realised) - set(expected)),
    }
    for key, values in derived.items():
        declared = population.get(key)
        if declared != values:
            _add(
                problems,
                PF_POPULATION_DECLARATION_MISMATCH,
                f"{pointer}/{key}",
                f"declared {declared!r}, derived {values!r}",
            )
    if any(derived.values()):
        _add(
            problems,
            PF_POPULATION_INCOMPLETE,
            pointer,
            "the realised population is not the frozen population",
        )
    return list(expected)


def _check_scope(record: dict, problems: list[Problem], expected: list[str]) -> None:
    pointer = "/scope"
    scope = record.get("scope")
    if not isinstance(scope, dict):
        _add(problems, PF_SCOPE_ABSENT, pointer, "scope must be an object")
        return
    if scope.get("level") not in SCOPE_LEVELS:
        _add(problems, PF_SCOPE_ABSENT, f"{pointer}/level", "level must be L1..L5")
    workloads = scope.get("workloads")
    if not _string_list(workloads) or not workloads:
        _add(
            problems,
            PF_SCOPE_ABSENT,
            f"{pointer}/workloads",
            "workloads must be a non-empty array",
        )
    elif expected and not set(workloads) <= set(expected):
        _add(
            problems,
            PF_SCOPE_ABSENT,
            f"{pointer}/workloads",
            "a workload is outside the frozen population",
        )
    if not _text(scope.get("security_profile")):
        _add(
            problems,
            PF_SCOPE_ABSENT,
            f"{pointer}/security_profile",
            "missing or empty",
        )
    if not isinstance(scope.get("exclusions"), list):
        _add(
            problems,
            PF_SCOPE_ABSENT,
            f"{pointer}/exclusions",
            "exclusions must be an explicit array, even when empty",
        )


def _check_threat_model(record: dict, problems: list[Problem]) -> None:
    pointer = "/threat_model"
    threat = record.get("threat_model")
    if not isinstance(threat, dict):
        _add(problems, PF_THREAT_MODEL_ABSENT, pointer, "threat_model must be an object")
        return
    classes = threat.get("secret_classification")
    if not _string_list(classes) or not classes:
        _add(
            problems,
            PF_THREAT_MODEL_ABSENT,
            f"{pointer}/secret_classification",
            "must be a non-empty array",
        )
    elif not set(classes) <= SECRET_CLASSES:
        _add(
            problems,
            PF_THREAT_MODEL_ABSENT,
            f"{pointer}/secret_classification",
            "unknown secret class",
        )
    if "tags" in threat and not _string_list(threat.get("tags")):
        _add(
            problems,
            PF_THREAT_MODEL_ABSENT,
            f"{pointer}/tags",
            "tags must be an array of strings when present",
        )
    if not _text(threat.get("statement")):
        _add(problems, PF_THREAT_MODEL_ABSENT, f"{pointer}/statement", "missing or empty")
    if not _bool(threat.get("constant_time_required")):
        _add(
            problems,
            PF_THREAT_MODEL_ABSENT,
            f"{pointer}/constant_time_required",
            "must be a boolean",
        )
    if not _text(threat.get("observation_model")):
        _add(
            problems,
            PF_THREAT_MODEL_ABSENT,
            f"{pointer}/observation_model",
            "missing or empty",
        )


def _check_venue(record: dict, problems: list[Problem]) -> None:
    pointer = "/venue"
    venue = record.get("venue")
    campaign = record.get("campaign")
    if not isinstance(venue, dict):
        _add(problems, PF_VENUE_ABSENT, pointer, "venue must be an object")
        return
    if venue.get("class") not in VENUE_CLASSES:
        _add(problems, PF_VENUE_ABSENT, f"{pointer}/class", "unknown or absent venue class")
    if not _text(venue.get("description")):
        _add(problems, PF_VENUE_ABSENT, f"{pointer}/description", "missing or empty")
    exposed = venue.get("pmu_exposed")
    if not _bool(exposed):
        _add(problems, PF_VENUE_ABSENT, f"{pointer}/pmu_exposed", "must be a boolean")
    controls = venue.get("controls")
    if not isinstance(controls, dict):
        _add(problems, PF_VENUE_ABSENT, f"{pointer}/controls", "must be an object")
        controls = {}
    for key in CONTROL_KEYS:
        if not _bool(controls.get(key)):
            _add(
                problems,
                PF_VENUE_ABSENT,
                f"{pointer}/controls/{key}",
                "must be a boolean",
            )
    if isinstance(campaign, dict) and campaign.get("venue_has_pmu") is True and exposed is False:
        _add(
            problems,
            PF_VENUE_EVIDENCE_CONTRADICTS,
            f"{pointer}/pmu_exposed",
            "the campaign records a PMU but the venue declares none",
        )


def _bare_metal_problems(
    venue: Any, pointer: str, problems: list[Problem]
) -> None:
    if not isinstance(venue, dict):
        _add(problems, PF_BARE_METAL_CONTROLS_ABSENT, pointer, "platform record is not an object")
        return
    if venue.get("class") != "BARE_METAL_PMU":
        _add(
            problems,
            PF_VENUE_CLASS_INSUFFICIENT,
            f"{pointer}/class",
            "a frontier claim needs bare metal on every platform",
        )
    controls = venue.get("controls")
    if not isinstance(controls, dict) or not all(controls.get(key) is True for key in CONTROL_KEYS):
        _add(
            problems,
            PF_BARE_METAL_CONTROLS_ABSENT,
            f"{pointer}/controls",
            "pinned frequency, turbo off, SMT off and core isolation are all required",
        )
    for key in ("microcode", "kernel"):
        if not _text(venue.get(key)):
            _add(problems, PF_BARE_METAL_CONTROLS_ABSENT, f"{pointer}/{key}", "missing or empty")
    if not _string_list(venue.get("pmu_events")) or not venue["pmu_events"]:
        _add(
            problems,
            PF_BARE_METAL_CONTROLS_ABSENT,
            f"{pointer}/pmu_events",
            "the hardware events must be listed",
        )
    if venue.get("pmu_exposed") is not True:
        _add(
            problems,
            PF_BARE_METAL_CONTROLS_ABSENT,
            f"{pointer}/pmu_exposed",
            "a bare-metal venue must expose its PMU",
        )


def _check_authority(record: dict, problems: list[Problem]) -> None:
    pointer = "/authority"
    authority = record.get("authority")
    if not isinstance(authority, dict):
        _add(problems, PF_AUTHORITY_ABSENT, pointer, "authority must be an object")
        return
    for key in ("id", "version"):
        if not _text(authority.get(key)):
            _add(problems, PF_AUTHORITY_ABSENT, f"{pointer}/{key}", "missing or empty")
    if not _sha(authority.get("sha256")) and not _text(authority.get("build_id")):
        _add(
            problems,
            PF_AUTHORITY_ABSENT,
            pointer,
            "the authority needs an artefact digest or a build id",
        )


def _check_comparators(record: dict, problems: list[Problem]) -> list[dict]:
    pointer = "/comparators"
    comparators = record.get("comparators")
    if not isinstance(comparators, list) or not comparators:
        _add(
            problems,
            PF_COMPARATOR_POPULATION_ABSENT,
            pointer,
            "comparators must be a non-empty array",
        )
        return []
    entries: list[dict] = []
    identifiers: list[str] = []
    for index, comparator in enumerate(comparators):
        where = f"{pointer}/{index}"
        if not isinstance(comparator, dict):
            _add(problems, PF_COMPARATOR_POPULATION_ABSENT, where, "not an object")
            continue
        ident = comparator.get("id")
        if not _text(ident):
            _add(problems, PF_COMPARATOR_POPULATION_ABSENT, f"{where}/id", "missing")
        else:
            identifiers.append(ident)
        status = comparator.get("status")
        if status not in COMPARATOR_STATUSES:
            _add(
                problems,
                PF_COMPARATOR_POPULATION_ABSENT,
                f"{where}/status",
                "unknown comparator status",
            )
            continue
        if status == "MEASURED" and not _text(comparator.get("identity")):
            _add(
                problems,
                PF_COMPARATOR_IDENTITY_ABSENT,
                f"{where}/identity",
                "a measured comparator needs an identity",
            )
        if status != "MEASURED" and not _text(comparator.get("reason")):
            _add(
                problems,
                PF_COMPARATOR_POPULATION_ABSENT,
                f"{where}/reason",
                "an unmeasured comparator needs a reason",
            )
        entries.append(comparator)
    if not _unique(identifiers):
        _add(
            problems,
            PF_COMPARATOR_POPULATION_ABSENT,
            pointer,
            "comparator ids are not unique",
        )
    if not any(entry.get("status") == "MEASURED" for entry in entries):
        _add(
            problems,
            PF_COMPARATOR_POPULATION_ABSENT,
            pointer,
            "no comparator was measured",
        )
    return entries


def _check_obligations(record: dict, problems: list[Problem]) -> None:
    pointer = "/obligations"
    obligations = record.get("obligations")
    if not isinstance(obligations, dict):
        _add(problems, PF_OBLIGATIONS_ABSENT, pointer, "obligations must be an object")
        return
    open_items = obligations.get("open")
    if not isinstance(open_items, list):
        _add(problems, PF_OBLIGATIONS_ABSENT, f"{pointer}/open", "must be an array")
        open_items = []
    identifiers: list[str] = []
    for index, item in enumerate(open_items):
        where = f"{pointer}/open/{index}"
        if not isinstance(item, dict) or not _text(item.get("id")) or not _text(
            item.get("description")
        ):
            _add(
                problems,
                PF_OBLIGATIONS_ABSENT,
                where,
                "an open obligation needs an id and a description",
            )
            continue
        identifiers.append(item["id"])
        if item.get("discharged") is not False or item.get("status") == "DISCHARGED":
            _add(
                problems,
                PF_TIMING_OBLIGATION_DISCHARGED_BY_PERFORMANCE,
                where,
                "a performance record may not discharge an obligation",
            )
    if not _unique(identifiers):
        _add(
            problems,
            PF_OBLIGATIONS_ABSENT,
            f"{pointer}/open",
            "open obligation ids are not unique",
        )
    if not open_items and not _text(obligations.get("none_open_because")):
        _add(
            problems,
            PF_OBLIGATIONS_ABSENT,
            f"{pointer}/none_open_because",
            "an empty set must say why nothing is open",
        )
    attempted = obligations.get("attempted_discharge")
    if not isinstance(attempted, list):
        _add(
            problems,
            PF_OBLIGATIONS_ABSENT,
            f"{pointer}/attempted_discharge",
            "must be an explicit array, even when empty",
        )
    elif attempted:
        _add(
            problems,
            PF_TIMING_OBLIGATION_DISCHARGED_BY_PERFORMANCE,
            f"{pointer}/attempted_discharge",
            f"performance evidence cannot discharge {attempted!r}",
        )


def _check_classification_laws(
    record: dict,
    problems: list[Problem],
    comparator_entries: list[dict],
    repo_root: Path,
) -> None:
    classification = record.get("classification")
    if classification not in CLASSIFICATIONS:
        _add(
            problems,
            PF_CLASSIFICATION_UNKNOWN,
            "/classification",
            f"{classification!r} is not a §10 classification",
        )
        return
    venue = record.get("venue") if isinstance(record.get("venue"), dict) else {}
    venue_class = venue.get("class")
    if classification == "SCOPED_OBSERVATION":
        return
    # MEASURED and everything above it rest on the instrument checks.
    if classification in {
        "COMPETITIVE",
        "PARITY_ESTABLISHED",
        "AHEAD",
        "FRONTIER_LEADING",
        "INDEPENDENTLY_REPRODUCED_FRONTIER",
    }:
        margin = record.get("preregistered_margin")
        if not isinstance(margin, dict):
            _add(
                problems,
                PF_PREREGISTRATION_ABSENT,
                "/preregistered_margin",
                "a relative classification needs a preregistered criterion",
            )
        else:
            for key in ("criterion", "unit"):
                if not _text(margin.get(key)):
                    _add(
                        problems,
                        PF_PREREGISTRATION_ABSENT,
                        f"/preregistered_margin/{key}",
                        "missing or empty",
                    )
            value = margin.get("value")
            if not isinstance(value, (int, float)) or isinstance(value, bool) or value <= 0:
                _add(
                    problems,
                    PF_PREREGISTRATION_ABSENT,
                    "/preregistered_margin/value",
                    "must be a positive number",
                )
            check_reference(
                margin.get("record"),
                "/preregistered_margin/record",
                problems,
                repo_root,
            )
    if classification == "PARITY_ESTABLISHED":
        equivalence = record.get("preregistered_equivalence")
        if not isinstance(equivalence, dict) or not _text(equivalence.get("criterion")):
            _add(
                problems,
                PF_PREREGISTRATION_ABSENT,
                "/preregistered_equivalence",
                "parity needs a preregistered equivalence criterion",
            )
    if classification in {"AHEAD", "FRONTIER_LEADING", "INDEPENDENTLY_REPRODUCED_FRONTIER"}:
        support = record.get("statistical_support")
        if (
            not isinstance(support, dict)
            or not _text(support.get("method"))
            or not isinstance(support.get("confidence_level"), (int, float))
            or isinstance(support.get("confidence_level"), bool)
            or not isinstance(support.get("interval"), list)
            or len(support.get("interval")) != 2
        ):
            _add(
                problems,
                PF_STATISTICAL_SUPPORT_ABSENT,
                "/statistical_support",
                "an advantage needs a method, a confidence level and an interval",
            )
        elif support.get("excludes_margin") is not True:
            _add(
                problems,
                PF_STATISTICAL_SUPPORT_ABSENT,
                "/statistical_support/excludes_margin",
                "the interval must be stated to exclude the preregistered margin",
            )
    if classification in CONTROLLED_ONLY_CLASSES and venue_class != "BARE_METAL_PMU":
        _add(
            problems,
            PF_VENUE_CLASS_INSUFFICIENT,
            "/venue/class",
            f"{classification} needs a controlled bare-metal venue",
        )
    if classification in FRONTIER_CLASSES:
        bare = venue
        _bare_metal_problems(bare, "/venue", problems)
        platforms = venue.get("platforms")
        if not isinstance(platforms, list) or not platforms:
            _add(
                problems,
                PF_BARE_METAL_CONTROLS_ABSENT,
                "/venue/platforms",
                "every platform the claim covers needs its own record",
            )
        else:
            for index, platform in enumerate(platforms):
                _bare_metal_problems(platform, f"/venue/platforms/{index}", problems)
        population = record.get("qualified_population")
        if not isinstance(population, dict) or population.get("frozen") is not True:
            _add(
                problems,
                PF_COMPARATOR_POPULATION_ABSENT,
                "/qualified_population",
                "a frontier claim needs a frozen qualified population",
            )
        else:
            identifiers = population.get("identifiers")
            measured = {
                entry.get("id")
                for entry in comparator_entries
                if entry.get("status") == "MEASURED"
            }
            if not _string_list(identifiers) or not identifiers:
                _add(
                    problems,
                    PF_COMPARATOR_POPULATION_ABSENT,
                    "/qualified_population/identifiers",
                    "must be a non-empty array",
                )
            elif set(identifiers) != measured:
                _add(
                    problems,
                    PF_COMPARATOR_NOT_QUALIFIED,
                    "/qualified_population",
                    "the frozen population and the measured comparators disagree",
                )
            for index, entry in enumerate(comparator_entries):
                if entry.get("status") != "MEASURED":
                    _add(
                        problems,
                        PF_COMPARATOR_NOT_QUALIFIED,
                        f"/comparators/{index}/status",
                        "a frontier claim may not include an unmeasured comparator",
                    )
    if classification == "INDEPENDENTLY_REPRODUCED_FRONTIER":
        reproduction = record.get("independent_reproduction")
        if not isinstance(reproduction, dict):
            _add(
                problems,
                PF_INDEPENDENT_RECEIPT_ABSENT,
                "/independent_reproduction",
                "no external reproduction record",
            )
            return
        author = record.get("author") if isinstance(record.get("author"), dict) else {}
        party = reproduction.get("party")
        if not _text(party) or party == author.get("identity"):
            _add(
                problems,
                PF_INDEPENDENCE_SELF_ASSERTED,
                "/independent_reproduction/party",
                "the reproducing party must differ from the record author",
            )
        if not _text(reproduction.get("trust_domain")):
            _add(
                problems,
                PF_INDEPENDENCE_SELF_ASSERTED,
                "/independent_reproduction/trust_domain",
                "a distinct trust domain must be named",
            )
        receipt = reproduction.get("receipt")
        check_reference(receipt, "/independent_reproduction/receipt", problems, repo_root)
        if isinstance(receipt, dict) and receipt.get("present") is not True:
            _add(
                problems,
                PF_INDEPENDENT_RECEIPT_ABSENT,
                "/independent_reproduction/receipt/present",
                "an absent receipt is not an independent reproduction",
            )
        candidate = record.get("candidate")
        artefact = candidate.get("artefact") if isinstance(candidate, dict) else None
        expected_digest = artefact.get("sha256") if isinstance(artefact, dict) else None
        if reproduction.get("candidate_sha256") != expected_digest:
            _add(
                problems,
                PF_REFERENCE_DIGEST_MISMATCH,
                "/independent_reproduction/candidate_sha256",
                "the reproduction is not bound to the candidate digest",
            )


# ---------------------------------------------------------------------------
# Whole-record check
# ---------------------------------------------------------------------------


def check_record(record: Any, repo_root: Path = REPO_ROOT) -> list[Problem]:
    problems: list[Problem] = []
    if not isinstance(record, dict):
        return [Problem(PF_SCHEMA, "", "record is not a JSON object")]
    if record.get("schema") != SCHEMA:
        _add(problems, PF_SCHEMA, "/schema", f"schema is {record.get('schema')!r}")
    for key in ("record_id", "queue_item"):
        if not _text(record.get(key)):
            _add(problems, PF_SCHEMA, f"/{key}", "missing or empty")
    classification = record.get("classification")
    if classification not in CLASSIFICATIONS:
        _add(
            problems,
            PF_CLASSIFICATION_UNKNOWN,
            "/classification",
            f"{classification!r} is not a §10 classification",
        )
    if not isinstance(record.get("author"), dict) or not _text(record["author"].get("identity")):
        _add(problems, PF_SCHEMA, "/author", "the record names no author identity")
    campaign = record.get("campaign")
    if not isinstance(campaign, dict) or not _text(campaign.get("id")):
        _add(problems, PF_SCHEMA, "/campaign", "the record names no campaign")
    else:
        check_reference(campaign.get("results"), "/campaign/results", problems, repo_root)
        if not _bool(campaign.get("venue_has_pmu")):
            _add(
                problems,
                PF_SCHEMA,
                "/campaign/venue_has_pmu",
                "must state whether the campaign exposed a PMU",
            )
    _scan_forbidden(record, "", problems)
    _check_producer(record, problems, repo_root)
    expected = _check_population(record, problems)
    _check_candidate(record, problems, repo_root)
    _check_instrument(record, problems, repo_root)
    _check_scope(record, problems, expected)
    _check_threat_model(record, problems)
    _check_venue(record, problems)
    _check_authority(record, problems)
    comparators = _check_comparators(record, problems)
    _check_obligations(record, problems)
    _check_classification_laws(record, problems, comparators, repo_root)
    unique = {(problem.code, problem.pointer, problem.detail) for problem in problems}
    return sorted((Problem(*item) for item in unique), key=Problem.sort_key)


def check_records(
    records: list[tuple[Path, Any]], repo_root: Path = REPO_ROOT
) -> dict[Path, list[Problem]]:
    """Validate a collection and refuse duplicate record ids."""
    results: dict[Path, list[Problem]] = {}
    seen: dict[str, Path] = {}
    for path, record in records:
        problems = check_record(record, repo_root)
        if isinstance(record, dict):
            ident = record.get("record_id")
            if _text(ident):
                if ident in seen and seen[ident] != path:
                    problems.append(
                        Problem(
                            PF_DUPLICATE_RECORD_ID,
                            "/record_id",
                            f"{ident!r} is also used by {seen[ident]}",
                        )
                    )
                else:
                    seen[ident] = path
        unique = {(problem.code, problem.pointer, problem.detail) for problem in problems}
        results[path] = sorted((Problem(*item) for item in unique), key=Problem.sort_key)
    return results


# ---------------------------------------------------------------------------
# Controls: one positive and one negative per code
# ---------------------------------------------------------------------------


def _methodology() -> dict[str, str]:
    path = "docs/PERFORMANCE-METHODOLOGY.md"
    return {"path": path, "sha256": sha256_file(REPO_ROOT / path), "present": True}


def _results_reference() -> dict[str, Any]:
    path = "evidence/performance-frontier/campaigns/PFP-0/results.json"
    return {"path": path, "sha256": sha256_file(REPO_ROOT / path), "present": True}


def _valid_record(classification: str = "FRONTIER_LEADING") -> dict[str, Any]:
    """A fully-populated synthetic record, used only as a control fixture."""
    frontier = classification in FRONTIER_CLASSES or classification == "AHEAD"
    venue = {
        "class": "BARE_METAL_PMU" if frontier else "VIRTUALISED_COURT",
        "description": "control fixture, not a measurement venue",
        "pmu_exposed": bool(frontier),
        "controls": {
            "frequency_pinned": bool(frontier),
            "turbo_disabled": bool(frontier),
            "smt_disabled": bool(frontier),
            "core_isolation": bool(frontier),
        },
    }
    if frontier:
        venue.update(
            {
                "microcode": "control-fixture-ucode",
                "kernel": "control-fixture-kernel",
                "pmu_events": ["cycles", "instructions"],
                "platforms": [
                    {
                        "id": "fixture-platform",
                        "class": "BARE_METAL_PMU",
                        "pmu_exposed": True,
                        "microcode": "control-fixture-ucode",
                        "kernel": "control-fixture-kernel",
                        "pmu_events": ["cycles"],
                        "controls": {
                            "frequency_pinned": True,
                            "turbo_disabled": True,
                            "smt_disabled": True,
                            "core_isolation": True,
                        },
                    }
                ],
            }
        )
    identifiers = ["workload-a", "workload-b"]
    record: dict[str, Any] = {
        "schema": SCHEMA,
        "record_id": "CONTROL-RECORD",
        "queue_item": "PFP-18",
        "author": {"identity": "control-fixture", "role": "producer"},
        "campaign": {
            "id": "CONTROL",
            "results": _results_reference(),
            "venue_has_pmu": bool(frontier),
        },
        "classification": classification,
        "producer": {
            "name": "performance_classification.py",
            "version": "1",
            "tool_path": "forensics/tools/performance_classification.py",
            "tool_sha256": sha256_file(TOOL_PATH),
            "limits": [
                "the control fixture is synthetic and measures nothing",
                "a passing record is a well-bound claim, not a true measurement",
            ],
            "inputs": [_results_reference()],
        },
        "candidate": {
            "source_commit": "0" * 40,
            "artefact": {
                "label": "control fixture DSO",
                "sha256": "1" * 64,
                "present_in_repository": False,
                "obligation": "the control fixture has no artefact bytes",
            },
            "build": {"profile": "release", "target": "x86_64-unknown-linux-gnu"},
        },
        "authority": {
            "id": "openssl-3.6.4-production",
            "version": "3.6.4",
            "sha256": "6" * 64,
        },
        "comparators": [
            {
                "id": "fixture-comparator",
                "role": "compatibility_authority",
                "status": "MEASURED",
                "identity": "sha256:" + "6" * 64,
            }
        ],
        "instrument": {
            "name": "control fixture instrument",
            "identity": {"analyser_sha256": "2" * 64},
            "measures": ["single-operation latency"],
            "unit": "microseconds per call",
            "procedure": "docs/PERFORMANCE-METHODOLOGY.md",
            "samples": {
                "location": "the control fixture has no samples",
                "present_in_repository": False,
                "obligation": "the control fixture has no sample bytes",
                "repetitions": 15,
                "unit_of_replication": "one process per subject per repetition",
                "statistic": "median of paired ratios",
            },
            "preregistration": _methodology(),
        },
        "population": {
            "frozen_at": "0" * 40,
            "expected": identifiers,
            "realised": identifiers,
            "missing": [],
            "duplicate": [],
            "undeclared": [],
            "completeness_rule": "the realised identifier set equals the frozen set",
        },
        "scope": {
            "level": "L3",
            "workloads": identifiers,
            "security_profile": "control fixture profile",
            "exclusions": ["the control fixture measures nothing"],
        },
        "threat_model": {
            "secret_classification": ["SECRET_DATA"],
            "tags": ["SECRET_DATA", "CONSTANT_TIME_REQUIRED"],
            "statement": "the control fixture asserts the shape of a constant-time contract",
            "constant_time_required": True,
            "observation_model": "control fixture, no observation",
        },
        "venue": venue,
        "obligations": {
            "open": [
                {
                    "id": "T23",
                    "description": "the control fixture does not address T23",
                    "discharged": False,
                },
            ],
            "attempted_discharge": [],
            "none_open_because": None,
        },
    }
    if classification in {
        "COMPETITIVE",
        "PARITY_ESTABLISHED",
        "AHEAD",
        "FRONTIER_LEADING",
        "INDEPENDENTLY_REPRODUCED_FRONTIER",
    }:
        record["preregistered_margin"] = {
            "criterion": "5 percent lower median latency",
            "value": 0.05,
            "unit": "relative median",
            "record": _methodology(),
        }
    if classification == "PARITY_ESTABLISHED":
        record["preregistered_equivalence"] = {
            "criterion": "within 5 percent of the comparator",
            "record": _methodology(),
        }
    if classification in {"AHEAD", "FRONTIER_LEADING", "INDEPENDENTLY_REPRODUCED_FRONTIER"}:
        record["statistical_support"] = {
            "method": "paired-ratio bootstrap interval",
            "confidence_level": 0.95,
            "interval": [0.90, 0.94],
            "excludes_margin": True,
        }
    if classification in FRONTIER_CLASSES:
        record["qualified_population"] = {
            "frozen": True,
            "identifiers": ["fixture-comparator"],
        }
    if classification == "INDEPENDENTLY_REPRODUCED_FRONTIER":
        record["independent_reproduction"] = {
            "party": "external-fixture-party",
            "trust_domain": "external fixture domain",
            "candidate_sha256": record["candidate"]["artefact"]["sha256"],
            "receipt": _methodology(),
        }
    return record


def _controls() -> list[tuple[str, dict, str | None]]:
    base = _valid_record()
    controls: list[tuple[str, dict, str | None]] = []

    def add(name: str, mutate: Callable[[dict], None], code: str | None) -> None:
        record = copy.deepcopy(base)
        mutate(record)
        controls.append((name, record, code))

    controls.append(("positive frontier-leading fixture", copy.deepcopy(base), None))
    controls.append(
        (
            "positive scoped-observation fixture",
            _valid_record("SCOPED_OBSERVATION"),
            None,
        )
    )
    controls.append(
        (
            "positive independently-reproduced fixture",
            _valid_record("INDEPENDENTLY_REPRODUCED_FRONTIER"),
            None,
        )
    )
    add("schema", lambda r: r.update(schema="wrong"), PF_SCHEMA)
    add("classification", lambda r: r.update(classification="WORLD_FASTEST"), PF_CLASSIFICATION_UNKNOWN)
    add("producer", lambda r: r.pop("producer"), PF_PRODUCER_ABSENT)
    add("limits", lambda r: r["producer"].update(limits=[]), PF_PRODUCER_LIMITS_ABSENT)
    add(
        "producer digest",
        lambda r: r["producer"].update(tool_sha256="0" * 64),
        PF_PRODUCER_UNBOUND,
    )
    add(
        "candidate commit",
        lambda r: r["candidate"].pop("source_commit"),
        PF_CANDIDATE_IDENTITY_ABSENT,
    )
    add(
        "multiple candidates",
        lambda r: r["candidate"].update(
            additional_candidates=[copy.deepcopy(r["candidate"])]
        ),
        PF_CANDIDATE_IDENTITY_MULTIPLE,
    )
    add(
        "instrument identity",
        lambda r: r["instrument"].update(identity={}),
        PF_INSTRUMENT_IDENTITY_ABSENT,
    )
    add(
        "sample repetitions",
        lambda r: r["instrument"]["samples"].update(repetitions=0),
        PF_INSTRUMENT_SAMPLES_ABSENT,
    )
    add(
        "absent artefact obligation",
        lambda r: r["candidate"]["artefact"].pop("obligation"),
        PF_ABSENCE_UNRECORDED,
    )
    add(
        "population expected",
        lambda r: r["population"].update(expected=[], realised=["x"]),
        PF_POPULATION_ABSENT,
    )
    add(
        "population incomplete",
        lambda r: r["population"].update(realised=["workload-a"]),
        PF_POPULATION_INCOMPLETE,
    )
    add(
        "population declaration",
        lambda r: r["population"].update(missing=["not-derived"]),
        PF_POPULATION_DECLARATION_MISMATCH,
    )
    add("scope level", lambda r: r["scope"].update(level="L9"), PF_SCOPE_ABSENT)
    add(
        "threat model",
        lambda r: r["threat_model"].pop("statement"),
        PF_THREAT_MODEL_ABSENT,
    )
    add("obligations", lambda r: r.pop("obligations"), PF_OBLIGATIONS_ABSENT)
    add(
        "timing discharge",
        lambda r: r["obligations"].update(attempted_discharge=["T23"]),
        PF_TIMING_OBLIGATION_DISCHARGED_BY_PERFORMANCE,
    )
    add("venue", lambda r: r.pop("venue"), PF_VENUE_ABSENT)
    add(
        "venue contradicts campaign",
        lambda r: r["venue"].update({"class": "VIRTUALISED_COURT", "pmu_exposed": False}),
        PF_VENUE_EVIDENCE_CONTRADICTS,
    )
    add(
        "venue insufficient",
        lambda r: (
            r["venue"].update({"class": "VIRTUALISED_COURT", "pmu_exposed": False}),
            r["venue"]["controls"].update(
                {
                    "frequency_pinned": False,
                    "turbo_disabled": False,
                    "smt_disabled": False,
                    "core_isolation": False,
                }
            ),
        ),
        PF_VENUE_CLASS_INSUFFICIENT,
    )
    add(
        "bare-metal controls",
        lambda r: r["venue"]["controls"].update(smt_disabled=False),
        PF_BARE_METAL_CONTROLS_ABSENT,
    )
    add("authority", lambda r: r.pop("authority"), PF_AUTHORITY_ABSENT)
    add(
        "comparator population",
        lambda r: r.update(comparators=[]),
        PF_COMPARATOR_POPULATION_ABSENT,
    )
    add(
        "comparator identity",
        lambda r: r["comparators"][0].pop("identity"),
        PF_COMPARATOR_IDENTITY_ABSENT,
    )
    add(
        "comparator not qualified",
        lambda r: r["comparators"].append(
            {"id": "unmeasured", "status": "UNAVAILABLE", "reason": "control fixture"}
        ),
        PF_COMPARATOR_NOT_QUALIFIED,
    )
    add(
        "preregistered margin",
        lambda r: r.pop("preregistered_margin"),
        PF_PREREGISTRATION_ABSENT,
    )
    add(
        "statistical support",
        lambda r: r.pop("statistical_support"),
        PF_STATISTICAL_SUPPORT_ABSENT,
    )

    add(
        "reference absent",
        lambda r: r["producer"]["inputs"].append(
            {"path": "docs/does-not-exist.md", "sha256": "0" * 64, "present": True}
        ),
        PF_REFERENCE_ABSENT,
    )
    add(
        "reference digest",
        lambda r: r["producer"]["inputs"].append(
            {
                "path": "docs/PERFORMANCE-METHODOLOGY.md",
                "sha256": "0" * 64,
                "present": True,
            }
        ),
        PF_REFERENCE_DIGEST_MISMATCH,
    )
    add(
        "reference unresolved",
        lambda r: r["producer"]["inputs"].append({"path": "", "sha256": ""}),
        PF_REFERENCE_UNRESOLVED,
    )
    add(
        "conflates assurance",
        lambda r: r.update(safe_compatible=True),
        PF_CLASSIFICATION_CONFLATES_ASSURANCE,
    )
    # Drop the independent-reproduction mutations that do not reach their rule on
    # the frontier base: they are re-pointed at the independent fixture below.
    return controls


def _independent_controls() -> list[tuple[str, dict, str | None]]:
    independent = _valid_record("INDEPENDENTLY_REPRODUCED_FRONTIER")
    self_asserted = copy.deepcopy(independent)
    self_asserted["independent_reproduction"]["party"] = self_asserted["author"]["identity"]
    missing = copy.deepcopy(independent)
    missing.pop("independent_reproduction")
    return [
        ("positive independent fixture", copy.deepcopy(independent), None),
        ("independence self-asserted", self_asserted, PF_INDEPENDENCE_SELF_ASSERTED),
        ("independent receipt", missing, PF_INDEPENDENT_RECEIPT_ABSENT),
    ]


def self_test() -> int:
    failures = 0
    controls = _controls() + _independent_controls()

    def expect(name: str, problems: list[Problem], code: str | None) -> None:
        nonlocal failures
        codes = sorted({problem.code for problem in problems})
        if code is None:
            ok = not problems
            detail = "accepted" if ok else f"unexpectedly refused: {problems}"
        else:
            ok = code in codes
            detail = f"refused {codes}" if ok else f"did not refuse with {code}: {codes}"
        print(f"CONTROL {name}: {'PASS' if ok else 'FAIL'} ({detail})")
        if not ok:
            failures += 1

    for name, record, code in controls:
        expect(name, check_record(record), code)

    # Loader controls.
    for name, text, code in (
        ("json malformed", "{", PF_JSON_MALFORMED),
        ("json duplicate key", '{"a": 1, "a": 1}', PF_JSON_DUPLICATE_KEY),
        ("json non-finite", '{"a": NaN}', PF_JSON_NON_FINITE),
    ):
        try:
            loads_document(text)
        except Refusal as exc:
            expect(name, [Problem(exc.code, exc.pointer, exc.detail)], code)
        else:
            expect(name, [], code)

    # Duplicate record id across a collection.
    path_a = Path("a.json")
    path_b = Path("b.json")
    collection = check_records(
        [(path_a, _valid_record("SCOPED_OBSERVATION")), (path_b, _valid_record("SCOPED_OBSERVATION"))]
    )
    codes = sorted({problem.code for problem in collection[path_b]})
    ok = PF_DUPLICATE_RECORD_ID in codes
    print(f"CONTROL duplicate record id: {'PASS' if ok else 'FAIL'} (refused {codes})")
    if not ok:
        failures += 1

    print(f"performance-classification: {len(controls) + 4} controls, {failures} failure(s)")
    return 1 if failures else 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _default_record_paths() -> list[Path]:
    return sorted(DEFAULT_RECORDS.glob("*.claim.json"))


def mode_check(paths: list[Path], repo_root: Path) -> int:
    loaded: list[tuple[Path, Any]] = []
    failures = 0
    for path in paths:
        try:
            loaded.append((path, load_document(path)))
        except Refusal as exc:
            failures += 1
            print(f"REFUSED {path} {exc.pointer or '/'} {exc.code} {exc.detail}")
    results = check_records(loaded, repo_root)
    accepted = 0
    for path, problems in results.items():
        if problems:
            failures += 1
            for problem in problems:
                print(
                    f"REFUSED {path} {problem.pointer or '/'} {problem.code} {problem.detail}"
                )
        else:
            accepted += 1
            print(f"OK {path}")
    print(
        f"performance-classification: {accepted} record(s) accepted, "
        f"{failures} refused"
    )
    return 0 if failures == 0 else 1


def mode_rules(as_json: bool) -> int:
    payload = {
        "schema": "openssl-rs/performance/classification-rules/1",
        "codes": [{"code": code, "condition": RULES[code]} for code in sorted(CODES)],
        "classifications": [
            {"classification": name, "requirement": CLASSIFICATION_REQUIREMENTS[name]}
            for name in CLASSIFICATIONS
        ],
    }
    if as_json:
        sys.stdout.write(dump(payload))
        return 0
    print("PERFORMANCE CLASSIFICATION RULES")
    for entry in payload["codes"]:
        print(f"{entry['code']}: {entry['condition']}")
    print("\nCLASSIFICATION REQUIREMENTS")
    for entry in payload["classifications"]:
        print(f"{entry['classification']}: {entry['requirement']}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    check = sub.add_parser("check", help="validate claim records")
    check.add_argument("--record", action="append", default=None, help="a record path")
    rules = sub.add_parser("rules", help="print the refusal codes and classification requirements")
    rules.add_argument("--json", action="store_true")
    sub.add_parser("self-test", help="run one positive and one negative control per code")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.mode == "rules":
        return mode_rules(args.json)
    if args.mode == "self-test":
        return self_test()
    paths = [Path(item) for item in args.record] if args.record else _default_record_paths()
    if not paths:
        print("performance-classification: no records found", file=sys.stderr)
        return 2
    return mode_check(paths, REPO_ROOT)


if __name__ == "__main__":
    raise SystemExit(main())
