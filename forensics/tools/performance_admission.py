#!/usr/bin/env python3
"""PFP-19 performance arm admission and evidence reuse validator.

The problem this tool exists for
--------------------------------
`docs/PERFORMANCE-FRONTIER.md` §0 states the binding rule: a faster arm that has
not passed the differential courts and the binary constant-time audit **at the
same digest** is an experiment, not a candidate. §11 adds that no faster path
may buy speed with a refused shortcut, and the queue preamble says a performance
result never discharges a timing obligation. None of it was executable, so an
arm could be described as a candidate on the strength of one latency number, a
measurement could be reused at a different identity, and a changed population
could be absorbed without notice.

This tool reads an arm register of type
`openssl-rs/performance/arm-register/v1` and refuses, by name:

* an arm whose candidate identity is absent;
* an arm whose status is `CANDIDATE` without a measurement, without a passing
  differential court, or without a binary constant-time audit, each bound to the
  same candidate digest;
* a measurement whose candidate digest differs from the arm's (a stale binary);
* a measurement whose population was not frozen before execution, or whose
  frozen population is not the one the reused identity names;
* a measurement reused at an incomplete or different identity (source, tool,
  instrument, target, population);
* an arm that uses performance evidence to discharge a timing obligation;
* an arm that records a safety or compatibility conclusion;
* an arm that records any shortcut from the §11 refused list;
* a cited reference that is absent or whose bytes do not match its digest.

What this tool does not decide
------------------------------
It does not run the courts, the audit or the benchmark it reads about. Passing
is a well-bound admission record, not an admission: the courts and audit must
still have been executed by their own instruments, and the measurement's own
claim record carries the classifications and limits. It does not turn an
`EXPERIMENT` into a `CANDIDATE`; only evidence bound at the same digest can do
that, and the register's `obligations` say what is still missing.

Exit codes
----------
  0  every arm accepted
  1  at least one arm refused
  2  usage error

Determinism
-----------
Problems are sorted by `(pointer, code, detail)`; JSON is serialised with sorted
keys and fixed separators; no timestamp is written.

Usage
-----
    python3 forensics/tools/performance_admission.py check
    python3 forensics/tools/performance_admission.py check --register PATH
    python3 forensics/tools/performance_admission.py rules [--json]
    python3 forensics/tools/performance_admission.py self-test

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = Path(__file__).resolve()
DEFAULT_REGISTER = REPO_ROOT / "evidence" / "performance-frontier" / "admission" / "ARMS.json"

sys.path.insert(0, str(Path(__file__).resolve().parent))
import performance_classification as pc  # noqa: E402  (shared types and loaders)

SCHEMA = "openssl-rs/performance/arm-register/v1"
STATUSES = ("EXPERIMENT", "CANDIDATE")
CT_KINDS = ("CTGRIND", "BINARY_BRANCH_AUDIT", "CTGRIND_PLUS_BRANCH_AUDIT")
CT_KINDS_ACCEPTED_FOR_CANDIDATE = {"BINARY_BRANCH_AUDIT", "CTGRIND_PLUS_BRANCH_AUDIT"}
IDENTITY_KEYS = ("source", "tool", "instrument", "target", "population")
SHORTCUTS = {
    "DISABLE_RSA_BLINDING",
    "SECRET_INDEXED_LOOKUP",
    "REMOVE_CLEANSING",
    "SKIP_CERTIFICATE_VALIDATION",
    "REDUCE_KEY_SIZE",
    "REUSE_STALE_MONTGOMERY_PARAMETERS",
    "IGNORE_CUSTOM_METHOD_OR_CALLBACK",
    "BENCHMARK_STALE_BINARY",
    "CHANGE_POPULATION_SILENTLY",
    "COMPARE_AGAINST_SLOWED_COMPETITOR",
    "PUBLISH_ONLY_WINNING_CASES",
}

PA_JSON_MALFORMED = "PA_JSON_MALFORMED"
PA_JSON_DUPLICATE_KEY = "PA_JSON_DUPLICATE_KEY"
PA_JSON_NON_FINITE = "PA_JSON_NON_FINITE"
PA_SCHEMA = "PA_SCHEMA"
PA_PRODUCER_ABSENT = "PA_PRODUCER_ABSENT"
PA_PRODUCER_LIMITS_ABSENT = "PA_PRODUCER_LIMITS_ABSENT"
PA_PRODUCER_UNBOUND = "PA_PRODUCER_UNBOUND"
PA_DUPLICATE_ARM_ID = "PA_DUPLICATE_ARM_ID"
PA_STATUS_UNKNOWN = "PA_STATUS_UNKNOWN"
PA_CANDIDATE_IDENTITY_ABSENT = "PA_CANDIDATE_IDENTITY_ABSENT"
PA_OBLIGATIONS_ABSENT = "PA_OBLIGATIONS_ABSENT"
PA_TIMING_OBLIGATION_DISCHARGED_BY_PERFORMANCE = (
    "PA_TIMING_OBLIGATION_DISCHARGED_BY_PERFORMANCE"
)
PA_ASSURANCE_ABSENT = "PA_ASSURANCE_ABSENT"
PA_ASSURANCE_CONFLATED = "PA_ASSURANCE_CONFLATED"
PA_SHORTCUT_TAKEN = "PA_SHORTCUT_TAKEN"
PA_UNMEASURED_ARM_CALLED_CANDIDATE = "PA_UNMEASURED_ARM_CALLED_CANDIDATE"
PA_CANDIDATE_WITHOUT_COURTS = "PA_CANDIDATE_WITHOUT_COURTS"
PA_CANDIDATE_WITHOUT_CONSTANT_TIME_AUDIT = "PA_CANDIDATE_WITHOUT_CONSTANT_TIME_AUDIT"
PA_CANDIDATE_WITHOUT_TIMING_EVIDENCE = "PA_CANDIDATE_WITHOUT_TIMING_EVIDENCE"
PA_EVIDENCE_NOT_AT_SAME_DIGEST = "PA_EVIDENCE_NOT_AT_SAME_DIGEST"
PA_STALE_BINARY = "PA_STALE_BINARY"
PA_POPULATION_CHANGED_AFTER_EXECUTION = "PA_POPULATION_CHANGED_AFTER_EXECUTION"
PA_REUSE_IDENTITY_INCOMPLETE = "PA_REUSE_IDENTITY_INCOMPLETE"
PA_REUSE_IDENTITY_MISMATCH = "PA_REUSE_IDENTITY_MISMATCH"
PA_REFERENCE_ABSENT = "PA_REFERENCE_ABSENT"
PA_REFERENCE_DIGEST_MISMATCH = "PA_REFERENCE_DIGEST_MISMATCH"
PA_REFERENCE_UNRESOLVED = "PA_REFERENCE_UNRESOLVED"

CODES = (
    PA_JSON_MALFORMED,
    PA_JSON_DUPLICATE_KEY,
    PA_JSON_NON_FINITE,
    PA_SCHEMA,
    PA_PRODUCER_ABSENT,
    PA_PRODUCER_LIMITS_ABSENT,
    PA_PRODUCER_UNBOUND,
    PA_DUPLICATE_ARM_ID,
    PA_STATUS_UNKNOWN,
    PA_CANDIDATE_IDENTITY_ABSENT,
    PA_OBLIGATIONS_ABSENT,
    PA_TIMING_OBLIGATION_DISCHARGED_BY_PERFORMANCE,
    PA_ASSURANCE_ABSENT,
    PA_ASSURANCE_CONFLATED,
    PA_SHORTCUT_TAKEN,
    PA_UNMEASURED_ARM_CALLED_CANDIDATE,
    PA_CANDIDATE_WITHOUT_COURTS,
    PA_CANDIDATE_WITHOUT_CONSTANT_TIME_AUDIT,
    PA_CANDIDATE_WITHOUT_TIMING_EVIDENCE,
    PA_EVIDENCE_NOT_AT_SAME_DIGEST,
    PA_STALE_BINARY,
    PA_POPULATION_CHANGED_AFTER_EXECUTION,
    PA_REUSE_IDENTITY_INCOMPLETE,
    PA_REUSE_IDENTITY_MISMATCH,
    PA_REFERENCE_ABSENT,
    PA_REFERENCE_DIGEST_MISMATCH,
    PA_REFERENCE_UNRESOLVED,
)

RULES: dict[str, str] = {
    PA_JSON_MALFORMED: "the register is not parseable JSON",
    PA_JSON_DUPLICATE_KEY: "the register repeats an object key",
    PA_JSON_NON_FINITE: "the register carries NaN or Infinity",
    PA_SCHEMA: "the register or an arm is malformed or of the wrong schema",
    PA_PRODUCER_ABSENT: "the register names no producer",
    PA_PRODUCER_LIMITS_ABSENT: "the producer states no limit on what the register establishes",
    PA_PRODUCER_UNBOUND: "the producer digest does not match the named tool",
    PA_DUPLICATE_ARM_ID: "two arms share an id",
    PA_STATUS_UNKNOWN: "the arm status is not EXPERIMENT or CANDIDATE",
    PA_CANDIDATE_IDENTITY_ABSENT: "no candidate commit, artefact digest or build profile",
    PA_OBLIGATIONS_ABSENT: "no timing obligation set",
    PA_TIMING_OBLIGATION_DISCHARGED_BY_PERFORMANCE: (
        "the arm uses performance evidence to discharge a timing obligation"
    ),
    PA_ASSURANCE_ABSENT: "the arm does not declare safety and compatibility conclusions false",
    PA_ASSURANCE_CONFLATED: "the arm records a safety or compatibility conclusion",
    PA_SHORTCUT_TAKEN: "the arm records a shortcut the programme refuses regardless of speed",
    PA_UNMEASURED_ARM_CALLED_CANDIDATE: "an unmeasured arm is called a candidate",
    PA_CANDIDATE_WITHOUT_COURTS: (
        "a candidate has no passing differential court at its digest"
    ),
    PA_CANDIDATE_WITHOUT_CONSTANT_TIME_AUDIT: (
        "a candidate has no binary constant-time audit at its digest"
    ),
    PA_CANDIDATE_WITHOUT_TIMING_EVIDENCE: "a candidate has no classification-bound measurement",
    PA_EVIDENCE_NOT_AT_SAME_DIGEST: "a court or audit is bound to another candidate digest",
    PA_STALE_BINARY: "the measurement's benchmarked artefact is not the arm's candidate",
    PA_POPULATION_CHANGED_AFTER_EXECUTION: (
        "the population was not frozen before execution, or the reuse names another one"
    ),
    PA_REUSE_IDENTITY_INCOMPLETE: "a reused measurement names an incomplete identity",
    PA_REUSE_IDENTITY_MISMATCH: "a reused measurement is read at a different identity",
    PA_REFERENCE_ABSENT: "a cited reference path does not exist",
    PA_REFERENCE_DIGEST_MISMATCH: "a cited reference's bytes differ from its recorded digest",
    PA_REFERENCE_UNRESOLVED: "a reference has no path or no digest",
}

ADMISSION_RULE = (
    "A candidate is the conjunction: a measurement bound to the candidate digest, "
    "a passing differential court at that digest, a binary constant-time audit at "
    "that digest, a population frozen before execution, an empty timing-discharge "
    "set, a false safety/compatibility declaration and no refused shortcut. Any "
    "arm that fails one conjunct is an EXPERIMENT."
)

Problem = pc.Problem


class Refusal(Exception):
    def __init__(self, code: str, pointer: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.pointer = pointer
        self.detail = detail


_LOADER_CODES = {
    pc.PF_JSON_MALFORMED: PA_JSON_MALFORMED,
    pc.PF_JSON_DUPLICATE_KEY: PA_JSON_DUPLICATE_KEY,
    pc.PF_JSON_NON_FINITE: PA_JSON_NON_FINITE,
}


def loads_document(text: str) -> Any:
    try:
        return pc.loads_document(text)
    except pc.Refusal as exc:
        raise Refusal(_LOADER_CODES[exc.code], exc.pointer, exc.detail) from exc


def load_document(path: Path) -> Any:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise Refusal(PA_JSON_MALFORMED, "", f"{path}: {exc}") from exc
    return loads_document(text)


def population_digest(identifiers: list[str]) -> str:
    return pc.sha256_bytes(
        json.dumps(sorted(identifiers), separators=(",", ":")).encode("utf-8")
    )


def _text(value: Any) -> bool:
    return isinstance(value, str) and value.strip() != ""


def _bool(value: Any) -> bool:
    return isinstance(value, bool)


def _sha(value: Any) -> bool:
    return isinstance(value, str) and pc.SHA256_RE.match(value) is not None


def _commit(value: Any) -> bool:
    return isinstance(value, str) and pc.COMMIT_RE.match(value) is not None


def _add(problems: list[Problem], code: str, pointer: str, detail: str) -> None:
    problems.append(Problem(code, pointer, detail))


def _reference(
    reference: Any, pointer: str, problems: list[Problem], repo_root: Path
) -> bool:
    if not isinstance(reference, dict):
        _add(problems, PA_REFERENCE_UNRESOLVED, pointer, "reference is not an object")
        return False
    path = reference.get("path")
    digest = reference.get("sha256")
    if not _text(path) or not _sha(digest):
        _add(
            problems,
            PA_REFERENCE_UNRESOLVED,
            pointer,
            "reference needs a path and a full SHA-256 digest",
        )
        return False
    target = repo_root / path
    if not target.is_file():
        _add(problems, PA_REFERENCE_ABSENT, pointer, f"{path} does not exist")
        return False
    actual = pc.sha256_file(target)
    if actual != digest:
        _add(
            problems,
            PA_REFERENCE_DIGEST_MISMATCH,
            pointer,
            f"{path}: recorded {digest}, actual {actual}",
        )
        return False
    return True


def _check_producer(register: dict, problems: list[Problem], repo_root: Path) -> None:
    pointer = "/producer"
    producer = register.get("producer")
    if not isinstance(producer, dict):
        _add(problems, PA_PRODUCER_ABSENT, pointer, "producer must be an object")
        return
    for key in ("name", "version", "tool_path"):
        if not _text(producer.get(key)):
            _add(problems, PA_PRODUCER_ABSENT, f"{pointer}/{key}", "missing or empty")
    limits = producer.get("limits")
    if not isinstance(limits, list) or not limits or not all(_text(item) for item in limits):
        _add(
            problems,
            PA_PRODUCER_LIMITS_ABSENT,
            f"{pointer}/limits",
            "limits must be a non-empty array of statements",
        )
    tool_path = producer.get("tool_path")
    tool_digest = producer.get("tool_sha256")
    if not _text(tool_path) or not _sha(tool_digest):
        _add(problems, PA_PRODUCER_UNBOUND, pointer, "tool_path and tool_sha256 are required")
    else:
        target = repo_root / tool_path
        if not target.is_file():
            _add(problems, PA_PRODUCER_UNBOUND, f"{pointer}/tool_path", f"{tool_path} missing")
        elif pc.sha256_file(target) != tool_digest:
            _add(
                problems,
                PA_PRODUCER_UNBOUND,
                f"{pointer}/tool_sha256",
                f"recorded {tool_digest}, actual {pc.sha256_file(target)}",
            )
        if target.resolve() != TOOL_PATH and repo_root.resolve() == REPO_ROOT:
            _add(
                problems,
                PA_PRODUCER_UNBOUND,
                f"{pointer}/tool_path",
                "the producer must be this validator",
            )
    inputs = producer.get("inputs")
    if not isinstance(inputs, list) or not inputs:
        _add(problems, PA_PRODUCER_UNBOUND, f"{pointer}/inputs", "no bound inputs")
    else:
        for index, reference in enumerate(inputs):
            _reference(reference, f"{pointer}/inputs/{index}", problems, repo_root)


def _check_candidate(arm: dict, pointer: str, problems: list[Problem]) -> str | None:
    candidate = arm.get("candidate")
    if not isinstance(candidate, dict):
        _add(problems, PA_CANDIDATE_IDENTITY_ABSENT, f"{pointer}/candidate", "not an object")
        return None
    if not _commit(candidate.get("source_commit")):
        _add(
            problems,
            PA_CANDIDATE_IDENTITY_ABSENT,
            f"{pointer}/candidate/source_commit",
            "missing or not a commit id",
        )
    artefact = candidate.get("artefact")
    if (
        not isinstance(artefact, dict)
        or not _text(artefact.get("label"))
        or not _sha(artefact.get("sha256"))
    ):
        _add(
            problems,
            PA_CANDIDATE_IDENTITY_ABSENT,
            f"{pointer}/candidate/artefact",
            "artefact needs a label and a full SHA-256",
        )
        digest = None
    else:
        digest = artefact["sha256"]
    if not _text(candidate.get("build_profile")):
        _add(
            problems,
            PA_CANDIDATE_IDENTITY_ABSENT,
            f"{pointer}/candidate/build_profile",
            "missing or empty",
        )
    return digest


def _check_obligations(arm: dict, pointer: str, problems: list[Problem]) -> None:
    obligations = arm.get("timing_obligations")
    if not isinstance(obligations, dict):
        _add(
            problems,
            PA_OBLIGATIONS_ABSENT,
            f"{pointer}/timing_obligations",
            "must be an object",
        )
        return
    open_items = obligations.get("open")
    if not isinstance(open_items, list):
        _add(
            problems,
            PA_OBLIGATIONS_ABSENT,
            f"{pointer}/timing_obligations/open",
            "must be an array",
        )
        open_items = []
    identifiers: list[str] = []
    for index, item in enumerate(open_items):
        where = f"{pointer}/timing_obligations/open/{index}"
        if not isinstance(item, dict) or not _text(item.get("id")) or not _text(
            item.get("description")
        ):
            _add(
                problems,
                PA_OBLIGATIONS_ABSENT,
                where,
                "an open obligation needs an id and a description",
            )
            continue
        identifiers.append(item["id"])
        if item.get("discharged") is not False or item.get("status") == "DISCHARGED":
            _add(
                problems,
                PA_TIMING_OBLIGATION_DISCHARGED_BY_PERFORMANCE,
                where,
                "a performance arm may not discharge a timing obligation",
            )
    if len(identifiers) != len(set(identifiers)):
        _add(
            problems,
            PA_OBLIGATIONS_ABSENT,
            f"{pointer}/timing_obligations/open",
            "open obligation ids are not unique",
        )
    attempted = obligations.get("attempted_discharge")
    if not isinstance(attempted, list):
        _add(
            problems,
            PA_OBLIGATIONS_ABSENT,
            f"{pointer}/timing_obligations/attempted_discharge",
            "must be an explicit array, even when empty",
        )
    elif attempted:
        _add(
            problems,
            PA_TIMING_OBLIGATION_DISCHARGED_BY_PERFORMANCE,
            f"{pointer}/timing_obligations/attempted_discharge",
            f"performance evidence cannot discharge {attempted!r}",
        )


def _check_assurance(arm: dict, pointer: str, problems: list[Problem]) -> None:
    assurance = arm.get("assurance")
    if not isinstance(assurance, dict):
        _add(
            problems,
            PA_ASSURANCE_ABSENT,
            f"{pointer}/assurance",
            "must declare safe_compatible and semantic_assurance false",
        )
        return
    for key in ("safe_compatible", "semantic_assurance"):
        if assurance.get(key) is not False:
            _add(
                problems,
                PA_ASSURANCE_CONFLATED,
                f"{pointer}/assurance/{key}",
                "a performance arm may not assert a safety or compatibility conclusion",
            )


def _check_shortcuts(arm: dict, pointer: str, problems: list[Problem]) -> None:
    shortcuts = arm.get("shortcuts")
    if not isinstance(shortcuts, list):
        _add(problems, PA_SCHEMA, f"{pointer}/shortcuts", "must be an array")
        return
    for index, shortcut in enumerate(shortcuts):
        where = f"{pointer}/shortcuts/{index}"
        if shortcut not in SHORTCUTS:
            _add(problems, PA_SCHEMA, where, f"unknown shortcut {shortcut!r}")
        else:
            _add(
                problems,
                PA_SHORTCUT_TAKEN,
                where,
                f"{shortcut} is refused regardless of speed",
            )


def _check_measurement(
    arm: dict,
    pointer: str,
    problems: list[Problem],
    repo_root: Path,
) -> dict | None:
    measurement = arm.get("measurement")
    if measurement is None:
        return None
    where = f"{pointer}/measurement"
    if not isinstance(measurement, dict):
        _add(problems, PA_SCHEMA, where, "must be an object or null")
        return None
    _reference(measurement.get("record"), f"{where}/record", problems, repo_root)
    classification = measurement.get("classification")
    if classification not in pc.CLASSIFICATIONS:
        _add(
            problems,
            PA_CANDIDATE_WITHOUT_TIMING_EVIDENCE,
            f"{where}/classification",
            f"{classification!r} is not a §10 classification",
        )
    digest = measurement.get("candidate_sha256")
    if not _sha(digest):
        _add(problems, PA_SCHEMA, f"{where}/candidate_sha256", "not a full SHA-256")
    population = measurement.get("population")
    if not isinstance(population, dict):
        _add(problems, PA_SCHEMA, f"{where}/population", "must be an object")
    else:
        if not _sha(population.get("digest")):
            _add(
                problems,
                PA_SCHEMA,
                f"{where}/population/digest",
                "not a full SHA-256",
            )
        if population.get("frozen_before_execution") is not True:
            _add(
                problems,
                PA_POPULATION_CHANGED_AFTER_EXECUTION,
                f"{where}/population/frozen_before_execution",
                "the population must be frozen before execution",
            )
    identity = measurement.get("identity")
    if not isinstance(identity, dict):
        _add(problems, PA_SCHEMA, f"{where}/identity", "must be an object")
    else:
        for key in IDENTITY_KEYS:
            if not _text(identity.get(key)):
                _add(
                    problems,
                    PA_SCHEMA,
                    f"{where}/identity/{key}",
                    "missing or empty",
                )
    return measurement


def _check_reuse(
    arm: dict,
    pointer: str,
    problems: list[Problem],
    measurement: dict | None,
    repo_root: Path,
) -> None:
    reuse = arm.get("reuse")
    if reuse is None:
        return
    where = f"{pointer}/reuse"
    if not isinstance(reuse, dict):
        _add(problems, PA_REUSE_IDENTITY_INCOMPLETE, where, "must be an object or null")
        return
    if not _text(reuse.get("of")):
        _add(problems, PA_REUSE_IDENTITY_INCOMPLETE, f"{where}/of", "missing or empty")
    _reference(reuse.get("record"), f"{where}/record", problems, repo_root)
    identity = reuse.get("identity")
    if not isinstance(identity, dict):
        _add(
            problems,
            PA_REUSE_IDENTITY_INCOMPLETE,
            f"{where}/identity",
            "a reused measurement needs a full identity",
        )
        return
    for key in IDENTITY_KEYS:
        if not _text(identity.get(key)):
            _add(
                problems,
                PA_REUSE_IDENTITY_INCOMPLETE,
                f"{where}/identity/{key}",
                "missing or empty",
            )
    if measurement is None:
        return
    measured = measurement.get("identity")
    if isinstance(measured, dict):
        for key in IDENTITY_KEYS:
            if identity.get(key) != measured.get(key):
                _add(
                    problems,
                    PA_REUSE_IDENTITY_MISMATCH,
                    f"{where}/identity/{key}",
                    f"reused {identity.get(key)!r}, measured {measured.get(key)!r}",
                )
    population = measurement.get("population")
    if isinstance(population, dict) and identity.get("population") != population.get("digest"):
        _add(
            problems,
            PA_POPULATION_CHANGED_AFTER_EXECUTION,
            f"{where}/identity/population",
            "the reused identity names a different population",
        )


def _check_arm(
    arm: Any,
    pointer: str,
    problems: list[Problem],
    repo_root: Path,
) -> None:
    if not isinstance(arm, dict):
        _add(problems, PA_SCHEMA, pointer, "arm is not an object")
        return
    if not _text(arm.get("arm_id")):
        _add(problems, PA_SCHEMA, f"{pointer}/arm_id", "missing or empty")
    status = arm.get("status")
    if status not in STATUSES:
        _add(problems, PA_STATUS_UNKNOWN, f"{pointer}/status", f"{status!r}")
    digest = _check_candidate(arm, pointer, problems)
    _check_obligations(arm, pointer, problems)
    _check_assurance(arm, pointer, problems)
    _check_shortcuts(arm, pointer, problems)
    measurement = _check_measurement(arm, pointer, problems, repo_root)
    if measurement is not None and digest is not None:
        measured_digest = measurement.get("candidate_sha256")
        if measured_digest != digest:
            _add(
                problems,
                PA_STALE_BINARY,
                f"{pointer}/measurement/candidate_sha256",
                f"measurement {measured_digest!r}, arm {digest!r}",
            )
    _check_reuse(arm, pointer, problems, measurement, repo_root)
    if status != "CANDIDATE":
        return
    if measurement is None:
        _add(
            problems,
            PA_UNMEASURED_ARM_CALLED_CANDIDATE,
            f"{pointer}/status",
            "a CANDIDATE needs a bound measurement",
        )
    courts = arm.get("differential_courts")
    if not isinstance(courts, dict):
        _add(
            problems,
            PA_CANDIDATE_WITHOUT_COURTS,
            f"{pointer}/differential_courts",
            "no differential court record",
        )
    else:
        _reference(courts.get("reference"), f"{pointer}/differential_courts", problems, repo_root)
        if courts.get("result") != "PASS":
            _add(
                problems,
                PA_CANDIDATE_WITHOUT_COURTS,
                f"{pointer}/differential_courts/result",
                f"result is {courts.get('result')!r}, not PASS",
            )
        if digest is not None and courts.get("candidate_sha256") != digest:
            _add(
                problems,
                PA_EVIDENCE_NOT_AT_SAME_DIGEST,
                f"{pointer}/differential_courts/candidate_sha256",
                f"court {courts.get('candidate_sha256')!r}, arm {digest!r}",
            )
    audit = arm.get("constant_time_audit")
    if not isinstance(audit, dict):
        _add(
            problems,
            PA_CANDIDATE_WITHOUT_CONSTANT_TIME_AUDIT,
            f"{pointer}/constant_time_audit",
            "no binary constant-time audit record",
        )
    else:
        _reference(audit.get("reference"), f"{pointer}/constant_time_audit", problems, repo_root)
        if audit.get("kind") not in CT_KINDS_ACCEPTED_FOR_CANDIDATE:
            _add(
                problems,
                PA_CANDIDATE_WITHOUT_CONSTANT_TIME_AUDIT,
                f"{pointer}/constant_time_audit/kind",
                "a candidate needs a binary branch audit, not a taint run alone",
            )
        if not _sha(audit.get("harness_sha256")):
            _add(
                problems,
                PA_CANDIDATE_WITHOUT_CONSTANT_TIME_AUDIT,
                f"{pointer}/constant_time_audit/harness_sha256",
                "the audit harness must be identified",
            )
        if digest is not None and audit.get("candidate_sha256") != digest:
            _add(
                problems,
                PA_EVIDENCE_NOT_AT_SAME_DIGEST,
                f"{pointer}/constant_time_audit/candidate_sha256",
                f"audit {audit.get('candidate_sha256')!r}, arm {digest!r}",
            )


def check_register(register: Any, repo_root: Path = REPO_ROOT) -> list[Problem]:
    problems: list[Problem] = []
    if not isinstance(register, dict):
        return [Problem(PA_SCHEMA, "", "register is not a JSON object")]
    if register.get("schema") != SCHEMA:
        _add(problems, PA_SCHEMA, "/schema", f"schema is {register.get('schema')!r}")
    if not isinstance(register.get("author"), dict) or not _text(
        register["author"].get("identity")
    ):
        _add(problems, PA_SCHEMA, "/author", "the register names no author identity")
    _check_producer(register, problems, repo_root)
    arms = register.get("arms")
    if not isinstance(arms, list) or not arms:
        _add(problems, PA_SCHEMA, "/arms", "arms must be a non-empty array")
        arms = []
    seen: dict[str, int] = {}
    for index, arm in enumerate(arms):
        pointer = f"/arms/{index}"
        _check_arm(arm, pointer, problems, repo_root)
        if isinstance(arm, dict) and _text(arm.get("arm_id")):
            if arm["arm_id"] in seen:
                _add(
                    problems,
                    PA_DUPLICATE_ARM_ID,
                    f"{pointer}/arm_id",
                    f"{arm['arm_id']!r} is also arm {seen[arm['arm_id']]}",
                )
            else:
                seen[arm["arm_id"]] = index
    unique = {(problem.code, problem.pointer, problem.detail) for problem in problems}
    return sorted((Problem(*item) for item in unique), key=Problem.sort_key)


# ---------------------------------------------------------------------------
# Controls
# ---------------------------------------------------------------------------


def _ref(path: str) -> dict[str, Any]:
    return {
        "path": path,
        "sha256": pc.sha256_file(REPO_ROOT / path),
        "present": True,
    }


def _valid_register() -> dict[str, Any]:
    identifiers = ["workload-a", "workload-b"]
    fixture = "docs/PERFORMANCE-METHODOLOGY.md"
    arm = {
        "arm_id": "CONTROL-ARM",
        "queue_item": "PFP-19",
        "description": "synthetic control fixture; it measures nothing",
        "status": "CANDIDATE",
        "candidate": {
            "source_commit": "0" * 40,
            "artefact": {"label": "control fixture DSO", "sha256": "1" * 64},
            "build_profile": "release, x86_64-unknown-linux-gnu",
        },
        "measurement": {
            "record": _ref("evidence/performance-frontier/claims/PFP-1.claim.json"),
            "classification": "SCOPED_OBSERVATION",
            "candidate_sha256": "1" * 64,
            "population": {
                "digest": population_digest(identifiers),
                "frozen_before_execution": True,
            },
            "identity": {
                "source": "candidate 0" * 5,
                "tool": "instrument fixture",
                "instrument": "benchmark fixture",
                "target": "x86_64-unknown-linux-gnu",
                "population": population_digest(identifiers),
            },
        },
        "differential_courts": {
            "reference": _ref(fixture),
            "result": "PASS",
            "candidate_sha256": "1" * 64,
        },
        "constant_time_audit": {
            "kind": "BINARY_BRANCH_AUDIT",
            "instrument": "binary_branch_audit fixture",
            "reference": _ref(fixture),
            "candidate_sha256": "1" * 64,
            "harness_sha256": "2" * 64,
            "result": "fixture",
        },
        "timing_obligations": {
            "open": [
                {
                    "id": "T23",
                    "description": "the control fixture does not address T23",
                    "discharged": False,
                }
            ],
            "attempted_discharge": [],
        },
        "assurance": {"safe_compatible": False, "semantic_assurance": False},
        "shortcuts": [],
        "reuse": None,
    }
    return {
        "schema": SCHEMA,
        "author": {"identity": "control-fixture", "role": "producer"},
        "producer": {
            "name": "performance_admission.py",
            "version": "1",
            "tool_path": "forensics/tools/performance_admission.py",
            "tool_sha256": pc.sha256_file(TOOL_PATH),
            "limits": [
                "the control fixture is synthetic and runs no court or benchmark",
                "a passing register is a well-bound admission record, not an admission",
            ],
            "inputs": [_ref("docs/PERFORMANCE-METHODOLOGY.md")],
        },
        "arms": [arm],
    }


def _controls() -> list[tuple[str, dict, str | None]]:
    base = _valid_register()
    controls: list[tuple[str, dict, str | None]] = []

    def add(name: str, mutate: Callable[[dict], None], code: str | None) -> None:
        register = copy.deepcopy(base)
        mutate(register)
        controls.append((name, register, code))

    controls.append(("positive candidate fixture", copy.deepcopy(base), None))
    experiment = copy.deepcopy(base)
    experiment["arms"][0]["status"] = "EXPERIMENT"
    experiment["arms"][0]["measurement"] = None
    experiment["arms"][0]["differential_courts"] = None
    experiment["arms"][0]["constant_time_audit"] = None
    controls.append(("positive experiment fixture", experiment, None))
    add("schema", lambda r: r.update(schema="wrong"), PA_SCHEMA)
    add("producer", lambda r: r.pop("producer"), PA_PRODUCER_ABSENT)
    add(
        "limits",
        lambda r: r["producer"].update(limits=[]),
        PA_PRODUCER_LIMITS_ABSENT,
    )
    add(
        "producer digest",
        lambda r: r["producer"].update(tool_sha256="0" * 64),
        PA_PRODUCER_UNBOUND,
    )
    add(
        "duplicate arm id",
        lambda r: r["arms"].append(copy.deepcopy(r["arms"][0])),
        PA_DUPLICATE_ARM_ID,
    )
    add(
        "status",
        lambda r: r["arms"][0].update(status="WINNER"),
        PA_STATUS_UNKNOWN,
    )
    add(
        "candidate identity",
        lambda r: r["arms"][0].pop("candidate"),
        PA_CANDIDATE_IDENTITY_ABSENT,
    )
    add(
        "obligations",
        lambda r: r["arms"][0].pop("timing_obligations"),
        PA_OBLIGATIONS_ABSENT,
    )
    add(
        "timing discharge",
        lambda r: r["arms"][0]["timing_obligations"].update(
            attempted_discharge=["T23"]
        ),
        PA_TIMING_OBLIGATION_DISCHARGED_BY_PERFORMANCE,
    )
    add(
        "assurance absent",
        lambda r: r["arms"][0].pop("assurance"),
        PA_ASSURANCE_ABSENT,
    )
    add(
        "assurance conflated",
        lambda r: r["arms"][0]["assurance"].update(safe_compatible=True),
        PA_ASSURANCE_CONFLATED,
    )
    add(
        "shortcut",
        lambda r: r["arms"][0].update(shortcuts=["DISABLE_RSA_BLINDING"]),
        PA_SHORTCUT_TAKEN,
    )
    add(
        "unmeasured candidate",
        lambda r: r["arms"][0].update(measurement=None),
        PA_UNMEASURED_ARM_CALLED_CANDIDATE,
    )
    add(
        "candidate without courts",
        lambda r: r["arms"][0].update(differential_courts=None),
        PA_CANDIDATE_WITHOUT_COURTS,
    )
    add(
        "candidate without audit",
        lambda r: r["arms"][0].update(constant_time_audit=None),
        PA_CANDIDATE_WITHOUT_CONSTANT_TIME_AUDIT,
    )
    add(
        "candidate with taint only",
        lambda r: r["arms"][0]["constant_time_audit"].update(kind="CTGRIND"),
        PA_CANDIDATE_WITHOUT_CONSTANT_TIME_AUDIT,
    )
    add(
        "no timing evidence",
        lambda r: r["arms"][0]["measurement"].pop("classification"),
        PA_CANDIDATE_WITHOUT_TIMING_EVIDENCE,
    )
    add(
        "court at another digest",
        lambda r: r["arms"][0]["differential_courts"].update(candidate_sha256="3" * 64),
        PA_EVIDENCE_NOT_AT_SAME_DIGEST,
    )
    add(
        "audit at another digest",
        lambda r: r["arms"][0]["constant_time_audit"].update(candidate_sha256="3" * 64),
        PA_EVIDENCE_NOT_AT_SAME_DIGEST,
    )
    add(
        "stale binary",
        lambda r: r["arms"][0]["measurement"].update(candidate_sha256="3" * 64),
        PA_STALE_BINARY,
    )
    add(
        "population not frozen",
        lambda r: r["arms"][0]["measurement"]["population"].update(
            frozen_before_execution=False
        ),
        PA_POPULATION_CHANGED_AFTER_EXECUTION,
    )
    add(
        "reuse incomplete",
        lambda r: r["arms"][0].update(
            reuse={
                "of": "PFP-1",
                "record": _ref("docs/PERFORMANCE-METHODOLOGY.md"),
                "identity": {"source": "x"},
            }
        ),
        PA_REUSE_IDENTITY_INCOMPLETE,
    )
    add(
        "reuse mismatch",
        lambda r: r["arms"][0].update(
            reuse={
                "of": "PFP-1",
                "record": _ref("docs/PERFORMANCE-METHODOLOGY.md"),
                "identity": dict(
                    r["arms"][0]["measurement"]["identity"], tool="another tool"
                ),
            }
        ),
        PA_REUSE_IDENTITY_MISMATCH,
    )
    add(
        "reuse population changed",
        lambda r: r["arms"][0].update(
            reuse={
                "of": "PFP-1",
                "record": _ref("docs/PERFORMANCE-METHODOLOGY.md"),
                "identity": dict(
                    r["arms"][0]["measurement"]["identity"],
                    population="4" * 64,
                ),
            }
        ),
        PA_POPULATION_CHANGED_AFTER_EXECUTION,
    )
    add(
        "reference absent",
        lambda r: r["producer"]["inputs"].append(
            {"path": "docs/does-not-exist.md", "sha256": "0" * 64, "present": True}
        ),
        PA_REFERENCE_ABSENT,
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
        PA_REFERENCE_DIGEST_MISMATCH,
    )
    add(
        "reference unresolved",
        lambda r: r["producer"]["inputs"].append({"path": "", "sha256": ""}),
        PA_REFERENCE_UNRESOLVED,
    )
    return controls


def self_test() -> int:
    failures = 0
    controls = _controls()

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

    for name, register, code in controls:
        expect(name, check_register(register), code)

    for name, text, code in (
        ("json malformed", "{", PA_JSON_MALFORMED),
        ("json duplicate key", '{"a": 1, "a": 1}', PA_JSON_DUPLICATE_KEY),
        ("json non-finite", '{"a": NaN}', PA_JSON_NON_FINITE),
    ):
        try:
            loads_document(text)
        except Refusal as exc:
            expect(name, [Problem(exc.code, exc.pointer, exc.detail)], code)
        else:
            expect(name, [], code)

    print(f"performance-admission: {len(controls) + 3} controls, {failures} failure(s)")
    return 1 if failures else 0


def mode_check(paths: list[Path], repo_root: Path) -> int:
    loaded: list[tuple[Path, Any]] = []
    failures = 0
    for path in paths:
        try:
            loaded.append((path, load_document(path)))
        except Refusal as exc:
            failures += 1
            print(f"REFUSED {path} {exc.pointer or '/'} {exc.code} {exc.detail}")
    accepted = 0
    for path, register in loaded:
        problems = check_register(register, repo_root)
        if problems:
            failures += 1
            for problem in problems:
                print(
                    f"REFUSED {path} {problem.pointer or '/'} {problem.code} {problem.detail}"
                )
        else:
            accepted += 1
            print(f"OK {path}")
    print(f"performance-admission: {accepted} register(s) accepted, {failures} refused")
    return 0 if failures == 0 else 1


def mode_rules(as_json: bool) -> int:
    payload = {
        "schema": "openssl-rs/performance/admission-rules/1",
        "admission_rule": ADMISSION_RULE,
        "codes": [{"code": code, "condition": RULES[code]} for code in sorted(CODES)],
        "shortcuts": sorted(SHORTCUTS),
        "candidate_constant_time_kinds": sorted(CT_KINDS_ACCEPTED_FOR_CANDIDATE),
    }
    if as_json:
        sys.stdout.write(pc.dump(payload))
        return 0
    print("PERFORMANCE ADMISSION RULES")
    print(ADMISSION_RULE)
    print()
    for entry in payload["codes"]:
        print(f"{entry['code']}: {entry['condition']}")
    print("\nREFUSED SHORTCUTS")
    for shortcut in payload["shortcuts"]:
        print(shortcut)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    check = sub.add_parser("check", help="validate an arm register")
    check.add_argument("--register", action="append", default=None)
    rules = sub.add_parser("rules", help="print the admission rules and refusal codes")
    rules.add_argument("--json", action="store_true")
    sub.add_parser("self-test", help="run one positive and one negative control per code")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.mode == "rules":
        return mode_rules(args.json)
    if args.mode == "self-test":
        return self_test()
    paths = [Path(item) for item in args.register] if args.register else [DEFAULT_REGISTER]
    if not paths[0].exists():
        print(f"performance-admission: {paths[0]} not found", file=sys.stderr)
        return 2
    return mode_check(paths, REPO_ROOT)


if __name__ == "__main__":
    raise SystemExit(main())
