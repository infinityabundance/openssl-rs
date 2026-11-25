#!/usr/bin/env python3
"""do178c_matrix.py -- validate the FRC-8 DO-178C objective-conformance matrix.

Why this tool exists
--------------------
FRC-8 asks for an objective-by-objective matrix of the programme's section 6 for
a declared system context, with the evidence satisfying each objective, the
independence the objective requires versus the independence actually held, and
every missing qualification or target-execution item named. It also asks for the
explicit statement that objective satisfaction is not certification.

Those are prose-shaped claims, so this tool enforces the rules that keep them
honest:

  * the system context is declared, and it excludes target hardware, airborne
    applicability, every DAL and every consequence that would follow from
    certification;
  * every objective row carries a status from a closed vocabulary, and every
    status other than ``UNVERIFIED`` cites at least one evidence path that
    exists; a ``SATISFIED_WITH_EVIDENCE`` row must cite a record or a test and
    name the check;
  * an exact DO-178C objective identifier and wording may be recorded, or it may
    be ``UNVERIFIED`` with the reading that would settle it -- never assumed;
  * the independence a row claims as held is checked against the project's own
    independence record, so the number of distinct parties cannot be invented;
  * a row that needs an independent check while the held independence is
    same-party is refused a satisfied status;
  * no row, record or document may claim certification, a DAL or an assurance
    level;
  * every required missing item is present, justified, has a settling method and
    is referenced by an objective that is not satisfied;
  * the non-claim statement is present in both records;
  * the normative document names every objective, context, exclusion, missing
    item and refusal code the machine record contains, so the two cannot drift.

What this tool does not do
--------------------------
It does not read DO-178C, AC 20-115D, DO-330 or DO-333, run a test, execute a
target, qualify a tool, review a work product or decide whether a cited record
supports its row. It checks that the matrix does not claim more than its own
evidence, not that the evidence is sufficient. An objective marked
``SATISFIED_WITH_EVIDENCE`` is a statement about this repository's records; it is
not a certification finding and this tool cannot make it one.

Determinism
-----------
``check`` reads only its inputs and returns refusals sorted by (code, detail).
No timestamp is written by the validator, and the summary is serialised with
sorted keys.

Usage
-----
    python3 forensics/tools/do178c_matrix.py check [--json]
    python3 forensics/tools/do178c_matrix.py inventory [--json]

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]

MATRIX = "evidence/frc8/DO178C-MATRIX.json"
DOCUMENT = "docs/DO178C-CONFORMANCE.md"
INDEPENDENCE = "evidence/etp-t15/INDEPENDENCE.json"

SCHEMA = "openssl-rs/frc8/do178c-matrix/1"

EXIT_OK = 0
EXIT_REFUSED = 1
EXIT_USAGE = 2
CODE_OK = "DO_OK"
CODE_USAGE = "DO_REFUSED_USAGE"

STATUSES = ("SATISFIED_WITH_EVIDENCE", "PARTIAL", "NOT_SATISFIED", "UNVERIFIED")
EVIDENCE_KINDS = ("RECORD", "TEST")
REQUIRED_INDEPENDENCE_STATES = ("UNVERIFIED", "NONE_REQUIRED", "INDEPENDENT_REQUIRED")
HELD_INDEPENDENCE_STATES = ("INDEPENDENT", "SAME_PARTY_ONLY")

SHA1_COMMIT = re.compile(r"^[0-9a-f]{40}$")
OBJECTIVE_ID = re.compile(r"^DO[0-9]+(-[A-Z0-9]+)+$")
MISSING_ID = re.compile(r"^MI(-[A-Z0-9]+)+$")
EXCLUSION_ID = re.compile(r"^XCE(-[A-Z0-9]+)+$")

# The context must exclude each of these; the identifiers are checked, not the
# prose, so the declaration cannot omit a category by rewording it.
MUST_EXCLUDE = {
    "XCE-TARGET-HARDWARE": "TARGET_HARDWARE",
    "XCE-AIRBORNE": "AIRBORNE_APPLICABILITY",
    "XCE-DAL": "DAL",
    "XCE-CERTIFICATION": "CERTIFICATION_CONSEQUENCE",
    "XCE-WCET": "WORST_CASE_EXECUTION",
    "XCE-ENVIRONMENT": "ENVIRONMENTAL_QUALIFICATION",
}

# Every item the programme's section 6 and paragraph after the table would
# require before the matrix could support anything.  The validator refuses a
# matrix that omits one, and an objective must cite the items that block it.
REQUIRED_MISSING = (
    "MI-PLANNING",
    "MI-REQUIREMENT-BASELINE",
    "MI-REQUIREMENTS-BASED-TESTS",
    "MI-STRUCTURAL-COVERAGE",
    "MI-SYSTEM-SAFETY-ASSESSMENT",
    "MI-TOOL-QUALIFICATION",
    "MI-TARGET-EXECUTION",
    "MI-CONFIGURATION-INDEX",
    "MI-INDEPENDENT-REVIEW",
    "MI-FORMAL-METHODS-JUSTIFICATION",
    "MI-TARGET-TIMING",
    "MI-PROBLEM-REPORTING",
)

# Phrases that would turn the matrix into a certification claim.  They are
# unambiguous as strings; the declaration's own "no DAL" sentences are worded so
# that none of them occurs.
FORBIDDEN_CERTIFICATION_PHRASES = (
    "DO-178C certified",
    "certified to DO-178C",
    "achieves DAL",
    "DAL A certification",
    "this document certifies",
)

# ---------------------------------------------------------------------------
# Refusal codes.  Each names the wrong conclusion it prevents.  The normative
# document must name every code here; the test suite refuses drift between the
# two, and each code has a negative control that fires it.
# ---------------------------------------------------------------------------

REFUSALS: dict[str, dict[str, str]] = {
    "DO_REFUSED_SCHEMA": {
        "condition": "the matrix has the wrong schema, a missing or mistyped field, "
                     "a malformed identifier, or a status outside its closed vocabulary",
        "prevents": "that an unreadable or out-of-vocabulary entry is read as a result",
    },
    "DO_REFUSED_DUPLICATE_KEY": {
        "condition": "a JSON object repeats a key at any depth",
        "prevents": "that last-wins parsing silently drops one of two values",
    },
    "DO_REFUSED_CONTEXT_ABSENT": {
        "condition": "the system context is missing, empty, or does not exclude target "
                     "hardware, airborne applicability, every DAL and the certification "
                     "consequence, or does not say it is a scope choice and not a "
                     "compliance claim",
        "prevents": "that a matrix is read against an undeclared system and silently "
                    "borrows a context it never stated",
    },
    "DO_REFUSED_STATUS_WITHOUT_EVIDENCE": {
        "condition": "a PARTIAL, NOT_SATISFIED or SATISFIED_WITH_EVIDENCE row cites no "
                     "evidence item, or a SATISFIED_WITH_EVIDENCE row cites no record or "
                     "test that names its check",
        "prevents": "that an objective status is asserted with nothing behind it",
    },
    "DO_REFUSED_EVIDENCE_ABSENT": {
        "condition": "an evidence item names a path that is not a file in this repository",
        "prevents": "that a citation to absent evidence is read as evidence",
    },
    "DO_REFUSED_UNVERIFIED_WITHOUT_METHOD": {
        "condition": "an UNVERIFIED status, or an UNVERIFIED required-independence or "
                     "normative-identifier field, names no settling method",
        "prevents": "that an unverified item is presented as settled by omission",
    },
    "DO_REFUSED_INDEPENDENCE_UNSUPPORTED": {
        "condition": "a row claims independent review without a declared distinct trust "
                     "domain, or claims SATISFIED_WITH_EVIDENCE while its required "
                     "independence is unread or is held by the same party; or the "
                     "recorded party counts disagree with the project's independence record",
        "prevents": "that a same-party check, or an unread independence requirement, is "
                    "reported as independent satisfaction",
    },
    "DO_REFUSED_CERTIFICATION_CLAIM": {
        "condition": "the matrix, an objective row, or the document claims certification, "
                     "a development assurance level or an assurance level",
        "prevents": "that satisfying objectives is reported as certification",
    },
    "DO_REFUSED_MISSING_ITEM_OMITTED": {
        "condition": "a required missing item is absent from the register, an unmet "
                     "objective names no missing item, or a named missing item is not "
                     "registered or is referenced by no objective",
        "prevents": "that an unmet objective leaves its qualification or target-execution "
                    "gap unnamed",
    },
    "DO_REFUSED_MISSING_ITEM_WITHOUT_METHOD": {
        "condition": "a missing item states no reason or no settling method",
        "prevents": "that a gap is recorded as an unexplained absence",
    },
    "DO_REFUSED_NON_CLAIM_ABSENT": {
        "condition": "the matrix or the document omits that objective satisfaction is not "
                     "certification, or omits what the matrix does not establish",
        "prevents": "that a matrix of unmet objectives is read as a positive result",
    },
    "DO_REFUSED_DOCUMENT_DRIFT": {
        "condition": "the normative document does not name an objective, context, "
                     "exclusion, missing item or refusal code the machine record contains",
        "prevents": "that the prose and the machine record describe different matrices",
    },
    "DO_REFUSED_USAGE": {
        "condition": "the command line is malformed or names an unknown subcommand",
        "prevents": "that a refusal is read as a pass by exit-status confusion",
    },
}


class Refusal(Exception):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


def _reject_duplicate(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    seen: dict[str, Any] = {}
    for key, value in pairs:
        if key in seen:
            raise Refusal("DO_REFUSED_DUPLICATE_KEY", f"duplicate object key {key!r}")
        seen[key] = value
    return seen


def _reject_nonfinite(token: str) -> Any:
    raise Refusal("DO_REFUSED_SCHEMA", f"non-finite number {token!r}")


def load_json_strict(path: Path) -> Any:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise Refusal("DO_REFUSED_SCHEMA", f"{path}: unreadable: {exc}") from exc
    try:
        return json.loads(text, object_pairs_hook=_reject_duplicate,
                          parse_constant=_reject_nonfinite)
    except json.JSONDecodeError as exc:
        raise Refusal("DO_REFUSED_SCHEMA", f"{path}: malformed JSON: {exc}") from exc


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _list(value: Any) -> bool:
    return isinstance(value, list)


def _exists(repo: Path, relpath: str) -> bool:
    candidate = Path(relpath)
    if candidate.is_absolute() or ".." in candidate.parts or not relpath:
        return False
    return (repo / relpath).is_file()


def load_independence(repo: Path) -> dict[str, Any]:
    """The project's own independence summary, which a row may not outrun."""
    path = repo / INDEPENDENCE
    if not path.is_file():
        raise Refusal("DO_REFUSED_INDEPENDENCE_UNSUPPORTED",
                      f"the independence record {INDEPENDENCE} is absent")
    document = load_json_strict(path)
    summary = document.get("summary") if isinstance(document, dict) else None
    if not isinstance(summary, dict):
        raise Refusal("DO_REFUSED_INDEPENDENCE_UNSUPPORTED",
                      f"{INDEPENDENCE} records no summary")
    return summary


def validate_context(context: Any) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    if not isinstance(context, dict):
        return [("DO_REFUSED_CONTEXT_ABSENT", "system_context is not an object")]
    for field in ("id", "product", "statement"):
        if not _text(context.get(field)):
            out.append(("DO_REFUSED_CONTEXT_ABSENT", f"system_context.{field} is empty"))
    if context.get("scope_choice_not_compliance") is not True:
        out.append(("DO_REFUSED_CONTEXT_ABSENT",
                    "system_context does not state that the declaration is a scope "
                    "choice and not a compliance claim"))
    excludes = context.get("excludes")
    if not _list(excludes):
        return out + [("DO_REFUSED_CONTEXT_ABSENT", "system_context.excludes is not an array")]
    seen: dict[str, str] = {}
    for index, exclusion in enumerate(excludes):
        where = f"system_context.excludes[{index}]"
        if not isinstance(exclusion, dict):
            out.append(("DO_REFUSED_CONTEXT_ABSENT", f"{where}: not an object"))
            continue
        exclusion_id = exclusion.get("id")
        if not isinstance(exclusion_id, str) or not EXCLUSION_ID.match(exclusion_id):
            out.append(("DO_REFUSED_CONTEXT_ABSENT", f"{where}: bad id {exclusion_id!r}"))
            continue
        if exclusion_id in seen:
            out.append(("DO_REFUSED_CONTEXT_ABSENT", f"{where}: duplicate id {exclusion_id}"))
        seen[exclusion_id] = str(exclusion.get("category"))
        if not _text(exclusion.get("exclusion")):
            out.append(("DO_REFUSED_CONTEXT_ABSENT", f"{exclusion_id}: exclusion is empty"))
    for exclusion_id, category in MUST_EXCLUDE.items():
        if exclusion_id not in seen:
            out.append(("DO_REFUSED_CONTEXT_ABSENT",
                        f"the context does not exclude {category} ({exclusion_id})"))
        elif seen[exclusion_id] != category:
            out.append(("DO_REFUSED_CONTEXT_ABSENT",
                        f"{exclusion_id}: category is {seen[exclusion_id]!r}, "
                        f"expected {category!r}"))
    return out


def _validate_independence_record(
    record: Any, counts: dict[str, Any] | None
) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    if not isinstance(record, dict):
        return [("DO_REFUSED_SCHEMA", "independence_record is not an object")]
    for field in ("path", "statement"):
        if not _text(record.get(field)):
            out.append(("DO_REFUSED_SCHEMA", f"independence_record.{field} is empty"))
    for field in ("assignments", "same_party_adjudicator", "declared_parties",
                  "external_parties"):
        value = record.get(field)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            out.append(("DO_REFUSED_SCHEMA",
                        f"independence_record.{field} is not a non-negative integer"))
    if counts is not None:
        for field in ("assignments", "same_party_adjudicator", "declared_parties",
                      "external_parties"):
            if record.get(field) != counts.get(field):
                out.append(("DO_REFUSED_INDEPENDENCE_UNSUPPORTED",
                            f"independence_record.{field} is {record.get(field)!r}, "
                            f"the record holds {counts.get(field)!r}"))
    return out


def _evidence_problems(
    where: str, evidence: Any, status: str, repo: Path
) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    if not _list(evidence):
        return [("DO_REFUSED_SCHEMA", f"{where}: evidence is not an array")]
    for index, item in enumerate(evidence):
        spot = f"{where}.evidence[{index}]"
        if not isinstance(item, dict):
            out.append(("DO_REFUSED_SCHEMA", f"{spot}: not an object"))
            continue
        path = item.get("path")
        if not _text(path) or not _exists(repo, path):
            out.append(("DO_REFUSED_EVIDENCE_ABSENT",
                        f"{spot}: path {path!r} is not a file"))
        if item.get("kind") not in EVIDENCE_KINDS:
            out.append(("DO_REFUSED_SCHEMA", f"{spot}: kind {item.get('kind')!r}"))
        if not _text(item.get("check")):
            out.append(("DO_REFUSED_SCHEMA", f"{spot}: check is empty"))
    if status != "UNVERIFIED" and not evidence:
        out.append(("DO_REFUSED_STATUS_WITHOUT_EVIDENCE",
                    f"{where}: {status} with no evidence item"))
    if status == "SATISFIED_WITH_EVIDENCE":
        named = [item for item in evidence
                 if isinstance(item, dict) and item.get("kind") in EVIDENCE_KINDS
                 and _text(item.get("check"))]
        if not named:
            out.append(("DO_REFUSED_STATUS_WITHOUT_EVIDENCE",
                        f"{where}: SATISFIED_WITH_EVIDENCE cites no record or test"))
    return out


def _independence_problems(
    where: str,
    required: Any,
    held: Any,
    status: str,
    counts: dict[str, Any] | None,
    repo: Path,
) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    if not isinstance(required, dict):
        out.append(("DO_REFUSED_SCHEMA", f"{where}: required_independence is not an object"))
        required_state = None
    else:
        required_state = required.get("state")
        if required_state not in REQUIRED_INDEPENDENCE_STATES:
            out.append(("DO_REFUSED_SCHEMA",
                        f"{where}: required independence {required_state!r}"))
        elif not _text(required.get("basis")):
            out.append(("DO_REFUSED_SCHEMA", f"{where}: independence basis is empty"))
        if required_state == "UNVERIFIED" and not _text(required.get("settling_method")):
            out.append(("DO_REFUSED_UNVERIFIED_WITHOUT_METHOD",
                        f"{where}: required independence is UNVERIFIED with no method"))

    if not isinstance(held, dict):
        out.append(("DO_REFUSED_SCHEMA", f"{where}: independence_held is not an object"))
        return out
    held_state = held.get("state")
    if held_state not in HELD_INDEPENDENCE_STATES:
        out.append(("DO_REFUSED_SCHEMA", f"{where}: held independence {held_state!r}"))
        return out
    witness = held.get("witness")
    if not _text(witness) or not _exists(repo, witness):
        out.append(("DO_REFUSED_INDEPENDENCE_UNSUPPORTED",
                    f"{where}: held independence cites no readable witness"))

    if held_state == "INDEPENDENT":
        if not _text(held.get("trust_domain")):
            out.append(("DO_REFUSED_INDEPENDENCE_UNSUPPORTED",
                        f"{where}: independent review with no distinct trust domain"))
        external = held.get("external_parties")
        if not isinstance(external, int) or isinstance(external, bool) or external < 1:
            out.append(("DO_REFUSED_INDEPENDENCE_UNSUPPORTED",
                        f"{where}: independent review with no external party"))
        if held.get("distinct_from_author") is not True:
            out.append(("DO_REFUSED_INDEPENDENCE_UNSUPPORTED",
                        f"{where}: independent review not declared distinct from the author"))
        if counts is not None and counts.get("external_parties", 0) < 1:
            out.append(("DO_REFUSED_INDEPENDENCE_UNSUPPORTED",
                        f"{where}: claims independent review while the record holds "
                        f"{counts.get('external_parties')!r} external parties"))

    if status == "SATISFIED_WITH_EVIDENCE":
        if required_state == "UNVERIFIED":
            out.append(("DO_REFUSED_INDEPENDENCE_UNSUPPORTED",
                        f"{where}: satisfied while its independence requirement is unread"))
        elif required_state == "INDEPENDENT_REQUIRED" and held_state != "INDEPENDENT":
            out.append(("DO_REFUSED_INDEPENDENCE_UNSUPPORTED",
                        f"{where}: satisfied while a required independent check is "
                        f"held as {held_state}"))
    return out


def validate_matrix(
    doc: Any,
    repo: Path,
    independence: dict[str, Any] | None = None,
) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    if not isinstance(doc, dict):
        return [("DO_REFUSED_SCHEMA", "the matrix is not an object")]
    if doc.get("schema") != SCHEMA:
        out.append(("DO_REFUSED_SCHEMA", f"schema is {doc.get('schema')!r}"))
    if not SHA1_COMMIT.match(str(doc.get("base_commit", ""))):
        out.append(("DO_REFUSED_SCHEMA", "base_commit is not a 40-hex commit"))
    if doc.get("certification_claimed") is not False:
        out.append(("DO_REFUSED_CERTIFICATION_CLAIM",
                    "certification_claimed must be false"))
    if doc.get("dal_claimed") is not False:
        out.append(("DO_REFUSED_CERTIFICATION_CLAIM", "dal_claimed must be false"))
    if doc.get("assurance_level") is not None:
        out.append(("DO_REFUSED_CERTIFICATION_CLAIM",
                    "assurance_level must be null: no DO-178C level or DAL is assigned"))
    if doc.get("objective_satisfaction_only") is not True:
        out.append(("DO_REFUSED_CERTIFICATION_CLAIM",
                    "the matrix must record objective satisfaction only"))

    out.extend(validate_context(doc.get("system_context")))

    if independence is None:
        try:
            independence = load_independence(repo)
        except Refusal as refusal:
            out.append((refusal.code, refusal.detail))
            independence = None
    out.extend(_validate_independence_record(doc.get("independence_record"), independence))

    missing = doc.get("missing_items")
    registered: dict[str, Any] = {}
    if not _list(missing) or not missing:
        out.append(("DO_REFUSED_MISSING_ITEM_OMITTED",
                    "missing_items must be a non-empty array"))
        missing = []
    for index, item in enumerate(missing):
        where = f"missing_items[{index}]"
        if not isinstance(item, dict):
            out.append(("DO_REFUSED_SCHEMA", f"{where}: not an object"))
            continue
        item_id = item.get("id")
        if not isinstance(item_id, str) or not MISSING_ID.match(item_id):
            out.append(("DO_REFUSED_SCHEMA", f"{where}: bad id {item_id!r}"))
            continue
        if item_id in registered:
            out.append(("DO_REFUSED_SCHEMA", f"{where}: duplicate id {item_id}"))
        registered[item_id] = item
        for field in ("item", "why_required", "settling_method"):
            if not _text(item.get(field)):
                out.append(("DO_REFUSED_MISSING_ITEM_WITHOUT_METHOD",
                            f"{item_id}: {field} is empty"))
    for required in REQUIRED_MISSING:
        if required not in registered:
            out.append(("DO_REFUSED_MISSING_ITEM_OMITTED",
                        f"required missing item {required} is not registered"))

    objectives = doc.get("objectives")
    if not _list(objectives) or not objectives:
        return out + [("DO_REFUSED_SCHEMA",
                       "objectives must be a non-empty array")]
    ids: set[str] = set()
    referenced: set[str] = set()
    statuses: list[str] = []
    for index, row in enumerate(objectives):
        where = f"objectives[{index}]"
        if not isinstance(row, dict):
            out.append(("DO_REFUSED_SCHEMA", f"{where}: not an object"))
            continue
        row_id = row.get("id")
        if not isinstance(row_id, str) or not OBJECTIVE_ID.match(row_id):
            out.append(("DO_REFUSED_SCHEMA", f"{where}: bad id {row_id!r}"))
            continue
        if row_id in ids:
            out.append(("DO_REFUSED_SCHEMA", f"{where}: duplicate id {row_id}"))
        ids.add(row_id)
        for field in ("area", "substance", "substance_source", "basis"):
            if not _text(row.get(field)):
                out.append(("DO_REFUSED_SCHEMA", f"{row_id}: {field} is empty"))

        normative = row.get("normative_objective_ids")
        if normative == "UNVERIFIED":
            if not _text(row.get("normative_settling_method")):
                out.append(("DO_REFUSED_UNVERIFIED_WITHOUT_METHOD",
                            f"{row_id}: objective identifiers UNVERIFIED with no method"))
        elif not _list(normative) or not normative or \
                not all(_text(value) for value in normative):
            out.append(("DO_REFUSED_SCHEMA",
                        f"{row_id}: normative_objective_ids must be a non-empty list "
                        "or 'UNVERIFIED'"))

        status = row.get("status")
        if status not in STATUSES:
            out.append(("DO_REFUSED_SCHEMA", f"{row_id}: status {status!r}"))
            continue
        statuses.append(status)
        out.extend(_evidence_problems(row_id, row.get("evidence"), status, repo))
        if status == "UNVERIFIED" and not _text(row.get("settling_method")):
            out.append(("DO_REFUSED_UNVERIFIED_WITHOUT_METHOD",
                        f"{row_id}: UNVERIFIED status with no settling method"))

        out.extend(_independence_problems(
            row_id, row.get("required_independence"), row.get("independence_held"),
            status, independence, repo))

        blocked = row.get("blocked_by")
        if not _list(blocked):
            out.append(("DO_REFUSED_SCHEMA", f"{row_id}: blocked_by is not an array"))
        else:
            for item_id in blocked:
                if not isinstance(item_id, str) or item_id not in registered:
                    out.append(("DO_REFUSED_MISSING_ITEM_OMITTED",
                                f"{row_id}: blocked_by {item_id!r} is not registered"))
                else:
                    referenced.add(item_id)
            if status != "SATISFIED_WITH_EVIDENCE" and not blocked:
                out.append(("DO_REFUSED_MISSING_ITEM_OMITTED",
                            f"{row_id}: an unmet objective names no missing item"))

    for required in REQUIRED_MISSING:
        if required not in referenced:
            out.append(("DO_REFUSED_MISSING_ITEM_OMITTED",
                        f"missing item {required} is referenced by no objective"))

    non_claim = doc.get("non_claim")
    if not isinstance(non_claim, dict):
        out.append(("DO_REFUSED_NON_CLAIM_ABSENT", "non_claim is not an object"))
    else:
        statement = non_claim.get("statement")
        if not _text(statement) or "is not certification" not in statement:
            out.append(("DO_REFUSED_NON_CLAIM_ABSENT",
                        "the matrix does not state that objective satisfaction is not "
                        "certification"))
        establishes = non_claim.get("what_this_establishes")
        if not _text(establishes):
            out.append(("DO_REFUSED_NON_CLAIM_ABSENT",
                        "what_this_establishes is empty"))
        does_not = non_claim.get("what_this_does_not_establish")
        if not _list(does_not) or not does_not:
            out.append(("DO_REFUSED_NON_CLAIM_ABSENT",
                        "what_this_does_not_establish is empty"))
        else:
            blob = " ".join(str(item) for item in does_not)
            for token in ("certification", "DAL"):
                if token not in blob:
                    out.append(("DO_REFUSED_NON_CLAIM_ABSENT",
                                f"the non-claim does not name {token}"))

    return out


def validate_document(text: str, matrix: Any) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    if not text.strip():
        return [("DO_REFUSED_DOCUMENT_DRIFT", "the normative document is empty")]
    tokens: list[tuple[str, str]] = []
    if isinstance(matrix, dict):
        context = matrix.get("system_context")
        if isinstance(context, dict) and isinstance(context.get("id"), str):
            tokens.append(("context", context["id"]))
        for exclusion in context.get("excludes", []) if isinstance(context, dict) else []:
            if isinstance(exclusion, dict) and isinstance(exclusion.get("id"), str):
                tokens.append(("exclusion", exclusion["id"]))
        for row in matrix.get("objectives", []):
            if isinstance(row, dict) and isinstance(row.get("id"), str):
                tokens.append(("objective", row["id"]))
        for item in matrix.get("missing_items", []):
            if isinstance(item, dict) and isinstance(item.get("id"), str):
                tokens.append(("missing item", item["id"]))
    for code in REFUSALS:
        tokens.append(("code", code))
    for kind, token in tokens:
        if token not in text:
            out.append(("DO_REFUSED_DOCUMENT_DRIFT", f"{kind} {token} is not named"))

    if "is not certification" not in text:
        out.append(("DO_REFUSED_NON_CLAIM_ABSENT",
                    "the document omits that objective satisfaction is not certification"))
    for phrase in FORBIDDEN_CERTIFICATION_PHRASES:
        if phrase.lower() in text.lower():
            out.append(("DO_REFUSED_CERTIFICATION_CLAIM",
                        f"the document contains the certification claim {phrase!r}"))
    return out


def check(
    matrix: Any,
    document_text: str,
    repo: Path = REPO_ROOT,
    independence: dict[str, Any] | None = None,
) -> list[str]:
    problems: list[tuple[str, str]] = []
    problems.extend(validate_matrix(matrix, repo, independence))
    problems.extend(validate_document(document_text, matrix))
    return [f"{code}: {detail}" for code, detail in sorted(set(problems))]


def summary(matrix: dict[str, Any], independence: dict[str, Any] | None = None) -> dict[str, Any]:
    rows = [row for row in matrix.get("objectives", []) if isinstance(row, dict)]
    record = matrix.get("independence_record")
    record = record if isinstance(record, dict) else {}
    counts = {status: sum(1 for row in rows if row.get("status") == status)
              for status in STATUSES}
    return {
        "objectives": len(rows),
        "satisfied": counts["SATISFIED_WITH_EVIDENCE"],
        "partial": counts["PARTIAL"],
        "not_satisfied": counts["NOT_SATISFIED"],
        "unverified": counts["UNVERIFIED"],
        "missing_items": len([item for item in matrix.get("missing_items", [])
                              if isinstance(item, dict)]),
        "normative_ids_unverified": sum(
            1 for row in rows if row.get("normative_objective_ids") == "UNVERIFIED"),
        "independence_assignments": record.get("assignments"),
        "same_party_adjudicator": record.get("same_party_adjudicator"),
        "external_parties": record.get("external_parties"),
        "refusal_codes": len(REFUSALS),
    }


def _resolve(repo: Path, override: str | None, default: str) -> Path:
    return Path(override) if override else repo / default


def run_check(args: argparse.Namespace) -> int:
    repo = Path(args.repo_root).resolve() if args.repo_root else REPO_ROOT
    matrix = load_json_strict(_resolve(repo, args.matrix, MATRIX))
    document = _resolve(repo, args.document, DOCUMENT)
    try:
        text = document.read_text(encoding="utf-8")
    except OSError as exc:
        raise Refusal("DO_REFUSED_SCHEMA", f"{document}: unreadable: {exc}") from exc
    independence = load_independence(repo)
    refusals = check(matrix, text, repo, independence)
    counts = summary(matrix, independence)
    if args.json:
        print(json.dumps({"ok": not refusals, "refusals": refusals,
                          "summary": counts}, indent=2, sort_keys=True))
    else:
        for line in refusals:
            print(line)
        print("do178c: objectives={objectives} satisfied={satisfied} "
              "partial={partial} not_satisfied={not_satisfied} "
              "unverified={unverified} missing_items={missing_items} "
              "normative_unverified={normative_ids_unverified} codes={codes}".format(
                  codes=CODE_OK if not refusals else "REFUSED", **counts))
    return EXIT_OK if not refusals else EXIT_REFUSED


def run_inventory(args: argparse.Namespace) -> int:
    repo = Path(args.repo_root).resolve() if args.repo_root else REPO_ROOT
    matrix = load_json_strict(_resolve(repo, args.matrix, MATRIX))
    counts = summary(matrix)
    if args.json:
        print(json.dumps(counts, indent=2, sort_keys=True))
    else:
        print(" ".join(f"{key}={value}" for key, value in sorted(counts.items())))
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    sub = parser.add_subparsers(dest="command")
    for name, handler in (("check", run_check), ("inventory", run_inventory)):
        command = sub.add_parser(name)
        command.add_argument("--repo-root", default=None)
        command.add_argument("--matrix", default=None)
        command.add_argument("--document", default=None)
        command.add_argument("--json", action="store_true")
        command.set_defaults(handler=handler)
    args = parser.parse_args(argv)
    if not getattr(args, "handler", None):
        print(f"{CODE_USAGE}: a subcommand is required (check, inventory)")
        return EXIT_USAGE
    try:
        return args.handler(args)
    except Refusal as refusal:
        print(f"{refusal.code}: {refusal.detail}")
        return EXIT_REFUSED


if __name__ == "__main__":
    raise SystemExit(main())
