#!/usr/bin/env python3
"""intoto.py -- in-toto Statement v1 attestations that cannot outrun their records.

Why this tool exists
--------------------
An in-toto Statement v1 is the envelope this project emits. It has exactly three
mandatory parts:

  * ``_type`` -- the literal ``https://in-toto.io/Statement/v1``;
  * ``subject`` -- a non-empty list of ``{name, digest}``, where the digest is a
    **content** digest of the exact bytes of the named artefact;
  * ``predicateType`` and ``predicate`` -- what is asserted about the subject.

The statement is not evidence by itself. It is a typed pointer at a record, and
it is only honest when the predicate restates values the named record actually
admits. This module makes the two failure modes unavailable:

  * a subject whose digest is not the content digest of the bytes it names; and
  * a predicate that asserts more than the record behind it admits (the
    **no-upgrade rule**).

The rule
--------
A subject digest is computed from the bytes, never supplied by a caller. The
predicate is built from the record's own admitted values, and every value is
compared with a fresh reading of that record at emission and again at
verification. A stronger admission state, a resolution a delta does not record,
a member census over an aggregate, a verified instrument that is only
``RECORDED``, a suppression with no expiry and an evidence identity with no
digest are each refused with a stable code naming the wrong conclusion.

What this module does not do
----------------------------
It does not sign, wrap in DSSE, apply PAE or establish a trust root. A10 owns the
DSSE envelope and the pre-authentication encoding; A11 owns parser hardening and
A12 independent cryptographic verification. A bare statement is **not** a signed
attestation and is not admission of anything. The statement's type is in-toto's;
the predicate types are this project's own, versioned, and are used for every
non-SLSA claim. Genuine SLSA provenance would use the SLSA predicate type; no
statement here is a SLSA statement, so a SLSA predicate type is refused rather
than borrowed.

Usage
-----
    python3 forensics/tools/intoto.py emit <predicate> <out> [--subject PATH] [--select ID]
    python3 forensics/tools/intoto.py verify <statement> [--repo-root PATH]
    python3 forensics/tools/intoto.py subjects <path>...

Exit status: 0 for success, 1 for a refusal (the stable code is always printed),
2 for a usage error (``IT_USAGE`` is printed).

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

REPO_ROOT = Path(__file__).resolve().parents[2]

MODEL_ID = "a9/v1"
STATEMENTS_SCHEMA = "openssl-rs/a9/statements/1"
CONTROLS_SCHEMA = "openssl-rs/a9/controls/1"
TOOL_PATH = "forensics/tools/intoto.py"

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
DIGEST_ALGORITHM = "sha256"
SHA256_HEX = re.compile(r"\A[0-9a-f]{64}\Z")

EXIT_OK = 0
EXIT_REFUSED = 1
EXIT_USAGE = 2
CODE_OK = "IT_OK"
CODE_USAGE = "IT_USAGE"

# ---------------------------------------------------------------------------
# Refusal codes. Each is stable and names the wrong conclusion it prevents.
# ---------------------------------------------------------------------------

IT_REFUSED_TYPE = "IT_REFUSED_TYPE"
IT_REFUSED_MISSING_SUBJECT = "IT_REFUSED_MISSING_SUBJECT"
IT_REFUSED_SUBJECT_ABSENT = "IT_REFUSED_SUBJECT_ABSENT"
IT_REFUSED_SUBJECT_DIGEST_FORM = "IT_REFUSED_SUBJECT_DIGEST_FORM"
IT_REFUSED_SUBJECT_DIGEST_MISMATCH = "IT_REFUSED_SUBJECT_DIGEST_MISMATCH"
IT_REFUSED_DUPLICATE_SUBJECT = "IT_REFUSED_DUPLICATE_SUBJECT"
IT_REFUSED_PREDICATE_TYPE = "IT_REFUSED_PREDICATE_TYPE"
IT_REFUSED_PREDICATE_FIELD = "IT_REFUSED_PREDICATE_FIELD"
IT_REFUSED_CLAIM_UPGRADE = "IT_REFUSED_CLAIM_UPGRADE"
IT_REFUSED_RECORD_ABSENT = "IT_REFUSED_RECORD_ABSENT"
IT_REFUSED_RECORD_INADMISSIBLE = "IT_REFUSED_RECORD_INADMISSIBLE"
IT_REFUSED_STATEMENT_MUTATED = "IT_REFUSED_STATEMENT_MUTATED"

REFUSALS: dict[str, dict[str, str]] = {
    IT_REFUSED_TYPE: {
        "condition": "the document's `_type` is not https://in-toto.io/Statement/v1",
        "prevents": (
            "that a document of another type (a DSSE envelope, an in-toto v0.1 "
            "statement, a bare predicate) is read as a Statement v1"
        ),
    },
    IT_REFUSED_MISSING_SUBJECT: {
        "condition": "the statement has no subject, or a subject has no name",
        "prevents": (
            "that an attestation about nothing is read as an attestation about an "
            "artefact"
        ),
    },
    IT_REFUSED_SUBJECT_ABSENT: {
        "condition": "the subject file is not present when the digest is computed",
        "prevents": (
            "that a missing artefact is silently skipped or hashed as empty, so a "
            "statement names a file that does not exist"
        ),
    },
    IT_REFUSED_SUBJECT_DIGEST_FORM: {
        "condition": (
            "a subject digest names an algorithm other than sha256, or its value "
            "is not 64 lowercase hexadecimal characters"
        ),
        "prevents": (
            "that a Git object id, an abbreviated token or a non-hex string is read "
            "as a content digest of the bytes"
        ),
    },
    IT_REFUSED_SUBJECT_DIGEST_MISMATCH: {
        "condition": (
            "a subject digest differs from the bytes on disk, or the predicate "
            "names a record at a digest the statement does not carry"
        ),
        "prevents": (
            "that a statement names an artefact it has not hashed, or carries a "
            "digest taken at another moment"
        ),
    },
    IT_REFUSED_DUPLICATE_SUBJECT: {
        "condition": "two subjects have the same name",
        "prevents": (
            "that two different digests for one artefact are both read as its "
            "identity, with the reader choosing one"
        ),
    },
    IT_REFUSED_PREDICATE_TYPE: {
        "condition": (
            "the predicate type is not a registered project predicate, or a SLSA "
            "predicate type is used for a statement that is not SLSA provenance"
        ),
        "prevents": (
            "that an unversioned or borrowed predicate type makes a project claim "
            "look like an external specification's claim"
        ),
    },
    IT_REFUSED_PREDICATE_FIELD: {
        "condition": (
            "a required predicate field is missing or malformed, or a forbidden "
            "field is present"
        ),
        "prevents": (
            "that an absent field is defaulted, or that a field the predicate is "
            "not licensed to carry smuggles a second, weaker claim"
        ),
    },
    IT_REFUSED_CLAIM_UPGRADE: {
        "condition": (
            "the predicate asserts a state, count or identity the named record does "
            "not admit, including a stronger state of the same kind"
        ),
        "prevents": (
            "that a statement upgrades a record: COMPLETE over TRUNCATED_BOUNDED, "
            "RESOLVED over zero resolutions, a member census over an aggregate, a "
            "verified instrument over a RECORDED one, an ACTIVE suppression with no "
            "expiry, or an evidence identity with no digest"
        ),
    },
    IT_REFUSED_RECORD_ABSENT: {
        "condition": "the record a predicate would restate is not present",
        "prevents": (
            "that a statement is built from an absent record, which would assert a "
            "predicate with no source at all"
        ),
    },
    IT_REFUSED_RECORD_INADMISSIBLE: {
        "condition": (
            "the source record exists but fails its own admission (A5, A6 or A7), "
            "or disagrees with the declaration it claims to record"
        ),
        "prevents": (
            "that a statement launders a refused declaration into an admitted one, "
            "because the envelope looks authoritative"
        ),
    },
    IT_REFUSED_STATEMENT_MUTATED: {
        "condition": (
            "re-reading the emitted bytes does not reproduce the canonical "
            "statement this tool writes, or the document shape is not the emitted "
            "shape"
        ),
        "prevents": (
            "that a reordered, re-spaced or re-shaped document is verified as if it "
            "were the statement that was emitted"
        ),
    },
}

# ---------------------------------------------------------------------------
# The predicate registry. A registered type declares the fields it requires and
# the fields it forbids; `carries` is what the predicate is allowed to restate.
# ---------------------------------------------------------------------------

P_POPULATION = "https://openssl-rs.invalid/attestation/population/v1"
P_BASELINE_DELTA = "https://openssl-rs.invalid/attestation/baseline-delta/v1"
P_SARIF_EMISSION = "https://openssl-rs.invalid/attestation/sarif-emission/v1"
P_INSTRUMENT = "https://openssl-rs.invalid/attestation/instrument-qualification/v1"
P_SUPPRESSION = "https://openssl-rs.invalid/attestation/suppression/v1"

PREDICATES: dict[str, dict[str, Any]] = {
    P_POPULATION: {
        "short": "population",
        "required": (
            "population",
            "state",
            "declared",
            "examined",
            "omitted",
            "membersRecorded",
            "refusal",
            "record",
        ),
        "forbidden": ("verified", "resolved", "absent", "complete"),
        "carries": "the A5 admission of one declared population",
        "defaultSubject": "evidence/a5/ADMISSION.json",
        "select": "a population id",
    },
    P_BASELINE_DELTA: {
        "short": "baseline-delta",
        "required": (
            "delta",
            "dispositions",
            "records",
            "resolved",
            "admitted",
            "codes",
            "record",
        ),
        "forbidden": ("verified", "absent", "complete", "census"),
        "carries": "the A7 disposition of one delta",
        "defaultSubject": "evidence/a7/DELTA.json",
        "select": "a delta id",
    },
    P_SARIF_EMISSION: {
        "short": "sarif-emission",
        "required": ("sarifVersion", "schema", "runs", "results", "subset", "record"),
        "forbidden": (
            "census",
            "complete",
            "suppressions",
            "baselineState",
            "rank",
            "fixes",
        ),
        "carries": "the shape of one SARIF 2.1.0 log or shard",
        "defaultSubject": None,
        "select": "none",
    },
    P_INSTRUMENT: {
        "short": "instrument-qualification",
        "required": ("instrument", "status", "mode", "control", "record"),
        "forbidden": ("resolved", "absent", "complete", "census"),
        "carries": "one instrument's registered qualification status",
        "defaultSubject": "evidence/etp3/instruments.json",
        "select": "an instrument id",
    },
    P_SUPPRESSION: {
        "short": "suppression",
        "required": (
            "suppression",
            "disposition",
            "declaredDisposition",
            "target",
            "authorisedScope",
            "justification",
            "reviewer",
            "reviewerRecord",
            "policyBasis",
            "expiry",
            "record",
        ),
        "forbidden": ("resolved", "absent", "complete", "census"),
        "carries": "one A6 suppression and its disposition",
        "defaultSubject": "evidence/a6/SUPPRESSIONS.json",
        "select": "a suppression or record id",
    },
}

PREDICATE_BY_SHORT = {entry["short"]: kind for kind, entry in PREDICATES.items()}

ADMISSION_STATES = (
    "COMPLETE",
    "SAMPLED",
    "TRUNCATED_BOUNDED",
    "ABSENT",
    "EMPTY",
    "UNKNOWN",
    "AGGREGATE_ONLY",
    "DEFERRED",
)
OBSERVED_STATES = ("COMPLETE", "EMPTY", "SAMPLED", "TRUNCATED_BOUNDED")
DELTA_DISPOSITIONS = (
    "STILL_PRESENT",
    "RESOLVED",
    "MOVED",
    "NEW",
    "UNSCANNED_ABSENT",
    "TOOL_CHANGED_ABSENT",
    "EXCLUDED_ABSENT",
    "SUPPRESSED_ABSENT",
    "POPULATION_SHRUNK_ABSENT",
    "UNKNOWN",
)
INSTRUMENT_STATUSES = ("PASS", "RECORDED", "NOT_RUN")
SUPPRESSION_DISPOSITIONS = (
    "ACTIVE",
    "EXPIRED",
    "INVALIDATED",
    "NON_ACTIONABLE",
    "PENDING_REVIEW",
)


class Refusal(Exception):
    """A stable refusal code and the conclusion it prevents."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


def _fail(code: str, message: str) -> None:
    raise Refusal(code, message)


# ---------------------------------------------------------------------------
# Hashing and canonical bytes.
# ---------------------------------------------------------------------------


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_text(value: Any) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ) + "\n"


def encode(statement: Mapping[str, Any]) -> str:
    """The canonical bytes of a statement, as text: strict JSON plus newline."""
    document = dict(statement)
    _validate_document(document)
    return _canonical_text(document)


def dump_document(document: Mapping[str, Any]) -> str:
    """Canonical JSON for an evidence index or control record: indent 1, sorted."""
    return json.dumps(document, indent=1, sort_keys=True) + "\n"


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and SHA256_HEX.match(value) is not None


# ---------------------------------------------------------------------------
# Subjects.
# ---------------------------------------------------------------------------


def artifact_name(path: Path | str, repo_root: Path = REPO_ROOT) -> str:
    """The repo-relative POSIX name of an artefact, wherever it is invoked from."""
    given = Path(path)
    absolute = given if given.is_absolute() else (repo_root / given)
    try:
        return absolute.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return given.as_posix()


def subject_for(path: Path | str, *, repo_root: Path = REPO_ROOT) -> dict[str, Any]:
    """Build a subject by reading the bytes; a missing file is refused, not skipped.

    There is deliberately no argument for a caller-supplied digest: a digest that
    did not come from these bytes is not a subject of this statement.
    """
    given = Path(path)
    absolute = given if given.is_absolute() else (repo_root / given)
    if not absolute.is_file():
        _fail(
            IT_REFUSED_SUBJECT_ABSENT,
            f"{artifact_name(absolute, repo_root)}: the subject file is absent; "
            "a statement is not emitted for an artefact that is not present",
        )
    name = artifact_name(absolute, repo_root)
    return {"name": name, "digest": {DIGEST_ALGORITHM: sha256_bytes(absolute.read_bytes())}}


def _validate_digest_form(value: Any, where: str) -> str:
    if not isinstance(value, Mapping):
        _fail(
            IT_REFUSED_SUBJECT_DIGEST_FORM,
            f"{where}: a digest is an object mapping an algorithm to a hex value",
        )
    if set(value) != {DIGEST_ALGORITHM}:
        _fail(
            IT_REFUSED_SUBJECT_DIGEST_FORM,
            f"{where}: the only accepted digest algorithm is {DIGEST_ALGORITHM}; "
            f"got {sorted(map(str, value))}. A Git object id is not a content digest.",
        )
    digest = value[DIGEST_ALGORITHM]
    if not _is_sha256(digest):
        _fail(
            IT_REFUSED_SUBJECT_DIGEST_FORM,
            f"{where}: the {DIGEST_ALGORITHM} value must be 64 lowercase hex "
            f"characters; got {digest!r}",
        )
    return digest


def _validate_subjects(subjects: Any) -> list[dict[str, Any]]:
    if not isinstance(subjects, list) or not subjects:
        _fail(
            IT_REFUSED_MISSING_SUBJECT,
            "a Statement v1 must name at least one subject",
        )
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, subject in enumerate(subjects):
        where = f"subject[{index}]"
        if not isinstance(subject, Mapping):
            _fail(IT_REFUSED_MISSING_SUBJECT, f"{where}: a subject is an object")
        name = subject.get("name")
        if not isinstance(name, str) or not name.strip():
            _fail(IT_REFUSED_MISSING_SUBJECT, f"{where}: the subject has no name")
        if "digest" not in subject:
            _fail(
                IT_REFUSED_SUBJECT_DIGEST_FORM,
                f"{where} ({name}): the subject has no digest",
            )
        digest = _validate_digest_form(subject["digest"], f"{where} ({name})")
        if name in seen:
            _fail(
                IT_REFUSED_DUPLICATE_SUBJECT,
                f"two subjects are named {name!r}; one artefact has one digest in "
                "one statement",
            )
        seen.add(name)
        normalized.append(
            {"name": name, "digest": {DIGEST_ALGORITHM: digest}}
        )
    return normalized


def verify_subject_files(
    statement: Mapping[str, Any], repo_root: Path = REPO_ROOT
) -> None:
    """Recompute every subject digest from the bytes; any difference is refused."""
    subjects = statement.get("subject")
    if not isinstance(subjects, list) or not subjects:
        _fail(IT_REFUSED_MISSING_SUBJECT, "a statement must name at least one subject")
    for subject in subjects:
        name = subject.get("name")
        if not isinstance(name, str) or not name:
            _fail(IT_REFUSED_MISSING_SUBJECT, "a subject has no name")
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts:
            _fail(
                IT_REFUSED_SUBJECT_ABSENT,
                f"{name}: a subject name must be a repo-relative artefact path",
            )
        path = repo_root / relative
        if not path.is_file():
            _fail(
                IT_REFUSED_SUBJECT_ABSENT,
                f"{name}: the subject file is absent, so its digest cannot be "
                "recomputed",
            )
        actual = sha256_bytes(path.read_bytes())
        stated = _validate_digest_form(subject.get("digest"), f"subject ({name})")
        if actual != stated:
            _fail(
                IT_REFUSED_SUBJECT_DIGEST_MISMATCH,
                f"{name}: the bytes hash to {actual}, not the stated {stated}",
            )


def verify_subject(subject: Mapping[str, Any], repo_root: Path = REPO_ROOT) -> None:
    """Verify one caller-supplied subject against the bytes it names."""
    normalized = _validate_subjects([dict(subject)])
    verify_subject_files({"subject": normalized}, repo_root)


# ---------------------------------------------------------------------------
# Predicate shape.
# ---------------------------------------------------------------------------


def _validate_predicate_type(predicate_type: Any) -> None:
    if not isinstance(predicate_type, str):
        _fail(IT_REFUSED_PREDICATE_TYPE, "the predicate type is not a string")
    if predicate_type.startswith("https://slsa.dev/"):
        _fail(
            IT_REFUSED_PREDICATE_TYPE,
            f"{predicate_type}: this project emits no genuine SLSA provenance "
            "statement, so it does not borrow the SLSA predicate type; a versioned "
            "project predicate is used instead",
        )
    if predicate_type not in PREDICATES:
        _fail(
            IT_REFUSED_PREDICATE_TYPE,
            f"{predicate_type}: not a registered predicate type; registered: "
            + ", ".join(sorted(PREDICATES)),
        )


def _require_int(predicate: Mapping[str, Any], field: str, where: str) -> None:
    value = predicate[field]
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        _fail(IT_REFUSED_PREDICATE_FIELD, f"{where}: {field} must be a non-negative int")


def _validate_predicate_fields(
    predicate_type: str, predicate: Mapping[str, Any]
) -> None:
    spec = PREDICATES[predicate_type]
    where = spec["short"]
    missing = [field for field in spec["required"] if field not in predicate]
    if missing:
        _fail(
            IT_REFUSED_PREDICATE_FIELD,
            f"{where}: missing required field(s) {missing}; a missing field is "
            "refused, never defaulted",
        )
    forbidden = [field for field in spec["forbidden"] if field in predicate]
    if forbidden:
        _fail(
            IT_REFUSED_PREDICATE_FIELD,
            f"{where}: field(s) {forbidden} are not licensed by this predicate",
        )

    record = predicate["record"]
    if not isinstance(record, Mapping) or set(record) != {"path", "sha256"}:
        _fail(
            IT_REFUSED_PREDICATE_FIELD,
            f"{where}: `record` must be exactly {{path, sha256}}",
        )
    if not isinstance(record["path"], str) or not record["path"]:
        _fail(IT_REFUSED_PREDICATE_FIELD, f"{where}: record.path is not a path")
    if not _is_sha256(record["sha256"]):
        _fail(
            IT_REFUSED_PREDICATE_FIELD,
            f"{where}: record.sha256 must be a content digest",
        )

    if predicate_type == P_POPULATION:
        for field in ("state", "declared"):
            if predicate[field] not in ADMISSION_STATES:
                _fail(
                    IT_REFUSED_PREDICATE_FIELD,
                    f"{where}: {field} {predicate[field]!r} is not an A5 state",
                )
        for field in ("examined", "omitted"):
            value = predicate[field]
            if value != "unknown" and (
                not isinstance(value, int) or isinstance(value, bool) or value < 0
            ):
                _fail(
                    IT_REFUSED_PREDICATE_FIELD,
                    f"{where}: {field} must be a non-negative int or 'unknown'",
                )
        if not isinstance(predicate["membersRecorded"], bool):
            _fail(
                IT_REFUSED_PREDICATE_FIELD,
                f"{where}: membersRecorded must be a boolean",
            )
        if predicate["refusal"] is not None and not isinstance(
            predicate["refusal"], str
        ):
            _fail(IT_REFUSED_PREDICATE_FIELD, f"{where}: refusal is null or a code")
    elif predicate_type == P_BASELINE_DELTA:
        for field in ("records", "resolved"):
            _require_int(predicate, field, where)
        dispositions = predicate["dispositions"]
        if not isinstance(dispositions, Mapping):
            _fail(IT_REFUSED_PREDICATE_FIELD, f"{where}: dispositions is an object")
        for disposition, value in dispositions.items():
            if disposition not in DELTA_DISPOSITIONS:
                _fail(
                    IT_REFUSED_PREDICATE_FIELD,
                    f"{where}: unknown disposition {disposition!r}",
                )
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                _fail(
                    IT_REFUSED_PREDICATE_FIELD,
                    f"{where}: dispositions.{disposition} must be a non-negative int",
                )
        if sum(dispositions.values()) != predicate["records"]:
            _fail(
                IT_REFUSED_PREDICATE_FIELD,
                f"{where}: the dispositions do not sum to records",
            )
        if not isinstance(predicate["admitted"], bool):
            _fail(IT_REFUSED_PREDICATE_FIELD, f"{where}: admitted must be a boolean")
        codes = predicate["codes"]
        if not isinstance(codes, list) or not all(isinstance(c, str) for c in codes):
            _fail(IT_REFUSED_PREDICATE_FIELD, f"{where}: codes is a string array")
    elif predicate_type == P_SARIF_EMISSION:
        if not isinstance(predicate["sarifVersion"], str):
            _fail(IT_REFUSED_PREDICATE_FIELD, f"{where}: sarifVersion is a string")
        if not isinstance(predicate["schema"], str):
            _fail(IT_REFUSED_PREDICATE_FIELD, f"{where}: schema is a string")
        for field in ("runs", "results"):
            _require_int(predicate, field, where)
        if not isinstance(predicate["subset"], bool):
            _fail(IT_REFUSED_PREDICATE_FIELD, f"{where}: subset must be a boolean")
        if "parentResultCount" in predicate:
            _require_int(predicate, "parentResultCount", where)
        if "shard" in predicate:
            shard = predicate["shard"]
            if not isinstance(shard, Mapping):
                _fail(IT_REFUSED_PREDICATE_FIELD, f"{where}: shard is an object")
            for field in ("index", "total", "resultCount"):
                if not isinstance(shard.get(field), int):
                    _fail(
                        IT_REFUSED_PREDICATE_FIELD,
                        f"{where}: shard.{field} must be an int",
                    )
            if not _is_sha256(shard.get("parentDigest")):
                _fail(
                    IT_REFUSED_PREDICATE_FIELD,
                    f"{where}: shard.parentDigest must be a content digest",
                )
    elif predicate_type == P_INSTRUMENT:
        for field in ("instrument", "mode", "control"):
            if not isinstance(predicate[field], str):
                _fail(IT_REFUSED_PREDICATE_FIELD, f"{where}: {field} is a string")
        if predicate["status"] not in INSTRUMENT_STATUSES:
            _fail(
                IT_REFUSED_PREDICATE_FIELD,
                f"{where}: status {predicate['status']!r} is not one of "
                f"{INSTRUMENT_STATUSES}",
            )
        if "verified" in predicate and not isinstance(predicate["verified"], bool):
            _fail(IT_REFUSED_PREDICATE_FIELD, f"{where}: verified must be a boolean")
        if "binding" in predicate:
            binding = predicate["binding"]
            if not isinstance(binding, Mapping) or not isinstance(
                binding.get("path"), str
            ):
                _fail(IT_REFUSED_PREDICATE_FIELD, f"{where}: binding.path is a string")
            if not _is_sha256(binding.get("sha256")):
                _fail(
                    IT_REFUSED_PREDICATE_FIELD,
                    f"{where}: binding.sha256 must be a content digest",
                )
    elif predicate_type == P_SUPPRESSION:
        if predicate["disposition"] not in SUPPRESSION_DISPOSITIONS:
            _fail(
                IT_REFUSED_PREDICATE_FIELD,
                f"{where}: disposition {predicate['disposition']!r} is not an A6 "
                "disposition",
            )
        for field in (
            "suppression",
            "declaredDisposition",
            "authorisedScope",
            "policyBasis",
        ):
            if not isinstance(predicate[field], str):
                _fail(IT_REFUSED_PREDICATE_FIELD, f"{where}: {field} is a string")
        for field in ("justification", "reviewer", "reviewerRecord", "expiry"):
            if predicate[field] is not None and not isinstance(
                predicate[field], str
            ):
                _fail(
                    IT_REFUSED_PREDICATE_FIELD,
                    f"{where}: {field} is a string or null",
                )
        if not isinstance(predicate["target"], Mapping):
            _fail(IT_REFUSED_PREDICATE_FIELD, f"{where}: target is an object")
        if "codes" in predicate and (
            not isinstance(predicate["codes"], list)
            or not all(isinstance(code, str) for code in predicate["codes"])
        ):
            _fail(IT_REFUSED_PREDICATE_FIELD, f"{where}: codes is a string array")

    _check_evidence_identities(predicate)


def _check_evidence_identities(predicate: Mapping[str, Any]) -> None:
    """Every evidence identity must name a content digest, or it binds nothing."""
    evidence = predicate.get("evidence")
    if evidence is None:
        return
    if not isinstance(evidence, list):
        _fail(IT_REFUSED_CLAIM_UPGRADE, "evidence must be a list of identities")
    for index, item in enumerate(evidence):
        if not isinstance(item, Mapping) or not isinstance(item.get("path"), str):
            _fail(
                IT_REFUSED_CLAIM_UPGRADE,
                f"evidence[{index}]: an evidence identity names a path",
            )
        if not _is_sha256(item.get("sha256")):
            _fail(
                IT_REFUSED_CLAIM_UPGRADE,
                f"evidence[{index}] ({item.get('path')}): the identity names no "
                "content digest, so it binds no bytes",
            )


def _check_structural(predicate_type: str, predicate: Mapping[str, Any]) -> None:
    """Refuse a predicate that is internally an upgrade, without the record."""
    if predicate_type == P_POPULATION:
        state = predicate["state"]
        members_recorded = predicate["membersRecorded"]
        if predicate.get("census") is True and (
            state != "COMPLETE" or not members_recorded
        ):
            _fail(
                IT_REFUSED_CLAIM_UPGRADE,
                f"a census is claimed over a record admitted at {state} with "
                f"membersRecorded={members_recorded}; an aggregate is not a census",
            )
        if "members" in predicate:
            if state != "COMPLETE" or not members_recorded:
                _fail(
                    IT_REFUSED_CLAIM_UPGRADE,
                    f"member identities are claimed over a record admitted at "
                    f"{state}; the record names no census",
                )
            if not isinstance(predicate["members"], list):
                _fail(
                    IT_REFUSED_PREDICATE_FIELD, "members must be a list of identities"
                )
            if len(predicate["members"]) != predicate["examined"]:
                _fail(
                    IT_REFUSED_CLAIM_UPGRADE,
                    "the member list length is not the examined count",
                )
    elif predicate_type == P_BASELINE_DELTA:
        resolved = predicate["dispositions"].get("RESOLVED", 0)
        if predicate["resolved"] != resolved:
            _fail(
                IT_REFUSED_CLAIM_UPGRADE,
                f"resolved={predicate['resolved']} disagrees with the RESOLVED "
                f"disposition count {resolved}",
            )
        if resolved > 0 and not predicate["admitted"]:
            _fail(
                IT_REFUSED_CLAIM_UPGRADE,
                "a refused delta is presented with resolutions",
            )
    elif predicate_type == P_INSTRUMENT:
        if predicate.get("verified") is True and predicate["status"] != "PASS":
            _fail(
                IT_REFUSED_CLAIM_UPGRADE,
                f"the instrument is recorded as {predicate['status']} but the "
                "predicate calls it verified",
            )
    elif predicate_type == P_SUPPRESSION:
        if predicate["disposition"] == "ACTIVE" and predicate["expiry"] in (
            None,
            "",
        ):
            _fail(
                IT_REFUSED_CLAIM_UPGRADE,
                "an ACTIVE suppression with no expiry and no explicit unbounded "
                "claim is presented as in force",
            )
        if predicate.get("resolved") is True or predicate.get("absent") is True:
            _fail(
                IT_REFUSED_CLAIM_UPGRADE,
                "a suppression disposes of a finding; it never resolves it or makes "
                "it absent",
            )
    elif predicate_type == P_SARIF_EMISSION:
        if not isinstance(predicate["subset"], bool):
            _fail(IT_REFUSED_PREDICATE_FIELD, "subset must be a boolean")


def _check_record_binding(
    subjects: list[dict[str, Any]], predicate: Mapping[str, Any]
) -> None:
    record = predicate["record"]
    matching = [s for s in subjects if s["name"] == record["path"]]
    if not matching:
        _fail(
            IT_REFUSED_SUBJECT_DIGEST_MISMATCH,
            f"the predicate names record {record['path']} but the statement has no "
            "subject with that name: a statement must not name an artefact it has "
            "not hashed",
        )
    if matching[0]["digest"][DIGEST_ALGORITHM] != record["sha256"]:
        _fail(
            IT_REFUSED_SUBJECT_DIGEST_MISMATCH,
            f"the predicate names {record['path']} at a digest the statement does "
            "not carry",
        )


# ---------------------------------------------------------------------------
# Statement construction and decoding.
# ---------------------------------------------------------------------------


def statement(
    subjects: Any, predicate_type: Any, predicate: Any
) -> dict[str, Any]:
    """Build and validate a Statement v1; nothing unvalidated is returned."""
    normalized = _validate_subjects(subjects)
    _validate_predicate_type(predicate_type)
    if not isinstance(predicate, Mapping):
        _fail(IT_REFUSED_PREDICATE_FIELD, "the predicate is an object")
    _validate_predicate_fields(predicate_type, predicate)
    _check_structural(predicate_type, predicate)
    _check_record_binding(normalized, predicate)
    return {
        "_type": STATEMENT_TYPE,
        "subject": normalized,
        "predicateType": predicate_type,
        "predicate": dict(predicate),
    }


def _validate_document(document: Any) -> None:
    if not isinstance(document, Mapping):
        _fail(IT_REFUSED_STATEMENT_MUTATED, "a statement is a JSON object")
    if set(document) != {"_type", "subject", "predicateType", "predicate"}:
        _fail(
            IT_REFUSED_STATEMENT_MUTATED,
            "the document has fields this tool does not emit: "
            f"{sorted(map(str, document))}",
        )
    if document["_type"] != STATEMENT_TYPE:
        _fail(
            IT_REFUSED_TYPE,
            f"_type is {document['_type']!r}, not {STATEMENT_TYPE!r}",
        )
    normalized = _validate_subjects(document["subject"])
    if normalized != document["subject"]:
        _fail(
            IT_REFUSED_STATEMENT_MUTATED,
            "the subject list is not the normalized list this tool emits",
        )
    predicate_type = document["predicateType"]
    _validate_predicate_type(predicate_type)
    predicate = document["predicate"]
    if not isinstance(predicate, Mapping):
        _fail(IT_REFUSED_PREDICATE_FIELD, "the predicate is an object")
    _validate_predicate_fields(predicate_type, predicate)
    _check_structural(predicate_type, predicate)
    _check_record_binding(normalized, predicate)


def decode(data: bytes | str, repo_root: Path | None = REPO_ROOT) -> dict[str, Any]:
    """Parse canonical statement bytes and refuse a non-canonical or mutated one.

    The bytes must be exactly what `encode` writes: re-serialising the parsed
    document must reproduce them byte for byte. The subject files are re-hashed
    as well, so a canonical document carrying a digest that is not of the bytes
    is refused. Pass `repo_root=None` only when the statement is not about files
    in this repository.
    """
    raw = data.encode("utf-8") if isinstance(data, str) else bytes(data)
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        _fail(
            IT_REFUSED_STATEMENT_MUTATED,
            f"the bytes are not the JSON this tool emits: {error}",
        )
    canonical = _canonical_text(document)
    if canonical.encode("utf-8") != raw:
        _fail(
            IT_REFUSED_STATEMENT_MUTATED,
            "re-reading the emitted bytes yields a different canonical statement: "
            "the document is reordered, re-spaced or otherwise not the emitted form",
        )
    _validate_document(document)
    if repo_root is not None:
        verify_subject_files(document, repo_root)
    return document


# ---------------------------------------------------------------------------
# Record readers. Every value a predicate carries is read here; nothing is typed.
# ---------------------------------------------------------------------------


def _record_path(repo_root: Path, record_path: str) -> tuple[str, Path]:
    relative = Path(record_path)
    if relative.is_absolute() or ".." in relative.parts:
        _fail(
            IT_REFUSED_RECORD_ABSENT,
            f"{record_path}: the record path must be repo-relative",
        )
    return relative.as_posix(), repo_root / relative


def read_record(
    repo_root: Path, record_path: str
) -> tuple[str, bytes, Any, dict[str, str]]:
    relative, path = _record_path(repo_root, record_path)
    if not path.is_file():
        _fail(
            IT_REFUSED_RECORD_ABSENT,
            f"{relative}: the record is absent; a statement is not built from a "
            "record that does not exist",
        )
    raw = path.read_bytes()
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        _fail(
            IT_REFUSED_RECORD_INADMISSIBLE,
            f"{relative}: the source record is not JSON: {error}",
        )
    block = {"path": relative, "sha256": sha256_bytes(raw)}
    return relative, raw, document, block


def _require(mapping: Any, field: str, where: str) -> Any:
    if not isinstance(mapping, Mapping) or field not in mapping:
        _fail(
            IT_REFUSED_RECORD_INADMISSIBLE,
            f"{where}: the source record does not state {field!r}",
        )
    return mapping[field]


def _find(items: Any, field: str, value: str, where: str) -> Mapping[str, Any]:
    if not isinstance(items, list):
        _fail(IT_REFUSED_RECORD_INADMISSIBLE, f"{where}: no list of records")
    for item in items:
        if isinstance(item, Mapping) and item.get(field) == value:
            return item
    _fail(
        IT_REFUSED_RECORD_INADMISSIBLE,
        f"{where}: the record names no {field} {value!r}",
    )


def _rederive_population(
    repo_root: Path, population_id: str
) -> tuple[str, str | None] | None:
    """Admit the A5 declaration afresh, so a tampered admission record is caught."""
    declaration = repo_root / "evidence" / "a5" / "POPULATIONS.json"
    if not declaration.is_file():
        return None
    tools = str(Path(__file__).resolve().parent)
    if tools not in sys.path:
        sys.path.insert(0, tools)
    import completeness  # noqa: PLC0415 -- one heavy import, only when proving A5

    try:
        populations = completeness.build_populations(repo_root)
        population = next(
            (p for p in populations if p.id == population_id), None
        )
        if population is None:
            _fail(
                IT_REFUSED_RECORD_INADMISSIBLE,
                f"the A5 declaration names no population {population_id!r}",
            )
        admission = completeness.admit(population)
    except Refusal:
        raise
    except Exception as error:  # the declaration itself could not be re-read
        _fail(
            IT_REFUSED_RECORD_INADMISSIBLE,
            f"the A5 declaration could not be re-derived: {error}",
        )
    return admission.state, admission.refusal


def population_entry(
    repo_root: Path, record_path: str, population_id: str
) -> dict[str, Any]:
    """The recorded admission entry, before any admission check is applied."""
    relative, _raw, document, block = read_record(repo_root, record_path)
    entry = _find(
        _require(document, "populations", relative),
        "id",
        population_id,
        relative,
    )
    return {
        "population": population_id,
        "state": _require(entry, "state", relative),
        "declared": _require(entry, "declared", relative),
        "examined": _require(entry, "examined", relative),
        "omitted": _require(entry, "omitted", relative),
        "membersRecorded": _require(entry, "membersRecorded", relative),
        "refusal": _require(entry, "refusal", relative),
        "record": block,
    }


def population_facts(
    repo_root: Path, record_path: str, population_id: str
) -> dict[str, Any]:
    facts = population_entry(repo_root, record_path, population_id)
    if facts["state"] not in ADMISSION_STATES:
        _fail(
            IT_REFUSED_RECORD_INADMISSIBLE,
            f"{facts['record']['path']}: {population_id} states an unknown "
            f"admission state {facts['state']!r}",
        )
    derived = _rederive_population(repo_root, population_id)
    if derived is not None:
        state, refusal = derived
        if refusal is not None:
            _fail(
                IT_REFUSED_RECORD_INADMISSIBLE,
                f"{population_id}: the declaration is refused {refusal}; an "
                "inadmissible declaration is not attested",
            )
        if state != facts["state"]:
            _fail(
                IT_REFUSED_RECORD_INADMISSIBLE,
                f"{population_id}: the admission record states {facts['state']} but "
                f"the declaration is admitted at {state}",
            )
    if facts["refusal"] is not None:
        _fail(
            IT_REFUSED_RECORD_INADMISSIBLE,
            f"{population_id}: the record itself refuses the declaration "
            f"({facts['refusal']}); it is not attested",
        )
    return facts


def _same(predicate: Mapping[str, Any], facts: Mapping[str, Any], field: str) -> None:
    if predicate.get(field) != facts.get(field):
        _fail(
            IT_REFUSED_CLAIM_UPGRADE,
            f"the predicate states {field}={predicate.get(field)!r}; the record "
            f"states {facts.get(field)!r}",
        )


def check_population(
    predicate: Mapping[str, Any], facts: Mapping[str, Any]
) -> None:
    """Refuse any population value the record does not admit."""
    for field in (
        "population",
        "state",
        "declared",
        "examined",
        "omitted",
        "membersRecorded",
        "refusal",
    ):
        _same(predicate, facts, field)
    if predicate.get("census") is True and (
        facts["state"] != "COMPLETE" or not facts["membersRecorded"]
    ):
        _fail(
            IT_REFUSED_CLAIM_UPGRADE,
            f"a census is claimed over a record admitted at {facts['state']} with "
            f"membersRecorded={facts['membersRecorded']}; an aggregate cannot "
            "support a member census",
        )
    if "members" in predicate:
        if facts["state"] != "COMPLETE" or not facts["membersRecorded"]:
            _fail(
                IT_REFUSED_CLAIM_UPGRADE,
                f"member identities are claimed over a record admitted at "
                f"{facts['state']}",
            )
        if len(predicate["members"]) != facts["examined"]:
            _fail(
                IT_REFUSED_CLAIM_UPGRADE,
                "the member list length is not the record's examined count",
            )
    _check_evidence_identities(predicate)


def population_predicate(
    repo_root: Path,
    record_path: str,
    population_id: str,
    asserted: Mapping[str, Any] | None = None,
    *,
    require_observed: bool = True,
) -> dict[str, Any]:
    facts = population_facts(repo_root, record_path, population_id)
    if require_observed and facts["state"] not in OBSERVED_STATES:
        _fail(
            IT_REFUSED_CLAIM_UPGRADE,
            f"{population_id}: admitted at {facts['state']}, which licenses no "
            "population statement; only the admission record can state it",
        )
    predicate = dict(facts)
    if asserted:
        predicate.update(asserted)
    check_population(predicate, facts)
    return predicate


def delta_facts(
    repo_root: Path, record_path: str, delta_id: str
) -> dict[str, Any]:
    relative, _raw, document, block = read_record(repo_root, record_path)
    entry = _find(_require(document, "deltas", relative), "id", delta_id, relative)
    counts = _require(entry, "counts", relative)
    if not isinstance(counts, Mapping):
        _fail(IT_REFUSED_RECORD_INADMISSIBLE, f"{relative}: {delta_id}: no counts")
    dispositions = {}
    for disposition in DELTA_DISPOSITIONS:
        value = counts.get(disposition, 0)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            _fail(
                IT_REFUSED_RECORD_INADMISSIBLE,
                f"{relative}: {delta_id}: disposition {disposition} is not a count",
            )
        dispositions[disposition] = value
    admitted = _require(entry, "admitted", relative)
    codes = _require(entry, "codes", relative)
    if not isinstance(admitted, bool):
        _fail(IT_REFUSED_RECORD_INADMISSIBLE, f"{relative}: {delta_id}: admitted is not a boolean")
    if not isinstance(codes, list) or not all(isinstance(c, str) for c in codes):
        _fail(IT_REFUSED_RECORD_INADMISSIBLE, f"{relative}: {delta_id}: codes is not a list")
    if admitted and codes:
        _fail(
            IT_REFUSED_RECORD_INADMISSIBLE,
            f"{relative}: {delta_id}: the delta is admitted but carries refusal "
            f"codes {codes}",
        )
    if not admitted and not codes:
        _fail(
            IT_REFUSED_RECORD_INADMISSIBLE,
            f"{relative}: {delta_id}: the delta is refused but names no code",
        )
    return {
        "delta": delta_id,
        "dispositions": dispositions,
        "records": sum(dispositions.values()),
        "resolved": dispositions["RESOLVED"],
        "admitted": admitted,
        "codes": list(codes),
        "record": block,
    }


def check_delta(predicate: Mapping[str, Any], facts: Mapping[str, Any]) -> None:
    for field in ("delta", "dispositions", "records", "resolved", "admitted", "codes"):
        _same(predicate, facts, field)
    _check_evidence_identities(predicate)


def delta_predicate(
    repo_root: Path,
    record_path: str,
    delta_id: str,
    asserted: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    facts = delta_facts(repo_root, record_path, delta_id)
    predicate = dict(facts)
    if asserted:
        predicate.update(asserted)
    check_delta(predicate, facts)
    return predicate


def sarif_facts(repo_root: Path, record_path: str) -> dict[str, Any]:
    relative, _raw, document, block = read_record(repo_root, record_path)
    version = _require(document, "version", relative)
    schema = _require(document, "$schema", relative)
    if version != "2.1.0" or not isinstance(schema, str) or not schema.startswith(
        "https://docs.oasis-open.org/sarif/"
    ):
        _fail(
            IT_REFUSED_RECORD_INADMISSIBLE,
            f"{relative}: not a SARIF 2.1.0 log (version={version!r})",
        )
    runs = _require(document, "runs", relative)
    if not isinstance(runs, list) or not runs:
        _fail(IT_REFUSED_RECORD_INADMISSIBLE, f"{relative}: no runs")
    results = 0
    for run in runs:
        if not isinstance(run, Mapping) or not isinstance(run.get("results", []), list):
            _fail(IT_REFUSED_RECORD_INADMISSIBLE, f"{relative}: a run has no result list")
        results += len(run.get("results", []))
    properties = document.get("properties")
    shard = properties.get("shard") if isinstance(properties, Mapping) else None
    facts: dict[str, Any] = {
        "sarifVersion": version,
        "schema": schema,
        "runs": len(runs),
        "results": results,
        "subset": shard is not None,
        "record": block,
    }
    if shard is not None:
        if not isinstance(shard, Mapping):
            _fail(IT_REFUSED_RECORD_INADMISSIBLE, f"{relative}: shard is not an object")
        for field in ("index", "total", "resultCount"):
            if not isinstance(shard.get(field), int):
                _fail(
                    IT_REFUSED_RECORD_INADMISSIBLE,
                    f"{relative}: shard.{field} is not an int",
                )
        if not _is_sha256(shard.get("parentDigest")):
            _fail(
                IT_REFUSED_RECORD_INADMISSIBLE,
                f"{relative}: shard.parentDigest is not a content digest",
            )
        if shard["resultCount"] != results:
            _fail(
                IT_REFUSED_RECORD_INADMISSIBLE,
                f"{relative}: the shard property states {shard['resultCount']} "
                f"results but the log holds {results}",
            )
        facts["parentResultCount"] = shard.get("parentResultCount")
        facts["shard"] = {
            "index": shard["index"],
            "total": shard["total"],
            "resultCount": shard["resultCount"],
            "parentDigest": shard["parentDigest"],
        }
    return facts


def check_sarif(predicate: Mapping[str, Any], facts: Mapping[str, Any]) -> None:
    for field in ("sarifVersion", "schema", "runs", "results", "subset"):
        _same(predicate, facts, field)
    if facts["subset"] and predicate.get("subset") is False:
        _fail(
            IT_REFUSED_CLAIM_UPGRADE,
            "a shard is presented as the parent population",
        )
    if predicate.get("results", 0) > facts["results"]:
        _fail(
            IT_REFUSED_CLAIM_UPGRADE,
            f"the predicate claims {predicate['results']} results but the log holds "
            f"{facts['results']}",
        )
    if "parentResultCount" in facts:
        if predicate.get("parentResultCount") != facts["parentResultCount"]:
            _fail(
                IT_REFUSED_CLAIM_UPGRADE,
                "the predicate's parentResultCount is not the shard's recorded "
                "parent population",
            )
    if "shard" in predicate:
        if predicate.get("shard") != facts.get("shard"):
            _fail(
                IT_REFUSED_CLAIM_UPGRADE,
                "the predicate's shard block is not the recorded shard block",
            )
    _check_evidence_identities(predicate)


def sarif_predicate(
    repo_root: Path,
    record_path: str,
    asserted: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    facts = sarif_facts(repo_root, record_path)
    predicate = dict(facts)
    if asserted:
        predicate.update(asserted)
    check_sarif(predicate, facts)
    return predicate


def instrument_facts(
    repo_root: Path, record_path: str, instrument_id: str
) -> dict[str, Any]:
    relative, _raw, document, block = read_record(repo_root, record_path)
    entry = _find(
        _require(document, "instruments", relative),
        "id",
        instrument_id,
        relative,
    )
    control = _require(entry, "sensitivity_control", relative)
    if not isinstance(control, Mapping):
        _fail(
            IT_REFUSED_RECORD_INADMISSIBLE,
            f"{relative}: {instrument_id}: no sensitivity control",
        )
    status = _require(control, "status", relative)
    mode = _require(control, "mode", relative)
    if status not in INSTRUMENT_STATUSES:
        _fail(
            IT_REFUSED_RECORD_INADMISSIBLE,
            f"{relative}: {instrument_id}: status {status!r} is not a registered "
            "status",
        )
    control_name = control.get("control_id")
    if not isinstance(control_name, str):
        binding = control.get("binding")
        if isinstance(binding, Mapping) and isinstance(binding.get("path"), str):
            control_name = "recorded:" + binding["path"]
        else:
            control_name = ""
    facts: dict[str, Any] = {
        "instrument": instrument_id,
        "status": status,
        "mode": mode,
        "control": control_name,
        "record": block,
    }
    binding = control.get("binding")
    if isinstance(binding, Mapping):
        facts["binding"] = {
            "path": binding.get("path"),
            "sha256": binding.get("sha256"),
        }
    return facts


def check_instrument(
    predicate: Mapping[str, Any], facts: Mapping[str, Any]
) -> None:
    for field in ("instrument", "status", "mode", "control"):
        _same(predicate, facts, field)
    if predicate.get("verified") is True and facts["status"] != "PASS":
        _fail(
            IT_REFUSED_CLAIM_UPGRADE,
            f"{facts['instrument']} is recorded as {facts['status']}; it is not "
            "verified",
        )
    if "binding" in predicate and predicate.get("binding") != facts.get("binding"):
        _fail(
            IT_REFUSED_CLAIM_UPGRADE,
            "the predicate's control binding is not the recorded binding",
        )
    _check_evidence_identities(predicate)


def instrument_predicate(
    repo_root: Path,
    record_path: str,
    instrument_id: str,
    asserted: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    facts = instrument_facts(repo_root, record_path, instrument_id)
    predicate = dict(facts)
    if asserted:
        predicate.update(asserted)
    check_instrument(predicate, facts)
    return predicate


def suppression_facts(
    repo_root: Path, record_path: str, suppression_id: str
) -> dict[str, Any]:
    relative, _raw, document, block = read_record(repo_root, record_path)
    entry = _find(
        _require(document, "records", relative),
        "id",
        suppression_id,
        relative,
    )
    if entry.get("classification") != "suppression":
        _fail(
            IT_REFUSED_RECORD_INADMISSIBLE,
            f"{relative}: {suppression_id}: the record is classified "
            f"{entry.get('classification')!r}, not a suppression",
        )
    admission = _find(
        _require(document, "admissions", relative),
        "id",
        suppression_id,
        relative,
    )
    disposition = _require(admission, "disposition", relative)
    if disposition not in SUPPRESSION_DISPOSITIONS:
        _fail(
            IT_REFUSED_RECORD_INADMISSIBLE,
            f"{relative}: {suppression_id}: disposition {disposition!r} is not an "
            "A6 disposition",
        )
    expiry = entry.get("expiresAt")
    if expiry in (None, "") and entry.get("unbounded") is True:
        expiry = "unbounded"
    return {
        "suppression": suppression_id,
        "disposition": disposition,
        "declaredDisposition": _require(entry, "declaredDisposition", relative),
        "target": _require(entry, "target", relative),
        "authorisedScope": _require(entry, "authorisedScope", relative),
        "justification": entry.get("justification"),
        "reviewer": entry.get("reviewer"),
        "reviewerRecord": entry.get("reviewerRecordedIn"),
        "policyBasis": _require(entry, "policyBasis", relative),
        "expiry": expiry,
        "memberCount": entry.get("memberCount"),
        "membersRecorded": entry.get("membersRecorded"),
        "codes": list(admission.get("codes", [])),
        "record": block,
    }


def check_suppression(
    predicate: Mapping[str, Any], facts: Mapping[str, Any]
) -> None:
    for field in (
        "suppression",
        "disposition",
        "declaredDisposition",
        "target",
        "authorisedScope",
        "justification",
        "reviewer",
        "reviewerRecord",
        "policyBasis",
        "expiry",
    ):
        _same(predicate, facts, field)
    if predicate.get("disposition") == "ACTIVE":
        if facts["disposition"] != "ACTIVE":
            _fail(
                IT_REFUSED_CLAIM_UPGRADE,
                f"{facts['suppression']} is {facts['disposition']}; an ACTIVE "
                "suppression is claimed over a refused record",
            )
        if predicate.get("expiry") in (None, ""):
            _fail(
                IT_REFUSED_CLAIM_UPGRADE,
                f"{facts['suppression']}: an ACTIVE suppression with no expiry and "
                "no explicit unbounded claim",
            )
    if predicate.get("resolved") is True or predicate.get("absent") is True:
        _fail(
            IT_REFUSED_CLAIM_UPGRADE,
            "a suppression never resolves a finding and never makes it absent",
        )
    _check_evidence_identities(predicate)


def suppression_predicate(
    repo_root: Path,
    record_path: str,
    suppression_id: str,
    asserted: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    facts = suppression_facts(repo_root, record_path, suppression_id)
    predicate = dict(facts)
    if asserted:
        predicate.update(asserted)
    check_suppression(predicate, facts)
    return predicate


# ---------------------------------------------------------------------------
# Verification: re-read the record and refuse a predicate it does not support.
# ---------------------------------------------------------------------------


def _reduce(facts: Mapping[str, Any], fields: Iterable[str]) -> dict[str, Any]:
    return {field: facts.get(field) for field in fields}


def verify_statement(
    data: bytes | str, repo_root: Path = REPO_ROOT
) -> dict[str, Any]:
    """Decode a statement, re-hash its subjects and re-derive its predicate."""
    document = decode(data, repo_root)
    predicate_type = document["predicateType"]
    predicate = document["predicate"]
    record = predicate["record"]
    relative = record["path"]

    if predicate_type == P_POPULATION:
        facts = population_facts(repo_root, relative, predicate["population"])
        check_population(predicate, facts)
        summary = _reduce(
            facts, ("population", "state", "declared", "examined", "omitted")
        )
    elif predicate_type == P_BASELINE_DELTA:
        facts = delta_facts(repo_root, relative, predicate["delta"])
        check_delta(predicate, facts)
        summary = _reduce(facts, ("delta", "records", "resolved", "admitted"))
    elif predicate_type == P_SARIF_EMISSION:
        facts = sarif_facts(repo_root, relative)
        check_sarif(predicate, facts)
        summary = _reduce(facts, ("runs", "results", "subset"))
    elif predicate_type == P_INSTRUMENT:
        facts = instrument_facts(repo_root, relative, predicate["instrument"])
        check_instrument(predicate, facts)
        summary = _reduce(facts, ("instrument", "status", "mode"))
    elif predicate_type == P_SUPPRESSION:
        facts = suppression_facts(repo_root, relative, predicate["suppression"])
        check_suppression(predicate, facts)
        summary = _reduce(facts, ("suppression", "disposition", "expiry"))
    else:  # pragma: no cover -- _validate_predicate_type already refused this
        _fail(IT_REFUSED_PREDICATE_TYPE, f"{predicate_type}: not registered")

    return {
        "subject": document["subject"][0]["name"],
        "sha256": document["subject"][0]["digest"][DIGEST_ALGORITHM],
        "predicateType": predicate_type,
        "predicate": summary,
    }


# ---------------------------------------------------------------------------
# Negative controls. Each mutates a real record's values in memory; each control
# proves one refusal fires, not that the substituted form occurs in the tree.
# ---------------------------------------------------------------------------


def _observed(action: Callable[[], Any]) -> tuple[str, str]:
    try:
        action()
    except Refusal as refusal:
        return refusal.code, refusal.message
    return "", ""


def _control(
    name: str, expected: str, condition: str, action: Callable[[], Any]
) -> dict[str, Any]:
    code, message = _observed(action)
    if code != expected:
        raise AssertionError(
            f"control {name!r} observed {code or 'no refusal'!r}, expected {expected!r}"
        )
    return {
        "control": name,
        "code": expected,
        "condition": condition,
        "observed": code,
        "detail": message,
    }


def build_controls(repo_root: Path = REPO_ROOT) -> list[dict[str, Any]]:
    """One control per refusal code, and one per distinct upgrade."""
    a1 = "evidence/a1/SARIF.json"
    admission = "evidence/a5/ADMISSION.json"
    delta = "evidence/a7/DELTA.json"
    instruments = "evidence/etp3/instruments.json"
    suppressions = "evidence/a6/SUPPRESSIONS.json"

    a1_subject = subject_for(a1, repo_root=repo_root)
    a1_statement = statement(
        [a1_subject],
        P_SARIF_EMISSION,
        sarif_predicate(repo_root, a1),
    )
    a1_text = encode(a1_statement)
    population = population_predicate(repo_root, admission, "a1-sarif-results")
    aggregate = population_entry(repo_root, admission, "t4-suppressions")
    aggregate["refusal"] = None  # reach the census check, not the record refusal

    controls = [
        _control(
            "missing-subject",
            IT_REFUSED_MISSING_SUBJECT,
            "a statement with no subject",
            lambda: statement([], P_POPULATION, population),
        ),
        _control(
            "absent-file",
            IT_REFUSED_SUBJECT_ABSENT,
            "the subject file is not present",
            lambda: subject_for("evidence/a9/absent-subject.json", repo_root=repo_root),
        ),
        _control(
            "git-object-id",
            IT_REFUSED_SUBJECT_DIGEST_FORM,
            "a 40-character Git object id as a content digest",
            lambda: statement(
                [
                    {
                        "name": a1,
                        "digest": {"sha256": "1efd02cbd1401c4cffb854b906c021915df94386"},
                    }
                ],
                P_SARIF_EMISSION,
                sarif_predicate(repo_root, a1),
            ),
        ),
        _control(
            "digest-mismatch",
            IT_REFUSED_SUBJECT_DIGEST_MISMATCH,
            "a caller-supplied digest that disagrees with the bytes",
            lambda: verify_subject(
                {"name": a1, "digest": {"sha256": "0" * 64}}, repo_root
            ),
        ),
        _control(
            "duplicate-subject",
            IT_REFUSED_DUPLICATE_SUBJECT,
            "one artefact named twice",
            lambda: statement(
                [a1_subject, dict(a1_subject)],
                P_SARIF_EMISSION,
                sarif_predicate(repo_root, a1),
            ),
        ),
        _control(
            "wrong-type",
            IT_REFUSED_TYPE,
            "a canonical document whose `_type` is not Statement v1",
            lambda: decode(
                _canonical_text(
                    {**a1_statement, "_type": "https://in-toto.io/Statement/v0.1"}
                )
            ),
        ),
        _control(
            "unknown-predicate-type",
            IT_REFUSED_PREDICATE_TYPE,
            "an unregistered predicate type",
            lambda: statement(
                [a1_subject],
                "https://openssl-rs.invalid/attestation/unknown/v1",
                sarif_predicate(repo_root, a1),
            ),
        ),
        _control(
            "missing-predicate-field",
            IT_REFUSED_PREDICATE_FIELD,
            "a required predicate field is absent",
            lambda: statement(
                [a1_subject],
                P_POPULATION,
                {key: value for key, value in population.items() if key != "record"},
            ),
        ),
        _control(
            "complete-over-truncated",
            IT_REFUSED_CLAIM_UPGRADE,
            "COMPLETE claimed over the TRUNCATED_BOUNDED curl residual population",
            lambda: _complete_over_truncated(repo_root, admission),
        ),
        _control(
            "resolved-over-none",
            IT_REFUSED_CLAIM_UPGRADE,
            "one RESOLVED claimed over a delta with zero resolutions",
            lambda: _resolved_over_none(repo_root, delta),
        ),
        _control(
            "census-over-aggregate",
            IT_REFUSED_CLAIM_UPGRADE,
            "a member census claimed over the AGGREGATE_ONLY suppression total",
            lambda: _census_over_aggregate(aggregate),
        ),
        _control(
            "verified-over-recorded",
            IT_REFUSED_CLAIM_UPGRADE,
            "a verified instrument claimed over a RECORDED-only control",
            lambda: _verified_over_recorded(repo_root, instruments),
        ),
        _control(
            "expiry-free-suppression",
            IT_REFUSED_CLAIM_UPGRADE,
            "an ACTIVE suppression with neither an expiry nor an unbounded claim",
            lambda: _expiry_free_suppression(repo_root, suppressions),
        ),
        _control(
            "evidence-without-digest",
            IT_REFUSED_CLAIM_UPGRADE,
            "an evidence identity that names no content digest",
            lambda: statement(
                [a1_subject],
                P_SARIF_EMISSION,
                {
                    **sarif_predicate(repo_root, a1),
                    "evidence": [{"path": a1}],
                },
            ),
        ),
        _control(
            "absent-record",
            IT_REFUSED_RECORD_ABSENT,
            "a predicate over a record that is not present",
            lambda: population_predicate(
                repo_root, "evidence/a9/absent-record.json", "a1-sarif-results"
            ),
        ),
        _control(
            "inadmissible-record",
            IT_REFUSED_RECORD_INADMISSIBLE,
            "a population whose own A5 declaration was refused",
            lambda: population_predicate(repo_root, admission, "t4-suppressions"),
        ),
        _control(
            "mutated-statement",
            IT_REFUSED_STATEMENT_MUTATED,
            "one byte changed in the emitted canonical bytes",
            lambda: decode(a1_text.replace(",", ", ", 1)),
        ),
    ]
    expected = set(REFUSALS)
    covered = {control["code"] for control in controls}
    if covered != expected:
        raise AssertionError(
            f"controls cover {sorted(covered)}, codes are {sorted(expected)}"
        )
    return controls


def _complete_over_truncated(repo_root: Path, admission: str) -> None:
    # `population_predicate` derives TRUNCATED_BOUNDED and refuses the asserted
    # COMPLETE against the record; nothing is checked against a doctored fact.
    population_predicate(
        repo_root, admission, "curl-residual-sites", {"state": "COMPLETE"}
    )


def _resolved_over_none(repo_root: Path, delta: str) -> None:
    facts = delta_facts(repo_root, delta, "a3-fingerprint-migration")
    predicate = delta_predicate(repo_root, delta, "a3-fingerprint-migration")
    predicate["resolved"] = 1
    predicate["dispositions"] = {**predicate["dispositions"], "RESOLVED": 1}
    predicate["records"] = facts["records"] + 1
    check_delta(predicate, facts)


def _census_over_aggregate(facts: Mapping[str, Any]) -> None:
    check_population({**facts, "census": True}, facts)


def _verified_over_recorded(repo_root: Path, instruments: str) -> None:
    facts = instrument_facts(repo_root, instruments, "timecop-supercop")
    predicate = instrument_predicate(repo_root, instruments, "timecop-supercop")
    predicate["status"] = "PASS"
    predicate["verified"] = True
    check_instrument(predicate, facts)


def _expiry_free_suppression(repo_root: Path, suppressions: str) -> None:
    facts = suppression_facts(repo_root, suppressions, "t4-suppressions")
    predicate = suppression_predicate(repo_root, suppressions, "t4-suppressions")
    predicate["disposition"] = "ACTIVE"
    predicate["expiry"] = None
    check_suppression(predicate, facts)


# ---------------------------------------------------------------------------
# Documents.
# ---------------------------------------------------------------------------


def controls_document(controls: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema": CONTROLS_SCHEMA,
        "model": MODEL_ID,
        "statementType": STATEMENT_TYPE,
        "tool": {
            "path": TOOL_PATH,
            "sha256": sha256_bytes(
                (Path(__file__).resolve().parent.parent.parent / TOOL_PATH).read_bytes()
            ),
        },
        "predicateTypes": {
            kind: {
                "required": list(entry["required"]),
                "forbidden": list(entry["forbidden"]),
                "carries": entry["carries"],
            }
            for kind, entry in PREDICATES.items()
        },
        "codes": {
            code: {"condition": entry["condition"], "prevents": entry["prevents"]}
            for code, entry in REFUSALS.items()
        },
        "controls": controls,
    }


# ---------------------------------------------------------------------------
# Command line.
# ---------------------------------------------------------------------------


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # argparse calls sys.exit itself
        self.print_usage(sys.stderr)
        print(f"code={CODE_USAGE}: {message}", file=sys.stderr)
        raise SystemExit(EXIT_USAGE)


def _predicate_for(
    short: str,
    repo_root: Path,
    subject: str,
    select: str | None,
) -> tuple[str, dict[str, Any]]:
    if short not in PREDICATE_BY_SHORT:
        _fail(
            IT_REFUSED_PREDICATE_TYPE,
            f"{short!r} is not a registered predicate short name; choose from "
            + ", ".join(sorted(PREDICATE_BY_SHORT)),
        )
    kind = PREDICATE_BY_SHORT[short]
    if kind == P_SARIF_EMISSION:
        return kind, sarif_predicate(repo_root, subject)
    if select is None:
        _fail(IT_REFUSED_PREDICATE_FIELD, f"{short}: --select is required")
    if kind == P_POPULATION:
        return kind, population_predicate(repo_root, subject, select)
    if kind == P_BASELINE_DELTA:
        return kind, delta_predicate(repo_root, subject, select)
    if kind == P_INSTRUMENT:
        return kind, instrument_predicate(repo_root, subject, select)
    if kind == P_SUPPRESSION:
        return kind, suppression_predicate(repo_root, subject, select)
    _fail(IT_REFUSED_PREDICATE_TYPE, f"{kind}: no builder")


def _command_emit(args: argparse.Namespace) -> int:
    entry = PREDICATES[PREDICATE_BY_SHORT[args.predicate]]
    record = args.subject or entry.get("defaultSubject")
    if record is None:
        _fail(
            IT_REFUSED_PREDICATE_FIELD,
            f"{args.predicate}: --subject is required",
        )
    kind, predicate = _predicate_for(
        args.predicate, args.repo_root, record, args.select
    )
    subject = subject_for(record, repo_root=args.repo_root)
    document = statement([subject], kind, predicate)
    text = encode(document)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text, encoding="utf-8")
    print(
        f"emit: code={CODE_OK} predicateType={kind} subject={subject['name']} "
        f"sha256={subject['digest'][DIGEST_ALGORITHM]} out={out}"
    )
    return EXIT_OK


def _command_verify(args: argparse.Namespace) -> int:
    path = Path(args.statement)
    try:
        data = path.read_bytes()
    except OSError as error:
        _fail(IT_REFUSED_STATEMENT_MUTATED, f"{path}: {error}")
    report = verify_statement(data, args.repo_root)
    print(
        f"verify: code={CODE_OK} subject={report['subject']} "
        f"sha256={report['sha256']} predicateType={report['predicateType']} "
        f"predicate={json.dumps(report['predicate'], sort_keys=True)}"
    )
    return EXIT_OK


def _command_subjects(args: argparse.Namespace) -> int:
    status = EXIT_OK
    for path in args.paths:
        try:
            subject = subject_for(path, repo_root=args.repo_root)
        except Refusal as refusal:
            print(f"subjects: code={refusal.code}: {refusal.message}", file=sys.stderr)
            status = EXIT_REFUSED
            continue
        print(_canonical_text(subject), end="")
    if status == EXIT_OK:
        print(f"subjects: code={CODE_OK} count={len(args.paths)}")
    return status


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(description="in-toto Statement v1 attestations")
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    commands = parser.add_subparsers(dest="command", required=True)

    emit = commands.add_parser("emit", help="build and write one statement")
    emit.add_argument("predicate", choices=sorted(PREDICATE_BY_SHORT))
    emit.add_argument("out")
    emit.add_argument("--subject", default=None)
    emit.add_argument("--select", default=None)

    verify = commands.add_parser("verify", help="verify one emitted statement")
    verify.add_argument("statement")

    subjects = commands.add_parser("subjects", help="print subjects for files")
    subjects.add_argument("paths", nargs="+")

    args = parser.parse_args(argv)
    try:
        if args.command == "emit":
            return _command_emit(args)
        if args.command == "verify":
            return _command_verify(args)
        return _command_subjects(args)
    except Refusal as refusal:
        print(f"{args.command}: code={refusal.code}: {refusal.message}", file=sys.stderr)
        return EXIT_REFUSED


if __name__ == "__main__":
    sys.exit(main())
