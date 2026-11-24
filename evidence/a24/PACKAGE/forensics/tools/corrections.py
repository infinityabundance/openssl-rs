#!/usr/bin/env python3
"""corrections.py -- an append-only, bound, propagating correction log.

Why this tool exists
--------------------
A correction is not an edit.  A project that silently changes a recorded value
keeps the new value and loses the fact that it once believed something else, so
the history becomes unfalsifiable: a reader cannot tell a value that was always
right from one that was repaired, cannot see which downstream conclusions relied
on the old value, and cannot check that the repair reached them.

This module makes a correction a first-class, machine-readable event with four
properties:

  * **append-only.**  The original ``assert`` is never edited or deleted.  A
    correction is a new event that names its predecessor.  The log carries a
    digest chain over every event; editing or deleting an event is refused
    (``CR_REFUSED_HISTORY_ERASED``).
  * **bound to the exact original.**  A correction names both the predecessor
    event id and that predecessor's canonical digest *and* the digest of the
    value it corrects.  A different value is a new assertion, not a correction.
  * **propagating.**  Every record that cites a superseded digest must be
    marked ``INVALIDATED``.  A dependent left valid is refused
    (``CR_REFUSED_INVALIDATION_NOT_PROPAGATED``) and an invalidation with no
    superseded citation is refused (``CR_REFUSED_SPURIOUS_INVALIDATION``).
  * **preserving.**  ``current`` returns the accepted event **and** the full
    history.  A retracted subject has no accepted value but keeps its history.

Events form a chain per subject.  A fork (two direct successors of one
predecessor) and a cycle are refused.  The original ``assert`` records what was
believed; a ``correct`` records the successor value; a ``retract`` records that
the subject now has no accepted value.

What this tool does not do
--------------------------
It makes **no authentication claim**.  Every event and the log itself are signed
with A10's test-only HMAC-SHA256 signer (a fixed public seed), and the log is
labelled ``SELF_ISSUED``.  The signature proves that the bytes under test have
not changed since signing; it does not prove who recorded the event, that the
recorder held the role, or that an independent party agrees.  Roles are read
from A14's assignment record; A14 declares **no identity**, so no event in this
tree is authenticated.

It also does not establish that the corrected value was wrong *for the right
reason*.  The record establishes that a bound successor exists and what the
project said about it, not that the successor is true.

Usage
-----
    python3 forensics/tools/corrections.py verify [--log PATH]
    python3 forensics/tools/corrections.py history SUBJECT [--log PATH]
    python3 forensics/tools/corrections.py append EVENT.json [--log PATH]
    python3 forensics/tools/corrections.py propagate [--log PATH] [--repo-root DIR]
    python3 forensics/tools/corrections.py sign-event EVENT.json

Exit status: 0 for success / an accepted log, 1 for a refusal or an UNKNOWN
subject, 2 for a usage or I/O error.  The code is always printed.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parent))

import dsse  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = "forensics/tools/corrections.py"

MODEL_ID = "a19/v1"
LOG_SCHEMA = "openssl-rs/a19/corrections-log/1"
EVENT_SCHEMA = "openssl-rs/a19/correction-event/1"
CONTROLS_SCHEMA = "openssl-rs/a19/controls/1"
STATUS_SCHEMA = "openssl-rs/a19/status/1"
PROPAGATION_SCHEMA = "openssl-rs/a19/propagation/1"

EVENT_PAYLOAD_TYPE = "application/vnd.openssl-rs.a19.correction-event.v1+json"
LOG_PAYLOAD_TYPE = "application/vnd.openssl-rs.a19.corrections-log.v1+json"

CODE_OK = "CR_OK"
CODE_USAGE = "CR_USAGE"
CODE_UNKNOWN = "CR_UNKNOWN"
CODE_NOT_RUN = "CR_NOT_RUN"

KIND_ASSERT = "assert"
KIND_CORRECT = "correct"
KIND_RETRACT = "retract"
KINDS = (KIND_ASSERT, KIND_CORRECT, KIND_RETRACT)

OUTCOME_CURRENT = "CURRENT"
OUTCOME_CORRECTED = "CORRECTED"
OUTCOME_RETRACTED = "RETRACTED"
OUTCOME_DISPUTED = "DISPUTED"
OUTCOME_UNKNOWN = "UNKNOWN"
OUTCOMES = (
    OUTCOME_CURRENT,
    OUTCOME_CORRECTED,
    OUTCOME_RETRACTED,
    OUTCOME_DISPUTED,
    OUTCOME_UNKNOWN,
)

# A19's mapping from an event kind to the role that may record it.  A14 has no
# "correction" role; this mapping is A19's decision and is documented as such.
# It does not invent an identity: the identity must already be assigned that role
# in evidence/a14/ROLES.json.
CORRECTING_ROLE = {
    KIND_ASSERT: "producer",
    KIND_CORRECT: "producer",
    KIND_RETRACT: "revocation_authority",
}

# Stable refusal codes.  Every code has a control in evidence/a19/CONTROLS.json.
CR_REFUSED_EVENT_INVALID = "CR_REFUSED_EVENT_INVALID"
CR_REFUSED_UNBOUND_CORRECTION = "CR_REFUSED_UNBOUND_CORRECTION"
CR_REFUSED_PREDECESSOR_MISMATCH = "CR_REFUSED_PREDECESSOR_MISMATCH"
CR_REFUSED_ORIGINAL_MISMATCH = "CR_REFUSED_ORIGINAL_MISMATCH"
CR_REFUSED_HISTORY_ERASED = "CR_REFUSED_HISTORY_ERASED"
CR_REFUSED_FORK = "CR_REFUSED_FORK"
CR_REFUSED_CYCLE = "CR_REFUSED_CYCLE"
CR_REFUSED_SUBJECT_CHANGED = "CR_REFUSED_SUBJECT_CHANGED"
CR_REFUSED_RETRACTION_UNBOUND = "CR_REFUSED_RETRACTION_UNBOUND"
CR_REFUSED_UNSIGNED = "CR_REFUSED_UNSIGNED"
CR_REFUSED_SIGNATURE = "CR_REFUSED_SIGNATURE"
CR_REFUSED_ROLE = "CR_REFUSED_ROLE"
CR_REFUSED_ASSERTION_EXISTS = "CR_REFUSED_ASSERTION_EXISTS"
CR_REFUSED_EVENT_ID_REUSED = "CR_REFUSED_EVENT_ID_REUSED"
CR_REFUSED_INVALIDATION_NOT_PROPAGATED = "CR_REFUSED_INVALIDATION_NOT_PROPAGATED"
CR_REFUSED_SPURIOUS_INVALIDATION = "CR_REFUSED_SPURIOUS_INVALIDATION"

REFUSALS: dict[str, dict[str, str]] = {
    CR_REFUSED_EVENT_INVALID: {
        "condition": "the event is missing a required field or has the wrong shape",
        "prevents": "a malformed event read as a checked correction",
    },
    CR_REFUSED_UNBOUND_CORRECTION: {
        "condition": "a correct/retract does not name both the predecessor id and digest",
        "prevents": "a correction that cannot be tied to the record it corrects",
    },
    CR_REFUSED_PREDECESSOR_MISMATCH: {
        "condition": "supersedes.previousDigest is not the stored predecessor's digest",
        "prevents": "a correction that points at bytes other than the predecessor's",
    },
    CR_REFUSED_ORIGINAL_MISMATCH: {
        "condition": "oldValue.digest is not the predecessor's accepted value digest",
        "prevents": "a correction that silently corrects a different value",
    },
    CR_REFUSED_HISTORY_ERASED: {
        "condition": "the recomputed event chain or log digest disagrees with the log",
        "prevents": "editing or deleting an event and keeping the new history",
    },
    CR_REFUSED_FORK: {
        "condition": "a predecessor already has a direct successor",
        "prevents": "two different corrections of one record, one silently dropped",
    },
    CR_REFUSED_CYCLE: {
        "condition": "the predecessor chain revisits an event",
        "prevents": "a correction that is its own ancestor",
    },
    CR_REFUSED_SUBJECT_CHANGED: {
        "condition": "a correct/retract names a subject other than its predecessor's",
        "prevents": "re-labelling a different subject as a correction",
    },
    CR_REFUSED_RETRACTION_UNBOUND: {
        "condition": "a retraction has no prior assertion for its subject",
        "prevents": "retracting a value the project never asserted",
    },
    CR_REFUSED_UNSIGNED: {
        "condition": "the event or the log carries no signature",
        "prevents": "an unsigned event read as a signed correction",
    },
    CR_REFUSED_SIGNATURE: {
        "condition": "the signature does not cover the canonical event/log bytes",
        "prevents": "a signature over different bytes counted as this event's",
    },
    CR_REFUSED_ROLE: {
        "condition": "the recording identity does not hold the correcting role",
        "prevents": "an identity outside the role recording a correction",
    },
    CR_REFUSED_ASSERTION_EXISTS: {
        "condition": "a subject already has an assert; a later value is a correction",
        "prevents": "a second assertion that silently replaces the first",
    },
    CR_REFUSED_EVENT_ID_REUSED: {
        "condition": "two events in the log share an eventId",
        "prevents": "one id satisfying two events in the chain",
    },
    CR_REFUSED_INVALIDATION_NOT_PROPAGATED: {
        "condition": "a dependent cites a superseded digest but is not INVALIDATED",
        "prevents": "a correction that leaves a relying record looking current",
    },
    CR_REFUSED_SPURIOUS_INVALIDATION: {
        "condition": "a dependent is INVALIDATED but cites no superseded digest",
        "prevents": "an invalidation with no superseded record behind it",
    },
}

CODE_ORDER = tuple(REFUSALS)


class Refusal(Exception):
    """A stable refusal code and a human-readable message."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def _fail(code: str, message: str) -> None:
    raise Refusal(code, message)


# ---------------------------------------------------------------------------
# Canonical bytes, digests and file identity
# ---------------------------------------------------------------------------


def canonical_bytes(document: Any) -> bytes:
    """Canonical JSON used for digests and signed payloads."""
    return json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path | str) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def tool_identity() -> dict[str, str]:
    return {"path": TOOL_PATH, "sha256": sha256_file(REPO_ROOT / TOOL_PATH)}


def value_digest(value: Any) -> str:
    """The digest of an exact value: a correction binds this, not a paraphrase."""
    return sha256_bytes(canonical_bytes(value))


def unsigned_event(event: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in event.items() if key != "signature"}


def event_digest(event: Mapping[str, Any]) -> str:
    """The canonical digest of a stored event, including its signature."""
    return sha256_bytes(canonical_bytes(event))


def log_digest(history: Sequence[Mapping[str, Any]]) -> str:
    return sha256_bytes(canonical_bytes(list(history)))


def unsigned_log(log: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in log.items() if key != "logEnvelope"}


# ---------------------------------------------------------------------------
# A14 roles.  No identity is invented; an event must use an assigned identity.
# ---------------------------------------------------------------------------


def load_role_assignments(repo_root: Path | str = REPO_ROOT) -> dict[str, set[str]]:
    """Read evidence/a14/ROLES.json as ``{role: {identity, ...}}``.

    An absent or unreadable record is an empty assignment map: no event can then
    pass the role check.  It is never treated as "all roles allowed".
    """
    path = Path(repo_root) / "evidence/a14/ROLES.json"
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    assignments: dict[str, set[str]] = {}
    for row in document.get("assignments", []):
        role = row.get("role")
        identity = row.get("identity")
        if isinstance(role, str) and isinstance(identity, str):
            assignments.setdefault(role, set()).add(identity)
    return assignments


def role_vocabulary(repo_root: Path | str = REPO_ROOT) -> set[str]:
    path = Path(repo_root) / "evidence/a14/ROLES.json"
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return set()
    return set(document.get("roleVocabulary", []))


# ---------------------------------------------------------------------------
# Event structure
# ---------------------------------------------------------------------------


def _require_text(event: Mapping[str, Any], field: str) -> str:
    value = event.get(field)
    if not isinstance(value, str) or not value.strip():
        _fail(CR_REFUSED_EVENT_INVALID, f"{field} is a non-empty string")
    return value


def _validate_value(value: Any, field: str) -> None:
    if not isinstance(value, Mapping):
        _fail(CR_REFUSED_EVENT_INVALID, f"{field} is an object")
    if "value" not in value:
        _fail(CR_REFUSED_EVENT_INVALID, f"{field}.value is present")
    digest = value.get("digest")
    if not isinstance(digest, str) or len(digest) != 64:
        _fail(CR_REFUSED_EVENT_INVALID, f"{field}.digest is a 64-hex SHA-256")
    if digest != value_digest(value["value"]):
        _fail(
            CR_REFUSED_EVENT_INVALID,
            f"{field}.digest is not the digest of {field}.value",
        )
    citation = value.get("citation")
    if not isinstance(citation, str) or not citation.strip():
        _fail(CR_REFUSED_EVENT_INVALID, f"{field}.citation is a non-empty string")
    record = value.get("record")
    if record is not None:
        if not isinstance(record, Mapping):
            _fail(CR_REFUSED_EVENT_INVALID, f"{field}.record is an object or null")
        if not isinstance(record.get("path"), str) or not record["path"]:
            _fail(CR_REFUSED_EVENT_INVALID, f"{field}.record.path is a path")
        bound = record.get("sha256")
        if bound is not None and (not isinstance(bound, str) or len(bound) != 64):
            _fail(
                CR_REFUSED_EVENT_INVALID,
                f"{field}.record.sha256 is a 64-hex SHA-256 or null",
            )


def validate_event_structure(event: Any) -> None:
    """Structural validation only; no chain, signature or role check."""
    if not isinstance(event, Mapping):
        _fail(CR_REFUSED_EVENT_INVALID, "an event is a JSON object")
    _require_text(event, "eventId")
    _require_text(event, "subject")
    _require_text(event, "reason")
    _require_text(event, "recordedAt")
    kind = event.get("kind")
    if kind not in KINDS:
        _fail(CR_REFUSED_EVENT_INVALID, f"kind is one of {list(KINDS)}")
    recorder = event.get("recordedBy")
    if not isinstance(recorder, Mapping):
        _fail(CR_REFUSED_EVENT_INVALID, "recordedBy is an object")
    if not isinstance(recorder.get("role"), str) or not recorder["role"]:
        _fail(CR_REFUSED_EVENT_INVALID, "recordedBy.role is a non-empty string")
    if not isinstance(recorder.get("identity"), str) or not recorder["identity"]:
        _fail(CR_REFUSED_EVENT_INVALID, "recordedBy.identity is a non-empty string")
    evidence = event.get("evidence")
    if not isinstance(evidence, list) or not all(
        isinstance(item, str) and item for item in evidence
    ):
        _fail(CR_REFUSED_EVENT_INVALID, "evidence is a list of non-empty strings")
    supersedes = event.get("supersedes")
    old = event.get("oldValue")
    new = event.get("newValue")
    if kind == KIND_ASSERT:
        if supersedes not in (None, {},):
            _fail(CR_REFUSED_EVENT_INVALID, "an assert does not supersede an event")
        if old is not None:
            _fail(CR_REFUSED_EVENT_INVALID, "an assert has no oldValue")
        if new is None:
            _fail(CR_REFUSED_EVENT_INVALID, "an assert has a newValue")
        _validate_value(new, "newValue")
    else:
        if not isinstance(supersedes, Mapping):
            _fail(
                CR_REFUSED_UNBOUND_CORRECTION,
                "a correct/retract names its predecessor id and digest",
            )
        for field in ("previousEventId", "previousDigest"):
            value = supersedes.get(field)
            if not isinstance(value, str) or not value:
                _fail(
                    CR_REFUSED_UNBOUND_CORRECTION,
                    f"supersedes.{field} is a non-empty string",
                )
        if old is None:
            _fail(CR_REFUSED_EVENT_INVALID, "a correct/retract has an oldValue")
        _validate_value(old, "oldValue")
        if kind == KIND_CORRECT:
            if new is None:
                _fail(CR_REFUSED_EVENT_INVALID, "a correct has a newValue")
            _validate_value(new, "newValue")
        else:
            if new is not None:
                _validate_value(new, "newValue")
    authentication = event.get("authentication")
    if authentication is not None:
        if not isinstance(authentication, Mapping):
            _fail(CR_REFUSED_EVENT_INVALID, "authentication is an object")
        if not isinstance(authentication.get("authenticated"), bool):
            _fail(
                CR_REFUSED_EVENT_INVALID,
                "authentication.authenticated is a boolean",
            )
        if not isinstance(authentication.get("status"), str):
            _fail(CR_REFUSED_EVENT_INVALID, "authentication.status is a string")


# ---------------------------------------------------------------------------
# Signatures: A10's DSSE framing, over the exact canonical bytes.
# ---------------------------------------------------------------------------


def sign_event(
    event: Mapping[str, Any],
    signer: Callable[[bytes], tuple[str, bytes]] | None = None,
) -> dict[str, Any]:
    """Return the event with a DSSE envelope over its unsigned canonical bytes."""
    validate_event_structure(event)
    chosen = signer if signer is not None else dsse.test_only_signer()
    envelope = dsse.envelope(
        EVENT_PAYLOAD_TYPE, canonical_bytes(unsigned_event(event)), chosen
    )
    produced = dict(event)
    produced["signature"] = envelope
    return produced


def verify_event_signature(
    event: Mapping[str, Any],
    verifier: Callable[[str, bytes, bytes], bool] | None = None,
) -> str:
    """Refuse an unsigned event or a signature over different bytes."""
    signature = event.get("signature")
    if signature in (None, {}, []):
        _fail(CR_REFUSED_UNSIGNED, "the event carries no signature")
    if not isinstance(signature, Mapping):
        _fail(CR_REFUSED_SIGNATURE, "signature is a DSSE envelope object")
    chosen = verifier if verifier is not None else dsse.test_only_verifier()
    try:
        result = dsse.verify_received_bytes(
            dsse.encode_envelope(signature),
            chosen,
            expected_payload_type=EVENT_PAYLOAD_TYPE,
        )
    except dsse.Refusal as refusal:
        _fail(CR_REFUSED_SIGNATURE, f"{refusal.code}: {refusal.message}")
    if result["payload"] != canonical_bytes(unsigned_event(event)):
        _fail(
            CR_REFUSED_SIGNATURE,
            "the signature covers different bytes than the canonical event",
        )
    return result["keyid"]


def sign_log(
    log: Mapping[str, Any],
    signer: Callable[[bytes], tuple[str, bytes]] | None = None,
) -> dict[str, Any]:
    chosen = signer if signer is not None else dsse.test_only_signer()
    envelope = dsse.envelope(
        LOG_PAYLOAD_TYPE, canonical_bytes(unsigned_log(log)), chosen
    )
    produced = dict(log)
    produced["logEnvelope"] = envelope
    return produced


def verify_log_envelope(
    log: Mapping[str, Any],
    verifier: Callable[[str, bytes, bytes], bool] | None = None,
) -> str:
    envelope = log.get("logEnvelope")
    if envelope in (None, {}, []):
        _fail(CR_REFUSED_UNSIGNED, "the log carries no logEnvelope")
    if not isinstance(envelope, Mapping):
        _fail(CR_REFUSED_SIGNATURE, "logEnvelope is a DSSE envelope object")
    chosen = verifier if verifier is not None else dsse.test_only_verifier()
    try:
        result = dsse.verify_received_bytes(
            dsse.encode_envelope(envelope),
            chosen,
            expected_payload_type=LOG_PAYLOAD_TYPE,
        )
    except dsse.Refusal as refusal:
        _fail(CR_REFUSED_SIGNATURE, f"{refusal.code}: {refusal.message}")
    if result["payload"] != canonical_bytes(unsigned_log(log)):
        _fail(
            CR_REFUSED_SIGNATURE,
            "the log signature covers different bytes than the canonical log",
        )
    return result["keyid"]


def validate_role(
    event: Mapping[str, Any],
    assignments: Mapping[str, Iterable[str]] | None = None,
    *,
    repo_root: Path | str = REPO_ROOT,
) -> None:
    """The recording identity must already hold the kind's correcting role."""
    recorder = event["recordedBy"]
    role = recorder["role"]
    identity = recorder["identity"]
    required = CORRECTING_ROLE[event["kind"]]
    if role != required:
        _fail(
            CR_REFUSED_ROLE,
            f"a {event['kind']} is recorded by the {required!r} role, not {role!r}",
        )
    table = assignments if assignments is not None else load_role_assignments(repo_root)
    if identity not in set(table.get(role, ())):
        _fail(
            CR_REFUSED_ROLE,
            f"identity {identity!r} holds no {role!r} assignment in A14's records",
        )


# ---------------------------------------------------------------------------
# The log: history witness, integrity and append-only chain
# ---------------------------------------------------------------------------


def new_log(
    *,
    source_identity: Mapping[str, Any] | None = None,
    authentication: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    log: dict[str, Any] = {
        "schema": LOG_SCHEMA,
        "model": MODEL_ID,
        "events": [],
        "history": [],
        "logDigest": log_digest([]),
    }
    if source_identity is not None:
        log["sourceIdentity"] = dict(source_identity)
    if authentication is not None:
        log["authentication"] = dict(authentication)
    return log


def _history_entry(event: Mapping[str, Any]) -> dict[str, Any]:
    supersedes = event.get("supersedes") or {}
    return {
        "eventId": event["eventId"],
        "digest": event_digest(event),
        "subject": event["subject"],
        "kind": event["kind"],
        "previousEventId": supersedes.get("previousEventId"),
        "previousDigest": supersedes.get("previousDigest"),
    }


def check_log(log: Any) -> None:
    """Recompute the digest chain.  An edit or deletion is HISTORY_ERASED."""
    if not isinstance(log, Mapping):
        _fail(CR_REFUSED_EVENT_INVALID, "a log is a JSON object")
    events = log.get("events")
    history = log.get("history")
    if not isinstance(events, list) or not isinstance(history, list):
        _fail(CR_REFUSED_EVENT_INVALID, "events and history are lists")
    if len(events) != len(history):
        _fail(
            CR_REFUSED_HISTORY_ERASED,
            f"{len(events)} events but {len(history)} history entries",
        )
    seen: set[str] = set()
    for index, (event, entry) in enumerate(zip(events, history)):
        if not isinstance(event, Mapping) or not isinstance(entry, Mapping):
            _fail(CR_REFUSED_EVENT_INVALID, f"event {index} is malformed")
        event_id = event.get("eventId")
        if event_id in seen:
            _fail(CR_REFUSED_EVENT_ID_REUSED, f"eventId {event_id!r} is reused")
        seen.add(event_id)
        expected = _history_entry(event)
        for field, value in expected.items():
            if entry.get(field) != value:
                _fail(
                    CR_REFUSED_HISTORY_ERASED,
                    f"event {index} ({event_id!r}) {field} does not match the "
                    "recomputed chain",
                )
    recorded = log.get("logDigest")
    if recorded != log_digest(history):
        _fail(
            CR_REFUSED_HISTORY_ERASED,
            "the log digest does not match the recomputed history digest",
        )


def _by_id(log: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    return {event["eventId"]: dict(event) for event in log["events"]}


def _root_id(by_id: Mapping[str, Mapping[str, Any]], event_id: str) -> str:
    seen: set[str] = set()
    current = event_id
    while True:
        if current in seen:
            _fail(CR_REFUSED_CYCLE, f"the predecessor chain revisits {current!r}")
        seen.add(current)
        event = by_id[current]
        supersedes = event.get("supersedes") or {}
        previous = supersedes.get("previousEventId")
        if not previous:
            return current
        if previous not in by_id:
            _fail(
                CR_REFUSED_PREDECESSOR_MISMATCH,
                f"predecessor {previous!r} is not in the log",
            )
        current = previous


def _successors(log: Mapping[str, Any]) -> dict[str, list[str]]:
    table: dict[str, list[str]] = {}
    for event in log["events"]:
        previous = (event.get("supersedes") or {}).get("previousEventId")
        if previous:
            table.setdefault(previous, []).append(event["eventId"])
    return table


def _check_binding(
    log: Mapping[str, Any],
    event: Mapping[str, Any],
    *,
    require_unique_assert: bool = True,
) -> None:
    """The chain checks for one event against the log it is being added to."""
    by_id = _by_id(log)
    kind = event["kind"]
    subject = event["subject"]
    same_subject = [item for item in log["events"] if item["subject"] == subject]
    if kind == KIND_ASSERT:
        if require_unique_assert and same_subject:
            _fail(
                CR_REFUSED_ASSERTION_EXISTS,
                f"subject {subject!r} already has an assert; a later value is a "
                "correction, not a new assertion",
            )
        return
    supersedes = event["supersedes"]
    previous_id = supersedes["previousEventId"]
    previous_digest = supersedes["previousDigest"]
    if previous_id not in by_id:
        if kind == KIND_RETRACT and not same_subject:
            _fail(
                CR_REFUSED_RETRACTION_UNBOUND,
                f"subject {subject!r} has no prior assertion to retract",
            )
        _fail(
            CR_REFUSED_PREDECESSOR_MISMATCH,
            f"predecessor {previous_id!r} is not in the log",
        )
    predecessor = by_id[previous_id]
    if predecessor["subject"] != subject:
        _fail(
            CR_REFUSED_SUBJECT_CHANGED,
            f"predecessor {previous_id!r} is about {predecessor['subject']!r}, "
            f"not {subject!r}; a different subject is a new assertion",
        )
    if event_digest(predecessor) != previous_digest:
        _fail(
            CR_REFUSED_PREDECESSOR_MISMATCH,
            f"supersedes.previousDigest is not the canonical digest of "
            f"{previous_id!r}",
        )
    # Cycle first: a chain that revisits an event is a stronger defect than a
    # fork, and a cycle necessarily makes the predecessor look forked.
    current = previous_id
    seen: set[str] = set()
    while current:
        if current == event["eventId"]:
            _fail(CR_REFUSED_CYCLE, f"{event['eventId']!r} is its own ancestor")
        if current in seen:
            _fail(CR_REFUSED_CYCLE, f"the chain already cycles at {current!r}")
        seen.add(current)
        if current not in by_id:
            break
        current = (by_id[current].get("supersedes") or {}).get("previousEventId") or ""
    # Exclude the event under test: when an existing event is re-validated it is
    # already in the log and would otherwise count as its own predecessor's
    # second successor.
    successors = {
        previous: [child for child in children if child != event["eventId"]]
        for previous, children in _successors(log).items()
    }
    if successors.get(previous_id):
        _fail(
            CR_REFUSED_FORK,
            f"predecessor {previous_id!r} already has successor "
            f"{successors[previous_id]!r}",
        )
    # The predecessor's root must be the one root of this subject.
    roots = {_root_id(by_id, item["eventId"]) for item in same_subject}
    if len(roots) != 1 or _root_id(by_id, previous_id) not in roots:
        _fail(
            CR_REFUSED_FORK,
            f"subject {subject!r} has more than one root assertion",
        )
    if predecessor["kind"] == KIND_RETRACT:
        _fail(
            CR_REFUSED_RETRACTION_UNBOUND,
            f"predecessor {previous_id!r} already retracted {subject!r}; there is "
            "no live assertion to correct",
        )
    accepted = predecessor.get("newValue")
    if not isinstance(accepted, Mapping):
        _fail(
            CR_REFUSED_ORIGINAL_MISMATCH,
            f"predecessor {previous_id!r} has no accepted value",
        )
    original = event["oldValue"]
    if original["digest"] != accepted["digest"]:
        _fail(
            CR_REFUSED_ORIGINAL_MISMATCH,
            "oldValue.digest is not the predecessor's accepted value digest",
        )
    original_record = (original.get("record") or {}).get("sha256")
    accepted_record = (accepted.get("record") or {}).get("sha256")
    if original_record != accepted_record:
        _fail(
            CR_REFUSED_ORIGINAL_MISMATCH,
            "oldValue.record.sha256 is not the predecessor's accepted record digest",
        )


def append(
    log: Mapping[str, Any],
    event: Mapping[str, Any],
    *,
    assignments: Mapping[str, Iterable[str]] | None = None,
    signer: Callable[[bytes], tuple[str, bytes]] | None = None,
    verifier: Callable[[str, bytes, bytes], bool] | None = None,
    repo_root: Path | str = REPO_ROOT,
) -> dict[str, Any]:
    """Return a new log with ``event`` appended, or refuse.

    The input log is not mutated.  The returned log is re-signed with the
    test-only signer (or ``signer``), so the append is visible in the log
    envelope as well as the digest chain.
    """
    check_log(log)
    if log.get("logEnvelope") is not None:
        verify_log_envelope(log, verifier)
    validate_event_structure(event)
    if event["eventId"] in {item["eventId"] for item in log["events"]}:
        _fail(
            CR_REFUSED_EVENT_ID_REUSED,
            f"eventId {event['eventId']!r} already exists",
        )
    validate_role(event, assignments, repo_root=repo_root)
    verify_event_signature(event, verifier)
    _check_binding(log, event)
    produced = dict(log)
    produced["events"] = list(log["events"]) + [dict(event)]
    produced["history"] = list(log["history"]) + [_history_entry(event)]
    produced["logDigest"] = log_digest(produced["history"])
    return sign_log(produced, signer)


# ---------------------------------------------------------------------------
# Outcomes: the accepted event and the full history
# ---------------------------------------------------------------------------


def _events_for(log: Mapping[str, Any], subject: str) -> list[dict[str, Any]]:
    return [dict(event) for event in log["events"] if event["subject"] == subject]


def _chain_for(
    log: Mapping[str, Any], subject: str
) -> tuple[list[dict[str, Any]], list[str]]:
    """Return the ordered chain and a list of dispute reasons."""
    events = _events_for(log, subject)
    if not events:
        return [], []
    by_id = {event["eventId"]: event for event in events}
    reasons: list[str] = []
    roots = [
        event["eventId"]
        for event in events
        if not (event.get("supersedes") or {}).get("previousEventId")
    ]
    if len(roots) != 1:
        reasons.append(f"{len(roots)} root assertions for one subject")
        return events, reasons
    successors: dict[str, list[str]] = {}
    for event in events:
        previous = (event.get("supersedes") or {}).get("previousEventId")
        if previous:
            if previous not in by_id:
                reasons.append(f"predecessor {previous!r} is absent")
                return events, reasons
            successors.setdefault(previous, []).append(event["eventId"])
    for previous, children in successors.items():
        if len(children) > 1:
            reasons.append(f"predecessor {previous!r} has {len(children)} successors")
    chain: list[dict[str, Any]] = []
    seen: set[str] = set()
    current = roots[0]
    while current:
        if current in seen:
            reasons.append(f"cycle at {current!r}")
            return events, reasons
        seen.add(current)
        chain.append(by_id[current])
        children = successors.get(current, [])
        if len(children) > 1:
            return chain, reasons
        current = children[0] if children else ""
    if len(chain) != len(events):
        reasons.append("the chain does not reach every event for the subject")
    return chain, reasons


def _tip_is_valid(
    log: Mapping[str, Any],
    tip: Mapping[str, Any],
    *,
    assignments: Mapping[str, Iterable[str]] | None,
    verifier: Callable[[str, bytes, bytes], bool] | None,
    repo_root: Path | str,
) -> list[str]:
    reasons: list[str] = []
    try:
        verify_event_signature(tip, verifier)
    except Refusal as refusal:
        reasons.append(refusal.code)
    try:
        validate_role(tip, assignments, repo_root=repo_root)
    except Refusal as refusal:
        reasons.append(refusal.code)
    if tip["kind"] != KIND_ASSERT:
        try:
            _check_binding(log, tip)
        except Refusal as refusal:
            reasons.append(refusal.code)
    return reasons


def current(
    log: Mapping[str, Any],
    subject: str,
    *,
    assignments: Mapping[str, Iterable[str]] | None = None,
    verifier: Callable[[str, bytes, bytes], bool] | None = None,
    repo_root: Path | str = REPO_ROOT,
) -> dict[str, Any]:
    """The accepted event and the full history; a retracted subject has none.

    ``UNKNOWN`` means the subject has no event.  ``DISPUTED`` means the chain has
    no unique accepted tip, or the tip fails its signature/role/binding checks.
    """
    check_log(log)
    chain, reasons = _chain_for(log, subject)
    if not chain:
        return {
            "subject": subject,
            "outcome": OUTCOME_UNKNOWN,
            "accepted": None,
            "acceptedEventId": None,
            "history": [],
            "reasons": ["no event for this subject"],
        }
    if reasons:
        return {
            "subject": subject,
            "outcome": OUTCOME_DISPUTED,
            "accepted": None,
            "acceptedEventId": None,
            "history": chain,
            "reasons": reasons,
        }
    tip = chain[-1]
    tip_reasons = _tip_is_valid(
        log,
        tip,
        assignments=assignments,
        verifier=verifier,
        repo_root=repo_root,
    )
    if tip_reasons:
        return {
            "subject": subject,
            "outcome": OUTCOME_DISPUTED,
            "accepted": None,
            "acceptedEventId": tip["eventId"],
            "history": chain,
            "reasons": tip_reasons,
        }
    if tip["kind"] == KIND_RETRACT:
        outcome = OUTCOME_RETRACTED
        accepted = None
    elif tip["kind"] == KIND_CORRECT:
        outcome = OUTCOME_CORRECTED
        accepted = tip["newValue"]
    else:
        outcome = OUTCOME_CURRENT
        accepted = tip["newValue"]
    return {
        "subject": subject,
        "outcome": outcome,
        "accepted": accepted,
        "acceptedEventId": tip["eventId"],
        "history": chain,
        "reasons": [],
    }


def verify_log(
    log: Mapping[str, Any],
    *,
    assignments: Mapping[str, Iterable[str]] | None = None,
    verifier: Callable[[str, bytes, bytes], bool] | None = None,
    repo_root: Path | str = REPO_ROOT,
    require_envelope: bool = True,
) -> dict[str, Any]:
    """Verify the chain, the signatures, the roles and every binding."""
    check_log(log)
    if require_envelope:
        verify_log_envelope(log, verifier)
    rebuilt = new_log()
    for event in log["events"]:
        rebuilt = append(
            rebuilt,
            event,
            assignments=assignments,
            verifier=verifier,
            repo_root=repo_root,
        )
    if rebuilt["logDigest"] != log["logDigest"]:
        _fail(
            CR_REFUSED_HISTORY_ERASED,
            "the replay does not reproduce the recorded log digest",
        )
    subjects = sorted({event["subject"] for event in log["events"]})
    outcomes = {
        subject: current(
            log,
            subject,
            assignments=assignments,
            verifier=verifier,
            repo_root=repo_root,
        )
        for subject in subjects
    }
    return {
        "code": CODE_OK,
        "events": len(log["events"]),
        "subjects": subjects,
        "outcomes": outcomes,
    }


# ---------------------------------------------------------------------------
# Propagation: a dependent that cites a superseded digest is INVALIDATED
# ---------------------------------------------------------------------------


def superseded_digests(event: Mapping[str, Any]) -> list[str]:
    """Every digest a correct/retract supersedes: the value and its record."""
    old = event.get("oldValue") or {}
    digests: list[str] = []
    digest = old.get("digest")
    if isinstance(digest, str) and digest:
        digests.append(digest)
    record = old.get("record") or {}
    bound = record.get("sha256")
    if isinstance(bound, str) and bound and bound not in digests:
        digests.append(bound)
    return digests


def superseded_index(
    log: Mapping[str, Any],
) -> dict[str, list[dict[str, Any]]]:
    index: dict[str, list[dict[str, Any]]] = {}
    for event in log["events"]:
        if event["kind"] not in (KIND_CORRECT, KIND_RETRACT):
            continue
        for digest in superseded_digests(event):
            index.setdefault(digest, []).append(
                {
                    "eventId": event["eventId"],
                    "subject": event["subject"],
                    "kind": event["kind"],
                }
            )
    return index


def _record_dependents(
    index: Mapping[str, Sequence[Mapping[str, Any]]],
    dependents: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for dependent in dependents:
        identifier = dependent.get("id") or dependent.get("path")
        if not isinstance(identifier, str) or not identifier:
            _fail(CR_REFUSED_EVENT_INVALID, "a dependent has an id or path")
        cites = dependent.get("cites", [])
        if not isinstance(cites, list) or not all(
            isinstance(item, str) for item in cites
        ):
            _fail(CR_REFUSED_EVENT_INVALID, f"{identifier}: cites is a list of digests")
        declared = dependent.get("declared") or dependent.get("invalidated")
        if declared not in ("VALID", "INVALIDATED", True, False):
            _fail(
                CR_REFUSED_EVENT_INVALID,
                f"{identifier}: declared is VALID or INVALIDATED",
            )
        if declared is True:
            declared = "INVALIDATED"
        elif declared is False:
            declared = "VALID"
        hits = [digest for digest in cites if digest in index]
        results.append(
            {
                "id": identifier,
                "path": dependent.get("path", identifier),
                "cites": list(cites),
                "supersededCites": hits,
                "supersededBy": sorted(
                    {
                        row["eventId"]
                        for digest in hits
                        for row in index.get(digest, [])
                    }
                ),
                "declared": declared,
                "state": "INVALIDATED" if hits else "VALID",
                "marker": dependent.get("marker"),
                "citations": list(dependent.get("citations", [])),
            }
        )
    return results


def propagate_report(
    log: Mapping[str, Any],
    dependents: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """The full propagation report, with every problem collected, not raised.

    A dependent that cites a superseded digest must be ``INVALIDATED``
    (``CR_REFUSED_INVALIDATION_NOT_PROPAGATED``).  A dependent that is
    ``INVALIDATED`` but cites no superseded digest
    (``CR_REFUSED_SPURIOUS_INVALIDATION``).  ``code`` is the first problem, or
    ``CR_OK``; ``codes`` lists every distinct problem.
    """
    check_log(log)
    index = superseded_index(log)
    results = _record_dependents(index, dependents)
    problems: list[tuple[str, dict[str, Any]]] = []
    for result in results:
        if result["supersededCites"] and result["declared"] != "INVALIDATED":
            problems.append((CR_REFUSED_INVALIDATION_NOT_PROPAGATED, result))
        if not result["supersededCites"] and result["declared"] == "INVALIDATED":
            problems.append((CR_REFUSED_SPURIOUS_INVALIDATION, result))
    codes = sorted({code for code, _ in problems})
    return {
        "code": problems[0][0] if problems else CODE_OK,
        "codes": codes,
        "supersededDigests": sorted(index),
        "dependents": results,
        "summary": {
            "dependents": len(results),
            "invalidated": sum(1 for row in results if row["state"] == "INVALIDATED"),
            "valid": sum(1 for row in results if row["state"] == "VALID"),
            "stale": sum(
                1
                for row in results
                if row["supersededCites"] and row["declared"] != "INVALIDATED"
            ),
            "spurious": sum(
                1
                for row in results
                if not row["supersededCites"] and row["declared"] == "INVALIDATED"
            ),
        },
    }


def propagate(
    log: Mapping[str, Any],
    dependents: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Mark and check propagation, refusing both failure directions."""
    report = propagate_report(log, dependents)
    if report["code"] != CODE_OK:
        first = next(
            row
            for row in report["dependents"]
            if row["declared"] != row["state"]
        )
        _fail(
            report["code"],
            f"{first['id']} cites {first['supersededCites']} and is "
            f"{first['declared']}",
        )
    return report


# Markers that a record uses when it is recording a supersession rather than
# relying on the value.  This is a *reported classification*, not a proof: the
# citation and the marker are both recorded so a reviewer can check the call.
INVALIDATION_MARKERS = (
    "withdrawn",
    "superseded",
    "invalidated",
    "retracted",
    "old recorded value",
    "old value",
    "old counts",
    "old sha-256",
    "old and new",
    "the earlier",
    "no longer",
    "correction",
    "corrected",
    "was wrong",
    "before_reconciliation",
    "preserved",
    "before and after",
    "not a pass",
)

DEPENDENT_SUFFIXES = (".md", ".json", ".py", ".txt")
DEPENDENT_ROOTS = ("evidence", "docs", "forensics/tools", "courts")
DEPENDENT_SKIP_DIRS = (
    "evidence/a19",
    "evidence/etp-t15/history",
    "forensics/downstream",
    "docs/CORRECTIONS.md",
    ".frf",
    ".gemel",
)
MAX_DEPENDENT_BYTES = 2 * 1024 * 1024


def _iter_dependent_files(repo_root: Path) -> Iterable[Path]:
    for root in DEPENDENT_ROOTS:
        base = repo_root / root
        if not base.exists():
            continue
        for path in sorted(base.rglob("*")):
            if not path.is_file() or path.suffix not in DEPENDENT_SUFFIXES:
                continue
            rel = path.relative_to(repo_root).as_posix()
            if any(rel == skip or rel.startswith(skip + "/") for skip in DEPENDENT_SKIP_DIRS):
                continue
            try:
                if path.stat().st_size > MAX_DEPENDENT_BYTES:
                    continue
            except OSError:
                continue
            yield path


def _citation_lines(text: str, token: str, limit: int = 8) -> list[dict[str, Any]]:
    lines = text.splitlines()
    found: list[dict[str, Any]] = []
    for number, line in enumerate(lines, start=1):
        position = line.find(token)
        if position < 0:
            continue
        start = max(0, position - 100)
        end = min(len(line), position + len(token) + 140)
        found.append({"line": number, "text": line[start:end].strip()})
        if len(found) >= limit:
            break
    return found


def _declared_state(text: str, token: str) -> tuple[str, str | None]:
    """Classify a citation by the marker nearest it.  Reported, not proved."""
    lines = text.splitlines()
    hit_lines = [index for index, line in enumerate(lines) if token in line]
    for hit in hit_lines:
        window = " ".join(lines[max(0, hit - 10) : hit + 11]).lower()
        for marker in INVALIDATION_MARKERS:
            if marker in window:
                return "INVALIDATED", marker
    return "VALID", None


def derive_dependents(
    log: Mapping[str, Any],
    repo_root: Path | str = REPO_ROOT,
) -> list[dict[str, Any]]:
    """Build dependencies from the records' own citations.

    Each correct/retract contributes its superseded value digest, its superseded
    record digest and its ``oldValue.citation``.  A file that contains one of
    those tokens cites the superseded record; the citation line and the
    supersession marker are recorded with it.  No dependent list is hand-written.
    """
    check_log(log)
    index = superseded_index(log)
    tokens: dict[str, str] = {}
    for event in log["events"]:
        if event["kind"] not in (KIND_CORRECT, KIND_RETRACT):
            continue
        old = event["oldValue"]
        for digest in superseded_digests(event):
            tokens[digest] = digest
        citation = old.get("citation")
        if isinstance(citation, str) and citation:
            tokens.setdefault(citation, old["digest"])
    root = Path(repo_root)
    rows: list[dict[str, Any]] = []
    for path in _iter_dependent_files(root):
        rel = path.relative_to(root).as_posix()
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        cites: list[str] = []
        citations: list[dict[str, Any]] = []
        declared = "VALID"
        marker: str | None = None
        for token, digest in tokens.items():
            found = _citation_lines(text, token)
            if not found:
                continue
            if digest not in cites:
                cites.append(digest)
            state, token_marker = _declared_state(text, token)
            if state == "INVALIDATED":
                declared = "INVALIDATED"
                marker = marker or token_marker
            for citation in found:
                citations.append(
                    {
                        "path": rel,
                        "line": citation["line"],
                        "text": citation["text"],
                        "token": token,
                    }
                )
        if not cites:
            continue
        rows.append(
            {
                "id": rel,
                "path": rel,
                "cites": cites,
                "declared": declared,
                "marker": marker,
                "citations": citations,
            }
        )
    rows.sort(key=lambda row: row["id"])
    return rows


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------


DEFAULT_LOG = REPO_ROOT / "evidence/a19/EVENTS.json"


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise SystemExit(f"{CODE_USAGE}: cannot read {path}: {error}") from error
    except ValueError as error:
        raise SystemExit(f"{CODE_USAGE}: {path} is not JSON: {error}") from error


def _write_json(path: Path, document: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _command_verify(log_path: Path) -> int:
    log = _read_json(log_path)
    try:
        report = verify_log(log)
    except Refusal as refusal:
        print(f"verify: code={refusal.code} {refusal.message}")
        return 1
    outcomes = sorted(
        {row["outcome"] for row in report["outcomes"].values()}
    )
    print(
        f"verify: code={report['code']} events={report['events']} "
        f"subjects={len(report['subjects'])} outcomes={','.join(outcomes)}"
    )
    for subject in report["subjects"]:
        row = report["outcomes"][subject]
        print(f"  subject={subject} outcome={row['outcome']} "
              f"accepted={row['acceptedEventId']} history={len(row['history'])}")
    return 0


def _command_history(log_path: Path, subject: str) -> int:
    log = _read_json(log_path)
    try:
        row = current(log, subject)
    except Refusal as refusal:
        print(f"history: code={refusal.code} {refusal.message}")
        return 1
    if row["outcome"] == OUTCOME_UNKNOWN:
        print(f"history: code={CODE_UNKNOWN} subject={subject} outcome=UNKNOWN")
        return 1
    print(
        f"history: code={CODE_OK} subject={subject} outcome={row['outcome']} "
        f"accepted={row['acceptedEventId']} events={len(row['history'])}"
    )
    for event in row["history"]:
        supersedes = event.get("supersedes") or {}
        print(
            f"  {event['eventId']} kind={event['kind']} "
            f"supersedes={supersedes.get('previousEventId')} "
            f"at={event['recordedAt']} by={event['recordedBy']['role']}"
        )
    if row["outcome"] == OUTCOME_RETRACTED:
        print("  acceptedValue=<none: retracted>")
    elif row["accepted"] is not None:
        print(f"  acceptedValue={json.dumps(row['accepted']['value'], sort_keys=True)}")
    for reason in row["reasons"]:
        print(f"  reason={reason}")
    return 0


def _command_append(log_path: Path, event_path: Path) -> int:
    log = _read_json(log_path)
    event = _read_json(event_path)
    try:
        produced = append(log, event)
    except Refusal as refusal:
        print(f"append: code={refusal.code} {refusal.message}")
        return 1
    _write_json(log_path, produced)
    print(
        f"append: code={CODE_OK} eventId={event['eventId']} "
        f"kind={event['kind']} subject={event['subject']} "
        f"events={len(produced['events'])} logDigest={produced['logDigest']}"
    )
    return 0


def _command_propagate(log_path: Path, repo_root: Path) -> int:
    log = _read_json(log_path)
    dependents = derive_dependents(log, repo_root)
    try:
        report = propagate(log, dependents)
    except Refusal as refusal:
        print(
            f"propagate: code={refusal.code} dependents={len(dependents)} "
            f"{refusal.message}"
        )
        return 1
    summary = report["summary"]
    print(
        f"propagate: code={report['code']} dependents={summary['dependents']} "
        f"invalidated={summary['invalidated']} valid={summary['valid']} "
        f"supersededDigests={len(report['supersededDigests'])}"
    )
    for row in report["dependents"]:
        print(
            f"  {row['id']} state={row['state']} "
            f"cites={len(row['cites'])} superseded={len(row['supersededCites'])}"
        )
    return 0


def _command_sign_event(event_path: Path) -> int:
    event = _read_json(event_path)
    try:
        produced = sign_event(event)
    except Refusal as refusal:
        print(f"sign-event: code={refusal.code} {refusal.message}")
        return 1
    print(
        "sign-event: "
        f"code={CODE_OK} eventId={produced['eventId']} "
        f"digest={event_digest(produced)}"
    )
    print(json.dumps(produced, indent=2, sort_keys=True))
    return 0


class _Parser(argparse.ArgumentParser):
    """A parser that prints the stable usage code on every usage error."""

    def error(self, message: str) -> None:
        print(f"{CODE_USAGE}: {message}")
        self.exit(2)


def main(argv: Sequence[str] | None = None) -> int:
    parser = _Parser(
        prog="corrections.py",
        description="Append-only, bound, propagating correction log.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--log", type=Path, default=DEFAULT_LOG)

    history_parser = subparsers.add_parser("history")
    history_parser.add_argument("subject")
    history_parser.add_argument("--log", type=Path, default=DEFAULT_LOG)

    append_parser = subparsers.add_parser("append")
    append_parser.add_argument("event", type=Path)
    append_parser.add_argument("--log", type=Path, default=DEFAULT_LOG)

    propagate_parser = subparsers.add_parser("propagate")
    propagate_parser.add_argument("--log", type=Path, default=DEFAULT_LOG)
    propagate_parser.add_argument("--repo-root", type=Path, default=REPO_ROOT)

    sign_parser = subparsers.add_parser("sign-event")
    sign_parser.add_argument("event", type=Path)

    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "verify":
            return _command_verify(arguments.log)
        if arguments.command == "history":
            return _command_history(arguments.log, arguments.subject)
        if arguments.command == "append":
            return _command_append(arguments.log, arguments.event)
        if arguments.command == "propagate":
            return _command_propagate(arguments.log, arguments.repo_root)
        if arguments.command == "sign-event":
            return _command_sign_event(arguments.event)
    except SystemExit as exit_error:
        message = str(exit_error)
        if message:
            print(
                message
                if message.startswith(CODE_USAGE)
                else f"{CODE_USAGE}: {message}"
            )
        return 2
    print(f"{CODE_USAGE}: unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
