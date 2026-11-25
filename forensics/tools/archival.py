#!/usr/bin/env python3
"""archival.py -- durable reconstruction, current-state metadata and anti-rollback.

B6 of ``docs/ETP-ADDENDUM-B.md`` (§B.17, §B.19) asks for one demonstrable
property:

> A withdrawn claim is refused by current-state policy while its original
> inclusion proof remains valid.

That sentence has three parts and this module implements each of them
separately, because conflating them is the defect the item exists to prevent:

  * **the archive** (``ARCHIVE/``) is a set of byte-identified members plus a
    reconstruction procedure that rebuilds a claim's evidence from those bytes
    alone.  It does not consult the working tree: the statement, the inclusion
    proof, the signed checkpoint, the leaf list, the two A19 events and both
    current-state versions are all members and every one is re-hashed.
    A missing member is ``RV_REFUSED_ARCHIVE_MISSING``; a member whose bytes do
    not hash to the recorded digest, or a reconstruction that does not verify,
    is ``RV_REFUSED_RECONSTRUCTION_MISMATCH``.

  * **the current state** (``CURRENT-STATE.json``) is an index over A19's
    correction log, *derived* from ``evidence/a19/EVENTS.json`` through
    ``corrections.py`` rather than written by hand.  Each entry is
    ``{subject, state: ACTIVE|CORRECTED|WITHDRAWN, supersededBy,
    correctionDigest, ...}``.  A withdrawal or correction with no bound A19
    event behind it is ``RV_REFUSED_REVOCATION_UNBOUND``; an A19 correction the
    state does not reflect is ``RV_REFUSED_CORRECTION_UNPROPAGATED``.

  * **the policy** refuses a present-tense use of a subject whose accepted state
    is not ACTIVE (``RV_REFUSED_WITHDRAWN_ACCEPTED``) while the inclusion lookup
    for the same subject must still succeed.  If the proof or the checkpoint was
    discarded, the *inclusion* claim is lost (``RV_REFUSED_INCLUSION_LOST``) --
    withdrawing a claim must not destroy the record of its inclusion.

Anti-rollback is the fourth mechanism: the version is the number of A19 events
the state was derived from, and A19's log is append-only, so a later derivation
covers a superset.  A state whose version decreases is
``RV_REFUSED_ROLLBACK_OF_STATE``; an earlier state file presented as the current
one is ``RV_REFUSED_REPLAY_AS_CURRENT``; two states at one version with different
digests are ``RV_REFUSED_STATE_CONFLICT``.

The normative document is ``docs/ARCHIVAL-REVOCATION.md``; the records are
``evidence/b6/``; the controls are ``forensics/tools/tests/test_archival.py``.

Nothing here is an authentication result.  The only signing key in this tree is
A10's test-only HMAC-SHA256 key, the fixture log is not an admitted log, and A19
records the withdrawal in prose-only events.  The refusal table and the
non-claims in the document say so.

Usage:

    python3 forensics/tools/archival.py current [--state PATH] [--subject S]
    python3 forensics/tools/archival.py inclusion [--archive DIR] [--subject S]
    python3 forensics/tools/archival.py reconstruct [--archive DIR]
    python3 forensics/tools/archival.py derive [--upto N] [--previous PATH]
    python3 forensics/tools/archival.py admit --candidate PATH --accepted PATH
    python3 forensics/tools/archival.py use --subject S [--state PATH]
    python3 forensics/tools/archival.py compare --previous PATH --next PATH

Exit status: 0 only for ``RV_OK``; 1 for a refusal (the code is always printed);
2 for a usage error.  Output is deterministic.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

TOOLS = Path(__file__).resolve().parent
REPO_ROOT = TOOLS.parents[1]
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import corrections  # noqa: E402
import dsse  # noqa: E402
import tlog  # noqa: E402

TOOL_PATH = "forensics/tools/archival.py"
MODEL_ID = "b6/archival/1"
STATE_SCHEMA = "openssl-rs/b6/current-state/1"
ARCHIVE_SCHEMA = "openssl-rs/b6/archive-manifest/1"
ARCHIVE_RECORD_SCHEMA = "openssl-rs/b6/archive/1"
PROOF_SCHEMA = "openssl-rs/b6/inclusion-proof/1"
LEAF_LIST_SCHEMA = "openssl-rs/b6/leaf-list/1"
BINDING_SCHEMA = "openssl-rs/b6/a19-binding/1"

DEFAULT_EVENTS = REPO_ROOT / "evidence/a19/EVENTS.json"
DEFAULT_STATE = REPO_ROOT / "evidence/b6/CURRENT-STATE.json"
DEFAULT_ARCHIVE = REPO_ROOT / "evidence/b6/ARCHIVE"
DEFAULT_SUBJECT = "ETP0-CLM-032/verdict"

EXIT_OK = 0
EXIT_REFUSED = 1
EXIT_USAGE = 2

STATE_ACTIVE = "ACTIVE"
STATE_CORRECTED = "CORRECTED"
STATE_WITHDRAWN = "WITHDRAWN"
STATE_UNKNOWN = "UNKNOWN"
STATES = (STATE_ACTIVE, STATE_CORRECTED, STATE_WITHDRAWN)

# A19 outcome -> current-state.  The mapping is exhaustive over the outcomes
# that carry an accepted state; DISPUTED and UNKNOWN have no current state and
# are refused rather than guessed.
STATE_FROM_OUTCOME = {
    corrections.OUTCOME_CURRENT: STATE_ACTIVE,
    corrections.OUTCOME_CORRECTED: STATE_CORRECTED,
    corrections.OUTCOME_RETRACTED: STATE_WITHDRAWN,
}

CODE_OK = "RV_OK"

RV_REFUSED_USAGE = "RV_REFUSED_USAGE"
RV_REFUSED_IO = "RV_REFUSED_IO"
RV_REFUSED_ARCHIVE_INVALID = "RV_REFUSED_ARCHIVE_INVALID"
RV_REFUSED_ARCHIVE_MISSING = "RV_REFUSED_ARCHIVE_MISSING"
RV_REFUSED_RECONSTRUCTION_MISMATCH = "RV_REFUSED_RECONSTRUCTION_MISMATCH"
RV_REFUSED_STATE_INVALID = "RV_REFUSED_STATE_INVALID"
RV_REFUSED_REVOCATION_UNBOUND = "RV_REFUSED_REVOCATION_UNBOUND"
RV_REFUSED_CORRECTION_UNPROPAGATED = "RV_REFUSED_CORRECTION_UNPROPAGATED"
RV_REFUSED_ROLLBACK_OF_STATE = "RV_REFUSED_ROLLBACK_OF_STATE"
RV_REFUSED_REPLAY_AS_CURRENT = "RV_REFUSED_REPLAY_AS_CURRENT"
RV_REFUSED_STATE_CONFLICT = "RV_REFUSED_STATE_CONFLICT"
RV_REFUSED_WITHDRAWN_ACCEPTED = "RV_REFUSED_WITHDRAWN_ACCEPTED"
RV_REFUSED_SUBJECT_UNKNOWN = "RV_REFUSED_SUBJECT_UNKNOWN"
RV_REFUSED_INCLUSION_LOST = "RV_REFUSED_INCLUSION_LOST"

REFUSALS: dict[str, dict[str, str]] = {
    RV_REFUSED_USAGE: {
        "condition": "the invocation or an argument is malformed",
        "prevents": "a mistyped request read as a check",
    },
    RV_REFUSED_IO: {
        "condition": "a required file cannot be read",
        "prevents": "an unreadable record read as absent or valid",
    },
    RV_REFUSED_ARCHIVE_INVALID: {
        "condition": "the archive manifest is malformed, unbound, or names a path outside the archive",
        "prevents": "an archive whose own contract does not hold treated as a store of bytes",
    },
    RV_REFUSED_ARCHIVE_MISSING: {
        "condition": "the manifest, or a member the manifest requires, is not present",
        "prevents": "a discarded member read as reconstructed",
    },
    RV_REFUSED_RECONSTRUCTION_MISMATCH: {
        "condition": "a member's bytes, a recomputed digest, the inclusion proof, the checkpoint or a state link does not verify",
        "prevents": "bytes that are not the archived member accepted as that member",
    },
    RV_REFUSED_STATE_INVALID: {
        "condition": "the current-state document is malformed, its digest does not cover its bytes, or an entry contradicts its own state",
        "prevents": "a hand-edited or unbound index read as the derived state",
    },
    RV_REFUSED_REVOCATION_UNBOUND: {
        "condition": "a CORRECTED/WITHDRAWN entry names no correction event present in the A19 log at the recorded digest",
        "prevents": "a withdrawal with nothing behind it",
    },
    RV_REFUSED_CORRECTION_UNPROPAGATED: {
        "condition": "the A19 log records a correction or retraction the state does not reflect (absent, ACTIVE, or bound to another event)",
        "prevents": "a correction that leaves the claim looking current",
    },
    RV_REFUSED_ROLLBACK_OF_STATE: {
        "condition": "a newer state's version is lower than the state it would follow",
        "prevents": "an index walked backwards and called current",
    },
    RV_REFUSED_REPLAY_AS_CURRENT: {
        "condition": "a state with an older version is presented as the current state",
        "prevents": "an old index replayed to resurrect a withdrawn claim",
    },
    RV_REFUSED_STATE_CONFLICT: {
        "condition": "two states at one version carry different digests",
        "prevents": "two current histories at one version, one silently preferred",
    },
    RV_REFUSED_WITHDRAWN_ACCEPTED: {
        "condition": "a present-tense use of a subject whose accepted state is WITHDRAWN (or of a superseded value of a CORRECTED subject)",
        "prevents": "a withdrawn claim used as if it were current",
    },
    RV_REFUSED_SUBJECT_UNKNOWN: {
        "condition": "the current state has no entry for the subject",
        "prevents": "an absent state read as an accepted one",
    },
    RV_REFUSED_INCLUSION_LOST: {
        "condition": "the inclusion lookup cannot verify the proof from the archive",
        "prevents": "a withdrawn claim's inclusion record discarded with the claim",
    },
}

REFUSAL_CODES = tuple(REFUSALS)
ALL_CODES = (CODE_OK,) + REFUSAL_CODES

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class Refusal(Exception):
    """A stable refusal code and a human-readable message."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def _fail(code: str, message: str) -> None:
    raise Refusal(code, message)


# ---------------------------------------------------------------------------
# Bytes, digests and small validators
# ---------------------------------------------------------------------------


def canonical(document: Any) -> bytes:
    """The canonical JSON A19 uses for its digests and signed payloads."""
    return corrections.canonical_bytes(document)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path | str) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _is_hex64(value: Any) -> bool:
    return isinstance(value, str) and _HEX64.match(value) is not None


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _require(mapping: Mapping[str, Any], field: str, where: str) -> Any:
    if field not in mapping:
        _fail(RV_REFUSED_STATE_INVALID, f"{where} has no {field!r} field")
    return mapping[field]


def _load_json(path: Path | str, *, what: str) -> Any:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        _fail(RV_REFUSED_IO, f"{what} {path}: {exc}")
    except ValueError as exc:
        _fail(RV_REFUSED_STATE_INVALID, f"{what} {path} is not JSON: {exc}")


def load_events(path: Path | str = DEFAULT_EVENTS) -> dict[str, Any]:
    """Read A19's correction log.  An unreadable log is IO, not an empty one."""
    return _load_json(path, what="the A19 log")


def load_state(path: Path | str) -> dict[str, Any]:
    """Read a current-state document.  The caller validates it."""
    return _load_json(path, what="the current state")


# ---------------------------------------------------------------------------
# The current state: derived from A19, versioned by event count
# ---------------------------------------------------------------------------


def state_digest(document: Mapping[str, Any]) -> str:
    return sha256_bytes(
        canonical({key: value for key, value in document.items() if key != "digest"})
    )


def prefix_log(
    log: Mapping[str, Any],
    upto: int | None = None,
    *,
    assignments: Mapping[str, Iterable[str]] | None = None,
    repo_root: Path | str = REPO_ROOT,
) -> dict[str, Any]:
    """A19's log rebuilt over the first ``upto`` events, with its own digest.

    Rebuilding through ``corrections.append`` re-checks every signature, role and
    binding against the prefix that is actually present, so the prefix is a valid
    A19 log rather than a truncation with the full log's witness still attached.
    """
    total = len(log.get("events", []))
    if upto is None:
        upto = total
    if not _is_int(upto) or upto < 1 or upto > total:
        _fail(
            RV_REFUSED_USAGE,
            f"the state covers 1..{total} A19 events; {upto!r} is not in range",
        )
    produced = corrections.new_log(
        source_identity=log.get("sourceIdentity"),
        authentication=log.get("authentication"),
    )
    for event in log["events"][:upto]:
        try:
            produced = corrections.append(
                produced, event, assignments=assignments, repo_root=repo_root
            )
        except corrections.Refusal as refusal:
            # A log A19 refuses cannot yield a current state.  The A19 code is
            # kept in the message so the cause is not lost.
            _fail(
                RV_REFUSED_STATE_INVALID,
                f"A19 refused the prefix at {event.get('eventId')!r}: "
                f"{refusal.code}: {refusal.message}",
            )
    return produced


def derive_state(
    log: Mapping[str, Any],
    *,
    upto: int | None = None,
    previous: Mapping[str, Any] | None = None,
    assignments: Mapping[str, Iterable[str]] | None = None,
    repo_root: Path | str = REPO_ROOT,
) -> dict[str, Any]:
    """Derive the current-state index from A19's log.

    ``version`` is the number of A19 events covered.  A19's log is append-only
    (A19's own ``CR_REFUSED_HISTORY_ERASED``), so a later derivation covers a
    strict superset and its version is greater; that is the anti-rollback rule.
    """
    prefix = prefix_log(log, upto, assignments=assignments, repo_root=repo_root)
    version = len(prefix["events"])
    subjects = sorted({event["subject"] for event in prefix["events"]})
    rows: list[dict[str, Any]] = []
    for subject in subjects:
        try:
            outcome = corrections.current(
                prefix, subject, assignments=assignments, repo_root=repo_root
            )
        except corrections.Refusal as refusal:
            _fail(
                RV_REFUSED_STATE_INVALID,
                f"A19 refused the chain for {subject!r}: "
                f"{refusal.code}: {refusal.message}",
            )
        state = STATE_FROM_OUTCOME.get(outcome["outcome"])
        if state is None:
            _fail(
                RV_REFUSED_STATE_INVALID,
                f"{subject!r} is {outcome['outcome']}: a disputed or unknown chain "
                "has no current state",
            )
        tip = outcome["history"][-1]
        rows.append(
            {
                "subject": subject,
                "state": state,
                "supersededBy": None if state == STATE_ACTIVE else tip["eventId"],
                "correctionDigest": (
                    None if state == STATE_ACTIVE else corrections.event_digest(tip)
                ),
                "history": [event["eventId"] for event in outcome["history"]],
            }
        )
    last = prefix["events"][-1]
    document: dict[str, Any] = {
        "schema": STATE_SCHEMA,
        "model": MODEL_ID,
        "identity": "current-state",
        "version": version,
        "versionRule": (
            "the version is the number of A19 events the state was derived from; "
            "A19's log is append-only, so a later derivation covers a superset and "
            "its version is strictly greater"
        ),
        "asOf": last["recordedAt"],
        "derivedFrom": {
            "path": "evidence/a19/EVENTS.json",
            "events": version,
            "logDigest": prefix["logDigest"],
            "sourceIdentity": prefix.get("sourceIdentity"),
        },
        "subjects": rows,
    }
    if previous is not None:
        validate_state(previous)
        if previous["version"] >= version:
            _fail(
                RV_REFUSED_ROLLBACK_OF_STATE,
                f"the previous state is version {previous['version']}, not lower "
                f"than the derived {version}",
            )
        document["previous"] = {
            "version": previous["version"],
            "asOf": previous["asOf"],
            "digest": previous["digest"],
        }
    document["digest"] = state_digest(document)
    return document


def state_entry(document: Mapping[str, Any], subject: str) -> dict[str, Any] | None:
    for entry in document["subjects"]:
        if entry["subject"] == subject:
            return dict(entry)
    return None


def _validate_entry(entry: Any, index: int) -> None:
    where = f"subject entry {index}"
    if not isinstance(entry, Mapping):
        _fail(RV_REFUSED_STATE_INVALID, f"{where} is not an object")
    for field in (
        "subject",
        "state",
        "supersededBy",
        "correctionDigest",
        "history",
    ):
        _require(entry, field, where)
    if not isinstance(entry["subject"], str) or not entry["subject"]:
        _fail(RV_REFUSED_STATE_INVALID, f"{where} has no subject text")
    if entry["state"] not in STATES:
        _fail(
            RV_REFUSED_STATE_INVALID,
            f"{where} state {entry['state']!r} is not one of {STATES}",
        )
    if not isinstance(entry["history"], list) or not entry["history"]:
        _fail(RV_REFUSED_STATE_INVALID, f"{where} has no history")
    if entry["state"] == STATE_ACTIVE:
        if entry["supersededBy"] is not None or entry["correctionDigest"] is not None:
            _fail(
                RV_REFUSED_STATE_INVALID,
                f"{where} is ACTIVE and names a correction; an active subject has "
                "none",
            )
        return
    # A non-active state without a bound correction is the withdrawal-with-nothing-
    # behind-it this item refuses.  It is not a structural defect: the document is
    # well formed, it simply asserts a state it cannot bind.
    if not isinstance(entry["supersededBy"], str) or not entry["supersededBy"]:
        _fail(
            RV_REFUSED_REVOCATION_UNBOUND,
            f"{where} ({entry['subject']!r}) is {entry['state']} with no "
            "supersededBy event",
        )
    if not _is_hex64(entry["correctionDigest"]):
        _fail(
            RV_REFUSED_REVOCATION_UNBOUND,
            f"{where} ({entry['subject']!r}) is {entry['state']} with no "
            "correctionDigest",
        )


def _bind_entry(
    entry: Mapping[str, Any],
    by_id: Mapping[str, Mapping[str, Any]],
) -> None:
    """Bind a non-active entry to the exact A19 event it names."""
    if entry["state"] == STATE_ACTIVE:
        return
    event = by_id.get(entry["supersededBy"])
    if event is None:
        _fail(
            RV_REFUSED_REVOCATION_UNBOUND,
            f"{entry['subject']!r} is {entry['state']} and names "
            f"{entry['supersededBy']!r}, which is not in the A19 log",
        )
    if event["subject"] != entry["subject"]:
        _fail(
            RV_REFUSED_REVOCATION_UNBOUND,
            f"{entry['subject']!r} names {entry['supersededBy']!r}, which is about "
            f"{event['subject']!r}",
        )
    expected_kind = (
        corrections.KIND_RETRACT
        if entry["state"] == STATE_WITHDRAWN
        else corrections.KIND_CORRECT
    )
    if event["kind"] != expected_kind:
        _fail(
            RV_REFUSED_REVOCATION_UNBOUND,
            f"{entry['subject']!r} is {entry['state']} but {entry['supersededBy']!r} "
            f"is a {event['kind']}, not a {expected_kind}",
        )
    if corrections.event_digest(event) != entry["correctionDigest"]:
        _fail(
            RV_REFUSED_REVOCATION_UNBOUND,
            f"{entry['subject']!r} correctionDigest is not the canonical digest of "
            f"{entry['supersededBy']!r}",
        )


def validate_state(
    document: Any,
    log: Mapping[str, Any] | None = None,
) -> None:
    """Structural and (when the log is supplied) binding checks on a state."""
    if not isinstance(document, Mapping):
        _fail(RV_REFUSED_STATE_INVALID, "a current state is a JSON object")
    for field in (
        "schema",
        "model",
        "identity",
        "version",
        "asOf",
        "derivedFrom",
        "subjects",
        "digest",
    ):
        _require(document, field, "the current state")
    if document["schema"] != STATE_SCHEMA:
        _fail(
            RV_REFUSED_STATE_INVALID,
            f"schema {document['schema']!r} is not {STATE_SCHEMA!r}",
        )
    if document["model"] != MODEL_ID:
        _fail(
            RV_REFUSED_STATE_INVALID,
            f"model {document['model']!r} is not {MODEL_ID!r}",
        )
    if not _is_int(document["version"]) or document["version"] < 1:
        _fail(RV_REFUSED_STATE_INVALID, "version is a positive integer")
    if not isinstance(document["asOf"], str) or not document["asOf"]:
        _fail(RV_REFUSED_STATE_INVALID, "asOf is a date-time string")
    subjects = document["subjects"]
    if not isinstance(subjects, list) or not subjects:
        _fail(RV_REFUSED_STATE_INVALID, "subjects is a non-empty list")
    recorded = document["digest"]
    if not _is_hex64(recorded):
        _fail(RV_REFUSED_STATE_INVALID, "digest is not SHA-256")
    if recorded != state_digest(document):
        _fail(
            RV_REFUSED_STATE_INVALID,
            "the state digest does not cover the document's bytes",
        )
    seen: set[str] = set()
    for index, entry in enumerate(subjects):
        _validate_entry(entry, index)
        if entry["subject"] in seen:
            _fail(
                RV_REFUSED_STATE_INVALID,
                f"subject {entry['subject']!r} appears twice",
            )
        seen.add(entry["subject"])
    previous = document.get("previous")
    if previous is not None:
        if not isinstance(previous, Mapping):
            _fail(RV_REFUSED_STATE_INVALID, "previous is an object")
        if not _is_int(previous.get("version")) or not _is_hex64(
            previous.get("digest")
        ):
            _fail(
                RV_REFUSED_STATE_INVALID,
                "previous names a version and a SHA-256 digest",
            )
        if previous["version"] >= document["version"]:
            _fail(
                RV_REFUSED_ROLLBACK_OF_STATE,
                f"previous version {previous['version']} is not lower than "
                f"{document['version']}",
            )
    if log is not None:
        corrections.check_log(log)
        by_id = {event["eventId"]: event for event in log["events"]}
        for entry in subjects:
            _bind_entry(entry, by_id)


def check_propagation(
    document: Mapping[str, Any],
    log: Mapping[str, Any],
    *,
    assignments: Mapping[str, Iterable[str]] | None = None,
    repo_root: Path | str = REPO_ROOT,
) -> dict[str, Any]:
    """Every A19 correction must be reflected by the state, and only exactly.

    The reverse direction -- a state that asserts a withdrawal the log does not
    record -- is refused by ``validate_state(document, log)`` as
    ``RV_REFUSED_REVOCATION_UNBOUND`` before this function counts anything.
    """
    validate_state(document, log)
    entries = {entry["subject"]: entry for entry in document["subjects"]}
    subjects = sorted({event["subject"] for event in log["events"]})
    problems: list[dict[str, Any]] = []
    for subject in subjects:
        try:
            outcome = corrections.current(
                log, subject, assignments=assignments, repo_root=repo_root
            )
        except corrections.Refusal as refusal:
            _fail(
                RV_REFUSED_STATE_INVALID,
                f"A19 refused the chain for {subject!r}: "
                f"{refusal.code}: {refusal.message}",
            )
        expected = STATE_FROM_OUTCOME.get(outcome["outcome"])
        entry = entries.get(subject)
        if entry is None:
            problems.append(
                {"subject": subject, "reason": "absent", "expected": expected}
            )
            continue
        if expected is None:
            _fail(
                RV_REFUSED_STATE_INVALID,
                f"A19 reports {subject!r} as {outcome['outcome']}",
            )
        if entry["state"] != expected:
            problems.append(
                {
                    "subject": subject,
                    "reason": "state",
                    "expected": expected,
                    "recorded": entry["state"],
                }
            )
        elif expected != STATE_ACTIVE and entry["supersededBy"] != outcome[
            "acceptedEventId"
        ]:
            problems.append(
                {
                    "subject": subject,
                    "reason": "supersededBy",
                    "expected": outcome["acceptedEventId"],
                    "recorded": entry["supersededBy"],
                }
            )
    for subject in sorted(entries):
        if subject not in subjects:
            problems.append(
                {"subject": subject, "reason": "not-in-log", "expected": None}
            )
    if problems:
        first = problems[0]
        _fail(
            RV_REFUSED_CORRECTION_UNPROPAGATED,
            f"{first['subject']!r}: {first['reason']} (expected "
            f"{first['expected']!r}); {len(problems)} problem(s)",
        )
    return {
        "code": CODE_OK,
        "version": document["version"],
        "events": len(log["events"]),
        "subjects": len(subjects),
        "checked": len(subjects),
    }


def current(
    document: Mapping[str, Any],
    subject: str,
    *,
    log: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """The accepted state for ``subject``; refusal is not this function's job."""
    validate_state(document, log)
    if not isinstance(subject, str) or not subject:
        _fail(RV_REFUSED_USAGE, "the subject is a non-empty string")
    entry = state_entry(document, subject)
    if entry is None:
        return {
            "code": CODE_OK,
            "subject": subject,
            "state": STATE_UNKNOWN,
            "version": document["version"],
            "asOf": document["asOf"],
            "entry": None,
        }
    return {
        "code": CODE_OK,
        "subject": subject,
        "state": entry["state"],
        "version": document["version"],
        "asOf": document["asOf"],
        "supersededBy": entry["supersededBy"],
        "correctionDigest": entry["correctionDigest"],
        "entry": entry,
    }


def present_tense(
    document: Mapping[str, Any],
    subject: str,
    *,
    log: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Use ``subject`` as a current claim, or refuse.

    This is the policy half of the item: a withdrawn claim fails here even when
    its inclusion proof verifies, and the refusal names the event that withdrew
    it so the caller can still reach the record.
    """
    result = current(document, subject, log=log)
    state = result["state"]
    if state == STATE_ACTIVE:
        return result
    if state == STATE_WITHDRAWN:
        _fail(
            RV_REFUSED_WITHDRAWN_ACCEPTED,
            f"{subject!r} was withdrawn by {result['supersededBy']} (state version "
            f"{result['version']}); its inclusion may still be proven but it is not "
            "current",
        )
    if state == STATE_CORRECTED:
        _fail(
            RV_REFUSED_WITHDRAWN_ACCEPTED,
            f"{subject!r} was corrected by {result['supersededBy']}; the archived "
            "value is superseded and is not current",
        )
    _fail(
        RV_REFUSED_SUBJECT_UNKNOWN,
        f"the current state has no entry for {subject!r}",
    )


def check_monotonic(
    previous: Mapping[str, Any],
    next_state: Mapping[str, Any],
) -> dict[str, Any]:
    """The producer's own rule: a state's version may not decrease."""
    validate_state(previous)
    validate_state(next_state)
    if next_state["version"] < previous["version"]:
        _fail(
            RV_REFUSED_ROLLBACK_OF_STATE,
            f"state version {next_state['version']} is lower than the previous "
            f"{previous['version']}: a version may not decrease",
        )
    return {
        "code": CODE_OK,
        "from": previous["version"],
        "to": next_state["version"],
    }


def admit(
    candidate: Mapping[str, Any],
    accepted: Mapping[str, Any],
    *,
    log: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Admit ``candidate`` as the current state, or refuse.

    Order matters: an older version is a replay before it is anything else, and
    only the exact accepted document may be re-admitted at its own version.
    """
    validate_state(candidate, log)
    validate_state(accepted, log)
    if candidate["version"] < accepted["version"]:
        _fail(
            RV_REFUSED_REPLAY_AS_CURRENT,
            f"state version {candidate['version']} is older than the accepted "
            f"{accepted['version']}: an old state cannot be presented as current",
        )
    if candidate["version"] == accepted["version"]:
        if candidate["digest"] != accepted["digest"]:
            _fail(
                RV_REFUSED_STATE_CONFLICT,
                f"two states at version {candidate['version']} carry different "
                f"digests ({candidate['digest']} and {accepted['digest']})",
            )
        return {
            "code": CODE_OK,
            "outcome": "UNCHANGED",
            "version": candidate["version"],
        }
    previous = candidate.get("previous")
    if not isinstance(previous, Mapping) or previous.get("digest") != accepted["digest"]:
        _fail(
            RV_REFUSED_STATE_INVALID,
            f"a newer state (version {candidate['version']}) must name the accepted "
            "state (version "
            f"{accepted['version']}) as its previous digest",
        )
    return {
        "code": CODE_OK,
        "outcome": "ADVANCED",
        "from": accepted["version"],
        "to": candidate["version"],
    }


# ---------------------------------------------------------------------------
# The archive: a self-contained set of byte-identified members
# ---------------------------------------------------------------------------


def _safe_member_path(archive_dir: Path, relative: Any) -> Path:
    if not isinstance(relative, str) or not relative:
        _fail(RV_REFUSED_ARCHIVE_INVALID, "a member path is a non-empty string")
    candidate = Path(relative)
    if candidate.is_absolute() or ".." in candidate.parts:
        _fail(
            RV_REFUSED_ARCHIVE_INVALID,
            f"member path {relative!r} is not relative to the archive",
        )
    resolved = (archive_dir / candidate).resolve()
    if not resolved.is_relative_to(archive_dir.resolve()):
        _fail(
            RV_REFUSED_ARCHIVE_INVALID,
            f"member path {relative!r} resolves outside the archive",
        )
    return resolved


def validate_manifest(document: Any) -> None:
    if not isinstance(document, Mapping):
        _fail(RV_REFUSED_ARCHIVE_INVALID, "an archive manifest is a JSON object")
    for field in (
        "schema",
        "model",
        "archiveId",
        "identity",
        "signer",
        "members",
        "claims",
        "manifestDigest",
    ):
        if field not in document:
            _fail(RV_REFUSED_ARCHIVE_INVALID, f"the manifest has no {field!r}")
    if document["schema"] != ARCHIVE_SCHEMA:
        _fail(
            RV_REFUSED_ARCHIVE_INVALID,
            f"schema {document['schema']!r} is not {ARCHIVE_SCHEMA!r}",
        )
    if document["model"] != MODEL_ID:
        _fail(RV_REFUSED_ARCHIVE_INVALID, f"model is not {MODEL_ID!r}")
    if not isinstance(document["archiveId"], str) or not document["archiveId"]:
        _fail(RV_REFUSED_ARCHIVE_INVALID, "archiveId is a non-empty string")
    if not isinstance(document["identity"], str) or not document["identity"]:
        _fail(RV_REFUSED_ARCHIVE_INVALID, "identity is a non-empty string")
    signer = document["signer"]
    if not isinstance(signer, Mapping) or not isinstance(signer.get("name"), str):
        _fail(RV_REFUSED_ARCHIVE_INVALID, "signer names a note key")
    members = document["members"]
    if not isinstance(members, list) or not members:
        _fail(RV_REFUSED_ARCHIVE_INVALID, "members is a non-empty list")
    ids: set[str] = set()
    paths: set[str] = set()
    for index, member in enumerate(members):
        if not isinstance(member, Mapping):
            _fail(RV_REFUSED_ARCHIVE_INVALID, f"member {index} is not an object")
        for field in ("id", "path", "bytes", "sha256", "role"):
            if field not in member:
                _fail(
                    RV_REFUSED_ARCHIVE_INVALID,
                    f"member {index} has no {field!r}",
                )
        if not isinstance(member["id"], str) or not member["id"]:
            _fail(RV_REFUSED_ARCHIVE_INVALID, f"member {index} has no id")
        if member["id"] in ids:
            _fail(
                RV_REFUSED_ARCHIVE_INVALID, f"member id {member['id']!r} is reused"
            )
        ids.add(member["id"])
        if not isinstance(member["path"], str) or member["path"] in paths:
            _fail(
                RV_REFUSED_ARCHIVE_INVALID,
                f"member {member['id']!r} has no unique path",
            )
        paths.add(member["path"])
        if not _is_int(member["bytes"]) or member["bytes"] < 0:
            _fail(
                RV_REFUSED_ARCHIVE_INVALID,
                f"member {member['id']!r} bytes is a non-negative integer",
            )
        if not _is_hex64(member["sha256"]):
            _fail(
                RV_REFUSED_ARCHIVE_INVALID,
                f"member {member['id']!r} sha256 is not SHA-256",
            )
    claims = document["claims"]
    if not isinstance(claims, list) or not claims:
        _fail(RV_REFUSED_ARCHIVE_INVALID, "claims is a non-empty list")
    for claim in claims:
        if not isinstance(claim, Mapping):
            _fail(RV_REFUSED_ARCHIVE_INVALID, "a claim is an object")
        if claim.get("statementId") not in ids:
            _fail(
                RV_REFUSED_ARCHIVE_INVALID,
                f"claim {claim.get('subject')!r} names no statement member",
            )
        if not _is_int(claim.get("leafIndex")) or claim["leafIndex"] < 0:
            _fail(
                RV_REFUSED_ARCHIVE_INVALID,
                f"claim {claim.get('subject')!r} leafIndex is an index",
            )
        if not isinstance(claim.get("subject"), str) or not claim["subject"]:
            _fail(RV_REFUSED_ARCHIVE_INVALID, "a claim names its subject")
        if not isinstance(claim.get("statementSubject"), str) or not claim[
            "statementSubject"
        ]:
            _fail(
                RV_REFUSED_ARCHIVE_INVALID,
                "a claim names the subject its statement carries",
            )
    recorded = document["manifestDigest"]
    if not _is_hex64(recorded):
        _fail(RV_REFUSED_ARCHIVE_INVALID, "manifestDigest is not SHA-256")
    recomputed = sha256_bytes(
        canonical(
            {
                key: value
                for key, value in document.items()
                if key != "manifestDigest"
            }
        )
    )
    if recomputed != recorded:
        _fail(
            RV_REFUSED_ARCHIVE_INVALID,
            "the manifest digest does not cover the manifest's bytes",
        )


def manifest_digest(document: Mapping[str, Any]) -> str:
    return sha256_bytes(
        canonical(
            {key: value for key, value in document.items() if key != "manifestDigest"}
        )
    )


def load_manifest(archive_dir: Path | str) -> dict[str, Any]:
    path = Path(archive_dir) / "MANIFEST.json"
    if not path.is_file():
        _fail(
            RV_REFUSED_ARCHIVE_MISSING,
            f"the archive has no MANIFEST.json at {path}",
        )
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        _fail(RV_REFUSED_IO, f"the archive manifest {path}: {exc}")
    except ValueError as exc:
        _fail(RV_REFUSED_ARCHIVE_INVALID, f"the archive manifest is not JSON: {exc}")
    validate_manifest(document)
    return document


def read_members(
    archive_dir: Path | str, manifest: Mapping[str, Any]
) -> dict[str, bytes]:
    """Read and re-hash every member.  The archive is the only input."""
    base = Path(archive_dir)
    produced: dict[str, bytes] = {}
    for member in manifest["members"]:
        path = _safe_member_path(base, member["path"])
        if not path.is_file():
            _fail(
                RV_REFUSED_ARCHIVE_MISSING,
                f"member {member['id']!r} is absent ({member['path']})",
            )
        try:
            data = path.read_bytes()
        except OSError as exc:
            _fail(RV_REFUSED_IO, f"member {member['id']!r}: {exc}")
        digest = sha256_bytes(data)
        if digest != member["sha256"]:
            _fail(
                RV_REFUSED_RECONSTRUCTION_MISMATCH,
                f"member {member['id']!r} hashes to {digest}, not the recorded "
                f"{member['sha256']}",
            )
        if len(data) != member["bytes"]:
            _fail(
                RV_REFUSED_RECONSTRUCTION_MISMATCH,
                f"member {member['id']!r} is {len(data)} bytes, not the recorded "
                f"{member['bytes']}",
            )
        produced[member["id"]] = data
    return produced


def _member(members: Mapping[str, bytes], member_id: str) -> bytes:
    data = members.get(member_id)
    if data is None:
        _fail(
            RV_REFUSED_ARCHIVE_INVALID,
            f"the archive names no member {member_id!r} for the reconstruction",
        )
    return data


def _member_json(data: bytes, what: str) -> Any:
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        _fail(
            RV_REFUSED_RECONSTRUCTION_MISMATCH,
            f"{what} is not valid JSON: {exc}",
        )


def _hex_bytes(value: Any, where: str) -> bytes:
    if not isinstance(value, str):
        _fail(
            RV_REFUSED_RECONSTRUCTION_MISMATCH,
            f"{where} is not a hexadecimal string",
        )
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        _fail(RV_REFUSED_RECONSTRUCTION_MISMATCH, f"{where}: {exc}")


def reconstruct(
    archive_dir: Path | str = DEFAULT_ARCHIVE,
    *,
    key: bytes | None = None,
) -> dict[str, Any]:
    """Rebuild the claim's evidence from the archive's bytes alone.

    The working tree is not consulted.  ``key`` defaults to A10's test-only
    HMAC-SHA256 key: the fixture checkpoint is signed by it, and the result
    records that this proves byte integrity under a public test key, not identity.
    """
    archive = Path(archive_dir)
    manifest = load_manifest(archive)
    members = read_members(archive, manifest)
    checks: list[dict[str, Any]] = [
        {
            "name": "member-digests",
            "members": len(manifest["members"]),
            "ok": True,
        },
        {"name": "manifest-digest", "digest": manifest["manifestDigest"], "ok": True},
    ]

    identity = manifest["identity"]
    signer_name = manifest["signer"]["name"]
    note = _member(members, "checkpoint")
    proof_document = _member_json(
        _member(members, "inclusion-proof"), "the inclusion proof"
    )
    if not isinstance(proof_document, Mapping):
        _fail(
            RV_REFUSED_RECONSTRUCTION_MISMATCH,
            "the inclusion proof is not a JSON object",
        )
    if proof_document.get("schema") != PROOF_SCHEMA:
        _fail(
            RV_REFUSED_RECONSTRUCTION_MISMATCH,
            f"the inclusion proof schema is {proof_document.get('schema')!r}",
        )
    leaf_index = proof_document.get("leafIndex")
    tree_size = proof_document.get("treeSize")
    if not _is_int(leaf_index) or not _is_int(tree_size):
        _fail(
            RV_REFUSED_RECONSTRUCTION_MISMATCH,
            "the inclusion proof has no integer leafIndex/treeSize",
        )
    proof = [_hex_bytes(value, "a proof element") for value in proof_document["proof"]]

    chosen = key if key is not None else dsse.test_only_key()
    try:
        head = tlog.verify_checkpoint(
            note,
            key_name=signer_name,
            key=chosen,
            expected_origin=identity,
        )
    except tlog.Refusal as refusal:
        _fail(
            RV_REFUSED_RECONSTRUCTION_MISMATCH,
            f"the archived checkpoint does not verify: {refusal.code}: "
            f"{refusal.message}",
        )
    if head.size != tree_size:
        _fail(
            RV_REFUSED_RECONSTRUCTION_MISMATCH,
            f"the checkpoint is size {head.size}, the proof is for size {tree_size}",
        )
    checks.append(
        {
            "name": "checkpoint-signature",
            "origin": head.origin,
            "size": head.size,
            "root": head.root.hex(),
            "keyName": head.signature.name,
            "ok": True,
        }
    )

    publication = _member_json(_member(members, "publication"), "the publication record")
    if not isinstance(publication, Mapping):
        _fail(
            RV_REFUSED_RECONSTRUCTION_MISMATCH,
            "the publication record is not a JSON object",
        )
    if (
        publication.get("leafIndex") != leaf_index
        or publication.get("treeSize") != tree_size
        or publication.get("rootHash") != head.root.hex()
    ):
        _fail(
            RV_REFUSED_RECONSTRUCTION_MISMATCH,
            "the archived publication record does not name this claim's leaf, tree "
            "size and root",
        )
    checks.append(
        {
            "name": "publication-record",
            "leafIndex": publication["leafIndex"],
            "treeSize": publication["treeSize"],
            "ok": True,
        }
    )

    claim = next(
        (
            row
            for row in manifest["claims"]
            if row["statementId"] == "statement-fixture"
        ),
        None,
    )
    statement = _member(members, "statement-fixture")
    if claim is None:
        _fail(
            RV_REFUSED_ARCHIVE_INVALID,
            "the manifest does not name the fixture statement as a claim",
        )
    if claim["leafIndex"] != leaf_index:
        _fail(
            RV_REFUSED_RECONSTRUCTION_MISMATCH,
            f"the claim is at index {claim['leafIndex']}, the proof at {leaf_index}",
        )
    if proof_document.get("leafSha256") != sha256_bytes(statement):
        _fail(
            RV_REFUSED_RECONSTRUCTION_MISMATCH,
            "the statement bytes are not the leaf the proof names",
        )
    if proof_document.get("leafHash") != tlog.leaf_hash(statement).hex():
        _fail(
            RV_REFUSED_RECONSTRUCTION_MISMATCH,
            "the statement does not hash to the recorded leaf hash",
        )
    checks.append(
        {
            "name": "leaf-identity",
            "leafIndex": leaf_index,
            "leafHash": tlog.leaf_hash(statement).hex(),
            "ok": True,
        }
    )

    try:
        tlog.verify_inclusion(statement, leaf_index, tree_size, proof, head.root)
    except tlog.Refusal as refusal:
        _fail(
            RV_REFUSED_RECONSTRUCTION_MISMATCH,
            f"the archived inclusion proof does not verify: {refusal.code}: "
            f"{refusal.message}",
        )
    checks.append(
        {
            "name": "inclusion",
            "leafIndex": leaf_index,
            "treeSize": tree_size,
            "proofElements": len(proof),
            "root": head.root.hex(),
            "ok": True,
        }
    )

    leaf_list = _member_json(_member(members, "leaf-list"), "the leaf list")
    if not isinstance(leaf_list, Mapping) or leaf_list.get("schema") != LEAF_LIST_SCHEMA:
        _fail(
            RV_REFUSED_RECONSTRUCTION_MISMATCH,
            "the archived leaf list does not carry the expected schema",
        )
    leaves = leaf_list.get("leaves")
    if not isinstance(leaves, list) or len(leaves) != tree_size:
        _fail(
            RV_REFUSED_RECONSTRUCTION_MISMATCH,
            "the archived leaf list does not cover the checkpoint's tree size",
        )
    hashes = [
        _hex_bytes(leaf.get("leafHash"), f"leaf {position} hash")
        for position, leaf in enumerate(leaves)
        if isinstance(leaf, Mapping)
    ]
    if len(hashes) != tree_size:
        _fail(
            RV_REFUSED_RECONSTRUCTION_MISMATCH,
            "an archived leaf entry is not an object",
        )
    recomputed_root = tlog.root_from_leaf_hashes(hashes)
    if recomputed_root != head.root:
        _fail(
            RV_REFUSED_RECONSTRUCTION_MISMATCH,
            "the archived leaf list recomputes a different root than the checkpoint",
        )
    if hashes[leaf_index] != tlog.leaf_hash(statement):
        _fail(
            RV_REFUSED_RECONSTRUCTION_MISMATCH,
            "the archived leaf at the claim's index is not this statement",
        )
    checks.append(
        {
            "name": "tree-root",
            "leaves": tree_size,
            "root": recomputed_root.hex(),
            "ok": True,
        }
    )

    subject = claim["subject"]
    try:
        statement_document = json.loads(statement.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        _fail(
            RV_REFUSED_RECONSTRUCTION_MISMATCH,
            f"the archived statement is not JSON: {exc}",
        )
    bindings = statement_document.get("subject")
    if not isinstance(bindings, list) or len(bindings) != 1:
        _fail(
            RV_REFUSED_RECONSTRUCTION_MISMATCH,
            "the fixture statement has exactly one subject",
        )
    digest = (bindings[0].get("digest") or {}).get("sha256")
    if bindings[0].get("name") != claim["statementSubject"]:
        _fail(
            RV_REFUSED_RECONSTRUCTION_MISMATCH,
            "the statement's subject name is not the manifest's claim",
        )
    predicate = statement_document.get("predicate") or {}
    retracted_by = (predicate.get("retractedBy") or {}).get("digest")

    # The A19 binding is archived as event *identities* (event id and canonical
    # event digest), not as copies of the events.  A copy would duplicate the
    # withdrawn value's digest, which is the original record itself rather than a
    # citation of it, and A19's citation scan has no way to tell the two apart
    # outside its own directory.  The event bytes remain in
    # ``evidence/a19/EVENTS.json``; re-deriving an event digest from its bytes is
    # therefore NOT part of this reconstruction, and the document says so.
    a19_binding = _member_json(
        _member(members, "a19-binding"), "the A19 binding"
    )
    if not isinstance(a19_binding, Mapping) or a19_binding.get(
        "schema"
    ) != BINDING_SCHEMA:
        _fail(
            RV_REFUSED_RECONSTRUCTION_MISMATCH,
            "the archived A19 binding does not carry the expected schema",
        )
    if a19_binding.get("subject") != subject:
        _fail(
            RV_REFUSED_RECONSTRUCTION_MISMATCH,
            "the archived A19 binding names another subject",
        )
    assertion = a19_binding.get("assertion") or {}
    retraction = a19_binding.get("retraction") or {}
    if digest != assertion.get("digest"):
        _fail(
            RV_REFUSED_RECONSTRUCTION_MISMATCH,
            "the statement's subject digest is not the archived assertion event "
            "digest",
        )
    if retracted_by != retraction.get("digest"):
        _fail(
            RV_REFUSED_RECONSTRUCTION_MISMATCH,
            "the statement does not name the archived retraction event",
        )
    checks.append(
        {
            "name": "statement-binding",
            "subject": subject,
            "assertionDigest": digest,
            "retractionDigest": retracted_by,
            "binding": "digest-reference (event bytes not duplicated)",
            "ok": True,
        }
    )

    earlier = _member_json(_member(members, "state-earlier"), "the earlier state")
    later = _member_json(_member(members, "state-current"), "the current state")
    for name, document in (("earlier", earlier), ("current", later)):
        try:
            validate_state(document)
        except Refusal as refusal:
            _fail(
                RV_REFUSED_RECONSTRUCTION_MISMATCH,
                f"the archived {name} state does not validate: {refusal.code}: "
                f"{refusal.message}",
            )
    previous = later.get("previous")
    if not isinstance(previous, Mapping) or previous.get("digest") != earlier["digest"]:
        _fail(
            RV_REFUSED_RECONSTRUCTION_MISMATCH,
            "the current state does not name the archived earlier state",
        )
    if later["version"] <= earlier["version"]:
        _fail(
            RV_REFUSED_RECONSTRUCTION_MISMATCH,
            "the archived current state is not later than the archived earlier state",
        )
    subject_state = current(later, subject)
    if subject_state["state"] != STATE_WITHDRAWN:
        _fail(
            RV_REFUSED_RECONSTRUCTION_MISMATCH,
            f"the archived current state records {subject_state['state']!r} for the "
            "claim, not WITHDRAWN",
        )
    if (
        subject_state["supersededBy"] != retraction.get("eventId")
        or subject_state["correctionDigest"] != retraction.get("digest")
    ):
        _fail(
            RV_REFUSED_RECONSTRUCTION_MISMATCH,
            "the archived current state does not bind the withdrawal to the "
            "archived retraction event",
        )
    if assertion.get("eventId") not in subject_state["entry"]["history"]:
        _fail(
            RV_REFUSED_RECONSTRUCTION_MISMATCH,
            "the archived current state does not record the archived assertion "
            "event in the subject's history",
        )
    checks.append(
        {
            "name": "state-link",
            "earlierVersion": earlier["version"],
            "currentVersion": later["version"],
            "subjectState": subject_state["state"],
            "ok": True,
        }
    )

    return {
        "code": CODE_OK,
        "archiveId": manifest["archiveId"],
        "identity": identity,
        "manifestDigest": manifest["manifestDigest"],
        "members": len(manifest["members"]),
        "bytes": sum(member["bytes"] for member in manifest["members"]),
        "checks": checks,
        "checkpoint": {
            "origin": head.origin,
            "size": head.size,
            "root": head.root.hex(),
            "signatureName": head.signature.name,
            "notATrustRoot": True,
        },
        "inclusion": {
            "leafIndex": leaf_index,
            "treeSize": tree_size,
            "leafHash": tlog.leaf_hash(statement).hex(),
            "verified": True,
        },
        "subject": subject,
        "state": {
            "version": later["version"],
            "state": subject_state["state"],
            "supersededBy": subject_state["supersededBy"],
        },
    }


def inclusion_lookup(
    archive_dir: Path | str = DEFAULT_ARCHIVE,
    subject: str | None = None,
    *,
    key: bytes | None = None,
) -> dict[str, Any]:
    """Look up the claim's inclusion in the archive, whatever its current state.

    A withdrawal must not destroy the record: this function succeeds for a
    WITHDRAWN subject.  When the archive, the proof or the checkpoint has been
    discarded, the *inclusion* claim is what is lost, so every archive-side
    failure is reported as ``RV_REFUSED_INCLUSION_LOST`` with its cause.
    """
    try:
        manifest = load_manifest(archive_dir)
        chosen = subject
        if chosen is None:
            chosen = manifest["claims"][0]["subject"]
        claim = next(
            (row for row in manifest["claims"] if row["subject"] == chosen), None
        )
        if claim is None:
            _fail(
                RV_REFUSED_SUBJECT_UNKNOWN,
                f"the archive holds no claim about {chosen!r}",
            )
        result = reconstruct(archive_dir, key=key)
    except Refusal as refusal:
        if refusal.code in (
            RV_REFUSED_ARCHIVE_MISSING,
            RV_REFUSED_ARCHIVE_INVALID,
            RV_REFUSED_RECONSTRUCTION_MISMATCH,
            RV_REFUSED_IO,
        ):
            _fail(
                RV_REFUSED_INCLUSION_LOST,
                f"the proof cannot be verified from the archive: {refusal.code}: "
                f"{refusal.message}",
            )
        raise
    if result["inclusion"]["leafIndex"] != claim["leafIndex"]:
        _fail(
            RV_REFUSED_INCLUSION_LOST,
            "the reconstructed leaf index is not the claim's recorded index",
        )
    return {
        "code": CODE_OK,
        "subject": chosen,
        "leafIndex": result["inclusion"]["leafIndex"],
        "treeSize": result["inclusion"]["treeSize"],
        "leafHash": result["inclusion"]["leafHash"],
        "root": result["checkpoint"]["root"],
        "verified": True,
        "checkpointSize": result["checkpoint"]["size"],
        "signatureName": result["checkpoint"]["signatureName"],
        "manifestDigest": result["manifestDigest"],
    }


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="archival.py",
        description=(
            "B6: reconstruct archived evidence, report the current state, and "
            "refuse a replayed or rolled-back index."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    current_parser = sub.add_parser("current", help="print the current state")
    current_parser.add_argument("--state", default=str(DEFAULT_STATE))
    current_parser.add_argument("--subject")

    inclusion_parser = sub.add_parser(
        "inclusion", help="verify the claim's inclusion from the archive"
    )
    inclusion_parser.add_argument("--archive", default=str(DEFAULT_ARCHIVE))
    inclusion_parser.add_argument("--subject")

    reconstruct_parser = sub.add_parser(
        "reconstruct", help="rebuild the claim's evidence from the archive"
    )
    reconstruct_parser.add_argument("--archive", default=str(DEFAULT_ARCHIVE))

    derive_parser = sub.add_parser("derive", help="derive a state from A19")
    derive_parser.add_argument("--events", default=str(DEFAULT_EVENTS))
    derive_parser.add_argument("--upto", type=int)
    derive_parser.add_argument("--previous")
    derive_parser.add_argument("--out")

    admit_parser = sub.add_parser("admit", help="admit a state as current")
    admit_parser.add_argument("--candidate", required=True)
    admit_parser.add_argument("--accepted", required=True)

    use_parser = sub.add_parser("use", help="use a subject as a current claim")
    use_parser.add_argument("--subject", required=True)
    use_parser.add_argument("--state", default=str(DEFAULT_STATE))

    compare_parser = sub.add_parser("compare", help="check version monotonicity")
    compare_parser.add_argument("--previous", required=True)
    compare_parser.add_argument("--next", required=True)

    return parser


def _print_result(result: Mapping[str, Any]) -> None:
    fields = []
    for key, value in result.items():
        if isinstance(value, (dict, list)):
            continue
        fields.append(f"{key}={value}")
    print(" ".join(fields))


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    try:
        arguments = parser.parse_args(argv)
    except SystemExit as exit_request:
        return EXIT_OK if exit_request.code == 0 else EXIT_USAGE

    try:
        if arguments.command == "current":
            document = load_state(arguments.state)
            validate_state(document)
            counts = {state: 0 for state in STATES}
            for entry in document["subjects"]:
                counts[entry["state"]] += 1
            result: dict[str, Any] = {
                "code": CODE_OK,
                "version": document["version"],
                "asOf": document["asOf"],
                "digest": document["digest"],
                "subjects": len(document["subjects"]),
                "active": counts[STATE_ACTIVE],
                "corrected": counts[STATE_CORRECTED],
                "withdrawn": counts[STATE_WITHDRAWN],
            }
            if arguments.subject:
                entry = current(document, arguments.subject)
                result.update(
                    {
                        "subject": arguments.subject,
                        "subjectState": entry["state"],
                        "supersededBy": entry.get("supersededBy"),
                        "correctionDigest": entry.get("correctionDigest"),
                    }
                )
            _print_result(result)
        elif arguments.command == "inclusion":
            _print_result(
                inclusion_lookup(arguments.archive, arguments.subject)
            )
        elif arguments.command == "reconstruct":
            result = reconstruct(arguments.archive)
            _print_result(
                {
                    "code": result["code"],
                    "archiveId": result["archiveId"],
                    "members": result["members"],
                    "checks": len(result["checks"]),
                    "leafIndex": result["inclusion"]["leafIndex"],
                    "treeSize": result["inclusion"]["treeSize"],
                    "root": result["checkpoint"]["root"],
                    "subject": result["subject"],
                    "subjectState": result["state"]["state"],
                    "version": result["state"]["version"],
                }
            )
        elif arguments.command == "derive":
            previous = load_state(arguments.previous) if arguments.previous else None
            document = derive_state(
                load_events(arguments.events),
                upto=arguments.upto,
                previous=previous,
            )
            if arguments.out:
                Path(arguments.out).write_text(
                    json.dumps(document, indent=1, sort_keys=True, ensure_ascii=False)
                    + "\n",
                    encoding="utf-8",
                )
            counts = {state: 0 for state in STATES}
            for entry in document["subjects"]:
                counts[entry["state"]] += 1
            _print_result(
                {
                    "code": CODE_OK,
                    "version": document["version"],
                    "asOf": document["asOf"],
                    "digest": document["digest"],
                    "subjects": len(document["subjects"]),
                    "active": counts[STATE_ACTIVE],
                    "corrected": counts[STATE_CORRECTED],
                    "withdrawn": counts[STATE_WITHDRAWN],
                }
            )
        elif arguments.command == "admit":
            _print_result(
                admit(load_state(arguments.candidate), load_state(arguments.accepted))
            )
        elif arguments.command == "use":
            document = load_state(arguments.state)
            entry = present_tense(document, arguments.subject)
            _print_result(
                {
                    "code": CODE_OK,
                    "subject": entry["subject"],
                    "state": entry["state"],
                    "version": entry["version"],
                }
            )
        elif arguments.command == "compare":
            _print_result(
                check_monotonic(
                    load_state(arguments.previous), load_state(arguments.next)
                )
            )
        else:  # pragma: no cover - argparse makes this unreachable
            _fail(RV_REFUSED_USAGE, f"unknown command {arguments.command!r}")
    except Refusal as refusal:
        print(f"code={refusal.code} message={refusal.message}")
        return EXIT_REFUSED if refusal.code != RV_REFUSED_USAGE else EXIT_USAGE
    except OSError as exc:
        print(f"code={RV_REFUSED_IO} message={exc}")
        return EXIT_REFUSED
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
