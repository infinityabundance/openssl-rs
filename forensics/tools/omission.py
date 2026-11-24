#!/usr/bin/env python3
"""omission.py -- freeze an expected evidence population, then close against it.

Why this tool exists
--------------------
A producer can omit a failed result and publish only what succeeded. A validator
that inspects only the claims a producer chose to publish cannot detect that
omission: the missing artefact never appears in the population it is asked about.
The defence is temporal, not rhetorical:

  1. **freeze** the expected population *before* execution: every expected
     artefact is declared with an id, a path, a predicate, a required flag and a
     phase, and the freeze records what produced it, when, and its own digest;
  2. **close** the freeze *after* execution against the observed population:
     every expected member is ``PRODUCED``, ``MISSING``, ``UNREADABLE`` or
     ``DIGEST_MISMATCH``, and every observed artefact that was not declared is an
     ``UNEXPECTED`` entry -- reported, never silently accepted;
  3. **sign** the reconciliation as a DSSE envelope over its canonical bytes.

The rule this module enforces is:

    A summary may not report success while an expected member is missing, and a
    producer may not shrink the population it is judged against.

What the signature proves, and what it does not
-----------------------------------------------
The only signing key in this tree is A10's test-only HMAC-SHA256 key derived from
a fixed public seed. A signature made with it proves that the manifest's bytes
have not changed since signing. It does **not** prove that an independent party
closed the reconciliation, that the closure is authentic, or that the expected
population was chosen honestly. A12 records every such envelope ``SELF_ISSUED``.

What this module does not establish
-----------------------------------
``PRODUCED`` means a byte string exists at the declared path and its digest was
recorded. It is not ``PASS``: it says nothing about whether the artefact is
correct, whether the predicate holds, or whether the declared predicate was the
right one. A closed manifest is not a safety, compatibility or cryptographic
result. ``MISSING`` is not proof of misconduct -- it is a state a closure records
so that a later reader cannot mistake absence for success.

Forward extensions, duplicate JSON keys, encodings and oversized inputs are A11's
``harden``/``dsse`` readers; this module uses ``json.loads`` on its own files and
``dsse`` for every envelope operation. Independent cryptographic verification is
A12's and is not performed here.

Usage
-----
    python3 forensics/tools/omission.py freeze <plan> <out>
    python3 forensics/tools/omission.py close <freeze> <out>
        [--observed FILE | --observe-dir DIR] [--recorded-at TS]
        [--closed-at TS]
    python3 forensics/tools/omission.py sign <reconciliation> <out>
    python3 forensics/tools/omission.py verify <freeze> <reconciliation> <envelope>
        [--observed FILE | --observe-dir DIR] [--recorded-at TS]

Exit status: 0 when the requested operation produced a well-formed result
(including a closure that records ``MISSING`` members, which is the point), 1 for
a refusal, 2 for a usage error. The stable code is always printed.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence

TOOLS = Path(__file__).resolve().parent
REPO_ROOT = TOOLS.parents[1]
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import dsse  # noqa: E402

TOOL_PATH = "forensics/tools/omission.py"
MODEL_ID = "a17/v1"
FREEZE_SCHEMA = "openssl-rs/a17/freeze/1"
RECONCILIATION_SCHEMA = "openssl-rs/a17/reconciliation/1"
OBSERVED_SCHEMA = "openssl-rs/a17/observed/1"
PAYLOAD_TYPE = "application/vnd.openssl-rs.a17.reconciliation+json"

STATE_PRODUCED = "PRODUCED"
STATE_MISSING = "MISSING"
STATE_UNREADABLE = "UNREADABLE"
STATE_DIGEST_MISMATCH = "DIGEST_MISMATCH"
STATES = (STATE_PRODUCED, STATE_MISSING, STATE_UNREADABLE, STATE_DIGEST_MISMATCH)

STATE_OPEN = "OPEN"
STATE_FROZEN = "FROZEN"

EXIT_OK = 0
EXIT_REFUSED = 1
EXIT_USAGE = 2

CODE_OK = "OM_OK"
CODE_CLOSED = "OM_CLOSED"
CODE_VERIFIED = "OM_VERIFIED"
CODE_USAGE = "OM_USAGE"

OM_REFUSED_FREEZE_ABSENT = "OM_REFUSED_FREEZE_ABSENT"
OM_REFUSED_FREEZE_AFTER_EXECUTION = "OM_REFUSED_FREEZE_AFTER_EXECUTION"
OM_REFUSED_FREEZE_AMENDED = "OM_REFUSED_FREEZE_AMENDED"
OM_REFUSED_MISSING_SILENT = "OM_REFUSED_MISSING_SILENT"
OM_REFUSED_UNEXPECTED_UNDECLARED = "OM_REFUSED_UNEXPECTED_UNDECLARED"
OM_REFUSED_RECONCILIATION_UNSIGNED = "OM_REFUSED_RECONCILIATION_UNSIGNED"
OM_REFUSED_RECONCILIATION_MUTATED = "OM_REFUSED_RECONCILIATION_MUTATED"
OM_REFUSED_DUPLICATE_EXPECTED = "OM_REFUSED_DUPLICATE_EXPECTED"
OM_REFUSED_DIGEST_MISMATCH = "OM_REFUSED_DIGEST_MISMATCH"
OM_REFUSED_EXIT_AS_PRODUCED = "OM_REFUSED_EXIT_AS_PRODUCED"
OM_REFUSED_PASS_WITH_MISSING = "OM_REFUSED_PASS_WITH_MISSING"
OM_REFUSED_POPULATION_DRIFT = "OM_REFUSED_POPULATION_DRIFT"
OM_REFUSED_UNREADABLE_AS_ABSENT = "OM_REFUSED_UNREADABLE_AS_ABSENT"
OM_REFUSED_COUNT_UNBALANCED = "OM_REFUSED_COUNT_UNBALANCED"
OM_REFUSED_MANIFEST_INVALID = "OM_REFUSED_MANIFEST_INVALID"
OM_REFUSED_SIGNATURE_INVALID = "OM_REFUSED_SIGNATURE_INVALID"

#: Every refusal, with the wrong conclusion it prevents. Stable identifiers.
REFUSALS: dict[str, dict[str, str]] = {
    OM_REFUSED_FREEZE_ABSENT: {
        "prevents": "closing, or claiming to have closed, against no frozen population",
        "rule": "a closure requires a freeze that exists and can be read",
    },
    OM_REFUSED_FREEZE_AFTER_EXECUTION: {
        "prevents": "choosing the expected population after seeing which artefacts succeeded",
        "rule": "frozenAt must not be later than the earliest produced artefact's recorded time",
    },
    OM_REFUSED_FREEZE_AMENDED: {
        "prevents": "editing a freeze after execution so the population matches what was produced",
        "rule": "the bytes of a frozen manifest must still hash to the digest recorded when frozen",
    },
    OM_REFUSED_MISSING_SILENT: {
        "prevents": "a closing summary that omits a MISSING member and reads as complete",
        "rule": "every frozen id appears once in the closure and every MISSING id is listed",
    },
    OM_REFUSED_UNEXPECTED_UNDECLARED: {
        "prevents": "an observed artefact entering the record without being declared or reported",
        "rule": "an observed artefact not declared in the freeze must appear as UNEXPECTED",
    },
    OM_REFUSED_RECONCILIATION_UNSIGNED: {
        "prevents": "an unsigned reconciliation being read as a closed, authenticated manifest",
        "rule": "verification requires a DSSE envelope",
    },
    OM_REFUSED_RECONCILIATION_MUTATED: {
        "prevents": "changing the reconciliation after signing and keeping the signature",
        "rule": "the envelope payload must equal the canonical bytes of the reconciliation",
    },
    OM_REFUSED_DUPLICATE_EXPECTED: {
        "prevents": "declaring one identity twice so one result can satisfy two requirements",
        "rule": "expected ids and expected paths are unique within a freeze",
    },
    OM_REFUSED_DIGEST_MISMATCH: {
        "prevents": "a changed artefact being reported as produced while the summary passes",
        "rule": "a required DIGEST_MISMATCH member cannot be part of a passing summary",
    },
    OM_REFUSED_EXIT_AS_PRODUCED: {
        "prevents": "treating a build step's exit status, or a failed exit, as the artefact",
        "rule": "production requires bytes at the declared path and a recorded digest, not an exit code",
    },
    OM_REFUSED_PASS_WITH_MISSING: {
        "prevents": "a PASS over a population that still has a missing required member",
        "rule": "a passing summary requires every required member to be PRODUCED",
    },
    OM_REFUSED_POPULATION_DRIFT: {
        "prevents": "closing against a different path or identity than the one frozen",
        "rule": "an observed or reconciled identity must equal the frozen identity",
    },
    OM_REFUSED_UNREADABLE_AS_ABSENT: {
        "prevents": "reporting an unreadable artefact as absent, or an absent one as unreadable",
        "rule": "UNREADABLE and MISSING are distinct states and are never interchanged",
    },
    OM_REFUSED_COUNT_UNBALANCED: {
        "prevents": "a summary whose counts do not add up hiding an unaccounted member",
        "rule": "produced + missing + unreadable + digestMismatch == expected; unexpected is separate",
    },
    OM_REFUSED_MANIFEST_INVALID: {
        "prevents": "a malformed or mislabelled manifest being read as a freeze or closure",
        "rule": "a manifest has the declared schema, kind and required fields",
    },
    OM_REFUSED_SIGNATURE_INVALID: {
        "prevents": "an envelope whose signature does not verify being accepted as signed",
        "rule": "the DSSE signature must verify over the PAE of the received bytes",
    },
}

CODE_ORDER = (
    OM_REFUSED_FREEZE_ABSENT,
    OM_REFUSED_FREEZE_AFTER_EXECUTION,
    OM_REFUSED_FREEZE_AMENDED,
    OM_REFUSED_MISSING_SILENT,
    OM_REFUSED_UNEXPECTED_UNDECLARED,
    OM_REFUSED_RECONCILIATION_UNSIGNED,
    OM_REFUSED_RECONCILIATION_MUTATED,
    OM_REFUSED_DUPLICATE_EXPECTED,
    OM_REFUSED_DIGEST_MISMATCH,
    OM_REFUSED_EXIT_AS_PRODUCED,
    OM_REFUSED_PASS_WITH_MISSING,
    OM_REFUSED_POPULATION_DRIFT,
    OM_REFUSED_UNREADABLE_AS_ABSENT,
    OM_REFUSED_COUNT_UNBALANCED,
    OM_REFUSED_MANIFEST_INVALID,
    OM_REFUSED_SIGNATURE_INVALID,
)


class Refusal(Exception):
    """A stable refusal: ``code`` is printed and never reworded."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def _fail(code: str, message: str) -> None:
    raise Refusal(code, message)


# ---------------------------------------------------------------------------
# Canonicalisation and digests.
# ---------------------------------------------------------------------------


def canonical_bytes(document: Any) -> bytes:
    """The canonical bytes this tool signs and hashes.

    Canonical JSON is for *producing* reproducible manifests and for the signing
    boundary. It is not a licence to reparse and re-encode someone else's signed
    bytes: verification compares the envelope payload with these bytes derived
    from the manifest under test.
    """
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
    path = REPO_ROOT / TOOL_PATH
    return {"path": TOOL_PATH, "sha256": sha256_file(path)}


def freeze_digest(document: Mapping[str, Any]) -> str:
    """The digest of a freeze with the ``digest`` field excluded."""
    body = {key: value for key, value in document.items() if key != "digest"}
    return sha256_bytes(canonical_bytes(body))


# ---------------------------------------------------------------------------
# Reading and shape checking.
# ---------------------------------------------------------------------------


def _as_document(value: Any, what: str) -> dict[str, Any]:
    """Parse a manifest supplied as a mapping, bytes or text.

    A path is read by the command line, not here: a programmatic caller passes
    the parsed manifest or the exact bytes it holds.
    """
    if isinstance(value, Mapping):
        return dict(value)
    if isinstance(value, (bytes, bytearray, memoryview)):
        try:
            return json.loads(bytes(value).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            _fail(OM_REFUSED_MANIFEST_INVALID, f"{what} is not JSON: {error}")
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError as error:
            _fail(OM_REFUSED_MANIFEST_INVALID, f"{what} is not JSON: {error}")
    _fail(OM_REFUSED_MANIFEST_INVALID, f"{what} is not a JSON object")


def _require_text(value: Any, what: str) -> str:
    if not isinstance(value, str) or not value:
        _fail(OM_REFUSED_MANIFEST_INVALID, f"{what} is a non-empty string")
    return value


def _require_bool(value: Any, what: str) -> bool:
    if not isinstance(value, bool):
        _fail(OM_REFUSED_MANIFEST_INVALID, f"{what} is a boolean")
    return value


def _require_int(value: Any, what: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        _fail(OM_REFUSED_MANIFEST_INVALID, f"{what} is an integer")
    return value


def _require_digest(value: Any, what: str) -> str:
    text = _require_text(value, what)
    if len(text) != 64 or any(character not in "0123456789abcdef" for character in text):
        _fail(OM_REFUSED_MANIFEST_INVALID, f"{what} is 64 lowercase hex characters")
    return text


def _normalise_member(member: Any, where: str) -> dict[str, Any]:
    if not isinstance(member, Mapping):
        _fail(OM_REFUSED_MANIFEST_INVALID, f"{where} is a JSON object")
    normalised: dict[str, Any] = {
        "id": _require_text(member.get("id"), f"{where}.id"),
        "path": _require_text(member.get("path"), f"{where}.path"),
        "predicate": _require_text(member.get("predicate"), f"{where}.predicate"),
        "required": _require_bool(member.get("required"), f"{where}.required"),
        "phase": _require_text(member.get("phase"), f"{where}.phase"),
    }
    if "expectedDigest" in member:
        normalised["expectedDigest"] = _require_digest(
            member["expectedDigest"], f"{where}.expectedDigest"
        )
    return normalised


def _check_unique(members: Sequence[Mapping[str, Any]]) -> None:
    ids: set[str] = set()
    paths: set[str] = set()
    for member in members:
        if member["id"] in ids:
            _fail(
                OM_REFUSED_DUPLICATE_EXPECTED,
                f"the expected id {member['id']!r} is declared twice; one result "
                "would satisfy two requirements",
            )
        if member["path"] in paths:
            _fail(
                OM_REFUSED_DUPLICATE_EXPECTED,
                f"the expected path {member['path']!r} is declared twice",
            )
        ids.add(member["id"])
        paths.add(member["path"])


# ---------------------------------------------------------------------------
# Freeze.
# ---------------------------------------------------------------------------


def freeze(
    plan: Mapping[str, Any],
    recorded_at: str,
    candidate: Any,
) -> dict[str, Any]:
    """Freeze an expected population into a manifest.

    ``plan`` carries ``members`` and optionally ``id`` and ``state``. The freeze
    records *what* produced it (this tool's identity), *when* (``frozenAt``) and
    its own digest. It carries exactly one count -- ``memberCount`` -- which must
    equal the length of its member list.
    """
    if not isinstance(plan, Mapping):
        _fail(OM_REFUSED_MANIFEST_INVALID, "the freeze plan is a JSON object")
    raw_members = plan.get("members")
    if not isinstance(raw_members, list) or not raw_members:
        _fail(OM_REFUSED_MANIFEST_INVALID, "the freeze plan has a non-empty members list")
    members = [
        _normalise_member(member, f"members[{index}]")
        for index, member in enumerate(raw_members)
    ]
    _check_unique(members)

    frozen_at = _require_text(recorded_at, "frozenAt")
    state = plan.get("state", STATE_FROZEN)
    if state not in (STATE_FROZEN, STATE_OPEN):
        _fail(OM_REFUSED_MANIFEST_INVALID, f"freeze state is {STATE_FROZEN} or {STATE_OPEN}")

    document: dict[str, Any] = {
        "schema": FREEZE_SCHEMA,
        "kind": "freeze",
        "id": _require_text(plan.get("id"), "id"),
        "state": state,
        "candidate": candidate,
        "frozenAt": frozen_at,
        "recordedAt": frozen_at,
        "producedBy": tool_identity(),
        "members": members,
        "memberCount": len(members),
    }
    document["digest"] = freeze_digest(document)
    return document


def validate_freeze(value: Any) -> dict[str, Any]:
    """Validate a freeze, its digest and its one count. Returns the document."""
    if value is None:
        _fail(OM_REFUSED_FREEZE_ABSENT, "no freeze manifest was supplied")
    document = _as_document(value, "the freeze manifest")
    if not document:
        _fail(OM_REFUSED_FREEZE_ABSENT, "the freeze manifest is empty")
    if document.get("schema") != FREEZE_SCHEMA or document.get("kind") != "freeze":
        _fail(
            OM_REFUSED_MANIFEST_INVALID,
            f"the freeze schema is {FREEZE_SCHEMA!r} and kind 'freeze'",
        )
    recorded = _require_digest(document.get("digest"), "the freeze digest")
    computed = freeze_digest(document)
    if recorded != computed:
        _fail(
            OM_REFUSED_FREEZE_AMENDED,
            f"the freeze bytes hash to {computed}, but the manifest records "
            f"{recorded} from the moment it was frozen",
        )
    raw_members = document.get("members")
    if not isinstance(raw_members, list) or not raw_members:
        _fail(OM_REFUSED_MANIFEST_INVALID, "the freeze has a non-empty members list")
    members = [
        _normalise_member(member, f"members[{index}]")
        for index, member in enumerate(raw_members)
    ]
    _check_unique(members)
    count = _require_int(document.get("memberCount"), "memberCount")
    if count != len(members):
        _fail(
            OM_REFUSED_FREEZE_AMENDED,
            f"memberCount is {count} but the member list has {len(members)} entries; "
            "a freeze may not carry a count that is not the length of its list",
        )
    _require_text(document.get("frozenAt"), "frozenAt")
    if "state" in document and document["state"] not in (STATE_FROZEN, STATE_OPEN):
        _fail(OM_REFUSED_MANIFEST_INVALID, "freeze state is FROZEN or OPEN")
    normalised = dict(document)
    normalised["members"] = members
    return normalised


# ---------------------------------------------------------------------------
# Observations.
# ---------------------------------------------------------------------------


def _parse_time(value: Any, what: str) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    text = value
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def observed_entries(observed: Any) -> list[dict[str, Any]]:
    """Normalise an observation set: a list, or ``{"artefacts": [...]}``."""
    if observed is None:
        return []
    if isinstance(observed, Mapping):
        raw = observed.get("artefacts")
        if raw is None:
            _fail(OM_REFUSED_MANIFEST_INVALID, "the observation set has an artefacts list")
    else:
        raw = observed
    if not isinstance(raw, list):
        _fail(OM_REFUSED_MANIFEST_INVALID, "the observation set is a list")
    entries: list[dict[str, Any]] = []
    for index, entry in enumerate(raw):
        if not isinstance(entry, Mapping):
            _fail(OM_REFUSED_MANIFEST_INVALID, f"artefacts[{index}] is a JSON object")
        normalised: dict[str, Any] = {
            "id": _require_text(entry.get("id"), f"artefacts[{index}].id"),
            "path": _require_text(entry.get("path"), f"artefacts[{index}].path"),
            "readable": entry.get("readable", True),
            "recordedAt": entry.get("recordedAt"),
        }
        if not isinstance(normalised["readable"], bool):
            _fail(OM_REFUSED_MANIFEST_INVALID, f"artefacts[{index}].readable is a boolean")
        if "exitCode" in entry and entry["exitCode"] is not None:
            normalised["exitCode"] = _require_int(
                entry["exitCode"], f"artefacts[{index}].exitCode"
            )
        if "digest" in entry and entry["digest"] is not None:
            normalised["digest"] = _require_digest(
                entry["digest"], f"artefacts[{index}].digest"
            )
        if "file" in entry and entry["file"] is not None:
            normalised["file"] = _require_text(
                entry["file"], f"artefacts[{index}].file"
            )
        entries.append(normalised)
    return entries


def _entry_file(entry: Mapping[str, Any]) -> Path:
    return Path(entry.get("file") or entry["path"])


def _entries_from_dir(
    members: Sequence[Mapping[str, Any]], directory: str | Path, recorded_at: str | None
) -> list[dict[str, Any]]:
    base = Path(directory)
    entries: list[dict[str, Any]] = []
    for member in members:
        target = base / Path(member["path"]).name
        entry: dict[str, Any] = {
            "id": member["id"],
            "path": member["path"],
            "file": str(target),
            "readable": True,
            "recordedAt": recorded_at,
        }
        entries.append(entry)
    return observed_entries(entries)


def _entries_from_filesystem(
    members: Sequence[Mapping[str, Any]], recorded_at: str | None
) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for member in members:
        entry: dict[str, Any] = {
            "id": member["id"],
            "path": member["path"],
            "readable": True,
            "recordedAt": recorded_at,
        }
        entries.append(entry)
    return observed_entries(entries)


# ---------------------------------------------------------------------------
# Close.
# ---------------------------------------------------------------------------


def _check_freeze_precedes(
    document: Mapping[str, Any], entries: Sequence[Mapping[str, Any]]
) -> None:
    frozen = _parse_time(document.get("frozenAt"), "frozenAt")
    if frozen is None:
        return
    produced: list[datetime] = []
    for entry in entries:
        if not _entry_file(entry).exists():
            continue
        recorded = _parse_time(entry.get("recordedAt"), "recordedAt")
        if recorded is not None:
            produced.append(recorded)
    if produced and frozen > min(produced):
        _fail(
            OM_REFUSED_FREEZE_AFTER_EXECUTION,
            f"frozenAt {document['frozenAt']} is later than the earliest produced "
            f"artefact's recorded time {min(produced).isoformat()}; the population "
            "was chosen after execution",
        )


def close(
    freeze_manifest: Any,
    observed: Any = None,
    *,
    observed_dir: str | Path | None = None,
    recorded_at: str | None = None,
    closed_at: str | None = None,
) -> dict[str, Any]:
    """Close a freeze against the observed population.

    Every expected member becomes ``PRODUCED`` (bytes exist and a digest was
    recorded), ``MISSING``, ``UNREADABLE`` or ``DIGEST_MISMATCH``. Every observed
    artefact that was not declared becomes an ``UNEXPECTED`` entry. The summary
    counts must reconcile exactly.
    """
    document = validate_freeze(freeze_manifest)
    members: list[dict[str, Any]] = list(document["members"])

    if observed is not None and observed_dir is not None:
        _fail(
            OM_REFUSED_MANIFEST_INVALID,
            "an observation set and an observation directory are alternatives",
        )
    if observed is not None:
        entries = observed_entries(observed)
    elif observed_dir is not None:
        entries = _entries_from_dir(members, observed_dir, recorded_at)
    else:
        entries = _entries_from_filesystem(members, recorded_at)

    _check_freeze_precedes(document, entries)

    declared_ids = {member["id"]: member for member in members}
    declared_paths = {member["path"]: member for member in members}

    results: list[dict[str, Any]] = []
    matched: set[int] = set()
    for member in members:
        matches = [
            (index, entry)
            for index, entry in enumerate(entries)
            if entry["id"] == member["id"] or entry["path"] == member["path"]
        ]
        if len(matches) > 1:
            _fail(
                OM_REFUSED_POPULATION_DRIFT,
                f"the member {member['id']!r} is observed {len(matches)} times",
            )
        if not matches:
            results.append(_result(member, STATE_MISSING))
            continue
        index, entry = matches[0]
        matched.add(index)
        if entry["id"] != member["id"] or entry["path"] != member["path"]:
            _fail(
                OM_REFUSED_POPULATION_DRIFT,
                f"the frozen identity ({member['id']!r}, {member['path']!r}) was "
                f"observed as ({entry['id']!r}, {entry['path']!r})",
            )

        exit_code = entry.get("exitCode")
        if exit_code is not None and exit_code != 0:
            _fail(
                OM_REFUSED_EXIT_AS_PRODUCED,
                f"{member['id']!r} exited {exit_code}; a non-zero exit is not production",
            )
        if exit_code is not None and exit_code == 0:
            target = _entry_file(entry)
            if not target.exists():
                _fail(
                    OM_REFUSED_EXIT_AS_PRODUCED,
                    f"{member['id']!r} has exit status 0 but no bytes at {target}; "
                    "an exit status is not an artefact",
                )

        if not entry["readable"]:
            results.append(_result(member, STATE_UNREADABLE, recordedAt=entry.get("recordedAt")))
            continue

        target = _entry_file(entry)
        if not target.exists():
            results.append(_result(member, STATE_MISSING))
            continue
        actual = sha256_file(target)
        if entry.get("digest") is not None and entry["digest"] != actual:
            results.append(
                _result(
                    member,
                    STATE_DIGEST_MISMATCH,
                    digest=actual,
                    recordedAt=entry.get("recordedAt"),
                    detail="the supplied digest differs from the bytes",
                )
            )
            continue
        expected = member.get("expectedDigest")
        if expected is not None and expected != actual:
            results.append(
                _result(
                    member,
                    STATE_DIGEST_MISMATCH,
                    digest=actual,
                    recordedAt=entry.get("recordedAt"),
                    detail=f"the frozen digest is {expected}",
                )
            )
            continue
        results.append(
            _result(
                member,
                STATE_PRODUCED,
                digest=actual,
                recordedAt=entry.get("recordedAt"),
            )
        )

    unexpected: list[dict[str, Any]] = []
    for index, entry in enumerate(entries):
        if index in matched:
            continue
        if entry["id"] in declared_ids or entry["path"] in declared_paths:
            # A declared identity that did not match its own member is drift, not
            # an undeclared extra.
            _fail(
                OM_REFUSED_POPULATION_DRIFT,
                f"the observed artefact ({entry['id']!r}, {entry['path']!r}) names a "
                "declared identity with a different identity",
            )
        unexpected.append(
            {
                "id": entry["id"],
                "path": entry["path"],
                "digest": entry.get("digest"),
                "recordedAt": entry.get("recordedAt"),
            }
        )

    summary = _summary(results, unexpected, document)
    if document.get("state") == STATE_OPEN:
        summary["pass"] = False
        summary["note"] = (
            "the freeze is OPEN; this reconciliation records what exists now and "
            "is not a closure of the item's expected population"
        )
    if closed_at is None:
        closed_at = _latest_time(results) or document["frozenAt"]

    return {
        "schema": RECONCILIATION_SCHEMA,
        "kind": "reconciliation",
        "item": document.get("id"),
        "freezeDigest": document["digest"],
        "freezeState": document.get("state", STATE_FROZEN),
        "candidate": document.get("candidate"),
        "closedAt": closed_at,
        "members": results,
        "unexpected": unexpected,
        "summary": summary,
        "signedBytes": (
            "the DSSE envelope over the canonical JSON of this object; the "
            "signature proves these bytes are unchanged, not that an independent "
            "party closed the population"
        ),
    }


def _result(member: Mapping[str, Any], state: str, **extra: Any) -> dict[str, Any]:
    result: dict[str, Any] = {
        "id": member["id"],
        "path": member["path"],
        "required": member["required"],
        "phase": member["phase"],
        "predicate": member["predicate"],
        "state": state,
        "digest": extra.get("digest"),
        "recordedAt": extra.get("recordedAt"),
    }
    if "detail" in extra:
        result["detail"] = extra["detail"]
    return result


def _latest_time(results: Sequence[Mapping[str, Any]]) -> str | None:
    times = [
        result["recordedAt"]
        for result in results
        if isinstance(result.get("recordedAt"), str)
    ]
    if not times:
        return None
    parsed = [(_parse_time(value, "recordedAt"), value) for value in times]
    parsed = [(moment, value) for moment, value in parsed if moment is not None]
    if not parsed:
        return None
    return max(parsed, key=lambda pair: pair[0])[1]


def _summary(
    results: Sequence[Mapping[str, Any]],
    unexpected: Sequence[Mapping[str, Any]],
    document: Mapping[str, Any],
) -> dict[str, Any]:
    counts = {state: 0 for state in STATES}
    for result in results:
        counts[result["state"]] += 1
    required = {
        result["id"]: result["state"] for result in results if result["required"]
    }
    passing = bool(required) and all(
        state == STATE_PRODUCED for state in required.values()
    )
    summary: dict[str, Any] = {
        "expected": len(document["members"]),
        "produced": counts[STATE_PRODUCED],
        "missing": counts[STATE_MISSING],
        "unreadable": counts[STATE_UNREADABLE],
        "digestMismatch": counts[STATE_DIGEST_MISMATCH],
        "unexpected": len(unexpected),
        "missingIds": [
            result["id"] for result in results if result["state"] == STATE_MISSING
        ],
        "unreadableIds": [
            result["id"] for result in results if result["state"] == STATE_UNREADABLE
        ],
        "digestMismatchIds": [
            result["id"]
            for result in results
            if result["state"] == STATE_DIGEST_MISMATCH
        ],
        "unexpectedIds": [entry["id"] for entry in unexpected],
        "pass": passing and not unexpected,
    }
    return summary


def validate_reconciliation(value: Any) -> dict[str, Any]:
    if value is None:
        _fail(OM_REFUSED_MANIFEST_INVALID, "no reconciliation was supplied")
    document = _as_document(value, "the reconciliation")
    if document.get("schema") != RECONCILIATION_SCHEMA or document.get(
        "kind"
    ) != "reconciliation":
        _fail(
            OM_REFUSED_MANIFEST_INVALID,
            f"the reconciliation schema is {RECONCILIATION_SCHEMA!r} and kind "
            "'reconciliation'",
        )
    for field in ("freezeDigest", "members", "unexpected", "summary", "closedAt"):
        if field not in document:
            _fail(OM_REFUSED_MANIFEST_INVALID, f"the reconciliation has {field!r}")
    if not isinstance(document["members"], list):
        _fail(OM_REFUSED_MANIFEST_INVALID, "reconciliation members is a list")
    if not isinstance(document["unexpected"], list):
        _fail(OM_REFUSED_MANIFEST_INVALID, "reconciliation unexpected is a list")
    if not isinstance(document["summary"], Mapping):
        _fail(OM_REFUSED_MANIFEST_INVALID, "reconciliation summary is an object")
    return document


# ---------------------------------------------------------------------------
# Reconciliation checks.
# ---------------------------------------------------------------------------


def check(
    freeze_manifest: Any,
    reconciliation: Any,
    observed: Any = None,
    *,
    observed_dir: str | Path | None = None,
    recorded_at: str | None = None,
) -> dict[str, Any]:
    """Validate a reconciliation against its freeze and, optionally, observations.

    Returns the summary. Raises ``Refusal`` on the first violation.
    """
    frozen = validate_freeze(freeze_manifest)
    closure = validate_reconciliation(reconciliation)
    members: list[dict[str, Any]] = list(frozen["members"])

    recorded_freeze = _require_digest(
        closure.get("freezeDigest"), "the reconciliation freezeDigest"
    )
    if recorded_freeze != frozen["digest"]:
        _fail(
            OM_REFUSED_POPULATION_DRIFT,
            f"the reconciliation closes freeze {recorded_freeze}, but the supplied "
            f"freeze is {frozen['digest']}",
        )
    if closure.get("candidate") != frozen.get("candidate"):
        _fail(
            OM_REFUSED_POPULATION_DRIFT,
            "the reconciliation candidate differs from the frozen candidate",
        )

    frozen_ids = [member["id"] for member in members]
    frozen_paths = {member["id"]: member["path"] for member in members}
    rows = closure["members"]
    seen: set[str] = set()
    by_id: dict[str, Mapping[str, Any]] = {}
    for index, row in enumerate(rows):
        if not isinstance(row, Mapping):
            _fail(OM_REFUSED_MANIFEST_INVALID, f"members[{index}] is an object")
        member_id = _require_text(row.get("id"), f"members[{index}].id")
        if member_id in seen:
            _fail(
                OM_REFUSED_DUPLICATE_EXPECTED,
                f"the reconciliation reports {member_id!r} twice",
            )
        seen.add(member_id)
        by_id[member_id] = row
        if row.get("state") not in STATES:
            _fail(
                OM_REFUSED_MANIFEST_INVALID,
                f"members[{index}].state is one of {', '.join(STATES)}",
            )
        if member_id in frozen_paths and row.get("path") != frozen_paths[member_id]:
            _fail(
                OM_REFUSED_POPULATION_DRIFT,
                f"{member_id!r} was frozen at {frozen_paths[member_id]!r} but "
                f"closed at {row.get('path')!r}",
            )

    missing_ids = set(frozen_ids) - seen
    if missing_ids:
        _fail(
            OM_REFUSED_MISSING_SILENT,
            f"the closure omits expected member(s) {sorted(missing_ids)}; an "
            "omitted member is not a produced one",
        )
    extra_ids = seen - set(frozen_ids)
    if extra_ids:
        _fail(
            OM_REFUSED_POPULATION_DRIFT,
            f"the closure reports member(s) {sorted(extra_ids)} that the freeze "
            "never declared",
        )

    required = {member["id"]: member["required"] for member in members}
    summary = closure["summary"]
    counts = {state: 0 for state in STATES}
    for member_id in frozen_ids:
        counts[by_id[member_id]["state"]] += 1
    expected = len(members)
    stated = {
        "expected": _require_int(summary.get("expected"), "summary.expected"),
        "produced": _require_int(summary.get("produced"), "summary.produced"),
        "missing": _require_int(summary.get("missing"), "summary.missing"),
        "unreadable": _require_int(summary.get("unreadable"), "summary.unreadable"),
        "digestMismatch": _require_int(
            summary.get("digestMismatch"), "summary.digestMismatch"
        ),
        "unexpected": _require_int(summary.get("unexpected"), "summary.unexpected"),
    }
    actual = {
        "expected": expected,
        "produced": counts[STATE_PRODUCED],
        "missing": counts[STATE_MISSING],
        "unreadable": counts[STATE_UNREADABLE],
        "digestMismatch": counts[STATE_DIGEST_MISMATCH],
        "unexpected": len(closure["unexpected"]),
    }
    for key in actual:
        if stated[key] != actual[key]:
            _fail(
                OM_REFUSED_COUNT_UNBALANCED,
                f"summary.{key} is {stated[key]} but the reconciliation holds "
                f"{actual[key]}",
            )
    if expected != (
        actual["produced"]
        + actual["missing"]
        + actual["unreadable"]
        + actual["digestMismatch"]
    ):
        _fail(
            OM_REFUSED_COUNT_UNBALANCED,
            "produced + missing + unreadable + digestMismatch does not equal expected",
        )

    stated_missing = summary.get("missingIds", [])
    if not isinstance(stated_missing, list) or set(stated_missing) != {
        member_id
        for member_id in frozen_ids
        if by_id[member_id]["state"] == STATE_MISSING
    }:
        _fail(
            OM_REFUSED_MISSING_SILENT,
            "summary.missingIds does not list exactly the MISSING members",
        )

    declared_ids = set(frozen_ids)
    declared_paths = set(frozen_paths.values())
    for entry in closure["unexpected"]:
        if not isinstance(entry, Mapping):
            _fail(OM_REFUSED_MANIFEST_INVALID, "an unexpected entry is an object")
        if entry.get("id") in declared_ids or entry.get("path") in declared_paths:
            _fail(
                OM_REFUSED_POPULATION_DRIFT,
                f"the unexpected entry {entry.get('id')!r} names a declared identity",
            )

    if observed is not None and observed_dir is not None:
        _fail(
            OM_REFUSED_MANIFEST_INVALID,
            "an observation set and an observation directory are alternatives",
        )
    if observed is not None:
        entries = observed_entries(observed)
    elif observed_dir is not None:
        entries = _entries_from_dir(members, observed_dir, recorded_at)
    else:
        entries = []

    if entries:
        seen_entries: set[int] = set()
        for index, entry in enumerate(entries):
            if entry["id"] in frozen_paths:
                if entry["path"] != frozen_paths[entry["id"]]:
                    _fail(
                        OM_REFUSED_POPULATION_DRIFT,
                        f"observed {entry['id']!r} at {entry['path']!r}, frozen at "
                        f"{frozen_paths[entry['id']]!r}",
                    )
                seen_entries.add(index)
            elif entry["path"] in declared_paths:
                _fail(
                    OM_REFUSED_POPULATION_DRIFT,
                    f"observed {entry['path']!r} under the id {entry['id']!r}, "
                    "which is not the frozen id",
                )
        declared_rows = {
            entry["id"]: entry
            for entry in entries
            if entry["id"] in declared_ids and entry["path"] == frozen_paths[entry["id"]]
        }
        for index, entry in enumerate(entries):
            if index in seen_entries or entry["path"] in declared_paths:
                continue
            if not any(
                unexpected.get("id") == entry["id"]
                and unexpected.get("path") == entry["path"]
                for unexpected in closure["unexpected"]
            ):
                _fail(
                    OM_REFUSED_UNEXPECTED_UNDECLARED,
                    f"the observed artefact ({entry['id']!r}, {entry['path']!r}) is "
                    "neither declared nor recorded as UNEXPECTED",
                )

        for member_id, entry in declared_rows.items():
            state = by_id[member_id]["state"]
            target = _entry_file(entry)
            if not entry["readable"]:
                if state not in (STATE_UNREADABLE,):
                    _fail(
                        OM_REFUSED_UNREADABLE_AS_ABSENT,
                        f"{member_id!r} was observed unreadable but is closed as "
                        f"{state}",
                    )
            elif not target.exists():
                if state == STATE_UNREADABLE:
                    _fail(
                        OM_REFUSED_UNREADABLE_AS_ABSENT,
                        f"{member_id!r} has no bytes at {target} but is closed as "
                        "UNREADABLE; an absent artefact is MISSING",
                    )
            elif state == STATE_UNREADABLE:
                _fail(
                    OM_REFUSED_UNREADABLE_AS_ABSENT,
                    f"{member_id!r} was read at {target} but is closed as UNREADABLE",
                )

    if summary.get("pass") is True:
        missing_required = [
            member_id
            for member_id in frozen_ids
            if required[member_id] and by_id[member_id]["state"] == STATE_MISSING
        ]
        if missing_required:
            _fail(
                OM_REFUSED_PASS_WITH_MISSING,
                f"the summary passes while required member(s) {missing_required} are "
                "MISSING",
            )
        unreadable_required = [
            member_id
            for member_id in frozen_ids
            if required[member_id] and by_id[member_id]["state"] == STATE_UNREADABLE
        ]
        if unreadable_required:
            _fail(
                OM_REFUSED_UNREADABLE_AS_ABSENT,
                f"the summary passes while required member(s) {unreadable_required} "
                "are UNREADABLE",
            )
        mismatch_required = [
            member_id
            for member_id in frozen_ids
            if required[member_id] and by_id[member_id]["state"] == STATE_DIGEST_MISMATCH
        ]
        if mismatch_required:
            _fail(
                OM_REFUSED_DIGEST_MISMATCH,
                f"the summary passes while required member(s) {mismatch_required} "
                "have DIGEST_MISMATCH",
            )
        not_produced = [
            member_id
            for member_id in frozen_ids
            if required[member_id] and by_id[member_id]["state"] != STATE_PRODUCED
        ]
        if not_produced:
            _fail(
                OM_REFUSED_PASS_WITH_MISSING,
                f"the summary passes while required member(s) {not_produced} are not "
                "PRODUCED",
            )
        if closure["unexpected"]:
            _fail(
                OM_REFUSED_UNEXPECTED_UNDECLARED,
                "the summary passes while UNEXPECTED artefacts are present",
            )

    return dict(summary)


# ---------------------------------------------------------------------------
# Signing and verification.
# ---------------------------------------------------------------------------


def sign(
    reconciliation: Mapping[str, Any],
    signer: Callable[[bytes], tuple[str, bytes]] | None = None,
) -> dict[str, Any]:
    """Return a DSSE envelope over the canonical bytes of ``reconciliation``.

    ``signer`` defaults to A10's test-only HMAC-SHA256 signer. That key is
    derived from a fixed public seed: the signature binds the bytes, it does not
    establish an independent closer.
    """
    document = _as_document(reconciliation, "the reconciliation")
    validate_reconciliation(document)
    chosen = signer if signer is not None else dsse.test_only_signer()
    return dsse.envelope(PAYLOAD_TYPE, canonical_bytes(document), chosen)


def verify(
    freeze_manifest: Any,
    reconciliation: Any,
    envelope: Any,
    verifier: Callable[[str, bytes, bytes], bool] | None = None,
    *,
    observed: Any = None,
    observed_dir: str | Path | None = None,
    recorded_at: str | None = None,
) -> dict[str, Any]:
    """Verify a signed reconciliation against its freeze.

    The envelope payload must be the canonical bytes of the reconciliation and
    the signature must verify over the PAE of the received bytes. Only then is
    the reconciliation itself checked with :func:`check`.
    """
    if envelope is None:
        _fail(
            OM_REFUSED_RECONCILIATION_UNSIGNED,
            "no envelope was supplied; an unsigned reconciliation is not a closure",
        )
    if isinstance(envelope, Mapping):
        envelope_bytes = dsse.encode_envelope(envelope)
    elif isinstance(envelope, (bytes, bytearray, memoryview)):
        envelope_bytes = bytes(envelope)
    else:
        _fail(OM_REFUSED_MANIFEST_INVALID, "the envelope is bytes or a JSON object")

    closure = _as_document(reconciliation, "the reconciliation")
    canonical = canonical_bytes(closure)
    chosen = verifier if verifier is not None else dsse.test_only_verifier()
    try:
        result = dsse.verify_received_bytes(
            envelope_bytes, chosen, expected_payload_type=PAYLOAD_TYPE
        )
    except dsse.Refusal as refusal:
        _fail(
            OM_REFUSED_SIGNATURE_INVALID,
            f"the envelope did not verify over its PAE ({refusal.code}): "
            f"{refusal.message}",
        )
    payload = result["payload"]
    if payload != canonical:
        _fail(
            OM_REFUSED_RECONCILIATION_MUTATED,
            f"the signed bytes hash to {sha256_bytes(payload)}, but the manifest "
            f"canonicalises to {sha256_bytes(canonical)}; the signature is over "
            "different bytes",
        )
    summary = check(
        freeze_manifest,
        closure,
        observed=observed,
        observed_dir=observed_dir,
        recorded_at=recorded_at,
    )
    return {
        "code": CODE_VERIFIED,
        "keyid": result["keyid"],
        "envelopeSha256": result["envelopeSha256"],
        "reconciliationSha256": sha256_bytes(canonical),
        "summary": summary,
    }


# ---------------------------------------------------------------------------
# Command line.
# ---------------------------------------------------------------------------


def _read_bytes(path: str, what: str, code: str) -> bytes:
    target = Path(path)
    if not target.exists():
        _fail(code, f"{what} {path} does not exist")
    return target.read_bytes()


def _read_json(path: str, what: str) -> Any:
    try:
        return json.loads(
            _read_bytes(path, what, OM_REFUSED_MANIFEST_INVALID).decode("utf-8")
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        _fail(OM_REFUSED_MANIFEST_INVALID, f"{what} {path} is not JSON: {error}")


def _write_json(path: str, document: Mapping[str, Any]) -> None:
    Path(path).write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _write_envelope(path: str, envelope: Mapping[str, Any]) -> None:
    Path(path).write_bytes(dsse.encode_envelope(envelope))


def _command_freeze(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(prog="omission.py freeze")
    parser.add_argument("plan")
    parser.add_argument("out")
    args = parser.parse_args(argv)
    plan = _read_json(args.plan, "the freeze plan")
    if not isinstance(plan, Mapping):
        _fail(OM_REFUSED_MANIFEST_INVALID, "the freeze plan is a JSON object")
    if "frozenAt" not in plan or "candidate" not in plan:
        print("omission: code=OM_USAGE detail=the plan needs frozenAt and candidate")
        return EXIT_USAGE
    document = freeze(plan, plan["frozenAt"], plan["candidate"])
    _write_json(args.out, document)
    print(
        f"omission: code={CODE_OK} state={document['state']} "
        f"members={document['memberCount']} digest={document['digest']} "
        f"frozenAt={document['frozenAt']}"
    )
    return EXIT_OK


def _command_close(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(prog="omission.py close")
    parser.add_argument("freeze")
    parser.add_argument("out")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--observed")
    group.add_argument("--observe-dir")
    parser.add_argument("--recorded-at")
    parser.add_argument("--closed-at")
    args = parser.parse_args(argv)
    raw_freeze = _read_bytes(args.freeze, "the freeze manifest", OM_REFUSED_FREEZE_ABSENT)
    observed = _read_json(args.observed, "the observation set") if args.observed else None
    document = close(
        raw_freeze,
        observed,
        observed_dir=args.observe_dir,
        recorded_at=args.recorded_at,
        closed_at=args.closed_at,
    )
    _write_json(args.out, document)
    summary = document["summary"]
    print(
        f"omission: code={CODE_CLOSED} expected={summary['expected']} "
        f"produced={summary['produced']} missing={summary['missing']} "
        f"unreadable={summary['unreadable']} "
        f"digestMismatch={summary['digestMismatch']} "
        f"unexpected={summary['unexpected']} pass={str(summary['pass']).lower()}"
    )
    return EXIT_OK


def _command_sign(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(prog="omission.py sign")
    parser.add_argument("reconciliation")
    parser.add_argument("out")
    args = parser.parse_args(argv)
    reconciliation = _read_json(args.reconciliation, "the reconciliation")
    envelope = sign(reconciliation)
    _write_envelope(args.out, envelope)
    print(
        f"omission: code={CODE_OK} payloadType={PAYLOAD_TYPE} "
        f"keyid={envelope['signatures'][0]['keyid']}"
    )
    return EXIT_OK


def _command_verify(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(prog="omission.py verify")
    parser.add_argument("freeze")
    parser.add_argument("reconciliation")
    parser.add_argument("envelope")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--observed")
    group.add_argument("--observe-dir")
    parser.add_argument("--recorded-at")
    args = parser.parse_args(argv)
    raw_freeze = _read_bytes(args.freeze, "the freeze manifest", OM_REFUSED_FREEZE_ABSENT)
    raw_reconciliation = _read_bytes(
        args.reconciliation, "the reconciliation", OM_REFUSED_MANIFEST_INVALID
    )
    raw_envelope = _read_bytes(
        args.envelope, "the envelope", OM_REFUSED_MANIFEST_INVALID
    )
    observed = _read_json(args.observed, "the observation set") if args.observed else None
    result = verify(
        raw_freeze,
        raw_reconciliation,
        raw_envelope,
        observed=observed,
        observed_dir=args.observe_dir,
        recorded_at=args.recorded_at,
    )
    summary = result["summary"]
    print(
        f"omission: code={CODE_VERIFIED} keyid={result['keyid']} "
        f"expected={summary['expected']} produced={summary['produced']} "
        f"missing={summary['missing']} unreadable={summary['unreadable']} "
        f"digestMismatch={summary['digestMismatch']} "
        f"unexpected={summary['unexpected']} pass={str(summary['pass']).lower()}"
    )
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if not arguments:
        print(
            "omission: code=OM_USAGE detail=freeze|close|sign|verify is required"
        )
        return EXIT_USAGE
    command, rest = arguments[0], arguments[1:]
    handlers = {
        "freeze": _command_freeze,
        "close": _command_close,
        "sign": _command_sign,
        "verify": _command_verify,
    }
    handler = handlers.get(command)
    if handler is None:
        print(f"omission: code=OM_USAGE detail=unknown command {command!r}")
        return EXIT_USAGE
    try:
        return handler(rest)
    except Refusal as refusal:
        print(f"omission: code={refusal.code} detail={refusal.message}")
        return EXIT_REFUSED
    except SystemExit as exit_request:
        # argparse uses SystemExit(2) for a usage error and SystemExit(0) for
        # --help. The stable code is printed for a refusal, never only the
        # usage text.
        code = int(exit_request.code or EXIT_USAGE)
        if code != 0:
            print("omission: code=OM_USAGE detail=see the usage above")
        return code


if __name__ == "__main__":
    sys.exit(main())
