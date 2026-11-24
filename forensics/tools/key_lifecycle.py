#!/usr/bin/env python3
"""key_lifecycle.py -- a signature is not survivable by itself.

Why this tool exists
--------------------
A signature says that whoever holds a key approved some bytes.  It says nothing
about what happens when that key is stolen.  If a repository has one key and no
metadata version, no expiry, no revocation record and no second root, then a
compromise of that key cannot be detected from inside the evidence: a release
signed before the compromise and a release signed after it are the same shape of
object.

This tool implements the survival properties on TUF principles so that the
absence of each one is a *named* refusal rather than an unstated assumption:

  * **rotation** -- a new root must be version-greater and signed by a threshold
    of both the old and the new root keys;
  * **delegation** -- a delegated role must be declared, hash-bound and
    unexpired;
  * **expiry** -- metadata whose ``expires`` is not after ``now`` is refused;
  * **revocation** -- a key revoked at or before ``now`` is refused, even when
    its signature verifies;
  * **anti-rollback** -- root may only increase; targets, snapshot and timestamp
    may not decrease;
  * **anti-freeze** -- an unexpired timestamp that was not refreshed within the
    declared maximum interval is refused;
  * **stale release** -- a release bound to an older metadata version, or signed
    by a key revoked at or before the release's recorded time, is refused.

The central rule is:

    An old signature never authorises a stale release.

What this tool does not do
--------------------------
It does **not** implement cryptography.  A signature is modelled structurally:
``sig`` must equal ``"sha256:" + SHA-256(canonical signed body || 0x00 || keyid)``.
That model catches a signature that was not produced over the bytes under test
(``TK_REFUSED_SIGNATURE``); it is not a production signature scheme, it has no
secret, and it establishes no authenticity.  Real signature verification is
``NOT_RUN``.  The model exists so that "a revoked key whose signature verifies"
can be demonstrated rather than asserted.

It does not decide that a repository is *true*, that its keys are honestly
held, that an accepted release is safe, or that a key ceremony happened.  There
is no ceremony in this project.

Usage
-----
    python3 forensics/tools/key_lifecycle.py evaluate REPOSITORY [--now TIME] [--previous PATH]
    python3 forensics/tools/key_lifecycle.py inventory
    python3 forensics/tools/key_lifecycle.py explain CODE

Exit status: 0 when a repository is ``ACCEPTED`` (or the query succeeds), 1 when
it is ``REFUSED``/``NOT_RUN``, 2 for a usage error.  The code is always printed.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

REPO_ROOT = Path(__file__).resolve().parents[2]

TOOL_PATH = "forensics/tools/key_lifecycle.py"
MODEL_ID = "a18/v1"
REPOSITORY_SCHEMA = "openssl-rs/a18/repository/1"
EVALUATION_SCHEMA = "openssl-rs/a18/key-lifecycle-evaluation/1"
INVENTORY_SCHEMA = "openssl-rs/a18/key-inventory/1"
CONTROLS_SCHEMA = "openssl-rs/a18/controls/1"
DEFAULT_REPOSITORY = REPO_ROOT / "evidence/a18/REPOSITORY.json"

ROLE_ROOT = "root"
ROLE_TARGETS = "targets"
ROLE_SNAPSHOT = "snapshot"
ROLE_TIMESTAMP = "timestamp"
ROLE_DELEGATION = "delegation"
ROLES: tuple[str, ...] = (
    ROLE_ROOT,
    ROLE_TARGETS,
    ROLE_SNAPSHOT,
    ROLE_TIMESTAMP,
    ROLE_DELEGATION,
)

OUTCOME_ACCEPTED = "ACCEPTED"
OUTCOME_REFUSED = "REFUSED"
OUTCOME_NOT_RUN = "NOT_RUN"
OUTCOMES = (OUTCOME_ACCEPTED, OUTCOME_REFUSED, OUTCOME_NOT_RUN)

EXIT_OK = 0
EXIT_REFUSED = 1
EXIT_USAGE = 2

CODE_OK = "TK_OK"
CODE_NOT_RUN = "TK_NOT_RUN"
CODE_USAGE = "TK_USAGE"

SIGNATURE_PREFIX = "sha256:"

# ---------------------------------------------------------------------------
# Refusal codes. Each is stable and names the wrong conclusion it prevents.
# ---------------------------------------------------------------------------

TK_REFUSED_REPOSITORY_INVALID = "TK_REFUSED_REPOSITORY_INVALID"
TK_REFUSED_ROOT_ROLLBACK = "TK_REFUSED_ROOT_ROLLBACK"
TK_REFUSED_ROOT_ROTATION_UNSIGNED_BY_OLD = "TK_REFUSED_ROOT_ROTATION_UNSIGNED_BY_OLD"
TK_REFUSED_TARGETS_ROLLBACK = "TK_REFUSED_TARGETS_ROLLBACK"
TK_REFUSED_SNAPSHOT_ROLLBACK = "TK_REFUSED_SNAPSHOT_ROLLBACK"
TK_REFUSED_TIMESTAMP_ROLLBACK = "TK_REFUSED_TIMESTAMP_ROLLBACK"
TK_REFUSED_SNAPSHOT_HASH_MISMATCH = "TK_REFUSED_SNAPSHOT_HASH_MISMATCH"
TK_REFUSED_TARGETS_HASH_MISMATCH = "TK_REFUSED_TARGETS_HASH_MISMATCH"
TK_REFUSED_EXPIRED_METADATA = "TK_REFUSED_EXPIRED_METADATA"
TK_REFUSED_FREEZE = "TK_REFUSED_FREEZE"
TK_REFUSED_KEY_EXPIRED = "TK_REFUSED_KEY_EXPIRED"
TK_REFUSED_KEY_NOT_YET_VALID = "TK_REFUSED_KEY_NOT_YET_VALID"
TK_REFUSED_KEY_REVOKED = "TK_REFUSED_KEY_REVOKED"
TK_REFUSED_UNKNOWN_KEY = "TK_REFUSED_UNKNOWN_KEY"
TK_REFUSED_ROLE_KEY_MISMATCH = "TK_REFUSED_ROLE_KEY_MISMATCH"
TK_REFUSED_METADATA_THRESHOLD = "TK_REFUSED_METADATA_THRESHOLD"
TK_REFUSED_DELEGATION_UNKNOWN = "TK_REFUSED_DELEGATION_UNKNOWN"
TK_REFUSED_DELEGATION_EXPIRED = "TK_REFUSED_DELEGATION_EXPIRED"
TK_REFUSED_DELEGATION_HASH_MISMATCH = "TK_REFUSED_DELEGATION_HASH_MISMATCH"
TK_REFUSED_STALE_RELEASE = "TK_REFUSED_STALE_RELEASE"
TK_REFUSED_SIGNATURE = "TK_REFUSED_SIGNATURE"

# The order a reader should apply them in; ``evaluate`` reports one code, and
# the controls are built so that only the named condition is present.
CODE_ORDER: tuple[str, ...] = (
    TK_REFUSED_REPOSITORY_INVALID,
    TK_REFUSED_ROOT_ROLLBACK,
    TK_REFUSED_ROOT_ROTATION_UNSIGNED_BY_OLD,
    TK_REFUSED_TARGETS_ROLLBACK,
    TK_REFUSED_SNAPSHOT_ROLLBACK,
    TK_REFUSED_TIMESTAMP_ROLLBACK,
    TK_REFUSED_SNAPSHOT_HASH_MISMATCH,
    TK_REFUSED_TARGETS_HASH_MISMATCH,
    TK_REFUSED_EXPIRED_METADATA,
    TK_REFUSED_FREEZE,
    TK_REFUSED_KEY_EXPIRED,
    TK_REFUSED_KEY_NOT_YET_VALID,
    TK_REFUSED_KEY_REVOKED,
    TK_REFUSED_UNKNOWN_KEY,
    TK_REFUSED_ROLE_KEY_MISMATCH,
    TK_REFUSED_METADATA_THRESHOLD,
    TK_REFUSED_DELEGATION_UNKNOWN,
    TK_REFUSED_DELEGATION_EXPIRED,
    TK_REFUSED_DELEGATION_HASH_MISMATCH,
    TK_REFUSED_STALE_RELEASE,
    TK_REFUSED_SIGNATURE,
)

REFUSALS: dict[str, dict[str, str]] = {
    TK_REFUSED_REPOSITORY_INVALID: {
        "condition": (
            "the repository is not a readable object with root, targets, "
            "snapshot and timestamp metadata, a declared maximum timestamp "
            "interval, and parseable versions, expiry times, keys and signatures"
        ),
        "prevents": (
            "that a malformed metadata set is read as a repository whose "
            "properties were checked"
        ),
    },
    TK_REFUSED_ROOT_ROLLBACK: {
        "condition": (
            "the offered root version is not greater than the last accepted root "
            "version"
        ),
        "prevents": (
            "that an attacker restores an old root and its old keys; a root that "
            "does not move forward is a rollback, not a rotation"
        ),
    },
    TK_REFUSED_ROOT_ROTATION_UNSIGNED_BY_OLD: {
        "condition": (
            "a rotation is not signed by the old root's declared threshold of old "
            "root keys"
        ),
        "prevents": (
            "that a party holding only the new root key replaces the root; the "
            "old root must authorise its own replacement"
        ),
    },
    TK_REFUSED_TARGETS_ROLLBACK: {
        "condition": (
            "the targets version is strictly lower than the last accepted targets "
            "version"
        ),
        "prevents": (
            "that an old targets metadata set is served as current, undoing a "
            "later delegation, revocation or file removal"
        ),
    },
    TK_REFUSED_SNAPSHOT_ROLLBACK: {
        "condition": (
            "the snapshot version is strictly lower than the last accepted "
            "snapshot version"
        ),
        "prevents": (
            "that an old snapshot is served alongside newer targets, hiding the "
            "targets version that was actually accepted"
        ),
    },
    TK_REFUSED_TIMESTAMP_ROLLBACK: {
        "condition": (
            "the timestamp version is strictly lower than the last accepted "
            "timestamp version"
        ),
        "prevents": (
            "that an old timestamp is replayed to make the repository look "
            "fresh at an earlier snapshot"
        ),
    },
    TK_REFUSED_SNAPSHOT_HASH_MISMATCH: {
        "condition": (
            "the timestamp names a snapshot version or snapshot digest that is not "
            "the snapshot being evaluated"
        ),
        "prevents": (
            "that a timestamp vouches for a different snapshot than the one "
            "supplied; freshness is bound to bytes, not to a role name"
        ),
    },
    TK_REFUSED_TARGETS_HASH_MISMATCH: {
        "condition": (
            "the snapshot names a targets version or targets digest that is not "
            "the targets metadata being evaluated"
        ),
        "prevents": (
            "that a snapshot vouches for different targets than the ones "
            "supplied, breaking the hash chain that makes rollback detectable"
        ),
    },
    TK_REFUSED_EXPIRED_METADATA: {
        "condition": "the metadata's ``expires`` is not after ``now``",
        "prevents": (
            "that expired metadata is read as current; expiry is what makes an "
            "old, still-correctly-signed set stop authorising anything"
        ),
    },
    TK_REFUSED_FREEZE: {
        "condition": (
            "the timestamp is unexpired but its ``issuedAt`` is older than the "
            "declared maximum refresh interval"
        ),
        "prevents": (
            "that an attacker stops updating the repository and serves a valid, "
            "unexpired timestamp forever; an unrefreshed repository is a freeze"
        ),
    },
    TK_REFUSED_KEY_EXPIRED: {
        "condition": "a signing key's ``notAfter`` is at or before ``now``",
        "prevents": (
            "that a key past its validity window is accepted because its "
            "signature still verifies"
        ),
    },
    TK_REFUSED_KEY_NOT_YET_VALID: {
        "condition": "a signing key's ``notBefore`` is after ``now``",
        "prevents": (
            "that a key introduced for a future rotation is used before the "
            "rotation that authorises it"
        ),
    },
    TK_REFUSED_KEY_REVOKED: {
        "condition": "a signing key has a ``revokedAt`` at or before ``now``",
        "prevents": (
            "that a signature by a revoked key is accepted because it verifies; "
            "revocation is a decision about the key, not about the bytes"
        ),
    },
    TK_REFUSED_UNKNOWN_KEY: {
        "condition": (
            "a signature names a keyid that no metadata in the repository "
            "declares, or that the root does not authorise for the role"
        ),
        "prevents": (
            "that an invented keyid supplies a signature the root never "
            "authorised"
        ),
    },
    TK_REFUSED_ROLE_KEY_MISMATCH: {
        "condition": (
            "a key declared or used by a role is bound by the root to a "
            "different role"
        ),
        "prevents": (
            "that a timestamp key signs targets, or any key acts outside the one "
            "role the root assigned it"
        ),
    },
    TK_REFUSED_METADATA_THRESHOLD: {
        "condition": (
            "fewer distinct valid keys signed a metadata record than its declared "
            "threshold"
        ),
        "prevents": (
            "that one key is counted twice, or a threshold is read as met by "
            "repeated signatures from the same key"
        ),
    },
    TK_REFUSED_DELEGATION_UNKNOWN: {
        "condition": (
            "targets declares a delegation with no matching record, or a "
            "delegation record is present that targets does not declare"
        ),
        "prevents": (
            "that an undeclared delegated role is trusted, or a declared one is "
            "silently absent"
        ),
    },
    TK_REFUSED_DELEGATION_EXPIRED: {
        "condition": "a delegation record's ``expires`` is not after ``now``",
        "prevents": (
            "that an expired delegated role continues to authorise targets after "
            "its delegation lapsed"
        ),
    },
    TK_REFUSED_DELEGATION_HASH_MISMATCH: {
        "condition": (
            "the digest targets records for a delegation is not the digest of the "
            "delegation record supplied"
        ),
        "prevents": (
            "that a delegation is replaced with different keys or different "
            "targets while keeping the name the parent approved"
        ),
    },
    TK_REFUSED_STALE_RELEASE: {
        "condition": (
            "a release is bound to a metadata version lower than the accepted "
            "version, or its signing key was revoked at or before the release's "
            "recorded time"
        ),
        "prevents": (
            "that an old signature authorises a stale release after metadata "
            "moved on or the key was revoked"
        ),
    },
    TK_REFUSED_SIGNATURE: {
        "condition": (
            "a signature does not match the structural signature model over the "
            "record's canonical signed body"
        ),
        "prevents": (
            "that a signature made over different bytes, or no signature at all, "
            "is counted toward a threshold"
        ),
    },
}


class ToolError(Exception):
    """An unreadable input or usage error (exit status 2)."""


class Refusal(Exception):
    """A stable refusal code and the conclusion it prevents."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


# ---------------------------------------------------------------------------
# Canonical bytes, digests and the test-only signature model
# ---------------------------------------------------------------------------


def canonical_bytes(document: Any) -> bytes:
    """Canonical JSON used for digests.  Never used to re-encode signed bytes."""
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


def metadata_digest(record: Mapping[str, Any]) -> str:
    """The digest a parent metadata record binds for this one."""
    return sha256_bytes(canonical_bytes(record))


def signed_body(record: Mapping[str, Any]) -> bytes:
    return canonical_bytes(
        {key: value for key, value in record.items() if key != "signatures"}
    )


def signature_value(record: Mapping[str, Any], keyid: str) -> str:
    """The test-only structural signature over ``record`` under ``keyid``.

    This is a reproducibility device, not cryptography: it has no secret and
    anyone can compute it.  It proves only that the bytes under test are the
    bytes the signature was computed over.
    """
    return SIGNATURE_PREFIX + sha256_bytes(
        signed_body(record) + b"\x00" + keyid.encode("utf-8")
    )


def _sign(record: dict[str, Any], keyids: Sequence[str]) -> dict[str, Any]:
    """Set ``record``'s signatures from the structural model (test/producer use)."""
    record["signatures"] = [
        {"keyid": keyid, "sig": signature_value(record, keyid)} for keyid in keyids
    ]
    return record


# ---------------------------------------------------------------------------
# Times and structural validation
# ---------------------------------------------------------------------------


def parse_time(value: Any) -> datetime:
    if isinstance(value, datetime):
        moment = value
    elif isinstance(value, str) and value.strip():
        text = value.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            moment = datetime.fromisoformat(text)
        except ValueError as error:
            raise ToolError(f"not an ISO-8601 time: {value!r}") from error
    else:
        raise ToolError(f"not a time: {value!r}")
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc)


def _require_mapping(value: Any, what: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise Refusal(TK_REFUSED_REPOSITORY_INVALID, f"{what} is a JSON object")
    return value


def _require_list(value: Any, what: str) -> list[Any]:
    if not isinstance(value, list):
        raise Refusal(TK_REFUSED_REPOSITORY_INVALID, f"{what} is a JSON array")
    return value


def _require_text(value: Any, what: str) -> str:
    if not isinstance(value, str) or not value:
        raise Refusal(TK_REFUSED_REPOSITORY_INVALID, f"{what} is a non-empty string")
    return value


def _require_int(value: Any, what: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise Refusal(
            TK_REFUSED_REPOSITORY_INVALID,
            f"{what} is an integer at least {minimum}",
        )
    return value


def _require_time(value: Any, what: str) -> datetime:
    try:
        return parse_time(value)
    except ToolError as error:
        raise Refusal(
            TK_REFUSED_REPOSITORY_INVALID, f"{what} is an ISO-8601 time: {error}"
        ) from error


def _require_digest(value: Any, what: str) -> str:
    text = _require_text(value, what)
    if len(text) != 64 or any(character not in "0123456789abcdef" for character in text):
        raise Refusal(
            TK_REFUSED_REPOSITORY_INVALID, f"{what} is 64 lowercase hex characters"
        )
    return text


def normalise_key(value: Any, where: str) -> dict[str, Any]:
    key = _require_mapping(value, where)
    keyid = _require_text(key.get("keyid"), f"{where}.keyid")
    role = _require_text(key.get("role"), f"{where}.role")
    if role not in ROLES:
        raise Refusal(
            TK_REFUSED_REPOSITORY_INVALID,
            f"{where}.role is one of {', '.join(ROLES)}",
        )
    not_before = _require_time(key.get("notBefore"), f"{where}.notBefore")
    not_after = _require_time(key.get("notAfter"), f"{where}.notAfter")
    if not_after <= not_before:
        raise Refusal(
            TK_REFUSED_REPOSITORY_INVALID,
            f"{where}: notAfter must be after notBefore",
        )
    revoked = key.get("revokedAt")
    if revoked is not None:
        _require_time(revoked, f"{where}.revokedAt")
    return dict(key)


def normalise_record(value: Any, role: str) -> dict[str, Any]:
    record = _require_mapping(value, f"metadata.{role}")
    declared_role = _require_text(record.get("role"), f"metadata.{role}.role")
    if declared_role != role:
        raise Refusal(
            TK_REFUSED_REPOSITORY_INVALID,
            f"metadata.{role}.role is {declared_role!r}, not {role!r}",
        )
    _require_int(record.get("version"), f"metadata.{role}.version", 1)
    _require_time(record.get("expires"), f"metadata.{role}.expires")
    if "threshold" in record:
        _require_int(record["threshold"], f"metadata.{role}.threshold", 1)
    keys = _require_list(record.get("keys"), f"metadata.{role}.keys")
    if not keys:
        raise Refusal(
            TK_REFUSED_REPOSITORY_INVALID, f"metadata.{role}.keys is not empty"
        )
    for index, key in enumerate(keys):
        normalise_key(key, f"metadata.{role}.keys[{index}]")
    signatures = _require_list(
        record.get("signatures"), f"metadata.{role}.signatures"
    )
    for index, entry in enumerate(signatures):
        item = _require_mapping(entry, f"metadata.{role}.signatures[{index}]")
        _require_text(item.get("keyid"), f"metadata.{role}.signatures[{index}].keyid")
        _require_text(item.get("sig"), f"metadata.{role}.signatures[{index}].sig")
    return dict(record)


def _normalise_reference(value: Any, what: str) -> dict[str, Any]:
    reference = _require_mapping(value, what)
    version = _require_int(reference.get("version"), f"{what}.version", 1)
    digest = _require_digest(reference.get("sha256"), f"{what}.sha256")
    return {"version": version, "sha256": digest}


def normalise_repository(value: Any) -> dict[str, Any]:
    """Validate the shape of a repository.  Refuses with REPOSITORY_INVALID."""
    repository = _require_mapping(value, "the repository")
    metadata = _require_mapping(repository.get("metadata"), "repository.metadata")
    records: dict[str, dict[str, Any]] = {}
    for role in (ROLE_ROOT, ROLE_TARGETS, ROLE_SNAPSHOT, ROLE_TIMESTAMP):
        records[role] = normalise_record(metadata.get(role), role)
    records[ROLE_SNAPSHOT]["targets"] = _normalise_reference(
        records[ROLE_SNAPSHOT].get("targets"), "metadata.snapshot.targets"
    )
    records[ROLE_TIMESTAMP]["snapshot"] = _normalise_reference(
        records[ROLE_TIMESTAMP].get("snapshot"), "metadata.timestamp.snapshot"
    )
    _require_time(records[ROLE_TIMESTAMP].get("issuedAt"), "metadata.timestamp.issuedAt")
    interval = _require_int(
        repository.get("maxTimestampInterval"),
        "repository.maxTimestampInterval",
        1,
    )
    declarations = records[ROLE_TARGETS].get("delegations") or []
    _require_list(declarations, "metadata.targets.delegations")
    for index, declaration in enumerate(declarations):
        item = _require_mapping(
            declaration, f"metadata.targets.delegations[{index}]"
        )
        _require_text(item.get("name"), f"metadata.targets.delegations[{index}].name")
        _require_digest(
            item.get("sha256"), f"metadata.targets.delegations[{index}].sha256"
        )
    delegations = repository.get("delegations") or []
    _require_list(delegations, "repository.delegations")
    normalised_delegations: list[dict[str, Any]] = []
    for index, delegation in enumerate(delegations):
        record = normalise_record(delegation, ROLE_DELEGATION)
        _require_text(record.get("name"), f"repository.delegations[{index}].name")
        normalised_delegations.append(record)
    releases = repository.get("releases") or []
    _require_list(releases, "repository.releases")
    normalised_releases: list[dict[str, Any]] = []
    for index, release in enumerate(releases):
        item = _require_mapping(release, f"repository.releases[{index}]")
        normalised_releases.append(
            {
                "id": _require_text(item.get("id"), f"repository.releases[{index}].id"),
                "version": _require_int(
                    item.get("version"), f"repository.releases[{index}].version", 1
                ),
                "time": _require_time(
                    item.get("time"), f"repository.releases[{index}].time"
                ),
                "keyid": _require_text(
                    item.get("keyid"), f"repository.releases[{index}].keyid"
                ),
            }
        )
    return {
        "metadata": records,
        "delegations": normalised_delegations,
        "releases": normalised_releases,
        "maxTimestampInterval": interval,
    }


# ---------------------------------------------------------------------------
# Keys and signatures
# ---------------------------------------------------------------------------


def _key_index(record: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    for key in record["keys"]:
        index.setdefault(key["keyid"], key)
    return index


def _check_key_window(key: Mapping[str, Any], role: str, now: datetime) -> None:
    if key["role"] != role:
        raise Refusal(
            TK_REFUSED_ROLE_KEY_MISMATCH,
            f"key {key['keyid']!r} is bound to {key['role']!r}, not {role!r}",
        )
    not_before = parse_time(key["notBefore"])
    not_after = parse_time(key["notAfter"])
    if not_before > now:
        raise Refusal(
            TK_REFUSED_KEY_NOT_YET_VALID,
            f"key {key['keyid']!r} is not valid before {key['notBefore']}",
        )
    if not_after <= now:
        raise Refusal(
            TK_REFUSED_KEY_EXPIRED,
            f"key {key['keyid']!r} expired at {key['notAfter']}",
        )
    revoked = key.get("revokedAt")
    if revoked is not None and parse_time(revoked) <= now:
        raise Refusal(
            TK_REFUSED_KEY_REVOKED,
            f"key {key['keyid']!r} was revoked at {revoked}",
        )


def _threshold(record: Mapping[str, Any]) -> int:
    return int(record.get("threshold", 1))


def _check_signatures(
    record: Mapping[str, Any],
    role: str,
    now: datetime,
    authorised: Mapping[str, Mapping[str, Any]],
) -> None:
    verified: set[str] = set()
    declared = _key_index(record)
    for entry in record["signatures"]:
        keyid = entry["keyid"]
        key = authorised.get(keyid)
        if key is None:
            if keyid in declared:
                raise Refusal(
                    TK_REFUSED_ROLE_KEY_MISMATCH,
                    f"key {keyid!r} is declared by {role!r} but the root does not "
                    f"authorise it for that role",
                )
            raise Refusal(
                TK_REFUSED_UNKNOWN_KEY,
                f"key {keyid!r} signs {role!r} but no metadata declares it",
            )
        _check_key_window(key, role, now)
        if entry["sig"] != signature_value(record, keyid):
            raise Refusal(
                TK_REFUSED_SIGNATURE,
                f"the signature by {keyid!r} on {role!r} is not over these bytes",
            )
        verified.add(keyid)
    if len(verified) < _threshold(record):
        raise Refusal(
            TK_REFUSED_METADATA_THRESHOLD,
            f"{role} has {len(verified)} distinct valid signature(s) and its "
            f"threshold is {_threshold(record)}",
        )


def _check_declared_keys(
    record: Mapping[str, Any],
    role: str,
    root: Mapping[str, Any],
) -> None:
    authorised = {
        key["keyid"]: key for key in root["keys"] if key["role"] == role
    }
    root_keys = _key_index(root)
    for key in record["keys"]:
        if key["role"] != role:
            raise Refusal(
                TK_REFUSED_ROLE_KEY_MISMATCH,
                f"{role} declares key {key['keyid']!r} bound to {key['role']!r}",
            )
        if key["keyid"] not in authorised:
            if key["keyid"] in root_keys:
                raise Refusal(
                    TK_REFUSED_ROLE_KEY_MISMATCH,
                    f"the root binds key {key['keyid']!r} to "
                    f"{root_keys[key['keyid']]['role']!r}, not {role!r}",
                )
            raise Refusal(
                TK_REFUSED_UNKNOWN_KEY,
                f"{role} declares key {key['keyid']!r} that the root never lists",
            )


# ---------------------------------------------------------------------------
# The role checks
# ---------------------------------------------------------------------------


def _check_root(
    root: Mapping[str, Any],
    previous_root: Mapping[str, Any] | None,
    now: datetime,
) -> None:
    if previous_root is not None and root["version"] <= previous_root["version"]:
        raise Refusal(
            TK_REFUSED_ROOT_ROLLBACK,
            f"root version {root['version']} is not greater than the accepted "
            f"version {previous_root['version']}",
        )
    if parse_time(root["expires"]) <= now:
        raise Refusal(
            TK_REFUSED_EXPIRED_METADATA,
            f"root expired at {root['expires']}",
        )
    new_keys = {
        key["keyid"]: key for key in root["keys"] if key["role"] == ROLE_ROOT
    }
    old_keys: dict[str, dict[str, Any]] = {}
    if previous_root is not None:
        old_keys = {
            key["keyid"]: key
            for key in previous_root["keys"]
            if key["role"] == ROLE_ROOT
        }
    declared = _key_index(root)
    new_verified: set[str] = set()
    old_verified: set[str] = set()
    for entry in root["signatures"]:
        keyid = entry["keyid"]
        key = new_keys.get(keyid) or old_keys.get(keyid)
        if key is None:
            if keyid in declared:
                raise Refusal(
                    TK_REFUSED_ROLE_KEY_MISMATCH,
                    f"root signature key {keyid!r} is bound to "
                    f"{declared[keyid]['role']!r}",
                )
            raise Refusal(
                TK_REFUSED_UNKNOWN_KEY,
                f"root signature key {keyid!r} is declared by no root",
            )
        _check_key_window(key, ROLE_ROOT, now)
        if entry["sig"] != signature_value(root, keyid):
            raise Refusal(
                TK_REFUSED_SIGNATURE,
                f"the root signature by {keyid!r} is not over these bytes",
            )
        if keyid in new_keys:
            new_verified.add(keyid)
        if keyid in old_keys:
            old_verified.add(keyid)
    if len(new_verified) < _threshold(root):
        raise Refusal(
            TK_REFUSED_METADATA_THRESHOLD,
            f"root has {len(new_verified)} distinct new-root signature(s) and its "
            f"threshold is {_threshold(root)}",
        )
    if previous_root is not None:
        old_threshold = _threshold(previous_root)
        if len(old_verified) < old_threshold:
            raise Refusal(
                TK_REFUSED_ROOT_ROTATION_UNSIGNED_BY_OLD,
                f"the new root is signed by {len(old_verified)} old-root key(s) "
                f"and the old root's threshold is {old_threshold}",
            )


ROLLBACK_CODES: dict[str, str] = {
    ROLE_TARGETS: TK_REFUSED_TARGETS_ROLLBACK,
    ROLE_SNAPSHOT: TK_REFUSED_SNAPSHOT_ROLLBACK,
    ROLE_TIMESTAMP: TK_REFUSED_TIMESTAMP_ROLLBACK,
}


def _check_role_record(
    record: Mapping[str, Any],
    role: str,
    root: Mapping[str, Any],
    previous_record: Mapping[str, Any] | None,
    now: datetime,
) -> None:
    if previous_record is not None and record["version"] < previous_record["version"]:
        raise Refusal(
            ROLLBACK_CODES[role],
            f"{role} version {record['version']} is lower than the accepted "
            f"version {previous_record['version']}",
        )
    if parse_time(record["expires"]) <= now:
        raise Refusal(
            TK_REFUSED_EXPIRED_METADATA,
            f"{role} expired at {record['expires']}",
        )
    _check_declared_keys(record, role, root)
    authorised = {
        key["keyid"]: key for key in root["keys"] if key["role"] == role
    }
    _check_signatures(record, role, now, authorised)


def _check_targets_chain(
    snapshot: Mapping[str, Any], targets: Mapping[str, Any]
) -> None:
    reference = snapshot["targets"]
    digest = metadata_digest(targets)
    if reference["version"] != targets["version"]:
        raise Refusal(
            TK_REFUSED_TARGETS_HASH_MISMATCH,
            f"the snapshot names targets version {reference['version']} and the "
            f"targets metadata is version {targets['version']}",
        )
    if reference["sha256"] != digest:
        raise Refusal(
            TK_REFUSED_TARGETS_HASH_MISMATCH,
            f"the snapshot names targets digest {reference['sha256']} and the "
            f"targets metadata hashes to {digest}",
        )


def _check_snapshot_chain(
    timestamp: Mapping[str, Any], snapshot: Mapping[str, Any]
) -> None:
    reference = timestamp["snapshot"]
    digest = metadata_digest(snapshot)
    if reference["version"] != snapshot["version"]:
        raise Refusal(
            TK_REFUSED_SNAPSHOT_HASH_MISMATCH,
            f"the timestamp names snapshot version {reference['version']} and the "
            f"snapshot is version {snapshot['version']}",
        )
    if reference["sha256"] != digest:
        raise Refusal(
            TK_REFUSED_SNAPSHOT_HASH_MISMATCH,
            f"the timestamp names snapshot digest {reference['sha256']} and the "
            f"snapshot hashes to {digest}",
        )


def _check_freeze(
    timestamp: Mapping[str, Any], now: datetime, interval: int
) -> None:
    issued = parse_time(timestamp["issuedAt"])
    age = (now - issued).total_seconds()
    if age > interval:
        raise Refusal(
            TK_REFUSED_FREEZE,
            f"the timestamp was issued at {timestamp['issuedAt']}, {int(age)}s "
            f"before now, and the declared maximum interval is {interval}s",
        )


def _check_delegations(
    repository: Mapping[str, Any], now: datetime
) -> None:
    targets = repository["metadata"][ROLE_TARGETS]
    declarations = targets.get("delegations") or []
    records = repository["delegations"]
    by_name = {record["name"]: record for record in records}
    declared_names = {declaration["name"] for declaration in declarations}
    for declaration in declarations:
        name = declaration["name"]
        record = by_name.get(name)
        if record is None:
            raise Refusal(
                TK_REFUSED_DELEGATION_UNKNOWN,
                f"targets declares delegation {name!r} and no record supplies it",
            )
        digest = metadata_digest(record)
        if declaration["sha256"] != digest:
            raise Refusal(
                TK_REFUSED_DELEGATION_HASH_MISMATCH,
                f"targets binds delegation {name!r} to {declaration['sha256']} "
                f"and the record hashes to {digest}",
            )
        if parse_time(record["expires"]) <= now:
            raise Refusal(
                TK_REFUSED_DELEGATION_EXPIRED,
                f"delegation {name!r} expired at {record['expires']}",
            )
        own = _key_index(record)
        for key in record["keys"]:
            if key["role"] != ROLE_DELEGATION:
                raise Refusal(
                    TK_REFUSED_ROLE_KEY_MISMATCH,
                    f"delegation {name!r} declares key {key['keyid']!r} bound to "
                    f"{key['role']!r}",
                )
        _check_signatures(record, ROLE_DELEGATION, now, own)
    for record in records:
        if record["name"] not in declared_names:
            raise Refusal(
                TK_REFUSED_DELEGATION_UNKNOWN,
                f"delegation {record['name']!r} is supplied but targets does not "
                "declare it",
            )


def _check_releases(
    repository: Mapping[str, Any],
    accepted_targets_version: int,
) -> None:
    root = repository["metadata"][ROLE_ROOT]
    keys = _key_index(root)
    for release in repository["releases"]:
        key = keys.get(release["keyid"])
        if key is None:
            raise Refusal(
                TK_REFUSED_UNKNOWN_KEY,
                f"release {release['id']!r} names key {release['keyid']!r} that "
                "the root never lists",
            )
        revoked = key.get("revokedAt")
        if revoked is not None and parse_time(revoked) <= release["time"]:
            raise Refusal(
                TK_REFUSED_STALE_RELEASE,
                f"release {release['id']!r} was signed at {release['time'].isoformat()} "
                f"by key {release['keyid']!r}, revoked at {revoked}",
            )
        if release["version"] < accepted_targets_version:
            raise Refusal(
                TK_REFUSED_STALE_RELEASE,
                f"release {release['id']!r} is bound to metadata version "
                f"{release['version']} and the accepted targets version is "
                f"{accepted_targets_version}",
            )


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------


def _status(outcome: str, code: str, detail: str) -> dict[str, str]:
    return {"outcome": outcome, "code": code, "detail": detail}


def _not_run_result(reason: str, moment: datetime | None) -> dict[str, Any]:
    roles = {
        role: _status(OUTCOME_NOT_RUN, CODE_NOT_RUN, reason) for role in ROLES
    }
    return {
        "schema": EVALUATION_SCHEMA,
        "model": MODEL_ID,
        "outcome": OUTCOME_NOT_RUN,
        "code": CODE_NOT_RUN,
        "codes": [CODE_NOT_RUN],
        "at": moment.isoformat() if moment is not None else None,
        "roles": roles,
        "staleRelease": _status(OUTCOME_NOT_RUN, CODE_NOT_RUN, reason),
        "detail": [reason],
        "accepted": None,
    }


def _result(
    outcome: str,
    code: str,
    statuses: Mapping[str, dict[str, str]],
    detail: list[str],
    moment: datetime,
    accepted: Mapping[str, Any] | None,
) -> dict[str, Any]:
    return {
        "schema": EVALUATION_SCHEMA,
        "model": MODEL_ID,
        "outcome": outcome,
        "code": code,
        "codes": [code],
        "at": moment.isoformat(),
        "roles": {role: statuses[role] for role in ROLES},
        "staleRelease": statuses["release"],
        "detail": detail,
        "accepted": accepted,
    }


def evaluate(
    repository: Any,
    now: Any = None,
    previous: Any = None,
) -> dict[str, Any]:
    """Evaluate one repository against the last accepted metadata set.

    ``repository`` is a repository object (or ``None`` when none exists).
    ``now`` is the evaluation time; it is required and is never read from the
    clock by this function.  ``previous`` is the last accepted repository, or
    ``None`` for an initial root.
    """
    if now is None:
        raise ToolError("an evaluation time is required; no clock is read")
    moment = parse_time(now)

    if repository is None:
        return _not_run_result(
            "no repository exists: there is no metadata set, no key record, no "
            "version and no delegation to evaluate, so every role and the "
            "stale-release check are NOT_RUN and NOT_RUN is not a pass",
            moment,
        )

    try:
        repo = normalise_repository(repository)
        prior = normalise_repository(previous) if previous is not None else None
    except Refusal as refusal:
        statuses = {
            role: _status(OUTCOME_NOT_RUN, CODE_NOT_RUN, "not evaluated")
            for role in ROLES
        }
        statuses["release"] = _status(
            OUTCOME_NOT_RUN, CODE_NOT_RUN, "not evaluated"
        )
        return _result(
            OUTCOME_REFUSED,
            refusal.code,
            statuses,
            [f"{refusal.code}: {refusal.message}"],
            moment,
            None,
        )

    metadata = repo["metadata"]
    previous_metadata = prior["metadata"] if prior is not None else None
    statuses: dict[str, dict[str, str]] = {}
    order = [ROLE_ROOT, ROLE_TARGETS, ROLE_SNAPSHOT, ROLE_TIMESTAMP,
             ROLE_DELEGATION, "release"]
    accepted_versions: dict[str, int] = {}

    steps = {
        ROLE_ROOT: lambda: _check_root(
            metadata[ROLE_ROOT],
            previous_metadata[ROLE_ROOT] if previous_metadata is not None else None,
            moment,
        ),
        ROLE_TARGETS: lambda: _check_role_record(
            metadata[ROLE_TARGETS], ROLE_TARGETS, metadata[ROLE_ROOT],
            previous_metadata[ROLE_TARGETS] if previous_metadata is not None else None,
            moment,
        ),
        ROLE_SNAPSHOT: lambda: _check_role_record(
            metadata[ROLE_SNAPSHOT], ROLE_SNAPSHOT, metadata[ROLE_ROOT],
            previous_metadata[ROLE_SNAPSHOT] if previous_metadata is not None else None,
            moment,
        ),
        ROLE_TIMESTAMP: lambda: _check_role_record(
            metadata[ROLE_TIMESTAMP], ROLE_TIMESTAMP, metadata[ROLE_ROOT],
            previous_metadata[ROLE_TIMESTAMP] if previous_metadata is not None else None,
            moment,
        ),
        ROLE_DELEGATION: lambda: _check_delegations(repo, moment),
        "release": lambda: _check_releases(repo, metadata[ROLE_TARGETS]["version"]),
    }

    for position, role in enumerate(order):
        try:
            steps[role]()
        except Refusal as refusal:
            statuses[role] = _status(
                OUTCOME_REFUSED, refusal.code, refusal.message
            )
            for remaining in order[position + 1:]:
                statuses[remaining] = _status(
                    OUTCOME_NOT_RUN, CODE_NOT_RUN,
                    f"not evaluated because {role!r} was refused",
                )
            return _result(
                OUTCOME_REFUSED,
                refusal.code,
                statuses,
                [f"{role}: {refusal.code}: {refusal.message}"],
                moment,
                None,
            )
        statuses[role] = _status(OUTCOME_ACCEPTED, CODE_OK, f"{role} accepted")
        if role in (ROLE_ROOT, ROLE_TARGETS, ROLE_SNAPSHOT, ROLE_TIMESTAMP):
            accepted_versions[role] = int(metadata[role]["version"])

    # The hash chain is checked after each record is individually valid.
    try:
        _check_targets_chain(metadata[ROLE_SNAPSHOT], metadata[ROLE_TARGETS])
        _check_snapshot_chain(metadata[ROLE_TIMESTAMP], metadata[ROLE_SNAPSHOT])
        _check_freeze(metadata[ROLE_TIMESTAMP], moment, repo["maxTimestampInterval"])
    except Refusal as refusal:
        failing = (
            ROLE_SNAPSHOT
            if refusal.code == TK_REFUSED_TARGETS_HASH_MISMATCH
            else ROLE_TIMESTAMP
        )
        statuses[failing] = _status(
            OUTCOME_REFUSED, refusal.code, refusal.message
        )
        statuses["delegation"] = _status(
            OUTCOME_NOT_RUN, CODE_NOT_RUN,
            f"not evaluated because {failing!r} was refused",
        )
        statuses["release"] = _status(
            OUTCOME_NOT_RUN, CODE_NOT_RUN,
            f"not evaluated because {failing!r} was refused",
        )
        return _result(
            OUTCOME_REFUSED,
            refusal.code,
            statuses,
            [f"{failing}: {refusal.code}: {refusal.message}"],
            moment,
            None,
        )

    accepted = {
        "rootVersion": accepted_versions[ROLE_ROOT],
        "targetsVersion": accepted_versions[ROLE_TARGETS],
        "snapshotVersion": accepted_versions[ROLE_SNAPSHOT],
        "timestampVersion": accepted_versions[ROLE_TIMESTAMP],
        "delegations": [record["name"] for record in repo["delegations"]],
        "releases": [release["id"] for release in repo["releases"]],
    }
    return _result(
        OUTCOME_ACCEPTED,
        CODE_OK,
        statuses,
        ["every role is unexpired, version-monotonic, threshold-signed and "
         "hash-bound; no release is stale"],
        moment,
        accepted,
    )


# ---------------------------------------------------------------------------
# The real inventory
# ---------------------------------------------------------------------------


def real_inventory() -> dict[str, Any]:
    """The measured key inventory: one test-only symmetric key, no repository."""
    path = REPO_ROOT / "evidence/a12/TRUST-ROOTS.json"
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ToolError(f"cannot read {path}: {error}") from error
    roots = document.get("roots")
    if not isinstance(roots, list) or len(roots) != 1:
        raise ToolError(
            f"{path} does not record exactly one root; the A18 inventory is "
            "written against the one-key state and would otherwise be wrong"
        )
    root = roots[0]
    findings = (
        "The single key is a single point of compromise with no detectable "
        "recovery. There is no second root to rotate to, no revocation list to "
        "consult and no metadata version to distinguish a pre-compromise "
        "signature from a post-compromise one. A bundle or envelope signed "
        "before a hypothetical compromise is indistinguishable from one signed "
        "after it."
    )
    return {
        "schema": INVENTORY_SCHEMA,
        "item": "A18",
        "model": MODEL_ID,
        "asOf": "2026-11-24",
        "keys": [
            {
                "keyid": root.get("keyid"),
                "algorithm": root.get("algorithm"),
                "symmetric": bool(root.get("symmetric")),
                "roles": ["statement-signing"],
                "trustDomain": root.get("trustDomain"),
                "provenance": root.get("provenance"),
                "establishedBy": {
                    "path": "evidence/a12/TRUST-ROOTS.json",
                    "sha256": sha256_file(path),
                },
                "hasExpiry": False,
                "expires": None,
                "hasRevocationRecord": False,
                "revocationRecord": None,
                "metadataVersion": None,
                "delegation": None,
            }
        ],
        "keyCount": 1,
        "repositories": 0,
        "metadataVersions": 0,
        "revocationRecords": 0,
        "expiryRecords": 0,
        "delegations": 0,
        "singlePointOfCompromise": True,
        "detectable": False,
        "recoverable": False,
        "beforeAfterIndistinguishable": True,
        "finding": findings,
        "explanation": (
            "The measured state is one key, zero repositories, zero metadata "
            "versions, zero revocation records, zero expiry records and zero "
            "delegations. That is the honest result, not an omission: no "
            "survivability property can be evaluated against a repository that "
            "does not exist, and the absence of a second root means compromise "
            "of the one key cannot be detected or recovered from within the "
            "evidence."
        ),
    }


# ---------------------------------------------------------------------------
# The command line
# ---------------------------------------------------------------------------


def _load_repository(path: Path) -> Any:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ToolError(f"cannot read {path}: {error}") from error


def _print_evaluation(result: Mapping[str, Any], source: str) -> None:
    print(
        f"key-lifecycle: outcome={result.get('outcome')} code={result.get('code')} "
        f"repository={source}"
    )
    for role, status in (result.get("roles") or {}).items():
        print(
            f"  role: {role} outcome={status.get('outcome')} "
            f"code={status.get('code')}"
        )
    release = result.get("staleRelease") or {}
    print(
        f"  stale-release: outcome={release.get('outcome')} "
        f"code={release.get('code')}"
    )
    for line in result.get("detail") or []:
        print(f"  detail: {line}")


def _print_inventory(document: Mapping[str, Any]) -> None:
    print(
        f"inventory: code={CODE_OK} outcome={OUTCOME_NOT_RUN} "
        f"keys={document.get('keyCount')} "
        f"repositories={document.get('repositories')} "
        f"metadataVersions={document.get('metadataVersions')} "
        f"revocationRecords={document.get('revocationRecords')} "
        f"expiryRecords={document.get('expiryRecords')} "
        f"delegations={document.get('delegations')} "
        f"singlePointOfCompromise={document.get('singlePointOfCompromise')}"
    )
    for key in document.get("keys") or []:
        print(
            f"  key: keyid={key.get('keyid')} symmetric={key.get('symmetric')} "
            f"expires={key.get('expires')} "
            f"revocationRecord={key.get('revocationRecord')} "
            f"metadataVersion={key.get('metadataVersion')} "
            f"delegation={key.get('delegation')}"
        )
    print(f"  finding: {document.get('finding')}")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    evaluate_parser = sub.add_parser("evaluate", help="evaluate a repository")
    evaluate_parser.add_argument("repository", nargs="?", default=None)
    evaluate_parser.add_argument("--now", default=None)
    evaluate_parser.add_argument("--previous", default=None)

    sub.add_parser("inventory", help="print the real key inventory")

    explain_parser = sub.add_parser("explain", help="explain a refusal code")
    explain_parser.add_argument("code")

    args = parser.parse_args(argv)

    try:
        if args.command == "inventory":
            _print_inventory(real_inventory())
            return EXIT_OK

        if args.command == "explain":
            entry = REFUSALS.get(args.code)
            if entry is None and args.code not in (CODE_OK, CODE_NOT_RUN):
                print(f"{CODE_USAGE}: unknown code {args.code!r}")
                return EXIT_USAGE
            if entry is None:
                print(f"explain: code={args.code} not-a-refusal")
            else:
                print(f"explain: code={args.code}")
                print(f"  condition: {entry['condition']}")
                print(f"  prevents: {entry['prevents']}")
            return EXIT_OK

        source = args.repository or str(DEFAULT_REPOSITORY)
        repository = _load_repository(Path(source))
        previous = None
        if args.previous:
            previous = _load_repository(Path(args.previous))
            if previous is None:
                print(f"{CODE_USAGE}: no previous repository at {args.previous}")
                return EXIT_USAGE
        now = args.now or datetime.now(timezone.utc)
        result = evaluate(repository, now, previous)
        _print_evaluation(result, source)
        return EXIT_OK if result["outcome"] == OUTCOME_ACCEPTED else EXIT_REFUSED
    except ToolError as error:
        print(f"{CODE_USAGE}: {error}")
        return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
