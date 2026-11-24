#!/usr/bin/env python3
"""build_evidence.py -- deterministic producer of the A18 records.

It writes three documents and nothing else:

  * ``INVENTORY.json``  -- the real key inventory: one test-only symmetric key,
    zero repositories, zero metadata versions, zero revocation records, zero
    expiry records and zero delegations, with the single-point-of-compromise
    finding stated explicitly;
  * ``EVALUATION.json`` -- every role evaluated against the absent repository:
    ``NOT_RUN`` with ``TK_NOT_RUN``, and the stale-release check ``NOT_RUN`` for
    the same reason;
  * ``CONTROLS.json``   -- ``control-only`` repositories, one per refusal code,
    plus a threshold-signed, version-incremented, unexpired positive control
    that reaches ``ACCEPTED``.

Nothing reads the clock: ``NOW`` is a literal.  Two runs are byte-identical.

Usage:
    python3 evidence/a18/build_evidence.py [--out DIR]

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path
from typing import Any, Mapping

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOLS = REPO_ROOT / "forensics/tools"
EVIDENCE = REPO_ROOT / "evidence/a18"
sys.path.insert(0, str(TOOLS))

import key_lifecycle as kl  # noqa: E402

BASE_COMMIT = "2e8e9aa65ba60321c18f54890aa73caa200f5bd7"
BASE_COMMIT_SHORT = "2e8e9aa65"
ITEM = "A18"
AS_OF = "2026-11-24"
NOW = "2026-11-24T00:00:00Z"
EXPIRES = "2027-01-01T00:00:00Z"
NOT_BEFORE = "2026-01-01T00:00:00Z"
NOT_AFTER = "2027-01-01T00:00:00Z"
REVOKED = "2026-06-01T00:00:00Z"
INTERVAL = 7 * 24 * 60 * 60

K_ROOT_OLD = "control-only:root-old"
K_ROOT_NEW_A = "control-only:root-new-a"
K_ROOT_NEW_B = "control-only:root-new-b"
K_TARGETS = "control-only:targets"
K_SNAPSHOT = "control-only:snapshot"
K_TIMESTAMP = "control-only:timestamp"
K_DELEGATION = "control-only:delegation"
K_TARGETS_REVOKED = "control-only:targets-revoked"
K_TARGETS_EXPIRED = "control-only:targets-expired"
K_TARGETS_FUTURE = "control-only:targets-future"
K_WRONG_ROLE = "control-only:targets-wrong-role"
K_RELEASE_REVOKED = "control-only:release-revoked"

CANDIDATE = {
    "baseCommit": BASE_COMMIT,
    "baseCommitShort": BASE_COMMIT_SHORT,
    "branch": "staging",
    "recordedAt": AS_OF,
}


def write_json(path: Path, document: Mapping[str, Any]) -> None:
    path.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def source_identity() -> dict[str, Any]:
    return {
        "baseCommit": BASE_COMMIT,
        "baseCommitShort": BASE_COMMIT_SHORT,
        "branch": "staging",
        "recordedAt": AS_OF,
        "item": ITEM,
        "tool": kl.tool_identity(),
    }


# ---------------------------------------------------------------------------
# Synthetic repositories.  Everything below is control-only.
# ---------------------------------------------------------------------------


def key(
    keyid: str,
    role: str,
    *,
    not_before: str = NOT_BEFORE,
    not_after: str = NOT_AFTER,
    revoked_at: str | None = None,
) -> dict[str, Any]:
    return {
        "keyid": keyid,
        "role": role,
        "notBefore": not_before,
        "notAfter": not_after,
        "revokedAt": revoked_at,
    }


def _role_keys() -> list[dict[str, Any]]:
    return [
        key(K_TARGETS, kl.ROLE_TARGETS),
        key(K_SNAPSHOT, kl.ROLE_SNAPSHOT),
        key(K_TIMESTAMP, kl.ROLE_TIMESTAMP),
    ]


def _control_keys() -> list[dict[str, Any]]:
    """Keys only the controls use; every stage lists them so a control can sign."""
    return [
        key(K_TARGETS_REVOKED, kl.ROLE_TARGETS, revoked_at=REVOKED),
        key(K_TARGETS_EXPIRED, kl.ROLE_TARGETS, not_after="2026-06-01T00:00:00Z"),
        key(
            K_TARGETS_FUTURE,
            kl.ROLE_TARGETS,
            not_before="2027-06-01T00:00:00Z",
            not_after="2028-01-01T00:00:00Z",
        ),
        key(K_WRONG_ROLE, kl.ROLE_TIMESTAMP),
        key(K_RELEASE_REVOKED, kl.ROLE_TARGETS, revoked_at=REVOKED),
    ]


def _root_keys(stage: str) -> list[dict[str, Any]]:
    if stage == "old":
        signing = [key(K_ROOT_OLD, kl.ROLE_ROOT)]
    else:
        signing = [
            key(K_ROOT_NEW_A, kl.ROLE_ROOT),
            key(K_ROOT_NEW_B, kl.ROLE_ROOT),
        ]
    return signing + _role_keys() + _control_keys()


def _root_signers(stage: str) -> list[str]:
    if stage == "old":
        return [K_ROOT_OLD]
    if stage == "new":
        return [K_ROOT_NEW_A, K_ROOT_NEW_B]
    return [K_ROOT_OLD, K_ROOT_NEW_A, K_ROOT_NEW_B]


def healthy_repository(
    version: int = 2,
    stage: str = "rotate",
    *,
    issued_at: str = NOW,
) -> dict[str, Any]:
    """A fully valid repository.  ``stage`` selects the root key generation."""
    threshold = 1 if stage == "old" else 2
    delegation = {
        "role": kl.ROLE_DELEGATION,
        "name": "control-only:delegated",
        "version": version,
        "expires": EXPIRES,
        "threshold": 1,
        "keys": [key(K_DELEGATION, kl.ROLE_DELEGATION)],
        "targets": ["control-only:delegated-target"],
    }
    kl._sign(delegation, [K_DELEGATION])

    targets = {
        "role": kl.ROLE_TARGETS,
        "version": version,
        "expires": EXPIRES,
        "threshold": 1,
        "keys": [key(K_TARGETS, kl.ROLE_TARGETS)],
        "delegations": [
            {"name": delegation["name"], "sha256": kl.metadata_digest(delegation)}
        ],
        "targets": ["control-only:file"],
    }
    kl._sign(targets, [K_TARGETS])

    snapshot = {
        "role": kl.ROLE_SNAPSHOT,
        "version": version,
        "expires": EXPIRES,
        "threshold": 1,
        "keys": [key(K_SNAPSHOT, kl.ROLE_SNAPSHOT)],
        "targets": {"version": version, "sha256": kl.metadata_digest(targets)},
    }
    kl._sign(snapshot, [K_SNAPSHOT])

    timestamp = {
        "role": kl.ROLE_TIMESTAMP,
        "version": version,
        "expires": EXPIRES,
        "threshold": 1,
        "keys": [key(K_TIMESTAMP, kl.ROLE_TIMESTAMP)],
        "issuedAt": issued_at,
        "snapshot": {"version": version, "sha256": kl.metadata_digest(snapshot)},
    }
    kl._sign(timestamp, [K_TIMESTAMP])

    root = {
        "role": kl.ROLE_ROOT,
        "version": version,
        "expires": EXPIRES,
        "threshold": threshold,
        "keys": _root_keys(stage),
    }
    kl._sign(root, _root_signers(stage))

    return {
        "schema": kl.REPOSITORY_SCHEMA,
        "metadata": {
            kl.ROLE_ROOT: root,
            kl.ROLE_TARGETS: targets,
            kl.ROLE_SNAPSHOT: snapshot,
            kl.ROLE_TIMESTAMP: timestamp,
        },
        "delegations": [delegation],
        "releases": [
            {
                "id": "control-only:release",
                "version": version,
                "time": issued_at,
                "keyid": K_TARGETS,
            }
        ],
        "maxTimestampInterval": INTERVAL,
    }


def _current_signers(record: Mapping[str, Any]) -> list[str]:
    return [entry["keyid"] for entry in record["signatures"]]


def rebuild_chain(repository: dict[str, Any]) -> dict[str, Any]:
    """Recompute the hash chain and re-sign each record with its current keys."""
    metadata = repository["metadata"]
    records = repository.get("delegations") or []
    by_name = {record["name"]: record for record in records}
    for record in records:
        kl._sign(record, _current_signers(record))
    for declaration in metadata[kl.ROLE_TARGETS].get("delegations") or []:
        record = by_name.get(declaration["name"])
        if record is not None:
            declaration["sha256"] = kl.metadata_digest(record)
    targets = metadata[kl.ROLE_TARGETS]
    kl._sign(targets, _current_signers(targets))
    snapshot = metadata[kl.ROLE_SNAPSHOT]
    snapshot["targets"] = {
        "version": targets["version"],
        "sha256": kl.metadata_digest(targets),
    }
    kl._sign(snapshot, _current_signers(snapshot))
    timestamp = metadata[kl.ROLE_TIMESTAMP]
    timestamp["snapshot"] = {
        "version": snapshot["version"],
        "sha256": kl.metadata_digest(snapshot),
    }
    kl._sign(timestamp, _current_signers(timestamp))
    root = metadata[kl.ROLE_ROOT]
    kl._sign(root, _current_signers(root))
    return repository


def reseal_from_targets(repository: dict[str, Any]) -> dict[str, Any]:
    """Update the snapshot and timestamp references after a targets mutation."""
    metadata = repository["metadata"]
    targets = metadata[kl.ROLE_TARGETS]
    snapshot = metadata[kl.ROLE_SNAPSHOT]
    snapshot["targets"] = {
        "version": targets["version"],
        "sha256": kl.metadata_digest(targets),
    }
    kl._sign(snapshot, _current_signers(snapshot))
    timestamp = metadata[kl.ROLE_TIMESTAMP]
    timestamp["snapshot"] = {
        "version": snapshot["version"],
        "sha256": kl.metadata_digest(snapshot),
    }
    kl._sign(timestamp, _current_signers(timestamp))
    return repository


# ---------------------------------------------------------------------------
# Controls
# ---------------------------------------------------------------------------


def _evaluate(repository: Any, previous: Any = None) -> dict[str, Any]:
    return kl.evaluate(repository, NOW, previous)


def _control(
    control_id: str,
    code: str,
    purpose: str,
    result: Mapping[str, Any],
) -> dict[str, Any]:
    observed = result.get("code")
    if result.get("outcome") != kl.OUTCOME_REFUSED or observed != code:
        raise SystemExit(
            f"control {control_id!r} expected REFUSED/{code} and observed "
            f"{result.get('outcome')}/{observed}"
        )
    return {
        "id": control_id,
        "code": code,
        "controlOnly": True,
        "prevents": kl.REFUSALS[code]["prevents"],
        "purpose": purpose,
        "observed": {
            "outcome": result["outcome"],
            "code": observed,
            "codes": list(result["codes"]),
        },
    }


def controls_document() -> dict[str, Any]:
    previous = healthy_repository(1, "old")
    healthy = healthy_repository(2, "rotate")
    controls: list[dict[str, Any]] = []

    # A malformed repository.
    malformed = copy.deepcopy(healthy)
    del malformed["metadata"][kl.ROLE_TIMESTAMP]
    controls.append(_control(
        "repository-invalid",
        kl.TK_REFUSED_REPOSITORY_INVALID,
        "a metadata set missing the timestamp is not a repository",
        _evaluate(malformed, previous),
    ))

    # Root rollback: an offered root that is not version-greater.
    previous_new = healthy_repository(2, "new")
    rolled_root = healthy_repository(2, "new")
    controls.append(_control(
        "root-rollback",
        kl.TK_REFUSED_ROOT_ROLLBACK,
        "a root at the accepted version is a rollback, not a rotation",
        _evaluate(rolled_root, previous_new),
    ))

    # Rotation signed only by the new root.
    unsigned = healthy_repository(2, "rotate")
    kl._sign(unsigned["metadata"][kl.ROLE_ROOT], [K_ROOT_NEW_A, K_ROOT_NEW_B])
    controls.append(_control(
        "rotation-unsigned-by-old",
        kl.TK_REFUSED_ROOT_ROTATION_UNSIGNED_BY_OLD,
        "a rotation signed by the new root alone is refused",
        _evaluate(unsigned, previous),
    ))

    # One rollback control per non-root role.
    rollback_previous = healthy_repository(2, "new")
    for role, code, control_id in (
        (kl.ROLE_TARGETS, kl.TK_REFUSED_TARGETS_ROLLBACK, "targets-rollback"),
        (kl.ROLE_SNAPSHOT, kl.TK_REFUSED_SNAPSHOT_ROLLBACK, "snapshot-rollback"),
        (kl.ROLE_TIMESTAMP, kl.TK_REFUSED_TIMESTAMP_ROLLBACK, "timestamp-rollback"),
    ):
        repository = healthy_repository(3, "new")
        repository["metadata"][role]["version"] = 1
        rebuild_chain(repository)
        controls.append(_control(
            control_id,
            code,
            f"a {role} version decrease is refused",
            _evaluate(repository, rollback_previous),
        ))

    # The snapshot names the wrong targets digest.
    targets_mismatch = healthy_repository(2, "rotate")
    snapshot = targets_mismatch["metadata"][kl.ROLE_SNAPSHOT]
    snapshot["targets"]["sha256"] = "0" * 64
    kl._sign(snapshot, _current_signers(snapshot))
    timestamp = targets_mismatch["metadata"][kl.ROLE_TIMESTAMP]
    timestamp["snapshot"] = {
        "version": snapshot["version"],
        "sha256": kl.metadata_digest(snapshot),
    }
    kl._sign(timestamp, _current_signers(timestamp))
    controls.append(_control(
        "targets-hash-mismatch",
        kl.TK_REFUSED_TARGETS_HASH_MISMATCH,
        "a snapshot that vouches for different targets is refused",
        _evaluate(targets_mismatch, previous),
    ))

    # The timestamp names the wrong snapshot digest.
    snapshot_mismatch = healthy_repository(2, "rotate")
    timestamp = snapshot_mismatch["metadata"][kl.ROLE_TIMESTAMP]
    timestamp["snapshot"]["sha256"] = "0" * 64
    kl._sign(timestamp, _current_signers(timestamp))
    controls.append(_control(
        "snapshot-hash-mismatch",
        kl.TK_REFUSED_SNAPSHOT_HASH_MISMATCH,
        "a timestamp that vouches for a different snapshot is refused",
        _evaluate(snapshot_mismatch, previous),
    ))

    # Expired timestamp metadata.
    expired = healthy_repository(2, "rotate")
    expired["metadata"][kl.ROLE_TIMESTAMP]["expires"] = "2026-11-23T00:00:00Z"
    rebuild_chain(expired)
    controls.append(_control(
        "expired-metadata",
        kl.TK_REFUSED_EXPIRED_METADATA,
        "an expired timestamp is refused even though it is version-correct",
        _evaluate(expired, previous),
    ))

    # A timestamp frozen past the declared interval.
    frozen = healthy_repository(2, "rotate", issued_at="2026-11-16T23:59:59Z")
    controls.append(_control(
        "freeze",
        kl.TK_REFUSED_FREEZE,
        "an unexpired timestamp not refreshed within the interval is a freeze",
        _evaluate(frozen, previous),
    ))

    # Key-level refusals: revoked, expired, not yet valid, unknown, wrong role.
    revoked = healthy_repository(2, "rotate")
    targets = revoked["metadata"][kl.ROLE_TARGETS]
    targets["keys"] = [key(K_TARGETS_REVOKED, kl.ROLE_TARGETS, revoked_at=REVOKED)]
    kl._sign(targets, [K_TARGETS_REVOKED])
    rebuild_chain(revoked)
    controls.append(_control(
        "key-revoked-verifying-signature",
        kl.TK_REFUSED_KEY_REVOKED,
        "a signature by a revoked key is refused although it verifies",
        _evaluate(revoked, previous),
    ))

    expired_key = healthy_repository(2, "rotate")
    targets = expired_key["metadata"][kl.ROLE_TARGETS]
    targets["keys"] = [
        key(K_TARGETS_EXPIRED, kl.ROLE_TARGETS, not_after="2026-06-01T00:00:00Z")
    ]
    kl._sign(targets, [K_TARGETS_EXPIRED])
    rebuild_chain(expired_key)
    controls.append(_control(
        "key-expired",
        kl.TK_REFUSED_KEY_EXPIRED,
        "an expired key is refused although its signature verifies",
        _evaluate(expired_key, previous),
    ))

    future_key = healthy_repository(2, "rotate")
    targets = future_key["metadata"][kl.ROLE_TARGETS]
    targets["keys"] = [
        key(
            K_TARGETS_FUTURE,
            kl.ROLE_TARGETS,
            not_before="2027-06-01T00:00:00Z",
            not_after="2028-01-01T00:00:00Z",
        )
    ]
    kl._sign(targets, [K_TARGETS_FUTURE])
    rebuild_chain(future_key)
    controls.append(_control(
        "key-not-yet-valid",
        kl.TK_REFUSED_KEY_NOT_YET_VALID,
        "a key outside its validity window is refused in both directions",
        _evaluate(future_key, previous),
    ))

    unknown = healthy_repository(2, "rotate")
    targets = unknown["metadata"][kl.ROLE_TARGETS]
    targets["signatures"] = [
        {"keyid": "control-only:not-a-key", "sig": "sha256:" + "0" * 64}
    ]
    rebuild_chain(unknown)
    controls.append(_control(
        "unknown-key",
        kl.TK_REFUSED_UNKNOWN_KEY,
        "a keyid no metadata declares is refused",
        _evaluate(unknown, previous),
    ))

    wrong_role = healthy_repository(2, "rotate")
    targets = wrong_role["metadata"][kl.ROLE_TARGETS]
    targets["keys"] = [key(K_WRONG_ROLE, kl.ROLE_TIMESTAMP)]
    kl._sign(targets, [K_WRONG_ROLE])
    rebuild_chain(wrong_role)
    controls.append(_control(
        "role-key-mismatch",
        kl.TK_REFUSED_ROLE_KEY_MISMATCH,
        "a key the root binds to another role cannot sign targets",
        _evaluate(wrong_role, previous),
    ))

    # A threshold of two met by one distinct key.
    threshold = healthy_repository(2, "rotate")
    threshold["metadata"][kl.ROLE_TARGETS]["threshold"] = 2
    rebuild_chain(threshold)
    controls.append(_control(
        "metadata-threshold",
        kl.TK_REFUSED_METADATA_THRESHOLD,
        "one distinct key cannot meet a threshold of two",
        _evaluate(threshold, previous),
    ))

    # Delegations.
    missing_delegation = healthy_repository(2, "rotate")
    missing_delegation["delegations"] = []
    controls.append(_control(
        "delegation-unknown",
        kl.TK_REFUSED_DELEGATION_UNKNOWN,
        "targets declares a delegation that no record supplies",
        _evaluate(missing_delegation, previous),
    ))

    expired_delegation = healthy_repository(2, "rotate")
    expired_delegation["delegations"][0]["expires"] = "2026-11-23T00:00:00Z"
    rebuild_chain(expired_delegation)
    controls.append(_control(
        "delegation-expired",
        kl.TK_REFUSED_DELEGATION_EXPIRED,
        "an expired delegation is refused although its hash binds",
        _evaluate(expired_delegation, previous),
    ))

    delegation_mismatch = healthy_repository(2, "rotate")
    targets = delegation_mismatch["metadata"][kl.ROLE_TARGETS]
    targets["delegations"][0]["sha256"] = "0" * 64
    kl._sign(targets, _current_signers(targets))
    reseal_from_targets(delegation_mismatch)
    controls.append(_control(
        "delegation-hash-mismatch",
        kl.TK_REFUSED_DELEGATION_HASH_MISMATCH,
        "a delegation record that disagrees with the parent's digest is refused",
        _evaluate(delegation_mismatch, previous),
    ))

    # Stale releases: behind the accepted version, and key revoked at release time.
    stale_previous = healthy_repository(2, "new")
    stale = healthy_repository(3, "new")
    stale["releases"][0]["version"] = 2
    controls.append(_control(
        "stale-release-version",
        kl.TK_REFUSED_STALE_RELEASE,
        "a release bound to an older metadata version is refused",
        _evaluate(stale, stale_previous),
    ))

    stale_key = healthy_repository(3, "new")
    stale_key["releases"][0]["keyid"] = K_RELEASE_REVOKED
    controls.append(_control(
        "stale-release-revoked-key",
        kl.TK_REFUSED_STALE_RELEASE,
        "a release signed by a key revoked before its recorded time is refused",
        _evaluate(stale_key, stale_previous),
    ))

    # A signature that is not over the record's bytes.
    tampered = healthy_repository(2, "rotate")
    tampered["metadata"][kl.ROLE_TARGETS]["signatures"][0]["sig"] = (
        "sha256:" + "0" * 64
    )
    controls.append(_control(
        "signature",
        kl.TK_REFUSED_SIGNATURE,
        "a signature over different bytes is refused",
        _evaluate(tampered, previous),
    ))

    positive = _evaluate(healthy, previous)
    if positive["outcome"] != kl.OUTCOME_ACCEPTED or positive["code"] != kl.CODE_OK:
        raise SystemExit(
            "the positive control did not reach ACCEPTED: "
            f"{positive.get('outcome')}/{positive.get('code')} "
            f"{positive.get('detail')}"
        )

    return {
        "schema": kl.CONTROLS_SCHEMA,
        "item": ITEM,
        "model": kl.MODEL_ID,
        "asOf": AS_OF,
        "now": NOW,
        "controlOnlyNote": (
            "Every repository below is a synthetic control-only fixture built in "
            "memory by this producer. A control that fires proves the refusal "
            "works; it is not a defect report and not evidence that the "
            "substituted form occurs in the tree."
        ),
        "controls": controls,
        "positive": {
            "id": "positive-accepted",
            "controlOnly": True,
            "purpose": (
                "a version-incremented, threshold-signed, unexpired repository "
                "with a hash-bound delegation reaches ACCEPTED"
            ),
            "observed": {
                "outcome": positive["outcome"],
                "code": positive["code"],
                "accepted": positive["accepted"],
            },
        },
        "coverage": {
            "refusalCodes": len(kl.CODE_ORDER),
            "controls": len(controls),
        },
        "sourceIdentity": source_identity(),
    }


# ---------------------------------------------------------------------------
# The three records
# ---------------------------------------------------------------------------


def inventory_document() -> dict[str, Any]:
    document = kl.real_inventory()
    document["sourceIdentity"] = source_identity()
    return document


def evaluation_document() -> dict[str, Any]:
    result = kl.evaluate(None, NOW, None)
    document = dict(result)
    document.update(
        {
            "item": ITEM,
            "asOf": AS_OF,
            "now": NOW,
            "repository": "evidence/a18/REPOSITORY.json",
            "repositoryPresent": False,
            "explanation": (
                "No repository exists, so every role and the stale-release "
                "check are NOT_RUN with TK_NOT_RUN. A repository that does not "
                "exist is never ACCEPTED, and NOT_RUN is not a pass."
            ),
            "sourceIdentity": source_identity(),
        }
    )
    return document


def build() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    return inventory_document(), evaluation_document(), controls_document()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", default=str(EVIDENCE))
    args = parser.parse_args(argv)

    output = Path(args.out)
    output.mkdir(parents=True, exist_ok=True)
    inventory, evaluation, controls = build()
    write_json(output / "INVENTORY.json", inventory)
    write_json(output / "EVALUATION.json", evaluation)
    write_json(output / "CONTROLS.json", controls)
    print(
        f"a18: keys={inventory['keyCount']} "
        f"repositories={inventory['repositories']} "
        f"outcome={evaluation['outcome']} code={evaluation['code']} "
        f"controls={len(controls['controls'])} "
        f"codes={controls['coverage']['refusalCodes']} "
        f"positive={controls['positive']['observed']['outcome']} "
        f"base={BASE_COMMIT_SHORT}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
