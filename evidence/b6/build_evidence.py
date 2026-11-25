#!/usr/bin/env python3
"""build_evidence.py -- the deterministic producer for B6 (archival and revocation).

The item's property is demonstrated, not asserted:

    a withdrawn claim is refused by current-state policy while its original
    inclusion proof remains valid.

The producer therefore builds four things and records each of them:

  1. ``FIXTURE-2``: a five-leaf RFC 6962 log carrying one real frozen A9
     statement and one *labelled fixture statement* whose subject is the A19
     claim ``ETP0-CLM-032/verdict``.  No A9 statement covers an A19 subject, so
     the statement is built over the withdrawn record's bytes and every record
     says that it is a fixture statement, not an A9 attestation.  The log is
     published with a leaf index, an inclusion proof and a checkpoint signed by
     A10's test-only HMAC key.

  2. ``ARCHIVE/``: the self-contained member set (statement, A9 statement,
     checkpoint, inclusion proof, leaf list, the two A19 events, both state
     versions, the publication record) plus ``ARCHIVE.json``, which records every
     member's digest and the reconstruction result obtained *from those bytes
     alone*.

  3. ``CURRENT-STATE.json``: the versioned index derived from
     ``evidence/a19/EVENTS.json`` through ``corrections.py``.  Version 21 still
     records the claim as ACTIVE (the retraction is not yet in the prefix);
     version 22 records it WITHDRAWN.

  4. ``DEMONSTRATION.json`` and ``CONTROLS.json``: the three facts in one record,
     the replayed-version refusals, and one control per refusal code with a
     restoration replay.

Two runs write the same bytes: canonical JSON with sorted keys, one-space indent
and a trailing newline; every field is derived from committed inputs or a fixed
seed.  No clock, environment, network or random source is read.

Usage:

    python3 evidence/b6/build_evidence.py [--check] [--out DIR]

``--check`` recomputes the records and the archive into a temporary directory and
compares them with the committed bytes instead of writing.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOLS = REPO_ROOT / "forensics" / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import archival  # noqa: E402
import corrections  # noqa: E402
import dsse  # noqa: E402
import tlog  # noqa: E402

EVIDENCE = REPO_ROOT / "evidence" / "b6"

BASE_COMMIT = "19b710192"
IDENTITY = "FIXTURE-2"
ORIGIN = IDENTITY
SIGNER_NAME = "FIXTURE-2 test-only hmac-sha256"
SEED = b"openssl-rs/b6/fixture-2/seed/v1"
SUBJECT = "ETP0-CLM-032/verdict"
STATEMENT_SUBJECT = "a19:" + SUBJECT
A19_ASSERTION = "A19-E21"
A19_RETRACTION = "A19-E22"

# The state that still records the claim as ACTIVE stops before the retraction.
EARLIER_UPTO = 21

REAL_STATEMENT_PATH = "evidence/a9/STATEMENTS/a8-shard-000.json"
SYNTHETIC_INDICES = (2, 3, 4)
TREE_SIZE = 2 + len(SYNTHETIC_INDICES)
CLAIM_INDEX = 1

LABELS = (
    IDENTITY,
    "test-only",
    "not-rekor-tiles",
    "no-log-key",
    "no-witness",
    "no-production-signature",
    "fixture-statement",
    "prose-only-withdrawal",
)


def _serialise(document: Any) -> bytes:
    return (
        json.dumps(document, indent=1, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")


def _write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    try:
        temporary.write_bytes(data)
        temporary.replace(path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _write_json(path: Path, document: Any) -> None:
    _write_bytes(path, _serialise(document))


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _synthetic_entry(index: int) -> bytes:
    """A deterministic, explicitly synthetic leaf derived from the fixed seed."""
    token = hashlib.sha256(SEED + b"/entry/" + str(index).encode("ascii")).hexdigest()
    document = {
        "fixture": IDENTITY,
        "index": index,
        "note": "test-only synthetic entry; not an ETP statement, not evidence",
        "seed": SEED.decode("ascii"),
        "token": token,
    }
    return corrections.canonical_bytes(document)


def _fixture_statement(
    assertion: Mapping[str, Any], retraction: Mapping[str, Any]
) -> dict[str, Any]:
    """The labelled fixture statement over the withdrawn A19 claim."""
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            {
                "name": STATEMENT_SUBJECT,
                "digest": {"sha256": corrections.event_digest(assertion)},
            }
        ],
        "predicateType": "https://openssl-rs.invalid/attestation/a19-subject/v1",
        "predicate": {
            "statementKind": "fixture-statement",
            "fixture": True,
            "notAnA9Statement": True,
            "why": (
                "no A9 statement covers an A19 correction subject, so this "
                "statement is built over the withdrawn record's bytes and is "
                "labelled a fixture statement; its predicate type is not in A9's "
                "registry"
            ),
            "record": {
                "path": "evidence/a19/EVENTS.json",
                "eventId": assertion["eventId"],
                "eventDigest": corrections.event_digest(assertion),
                "subject": assertion["subject"],
            },
            "retractedBy": {
                "eventId": retraction["eventId"],
                "digest": corrections.event_digest(retraction),
                "recordedAt": retraction["recordedAt"],
                "role": retraction["recordedBy"]["role"],
            },
        },
    }


def _build_fixture(
    repo_root: Path, assertion: Mapping[str, Any], retraction: Mapping[str, Any]
) -> dict[str, Any]:
    real = (repo_root / REAL_STATEMENT_PATH).read_bytes()
    statement_document = _fixture_statement(assertion, retraction)
    statement = corrections.canonical_bytes(statement_document)
    entries = [real, statement]
    entries.extend(_synthetic_entry(index) for index in SYNTHETIC_INDICES)
    leaf_hashes = [tlog.leaf_hash(entry) for entry in entries]
    root = tlog.root_from_leaf_hashes(leaf_hashes)
    proof = tlog.inclusion_path(leaf_hashes, CLAIM_INDEX, TREE_SIZE)
    text = tlog.checkpoint_text(ORIGIN, TREE_SIZE, root)
    signed = tlog.sign_checkpoint(text, SIGNER_NAME, dsse.test_only_key())
    return {
        "real": real,
        "statement": statement,
        "statementDocument": statement_document,
        "entries": entries,
        "leafHashes": leaf_hashes,
        "root": root,
        "proof": proof,
        "noteText": text,
        "signedNote": signed,
    }


def _leaf_rows(fixture: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows = []
    real_entry = fixture["entries"][0]
    rows.append(
        {
            "index": 0,
            "kind": "real-a9-statement",
            "path": REAL_STATEMENT_PATH,
            "bytes": len(real_entry),
            "sha256": _sha256(real_entry),
            "leafHash": tlog.leaf_hash(real_entry).hex(),
            "subjects": json.loads(real_entry.decode("utf-8")).get("subject", []),
        }
    )
    statement = fixture["statement"]
    rows.append(
        {
            "index": CLAIM_INDEX,
            "kind": "fixture-statement",
            "path": None,
            "bytes": len(statement),
            "sha256": _sha256(statement),
            "leafHash": tlog.leaf_hash(statement).hex(),
            "subjects": fixture["statementDocument"]["subject"],
        }
    )
    for index in SYNTHETIC_INDICES:
        entry = fixture["entries"][index]
        rows.append(
            {
                "index": index,
                "kind": "synthetic-test-only",
                "path": None,
                "bytes": len(entry),
                "sha256": _sha256(entry),
                "leafHash": tlog.leaf_hash(entry).hex(),
                "subjects": [],
            }
        )
    return rows


def _capture(
    call: Callable[[], Any],
    replacements: Sequence[tuple[Path, str]] = (),
) -> dict[str, Any]:
    """Run ``call`` and record the refusal code with paths normalised."""
    try:
        call()
    except archival.Refusal as refusal:
        message = refusal.message
        for actual, token in sorted(replacements, key=lambda row: -len(str(row[0]))):
            message = message.replace(str(actual), token)
        return {"code": refusal.code, "message": message}
    raise AssertionError("the control did not fire")


def _accepted(call: Callable[[], Any]) -> dict[str, Any]:
    try:
        result = call()
    except archival.Refusal as refusal:
        raise AssertionError(
            f"the restoration was refused {refusal.code}: {refusal.message}"
        ) from refusal
    return {"accepted": True, "result": result}


def _control(
    name: str,
    mutation: str,
    refusal: Mapping[str, Any],
    restoration: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "name": name,
        "controlOnly": True,
        "mutation": mutation,
        "code": refusal["code"],
        "message": refusal["message"],
        "fired": True,
        "restoration": restoration,
    }


def _redigest(document: dict[str, Any]) -> dict[str, Any]:
    document.pop("digest", None)
    document["digest"] = archival.state_digest(document)
    return document


def _run_controls(
    events: Mapping[str, Any],
    earlier: Mapping[str, Any],
    current_state: Mapping[str, Any],
    archive: Path,
    out_dir: Path,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    temporary_directories: list[Path] = []

    def copy_archive() -> Path:
        temporary = Path(tempfile.mkdtemp(prefix="b6-control-archive-"))
        temporary_directories.append(temporary)
        for path in archive.rglob("*"):
            if path.is_dir():
                continue
            target = temporary / path.relative_to(archive)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(path.read_bytes())
        return temporary

    # 1. One flipped byte in an archived member.
    tmp = copy_archive()
    proof_path = tmp / "members/log/inclusion-proof.json"
    proof_path.write_bytes(
        proof_path.read_bytes().replace(b'"leafIndex": 1', b'"leafIndex": 9', 1)
    )
    rows.append(
        _control(
            "reconstruction-flipped-byte",
            "one byte of the archived inclusion proof changed so its bytes differ "
            "from the recorded digest",
            _capture(
                lambda: archival.reconstruct(tmp),
                [(tmp, "<control-archive>"), (out_dir, "<out>")],
            ),
            _accepted(lambda: archival.reconstruct(archive)),
        )
    )

    # 2. A required member discarded.
    tmp = copy_archive()
    (tmp / "members/a19/binding.json").unlink()
    rows.append(
        _control(
            "archive-member-discarded",
            "the A19 binding member removed from the archive",
            _capture(
                lambda: archival.reconstruct(tmp),
                [(tmp, "<control-archive>"), (out_dir, "<out>")],
            ),
            _accepted(lambda: archival.reconstruct(archive)),
        )
    )

    # 3. A manifest whose digest does not cover its bytes.
    tmp = copy_archive()
    manifest_path = tmp / "MANIFEST.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["archiveId"] = "b6-archive-1-edited"
    manifest_path.write_text(
        json.dumps(manifest, indent=1, sort_keys=True) + "\n", encoding="utf-8"
    )
    rows.append(
        _control(
            "archive-manifest-unbound",
            "the manifest's archiveId edited without recomputing manifestDigest",
            _capture(
                lambda: archival.reconstruct(tmp),
                [(tmp, "<control-archive>"), (out_dir, "<out>")],
            ),
            _accepted(lambda: archival.reconstruct(archive)),
        )
    )

    # 4. The proof discarded: the inclusion claim is what is lost.
    tmp = copy_archive()
    (tmp / "members/log/inclusion-proof.json").unlink()
    rows.append(
        _control(
            "inclusion-proof-discarded",
            "the inclusion-proof member removed and the inclusion lookup re-run",
            _capture(
                lambda: archival.inclusion_lookup(tmp, SUBJECT),
                [(tmp, "<control-archive>"), (out_dir, "<out>")],
            ),
            _accepted(lambda: archival.inclusion_lookup(archive, SUBJECT)),
        )
    )

    # 5. A hand-edited state whose digest no longer covers it.
    tampered = copy.deepcopy(current_state)
    tampered["version"] = 23
    rows.append(
        _control(
            "state-not-covered-by-digest",
            "the state's version edited without recomputing its digest",
            _capture(lambda: archival.validate_state(tampered)),
            _accepted(lambda: archival.validate_state(current_state)),
        )
    )

    # 6. A withdrawal with nothing behind it.
    unbound = copy.deepcopy(current_state)
    for entry in unbound["subjects"]:
        if entry["subject"] == SUBJECT:
            entry["correctionDigest"] = None
    _redigest(unbound)
    rows.append(
        _control(
            "withdrawal-unbound",
            "the WITHDRAWN entry's correctionDigest removed and the digest recomputed",
            _capture(lambda: archival.validate_state(unbound, events)),
            _accepted(lambda: archival.validate_state(current_state, events)),
        )
    )

    # 7. The A19 retraction absent from the state.
    rows.append(
        _control(
            "correction-unpropagated",
            "the field's version-21 state checked against the full A19 log, whose "
            "version 22 retracts the claim",
            _capture(lambda: archival.check_propagation(earlier, events)),
            _accepted(lambda: archival.check_propagation(current_state, events)),
        )
    )

    # 8. The version walked backwards.
    rows.append(
        _control(
            "version-decreases",
            "the newer state (version 22) followed by the older (version 21)",
            _capture(lambda: archival.check_monotonic(current_state, earlier)),
            _accepted(lambda: archival.check_monotonic(earlier, current_state)),
        )
    )

    # 9. The older state replayed as current.
    rows.append(
        _control(
            "stale-state-as-current",
            "the version-21 state offered as the current state against version 22",
            _capture(lambda: archival.admit(earlier, current_state, log=events)),
            _accepted(lambda: archival.admit(current_state, current_state, log=events)),
        )
    )

    # 10. Two states at one version.
    conflicting = copy.deepcopy(current_state)
    conflicting["asOf"] = "2026-11-24T00:00:00Z"
    _redigest(conflicting)
    rows.append(
        _control(
            "same-version-conflict",
            "a second version-22 state with a different asOf, digest recomputed",
            _capture(lambda: archival.admit(conflicting, current_state, log=events)),
            _accepted(lambda: archival.admit(current_state, current_state, log=events)),
        )
    )

    # 11. Present-tense use of the withdrawn subject.
    rows.append(
        _control(
            "withdrawn-used-as-current",
            "the withdrawn subject used in the present tense at version 22",
            _capture(lambda: archival.present_tense(current_state, SUBJECT)),
            {
                "accepted": True,
                "scope": (
                    "the same subject is accepted in the present tense at version "
                    "21, which is exactly why RV_REFUSED_REPLAY_AS_CURRENT exists"
                ),
                "result": archival.present_tense(earlier, SUBJECT),
            },
        )
    )

    # 12. A subject the state does not index.
    rows.append(
        _control(
            "subject-not-indexed",
            "a present-tense use of a subject the state does not contain",
            _capture(
                lambda: archival.present_tense(current_state, "no/such/subject")
            ),
            {
                "accepted": False,
                "reason": (
                    "no state exists for an unknown subject; the restoration is the "
                    "control subject, which the index does contain"
                ),
                "result": archival.current(current_state, SUBJECT),
            },
        )
    )

    # 13. A derivation that covers no event.
    rows.append(
        _control(
            "derivation-out-of-range",
            "a state derived from 0 A19 events",
            _capture(lambda: archival.derive_state(events, upto=0)),
            _accepted(lambda: archival.derive_state(events)),
        )
    )

    # 14. A state file that cannot be read.
    missing_state = out_dir / "CONTROL-ONLY/absent-state.json"
    rows.append(
        _control(
            "state-unreadable",
            "a current-state path that holds no file",
            _capture(
                lambda: archival.load_state(missing_state), [(out_dir, "<out>")]
            ),
            _accepted(lambda: archival.load_state(out_dir / "CURRENT-STATE.json")),
        )
    )

    rows.append(
        {
            "name": "positive-control",
            "controlOnly": True,
            "mutation": "none: the produced archive, state and policy are checked",
            "code": archival.CODE_OK,
            "fired": True,
            "restoration": {
                "accepted": True,
                "reconstruction": archival.reconstruct(archive)["code"],
                "inclusion": archival.inclusion_lookup(archive, SUBJECT)["code"],
                "current": archival.current(current_state, SUBJECT)["state"],
            },
        }
    )
    for directory in temporary_directories:
        shutil.rmtree(directory, ignore_errors=True)
    return rows


def build(
    repo_root: Path | str = REPO_ROOT, out_dir: Path | str = EVIDENCE
) -> dict[str, Any]:
    """Write every B6 record and the archive under ``out_dir``."""
    repo = Path(repo_root)
    out = Path(out_dir)
    events = archival.load_events(repo / "evidence/a19/EVENTS.json")
    assignments = corrections.load_role_assignments(repo)
    by_id = {event["eventId"]: event for event in events["events"]}
    assertion = by_id[A19_ASSERTION]
    retraction = by_id[A19_RETRACTION]
    if assertion["subject"] != SUBJECT or retraction["subject"] != SUBJECT:
        raise AssertionError("the A19 events do not describe the selected subject")
    if retraction["kind"] != corrections.KIND_RETRACT:
        raise AssertionError("A19-E22 is not a retraction")

    earlier = archival.derive_state(
        events,
        upto=EARLIER_UPTO,
        assignments=assignments,
        repo_root=repo,
    )
    current_state = archival.derive_state(
        events,
        upto=len(events["events"]),
        previous=earlier,
        assignments=assignments,
        repo_root=repo,
    )
    if archival.current(earlier, SUBJECT)["state"] != archival.STATE_ACTIVE:
        raise AssertionError("the earlier state does not record the claim as ACTIVE")
    if archival.current(current_state, SUBJECT)["state"] != archival.STATE_WITHDRAWN:
        raise AssertionError("the current state does not record the claim as WITHDRAWN")

    fixture = _build_fixture(repo, assertion, retraction)

    proof_document = {
        "schema": archival.PROOF_SCHEMA,
        "subject": SUBJECT,
        "statementSubject": STATEMENT_SUBJECT,
        "leafIndex": CLAIM_INDEX,
        "treeSize": TREE_SIZE,
        "leafHash": tlog.leaf_hash(fixture["statement"]).hex(),
        "leafSha256": _sha256(fixture["statement"]),
        "rootHash": fixture["root"].hex(),
        "proof": [element.hex() for element in fixture["proof"]],
        "checkpointSha256": _sha256(fixture["signedNote"]),
    }
    leaf_list = {
        "schema": archival.LEAF_LIST_SCHEMA,
        "origin": ORIGIN,
        "treeSize": TREE_SIZE,
        "leaves": _leaf_rows(fixture),
    }
    publication = {
        "schema": "openssl-rs/b6/publication/1",
        "identity": IDENTITY,
        "origin": ORIGIN,
        "admittedService": False,
        "leafIndex": CLAIM_INDEX,
        "treeSize": TREE_SIZE,
        "rootHash": fixture["root"].hex(),
        "leafHash": tlog.leaf_hash(fixture["statement"]).hex(),
        "statementSha256": _sha256(fixture["statement"]),
        "signatureName": SIGNER_NAME,
        "signedNoteSha256": _sha256(fixture["signedNote"]),
        "notALogKey": True,
    }

    members: list[tuple[str, str, bytes, str]] = [
        (
            "statement-fixture",
            "members/statements/fixture-withdrawn-claim.json",
            fixture["statement"],
            "the labelled fixture statement over the withdrawn A19 claim; leaf 1",
        ),
        (
            "statement-a9",
            "members/statements/a9-a8-shard-000.json",
            fixture["real"],
            "the real frozen A9 statement used as leaf 0",
        ),
        (
            "checkpoint",
            "members/log/checkpoint.note",
            fixture["signedNote"],
            "the signed checkpoint for size 5, test-only HMAC key",
        ),
        (
            "inclusion-proof",
            "members/log/inclusion-proof.json",
            _serialise(proof_document),
            "the RFC 6962 inclusion proof for the claim's leaf",
        ),
        (
            "leaf-list",
            "members/log/leaf-list.json",
            _serialise(leaf_list),
            "every leaf's hash, so the root can be recomputed from the archive",
        ),
        (
            "publication",
            "members/log/publication.json",
            _serialise(publication),
            "the FIXTURE-2 publication record",
        ),
        (
            "a19-binding",
            "members/a19/binding.json",
            _serialise(
                {
                    "schema": archival.BINDING_SCHEMA,
                    "subject": SUBJECT,
                    "assertion": {
                        "eventId": assertion["eventId"],
                        "digest": corrections.event_digest(assertion),
                    },
                    "retraction": {
                        "eventId": retraction["eventId"],
                        "digest": corrections.event_digest(retraction),
                    },
                    "note": (
                        "A19 event identities by canonical digest; the event bytes "
                        "remain in evidence/a19/EVENTS.json and are not duplicated "
                        "here"
                    ),
                }
            ),
            "the A19 assertion and retraction event identities the claim binds",
        ),
        (
            "state-earlier",
            "members/state/current-state-21.json",
            _serialise(earlier),
            "the derived state at version 21, which still records the claim ACTIVE",
        ),
        (
            "state-current",
            "members/state/current-state-22.json",
            _serialise(current_state),
            "the derived state at version 22, which records the claim WITHDRAWN",
        ),
    ]
    manifest: dict[str, Any] = {
        "schema": archival.ARCHIVE_SCHEMA,
        "model": archival.MODEL_ID,
        "archiveId": "b6-archive-1",
        "identity": IDENTITY,
        "signer": {
            "name": SIGNER_NAME,
            "kind": "test-only-hmac-sha256",
            "notATrustRoot": True,
        },
        "labels": list(LABELS),
        "members": [
            {
                "id": member_id,
                "path": relative,
                "bytes": len(data),
                "sha256": _sha256(data),
                "role": role,
            }
            for member_id, relative, data, role in members
        ],
        "claims": [
            {
                "subject": SUBJECT,
                "statementSubject": STATEMENT_SUBJECT,
                "statementId": "statement-fixture",
                "leafIndex": CLAIM_INDEX,
            }
        ],
    }
    manifest["manifestDigest"] = archival.manifest_digest(manifest)

    archive_dir = out / "ARCHIVE"
    _write_json(archive_dir / "MANIFEST.json", manifest)
    for _member_id, relative, data, _role in members:
        _write_bytes(archive_dir / relative, data)

    reconstruction = archival.reconstruct(archive_dir)
    for member in manifest["members"]:
        if not (archive_dir / member["path"]).is_file():
            raise AssertionError(f"member {member['id']} was not written")

    archive_record = {
        "schema": archival.ARCHIVE_RECORD_SCHEMA,
        "model": archival.MODEL_ID,
        "item": "B6",
        "identity": IDENTITY,
        "baseCommit": BASE_COMMIT,
        "archiveId": manifest["archiveId"],
        "manifestPath": "ARCHIVE/MANIFEST.json",
        "manifestDigest": manifest["manifestDigest"],
        "members": manifest["members"],
        "claim": manifest["claims"][0],
        "states": {
            "earlier": {
                "version": earlier["version"],
                "asOf": earlier["asOf"],
                "digest": earlier["digest"],
                "member": "members/state/current-state-21.json",
            },
            "current": {
                "version": current_state["version"],
                "asOf": current_state["asOf"],
                "digest": current_state["digest"],
                "member": "members/state/current-state-22.json",
            },
        },
        "reconstruction": reconstruction,
        "labels": list(LABELS),
        "nonClaims": [
            "the archive is one copy, not an independent mirror of itself",
            "the checkpoint is signed by A10's test-only HMAC key, not a log key",
            "reconstruction establishes that the archived bytes verify; it does not "
            "establish that the archive is the only or the earliest copy",
            "the archive holds the leaf hashes of all five leaves but the payloads "
            "only of the two statements it reconstructs",
            "the A19 events are archived as event identities by digest, not as event "
            "bytes: re-deriving an event digest from its bytes needs "
            "evidence/a19/EVENTS.json",
        ],
    }

    inclusion = archival.inclusion_lookup(archive_dir, SUBJECT)
    present_tense = _capture(
        lambda: archival.present_tense(current_state, SUBJECT),
        [(out, "<out>")],
    )
    replay = _capture(lambda: archival.admit(earlier, current_state, log=events))
    rollback = _capture(lambda: archival.check_monotonic(current_state, earlier))

    withdrawn = archival.current(current_state, SUBJECT)
    demonstration = {
        "schema": "openssl-rs/b6/demonstration/1",
        "model": archival.MODEL_ID,
        "identity": IDENTITY,
        "baseCommit": BASE_COMMIT,
        "subject": SUBJECT,
        "claim": {
            "a19Subject": SUBJECT,
            "assertedBy": A19_ASSERTION,
            "withdrawnBy": A19_RETRACTION,
            "statementSubject": STATEMENT_SUBJECT,
            "leafIndex": CLAIM_INDEX,
        },
        "facts": {
            "inclusionStillValid": {
                "code": inclusion["code"],
                "leafIndex": inclusion["leafIndex"],
                "treeSize": inclusion["treeSize"],
                "leafHash": inclusion["leafHash"],
                "root": inclusion["root"],
                "proofElements": len(fixture["proof"]),
                "checkpointSize": inclusion["checkpointSize"],
                "signatureName": inclusion["signatureName"],
                "record": "ARCHIVE.json#/reconstruction",
            },
            "currentIsWithdrawn": {
                "code": archival.CODE_OK,
                "version": current_state["version"],
                "state": withdrawn["state"],
                "supersededBy": withdrawn["supersededBy"],
                "correctionDigest": withdrawn["correctionDigest"],
                "asOf": current_state["asOf"],
                "record": "CURRENT-STATE.json",
            },
            "presentTenseRefused": {
                "code": present_tense["code"],
                "message": present_tense["message"],
                "record": (
                    "CURRENT-STATE.json#/subjects[ETP0-CLM-032/verdict]"
                ),
            },
        },
        "replay": {
            "earlierVersion": {
                "version": earlier["version"],
                "state": archival.current(earlier, SUBJECT)["state"],
                "digest": earlier["digest"],
                "member": "members/state/current-state-21.json",
            },
            "replayedAsCurrent": replay,
            "versionDecrease": rollback,
            "why": (
                "the older state still records the claim ACTIVE; admitting it would "
                "resurrect a withdrawn claim, so both the current-state admission "
                "(REPLAY_AS_CURRENT) and the version sequence (ROLLBACK_OF_STATE) "
                "refuse it"
            ),
        },
        "sequence": [
            "FIXTURE-2 publishes leaf 1 and the size-5 checkpoint",
            "the inclusion lookup verifies the proof from the archive",
            "the state advances from version 21 (ACTIVE) to version 22 (WITHDRAWN)",
            "current(subject) reports WITHDRAWN",
            "a present-tense use is refused",
            "the version-21 state replayed as current is refused",
        ],
        "labels": list(LABELS),
        "nonClaims": [
            "FIXTURE-2 is a fixture log, not an admitted log and not a Rekor publication",
            "the withdrawal is an A19 prose-only event, not an authenticated correction",
            "inclusion in FIXTURE-2 does not establish inclusion in any public log",
            "a withdrawal does not make the original untrue; it makes it not current",
        ],
    }

    # The state is written before the controls run: one control reads the
    # committed state path, so it must exist when the control reaches it.
    _write_json(out / "CURRENT-STATE.json", current_state)
    controls = _run_controls(events, earlier, current_state, archive_dir, out)

    fixture_record = {
        "schema": "openssl-rs/b6/fixture/1",
        "model": archival.MODEL_ID,
        "identity": IDENTITY,
        "item": "B6",
        "baseCommit": BASE_COMMIT,
        "admittedService": False,
        "labels": list(LABELS),
        "construction": {
            "clause": "RFC 6962 §2.1; docs/ETP-ADDENDUM-B.md §B.3.2",
            "hash": "sha256",
            "leafHash": "SHA-256(0x00 || leaf)",
            "nodeHash": "SHA-256(0x01 || left || right)",
            "treeSize": TREE_SIZE,
            "emptyRoot": tlog.empty_tree_root().hex(),
        },
        "leaves": _leaf_rows(fixture),
        "publication": {
            "leafIndex": CLAIM_INDEX,
            "treeSize": TREE_SIZE,
            "rootHash": fixture["root"].hex(),
            "leafHash": tlog.leaf_hash(fixture["statement"]).hex(),
            "statementSha256": _sha256(fixture["statement"]),
            "inclusionProof": [element.hex() for element in fixture["proof"]],
            "checkpoint": {
                "noteText": fixture["noteText"].decode("utf-8"),
                "noteTextSha256": _sha256(fixture["noteText"]),
                "signedNote": fixture["signedNote"].decode("utf-8"),
                "signedNoteSha256": _sha256(fixture["signedNote"]),
                "signatureName": SIGNER_NAME,
                "keyHash": tlog.note_key_hash(SIGNER_NAME).hex()[:8],
                "testOnly": True,
                "notALogKey": True,
            },
            "archiveMember": "members/log/checkpoint.note",
        },
        "subject": {
            "a19Subject": SUBJECT,
            "statementSubject": STATEMENT_SUBJECT,
            "isA9Statement": False,
            "fixtureStatement": True,
            "why": (
                "A9's four statements cover A1, A5, A7 and A8 artefacts; none covers "
                "an A19 correction subject, so the statement is built over the "
                "withdrawn record's bytes and labelled a fixture statement"
            ),
        },
        "nonClaims": [
            "FIXTURE-2 is a fixture, not an admitted log",
            "the checkpoint is signed by A10's test-only HMAC key, not a log key",
            "no Rekor entry, hashedrekord submission or integrated time exists",
            "no witness cosignature exists",
            "the fixture statement is not an in-toto attestation registered by A9",
        ],
    }

    _write_json(out / "ARCHIVE.json", archive_record)
    _write_json(out / "DEMONSTRATION.json", demonstration)
    _write_json(out / "CONTROLS.json", {"controls": controls})
    _write_json(out / "FIXTURE-2.json", fixture_record)

    return {
        "version": current_state["version"],
        "earlier": earlier["version"],
        "state": withdrawn["state"],
        "leafIndex": CLAIM_INDEX,
        "root": fixture["root"].hex(),
        "members": len(manifest["members"]),
        "checks": len(reconstruction["checks"]),
        "controls": len(controls),
        "codes": sorted({row["code"] for row in controls}),
        "manifestDigest": manifest["manifestDigest"],
    }


def _committed(directory: Path) -> dict[str, bytes]:
    return {
        str(path.relative_to(directory)): path.read_bytes()
        for path in sorted(directory.rglob("*"))
        if path.is_file() and path.suffix != ".tmp"
    }


GENERATED = (
    "ARCHIVE.json",
    "CURRENT-STATE.json",
    "DEMONSTRATION.json",
    "CONTROLS.json",
    "FIXTURE-2.json",
)


def check() -> int:
    with tempfile.TemporaryDirectory(prefix="b6-check-") as temporary:
        produced_dir = Path(temporary) / "b6"
        summary = build(REPO_ROOT, produced_dir)
        produced = _committed(produced_dir)
        # Only the bytes this producer writes are compared.  ``build_evidence.py``
        # and ``RECEIPT.md`` live beside them and are not its output.
        committed = {
            name: data
            for name, data in _committed(EVIDENCE).items()
            if name in produced or name in GENERATED or name.startswith("ARCHIVE/")
        }
        problems = []
        for name in sorted(set(produced) | set(committed)):
            if name not in produced:
                problems.append(f"missing from the rebuild: {name}")
            elif name not in committed:
                problems.append(f"not committed: {name}")
            elif produced[name] != committed[name]:
                problems.append(f"differs: {name}")
        if problems:
            for problem in problems:
                print(f"code=RV_REFUSED_RECONSTRUCTION_MISMATCH b6: {problem}")
            return 1
        print(
            "code=RV_OK b6: check ok files="
            f"{len(produced)} version={summary['version']} "
            f"root={summary['root']} manifest={summary['manifestDigest']}"
        )
        return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--out", default=str(EVIDENCE))
    arguments = parser.parse_args(argv)
    if arguments.check:
        return check()
    summary = build(REPO_ROOT, Path(arguments.out))
    print(
        "code=RV_OK b6: "
        f"version={summary['version']} earlier={summary['earlier']} "
        f"state={summary['state']} leafIndex={summary['leafIndex']} "
        f"root={summary['root']}"
    )
    print(
        "code=RV_OK b6: "
        f"members={summary['members']} checks={summary['checks']} "
        f"controls={summary['controls']} codes={','.join(summary['codes'])} "
        f"manifest={summary['manifestDigest']}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
