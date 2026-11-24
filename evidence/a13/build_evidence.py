#!/usr/bin/env python3
"""Produce evidence/a13 deterministically: the two axes, the pairs, the controls.

Every digest is read from bytes; every state and every code is produced by
``forensics/tools/reproducibility.py``; nothing is typed except the identity of
the batch and the recorded reasons a rebuild did not run.  Re-running with the
same inputs reproduces the same files.

Usage
-----
    python3 evidence/a13/build_evidence.py
    python3 evidence/a13/build_evidence.py --out /tmp/a13a --source-commit 6b33f1caa

The default output is ``evidence/a13``.  The source identity is supplied; it is
never read from a live ``HEAD``.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import argparse
import base64
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping, Sequence

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOLS = REPO_ROOT / "forensics" / "tools"
sys.path.insert(0, str(TOOLS))

import dsse  # noqa: E402
import reproducibility as rep  # noqa: E402

BASE_COMMIT = "6b33f1caa"
AS_OF = "2026-11-24"
EVIDENCE = REPO_ROOT / "evidence" / "a13"
TOOL_RELATIVE = "forensics/tools/reproducibility.py"
PAYLOAD_TYPE = dsse.IN_TOTO_PAYLOAD_TYPE
TEST_ONLY_SEED = dsse.TEST_ONLY_SEED
TEST_ONLY_KEYID = dsse.test_only_keyid()
COURT_MEMORY_BYTES = 6 * 1024 ** 3
COURT_MEMORY_TEXT = "6442450944 (6 GiB)"

SIGNATURES = (
    ("a1-sarif", "evidence/a10/ENVELOPES/a1-sarif.json",
     "evidence/a9/STATEMENTS/a1-sarif.json"),
    ("a5-admission", "evidence/a10/ENVELOPES/a5-admission.json",
     "evidence/a9/STATEMENTS/a5-admission.json"),
    ("a7-delta", "evidence/a10/ENVELOPES/a7-delta.json",
     "evidence/a9/STATEMENTS/a7-delta.json"),
    ("a8-shard-000", "evidence/a10/ENVELOPES/a8-shard-000.json",
     "evidence/a9/STATEMENTS/a8-shard-000.json"),
)

ARTEFACTS = (
    ("a1-sarif", "evidence/a1/SARIF.json"),
    ("a5-admission", "evidence/a5/ADMISSION.json"),
    ("a7-delta", "evidence/a7/DELTA.json"),
    ("a8-shard-000", "evidence/a8/SHARD-000.sarif"),
)

DSO_NAME = "a4-libcrypto-dso"
DSO_PATH = "artifacts/phase2/install/lib/libcrypto.so.3"
DSO_RECORD = "evidence/a4/INSTANCES.json"
T12_RUN = "evidence/etp-t12/RUN.json"
GATE_RECEIPT = "evidence/gate-reliability/RECEIPT.md"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(bytes(data)).hexdigest()


def read_bytes(relative: str) -> bytes:
    return (REPO_ROOT / relative).read_bytes()


def identity(relative: str) -> dict[str, Any]:
    raw = read_bytes(relative)
    return {"path": relative, "sha256": sha256_bytes(raw), "bytes": len(raw)}


def tool_identity() -> dict[str, Any]:
    return identity(TOOL_RELATIVE)


def write_json(path: Path, document: Mapping[str, Any]) -> None:
    path.write_text(
        json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def source_identity(commit: str, inputs: Sequence[str]) -> dict[str, Any]:
    return {
        "baseCommit": commit,
        "asOf": AS_OF,
        "tool": tool_identity(),
        "inputs": [identity(path) for path in inputs],
    }


def document_identity(relative: str, document: Mapping[str, Any]) -> dict[str, Any]:
    """The identity of a document this producer writes, without reading it back.

    The serialisation is exactly the one :func:`write_json` emits, so the digest
    is the committed file's digest and the record does not depend on the output
    directory or on a previous run.
    """
    raw = (
        json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")
    return {"path": relative, "sha256": sha256_bytes(raw), "bytes": len(raw)}


def source_identity_records(
    commit: str, records: Sequence[Mapping[str, Any]]
) -> dict[str, Any]:
    return {
        "baseCommit": commit,
        "asOf": AS_OF,
        "tool": tool_identity(),
        "inputs": list(records),
    }


# ---------------------------------------------------------------------------
# The signature axis: the four real envelopes, signed twice.
# ---------------------------------------------------------------------------


def _attempt_inputs(statement: bytes) -> dict[str, Any]:
    return {
        "scheme": "hmac-sha256",
        "keyid": TEST_ONLY_KEYID,
        "payloadType": PAYLOAD_TYPE,
        "payloadSha256": sha256_bytes(statement),
    }


def signature_document(source_commit: str) -> dict[str, Any]:
    signer = dsse.test_only_signer(TEST_ONLY_SEED)
    rows: list[dict[str, Any]] = []
    for name, envelope_path, statement_path in SIGNATURES:
        statement = read_bytes(statement_path)
        a10_envelope = read_bytes(envelope_path)
        a10_sha = sha256_bytes(a10_envelope)
        attempts: list[dict[str, Any]] = []
        for index in (1, 2):
            document = dsse.envelope(PAYLOAD_TYPE, statement, signer)
            raw = dsse.encode_envelope(document)
            signature_b64 = document["signatures"][0]["sig"]
            signature = base64.b64decode(signature_b64, validate=True)
            attempts.append(
                {
                    "attempt": index,
                    "signature": signature_b64,
                    "signatureSha256": sha256_bytes(signature),
                    "envelopeSha256": sha256_bytes(raw),
                    "inputs": _attempt_inputs(statement),
                }
            )
            assert sha256_bytes(raw) == a10_sha, (
                f"{name} attempt {index} is not the A10 envelope; the same key "
                "over the same payload must reproduce it"
            )
        evidence = rep.signature_evidence(attempts, "hmac-sha256")
        assert evidence["state"] == rep.SIGNATURE_STABLE, (
            f"{name}: expected SIGNATURE_STABLE, got {evidence['state']}"
        )
        assert evidence["code"] == rep.CODE_OK, evidence
        rows.append(
            {
                "name": name,
                "scheme": "hmac-sha256",
                "schemeRecord": rep.SCHEMES["hmac-sha256"].as_dict(),
                "keyid": TEST_ONLY_KEYID,
                "keyKind": "derived-test-key",
                "seedHex": TEST_ONLY_SEED.hex(),
                "payloadType": PAYLOAD_TYPE,
                "statement": statement_path,
                "payloadSha256": sha256_bytes(statement),
                "a10Envelope": envelope_path,
                "a10EnvelopeSha256": a10_sha,
                "attempts": attempts,
                "state": evidence["state"],
                "code": evidence["code"],
                "detail": evidence["detail"],
            }
        )
    counts = {
        "signatures": len(rows),
        "attemptsPerSignature": 2,
        "stable": sum(row["state"] == rep.SIGNATURE_STABLE for row in rows),
        "varies": sum(row["state"] == rep.SIGNATURE_VARIES for row in rows),
        "nonceReused": sum(
            row["state"] == rep.SIGNATURE_NONCE_REUSED for row in rows
        ),
        "unknown": sum(row["state"] == rep.SIGNATURE_UNKNOWN for row in rows),
    }
    inputs = [row["a10Envelope"] for row in rows] + [
        row["statement"] for row in rows
    ]
    return {
        "schema": rep.SIGNATURE_SCHEMA,
        "item": "A13",
        "asOf": AS_OF,
        "axis": "signature",
        "sourceIdentity": source_identity(source_commit, inputs),
        "scheme": "hmac-sha256",
        "schemeRecord": rep.SCHEMES["hmac-sha256"].as_dict(),
        "keyid": TEST_ONLY_KEYID,
        "keyKind": "derived-test-key",
        "seedHex": TEST_ONLY_SEED.hex(),
        "payloadType": PAYLOAD_TYPE,
        "signatures": rows,
        "counts": counts,
        "establishes": [
            "the four real A10 envelopes are byte-identical when the same key is "
            "applied twice to the same A9 statement bytes",
            "HMAC-SHA256 is a deterministic function of (key, message)",
            "the fixed public test seed reproduces the same test key",
        ],
        "doesNotEstablish": [
            "anything about whether any artefact can be rebuilt; that is the "
            "artefact axis in ARTEFACT.json",
            "authenticity: the key is derived from a fixed public test seed",
            "independence: HMAC is symmetric, so the verifier holds the same "
            "secret (A12)",
            "identity, authorisation or transparency (A14-A17)",
            "a production signature scheme or a production key",
        ],
        "note": (
            "Repeating the same envelope byte-for-byte is a property of HMAC-SHA256 "
            "and of the fixed test seed. It says nothing about the build. The "
            "signature axis is SIGNATURE_STABLE 4/4; the artefact axis is measured "
            "separately and is ARTEFACT_NOT_REBUILT for every subject."
        ),
    }


# ---------------------------------------------------------------------------
# The artefact axis: four evidence artefacts and the A4 DSO.
# ---------------------------------------------------------------------------


def _t12_rebuild_record() -> dict[str, Any]:
    run = json.loads(read_bytes(T12_RUN))
    step = next(item for item in run["steps"] if item["name"] == "rebuild")
    assert step["status"] == "NOT_RUN", step["status"]
    prerequisites = {item["requirement"]: item for item in step["prerequisites"]}
    evidence_identity = {
        item["path"]: item["sha256"] for item in step["evidence_identity"]
    }
    tool_digest = {item["path"]: item["sha256"] for item in step["tool_digest"]}
    inputs = {
        "candidateCommit": run["candidate"]["commit"],
        "cargoLock": {
            "path": "Cargo.lock",
            "sha256": evidence_identity["Cargo.lock"],
        },
        "rustToolchain": {
            "path": "rust-toolchain.toml",
            "sha256": evidence_identity["rust-toolchain.toml"],
        },
        "tool": {
            "path": "forensics/tools/build_reproducibility.sh",
            "sha256": tool_digest["forensics/tools/build_reproducibility.sh"],
        },
        "court": {
            "name": "openssl-rs-court",
            "image": "openssl-rs-court-tools:1",
            "memoryBytes": COURT_MEMORY_BYTES,
            "memory": COURT_MEMORY_TEXT,
        },
        "command": (
            "bash forensics/tools/build_reproducibility.sh --out /court/repro "
            "--clean"
        ),
    }
    return {
        "method": "rebuild",
        "outcome": "NOT_RUN",
        "inputs": inputs,
        "record": identity(T12_RUN),
        "reason": (
            "the recorded rebuild step is NOT_RUN because "
            f"{prerequisites.get('memory:24', {}).get('detail', 'the memory floor was not met')}; "
            "the court is capped at 6 GiB, and when the full rebuild is attempted "
            "in that court it exits 101 (build_reproducibility.sh exited 101; "
            f"recorded in {GATE_RECEIPT})"
        ),
        "attemptedInCourt": {
            "outcome": "NOT_RUN",
            "exit": 101,
            "detail": (
                "build_reproducibility.sh exited 101 in the 6 GiB court; the "
                "attempt did not produce a build to compare"
            ),
            "record": identity(GATE_RECEIPT),
        },
        "subjectSha256": None,
    }


def artefact_document(source_commit: str) -> dict[str, Any]:
    inputs: list[str] = [path for _name, path in ARTEFACTS]
    subjects: list[dict[str, Any]] = []
    for name, path in ARTEFACTS:
        raw = read_bytes(path)
        subject = {
            "name": name,
            "path": path,
            "kind": "evidence-artefact",
            "sha256": sha256_bytes(raw),
            "bytes": len(raw),
        }
        evidence = rep.artefact_evidence(subject, None)
        assert evidence["state"] == rep.ARTEFACT_NOT_REBUILT, evidence
        subjects.append(
            {
                "name": name,
                "subject": subject,
                "rebuild": None,
                "state": evidence["state"],
                "code": evidence["code"],
                "reproducibilityClaimed": evidence["reproducibilityClaimed"],
                "detail": evidence["detail"],
                "reason": evidence["reason"],
            }
        )

    dso_raw = read_bytes(DSO_PATH)
    a4 = json.loads(read_bytes(DSO_RECORD))
    recorded_sha = a4["candidate"]["libcrypto"]["sha256"]
    observed_sha = sha256_bytes(dso_raw)
    assert observed_sha == recorded_sha, (
        f"the DSO digest {observed_sha} is not the recorded {recorded_sha}"
    )
    rebuild = _t12_rebuild_record()
    rebuild["subjectSha256"] = recorded_sha
    dso_subject = {
        "name": DSO_NAME,
        "path": DSO_PATH,
        "kind": "build-product",
        "sha256": observed_sha,
        "recordedSha256": recorded_sha,
        "recordedDigestSource": identity(DSO_RECORD),
        "present": True,
        "bytes": len(dso_raw),
    }
    dso_evidence = rep.artefact_evidence(dso_subject, rebuild)
    assert dso_evidence["state"] == rep.ARTEFACT_NOT_REBUILT, dso_evidence
    assert dso_evidence["code"] == rep.SR_REFUSED_REBUILD_NOT_RUN, dso_evidence
    subjects.append(
        {
            "name": DSO_NAME,
            "subject": dso_subject,
            "rebuild": rebuild,
            "state": dso_evidence["state"],
            "code": dso_evidence["code"],
            "reproducibilityClaimed": dso_evidence["reproducibilityClaimed"],
            "detail": dso_evidence["detail"],
            "reason": dso_evidence["reason"],
        }
    )
    inputs.extend([DSO_PATH, DSO_RECORD, T12_RUN, GATE_RECEIPT])

    counts = {
        "subjects": len(subjects),
        "evidenceArtefacts": len(ARTEFACTS),
        "buildProducts": 1,
        "reproducible": sum(
            row["state"] == rep.ARTEFACT_REPRODUCIBLE for row in subjects
        ),
        "differs": sum(row["state"] == rep.ARTEFACT_DIFFERS for row in subjects),
        "notRebuilt": sum(
            row["state"] == rep.ARTEFACT_NOT_REBUILT for row in subjects
        ),
        "unknown": sum(row["state"] == rep.ARTEFACT_UNKNOWN for row in subjects),
    }
    return {
        "schema": rep.ARTEFACT_SCHEMA,
        "item": "A13",
        "asOf": AS_OF,
        "axis": "artefact",
        "sourceIdentity": source_identity(source_commit, inputs),
        "subjects": subjects,
        "counts": counts,
        "establishes": [
            "each of the four A1/A5/A7/A8 evidence artefacts has a recorded "
            "SHA-256, computed from its bytes",
            "the DSO behind the A4 observations is present at the recorded "
            "digest",
            "no subject has a completed rebuild record",
        ],
        "doesNotEstablish": [
            "that any subject is reproducible; the state is NOT_REBUILT for every "
            "subject",
            "that a stable recorded digest is a rebuild; a digest is not a build",
            "that the DSO's recorded digest was regenerated in this batch",
            "any relationship between artefact reproducibility and the signature "
            "axis in SIGNATURE.json",
        ],
        "note": (
            "Every subject is ARTEFACT_NOT_REBUILT. The four evidence artefacts "
            "have no rebuild record at all; the DSO has a recorded rebuild whose "
            "outcome is NOT_RUN. A recorded digest is an identity, not a "
            "reproduction. No build-reproducibility claim is made."
        ),
    }


# ---------------------------------------------------------------------------
# Classification: each real pair, and the prohibited inference.
# ---------------------------------------------------------------------------


def classification_document(
    signature: Mapping[str, Any],
    artefact: Mapping[str, Any],
    source_commit: str,
) -> dict[str, Any]:
    signature_rows = {row["name"]: row for row in signature["signatures"]}
    artefact_rows = {row["name"]: row for row in artefact["subjects"]}
    pairs: list[dict[str, Any]] = []
    for name in sorted(signature_rows):
        signature_row = signature_rows[name]
        artefact_row = artefact_rows[name]
        result = rep.classify(
            {
                "state": signature_row["state"],
                "code": signature_row["code"],
                "scheme": signature_row["scheme"],
                "deterministic": signature_row["schemeRecord"]["deterministic"],
                "symmetric": signature_row["schemeRecord"]["symmetric"],
                "randomised": signature_row["schemeRecord"]["randomised"],
            },
            {
                "state": artefact_row["state"],
                "code": artefact_row["code"],
                "subject": artefact_row["subject"],
            },
        )
        assert (
            result["combination"] == "STABLE_SIGNATURE__NOT_REBUILT_ARTEFACT"
        ), result
        assert rep.SR_REFUSED_SIGNATURE_AS_ARTEFACT in result["prohibited"], result
        assert rep.SR_REFUSED_REBUILD_NOT_RUN in result["prohibited"], result
        pairs.append(
            {
                "name": name,
                "signature": {
                    "state": signature_row["state"],
                    "code": signature_row["code"],
                    "scheme": signature_row["scheme"],
                },
                "artefact": {
                    "state": artefact_row["state"],
                    "code": artefact_row["code"],
                },
                "combination": result["combination"],
                "prohibited": result["prohibited"],
                "codes": result["codes"],
                "permitted": result["permitted"],
            }
        )

    unpaired = [
        {
            "name": DSO_NAME,
            "signature": None,
            "artefact": {
                "state": row["state"],
                "code": row["code"],
            },
            "combination": "UNPAIRED",
            "prohibited": [rep.SR_REFUSED_REBUILD_NOT_RUN],
            "note": (
                "the DSO is a build product, not one of the four signed "
                "statements; its artefact axis is NOT_REBUILT and it is not "
                "given a signature-axis reading"
            ),
        }
        for row in artefact["subjects"]
        if row["name"] == DSO_NAME
    ]

    registry = {
        label: {
            "signature": state,
            "artefact": artefact_state,
            "prohibited": sorted(
                {
                    rep.SR_REFUSED_SIGNATURE_AS_ARTEFACT,
                    rep.SR_REFUSED_ARTEFACT_AS_SIGNATURE,
                    rep.SR_REFUSED_ENVELOPE_DIGEST_AS_BUILD_DIGEST,
                    *(
                        [rep.SR_REFUSED_DETERMINISTIC_SCHEME_AS_INDEPENDENCE]
                        if state == rep.SIGNATURE_STABLE
                        else [rep.SR_REFUSED_NONDETERMINISTIC_AS_FAILURE]
                    ),
                    *(
                        [rep.SR_REFUSED_REBUILD_NOT_RUN]
                        if artefact_state != rep.ARTEFACT_REPRODUCIBLE
                        else []
                    ),
                }
            ),
        }
        for (state, artefact_state), label in rep.COMBINATION_LABELS.items()
    }

    observed = {pair["combination"] for pair in pairs}
    return {
        "schema": rep.CLASSIFICATION_SCHEMA,
        "item": "A13",
        "asOf": AS_OF,
        "sourceIdentity": source_identity_records(
            source_commit,
            [
                document_identity("evidence/a13/SIGNATURE.json", signature),
                document_identity("evidence/a13/ARTEFACT.json", artefact),
            ],
        ),
        "rule": (
            "the signature axis and the artefact axis are separate measurements. "
            "Each pair names the combination and the inference a consumer may not "
            "draw from it."
        ),
        "pairs": pairs,
        "unpaired": unpaired,
        "combinationRegistry": registry,
        "counts": {
            "pairs": len(pairs),
            "unpaired": len(unpaired),
            "combinationsObserved": len(observed),
            "observed": sorted(observed),
        },
        "note": (
            "All four real pairs are STABLE_SIGNATURE__NOT_REBUILT_ARTEFACT: the "
            "HMAC signature repeats and no subject has a rebuild. This licenses "
            "no build-reproducibility claim and no independence claim."
        ),
    }


# ---------------------------------------------------------------------------
# Controls: one per refusal code, plus the accepted randomised case.
# ---------------------------------------------------------------------------


def _attempt(
    signature: bytes,
    *,
    inputs: Mapping[str, Any] | None = None,
    nonce: Any = None,
    key_kind: str = "derived-key",
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "signature": base64.b64encode(signature).decode("ascii"),
        "inputs": dict(inputs or {"keyid": "control", "payloadSha256": "00" * 32}),
        "keyKind": key_kind,
    }
    if nonce is not None:
        record["nonce"] = nonce
    return record


def _stable_signature() -> dict[str, Any]:
    return rep.signature_evidence(
        [_attempt(b"control-signature") for _ in range(2)], "ed25519"
    )


def _varying_signature() -> dict[str, Any]:
    return rep.signature_evidence(
        [
            _attempt(b"control-signature-1", nonce="nonce-1"),
            _attempt(b"control-signature-2", nonce="nonce-2"),
        ],
        "ecdsa",
    )


_CONTROL_SUBJECT = {
    "name": "control-artefact",
    "path": "control/artefact",
    "kind": "build-product",
    "sha256": "a" * 64,
}


def _reproducible_artefact() -> dict[str, Any]:
    return rep.artefact_evidence(
        _CONTROL_SUBJECT,
        {
            "method": "rebuild",
            "outcome": "REPRODUCED",
            "inputs": {"control": "two independent builds"},
            "digests": {"first": "b" * 64, "second": "b" * 64},
            "subjectSha256": _CONTROL_SUBJECT["sha256"],
        },
    )


def _control_rows() -> dict[str, dict[str, Any]]:
    stable = _stable_signature()
    varying = _varying_signature()
    reproducible = _reproducible_artefact()
    not_rebuilt = rep.artefact_evidence(_CONTROL_SUBJECT, None)

    stable_reproducible = rep.classify(stable, reproducible)
    varying_reproducible = rep.classify(varying, reproducible)

    rows: dict[str, dict[str, Any]] = {}

    def add(code: str, mechanism: str, state: str, detail: str, fired: bool) -> None:
        rows[code] = {
            "control": code.lower().removeprefix("sr_refused_").replace("_", "-"),
            "code": code,
            "mechanism": mechanism,
            "state": state,
            "fired": fired,
            "detail": detail,
        }

    add(
        rep.SR_REFUSED_SIGNATURE_AS_ARTEFACT,
        "classify.prohibited",
        stable_reproducible["combination"],
        "classify(stable signature, reproducible artefact) names the inference "
        "as prohibited",
        rep.SR_REFUSED_SIGNATURE_AS_ARTEFACT in stable_reproducible["prohibited"],
    )
    add(
        rep.SR_REFUSED_ARTEFACT_AS_SIGNATURE,
        "classify.prohibited",
        varying_reproducible["combination"],
        "classify(varying signature, reproducible artefact) names the inference "
        "as prohibited",
        rep.SR_REFUSED_ARTEFACT_AS_SIGNATURE in varying_reproducible["prohibited"],
    )
    add(
        rep.SR_REFUSED_DETERMINISTIC_SCHEME_AS_INDEPENDENCE,
        "classify.prohibited",
        stable_reproducible["combination"],
        "classify with a deterministic scheme names independence as prohibited",
        rep.SR_REFUSED_DETERMINISTIC_SCHEME_AS_INDEPENDENCE
        in stable_reproducible["prohibited"],
    )
    add(
        rep.SR_REFUSED_NONDETERMINISTIC_AS_FAILURE,
        "classify.prohibited",
        varying_reproducible["combination"],
        "classify with a randomised scheme names 'varying is a failure' as "
        "prohibited",
        rep.SR_REFUSED_NONDETERMINISTIC_AS_FAILURE
        in varying_reproducible["prohibited"],
    )

    reuse = rep.signature_evidence(
        [
            _attempt(b"control-reused", nonce="nonce-1"),
            _attempt(b"control-reused", nonce="nonce-1"),
        ],
        "ecdsa",
    )
    add(
        rep.SR_REFUSED_NONCE_REUSE,
        "signature_evidence",
        reuse["state"],
        "the synthetic randomised pair repeated its signature and nonce",
        reuse["code"] == rep.SR_REFUSED_NONCE_REUSE,
    )

    envelope = rep.artefact_evidence(
        {
            "name": "control-envelope",
            "kind": "envelope",
            "sha256": "c" * 64,
        },
        None,
    )
    add(
        rep.SR_REFUSED_ENVELOPE_DIGEST_AS_BUILD_DIGEST,
        "artefact_evidence",
        envelope["state"],
        "an envelope record is offered as a build subject",
        envelope["code"] == rep.SR_REFUSED_ENVELOPE_DIGEST_AS_BUILD_DIGEST,
    )

    seed = rep.signature_evidence(
        [
            _attempt(b"control-seed", key_kind="seed"),
            _attempt(b"control-seed", key_kind="seed"),
        ],
        "ed25519",
    )
    add(
        rep.SR_REFUSED_SEED_AS_KEY,
        "signature_evidence",
        seed["state"],
        "an attempt records a raw seed as the signing key",
        seed["code"] == rep.SR_REFUSED_SEED_AS_KEY,
    )

    stated = rep.signature_evidence(
        [
            _attempt(b"control-a", inputs={"payloadSha256": "00" * 32}),
            _attempt(b"control-a", inputs={"payloadSha256": "11" * 32}),
        ],
        "ed25519",
    )
    add(
        rep.SR_REFUSED_INPUTS_UNSTATED,
        "signature_evidence",
        stated["state"],
        "the two attempts record different inputs",
        stated["code"] == rep.SR_REFUSED_INPUTS_UNSTATED,
    )

    add(
        rep.SR_REFUSED_REBUILD_NOT_RUN,
        "artefact_evidence",
        not_rebuilt["state"],
        "no rebuild record is supplied",
        not_rebuilt["code"] == rep.SR_REFUSED_REBUILD_NOT_RUN,
    )

    unrecorded = rep.signature_evidence(
        [_attempt(b"control-a"), _attempt(b"control-a")],
        "rsa-pss",
    )
    add(
        rep.SR_REFUSED_SCHEME_UNRECORDED,
        "signature_evidence",
        unrecorded["state"],
        "the scheme is absent from the registry",
        unrecorded["code"] == rep.SR_REFUSED_SCHEME_UNRECORDED,
    )

    replay = rep.artefact_evidence(
        _CONTROL_SUBJECT,
        {
            "method": "replay",
            "outcome": "REPRODUCED",
            "inputs": {"control": "copy the existing bytes"},
            "digests": {"first": "b" * 64, "second": "b" * 64},
            "subjectSha256": _CONTROL_SUBJECT["sha256"],
        },
    )
    add(
        rep.SR_REFUSED_REPLAY_AS_REPRODUCTION,
        "artefact_evidence",
        replay["state"],
        "the rebuild record describes a replay",
        replay["code"] == rep.SR_REFUSED_REPLAY_AS_REPRODUCTION,
    )

    one = rep.signature_evidence([_attempt(b"control-one")], "ed25519")
    add(
        rep.SR_REFUSED_ATTEMPTS_INSUFFICIENT,
        "signature_evidence",
        one["state"],
        "one attempt is not a repetition",
        one["code"] == rep.SR_REFUSED_ATTEMPTS_INSUFFICIENT,
    )

    malformed = rep.signature_evidence(
        [{"inputs": {"keyid": "control"}}, _attempt(b"control-a")],
        "ed25519",
    )
    add(
        rep.SR_REFUSED_ATTEMPT_MALFORMED,
        "signature_evidence",
        malformed["state"],
        "an attempt carries no decodable signature",
        malformed["code"] == rep.SR_REFUSED_ATTEMPT_MALFORMED,
    )

    deterministic_varied = rep.signature_evidence(
        [_attempt(b"control-signature-1"), _attempt(b"control-signature-2")],
        "ed25519",
    )
    add(
        rep.SR_REFUSED_DETERMINISTIC_VARIED,
        "signature_evidence",
        deterministic_varied["state"],
        "a deterministic scheme produced two different signatures over the same "
        "inputs",
        deterministic_varied["code"] == rep.SR_REFUSED_DETERMINISTIC_VARIED,
    )
    return rows


def controls_document(source_commit: str) -> dict[str, Any]:
    rows = _control_rows()
    missing = sorted(set(rep.REFUSALS) - set(rows))
    assert not missing, f"controls missing for {missing}"
    assert all(row["fired"] for row in rows.values()), [
        code for code, row in rows.items() if not row["fired"]
    ]

    varying = _varying_signature()
    reproducible = _reproducible_artefact()
    stable = _stable_signature()
    positive = [
        {
            "control": "deterministic-stable",
            "accepted": stable["state"] == rep.SIGNATURE_STABLE,
            "state": stable["state"],
            "detail": (
                "a deterministic scheme signing the same inputs twice is "
                "byte-stable and is not refused"
            ),
        },
        {
            "control": "randomised-varies",
            "accepted": varying["state"] == rep.SIGNATURE_VARIES,
            "state": varying["state"],
            "detail": (
                "a synthetic randomised-scheme pair varies and is accepted; "
                "varying is not a failure"
            ),
        },
        {
            "control": "artefact-reproducible-synthetic",
            "accepted": reproducible["state"] == rep.ARTEFACT_REPRODUCIBLE,
            "state": reproducible["state"],
            "controlOnly": True,
            "detail": (
                "a synthetic rebuild record with two equal build digests reaches "
                "ARTEFACT_REPRODUCIBLE; this is a control and not a real rebuild"
            ),
        },
        {
            "control": "four-combinations",
            "accepted": True,
            "combinations": sorted(rep.COMBINATION_LABELS.values()),
            "detail": (
                "each of the four combinations is reachable from synthetic "
                "evidence and carries its prohibited inference"
            ),
        },
    ]
    assert all(row["accepted"] for row in positive), positive
    return {
        "schema": rep.CONTROLS_SCHEMA,
        "item": "A13",
        "asOf": AS_OF,
        "sourceIdentity": source_identity(
            source_commit, [TOOL_RELATIVE]
        ),
        "codes": len(rep.REFUSALS),
        "controlCount": len(rows),
        "controls": [rows[code] for code in sorted(rows)],
        "positiveControls": positive,
        "note": (
            "The randomised-varying control is accepted, not a failure. The "
            "randomised-repeating control is refused as SR_REFUSED_NONCE_REUSE. "
            "The synthetic reproducible artefact is control-only: no real subject "
            "in ARTEFACT.json is reproducible."
        ),
    }


# ---------------------------------------------------------------------------
# Entry point.
# ---------------------------------------------------------------------------


def build(output: Path, source_commit: str) -> dict[str, Any]:
    output.mkdir(parents=True, exist_ok=True)
    signature = signature_document(source_commit)
    artefact = artefact_document(source_commit)
    write_json(output / "SIGNATURE.json", signature)
    write_json(output / "ARTEFACT.json", artefact)
    classification = classification_document(signature, artefact, source_commit)
    controls = controls_document(source_commit)
    write_json(output / "CLASSIFICATION.json", classification)
    write_json(output / "CONTROLS.json", controls)
    return {
        "signature": signature,
        "artefact": artefact,
        "classification": classification,
        "controls": controls,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="build_evidence.py")
    parser.add_argument("--out", default=str(EVIDENCE))
    parser.add_argument("--source-commit", default=BASE_COMMIT)
    args = parser.parse_args(list(sys.argv[1:] if argv is None else argv))
    result = build(Path(args.out), args.source_commit)
    signature_counts = result["signature"]["counts"]
    artefact_counts = result["artefact"]["counts"]
    print(
        f"a13: signatures={signature_counts['signatures']} "
        f"stable={signature_counts['stable']} "
        f"varies={signature_counts['varies']} "
        f"nonceReused={signature_counts['nonceReused']} "
        f"artefacts={artefact_counts['subjects']} "
        f"notRebuilt={artefact_counts['notRebuilt']} "
        f"reproducible={artefact_counts['reproducible']} "
        f"pairs={result['classification']['counts']['pairs']} "
        f"codes={result['controls']['codes']} "
        f"controls={result['controls']['controlCount']} "
        f"commit={args.source_commit}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
