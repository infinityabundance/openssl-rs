#!/usr/bin/env python3
"""Produce evidence/a12 deterministically: the inventory, the verification, the controls.

Every digest is read from bytes and every outcome is produced by
``forensics/tools/independent_verify.py``; nothing is typed.  Re-running with the
same inputs reproduces the same files.

Usage
-----
    python3 evidence/a12/build_evidence.py
    python3 evidence/a12/build_evidence.py --out /tmp/a12a --source-commit 1d571da35

The default output is ``evidence/a12``.  The source identity is supplied; it is
never read from a live ``HEAD``.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import argparse
import hashlib
import json
import shutil
import tempfile
from pathlib import Path
from typing import Any, Callable, Mapping

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOLS = REPO_ROOT / "forensics" / "tools"
sys.path.insert(0, str(TOOLS))

import dsse  # noqa: E402
import independent_verify as iv  # noqa: E402

BASE_COMMIT = "1d571da35"
EVIDENCE = REPO_ROOT / "evidence" / "a12"
TOOL_RELATIVE = "forensics/tools/independent_verify.py"
INVENTORY_NAME = "TRUST-ROOTS.json"

TEST_ONLY_KEYID = "test-only:hmac-sha256:8e10a5a15d233d54"

ENVELOPES = (
    ("a1-sarif", "evidence/a10/ENVELOPES/a1-sarif.json",
     "evidence/a9/STATEMENTS/a1-sarif.json", "evidence/a1/SARIF.json"),
    ("a5-admission", "evidence/a10/ENVELOPES/a5-admission.json",
     "evidence/a9/STATEMENTS/a5-admission.json", "evidence/a5/ADMISSION.json"),
    ("a7-delta", "evidence/a10/ENVELOPES/a7-delta.json",
     "evidence/a9/STATEMENTS/a7-delta.json", "evidence/a7/DELTA.json"),
    ("a8-shard-000", "evidence/a10/ENVELOPES/a8-shard-000.json",
     "evidence/a9/STATEMENTS/a8-shard-000.json", "evidence/a8/SHARD-000.sarif"),
)

A1_STATEMENT = REPO_ROOT / "evidence" / "a9" / "STATEMENTS" / "a1-sarif.json"
A1_ARTEFACT_NAME = "evidence/a1/SARIF.json"
A1_ARTEFACT = REPO_ROOT / A1_ARTEFACT_NAME

STUB_KEYID = "control-only:public-key:stub"
STUB_SIGNATURE = b"control-only-signature"
STUB_PUBLIC = "control-only stub public key material"
STUB_PROVENANCE = b'{"control":"external stub trust root"}\n'


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def tool_identity() -> dict[str, Any]:
    raw = (REPO_ROOT / TOOL_RELATIVE).read_bytes()
    return {"path": TOOL_RELATIVE, "sha256": sha256_bytes(raw), "bytes": len(raw)}


def write_json(path: Path, document: Mapping[str, Any]) -> None:
    path.write_text(
        json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# The real inventory.
# ---------------------------------------------------------------------------


def inventory_document() -> dict[str, Any]:
    provenance = (REPO_ROOT / "evidence" / "a10" / "ENVELOPES.json").read_bytes()
    root = {
        "keyid": TEST_ONLY_KEYID,
        "algorithm": "hmac-sha256",
        "symmetric": True,
        "publicMaterial": None,
        "provenance": {
            "path": "evidence/a10/ENVELOPES.json",
            "sha256": sha256_bytes(provenance),
        },
        "trustDomain": "same-party",
        "independenceBasis": (
            "none: the key is derived from a fixed public seed recorded inside the "
            "candidate tree; the signer and the verifier hold the same secret, so "
            "the verifier could have produced the signature"
        ),
        "recordedAt": "2026-11-24",
        "selfIssued": True,
    }
    return {
        "schema": iv.INVENTORY_SCHEMA,
        "item": "A12",
        "asOf": "2026-11-24",
        "candidate": {
            "domain": "openssl-rs",
            "root": ".",
            "evidenceRoot": "evidence/a10",
        },
        "producer": {
            "domain": "openssl-rs",
            "note": "the A10 envelopes were produced inside this candidate",
        },
        "policy": {
            "keyid": TEST_ONLY_KEYID,
            "candidateDomain": "openssl-rs",
            "producerDomain": "openssl-rs",
            "candidateRoot": ".",
            "candidateEvidenceRoot": "evidence/a10",
            "asOf": "2026-11-24",
            "maxRootAgeDays": 365,
        },
        "roots": [root],
        "counts": {
            "roots": 1,
            "externalRoots": 0,
            "symmetricRoots": 1,
        },
        "externalRoots": [],
        "externalRootsNote": (
            "The inventory records no external root. This is the measured state, not "
            "an omission: the only recorded root is the A10 test-only HMAC-SHA256 "
            "key, which is symmetric and same-party and therefore cannot establish "
            "independence."
        ),
        "samePartyNote": (
            "The single root is recorded with trustDomain 'same-party' and "
            "symmetric: true so that the refusal is visible in the inventory itself."
        ),
    }


# ---------------------------------------------------------------------------
# The real verification.
# ---------------------------------------------------------------------------


def _real_verifier(keyid: str, pae: bytes, signature: bytes, material: Any) -> bool:
    """A caller-supplied verifier for the A10 test-only HMAC key.

    It is used only to record that the received signature is the one A10 made.
    It establishes no independence: the root refusal has already decided that.
    """
    return dsse.test_only_verifier()(keyid, pae, signature)


def verification_document(inventory_path: Path, source_commit: str) -> dict[str, Any]:
    policy = iv.policy_from_inventory(iv.load_inventory(inventory_path), inventory_path)
    rows = []
    counts = {
        "envelopes": len(ENVELOPES),
        iv.OUTCOME_VERIFIED: 0,
        iv.OUTCOME_SELF_ISSUED: 0,
        iv.OUTCOME_UNVERIFIED: 0,
        iv.OUTCOME_NOT_RUN: 0,
        "independentlyVerified": 0,
    }
    for name, envelope_path, statement_path, artefact_path in ENVELOPES:
        envelope_bytes = (REPO_ROOT / envelope_path).read_bytes()
        statement_bytes = (REPO_ROOT / statement_path).read_bytes()
        artefact_bytes = (REPO_ROOT / artefact_path).read_bytes()
        local = dict(policy)
        local["artefact"] = artefact_path
        result = iv.verify(envelope_bytes, local, _real_verifier)
        if result["payloadSha256"] != sha256_bytes(statement_bytes):
            raise AssertionError(
                f"{name}: the verified payload is not the A9 statement bytes"
            )
        if result["artefact"] is None or result["artefact"].get("sha256") != sha256_bytes(
            artefact_bytes
        ):
            raise AssertionError(f"{name}: the artefact was not re-hashed")
        counts[result["outcome"]] += 1
        if result["independentlyVerified"]:
            counts["independentlyVerified"] += 1
        rows.append({
            "name": name,
            "envelope": envelope_path,
            "envelopeSha256": sha256_bytes(envelope_bytes),
            "statement": statement_path,
            "statementSha256": sha256_bytes(statement_bytes),
            "artefact": artefact_path,
            "artefactSha256": sha256_bytes(artefact_bytes),
            "outcome": result["outcome"],
            "independentlyVerified": result["independentlyVerified"],
            "codes": result["codes"],
            "checks": result["checks"],
            "keyid": result["keyid"],
            "signatureChecked": result["signatureChecked"],
            "payloadSha256": result["payloadSha256"],
            "root": result["root"],
        })
    return {
        "schema": iv.VERIFICATION_SCHEMA,
        "item": "A12",
        "asOf": "2026-11-24",
        "sourceIdentity": {
            "baseCommit": source_commit,
            "tool": tool_identity(),
            "inventory": {
                "path": INVENTORY_NAME,
                "sha256": sha256_bytes(inventory_path.read_bytes()),
            },
        },
        "policy": {
            "keyidSelectedBy": "policy",
            "producerVerifiedItsOwnEnvelopes": True,
        },
        "counts": counts,
        "independentlyVerified": counts["independentlyVerified"],
        "verifications": rows,
        "aggregate": {
            "envelopes": counts["envelopes"],
            "independentlyVerified": counts["independentlyVerified"],
            "selfIssued": counts[iv.OUTCOME_SELF_ISSUED],
            "unverified": counts[iv.OUTCOME_UNVERIFIED],
            "notRun": counts[iv.OUTCOME_NOT_RUN],
            "statement": (
                "0 of 4 envelopes are independently verified. Each is an A10 "
                "test-only HMAC-SHA256 envelope whose root is symmetric, recorded "
                "inside the candidate tree and self-issued. A symmetric signature "
                "cannot establish independence, so SELF_ISSUED is the correct "
                "output, not a defect to repair."
            ),
        },
    }


# ---------------------------------------------------------------------------
# Controls: one per refusal code, plus the stub-verifier positive control.
# ---------------------------------------------------------------------------


class Fixture:
    """A control fixture: a stub-signed A1 statement and a root record."""

    def __init__(
        self,
        base: Path,
        *,
        artefact_bytes: bytes | None,
        artefact_present: bool = True,
    ) -> None:
        self.base = base
        self.candidate = base / "candidate"
        self.candidate.mkdir(parents=True, exist_ok=True)
        self.artefact_name = A1_ARTEFACT_NAME
        if artefact_present:
            path = base / self.artefact_name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(
                artefact_bytes if artefact_bytes is not None
                else A1_ARTEFACT.read_bytes()
            )
        self.root = {
            "keyid": STUB_KEYID,
            "algorithm": "control-only-stub-public-key",
            "symmetric": False,
            "publicMaterial": STUB_PUBLIC,
            "provenance": {
                "path": str(base / "external-root.json"),
                "sha256": "",
            },
            "trustDomain": "external-control",
            "independenceBasis": (
                "control fixture: a separate stub key selected by the recorded policy"
            ),
            "recordedAt": "2026-11-24",
        }
        provenance_path = Path(self.root["provenance"]["path"])
        provenance_path.write_bytes(STUB_PROVENANCE)
        self.root["provenance"]["sha256"] = sha256_bytes(STUB_PROVENANCE)
        self.policy = {
            "keyid": STUB_KEYID,
            "candidateDomain": "candidate",
            "producerDomain": "candidate-producer",
            "candidateRoot": str(self.candidate),
            "candidateEvidenceRoot": str(self.candidate / "evidence"),
            "asOf": "2026-11-24",
            "maxRootAgeDays": 365,
            "baseDir": str(base),
            "artefact": self.artefact_name,
            "trustRoots": {"schema": iv.INVENTORY_SCHEMA, "roots": [self.root]},
        }
        self.envelope = dsse.encode_envelope(
            dsse.envelope(
                dsse.IN_TOTO_PAYLOAD_TYPE,
                A1_STATEMENT.read_bytes(),
                lambda pae: (STUB_KEYID, STUB_SIGNATURE),
            )
        )

    def check(self, keyid: str, pae: bytes, signature: bytes, material: Any) -> bool:
        return (
            keyid == STUB_KEYID
            and signature == STUB_SIGNATURE
            and material == STUB_PUBLIC
        )


_NOT_GIVEN = object()


def _run(
    control: str,
    code: str,
    *,
    root_update: Mapping[str, Any] | None = None,
    policy_update: Mapping[str, Any] | None = None,
    verifier: Any = _NOT_GIVEN,
    envelope: bytes | None = None,
    artefact: str | None = None,
    artefact_bytes: bytes | None = None,
    artefact_present: bool = True,
) -> dict[str, Any]:
    base = Path(tempfile.mkdtemp(prefix="a12-control-"))
    try:
        fixture = Fixture(
            base,
            artefact_bytes=artefact_bytes,
            artefact_present=artefact_present,
        )
        root = dict(fixture.root)
        if root_update:
            root.update(root_update)
        policy = dict(fixture.policy)
        if policy_update:
            policy.update(policy_update)
        policy["trustRoots"] = {
            "schema": iv.INVENTORY_SCHEMA,
            "roots": [root],
        }
        if artefact is not None:
            policy["artefact"] = artefact
        raw = fixture.envelope if envelope is None else envelope
        chosen = fixture.check if verifier is _NOT_GIVEN else verifier
        result = iv.verify(raw, policy, chosen)
        if code not in result["codes"]:
            raise AssertionError(
                f"{control}: expected {code}, got {result['codes']} ({result['outcome']})"
            )
        return {
            "control": control,
            "code": code,
            "outcome": result["outcome"],
            "codes": result["codes"],
            "wrongConclusion": iv.REFUSALS[code]["prevents"],
        }
    finally:
        shutil.rmtree(base, ignore_errors=True)


def controls_document() -> dict[str, Any]:
    controls: list[dict[str, Any]] = []

    controls.append(_run("envelope-invalid", iv.IV_REFUSED_ENVELOPE, envelope=b"not-json"))
    controls.append(_run(
        "key-from-envelope", iv.IV_REFUSED_KEY_FROM_ENVELOPE,
        policy_update={"keyid": None},
    ))
    controls.append(_run(
        "symmetric-root", iv.IV_REFUSED_SYMMETRIC,
        root_update={
            "symmetric": True,
            "publicMaterial": None,
            "algorithm": "hmac-sha256",
        },
    ))
    controls.append(_run(
        "candidate-trust-root", iv.IV_REFUSED_CANDIDATE_TRUST_ROOT,
        root_update={
            "provenance": {
                "path": str(REPO_ROOT / "evidence" / "a10" / "ENVELOPES.json"),
                "sha256": sha256_bytes(
                    (REPO_ROOT / "evidence" / "a10" / "ENVELOPES.json").read_bytes()
                ),
            },
        },
        policy_update={"candidateRoot": str(REPO_ROOT)},
    ))
    controls.append(_run(
        "trust-root-unrecorded", iv.IV_REFUSED_TRUST_ROOT_UNRECORDED,
        policy_update={"keyid": "external:unrecorded-key"},
    ))
    controls.append(_run(
        "trust-root-digest-mismatch", iv.IV_REFUSED_TRUST_ROOT_DIGEST_MISMATCH,
        root_update={
            "provenance": {
                "path": str(REPO_ROOT / "evidence" / "a10" / "ENVELOPES.json"),
                "sha256": "0" * 64,
            },
        },
        policy_update={"candidateRoot": str(REPO_ROOT / "forensics")},
    ))
    controls.append(_run(
        "same-domain", iv.IV_REFUSED_SAME_DOMAIN,
        root_update={"trustDomain": "candidate-producer"},
    ))
    controls.append(_run(
        "self-issued-basis", iv.IV_REFUSED_SELF_ISSUED,
        root_update={"selfIssued": True},
    ))
    controls.append(_run(
        "signature-invalid", iv.IV_REFUSED_SIGNATURE,
        verifier=lambda keyid, pae, signature, material: False,
    ))
    controls.append(_run(
        "payload-not-subject", iv.IV_REFUSED_PAYLOAD_NOT_SUBJECT,
        artefact_bytes=b"different artefact bytes\n",
    ))
    controls.append(_run(
        "subject-absent", iv.IV_REFUSED_SUBJECT_ABSENT,
        artefact_present=False,
    ))
    controls.append(_run(
        "subject-mismatch", iv.IV_REFUSED_SUBJECT_MISMATCH,
        artefact="evidence/a5/ADMISSION.json",
    ))
    controls.append(_run(
        "no-public-verifier", iv.IV_REFUSED_NO_PUBLIC_VERIFIER,
        verifier=None,
    ))
    controls.append(_run(
        "trust-root-stale", iv.IV_REFUSED_TRUST_ROOT_STALE,
        root_update={"recordedAt": "2020-01-01"},
        policy_update={"asOf": "2026-11-24", "maxRootAgeDays": 1},
    ))

    # Two roots claiming one keyid.  `_run` builds the roots from the fixture, so
    # this control constructs the policy itself.
    base = Path(tempfile.mkdtemp(prefix="a12-control-"))
    try:
        fixture = Fixture(base, artefact_bytes=None)
        policy = dict(fixture.policy)
        policy["trustRoots"] = {
            "schema": iv.INVENTORY_SCHEMA,
            "roots": [fixture.root, dict(fixture.root)],
        }
        result = iv.verify(fixture.envelope, policy, fixture.check)
        if iv.IV_REFUSED_MULTIPLE_ROOTS not in result["codes"]:
            raise AssertionError(
                f"multiple-roots: got {result['codes']} ({result['outcome']})"
            )
        controls.append({
            "control": "multiple-roots",
            "code": iv.IV_REFUSED_MULTIPLE_ROOTS,
            "outcome": result["outcome"],
            "codes": result["codes"],
            "wrongConclusion": iv.REFUSALS[iv.IV_REFUSED_MULTIPLE_ROOTS]["prevents"],
        })
    finally:
        shutil.rmtree(base, ignore_errors=True)

    seen = {control["code"] for control in controls}
    if seen != set(iv.REFUSALS):
        raise AssertionError(
            f"controls do not cover every code: missing {sorted(set(iv.REFUSALS) - seen)}, "
            f"extra {sorted(seen - set(iv.REFUSALS))}"
        )
    if len(controls) != len(iv.REFUSALS):
        raise AssertionError(
            f"{len(controls)} controls for {len(iv.REFUSALS)} codes"
        )

    # The positive control: a distinct public-key root and a caller-supplied stub
    # verifier.  It establishes the decision procedure, not a real independent
    # party, so it is labelled control-only.
    base = Path(tempfile.mkdtemp(prefix="a12-control-"))
    try:
        fixture = Fixture(base, artefact_bytes=None)
        positive = iv.verify(fixture.envelope, fixture.policy, fixture.check)
        if positive["outcome"] != iv.OUTCOME_VERIFIED:
            raise AssertionError(
                f"the stub-verifier positive control is {positive['outcome']}: "
                f"{positive['codes']}"
            )
        positive_control = {
            "control": "stub-verifier-public-key",
            "label": "control-only",
            "outcome": positive["outcome"],
            "independentlyVerified": positive["independentlyVerified"],
            "codes": positive["codes"],
            "root": {
                "keyid": STUB_KEYID,
                "algorithm": "control-only-stub-public-key",
                "symmetric": False,
                "trustDomain": "external-control",
                "independenceBasis": (
                    "control fixture: a separate stub key selected by the recorded "
                    "policy"
                ),
            },
            "verifier": (
                "a caller-supplied stub that accepts only the control key and the "
                "control signature"
            ),
            "establishes": [
                "the decision procedure: policy-selected keyid, public-root refusal "
                "checks, PAE verification through the caller, and subject re-hashing",
                "that the outcome state INDEPENDENTLY_VERIFIED is reachable when a "
                "caller supplies a verifier for a distinct public-key root",
            ],
            "doesNotEstablish": [
                "a real independent party: the verifier is a test stub",
                "a signature primitive: none is implemented by this tool",
                "that any real envelope in the tree is independently verified",
                "a trust domain outside this project",
            ],
        }
    finally:
        shutil.rmtree(base, ignore_errors=True)

    return {
        "schema": iv.CONTROLS_SCHEMA,
        "item": "A12",
        "asOf": "2026-11-24",
        "codes": len(iv.REFUSALS),
        "controlCount": len(controls),
        "controls": controls,
        "positiveControl": positive_control,
        "positiveControlNote": (
            "The positive control is control-only. It proves the decision procedure "
            "can reach INDEPENDENTLY_VERIFIED under a caller-supplied verifier and a "
            "distinct public-key root. It does not establish a real independent "
            "party, and it is excluded from the real aggregate of 0 independently "
            "verified envelopes."
        ),
    }


# ---------------------------------------------------------------------------
# Entry point.
# ---------------------------------------------------------------------------


def build(output: Path, source_commit: str) -> dict[str, Any]:
    output.mkdir(parents=True, exist_ok=True)
    inventory = inventory_document()
    inventory_path = output / INVENTORY_NAME
    write_json(inventory_path, inventory)
    verification = verification_document(inventory_path, source_commit)
    controls = controls_document()
    write_json(output / "VERIFICATION.json", verification)
    write_json(output / "CONTROLS.json", controls)
    return {
        "inventory": inventory,
        "verification": verification,
        "controls": controls,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="build_evidence.py")
    parser.add_argument("--out", default=str(EVIDENCE))
    parser.add_argument("--source-commit", default=BASE_COMMIT)
    args = parser.parse_args(list(sys.argv[1:] if argv is None else argv))
    result = build(Path(args.out), args.source_commit)
    counts = result["verification"]["counts"]
    print(
        f"a12: envelopes={counts['envelopes']} "
        f"independentlyVerified={counts['independentlyVerified']} "
        f"selfIssued={counts[iv.OUTCOME_SELF_ISSUED]} "
        f"unverified={counts[iv.OUTCOME_UNVERIFIED]} "
        f"notRun={counts[iv.OUTCOME_NOT_RUN]} "
        f"codes={result['controls']['codes']} "
        f"controls={result['controls']['controlCount']} "
        f"commit={args.source_commit}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
