#!/usr/bin/env python3
"""build_evidence.py -- deterministic producer of the A16 records.

It writes three documents and nothing else:

  * ``INVENTORY.json`` -- the measured bundle population (0 bundles, 0 log keys,
    0 certificates), bound to this tree;
  * ``PROFILE.json``   -- the v0.3 profile ``sigstore_bundle.bundle_profile()``
    implements, field by field, with the trust-root and freshness assumptions;
  * ``CONTROLS.json``  -- one synthetic, ``control-only`` bundle per refusal
    code, the boundary cases around the certificate window, and one
    structurally complete bundle that reaches ``BUNDLE_VERIFIED_OFFLINE`` only
    with stub verifiers.

Every certificate here is synthetic DER with a placeholder signature.  It is
structurally parseable and cryptographically meaningless: the controls establish
the decision procedure, not a real signing event and not an automated build
provenance.  Every fixture is labelled ``control-only`` and is excluded from the
real inventory, which is measured from the tree and is zero.

Two runs are byte-identical.  Nothing reads the clock; the times are literals.

Usage:
    python3 evidence/a16/build_evidence.py [--out DIR] [--source-commit SHA]
    python3 evidence/a16/build_evidence.py --freeze-population CANDIDATE

The population is never read from a live glob.  ``INVENTORY.json`` declares an
explicit ``{path, sha256}`` member list frozen at a candidate commit, and this
producer reproduces that list.  ``--freeze-population CANDIDATE`` is the one
explicit act that replaces it: it takes the tracked evidence JSON and
certificate files that existed at ``CANDIDATE``, so a record added later is
``NEW_SINCE_RECORD`` rather than silently included.  A new bundle therefore
needs a re-freeze and a fresh inventory; it is not absorbed.

Every digest is read from the candidate commit's blobs (``git cat-file blob
CANDIDATE:path``), never from the working tree.  ``sourceIdentity`` and each
member's ``sha256`` are therefore bound to the exact candidate; an uncommitted
edit to a member cannot be absorbed.  This item's own records
(``INVENTORY.json``, ``PROFILE.json``, ``CONTROLS.json``) are excluded by
identity because each embeds ``sourceIdentity.baseCommit``.

``BASE_COMMIT`` is the declared default candidate.  The tests pin it separately;
see the comment beside it.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOLS = REPO_ROOT / "forensics/tools"
A16 = REPO_ROOT / "evidence/a16"
sys.path.insert(0, str(TOOLS))

import harden as h  # noqa: E402
import sigstore_bundle as sb  # noqa: E402

# The record's declared default candidate: the commit that carries the
# identity-exclusion contract and the candidate-blob reader.  The records name
# it as ``sourceIdentity.baseCommit`` and ``population.frozenAtCandidate``, and
# every member digest is read from its tree.  A later build-relevant change to
# the generator or the tool invalidates that binding and requires a new
# candidate, not an edit here alone.
BASE_COMMIT = "cd371ec9624d0633d21ce8944d14923baf87b14d"
BASE_COMMIT_SHORT = "cd371ec96"
RECORD_PATHS = (
    "evidence/a16/INVENTORY.json",
    "evidence/a16/PROFILE.json",
    "evidence/a16/CONTROLS.json",
)
ITEM = "A16"
AS_OF = "2026-11-24"
TOOL_PATH = "forensics/tools/sigstore_bundle.py"
DELEGATED_TOOLS = ("forensics/tools/harden.py", "forensics/tools/dsse.py")
CERTIFICATE_SUFFIXES = (".pem", ".crt", ".der", ".p7b", ".p12")

# The certificate validity window and the log's integratedTime are literals, so
# two runs and two machines agree.  The window is inclusive at both ends.
NOT_BEFORE = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
NOT_AFTER = datetime(2026, 12, 31, 0, 0, 0, tzinfo=timezone.utc)
INTEGRATED = datetime(2026, 6, 1, 0, 0, 0, tzinfo=timezone.utc)
LOG_INDEX = 4242

PAYLOAD_TYPE = "application/vnd.openssl-rs.control-only+json"
PAYLOAD = b"openssl-rs/a16 control-only artefact payload\n"
OTHER_ARTEFACT = b"openssl-rs/a16 control-only different artefact\n"

EXPECTED_ISSUER = "CN=control-only signer,O=control-only"
EXPECTED_IDENTITY = "control-only.example"
LOG_KEY = {"keyId": "Y29udHJvbC1vbmx5LWxvZy1rZXk=", "note": "control-only: no real log"}
CA_ROOT = {"path": "control-only/root-ca.pem", "sha256": "1" * 64}
TSA_ROOT = {"path": "control-only/tsa.pem", "sha256": "2" * 64}

POLICY = {
    "expectedIssuer": EXPECTED_ISSUER,
    "expectedIdentity": EXPECTED_IDENTITY,
    "identityType": "dns",
    "logKey": LOG_KEY,
    "caRoots": [CA_ROOT],
    "timestampRoots": [TSA_ROOT],
}

# ---------------------------------------------------------------------------
# A tiny DER writer.  It produces structurally valid certificates with a
# placeholder signature; it is not a certificate authority and signs nothing.
# ---------------------------------------------------------------------------


def _der_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def _tlv(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + _der_length(len(body)) + body


def _seq(*parts: bytes) -> bytes:
    return _tlv(0x30, b"".join(parts))


def _set_of(*parts: bytes) -> bytes:
    return _tlv(0x31, b"".join(parts))


def _integer(value: int) -> bytes:
    if value == 0:
        body = b"\x00"
    else:
        body = value.to_bytes((value.bit_length() + 7) // 8, "big")
        if body[0] & 0x80:
            body = b"\x00" + body
    return _tlv(0x02, body)


def _oid(dotted: str) -> bytes:
    arcs = [int(arc) for arc in dotted.split(".")]
    body = bytes([arcs[0] * 40 + arcs[1]])
    for arc in arcs[2:]:
        chunk = [arc & 0x7F]
        arc >>= 7
        while arc:
            chunk.append(0x80 | (arc & 0x7F))
            arc >>= 7
        body += bytes(reversed(chunk))
    return _tlv(0x06, body)


def _utf8(value: str) -> bytes:
    return _tlv(0x0C, value.encode("utf-8"))


def _utc_time(value: datetime) -> bytes:
    return _tlv(0x17, value.strftime("%y%m%d%H%M%SZ").encode("ascii"))


def _bit_string(value: bytes) -> bytes:
    return _tlv(0x03, b"\x00" + value)


def _octet_string(value: bytes) -> bytes:
    return _tlv(0x04, value)


def _explicit(number: int, body: bytes) -> bytes:
    return _tlv(0xA0 | number, body)


def _name(attributes: list[tuple[str, str]]) -> bytes:
    return _seq(*[_set_of(_seq(_oid(oid), _utf8(value))) for oid, value in attributes])


_ECDSA_WITH_SHA256 = "1.2.840.10045.4.3.2"
_ID_EC_PUBLIC_KEY = "1.2.840.10045.2.1"
_PRIME256V1 = "1.2.840.10045.3.1.7"


def _spki() -> bytes:
    algorithm = _seq(_oid(_ID_EC_PUBLIC_KEY), _oid(_PRIME256V1))
    return _seq(algorithm, _bit_string(b"\x04" + b"\x11" * 64))


def _extensions(identities: list[tuple[str, str]]) -> bytes:
    general_names = []
    for kind, value in identities:
        if kind == "dns":
            general_names.append(_tlv(0x82, value.encode("ascii")))
        elif kind == "email":
            general_names.append(_tlv(0x81, value.encode("ascii")))
        elif kind == "uri":
            general_names.append(_tlv(0x86, value.encode("ascii")))
        else:
            raise ValueError(f"unsupported control identity kind {kind!r}")
    san = _seq(_oid("2.5.29.17"), _octet_string(_seq(*general_names)))
    return _explicit(3, _seq(san))


def certificate(
    *,
    not_before: datetime = NOT_BEFORE,
    not_after: datetime = NOT_AFTER,
    issuer: list[tuple[str, str]] | None = None,
    subject: list[tuple[str, str]] | None = None,
    identities: list[tuple[str, str]] | None = None,
) -> bytes:
    issuer = issuer or [("2.5.4.3", "control-only signer"), ("2.5.4.10", "control-only")]
    subject = subject or [("2.5.4.3", "control-only signer"), ("2.5.4.10", "control-only")]
    identities = identities or [("dns", EXPECTED_IDENTITY)]
    tbs = _seq(
        _explicit(0, _integer(2)),
        _integer(0x0A16),
        _seq(_oid(_ECDSA_WITH_SHA256)),
        _name(issuer),
        _seq(_utc_time(not_before), _utc_time(not_after)),
        _name(subject),
        _spki(),
        _extensions(identities),
    )
    return _seq(tbs, _seq(_oid(_ECDSA_WITH_SHA256)), _bit_string(b"\x55" * 72))


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _epoch(value: datetime) -> int:
    return int(value.timestamp())


def base_document() -> dict[str, Any]:
    """A structurally complete, control-only v0.3 bundle."""
    return {
        "mediaType": sb.MEDIA_TYPE_V03,
        "verificationMaterial": {
            "x509CertificateChain": {
                "certificates": [{"rawBytes": _b64(certificate())}]
            },
            "tlogEntries": [
                {
                    "logIndex": LOG_INDEX,
                    "logId": {"keyId": LOG_KEY["keyId"]},
                    "kindVersion": {"kind": sb.TLOG_KIND, "version": sb.TLOG_API_VERSION},
                    "integratedTime": _epoch(INTEGRATED),
                    "canonicalizedBody": _b64(b"control-only canonicalized body"),
                    "inclusionProof": {
                        "logIndex": LOG_INDEX,
                        "rootHash": _b64(b"\x22" * 32),
                        "treeSize": LOG_INDEX + 1,
                        "hashes": [_b64(b"\x33" * 32)],
                        "checkpoint": {"envelope": "control-only checkpoint\n"},
                    },
                }
            ],
            "timestampVerificationData": {
                "rfc3161Timestamps": [{"signedTimestamp": _b64(b"\x44" * 32)}]
            },
        },
        "dsseEnvelope": {
            "payloadType": PAYLOAD_TYPE,
            "payload": _b64(PAYLOAD),
            "signatures": [{"keyid": "", "sig": _b64(b"\x66" * 64)}],
        },
    }


def encode(document: Any) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _accept_cert(*_args: Any) -> bool:
    return True


def _accept_signature(*_args: Any) -> bool:
    return True


def _accept_log(*_args: Any) -> bool:
    return True


def _accept_timestamp(*_args: Any) -> bool:
    return True


def _reject(*_args: Any) -> bool:
    return False


ALL_ACCEPT = {
    "cert_verify": _accept_cert,
    "signature_verify": _accept_signature,
    "log_verify": _accept_log,
    "timestamp_verify": _accept_timestamp,
}
VERIFIER_LABELS = {
    "cert_verify": "accept",
    "signature_verify": "accept",
    "log_verify": "accept",
    "timestamp_verify": "accept",
}


def _policy_without(*keys: str) -> dict[str, Any]:
    return {key: value for key, value in POLICY.items() if key not in keys}


def _observed(report: dict[str, Any]) -> dict[str, Any]:
    return {
        "outcome": report["outcome"],
        "codes": list(report["codes"]),
        "checks": [
            {
                "check": check["check"],
                "status": check["status"],
                "code": check["code"],
                "detail": check["detail"],
            }
            for check in report["checks"]
        ],
    }


def _run(
    *,
    bundle: dict[str, Any] | None = None,
    bundle_bytes: bytes | None = None,
    artefact: bytes = PAYLOAD,
    policy: dict[str, Any] | None = POLICY,
    verifiers: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if bundle is None and bundle_bytes is None:
        bundle = base_document()
    raw = encode(bundle) if bundle_bytes is None else bundle_bytes
    return sb.validate_bundle(
        raw,
        artefact,
        policy=policy,
        **(ALL_ACCEPT if verifiers is None else verifiers),
    )


def _control(
    control_id: str,
    expected_code: str,
    note: str,
    *,
    bundle: dict[str, Any] | None = None,
    bundle_bytes: bytes | None = None,
    artefact: bytes = PAYLOAD,
    policy: dict[str, Any] | None = POLICY,
    verifiers: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if bundle is None and bundle_bytes is None:
        bundle = base_document()
    report = _run(
        bundle=bundle,
        bundle_bytes=bundle_bytes,
        artefact=artefact,
        policy=policy,
        verifiers=verifiers,
    )
    if expected_code not in report["codes"]:
        raise SystemExit(
            f"control {control_id} failed: expected {expected_code}, observed "
            f"{report['codes']} ({report['outcome']})"
        )
    return {
        "id": control_id,
        "controlOnly": True,
        "code": expected_code,
        "note": note,
        "bundle": bundle,
        "bundleBytesSha256": (
            hashlib.sha256(bundle_bytes).hexdigest()
            if bundle_bytes is not None
            else hashlib.sha256(encode(bundle)).hexdigest()
        ),
        "artefactSha256": hashlib.sha256(artefact).hexdigest(),
        "policy": policy,
        "verifiers": VERIFIER_LABELS
        if verifiers is None
        else {name: "custom" for name in verifiers},
        "expected": {"outcome": None, "code": expected_code},
        "observed": _observed(report),
    }


def controls() -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []

    document = base_document()
    document["mediaType"] = "application/json"
    records.append(
        _control(
            "media-type",
            sb.SB_REFUSED_MEDIATYPE,
            "an ordinary JSON object is not a Sigstore bundle",
            bundle=document,
        )
    )

    document = base_document()
    document["mediaType"] = "application/vnd.dev.sigstore.bundle.v0.2+json"
    records.append(
        _control(
            "version-v0.2",
            sb.SB_REFUSED_VERSION,
            "the v0.2 shape is not validated here; it is refused, not guessed",
            bundle=document,
        )
    )

    document = base_document()
    document.pop("dsseEnvelope")
    records.append(
        _control(
            "bundle-invalid-no-envelope",
            sb.SB_REFUSED_BUNDLE_INVALID,
            "a bundle with no DSSE envelope is not a bundle",
            bundle=document,
        )
    )

    document = base_document()
    duplicate = b'{"mediaType":"duplicate-control-only",' + encode(document)[1:]
    records.append(
        _control(
            "duplicate-key",
            sb.SB_REFUSED_DUPLICATE_KEY,
            "harden.loads refuses the second mediaType rather than letting it win",
            bundle_bytes=duplicate,
        )
    )

    document = base_document()
    document.pop("verificationMaterial")
    records.append(
        _control(
            "material-absent",
            sb.SB_REFUSED_MATERIAL,
            "no verification material means no signer",
            bundle=document,
        )
    )

    document = base_document()
    document["verificationMaterial"]["x509CertificateChain"]["certificates"] = []
    records.append(
        _control(
            "cert-chain-empty",
            sb.SB_REFUSED_CERT_CHAIN,
            "an empty certificate list is not a chain",
            bundle=document,
        )
    )

    verifiers = dict(ALL_ACCEPT)
    verifiers.pop("cert_verify")
    records.append(
        _control(
            "cert-root-absent",
            sb.SB_REFUSED_CERT_ROOT_ABSENT,
            "a parsed certificate is not a verified chain",
            policy=POLICY,
            verifiers=verifiers,
        )
    )

    document = base_document()
    document["verificationMaterial"]["tlogEntries"][0]["integratedTime"] = (
        _epoch(NOT_AFTER) + 1
    )
    records.append(
        _control(
            "certificate-expired-at-integrated-time",
            sb.SB_REFUSED_EXPIRED_CERT,
            "one second after notAfter is out of the window",
            bundle=document,
        )
    )

    document = base_document()
    document["verificationMaterial"]["tlogEntries"][0]["integratedTime"] = (
        _epoch(NOT_BEFORE) - 1
    )
    records.append(
        _control(
            "certificate-not-yet-valid-at-integrated-time",
            sb.SB_REFUSED_EXPIRED_CERT,
            "one second before notBefore is out of the window",
            bundle=document,
        )
    )

    records.append(
        _control(
            "issuer-mismatch",
            sb.SB_REFUSED_ISSUER_MISMATCH,
            "the policy names a different issuer",
            policy={**POLICY, "expectedIssuer": "CN=control-only other,O=control-only"},
        )
    )

    records.append(
        _control(
            "identity-mismatch",
            sb.SB_REFUSED_IDENTITY_MISMATCH,
            "the policy names a SAN the certificate does not carry",
            policy={**POLICY, "expectedIdentity": "other.example"},
        )
    )

    records.append(
        _control(
            "payload-digest",
            sb.SB_REFUSED_PAYLOAD_DIGEST,
            "the payload signs one artefact, not the artefact under verification",
            artefact=OTHER_ARTEFACT,
        )
    )

    document = base_document()
    document["verificationMaterial"]["tlogEntries"] = []
    records.append(
        _control(
            "tlog-absent",
            sb.SB_REFUSED_TLOG_ABSENT,
            "no transparency entry means no log claim",
            bundle=document,
        )
    )

    document = base_document()
    document["verificationMaterial"]["tlogEntries"][0]["kindVersion"] = {
        "kind": "hashedrekord",
        "version": "0.0.1",
    }
    records.append(
        _control(
            "tlog-kind",
            sb.SB_REFUSED_TLOG_KIND,
            "a hashedrekord entry is not the DSSE entry for this envelope",
            bundle=document,
        )
    )

    document = base_document()
    document["verificationMaterial"]["tlogEntries"][0]["inclusionProof"]["logIndex"] = (
        LOG_INDEX + 1
    )
    records.append(
        _control(
            "integrated-time-index-disagreement",
            sb.SB_REFUSED_INTEGRATED_TIME,
            "the proof's index disagrees with the entry's",
            bundle=document,
        )
    )

    document = base_document()
    document["verificationMaterial"]["tlogEntries"][0].pop("inclusionProof")
    records.append(
        _control(
            "inclusion-proof-absent",
            sb.SB_REFUSED_INCLUSION_PROOF,
            "an entry with no promise and no proof is unproven",
            bundle=document,
        )
    )

    verifiers = dict(ALL_ACCEPT)
    verifiers["log_verify"] = _reject
    records.append(
        _control(
            "inclusion-proof-rejected",
            sb.SB_REFUSED_INCLUSION_PROOF,
            "a present proof the supplied log verifier rejects is not inclusion",
            verifiers=verifiers,
        )
    )

    verifiers = dict(ALL_ACCEPT)
    verifiers.pop("log_verify")
    records.append(
        _control(
            "log-key-absent",
            sb.SB_REFUSED_LOG_KEY_ABSENT,
            "presence of a proof is not verification of it",
            policy=_policy_without("logKey"),
            verifiers=verifiers,
        )
    )

    document = base_document()
    document["verificationMaterial"].pop("timestampVerificationData")
    records.append(
        _control(
            "timestamp-absent",
            sb.SB_REFUSED_TIMESTAMP_ABSENT,
            "the profile requires a timestamp",
            bundle=document,
        )
    )

    verifiers = dict(ALL_ACCEPT)
    verifiers.pop("timestamp_verify")
    records.append(
        _control(
            "timestamp-root-absent",
            sb.SB_REFUSED_TIMESTAMP_ROOT_ABSENT,
            "a timestamp is not verified without a TSA root",
            policy=_policy_without("timestampRoots"),
            verifiers=verifiers,
        )
    )

    verifiers = dict(ALL_ACCEPT)
    verifiers["timestamp_verify"] = _reject
    records.append(
        _control(
            "timestamp-rejected",
            sb.SB_REFUSED_TIMESTAMP_INVALID,
            "a timestamp the supplied verifier rejects is not freshness",
            verifiers=verifiers,
        )
    )

    verifiers = dict(ALL_ACCEPT)
    verifiers["signature_verify"] = _reject
    records.append(
        _control(
            "signature-rejected",
            sb.SB_REFUSED_SIGNATURE,
            "a rejected DSSE signature is not authentication",
            verifiers=verifiers,
        )
    )

    verifiers = dict(ALL_ACCEPT)
    verifiers.pop("signature_verify")
    records.append(
        _control(
            "signature-verifier-absent",
            sb.SB_REFUSED_SIGNATURE,
            "no verifier means the signature is NOT_RUN, not accepted",
            verifiers=verifiers,
        )
    )

    records.append(
        _control(
            "policy-absent",
            sb.SB_REFUSED_POLICY_ABSENT,
            "with no expected issuer or identity, any certificate would pass",
            policy=None,
        )
    )

    absent = sb.validate_paths(
        REPO_ROOT / "control-only/absent.sigstore.json",
        REPO_ROOT / "control-only/absent.artefact",
    )
    if sb.SB_REFUSED_INPUT_ABSENT not in absent["codes"]:
        raise SystemExit(f"input-absent control failed: {absent['codes']}")
    records.append(
        {
            "id": "input-absent",
            "controlOnly": True,
            "code": sb.SB_REFUSED_INPUT_ABSENT,
            "note": "absence is NOT_RUN, never a pass",
            "bundle": None,
            "bundlePath": "control-only/absent.sigstore.json",
            "artefactPath": "control-only/absent.artefact",
            "expected": {"outcome": sb.OUTCOME_NOT_RUN, "code": sb.SB_REFUSED_INPUT_ABSENT},
            "observed": _observed(absent),
        }
    )

    for control_id, source, note in (
        (
            "network-import",
            "import socket\n",
            "an import of a network client is refused structurally",
        ),
        (
            "sigstore-client-invocation",
            "import subprocess\nsubprocess.run(['cosign', 'verify'])\n",
            "a Sigstore client invocation is refused structurally",
        ),
    ):
        findings = sb.network_or_client_findings(source)
        codes = sorted({finding["code"] for finding in findings})
        if sb.SB_REFUSED_NETWORK_OR_CLIENT not in codes:
            raise SystemExit(f"control {control_id} failed: {findings}")
        records.append(
            {
                "id": control_id,
                "controlOnly": True,
                "code": sb.SB_REFUSED_NETWORK_OR_CLIENT,
                "note": note,
                "kind": "source-inspection",
                "source": source,
                "expected": {"outcome": "STRUCTURAL", "code": sb.SB_REFUSED_NETWORK_OR_CLIENT},
                "observed": {"codes": codes, "findings": findings},
            }
        )

    return records


def positive_control() -> dict[str, Any]:
    report = _run()
    if report["outcome"] != sb.OUTCOME_VERIFIED or report["codes"]:
        raise SystemExit(
            f"the positive control did not verify: {report['outcome']} {report['codes']}"
        )
    return {
        "id": "positive-structurally-complete",
        "controlOnly": True,
        "code": None,
        "note": (
            "reaches BUNDLE_VERIFIED_OFFLINE only with stub cert_verify, "
            "signature_verify, log_verify and timestamp_verify callables; it "
            "establishes the decision procedure, not a real signing event, not a "
            "real log and not an automated build provenance"
        ),
        "bundle": base_document(),
        "artefactSha256": hashlib.sha256(PAYLOAD).hexdigest(),
        "policy": POLICY,
        "verifiers": VERIFIER_LABELS,
        "expected": {"outcome": sb.OUTCOME_VERIFIED, "code": sb.CODE_OK},
        "observed": _observed(report),
    }


def boundary_controls() -> list[dict[str, Any]]:
    """The inclusive certificate window, at each edge and one second outside it."""
    cases = (
        ("at-not-before", _epoch(NOT_BEFORE), sb.OUTCOME_VERIFIED),
        ("one-second-before-not-before", _epoch(NOT_BEFORE) - 1, sb.OUTCOME_INVALID),
        ("at-not-after", _epoch(NOT_AFTER), sb.OUTCOME_VERIFIED),
        ("one-second-after-not-after", _epoch(NOT_AFTER) + 1, sb.OUTCOME_INVALID),
    )
    records: list[dict[str, Any]] = []
    for case_id, integrated_time, expected_outcome in cases:
        document = base_document()
        document["verificationMaterial"]["tlogEntries"][0]["integratedTime"] = (
            integrated_time
        )
        report = _run(bundle=document)
        if report["outcome"] != expected_outcome:
            raise SystemExit(
                f"boundary {case_id} failed: expected {expected_outcome}, "
                f"observed {report['outcome']} {report['codes']}"
            )
        records.append(
            {
                "id": case_id,
                "controlOnly": True,
                "integratedTime": integrated_time,
                "notBefore": _epoch(NOT_BEFORE),
                "notAfter": _epoch(NOT_AFTER),
                "expected": {"outcome": expected_outcome},
                "observed": _observed(report),
            }
        )
    return records


@lru_cache(maxsize=None)
def _candidate_blob(commit: str, relative: str) -> bytes:
    """Read ``relative`` from ``commit``'s tree, never from the working tree."""
    result = subprocess.run(
        [
            "git",
            "-c",
            "safe.directory=*",
            "-C",
            str(REPO_ROOT),
            "cat-file",
            "blob",
            f"{commit}:{relative}",
        ],
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise SystemExit(
            f"{relative} is not readable at candidate {commit}: "
            f"{result.stderr.decode('utf-8', 'replace').strip()}; a live glob "
            "or the working tree is not a substitute"
        )
    return result.stdout


def _blob_reader(commit: str):
    def read(relative: str) -> bytes:
        return _candidate_blob(commit, relative)

    return read


def source_identity(source_commit: str) -> dict[str, Any]:
    return {
        "baseCommit": source_commit,
        "baseCommitShort": source_commit[:9],
        "item": ITEM,
        "asOf": AS_OF,
        "tool": {
            "path": TOOL_PATH,
            "sha256": hashlib.sha256(
                _candidate_blob(source_commit, TOOL_PATH)
            ).hexdigest(),
        },
        "delegatedTools": [
            {
                "path": path,
                "sha256": hashlib.sha256(
                    _candidate_blob(source_commit, path)
                ).hexdigest(),
            }
            for path in DELEGATED_TOOLS
        ],
    }


def build(source_commit: str, population: dict[str, Any] | None = None) -> dict[str, Any]:
    declared = population if population is not None else _declared_population(None, source_commit)
    blobs = _blob_reader(source_commit)
    measured = sb.inventory(
        declared["members"],
        declared["certificateMembers"],
        frozen_at_candidate=declared["frozenAtCandidate"],
        blobs=blobs,
    )
    if declared.get("superseded"):
        measured["population"]["superseded"] = declared["superseded"]
    measured.update(
        {
            "schema": sb.INVENTORY_SCHEMA,
            "item": ITEM,
            "asOf": AS_OF,
            "sourceIdentity": source_identity(source_commit),
        }
    )
    if (
        measured["bundles"] != 0
        or measured["transparencyLogs"] != 0
        or measured["certificates"] != 0
    ):
        raise SystemExit(
            "the real inventory is not zero: "
            f"{measured['bundles']} bundles, {measured['transparencyLogs']} logs, "
            f"{measured['certificates']} certificates"
        )
    profile = {
        "schema": sb.PROFILE_SCHEMA,
        "item": ITEM,
        "asOf": AS_OF,
        "sourceIdentity": source_identity(source_commit),
        "profile": sb.bundle_profile(),
    }
    real_controls = controls()
    positive = positive_control()
    boundaries = boundary_controls()
    controls_document = {
        "schema": sb.CONTROLS_SCHEMA,
        "item": ITEM,
        "asOf": AS_OF,
        "sourceIdentity": source_identity(source_commit),
        "note": (
            "Every fixture is control-only and is excluded from the real "
            "inventory. The positive control establishes the decision procedure "
            "under stub verifiers; it is not a real signing event, a real log, a "
            "real CA or an automated build provenance."
        ),
        "summary": {
            "controls": len(real_controls),
            "codesCovered": len({record["code"] for record in real_controls}),
            "positiveVerified": positive["observed"]["outcome"] == sb.OUTCOME_VERIFIED,
            "boundaryCases": len(boundaries),
        },
        "controls": real_controls,
        "positive": positive,
        "boundaries": boundaries,
    }
    return {
        "INVENTORY.json": measured,
        "PROFILE.json": profile,
        "CONTROLS.json": controls_document,
    }


def _dump(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode(
        "utf-8"
    )


def _git(*arguments: str) -> bytes:
    result = subprocess.run(
        ["git", "-c", "safe.directory=*", "-C", str(REPO_ROOT), *arguments],
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise SystemExit(
            f"git {' '.join(arguments)} failed: "
            f"{result.stderr.decode('utf-8', 'replace').strip()}"
        )
    return result.stdout


def _tree_blobs(commit: str) -> dict[str, str]:
    """The blob oid of every file under ``evidence/`` at a commit."""
    rows: dict[str, str] = {}
    for entry in _git("ls-tree", "-r", "-z", commit, "--", "evidence").split(b"\x00"):
        if not entry:
            continue
        meta, path = entry.split(b"\t", 1)
        _mode, kind, oid = meta.split(b" ")
        if kind != b"blob":
            continue
        rows[path.decode("utf-8")] = oid.decode("ascii")
    return rows


def candidate_population(commit: str) -> tuple[list[str], list[str]]:
    """The evidence JSON and certificate files that existed at ``commit``.

    This item's own records (``INVENTORY.json``, ``PROFILE.json``,
    ``CONTROLS.json``) are excluded by identity: each embeds
    ``sourceIdentity.baseCommit``, so it cannot also be bound to its own digest
    at the commit that carries it.  That exclusion is separate from the declared
    cut (``sb.POPULATION_EXCLUDED_PATHS``), which remains exactly the three A11
    records and must exist at the candidate, so it can never hide a record that
    is missing rather than excluded.

    Only the candidate tree is read; the working tree is never a fallback.
    """
    candidate = _tree_blobs(commit)
    excluded = set(sb.POPULATION_EXCLUDED_PATHS)
    identity = set(sb.POPULATION_IDENTITY_EXCLUDED)
    missing = sorted(excluded - set(candidate))
    if missing:
        raise SystemExit(
            "the declared exclusion names a path that is not in the candidate "
            f"{commit}: {', '.join(missing)}"
        )
    json_paths = sorted(
        path
        for path in candidate
        if path.endswith(".json")
        and path not in excluded
        and path not in identity
    )
    certificate_paths = sorted(
        path for path in candidate if path.endswith(CERTIFICATE_SUFFIXES)
    )
    if not json_paths:
        raise SystemExit(f"the candidate {commit} has no evidence JSON to freeze")
    return json_paths, certificate_paths


def _prior_record(source_commit: str) -> dict[str, Any] | None:
    """The record the re-freeze supersedes, read from ``source_commit``'s tree."""
    try:
        raw = _candidate_blob(source_commit, "evidence/a16/INVENTORY.json")
    except SystemExit:
        return None
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return document if isinstance(document, dict) else None


def _record_digests(commit: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for relative in RECORD_PATHS:
        try:
            data = _candidate_blob(commit, relative)
        except SystemExit:
            continue
        rows.append(
            {"path": relative, "sha256": hashlib.sha256(data).hexdigest()}
        )
    return rows


def _superseded_entries(
    prior: dict[str, Any] | None,
    prior_commit: str,
    new_candidate: str,
    new_paths: list[str],
) -> list[dict[str, Any]]:
    """The prior freeze, preserved inside the record instead of overwritten.

    A re-freeze is only recorded as superseding a *different* freeze; repeating
    the same freeze at the same candidate produces no entry, so two runs stay
    byte-identical.
    """
    population = prior.get("population") if isinstance(prior, dict) else None
    if not isinstance(population, dict):
        return []
    prior_members = population.get("members")
    prior_paths = (
        [
            member.get("path")
            for member in prior_members
            if isinstance(member, dict) and isinstance(member.get("path"), str)
        ]
        if isinstance(prior_members, list)
        else []
    )
    if population.get("frozenAtCandidate") == new_candidate and sorted(
        prior_paths
    ) == sorted(new_paths):
        return []
    entries: list[dict[str, Any]] = []
    existing = population.get("superseded")
    if isinstance(existing, list):
        entries.extend(existing)
    identity = sorted(set(prior_paths) & set(sb.POPULATION_IDENTITY_EXCLUDED))
    if identity:
        reason = (
            "the prior freeze listed "
            + ", ".join(identity)
            + " as members; each embeds sourceIdentity.baseCommit, so a population "
            "frozen at that commit cannot also contain the record's own bytes (a "
            "commit-hash fixed point). This item's own records are now excluded "
            "by identity, not by the declared cut, and the population is "
            "re-frozen at the candidate's blobs."
        )
    else:
        reason = (
            "an explicit re-freeze replaced the prior population at a new "
            "candidate; the prior freeze, member count and record digests are "
            "preserved here rather than silently overwritten."
        )
    entries.append(
        {
            "frozenAtCandidate": population.get("frozenAtCandidate"),
            "files": population.get("files"),
            "memberCount": len(prior_paths),
            "recordDigests": _record_digests(prior_commit),
            "reason": reason,
        }
    )
    return entries


def _declared_population(
    freeze_candidate: str | None, source_commit: str
) -> dict[str, Any]:
    """The population to reproduce, or the one an explicit re-freeze creates.

    The record is the declared evidence artifact (the thing being regenerated);
    its member *list* is read from the committed record.  Every member *digest*
    and every ``sourceIdentity`` digest is read from ``source_commit``'s blobs,
    never from the working tree, so an uncommitted edit cannot be absorbed.  A
    live glob is not a substitute for the declared record in either branch.
    """
    if freeze_candidate is not None:
        paths, certificate_paths = candidate_population(freeze_candidate)
        blobs = _blob_reader(freeze_candidate)
        result: dict[str, Any] = {
            "frozenAtCandidate": freeze_candidate,
            "members": sb.freeze_population(paths, blobs=blobs),
            "certificateMembers": sb.freeze_population(
                certificate_paths, blobs=blobs
            ),
        }
        superseded = _superseded_entries(
            _prior_record(source_commit), source_commit, freeze_candidate, paths
        )
        if superseded:
            result["superseded"] = superseded
        return result
    record = A16 / "INVENTORY.json"
    if not record.is_file():
        raise SystemExit(
            "evidence/a16/INVENTORY.json is the declared population and is "
            "missing; a live glob is not a substitute (re-freeze with "
            "--freeze-population CANDIDATE)"
        )
    try:
        document = json.loads(record.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SystemExit(
            "evidence/a16/INVENTORY.json is not valid JSON: " f"{error}"
        )
    population = document.get("population") if isinstance(document, dict) else None
    if not isinstance(population, dict) or population.get("binding") != sb.POPULATION_BINDING:
        raise SystemExit(
            "evidence/a16/INVENTORY.json declares no frozen population; a live "
            "glob is not a substitute (re-freeze with --freeze-population "
            "CANDIDATE)"
        )
    excluded = population.get("excluded")
    excluded_paths = excluded.get("paths") if isinstance(excluded, dict) else None
    if not isinstance(excluded_paths, list) or tuple(excluded_paths) != (
        sb.POPULATION_EXCLUDED_PATHS
    ):
        raise SystemExit(
            "evidence/a16/INVENTORY.json does not declare the closed exclusion "
            f"{list(sb.POPULATION_EXCLUDED_PATHS)}; a record that drops it cannot "
            "be reproduced (re-freeze with --freeze-population CANDIDATE)"
        )
    members = population.get("members")
    certificates = document.get("certificatePopulation")
    certificate_members = (
        certificates.get("members") if isinstance(certificates, dict) else None
    )
    if not isinstance(members, list) or not members or not isinstance(certificate_members, list):
        raise SystemExit(
            "evidence/a16/INVENTORY.json has no usable member list; re-freeze "
            "with --freeze-population CANDIDATE"
        )
    identity_members = sorted(
        {
            member.get("path")
            for member in members
            if isinstance(member, dict) and isinstance(member.get("path"), str)
        }
        & set(sb.POPULATION_IDENTITY_EXCLUDED)
    )
    if identity_members:
        raise SystemExit(
            "evidence/a16/INVENTORY.json lists this item's own records as "
            f"members ({', '.join(identity_members)}); each embeds the candidate "
            "commit, so the population would be a commit-hash fixed point. "
            "Re-freeze with --freeze-population CANDIDATE to exclude them by "
            "identity."
        )
    return {
        "frozenAtCandidate": population.get("frozenAtCandidate"),
        "members": members,
        "certificateMembers": certificate_members,
        "superseded": (
            population.get("superseded")
            if isinstance(population.get("superseded"), list)
            else []
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", default=str(A16))
    parser.add_argument("--source-commit", default=None)
    parser.add_argument(
        "--freeze-population",
        metavar="CANDIDATE",
        default=None,
        help=(
            "explicitly replace the frozen population with the evidence files "
            "that existed at CANDIDATE; growth is never absorbed implicitly"
        ),
    )
    args = parser.parse_args(argv)
    if args.freeze_population is not None:
        source_commit = args.source_commit or args.freeze_population
        if source_commit != args.freeze_population:
            print(
                "a16: --freeze-population CANDIDATE must be the same candidate "
                "as --source-commit: the member digests and the recorded "
                "sourceIdentity must name the same commit",
                file=sys.stderr,
            )
            return 2
    else:
        source_commit = args.source_commit or BASE_COMMIT
    try:
        declared = _declared_population(args.freeze_population, source_commit)
        records = build(source_commit, declared)
        growth = sb.growth_report(
            declared["members"], declared["certificateMembers"]
        )
    except h.Refusal as refusal:
        print(f"{refusal.code}: {refusal.message}", file=sys.stderr)
        return 1
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for name, value in records.items():
        (out / name).write_bytes(_dump(value))
    inventory_record = records["INVENTORY.json"]
    controls_record = records["CONTROLS.json"]
    for entry in growth:
        print(
            f"growth: result={entry['result']} path={entry['path']} "
            f"sha256={entry['sha256']} bytes={entry['bytes']}",
            file=sys.stderr,
        )
    print(
        f"a16: bundles={inventory_record['bundles']} "
        f"logs={inventory_record['transparencyLogs']} "
        f"certificates={inventory_record['certificates']} "
        f"controls={controls_record['summary']['controls']} "
        f"codes={controls_record['summary']['codesCovered']} "
        f"boundaries={controls_record['summary']['boundaryCases']} "
        f"positive={controls_record['positive']['observed']['outcome']} "
        f"commit={source_commit[:9]} "
        f"population={inventory_record['population']['binding']} "
        f"files={inventory_record['populationFiles']} growth={len(growth)}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
