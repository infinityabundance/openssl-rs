#!/usr/bin/env python3
"""build_evidence.py -- the deterministic producer for B2.

B2 asks for RFC 3161 timestamp evidence and verification without the original
live service.  This venue has **no TSA, no certificate, no trust root and no
network**; B0 records the assumption as ``TA-B2`` ``UNMET`` (0 certificates, no
timestamp-authority root).  The producer therefore writes what is true:

  * the **nine times** of §B.9 as nine separate slots for the real A9 statements
    and the real B1 fixture publication, each slot with a source and an
    ``established`` state -- most authority and log slots are ``unknown``;
  * **zero tokens** found in the tree, and ``NO_TOKEN`` for every artefact;
  * ``trusted: 0`` -- no imprint, signature, chain or root outcome is ``PASS``
    for a real artefact because there is no token to check;
  * the **control fixtures** that exercise every refusal code, labelled
    ``control-only`` and ``UNTRUSTED``.

Every record is derived from committed inputs, a fixed control seed and fixed
fixture times.  No clock, environment, network or random source is read.  Two
runs write the same bytes: canonical JSON, sorted keys, one-space indent, a
trailing newline.

Usage:
    python3 evidence/b2/build_evidence.py [--check]

``--check`` recomputes all four records and compares them with the committed
bytes instead of writing.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOLS = REPO_ROOT / "forensics" / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import timestamp  # noqa: E402

EVIDENCE = REPO_ROOT / "evidence" / "b2"
TIMES_OUT = EVIDENCE / "TIMES.json"
TOKENS_OUT = EVIDENCE / "TOKENS.json"
VERIFICATION_OUT = EVIDENCE / "VERIFICATION.json"
CONTROLS_OUT = EVIDENCE / "CONTROLS.json"

BASE_COMMIT = "ebc539869"
RECORDED_AT = "2026-11-24"
ITEM = "B2"

STATEMENTS_RECORD = "evidence/a9/STATEMENTS.json"
ENVELOPES_RECORD = "evidence/a10/ENVELOPES.json"
PUBLICATION_RECORD = "evidence/b1/PUBLICATION.json"
SERVICE_CONFIGURATION = "evidence/b0/SERVICE-CONFIGURATION.json"

# The real artefacts the nine-times record is applied to: the four frozen A9
# statements and the B1 fixture publication.
ARTEFACTS: tuple[tuple[str, str, str], ...] = (
    ("a9-a1-sarif", "evidence/a9/STATEMENTS/a1-sarif.json", "a9-statement"),
    ("a9-a5-admission", "evidence/a9/STATEMENTS/a5-admission.json", "a9-statement"),
    ("a9-a7-delta", "evidence/a9/STATEMENTS/a7-delta.json", "a9-statement"),
    ("a9-a8-shard-000", "evidence/a9/STATEMENTS/a8-shard-000.json", "a9-statement"),
    ("b1-publication", PUBLICATION_RECORD, "b1-fixture-publication"),
)

NO_TOKEN_REASON = (
    "no RFC 3161 token exists for this artefact: no TSA is admitted (TA-B2 UNMET), "
    "no certificate or trust root exists, and the tree contains no token file"
)

TSA_ABSENT = (
    "TA-B2 is UNMET: evidence/b0/SERVICE-CONFIGURATION.json records "
    "'0 certificates and no timestamp-authority root'"
)


def _serialise(document: Any) -> bytes:
    return (json.dumps(document, sort_keys=True, indent=1, ensure_ascii=False) + "\n").encode(
        "utf-8"
    )


def _write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read(relative: str) -> bytes:
    return (REPO_ROOT / relative).read_bytes()


def _slot(slots: list[dict[str, Any]], name: str) -> dict[str, Any]:
    for slot in slots:
        if slot["name"] == name:
            return slot
    raise AssertionError(name)


def _unknown(
    slot: dict[str, Any],
    *,
    source: str,
    recorded_by: str,
    reason: str,
) -> None:
    slot.update(
        {
            "value": None,
            "source": source,
            "recordedBy": recorded_by,
            "accuracy": "unknown",
            "established": "unknown",
            "reason": reason,
        }
    )


def _absent(
    slot: dict[str, Any],
    *,
    source: str,
    recorded_by: str,
    reason: str,
) -> None:
    slot.update(
        {
            "value": None,
            "source": source,
            "recordedBy": recorded_by,
            "accuracy": "unknown",
            "established": False,
            "reason": reason,
        }
    )


def _known(
    slot: dict[str, Any],
    *,
    value: str,
    source: str,
    recorded_by: str,
    accuracy: str,
    reason: str | None = None,
) -> None:
    slot.update(
        {
            "value": value,
            "source": source,
            "recordedBy": recorded_by,
            "accuracy": accuracy,
            "established": True,
            "reason": reason,
        }
    )


def _slots(identifier: str, kind: str) -> list[dict[str, Any]]:
    slots = timestamp.canonical_slots()

    source_creation = _slot(slots, "source-creation")
    execution = _slot(slots, "experimental-execution")
    production = _slot(slots, "evidence-production")
    authentication = _slot(slots, "statement-authentication")
    timestamping = _slot(slots, "trusted-timestamping")
    inclusion = _slot(slots, "transparency-inclusion")
    witness = _slot(slots, "witness-observation")
    promotion = _slot(slots, "release-promotion")
    correction = _slot(slots, "correction-or-revocation")

    _unknown(
        source_creation,
        source="evidence/a8/MANIFEST.json#/candidate/perRun",
        recorded_by="A8 producer",
        reason=(
            "the A8 manifest names six run candidates (for example source candidate "
            "17042ccf29bc39df638c63e69d3be6c6f965eef7) but records no date for the source "
            "tree; no tracked record states when the source was created"
        ),
    )
    _unknown(
        execution,
        source="evidence/a8/MANIFEST.json#/candidate/perRun",
        recorded_by="A8 producer",
        reason=(
            "the SARIF runs carry candidate identities, not execution timestamps; A8's "
            "asOf is the record's date and §B.9 forbids inferring execution from a later "
            "timestamp"
        ),
    )
    if kind == "a9-statement":
        _known(
            production,
            value=RECORDED_AT,
            source=f"{STATEMENTS_RECORD}#/sourceIdentity/asOf",
            recorded_by="A9 producer",
            accuracy="day",
            reason="the record carries a date, not an instant; day granularity only",
        )
        _unknown(
            timestamping,
            source=f"{SERVICE_CONFIGURATION}#/trustAssumptions[id=TA-B2]",
            recorded_by="B0 audit",
            reason=TSA_ABSENT,
        )
        _unknown(
            inclusion,
            source="none",
            recorded_by="none",
            reason=(
                "no transparency log exists; B1's FIXTURE-1 is an offline fixture with no "
                "integrated time, and no statement was submitted to an admitted log"
            ),
        )
        _unknown(
            witness,
            source="none",
            recorded_by="none",
            reason="no independent witness exists (TA-B5 UNMET); no cosignature was observed",
        )
        _unknown(
            promotion,
            source="none",
            recorded_by="none",
            reason="no release was promoted; the statements exist only on the staging branch",
        )
        _absent(
            correction,
            source="none",
            recorded_by="none",
            reason="no correction or revocation of this statement exists in the tracked record",
        )
    else:
        _known(
            production,
            value=RECORDED_AT,
            source=f"{PUBLICATION_RECORD}#/recordedAt",
            recorded_by="B1 producer",
            accuracy="day",
            reason="the publication record carries a date, not an instant",
        )
        _unknown(
            timestamping,
            source=f"{SERVICE_CONFIGURATION}#/trustAssumptions[id=TA-B2]",
            recorded_by="B0 audit",
            reason=TSA_ABSENT,
        )
        _absent(
            inclusion,
            source=f"{PUBLICATION_RECORD}#/inclusion",
            recorded_by="B1 producer",
            reason=(
                "inclusion is in FIXTURE-1, which is not a transparency log: it has no log "
                "key, no integrated time and no operator, so no transparency inclusion "
                "time exists"
            ),
        )
        _absent(
            witness,
            source="none",
            recorded_by="none",
            reason="no witness observed FIXTURE-1; it is not a log",
        )
        _unknown(
            promotion,
            source="none",
            recorded_by="none",
            reason="no release was promoted; the fixture evidence is not a release",
        )
        _absent(
            correction,
            source="none",
            recorded_by="none",
            reason="no correction or revocation of this publication exists",
        )

    _known(
        authentication,
        value=RECORDED_AT,
        source=f"{ENVELOPES_RECORD}#/sourceIdentity/asOf",
        recorded_by="A10 producer (test-only HMAC-SHA256; not a trust root)",
        accuracy="day",
        reason=(
            "the A10 record's asOf dates the test-only signature; the envelope records no "
            "signing instant and the signer is not an independent authority"
        ),
    )

    return slots


def times_document() -> dict[str, Any]:
    artefacts = []
    established = {"true": 0, "false": 0, "unknown": 0}
    for identifier, relative, kind in ARTEFACTS:
        body = _read(relative)
        slots = _slots(identifier, kind)
        refusals = timestamp.validate_times({"id": identifier, "slots": slots}, identifier)
        for slot in slots:
            established[str(slot["established"]).lower()] += 1
        artefacts.append(
            {
                "id": identifier,
                "kind": kind,
                "path": relative,
                "sha256": _sha256(body),
                "slots": slots,
                "refusals": refusals,
            }
        )
    return {
        "schema": timestamp.SCHEMA_TIMES,
        "item": ITEM,
        "model": timestamp.MODEL_ID,
        "baseCommit": BASE_COMMIT,
        "recordedAt": RECORDED_AT,
        "clause": "docs/ETP-ADDENDUM-B.md §B.9, §B.24 items 24-26, §B.30 B2",
        "twoClaims": {
            "imprintMatchesArtefact": {
                "checkableOffline": True,
                "needs": "the artefact bytes and the token's hashedMessage",
                "establishedForRealArtefacts": 0,
                "reason": NO_TOKEN_REASON,
            },
            "authorityAssertedTheTime": {
                "checkableOffline": False,
                "needs": [
                    "the token signature",
                    "the TSA certificate chain",
                    "id-kp-timeStamping extended key usage",
                    "an admitted root of trust",
                ],
                "establishedForRealArtefacts": 0,
                "reason": TSA_ABSENT,
            },
        },
        "orderingInvariants": [
            {"earlier": earlier, "later": later}
            for earlier, later in timestamp.ORDER_INVARIANTS
        ],
        "artefacts": artefacts,
        "summary": {
            "artefacts": len(artefacts),
            "slots": len(artefacts) * len(timestamp.SLOTS),
            "established": established["true"],
            "notEstablished": established["false"],
            "unknown": established["unknown"],
            "refusals": sum(len(artefact["refusals"]) for artefact in artefacts),
        },
        "nonClaims": [
            "a recorded date is not a trusted time; no slot here is an authority's assertion",
            "no clock is trustworthy because it is read; no slot is filled from the wall clock",
            "the nine slots are not interchangeable and were not collapsed into one timestamp",
        ],
    }


def tokens_document() -> dict[str, Any]:
    found, scanned = timestamp.scan_for_tokens(REPO_ROOT)
    relative = sorted(str(path.relative_to(REPO_ROOT)) for path in found)
    per_artefact = []
    for identifier, path, _kind in ARTEFACTS:
        per_artefact.append(
            {
                "id": identifier,
                "path": path,
                "outcome": "NO_TOKEN",
                "tokenPath": None,
                "reason": NO_TOKEN_REASON,
            }
        )
    return {
        "schema": timestamp.SCHEMA_TOKENS,
        "item": ITEM,
        "baseCommit": BASE_COMMIT,
        "recordedAt": RECORDED_AT,
        "scannedRoot": ".",
        "scannedSuffixes": list(timestamp.TOKEN_SUFFIXES),
        "scannedFiles": scanned,
        "tokens": relative,
        "perArtefact": per_artefact,
        "controlFixtures": {
            "location": "evidence/b2/CONTROLS.json#/controls[*]/tokenBase64",
            "label": "control-only",
            "trusted": False,
            "note": (
                "deterministic fixture tokens for the refusal controls; they are HMAC-SHA256 "
                "under a fixed public seed, are not signed by a certificate, and are not "
                "timestamp tokens issued by any TSA"
            ),
        },
        "summary": {
            "tokensFound": len(relative),
            "noToken": len(per_artefact),
            "fabricatedTokens": 0,
        },
        "nonClaims": [
            "zero tokens found is a true observation about this tree, not a failed search",
            "a control fixture token in CONTROLS.json is not a token found in the tree",
        ],
    }


def _verify(
    variant: str,
    *,
    artifact: bytes,
    certificate: bytes | None = None,
    verify_signature: Any = None,
    **kwargs: Any,
) -> timestamp.Verification:
    token = timestamp.control_token(variant, artifact=artifact, algorithm="sha256")
    return timestamp.verify_token(
        token,
        artifact,
        algorithm="sha256",
        certificate=certificate,
        verify_signature=verify_signature,
        **kwargs,
    )


def verification_document() -> dict[str, Any]:
    with_eku = timestamp.control_certificate(with_eku=True)
    without_eku = timestamp.control_certificate(with_eku=False)
    verify = timestamp.control_verify_signature
    per_artefact = []
    for identifier, path, _kind in ARTEFACTS:
        per_artefact.append(
            {
                "id": identifier,
                "path": path,
                "algorithm": "sha256",
                "token": None,
                "code": timestamp.CODE_NO_TOKEN,
                "outcome": timestamp.OUTCOME_NO_TOKEN,
                "imprint": "NOT_RUN",
                "signature": "NOT_RUN",
                "chain": "NOT_RUN",
                "eku": "NOT_RUN",
                "root": "NOT_RUN",
                "accuracy": "NOT_RUN",
                "trusted": False,
                "reason": NO_TOKEN_REASON,
            }
        )
    # A control-only baseline, recorded so the aggregate is not a bare zero: the
    # verifier works, but only on fixtures, and the outcome is UNTRUSTED.
    artifact = _read("evidence/a9/STATEMENTS/a8-shard-000.json")
    baseline = _verify(
        "valid", artifact=artifact, certificate=with_eku, verify_signature=verify
    )
    return {
        "schema": timestamp.SCHEMA_VERIFICATION,
        "item": ITEM,
        "baseCommit": BASE_COMMIT,
        "recordedAt": RECORDED_AT,
        "perArtefact": per_artefact,
        "controlBaseline": {
            "artifact": "evidence/a9/STATEMENTS/a8-shard-000.json",
            "fixture": "control-only",
            "code": baseline.code,
            "outcome": baseline.outcome,
            "imprint": baseline.imprint,
            "signature": baseline.signature,
            "chain": baseline.chain,
            "eku": baseline.eku,
            "root": baseline.root,
            "trusted": False,
            "note": (
                "a deterministic fixture token verifies because the fixture verification "
                "function is the control HMAC; it is not an authority's token and the outcome "
                "is UNTRUSTED"
            ),
        },
        "unusedCertificateFixture": {
            "eku": "control-only",
            "sha256": _sha256(without_eku),
            "note": "the certificate without an EKU is used only by the TS_REFUSED_EKU control",
        },
        "aggregate": {
            "artefacts": len(per_artefact),
            "noToken": len(per_artefact),
            "imprintVerified": 0,
            "signatureVerified": 0,
            "chainVerified": 0,
            "rootAdmitted": 0,
            "trusted": 0,
        },
        "notRun": [
            "signature verification of a real token (no token exists)",
            "certificate-chain validation against an admitted root (no certificate, no root)",
            "id-kp-timeStamping evaluation for a real TSA (no certificate)",
            "nonce correspondence with a real request (no request, no TSA)",
            "revocation and historical validity (no chain, no revocation source)",
        ],
        "nonClaims": [
            "an imprint match is not a trusted time",
            "a fixture token that verifies is not an authority's assertion",
            "trusted is 0 because no authority exists, not because verification was skipped",
        ],
    }


def _token_control(
    identifier: str,
    control: str,
    variant: str,
    *,
    artifact: bytes,
    certificate: bytes | None = None,
    verify_signature: Any = None,
    canary: str,
    canary_result: str,
    **kwargs: Any,
) -> dict[str, Any]:
    token = timestamp.control_token(variant, artifact=artifact, algorithm="sha256")
    result = timestamp.verify_token(
        token,
        artifact,
        algorithm="sha256",
        certificate=certificate,
        verify_signature=verify_signature,
        **kwargs,
    )
    return {
        "id": identifier,
        "control": control,
        "kind": "token",
        "fixture": "control-only",
        "clause": "docs/ETP-ADDENDUM-B.md §B.24 items 24-26; §B.30 B2",
        "refusalCode": result.code,
        "outcome": result.outcome,
        "detail": result.detail,
        "imprint": result.imprint,
        "signature": result.signature,
        "eku": result.eku,
        "root": result.root,
        "trusted": False,
        "canary": canary,
        "canaryResult": canary_result,
        "tokenSha256": _sha256(token),
        "tokenBase64": base64.b64encode(token).decode("ascii"),
    }


def _times_control(
    identifier: str,
    control: str,
    variant: str,
    *,
    canary: str,
    canary_result: str,
) -> dict[str, Any]:
    fixture = timestamp.control_times(variant)
    refusals = timestamp.validate_times(fixture)
    codes = sorted({refusal["code"] for refusal in refusals})
    return {
        "id": identifier,
        "control": control,
        "kind": "times",
        "fixture": "control-only",
        "clause": "docs/ETP-ADDENDUM-B.md §B.9",
        "refusalCode": codes[0] if codes else None,
        "observedCodes": codes,
        "refusalCount": len(refusals),
        "detail": refusals[0]["message"] if refusals else None,
        "trusted": False,
        "canary": canary,
        "canaryResult": canary_result,
        "fixtureRecord": fixture,
    }


def controls_document() -> dict[str, Any]:
    artifact = _read("evidence/a9/STATEMENTS/a8-shard-000.json")
    with_eku = timestamp.control_certificate(with_eku=True)
    without_eku = timestamp.control_certificate(with_eku=False)
    verify = timestamp.control_verify_signature

    baseline_token = timestamp.control_token("valid", artifact=artifact, algorithm="sha256")
    baseline = timestamp.verify_token(
        baseline_token,
        artifact,
        algorithm="sha256",
        certificate=with_eku,
        verify_signature=verify,
    )
    if not baseline.accepted:
        raise AssertionError(baseline.detail)

    controls = [
        _token_control(
            "ts-malformed-der",
            "a truncated token is not one DER value",
            "malformed-der",
            artifact=artifact,
            canary="the unmutated fixture token is accepted",
            canary_result="ACCEPTED",
        ),
        _token_control(
            "ts-trailing-byte",
            "one trailing byte after the ContentInfo",
            "trailing-byte",
            artifact=artifact,
            canary="the unmutated fixture token is accepted",
            canary_result="ACCEPTED",
        ),
        _token_control(
            "ts-unsupported-version",
            "TSTInfo.version is 2",
            "unsupported-version",
            artifact=artifact,
            canary="TSTInfo.version 1 is accepted",
            canary_result="ACCEPTED",
        ),
        _token_control(
            "ts-wrong-imprint",
            "the imprint is the digest of another artefact",
            "wrong-imprint",
            artifact=artifact,
            canary="the imprint of the declared artefact is accepted",
            canary_result="ACCEPTED",
        ),
        _token_control(
            "ts-wrong-algorithm",
            "the token names SHA-384 while the caller declares SHA-256",
            "wrong-algorithm",
            artifact=artifact,
            canary="the declared SHA-256 token is accepted",
            canary_result="ACCEPTED",
        ),
        _token_control(
            "ts-absent-gen-time",
            "TSTInfo.genTime is absent",
            "absent-gen-time",
            artifact=artifact,
            canary="a token with genTime is accepted",
            canary_result="ACCEPTED",
        ),
        _token_control(
            "ts-missing-eku",
            "the certificate lacks id-kp-timeStamping",
            "missing-eku",
            artifact=artifact,
            certificate=without_eku,
            verify_signature=verify,
            canary="the certificate carrying id-kp-timeStamping is accepted",
            canary_result="ACCEPTED",
        ),
        _token_control(
            "ts-bad-signature",
            "the signed attributes carry a corrupted signature",
            "bad-signature",
            artifact=artifact,
            certificate=with_eku,
            verify_signature=verify,
            canary="the correctly signed fixture token is accepted",
            canary_result="ACCEPTED",
        ),
        _token_control(
            "ts-absent-root",
            "the caller requires an admitted root and supplies none",
            "valid",
            artifact=artifact,
            certificate=with_eku,
            verify_signature=verify,
            require_root=True,
            canary="the same token is accepted when no root is required",
            canary_result="ACCEPTED",
        ),
        _token_control(
            "ts-live-service",
            "the token asserts a live-service verification",
            "live-service",
            artifact=artifact,
            canary="a token with the normal fixture policy is accepted",
            canary_result="ACCEPTED",
        ),
        _token_control(
            "ts-nonce-mismatch",
            "the caller expects nonce 8 and the token carries 7",
            "nonce-mismatch",
            artifact=artifact,
            expected_nonce=8,
            canary="the expected nonce 7 is accepted",
            canary_result="ACCEPTED",
        ),
        _token_control(
            "ts-invalid-accuracy",
            "accuracy.millis is 1000, outside 1..999",
            "invalid-accuracy",
            artifact=artifact,
            canary="accuracy.millis 1 is accepted",
            canary_result="ACCEPTED",
        ),
        _times_control(
            "ts-collapsed-times",
            "nine slots carry one value from one source",
            "collapsed",
            canary="the nine distinct fixture times are accepted",
            canary_result="ACCEPTED",
        ),
        _times_control(
            "ts-unsourced-time",
            "a slot has a value and no source",
            "unsourced",
            canary="the sourced fixture is accepted",
            canary_result="ACCEPTED",
        ),
        _times_control(
            "ts-out-of-order",
            "statement authentication precedes evidence production",
            "out-of-order",
            canary="the correctly ordered fixture is accepted",
            canary_result="ACCEPTED",
        ),
        _times_control(
            "ts-wrong-time-model",
            "the record carries eight slots instead of the nine of §B.9",
            "missing-slot",
            canary="the nine-slot fixture is accepted",
            canary_result="ACCEPTED",
        ),
    ]

    valid_times = timestamp.control_times("valid")
    if timestamp.validate_times(valid_times):
        raise AssertionError("the valid times fixture was refused")

    fired_codes = sorted(
        {
            control["refusalCode"]
            for control in controls
            if control.get("refusalCode") is not None
        }
    )
    return {
        "schema": timestamp.SCHEMA_CONTROLS,
        "item": ITEM,
        "baseCommit": BASE_COMMIT,
        "recordedAt": RECORDED_AT,
        "controlOnly": True,
        "trusted": False,
        "positiveControl": {
            "name": "valid control token and valid nine-slot record",
            "fixture": "control-only",
            "code": baseline.code,
            "outcome": baseline.outcome,
            "imprint": baseline.imprint,
            "signature": baseline.signature,
            "eku": baseline.eku,
            "trusted": False,
            "tokenSha256": _sha256(baseline_token),
            "tokenBase64": base64.b64encode(baseline_token).decode("ascii"),
            "note": (
                "the positive control is a fixture token verified by the control HMAC; it "
                "establishes that the refusals are attributable to the mutated field, not "
                "that any TSA signed anything"
            ),
        },
        "controls": controls,
        "summary": {
            "total": len(controls),
            "fired": sum(1 for control in controls if control["refusalCode"]),
            "canariesAccepted": sum(
                1 for control in controls if control["canaryResult"] == "ACCEPTED"
            ),
            "refusalCodes": fired_codes,
            "onePerCode": sorted(fired_codes) == sorted(timestamp.REFUSAL_CODES),
        },
        "nonClaims": [
            "a control fixture token is not an authority and is never TRUSTED",
            "a refusal proves the verifier rejects that mutation, not that a TSA behaves so",
            "the fixtures are deterministic test inputs, not evidence of timestamping",
        ],
    }


def build() -> dict[str, bytes]:
    return {
        "TIMES.json": _serialise(times_document()),
        "TOKENS.json": _serialise(tokens_document()),
        "VERIFICATION.json": _serialise(verification_document()),
        "CONTROLS.json": _serialise(controls_document()),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="produce the B2 records")
    parser.add_argument("--check", action="store_true", help="compare with the committed bytes")
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)

    records = build()

    if args.check:
        bad = []
        for name, data in sorted(records.items()):
            path = EVIDENCE / name
            if not path.is_file() or path.read_bytes() != data:
                bad.append(name)
        if bad:
            for name in bad:
                print(f"b2: differs from the committed build: {name}")
            return 1
        print(f"b2: check ok records={len(records)} controlOnly=true trusted=0")
        print("b2: codes=NONE")
        return 0

    for name, data in sorted(records.items()):
        _write_bytes(EVIDENCE / name, data)

    times = json.loads(records["TIMES.json"])
    tokens = json.loads(records["TOKENS.json"])
    verification = json.loads(records["VERIFICATION.json"])
    controls = json.loads(records["CONTROLS.json"])
    print(
        f"b2: artefacts={times['summary']['artefacts']} slots={times['summary']['slots']} "
        f"established={times['summary']['established']} unknown={times['summary']['unknown']} "
        f"notEstablished={times['summary']['notEstablished']} refusals={times['summary']['refusals']}"
    )
    print(
        f"b2: tokensFound={tokens['summary']['tokensFound']} noToken={tokens['summary']['noToken']} "
        f"trusted={verification['aggregate']['trusted']}"
    )
    print(
        f"b2: controls={controls['summary']['total']} fired={controls['summary']['fired']} "
        f"canariesAccepted={controls['summary']['canariesAccepted']} "
        f"onePerCode={controls['summary']['onePerCode']}"
    )
    print("b2: codes=NONE")
    return 0


if __name__ == "__main__":
    sys.exit(main())
